/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdecho/echo.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_ECHO

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_debug.h>
#include <lustre_dlm.h>
#include <lprocfs_status.h>

#include "echo_internal.h"

/* The echo objid needs to be below 2^32, because regular FID numbers are
 * limited to 2^32 objects in f_oid for the FID_SEQ_ECHO range. b=23335 */
#define ECHO_INIT_OID        0x10000000ULL
#define ECHO_HANDLE_MAGIC    0xabcd0123fedc9876ULL

#define ECHO_PERSISTENT_PAGES (ECHO_PERSISTENT_SIZE >> PAGE_SHIFT)
static struct page *echo_persistent_pages[ECHO_PERSISTENT_PAGES];

enum {
        LPROC_ECHO_READ_BYTES = 1,
        LPROC_ECHO_WRITE_BYTES = 2,
        LPROC_ECHO_LAST = LPROC_ECHO_WRITE_BYTES +1
};

struct echo_srv_device {
	struct lu_device esd_dev;
	struct lu_target esd_lut;
};

static inline struct echo_srv_device *echo_srv_dev(struct lu_device *d)
{
	return container_of0(d, struct echo_srv_device, esd_dev);
}

static inline struct obd_device *echo_srv_obd(struct echo_srv_device *esd)
{
	return esd->esd_dev.ld_obd;
}

static int echo_connect(const struct lu_env *env,
                        struct obd_export **exp, struct obd_device *obd,
                        struct obd_uuid *cluuid, struct obd_connect_data *data,
                        void *localdata)
{
	struct lustre_handle conn = { 0 };
	int rc;

	data->ocd_connect_flags &= ECHO_CONNECT_SUPPORTED;

	if (data->ocd_connect_flags & OBD_CONNECT_FLAGS2)
		data->ocd_connect_flags2 &= ECHO_CONNECT_SUPPORTED2;

	rc = class_connect(&conn, obd, cluuid);
	if (rc) {
		CERROR("can't connect %d\n", rc);
		return rc;
	}
	*exp = class_conn2export(&conn);

	return 0;
}

static int echo_disconnect(struct obd_export *exp)
{
        LASSERT (exp != NULL);

        return server_disconnect_export(exp);
}

static int echo_init_export(struct obd_export *exp)
{
        return ldlm_init_export(exp);
}

static int echo_destroy_export(struct obd_export *exp)
{
        ENTRY;

        target_destroy_export(exp);
        ldlm_destroy_export(exp);

        RETURN(0);
}

static u64 echo_next_id(struct obd_device *obddev)
{
	u64 id;

	spin_lock(&obddev->u.echo.eo_lock);
	id = ++obddev->u.echo.eo_lastino;
	spin_unlock(&obddev->u.echo.eo_lock);

	return id;
}

static void
echo_page_debug_setup(struct page *page, int rw, u64 id,
		      __u64 offset, int len)
{
	int   page_offset = offset & ~PAGE_MASK;
	char *addr        = ((char *)kmap(page)) + page_offset;

        if (len % OBD_ECHO_BLOCK_SIZE != 0)
                CERROR("Unexpected block size %d\n", len);

        while (len > 0) {
                if (rw & OBD_BRW_READ)
                        block_debug_setup(addr, OBD_ECHO_BLOCK_SIZE,
                                          offset, id);
                else
                        block_debug_setup(addr, OBD_ECHO_BLOCK_SIZE,
                                          0xecc0ecc0ecc0ecc0ULL,
                                          0xecc0ecc0ecc0ecc0ULL);

                addr   += OBD_ECHO_BLOCK_SIZE;
                offset += OBD_ECHO_BLOCK_SIZE;
                len    -= OBD_ECHO_BLOCK_SIZE;
        }

	kunmap(page);
}

static int
echo_page_debug_check(struct page *page, u64 id,
		      __u64 offset, int len)
{
	int   page_offset = offset & ~PAGE_MASK;
	char *addr        = ((char *)kmap(page)) + page_offset;
	int   rc          = 0;
	int   rc2;

        if (len % OBD_ECHO_BLOCK_SIZE != 0)
                CERROR("Unexpected block size %d\n", len);

        while (len > 0) {
                rc2 = block_debug_check("echo", addr, OBD_ECHO_BLOCK_SIZE,
                                        offset, id);

                if (rc2 != 0 && rc == 0)
                        rc = rc2;

                addr   += OBD_ECHO_BLOCK_SIZE;
                offset += OBD_ECHO_BLOCK_SIZE;
                len    -= OBD_ECHO_BLOCK_SIZE;
        }

	kunmap(page);

	return rc;
}

static int echo_map_nb_to_lb(struct obdo *oa, struct obd_ioobj *obj,
                             struct niobuf_remote *nb, int *pages,
                             struct niobuf_local *lb, int cmd, int *left)
{
	gfp_t gfp_mask = (ostid_id(&obj->ioo_oid) & 1) ?
			GFP_HIGHUSER : GFP_KERNEL;
	int ispersistent = ostid_id(&obj->ioo_oid) == ECHO_PERSISTENT_OBJID;
	int debug_setup = (!ispersistent &&
			   (oa->o_valid & OBD_MD_FLFLAGS) != 0 &&
			   (oa->o_flags & OBD_FL_DEBUG_CHECK) != 0);
	struct niobuf_local *res = lb;
	u64 offset = nb->rnb_offset;
	int len = nb->rnb_len;

	while (len > 0) {
		int plen = PAGE_SIZE - (offset & (PAGE_SIZE-1));
		if (len < plen)
			plen = len;

                /* check for local buf overflow */
                if (*left == 0)
                        return -EINVAL;

		res->lnb_file_offset = offset;
		res->lnb_len = plen;
		LASSERT((res->lnb_file_offset & ~PAGE_MASK) +
			res->lnb_len <= PAGE_SIZE);

		if (ispersistent &&
		    ((res->lnb_file_offset >> PAGE_SHIFT) <
		      ECHO_PERSISTENT_PAGES)) {
			res->lnb_page =
				echo_persistent_pages[res->lnb_file_offset >>
						      PAGE_SHIFT];
			/* Take extra ref so __free_pages() can be called OK */
			get_page(res->lnb_page);
		} else {
			res->lnb_page = alloc_page(gfp_mask);
			if (res->lnb_page == NULL) {
				CERROR("can't get page for id " DOSTID"\n",
				       POSTID(&obj->ioo_oid));
				return -ENOMEM;
			}
		}

		CDEBUG(D_PAGE, "$$$$ get page %p @ %llu for %d\n",
		       res->lnb_page, res->lnb_file_offset, res->lnb_len);

		if (cmd & OBD_BRW_READ)
			res->lnb_rc = res->lnb_len;

		if (debug_setup)
			echo_page_debug_setup(res->lnb_page, cmd,
					      ostid_id(&obj->ioo_oid),
					      res->lnb_file_offset,
					      res->lnb_len);

                offset += plen;
                len -= plen;
                res++;

                (*left)--;
                (*pages)++;
        }

        return 0;
}

static int echo_finalize_lb(struct obdo *oa, struct obd_ioobj *obj,
			    struct niobuf_remote *rb, int *pgs,
			    struct niobuf_local *lb, int verify)
{
	struct niobuf_local *res = lb;
	u64 start = rb->rnb_offset >> PAGE_SHIFT;
	u64 end   = (rb->rnb_offset + rb->rnb_len + PAGE_SIZE - 1) >>
		    PAGE_SHIFT;
	int     count  = (int)(end - start);
	int     rc     = 0;
	int     i;

	for (i = 0; i < count; i++, (*pgs) ++, res++) {
		struct page *page = res->lnb_page;
		void       *addr;

		if (page == NULL) {
			CERROR("null page objid %llu:%p, buf %d/%d\n",
			       ostid_id(&obj->ioo_oid), page, i,
			       obj->ioo_bufcnt);
			return -EFAULT;
		}

		addr = kmap(page);

		CDEBUG(D_PAGE, "$$$$ use page %p, addr %p@%llu\n",
		       res->lnb_page, addr, res->lnb_file_offset);

		if (verify) {
			int vrc = echo_page_debug_check(page,
							ostid_id(&obj->ioo_oid),
							res->lnb_file_offset,
							res->lnb_len);
			/* check all the pages always */
			if (vrc != 0 && rc == 0)
				rc = vrc;
		}

		kunmap(page);
		/* NB see comment above regarding persistent pages */
		__free_page(page);
	}

	return rc;
}

static int echo_preprw(const struct lu_env *env, int cmd,
		       struct obd_export *export, struct obdo *oa,
		       int objcount, struct obd_ioobj *obj,
		       struct niobuf_remote *nb, int *pages,
		       struct niobuf_local *res)
{
        struct obd_device *obd;
        int tot_bytes = 0;
        int rc = 0;
        int i, left;
        ENTRY;

        obd = export->exp_obd;
        if (obd == NULL)
                RETURN(-EINVAL);

        /* Temp fix to stop falling foul of osc_announce_cached() */
        oa->o_valid &= ~(OBD_MD_FLBLOCKS | OBD_MD_FLGRANT);

        memset(res, 0, sizeof(*res) * *pages);

        CDEBUG(D_PAGE, "%s %d obdos with %d IOs\n",
               cmd == OBD_BRW_READ ? "reading" : "writing", objcount, *pages);

        left = *pages;
        *pages = 0;

        for (i = 0; i < objcount; i++, obj++) {
                int j;

                for (j = 0 ; j < obj->ioo_bufcnt ; j++, nb++) {

                        rc = echo_map_nb_to_lb(oa, obj, nb, pages,
                                               res + *pages, cmd, &left);
                        if (rc)
                                GOTO(preprw_cleanup, rc);

			tot_bytes += nb->rnb_len;
                }
        }

	atomic_add(*pages, &obd->u.echo.eo_prep);

        if (cmd & OBD_BRW_READ)
                lprocfs_counter_add(obd->obd_stats, LPROC_ECHO_READ_BYTES,
                                    tot_bytes);
        else
                lprocfs_counter_add(obd->obd_stats, LPROC_ECHO_WRITE_BYTES,
                                    tot_bytes);

        CDEBUG(D_PAGE, "%d pages allocated after prep\n",
	       atomic_read(&obd->u.echo.eo_prep));

        RETURN(0);

preprw_cleanup:
        /* It is possible that we would rather handle errors by  allow
         * any already-set-up pages to complete, rather than tearing them
         * all down again.  I believe that this is what the in-kernel
         * prep/commit operations do.
         */
        CERROR("cleaning up %u pages (%d obdos)\n", *pages, objcount);
        for (i = 0; i < *pages; i++) {
		kunmap(res[i].lnb_page);
		/* NB if this is a persistent page, __free_page() will just
		 * lose the extra ref gained above */
		__free_page(res[i].lnb_page);
		res[i].lnb_page = NULL;
		atomic_dec(&obd->u.echo.eo_prep);
	}

	return rc;
}

static int echo_commitrw(const struct lu_env *env, int cmd,
			 struct obd_export *export, struct obdo *oa,
			 int objcount, struct obd_ioobj *obj,
			 struct niobuf_remote *rb, int niocount,
			 struct niobuf_local *res, int rc)
{
        struct obd_device *obd;
        int pgs = 0;
        int i;
        ENTRY;

        obd = export->exp_obd;
        if (obd == NULL)
                RETURN(-EINVAL);

        if (rc)
                GOTO(commitrw_cleanup, rc);

        if ((cmd & OBD_BRW_RWMASK) == OBD_BRW_READ) {
                CDEBUG(D_PAGE, "reading %d obdos with %d IOs\n",
                       objcount, niocount);
        } else {
                CDEBUG(D_PAGE, "writing %d obdos with %d IOs\n",
                       objcount, niocount);
        }

        if (niocount && res == NULL) {
                CERROR("NULL res niobuf with niocount %d\n", niocount);
                RETURN(-EINVAL);
        }

	for (i = 0; i < objcount; i++, obj++) {
		int verify = (rc == 0 &&
			     ostid_id(&obj->ioo_oid) != ECHO_PERSISTENT_OBJID &&
			      (oa->o_valid & OBD_MD_FLFLAGS) != 0 &&
			      (oa->o_flags & OBD_FL_DEBUG_CHECK) != 0);
		int j;

		for (j = 0 ; j < obj->ioo_bufcnt ; j++, rb++) {
			int vrc = echo_finalize_lb(oa, obj, rb, &pgs, &res[pgs],
						   verify);
			if (vrc == 0)
				continue;

			if (vrc == -EFAULT)
				GOTO(commitrw_cleanup, rc = vrc);

			if (rc == 0)
				rc = vrc;
		}

	}

	atomic_sub(pgs, &obd->u.echo.eo_prep);

        CDEBUG(D_PAGE, "%d pages remain after commit\n",
	       atomic_read(&obd->u.echo.eo_prep));
        RETURN(rc);

commitrw_cleanup:
	atomic_sub(pgs, &obd->u.echo.eo_prep);

	CERROR("cleaning up %d pages (%d obdos)\n",
	       niocount - pgs - 1, objcount);

	while (pgs < niocount) {
		struct page *page = res[pgs++].lnb_page;

		if (page == NULL)
			continue;

		/* NB see comment above regarding persistent pages */
		__free_page(page);
		atomic_dec(&obd->u.echo.eo_prep);
	}
	return rc;
}

LPROC_SEQ_FOPS_RO_TYPE(echo, uuid);
static struct lprocfs_vars lprocfs_echo_obd_vars[] = {
	{ .name =       "uuid",
	  .fops =       &echo_uuid_fops         },
	{ NULL }
};

struct obd_ops echo_obd_ops = {
	.o_owner           = THIS_MODULE,
	.o_connect         = echo_connect,
	.o_disconnect      = echo_disconnect,
	.o_init_export     = echo_init_export,
	.o_destroy_export  = echo_destroy_export,
	.o_preprw          = echo_preprw,
	.o_commitrw        = echo_commitrw,
};

/**
 * Echo Server request handler for OST_CREATE RPC.
 *
 * This is part of request processing. Its simulates the object
 * creation on OST.
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int esd_create_hdl(struct tgt_session_info *tsi)
{
	const struct obdo *oa = &tsi->tsi_ost_body->oa;
	struct obd_device *obd = tsi->tsi_exp->exp_obd;
	struct ost_body *repbody;
	struct obdo *rep_oa;

	ENTRY;

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_OST_BODY);
	if (repbody == NULL)
		RETURN(-ENOMEM);

	if (!(oa->o_mode & S_IFMT)) {
		CERROR("%s: no type is set in obdo!\n",
		       tsi->tsi_exp->exp_obd->obd_name);
		RETURN(-ENOENT);
	}

	if (!(oa->o_valid & OBD_MD_FLTYPE)) {
		CERROR("%s: invalid o_valid in obdo: %#llx\n",
		       tsi->tsi_exp->exp_obd->obd_name, oa->o_valid);
		RETURN(-EINVAL);
	}

	rep_oa = &repbody->oa;

	if (!fid_seq_is_echo(ostid_seq(&oa->o_oi))) {
		CERROR("%s: invalid seq %#llx\n",
		       tsi->tsi_exp->exp_obd->obd_name, ostid_seq(&oa->o_oi));
		return -EINVAL;
	}

	ostid_set_seq_echo(&rep_oa->o_oi);
	ostid_set_id(&rep_oa->o_oi, echo_next_id(obd));

	CDEBUG(D_INFO, "%s: Create object "DOSTID"\n",
	       tsi->tsi_exp->exp_obd->obd_name, POSTID(&rep_oa->o_oi));

	rep_oa->o_valid |= OBD_MD_FLID | OBD_MD_FLGROUP;

	RETURN(0);
}

/**
 * Echo Server request handler for OST_DESTROY RPC.
 *
 * This is Echo Server part of request handling. It simulates the objects
 * destroy on OST.
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int esd_destroy_hdl(struct tgt_session_info *tsi)
{
	const struct obdo *oa = &tsi->tsi_ost_body->oa;
	struct obd_device *obd = tsi->tsi_exp->exp_obd;
	struct ost_body *repbody;
	u64 oid;

	ENTRY;

	oid = ostid_id(&oa->o_oi);
	LASSERT(oid != 0);

	if (!(oa->o_valid & OBD_MD_FLID)) {
		CERROR("%s: obdo missing FLID valid flag: %#llx\n",
		       tsi->tsi_exp->exp_obd->obd_name, oa->o_valid);
		RETURN(-EINVAL);
	}

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_OST_BODY);

	if (ostid_id(&oa->o_oi) > obd->u.echo.eo_lastino ||
	    ostid_id(&oa->o_oi) < ECHO_INIT_OID) {
		CERROR("%s: bad objid to destroy: "DOSTID"\n",
		       tsi->tsi_exp->exp_obd->obd_name, POSTID(&oa->o_oi));
		RETURN(-EINVAL);
	}

	CDEBUG(D_INFO, "%s: Destroy object "DOSTID"\n",
	       tsi->tsi_exp->exp_obd->obd_name, POSTID(&oa->o_oi));

	repbody->oa.o_oi = oa->o_oi;
	RETURN(0);
}

/**
 * Echo Server request handler for OST_GETATTR RPC.
 *
 * This is Echo Server part of request handling. It returns an object
 * attributes to the client. All objects have the same attributes in
 * Echo Server.
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int esd_getattr_hdl(struct tgt_session_info *tsi)
{
	const struct obdo *oa = &tsi->tsi_ost_body->oa;
	struct obd_device *obd = tsi->tsi_exp->exp_obd;
	struct ost_body *repbody;

	ENTRY;

	if (!(oa->o_valid & OBD_MD_FLID)) {
		CERROR("%s: obdo missing FLID valid flag: %#llx\n",
		       tsi->tsi_exp->exp_obd->obd_name, oa->o_valid);
		RETURN(-EINVAL);
	}

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_OST_BODY);
	if (repbody == NULL)
		RETURN(-ENOMEM);

	repbody->oa.o_oi = oa->o_oi;
	repbody->oa.o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;

	obdo_cpy_md(&repbody->oa, &obd->u.echo.eo_oa, oa->o_valid);

	repbody->oa.o_valid |= OBD_MD_FLFLAGS;
	repbody->oa.o_flags = OBD_FL_FLUSH;

	RETURN(0);
}

/**
 * Echo Server request handler for OST_SETATTR RPC.
 *
 * This is Echo Server part of request handling. It sets common
 * attributes from request to the Echo Server objects.
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int esd_setattr_hdl(struct tgt_session_info *tsi)
{
	struct ost_body *body = tsi->tsi_ost_body;
	struct obd_device *obd = tsi->tsi_exp->exp_obd;
	struct ost_body *repbody;

	ENTRY;

	if (!(body->oa.o_valid & OBD_MD_FLID)) {
		CERROR("%s: obdo missing FLID valid flag: %#llx\n",
		       tsi->tsi_exp->exp_obd->obd_name,
		       body->oa.o_valid);
		RETURN(-EINVAL);
	}

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_OST_BODY);
	if (repbody == NULL)
		RETURN(-ENOMEM);

	repbody->oa.o_oi = body->oa.o_oi;
	repbody->oa.o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;

	obd->u.echo.eo_oa = body->oa;

	RETURN(0);
}

#define OBD_FAIL_OST_READ_NET	OBD_FAIL_OST_BRW_NET
#define OBD_FAIL_OST_WRITE_NET	OBD_FAIL_OST_BRW_NET
#define OST_BRW_READ	OST_READ
#define OST_BRW_WRITE	OST_WRITE

/**
 * Table of Echo Server specific request handlers
 *
 * This table contains all opcodes accepted by Echo Server and
 * specifies handlers for them. The tgt_request_handler()
 * uses such table from each target to process incoming
 * requests.
 */
static struct tgt_handler esd_tgt_handlers[] = {
TGT_RPC_HANDLER(OST_FIRST_OPC, 0, OST_CONNECT, tgt_connect,
		&RQF_CONNECT, LUSTRE_OBD_VERSION),
TGT_RPC_HANDLER(OST_FIRST_OPC, 0, OST_DISCONNECT, tgt_disconnect,
		&RQF_OST_DISCONNECT, LUSTRE_OBD_VERSION),
TGT_OST_HDL(HABEO_CORPUS | HABEO_REFERO, OST_GETATTR, esd_getattr_hdl),
TGT_OST_HDL(HABEO_CORPUS | HABEO_REFERO | MUTABOR, OST_SETATTR,
	    esd_setattr_hdl),
TGT_OST_HDL(HABEO_REFERO | MUTABOR, OST_CREATE, esd_create_hdl),
TGT_OST_HDL(HABEO_REFERO | MUTABOR, OST_DESTROY, esd_destroy_hdl),
TGT_OST_HDL(HABEO_CORPUS | HABEO_REFERO, OST_BRW_READ, tgt_brw_read),
TGT_OST_HDL(HABEO_CORPUS | MUTABOR, OST_BRW_WRITE, tgt_brw_write),
};

static struct tgt_opc_slice esd_common_slice[] = {
	{
		.tos_opc_start	= OST_FIRST_OPC,
		.tos_opc_end	= OST_LAST_OPC,
		.tos_hs		= esd_tgt_handlers
	},
	{
		.tos_opc_start	= OBD_FIRST_OPC,
		.tos_opc_end	= OBD_LAST_OPC,
		.tos_hs		= tgt_obd_handlers
	},
	{
		.tos_opc_start	= LDLM_FIRST_OPC,
		.tos_opc_end	= LDLM_LAST_OPC,
		.tos_hs		= tgt_dlm_handlers
	},
	{
		.tos_opc_start  = SEC_FIRST_OPC,
		.tos_opc_end    = SEC_LAST_OPC,
		.tos_hs         = tgt_sec_ctx_handlers
	},
	{
		.tos_hs		= NULL
	}
};

/**
 * lu_device_operations matrix for ECHO SRV device is NULL,
 * this device is just serving incoming requests immediately
 * without building a stack of lu_devices.
 */
static struct lu_device_operations echo_srv_lu_ops = { 0 };

/**
 * Initialize Echo Server device with parameters in the config log \a cfg.
 *
 * This is the main starting point of Echo Server initialization. It fills all
 * parameters with their initial values and starts Echo Server.
 *
 * \param[in] env	execution environment
 * \param[in] m		Echo Server device
 * \param[in] ldt	LU device type of Echo Server
 * \param[in] cfg	configuration log
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int echo_srv_init0(const struct lu_env *env,
			  struct echo_srv_device *esd,
			  struct lu_device_type *ldt, struct lustre_cfg *cfg)
{
	const char *dev = lustre_cfg_string(cfg, 0);
	struct obd_device *obd;
	char ns_name[48];
	int rc;

	ENTRY;

	obd = class_name2obd(dev);
	if (obd == NULL) {
		CERROR("Cannot find obd with name %s\n", dev);
		RETURN(-ENODEV);
	}

	spin_lock_init(&obd->u.echo.eo_lock);
	obd->u.echo.eo_lastino = ECHO_INIT_OID;

	esd->esd_dev.ld_ops = &echo_srv_lu_ops;
	esd->esd_dev.ld_obd = obd;
	/* set this lu_device to obd, because error handling need it */
	obd->obd_lu_dev = &esd->esd_dev;

	/* No connection accepted until configurations will finish */
	spin_lock(&obd->obd_dev_lock);
	obd->obd_no_conn = 1;
	spin_unlock(&obd->obd_dev_lock);

	/* non-replayable target */
	obd->obd_replayable = 0;

	snprintf(ns_name, sizeof(ns_name), "echotgt-%s", obd->obd_uuid.uuid);
	obd->obd_namespace = ldlm_namespace_new(obd, ns_name,
						LDLM_NAMESPACE_SERVER,
						LDLM_NAMESPACE_MODEST,
						LDLM_NS_TYPE_OST);
	if (obd->obd_namespace == NULL)
		RETURN(-ENOMEM);

	obd->obd_vars = lprocfs_echo_obd_vars;
	if (!lprocfs_obd_setup(obd, true) &&
            lprocfs_alloc_obd_stats(obd, LPROC_ECHO_LAST) == 0) {
                lprocfs_counter_init(obd->obd_stats, LPROC_ECHO_READ_BYTES,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "read_bytes", "bytes");
                lprocfs_counter_init(obd->obd_stats, LPROC_ECHO_WRITE_BYTES,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "write_bytes", "bytes");
        }

	ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
			   "echo_ldlm_cb_client", &obd->obd_ldlm_client);

	rc = tgt_init(env, &esd->esd_lut, obd, NULL, esd_common_slice,
		      OBD_FAIL_OST_ALL_REQUEST_NET,
		      OBD_FAIL_OST_ALL_REPLY_NET);
	if (rc)
		GOTO(err_out, rc);

	spin_lock(&obd->obd_dev_lock);
	obd->obd_no_conn = 0;
	spin_unlock(&obd->obd_dev_lock);

	RETURN(0);

err_out:
	ldlm_namespace_free(obd->obd_namespace, NULL, obd->obd_force);
	obd->obd_namespace = NULL;

	lprocfs_obd_cleanup(obd);
	lprocfs_free_obd_stats(obd);
	RETURN(rc);
}

/**
 * Stop the Echo Server device.
 *
 * This function stops the Echo Server device and all its subsystems.
 * This is the end of Echo Server lifecycle.
 *
 * \param[in] env	execution environment
 * \param[in] esd		ESD device
 */
static void echo_srv_fini(const struct lu_env *env,
			  struct echo_srv_device *esd)
{
	struct obd_device *obd = echo_srv_obd(esd);
	struct lu_device *d = &esd->esd_dev;
	int leaked;

	ENTRY;

	class_disconnect_exports(obd);
	if (obd->obd_namespace != NULL)
		ldlm_namespace_free_prior(obd->obd_namespace, NULL,
					  obd->obd_force);

	obd_exports_barrier(obd);
	obd_zombie_barrier();

	tgt_fini(env, &esd->esd_lut);

	if (obd->obd_namespace != NULL) {
		ldlm_namespace_free_post(obd->obd_namespace);
		obd->obd_namespace = NULL;
	}

	lprocfs_obd_cleanup(obd);
	lprocfs_free_obd_stats(obd);

	leaked = atomic_read(&obd->u.echo.eo_prep);
	if (leaked != 0)
		CERROR("%d prep/commitrw pages leaked\n", leaked);

	LASSERT(atomic_read(&d->ld_ref) == 0);
	EXIT;
}

/**
 * Implementation of lu_device_type_operations::ldto_device_fini.
 *
 * Finalize device. Dual to echo_srv_device_init(). It is called from
 * obd_precleanup() and stops the current device.
 *
 * \param[in] env	execution environment
 * \param[in] d		LU device of ESD
 *
 * \retval		NULL
 */
static struct lu_device *echo_srv_device_fini(const struct lu_env *env,
					      struct lu_device *d)
{
	ENTRY;
	echo_srv_fini(env, echo_srv_dev(d));
	RETURN(NULL);
}

/**
 * Implementation of lu_device_type_operations::ldto_device_free.
 *
 * Free Echo Server device. Dual to echo_srv_device_alloc().
 *
 * \param[in] env	execution environment
 * \param[in] d		LU device of ESD
 *
 * \retval		NULL
 */
static struct lu_device *echo_srv_device_free(const struct lu_env *env,
					      struct lu_device *d)
{
	struct echo_srv_device *esd = echo_srv_dev(d);

	lu_device_fini(&esd->esd_dev);
	OBD_FREE_PTR(esd);
	RETURN(NULL);
}

/**
 * Implementation of lu_device_type_operations::ldto_device_alloc.
 *
 * This function allocates the new Echo Server device. It is called from
 * obd_setup() if OBD device had lu_device_type defined.
 *
 * \param[in] env	execution environment
 * \param[in] t		lu_device_type of ESD device
 * \param[in] cfg	configuration log
 *
 * \retval		pointer to the lu_device of just allocated OFD
 * \retval		ERR_PTR of return value on error
 */
static struct lu_device *echo_srv_device_alloc(const struct lu_env *env,
					       struct lu_device_type *t,
					       struct lustre_cfg *cfg)
{
	struct echo_srv_device *esd;
	struct lu_device *l;
	int rc;

	OBD_ALLOC_PTR(esd);
	if (esd == NULL)
		return ERR_PTR(-ENOMEM);

	l = &esd->esd_dev;
	lu_device_init(l, t);
	rc = echo_srv_init0(env, esd, t, cfg);
	if (rc != 0) {
		echo_srv_device_free(env, l);
		l = ERR_PTR(rc);
	}

	return l;
}

static const struct lu_device_type_operations echo_srv_type_ops = {
	.ldto_device_alloc = echo_srv_device_alloc,
	.ldto_device_free = echo_srv_device_free,
	.ldto_device_fini = echo_srv_device_fini
};

struct lu_device_type echo_srv_type = {
	.ldt_tags = LU_DEVICE_DT,
	.ldt_name = LUSTRE_ECHO_NAME,
	.ldt_ops = &echo_srv_type_ops,
	.ldt_ctx_tags = LCT_DT_THREAD,
};

void echo_persistent_pages_fini(void)
{
	int i;

	for (i = 0; i < ECHO_PERSISTENT_PAGES; i++)
		if (echo_persistent_pages[i] != NULL) {
			__free_page(echo_persistent_pages[i]);
			echo_persistent_pages[i] = NULL;
		}
}

int echo_persistent_pages_init(void)
{
	struct page *pg;
	int          i;

	for (i = 0; i < ECHO_PERSISTENT_PAGES; i++) {
		gfp_t gfp_mask = (i < ECHO_PERSISTENT_PAGES/2) ?
			GFP_KERNEL : GFP_HIGHUSER;

		pg = alloc_page(gfp_mask);
		if (pg == NULL) {
			echo_persistent_pages_fini();
			return -ENOMEM;
		}

		memset(kmap(pg), 0, PAGE_SIZE);
		kunmap(pg);

		echo_persistent_pages[i] = pg;
	}

	return 0;
}
