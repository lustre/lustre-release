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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LMV

#include <linux/file.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/user_namespace.h>
#ifdef HAVE_UIDGID_HEADER
# include <linux/uidgid.h>
#endif
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/math64.h>
#include <linux/seq_file.h>
#include <linux/namei.h>

#include <obd_support.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <obd_class.h>
#include <lustre_lmv.h>
#include <lprocfs_status.h>
#include <cl_object.h>
#include <lustre_fid.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <lustre_kernelcomm.h>
#include "lmv_internal.h"

static int lmv_check_connect(struct obd_device *obd);

static void lmv_activate_target(struct lmv_obd *lmv,
                                struct lmv_tgt_desc *tgt,
                                int activate)
{
        if (tgt->ltd_active == activate)
                return;

        tgt->ltd_active = activate;
        lmv->desc.ld_active_tgt_count += (activate ? 1 : -1);

	tgt->ltd_exp->exp_obd->obd_inactive = !activate;
}

/**
 * Error codes:
 *
 *  -EINVAL  : UUID can't be found in the LMV's target list
 *  -ENOTCONN: The UUID is found, but the target connection is bad (!)
 *  -EBADF   : The UUID is found, but the OBD of the wrong type (!)
 */
static int lmv_set_mdc_active(struct lmv_obd *lmv,
			      const struct obd_uuid *uuid,
			      int activate)
{
	struct lmv_tgt_desc	*tgt = NULL;
	struct obd_device	*obd;
	__u32			 i;
	int			 rc = 0;
	ENTRY;

	CDEBUG(D_INFO, "Searching in lmv %p for uuid %s (activate=%d)\n",
			lmv, uuid->uuid, activate);

	spin_lock(&lmv->lmv_lock);
	for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
		tgt = lmv->tgts[i];
		if (tgt == NULL || tgt->ltd_exp == NULL)
			continue;

		CDEBUG(D_INFO, "Target idx %d is %s conn %#llx\n", i,
		       tgt->ltd_uuid.uuid, tgt->ltd_exp->exp_handle.h_cookie);

		if (obd_uuid_equals(uuid, &tgt->ltd_uuid))
			break;
	}

        if (i == lmv->desc.ld_tgt_count)
                GOTO(out_lmv_lock, rc = -EINVAL);

        obd = class_exp2obd(tgt->ltd_exp);
        if (obd == NULL)
                GOTO(out_lmv_lock, rc = -ENOTCONN);

        CDEBUG(D_INFO, "Found OBD %s=%s device %d (%p) type %s at LMV idx %d\n",
               obd->obd_name, obd->obd_uuid.uuid, obd->obd_minor, obd,
               obd->obd_type->typ_name, i);
        LASSERT(strcmp(obd->obd_type->typ_name, LUSTRE_MDC_NAME) == 0);

        if (tgt->ltd_active == activate) {
                CDEBUG(D_INFO, "OBD %p already %sactive!\n", obd,
                       activate ? "" : "in");
                GOTO(out_lmv_lock, rc);
        }

        CDEBUG(D_INFO, "Marking OBD %p %sactive\n", obd,
               activate ? "" : "in");
        lmv_activate_target(lmv, tgt, activate);
        EXIT;

 out_lmv_lock:
	spin_unlock(&lmv->lmv_lock);
	return rc;
}

struct obd_uuid *lmv_get_uuid(struct obd_export *exp)
{
	struct lmv_obd		*lmv = &exp->exp_obd->u.lmv;
	struct lmv_tgt_desc	*tgt = lmv->tgts[0];

	return (tgt == NULL) ? NULL : obd_get_uuid(tgt->ltd_exp);
}

static int lmv_notify(struct obd_device *obd, struct obd_device *watched,
		      enum obd_notify_event ev)
{
        struct obd_connect_data *conn_data;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct obd_uuid         *uuid;
        int                      rc = 0;
        ENTRY;

        if (strcmp(watched->obd_type->typ_name, LUSTRE_MDC_NAME)) {
                CERROR("unexpected notification of %s %s!\n",
                       watched->obd_type->typ_name,
                       watched->obd_name);
                RETURN(-EINVAL);
        }

        uuid = &watched->u.cli.cl_target_uuid;
        if (ev == OBD_NOTIFY_ACTIVE || ev == OBD_NOTIFY_INACTIVE) {
                /*
                 * Set MDC as active before notifying the observer, so the
                 * observer can use the MDC normally.
                 */
                rc = lmv_set_mdc_active(lmv, uuid,
                                        ev == OBD_NOTIFY_ACTIVE);
                if (rc) {
                        CERROR("%sactivation of %s failed: %d\n",
                               ev == OBD_NOTIFY_ACTIVE ? "" : "de",
                               uuid->uuid, rc);
                        RETURN(rc);
                }
	} else if (ev == OBD_NOTIFY_OCD) {
		conn_data = &watched->u.cli.cl_import->imp_connect_data;
		/*
		 * XXX: Make sure that ocd_connect_flags from all targets are
		 * the same. Otherwise one of MDTs runs wrong version or
		 * something like this.  --umka
		 */
		obd->obd_self_export->exp_connect_data = *conn_data;
	}

	/*
	 * Pass the notification up the chain.
	 */
	if (obd->obd_observer)
		rc = obd_notify(obd->obd_observer, watched, ev);

	RETURN(rc);
}

static int lmv_connect(const struct lu_env *env,
		       struct obd_export **pexp, struct obd_device *obd,
		       struct obd_uuid *cluuid, struct obd_connect_data *data,
		       void *localdata)
{
	struct lmv_obd *lmv = &obd->u.lmv;
	struct lustre_handle conn = { 0 };
	struct obd_export *exp;
	int rc;
	ENTRY;

	rc = class_connect(&conn, obd, cluuid);
	if (rc) {
		CERROR("class_connection() returned %d\n", rc);
		RETURN(rc);
	}

	exp = class_conn2export(&conn);

	lmv->connected = 0;
	lmv->conn_data = *data;

	lmv->lmv_tgts_kobj = kobject_create_and_add("target_obds",
						    &obd->obd_kset.kobj);
	if (!lmv->lmv_tgts_kobj) {
		CERROR("%s: cannot create /sys/fs/lustre/%s/%s/target_obds\n",
		       obd->obd_name, obd->obd_type->typ_name, obd->obd_name);
	}

	rc = lmv_check_connect(obd);
	if (rc != 0)
		GOTO(out_sysfs, rc);

	*pexp = exp;

	RETURN(rc);

out_sysfs:
	if (lmv->lmv_tgts_kobj)
		kobject_put(lmv->lmv_tgts_kobj);

	class_disconnect(exp);

	return rc;
}

static int lmv_init_ea_size(struct obd_export *exp, __u32 easize,
			    __u32 def_easize)
{
	struct obd_device	*obd = exp->exp_obd;
	struct lmv_obd		*lmv = &obd->u.lmv;
	__u32			 i;
	int			 rc = 0;
	int			 change = 0;
	ENTRY;

        if (lmv->max_easize < easize) {
                lmv->max_easize = easize;
                change = 1;
        }
        if (lmv->max_def_easize < def_easize) {
                lmv->max_def_easize = def_easize;
                change = 1;
        }

	if (change == 0)
		RETURN(0);

	if (lmv->connected == 0)
		RETURN(0);

	for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
		struct lmv_tgt_desc *tgt = lmv->tgts[i];

		if (tgt == NULL || tgt->ltd_exp == NULL) {
			CWARN("%s: NULL export for %d\n", obd->obd_name, i);
			continue;
		}
		if (!tgt->ltd_active)
			continue;

		rc = md_init_ea_size(tgt->ltd_exp, easize, def_easize);
		if (rc) {
			CERROR("%s: obd_init_ea_size() failed on MDT target %d:"
			       " rc = %d\n", obd->obd_name, i, rc);
			break;
		}
	}
	RETURN(rc);
}

#define MAX_STRING_SIZE 128

int lmv_connect_mdc(struct obd_device *obd, struct lmv_tgt_desc *tgt)
{
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct obd_device       *mdc_obd;
        struct obd_export       *mdc_exp;
        struct lu_fld_target     target;
        int                      rc;
        ENTRY;

        mdc_obd = class_find_client_obd(&tgt->ltd_uuid, LUSTRE_MDC_NAME,
                                        &obd->obd_uuid);
        if (!mdc_obd) {
                CERROR("target %s not attached\n", tgt->ltd_uuid.uuid);
                RETURN(-EINVAL);
        }

	CDEBUG(D_CONFIG, "connect to %s(%s) - %s, %s\n",
	       mdc_obd->obd_name, mdc_obd->obd_uuid.uuid,
	       tgt->ltd_uuid.uuid, obd->obd_uuid.uuid);

        if (!mdc_obd->obd_set_up) {
                CERROR("target %s is not set up\n", tgt->ltd_uuid.uuid);
                RETURN(-EINVAL);
        }

	rc = obd_connect(NULL, &mdc_exp, mdc_obd, &obd->obd_uuid,
			 &lmv->conn_data, NULL);
        if (rc) {
                CERROR("target %s connect error %d\n", tgt->ltd_uuid.uuid, rc);
                RETURN(rc);
        }

	/*
	 * Init fid sequence client for this mdc and add new fld target.
	 */
	rc = obd_fid_init(mdc_obd, mdc_exp, LUSTRE_SEQ_METADATA);
	if (rc)
		RETURN(rc);

        target.ft_srv = NULL;
        target.ft_exp = mdc_exp;
        target.ft_idx = tgt->ltd_idx;

        fld_client_add_target(&lmv->lmv_fld, &target);

        rc = obd_register_observer(mdc_obd, obd);
        if (rc) {
                obd_disconnect(mdc_exp);
                CERROR("target %s register_observer error %d\n",
                       tgt->ltd_uuid.uuid, rc);
                RETURN(rc);
        }

	if (obd->obd_observer) {
		/*
		 * Tell the observer about the new target.
		 */
		rc = obd_notify(obd->obd_observer, mdc_exp->exp_obd,
				OBD_NOTIFY_ACTIVE);
		if (rc) {
			obd_disconnect(mdc_exp);
			RETURN(rc);
		}
	}

	tgt->ltd_active = 1;
	tgt->ltd_exp = mdc_exp;
	lmv->desc.ld_active_tgt_count++;

	md_init_ea_size(tgt->ltd_exp, lmv->max_easize, lmv->max_def_easize);

	CDEBUG(D_CONFIG, "Connected to %s(%s) successfully (%d)\n",
		mdc_obd->obd_name, mdc_obd->obd_uuid.uuid,
		atomic_read(&obd->obd_refcount));

	if (lmv->lmv_tgts_kobj)
		/* Even if we failed to create the link, that's fine */
		rc = sysfs_create_link(lmv->lmv_tgts_kobj,
				       &mdc_obd->obd_kset.kobj,
				       mdc_obd->obd_name);
	RETURN(0);
}

static void lmv_del_target(struct lmv_obd *lmv, int index)
{
	if (lmv->tgts[index] == NULL)
		return;

	OBD_FREE_PTR(lmv->tgts[index]);
	lmv->tgts[index] = NULL;
	return;
}

static int lmv_add_target(struct obd_device *obd, struct obd_uuid *uuidp,
			   __u32 index, int gen)
{
	struct obd_device *mdc_obd;
        struct lmv_obd      *lmv = &obd->u.lmv;
        struct lmv_tgt_desc *tgt;
	int		     orig_tgt_count = 0;
        int                  rc = 0;
        ENTRY;

	CDEBUG(D_CONFIG, "Target uuid: %s. index %d\n", uuidp->uuid, index);
	mdc_obd = class_find_client_obd(uuidp, LUSTRE_MDC_NAME,
					&obd->obd_uuid);
	if (!mdc_obd) {
		CERROR("%s: Target %s not attached: rc = %d\n",
		       obd->obd_name, uuidp->uuid, -EINVAL);
		RETURN(-EINVAL);
	}

	mutex_lock(&lmv->lmv_init_mutex);
	if ((index < lmv->tgts_size) && (lmv->tgts[index] != NULL)) {
		tgt = lmv->tgts[index];
		CERROR("%s: UUID %s already assigned at LMV target index %d:"
		       " rc = %d\n", obd->obd_name,
		       obd_uuid2str(&tgt->ltd_uuid), index, -EEXIST);
		mutex_unlock(&lmv->lmv_init_mutex);
		RETURN(-EEXIST);
	}

	if (index >= lmv->tgts_size) {
		/* We need to reallocate the lmv target array. */
		struct lmv_tgt_desc **newtgts, **old = NULL;
		__u32 newsize = 1;
		__u32 oldsize = 0;

		while (newsize < index + 1)
			newsize = newsize << 1;
		OBD_ALLOC(newtgts, sizeof(*newtgts) * newsize);
		if (newtgts == NULL) {
			mutex_unlock(&lmv->lmv_init_mutex);
			RETURN(-ENOMEM);
		}

		if (lmv->tgts_size) {
			memcpy(newtgts, lmv->tgts,
			       sizeof(*newtgts) * lmv->tgts_size);
			old = lmv->tgts;
			oldsize = lmv->tgts_size;
		}

		lmv->tgts = newtgts;
		lmv->tgts_size = newsize;
		smp_rmb();
		if (old)
			OBD_FREE(old, sizeof(*old) * oldsize);

		CDEBUG(D_CONFIG, "tgts: %p size: %d\n", lmv->tgts,
		       lmv->tgts_size);
	}

	OBD_ALLOC_PTR(tgt);
	if (!tgt) {
		mutex_unlock(&lmv->lmv_init_mutex);
		RETURN(-ENOMEM);
	}

	mutex_init(&tgt->ltd_fid_mutex);
	tgt->ltd_idx = index;
	tgt->ltd_uuid = *uuidp;
	tgt->ltd_active = 0;
	lmv->tgts[index] = tgt;
	if (index >= lmv->desc.ld_tgt_count) {
		orig_tgt_count = lmv->desc.ld_tgt_count;
		lmv->desc.ld_tgt_count = index + 1;
	}

	if (lmv->connected == 0) {
		/* lmv_check_connect() will connect this target. */
		mutex_unlock(&lmv->lmv_init_mutex);
		RETURN(0);
	}

	/* Otherwise let's connect it ourselves */
	mutex_unlock(&lmv->lmv_init_mutex);
	rc = lmv_connect_mdc(obd, tgt);
	if (rc != 0) {
		spin_lock(&lmv->lmv_lock);
		if (lmv->desc.ld_tgt_count == index + 1)
			lmv->desc.ld_tgt_count = orig_tgt_count;
		memset(tgt, 0, sizeof(*tgt));
		spin_unlock(&lmv->lmv_lock);
	} else {
		int easize = sizeof(struct lmv_stripe_md) +
			lmv->desc.ld_tgt_count * sizeof(struct lu_fid);
		lmv_init_ea_size(obd->obd_self_export, easize, 0);
	}

	RETURN(rc);
}

static int lmv_check_connect(struct obd_device *obd)
{
	struct lmv_obd		*lmv = &obd->u.lmv;
	struct lmv_tgt_desc	*tgt;
	__u32			 i;
	int			 rc;
	int			 easize;
	ENTRY;

        if (lmv->connected)
                RETURN(0);

	mutex_lock(&lmv->lmv_init_mutex);
        if (lmv->connected) {
		mutex_unlock(&lmv->lmv_init_mutex);
                RETURN(0);
        }

        if (lmv->desc.ld_tgt_count == 0) {
		mutex_unlock(&lmv->lmv_init_mutex);
                CERROR("%s: no targets configured.\n", obd->obd_name);
                RETURN(-EINVAL);
        }

	LASSERT(lmv->tgts != NULL);

	if (lmv->tgts[0] == NULL) {
		mutex_unlock(&lmv->lmv_init_mutex);
		CERROR("%s: no target configured for index 0.\n",
		       obd->obd_name);
		RETURN(-EINVAL);
	}

	CDEBUG(D_CONFIG, "Time to connect %s to %s\n",
	       obd->obd_uuid.uuid, obd->obd_name);

	for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
		tgt = lmv->tgts[i];
		if (tgt == NULL)
			continue;
		rc = lmv_connect_mdc(obd, tgt);
		if (rc)
			GOTO(out_disc, rc);
	}

	lmv->connected = 1;
	easize = lmv_mds_md_size(lmv->desc.ld_tgt_count, LMV_MAGIC);
	lmv_init_ea_size(obd->obd_self_export, easize, 0);
	mutex_unlock(&lmv->lmv_init_mutex);
	RETURN(0);

 out_disc:
        while (i-- > 0) {
                int rc2;
		tgt = lmv->tgts[i];
		if (tgt == NULL)
			continue;
                tgt->ltd_active = 0;
                if (tgt->ltd_exp) {
                        --lmv->desc.ld_active_tgt_count;
                        rc2 = obd_disconnect(tgt->ltd_exp);
                        if (rc2) {
                                CERROR("LMV target %s disconnect on "
                                       "MDC idx %d: error %d\n",
                                       tgt->ltd_uuid.uuid, i, rc2);
                        }
                }
        }

	mutex_unlock(&lmv->lmv_init_mutex);

	RETURN(rc);
}

static int lmv_disconnect_mdc(struct obd_device *obd, struct lmv_tgt_desc *tgt)
{
        struct lmv_obd         *lmv = &obd->u.lmv;
        struct obd_device      *mdc_obd;
        int                     rc;
        ENTRY;

        LASSERT(tgt != NULL);
        LASSERT(obd != NULL);

        mdc_obd = class_exp2obd(tgt->ltd_exp);

        if (mdc_obd) {
                mdc_obd->obd_force = obd->obd_force;
                mdc_obd->obd_fail = obd->obd_fail;
                mdc_obd->obd_no_recov = obd->obd_no_recov;

		if (lmv->lmv_tgts_kobj)
			sysfs_remove_link(lmv->lmv_tgts_kobj,
					  mdc_obd->obd_name);
	}

	rc = obd_fid_fini(tgt->ltd_exp->exp_obd);
	if (rc)
		CERROR("Can't finanize fids factory\n");

        CDEBUG(D_INFO, "Disconnected from %s(%s) successfully\n",
               tgt->ltd_exp->exp_obd->obd_name,
               tgt->ltd_exp->exp_obd->obd_uuid.uuid);

        obd_register_observer(tgt->ltd_exp->exp_obd, NULL);
        rc = obd_disconnect(tgt->ltd_exp);
        if (rc) {
                if (tgt->ltd_active) {
                        CERROR("Target %s disconnect error %d\n",
                               tgt->ltd_uuid.uuid, rc);
                }
        }

        lmv_activate_target(lmv, tgt, 0);
        tgt->ltd_exp = NULL;
        RETURN(0);
}

static int lmv_disconnect(struct obd_export *exp)
{
	struct obd_device	*obd = class_exp2obd(exp);
	struct lmv_obd		*lmv = &obd->u.lmv;
	int			 rc;
	__u32			 i;
	ENTRY;

        if (!lmv->tgts)
                goto out_local;

        for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
		if (lmv->tgts[i] == NULL || lmv->tgts[i]->ltd_exp == NULL)
                        continue;

		lmv_disconnect_mdc(obd, lmv->tgts[i]);
        }

	if (lmv->lmv_tgts_kobj)
		kobject_put(lmv->lmv_tgts_kobj);

out_local:
        /*
         * This is the case when no real connection is established by
         * lmv_check_connect().
         */
        if (!lmv->connected)
                class_export_put(exp);
        rc = class_disconnect(exp);
	lmv->connected = 0;

	RETURN(rc);
}

static int lmv_fid2path(struct obd_export *exp, int len, void *karg,
			void __user *uarg)
{
	struct obd_device	*obddev = class_exp2obd(exp);
	struct lmv_obd		*lmv = &obddev->u.lmv;
	struct getinfo_fid2path *gf;
	struct lmv_tgt_desc     *tgt;
	struct getinfo_fid2path *remote_gf = NULL;
	struct lu_fid		root_fid;
	int			remote_gf_size = 0;
	int			rc;

	gf = karg;
	tgt = lmv_find_target(lmv, &gf->gf_fid);
	if (IS_ERR(tgt))
		RETURN(PTR_ERR(tgt));

	root_fid = *gf->gf_u.gf_root_fid;
	LASSERT(fid_is_sane(&root_fid));

repeat_fid2path:
	rc = obd_iocontrol(OBD_IOC_FID2PATH, tgt->ltd_exp, len, gf, uarg);
	if (rc != 0 && rc != -EREMOTE)
		GOTO(out_fid2path, rc);

	/* If remote_gf != NULL, it means just building the
	 * path on the remote MDT, copy this path segement to gf */
	if (remote_gf != NULL) {
		struct getinfo_fid2path *ori_gf;
		char *ptr;
		int len;

		ori_gf = (struct getinfo_fid2path *)karg;
		if (strlen(ori_gf->gf_u.gf_path) + 1 +
		    strlen(gf->gf_u.gf_path) + 1 > ori_gf->gf_pathlen)
			GOTO(out_fid2path, rc = -EOVERFLOW);

		ptr = ori_gf->gf_u.gf_path;

		len = strlen(gf->gf_u.gf_path);
		/* move the current path to the right to release space
		 * for closer-to-root part */
		memmove(ptr + len + 1, ptr, strlen(ori_gf->gf_u.gf_path));
		memcpy(ptr, gf->gf_u.gf_path, len);
		ptr[len] = '/';
	}

	CDEBUG(D_INFO, "%s: get path %s "DFID" rec: %llu ln: %u\n",
	       tgt->ltd_exp->exp_obd->obd_name,
	       gf->gf_u.gf_path, PFID(&gf->gf_fid), gf->gf_recno,
	       gf->gf_linkno);

	if (rc == 0)
		GOTO(out_fid2path, rc);

	/* sigh, has to go to another MDT to do path building further */
	if (remote_gf == NULL) {
		remote_gf_size = sizeof(*remote_gf) + PATH_MAX;
		OBD_ALLOC(remote_gf, remote_gf_size);
		if (remote_gf == NULL)
			GOTO(out_fid2path, rc = -ENOMEM);
		remote_gf->gf_pathlen = PATH_MAX;
	}

	if (!fid_is_sane(&gf->gf_fid)) {
		CERROR("%s: invalid FID "DFID": rc = %d\n",
		       tgt->ltd_exp->exp_obd->obd_name,
		       PFID(&gf->gf_fid), -EINVAL);
		GOTO(out_fid2path, rc = -EINVAL);
	}

	tgt = lmv_find_target(lmv, &gf->gf_fid);
	if (IS_ERR(tgt))
		GOTO(out_fid2path, rc = -EINVAL);

	remote_gf->gf_fid = gf->gf_fid;
	remote_gf->gf_recno = -1;
	remote_gf->gf_linkno = -1;
	memset(remote_gf->gf_u.gf_path, 0, remote_gf->gf_pathlen);
	*remote_gf->gf_u.gf_root_fid = root_fid;
	gf = remote_gf;
	goto repeat_fid2path;

out_fid2path:
	if (remote_gf != NULL)
		OBD_FREE(remote_gf, remote_gf_size);
	RETURN(rc);
}

static int lmv_hsm_req_count(struct lmv_obd *lmv,
			     const struct hsm_user_request *hur,
			     const struct lmv_tgt_desc *tgt_mds)
{
	__u32			 i;
	int			 nr = 0;
	struct lmv_tgt_desc	*curr_tgt;

	/* count how many requests must be sent to the given target */
	for (i = 0; i < hur->hur_request.hr_itemcount; i++) {
		curr_tgt = lmv_find_target(lmv, &hur->hur_user_item[i].hui_fid);
		if (IS_ERR(curr_tgt))
			RETURN(PTR_ERR(curr_tgt));
		if (obd_uuid_equals(&curr_tgt->ltd_uuid, &tgt_mds->ltd_uuid))
			nr++;
	}
	return nr;
}

static int lmv_hsm_req_build(struct lmv_obd *lmv,
			      struct hsm_user_request *hur_in,
			      const struct lmv_tgt_desc *tgt_mds,
			      struct hsm_user_request *hur_out)
{
	__u32			 i, nr_out;
	struct lmv_tgt_desc	*curr_tgt;

	/* build the hsm_user_request for the given target */
	hur_out->hur_request = hur_in->hur_request;
	nr_out = 0;
	for (i = 0; i < hur_in->hur_request.hr_itemcount; i++) {
		curr_tgt = lmv_find_target(lmv,
					   &hur_in->hur_user_item[i].hui_fid);
		if (IS_ERR(curr_tgt))
			RETURN(PTR_ERR(curr_tgt));
		if (obd_uuid_equals(&curr_tgt->ltd_uuid, &tgt_mds->ltd_uuid)) {
			hur_out->hur_user_item[nr_out] =
						hur_in->hur_user_item[i];
			nr_out++;
		}
	}
	hur_out->hur_request.hr_itemcount = nr_out;
	memcpy(hur_data(hur_out), hur_data(hur_in),
	       hur_in->hur_request.hr_data_len);

	RETURN(0);
}

static int lmv_hsm_ct_unregister(struct obd_device *obd, unsigned int cmd,
				 int len, struct lustre_kernelcomm *lk,
				 void __user *uarg)
{
	struct lmv_obd *lmv = &obd->u.lmv;
	__u32	i;
	int	rc;
	ENTRY;

	/* unregister request (call from llapi_hsm_copytool_fini) */
	for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
		struct lmv_tgt_desc *tgt = lmv->tgts[i];

		if (tgt == NULL || tgt->ltd_exp == NULL)
			continue;
		/* best effort: try to clean as much as possible
		 * (continue on error) */
		obd_iocontrol(cmd, tgt->ltd_exp, len, lk, uarg);
	}

	/* Whatever the result, remove copytool from kuc groups.
	 * Unreached coordinators will get EPIPE on next requests
	 * and will unregister automatically.
	 */
	rc = libcfs_kkuc_group_rem(&obd->obd_uuid, lk->lk_uid, lk->lk_group);

	RETURN(rc);
}

static int lmv_hsm_ct_register(struct obd_device *obd, unsigned int cmd,
			       int len, struct lustre_kernelcomm *lk,
			       void __user *uarg)
{
	struct lmv_obd *lmv = &obd->u.lmv;
	struct file *filp;
	__u32 i, j;
	int err;
	bool any_set = false;
	struct kkuc_ct_data *kcd;
	size_t kcd_size;
	int rc = 0;
	ENTRY;

	filp = fget(lk->lk_wfd);
	if (!filp)
		RETURN(-EBADF);

	if (lk->lk_flags & LK_FLG_DATANR)
		kcd_size = offsetof(struct kkuc_ct_data,
				    kcd_archives[lk->lk_data_count]);
	else
		kcd_size = sizeof(*kcd);

	OBD_ALLOC(kcd, kcd_size);
	if (kcd == NULL)
		GOTO(err_fput, rc = -ENOMEM);

	kcd->kcd_nr_archives = lk->lk_data_count;
	if (lk->lk_flags & LK_FLG_DATANR) {
		kcd->kcd_magic = KKUC_CT_DATA_ARRAY_MAGIC;
		if (lk->lk_data_count > 0)
			memcpy(kcd->kcd_archives, lk->lk_data,
			       sizeof(*kcd->kcd_archives) * lk->lk_data_count);
	} else {
		kcd->kcd_magic = KKUC_CT_DATA_BITMAP_MAGIC;
	}

	rc = libcfs_kkuc_group_add(filp, &obd->obd_uuid, lk->lk_uid,
				   lk->lk_group, kcd, kcd_size);
	OBD_FREE(kcd, kcd_size);
	if (rc)
		GOTO(err_fput, rc);

	/* All or nothing: try to register to all MDS.
	 * In case of failure, unregister from previous MDS,
	 * except if it because of inactive target. */
	for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
		struct lmv_tgt_desc *tgt = lmv->tgts[i];

		if (tgt == NULL || tgt->ltd_exp == NULL)
			continue;

		err = obd_iocontrol(cmd, tgt->ltd_exp, len, lk, uarg);
		if (err) {
			if (tgt->ltd_active) {
				/* permanent error */
				CERROR("%s: iocontrol MDC %s on MDT"
				       " idx %d cmd %x: err = %d\n",
				       lmv2obd_dev(lmv)->obd_name,
				       tgt->ltd_uuid.uuid, i, cmd, err);
				rc = err;
				lk->lk_flags |= LK_FLG_STOP;
				/* unregister from previous MDS */
				for (j = 0; j < i; j++) {
					tgt = lmv->tgts[j];
					if (tgt == NULL || tgt->ltd_exp == NULL)
						continue;
					obd_iocontrol(cmd, tgt->ltd_exp, len,
						      lk, uarg);
				}
				GOTO(err_kkuc_rem, rc);
			}
			/* else: transient error.
			 * kuc will register to the missing MDT
			 * when it is back */
		} else {
			any_set = true;
		}
	}

	if (!any_set)
		/* no registration done: return error */
		GOTO(err_kkuc_rem, rc = -ENOTCONN);

	RETURN(0);

err_kkuc_rem:
	libcfs_kkuc_group_rem(&obd->obd_uuid, lk->lk_uid, lk->lk_group);

err_fput:
	fput(filp);
	return rc;
}




static int lmv_iocontrol(unsigned int cmd, struct obd_export *exp,
			 int len, void *karg, void __user *uarg)
{
	struct obd_device	*obddev = class_exp2obd(exp);
	struct lmv_obd		*lmv = &obddev->u.lmv;
	struct lmv_tgt_desc	*tgt = NULL;
	__u32			 i = 0;
	int			 rc = 0;
	int			 set = 0;
	__u32			 count = lmv->desc.ld_tgt_count;
	ENTRY;

        if (count == 0)
                RETURN(-ENOTTY);

        switch (cmd) {
        case IOC_OBD_STATFS: {
                struct obd_ioctl_data *data = karg;
                struct obd_device *mdc_obd;
                struct obd_statfs stat_buf = {0};
                __u32 index;

                memcpy(&index, data->ioc_inlbuf2, sizeof(__u32));
                if ((index >= count))
                        RETURN(-ENODEV);

		tgt = lmv->tgts[index];
		if (tgt == NULL || !tgt->ltd_active)
			RETURN(-ENODATA);

		mdc_obd = class_exp2obd(tgt->ltd_exp);
		if (!mdc_obd)
			RETURN(-EINVAL);

		/* copy UUID */
		if (copy_to_user(data->ioc_pbuf2, obd2cli_tgt(mdc_obd),
				 min((int) data->ioc_plen2,
				     (int) sizeof(struct obd_uuid))))
			RETURN(-EFAULT);

		rc = obd_statfs(NULL, tgt->ltd_exp, &stat_buf,
				ktime_get_seconds() - OBD_STATFS_CACHE_SECONDS,
				0);
		if (rc)
			RETURN(rc);
		if (copy_to_user(data->ioc_pbuf1, &stat_buf,
				 min((int) data->ioc_plen1,
				     (int) sizeof(stat_buf))))
			RETURN(-EFAULT);
		break;
        }
        case OBD_IOC_QUOTACTL: {
                struct if_quotactl *qctl = karg;
                struct obd_quotactl *oqctl;

		if (qctl->qc_valid == QC_MDTIDX) {
			if (count <= qctl->qc_idx)
				RETURN(-EINVAL);

			tgt = lmv->tgts[qctl->qc_idx];
			if (tgt == NULL || tgt->ltd_exp == NULL)
				RETURN(-EINVAL);
		} else if (qctl->qc_valid == QC_UUID) {
			for (i = 0; i < count; i++) {
				tgt = lmv->tgts[i];
				if (tgt == NULL)
					continue;
				if (!obd_uuid_equals(&tgt->ltd_uuid,
						     &qctl->obd_uuid))
					continue;

                                if (tgt->ltd_exp == NULL)
                                        RETURN(-EINVAL);

                                break;
                        }
                } else {
                        RETURN(-EINVAL);
                }

                if (i >= count)
                        RETURN(-EAGAIN);

                LASSERT(tgt != NULL && tgt->ltd_exp != NULL);
                OBD_ALLOC_PTR(oqctl);
                if (!oqctl)
                        RETURN(-ENOMEM);

                QCTL_COPY(oqctl, qctl);
                rc = obd_quotactl(tgt->ltd_exp, oqctl);
                if (rc == 0) {
                        QCTL_COPY(qctl, oqctl);
                        qctl->qc_valid = QC_MDTIDX;
                        qctl->obd_uuid = tgt->ltd_uuid;
                }
                OBD_FREE_PTR(oqctl);
                break;
        }
	case LL_IOC_GET_CONNECT_FLAGS: {
		tgt = lmv->tgts[0];
		if (tgt == NULL || tgt->ltd_exp == NULL)
			RETURN(-ENODATA);
		rc = obd_iocontrol(cmd, tgt->ltd_exp, len, karg, uarg);
		break;
	}
	case LL_IOC_FID2MDTIDX: {
		struct lu_fid *fid = karg;
		int		mdt_index;

		rc = lmv_fld_lookup(lmv, fid, &mdt_index);
		if (rc != 0)
			RETURN(rc);

		/* Note: this is from llite(see ll_dir_ioctl()), @uarg does not
		 * point to user space memory for FID2MDTIDX. */
		*(__u32 *)uarg = mdt_index;
		break;
	}
	case OBD_IOC_FID2PATH: {
		rc = lmv_fid2path(exp, len, karg, uarg);
		break;
	}
	case LL_IOC_HSM_STATE_GET:
	case LL_IOC_HSM_STATE_SET:
	case LL_IOC_HSM_ACTION: {
		struct md_op_data	*op_data = karg;

		tgt = lmv_find_target(lmv, &op_data->op_fid1);
		if (IS_ERR(tgt))
			RETURN(PTR_ERR(tgt));

		if (tgt->ltd_exp == NULL)
			RETURN(-EINVAL);

		rc = obd_iocontrol(cmd, tgt->ltd_exp, len, karg, uarg);
		break;
	}
	case LL_IOC_HSM_PROGRESS: {
		const struct hsm_progress_kernel *hpk = karg;

		tgt = lmv_find_target(lmv, &hpk->hpk_fid);
		if (IS_ERR(tgt))
			RETURN(PTR_ERR(tgt));
		rc = obd_iocontrol(cmd, tgt->ltd_exp, len, karg, uarg);
		break;
	}
	case LL_IOC_HSM_REQUEST: {
		struct hsm_user_request *hur = karg;
		unsigned int reqcount = hur->hur_request.hr_itemcount;

		if (reqcount == 0)
			RETURN(0);

		/* if the request is about a single fid
		 * or if there is a single MDS, no need to split
		 * the request. */
		if (reqcount == 1 || count == 1) {
			tgt = lmv_find_target(lmv,
					      &hur->hur_user_item[0].hui_fid);
			if (IS_ERR(tgt))
				RETURN(PTR_ERR(tgt));
			rc = obd_iocontrol(cmd, tgt->ltd_exp, len, karg, uarg);
		} else {
			/* split fid list to their respective MDS */
			for (i = 0; i < count; i++) {
				int nr, rc1;
				size_t reqlen;
				struct hsm_user_request *req;

				tgt = lmv->tgts[i];
				if (tgt == NULL || tgt->ltd_exp == NULL)
					continue;

				nr = lmv_hsm_req_count(lmv, hur, tgt);
				if (nr < 0)
					RETURN(nr);
				if (nr == 0) /* nothing for this MDS */
					continue;

				/* build a request with fids for this MDS */
				reqlen = offsetof(typeof(*hur),
						  hur_user_item[nr])
						+ hur->hur_request.hr_data_len;
				OBD_ALLOC_LARGE(req, reqlen);
				if (req == NULL)
					RETURN(-ENOMEM);
				rc1 = lmv_hsm_req_build(lmv, hur, tgt, req);
				if (rc1 < 0)
					GOTO(hsm_req_err, rc1);
				rc1 = obd_iocontrol(cmd, tgt->ltd_exp, reqlen,
						    req, uarg);
hsm_req_err:
				if (rc1 != 0 && rc == 0)
					rc = rc1;
				OBD_FREE_LARGE(req, reqlen);
			}
		}
		break;
	}
	case LL_IOC_LOV_SWAP_LAYOUTS: {
		struct md_op_data	*op_data = karg;
		struct lmv_tgt_desc	*tgt1, *tgt2;

		tgt1 = lmv_find_target(lmv, &op_data->op_fid1);
		if (IS_ERR(tgt1))
			RETURN(PTR_ERR(tgt1));

		tgt2 = lmv_find_target(lmv, &op_data->op_fid2);
		if (IS_ERR(tgt2))
			RETURN(PTR_ERR(tgt2));

		if ((tgt1->ltd_exp == NULL) || (tgt2->ltd_exp == NULL))
			RETURN(-EINVAL);

		/* only files on same MDT can have their layouts swapped */
		if (tgt1->ltd_idx != tgt2->ltd_idx)
			RETURN(-EPERM);

		rc = obd_iocontrol(cmd, tgt1->ltd_exp, len, karg, uarg);
		break;
	}
	case LL_IOC_HSM_CT_START: {
		struct lustre_kernelcomm *lk = karg;
		if (lk->lk_flags & LK_FLG_STOP)
			rc = lmv_hsm_ct_unregister(obddev, cmd, len, lk, uarg);
		else
			rc = lmv_hsm_ct_register(obddev, cmd, len, lk, uarg);
		break;
	}
	default:
		for (i = 0; i < count; i++) {
			struct obd_device *mdc_obd;
			int err;

			tgt = lmv->tgts[i];
			if (tgt == NULL || tgt->ltd_exp == NULL)
				continue;
			/* ll_umount_begin() sets force flag but for lmv, not
			 * mdc. Let's pass it through */
			mdc_obd = class_exp2obd(tgt->ltd_exp);
			mdc_obd->obd_force = obddev->obd_force;
			err = obd_iocontrol(cmd, tgt->ltd_exp, len, karg, uarg);
			if (err) {
				if (tgt->ltd_active) {
					CERROR("error: iocontrol MDC %s on MDT"
					       " idx %d cmd %x: err = %d\n",
					       tgt->ltd_uuid.uuid, i, cmd, err);
					if (!rc)
						rc = err;
				}
			} else
				set = 1;
                }
                if (!set && !rc)
                        rc = -EIO;
        }
        RETURN(rc);
}

/**
 * This is _inode_ placement policy function (not name).
 */
static int lmv_placement_policy(struct obd_device *obd,
				struct md_op_data *op_data, u32 *mds)
{
	struct lmv_obd	   *lmv = &obd->u.lmv;
	struct lmv_user_md *lum;

	ENTRY;

	LASSERT(mds != NULL);

	if (lmv->desc.ld_tgt_count == 1) {
		*mds = 0;
		RETURN(0);
	}

	lum = op_data->op_data;
	/* Choose MDS by
	 * 1. See if the stripe offset is specified by lum.
	 * 2. Then check if there is default stripe offset.
	 * 3. Finally choose MDS by name hash if the parent
	 *    is striped directory. (see lmv_locate_tgt()). */
	if (op_data->op_cli_flags & CLI_SET_MEA && lum != NULL &&
	    le32_to_cpu(lum->lum_stripe_offset) != (__u32)-1) {
		*mds = le32_to_cpu(lum->lum_stripe_offset);
	} else if (op_data->op_default_stripe_offset != (__u32)-1) {
		*mds = op_data->op_default_stripe_offset;
		op_data->op_mds = *mds;
		/* Correct the stripe offset in lum */
		if (lum != NULL)
			lum->lum_stripe_offset = cpu_to_le32(*mds);
	} else {
		*mds = op_data->op_mds;
	}

	RETURN(0);
}

int __lmv_fid_alloc(struct lmv_obd *lmv, struct lu_fid *fid, u32 mds)
{
	struct lmv_tgt_desc	*tgt;
	int			 rc;
	ENTRY;

	tgt = lmv_get_target(lmv, mds, NULL);
	if (IS_ERR(tgt))
		RETURN(PTR_ERR(tgt));

	/*
	 * New seq alloc and FLD setup should be atomic. Otherwise we may find
	 * on server that seq in new allocated fid is not yet known.
	 */
	mutex_lock(&tgt->ltd_fid_mutex);

	if (tgt->ltd_active == 0 || tgt->ltd_exp == NULL)
		GOTO(out, rc = -ENODEV);

	/*
	 * Asking underlying tgt layer to allocate new fid.
	 */
	rc = obd_fid_alloc(NULL, tgt->ltd_exp, fid, NULL);
	if (rc > 0) {
		LASSERT(fid_is_sane(fid));
		rc = 0;
	}

        EXIT;
out:
	mutex_unlock(&tgt->ltd_fid_mutex);
        return rc;
}

int lmv_fid_alloc(const struct lu_env *env, struct obd_export *exp,
		  struct lu_fid *fid, struct md_op_data *op_data)
{
        struct obd_device     *obd = class_exp2obd(exp);
        struct lmv_obd        *lmv = &obd->u.lmv;
	u32		       mds = 0;
        int                    rc;
        ENTRY;

        LASSERT(op_data != NULL);
        LASSERT(fid != NULL);

        rc = lmv_placement_policy(obd, op_data, &mds);
        if (rc) {
                CERROR("Can't get target for allocating fid, "
                       "rc %d\n", rc);
                RETURN(rc);
        }

        rc = __lmv_fid_alloc(lmv, fid, mds);
        if (rc) {
                CERROR("Can't alloc new fid, rc %d\n", rc);
                RETURN(rc);
        }

        RETURN(rc);
}

static int lmv_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	struct lmv_obd	*lmv = &obd->u.lmv;
	struct lmv_desc	*desc;
	int		rc;
	ENTRY;

        if (LUSTRE_CFG_BUFLEN(lcfg, 1) < 1) {
                CERROR("LMV setup requires a descriptor\n");
                RETURN(-EINVAL);
        }

        desc = (struct lmv_desc *)lustre_cfg_buf(lcfg, 1);
        if (sizeof(*desc) > LUSTRE_CFG_BUFLEN(lcfg, 1)) {
                CERROR("Lmv descriptor size wrong: %d > %d\n",
                       (int)sizeof(*desc), LUSTRE_CFG_BUFLEN(lcfg, 1));
                RETURN(-EINVAL);
        }

	lmv->tgts_size = 32U;
	OBD_ALLOC(lmv->tgts, sizeof(*lmv->tgts) * lmv->tgts_size);
	if (lmv->tgts == NULL)
		RETURN(-ENOMEM);

	obd_str2uuid(&lmv->desc.ld_uuid, desc->ld_uuid.uuid);
	lmv->desc.ld_tgt_count = 0;
	lmv->desc.ld_active_tgt_count = 0;
	lmv->max_def_easize = 0;
	lmv->max_easize = 0;

	spin_lock_init(&lmv->lmv_lock);
	mutex_init(&lmv->lmv_init_mutex);

	rc = lmv_tunables_init(obd);
	if (rc)
		CWARN("%s: error adding LMV sysfs/debugfs files: rc = %d\n",
		      obd->obd_name, rc);

	rc = fld_client_init(&lmv->lmv_fld, obd->obd_name,
			     LUSTRE_CLI_FLD_HASH_DHT);
	if (rc) {
		CERROR("Can't init FLD, err %d\n", rc);
		GOTO(out, rc);
	}

        RETURN(0);

out:
        return rc;
}

static int lmv_cleanup(struct obd_device *obd)
{
	struct lmv_obd   *lmv = &obd->u.lmv;
	ENTRY;

	fld_client_fini(&lmv->lmv_fld);
	if (lmv->tgts != NULL) {
		int i;
		for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
			if (lmv->tgts[i] == NULL)
				continue;
			lmv_del_target(lmv, i);
		}
		OBD_FREE(lmv->tgts, sizeof(*lmv->tgts) * lmv->tgts_size);
		lmv->tgts_size = 0;
	}
	RETURN(0);
}

static int lmv_process_config(struct obd_device *obd, size_t len, void *buf)
{
	struct lustre_cfg	*lcfg = buf;
	struct obd_uuid		obd_uuid;
	int			gen;
	__u32			index;
	int			rc;
	ENTRY;

	switch (lcfg->lcfg_command) {
	case LCFG_ADD_MDC:
		/* modify_mdc_tgts add 0:lustre-clilmv  1:lustre-MDT0000_UUID
		 * 2:0  3:1  4:lustre-MDT0000-mdc_UUID */
		if (LUSTRE_CFG_BUFLEN(lcfg, 1) > sizeof(obd_uuid.uuid))
			GOTO(out, rc = -EINVAL);

		obd_str2uuid(&obd_uuid,  lustre_cfg_buf(lcfg, 1));

		if (sscanf(lustre_cfg_buf(lcfg, 2), "%u", &index) != 1)
			GOTO(out, rc = -EINVAL);
		if (sscanf(lustre_cfg_buf(lcfg, 3), "%d", &gen) != 1)
			GOTO(out, rc = -EINVAL);
		rc = lmv_add_target(obd, &obd_uuid, index, gen);
		GOTO(out, rc);
	default:
		CERROR("Unknown command: %d\n", lcfg->lcfg_command);
		GOTO(out, rc = -EINVAL);
	}
out:
	RETURN(rc);
}

static int lmv_select_statfs_mdt(struct lmv_obd *lmv, __u32 flags)
{
	int i;

	if (flags & OBD_STATFS_FOR_MDT0)
		return 0;

	if (lmv->lmv_statfs_start || lmv->desc.ld_tgt_count == 1)
		return lmv->lmv_statfs_start;

	/* choose initial MDT for this client */
	for (i = 0;; i++) {
		struct lnet_process_id lnet_id;
		if (LNetGetId(i, &lnet_id) == -ENOENT)
			break;

		if (lnet_id.nid != LNET_NID_LO_0) {
			/* We dont need a full 64-bit modulus, just enough
			 * to distribute the requests across MDTs evenly.
			 */
			lmv->lmv_statfs_start =
				(u32)lnet_id.nid % lmv->desc.ld_tgt_count;
			break;
		}
	}

	return lmv->lmv_statfs_start;
}

static int lmv_statfs(const struct lu_env *env, struct obd_export *exp,
		      struct obd_statfs *osfs, time64_t max_age, __u32 flags)
{
	struct obd_device	*obd = class_exp2obd(exp);
	struct lmv_obd		*lmv = &obd->u.lmv;
	struct obd_statfs	*temp;
	int			 rc = 0;
	__u32			 i, idx;
	ENTRY;

        OBD_ALLOC(temp, sizeof(*temp));
        if (temp == NULL)
                RETURN(-ENOMEM);

	/* distribute statfs among MDTs */
	idx = lmv_select_statfs_mdt(lmv, flags);

	for (i = 0; i < lmv->desc.ld_tgt_count; i++, idx++) {
		idx = idx % lmv->desc.ld_tgt_count;
		if (lmv->tgts[idx] == NULL || lmv->tgts[idx]->ltd_exp == NULL)
			continue;

		rc = obd_statfs(env, lmv->tgts[idx]->ltd_exp, temp,
				max_age, flags);
		if (rc) {
			CERROR("%s: can't stat MDS #%d: rc = %d\n",
			       lmv->tgts[idx]->ltd_exp->exp_obd->obd_name, i,
			       rc);
			GOTO(out_free_temp, rc);
		}

		if (temp->os_state & OS_STATE_SUM ||
		    flags == OBD_STATFS_FOR_MDT0) {
			/* reset to the last aggregated values
			 * and don't sum with non-aggrated data */
			/* If the statfs is from mount, it needs to retrieve
			 * necessary information from MDT0. i.e. mount does
			 * not need the merged osfs from all of MDT. Also
			 * clients can be mounted as long as MDT0 is in
			 * service */
			*osfs = *temp;
			break;
		}

		if (i == 0) {
			*osfs = *temp;
		} else {
			osfs->os_bavail += temp->os_bavail;
			osfs->os_blocks += temp->os_blocks;
			osfs->os_ffree += temp->os_ffree;
			osfs->os_files += temp->os_files;
			osfs->os_granted += temp->os_granted;
		}
        }

        EXIT;
out_free_temp:
        OBD_FREE(temp, sizeof(*temp));
        return rc;
}

static int lmv_get_root(struct obd_export *exp, const char *fileset,
			struct lu_fid *fid)
{
        struct obd_device    *obd = exp->exp_obd;
        struct lmv_obd       *lmv = &obd->u.lmv;
        int                   rc;
        ENTRY;

	rc = md_get_root(lmv->tgts[0]->ltd_exp, fileset, fid);
	RETURN(rc);
}

static int lmv_getxattr(struct obd_export *exp, const struct lu_fid *fid,
			u64 obd_md_valid, const char *name, size_t buf_size,
			struct ptlrpc_request **req)
{
        struct obd_device      *obd = exp->exp_obd;
        struct lmv_obd         *lmv = &obd->u.lmv;
        struct lmv_tgt_desc    *tgt;
        int                     rc;
        ENTRY;

        tgt = lmv_find_target(lmv, fid);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

	rc = md_getxattr(tgt->ltd_exp, fid, obd_md_valid, name, buf_size, req);

	RETURN(rc);
}

static int lmv_setxattr(struct obd_export *exp, const struct lu_fid *fid,
			u64 obd_md_valid, const char *name,
			const void *value, size_t value_size,
			unsigned int xattr_flags, u32 suppgid,
			struct ptlrpc_request **req)
{
        struct obd_device      *obd = exp->exp_obd;
        struct lmv_obd         *lmv = &obd->u.lmv;
        struct lmv_tgt_desc    *tgt;
        int                     rc;
        ENTRY;

        tgt = lmv_find_target(lmv, fid);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

	rc = md_setxattr(tgt->ltd_exp, fid, obd_md_valid, name,
			 value, value_size, xattr_flags, suppgid, req);

	RETURN(rc);
}

static int lmv_getattr(struct obd_export *exp, struct md_op_data *op_data,
                       struct ptlrpc_request **request)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_tgt_desc     *tgt;
        int                      rc;
        ENTRY;

        tgt = lmv_find_target(lmv, &op_data->op_fid1);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

	if (op_data->op_flags & MF_GET_MDT_IDX) {
		op_data->op_mds = tgt->ltd_idx;
		RETURN(0);
	}

        rc = md_getattr(tgt->ltd_exp, op_data, request);

        RETURN(rc);
}

static int lmv_null_inode(struct obd_export *exp, const struct lu_fid *fid)
{
        struct obd_device   *obd = exp->exp_obd;
        struct lmv_obd      *lmv = &obd->u.lmv;
	__u32                i;
        ENTRY;

        CDEBUG(D_INODE, "CBDATA for "DFID"\n", PFID(fid));

	/*
	 * With DNE every object can have two locks in different namespaces:
	 * lookup lock in space of MDT storing direntry and update/open lock in
	 * space of MDT storing inode.
	 */
	for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
		if (lmv->tgts[i] == NULL || lmv->tgts[i]->ltd_exp == NULL)
			continue;
		md_null_inode(lmv->tgts[i]->ltd_exp, fid);
	}

	RETURN(0);
}

static int lmv_close(struct obd_export *exp, struct md_op_data *op_data,
                     struct md_open_data *mod, struct ptlrpc_request **request)
{
        struct obd_device     *obd = exp->exp_obd;
        struct lmv_obd        *lmv = &obd->u.lmv;
        struct lmv_tgt_desc   *tgt;
        int                    rc;
        ENTRY;

        tgt = lmv_find_target(lmv, &op_data->op_fid1);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        CDEBUG(D_INODE, "CLOSE "DFID"\n", PFID(&op_data->op_fid1));
        rc = md_close(tgt->ltd_exp, op_data, mod, request);
        RETURN(rc);
}

struct lmv_tgt_desc*
__lmv_locate_tgt(struct lmv_obd *lmv, struct lmv_stripe_md *lsm,
		 const char *name, int namelen, struct lu_fid *fid, u32 *mds,
		 bool post_migrate)
{
	struct lmv_tgt_desc *tgt;
	const struct lmv_oinfo *oinfo;

	if (lsm == NULL || namelen == 0) {
		tgt = lmv_find_target(lmv, fid);
		if (IS_ERR(tgt))
			return tgt;

		LASSERT(mds);
		*mds = tgt->ltd_idx;
		return tgt;
	}

	if (OBD_FAIL_CHECK(OBD_FAIL_LFSCK_BAD_NAME_HASH)) {
		if (cfs_fail_val >= lsm->lsm_md_stripe_count)
			return ERR_PTR(-EBADF);
		oinfo = &lsm->lsm_md_oinfo[cfs_fail_val];
	} else {
		oinfo = lsm_name_to_stripe_info(lsm, name, namelen,
						post_migrate);
		if (IS_ERR(oinfo))
			return ERR_CAST(oinfo);
	}

	if (fid != NULL)
		*fid = oinfo->lmo_fid;
	if (mds != NULL)
		*mds = oinfo->lmo_mds;
	/* check stripe FID is sane */
	if (!fid_is_sane(&oinfo->lmo_fid))
		return ERR_PTR(-ENODEV);

	tgt = lmv_get_target(lmv, oinfo->lmo_mds, NULL);

	CDEBUG(D_INFO, "locate on mds %u "DFID"\n", oinfo->lmo_mds,
	       PFID(&oinfo->lmo_fid));

	return tgt;
}


/**
 * Locate mdt by fid or name
 *
 * For striped directory, it will locate the stripe by name hash, if hash_type
 * is unknown, it will return the stripe specified by 'op_data->op_stripe_index'
 * which is set outside, and if dir is migrating, 'op_data->op_post_migrate'
 * indicates whether old or new layout is used to locate.
 *
 * For normal direcotry, it will locate MDS by FID directly.
 *
 * \param[in] lmv		LMV device
 * \param[in/out] op_data	client MD stack parameters, name, namelen etc,
 *                      	op_mds and op_fid1 will be updated if op_mea1
 *                      	indicates fid1 represents a striped directory.
 * \param[out] fid		object FID used to locate MDS.
 *
 * retval		pointer to the lmv_tgt_desc if succeed.
 *                      ERR_PTR(errno) if failed.
 */
struct lmv_tgt_desc*
lmv_locate_tgt(struct lmv_obd *lmv, struct md_op_data *op_data,
	       struct lu_fid *fid)
{
	struct lmv_stripe_md *lsm = op_data->op_mea1;
	struct lmv_oinfo *oinfo;
	struct lmv_tgt_desc *tgt;

	/* During creating VOLATILE file, it should honor the mdt
	 * index if the file under striped dir is being restored, see
	 * ct_restore(). */
	if (op_data->op_bias & MDS_CREATE_VOLATILE &&
	    (int)op_data->op_mds != -1) {
		tgt = lmv_get_target(lmv, op_data->op_mds, NULL);
		if (IS_ERR(tgt))
			return tgt;

		if (lsm) {
			int i;

			/* refill the right parent fid */
			for (i = 0; i < lsm->lsm_md_stripe_count; i++) {
				oinfo = &lsm->lsm_md_oinfo[i];
				if (oinfo->lmo_mds == op_data->op_mds) {
					*fid = oinfo->lmo_fid;
					break;
				}
			}

			if (i == lsm->lsm_md_stripe_count)
				*fid = lsm->lsm_md_oinfo[0].lmo_fid;
		}
	} else if (lmv_is_dir_bad_hash(lsm)) {
		LASSERT(op_data->op_stripe_index < lsm->lsm_md_stripe_count);
		oinfo = &lsm->lsm_md_oinfo[op_data->op_stripe_index];

		*fid = oinfo->lmo_fid;
		op_data->op_mds = oinfo->lmo_mds;
		tgt = lmv_get_target(lmv, oinfo->lmo_mds, NULL);
	} else {
		tgt = __lmv_locate_tgt(lmv, lsm, op_data->op_name,
				       op_data->op_namelen, fid,
				       &op_data->op_mds,
				       op_data->op_post_migrate);
	}

	return tgt;
}

int lmv_create(struct obd_export *exp, struct md_op_data *op_data,
		const void *data, size_t datalen, umode_t mode, uid_t uid,
		gid_t gid, cfs_cap_t cap_effective, __u64 rdev,
		struct ptlrpc_request **request)
{
	struct obd_device       *obd = exp->exp_obd;
	struct lmv_obd          *lmv = &obd->u.lmv;
	struct lmv_tgt_desc     *tgt;
	int                      rc;
	ENTRY;

	if (!lmv->desc.ld_active_tgt_count)
		RETURN(-EIO);

	if (lmv_is_dir_bad_hash(op_data->op_mea1))
		RETURN(-EBADF);

	if (lmv_is_dir_migrating(op_data->op_mea1)) {
		/*
		 * if parent is migrating, create() needs to lookup existing
		 * name, to avoid creating new file under old layout of
		 * migrating directory, check old layout here.
		 */
		tgt = lmv_locate_tgt(lmv, op_data, &op_data->op_fid1);
		if (IS_ERR(tgt))
			RETURN(PTR_ERR(tgt));

		rc = md_getattr_name(tgt->ltd_exp, op_data, request);
		if (!rc) {
			ptlrpc_req_finished(*request);
			*request = NULL;
			RETURN(-EEXIST);
		}

		if (rc != -ENOENT)
			RETURN(rc);

		op_data->op_post_migrate = true;
	}

	tgt = lmv_locate_tgt(lmv, op_data, &op_data->op_fid1);
	if (IS_ERR(tgt))
		RETURN(PTR_ERR(tgt));

	CDEBUG(D_INODE, "CREATE name '%.*s' on "DFID" -> mds #%x\n",
		(int)op_data->op_namelen, op_data->op_name,
		PFID(&op_data->op_fid1), op_data->op_mds);

	rc = lmv_fid_alloc(NULL, exp, &op_data->op_fid2, op_data);
	if (rc)
		RETURN(rc);

	if (exp_connect_flags(exp) & OBD_CONNECT_DIR_STRIPE) {
		/* Send the create request to the MDT where the object
		 * will be located */
		tgt = lmv_find_target(lmv, &op_data->op_fid2);
		if (IS_ERR(tgt))
			RETURN(PTR_ERR(tgt));

		op_data->op_mds = tgt->ltd_idx;
	} else {
		CDEBUG(D_CONFIG, "Server doesn't support striped dirs\n");
	}

	CDEBUG(D_INODE, "CREATE obj "DFID" -> mds #%x\n",
	       PFID(&op_data->op_fid2), op_data->op_mds);

	op_data->op_flags |= MF_MDC_CANCEL_FID1;
	rc = md_create(tgt->ltd_exp, op_data, data, datalen, mode, uid, gid,
		       cap_effective, rdev, request);
	if (rc == 0) {
		if (*request == NULL)
			RETURN(rc);
		CDEBUG(D_INODE, "Created - "DFID"\n", PFID(&op_data->op_fid2));
	}
	RETURN(rc);
}

static int
lmv_enqueue(struct obd_export *exp, struct ldlm_enqueue_info *einfo,
	    const union ldlm_policy_data *policy, struct md_op_data *op_data,
	    struct lustre_handle *lockh, __u64 extra_lock_flags)
{
	struct obd_device        *obd = exp->exp_obd;
	struct lmv_obd           *lmv = &obd->u.lmv;
	struct lmv_tgt_desc      *tgt;
	int                       rc;
	ENTRY;

	CDEBUG(D_INODE, "ENQUEUE on "DFID"\n", PFID(&op_data->op_fid1));

	tgt = lmv_find_target(lmv, &op_data->op_fid1);
	if (IS_ERR(tgt))
		RETURN(PTR_ERR(tgt));

	CDEBUG(D_INODE, "ENQUEUE on "DFID" -> mds #%u\n",
	       PFID(&op_data->op_fid1), tgt->ltd_idx);

	rc = md_enqueue(tgt->ltd_exp, einfo, policy, op_data, lockh,
			extra_lock_flags);

	RETURN(rc);
}

int
lmv_getattr_name(struct obd_export *exp,struct md_op_data *op_data,
		 struct ptlrpc_request **preq)
{
	struct obd_device *obd = exp->exp_obd;
	struct lmv_obd *lmv = &obd->u.lmv;
	struct lmv_tgt_desc *tgt;
	struct mdt_body *body;
	int rc;

	ENTRY;

retry:
	tgt = lmv_locate_tgt(lmv, op_data, &op_data->op_fid1);
	if (IS_ERR(tgt))
		RETURN(PTR_ERR(tgt));

	CDEBUG(D_INODE, "GETATTR_NAME for %*s on "DFID" -> mds #%d\n",
		(int)op_data->op_namelen, op_data->op_name,
		PFID(&op_data->op_fid1), tgt->ltd_idx);

	rc = md_getattr_name(tgt->ltd_exp, op_data, preq);
	if (rc == -ENOENT && lmv_dir_retry_check_update(op_data)) {
		ptlrpc_req_finished(*preq);
		*preq = NULL;
		goto retry;
	}

	if (rc)
		RETURN(rc);

	body = req_capsule_server_get(&(*preq)->rq_pill, &RMF_MDT_BODY);
	LASSERT(body != NULL);

	if (body->mbo_valid & OBD_MD_MDS) {
		op_data->op_fid1 = body->mbo_fid1;
		op_data->op_valid |= OBD_MD_FLCROSSREF;
		op_data->op_namelen = 0;
		op_data->op_name = NULL;

		ptlrpc_req_finished(*preq);
		*preq = NULL;

		goto retry;
	}

	RETURN(rc);
}

#define md_op_data_fid(op_data, fl)                     \
        (fl == MF_MDC_CANCEL_FID1 ? &op_data->op_fid1 : \
         fl == MF_MDC_CANCEL_FID2 ? &op_data->op_fid2 : \
         fl == MF_MDC_CANCEL_FID3 ? &op_data->op_fid3 : \
         fl == MF_MDC_CANCEL_FID4 ? &op_data->op_fid4 : \
         NULL)

static int lmv_early_cancel(struct obd_export *exp, struct lmv_tgt_desc *tgt,
			    struct md_op_data *op_data, __u32 op_tgt,
			    enum ldlm_mode mode, int bits, int flag)
{
	struct lu_fid *fid = md_op_data_fid(op_data, flag);
	struct lmv_obd *lmv = &exp->exp_obd->u.lmv;
	union ldlm_policy_data policy = { { 0 } };
	int rc = 0;
	ENTRY;

	if (!fid_is_sane(fid))
		RETURN(0);

	if (tgt == NULL) {
		tgt = lmv_find_target(lmv, fid);
		if (IS_ERR(tgt))
			RETURN(PTR_ERR(tgt));
	}

	if (tgt->ltd_idx != op_tgt) {
		CDEBUG(D_INODE, "EARLY_CANCEL on "DFID"\n", PFID(fid));
		policy.l_inodebits.bits = bits;
		rc = md_cancel_unused(tgt->ltd_exp, fid, &policy,
				      mode, LCF_ASYNC, NULL);
	} else {
		CDEBUG(D_INODE,
		       "EARLY_CANCEL skip operation target %d on "DFID"\n",
		       op_tgt, PFID(fid));
		op_data->op_flags |= flag;
		rc = 0;
	}

	RETURN(rc);
}

/*
 * llite passes fid of an target inode in op_data->op_fid1 and id of directory in
 * op_data->op_fid2
 */
static int lmv_link(struct obd_export *exp, struct md_op_data *op_data,
                    struct ptlrpc_request **request)
{
	struct obd_device       *obd = exp->exp_obd;
	struct lmv_obd          *lmv = &obd->u.lmv;
	struct lmv_tgt_desc     *tgt;
	int                      rc;
	ENTRY;

	LASSERT(op_data->op_namelen != 0);

	CDEBUG(D_INODE, "LINK "DFID":%*s to "DFID"\n",
	       PFID(&op_data->op_fid2), (int)op_data->op_namelen,
	       op_data->op_name, PFID(&op_data->op_fid1));

	op_data->op_fsuid = from_kuid(&init_user_ns, current_fsuid());
	op_data->op_fsgid = from_kgid(&init_user_ns, current_fsgid());
	op_data->op_cap = cfs_curproc_cap_pack();

	if (lmv_is_dir_migrating(op_data->op_mea2)) {
		struct lu_fid fid1 = op_data->op_fid1;
		struct lmv_stripe_md *lsm1 = op_data->op_mea1;

		/*
		 * avoid creating new file under old layout of migrating
		 * directory, check it here.
		 */
		tgt = __lmv_locate_tgt(lmv, op_data->op_mea2, op_data->op_name,
				       op_data->op_namelen, &op_data->op_fid2,
				       &op_data->op_mds, false);
		tgt = lmv_locate_tgt(lmv, op_data, &op_data->op_fid1);
		if (IS_ERR(tgt))
			RETURN(PTR_ERR(tgt));

		op_data->op_fid1 = op_data->op_fid2;
		op_data->op_mea1 = op_data->op_mea2;
		rc = md_getattr_name(tgt->ltd_exp, op_data, request);
		op_data->op_fid1 = fid1;
		op_data->op_mea1 = lsm1;
		if (!rc) {
			ptlrpc_req_finished(*request);
			*request = NULL;
			RETURN(-EEXIST);
		}

		if (rc != -ENOENT)
			RETURN(rc);
	}

	tgt = __lmv_locate_tgt(lmv, op_data->op_mea2, op_data->op_name,
			       op_data->op_namelen, &op_data->op_fid2,
			       &op_data->op_mds, true);
	if (IS_ERR(tgt))
		RETURN(PTR_ERR(tgt));

	/*
	 * Cancel UPDATE lock on child (fid1).
	 */
	op_data->op_flags |= MF_MDC_CANCEL_FID2;
	rc = lmv_early_cancel(exp, NULL, op_data, tgt->ltd_idx, LCK_EX,
			      MDS_INODELOCK_UPDATE, MF_MDC_CANCEL_FID1);
	if (rc != 0)
		RETURN(rc);

	rc = md_link(tgt->ltd_exp, op_data, request);

	RETURN(rc);
}

static int lmv_migrate(struct obd_export *exp, struct md_op_data *op_data,
			const char *name, size_t namelen,
			struct ptlrpc_request **request)
{
	struct obd_device *obd = exp->exp_obd;
	struct lmv_obd *lmv = &obd->u.lmv;
	struct lmv_stripe_md *lsm = op_data->op_mea1;
	struct lmv_tgt_desc *parent_tgt;
	struct lmv_tgt_desc *sp_tgt;
	struct lmv_tgt_desc *tp_tgt = NULL;
	struct lmv_tgt_desc *child_tgt;
	struct lmv_tgt_desc *tgt;
	struct lu_fid target_fid;
	int rc;

	ENTRY;

	LASSERT(op_data->op_cli_flags & CLI_MIGRATE);

	CDEBUG(D_INODE, "MIGRATE "DFID"/%.*s\n",
	       PFID(&op_data->op_fid1), (int)namelen, name);

	op_data->op_fsuid = from_kuid(&init_user_ns, current_fsuid());
	op_data->op_fsgid = from_kgid(&init_user_ns, current_fsgid());
	op_data->op_cap = cfs_curproc_cap_pack();

	parent_tgt = lmv_find_target(lmv, &op_data->op_fid1);
	if (IS_ERR(parent_tgt))
		RETURN(PTR_ERR(parent_tgt));

	if (lsm) {
		__u32 hash_type = lsm->lsm_md_hash_type;
		__u32 stripe_count = lsm->lsm_md_stripe_count;

		/*
		 * old stripes are appended after new stripes for migrating
		 * directory.
		 */
		if (lsm->lsm_md_hash_type & LMV_HASH_FLAG_MIGRATION) {
			hash_type = lsm->lsm_md_migrate_hash;
			stripe_count -= lsm->lsm_md_migrate_offset;
		}

		rc = lmv_name_to_stripe_index(hash_type, stripe_count, name,
					      namelen);
		if (rc < 0)
			RETURN(rc);

		if (lsm->lsm_md_hash_type & LMV_HASH_FLAG_MIGRATION)
			rc += lsm->lsm_md_migrate_offset;

		/* save it in fid4 temporarily for early cancel */
		op_data->op_fid4 = lsm->lsm_md_oinfo[rc].lmo_fid;
		sp_tgt = lmv_get_target(lmv, lsm->lsm_md_oinfo[rc].lmo_mds,
					NULL);
		if (IS_ERR(sp_tgt))
			RETURN(PTR_ERR(sp_tgt));

		/*
		 * if parent is being migrated too, fill op_fid2 with target
		 * stripe fid, otherwise the target stripe is not created yet.
		 */
		if (lsm->lsm_md_hash_type & LMV_HASH_FLAG_MIGRATION) {
			hash_type = lsm->lsm_md_hash_type &
				    ~LMV_HASH_FLAG_MIGRATION;
			stripe_count = lsm->lsm_md_migrate_offset;

			rc = lmv_name_to_stripe_index(hash_type, stripe_count,
						      name, namelen);
			if (rc < 0)
				RETURN(rc);

			op_data->op_fid2 = lsm->lsm_md_oinfo[rc].lmo_fid;
			tp_tgt = lmv_get_target(lmv,
						lsm->lsm_md_oinfo[rc].lmo_mds,
						NULL);
			if (IS_ERR(tp_tgt))
				RETURN(PTR_ERR(tp_tgt));
		}
	} else {
		sp_tgt = parent_tgt;
	}

	child_tgt = lmv_find_target(lmv, &op_data->op_fid3);
	if (IS_ERR(child_tgt))
		RETURN(PTR_ERR(child_tgt));

	if (!S_ISDIR(op_data->op_mode) && tp_tgt)
		rc = __lmv_fid_alloc(lmv, &target_fid, tp_tgt->ltd_idx);
	else
		rc = lmv_fid_alloc(NULL, exp, &target_fid, op_data);
	if (rc)
		RETURN(rc);

	/*
	 * for directory, send migrate request to the MDT where the object will
	 * be migrated to, because we can't create a striped directory remotely.
	 *
	 * otherwise, send to the MDT where source is located because regular
	 * file may open lease.
	 *
	 * NB. if MDT doesn't support DIR_MIGRATE, send to source MDT too for
	 * backward compatibility.
	 */
	if (S_ISDIR(op_data->op_mode) &&
	    (exp_connect_flags2(exp) & OBD_CONNECT2_DIR_MIGRATE)) {
		tgt = lmv_find_target(lmv, &target_fid);
		if (IS_ERR(tgt))
			RETURN(PTR_ERR(tgt));
	} else {
		tgt = child_tgt;
	}

	/* cancel UPDATE lock of parent master object */
	rc = lmv_early_cancel(exp, parent_tgt, op_data, tgt->ltd_idx, LCK_EX,
			      MDS_INODELOCK_UPDATE, MF_MDC_CANCEL_FID1);
	if (rc)
		RETURN(rc);

	/* cancel UPDATE lock of source parent */
	if (sp_tgt != parent_tgt) {
		/*
		 * migrate RPC packs master object FID, because we can only pack
		 * two FIDs in reint RPC, but MDS needs to know both source
		 * parent and target parent, and it will obtain them from master
		 * FID and LMV, the other FID in RPC is kept for target.
		 *
		 * since this FID is not passed to MDC, cancel it anyway.
		 */
		rc = lmv_early_cancel(exp, sp_tgt, op_data, -1, LCK_EX,
				      MDS_INODELOCK_UPDATE, MF_MDC_CANCEL_FID4);
		if (rc)
			RETURN(rc);

		op_data->op_flags &= ~MF_MDC_CANCEL_FID4;
	}
	op_data->op_fid4 = target_fid;

	/* cancel UPDATE locks of target parent */
	rc = lmv_early_cancel(exp, tp_tgt, op_data, tgt->ltd_idx, LCK_EX,
			      MDS_INODELOCK_UPDATE, MF_MDC_CANCEL_FID2);
	if (rc)
		RETURN(rc);

	/* cancel LOOKUP lock of source if source is remote object */
	if (child_tgt != sp_tgt) {
		rc = lmv_early_cancel(exp, sp_tgt, op_data, tgt->ltd_idx,
				      LCK_EX, MDS_INODELOCK_LOOKUP,
				      MF_MDC_CANCEL_FID3);
		if (rc)
			RETURN(rc);
	}

	/* cancel ELC locks of source */
	rc = lmv_early_cancel(exp, child_tgt, op_data, tgt->ltd_idx, LCK_EX,
			      MDS_INODELOCK_ELC, MF_MDC_CANCEL_FID3);
	if (rc)
		RETURN(rc);

	rc = md_rename(tgt->ltd_exp, op_data, name, namelen, NULL, 0, request);

	RETURN(rc);
}

static int lmv_rename(struct obd_export *exp, struct md_op_data *op_data,
		      const char *old, size_t oldlen,
		      const char *new, size_t newlen,
		      struct ptlrpc_request **request)
{
	struct obd_device *obd = exp->exp_obd;
	struct lmv_obd *lmv = &obd->u.lmv;
	struct lmv_tgt_desc *sp_tgt;
	struct lmv_tgt_desc *tp_tgt = NULL;
	struct lmv_tgt_desc *src_tgt = NULL;
	struct lmv_tgt_desc *tgt;
	struct mdt_body *body;
	int rc;

	ENTRY;

	LASSERT(oldlen != 0);

	if (op_data->op_cli_flags & CLI_MIGRATE) {
		rc = lmv_migrate(exp, op_data, old, oldlen, request);
		RETURN(rc);
	}

	op_data->op_fsuid = from_kuid(&init_user_ns, current_fsuid());
	op_data->op_fsgid = from_kgid(&init_user_ns, current_fsgid());
	op_data->op_cap = cfs_curproc_cap_pack();

	if (lmv_is_dir_migrating(op_data->op_mea2)) {
		struct lu_fid fid1 = op_data->op_fid1;
		struct lmv_stripe_md *lsm1 = op_data->op_mea1;

		/*
		 * we avoid creating new file under old layout of migrating
		 * directory, if there is an existing file with new name under
		 * old layout, we can't unlink file in old layout and rename to
		 * new layout in one transaction, so return -EBUSY here.`
		 */
		tgt = __lmv_locate_tgt(lmv, op_data->op_mea2, new, newlen,
				       &op_data->op_fid2, &op_data->op_mds,
				       false);
		if (IS_ERR(tgt))
			RETURN(PTR_ERR(tgt));

		op_data->op_fid1 = op_data->op_fid2;
		op_data->op_mea1 = op_data->op_mea2;
		op_data->op_name = new;
		op_data->op_namelen = newlen;
		rc = md_getattr_name(tgt->ltd_exp, op_data, request);
		op_data->op_fid1 = fid1;
		op_data->op_mea1 = lsm1;
		op_data->op_name = NULL;
		op_data->op_namelen = 0;
		if (!rc) {
			ptlrpc_req_finished(*request);
			*request = NULL;
			RETURN(-EBUSY);
		}

		if (rc != -ENOENT)
			RETURN(rc);
	}

	/* rename to new layout for migrating directory */
	tp_tgt = __lmv_locate_tgt(lmv, op_data->op_mea2, new, newlen,
				  &op_data->op_fid2, &op_data->op_mds, true);
	if (IS_ERR(tp_tgt))
		RETURN(PTR_ERR(tp_tgt));

	/* Since the target child might be destroyed, and it might become
	 * orphan, and we can only check orphan on the local MDT right now, so
	 * we send rename request to the MDT where target child is located. If
	 * target child does not exist, then it will send the request to the
	 * target parent */
	if (fid_is_sane(&op_data->op_fid4)) {
		tgt = lmv_find_target(lmv, &op_data->op_fid4);
		if (IS_ERR(tgt))
			RETURN(PTR_ERR(tgt));
	} else {
		tgt = tp_tgt;
	}

	op_data->op_flags |= MF_MDC_CANCEL_FID4;

	/* cancel UPDATE locks of target parent */
	rc = lmv_early_cancel(exp, tp_tgt, op_data, tgt->ltd_idx, LCK_EX,
			      MDS_INODELOCK_UPDATE, MF_MDC_CANCEL_FID2);
	if (rc != 0)
		RETURN(rc);

	if (fid_is_sane(&op_data->op_fid4)) {
		/* cancel LOOKUP lock of target on target parent */
		if (tgt != tp_tgt) {
			rc = lmv_early_cancel(exp, tp_tgt, op_data,
					      tgt->ltd_idx, LCK_EX,
					      MDS_INODELOCK_LOOKUP,
					      MF_MDC_CANCEL_FID4);
			if (rc != 0)
				RETURN(rc);
		}
	}

	if (fid_is_sane(&op_data->op_fid3)) {
		src_tgt = lmv_find_target(lmv, &op_data->op_fid3);
		if (IS_ERR(src_tgt))
			RETURN(PTR_ERR(src_tgt));

		/* cancel ELC locks of source */
		rc = lmv_early_cancel(exp, src_tgt, op_data, tgt->ltd_idx,
				      LCK_EX, MDS_INODELOCK_ELC,
				      MF_MDC_CANCEL_FID3);
		if (rc != 0)
			RETURN(rc);
	}

retry:
	sp_tgt = __lmv_locate_tgt(lmv, op_data->op_mea1, old, oldlen,
				  &op_data->op_fid1, &op_data->op_mds,
				  op_data->op_post_migrate);
	if (IS_ERR(sp_tgt))
		RETURN(PTR_ERR(sp_tgt));

	/* cancel UPDATE locks of source parent */
	rc = lmv_early_cancel(exp, sp_tgt, op_data, tgt->ltd_idx, LCK_EX,
			      MDS_INODELOCK_UPDATE, MF_MDC_CANCEL_FID1);
	if (rc != 0)
		RETURN(rc);

	if (fid_is_sane(&op_data->op_fid3)) {
		/* cancel LOOKUP lock of source on source parent */
		if (src_tgt != sp_tgt) {
			rc = lmv_early_cancel(exp, sp_tgt, op_data,
					      tgt->ltd_idx, LCK_EX,
					      MDS_INODELOCK_LOOKUP,
					      MF_MDC_CANCEL_FID3);
			if (rc != 0)
				RETURN(rc);
		}
	}

rename:
	CDEBUG(D_INODE, "RENAME "DFID"/%.*s to "DFID"/%.*s\n",
		PFID(&op_data->op_fid1), (int)oldlen, old,
		PFID(&op_data->op_fid2), (int)newlen, new);

	rc = md_rename(tgt->ltd_exp, op_data, old, oldlen, new, newlen,
			request);
	if (rc == -ENOENT && lmv_dir_retry_check_update(op_data)) {
		ptlrpc_req_finished(*request);
		*request = NULL;
		goto retry;
	}

	if (rc && rc != -EXDEV)
		RETURN(rc);

	body = req_capsule_server_get(&(*request)->rq_pill, &RMF_MDT_BODY);
	if (body == NULL)
		RETURN(-EPROTO);

	/* Not cross-ref case, just get out of here. */
	if (likely(!(body->mbo_valid & OBD_MD_MDS)))
		RETURN(rc);

	op_data->op_fid4 = body->mbo_fid1;

	ptlrpc_req_finished(*request);
	*request = NULL;

	tgt = lmv_find_target(lmv, &op_data->op_fid4);
	if (IS_ERR(tgt))
		RETURN(PTR_ERR(tgt));

	if (fid_is_sane(&op_data->op_fid4)) {
		/* cancel LOOKUP lock of target on target parent */
		if (tgt != tp_tgt) {
			rc = lmv_early_cancel(exp, tp_tgt, op_data,
					      tgt->ltd_idx, LCK_EX,
					      MDS_INODELOCK_LOOKUP,
					      MF_MDC_CANCEL_FID4);
			if (rc != 0)
				RETURN(rc);
		}
	}

	goto rename;
}

static int lmv_setattr(struct obd_export *exp, struct md_op_data *op_data,
		       void *ea, size_t ealen, struct ptlrpc_request **request)
{
	struct obd_device       *obd = exp->exp_obd;
	struct lmv_obd          *lmv = &obd->u.lmv;
	struct lmv_tgt_desc     *tgt;
	int                      rc = 0;
	ENTRY;

	CDEBUG(D_INODE, "SETATTR for "DFID", valid 0x%x/0x%x\n",
	       PFID(&op_data->op_fid1), op_data->op_attr.ia_valid,
	       op_data->op_xvalid);

	op_data->op_flags |= MF_MDC_CANCEL_FID1;
	tgt = lmv_find_target(lmv, &op_data->op_fid1);
	if (IS_ERR(tgt))
		RETURN(PTR_ERR(tgt));

	rc = md_setattr(tgt->ltd_exp, op_data, ea, ealen, request);

	RETURN(rc);
}

static int lmv_fsync(struct obd_export *exp, const struct lu_fid *fid,
		     struct ptlrpc_request **request)
{
	struct obd_device	*obd = exp->exp_obd;
	struct lmv_obd		*lmv = &obd->u.lmv;
	struct lmv_tgt_desc	*tgt;
	int			 rc;
	ENTRY;

	tgt = lmv_find_target(lmv, fid);
	if (IS_ERR(tgt))
		RETURN(PTR_ERR(tgt));

	rc = md_fsync(tgt->ltd_exp, fid, request);
	RETURN(rc);
}

struct stripe_dirent {
	struct page		*sd_page;
	struct lu_dirpage	*sd_dp;
	struct lu_dirent	*sd_ent;
	bool			 sd_eof;
};

struct lmv_dir_ctxt {
	struct lmv_obd		*ldc_lmv;
	struct md_op_data	*ldc_op_data;
	struct md_callback	*ldc_cb_op;
	__u64			 ldc_hash;
	int			 ldc_count;
	struct stripe_dirent	 ldc_stripes[0];
};

static inline void stripe_dirent_unload(struct stripe_dirent *stripe)
{
	if (stripe->sd_page) {
		kunmap(stripe->sd_page);
		put_page(stripe->sd_page);
		stripe->sd_page = NULL;
		stripe->sd_ent = NULL;
	}
}

static inline void put_lmv_dir_ctxt(struct lmv_dir_ctxt *ctxt)
{
	int i;

	for (i = 0; i < ctxt->ldc_count; i++)
		stripe_dirent_unload(&ctxt->ldc_stripes[i]);
}

/* if @ent is dummy, or . .., get next */
static struct lu_dirent *stripe_dirent_get(struct lmv_dir_ctxt *ctxt,
					   struct lu_dirent *ent,
					   int stripe_index)
{
	for (; ent; ent = lu_dirent_next(ent)) {
		/* Skip dummy entry */
		if (le16_to_cpu(ent->lde_namelen) == 0)
			continue;

		/* skip . and .. for other stripes */
		if (stripe_index &&
		    (strncmp(ent->lde_name, ".",
			     le16_to_cpu(ent->lde_namelen)) == 0 ||
		     strncmp(ent->lde_name, "..",
			     le16_to_cpu(ent->lde_namelen)) == 0))
			continue;

		if (le64_to_cpu(ent->lde_hash) >= ctxt->ldc_hash)
			break;
	}

	return ent;
}

static struct lu_dirent *stripe_dirent_load(struct lmv_dir_ctxt *ctxt,
					    struct stripe_dirent *stripe,
					    int stripe_index)
{
	struct md_op_data *op_data = ctxt->ldc_op_data;
	struct lmv_oinfo *oinfo;
	struct lu_fid fid = op_data->op_fid1;
	struct inode *inode = op_data->op_data;
	struct lmv_tgt_desc *tgt;
	struct lu_dirent *ent = stripe->sd_ent;
	__u64 hash = ctxt->ldc_hash;
	int rc = 0;

	ENTRY;

	LASSERT(stripe == &ctxt->ldc_stripes[stripe_index]);
	LASSERT(!ent);

	do {
		if (stripe->sd_page) {
			__u64 end = le64_to_cpu(stripe->sd_dp->ldp_hash_end);

			/* @hash should be the last dirent hash */
			LASSERTF(hash <= end,
				 "ctxt@%p stripe@%p hash %llx end %llx\n",
				 ctxt, stripe, hash, end);
			/* unload last page */
			stripe_dirent_unload(stripe);
			/* eof */
			if (end == MDS_DIR_END_OFF) {
				stripe->sd_eof = true;
				break;
			}
			hash = end;
		}

		oinfo = &op_data->op_mea1->lsm_md_oinfo[stripe_index];
		if (!oinfo->lmo_root) {
			rc = -ENOENT;
			break;
		}

		tgt = lmv_get_target(ctxt->ldc_lmv, oinfo->lmo_mds, NULL);
		if (IS_ERR(tgt)) {
			rc = PTR_ERR(tgt);
			break;
		}

		/* op_data is shared by stripes, reset after use */
		op_data->op_fid1 = oinfo->lmo_fid;
		op_data->op_fid2 = oinfo->lmo_fid;
		op_data->op_data = oinfo->lmo_root;

		rc = md_read_page(tgt->ltd_exp, op_data, ctxt->ldc_cb_op, hash,
				  &stripe->sd_page);

		op_data->op_fid1 = fid;
		op_data->op_fid2 = fid;
		op_data->op_data = inode;

		if (rc)
			break;

		stripe->sd_dp = page_address(stripe->sd_page);
		ent = stripe_dirent_get(ctxt, lu_dirent_start(stripe->sd_dp),
					stripe_index);
		/* in case a page filled with ., .. and dummy, read next */
	} while (!ent);

	stripe->sd_ent = ent;
	if (rc) {
		LASSERT(!ent);
		/* treat error as eof, so dir can be partially accessed */
		stripe->sd_eof = true;
		LCONSOLE_WARN("dir "DFID" stripe %d readdir failed: %d, "
			      "directory is partially accessed!\n",
			      PFID(&ctxt->ldc_op_data->op_fid1), stripe_index,
			      rc);
	}

	RETURN(ent);
}

static int lmv_file_resync(struct obd_export *exp, struct md_op_data *data)
{
	struct obd_device	*obd = exp->exp_obd;
	struct lmv_obd		*lmv = &obd->u.lmv;
	struct lmv_tgt_desc	*tgt;
	int			 rc;
	ENTRY;

	rc = lmv_check_connect(obd);
	if (rc != 0)
		RETURN(rc);

	tgt = lmv_find_target(lmv, &data->op_fid1);
	if (IS_ERR(tgt))
		RETURN(PTR_ERR(tgt));

	data->op_flags |= MF_MDC_CANCEL_FID1;
	rc = md_file_resync(tgt->ltd_exp, data);
	RETURN(rc);
}

/**
 * Get dirent with the closest hash for striped directory
 *
 * This function will search the dir entry, whose hash value is the
 * closest(>=) to hash from all of sub-stripes, and it is only being called
 * for striped directory.
 *
 * \param[in] ctxt		dir read context
 *
 * \retval                      dirent get the entry successfully
 *                              NULL does not get the entry, normally it means
 *                              it reaches the end of the directory, while read
 *                              stripe dirent error is ignored to allow partial
 *                              access.
 */
static struct lu_dirent *lmv_dirent_next(struct lmv_dir_ctxt *ctxt)
{
	struct stripe_dirent *stripe;
	struct lu_dirent *ent = NULL;
	int i;
	int min = -1;

	/* TODO: optimize with k-way merge sort */
	for (i = 0; i < ctxt->ldc_count; i++) {
		stripe = &ctxt->ldc_stripes[i];
		if (stripe->sd_eof)
			continue;

		if (!stripe->sd_ent) {
			stripe_dirent_load(ctxt, stripe, i);
			if (!stripe->sd_ent) {
				LASSERT(stripe->sd_eof);
				continue;
			}
		}

		if (min == -1 ||
		    le64_to_cpu(ctxt->ldc_stripes[min].sd_ent->lde_hash) >
		    le64_to_cpu(stripe->sd_ent->lde_hash)) {
			min = i;
			if (le64_to_cpu(stripe->sd_ent->lde_hash) ==
			    ctxt->ldc_hash)
				break;
		}
	}

	if (min != -1) {
		stripe = &ctxt->ldc_stripes[min];
		ent = stripe->sd_ent;
		/* pop found dirent */
		stripe->sd_ent = stripe_dirent_get(ctxt, lu_dirent_next(ent),
						   min);
	}

	return ent;
}

/**
 * Build dir entry page for striped directory
 *
 * This function gets one entry by @offset from a striped directory. It will
 * read entries from all of stripes, and choose one closest to the required
 * offset(&offset). A few notes
 * 1. skip . and .. for non-zero stripes, because there can only have one .
 * and .. in a directory.
 * 2. op_data will be shared by all of stripes, instead of allocating new
 * one, so need to restore before reusing.
 *
 * \param[in] exp	obd export refer to LMV
 * \param[in] op_data	hold those MD parameters of read_entry
 * \param[in] cb_op	ldlm callback being used in enqueue in mdc_read_entry
 * \param[in] offset	starting hash offset
 * \param[out] ppage	the page holding the entry. Note: because the entry
 *                      will be accessed in upper layer, so we need hold the
 *                      page until the usages of entry is finished, see
 *                      ll_dir_entry_next.
 *
 * retval		=0 if get entry successfully
 *                      <0 cannot get entry
 */
static int lmv_striped_read_page(struct obd_export *exp,
				 struct md_op_data *op_data,
				 struct md_callback *cb_op,
				 __u64 offset, struct page **ppage)
{
	struct page *page = NULL;
	struct lu_dirpage *dp;
	void *start;
	struct lu_dirent *ent;
	struct lu_dirent *last_ent;
	int stripe_count;
	struct lmv_dir_ctxt *ctxt;
	struct lu_dirent *next = NULL;
	__u16 ent_size;
	size_t left_bytes;
	int rc = 0;
	ENTRY;

	/* Allocate a page and read entries from all of stripes and fill
	 * the page by hash order */
	page = alloc_page(GFP_KERNEL);
	if (!page)
		RETURN(-ENOMEM);

	/* Initialize the entry page */
	dp = kmap(page);
	memset(dp, 0, sizeof(*dp));
	dp->ldp_hash_start = cpu_to_le64(offset);

	start = dp + 1;
	left_bytes = PAGE_SIZE - sizeof(*dp);
	ent = start;
	last_ent = ent;

	/* initalize dir read context */
	stripe_count = op_data->op_mea1->lsm_md_stripe_count;
	OBD_ALLOC(ctxt, offsetof(typeof(*ctxt), ldc_stripes[stripe_count]));
	if (!ctxt)
		GOTO(free_page, rc = -ENOMEM);
	ctxt->ldc_lmv = &exp->exp_obd->u.lmv;
	ctxt->ldc_op_data = op_data;
	ctxt->ldc_cb_op = cb_op;
	ctxt->ldc_hash = offset;
	ctxt->ldc_count = stripe_count;

	while (1) {
		next = lmv_dirent_next(ctxt);

		/* end of directory */
		if (!next) {
			ctxt->ldc_hash = MDS_DIR_END_OFF;
			break;
		}
		ctxt->ldc_hash = le64_to_cpu(next->lde_hash);

		ent_size = le16_to_cpu(next->lde_reclen);

		/* the last entry lde_reclen is 0, but it might not be the last
		 * one of this temporay dir page */
		if (!ent_size)
			ent_size = lu_dirent_calc_size(
					le16_to_cpu(next->lde_namelen),
					le32_to_cpu(next->lde_attrs));
		/* page full */
		if (ent_size > left_bytes)
			break;

		memcpy(ent, next, ent_size);

		/* Replace . with master FID and Replace .. with the parent FID
		 * of master object */
		if (strncmp(ent->lde_name, ".",
			    le16_to_cpu(ent->lde_namelen)) == 0 &&
		    le16_to_cpu(ent->lde_namelen) == 1)
			fid_cpu_to_le(&ent->lde_fid, &op_data->op_fid1);
		else if (strncmp(ent->lde_name, "..",
				   le16_to_cpu(ent->lde_namelen)) == 0 &&
			   le16_to_cpu(ent->lde_namelen) == 2)
			fid_cpu_to_le(&ent->lde_fid, &op_data->op_fid3);

		CDEBUG(D_INODE, "entry %.*s hash %#llx\n",
		       le16_to_cpu(ent->lde_namelen), ent->lde_name,
		       le64_to_cpu(ent->lde_hash));

		left_bytes -= ent_size;
		ent->lde_reclen = cpu_to_le16(ent_size);
		last_ent = ent;
		ent = (void *)ent + ent_size;
	};

	last_ent->lde_reclen = 0;

	if (ent == start)
		dp->ldp_flags |= LDF_EMPTY;
	else if (ctxt->ldc_hash == le64_to_cpu(last_ent->lde_hash))
		dp->ldp_flags |= LDF_COLLIDE;
	dp->ldp_flags = cpu_to_le32(dp->ldp_flags);
	dp->ldp_hash_end = cpu_to_le64(ctxt->ldc_hash);

	put_lmv_dir_ctxt(ctxt);
	OBD_FREE(ctxt, offsetof(typeof(*ctxt), ldc_stripes[stripe_count]));

	*ppage = page;

	RETURN(0);

free_page:
	kunmap(page);
	__free_page(page);

	return rc;
}

int lmv_read_page(struct obd_export *exp, struct md_op_data *op_data,
		  struct md_callback *cb_op, __u64 offset,
		  struct page **ppage)
{
	struct obd_device	*obd = exp->exp_obd;
	struct lmv_obd		*lmv = &obd->u.lmv;
	struct lmv_stripe_md	*lsm = op_data->op_mea1;
	struct lmv_tgt_desc	*tgt;
	int			rc;
	ENTRY;

	if (unlikely(lsm != NULL)) {
		rc = lmv_striped_read_page(exp, op_data, cb_op, offset, ppage);
		RETURN(rc);
	}

	tgt = lmv_find_target(lmv, &op_data->op_fid1);
	if (IS_ERR(tgt))
		RETURN(PTR_ERR(tgt));

	rc = md_read_page(tgt->ltd_exp, op_data, cb_op, offset, ppage);

	RETURN(rc);
}

/**
 * Unlink a file/directory
 *
 * Unlink a file or directory under the parent dir. The unlink request
 * usually will be sent to the MDT where the child is located, but if
 * the client does not have the child FID then request will be sent to the
 * MDT where the parent is located.
 *
 * If the parent is a striped directory then it also needs to locate which
 * stripe the name of the child is located, and replace the parent FID
 * (@op->op_fid1) with the stripe FID. Note: if the stripe is unknown,
 * it will walk through all of sub-stripes until the child is being
 * unlinked finally.
 *
 * \param[in] exp	export refer to LMV
 * \param[in] op_data	different parameters transferred beween client
 *                      MD stacks, name, namelen, FIDs etc.
 *                      op_fid1 is the parent FID, op_fid2 is the child
 *                      FID.
 * \param[out] request	point to the request of unlink.
 *
 * retval		0 if succeed
 *                      negative errno if failed.
 */
static int lmv_unlink(struct obd_export *exp, struct md_op_data *op_data,
		      struct ptlrpc_request **request)
{
	struct obd_device *obd = exp->exp_obd;
	struct lmv_obd *lmv = &obd->u.lmv;
	struct lmv_tgt_desc *tgt;
	struct lmv_tgt_desc *parent_tgt;
	struct mdt_body *body;
	int rc;

	ENTRY;

	op_data->op_fsuid = from_kuid(&init_user_ns, current_fsuid());
	op_data->op_fsgid = from_kgid(&init_user_ns, current_fsgid());
	op_data->op_cap = cfs_curproc_cap_pack();

retry:
	parent_tgt = lmv_locate_tgt(lmv, op_data, &op_data->op_fid1);
	if (IS_ERR(parent_tgt))
		RETURN(PTR_ERR(parent_tgt));

	if (likely(!fid_is_zero(&op_data->op_fid2))) {
		tgt = lmv_find_target(lmv, &op_data->op_fid2);
		if (IS_ERR(tgt))
			RETURN(PTR_ERR(tgt));
	} else {
		tgt = parent_tgt;
	}

	/*
	 * If child's fid is given, cancel unused locks for it if it is from
	 * another export than parent.
	 *
	 * LOOKUP lock for child (fid3) should also be cancelled on parent
	 * tgt_tgt in mdc_unlink().
	 */
	op_data->op_flags |= MF_MDC_CANCEL_FID1 | MF_MDC_CANCEL_FID3;

	if (parent_tgt != tgt)
		rc = lmv_early_cancel(exp, parent_tgt, op_data, tgt->ltd_idx,
				      LCK_EX, MDS_INODELOCK_LOOKUP,
				      MF_MDC_CANCEL_FID3);

	rc = lmv_early_cancel(exp, NULL, op_data, tgt->ltd_idx, LCK_EX,
			      MDS_INODELOCK_ELC, MF_MDC_CANCEL_FID3);
	if (rc)
		RETURN(rc);

	CDEBUG(D_INODE, "unlink with fid="DFID"/"DFID" -> mds #%u\n",
	       PFID(&op_data->op_fid1), PFID(&op_data->op_fid2), tgt->ltd_idx);

	rc = md_unlink(tgt->ltd_exp, op_data, request);
	if (rc == -ENOENT && lmv_dir_retry_check_update(op_data)) {
		ptlrpc_req_finished(*request);
		*request = NULL;
		goto retry;
	}

	if (rc != -EREMOTE)
		RETURN(rc);

	body = req_capsule_server_get(&(*request)->rq_pill, &RMF_MDT_BODY);
	if (body == NULL)
		RETURN(-EPROTO);

	/* Not cross-ref case, just get out of here. */
	if (likely(!(body->mbo_valid & OBD_MD_MDS)))
		RETURN(rc);

	/* This is a remote object, try remote MDT. */
	op_data->op_fid2 = body->mbo_fid1;
	ptlrpc_req_finished(*request);
	*request = NULL;

	tgt = lmv_find_target(lmv, &op_data->op_fid2);
	if (IS_ERR(tgt))
		RETURN(PTR_ERR(tgt));

	goto retry;
}

static int lmv_precleanup(struct obd_device *obd)
{
	ENTRY;
	libcfs_kkuc_group_rem(&obd->obd_uuid, 0, KUC_GRP_HSM);
	fld_client_debugfs_fini(&obd->u.lmv.lmv_fld);
	lprocfs_obd_cleanup(obd);
	lprocfs_free_md_stats(obd);
	RETURN(0);
}

/**
 * Get by key a value associated with a LMV device.
 *
 * Dispatch request to lower-layer devices as needed.
 *
 * \param[in] env		execution environment for this thread
 * \param[in] exp		export for the LMV device
 * \param[in] keylen		length of key identifier
 * \param[in] key		identifier of key to get value for
 * \param[in] vallen		size of \a val
 * \param[out] val		pointer to storage location for value
 * \param[in] lsm		optional striping metadata of object
 *
 * \retval 0		on success
 * \retval negative	negated errno on failure
 */
static int lmv_get_info(const struct lu_env *env, struct obd_export *exp,
			__u32 keylen, void *key, __u32 *vallen, void *val)
{
        struct obd_device       *obd;
        struct lmv_obd          *lmv;
        int                      rc = 0;
        ENTRY;

        obd = class_exp2obd(exp);
        if (obd == NULL) {
		CDEBUG(D_IOCTL, "Invalid client cookie %#llx\n",
                       exp->exp_handle.h_cookie);
                RETURN(-EINVAL);
        }

        lmv = &obd->u.lmv;
        if (keylen >= strlen("remote_flag") && !strcmp(key, "remote_flag")) {
                int i;

                LASSERT(*vallen == sizeof(__u32));
		for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
			struct lmv_tgt_desc *tgt = lmv->tgts[i];
			/*
			 * All tgts should be connected when this gets called.
			 */
			if (tgt == NULL || tgt->ltd_exp == NULL)
				continue;

			if (!obd_get_info(env, tgt->ltd_exp, keylen, key,
					  vallen, val))
				RETURN(0);
		}
		RETURN(-EINVAL);
	} else if (KEY_IS(KEY_MAX_EASIZE) ||
		   KEY_IS(KEY_DEFAULT_EASIZE) ||
		   KEY_IS(KEY_CONN_DATA)) {
		/*
		 * Forwarding this request to first MDS, it should know LOV
		 * desc.
		 */
		rc = obd_get_info(env, lmv->tgts[0]->ltd_exp, keylen, key,
				  vallen, val);
		if (!rc && KEY_IS(KEY_CONN_DATA))
			exp->exp_connect_data = *(struct obd_connect_data *)val;
                RETURN(rc);
        } else if (KEY_IS(KEY_TGT_COUNT)) {
                *((int *)val) = lmv->desc.ld_tgt_count;
                RETURN(0);
        }

        CDEBUG(D_IOCTL, "Invalid key\n");
        RETURN(-EINVAL);
}

static int lmv_rmfid(struct obd_export *exp, struct fid_array *fa,
		     int *__rcs, struct ptlrpc_request_set *_set)
{
	struct obd_device *obddev = class_exp2obd(exp);
	struct ptlrpc_request_set *set = _set;
	struct lmv_obd *lmv = &obddev->u.lmv;
	int tgt_count = lmv->desc.ld_tgt_count;
	struct fid_array *fat, **fas = NULL;
	int i, rc, **rcs = NULL;

	if (!set) {
		set = ptlrpc_prep_set();
		if (!set)
			RETURN(-ENOMEM);
	}

	/* split FIDs by targets */
	OBD_ALLOC(fas, sizeof(fas) * tgt_count);
	if (fas == NULL)
		GOTO(out, rc = -ENOMEM);
	OBD_ALLOC(rcs, sizeof(int *) * tgt_count);
	if (rcs == NULL)
		GOTO(out_fas, rc = -ENOMEM);

	for (i = 0; i < fa->fa_nr; i++) {
		unsigned int idx;

		rc = lmv_fld_lookup(lmv, &fa->fa_fids[i], &idx);
		if (rc) {
			CDEBUG(D_OTHER, "can't lookup "DFID": rc = %d\n",
			       PFID(&fa->fa_fids[i]), rc);
			continue;
		}
		LASSERT(idx < tgt_count);
		if (!fas[idx])
			OBD_ALLOC(fas[idx], offsetof(struct fid_array,
				  fa_fids[fa->fa_nr]));
		if (!fas[idx])
			GOTO(out, rc = -ENOMEM);
		if (!rcs[idx])
			OBD_ALLOC(rcs[idx], sizeof(int) * fa->fa_nr);
		if (!rcs[idx])
			GOTO(out, rc = -ENOMEM);

		fat = fas[idx];
		fat->fa_fids[fat->fa_nr++] = fa->fa_fids[i];
	}

	for (i = 0; i < tgt_count; i++) {
		fat = fas[i];
		if (!fat || fat->fa_nr == 0)
			continue;
		rc = md_rmfid(lmv->tgts[i]->ltd_exp, fat, rcs[i], set);
	}

	rc = ptlrpc_set_wait(NULL, set);
	if (rc == 0) {
		int j = 0;
		for (i = 0; i < tgt_count; i++) {
			fat = fas[i];
			if (!fat || fat->fa_nr == 0)
				continue;
			/* copy FIDs back */
			memcpy(fa->fa_fids + j, fat->fa_fids,
			       fat->fa_nr * sizeof(struct lu_fid));
			/* copy rcs back */
			memcpy(__rcs + j, rcs[i], fat->fa_nr * sizeof(**rcs));
			j += fat->fa_nr;
		}
	}
	if (set != _set)
		ptlrpc_set_destroy(set);

out:
	for (i = 0; i < tgt_count; i++) {
		if (fas && fas[i])
			OBD_FREE(fas[i], offsetof(struct fid_array,
						fa_fids[fa->fa_nr]));
		if (rcs && rcs[i])
			OBD_FREE(rcs[i], sizeof(int) * fa->fa_nr);
	}
	if (rcs)
		OBD_FREE(rcs, sizeof(int *) * tgt_count);
out_fas:
	if (fas)
		OBD_FREE(fas, sizeof(fas) * tgt_count);

	RETURN(rc);
}

/**
 * Asynchronously set by key a value associated with a LMV device.
 *
 * Dispatch request to lower-layer devices as needed.
 *
 * \param[in] env	execution environment for this thread
 * \param[in] exp	export for the LMV device
 * \param[in] keylen	length of key identifier
 * \param[in] key	identifier of key to store value for
 * \param[in] vallen	size of value to store
 * \param[in] val	pointer to data to be stored
 * \param[in] set	optional list of related ptlrpc requests
 *
 * \retval 0		on success
 * \retval negative	negated errno on failure
 */
int lmv_set_info_async(const struct lu_env *env, struct obd_export *exp,
			__u32 keylen, void *key, __u32 vallen, void *val,
			struct ptlrpc_request_set *set)
{
	struct lmv_tgt_desc	*tgt = NULL;
	struct obd_device	*obd;
	struct lmv_obd		*lmv;
	int rc = 0;
	ENTRY;

	obd = class_exp2obd(exp);
	if (obd == NULL) {
		CDEBUG(D_IOCTL, "Invalid client cookie %#llx\n",
		       exp->exp_handle.h_cookie);
		RETURN(-EINVAL);
	}
	lmv = &obd->u.lmv;

	if (KEY_IS(KEY_READ_ONLY) || KEY_IS(KEY_FLUSH_CTX) ||
	    KEY_IS(KEY_DEFAULT_EASIZE)) {
		int i, err = 0;

		for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
			tgt = lmv->tgts[i];

			if (tgt == NULL || tgt->ltd_exp == NULL)
				continue;

			err = obd_set_info_async(env, tgt->ltd_exp,
						 keylen, key, vallen, val, set);
			if (err && rc == 0)
				rc = err;
		}

		RETURN(rc);
	}

	RETURN(-EINVAL);
}

static int lmv_unpack_md_v1(struct obd_export *exp, struct lmv_stripe_md *lsm,
			    const struct lmv_mds_md_v1 *lmm1)
{
	struct lmv_obd	*lmv = &exp->exp_obd->u.lmv;
	int		stripe_count;
	int		cplen;
	int		i;
	int		rc = 0;
	ENTRY;

	lsm->lsm_md_magic = le32_to_cpu(lmm1->lmv_magic);
	lsm->lsm_md_stripe_count = le32_to_cpu(lmm1->lmv_stripe_count);
	lsm->lsm_md_master_mdt_index = le32_to_cpu(lmm1->lmv_master_mdt_index);
	if (OBD_FAIL_CHECK(OBD_FAIL_UNKNOWN_LMV_STRIPE))
		lsm->lsm_md_hash_type = LMV_HASH_TYPE_UNKNOWN;
	else
		lsm->lsm_md_hash_type = le32_to_cpu(lmm1->lmv_hash_type);
	lsm->lsm_md_layout_version = le32_to_cpu(lmm1->lmv_layout_version);
	lsm->lsm_md_migrate_offset = le32_to_cpu(lmm1->lmv_migrate_offset);
	lsm->lsm_md_migrate_hash = le32_to_cpu(lmm1->lmv_migrate_hash);
	cplen = strlcpy(lsm->lsm_md_pool_name, lmm1->lmv_pool_name,
			sizeof(lsm->lsm_md_pool_name));

	if (cplen >= sizeof(lsm->lsm_md_pool_name))
		RETURN(-E2BIG);

	CDEBUG(D_INFO, "unpack lsm count %d, master %d hash_type %#x "
	       "layout_version %d\n", lsm->lsm_md_stripe_count,
	       lsm->lsm_md_master_mdt_index, lsm->lsm_md_hash_type,
	       lsm->lsm_md_layout_version);

	stripe_count = le32_to_cpu(lmm1->lmv_stripe_count);
	for (i = 0; i < stripe_count; i++) {
		fid_le_to_cpu(&lsm->lsm_md_oinfo[i].lmo_fid,
			      &lmm1->lmv_stripe_fids[i]);
		/*
		 * set default value -1, so lmv_locate_tgt() knows this stripe
		 * target is not initialized.
		 */
		lsm->lsm_md_oinfo[i].lmo_mds = (u32)-1;
		if (!fid_is_sane(&lsm->lsm_md_oinfo[i].lmo_fid))
			continue;

		rc = lmv_fld_lookup(lmv, &lsm->lsm_md_oinfo[i].lmo_fid,
				    &lsm->lsm_md_oinfo[i].lmo_mds);
		if (rc == -ENOENT)
			continue;

		if (rc)
			RETURN(rc);

		CDEBUG(D_INFO, "unpack fid #%d "DFID"\n", i,
		       PFID(&lsm->lsm_md_oinfo[i].lmo_fid));
	}

	RETURN(rc);
}

static int lmv_unpackmd(struct obd_export *exp, struct lmv_stripe_md **lsmp,
			const union lmv_mds_md *lmm, size_t lmm_size)
{
	struct lmv_stripe_md	 *lsm;
	int			 lsm_size;
	int			 rc;
	bool			 allocated = false;
	ENTRY;

	LASSERT(lsmp != NULL);

	lsm = *lsmp;
	/* Free memmd */
	if (lsm != NULL && lmm == NULL) {
		int i;

		for (i = 0; i < lsm->lsm_md_stripe_count; i++) {
			if (lsm->lsm_md_oinfo[i].lmo_root)
				iput(lsm->lsm_md_oinfo[i].lmo_root);
		}
		lsm_size = lmv_stripe_md_size(lsm->lsm_md_stripe_count);
		OBD_FREE(lsm, lsm_size);
		*lsmp = NULL;
		RETURN(0);
	}

	if (le32_to_cpu(lmm->lmv_magic) == LMV_MAGIC_STRIPE)
		RETURN(-EPERM);

	/* Unpack memmd */
	if (le32_to_cpu(lmm->lmv_magic) != LMV_MAGIC_V1 &&
	    le32_to_cpu(lmm->lmv_magic) != LMV_USER_MAGIC) {
		CERROR("%s: invalid lmv magic %x: rc = %d\n",
		       exp->exp_obd->obd_name, le32_to_cpu(lmm->lmv_magic),
		       -EIO);
		RETURN(-EIO);
	}

	if (le32_to_cpu(lmm->lmv_magic) == LMV_MAGIC_V1)
		lsm_size = lmv_stripe_md_size(lmv_mds_md_stripe_count_get(lmm));
	else
		/**
		 * Unpack default dirstripe(lmv_user_md) to lmv_stripe_md,
		 * stripecount should be 0 then.
		 */
		lsm_size = lmv_stripe_md_size(0);

	lsm_size = lmv_stripe_md_size(lmv_mds_md_stripe_count_get(lmm));
	if (lsm == NULL) {
		OBD_ALLOC(lsm, lsm_size);
		if (lsm == NULL)
			RETURN(-ENOMEM);
		allocated = true;
		*lsmp = lsm;
	}

	switch (le32_to_cpu(lmm->lmv_magic)) {
	case LMV_MAGIC_V1:
		rc = lmv_unpack_md_v1(exp, lsm, &lmm->lmv_md_v1);
		break;
	default:
		CERROR("%s: unrecognized magic %x\n", exp->exp_obd->obd_name,
		       le32_to_cpu(lmm->lmv_magic));
		rc = -EINVAL;
		break;
	}

	if (rc != 0 && allocated) {
		OBD_FREE(lsm, lsm_size);
		*lsmp = NULL;
		lsm_size = rc;
	}
	RETURN(lsm_size);
}

void lmv_free_memmd(struct lmv_stripe_md *lsm)
{
	lmv_unpackmd(NULL, &lsm, NULL, 0);
}
EXPORT_SYMBOL(lmv_free_memmd);

static int lmv_cancel_unused(struct obd_export *exp, const struct lu_fid *fid,
			     union ldlm_policy_data *policy,
			     enum ldlm_mode mode, enum ldlm_cancel_flags flags,
			     void *opaque)
{
	struct lmv_obd *lmv = &exp->exp_obd->u.lmv;
	int rc = 0;
	__u32 i;
	ENTRY;

	LASSERT(fid != NULL);

	for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
		struct lmv_tgt_desc *tgt = lmv->tgts[i];
		int err;

		if (tgt == NULL || tgt->ltd_exp == NULL || !tgt->ltd_active)
			continue;

		err = md_cancel_unused(tgt->ltd_exp, fid, policy, mode, flags,
				       opaque);
		if (!rc)
			rc = err;
	}
	RETURN(rc);
}

static int lmv_set_lock_data(struct obd_export *exp,
			     const struct lustre_handle *lockh,
			     void *data, __u64 *bits)
{
	struct lmv_obd		*lmv = &exp->exp_obd->u.lmv;
	struct lmv_tgt_desc	*tgt = lmv->tgts[0];
	int			 rc;
	ENTRY;

	if (tgt == NULL || tgt->ltd_exp == NULL)
		RETURN(-EINVAL);
	rc =  md_set_lock_data(tgt->ltd_exp, lockh, data, bits);
	RETURN(rc);
}

enum ldlm_mode lmv_lock_match(struct obd_export *exp, __u64 flags,
			      const struct lu_fid *fid, enum ldlm_type type,
			      union ldlm_policy_data *policy,
			      enum ldlm_mode mode, struct lustre_handle *lockh)
{
	struct obd_device	*obd = exp->exp_obd;
	struct lmv_obd		*lmv = &obd->u.lmv;
	enum ldlm_mode		rc;
	int			tgt;
	int			i;
	ENTRY;

	CDEBUG(D_INODE, "Lock match for "DFID"\n", PFID(fid));

        /*
	 * With DNE every object can have two locks in different namespaces:
	 * lookup lock in space of MDT storing direntry and update/open lock in
	 * space of MDT storing inode.  Try the MDT that the FID maps to first,
	 * since this can be easily found, and only try others if that fails.
	 */
	for (i = 0, tgt = lmv_find_target_index(lmv, fid);
	     i < lmv->desc.ld_tgt_count;
	     i++, tgt = (tgt + 1) % lmv->desc.ld_tgt_count) {
		if (tgt < 0) {
			CDEBUG(D_HA, "%s: "DFID" is inaccessible: rc = %d\n",
			       obd->obd_name, PFID(fid), tgt);
			tgt = 0;
		}

		if (lmv->tgts[tgt] == NULL ||
		    lmv->tgts[tgt]->ltd_exp == NULL ||
		    lmv->tgts[tgt]->ltd_active == 0)
			continue;

		rc = md_lock_match(lmv->tgts[tgt]->ltd_exp, flags, fid,
				   type, policy, mode, lockh);
		if (rc)
			RETURN(rc);
	}

	RETURN(0);
}

int lmv_get_lustre_md(struct obd_export *exp, struct ptlrpc_request *req,
		      struct obd_export *dt_exp, struct obd_export *md_exp,
		      struct lustre_md *md)
{
	struct lmv_obd          *lmv = &exp->exp_obd->u.lmv;
	struct lmv_tgt_desc	*tgt = lmv->tgts[0];

	if (tgt == NULL || tgt->ltd_exp == NULL)
		RETURN(-EINVAL);

	return md_get_lustre_md(lmv->tgts[0]->ltd_exp, req, dt_exp, md_exp, md);
}

int lmv_free_lustre_md(struct obd_export *exp, struct lustre_md *md)
{
	struct obd_device	*obd = exp->exp_obd;
	struct lmv_obd		*lmv = &obd->u.lmv;
	struct lmv_tgt_desc	*tgt = lmv->tgts[0];
	ENTRY;

	if (md->lmv != NULL) {
		lmv_free_memmd(md->lmv);
		md->lmv = NULL;
	}
	if (tgt == NULL || tgt->ltd_exp == NULL)
		RETURN(-EINVAL);
	RETURN(md_free_lustre_md(lmv->tgts[0]->ltd_exp, md));
}

int lmv_set_open_replay_data(struct obd_export *exp,
			     struct obd_client_handle *och,
			     struct lookup_intent *it)
{
	struct obd_device	*obd = exp->exp_obd;
	struct lmv_obd		*lmv = &obd->u.lmv;
	struct lmv_tgt_desc	*tgt;
	ENTRY;

	tgt = lmv_find_target(lmv, &och->och_fid);
	if (IS_ERR(tgt))
		RETURN(PTR_ERR(tgt));

	RETURN(md_set_open_replay_data(tgt->ltd_exp, och, it));
}

int lmv_clear_open_replay_data(struct obd_export *exp,
                               struct obd_client_handle *och)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_tgt_desc     *tgt;
        ENTRY;

        tgt = lmv_find_target(lmv, &och->och_fid);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        RETURN(md_clear_open_replay_data(tgt->ltd_exp, och));
}

int lmv_intent_getattr_async(struct obd_export *exp,
			     struct md_enqueue_info *minfo)
{
	struct md_op_data *op_data = &minfo->mi_data;
	struct obd_device *obd = exp->exp_obd;
	struct lmv_obd *lmv = &obd->u.lmv;
	struct lmv_tgt_desc *ptgt;
	struct lmv_tgt_desc *ctgt;
	int rc;

	ENTRY;

	if (!fid_is_sane(&op_data->op_fid2))
		RETURN(-EINVAL);

	ptgt = lmv_locate_tgt(lmv, op_data, &op_data->op_fid1);
	if (IS_ERR(ptgt))
		RETURN(PTR_ERR(ptgt));

	ctgt = lmv_find_target(lmv, &op_data->op_fid2);
	if (IS_ERR(ctgt))
		RETURN(PTR_ERR(ctgt));

	/* remote object needs two RPCs to lookup and getattr, considering the
	 * complexity, don't support statahead for now.
	 */
	if (ptgt != ctgt)
		RETURN(-EREMOTE);

	rc = md_intent_getattr_async(ptgt->ltd_exp, minfo);

	RETURN(rc);
}

int lmv_revalidate_lock(struct obd_export *exp, struct lookup_intent *it,
                        struct lu_fid *fid, __u64 *bits)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_tgt_desc     *tgt;
        int                      rc;
        ENTRY;

        tgt = lmv_find_target(lmv, fid);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        rc = md_revalidate_lock(tgt->ltd_exp, it, fid, bits);
        RETURN(rc);
}

int lmv_get_fid_from_lsm(struct obd_export *exp,
			 const struct lmv_stripe_md *lsm,
			 const char *name, int namelen, struct lu_fid *fid)
{
	const struct lmv_oinfo *oinfo;

	LASSERT(lsm != NULL);
	oinfo = lsm_name_to_stripe_info(lsm, name, namelen, false);
	if (IS_ERR(oinfo))
		return PTR_ERR(oinfo);

	*fid = oinfo->lmo_fid;

	RETURN(0);
}

/**
 * For lmv, only need to send request to master MDT, and the master MDT will
 * process with other slave MDTs. The only exception is Q_GETOQUOTA for which
 * we directly fetch data from the slave MDTs.
 */
int lmv_quotactl(struct obd_device *unused, struct obd_export *exp,
		 struct obd_quotactl *oqctl)
{
	struct obd_device   *obd = class_exp2obd(exp);
	struct lmv_obd      *lmv = &obd->u.lmv;
	struct lmv_tgt_desc *tgt = lmv->tgts[0];
	int                  rc = 0;
	__u32                i;
	__u64                curspace, curinodes;
	ENTRY;

	if (tgt == NULL ||
	    tgt->ltd_exp == NULL ||
	    !tgt->ltd_active ||
	    lmv->desc.ld_tgt_count == 0) {
		CERROR("master lmv inactive\n");
		RETURN(-EIO);
	}

        if (oqctl->qc_cmd != Q_GETOQUOTA) {
                rc = obd_quotactl(tgt->ltd_exp, oqctl);
                RETURN(rc);
        }

        curspace = curinodes = 0;
        for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
		int err;
		tgt = lmv->tgts[i];

		if (tgt == NULL || tgt->ltd_exp == NULL || !tgt->ltd_active)
			continue;

                err = obd_quotactl(tgt->ltd_exp, oqctl);
                if (err) {
                        CERROR("getquota on mdt %d failed. %d\n", i, err);
                        if (!rc)
                                rc = err;
                } else {
                        curspace += oqctl->qc_dqblk.dqb_curspace;
                        curinodes += oqctl->qc_dqblk.dqb_curinodes;
                }
        }
        oqctl->qc_dqblk.dqb_curspace = curspace;
        oqctl->qc_dqblk.dqb_curinodes = curinodes;

        RETURN(rc);
}

static int lmv_merge_attr(struct obd_export *exp,
			  const struct lmv_stripe_md *lsm,
			  struct cl_attr *attr,
			  ldlm_blocking_callback cb_blocking)
{
	int rc;
	int i;

	rc = lmv_revalidate_slaves(exp, lsm, cb_blocking, 0);
	if (rc < 0)
		return rc;

	for (i = 0; i < lsm->lsm_md_stripe_count; i++) {
		struct inode *inode = lsm->lsm_md_oinfo[i].lmo_root;

		if (!inode)
			continue;

		CDEBUG(D_INFO,
		       "" DFID " size %llu, blocks %llu nlink %u, atime %lld ctime %lld, mtime %lld.\n",
		       PFID(&lsm->lsm_md_oinfo[i].lmo_fid),
		       i_size_read(inode), (unsigned long long)inode->i_blocks,
		       inode->i_nlink, (s64)inode->i_atime.tv_sec,
		       (s64)inode->i_ctime.tv_sec, (s64)inode->i_mtime.tv_sec);

		/* for slave stripe, it needs to subtract nlink for . and .. */
		if (i != 0)
			attr->cat_nlink += inode->i_nlink - 2;
		else
			attr->cat_nlink = inode->i_nlink;

		attr->cat_size += i_size_read(inode);
		attr->cat_blocks += inode->i_blocks;

		if (attr->cat_atime < inode->i_atime.tv_sec)
			attr->cat_atime = inode->i_atime.tv_sec;

		if (attr->cat_ctime < inode->i_ctime.tv_sec)
			attr->cat_ctime = inode->i_ctime.tv_sec;

		if (attr->cat_mtime < inode->i_mtime.tv_sec)
			attr->cat_mtime = inode->i_mtime.tv_sec;
	}
	return 0;
}

struct obd_ops lmv_obd_ops = {
        .o_owner                = THIS_MODULE,
        .o_setup                = lmv_setup,
        .o_cleanup              = lmv_cleanup,
        .o_precleanup           = lmv_precleanup,
        .o_process_config       = lmv_process_config,
        .o_connect              = lmv_connect,
        .o_disconnect           = lmv_disconnect,
        .o_statfs               = lmv_statfs,
        .o_get_info             = lmv_get_info,
        .o_set_info_async       = lmv_set_info_async,
        .o_notify               = lmv_notify,
        .o_get_uuid             = lmv_get_uuid,
        .o_iocontrol            = lmv_iocontrol,
        .o_quotactl             = lmv_quotactl
};

struct md_ops lmv_md_ops = {
	.m_get_root		= lmv_get_root,
        .m_null_inode		= lmv_null_inode,
        .m_close                = lmv_close,
        .m_create               = lmv_create,
        .m_enqueue              = lmv_enqueue,
        .m_getattr              = lmv_getattr,
        .m_getxattr             = lmv_getxattr,
        .m_getattr_name         = lmv_getattr_name,
        .m_intent_lock          = lmv_intent_lock,
        .m_link                 = lmv_link,
        .m_rename               = lmv_rename,
        .m_setattr              = lmv_setattr,
        .m_setxattr             = lmv_setxattr,
	.m_fsync		= lmv_fsync,
	.m_file_resync		= lmv_file_resync,
	.m_read_page		= lmv_read_page,
        .m_unlink               = lmv_unlink,
        .m_init_ea_size         = lmv_init_ea_size,
        .m_cancel_unused        = lmv_cancel_unused,
        .m_set_lock_data        = lmv_set_lock_data,
        .m_lock_match           = lmv_lock_match,
	.m_get_lustre_md        = lmv_get_lustre_md,
	.m_free_lustre_md       = lmv_free_lustre_md,
	.m_merge_attr		= lmv_merge_attr,
        .m_set_open_replay_data = lmv_set_open_replay_data,
        .m_clear_open_replay_data = lmv_clear_open_replay_data,
        .m_intent_getattr_async = lmv_intent_getattr_async,
	.m_revalidate_lock      = lmv_revalidate_lock,
	.m_get_fid_from_lsm	= lmv_get_fid_from_lsm,
	.m_unpackmd		= lmv_unpackmd,
	.m_rmfid		= lmv_rmfid,
};

static int __init lmv_init(void)
{
	return class_register_type(&lmv_obd_ops, &lmv_md_ops, true, NULL,
				   LUSTRE_LMV_NAME, NULL);
}

static void __exit lmv_exit(void)
{
	class_unregister_type(LUSTRE_LMV_NAME);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Logical Metadata Volume");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(lmv_init);
module_exit(lmv_exit);
