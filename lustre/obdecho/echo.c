/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, Intel Corporation.
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

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

#define ECHO_PERSISTENT_PAGES (ECHO_PERSISTENT_SIZE >> CFS_PAGE_SHIFT)
static cfs_page_t *echo_persistent_pages[ECHO_PERSISTENT_PAGES];

enum {
        LPROC_ECHO_READ_BYTES = 1,
        LPROC_ECHO_WRITE_BYTES = 2,
        LPROC_ECHO_LAST = LPROC_ECHO_WRITE_BYTES +1
};

static int echo_connect(const struct lu_env *env,
                        struct obd_export **exp, struct obd_device *obd,
                        struct obd_uuid *cluuid, struct obd_connect_data *data,
                        void *localdata)
{
        struct lustre_handle conn = { 0 };
        int rc;

        data->ocd_connect_flags &= ECHO_CONNECT_SUPPORTED;
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

 static __u64 echo_next_id(struct obd_device *obddev)
{
        obd_id id;

        cfs_spin_lock(&obddev->u.echo.eo_lock);
        id = ++obddev->u.echo.eo_lastino;
        cfs_spin_unlock(&obddev->u.echo.eo_lock);

        return id;
}

int echo_create(struct obd_export *exp, struct obdo *oa,
                struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct obd_device *obd = class_exp2obd(exp);

        if (!obd) {
                CERROR("invalid client cookie "LPX64"\n",
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }

        if (!(oa->o_mode && S_IFMT)) {
                CERROR("echo obd: no type!\n");
                return -ENOENT;
        }

        if (!(oa->o_valid & OBD_MD_FLTYPE)) {
                CERROR("invalid o_valid "LPX64"\n", oa->o_valid);
                return -EINVAL;
        }

        oa->o_id = echo_next_id(obd);
        oa->o_valid = OBD_MD_FLID;

        return 0;
}

int echo_destroy(struct obd_export *exp, struct obdo *oa,
                 struct lov_stripe_md *ea, struct obd_trans_info *oti,
                 struct obd_export *md_exp, void *capa)
{
        struct obd_device *obd = class_exp2obd(exp);

        ENTRY;
        if (!obd) {
                CERROR("invalid client cookie "LPX64"\n",
                       exp->exp_handle.h_cookie);
                RETURN(-EINVAL);
        }

        if (!(oa->o_valid & OBD_MD_FLID)) {
                CERROR("obdo missing FLID valid flag: "LPX64"\n", oa->o_valid);
                RETURN(-EINVAL);
        }

        if (oa->o_id > obd->u.echo.eo_lastino || oa->o_id < ECHO_INIT_OID) {
                CERROR("bad destroy objid: "LPX64"\n", oa->o_id);
                RETURN(-EINVAL);
        }

        RETURN(0);
}

static int echo_getattr(struct obd_export *exp, struct obd_info *oinfo)
{
        struct obd_device *obd = class_exp2obd(exp);
        obd_id id = oinfo->oi_oa->o_id;

        ENTRY;
        if (!obd) {
                CERROR("invalid client cookie "LPX64"\n",
                       exp->exp_handle.h_cookie);
                RETURN(-EINVAL);
        }

        if (!(oinfo->oi_oa->o_valid & OBD_MD_FLID)) {
                CERROR("obdo missing FLID valid flag: "LPX64"\n",
                       oinfo->oi_oa->o_valid);
                RETURN(-EINVAL);
        }

        obdo_cpy_md(oinfo->oi_oa, &obd->u.echo.eo_oa, oinfo->oi_oa->o_valid);
        oinfo->oi_oa->o_id = id;

        RETURN(0);
}

static int echo_setattr(struct obd_export *exp, struct obd_info *oinfo,
                        struct obd_trans_info *oti)
{
        struct obd_device *obd = class_exp2obd(exp);

        ENTRY;
        if (!obd) {
                CERROR("invalid client cookie "LPX64"\n",
                       exp->exp_handle.h_cookie);
                RETURN(-EINVAL);
        }

        if (!(oinfo->oi_oa->o_valid & OBD_MD_FLID)) {
                CERROR("obdo missing FLID valid flag: "LPX64"\n",
                       oinfo->oi_oa->o_valid);
                RETURN(-EINVAL);
        }

        memcpy(&obd->u.echo.eo_oa, oinfo->oi_oa, sizeof(*oinfo->oi_oa));

        if (oinfo->oi_oa->o_id & 4) {
                /* Save lock to force ACKed reply */
                ldlm_lock_addref (&obd->u.echo.eo_nl_lock, LCK_NL);
                oti->oti_ack_locks[0].mode = LCK_NL;
                oti->oti_ack_locks[0].lock = obd->u.echo.eo_nl_lock;
        }

        RETURN(0);
}

static void
echo_page_debug_setup(cfs_page_t *page, int rw, obd_id id,
                      __u64 offset, int len)
{
        int   page_offset = offset & ~CFS_PAGE_MASK;
        char *addr        = ((char *)cfs_kmap(page)) + page_offset;

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

        cfs_kunmap(page);
}

static int
echo_page_debug_check(cfs_page_t *page, obd_id id,
                      __u64 offset, int len)
{
        int   page_offset = offset & ~CFS_PAGE_MASK;
        char *addr        = ((char *)cfs_kmap(page)) + page_offset;
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

        cfs_kunmap(page);

        return (rc);
}

/* This allows us to verify that desc_private is passed unmolested */
#define DESC_PRIV 0x10293847

static int echo_map_nb_to_lb(struct obdo *oa, struct obd_ioobj *obj,
                             struct niobuf_remote *nb, int *pages,
                             struct niobuf_local *lb, int cmd, int *left)
{
        int gfp_mask = (obj->ioo_id & 1) ? CFS_ALLOC_HIGHUSER : CFS_ALLOC_STD;
        int ispersistent = obj->ioo_id == ECHO_PERSISTENT_OBJID;
        int debug_setup = (!ispersistent &&
                           (oa->o_valid & OBD_MD_FLFLAGS) != 0 &&
                           (oa->o_flags & OBD_FL_DEBUG_CHECK) != 0);
        struct niobuf_local *res = lb;
        obd_off offset = nb->offset;
        int len = nb->len;

        while (len > 0) {
                int plen = CFS_PAGE_SIZE - (offset & (CFS_PAGE_SIZE-1));
                if (len < plen)
                        plen = len;

                /* check for local buf overflow */
                if (*left == 0)
                        return -EINVAL;

                res->offset = offset;
                res->len = plen;
                LASSERT((res->offset & ~CFS_PAGE_MASK) + res->len <= CFS_PAGE_SIZE);


                if (ispersistent &&
                    (res->offset >> CFS_PAGE_SHIFT) < ECHO_PERSISTENT_PAGES) {
                        res->page = echo_persistent_pages[res->offset >>
                                CFS_PAGE_SHIFT];
                        /* Take extra ref so __free_pages() can be called OK */
                        cfs_get_page (res->page);
                } else {
                        OBD_PAGE_ALLOC(res->page, gfp_mask);
                        if (res->page == NULL) {
                                CERROR("can't get page for id " LPU64"\n",
                                       obj->ioo_id);
                                return -ENOMEM;
                        }
                }

                CDEBUG(D_PAGE, "$$$$ get page %p @ "LPU64" for %d\n",
                       res->page, res->offset, res->len);

                if (cmd & OBD_BRW_READ)
                        res->rc = res->len;

                if (debug_setup)
                        echo_page_debug_setup(res->page, cmd, obj->ioo_id,
                                              res->offset, res->len);

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
        obd_off start  = rb->offset >> CFS_PAGE_SHIFT;
        obd_off end    = (rb->offset + rb->len + CFS_PAGE_SIZE - 1) >> CFS_PAGE_SHIFT;
        int     count  = (int)(end - start);
        int     rc     = 0;
        int     i;

        for (i = 0; i < count; i++, (*pgs) ++, res++) {
                cfs_page_t *page = res->page;
                void       *addr;

                if (page == NULL) {
                        CERROR("null page objid "LPU64":%p, buf %d/%d\n",
                               obj->ioo_id, page, i, obj->ioo_bufcnt);
                        return -EFAULT;
                }

                addr = cfs_kmap(page);

                CDEBUG(D_PAGE, "$$$$ use page %p, addr %p@"LPU64"\n",
                       res->page, addr, res->offset);

                if (verify) {
                        int vrc = echo_page_debug_check(page, obj->ioo_id,
                                                        res->offset, res->len);
                        /* check all the pages always */
                        if (vrc != 0 && rc == 0)
                                rc = vrc;
                }

                cfs_kunmap(page);
                /* NB see comment above regarding persistent pages */
                OBD_PAGE_FREE(page);
        }

        return rc;
}

int echo_preprw(int cmd, struct obd_export *export, struct obdo *oa,
                int objcount, struct obd_ioobj *obj, struct niobuf_remote *nb,
                int *pages, struct niobuf_local *res,
                struct obd_trans_info *oti, struct lustre_capa *unused)
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

        if (oti)
                oti->oti_handle = (void *)DESC_PRIV;

        left = *pages;
        *pages = 0;

        for (i = 0; i < objcount; i++, obj++) {
                int j;

                for (j = 0 ; j < obj->ioo_bufcnt ; j++, nb++) {

                        rc = echo_map_nb_to_lb(oa, obj, nb, pages,
                                               res + *pages, cmd, &left);
                        if (rc)
                                GOTO(preprw_cleanup, rc);

                        tot_bytes += nb->len;
                }
        }

        cfs_atomic_add(*pages, &obd->u.echo.eo_prep);

        if (cmd & OBD_BRW_READ)
                lprocfs_counter_add(obd->obd_stats, LPROC_ECHO_READ_BYTES,
                                    tot_bytes);
        else
                lprocfs_counter_add(obd->obd_stats, LPROC_ECHO_WRITE_BYTES,
                                    tot_bytes);

        CDEBUG(D_PAGE, "%d pages allocated after prep\n",
               cfs_atomic_read(&obd->u.echo.eo_prep));

        RETURN(0);

preprw_cleanup:
        /* It is possible that we would rather handle errors by  allow
         * any already-set-up pages to complete, rather than tearing them
         * all down again.  I believe that this is what the in-kernel
         * prep/commit operations do.
         */
        CERROR("cleaning up %u pages (%d obdos)\n", *pages, objcount);
        for (i = 0; i < *pages; i++) {
                cfs_kunmap(res[i].page);
                /* NB if this is a persistent page, __free_pages will just
                 * lose the extra ref gained above */
                OBD_PAGE_FREE(res[i].page);
                res[i].page = NULL;
                cfs_atomic_dec(&obd->u.echo.eo_prep);
        }

        return rc;
}

int echo_commitrw(int cmd, struct obd_export *export, struct obdo *oa,
                  int objcount, struct obd_ioobj *obj,
                  struct niobuf_remote *rb, int niocount,
                  struct niobuf_local *res, struct obd_trans_info *oti, int rc)
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

        LASSERT(oti == NULL || oti->oti_handle == (void *)DESC_PRIV);

        for (i = 0; i < objcount; i++, obj++) {
                int verify = (rc == 0 &&
                              obj->ioo_id != ECHO_PERSISTENT_OBJID &&
                              (oa->o_valid & OBD_MD_FLFLAGS) != 0 &&
                              (oa->o_flags & OBD_FL_DEBUG_CHECK) != 0);
                int j;

                for (j = 0 ; j < obj->ioo_bufcnt ; j++, rb++) {
                        int vrc = echo_finalize_lb(oa, obj, rb, &pgs, &res[pgs], verify);

                        if (vrc == 0)
                                continue;

                        if (vrc == -EFAULT)
                                GOTO(commitrw_cleanup, rc = vrc);

                        if (rc == 0)
                                rc = vrc;
                }

        }

        cfs_atomic_sub(pgs, &obd->u.echo.eo_prep);

        CDEBUG(D_PAGE, "%d pages remain after commit\n",
               cfs_atomic_read(&obd->u.echo.eo_prep));
        RETURN(rc);

commitrw_cleanup:
        cfs_atomic_sub(pgs, &obd->u.echo.eo_prep);

        CERROR("cleaning up %d pages (%d obdos)\n",
               niocount - pgs - 1, objcount);

        while (pgs < niocount) {
                cfs_page_t *page = res[pgs++].page;

                if (page == NULL)
                        continue;

                /* NB see comment above regarding persistent pages */
                OBD_PAGE_FREE(page);
                cfs_atomic_dec(&obd->u.echo.eo_prep);
        }
        return rc;
}

static int echo_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        struct lprocfs_static_vars lvars;
        int                        rc;
        int                        lock_flags = 0;
        struct ldlm_res_id         res_id = {.name = {1}};
        char                       ns_name[48];
        ENTRY;

        cfs_spin_lock_init(&obd->u.echo.eo_lock);
        obd->u.echo.eo_lastino = ECHO_INIT_OID;

        sprintf(ns_name, "echotgt-%s", obd->obd_uuid.uuid);
        obd->obd_namespace = ldlm_namespace_new(obd, ns_name,
                                                LDLM_NAMESPACE_SERVER,
                                                LDLM_NAMESPACE_MODEST,
                                                LDLM_NS_TYPE_OST);
        if (obd->obd_namespace == NULL) {
                LBUG();
                RETURN(-ENOMEM);
        }

        rc = ldlm_cli_enqueue_local(obd->obd_namespace, &res_id, LDLM_PLAIN,
                                    NULL, LCK_NL, &lock_flags, NULL,
                                    ldlm_completion_ast, NULL, NULL, 0, NULL,
                                    &obd->u.echo.eo_nl_lock);
        LASSERT (rc == ELDLM_OK);

        lprocfs_echo_init_vars(&lvars);
        if (lprocfs_obd_setup(obd, lvars.obd_vars) == 0 &&
            lprocfs_alloc_obd_stats(obd, LPROC_ECHO_LAST) == 0) {
                lprocfs_counter_init(obd->obd_stats, LPROC_ECHO_READ_BYTES,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "read_bytes", "bytes");
                lprocfs_counter_init(obd->obd_stats, LPROC_ECHO_WRITE_BYTES,
                                     LPROCFS_CNTR_AVGMINMAX,
                                     "write_bytes", "bytes");
        }

        ptlrpc_init_client (LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                            "echo_ldlm_cb_client", &obd->obd_ldlm_client);
        RETURN(0);
}

static int echo_cleanup(struct obd_device *obd)
{
        int leaked;
        ENTRY;

        lprocfs_obd_cleanup(obd);
        lprocfs_free_obd_stats(obd);

        ldlm_lock_decref(&obd->u.echo.eo_nl_lock, LCK_NL);

        /* XXX Bug 3413; wait for a bit to ensure the BL callback has
         * happened before calling ldlm_namespace_free() */
        cfs_schedule_timeout_and_set_state(CFS_TASK_UNINT, cfs_time_seconds(1));

        ldlm_namespace_free(obd->obd_namespace, NULL, obd->obd_force);
        obd->obd_namespace = NULL;

        leaked = cfs_atomic_read(&obd->u.echo.eo_prep);
        if (leaked != 0)
                CERROR("%d prep/commitrw pages leaked\n", leaked);

        RETURN(0);
}

static struct obd_ops echo_obd_ops = {
        .o_owner           = THIS_MODULE,
        .o_connect         = echo_connect,
        .o_disconnect      = echo_disconnect,
        .o_init_export     = echo_init_export,
        .o_destroy_export  = echo_destroy_export,
        .o_create          = echo_create,
        .o_destroy         = echo_destroy,
        .o_getattr         = echo_getattr,
        .o_setattr         = echo_setattr,
        .o_preprw          = echo_preprw,
        .o_commitrw        = echo_commitrw,
        .o_setup           = echo_setup,
        .o_cleanup         = echo_cleanup
};

extern int echo_client_init(void);
extern void echo_client_exit(void);

static void
echo_persistent_pages_fini (void)
{
        int     i;

        for (i = 0; i < ECHO_PERSISTENT_PAGES; i++)
                if (echo_persistent_pages[i] != NULL) {
                        OBD_PAGE_FREE(echo_persistent_pages[i]);
                        echo_persistent_pages[i] = NULL;
                }
}

static int
echo_persistent_pages_init (void)
{
        cfs_page_t *pg;
        int          i;

        for (i = 0; i < ECHO_PERSISTENT_PAGES; i++) {
                int gfp_mask = (i < ECHO_PERSISTENT_PAGES/2) ?
                        CFS_ALLOC_STD : CFS_ALLOC_HIGHUSER;

                OBD_PAGE_ALLOC(pg, gfp_mask);
                if (pg == NULL) {
                        echo_persistent_pages_fini ();
                        return (-ENOMEM);
                }

                memset (cfs_kmap (pg), 0, CFS_PAGE_SIZE);
                cfs_kunmap (pg);

                echo_persistent_pages[i] = pg;
        }

        return (0);
}

static int __init obdecho_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;

        ENTRY;
        LCONSOLE_INFO("Echo OBD driver; http://www.lustre.org/\n");

        LASSERT(CFS_PAGE_SIZE % OBD_ECHO_BLOCK_SIZE == 0);

        lprocfs_echo_init_vars(&lvars);

        rc = echo_persistent_pages_init ();
        if (rc != 0)
                goto failed_0;

        rc = class_register_type(&echo_obd_ops, NULL, lvars.module_vars,
                                 LUSTRE_ECHO_NAME, NULL);
        if (rc != 0)
                goto failed_1;

        rc = echo_client_init();
        if (rc == 0)
                RETURN (0);

        class_unregister_type(LUSTRE_ECHO_NAME);
 failed_1:
        echo_persistent_pages_fini ();
 failed_0:
        RETURN(rc);
}

static void /*__exit*/ obdecho_exit(void)
{
        echo_client_exit();
        class_unregister_type(LUSTRE_ECHO_NAME);
        echo_persistent_pages_fini ();
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Testing Echo OBD driver");
MODULE_LICENSE("GPL");

cfs_module(obdecho, "1.0.0", obdecho_init, obdecho_exit);
