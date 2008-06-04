/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_ECHO

#include <obd_support.h>
#include <obd_class.h>
#include <obd_echo.h>
#include <lustre_debug.h>
#include <lustre_dlm.h>
#include <lprocfs_status.h>

#define ECHO_INIT_OBJID      0x1000000000000000ULL
#define ECHO_HANDLE_MAGIC    0xabcd0123fedc9876ULL

#define ECHO_PERSISTENT_PAGES (ECHO_PERSISTENT_SIZE >> CFS_PAGE_SHIFT)
static cfs_page_t *echo_persistent_pages[ECHO_PERSISTENT_PAGES];

enum {
        LPROC_ECHO_READ_BYTES = 1,
        LPROC_ECHO_WRITE_BYTES = 2,
        LPROC_ECHO_LAST = LPROC_ECHO_WRITE_BYTES +1
};

static int echo_connect(const struct lu_env *env,
                        struct lustre_handle *conn, struct obd_device *obd,
                        struct obd_uuid *cluuid, struct obd_connect_data *data,
                        void *localdata)
{
        data->ocd_connect_flags &= ECHO_CONNECT_SUPPORTED;
        return class_connect(conn, obd, cluuid);
}

static int echo_disconnect(struct obd_export *exp)
{
        LASSERT (exp != NULL);

        ldlm_cancel_locks_for_export(exp);

        /* complete all outstanding replies */
        spin_lock(&exp->exp_lock);
        while (!list_empty(&exp->exp_outstanding_replies)) {
                struct ptlrpc_reply_state *rs =
                        list_entry(exp->exp_outstanding_replies.next,
                                   struct ptlrpc_reply_state, rs_exp_list);
                struct ptlrpc_service *svc = rs->rs_service;

                spin_lock(&svc->srv_lock);
                list_del_init(&rs->rs_exp_list);
                ptlrpc_schedule_difficult_reply(rs);
                spin_unlock(&svc->srv_lock);
        }
        spin_unlock(&exp->exp_lock);

        return class_disconnect(exp);
}

static int echo_destroy_export(struct obd_export *exp)
{
        ENTRY;

        target_destroy_export(exp);

        RETURN(0);
}

 static __u64 echo_next_id(struct obd_device *obddev)
{
        obd_id id;

        spin_lock(&obddev->u.echo.eo_lock);
        id = ++obddev->u.echo.eo_lastino;
        spin_unlock(&obddev->u.echo.eo_lock);

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
                 struct obd_export *md_exp)
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

        if (oa->o_id > obd->u.echo.eo_lastino || oa->o_id < ECHO_INIT_OBJID) {
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

int echo_preprw(int cmd, struct obd_export *export, struct obdo *oa,
                int objcount, struct obd_ioobj *obj, int niocount,
                struct niobuf_remote *nb, struct niobuf_local *res,
                struct obd_trans_info *oti, struct lustre_capa *unused)
{
        struct obd_device *obd;
        struct niobuf_local *r = res;
        int tot_bytes = 0;
        int rc = 0;
        int i;
        ENTRY;

        obd = export->exp_obd;
        if (obd == NULL)
                RETURN(-EINVAL);

        /* Temp fix to stop falling foul of osc_announce_cached() */
        oa->o_valid &= ~(OBD_MD_FLBLOCKS | OBD_MD_FLGRANT);

        memset(res, 0, sizeof(*res) * niocount);

        CDEBUG(D_PAGE, "%s %d obdos with %d IOs\n",
               cmd == OBD_BRW_READ ? "reading" : "writing", objcount, niocount);

        if (oti)
                oti->oti_handle = (void *)DESC_PRIV;

        for (i = 0; i < objcount; i++, obj++) {
                int gfp_mask = (obj->ioo_id & 1) ? CFS_ALLOC_HIGHUSER : CFS_ALLOC_STD;
                int ispersistent = obj->ioo_id == ECHO_PERSISTENT_OBJID;
                int debug_setup = (!ispersistent &&
                                   (oa->o_valid & OBD_MD_FLFLAGS) != 0 &&
                                   (oa->o_flags & OBD_FL_DEBUG_CHECK) != 0);
                int j;

                for (j = 0 ; j < obj->ioo_bufcnt ; j++, nb++, r++) {

                        if (ispersistent &&
                            (nb->offset >> CFS_PAGE_SHIFT) < ECHO_PERSISTENT_PAGES) {
                                r->page = echo_persistent_pages[nb->offset >>
                                                                CFS_PAGE_SHIFT];
                                /* Take extra ref so __free_pages() can be called OK */
                                cfs_get_page (r->page);
                        } else {
                                OBD_PAGE_ALLOC(r->page, gfp_mask);
                                if (r->page == NULL) {
                                        CERROR("can't get page %u/%u for id "
                                               LPU64"\n",
                                               j, obj->ioo_bufcnt, obj->ioo_id);
                                        GOTO(preprw_cleanup, rc = -ENOMEM);
                                }
                        }

                        tot_bytes += nb->len;

                        atomic_inc(&obd->u.echo.eo_prep);

                        r->offset = nb->offset;
                        r->len = nb->len;
                        LASSERT((r->offset & ~CFS_PAGE_MASK) + r->len <= CFS_PAGE_SIZE);

                        CDEBUG(D_PAGE, "$$$$ get page %p @ "LPU64" for %d\n",
                               r->page, r->offset, r->len);

                        if (cmd & OBD_BRW_READ)
                                r->rc = r->len;

                        if (debug_setup)
                                echo_page_debug_setup(r->page, cmd, obj->ioo_id,
                                                      r->offset, r->len);
                }
        }
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
        CERROR("cleaning up %ld pages (%d obdos)\n", (long)(r - res), objcount);
        while (r-- > res) {
                cfs_kunmap(r->page);
                /* NB if this is a persistent page, __free_pages will just
                 * lose the extra ref gained above */
                OBD_PAGE_FREE(r->page);
                atomic_dec(&obd->u.echo.eo_prep);
        }
        memset(res, 0, sizeof(*res) * niocount);

        return rc;
}

int echo_commitrw(int cmd, struct obd_export *export, struct obdo *oa,
                  int objcount, struct obd_ioobj *obj, int niocount,
                  struct niobuf_local *res, struct obd_trans_info *oti, int rc)
{
        struct obd_device *obd;
        struct niobuf_local *r = res;
        int i, vrc = 0;
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

        if (niocount && !r) {
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

                for (j = 0 ; j < obj->ioo_bufcnt ; j++, r++) {
                        cfs_page_t *page = r->page;
                        void *addr;

                        if (page == NULL) {
                                CERROR("null page objid "LPU64":%p, buf %d/%d\n",
                                       obj->ioo_id, page, j, obj->ioo_bufcnt);
                                GOTO(commitrw_cleanup, rc = -EFAULT);
                        }

                        addr = cfs_kmap(page);

                        CDEBUG(D_PAGE, "$$$$ use page %p, addr %p@"LPU64"\n",
                               r->page, addr, r->offset);

                        if (verify) {
                                vrc = echo_page_debug_check(page, obj->ioo_id,
                                                            r->offset, r->len);
                                /* check all the pages always */
                                if (vrc != 0 && rc == 0)
                                        rc = vrc;
                        }

                        cfs_kunmap(page);
                        /* NB see comment above regarding persistent pages */
                        OBD_PAGE_FREE(page);
                        atomic_dec(&obd->u.echo.eo_prep);
                }
        }
        CDEBUG(D_PAGE, "%d pages remain after commit\n",
               atomic_read(&obd->u.echo.eo_prep));
        RETURN(rc);

commitrw_cleanup:
        CERROR("cleaning up %ld pages (%d obdos)\n",
               niocount - (long)(r - res) - 1, objcount);
        while (++r < res + niocount) {
                cfs_page_t *page = r->page;

                /* NB see comment above regarding persistent pages */
                OBD_PAGE_FREE(page);
                atomic_dec(&obd->u.echo.eo_prep);
        }
        return rc;
}

static int echo_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        struct lprocfs_static_vars lvars;
        int                        rc;
        int                        lock_flags = 0;
        struct ldlm_res_id         res_id = {.name = {1}};
        ENTRY;

        spin_lock_init(&obd->u.echo.eo_lock);
        obd->u.echo.eo_lastino = ECHO_INIT_OBJID;

        obd->obd_namespace = ldlm_namespace_new(obd, "echo-tgt",
                                                LDLM_NAMESPACE_SERVER,
                                                LDLM_NAMESPACE_MODEST);
        if (obd->obd_namespace == NULL) {
                LBUG();
                RETURN(-ENOMEM);
        }

        rc = ldlm_cli_enqueue_local(obd->obd_namespace, &res_id, LDLM_PLAIN,
                                    NULL, LCK_NL, &lock_flags, NULL,
                                    ldlm_completion_ast, NULL, NULL,
                                    0, NULL, &obd->u.echo.eo_nl_lock);
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

        ldlm_lock_decref (&obd->u.echo.eo_nl_lock, LCK_NL);

        /* XXX Bug 3413; wait for a bit to ensure the BL callback has
         * happened before calling ldlm_namespace_free() */
        set_current_state (TASK_UNINTERRUPTIBLE);
        cfs_schedule_timeout (CFS_TASK_UNINT, cfs_time_seconds(1));

        ldlm_namespace_free(obd->obd_namespace, NULL, obd->obd_force);
        obd->obd_namespace = NULL;

        leaked = atomic_read(&obd->u.echo.eo_prep);
        if (leaked != 0)
                CERROR("%d prep/commitrw pages leaked\n", leaked);

        RETURN(0);
}

static struct obd_ops echo_obd_ops = {
        .o_owner           = THIS_MODULE,
        .o_connect         = echo_connect,
        .o_disconnect      = echo_disconnect,
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
        printk(KERN_INFO "Lustre: Echo OBD driver; info@clusterfs.com\n");

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

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Testing Echo OBD driver");
MODULE_LICENSE("GPL");

cfs_module(obdecho, "1.0.0", obdecho_init, obdecho_exit);
