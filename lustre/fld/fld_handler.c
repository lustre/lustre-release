/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/fld/fld_handler.c
 *  FLD (Fids Location Database)
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: WangDi <wangdi@clusterfs.com>
 *           Yury Umanets <umka@clusterfs.com>
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
#define DEBUG_SUBSYSTEM S_FLD

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
# include <linux/module.h>
# include <linux/jbd.h>
# include <asm/div64.h>
#else /* __KERNEL__ */
# include <liblustre.h>
# include <libcfs/list.h>
#endif

#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <lprocfs_status.h>

#include <dt_object.h>
#include <md_object.h>
#include <lustre_req_layout.h>
#include <lustre_fld.h>
#include "fld_internal.h"

#ifdef __KERNEL__
struct fld_cache_info *fld_cache = NULL;

static int fld_init(void)
{
        int rc = 0;
        ENTRY;
        
        fld_cache = fld_cache_init(FLD_HTABLE_SIZE);
        if (IS_ERR(fld_cache))
                rc = PTR_ERR(fld_cache);

        if (rc != 0)
                fld_cache = NULL;
        
        RETURN(rc);
}

static void fld_fini(void)
{
        ENTRY;
        if (fld_cache != NULL) {
                fld_cache_fini(fld_cache);
                fld_cache = NULL;
        }
        EXIT;
}

static int __init fld_mod_init(void)
{
        fld_init();
        return 0;
}

static void __exit fld_mod_exit(void)
{
        fld_fini();
        return;
}

/* insert index entry and update cache */
int
fld_server_create(struct lu_server_fld *fld,
                  const struct lu_context *ctx,
                  __u64 seq, mdsno_t mds)
{
        int rc;
        ENTRY;
        
        rc = fld_index_create(fld, ctx, seq, mds);
        if (rc == 0) {
                /* do not return result of calling fld_cache_insert()
                 * here. First of all because it may return -EEXISTS. Another
                 * reason is that, we do not want to stop proceeding because of
                 * cache errors. --umka */
                fld_cache_insert(fld_cache, seq, mds);
        }
        RETURN(rc);
}
EXPORT_SYMBOL(fld_server_create);

/* delete index entry and update cache */
int
fld_server_delete(struct lu_server_fld *fld,
                  const struct lu_context *ctx,
                  __u64 seq)
{
        ENTRY;
        fld_cache_delete(fld_cache, seq);
        RETURN(fld_index_delete(fld, ctx, seq));
}
EXPORT_SYMBOL(fld_server_delete);

/* lookup in cache first and then issue index lookup */
int
fld_server_lookup(struct lu_server_fld *fld,
                  const struct lu_context *ctx,
                  __u64 seq, mdsno_t *mds)
{
        struct fld_cache_entry *flde;
        int rc;
        ENTRY;
        
        /* lookup it in the cache first */
        flde = fld_cache_lookup(fld_cache, seq);
        if (flde != NULL) {
                *mds = flde->fce_mds;
                RETURN(0);
        }

        rc = fld_index_lookup(fld, ctx, seq, mds);
        RETURN(rc);
}
EXPORT_SYMBOL(fld_server_lookup);

static int
fld_server_handle(struct lu_server_fld *fld,
                  const struct lu_context *ctx,
                  __u32 opc, struct md_fld *mf)
{
        int rc;
        ENTRY;

        switch (opc) {
        case FLD_CREATE:
                rc = fld_server_create(fld, ctx,
                                       mf->mf_seq, mf->mf_mds);
                break;
        case FLD_DELETE:
                rc = fld_server_delete(fld, ctx, mf->mf_seq);
                break;
        case FLD_LOOKUP:
                rc = fld_server_lookup(fld, ctx,
                                       mf->mf_seq, &mf->mf_mds);
                break;
        default:
                rc = -EINVAL;
                break;
        }
        RETURN(rc);

}

static int
fld_req_handle0(const struct lu_context *ctx,
                struct lu_server_fld *fld,
                struct ptlrpc_request *req)
{
        int rep_buf_size[3] = { 0, };
        struct req_capsule pill;
        struct md_fld *in;
        struct md_fld *out;
        int rc = -EPROTO;
        __u32 *opc;
        ENTRY;

        req_capsule_init(&pill, req, RCL_SERVER,
                         rep_buf_size);

        req_capsule_set(&pill, &RQF_FLD_QUERY);
        req_capsule_pack(&pill);

        opc = req_capsule_client_get(&pill, &RMF_FLD_OPC);
        if (opc != NULL) {
                in = req_capsule_client_get(&pill, &RMF_FLD_MDFLD);
                if (in == NULL) {
                        CERROR("cannot unpack fld request\n");
                        GOTO(out_pill, rc = -EPROTO);
                }
                out = req_capsule_server_get(&pill, &RMF_FLD_MDFLD);
                if (out == NULL) {
                        CERROR("cannot allocate fld response\n");
                        GOTO(out_pill, rc = -EPROTO);
                }
                *out = *in;
                rc = fld_server_handle(fld, ctx, *opc, out);
        } else {
                CERROR("cannot unpack FLD operation\n");
        }
        
out_pill:
        EXIT;
        req_capsule_fini(&pill);
        return rc;
}

static int fld_req_handle(struct ptlrpc_request *req)
{
        int fail = OBD_FAIL_FLD_ALL_REPLY_NET;
        const struct lu_context *ctx;
        struct lu_site    *site;
        int rc = -EPROTO;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_FLD_ALL_REPLY_NET | OBD_FAIL_ONCE, 0);

        ctx = req->rq_svc_thread->t_ctx;
        LASSERT(ctx != NULL);
        LASSERT(ctx->lc_thread == req->rq_svc_thread);
        if (req->rq_reqmsg->opc == FLD_QUERY) {
                if (req->rq_export != NULL) {
                        site = req->rq_export->exp_obd->obd_lu_dev->ld_site;
                        LASSERT(site != NULL);
                        rc = fld_req_handle0(ctx, site->ls_fld, req);
                } else {
                        CERROR("Unconnected request\n");
                        req->rq_status = -ENOTCONN;
                        GOTO(out, rc = -ENOTCONN);
                }
        } else {
                CERROR("Wrong opcode: %d\n", req->rq_reqmsg->opc);
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req);
                RETURN(rc);
        }

        EXIT;
out:
        target_send_reply(req, rc, fail);
        return 0;
}

#ifdef LPROCFS
static int
fld_server_proc_init(struct lu_server_fld *fld)
{
        int rc;
        ENTRY;

        fld->fld_proc_dir = lprocfs_register(fld->fld_name,
                                             proc_lustre_root,
                                             NULL, NULL);
        if (IS_ERR(fld->fld_proc_dir)) {
                CERROR("LProcFS failed in fld-init\n");
                rc = PTR_ERR(fld->fld_proc_dir);
                GOTO(err, rc);
        }

        fld->fld_proc_entry = lprocfs_register("services",
                                               fld->fld_proc_dir,
                                               NULL, NULL);
        if (IS_ERR(fld->fld_proc_entry)) {
                CERROR("LProcFS failed in fld-init\n");
                rc = PTR_ERR(fld->fld_proc_entry);
                GOTO(err_type, rc);
        }

        rc = lprocfs_add_vars(fld->fld_proc_dir,
                              fld_server_proc_list, fld);
        if (rc) {
                CERROR("can't init FLD proc, rc %d\n", rc);
                GOTO(err_type, rc);
        }

        RETURN(0);

err_type:
        lprocfs_remove(fld->fld_proc_dir);
err:
        fld->fld_proc_dir = NULL;
        fld->fld_proc_entry = NULL;
        return rc;
}

static void
fld_server_proc_fini(struct lu_server_fld *fld)
{
        ENTRY;
        if (fld->fld_proc_entry) {
                lprocfs_remove(fld->fld_proc_entry);
                fld->fld_proc_entry = NULL;
        }

        if (fld->fld_proc_dir) {
                lprocfs_remove(fld->fld_proc_dir);
                fld->fld_proc_dir = NULL;
        }
        EXIT;
}
#endif

int
fld_server_init(struct lu_server_fld *fld,
                const struct lu_context *ctx,
                const char *uuid,
                struct dt_device *dt)
{
        int rc;
        struct ptlrpc_service_conf fld_conf = {
                .psc_nbufs            = MDS_NBUFS,
                .psc_bufsize          = MDS_BUFSIZE,
                .psc_max_req_size     = MDS_MAXREQSIZE,
                .psc_max_reply_size   = MDS_MAXREPSIZE,
                .psc_req_portal       = FLD_REQUEST_PORTAL,
                .psc_rep_portal       = MDC_REPLY_PORTAL,
                .psc_watchdog_timeout = FLD_SERVICE_WATCHDOG_TIMEOUT,
                .psc_num_threads      = FLD_NUM_THREADS
        };
        ENTRY;

        fld->fld_dt = dt;
        lu_device_get(&dt->dd_lu_dev);

        snprintf(fld->fld_name, sizeof(fld->fld_name),
                 "%s-%s", LUSTRE_FLD_NAME, uuid);
        
        rc = fld_index_init(fld, ctx);
        if (rc)
                GOTO(out, rc);

#ifdef LPROCFS
        rc = fld_server_proc_init(fld);
        if (rc)
                GOTO(out, rc);
#endif

        fld->fld_service =
                ptlrpc_init_svc_conf(&fld_conf, fld_req_handle,
                                     LUSTRE_FLD_NAME,
                                     fld->fld_proc_entry, NULL);
        if (fld->fld_service != NULL)
                rc = ptlrpc_start_threads(NULL, fld->fld_service,
                                          LUSTRE_FLD_NAME);
        else
                rc = -ENOMEM;

        EXIT;
out:
        if (rc)
                fld_server_fini(fld, ctx);
        else
                CDEBUG(D_INFO|D_WARNING, "Server FLD\n");
        return rc;
}
EXPORT_SYMBOL(fld_server_init);

void
fld_server_fini(struct lu_server_fld *fld,
                const struct lu_context *ctx)
{
        ENTRY;

#ifdef LPROCFS
        fld_server_proc_fini(fld);
#endif
        
        if (fld->fld_service != NULL) {
                ptlrpc_unregister_service(fld->fld_service);
                fld->fld_service = NULL;
        }

        if (fld->fld_dt != NULL) {
                lu_device_put(&fld->fld_dt->dd_lu_dev);
                fld_index_fini(fld, ctx);
                fld->fld_dt = NULL;
        }
        CDEBUG(D_INFO|D_WARNING, "Server FLD\n");
        EXIT;
}
EXPORT_SYMBOL(fld_server_fini);

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre FLD");
MODULE_LICENSE("GPL");

cfs_module(mdd, "0.0.4", fld_mod_init, fld_mod_exit);
#endif
