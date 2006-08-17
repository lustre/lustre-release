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

#include <md_object.h>

#include "fld_internal.h"

#ifdef __KERNEL__
static void *fld_key_init(const struct lu_context *ctx,
                          struct lu_context_key *key)
{
        struct fld_thread_info *info;
        ENTRY;

        OBD_ALLOC_PTR(info);
        if (info == NULL)
                info = ERR_PTR(-ENOMEM);
        RETURN(info);
}

static void fld_key_fini(const struct lu_context *ctx,
                         struct lu_context_key *key, void *data)
{
        struct fld_thread_info *info = data;
        ENTRY;
        OBD_FREE_PTR(info);
        EXIT;
}

struct lu_context_key fld_thread_key = {
        .lct_tags = LCT_MD_THREAD|LCT_DT_THREAD,
        .lct_init = fld_key_init,
        .lct_fini = fld_key_fini
};

static int __init fld_mod_init(void)
{
        lu_context_key_register(&fld_thread_key);
        return 0;
}

static void __exit fld_mod_exit(void)
{
        lu_context_key_degister(&fld_thread_key);
        return;
}

/* insert index entry and update cache */
static int fld_server_create(struct lu_server_fld *fld,
                             const struct lu_context *ctx,
                             seqno_t seq, mdsno_t mds)
{
        return fld_index_create(fld, ctx, seq, mds);
}

/* delete index entry */
static int fld_server_delete(struct lu_server_fld *fld,
                             const struct lu_context *ctx,
                             seqno_t seq)
{
        return fld_index_delete(fld, ctx, seq);
}

/* issue on-disk index lookup */
static int fld_server_lookup(struct lu_server_fld *fld,
                             const struct lu_context *ctx,
                             seqno_t seq, mdsno_t *mds)
{
        return fld_index_lookup(fld, ctx, seq, mds);
}

static int fld_server_handle(struct lu_server_fld *fld,
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

static int fld_req_handle0(const struct lu_context *ctx,
                           struct lu_server_fld *fld,
                           struct ptlrpc_request *req,
                           struct fld_thread_info *info)
{
        struct md_fld *in;
        struct md_fld *out;
        int rc = -EPROTO;
        __u32 *opc;
        ENTRY;

        rc = req_capsule_pack(&info->fti_pill);
        if (rc)
                RETURN(rc);

        opc = req_capsule_client_get(&info->fti_pill, &RMF_FLD_OPC);
        if (opc != NULL) {
                in = req_capsule_client_get(&info->fti_pill, &RMF_FLD_MDFLD);
                if (in == NULL)
                        RETURN(-EPROTO);
                out = req_capsule_server_get(&info->fti_pill, &RMF_FLD_MDFLD);
                if (out == NULL)
                        RETURN(-EPROTO);
                *out = *in;
                rc = fld_server_handle(fld, ctx, *opc, out);
        }

        RETURN(rc);
}

static void fld_thread_info_init(struct ptlrpc_request *req,
                                 struct fld_thread_info *info)
{
        int i;

        /* mark rep buffer as req-layout stuff expects */
        for (i = 0; i < ARRAY_SIZE(info->fti_rep_buf_size); i++)
                info->fti_rep_buf_size[i] = -1;

        /* init request capsule */
        req_capsule_init(&info->fti_pill, req, RCL_SERVER,
                         info->fti_rep_buf_size);

        req_capsule_set(&info->fti_pill, &RQF_FLD_QUERY);
}

static void fld_thread_info_fini(struct fld_thread_info *info)
{
        req_capsule_fini(&info->fti_pill);
}

static int fld_req_handle(struct ptlrpc_request *req)
{
        const struct lu_context *ctx;
        struct fld_thread_info *info;
        struct lu_site *site;
        int rc = 0;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_FLD_ALL_REPLY_NET | OBD_FAIL_ONCE, 0);

        ctx = req->rq_svc_thread->t_ctx;
        LASSERT(ctx != NULL);
        LASSERT(ctx->lc_thread == req->rq_svc_thread);

        info = lu_context_key_get(ctx, &fld_thread_key);
        LASSERT(info != NULL);

        fld_thread_info_init(req, info);

        if (req->rq_reqmsg->opc == FLD_QUERY) {
                if (req->rq_export != NULL) {
                        site = req->rq_export->exp_obd->obd_lu_dev->ld_site;
                        LASSERT(site != NULL);
                        /* 
                         * no need to return error here and overwrite @rc, this
                         * function should return 0 even if fld_req_handle0()
                         * returns some error code.
                         */
                        fld_req_handle0(ctx, site->ls_server_fld, req, info);
                } else {
                        CERROR("Unconnected request\n");
                        req->rq_status = -ENOTCONN;
                }
        } else {
                CERROR("Wrong opcode: %d\n", req->rq_reqmsg->opc);
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req);
                GOTO(out_info, rc);
        }

        target_send_reply(req, rc, OBD_FAIL_FLD_ALL_REPLY_NET);
        EXIT;
out_info:
        fld_thread_info_fini(info);
        return rc;
}

/*
 * Returns true, if fid is local to this server node.
 *
 * WARNING: this function is *not* guaranteed to return false if fid is
 * remote: it makes an educated conservative guess only.
 *
 * fid_is_local() is supposed to be used in assertion checks only.
 */
int fid_is_local(struct lu_site *site, const struct lu_fid *fid)
{
        int result;

        result = 1; /* conservatively assume fid is local */
        if (site->ls_client_fld != NULL) {
                mdsno_t mds;
                int rc;

                rc = fld_cache_lookup(site->ls_client_fld->fld_cache,
                                      fid_seq(fid), &mds);
                if (rc == 0)
                        result = (mds == site->ls_node_id);
        }
        return result;
}
EXPORT_SYMBOL(fid_is_local);

static void fld_server_proc_fini(struct lu_server_fld *fld);

#ifdef LPROCFS
static int fld_server_proc_init(struct lu_server_fld *fld)
{
        int rc = 0;
        ENTRY;

        fld->fld_proc_dir = lprocfs_register(fld->fld_name,
                                             proc_lustre_root,
                                             fld_server_proc_list, fld);
        if (IS_ERR(fld->fld_proc_dir)) {
                rc = PTR_ERR(fld->fld_proc_dir);
                RETURN(rc);
        }

        fld->fld_proc_entry = lprocfs_register("services",
                                               fld->fld_proc_dir,
                                               NULL, NULL);
        if (IS_ERR(fld->fld_proc_entry)) {
                rc = PTR_ERR(fld->fld_proc_entry);
                GOTO(out_cleanup, rc);
        }
        RETURN(rc);

out_cleanup:
        fld_server_proc_fini(fld);
        return rc;
}

static void fld_server_proc_fini(struct lu_server_fld *fld)
{
        ENTRY;
        if (fld->fld_proc_entry != NULL) {
                if (!IS_ERR(fld->fld_proc_entry))
                        lprocfs_remove(fld->fld_proc_entry);
                fld->fld_proc_entry = NULL;
        }

        if (fld->fld_proc_dir != NULL) {
                if (!IS_ERR(fld->fld_proc_dir))
                        lprocfs_remove(fld->fld_proc_dir);
                fld->fld_proc_dir = NULL;
        }
        EXIT;
}
#else
static int fld_server_proc_init(struct lu_server_fld *fld)
{
        return 0;
}

static void fld_server_proc_fini(struct lu_server_fld *fld)
{
        return;
}
#endif

int fld_server_init(struct lu_server_fld *fld,
                    const struct lu_context *ctx,
                    struct dt_device *dt,
                    const char *uuid)
{
        int rc;
        struct ptlrpc_service_conf fld_conf = {
                .psc_nbufs            = MDS_NBUFS,
                .psc_bufsize          = MDS_BUFSIZE,
                .psc_max_req_size     = FLD_MAXREQSIZE,
                .psc_max_reply_size   = FLD_MAXREPSIZE,
                .psc_req_portal       = FLD_REQUEST_PORTAL,
                .psc_rep_portal       = MDC_REPLY_PORTAL,
                .psc_watchdog_timeout = FLD_SERVICE_WATCHDOG_TIMEOUT,
                .psc_num_threads      = FLD_NUM_THREADS,
                .psc_ctx_tags         = LCT_DT_THREAD|LCT_MD_THREAD
        };
        ENTRY;

        snprintf(fld->fld_name, sizeof(fld->fld_name),
                 "%s-srv-%s", LUSTRE_FLD_NAME, uuid);

        rc = fld_index_init(fld, ctx, dt);
        if (rc)
                GOTO(out, rc);

        rc = fld_server_proc_init(fld);
        if (rc)
                GOTO(out, rc);

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

void fld_server_fini(struct lu_server_fld *fld,
                     const struct lu_context *ctx)
{
        ENTRY;

        if (fld->fld_service != NULL) {
                ptlrpc_unregister_service(fld->fld_service);
                fld->fld_service = NULL;
        }

        fld_server_proc_fini(fld);

        fld_index_fini(fld, ctx);
        
        EXIT;
}
EXPORT_SYMBOL(fld_server_fini);

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre FLD");
MODULE_LICENSE("GPL");

cfs_module(mdd, "0.1.0", fld_mod_init, fld_mod_exit);
#endif
