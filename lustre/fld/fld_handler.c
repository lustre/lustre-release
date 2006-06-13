/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/fld/fld_handler.c
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
/* XXX: maybe these 2 items should go to sbi */
struct fld_cache_info *fld_cache = NULL;

enum {
        FLD_HTABLE_BITS = 8,
        FLD_HTABLE_SIZE = (1 << FLD_HTABLE_BITS),
        FLD_HTABLE_MASK = FLD_HTABLE_SIZE - 1
};

static __u32 fld_hash(__u64 lu_seq)
{
        return lu_seq;
}

static int
fld_cache_insert(struct fld_cache_info *fld_cache,
                 __u64 lu_seq, __u64 mds_num)
{
        struct fld_cache *fld;
        struct hlist_head *bucket;
        struct hlist_node *scan;
        int rc = 0;
        ENTRY;

        bucket = fld_cache->fld_hash + (fld_hash(lu_seq) &
                                        fld_cache->fld_hash_mask);

        OBD_ALLOC_PTR(fld);
        if (!fld)
                RETURN(-ENOMEM);

        INIT_HLIST_NODE(&fld->fld_list);
        fld->fld_mds = mds_num;
        fld->fld_seq = lu_seq;

        spin_lock(&fld_cache->fld_lock);
        hlist_for_each_entry(fld, scan, bucket, fld_list) {
                if (fld->fld_seq == lu_seq) {
                        spin_unlock(&fld_cache->fld_lock);
                        GOTO(exit, rc = -EEXIST);
                }
        }
        hlist_add_head(&fld->fld_list, bucket);
        spin_unlock(&fld_cache->fld_lock);
exit:
        if (rc != 0)
                OBD_FREE(fld, sizeof(*fld));
        RETURN(rc);
}

static struct fld_cache *
fld_cache_lookup(struct fld_cache_info *fld_cache, __u64 lu_seq)
{
        struct hlist_head *bucket;
        struct hlist_node *scan;
        struct fld_cache *fld;
        ENTRY;

        bucket = fld_cache->fld_hash + (fld_hash(lu_seq) &
                                        fld_cache->fld_hash_mask);

        spin_lock(&fld_cache->fld_lock);
        hlist_for_each_entry(fld, scan, bucket, fld_list) {
                if (fld->fld_seq == lu_seq) {
                        spin_unlock(&fld_cache->fld_lock);
                        RETURN(fld);
                }
        }
        spin_unlock(&fld_cache->fld_lock);

        RETURN(NULL);
}

static void
fld_cache_delete(struct fld_cache_info *fld_cache, __u64 lu_seq)
{
        struct hlist_head *bucket;
        struct hlist_node *scan;
        struct fld_cache *fld;
        ENTRY;

        bucket = fld_cache->fld_hash + (fld_hash(lu_seq) &
                                        fld_cache->fld_hash_mask);

        spin_lock(&fld_cache->fld_lock);
        hlist_for_each_entry(fld, scan, bucket, fld_list) {
                if (fld->fld_seq == lu_seq) {
                        hlist_del_init(&fld->fld_list);
                        spin_unlock(&fld_cache->fld_lock);
                        EXIT;
                        return;
                }
        }
        spin_unlock(&fld_cache->fld_lock);
        return;
}
#endif

static int dht_mdt_hash(__u64 seq)
{
        return 0;
}

static struct obd_export *
fld_client_get_exp(struct lu_client_fld *fld, __u64 seq)
{
        int seq_mds;

        seq_mds = dht_mdt_hash(seq);
        CDEBUG(D_INFO, "mds number %d\n", seq_mds);

        /* XXX: get exp according to lu_seq */
        return fld->fld_exp;
}

int fld_client_init(struct lu_client_fld *fld,
                    struct obd_export *exp)
{
        int rc = 0;
        ENTRY;

        LASSERT(exp != NULL);
        fld->fld_exp = class_export_get(exp);
        CDEBUG(D_INFO, "Client FLD initialized\n");
        
        RETURN(rc);
}

void fld_client_fini(struct lu_client_fld *fld)
{
        ENTRY;
        if (fld->fld_exp != NULL) {
                class_export_put(fld->fld_exp);
                fld->fld_exp = NULL;
        }
        CDEBUG(D_INFO, "Client FLD finalized\n");
        EXIT;
}

static int
fld_client_rpc(struct obd_export *exp,
               struct md_fld *mf, __u32 fld_op)
{
        struct ptlrpc_request *req;
        struct md_fld *pmf;
        int mf_size = sizeof(*mf);
        __u32 *op;
        int size[2] = {sizeof(*op), mf_size}, rc;
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp),
                              LUSTRE_MDS_VERSION, FLD_QUERY,
                              2, size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        op = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*op));
        *op = fld_op;

        pmf = lustre_msg_buf(req->rq_reqmsg, 1, sizeof (*pmf));
        memcpy(pmf, mf, sizeof(*mf));

        req->rq_replen = lustre_msg_size(1, &mf_size);
        req->rq_request_portal = MDS_FLD_PORTAL;
        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(out_req, rc);

        pmf = lustre_swab_repbuf(req, 0, sizeof(*pmf),
                                 lustre_swab_md_fld);
        *mf = *pmf; 
out_req:
        ptlrpc_req_finished(req);
        RETURN(rc);
}

int
fld_client_create(struct lu_client_fld *fld,
                  __u64 seq, __u64 mds_num)
{
        struct obd_export *fld_exp;
        struct md_fld      md_fld;
        __u32 rc;
        ENTRY;

        fld_exp = fld_client_get_exp(fld, seq);
        if (!fld_exp)
                RETURN(-EINVAL);
        
        md_fld.mf_seq = seq;
        md_fld.mf_mds = mds_num;

        rc = fld_client_rpc(fld_exp, &md_fld, FLD_CREATE);
        
#ifdef __KERNEL__
        fld_cache_insert(fld_cache, seq, mds_num);
#endif
        
        RETURN(rc);
}

int
fld_client_delete(struct lu_client_fld *fld,
                  __u64 seq, __u64 mds_num)
{
        struct obd_export *fld_exp;
        struct md_fld      md_fld;
        __u32 rc;

#ifdef __KERNEL__
        fld_cache_delete(fld_cache, seq);
#endif
        
        fld_exp = fld_client_get_exp(fld, seq);
        if (!fld_exp)
                RETURN(-EINVAL);

        md_fld.mf_seq = seq;
        md_fld.mf_mds = mds_num;

        rc = fld_client_rpc(fld_exp, &md_fld, FLD_DELETE);
        RETURN(rc);
}

int
fld_client_get(struct lu_client_fld *fld,
               __u64 lu_seq, __u64 *mds_num)
{
        struct obd_export *fld_exp;
        struct md_fld      md_fld;
        int    vallen, rc;

        fld_exp = fld_client_get_exp(fld, lu_seq);
        if (!fld_exp);
                RETURN(-EINVAL);

        md_fld.mf_seq = lu_seq;
        vallen = sizeof(struct md_fld);

        rc = fld_client_rpc(fld_exp, &md_fld, FLD_GET);
        if (rc == 0)
                *mds_num = md_fld.mf_mds;

        RETURN(rc);
}

/* lookup fid in the namespace of pfid according to the name */
int
fld_client_lookup(struct lu_client_fld *fld,
                  __u64 lu_seq, __u64 *mds_num)
{
        struct fld_cache *fld_entry;
        int rc;
        ENTRY;

#ifdef __KERNEL__
        /* lookup it in the cache */
        fld_entry = fld_cache_lookup(fld_cache, lu_seq);
        if (fld_entry != NULL) {
                *mds_num = fld_entry->fld_mds;
                RETURN(0);
        }
#endif
        
        /* can not find it in the cache */
        rc = fld_client_get(fld, lu_seq, mds_num);
        if (rc)
                RETURN(rc);

#ifdef __KERNEL__
        rc = fld_cache_insert(fld_cache, lu_seq, *mds_num);
#endif
        
        RETURN(rc);
}

#ifdef __KERNEL__
static int fld_init(void)
{
        ENTRY;

        OBD_ALLOC_PTR(fld_cache);
        if (fld_cache == NULL)
                RETURN(-ENOMEM);

        /* init fld cache info */
        fld_cache->fld_hash_mask = FLD_HTABLE_MASK;
        OBD_ALLOC(fld_cache->fld_hash, FLD_HTABLE_SIZE *
                  sizeof fld_cache->fld_hash[0]);
        spin_lock_init(&fld_cache->fld_lock);

        RETURN(0);
}

static int fld_fini(void)
{
        if (fld_cache != NULL) {
                OBD_FREE(fld_cache->fld_hash, FLD_HTABLE_SIZE *
                         sizeof fld_cache->fld_hash[0]);
                OBD_FREE_PTR(fld_cache);
        }
        return 0;
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


static struct fld_list fld_list_head;

static int
fld_server_handle(struct lu_server_fld *fld,
                  const struct lu_context *ctx,
                  __u32 opts, struct md_fld *mf)
{
        int rc;
        ENTRY;

        switch (opts) {
        case FLD_CREATE:
                rc = fld_handle_insert(fld, ctx, mf->mf_seq, mf->mf_mds);
                break;
        case FLD_DELETE:
                rc = fld_handle_delete(fld, ctx, mf->mf_seq);
                break;
        case FLD_GET:
                rc = fld_handle_lookup(fld, ctx, mf->mf_seq, &mf->mf_mds);
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
        int result;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_FLD_ALL_REPLY_NET | OBD_FAIL_ONCE, 0);

        ctx = req->rq_svc_thread->t_ctx;
        LASSERT(ctx != NULL);
        LASSERT(ctx->lc_thread == req->rq_svc_thread);
        result = -EPROTO;
        if (req->rq_reqmsg->opc == FLD_QUERY) {
                if (req->rq_export != NULL) {
                        site = req->rq_export->exp_obd->obd_lu_dev->ld_site;
                        LASSERT(site != NULL);
                        result = fld_req_handle0(ctx, site->ls_fld, req);
                } else {
                        CERROR("Unconnected request\n");
                        req->rq_status = -ENOTCONN;
                        GOTO(out, result = -ENOTCONN);
                }
        } else {
                CERROR("Wrong opcode: %d\n", req->rq_reqmsg->opc);
                req->rq_status = -ENOTSUPP;
                result = ptlrpc_error(req);
                RETURN(result);
        }

        EXIT;
out:
        target_send_reply(req, result, fail);
        return 0;
}

int
fld_server_init(struct lu_server_fld *fld,
                const struct lu_context *ctx,
                struct dt_device *dt)
{
        int result;
        struct ptlrpc_service_conf fld_conf = {
                .psc_nbufs            = MDS_NBUFS,
                .psc_bufsize          = MDS_BUFSIZE,
                .psc_max_req_size     = MDS_MAXREQSIZE,
                .psc_max_reply_size   = MDS_MAXREPSIZE,
                .psc_req_portal       = MDS_FLD_PORTAL,
                .psc_rep_portal       = MDC_REPLY_PORTAL,
                .psc_watchdog_timeout = FLD_SERVICE_WATCHDOG_TIMEOUT,
                .psc_num_threads      = FLD_NUM_THREADS
        };

        fld->fld_dt = dt;
        lu_device_get(&dt->dd_lu_dev);
        INIT_LIST_HEAD(&fld_list_head.fld_list);
        spin_lock_init(&fld_list_head.fld_lock);

        result = fld_iam_init(fld, ctx);

        if (result == 0) {
                fld->fld_service =
                        ptlrpc_init_svc_conf(&fld_conf, fld_req_handle,
                                             LUSTRE_FLD0_NAME,
                                             fld->fld_proc_entry, NULL);
                if (fld->fld_service != NULL)
                        result = ptlrpc_start_threads(NULL, fld->fld_service,
                                                      LUSTRE_FLD0_NAME);
                else
                        result = -ENOMEM;
        }

        if (result != 0)
                fld_server_fini(fld, ctx);
        else
                CDEBUG(D_INFO, "Server FLD initialized\n");
        return result;
}
EXPORT_SYMBOL(fld_server_init);

void
fld_server_fini(struct lu_server_fld *fld,
                const struct lu_context *ctx)
{
        struct list_head *pos, *n;

        if (fld->fld_service != NULL) {
                ptlrpc_unregister_service(fld->fld_service);
                fld->fld_service = NULL;
        }

        spin_lock(&fld_list_head.fld_lock);
        list_for_each_safe(pos, n, &fld_list_head.fld_list) {
                struct fld_item *fld = list_entry(pos, struct fld_item,
                                                  fld_list);
                list_del_init(&fld->fld_list);
                OBD_FREE_PTR(fld);
        }
        spin_unlock(&fld_list_head.fld_lock);
        if (fld->fld_dt != NULL) {
                lu_device_put(&fld->fld_dt->dd_lu_dev);
                fld_iam_fini(fld, ctx);
                fld->fld_dt = NULL;
        }
        CDEBUG(D_INFO, "Server FLD finalized\n");
}
EXPORT_SYMBOL(fld_server_fini);

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre FLD");
MODULE_LICENSE("GPL");

cfs_module(mdd, "0.0.4", fld_mod_init, fld_mod_exit);
#endif
