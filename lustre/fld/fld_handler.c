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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/fld/fld_handler.c
 *
 * FLD (Fids Location Database)
 *
 * Author: Yury Umanets <umka@clusterfs.com>
 * Author: WangDi <wangdi@clusterfs.com>
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
#include <lustre_fid.h>
#include <lustre_req_layout.h>
#include "fld_internal.h"

#ifdef __KERNEL__

/* context key constructor/destructor: fld_key_init, fld_key_fini */
LU_KEY_INIT_FINI(fld, struct fld_thread_info);

/* context key: fld_thread_key */
LU_CONTEXT_KEY_DEFINE(fld, LCT_MD_THREAD|LCT_DT_THREAD);

cfs_proc_dir_entry_t *fld_type_proc_dir = NULL;

static struct lu_local_obj_desc llod_fld_index = {
        .llod_name      = fld_index_name,
        .llod_oid       = FLD_INDEX_OID,
        .llod_is_index  = 1,
        .llod_feat      = &fld_index_features,
};

static int __init fld_mod_init(void)
{
        fld_type_proc_dir = lprocfs_register(LUSTRE_FLD_NAME,
                                             proc_lustre_root,
                                             NULL, NULL);
        if (IS_ERR(fld_type_proc_dir))
                return PTR_ERR(fld_type_proc_dir);

        llo_local_obj_register(&llod_fld_index);

        LU_CONTEXT_KEY_INIT(&fld_thread_key);
        lu_context_key_register(&fld_thread_key);
        return 0;
}

static void __exit fld_mod_exit(void)
{
        lu_context_key_degister(&fld_thread_key);
        if (fld_type_proc_dir != NULL && !IS_ERR(fld_type_proc_dir)) {
                lprocfs_remove(&fld_type_proc_dir);
                fld_type_proc_dir = NULL;
        }
}

/* Insert index entry and update cache. */
int fld_server_create(struct lu_server_fld *fld,
                      const struct lu_env *env,
                      seqno_t seq, mdsno_t mds)
{
        int rc;
        ENTRY;
        
        rc = fld_index_create(fld, env, seq, mds);
        
        if (rc == 0) {
                /*
                 * Do not return result of calling fld_cache_insert()
                 * here. First of all because it may return -EEXISTS. Another
                 * reason is that, we do not want to stop proceeding even after
                 * cache errors.
                 */
                fld_cache_insert(fld->lsf_cache, seq, mds);
        }

        RETURN(rc);
}
EXPORT_SYMBOL(fld_server_create);

/* Delete index entry. */
int fld_server_delete(struct lu_server_fld *fld,
                      const struct lu_env *env,
                      seqno_t seq)
{
        int rc;
        ENTRY;

        fld_cache_delete(fld->lsf_cache, seq);
        rc = fld_index_delete(fld, env, seq);
        
        RETURN(rc);
}
EXPORT_SYMBOL(fld_server_delete);

/* Lookup mds by seq. */
int fld_server_lookup(struct lu_server_fld *fld,
                      const struct lu_env *env,
                      seqno_t seq, mdsno_t *mds)
{
        int rc;
        ENTRY;
        
        /* Lookup it in the cache. */
        rc = fld_cache_lookup(fld->lsf_cache, seq, mds);
        if (rc == 0)
                RETURN(0);

        rc = fld_index_lookup(fld, env, seq, mds);
        if (rc == 0) {
                /*
                 * Do not return error here as well. See previous comment in
                 * same situation in function fld_server_create().
                 */
                fld_cache_insert(fld->lsf_cache, seq, *mds);
        }
        RETURN(rc);
}
EXPORT_SYMBOL(fld_server_lookup);

static int fld_server_handle(struct lu_server_fld *fld,
                             const struct lu_env *env,
                             __u32 opc, struct md_fld *mf,
                             struct fld_thread_info *info)
{
        int rc;
        ENTRY;

        switch (opc) {
        case FLD_CREATE:
                rc = fld_server_create(fld, env,
                                       mf->mf_seq, mf->mf_mds);

                /* Do not return -EEXIST error for resent case */
                if ((info->fti_flags & MSG_RESENT) && rc == -EEXIST)
                        rc = 0;
                break;
        case FLD_DELETE:
                rc = fld_server_delete(fld, env, mf->mf_seq);

                /* Do not return -ENOENT error for resent case */
                if ((info->fti_flags & MSG_RESENT) && rc == -ENOENT)
                        rc = 0;
                break;
        case FLD_LOOKUP:
                rc = fld_server_lookup(fld, env,
                                       mf->mf_seq, &mf->mf_mds);
                break;
        default:
                rc = -EINVAL;
                break;
        }

        CDEBUG(D_INFO, "%s: FLD req handle: error %d (opc: %d, seq: "
               LPX64", mds: "LPU64")\n", fld->lsf_name, rc, opc,
               mf->mf_seq, mf->mf_mds);
        
        RETURN(rc);

}

static int fld_req_handle(struct ptlrpc_request *req,
                          struct fld_thread_info *info)
{
        struct lu_site *site;
        struct md_fld *in;
        struct md_fld *out;
        int rc;
        __u32 *opc;
        ENTRY;

        site = req->rq_export->exp_obd->obd_lu_dev->ld_site;

        rc = req_capsule_server_pack(info->fti_pill);
        if (rc)
                RETURN(err_serious(rc));

        opc = req_capsule_client_get(info->fti_pill, &RMF_FLD_OPC);
        if (opc != NULL) {
                in = req_capsule_client_get(info->fti_pill, &RMF_FLD_MDFLD);
                if (in == NULL)
                        RETURN(err_serious(-EPROTO));
                out = req_capsule_server_get(info->fti_pill, &RMF_FLD_MDFLD);
                if (out == NULL)
                        RETURN(err_serious(-EPROTO));
                *out = *in;

                rc = fld_server_handle(lu_site2md(site)->ms_server_fld,
                                       req->rq_svc_thread->t_env,
                                       *opc, out, info);
        } else
                rc = err_serious(-EPROTO);

        RETURN(rc);
}

static void fld_thread_info_init(struct ptlrpc_request *req,
                                 struct fld_thread_info *info)
{
        info->fti_flags = lustre_msg_get_flags(req->rq_reqmsg);

        info->fti_pill = &req->rq_pill;
        /* Init request capsule. */
        req_capsule_init(info->fti_pill, req, RCL_SERVER);
        req_capsule_set(info->fti_pill, &RQF_FLD_QUERY);
}

static void fld_thread_info_fini(struct fld_thread_info *info)
{
        req_capsule_fini(info->fti_pill);
}

static int fld_handle(struct ptlrpc_request *req)
{
        struct fld_thread_info *info;
        const struct lu_env *env;
        int rc;

        env = req->rq_svc_thread->t_env;
        LASSERT(env != NULL);

        info = lu_context_key_get(&env->le_ctx, &fld_thread_key);
        LASSERT(info != NULL);

        fld_thread_info_init(req, info);
        rc = fld_req_handle(req, info);
        fld_thread_info_fini(info);

        return rc;
}

/*
 * Entry point for handling FLD RPCs called from MDT.
 */
int fld_query(struct com_thread_info *info)
{
        return fld_handle(info->cti_pill->rc_req);
}
EXPORT_SYMBOL(fld_query);

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
        struct md_site *msite;

        result = 1; /* conservatively assume fid is local */
        msite = lu_site2md(site);
        if (msite->ms_client_fld != NULL) {
                mdsno_t mds;
                int rc;

                rc = fld_cache_lookup(msite->ms_client_fld->lcf_cache,
                                      fid_seq(fid), &mds);
                if (rc == 0)
                        result = (mds == msite->ms_node_id);
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

        fld->lsf_proc_dir = lprocfs_register(fld->lsf_name,
                                             fld_type_proc_dir,
                                             fld_server_proc_list, fld);
        if (IS_ERR(fld->lsf_proc_dir)) {
                rc = PTR_ERR(fld->lsf_proc_dir);
                RETURN(rc);
        }

        RETURN(rc);
}

static void fld_server_proc_fini(struct lu_server_fld *fld)
{
        ENTRY;
        if (fld->lsf_proc_dir != NULL) {
                if (!IS_ERR(fld->lsf_proc_dir))
                        lprocfs_remove(&fld->lsf_proc_dir);
                fld->lsf_proc_dir = NULL;
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

int fld_server_init(struct lu_server_fld *fld, struct dt_device *dt,
                    const char *prefix, const struct lu_env *env)
{
        int cache_size, cache_threshold;
        int rc;
        ENTRY;

        snprintf(fld->lsf_name, sizeof(fld->lsf_name),
                 "srv-%s", prefix);

        cache_size = FLD_SERVER_CACHE_SIZE /
                sizeof(struct fld_cache_entry);

        cache_threshold = cache_size *
                FLD_SERVER_CACHE_THRESHOLD / 100;

        fld->lsf_cache = fld_cache_init(fld->lsf_name,
                                        FLD_SERVER_HTABLE_SIZE,
                                        cache_size, cache_threshold);
        if (IS_ERR(fld->lsf_cache)) {
                rc = PTR_ERR(fld->lsf_cache);
                fld->lsf_cache = NULL;
                GOTO(out, rc);
        }

        rc = fld_index_init(fld, env, dt);
        if (rc)
                GOTO(out, rc);

        rc = fld_server_proc_init(fld);
        if (rc)
                GOTO(out, rc);

        EXIT;
out:
        if (rc)
                fld_server_fini(fld, env);
        return rc;
}
EXPORT_SYMBOL(fld_server_init);

void fld_server_fini(struct lu_server_fld *fld,
                     const struct lu_env *env)
{
        ENTRY;

        fld_server_proc_fini(fld);
        fld_index_fini(fld, env);

        if (fld->lsf_cache != NULL) {
                if (!IS_ERR(fld->lsf_cache))
                        fld_cache_fini(fld->lsf_cache);
                fld->lsf_cache = NULL;
        }

        EXIT;
}
EXPORT_SYMBOL(fld_server_fini);

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre FLD");
MODULE_LICENSE("GPL");

cfs_module(mdd, "0.1.0", fld_mod_init, fld_mod_exit);
#endif
