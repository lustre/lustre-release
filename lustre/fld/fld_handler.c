/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/fld/fld_handler.c
 *  FLD (Fids Location Database)
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Yury Umanets <umka@clusterfs.com>
 *           WangDi <wangdi@clusterfs.com>
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
#include <lustre_req_layout.h>
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

cfs_proc_dir_entry_t *fld_type_proc_dir = NULL;

static int __init fld_mod_init(void)
{
        printk(KERN_INFO "Lustre: Fid Location Database; "
               "info@clusterfs.com\n");

        fld_type_proc_dir = lprocfs_register(LUSTRE_FLD_NAME,
                                             proc_lustre_root,
                                             NULL, NULL);
        if (IS_ERR(fld_type_proc_dir))
                return PTR_ERR(fld_type_proc_dir);

        lu_context_key_register(&fld_thread_key);
        return 0;
}

static void __exit fld_mod_exit(void)
{
        lu_context_key_degister(&fld_thread_key);
        if (fld_type_proc_dir != NULL && !IS_ERR(fld_type_proc_dir)) {
                lprocfs_remove(fld_type_proc_dir);
                fld_type_proc_dir = NULL;
        }
}

/* insert index entry and update cache */
int fld_server_create(struct lu_server_fld *fld,
                      const struct lu_env *env,
                      seqno_t seq, mdsno_t mds)
{
        return fld_index_create(fld, env, seq, mds);
}
EXPORT_SYMBOL(fld_server_create);

/* delete index entry */
int fld_server_delete(struct lu_server_fld *fld,
                      const struct lu_env *env,
                      seqno_t seq)
{
        return fld_index_delete(fld, env, seq);
}
EXPORT_SYMBOL(fld_server_delete);

/* issue on-disk index lookup */
int fld_server_lookup(struct lu_server_fld *fld,
                      const struct lu_env *env,
                      seqno_t seq, mdsno_t *mds)
{
        return fld_index_lookup(fld, env, seq, mds);
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

                /* do not return -EEXIST error for resent case */
                if ((info->fti_flags & MSG_RESENT) && rc == -EEXIST)
                        rc = 0;
                break;
        case FLD_DELETE:
                rc = fld_server_delete(fld, env, mf->mf_seq);

                /* do not return -ENOENT error for resent case */
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

        rc = req_capsule_pack(&info->fti_pill);
        if (rc)
                RETURN(err_serious(rc));

        opc = req_capsule_client_get(&info->fti_pill, &RMF_FLD_OPC);
        if (opc != NULL) {
                in = req_capsule_client_get(&info->fti_pill, &RMF_FLD_MDFLD);
                if (in == NULL)
                        RETURN(err_serious(-EPROTO));
                out = req_capsule_server_get(&info->fti_pill, &RMF_FLD_MDFLD);
                if (out == NULL)
                        RETURN(err_serious(-EPROTO));
                *out = *in;

                rc = fld_server_handle(site->ls_server_fld,
                                       req->rq_svc_thread->t_env,
                                       *opc, out, info);
        } else
                rc = err_serious(-EPROTO);

        RETURN(rc);
}

static void fld_thread_info_init(struct ptlrpc_request *req,
                                 struct fld_thread_info *info)
{
        int i;

        info->fti_flags = lustre_msg_get_flags(req->rq_reqmsg);

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

static int fld_handle(struct ptlrpc_request *req)
{
        const struct lu_env *env;
        struct fld_thread_info *info;
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
        return fld_handle(info->cti_pill.rc_req);
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

        result = 1; /* conservatively assume fid is local */
        if (site->ls_client_fld != NULL) {
                mdsno_t mds;
                int rc;

                rc = fld_cache_lookup(site->ls_client_fld->lcf_cache,
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
                        lprocfs_remove(fld->lsf_proc_dir);
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
        int rc;
        ENTRY;

        snprintf(fld->lsf_name, sizeof(fld->lsf_name),
                 "srv-%s", prefix);

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

        EXIT;
}
EXPORT_SYMBOL(fld_server_fini);

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre FLD");
MODULE_LICENSE("GPL");

cfs_module(mdd, "0.1.0", fld_mod_init, fld_mod_exit);
#endif
