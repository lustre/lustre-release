/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/fid/fid_handler.c
 *  Lustre Sequence Manager
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Yury Umanets <umka@clusterfs.com>
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
#define DEBUG_SUBSYSTEM S_FID

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
# include <linux/module.h>
#else /* __KERNEL__ */
# include <liblustre.h>
#endif

#include <obd.h>
#include <obd_class.h>
#include <dt_object.h>
#include <md_object.h>
#include <obd_support.h>
#include <lustre_req_layout.h>
#include <lustre_fid.h>
#include "fid_internal.h"

#ifdef __KERNEL__
/* Assigns client to sequence controller node. */
int seq_server_set_cli(struct lu_server_seq *seq,
                       struct lu_client_seq *cli,
                       const struct lu_env *env)
{
        int rc = 0;
        ENTRY;

        /*
         * Ask client for new range, assign that range to ->seq_space and write
         * seq state to backing store should be atomic.
         */
        down(&seq->lss_sem);

        if (cli == NULL) {
                CDEBUG(D_INFO|D_WARNING, "%s: Detached "
                       "sequence client %s\n", seq->lss_name,
                       cli->lcs_name);
                seq->lss_cli = cli;
                GOTO(out_up, rc = 0);
        }

        if (seq->lss_cli != NULL) {
                CERROR("%s: Sequence controller is already "
                       "assigned\n", seq->lss_name);
                GOTO(out_up, rc = -EINVAL);
        }

        CDEBUG(D_INFO|D_WARNING, "%s: Attached sequence "
               "controller %s\n", seq->lss_name, cli->lcs_name);

        seq->lss_cli = cli;
        EXIT;
out_up:
        up(&seq->lss_sem);
        return rc;
}
EXPORT_SYMBOL(seq_server_set_cli);

/*
 * On controller node, allocate new super sequence for regular sequence server.
 */
static int __seq_server_alloc_super(struct lu_server_seq *seq,
                                    struct lu_range *in,
                                    struct lu_range *out,
                                    const struct lu_env *env)
{
        struct lu_range *space = &seq->lss_space;
        int rc;
        ENTRY;

        LASSERT(range_is_sane(space));

        if (in != NULL) {
                CDEBUG(D_INFO|D_WARNING, "%s: Input seq range: "
                       DRANGE"\n", seq->lss_name, PRANGE(in));

                if (in->lr_end > space->lr_start)
                        space->lr_start = in->lr_end;
                *out = *in;

                CDEBUG(D_INFO|D_WARNING, "%s: Recovered space: "DRANGE"\n",
                       seq->lss_name, PRANGE(space));
        } else {
                if (range_space(space) < seq->lss_width) {
                        CWARN("%s: Sequences space to be exhausted soon. "
                              "Only "LPU64" sequences left\n", seq->lss_name,
                              range_space(space));
                        *out = *space;
                        space->lr_start = space->lr_end;
                } else if (range_is_exhausted(space)) {
                        CERROR("%s: Sequences space is exhausted\n",
                               seq->lss_name);
                        RETURN(-ENOSPC);
                } else {
                        range_alloc(out, space, seq->lss_width);
                }
        }

        rc = seq_store_write(seq, env);
        if (rc) {
                CERROR("%s: Can't write space data, rc %d\n",
                       seq->lss_name, rc);
                RETURN(rc);
        }

        CDEBUG(D_INFO, "%s: Allocated super-sequence "
               DRANGE"\n", seq->lss_name, PRANGE(out));

        RETURN(rc);
}

int seq_server_alloc_super(struct lu_server_seq *seq,
                           struct lu_range *in,
                           struct lu_range *out,
                           const struct lu_env *env)
{
        int rc;
        ENTRY;

        down(&seq->lss_sem);
        rc = __seq_server_alloc_super(seq, in, out, env);
        up(&seq->lss_sem);

        RETURN(rc);
}

static int __seq_server_alloc_meta(struct lu_server_seq *seq,
                                   struct lu_range *in,
                                   struct lu_range *out,
                                   const struct lu_env *env)
{
        struct lu_range *space = &seq->lss_space;
        int rc = 0;
        ENTRY;

        LASSERT(range_is_sane(space));

        /*
         * This is recovery case. Adjust super range if input range looks like
         * it is allocated from new super.
         */
        if (in != NULL) {
                CDEBUG(D_INFO|D_WARNING, "%s: Input seq range: "
                       DRANGE"\n", seq->lss_name, PRANGE(in));

                if (range_is_exhausted(space)) {
                        /*
                         * Server cannot send empty range to client, this is why
                         * we check here that range from client is "newer" than
                         * exhausted super.
                         */
                        LASSERT(in->lr_end > space->lr_start);

                        /* 
                         * Start is set to end of last allocated, because it
                         * *is* already allocated so we take that into account
                         * and do not use for other allocations.
                         */
                        space->lr_start = in->lr_end;

                        /* 
                         * End is set to in->lr_start + super sequence
                         * allocation unit. That is because in->lr_start is
                         * first seq in new allocated range from controller
                         * before failure.
                         */
                        space->lr_end = in->lr_start + LUSTRE_SEQ_SUPER_WIDTH;
                } else {
                        /*
                         * Update super start by end from client's range. Super
                         * end should not be changed if range was not exhausted.
                         */
                        if (in->lr_end > space->lr_start)
                                space->lr_start = in->lr_end;
                }

                *out = *in;

                CDEBUG(D_INFO|D_WARNING, "%s: Recovered space: "DRANGE"\n",
                       seq->lss_name, PRANGE(space));
        } else {
                /*
                 * XXX: Avoid cascading RPCs using kind of async preallocation
                 * when meta-sequence is close to exhausting.
                 */
                if (range_is_exhausted(space)) {
                        if (!seq->lss_cli) {
                                CERROR("%s: No sequence controller "
                                       "is attached.\n", seq->lss_name);
                                RETURN(-ENODEV);
                        }

                        rc = seq_client_alloc_super(seq->lss_cli, env);
                        if (rc) {
                                CERROR("%s: Can't allocate super-sequence, "
                                       "rc %d\n", seq->lss_name, rc);
                                RETURN(rc);
                        }

                        /* Saving new range to allocation space. */
                        *space = seq->lss_cli->lcs_space;
                        LASSERT(range_is_sane(space));
                }
                
                range_alloc(out, space, seq->lss_width);
        }

        rc = seq_store_write(seq, env);
        if (rc) {
                CERROR("%s: Can't write space data, rc %d\n",
		       seq->lss_name, rc);
        }

        if (rc == 0) {
                CDEBUG(D_INFO, "%s: Allocated meta-sequence "
                       DRANGE"\n", seq->lss_name, PRANGE(out));
        }

        RETURN(rc);
}

int seq_server_alloc_meta(struct lu_server_seq *seq,
                          struct lu_range *in,
                          struct lu_range *out,
                          const struct lu_env *env)
{
        int rc;
        ENTRY;

        down(&seq->lss_sem);
        rc = __seq_server_alloc_meta(seq, in, out, env);
        up(&seq->lss_sem);

        RETURN(rc);
}

static int seq_server_handle(struct lu_site *site,
                             const struct lu_env *env,
                             __u32 opc, struct lu_range *in,
                             struct lu_range *out)
{
        int rc;
        ENTRY;

        switch (opc) {
        case SEQ_ALLOC_META:
                if (!site->ls_server_seq) {
                        CERROR("Sequence server is not "
                               "initialized\n");
                        RETURN(-EINVAL);
                }
                rc = seq_server_alloc_meta(site->ls_server_seq,
                                           in, out, env);
                break;
        case SEQ_ALLOC_SUPER:
                if (!site->ls_control_seq) {
                        CERROR("Sequence controller is not "
                               "initialized\n");
                        RETURN(-EINVAL);
                }
                rc = seq_server_alloc_super(site->ls_control_seq,
                                            in, out, env);
                break;
        default:
                rc = -EINVAL;
                break;
        }

        RETURN(rc);
}

static int seq_req_handle(struct ptlrpc_request *req,
                          const struct lu_env *env,
                          struct seq_thread_info *info)
{
        struct lu_range *out, *in = NULL;
        struct lu_site *site;
        int rc = -EPROTO;
        __u32 *opc;
        ENTRY;

        site = req->rq_export->exp_obd->obd_lu_dev->ld_site;
        LASSERT(site != NULL);
			
        rc = req_capsule_pack(&info->sti_pill);
        if (rc)
                RETURN(err_serious(rc));

        opc = req_capsule_client_get(&info->sti_pill,
                                     &RMF_SEQ_OPC);
        if (opc != NULL) {
                out = req_capsule_server_get(&info->sti_pill,
                                             &RMF_SEQ_RANGE);
                if (out == NULL)
                        RETURN(err_serious(-EPROTO));

                if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                        in = req_capsule_client_get(&info->sti_pill,
                                                    &RMF_SEQ_RANGE);

                        LASSERT(!range_is_zero(in) && range_is_sane(in));
                }

                rc = seq_server_handle(site, env, *opc, in, out);
        } else
                rc = err_serious(-EPROTO);

        RETURN(rc);
}

static void *seq_key_init(const struct lu_context *ctx,
                          struct lu_context_key *key)
{
        struct seq_thread_info *info;

        /*
         * check that no high order allocations are incurred.
         */
        CLASSERT(CFS_PAGE_SIZE >= sizeof *info);
        OBD_ALLOC_PTR(info);
        if (info == NULL)
                info = ERR_PTR(-ENOMEM);
        return info;
}

static void seq_key_fini(const struct lu_context *ctx,
                         struct lu_context_key *key, void *data)
{
        struct seq_thread_info *info = data;
        OBD_FREE_PTR(info);
}

struct lu_context_key seq_thread_key = {
        .lct_tags = LCT_MD_THREAD,
        .lct_init = seq_key_init,
        .lct_fini = seq_key_fini
};

static void seq_thread_info_init(struct ptlrpc_request *req,
                                 struct seq_thread_info *info)
{
        int i;

        /* Mark rep buffer as req-layout stuff expects */
        for (i = 0; i < ARRAY_SIZE(info->sti_rep_buf_size); i++)
                info->sti_rep_buf_size[i] = -1;

        /* Init request capsule */
        req_capsule_init(&info->sti_pill, req, RCL_SERVER,
                         info->sti_rep_buf_size);

        req_capsule_set(&info->sti_pill, &RQF_SEQ_QUERY);
}

static void seq_thread_info_fini(struct seq_thread_info *info)
{
        req_capsule_fini(&info->sti_pill);
}

static int seq_handle(struct ptlrpc_request *req)
{
        const struct lu_env *env;
        struct seq_thread_info *info;
        int rc;

        env = req->rq_svc_thread->t_env;
        LASSERT(env != NULL);

        info = lu_context_key_get(&env->le_ctx, &seq_thread_key);
        LASSERT(info != NULL);

        seq_thread_info_init(req, info);
        rc = seq_req_handle(req, env, info);
        seq_thread_info_fini(info);

        return rc;
}

/*
 * Entry point for handling FLD RPCs called from MDT.
 */
int seq_query(struct com_thread_info *info)
{
        return seq_handle(info->cti_pill.rc_req);
}
EXPORT_SYMBOL(seq_query);

static void seq_server_proc_fini(struct lu_server_seq *seq);

#ifdef LPROCFS
static int seq_server_proc_init(struct lu_server_seq *seq)
{
        int rc;
        ENTRY;

        seq->lss_proc_dir = lprocfs_register(seq->lss_name,
                                             seq_type_proc_dir,
                                             NULL, NULL);
        if (IS_ERR(seq->lss_proc_dir)) {
                rc = PTR_ERR(seq->lss_proc_dir);
                RETURN(rc);
        }

        rc = lprocfs_add_vars(seq->lss_proc_dir,
                              seq_server_proc_list, seq);
        if (rc) {
                CERROR("%s: Can't init sequence manager "
                       "proc, rc %d\n", seq->lss_name, rc);
                GOTO(out_cleanup, rc);
        }

        RETURN(0);

out_cleanup:
        seq_server_proc_fini(seq);
        return rc;
}

static void seq_server_proc_fini(struct lu_server_seq *seq)
{
        ENTRY;
        if (seq->lss_proc_dir != NULL) {
                if (!IS_ERR(seq->lss_proc_dir))
                        lprocfs_remove(seq->lss_proc_dir);
                seq->lss_proc_dir = NULL;
        }
        EXIT;
}
#else
static int seq_server_proc_init(struct lu_server_seq *seq)
{
        return 0;
}

static void seq_server_proc_fini(struct lu_server_seq *seq)
{
        return;
}
#endif

int seq_server_init(struct lu_server_seq *seq,
                    struct dt_device *dev,
                    const char *prefix,
                    enum lu_mgr_type type,
                    const struct lu_env *env)
{
        int rc, is_srv = (type == LUSTRE_SEQ_SERVER);
        ENTRY;

	LASSERT(dev != NULL);
        LASSERT(prefix != NULL);

        seq->lss_cli = NULL;
        seq->lss_type = type;
        range_zero(&seq->lss_space);
        sema_init(&seq->lss_sem, 1);

        seq->lss_width = is_srv ?
                LUSTRE_SEQ_META_WIDTH : LUSTRE_SEQ_SUPER_WIDTH;

        snprintf(seq->lss_name, sizeof(seq->lss_name),
                 "%s-%s", (is_srv ? "srv" : "ctl"), prefix);

        rc = seq_store_init(seq, env, dev);
        if (rc)
                GOTO(out, rc);

        /* Request backing store for saved sequence info. */
        rc = seq_store_read(seq, env);
        if (rc == -ENODATA) {
                CDEBUG(D_INFO|D_WARNING, "%s: No data found "
                       "on storage\n", seq->lss_name);

                /* Nothing is read, init by default value. */
                seq->lss_space = is_srv ?
                        LUSTRE_SEQ_ZERO_RANGE:
                        LUSTRE_SEQ_SPACE_RANGE;

                if (!is_srv) {
                        /* Save default controller value to store. */
                        rc = seq_store_write(seq, env);
                        if (rc) {
                                CERROR("%s: Can't write space data, "
                                       "rc %d\n", seq->lss_name, rc);
                        }
                }
        } else if (rc) {
		CERROR("%s: Can't read space data, rc %d\n",
		       seq->lss_name, rc);
		GOTO(out, rc);
	}

        if (is_srv) {
                LASSERT(range_is_sane(&seq->lss_space));
        } else {
                LASSERT(!range_is_zero(&seq->lss_space) &&
                        range_is_sane(&seq->lss_space));
        }

        rc  = seq_server_proc_init(seq);
        if (rc)
		GOTO(out, rc);

	EXIT;
out:
	if (rc)
		seq_server_fini(seq, env);
	return rc;
}
EXPORT_SYMBOL(seq_server_init);

void seq_server_fini(struct lu_server_seq *seq,
                     const struct lu_env *env)
{
        ENTRY;

        seq_server_proc_fini(seq);
        seq_store_fini(seq, env);

        EXIT;
}
EXPORT_SYMBOL(seq_server_fini);

cfs_proc_dir_entry_t *seq_type_proc_dir = NULL;

static int __init fid_mod_init(void)
{
        printk(KERN_INFO "Lustre: Sequence Manager; "
               "info@clusterfs.com\n");

        seq_type_proc_dir = lprocfs_register(LUSTRE_SEQ_NAME,
                                             proc_lustre_root,
                                             NULL, NULL);
        if (IS_ERR(seq_type_proc_dir))
                return PTR_ERR(seq_type_proc_dir);

        lu_context_key_register(&seq_thread_key);
        return 0;
}

static void __exit fid_mod_exit(void)
{
        lu_context_key_degister(&seq_thread_key);
        if (seq_type_proc_dir != NULL && !IS_ERR(seq_type_proc_dir)) {
                lprocfs_remove(seq_type_proc_dir);
                seq_type_proc_dir = NULL;
        }
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre FID Module");
MODULE_LICENSE("GPL");

cfs_module(fid, "0.1.0", fid_mod_init, fid_mod_exit);
#endif
