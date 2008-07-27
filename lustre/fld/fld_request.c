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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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
 * lustre/fld/fld_request.c
 *
 * FLD (Fids Location Database)
 *
 * Author: Yury Umanets <umka@clusterfs.com>
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
#include <lustre_mdc.h>
#include "fld_internal.h"

/* TODO: these 3 functions are copies of flow-control code from mdc_lib.c 
 * It should be common thing. The same about mdc RPC lock */
static int fld_req_avail(struct client_obd *cli, struct mdc_cache_waiter *mcw)
{
        int rc;
        ENTRY;
        spin_lock(&cli->cl_loi_list_lock);
        rc = list_empty(&mcw->mcw_entry);
        spin_unlock(&cli->cl_loi_list_lock);
        RETURN(rc);
};

static void fld_enter_request(struct client_obd *cli)
{
        struct mdc_cache_waiter mcw;
        struct l_wait_info lwi = { 0 };

        spin_lock(&cli->cl_loi_list_lock);
        if (cli->cl_r_in_flight >= cli->cl_max_rpcs_in_flight) {
                list_add_tail(&mcw.mcw_entry, &cli->cl_cache_waiters);
                cfs_waitq_init(&mcw.mcw_waitq);
                spin_unlock(&cli->cl_loi_list_lock);
                l_wait_event(mcw.mcw_waitq, fld_req_avail(cli, &mcw), &lwi);
        } else {
                cli->cl_r_in_flight++;
                spin_unlock(&cli->cl_loi_list_lock);
        }
}

static void fld_exit_request(struct client_obd *cli)
{
        struct list_head *l, *tmp;
        struct mdc_cache_waiter *mcw;

        spin_lock(&cli->cl_loi_list_lock);
        cli->cl_r_in_flight--;
        list_for_each_safe(l, tmp, &cli->cl_cache_waiters) {
                
                if (cli->cl_r_in_flight >= cli->cl_max_rpcs_in_flight) {
                        /* No free request slots anymore */
                        break;
                }

                mcw = list_entry(l, struct mdc_cache_waiter, mcw_entry);
                list_del_init(&mcw->mcw_entry);
                cli->cl_r_in_flight++;
                cfs_waitq_signal(&mcw->mcw_waitq);
        }
        spin_unlock(&cli->cl_loi_list_lock);
}

static int fld_rrb_hash(struct lu_client_fld *fld,
                        seqno_t seq)
{
        LASSERT(fld->lcf_count > 0);
        return do_div(seq, fld->lcf_count);
}

static struct lu_fld_target *
fld_rrb_scan(struct lu_client_fld *fld, seqno_t seq)
{
        struct lu_fld_target *target;
        int hash;
        ENTRY;

        hash = fld_rrb_hash(fld, seq);

        list_for_each_entry(target, &fld->lcf_targets, ft_chain) {
                if (target->ft_idx == hash)
                        RETURN(target);
        }

        CERROR("%s: Can't find target by hash %d (seq "LPX64"). "
               "Targets (%d):\n", fld->lcf_name, hash, seq,
               fld->lcf_count);

        list_for_each_entry(target, &fld->lcf_targets, ft_chain) {
                const char *srv_name = target->ft_srv != NULL  ?
                        target->ft_srv->lsf_name : "<null>";
                const char *exp_name = target->ft_exp != NULL ?
                        (char *)target->ft_exp->exp_obd->obd_uuid.uuid :
                        "<null>";

                CERROR("  exp: 0x%p (%s), srv: 0x%p (%s), idx: "LPU64"\n",
                       target->ft_exp, exp_name, target->ft_srv,
                       srv_name, target->ft_idx);
        }

        /*
         * If target is not found, there is logical error anyway, so here is
         * LBUG() to catch this situation.
         */
        LBUG();
        RETURN(NULL);
}

static int fld_dht_hash(struct lu_client_fld *fld,
                        seqno_t seq)
{
        /* XXX: here should be DHT hash */
        return fld_rrb_hash(fld, seq);
}

static struct lu_fld_target *
fld_dht_scan(struct lu_client_fld *fld, seqno_t seq)
{
        /* XXX: here should be DHT scan code */
        return fld_rrb_scan(fld, seq);
}

struct lu_fld_hash fld_hash[3] = {
        {
                .fh_name = "DHT",
                .fh_hash_func = fld_dht_hash,
                .fh_scan_func = fld_dht_scan
        },
        {
                .fh_name = "RRB",
                .fh_hash_func = fld_rrb_hash,
                .fh_scan_func = fld_rrb_scan
        },
        {
                0,
        }
};

static struct lu_fld_target *
fld_client_get_target(struct lu_client_fld *fld,
                      seqno_t seq)
{
        struct lu_fld_target *target;
        ENTRY;

        LASSERT(fld->lcf_hash != NULL);

        spin_lock(&fld->lcf_lock);
        target = fld->lcf_hash->fh_scan_func(fld, seq);
        spin_unlock(&fld->lcf_lock);

        if (target != NULL) {
                CDEBUG(D_INFO, "%s: Found target (idx "LPU64
                       ") by seq "LPX64"\n", fld->lcf_name,
                       target->ft_idx, seq);
        }

        RETURN(target);
}

/*
 * Add export to FLD. This is usually done by CMM and LMV as they are main users
 * of FLD module.
 */
int fld_client_add_target(struct lu_client_fld *fld,
                          struct lu_fld_target *tar)
{
        const char *name = fld_target_name(tar);
        struct lu_fld_target *target, *tmp;
        ENTRY;

        LASSERT(tar != NULL);
        LASSERT(name != NULL);
        LASSERT(tar->ft_srv != NULL || tar->ft_exp != NULL);

        if (fld->lcf_flags != LUSTRE_FLD_INIT) {
                CERROR("%s: Attempt to add target %s (idx "LPU64") "
                       "on fly - skip it\n", fld->lcf_name, name,
                       tar->ft_idx);
                RETURN(0);
        } else {
                CDEBUG(D_INFO, "%s: Adding target %s (idx "
                       LPU64")\n", fld->lcf_name, name, tar->ft_idx);
        }

        OBD_ALLOC_PTR(target);
        if (target == NULL)
                RETURN(-ENOMEM);

        spin_lock(&fld->lcf_lock);
        list_for_each_entry(tmp, &fld->lcf_targets, ft_chain) {
                if (tmp->ft_idx == tar->ft_idx) {
                        spin_unlock(&fld->lcf_lock);
                        OBD_FREE_PTR(target);
                        CERROR("Target %s exists in FLD and known as %s:#"LPU64"\n",
                               name, fld_target_name(tmp), tmp->ft_idx);
                        RETURN(-EEXIST);
                }
        }

        target->ft_exp = tar->ft_exp;
        if (target->ft_exp != NULL)
                class_export_get(target->ft_exp);
        target->ft_srv = tar->ft_srv;
        target->ft_idx = tar->ft_idx;

        list_add_tail(&target->ft_chain,
                      &fld->lcf_targets);

        fld->lcf_count++;
        spin_unlock(&fld->lcf_lock);

        RETURN(0);
}
EXPORT_SYMBOL(fld_client_add_target);

/* Remove export from FLD */
int fld_client_del_target(struct lu_client_fld *fld,
                          __u64 idx)
{
        struct lu_fld_target *target, *tmp;
        ENTRY;

        spin_lock(&fld->lcf_lock);
        list_for_each_entry_safe(target, tmp,
                                 &fld->lcf_targets, ft_chain) {
                if (target->ft_idx == idx) {
                        fld->lcf_count--;
                        list_del(&target->ft_chain);
                        spin_unlock(&fld->lcf_lock);

                        if (target->ft_exp != NULL)
                                class_export_put(target->ft_exp);

                        OBD_FREE_PTR(target);
                        RETURN(0);
                }
        }
        spin_unlock(&fld->lcf_lock);
        RETURN(-ENOENT);
}
EXPORT_SYMBOL(fld_client_del_target);

static void fld_client_proc_fini(struct lu_client_fld *fld);

#ifdef LPROCFS
static int fld_client_proc_init(struct lu_client_fld *fld)
{
        int rc;
        ENTRY;

        fld->lcf_proc_dir = lprocfs_register(fld->lcf_name,
                                             fld_type_proc_dir,
                                             NULL, NULL);

        if (IS_ERR(fld->lcf_proc_dir)) {
                CERROR("%s: LProcFS failed in fld-init\n",
                       fld->lcf_name);
                rc = PTR_ERR(fld->lcf_proc_dir);
                RETURN(rc);
        }

        rc = lprocfs_add_vars(fld->lcf_proc_dir,
                              fld_client_proc_list, fld);
        if (rc) {
                CERROR("%s: Can't init FLD proc, rc %d\n",
                       fld->lcf_name, rc);
                GOTO(out_cleanup, rc);
        }

        RETURN(0);

out_cleanup:
        fld_client_proc_fini(fld);
        return rc;
}

static void fld_client_proc_fini(struct lu_client_fld *fld)
{
        ENTRY;
        if (fld->lcf_proc_dir) {
                if (!IS_ERR(fld->lcf_proc_dir))
                        lprocfs_remove(&fld->lcf_proc_dir);
                fld->lcf_proc_dir = NULL;
        }
        EXIT;
}
#else
static int fld_client_proc_init(struct lu_client_fld *fld)
{
        return 0;
}

static void fld_client_proc_fini(struct lu_client_fld *fld)
{
        return;
}
#endif

static inline int hash_is_sane(int hash)
{
        return (hash >= 0 && hash < ARRAY_SIZE(fld_hash));
}

int fld_client_init(struct lu_client_fld *fld,
                    const char *prefix, int hash)
{
#ifdef __KERNEL__
        int cache_size, cache_threshold;
#endif
        int rc;
        ENTRY;

        LASSERT(fld != NULL);

        snprintf(fld->lcf_name, sizeof(fld->lcf_name),
                 "cli-%s", prefix);

        if (!hash_is_sane(hash)) {
                CERROR("%s: Wrong hash function %#x\n",
                       fld->lcf_name, hash);
                RETURN(-EINVAL);
        }

        fld->lcf_count = 0;
        spin_lock_init(&fld->lcf_lock);
        fld->lcf_hash = &fld_hash[hash];
        fld->lcf_flags = LUSTRE_FLD_INIT;
        CFS_INIT_LIST_HEAD(&fld->lcf_targets);

#ifdef __KERNEL__
        cache_size = FLD_CLIENT_CACHE_SIZE /
                sizeof(struct fld_cache_entry);

        cache_threshold = cache_size *
                FLD_CLIENT_CACHE_THRESHOLD / 100;

        fld->lcf_cache = fld_cache_init(fld->lcf_name,
                                        FLD_CLIENT_HTABLE_SIZE,
                                        cache_size, cache_threshold);
        if (IS_ERR(fld->lcf_cache)) {
                rc = PTR_ERR(fld->lcf_cache);
                fld->lcf_cache = NULL;
                GOTO(out, rc);
        }
#endif

        rc = fld_client_proc_init(fld);
        if (rc)
                GOTO(out, rc);
        EXIT;
out:
        if (rc)
                fld_client_fini(fld);
        else
                CDEBUG(D_INFO, "%s: Using \"%s\" hash\n",
                       fld->lcf_name, fld->lcf_hash->fh_name);
        return rc;
}
EXPORT_SYMBOL(fld_client_init);

void fld_client_fini(struct lu_client_fld *fld)
{
        struct lu_fld_target *target, *tmp;
        ENTRY;

        fld_client_proc_fini(fld);

        spin_lock(&fld->lcf_lock);
        list_for_each_entry_safe(target, tmp,
                                 &fld->lcf_targets, ft_chain) {
                fld->lcf_count--;
                list_del(&target->ft_chain);
                if (target->ft_exp != NULL)
                        class_export_put(target->ft_exp);
                OBD_FREE_PTR(target);
        }
        spin_unlock(&fld->lcf_lock);

#ifdef __KERNEL__
        if (fld->lcf_cache != NULL) {
                if (!IS_ERR(fld->lcf_cache))
                        fld_cache_fini(fld->lcf_cache);
                fld->lcf_cache = NULL;
        }
#endif

        EXIT;
}
EXPORT_SYMBOL(fld_client_fini);

static int fld_client_rpc(struct obd_export *exp,
                          struct md_fld *mf, __u32 fld_op)
{
        struct ptlrpc_request *req;
        struct md_fld         *pmf;
        __u32                 *op;
        int                    rc;
        ENTRY;

        LASSERT(exp != NULL);

        req = ptlrpc_request_alloc_pack(class_exp2cliimp(exp), &RQF_FLD_QUERY,
                                        LUSTRE_MDS_VERSION, FLD_QUERY);
        if (req == NULL)
                RETURN(-ENOMEM);

        op = req_capsule_client_get(&req->rq_pill, &RMF_FLD_OPC);
        *op = fld_op;

        pmf = req_capsule_client_get(&req->rq_pill, &RMF_FLD_MDFLD);
        *pmf = *mf;

        ptlrpc_request_set_replen(req);
        req->rq_request_portal = FLD_REQUEST_PORTAL;
        ptlrpc_at_set_req_timeout(req);

        if (fld_op != FLD_LOOKUP)
                mdc_get_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);
        fld_enter_request(&exp->exp_obd->u.cli);
        rc = ptlrpc_queue_wait(req);
        fld_exit_request(&exp->exp_obd->u.cli);
        if (fld_op != FLD_LOOKUP)
                mdc_put_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);
        if (rc)
                GOTO(out_req, rc);

        pmf = req_capsule_server_get(&req->rq_pill, &RMF_FLD_MDFLD);
        if (pmf == NULL)
                GOTO(out_req, rc = -EFAULT);
        *mf = *pmf;
        EXIT;
out_req:
        ptlrpc_req_finished(req);
        return rc;
}

int fld_client_create(struct lu_client_fld *fld,
                      seqno_t seq, mdsno_t mds,
                      const struct lu_env *env)
{
        struct md_fld md_fld = { .mf_seq = seq, .mf_mds = mds };
        struct lu_fld_target *target;
        int rc;
        ENTRY;

        fld->lcf_flags |= LUSTRE_FLD_RUN;
        target = fld_client_get_target(fld, seq);
        LASSERT(target != NULL);

        CDEBUG(D_INFO, "%s: Create fld entry (seq: "LPX64"; mds: "
               LPU64") on target %s (idx "LPU64")\n", fld->lcf_name,
               seq, mds, fld_target_name(target), target->ft_idx);

#ifdef __KERNEL__
        if (target->ft_srv != NULL) {
                LASSERT(env != NULL);
                rc = fld_server_create(target->ft_srv, env, seq, mds);
        } else {
#endif
                rc = fld_client_rpc(target->ft_exp, &md_fld, FLD_CREATE);
#ifdef __KERNEL__
        }
#endif

        if (rc == 0) {
                /*
                 * Do not return result of calling fld_cache_insert()
                 * here. First of all because it may return -EEXISTS. Another
                 * reason is that, we do not want to stop proceeding because of
                 * cache errors.
                 */
                fld_cache_insert(fld->lcf_cache, seq, mds);
        } else {
                CERROR("%s: Can't create FLD entry, rc %d\n",
                       fld->lcf_name, rc);
        }

        RETURN(rc);
}
EXPORT_SYMBOL(fld_client_create);

int fld_client_delete(struct lu_client_fld *fld, seqno_t seq,
                      const struct lu_env *env)
{
        struct md_fld md_fld = { .mf_seq = seq, .mf_mds = 0 };
        struct lu_fld_target *target;
        int rc;
        ENTRY;

        fld->lcf_flags |= LUSTRE_FLD_RUN;
        fld_cache_delete(fld->lcf_cache, seq);

        target = fld_client_get_target(fld, seq);
        LASSERT(target != NULL);

        CDEBUG(D_INFO, "%s: Delete fld entry (seq: "LPX64") on "
               "target %s (idx "LPU64")\n", fld->lcf_name, seq,
               fld_target_name(target), target->ft_idx);

#ifdef __KERNEL__
        if (target->ft_srv != NULL) {
                LASSERT(env != NULL);
                rc = fld_server_delete(target->ft_srv,
                                       env, seq);
        } else {
#endif
                rc = fld_client_rpc(target->ft_exp,
                                    &md_fld, FLD_DELETE);
#ifdef __KERNEL__
        }
#endif

        RETURN(rc);
}
EXPORT_SYMBOL(fld_client_delete);

int fld_client_lookup(struct lu_client_fld *fld,
                      seqno_t seq, mdsno_t *mds,
                      const struct lu_env *env)
{
        struct md_fld md_fld = { .mf_seq = seq, .mf_mds = 0 };
        struct lu_fld_target *target;
        int rc;
        ENTRY;

        fld->lcf_flags |= LUSTRE_FLD_RUN;

        rc = fld_cache_lookup(fld->lcf_cache, seq, mds);
        if (rc == 0)
                RETURN(0);

        /* Can not find it in the cache */
        target = fld_client_get_target(fld, seq);
        LASSERT(target != NULL);

        CDEBUG(D_INFO, "%s: Lookup fld entry (seq: "LPX64") on "
               "target %s (idx "LPU64")\n", fld->lcf_name, seq,
               fld_target_name(target), target->ft_idx);

#ifdef __KERNEL__
        if (target->ft_srv != NULL) {
                LASSERT(env != NULL);
                rc = fld_server_lookup(target->ft_srv,
                                       env, seq, &md_fld.mf_mds);
        } else {
#endif
                /*
                 * insert the 'inflight' sequence. No need to protect that,
                 * we are trying to reduce numbers of RPC but not restrict
                 * to them exactly one 
                 */
                fld_cache_insert_inflight(fld->lcf_cache, seq);
                rc = fld_client_rpc(target->ft_exp,
                                    &md_fld, FLD_LOOKUP);
#ifdef __KERNEL__
        }
#endif
        if (seq < FID_SEQ_START) {
                /*
                 * The current solution for IGIF is to bind it to mds0.
                 * In the future, this should be fixed once IGIF can be found
                 * in FLD.
                 */ 
                md_fld.mf_mds = 0;
                rc = 0;
        }

        if (rc == 0) {
                *mds = md_fld.mf_mds;

                /*
                 * Do not return error here as well. See previous comment in
                 * same situation in function fld_client_create().
                 */
                fld_cache_insert(fld->lcf_cache, seq, *mds);
        } else {
                /* remove 'inflight' seq if it exists */
                fld_cache_delete(fld->lcf_cache, seq);
        }
        RETURN(rc);
}
EXPORT_SYMBOL(fld_client_lookup);

void fld_client_flush(struct lu_client_fld *fld)
{
#ifdef __KERNEL__
        fld_cache_flush(fld->lcf_cache);
#endif
}
EXPORT_SYMBOL(fld_client_flush);
