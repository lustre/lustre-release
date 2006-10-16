/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/fld/fld_request.c
 *  FLD (Fids Location Database)
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
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

        CDEBUG(D_INFO|D_WARNING, "%s: Adding target %s (idx "LPU64")\n",
	       fld->lcf_name, name, tar->ft_idx);

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
                        lprocfs_remove(fld->lcf_proc_dir);
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

/* 1M of FLD cache will not hurt client a lot */
#define FLD_CACHE_SIZE 1024000

/* cache threshold is 10 percent of size */
#define FLD_CACHE_THRESHOLD 10

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
                 "cli-srv-%s", prefix);

        if (!hash_is_sane(hash)) {
                CERROR("%s: Wrong hash function %#x\n",
                       fld->lcf_name, hash);
                RETURN(-EINVAL);
        }

        fld->lcf_count = 0;
        spin_lock_init(&fld->lcf_lock);
        sema_init(&fld->lcf_sem, 1);
        fld->lcf_hash = &fld_hash[hash];
        INIT_LIST_HEAD(&fld->lcf_targets);

#ifdef __KERNEL__
        cache_size = FLD_CACHE_SIZE /
                sizeof(struct fld_cache_entry);

        cache_threshold = cache_size *
                FLD_CACHE_THRESHOLD / 100;

        fld->lcf_cache = fld_cache_init(FLD_HTABLE_SIZE,
                                        cache_size,
                                        cache_threshold);
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
                CDEBUG(D_INFO|D_WARNING,
                       "%s: Using \"%s\" hash\n",
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
        int size[3] = { sizeof(struct ptlrpc_body),
                        sizeof(__u32),
                        sizeof(struct md_fld) };
        struct ptlrpc_request *req;
        struct req_capsule pill;
        struct md_fld *pmf;
        __u32 *op;
        int rc;
        ENTRY;

        LASSERT(exp != NULL);

        req = ptlrpc_prep_req(class_exp2cliimp(exp),
                              LUSTRE_MDS_VERSION,
                              FLD_QUERY, 3, size,
                              NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        req_capsule_init(&pill, req, RCL_CLIENT, NULL);
        req_capsule_set(&pill, &RQF_FLD_QUERY);

        op = req_capsule_client_get(&pill, &RMF_FLD_OPC);
        *op = fld_op;

        pmf = req_capsule_client_get(&pill, &RMF_FLD_MDFLD);
        *pmf = *mf;

        size[1] = sizeof(struct md_fld);
        ptlrpc_req_set_repsize(req, 2, size);
        req->rq_request_portal = FLD_REQUEST_PORTAL;

        if (fld_op != FLD_LOOKUP)
                mdc_get_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        if (fld_op != FLD_LOOKUP)
                mdc_put_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);
        if (rc)
                GOTO(out_req, rc);

        pmf = req_capsule_server_get(&pill, &RMF_FLD_MDFLD);
        if (pmf == NULL)
                GOTO(out_req, rc = -EFAULT);
        *mf = *pmf;
        EXIT;
out_req:
        req_capsule_fini(&pill);
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

        down(&fld->lcf_sem);
        
        target = fld_client_get_target(fld, seq);
        LASSERT(target != NULL);

        CDEBUG(D_INFO, "%s: Create fld entry (seq: "LPX64"; mds: "
               LPU64") on target %s (idx "LPU64")\n", fld->lcf_name,
               seq, mds, fld_target_name(target), target->ft_idx);
        
#ifdef __KERNEL__
        if (target->ft_srv != NULL) {
                LASSERT(env != NULL);
                rc = fld_server_create(target->ft_srv,
                                       env, seq, mds);
        } else {
#endif
                rc = fld_client_rpc(target->ft_exp,
                                    &md_fld, FLD_CREATE);
#ifdef __KERNEL__
        }
#endif

        if (rc == 0) {
                /*
                 * Do not return result of calling fld_cache_insert()
                 * here. First of all because it may return -EEXISTS. Another
                 * reason is that, we do not want to stop proceeding because of
                 * cache errors. --umka
                 */
                fld_cache_insert(fld->lcf_cache, seq, mds);
        } else {
                CERROR("%s: Can't create FLD entry, rc %d\n",
                       fld->lcf_name, rc);
        }
        up(&fld->lcf_sem);
        
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

        down(&fld->lcf_sem);
        
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

        up(&fld->lcf_sem);
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

        down(&fld->lcf_sem);
        
        /* Lookup it in the cache */
        rc = fld_cache_lookup(fld->lcf_cache, seq, mds);
        if (rc == 0) {
                up(&fld->lcf_sem);
                RETURN(0);
        }

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
                rc = fld_client_rpc(target->ft_exp,
                                    &md_fld, FLD_LOOKUP);
#ifdef __KERNEL__
        }
#endif
        if (rc == 0) {
                *mds = md_fld.mf_mds;

                /*
                 * Do not return error here as well. See previous comment in
                 * same situation in function fld_client_create(). --umka
                 */
                fld_cache_insert(fld->lcf_cache, seq, *mds);
        }
        up(&fld->lcf_sem);
        RETURN(rc);
}
EXPORT_SYMBOL(fld_client_lookup);
