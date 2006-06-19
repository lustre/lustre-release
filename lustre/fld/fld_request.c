/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/fld/fld_handler.c
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
#include "fld_internal.h"

#ifdef __KERNEL__
extern struct fld_cache_info *fld_cache;

static __u32 fld_cache_hash(__u64 seq)
{
        return seq;
}

static int
fld_cache_insert(struct fld_cache_info *fld_cache,
                 __u64 seq, __u64 mds)
{
        struct fld_cache *fld;
        struct hlist_head *bucket;
        struct hlist_node *scan;
        int rc = 0;
        ENTRY;

        bucket = fld_cache->fld_hash + (fld_cache_hash(seq) &
                                        fld_cache->fld_hash_mask);

        OBD_ALLOC_PTR(fld);
        if (!fld)
                RETURN(-ENOMEM);

        INIT_HLIST_NODE(&fld->fld_list);
        fld->fld_mds = mds;
        fld->fld_seq = seq;

        spin_lock(&fld_cache->fld_lock);
        hlist_for_each_entry(fld, scan, bucket, fld_list) {
                if (fld->fld_seq == seq)
                        GOTO(exit_unlock, rc = -EEXIST);
        }
        hlist_add_head(&fld->fld_list, bucket);
        EXIT;
exit_unlock:
        spin_unlock(&fld_cache->fld_lock);
        if (rc != 0)
                OBD_FREE(fld, sizeof(*fld));
        return rc;
}

static struct fld_cache *
fld_cache_lookup(struct fld_cache_info *fld_cache, __u64 seq)
{
        struct hlist_head *bucket;
        struct hlist_node *scan;
        struct fld_cache *fld;
        ENTRY;

        bucket = fld_cache->fld_hash + (fld_cache_hash(seq) &
                                        fld_cache->fld_hash_mask);

        spin_lock(&fld_cache->fld_lock);
        hlist_for_each_entry(fld, scan, bucket, fld_list) {
                if (fld->fld_seq == seq) {
                        spin_unlock(&fld_cache->fld_lock);
                        RETURN(fld);
                }
        }
        spin_unlock(&fld_cache->fld_lock);

        RETURN(NULL);
}

static void
fld_cache_delete(struct fld_cache_info *fld_cache, __u64 seq)
{
        struct hlist_head *bucket;
        struct hlist_node *scan;
        struct fld_cache *fld;
        ENTRY;

        bucket = fld_cache->fld_hash + (fld_cache_hash(seq) &
                                        fld_cache->fld_hash_mask);

        spin_lock(&fld_cache->fld_lock);
        hlist_for_each_entry(fld, scan, bucket, fld_list) {
                if (fld->fld_seq == seq) {
                        hlist_del_init(&fld->fld_list);
                        GOTO(out_unlock, 0);
                }
        }

        EXIT;
out_unlock:
        spin_unlock(&fld_cache->fld_lock);
        return;
}
#endif

static int fld_rrb_hash(struct lu_client_fld *fld, __u64 seq)
{
        if (fld->fld_count == 0)
                return 0;
        
        return do_div(seq, fld->fld_count);
}

static int fld_dht_hash(struct lu_client_fld *fld, __u64 seq)
{
        /* XXX: here should DHT hash */
        return fld_rrb_hash(fld, seq);
}

static struct lu_fld_hash fld_hash[3] = {
        {
                .fh_name = "DHT",
                .fh_func = fld_dht_hash
        },
        {
                .fh_name = "Round Robin",
                .fh_func = fld_rrb_hash
        },
        {
                0,
        }
};

static struct obd_export *
fld_client_get_export(struct lu_client_fld *fld, __u64 seq)
{
        struct obd_export *fld_exp;
        int count = 0, hash;
        ENTRY;

        LASSERT(fld->fld_hash != NULL);
        hash = fld->fld_hash->fh_func(fld, seq);

        spin_lock(&fld->fld_lock);
        list_for_each_entry(fld_exp,
                            &fld->fld_exports, exp_fld_chain) {
                if (count == hash) {
                        spin_unlock(&fld->fld_lock);
                        RETURN(fld_exp);
                }
                count++;
        }
        spin_unlock(&fld->fld_lock);
        RETURN(NULL);
}

/* add export to FLD. This is usually done by CMM and LMV as they are main users
 * of FLD module. */
int fld_client_add_export(struct lu_client_fld *fld,
                          struct obd_export *exp)
{
        struct obd_export *fld_exp;
        ENTRY;

        LASSERT(exp != NULL);

        CDEBUG(D_INFO|D_WARNING, "adding export %s\n",
	       exp->exp_client_uuid.uuid);
        
        spin_lock(&fld->fld_lock);
        list_for_each_entry(fld_exp, &fld->fld_exports, exp_fld_chain) {
                if (obd_uuid_equals(&fld_exp->exp_client_uuid,
                                    &exp->exp_client_uuid))
                {
                        spin_unlock(&fld->fld_lock);
                        RETURN(-EEXIST);
                }
        }
        
        fld_exp = class_export_get(exp);
        list_add_tail(&fld_exp->exp_fld_chain,
                      &fld->fld_exports);
        fld->fld_count++;
        
        spin_unlock(&fld->fld_lock);
        
        RETURN(0);
}
EXPORT_SYMBOL(fld_client_add_export);

/* remove export from FLD */
int fld_client_del_export(struct lu_client_fld *fld,
                          struct obd_export *exp)
{
        struct obd_export *fld_exp;
        struct obd_export *tmp;
        ENTRY;

        spin_lock(&fld->fld_lock);
        list_for_each_entry_safe(fld_exp, tmp, &fld->fld_exports, exp_fld_chain) {
                if (obd_uuid_equals(&fld_exp->exp_client_uuid,
                                    &exp->exp_client_uuid))
                {
                        fld->fld_count--;
                        list_del(&fld_exp->exp_fld_chain);
                        class_export_get(fld_exp);

                        spin_unlock(&fld->fld_lock);
                        RETURN(0);
                }
        }
        spin_unlock(&fld->fld_lock);
        RETURN(-ENOENT);
}
EXPORT_SYMBOL(fld_client_del_export);

int fld_client_init(struct lu_client_fld *fld, int hash)
{
        int rc = 0;
        ENTRY;

        LASSERT(fld != NULL);

        if (hash < 0 || hash >= LUSTRE_CLI_FLD_HASH_LAST) {
                CERROR("wrong hash function 0x%x\n", hash);
                RETURN(-EINVAL);
        }
        
        INIT_LIST_HEAD(&fld->fld_exports);
        spin_lock_init(&fld->fld_lock);
        fld->fld_hash = &fld_hash[hash];
        fld->fld_count = 0;
        
        CDEBUG(D_INFO|D_WARNING, "Client FLD initialized, using \"%s\" hash\n",
               fld->fld_hash->fh_name);
        RETURN(rc);
}
EXPORT_SYMBOL(fld_client_init);

void fld_client_fini(struct lu_client_fld *fld)
{
        struct obd_export *fld_exp;
        struct obd_export *tmp;
        ENTRY;

        spin_lock(&fld->fld_lock);
        list_for_each_entry_safe(fld_exp, tmp,
                                 &fld->fld_exports, exp_fld_chain) {
                fld->fld_count--;
                list_del(&fld_exp->exp_fld_chain);
                class_export_get(fld_exp);
        }
        spin_unlock(&fld->fld_lock);
        CDEBUG(D_INFO|D_WARNING, "Client FLD finalized\n");
        EXIT;
}
EXPORT_SYMBOL(fld_client_fini);

static int
fld_client_rpc(struct obd_export *exp,
               struct md_fld *mf, __u32 fld_op)
{
        int size[2] = {sizeof(__u32), sizeof(struct md_fld)}, rc;
        int mf_size = sizeof(struct md_fld);
        struct ptlrpc_request *req;
        struct md_fld *pmf;
        __u32 *op;
        ENTRY;

        LASSERT(exp != NULL);

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
                  __u64 seq, __u64 mds)
{
        struct obd_export *fld_exp;
        struct md_fld      md_fld;
        __u32 rc;
        ENTRY;

        fld_exp = fld_client_get_export(fld, seq);
        if (!fld_exp)
                RETURN(-EINVAL);
        md_fld.mf_seq = seq;
        md_fld.mf_mds = mds;
        
        rc = fld_client_rpc(fld_exp, &md_fld, FLD_CREATE);
#ifdef __KERNEL__
        fld_cache_insert(fld_cache, seq, mds);
#endif
        
        RETURN(rc);
}
EXPORT_SYMBOL(fld_client_create);

int
fld_client_delete(struct lu_client_fld *fld,
                  __u64 seq, __u64 mds)
{
        struct obd_export *fld_exp;
        struct md_fld      md_fld;
        __u32 rc;

#ifdef __KERNEL__
        fld_cache_delete(fld_cache, seq);
#endif
        
        fld_exp = fld_client_get_export(fld, seq);
        if (!fld_exp)
                RETURN(-EINVAL);

        md_fld.mf_seq = seq;
        md_fld.mf_mds = mds;

        rc = fld_client_rpc(fld_exp, &md_fld, FLD_DELETE);
        RETURN(rc);
}
EXPORT_SYMBOL(fld_client_delete);

static int
fld_client_get(struct lu_client_fld *fld,
               __u64 seq, __u64 *mds)
{
        struct obd_export *fld_exp;
        struct md_fld md_fld;
        int rc;
        ENTRY;

        fld_exp = fld_client_get_export(fld, seq);
        if (!fld_exp)
                RETURN(-EINVAL);
                
        md_fld.mf_seq = seq;
        rc = fld_client_rpc(fld_exp,
                            &md_fld, FLD_LOOKUP);
        if (rc == 0)
                *mds = md_fld.mf_mds;

        RETURN(rc);
}

/* lookup fid in the namespace of pfid according to the name */
int
fld_client_lookup(struct lu_client_fld *fld,
                  __u64 seq, __u64 *mds)
{
#ifdef __KERNEL__
        struct fld_cache *fld_entry;
#endif
        int rc;
        ENTRY;

#ifdef __KERNEL__
        /* lookup it in the cache */
        fld_entry = fld_cache_lookup(fld_cache, seq);
        if (fld_entry != NULL) {
                *mds = fld_entry->fld_mds;
                RETURN(0);
        }
#endif
        
        /* can not find it in the cache */
        rc = fld_client_get(fld, seq, mds);
        if (rc)
                RETURN(rc);

#ifdef __KERNEL__
        rc = fld_cache_insert(fld_cache, seq, *mds);
#endif
        
        RETURN(rc);
}
EXPORT_SYMBOL(fld_client_lookup);
