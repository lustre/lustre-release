/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  fld/fld.c 
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
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
#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/module.h>

#include <linux/obd.h>
#include <linux/obd_class.h>
#include <linux/lustre_ver.h>
#include <linux/obd_support.h>
#include <linux/lprocfs_status.h>

#include <linux/md_object.h>
#include "fld_internal.h"
 
/*XXX maybe these 2 items should go to sbi*/
struct fld_cache_info *fld_cache = NULL;

static int dht_mdt_hash(__u64 seq)
{
        return 0; 
}
struct obd_export* get_fld_exp(struct obd_export *exp, __u64 seq)
{
        int seq_mds;
 
        seq_mds = dht_mdt_hash(seq);
        CDEBUG(D_INFO, "mds number %d\n", seq_mds);
       
        /*get exp according to lu_seq*/
        return exp;
}
 
enum {
        FLD_HTABLE_BITS = 8,
        FLD_HTABLE_SIZE = (1 << FLD_HTABLE_BITS),
        FLD_HTABLE_MASK = FLD_HTABLE_SIZE - 1
};

static __u32 fld_hash(__u64 lu_seq)
{
        return lu_seq;
}


static int fld_cache_insert(struct fld_cache_info *fld_cache, __u64 lu_seq, 
                            __u64 mds_num)
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

static struct fld_cache* 
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

static void fld_cache_delete(struct fld_cache_info *fld_cache, __u64 lu_seq)
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

int fld_create(struct obd_export *exp, __u64 seq, __u64 mds_num)
{
        struct obd_export *fld_exp;
        struct md_fld      md_fld; 
        __u32 rc;
        ENTRY;

        fld_exp = get_fld_exp(exp, seq);
        if (!fld_exp)
                RETURN(-EINVAL);

        md_fld.mf_seq = seq;
        md_fld.mf_mds = mds_num;

        rc = obd_set_info(fld_exp, strlen("fld_create"), "fld_create", 
                          sizeof(struct md_fld), &md_fld);
        fld_cache_insert(fld_cache, seq, mds_num);

        RETURN(rc);
}

int fld_delete(struct obd_export *exp, __u64 seq, __u64 mds_num)
{
        struct obd_export *fld_exp;
        struct md_fld      md_fld; 
        __u32 rc;
        
        fld_cache_delete(fld_cache, seq);

        fld_exp = get_fld_exp(exp, seq);
        if (!fld_exp)
                RETURN(-EINVAL);

        md_fld.mf_seq = seq;
        md_fld.mf_mds = mds_num;

        rc = obd_set_info(fld_exp, strlen("fld_delete"), "fld_delete",
                          sizeof(struct md_fld), &md_fld);

        RETURN(rc);
}

int fld_get(struct obd_export *exp, __u64 lu_seq, __u64 *mds_num)
{
        struct obd_export *fld_exp;
        struct md_fld      md_fld; 
        int    vallen, rc;
 
        fld_exp = get_fld_exp(exp, lu_seq);
        if (!fld_exp);
                RETURN(-EINVAL);

        md_fld.mf_seq = lu_seq;
       
        vallen = sizeof(struct md_fld);
 
        rc = obd_get_info(fld_exp, strlen("fld_delete"), "fld_delete",
                          &vallen, &md_fld);

        *mds_num = md_fld.mf_mds;
 
        RETURN(rc);
}

/*lookup fid in the namespace of pfid according to the name*/
int fld_lookup(struct obd_export *exp, __u64 lu_seq, __u64 *mds_num)
{
        struct fld_cache *fld; 
        int rc;
        ENTRY;

        /*lookup it in the cache*/
        fld = fld_cache_lookup(fld_cache, lu_seq);
        if (fld != NULL) {
                *mds_num = fld->fld_mds;
                RETURN(0);
        }
        /*can not find it in the cache*/ 
        rc = fld_get(exp, lu_seq, mds_num);
        if (rc)
                RETURN(rc); 
       
        rc = fld_cache_insert(fld_cache, lu_seq, *mds_num);
 
        RETURN(rc);
}

static int fld_init(void)
{
        ENTRY;

        OBD_ALLOC_PTR(fld_cache);
        if (fld_cache == NULL)
                RETURN(-ENOMEM);        
       
        /*init fld cache info*/
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

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre fld Prototype");
MODULE_LICENSE("GPL");

cfs_module(mdd, "0.0.2", fld_mod_init, fld_mod_exit);
