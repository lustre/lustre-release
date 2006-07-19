/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/fld/fld_cache.c
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
struct fld_cache_info *
fld_cache_init(int size)
{
	struct fld_cache_info *cache;
        int i;
        ENTRY;

        OBD_ALLOC_PTR(cache);
        if (cache == NULL)
                RETURN(ERR_PTR(-ENOMEM));

	cache->fci_size = size;
        spin_lock_init(&cache->fci_lock);

        /* init fld cache info */
        cache->fci_hash_mask = size - 1;
        OBD_ALLOC(cache->fci_hash, size *
                  sizeof(*cache->fci_hash));
        if (cache->fci_hash == NULL) {
                OBD_FREE_PTR(cache);
                RETURN(ERR_PTR(-ENOMEM));
        }

        for (i = 0; i < size; i++)
                INIT_HLIST_HEAD(&cache->fci_hash[i]);

        CDEBUG(D_INFO|D_WARNING, "FLD cache size %d\n",
               size);

        RETURN(cache);
}
EXPORT_SYMBOL(fld_cache_init);

void
fld_cache_fini(struct fld_cache_info *cache)
{
        struct fld_cache_entry *flde;
        struct hlist_head *bucket;
        struct hlist_node *scan;
        struct hlist_node *next;
	int i;
        ENTRY;

        LASSERT(cache != NULL);

	/* free all cache entries */
	spin_lock(&cache->fci_lock);
	for (i = 0; i < cache->fci_size; i++) {
		bucket = cache->fci_hash + i;
		hlist_for_each_entry_safe(flde, scan, next, bucket, fce_list) {
			hlist_del_init(&flde->fce_list);
			OBD_FREE_PTR(flde);
		}
	}
        spin_unlock(&cache->fci_lock);

	/* free cache hash table and cache itself */
	OBD_FREE(cache->fci_hash, cache->fci_size *
		 sizeof(*cache->fci_hash));
	OBD_FREE_PTR(cache);
	
        EXIT;
}
EXPORT_SYMBOL(fld_cache_fini);

int
fld_cache_insert(struct fld_cache_info *cache,
                 seqno_t seq, mdsno_t mds)
{
        struct fld_cache_entry *flde, *fldt;
        struct hlist_head *bucket;
        struct hlist_node *scan;
        int rc = 0;
        ENTRY;

        OBD_ALLOC_PTR(flde);
        if (!flde)
                RETURN(-ENOMEM);

        bucket = cache->fci_hash + (fld_cache_hash(seq) &
				    cache->fci_hash_mask);

        spin_lock(&cache->fci_lock);
        hlist_for_each_entry(fldt, scan, bucket, fce_list) {
                if (fldt->fce_seq == seq)
                        GOTO(exit_unlock, rc = -EEXIST);
        }

        INIT_HLIST_NODE(&flde->fce_list);
        flde->fce_mds = mds;
        flde->fce_seq = seq;

        hlist_add_head(&flde->fce_list, bucket);

        EXIT;
exit_unlock:
        spin_unlock(&cache->fci_lock);
        if (rc != 0)
                OBD_FREE_PTR(flde);
        return rc;
}
EXPORT_SYMBOL(fld_cache_insert);

void
fld_cache_delete(struct fld_cache_info *cache, seqno_t seq)
{
        struct fld_cache_entry *flde;
        struct hlist_head *bucket;
        struct hlist_node *scan;
        ENTRY;

        bucket = cache->fci_hash + (fld_cache_hash(seq) &
				    cache->fci_hash_mask);
	
        spin_lock(&cache->fci_lock);
        hlist_for_each_entry(flde, scan, bucket, fce_list) {
                if (flde->fce_seq == seq) {
                        hlist_del_init(&flde->fce_list);
			OBD_FREE_PTR(flde);
                        GOTO(out_unlock, 0);
                }
        }

        EXIT;
out_unlock:
        spin_unlock(&cache->fci_lock);
}
EXPORT_SYMBOL(fld_cache_delete);

int
fld_cache_lookup(struct fld_cache_info *cache,
                 seqno_t seq, mdsno_t *mds)
{
        struct fld_cache_entry *flde;
        struct hlist_head *bucket;
        struct hlist_node *scan;
        ENTRY;

        bucket = cache->fci_hash + (fld_cache_hash(seq) &
				    cache->fci_hash_mask);

        spin_lock(&cache->fci_lock);
        hlist_for_each_entry(flde, scan, bucket, fce_list) {
                if (flde->fce_seq == seq) {
                        *mds = flde->fce_mds;
                        spin_unlock(&cache->fci_lock);
                        RETURN(0);
                }
        }
        spin_unlock(&cache->fci_lock);
        RETURN(-ENOENT);
}
EXPORT_SYMBOL(fld_cache_lookup);
#else
int
fld_cache_insert(struct fld_cache_info *cache,
                 seqno_t seq, mdsno_t mds)
{
        return -ENOTSUPP;
}
EXPORT_SYMBOL(fld_cache_insert);

void
fld_cache_delete(struct fld_cache_info *cache, seqno_t seq)
{
        return;
}
EXPORT_SYMBOL(fld_cache_delete);

int
fld_cache_lookup(struct fld_cache_info *cache,
                 seqno_t seq, mdsno_t *mds)
{
        return -ENOTSUPP;
}
EXPORT_SYMBOL(fld_cache_lookup);
#endif

