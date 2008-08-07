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
 */

#ifndef __CLASS_HASH_H
#define __CLASS_HASH_H

#include <lustre_lib.h>

/* #define LUSTRE_HASH_DEBUG 1 */

/* define the hash bucket*/
struct lustre_hash_bucket { 
        struct hlist_head lhb_head;
        spinlock_t lhb_lock;
#ifdef LUSTRE_HASH_DEBUG
        /* the number of hash item per bucket, 
         * it will help us to analyse the hash distribute 
         */
        int lhb_item_count; 
#endif
};

struct lustre_hash_operations;

struct lustre_class_hash_body {
        char hashname[128];
        spinlock_t lchb_lock; /* body lock */
        struct lustre_hash_bucket *lchb_hash_tables;
        __u32 lchb_hash_max_size; /* define the hash tables size */
        /* define the hash operations */
        struct lustre_hash_operations *lchb_hash_operations;
};

/* hash operations method define */
struct lustre_hash_operations {
        __u32 (*lustre_hashfn) (struct lustre_class_hash_body *hash_body, 
                                void *key);
        int   (*lustre_hash_key_compare) (void *key, 
                                          struct hlist_node *compared_hnode);
        /* add refcount */ 
        void* (*lustre_hash_object_refcount_get) (struct hlist_node *hash_item);
        /* dec refcount */
        void  (*lustre_hash_object_refcount_put) (struct hlist_node *hash_item);
};

static inline struct hlist_node * 
lustre_hash_getitem_in_bucket_nolock(struct lustre_class_hash_body *hash_body, 
                                     int hashent, void *key)
{
        struct lustre_hash_bucket *bucket;
        struct hlist_node  *hash_item_node;
        struct lustre_hash_operations *hop = hash_body->lchb_hash_operations;
        int find = 0;
        ENTRY;

        bucket = &hash_body->lchb_hash_tables[hashent];
        hlist_for_each(hash_item_node, &(bucket->lhb_head)) {
                find = hop->lustre_hash_key_compare(key, hash_item_node);
                if (find == 1)
                        break;
        }
        RETURN(find == 1 ? hash_item_node : NULL);
}

static inline int 
lustre_hash_delitem_nolock(struct lustre_class_hash_body *hash_body, 
                           int hashent, struct hlist_node * hash_item)
{
        struct lustre_hash_operations *hop = hash_body->lchb_hash_operations;

        hlist_del_init(hash_item);

        hop->lustre_hash_object_refcount_put(hash_item);

#ifdef LUSTRE_HASH_DEBUG
        hash_body->lchb_hash_tables[hashent].lhb_item_count--;
        CDEBUG(D_INFO, "hashname[%s] bucket[%d] has [%d] hashitem\n", 
                        hash_body->hashname, hashent, 
                        hash_body->lchb_hash_tables[hashent].lhb_item_count);
#endif

        RETURN(0);
}

typedef void (*hash_item_iterate_cb) (void *obj, void *data);

int lustre_hash_init(struct lustre_class_hash_body **hash_body,
                     char *hashname, __u32 hashsize, 
                     struct lustre_hash_operations *hash_operations);
void lustre_hash_exit(struct lustre_class_hash_body **hash_body);
int lustre_hash_additem_unique(struct lustre_class_hash_body *hash_body, 
                               void *key, struct hlist_node *actual_hnode);
void *lustre_hash_findadd_unique(struct lustre_class_hash_body *hash_body,
                                 void *key, struct hlist_node *actual_hnode);
int lustre_hash_additem(struct lustre_class_hash_body *hash_body, void *key, 
                        struct hlist_node *actual_hnode);
int lustre_hash_delitem_by_key(struct lustre_class_hash_body *hash_body, 
                               void *key);
int lustre_hash_delitem(struct lustre_class_hash_body *hash_body, void *key, 
                        struct hlist_node *hash_item);
void lustre_hash_bucket_iterate(struct lustre_class_hash_body *hash_body,
                                void *key, hash_item_iterate_cb,
                                void *data);
void lustre_hash_iterate_all(struct lustre_class_hash_body *hash_body,
                             hash_item_iterate_cb, void *data);

void * lustre_hash_get_object_by_key(struct lustre_class_hash_body *hash_body,
                                      void *key);

__u32 djb2_hashfn(struct lustre_class_hash_body *hash_body, void* key,
                  size_t size);

/* ( uuid <-> export ) hash operations define */
__u32 uuid_hashfn(struct lustre_class_hash_body *hash_body,  void * key);
int uuid_hash_key_compare(void *key, struct hlist_node * compared_hnode);
void * uuid_export_refcount_get(struct hlist_node * actual_hnode);
void uuid_export_refcount_put(struct hlist_node * actual_hnode);

/* ( nid <-> export ) hash operations define */
__u32 nid_hashfn(struct lustre_class_hash_body *hash_body,  void * key);
int nid_hash_key_compare(void *key, struct hlist_node * compared_hnode);
void * nid_export_refcount_get(struct hlist_node * actual_hnode);
void nid_export_refcount_put(struct hlist_node * actual_hnode);

/* ( net_peer <-> connection ) hash operations define */
__u32 conn_hashfn(struct lustre_class_hash_body *hash_body,  void * key);
int conn_hash_key_compare(void *key, struct hlist_node * compared_hnode);
void * conn_refcount_get(struct hlist_node * actual_hnode);
void conn_refcount_put(struct hlist_node * actual_hnode);

/* ( nid <-> nidstats ) hash operations define. uses nid_hashfn */
int nidstats_hash_key_compare(void *key, struct hlist_node * compared_hnode);
void* nidstats_refcount_get(struct hlist_node * actual_hnode);
void nidstats_refcount_put(struct hlist_node * actual_hnode);
extern struct lustre_hash_operations nid_stat_hash_operations;

#endif /* __CLASS_HASH_H */
