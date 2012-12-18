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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/lustre_handles.c
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS
#ifndef __KERNEL__
# include <liblustre.h>
#endif

#include <obd_support.h>
#include <lustre_handles.h>
#include <lustre_lib.h>

#if !defined(HAVE_RCU) || !defined(__KERNEL__)
# define list_add_rcu            cfs_list_add
# define list_del_rcu            cfs_list_del
# define list_for_each_rcu       cfs_list_for_each
# define list_for_each_safe_rcu  cfs_list_for_each_safe
# define list_for_each_entry_rcu cfs_list_for_each_entry
# define rcu_read_lock()         cfs_spin_lock(&bucket->lock)
# define rcu_read_unlock()       cfs_spin_unlock(&bucket->lock)
#endif /* ifndef HAVE_RCU */

static __u64 handle_base;
#define HANDLE_INCR 7
static cfs_spinlock_t handle_base_lock;

static struct handle_bucket {
        cfs_spinlock_t  lock;
        cfs_list_t      head;
} *handle_hash;

#ifdef __arch_um__
/* For unknown reason, UML uses kmalloc rather than vmalloc to allocate
 * memory(OBD_VMALLOC). Therefore, we have to redefine the
 * HANDLE_HASH_SIZE to make the hash heads don't exceed 128K.
 */
#define HANDLE_HASH_SIZE 4096
#else
#define HANDLE_HASH_SIZE (1 << 16)
#endif /* ifdef __arch_um__ */

#define HANDLE_HASH_MASK (HANDLE_HASH_SIZE - 1)

/*
 * Generate a unique 64bit cookie (hash) for a handle and insert it into
 * global (per-node) hash-table.
 */
void class_handle_hash(struct portals_handle *h, portals_handle_addref_cb cb)
{
        struct handle_bucket *bucket;
        ENTRY;

        LASSERT(h != NULL);
        LASSERT(cfs_list_empty(&h->h_link));

        /*
         * This is fast, but simplistic cookie generation algorithm, it will
         * need a re-do at some point in the future for security.
         */
        cfs_spin_lock(&handle_base_lock);
        handle_base += HANDLE_INCR;

        h->h_cookie = handle_base;
        if (unlikely(handle_base == 0)) {
                /*
                 * Cookie of zero is "dangerous", because in many places it's
                 * assumed that 0 means "unassigned" handle, not bound to any
                 * object.
                 */
                CWARN("The universe has been exhausted: cookie wrap-around.\n");
                handle_base += HANDLE_INCR;
        }
        cfs_spin_unlock(&handle_base_lock);
 
        h->h_addref = cb;
        cfs_spin_lock_init(&h->h_lock);

        bucket = &handle_hash[h->h_cookie & HANDLE_HASH_MASK];
        cfs_spin_lock(&bucket->lock);
        list_add_rcu(&h->h_link, &bucket->head);
        h->h_in = 1;
        cfs_spin_unlock(&bucket->lock);

        CDEBUG(D_INFO, "added object %p with handle "LPX64" to hash\n",
               h, h->h_cookie);
        EXIT;
}

static void class_handle_unhash_nolock(struct portals_handle *h)
{
        if (cfs_list_empty(&h->h_link)) {
                CERROR("removing an already-removed handle ("LPX64")\n",
                       h->h_cookie);
                return;
        }

        CDEBUG(D_INFO, "removing object %p with handle "LPX64" from hash\n",
               h, h->h_cookie);

        cfs_spin_lock(&h->h_lock);
        if (h->h_in == 0) {
                cfs_spin_unlock(&h->h_lock);
                return;
        }
        h->h_in = 0;
        cfs_spin_unlock(&h->h_lock);
        list_del_rcu(&h->h_link);
}

void class_handle_unhash(struct portals_handle *h)
{
        struct handle_bucket *bucket;
        bucket = handle_hash + (h->h_cookie & HANDLE_HASH_MASK);

        cfs_spin_lock(&bucket->lock);
        class_handle_unhash_nolock(h);
        cfs_spin_unlock(&bucket->lock);
}

void class_handle_hash_back(struct portals_handle *h)
{
        struct handle_bucket *bucket;
        ENTRY;

        bucket = handle_hash + (h->h_cookie & HANDLE_HASH_MASK);

        cfs_spin_lock(&bucket->lock);
        list_add_rcu(&h->h_link, &bucket->head);
        h->h_in = 1;
        cfs_spin_unlock(&bucket->lock);

        EXIT;
}

void *class_handle2object(__u64 cookie)
{
        struct handle_bucket *bucket;
        struct portals_handle *h;
        void *retval = NULL;
        ENTRY;

        LASSERT(handle_hash != NULL);

        /* Be careful when you want to change this code. See the 
         * rcu_read_lock() definition on top this file. - jxiong */
        bucket = handle_hash + (cookie & HANDLE_HASH_MASK);

        rcu_read_lock();
        list_for_each_entry_rcu(h, &bucket->head, h_link) {
                if (h->h_cookie != cookie)
                        continue;

                cfs_spin_lock(&h->h_lock);
                if (likely(h->h_in != 0)) {
                        h->h_addref(h);
                        retval = h;
                }
                cfs_spin_unlock(&h->h_lock);
                break;
        }
        rcu_read_unlock();

        RETURN(retval);
}

void class_handle_free_cb(cfs_rcu_head_t *rcu)
{
        struct portals_handle *h = RCU2HANDLE(rcu);
        if (h->h_free_cb) {
                h->h_free_cb(h->h_ptr, h->h_size);
        } else {
                void *ptr = h->h_ptr;
                unsigned int size = h->h_size;
                OBD_FREE(ptr, size);
        }
}

int class_handle_init(void)
{
        struct handle_bucket *bucket;
        struct timeval tv;
        int seed[2];

        LASSERT(handle_hash == NULL);

        OBD_ALLOC_LARGE(handle_hash, sizeof(*bucket) * HANDLE_HASH_SIZE);
        if (handle_hash == NULL)
                return -ENOMEM;

        cfs_spin_lock_init(&handle_base_lock);
        for (bucket = handle_hash + HANDLE_HASH_SIZE - 1; bucket >= handle_hash;
             bucket--) {
                CFS_INIT_LIST_HEAD(&bucket->head);
                cfs_spin_lock_init(&bucket->lock);
        }

        /** bug 21430: add randomness to the initial base */
        cfs_get_random_bytes(seed, sizeof(seed));
        cfs_gettimeofday(&tv);
        cfs_srand(tv.tv_sec ^ seed[0], tv.tv_usec ^ seed[1]);

        cfs_get_random_bytes(&handle_base, sizeof(handle_base));
        LASSERT(handle_base != 0ULL);

        return 0;
}

static int cleanup_all_handles(void)
{
        int rc;
        int i;

        for (rc = i = 0; i < HANDLE_HASH_SIZE; i++) {
                struct portals_handle *h;

                cfs_spin_lock(&handle_hash[i].lock);
                list_for_each_entry_rcu(h, &(handle_hash[i].head), h_link) {
                        CERROR("force clean handle "LPX64" addr %p addref %p\n",
                               h->h_cookie, h, h->h_addref);

                        class_handle_unhash_nolock(h);
                        rc++;
                }
                cfs_spin_unlock(&handle_hash[i].lock);
        }

        return rc;
}

void class_handle_cleanup(void)
{
        int count;
        LASSERT(handle_hash != NULL);

        count = cleanup_all_handles();

        OBD_FREE_LARGE(handle_hash, sizeof(*handle_hash) * HANDLE_HASH_SIZE);
        handle_hash = NULL;

        if (count != 0)
                CERROR("handle_count at cleanup: %d\n", count);
}
