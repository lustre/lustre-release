/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Phil Schwan <phil@clusterfs.com>
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

#define DEBUG_SUBSYSTEM S_CLASS
#ifndef __KERNEL__
# include <liblustre.h>
#endif

#include <obd_support.h>
#include <lustre_handles.h>

spinlock_t handle_lock;
static __u64 handle_base;
#define HANDLE_INCR 7
static struct list_head *handle_hash = NULL;
static int handle_count = 0;

#define HANDLE_HASH_SIZE (1 << 14)
#define HANDLE_HASH_MASK (HANDLE_HASH_SIZE - 1)

/*
 * Generate a unique 64bit cookie (hash) for a handle and insert it into
 * global (per-node) hash-table.
 */
void class_handle_hash(struct portals_handle *h, portals_handle_addref_cb cb)
{
        struct list_head *bucket;
        ENTRY;

        LASSERT(h != NULL);
        LASSERT(list_empty(&h->h_link));

        spin_lock(&handle_lock);

        /*
         * This is fast, but simplistic cookie generation algorithm, it will
         * need a re-do at some point in the future for security.
         */
        h->h_cookie = handle_base;
        handle_base += HANDLE_INCR;

        bucket = handle_hash + (h->h_cookie & HANDLE_HASH_MASK);
        list_add(&h->h_link, bucket);
        handle_count++;

        if (unlikely(handle_base == 0)) {
                /*
                 * Cookie of zero is "dangerous", because in many places it's
                 * assumed that 0 means "unassigned" handle, not bound to any
                 * object.
                 */
                CWARN("The universe has been exhausted: cookie wrap-around.\n");
                handle_base += HANDLE_INCR;
        }

        spin_unlock(&handle_lock);

        h->h_addref = cb;
        CDEBUG(D_INFO, "added object %p with handle "LPX64" to hash\n",
               h, h->h_cookie);
        EXIT;
}

static void class_handle_unhash_nolock(struct portals_handle *h)
{
        if (list_empty(&h->h_link)) {
                CERROR("removing an already-removed handle ("LPX64")\n",
                       h->h_cookie);
                return;
        }

        CDEBUG(D_INFO, "removing object %p with handle "LPX64" from hash\n",
               h, h->h_cookie);

        handle_count--;
        list_del_init(&h->h_link);
}

void class_handle_unhash(struct portals_handle *h)
{
        spin_lock(&handle_lock);
        class_handle_unhash_nolock(h);
        spin_unlock(&handle_lock);
}

void *class_handle2object(__u64 cookie)
{
        struct list_head *bucket, *tmp;
        void *retval = NULL;
        ENTRY;

        LASSERT(handle_hash != NULL);

        bucket = handle_hash + (cookie & HANDLE_HASH_MASK);

        spin_lock(&handle_lock);
        list_for_each(tmp, bucket) {
                struct portals_handle *h;
                h = list_entry(tmp, struct portals_handle, h_link);

                if (h->h_cookie == cookie) {
                        h->h_addref(h);
                        retval = h;
                        break;
                }
        }
        spin_unlock(&handle_lock);

        RETURN(retval);
}

int class_handle_init(void)
{
        struct list_head *bucket;

        LASSERT(handle_hash == NULL);

        OBD_VMALLOC(handle_hash, sizeof(*handle_hash) * HANDLE_HASH_SIZE);
        if (handle_hash == NULL)
                return -ENOMEM;

        for (bucket = handle_hash + HANDLE_HASH_SIZE - 1; bucket >= handle_hash;
             bucket--)
                CFS_INIT_LIST_HEAD(bucket);

        get_random_bytes(&handle_base, sizeof(handle_base));
        LASSERT(handle_base != 0ULL);

        return 0;
}

static void cleanup_all_handles(void)
{
        int i;

        spin_lock(&handle_lock);
        for (i = 0; i < HANDLE_HASH_SIZE; i++) {
                struct list_head *tmp, *pos;
                list_for_each_safe(tmp, pos, &(handle_hash[i])) {
                        struct portals_handle *h;
                        h = list_entry(tmp, struct portals_handle, h_link);

                        CERROR("force clean handle "LPX64" addr %p addref %p\n",
                               h->h_cookie, h, h->h_addref);

                        class_handle_unhash_nolock(h);
                }
        }
        spin_unlock(&handle_lock);
}

void class_handle_cleanup(void)
{
        LASSERT(handle_hash != NULL);

        if (handle_count != 0) {
                CERROR("handle_count at cleanup: %d\n", handle_count);
                cleanup_all_handles();
        }

        OBD_VFREE(handle_hash, sizeof(*handle_hash) * HANDLE_HASH_SIZE);
        handle_hash = NULL;

        if (handle_count)
                CERROR("leaked %d handles\n", handle_count);
}
