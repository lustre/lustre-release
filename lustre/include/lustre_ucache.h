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
 */

#ifndef _UPCALL_CACHE_H
#define _UPCALL_CACHE_H

#define UC_CACHE_NEW            0x01
#define UC_CACHE_ACQUIRING      0x02
#define UC_CACHE_INVALID        0x04
#define UC_CACHE_EXPIRED        0x08

#define UC_CACHE_IS_NEW(i)          ((i)->ue_flags & UC_CACHE_NEW)
#define UC_CACHE_IS_INVALID(i)      ((i)->ue_flags & UC_CACHE_INVALID)
#define UC_CACHE_IS_ACQUIRING(i)    ((i)->ue_flags & UC_CACHE_ACQUIRING)
#define UC_CACHE_IS_EXPIRED(i)      ((i)->ue_flags & UC_CACHE_EXPIRED)
#define UC_CACHE_IS_VALID(i)        ((i)->ue_flags == 0)

#define UC_CACHE_SET_NEW(i)         (i)->ue_flags |= UC_CACHE_NEW
#define UC_CACHE_SET_INVALID(i)     (i)->ue_flags |= UC_CACHE_INVALID
#define UC_CACHE_SET_ACQUIRING(i)   (i)->ue_flags |= UC_CACHE_ACQUIRING
#define UC_CACHE_SET_EXPIRED(i)     (i)->ue_flags |= UC_CACHE_EXPIRED
#define UC_CACHE_SET_VALID(i)       (i)->ue_flags = 0

#define UC_CACHE_CLEAR_NEW(i)       (i)->ue_flags &= ~UC_CACHE_NEW
#define UC_CACHE_CLEAR_ACQUIRING(i) (i)->ue_flags &= ~UC_CACHE_ACQUIRING
#define UC_CACHE_CLEAR_INVALID(i)   (i)->ue_flags &= ~UC_CACHE_INVALID
#define UC_CACHE_CLEAR_EXPIRED(i)   (i)->ue_flags &= ~UC_CACHE_EXPIRED

struct upcall_cache_entry;

struct md_perm {
        lnet_nid_t      mp_nid;
        __u32           mp_perm;
};

struct md_identity {
        struct upcall_cache_entry *mi_uc_entry;
        uid_t                      mi_uid;
        gid_t                      mi_gid;
        struct group_info         *mi_ginfo;
        int                        mi_nperms;
        struct md_perm            *mi_perms;
};

struct upcall_cache_entry {
        struct list_head        ue_hash;
        __u64                   ue_key;
        atomic_t                ue_refcount;
        int                     ue_flags;
        cfs_waitq_t             ue_waitq;
        cfs_time_t              ue_acquire_expire;
        cfs_time_t              ue_expire;
        union {
                struct md_identity     identity;
        } u;
};

#define UC_CACHE_HASH_SIZE        (128)
#define UC_CACHE_HASH_INDEX(id)   ((id) & (UC_CACHE_HASH_SIZE - 1))
#define UC_CACHE_UPCALL_MAXPATH   (1024UL)

struct upcall_cache;

struct upcall_cache_ops {
        void            (*init_entry)(struct upcall_cache_entry *, void *args);
        void            (*free_entry)(struct upcall_cache *,
                                      struct upcall_cache_entry *);
        int             (*upcall_compare)(struct upcall_cache *,
                                          struct upcall_cache_entry *,
                                          __u64 key, void *args);
        int             (*downcall_compare)(struct upcall_cache *,
                                            struct upcall_cache_entry *,
                                            __u64 key, void *args);
        int             (*do_upcall)(struct upcall_cache *,
                                     struct upcall_cache_entry *);
        int             (*parse_downcall)(struct upcall_cache *,
                                          struct upcall_cache_entry *, void *);
};

struct upcall_cache {
        struct list_head        uc_hashtable[UC_CACHE_HASH_SIZE];
        spinlock_t              uc_lock;
        rwlock_t                uc_upcall_rwlock;

        char                    uc_name[40];            /* for upcall */
        char                    uc_upcall[UC_CACHE_UPCALL_MAXPATH];
        cfs_time_t              uc_acquire_expire;      /* jiffies */
        cfs_time_t              uc_entry_expire;        /* jiffies */
        struct upcall_cache_ops *uc_ops;
};

struct upcall_cache_entry *upcall_cache_get_entry(struct upcall_cache *cache,
                                                  __u64 key, void *args);
void upcall_cache_put_entry(struct upcall_cache *cache,
                            struct upcall_cache_entry *entry);
int upcall_cache_downcall(struct upcall_cache *cache, __u32 err, __u64 key,
                          void *args);
void upcall_cache_flush_idle(struct upcall_cache *cache);
void upcall_cache_flush_all(struct upcall_cache *cache);
void upcall_cache_flush_one(struct upcall_cache *cache, __u64 key, void *args);
struct upcall_cache *upcall_cache_init(const char *name, const char *upcall,
                                       struct upcall_cache_ops *ops);
void upcall_cache_cleanup(struct upcall_cache *cache);

#if 0
struct upcall_cache_entry *upcall_cache_get_entry(struct upcall_cache *hash,
                                                  __u64 key, __u32 primary,
                                                  __u32 ngroups, __u32 *groups);
void upcall_cache_put_entry(struct upcall_cache *hash,
                            struct upcall_cache_entry *entry);
int upcall_cache_downcall(struct upcall_cache *hash, __u32 err, __u64 key,
                          __u32 primary, __u32 ngroups, __u32 *groups);
void upcall_cache_flush_idle(struct upcall_cache *cache);
void upcall_cache_flush_all(struct upcall_cache *cache);
struct upcall_cache *upcall_cache_init(const char *name);
void upcall_cache_cleanup(struct upcall_cache *hash);

#endif
#endif /* _UPCALL_CACHE_H */
