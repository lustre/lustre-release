/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
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

struct upcall_cache;

struct upcall_cache_entry {
        struct list_head        ue_hash;
        atomic_t                ue_refcount;
        __u64                   ue_key;
        struct upcall_cache    *ue_cache;
        int                     ue_flags;
        wait_queue_head_t       ue_waitq;
        unsigned long           ue_acquire_expire;
        unsigned long           ue_expire;
};

#define UC_CACHE_UPCALL_MAXPATH (1024)

struct upcall_cache {
        struct list_head       *uc_hashtable;
        int                     uc_hashsize;
        rwlock_t                uc_hashlock;

        char                   *uc_name;
        char                    uc_upcall[UC_CACHE_UPCALL_MAXPATH];
        unsigned long           uc_acquire_expire;
        unsigned long           uc_entry_expire;

        /* functions */
        unsigned int                (*hash)(struct upcall_cache *, __u64);
        struct upcall_cache_entry*  (*alloc_entry)(struct upcall_cache *, __u64);
        void                        (*free_entry)(struct upcall_cache *,
                                                  struct upcall_cache_entry *);
        int                         (*make_upcall)(struct upcall_cache *,
                                                   struct upcall_cache_entry *);
        int                         (*parse_downcall)(struct upcall_cache *,
                                                      struct upcall_cache_entry *,
                                                      void *args);
};

void upcall_cache_init_entry(struct upcall_cache *cache,
                             struct upcall_cache_entry *entry,
                             __u64 key);
struct upcall_cache_entry *
upcall_cache_get_entry(struct upcall_cache *cache, __u64 key);
void upcall_cache_put_entry(struct upcall_cache_entry *entry);
int upcall_cache_downcall(struct upcall_cache *cache, __u64 key,
                          int err, void *args);
void upcall_cache_flush_one(struct upcall_cache *cache, __u64 key);
void upcall_cache_flush_idle(struct upcall_cache *cache);
void upcall_cache_flush_all(struct upcall_cache *cache);

#endif /* _UPCALL_CACHE_H */
