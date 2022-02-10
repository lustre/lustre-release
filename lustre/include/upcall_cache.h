/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _UPCALL_CACHE_H
#define _UPCALL_CACHE_H

#include <libcfs/libcfs.h>
#include <uapi/linux/lnet/lnet-types.h>
#include <uapi/linux/lustre/lustre_disk.h>
#include <obd.h>
#include <lustre_sec.h>

/* The special identity_upcall value "INTERNAL" implements a particular behavior
 * which does not involve an actual upcall. Instead, the cache is filled with
 * supplementary groups read from the user's credentials provided as input
 * (usually got from the client request), cumulatively at each request.
 */
#define IDENTITY_UPCALL_INTERNAL	"INTERNAL"

/** \defgroup ucache ucache
 *
 * @{
 */

#define UC_CACHE_NEW            0x01
#define UC_CACHE_ACQUIRING      0x02
#define UC_CACHE_INVALID        0x04
#define UC_CACHE_EXPIRED        0x08

#define UC_CACHE_IS_NEW(i)          ((i)->ue_flags & UC_CACHE_NEW)
#define UC_CACHE_IS_INVALID(i)      ((i)->ue_flags & UC_CACHE_INVALID)
#define UC_CACHE_IS_ACQUIRING(i)    ((i)->ue_flags & UC_CACHE_ACQUIRING)
#define UC_CACHE_IS_EXPIRED(i)      ((i)->ue_flags & UC_CACHE_EXPIRED)
#define UC_CACHE_IS_VALID(i)        ((i)->ue_flags == 0)

#define UC_CACHE_SET_NEW(i)         ((i)->ue_flags |= UC_CACHE_NEW)
#define UC_CACHE_SET_INVALID(i)     ((i)->ue_flags |= UC_CACHE_INVALID)
#define UC_CACHE_SET_ACQUIRING(i)   ((i)->ue_flags |= UC_CACHE_ACQUIRING)
#define UC_CACHE_SET_EXPIRED(i)     ((i)->ue_flags |= UC_CACHE_EXPIRED)
#define UC_CACHE_SET_VALID(i)       ((i)->ue_flags = 0)

#define UC_CACHE_CLEAR_NEW(i)       ((i)->ue_flags &= ~UC_CACHE_NEW)
#define UC_CACHE_CLEAR_ACQUIRING(i) ((i)->ue_flags &= ~UC_CACHE_ACQUIRING)
#define UC_CACHE_CLEAR_INVALID(i)   ((i)->ue_flags &= ~UC_CACHE_INVALID)
#define UC_CACHE_CLEAR_EXPIRED(i)   ((i)->ue_flags &= ~UC_CACHE_EXPIRED)

struct upcall_cache_entry;

struct md_perm {
	struct lnet_nid	mp_nid;
	uint32_t	mp_perm;
};

struct md_identity {
	struct upcall_cache_entry *mi_uc_entry;
	uid_t                      mi_uid;
	gid_t                      mi_gid;
	struct group_info          *mi_ginfo;
	int                        mi_nperms;
	struct md_perm            *mi_perms;
};

struct gss_rsi {
	struct upcall_cache_entry *si_uc_entry;
	lnet_nid_t		   si_nid4; /* FIXME Support larger NID */
	char			   si_nm_name[LUSTRE_NODEMAP_NAME_LENGTH + 1];
	__u32			   si_lustre_svc;
	rawobj_t		   si_in_handle;
	rawobj_t		   si_in_token;
	rawobj_t		   si_out_handle;
	rawobj_t		   si_out_token;
	int			   si_major_status;
	int			   si_minor_status;
};

struct gss_rsc {
	struct upcall_cache_entry *sc_uc_entry;
	struct obd_device	  *sc_target;
	rawobj_t		   sc_handle;
	struct gss_svc_ctx	   sc_ctx;
};

struct upcall_cache_entry {
	struct list_head	ue_hash;
	uint64_t		ue_key;
	atomic_t		ue_refcount;
	int			ue_flags;
	wait_queue_head_t	ue_waitq;
	time64_t		ue_acquire_expire;
	time64_t		ue_expire;
	union {
		struct md_identity	identity;
		struct gss_rsi		rsi;
		struct gss_rsc		rsc;
	} u;
};

#define UC_CACHE_HASH_INDEX(id, size)   ((id) & ((size) - 1))
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
	struct list_head	*uc_hashtable;
	int			uc_hashsize;
	rwlock_t		uc_lock;
	struct rw_semaphore	uc_upcall_rwsem;

	char			uc_name[40];		/* for upcall */
	char			uc_upcall[UC_CACHE_UPCALL_MAXPATH];
	bool			uc_acquire_replay;
	time64_t		uc_acquire_expire;	/* seconds */
	time64_t		uc_entry_expire;	/* seconds */
	struct upcall_cache_ops	*uc_ops;
};

int upcall_cache_set_upcall(struct upcall_cache *cache, const char *buffer,
			    size_t count, bool path_only);
struct upcall_cache_entry *upcall_cache_get_entry(struct upcall_cache *cache,
						  __u64 key, void *args);
void upcall_cache_get_entry_raw(struct upcall_cache_entry *entry);
void upcall_cache_update_entry(struct upcall_cache *cache,
			       struct upcall_cache_entry *entry,
			       time64_t expire, int state);
void upcall_cache_put_entry(struct upcall_cache *cache,
			    struct upcall_cache_entry *entry);
int upcall_cache_downcall(struct upcall_cache *cache, __u32 err, __u64 key,
			  void *args);
void upcall_cache_flush(struct upcall_cache *cache, int force);

static inline void upcall_cache_flush_idle(struct upcall_cache *cache)
{
	upcall_cache_flush(cache, 0);
}

static inline void upcall_cache_flush_all(struct upcall_cache *cache)
{
	upcall_cache_flush(cache, 1);
}

void upcall_cache_flush_one(struct upcall_cache *cache, __u64 key, void *args);
struct upcall_cache *upcall_cache_init(const char *name, const char *upcall,
				       int hashsz, time64_t entry_expire,
				       time64_t acquire_expire, bool replayable,
				       struct upcall_cache_ops *ops);
void upcall_cache_cleanup(struct upcall_cache *cache);

/** @} ucache */

#endif /* _UPCALL_CACHE_H */
