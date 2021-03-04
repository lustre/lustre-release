/*
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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/*
 * lustre/include/lustre_osc.h
 *
 * OSC layer structures and methods common for both OSC and MDC.
 *
 * This file contains OSC interfaces used by OSC and MDC. Most of them
 * were just moved from lustre/osc/osc_cl_internal.h for Data-on-MDT
 * purposes.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 *   Author: Jinshan Xiong <jinshan.xiong@whamcloud.com>
 *   Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#ifndef LUSTRE_OSC_H
#define LUSTRE_OSC_H

#include <libcfs/libcfs.h>
#include <obd.h>
#include <cl_object.h>
#include <lustre_crypto.h>

/** \defgroup osc osc
 *  @{
 */

struct osc_quota_info {
	/** linkage for quota hash table */
	struct hlist_node oqi_hash;
	__u32             oqi_id;
};

enum async_flags {
	ASYNC_READY = 0x1, /* ap_make_ready will not be called before this
			      page is added to an rpc */
	ASYNC_URGENT = 0x2, /* page must be put into an RPC before return */
	ASYNC_COUNT_STABLE = 0x4, /* ap_refresh_count will not be called
				     to give the caller a chance to update
				     or cancel the size of the io */
	ASYNC_HP = 0x10,
};

struct osc_async_page {
	int			oap_magic;
	unsigned short		oap_cmd;

	struct list_head	oap_pending_item;
	struct list_head	oap_rpc_item;

	loff_t			oap_obj_off;
	unsigned		oap_page_off;
	enum async_flags	oap_async_flags;

	struct brw_page		oap_brw_page;

	struct ptlrpc_request	*oap_request;
	struct client_obd	*oap_cli;
	struct osc_object	*oap_obj;

	spinlock_t		 oap_lock;
};

#define oap_page	oap_brw_page.pg
#define oap_count	oap_brw_page.count
#define oap_brw_flags	oap_brw_page.flag

static inline struct osc_async_page *brw_page2oap(struct brw_page *pga)
{
	return container_of(pga, struct osc_async_page, oap_brw_page);
}

struct osc_device {
	struct cl_device	od_cl;
	struct obd_export	*od_exp;

	/* Write stats is actually protected by client_obd's lock. */
	struct osc_stats {
		uint64_t	os_lockless_writes;    /* by bytes */
		uint64_t	os_lockless_reads;     /* by bytes */
		uint64_t	os_lockless_truncates; /* by times */
	} od_stats;

	/* configuration item(s) */
	time64_t		od_contention_time;
	int			od_lockless_truncate;
};

struct osc_extent;

/**
 * State maintained by osc layer for each IO context.
 */
struct osc_io {
	/** super class */
	struct cl_io_slice oi_cl;
	/** true if this io is lockless. */
	unsigned int	   oi_lockless:1,
	/** true if this io is counted as active IO */
			   oi_is_active:1,
	/** true if this io has CAP_SYS_RESOURCE */
			   oi_cap_sys_resource:1,
	/** true if this io issued by readahead */
			   oi_is_readahead:1;
	/** how many LRU pages are reserved for this IO */
	unsigned long	   oi_lru_reserved;

	/** active extents, we know how many bytes is going to be written,
	 * so having an active extent will prevent it from being fragmented */
	struct osc_extent *oi_active;
	/** partially truncated extent, we need to hold this extent to prevent
	 * page writeback from happening. */
	struct osc_extent *oi_trunc;
	/** write osc_lock for this IO, used by osc_extent_find(). */
	struct osc_lock   *oi_write_osclock;
	struct obdo        oi_oa;
	struct osc_async_cbargs {
		bool		  opc_rpc_sent;
		int		  opc_rc;
		struct completion opc_sync;
	} oi_cbarg;
};

/**
 * State maintained by osc layer for the duration of a system call.
 */
struct osc_session {
	struct osc_io os_io;
};

#define OTI_PVEC_SIZE 256
struct osc_thread_info {
	struct ldlm_res_id	oti_resname;
	union ldlm_policy_data	oti_policy;
	struct cl_attr		oti_attr;
	struct cl_io		oti_io;
	struct pagevec		oti_pagevec;
	void			*oti_pvec[OTI_PVEC_SIZE];
	/**
	 * Fields used by cl_lock_discard_pages().
	 */
	pgoff_t			oti_next_index;
	pgoff_t			oti_fn_index; /* first non-overlapped index */
	pgoff_t			oti_ng_index; /* negative lock caching */
	struct cl_sync_io	oti_anchor;
	struct cl_req_attr	oti_req_attr;
	struct lu_buf		oti_ladvise_buf;
};

static inline __u64 osc_enq2ldlm_flags(__u32 enqflags)
{
	__u64 result = 0;

	CDEBUG(D_DLMTRACE, "flags: %x\n", enqflags);

	LASSERT((enqflags & ~CEF_MASK) == 0);

	if (enqflags & CEF_NONBLOCK)
		result |= LDLM_FL_BLOCK_NOWAIT;
	if (enqflags & CEF_GLIMPSE)
		result |= LDLM_FL_HAS_INTENT|LDLM_FL_CBPENDING;
	if (enqflags & CEF_DISCARD_DATA)
		result |= LDLM_FL_AST_DISCARD_DATA;
	if (enqflags & CEF_PEEK)
		result |= LDLM_FL_TEST_LOCK;
	if (enqflags & CEF_LOCK_MATCH)
		result |= LDLM_FL_MATCH_LOCK;
	if (enqflags & CEF_LOCK_NO_EXPAND)
		result |= LDLM_FL_NO_EXPANSION;
	if (enqflags & CEF_SPECULATIVE)
		result |= LDLM_FL_SPECULATIVE;
	return result;
}

typedef int (*osc_enqueue_upcall_f)(void *cookie, struct lustre_handle *lockh,
				    int rc);

struct osc_enqueue_args {
	struct obd_export	*oa_exp;
	enum ldlm_type		oa_type;
	enum ldlm_mode		oa_mode;
	__u64			*oa_flags;
	osc_enqueue_upcall_f	oa_upcall;
	void			*oa_cookie;
	struct ost_lvb		*oa_lvb;
	struct lustre_handle	oa_lockh;
	bool			oa_speculative;
};

/**
 * Bit flags for osc_dlm_lock_at_pageoff().
 */
enum osc_dap_flags {
	/**
	 * Just check if the desired lock exists, it won't hold reference
	 * count on lock.
	 */
	OSC_DAP_FL_TEST_LOCK = BIT(0),
	/**
	 * Return the lock even if it is being canceled.
	 */
	OSC_DAP_FL_CANCELING = BIT(1),
	/**
	 * check ast data is present, requested to cancel cb
	 */
	OSC_DAP_FL_AST	     = BIT(2),
	/**
	 * look at right region for the desired lock
	 */
	OSC_DAP_FL_RIGHT     = BIT(3),
};

/*
 * The set of operations which are different for MDC and OSC objects
 */
struct osc_object_operations {
	void (*oto_build_res_name)(struct osc_object *osc,
				   struct ldlm_res_id *resname);
	struct ldlm_lock* (*oto_dlmlock_at_pgoff)(const struct lu_env *env,
						struct osc_object *obj,
						pgoff_t index,
						enum osc_dap_flags dap_flags);
};

struct osc_object {
	struct cl_object	oo_cl;
	struct lov_oinfo	*oo_oinfo;
	/**
	 * True if locking against this stripe got -EUSERS.
	 */
	int			oo_contended;
	ktime_t			oo_contention_time;
#ifdef CONFIG_LUSTRE_DEBUG_EXPENSIVE_CHECK
	/**
	 * IO context used for invariant checks in osc_lock_has_pages().
	 */
	struct cl_io		oo_debug_io;
	/** Serialization object for osc_object::oo_debug_io. */
	struct mutex		oo_debug_mutex;
#endif
	/**
	 * used by the osc to keep track of what objects to build into rpcs.
	 * Protected by client_obd->cli_loi_list_lock.
	 */
	struct list_head	oo_ready_item;
	struct list_head	oo_hp_ready_item;
	struct list_head	oo_write_item;
	struct list_head	oo_read_item;

	/**
	 * extent is a red black tree to manage (async) dirty pages.
	 */
	struct rb_root		oo_root;
	/**
	 * Manage write(dirty) extents.
	 */
	struct list_head	oo_hp_exts;	/* list of hp extents */
	struct list_head	oo_urgent_exts;	/* list of writeback extents */
	struct list_head	oo_full_exts;

	struct list_head	oo_reading_exts;

	atomic_t		oo_nr_reads;
	atomic_t		oo_nr_writes;

	/** Protect extent tree. Will be used to protect
	 * oo_{read|write}_pages soon. */
	spinlock_t		oo_lock;

	/**
	 * Radix tree for caching pages
	 */
	spinlock_t		oo_tree_lock;
	struct radix_tree_root	oo_tree;
	unsigned long		oo_npages;

	/* Protect osc_lock this osc_object has */
	struct list_head	oo_ol_list;
	spinlock_t		oo_ol_spin;

	/** number of active IOs of this object */
	atomic_t		oo_nr_ios;
	wait_queue_head_t	oo_io_waitq;

	const struct osc_object_operations *oo_obj_ops;
	bool			oo_initialized;
};

static inline void osc_build_res_name(struct osc_object *osc,
				      struct ldlm_res_id *resname)
{
	return osc->oo_obj_ops->oto_build_res_name(osc, resname);
}

static inline struct ldlm_lock *osc_dlmlock_at_pgoff(const struct lu_env *env,
						    struct osc_object *obj,
						    pgoff_t index,
						    enum osc_dap_flags flags)
{
	return obj->oo_obj_ops->oto_dlmlock_at_pgoff(env, obj, index, flags);
}

static inline void osc_object_lock(struct osc_object *obj)
{
	spin_lock(&obj->oo_lock);
}

static inline int osc_object_trylock(struct osc_object *obj)
{
	return spin_trylock(&obj->oo_lock);
}

static inline void osc_object_unlock(struct osc_object *obj)
{
	spin_unlock(&obj->oo_lock);
}

#define assert_osc_object_is_locked(obj)	\
	assert_spin_locked(&obj->oo_lock)

static inline void osc_object_set_contended(struct osc_object *obj)
{
	obj->oo_contention_time = ktime_get();
	/* mb(); */
	obj->oo_contended = 1;
}

static inline void osc_object_clear_contended(struct osc_object *obj)
{
	obj->oo_contended = 0;
}

/*
 * Lock "micro-states" for osc layer.
 */
enum osc_lock_state {
	OLS_NEW,
	OLS_ENQUEUED,
	OLS_UPCALL_RECEIVED,
	OLS_GRANTED,
	OLS_CANCELLED
};

/**
 * osc-private state of cl_lock.
 *
 * Interaction with DLM.
 *
 * Once receive upcall is invoked, osc_lock remembers a handle of DLM lock in
 * osc_lock::ols_handle and a pointer to that lock in osc_lock::ols_dlmlock.
 *
 * This pointer is protected through a reference, acquired by
 * osc_lock_upcall0(). Also, an additional reference is acquired by
 * ldlm_lock_addref() call protecting the lock from cancellation, until
 * osc_lock_unuse() releases it.
 *
 * Below is a description of how lock references are acquired and released
 * inside of DLM.
 *
 * - When new lock is created and enqueued to the server (ldlm_cli_enqueue())
 *      - ldlm_lock_create()
 *          - ldlm_lock_new(): initializes a lock with 2 references. One for
 *            the caller (released when reply from the server is received, or on
 *            error), and another for the hash table.
 *      - ldlm_lock_addref_internal(): protects the lock from cancellation.
 *
 * - When reply is received from the server (osc_enqueue_interpret())
 *      - ldlm_cli_enqueue_fini()
 *          - LDLM_LOCK_PUT(): releases caller reference acquired by
 *            ldlm_lock_new().
 *          - if (rc != 0)
 *                ldlm_lock_decref(): error case: matches ldlm_cli_enqueue().
 *      - ldlm_lock_decref(): for async locks, matches ldlm_cli_enqueue().
 *
 * - When lock is being cancelled (ldlm_lock_cancel())
 *      - ldlm_lock_destroy()
 *          - LDLM_LOCK_PUT(): releases hash-table reference acquired by
 *            ldlm_lock_new().
 *
 * osc_lock is detached from ldlm_lock by osc_lock_detach() that is called
 * either when lock is cancelled (osc_lock_blocking()), or when locks is
 * deleted without cancellation (e.g., from cl_locks_prune()). In the latter
 * case ldlm lock remains in memory, and can be re-attached to osc_lock in the
 * future.
 */
struct osc_lock {
	struct cl_lock_slice	ols_cl;
	/** Internal lock to protect states, etc. */
	spinlock_t		ols_lock;
	/** Owner sleeps on this channel for state change */
	struct cl_sync_io	*ols_owner;
	/** waiting list for this lock to be cancelled */
	struct list_head	ols_waiting_list;
	/** wait entry of ols_waiting_list */
	struct list_head	ols_wait_entry;
	/** list entry for osc_object::oo_ol_list */
	struct list_head	ols_nextlock_oscobj;

	/** underlying DLM lock */
	struct ldlm_lock	*ols_dlmlock;
	/** DLM flags with which osc_lock::ols_lock was enqueued */
	__u64			ols_flags;
	/** osc_lock::ols_lock handle */
	struct lustre_handle	ols_handle;
	struct ldlm_enqueue_info ols_einfo;
	enum osc_lock_state	ols_state;
	/** lock value block */
	struct ost_lvb		ols_lvb;
	/** Lockless operations to be used by lockless lock */
	const struct cl_lock_operations *ols_lockless_ops;
	/**
	 * true, if ldlm_lock_addref() was called against
	 * osc_lock::ols_lock. This is used for sanity checking.
	 *
	 * \see osc_lock::ols_has_ref
	 */
	unsigned		ols_hold :1,
	/**
	 * this is much like osc_lock::ols_hold, except that this bit is
	 * cleared _after_ reference in released in osc_lock_unuse(). This
	 * fine distinction is needed because:
	 *
	 *     - if ldlm lock still has a reference, osc_ast_data_get() needs
	 *       to return associated cl_lock (so that a flag is needed that is
	 *       cleared after ldlm_lock_decref() returned), and
	 *
	 *     - ldlm_lock_decref() can invoke blocking ast (for a
	 *       LDLM_FL_CBPENDING lock), and osc_lock functions like
	 *       osc_lock_cancel() called from there need to know whether to
	 *       release lock reference (so that a flag is needed that is
	 *       cleared before ldlm_lock_decref() is called).
	 */
				ols_has_ref:1,
	/**
	 * inherit the lockless attribute from top level cl_io.
	 * If true, osc_lock_enqueue is able to tolerate the -EUSERS error.
	 */
				ols_locklessable:1,
	/**
	 * if set, the osc_lock is a glimpse lock. For glimpse locks, we treat
	 * the EVAVAIL error as torerable, this will make upper logic happy
	 * to wait all glimpse locks to each OSTs to be completed.
	 * Glimpse lock converts to normal lock if the server lock is granted.
	 * Glimpse lock should be destroyed immediately after use.
	 */
				ols_glimpse:1,
	/**
	 * For async glimpse lock.
	 */
				ols_agl:1,
	/**
	 * for speculative locks - asynchronous glimpse locks and ladvise
	 * lockahead manual lock requests
	 *
	 * Used to tell osc layer to not wait for the ldlm reply from the
	 * server, so the osc lock will be short lived - It only exists to
	 * create the ldlm request and is not updated on request completion.
	 */
				ols_speculative:1;
};

static inline int osc_lock_is_lockless(const struct osc_lock *ols)
{
	return (ols->ols_cl.cls_ops == ols->ols_lockless_ops);
}

/**
 * Page state private for osc layer.
 */
struct osc_page {
	struct cl_page_slice  ops_cl;
	/**
	 * Page queues used by osc to detect when RPC can be formed.
	 */
	struct osc_async_page ops_oap;
	/**
	 * An offset within page from which next transfer starts. This is used
	 * by cl_page_clip() to submit partial page transfers.
	 */
	unsigned int		ops_from:PAGE_SHIFT,
	/**
	 * An offset within page at which next transfer ends(inclusive).
	 *
	 * \see osc_page::ops_from.
	 */
				ops_to:PAGE_SHIFT,
	/**
	 * Boolean, true iff page is under transfer. Used for sanity checking.
	 */
				ops_transfer_pinned:1,
	/**
	 * in LRU?
	 */
				ops_in_lru:1,
	/**
	 * Set if the page must be transferred with OBD_BRW_SRVLOCK.
	 */
				ops_srvlock:1,
	/**
	 * If the page is in osc_object::oo_tree.
	 */
				ops_intree:1;
	/**
	 * lru page list. See osc_lru_{del|use}() in osc_page.c for usage.
	 */
	struct list_head	ops_lru;
	/**
	 * Submit time - the time when the page is starting RPC. For debugging.
	 */
	ktime_t			ops_submit_time;
};

struct osc_brw_async_args {
	struct obdo		*aa_oa;
	int			 aa_requested_nob;
	int			 aa_nio_count;
	u32			 aa_page_count;
	s32			 aa_resends;
	struct brw_page		**aa_ppga;
	struct client_obd	*aa_cli;
	struct list_head	 aa_oaps;
	struct list_head	 aa_exts;
};

extern struct kmem_cache *osc_lock_kmem;
extern struct kmem_cache *osc_object_kmem;
extern struct kmem_cache *osc_thread_kmem;
extern struct kmem_cache *osc_session_kmem;
extern struct kmem_cache *osc_extent_kmem;
extern struct kmem_cache *osc_quota_kmem;
extern struct kmem_cache *osc_obdo_kmem;

extern struct lu_context_key osc_key;
extern struct lu_context_key osc_session_key;

#define OSC_FLAGS (ASYNC_URGENT|ASYNC_READY)

/* osc_page.c */
int osc_page_init(const struct lu_env *env, struct cl_object *obj,
		  struct cl_page *page, pgoff_t ind);
void osc_index2policy(union ldlm_policy_data *policy, const struct cl_object *obj,
		      pgoff_t start, pgoff_t end);
void osc_lru_add_batch(struct client_obd *cli, struct list_head *list);
void osc_page_submit(const struct lu_env *env, struct osc_page *opg,
		     enum cl_req_type crt, int brw_flags);
int lru_queue_work(const struct lu_env *env, void *data);
long osc_lru_shrink(const struct lu_env *env, struct client_obd *cli,
		    long target, bool force);

/* osc_cache.c */
int osc_set_async_flags(struct osc_object *obj, struct osc_page *opg,
			u32 async_flags);
int osc_prep_async_page(struct osc_object *osc, struct osc_page *ops,
			struct page *page, loff_t offset);
int osc_queue_async_io(const struct lu_env *env, struct cl_io *io,
		       struct osc_page *ops, cl_commit_cbt cb);
int osc_page_cache_add(const struct lu_env *env, struct osc_page *opg,
		       struct cl_io *io, cl_commit_cbt cb);
int osc_teardown_async_page(const struct lu_env *env, struct osc_object *obj,
			    struct osc_page *ops);
int osc_flush_async_page(const struct lu_env *env, struct cl_io *io,
			 struct osc_page *ops);
int osc_queue_sync_pages(const struct lu_env *env, const struct cl_io *io,
			 struct osc_object *obj, struct list_head *list,
			 int brw_flags);
int osc_cache_truncate_start(const struct lu_env *env, struct osc_object *obj,
			     __u64 size, struct osc_extent **extp);
void osc_cache_truncate_end(const struct lu_env *env, struct osc_extent *ext);
int osc_cache_writeback_range(const struct lu_env *env, struct osc_object *obj,
			      pgoff_t start, pgoff_t end, int hp, int discard);
int osc_cache_wait_range(const struct lu_env *env, struct osc_object *obj,
			 pgoff_t start, pgoff_t end);
int osc_io_unplug0(const struct lu_env *env, struct client_obd *cli,
		   struct osc_object *osc, int async);
static inline void osc_wake_cache_waiters(struct client_obd *cli)
{
	wake_up(&cli->cl_cache_waiters);
}

static inline int osc_io_unplug_async(const struct lu_env *env,
				      struct client_obd *cli,
				      struct osc_object *osc)
{
	return osc_io_unplug0(env, cli, osc, 1);
}

static inline void osc_io_unplug(const struct lu_env *env,
				 struct client_obd *cli,
				 struct osc_object *osc)
{
	(void)osc_io_unplug0(env, cli, osc, 0);
}

typedef bool (*osc_page_gang_cbt)(const struct lu_env *, struct cl_io *,
				  struct osc_page *, void *);
bool osc_page_gang_lookup(const struct lu_env *env, struct cl_io *io,
			  struct osc_object *osc, pgoff_t start, pgoff_t end,
			  osc_page_gang_cbt cb, void *cbdata);
bool osc_discard_cb(const struct lu_env *env, struct cl_io *io,
		    struct osc_page *ops, void *cbdata);

/* osc_dev.c */
int osc_device_init(const struct lu_env *env, struct lu_device *d,
		    const char *name, struct lu_device *next);
struct lu_device *osc_device_fini(const struct lu_env *env,
				  struct lu_device *d);
struct lu_device *osc_device_free(const struct lu_env *env,
				  struct lu_device *d);

/* osc_object.c */
int osc_object_init(const struct lu_env *env, struct lu_object *obj,
		    const struct lu_object_conf *conf);
void osc_object_free(const struct lu_env *env, struct lu_object *obj);
int osc_lvb_print(const struct lu_env *env, void *cookie,
		  lu_printer_t p, const struct ost_lvb *lvb);
int osc_object_print(const struct lu_env *env, void *cookie,
		     lu_printer_t p, const struct lu_object *obj);
int osc_attr_get(const struct lu_env *env, struct cl_object *obj,
		 struct cl_attr *attr);
int osc_attr_update(const struct lu_env *env, struct cl_object *obj,
		    const struct cl_attr *attr, unsigned valid);
int osc_object_glimpse(const struct lu_env *env, const struct cl_object *obj,
		       struct ost_lvb *lvb);
int osc_object_invalidate(const struct lu_env *env, struct osc_object *osc);
int osc_object_is_contended(struct osc_object *obj);
int osc_object_find_cbdata(const struct lu_env *env, struct cl_object *obj,
			   ldlm_iterator_t iter, void *data);
int osc_object_prune(const struct lu_env *env, struct cl_object *obj);

/* osc_request.c */
void osc_init_grant(struct client_obd *cli, struct obd_connect_data *ocd);
int osc_setup_common(struct obd_device *obd, struct lustre_cfg *lcfg);
int osc_precleanup_common(struct obd_device *obd);
int osc_cleanup_common(struct obd_device *obd);
int osc_set_info_async(const struct lu_env *env, struct obd_export *exp,
		       u32 keylen, void *key, u32 vallen, void *val,
		       struct ptlrpc_request_set *set);
int osc_ldlm_resource_invalidate(struct cfs_hash *hs, struct cfs_hash_bd *bd,
				 struct hlist_node *hnode, void *arg);
int osc_reconnect(const struct lu_env *env, struct obd_export *exp,
		  struct obd_device *obd, struct obd_uuid *cluuid,
		  struct obd_connect_data *data, void *localdata);
int osc_disconnect(struct obd_export *exp);
int osc_punch_send(struct obd_export *exp, struct obdo *oa,
		   obd_enqueue_update_f upcall, void *cookie);

/* osc_io.c */
int osc_io_submit(const struct lu_env *env, const struct cl_io_slice *ios,
		  enum cl_req_type crt, struct cl_2queue *queue);
int osc_io_commit_async(const struct lu_env *env,
			const struct cl_io_slice *ios,
			struct cl_page_list *qin, int from, int to,
			cl_commit_cbt cb);
void osc_io_extent_release(const struct lu_env *env,
			   const struct cl_io_slice *ios);
int osc_io_iter_init(const struct lu_env *env, const struct cl_io_slice *ios);
void osc_io_iter_fini(const struct lu_env *env,
		      const struct cl_io_slice *ios);
void osc_io_rw_iter_fini(const struct lu_env *env,
			    const struct cl_io_slice *ios);
int osc_io_fault_start(const struct lu_env *env, const struct cl_io_slice *ios);
void osc_io_setattr_end(const struct lu_env *env,
			const struct cl_io_slice *slice);
int osc_io_read_start(const struct lu_env *env,
		      const struct cl_io_slice *slice);
int osc_io_write_start(const struct lu_env *env,
		       const struct cl_io_slice *slice);
void osc_io_end(const struct lu_env *env, const struct cl_io_slice *slice);
int osc_fsync_ost(const struct lu_env *env, struct osc_object *obj,
		  struct cl_fsync_io *fio);
void osc_io_fsync_end(const struct lu_env *env,
		      const struct cl_io_slice *slice);
void osc_read_ahead_release(const struct lu_env *env, struct cl_read_ahead *ra);
int osc_io_lseek_start(const struct lu_env *env,
		       const struct cl_io_slice *slice);
void osc_io_lseek_end(const struct lu_env *env,
		      const struct cl_io_slice *slice);
int osc_io_lru_reserve(const struct lu_env *env, const struct cl_io_slice *ios,
		       loff_t pos, size_t count);

/* osc_lock.c */
void osc_lock_to_lockless(const struct lu_env *env, struct osc_lock *ols,
			  int force);
void osc_lock_wake_waiters(const struct lu_env *env, struct osc_object *osc,
			   struct osc_lock *oscl);
int osc_lock_enqueue_wait(const struct lu_env *env, struct osc_object *obj,
			  struct osc_lock *oscl);
void osc_lock_set_writer(const struct lu_env *env, const struct cl_io *io,
			 struct cl_object *obj, struct osc_lock *oscl);
int osc_lock_print(const struct lu_env *env, void *cookie,
		   lu_printer_t p, const struct cl_lock_slice *slice);
void osc_lock_cancel(const struct lu_env *env,
		     const struct cl_lock_slice *slice);
void osc_lock_fini(const struct lu_env *env, struct cl_lock_slice *slice);
int osc_ldlm_glimpse_ast(struct ldlm_lock *dlmlock, void *data);
unsigned long osc_ldlm_weigh_ast(struct ldlm_lock *dlmlock);

/*****************************************************************************
 *
 * Accessors and type conversions.
 *
 */
static inline struct osc_thread_info *osc_env_info(const struct lu_env *env)
{
	struct osc_thread_info *info;

	info = lu_context_key_get(&env->le_ctx, &osc_key);
	LASSERT(info != NULL);
	return info;
}

static inline struct osc_session *osc_env_session(const struct lu_env *env)
{
	struct osc_session *ses;

	ses = lu_context_key_get(env->le_ses, &osc_session_key);
	LASSERT(ses != NULL);
	return ses;
}

static inline struct osc_io *osc_env_io(const struct lu_env *env)
{
	return &osc_env_session(env)->os_io;
}

static inline struct osc_device *lu2osc_dev(const struct lu_device *d)
{
	return container_of_safe(d, struct osc_device, od_cl.cd_lu_dev);
}

static inline struct obd_export *osc_export(const struct osc_object *obj)
{
	return lu2osc_dev(obj->oo_cl.co_lu.lo_dev)->od_exp;
}

static inline struct client_obd *osc_cli(const struct osc_object *obj)
{
	return &osc_export(obj)->exp_obd->u.cli;
}

static inline struct osc_object *cl2osc(const struct cl_object *obj)
{
	return container_of_safe(obj, struct osc_object, oo_cl);
}

static inline struct cl_object *osc2cl(const struct osc_object *obj)
{
	return (struct cl_object *)&obj->oo_cl;
}

static inline struct osc_device *obd2osc_dev(const struct obd_device *obd)
{
	return container_of_safe(obd->obd_lu_dev, struct osc_device,
				 od_cl.cd_lu_dev);
}

static inline struct lu_device *osc2lu_dev(struct osc_device *osc)
{
	return &osc->od_cl.cd_lu_dev;
}

static inline struct lu_object *osc2lu(struct osc_object *osc)
{
	return &osc->oo_cl.co_lu;
}

static inline struct osc_object *lu2osc(const struct lu_object *obj)
{
	return container_of_safe(obj, struct osc_object, oo_cl.co_lu);
}

static inline struct osc_io *cl2osc_io(const struct lu_env *env,
				       const struct cl_io_slice *slice)
{
	struct osc_io *oio = container_of(slice, struct osc_io, oi_cl);

	LINVRNT(oio == osc_env_io(env));
	return oio;
}

static inline enum ldlm_mode osc_cl_lock2ldlm(enum cl_lock_mode mode)
{
	LASSERT(mode == CLM_READ || mode == CLM_WRITE || mode == CLM_GROUP);
	if (mode == CLM_READ)
		return LCK_PR;
	if (mode == CLM_WRITE)
		return LCK_PW;
	return LCK_GROUP;
}

static inline enum cl_lock_mode osc_ldlm2cl_lock(enum ldlm_mode mode)
{
	LASSERT(mode == LCK_PR || mode == LCK_PW || mode == LCK_GROUP);
	if (mode == LCK_PR)
		return CLM_READ;
	if (mode == LCK_PW)
		return CLM_WRITE;
	return CLM_GROUP;
}

static inline struct osc_page *cl2osc_page(const struct cl_page_slice *slice)
{
	return container_of_safe(slice, struct osc_page, ops_cl);
}

static inline struct osc_page *oap2osc(struct osc_async_page *oap)
{
	return container_of_safe(oap, struct osc_page, ops_oap);
}

static inline pgoff_t osc_index(struct osc_page *opg)
{
	return opg->ops_cl.cpl_page->cp_osc_index;
}

static inline struct cl_page *oap2cl_page(struct osc_async_page *oap)
{
	return oap2osc(oap)->ops_cl.cpl_page;
}

static inline struct osc_page *oap2osc_page(struct osc_async_page *oap)
{
	return (struct osc_page *)container_of(oap, struct osc_page, ops_oap);
}

static inline struct osc_page *
osc_cl_page_osc(struct cl_page *page, struct osc_object *osc)
{
	const struct cl_page_slice *slice;

	LASSERT(osc != NULL);
	slice = cl_object_page_slice(&osc->oo_cl, page);
	return cl2osc_page(slice);
}

static inline struct osc_lock *cl2osc_lock(const struct cl_lock_slice *slice)
{
	return container_of_safe(slice, struct osc_lock, ols_cl);
}

static inline int osc_io_srvlock(struct osc_io *oio)
{
	return (oio->oi_lockless && !oio->oi_cl.cis_io->ci_no_srvlock);
}

enum osc_extent_state {
	OES_INV       = 0, /** extent is just initialized or destroyed */
	OES_ACTIVE    = 1, /** process is using this extent */
	OES_CACHE     = 2, /** extent is ready for IO */
	OES_LOCKING   = 3, /** locking page to prepare IO */
	OES_LOCK_DONE = 4, /** locking finished, ready to send */
	OES_RPC       = 5, /** in RPC */
	OES_TRUNC     = 6, /** being truncated */
	OES_STATE_MAX
};

/**
 * osc_extent data to manage dirty pages.
 * osc_extent has the following attributes:
 * 1. all pages in the same must be in one RPC in write back;
 * 2. # of pages must be less than max_pages_per_rpc - implied by 1;
 * 3. must be covered by only 1 osc_lock;
 * 4. exclusive. It's impossible to have overlapped osc_extent.
 *
 * The lifetime of an extent is from when the 1st page is dirtied to when
 * all pages inside it are written out.
 *
 * LOCKING ORDER
 * =============
 * page lock -> client_obd_list_lock -> object lock(osc_object::oo_lock)
 */
struct osc_extent {
	/** red-black tree node */
	struct rb_node		oe_node;
	/** osc_object of this extent */
	struct osc_object	*oe_obj;
	/** refcount, removed from red-black tree if reaches zero. */
	struct kref		oe_refc;
	/** busy if non-zero */
	atomic_t		oe_users;
	/** link list of osc_object's oo_{hp|urgent|locking}_exts. */
	struct list_head	oe_link;
	/** state of this extent */
	enum osc_extent_state	oe_state;
	/** flags for this extent. */
	/** 0 is write, 1 is read */
	unsigned int		oe_rw:1,
	/** sync extent, queued by osc_queue_sync_pages() */
				oe_sync:1,
	/** set if this extent has partial, sync pages.
	 * Extents with partial page(s) can't merge with others in RPC */
				oe_no_merge:1,
				oe_srvlock:1,
				oe_memalloc:1,
	/** an ACTIVE extent is going to be truncated, so when this extent
	 * is released, it will turn into TRUNC state instead of CACHE. */
				oe_trunc_pending:1,
	/** this extent should be written asap and someone may wait for the
	 * write to finish. This bit is usually set along with urgent if
	 * the extent was CACHE state.
	 * fsync_wait extent can't be merged because new extent region may
	 * exceed fsync range. */
				oe_fsync_wait:1,
	/** covering lock is being canceled */
				oe_hp:1,
	/** this extent should be written back asap. set if one of pages is
	 * called by page WB daemon, or sync write or reading requests. */
				oe_urgent:1,
	/** Non-delay RPC should be used for this extent. */
				oe_ndelay:1,
	/** direct IO pages */
				oe_dio:1,
	/** this extent consists of RDMA only pages */
				oe_is_rdma_only;
	/** how many grants allocated for this extent.
	 *  Grant allocated for this extent. There is no grant allocated
	 *  for reading extents and sync write extents. */
	unsigned int		oe_grants;
	/** # of dirty pages in this extent */
	unsigned int		oe_nr_pages;
	/** list of pending oap pages. Pages in this list are NOT sorted. */
	struct list_head	oe_pages;
	/** start and end index of this extent, include start and end
	 * themselves. Page offset here is the page index of osc_pages.
	 * oe_start is used as keyword for red-black tree. */
	pgoff_t			oe_start;
	pgoff_t			oe_end;
	/** maximum ending index of this extent, this is limited by
	 * max_pages_per_rpc, lock extent and chunk size. */
	pgoff_t			oe_max_end;
	/** waitqueue - for those who want to be notified if this extent's
	 * state has changed. */
	wait_queue_head_t	oe_waitq;
	/** lock covering this extent */
	struct ldlm_lock	*oe_dlmlock;
	/** terminator of this extent. Must be true if this extent is in IO. */
	struct task_struct	*oe_owner;
	/** return value of writeback. If somebody is waiting for this extent,
	 * this value can be known by outside world. */
	int			oe_rc;
	/** max pages per rpc when this extent was created */
	unsigned int		oe_mppr;
	/** FLR: layout version when this osc_extent is publised */
	__u32			oe_layout_version;
};

/** @} osc */

#endif /* LUSTRE_OSC_H */
