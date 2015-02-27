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
 * Copyright (c) 2011, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define MAX_STRING_SIZE 128

extern int ldlm_srv_namespace_nr;
extern int ldlm_cli_namespace_nr;
extern struct mutex ldlm_srv_namespace_lock;
extern struct list_head ldlm_srv_namespace_list;
extern struct mutex ldlm_cli_namespace_lock;
extern struct list_head ldlm_cli_active_namespace_list;
extern struct list_head ldlm_cli_inactive_namespace_list;
extern unsigned int ldlm_cancel_unused_locks_before_replay;

static inline int ldlm_namespace_nr_read(enum ldlm_side client)
{
	return client == LDLM_NAMESPACE_SERVER ?
		ldlm_srv_namespace_nr : ldlm_cli_namespace_nr;
}

static inline void ldlm_namespace_nr_inc(enum ldlm_side client)
{
	if (client == LDLM_NAMESPACE_SERVER)
		ldlm_srv_namespace_nr++;
	else
		ldlm_cli_namespace_nr++;
}

static inline void ldlm_namespace_nr_dec(enum ldlm_side client)
{
	if (client == LDLM_NAMESPACE_SERVER)
		ldlm_srv_namespace_nr--;
	else
		ldlm_cli_namespace_nr--;
}

static inline struct list_head *ldlm_namespace_list(enum ldlm_side client)
{
	return client == LDLM_NAMESPACE_SERVER ?
		&ldlm_srv_namespace_list : &ldlm_cli_active_namespace_list;
}

static inline
struct list_head *ldlm_namespace_inactive_list(enum ldlm_side client)
{
	return client == LDLM_NAMESPACE_SERVER ?
		&ldlm_srv_namespace_list : &ldlm_cli_inactive_namespace_list;
}

static inline struct mutex *ldlm_namespace_lock(enum ldlm_side client)
{
	return client == LDLM_NAMESPACE_SERVER ?
		&ldlm_srv_namespace_lock : &ldlm_cli_namespace_lock;
}

/* ns_bref is the number of resources in this namespace */
static inline int ldlm_ns_empty(struct ldlm_namespace *ns)
{
	return atomic_read(&ns->ns_bref) == 0;
}

void ldlm_namespace_move_to_active_locked(struct ldlm_namespace *,
					  enum ldlm_side);
void ldlm_namespace_move_to_inactive_locked(struct ldlm_namespace *,
					    enum ldlm_side);
struct ldlm_namespace *ldlm_namespace_first_locked(enum ldlm_side);

/* ldlm_request.c */
/* Cancel lru flag, it indicates we cancel aged locks. */
enum ldlm_lru_flags {
	LDLM_LRU_FLAG_AGED	= 0x01, /* Cancel aged locks (non LRU resize) */
	LDLM_LRU_FLAG_PASSED	= 0x02, /* Cancel passed number of locks */
	LDLM_LRU_FLAG_SHRINK	= 0x04, /* Cancel locks from shrinker */
	LDLM_LRU_FLAG_LRUR	= 0x08, /* Cancel locks from lru resize */
	LDLM_LRU_FLAG_NO_WAIT	= 0x10, /* Cancel locks w/o blocking (neither
					 * sending nor waiting for any RPCs) */
	LDLM_LRU_FLAG_LRUR_NO_WAIT = 0x20, /* LRUR + NO_WAIT */
};

int ldlm_cancel_lru(struct ldlm_namespace *ns, int nr,
		    enum ldlm_cancel_flags cancel_flags,
		    enum ldlm_lru_flags lru_flags);
int ldlm_cancel_lru_local(struct ldlm_namespace *ns,
			  struct list_head *cancels, int count, int max,
			  enum ldlm_cancel_flags cancel_flags,
			  enum ldlm_lru_flags lru_flags);
extern unsigned int ldlm_enqueue_min;
/* ldlm_resource.c */
extern struct kmem_cache *ldlm_resource_slab;
extern struct kmem_cache *ldlm_lock_slab;
extern struct kmem_cache *ldlm_interval_tree_slab;

void ldlm_resource_insert_lock_after(struct ldlm_lock *original,
                                     struct ldlm_lock *new);

/* ldlm_lock.c */

struct ldlm_cb_set_arg {
	struct ptlrpc_request_set	*set;
	int				 type; /* LDLM_{CP,BL,GL}_CALLBACK */
	atomic_t			 restart;
	struct list_head			*list;
	union ldlm_gl_desc		*gl_desc; /* glimpse AST descriptor */
};

typedef enum {
	LDLM_WORK_BL_AST,
	LDLM_WORK_CP_AST,
	LDLM_WORK_REVOKE_AST,
	LDLM_WORK_GL_AST
} ldlm_desc_ast_t;

void ldlm_grant_lock(struct ldlm_lock *lock, struct list_head *work_list);
int ldlm_fill_lvb(struct ldlm_lock *lock, struct req_capsule *pill,
		  enum req_location loc, void *data, int size);
struct ldlm_lock *
ldlm_lock_create(struct ldlm_namespace *ns, const struct ldlm_res_id *,
		 enum ldlm_type type, enum ldlm_mode mode,
		 const struct ldlm_callback_suite *cbs,
		 void *data, __u32 lvb_len, enum lvb_type lvb_type);
enum ldlm_error ldlm_lock_enqueue(struct ldlm_namespace *, struct ldlm_lock **,
				  void *cookie, __u64 *flags);
void ldlm_lock_addref_internal(struct ldlm_lock *, enum ldlm_mode mode);
void ldlm_lock_addref_internal_nolock(struct ldlm_lock *, enum ldlm_mode mode);
void ldlm_lock_decref_internal(struct ldlm_lock *, enum ldlm_mode mode);
void ldlm_lock_decref_internal_nolock(struct ldlm_lock *, enum ldlm_mode mode);
void ldlm_add_ast_work_item(struct ldlm_lock *lock, struct ldlm_lock *new,
			    struct list_head *work_list);
#ifdef HAVE_SERVER_SUPPORT
int ldlm_reprocess_queue(struct ldlm_resource *res, struct list_head *queue,
			 struct list_head *work_list);
#endif
int ldlm_run_ast_work(struct ldlm_namespace *ns, struct list_head *rpc_list,
                      ldlm_desc_ast_t ast_type);
int ldlm_work_gl_ast_lock(struct ptlrpc_request_set *rqset, void *opaq);
int ldlm_lock_remove_from_lru_check(struct ldlm_lock *lock,
				    cfs_time_t last_use);
#define ldlm_lock_remove_from_lru(lock) ldlm_lock_remove_from_lru_check(lock, 0)
int ldlm_lock_remove_from_lru_nolock(struct ldlm_lock *lock);
void ldlm_lock_add_to_lru_nolock(struct ldlm_lock *lock);
void ldlm_lock_add_to_lru(struct ldlm_lock *lock);
void ldlm_lock_touch_in_lru(struct ldlm_lock *lock);
void ldlm_lock_destroy_nolock(struct ldlm_lock *lock);

int ldlm_export_cancel_blocked_locks(struct obd_export *exp);
int ldlm_export_cancel_locks(struct obd_export *exp);

/* ldlm_lockd.c */
int ldlm_bl_to_thread_lock(struct ldlm_namespace *ns, struct ldlm_lock_desc *ld,
                           struct ldlm_lock *lock);
int ldlm_bl_to_thread_list(struct ldlm_namespace *ns,
			   struct ldlm_lock_desc *ld,
			   struct list_head *cancels, int count,
			   enum ldlm_cancel_flags cancel_flags);
int ldlm_bl_thread_wakeup(void);

void ldlm_handle_bl_callback(struct ldlm_namespace *ns,
                             struct ldlm_lock_desc *ld, struct ldlm_lock *lock);

#ifdef HAVE_SERVER_SUPPORT
/* ldlm_plain.c */
int ldlm_process_plain_lock(struct ldlm_lock *lock, __u64 *flags,
			    int first_enq, enum ldlm_error *err,
			    struct list_head *work_list);

/* ldlm_inodebits.c */
int ldlm_process_inodebits_lock(struct ldlm_lock *lock, __u64 *flags,
				int first_enq, enum ldlm_error *err,
				struct list_head *work_list);
#endif

/* ldlm_extent.c */
#ifdef HAVE_SERVER_SUPPORT
int ldlm_process_extent_lock(struct ldlm_lock *lock, __u64 *flags,
			     int first_enq, enum ldlm_error *err,
			     struct list_head *work_list);
#endif
void ldlm_extent_add_lock(struct ldlm_resource *res, struct ldlm_lock *lock);
void ldlm_extent_unlink_lock(struct ldlm_lock *lock);

/* ldlm_flock.c */
int ldlm_process_flock_lock(struct ldlm_lock *req, __u64 *flags,
			    int first_enq, enum ldlm_error *err,
			    struct list_head *work_list);
int ldlm_init_flock_export(struct obd_export *exp);
void ldlm_destroy_flock_export(struct obd_export *exp);

/* l_lock.c */
void l_check_ns_lock(struct ldlm_namespace *ns);
void l_check_no_ns_lock(struct ldlm_namespace *ns);

extern struct proc_dir_entry *ldlm_svc_proc_dir;

struct ldlm_state {
        struct ptlrpc_service *ldlm_cb_service;
        struct ptlrpc_service *ldlm_cancel_service;
        struct ptlrpc_client *ldlm_client;
        struct ptlrpc_connection *ldlm_server_conn;
        struct ldlm_bl_pool *ldlm_bl_pool;
};

/* interval tree, for LDLM_EXTENT. */
extern struct kmem_cache *ldlm_interval_slab; /* slab cache for ldlm_interval */
extern void ldlm_interval_attach(struct ldlm_interval *n, struct ldlm_lock *l);
extern struct ldlm_interval *ldlm_interval_detach(struct ldlm_lock *l);
extern struct ldlm_interval *ldlm_interval_alloc(struct ldlm_lock *lock);
extern void ldlm_interval_free(struct ldlm_interval *node);
/* this function must be called with res lock held */
static inline struct ldlm_extent *
ldlm_interval_extent(struct ldlm_interval *node)
{
        struct ldlm_lock *lock;
	LASSERT(!list_empty(&node->li_group));

	lock = list_entry(node->li_group.next, struct ldlm_lock,
                              l_sl_policy);
        return &lock->l_policy_data.l_extent;
}

int ldlm_init(void);
void ldlm_exit(void);

enum ldlm_policy_res {
        LDLM_POLICY_CANCEL_LOCK,
        LDLM_POLICY_KEEP_LOCK,
        LDLM_POLICY_SKIP_LOCK
};

#define LDLM_POOL_PROC_READER_SEQ_SHOW(var, type)			\
	static int lprocfs_##var##_seq_show(struct seq_file *m, void *v)\
	{								\
		struct ldlm_pool *pl = m->private;			\
		type tmp;						\
									\
		spin_lock(&pl->pl_lock);				\
		tmp = pl->pl_##var;					\
		spin_unlock(&pl->pl_lock);				\
									\
		return lprocfs_uint_seq_show(m, &tmp);			\
	}								\
	struct __##var##__dummy_read {;} /* semicolon catcher */

#define LDLM_POOL_PROC_WRITER(var, type)				\
	static int lprocfs_wr_##var(struct file *file,			\
			     const char __user *buffer,			\
			     unsigned long count, void *data)		\
	{								\
		struct ldlm_pool *pl = data;				\
		type tmp;						\
		int rc;							\
									\
		rc = lprocfs_wr_uint(file, buffer, count, &tmp);	\
		if (rc < 0) {						\
			CERROR("Can't parse user input, rc = %d\n", rc);\
			return rc;					\
		}							\
									\
		spin_lock(&pl->pl_lock);				\
		pl->pl_##var = tmp;					\
		spin_unlock(&pl->pl_lock);				\
									\
		return rc;						\
	}								\
	struct __##var##__dummy_write {;} /* semicolon catcher */

static inline void
ldlm_add_var(struct lprocfs_vars *vars, struct proc_dir_entry *proc_dir,
	     const char *name, void *data, const struct file_operations *ops)
{
	snprintf((char *)vars->name, MAX_STRING_SIZE, "%s", name);
	vars->data = data;
	vars->fops = ops;
	lprocfs_add_vars(proc_dir, vars, NULL);
}

static inline int is_granted_or_cancelled(struct ldlm_lock *lock)
{
        int ret = 0;

        lock_res_and_lock(lock);
	if ((lock->l_req_mode == lock->l_granted_mode) &&
	     !ldlm_is_cp_reqd(lock))
		ret = 1;
	else if (ldlm_is_failed(lock) || ldlm_is_cancel(lock))
                ret = 1;
        unlock_res_and_lock(lock);

        return ret;
}

typedef void (*ldlm_policy_wire_to_local_t)(const union ldlm_wire_policy_data *,
					    union ldlm_policy_data *);
typedef void (*ldlm_policy_local_to_wire_t)(const union ldlm_policy_data *,
					    union ldlm_wire_policy_data *);
void ldlm_plain_policy_wire_to_local(const union ldlm_wire_policy_data *wpolicy,
				     union ldlm_policy_data *lpolicy);
void ldlm_plain_policy_local_to_wire(const union ldlm_policy_data *lpolicy,
				     union ldlm_wire_policy_data *wpolicy);
void ldlm_ibits_policy_wire_to_local(const union ldlm_wire_policy_data *wpolicy,
				     union ldlm_policy_data *lpolicy);
void ldlm_ibits_policy_local_to_wire(const union ldlm_policy_data *lpolicy,
				     union ldlm_wire_policy_data *wpolicy);
void ldlm_extent_policy_wire_to_local(const union ldlm_wire_policy_data *wpolicy,
				      union ldlm_policy_data *lpolicy);
void ldlm_extent_policy_local_to_wire(const union ldlm_policy_data *lpolicy,
				      union ldlm_wire_policy_data *wpolicy);
void ldlm_flock_policy_wire_to_local(const union ldlm_wire_policy_data *wpolicy,
				     union ldlm_policy_data *lpolicy);
void ldlm_flock_policy_local_to_wire(const union ldlm_policy_data *lpolicy,
				     union ldlm_wire_policy_data *wpolicy);

/* ldlm_reclaim.c */
#ifdef HAVE_SERVER_SUPPORT
extern __u64 ldlm_reclaim_threshold;
extern __u64 ldlm_lock_limit;
extern __u64 ldlm_reclaim_threshold_mb;
extern __u64 ldlm_lock_limit_mb;
extern struct percpu_counter ldlm_granted_total;
#endif
int ldlm_reclaim_setup(void);
void ldlm_reclaim_cleanup(void);
void ldlm_reclaim_add(struct ldlm_lock *lock);
void ldlm_reclaim_del(struct ldlm_lock *lock);
bool ldlm_reclaim_full(void);
