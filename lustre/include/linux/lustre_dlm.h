/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * (visit-tags-table FILE)
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _LUSTRE_DLM_H__
#define _LUSTRE_DLM_H__

#ifdef __KERNEL__
# include <linux/proc_fs.h>
#endif 

#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_import.h>
#include <linux/lustre_handles.h>
#include <linux/lustre_export.h> /* for obd_export, for LDLM_DEBUG */

struct obd_ops;
struct obd_device;

#define OBD_LDLM_DEVICENAME  "ldlm"

#define LDLM_DEFAULT_LRU_SIZE 100

typedef enum {
        ELDLM_OK = 0,

        ELDLM_LOCK_CHANGED = 300,
        ELDLM_LOCK_ABORTED = 301,
        ELDLM_LOCK_REPLACED = 302,

        ELDLM_NAMESPACE_EXISTS = 400,
        ELDLM_BAD_NAMESPACE    = 401
} ldlm_error_t;

#define LDLM_NAMESPACE_SERVER 0
#define LDLM_NAMESPACE_CLIENT 1

#define LDLM_FL_LOCK_CHANGED   0x000001 /* extent, mode, or resource changed */

/* If the server returns one of these flags, then the lock was put on that list.
 * If the client sends one of these flags (during recovery ONLY!), it wants the
 * lock added to the specified list, no questions asked. -p */
#define LDLM_FL_BLOCK_GRANTED  0x000002
#define LDLM_FL_BLOCK_CONV     0x000004
#define LDLM_FL_BLOCK_WAIT     0x000008

#define LDLM_FL_CBPENDING      0x000010 /* this lock is being destroyed */
#define LDLM_FL_AST_SENT       0x000020 /* blocking or cancel packet was sent */
#define LDLM_FL_WAIT_NOREPROC  0x000040 /* not a real flag, not saved in lock */
#define LDLM_FL_CANCEL         0x000080 /* cancellation callback already run */

/* Lock is being replayed.  This could probably be implied by the fact that one
 * of BLOCK_{GRANTED,CONV,WAIT} is set, but that is pretty dangerous. */
#define LDLM_FL_REPLAY         0x000100

#define LDLM_FL_INTENT_ONLY    0x000200 /* don't grant lock, just do intent */
#define LDLM_FL_LOCAL_ONLY     0x000400 /* see ldlm_cli_cancel_unused */

/* don't run the cancel callback under ldlm_cli_cancel_unused */
#define LDLM_FL_NO_CALLBACK    0x000800

#define LDLM_FL_HAS_INTENT     0x001000 /* lock request has intent */
#define LDLM_FL_CANCELING      0x002000 /* lock cancel has already been sent */
#define LDLM_FL_LOCAL          0x004000 /* local lock (ie, no srv/cli split) */
#define LDLM_FL_WARN           0x008000 /* see ldlm_cli_cancel_unused */
#define LDLM_FL_DISCARD_DATA   0x010000 /* discard (no writeback) on cancel */

/* file & record locking */
#define LDLM_FL_BLOCK_NOWAIT   0x040000 // server told not to wait if blocked
#define LDLM_FL_TEST_LOCK      0x080000 // return blocking lock

/* These are flags that are mapped into the flags and ASTs of blocking locks */
#define LDLM_AST_DISCARD_DATA  0x80000000 /* Add FL_DISCARD to blocking ASTs */
/* Flags sent in AST lock_flags to be mapped into the receiving lock. */
#define LDLM_AST_FLAGS         (LDLM_FL_DISCARD_DATA)

/* XXX FIXME: This is being added to b_size as a low-risk fix to the fact that
 * the LVB filling happens _after_ the lock has been granted, so another thread
 * can match before the LVB has been updated.  As a dirty hack, we set
 * LDLM_FL_CAN_MATCH only after we've done the LVB poop.
 *
 * The proper fix is to do the granting inside of the completion AST, which can
 * be replaced with a LVB-aware wrapping function for OSC locks.  That change is
 * pretty high-risk, though, and would need a lot more testing. */
#define LDLM_FL_CAN_MATCH      0x100000

/* The blocking callback is overloaded to perform two functions.  These flags
 * indicate which operation should be performed. */
#define LDLM_CB_BLOCKING    1
#define LDLM_CB_CANCELING   2

#define L2B(c) (1 << c)

/* compatibility matrix */
#define LCK_COMPAT_EX  L2B(LCK_NL)
#define LCK_COMPAT_PW  (LCK_COMPAT_EX | L2B(LCK_CR))
#define LCK_COMPAT_PR  (LCK_COMPAT_PW | L2B(LCK_PR))
#define LCK_COMPAT_CW  (LCK_COMPAT_PW | L2B(LCK_CW))
#define LCK_COMPAT_CR  (LCK_COMPAT_CW | L2B(LCK_PR) | L2B(LCK_PW))
#define LCK_COMPAT_NL  (LCK_COMPAT_CR | L2B(LCK_EX))

static ldlm_mode_t lck_compat_array[] = {
        [LCK_EX] LCK_COMPAT_EX,
        [LCK_PW] LCK_COMPAT_PW,
        [LCK_PR] LCK_COMPAT_PR,
        [LCK_CW] LCK_COMPAT_CW,
        [LCK_CR] LCK_COMPAT_CR,
        [LCK_NL] LCK_COMPAT_NL
};

static inline int lockmode_compat(ldlm_mode_t exist, ldlm_mode_t new)
{
       LASSERT(exist >= LCK_EX && exist <= LCK_NL);
       LASSERT(new >= LCK_EX && new <= LCK_NL);

       return (lck_compat_array[exist] & L2B(new));
}

/*
 *
 * cluster name spaces
 *
 */

#define DLM_OST_NAMESPACE 1
#define DLM_MDS_NAMESPACE 2

/* XXX
   - do we just separate this by security domains and use a prefix for
     multiple namespaces in the same domain?
   -
*/

struct ldlm_lock; 
struct ldlm_resource; 
struct ldlm_namespace;

typedef int (*ldlm_res_policy)(struct ldlm_namespace *, struct ldlm_lock **,
                               void *req_cookie, ldlm_mode_t mode, int flags,
                               void *data);

struct ldlm_valblock_ops {
        int (*lvbo_init)(struct ldlm_resource *res);
        int (*lvbo_update)(struct ldlm_resource *res, struct lustre_msg *m,
                           int buf_idx);
};

struct ldlm_namespace {
        char                  *ns_name;
        __u32                  ns_client; /* is this a client-side lock tree? */
        struct list_head      *ns_hash; /* hash table for ns */
        __u32                  ns_refcount; /* count of resources in the hash */
        struct list_head       ns_root_list; /* all root resources in ns */
        struct lustre_lock     ns_lock; /* protects hash, refcount, list */
        struct list_head       ns_list_chain; /* position in global NS list */
        /* 
        struct proc_dir_entry *ns_proc_dir;
        */

        struct list_head       ns_unused_list; /* all root resources in ns */
        int                    ns_nr_unused;
        unsigned int           ns_max_unused;

        spinlock_t             ns_counter_lock;
        __u64                  ns_locks;
        __u64                  ns_resources;
        ldlm_res_policy        ns_policy;
        struct ldlm_valblock_ops *ns_lvbo;
        void                    *ns_lvbp;
};

/*
 *
 * Resource hash table
 *
 */

#define RES_HASH_BITS 10
#define RES_HASH_SIZE (1UL << RES_HASH_BITS)
#define RES_HASH_MASK (RES_HASH_SIZE - 1)

struct ldlm_lock;

typedef int (*ldlm_blocking_callback)(struct ldlm_lock *lock,
                                      struct ldlm_lock_desc *new, void *data,
                                      int flag);
typedef int (*ldlm_completion_callback)(struct ldlm_lock *lock, int flags,
                                        void *data);
typedef int (*ldlm_glimpse_callback)(struct ldlm_lock *lock, void *data);

struct ldlm_lock {
        struct portals_handle l_handle; // must be first in the structure
        atomic_t              l_refc;
        struct ldlm_resource *l_resource;
        struct ldlm_lock     *l_parent;
        struct list_head      l_children;
        struct list_head      l_childof;
        struct list_head      l_lru;
        struct list_head      l_res_link; // position in one of three res lists
        struct list_head      l_export_chain; // per-export chain of locks
        struct list_head      l_pending_chain; // locks with callbacks pending
        unsigned long         l_callback_timeout;

        ldlm_mode_t           l_req_mode;
        ldlm_mode_t           l_granted_mode;

        ldlm_completion_callback l_completion_ast;
        ldlm_blocking_callback   l_blocking_ast;
        ldlm_glimpse_callback    l_glimpse_ast;
        void                    *l_ast_data;

        struct obd_export    *l_export;
        /* XXX phil can fix this, I'm sure */
        struct obd_export    *l_conn_export;
//        struct lustre_handle *l_connh;
        __u32                 l_flags;
        struct lustre_handle  l_remote_handle;
        ldlm_policy_data_t    l_policy_data;

        /* This LVB is used only on the client side, as temporary storage for
         * a lock value block received during an enqueue */
        __u32                 l_lvb_len;
        void                 *l_lvb_data;
        void                 *l_lvb_swabber;

        __u32                 l_readers;
        __u32                 l_writers;
        __u8                  l_destroyed;

        /* If the lock is granted, a process sleeps on this waitq to learn when
         * it's no longer in use.  If the lock is not granted, a process sleeps
         * on this waitq to learn when it becomes granted. */
        wait_queue_head_t     l_waitq;
        struct timeval        l_enqueued_time;
        unsigned long         l_last_used; /* jiffies */
};


#define LDLM_PLAIN       10
#define LDLM_EXTENT      11
#define LDLM_FLOCK       12

#define LDLM_MIN_TYPE 10
#define LDLM_MAX_TYPE 12

struct ldlm_resource {
        struct ldlm_namespace *lr_namespace;
        struct list_head       lr_hash;
        struct ldlm_resource  *lr_parent;   /* 0 for a root resource */
        struct list_head       lr_children; /* list head for child resources */
        struct list_head       lr_childof;  /* part of ns_root_list if root res,
                                             * part of lr_children if child */

        struct list_head       lr_granted;
        struct list_head       lr_converting;
        struct list_head       lr_waiting;
        ldlm_mode_t            lr_most_restr;
        __u32                  lr_type; /* LDLM_PLAIN or LDLM_EXTENT */
        struct ldlm_resource  *lr_root;
        struct ldlm_res_id     lr_name;
        atomic_t               lr_refcount;

        /* Server-side-only lock value block elements */
        struct semaphore       lr_lvb_sem;
        __u32                  lr_lvb_len;
        void                  *lr_lvb_data;

        /* lr_tmp holds a list head temporarily, during the building of a work
         * queue.  see ldlm_add_ast_work_item and ldlm_run_ast_work */
        void                  *lr_tmp;
};

struct ldlm_ast_work {
        struct ldlm_lock *w_lock;
        int               w_blocking;
        struct ldlm_lock_desc w_desc;
        struct list_head   w_list;
        int w_flags;
        void *w_data;
        int w_datalen;
};

extern struct obd_ops ldlm_obd_ops;

extern char *ldlm_lockname[];
extern char *ldlm_typename[];
extern char *ldlm_it2str(int it);

#define __LDLM_DEBUG(level, lock, format, a...)                               \
do {                                                                          \
        if (lock->l_resource == NULL) {                                       \
                CDEBUG(level, "### " format                                   \
                       " ns: \?\? lock: %p/"LPX64" lrc: %d/%d,%d mode: %s/%s "\
                       "res: \?\? rrc=\?\? type: \?\?\? flags: %x remote: "   \
                       LPX64" expref: %d\n" , ## a, lock,                     \
                       lock->l_handle.h_cookie, atomic_read(&lock->l_refc),   \
                       lock->l_readers, lock->l_writers,                      \
                       ldlm_lockname[lock->l_granted_mode],                   \
                       ldlm_lockname[lock->l_req_mode],                       \
                       lock->l_flags, lock->l_remote_handle.cookie,           \
                       lock->l_export ?                                       \
                       atomic_read(&lock->l_export->exp_refcount) : -99);     \
                break;                                                        \
        }                                                                     \
        if (lock->l_resource->lr_type == LDLM_EXTENT) {                       \
                CDEBUG(level, "### " format                                   \
                       " ns: %s lock: %p/"LPX64" lrc: %d/%d,%d mode: %s/%s "  \
                       "res: "LPU64"/"LPU64" rrc: %d type: %s ["LPU64"->"LPU64\
                       "] flags: %x remote: "LPX64" expref: %d\n" , ## a,     \
                       lock->l_resource->lr_namespace->ns_name, lock,         \
                       lock->l_handle.h_cookie, atomic_read(&lock->l_refc),   \
                       lock->l_readers, lock->l_writers,                      \
                       ldlm_lockname[lock->l_granted_mode],                   \
                       ldlm_lockname[lock->l_req_mode],                       \
                       lock->l_resource->lr_name.name[0],                     \
                       lock->l_resource->lr_name.name[1],                     \
                       atomic_read(&lock->l_resource->lr_refcount),           \
                       ldlm_typename[lock->l_resource->lr_type],              \
                       lock->l_policy_data.l_extent.start,                    \
                       lock->l_policy_data.l_extent.end,                      \
                       lock->l_flags, lock->l_remote_handle.cookie,           \
                       lock->l_export ?                                       \
                       atomic_read(&lock->l_export->exp_refcount) : -99);     \
                break;                                                        \
        }                                                                     \
        if (lock->l_resource->lr_type == LDLM_FLOCK) {                        \
                CDEBUG(level, "### " format                                   \
                       " ns: %s lock: %p/"LPX64" lrc: %d/%d,%d mode: %s/%s "  \
                       "res: "LPU64"/"LPU64" rrc: %d type: %s pid: %d "       \
                       "["LPU64"->"LPU64"] flags: %x remote: "LPX64           \
                       " expref: %d\n" , ## a,                                \
                       lock->l_resource->lr_namespace->ns_name, lock,         \
                       lock->l_handle.h_cookie, atomic_read(&lock->l_refc),   \
                       lock->l_readers, lock->l_writers,                      \
                       ldlm_lockname[lock->l_granted_mode],                   \
                       ldlm_lockname[lock->l_req_mode],                       \
                       lock->l_resource->lr_name.name[0],                     \
                       lock->l_resource->lr_name.name[1],                     \
                       atomic_read(&lock->l_resource->lr_refcount),           \
                       ldlm_typename[lock->l_resource->lr_type],              \
                       lock->l_policy_data.l_flock.pid,                       \
                       lock->l_policy_data.l_flock.start,                     \
                       lock->l_policy_data.l_flock.end,                       \
                       lock->l_flags, lock->l_remote_handle.cookie,           \
                       lock->l_export ?                                       \
                       atomic_read(&lock->l_export->exp_refcount) : -99);     \
                break;                                                        \
        }                                                                     \
        {                                                                     \
                CDEBUG(level, "### " format                                   \
                       " ns: %s lock: %p/"LPX64" lrc: %d/%d,%d mode: %s/%s "  \
                       "res: "LPU64"/"LPU64" rrc: %d type: %s flags: %x "     \
                       "remote: "LPX64" expref: %d\n" , ## a,                 \
                       lock->l_resource->lr_namespace->ns_name,               \
                       lock, lock->l_handle.h_cookie,                         \
                       atomic_read (&lock->l_refc),                           \
                       lock->l_readers, lock->l_writers,                      \
                       ldlm_lockname[lock->l_granted_mode],                   \
                       ldlm_lockname[lock->l_req_mode],                       \
                       lock->l_resource->lr_name.name[0],                     \
                       lock->l_resource->lr_name.name[1],                     \
                       atomic_read(&lock->l_resource->lr_refcount),           \
                       ldlm_typename[lock->l_resource->lr_type],              \
                       lock->l_flags, lock->l_remote_handle.cookie,           \
                       lock->l_export ?                                       \
                       atomic_read(&lock->l_export->exp_refcount) : -99);     \
        }                                                                     \
} while (0)

#define LDLM_DEBUG(lock, format, a...) __LDLM_DEBUG(D_DLMTRACE, lock, \
                                                    format, ## a)
#define LDLM_ERROR(lock, format, a...) __LDLM_DEBUG(D_ERROR, lock, format, ## a)

#define LDLM_DEBUG_NOLOCK(format, a...)                 \
        CDEBUG(D_DLMTRACE, "### " format "\n" , ## a)

typedef int (*ldlm_processing_policy)(struct ldlm_lock *lock, int *flags,
                                      int first_enq, ldlm_error_t *err);

/*
 * Iterators.
 */

#define LDLM_ITER_CONTINUE 1 /* keep iterating */
#define LDLM_ITER_STOP     2 /* stop iterating */

typedef int (*ldlm_iterator_t)(struct ldlm_lock *, void *);
typedef int (*ldlm_res_iterator_t)(struct ldlm_resource *, void *);

int ldlm_resource_foreach(struct ldlm_resource *res, ldlm_iterator_t iter,
                          void *closure);
int ldlm_namespace_foreach(struct ldlm_namespace *ns, ldlm_iterator_t iter,
                           void *closure);
int ldlm_namespace_foreach_res(struct ldlm_namespace *ns,
                               ldlm_res_iterator_t iter, void *closure);

int ldlm_replay_locks(struct obd_import *imp);
void ldlm_change_cbdata(struct ldlm_namespace *, struct ldlm_res_id *,
                        ldlm_iterator_t iter, void *data);

/* ldlm_flock.c */
int ldlm_flock_completion_ast(struct ldlm_lock *lock, int flags, void *data);

/* ldlm_extent.c */
__u64 ldlm_extent_shift_kms(struct ldlm_lock *lock, __u64 old_kms);


/* ldlm_lockd.c */
int ldlm_server_blocking_ast(struct ldlm_lock *, struct ldlm_lock_desc *,
                             void *data, int flag);
int ldlm_server_completion_ast(struct ldlm_lock *lock, int flags, void *data);
int ldlm_server_glimpse_ast(struct ldlm_lock *lock, void *data);
int ldlm_handle_enqueue(struct ptlrpc_request *req, ldlm_completion_callback,
                        ldlm_blocking_callback, ldlm_glimpse_callback);
int ldlm_handle_convert(struct ptlrpc_request *req);
int ldlm_handle_cancel(struct ptlrpc_request *req);
int ldlm_del_waiting_lock(struct ldlm_lock *lock);
int ldlm_get_ref(void);
void ldlm_put_ref(int force);

/* ldlm_lock.c */
ldlm_processing_policy ldlm_get_processing_policy(struct ldlm_resource *res);
void ldlm_register_intent(struct ldlm_namespace *ns, ldlm_res_policy arg);
void ldlm_lock2handle(struct ldlm_lock *lock, struct lustre_handle *lockh);
struct ldlm_lock *__ldlm_handle2lock(struct lustre_handle *, int flags);
void ldlm_cancel_callback(struct ldlm_lock *);
int ldlm_lock_set_data(struct lustre_handle *, void *data);
void ldlm_lock_remove_from_lru(struct ldlm_lock *);
struct ldlm_lock *ldlm_handle2lock_ns(struct ldlm_namespace *,
                                      struct lustre_handle *);

static inline struct ldlm_lock *ldlm_handle2lock(struct lustre_handle *h)
{
        return __ldlm_handle2lock(h, 0);
}

#define LDLM_LOCK_PUT(lock)                     \
do {                                            \
        /*LDLM_DEBUG((lock), "put");*/          \
        ldlm_lock_put(lock);                    \
} while (0)

#define LDLM_LOCK_GET(lock)                     \
({                                              \
        ldlm_lock_get(lock);                    \
        /*LDLM_DEBUG((lock), "get");*/          \
        lock;                                   \
})

struct ldlm_lock *ldlm_lock_get(struct ldlm_lock *lock);
void ldlm_lock_put(struct ldlm_lock *lock);
void ldlm_lock_destroy(struct ldlm_lock *lock);
void ldlm_lock2desc(struct ldlm_lock *lock, struct ldlm_lock_desc *desc);
void ldlm_lock_addref(struct lustre_handle *lockh, __u32 mode);
void ldlm_lock_decref(struct lustre_handle *lockh, __u32 mode);
void ldlm_lock_decref_and_cancel(struct lustre_handle *lockh, __u32 mode);
void ldlm_lock_allow_match(struct ldlm_lock *lock);
int ldlm_lock_match(struct ldlm_namespace *ns, int flags, struct ldlm_res_id *,
                    __u32 type, ldlm_policy_data_t *, ldlm_mode_t mode,
                    struct lustre_handle *);
struct ldlm_resource *ldlm_lock_convert(struct ldlm_lock *lock, int new_mode,
                                        int *flags);
void ldlm_lock_cancel(struct ldlm_lock *lock);
void ldlm_cancel_locks_for_export(struct obd_export *export);
void ldlm_reprocess_all(struct ldlm_resource *res);
void ldlm_reprocess_all_ns(struct ldlm_namespace *ns);
void ldlm_lock_dump(int level, struct ldlm_lock *lock, int pos);
void ldlm_lock_dump_handle(int level, struct lustre_handle *);

/* ldlm_test.c */
int ldlm_test(struct obd_device *device, struct lustre_handle *connh);
int ldlm_regression_start(struct obd_device *obddev,
                          struct lustre_handle *connh,
                          unsigned int threads, unsigned int max_locks_in,
                          unsigned int num_resources_in,
                          unsigned int num_extents_in);
int ldlm_regression_stop(void);


/* resource.c */
struct ldlm_namespace *ldlm_namespace_new(char *name, __u32 local);
int ldlm_namespace_cleanup(struct ldlm_namespace *ns, int flags);
int ldlm_namespace_free(struct ldlm_namespace *ns, int force);
int ldlm_proc_setup(void);
void ldlm_proc_cleanup(void);

/* resource.c - internal */
struct ldlm_resource *ldlm_resource_get(struct ldlm_namespace *ns,
                                        struct ldlm_resource *parent,
                                        struct ldlm_res_id, __u32 type,
                                        int create);
struct ldlm_resource *ldlm_resource_getref(struct ldlm_resource *res);
int ldlm_resource_putref(struct ldlm_resource *res);
void ldlm_resource_add_lock(struct ldlm_resource *res, struct list_head *head,
                            struct ldlm_lock *lock);
void ldlm_resource_unlink_lock(struct ldlm_lock *lock);
void ldlm_res2desc(struct ldlm_resource *res, struct ldlm_resource_desc *desc);
void ldlm_dump_all_namespaces(void);
void ldlm_namespace_dump(struct ldlm_namespace *);
void ldlm_resource_dump(struct ldlm_resource *);
int ldlm_lock_change_resource(struct ldlm_namespace *, struct ldlm_lock *,
                              struct ldlm_res_id);

/* ldlm_request.c */
int ldlm_expired_completion_wait(void *data);
int ldlm_completion_ast(struct ldlm_lock *lock, int flags, void *data);
int ldlm_cli_enqueue(struct obd_export *exp,
                     struct ptlrpc_request *req,
                     struct ldlm_namespace *ns,
                     struct ldlm_res_id,
                     __u32 type,
                     ldlm_policy_data_t *,
                     ldlm_mode_t mode,
                     int *flags,
                     ldlm_blocking_callback blocking,
                     ldlm_completion_callback completion,
                     ldlm_glimpse_callback glimpse,
                     void *data,
                     void *lvb,
                     __u32 lvb_len,
                     void *lvb_swabber,
                     struct lustre_handle *lockh);
int ldlm_server_ast(struct lustre_handle *lockh, struct ldlm_lock_desc *new,
                    void *data, __u32 data_len);
int ldlm_cli_convert(struct lustre_handle *, int new_mode, int *flags);
int ldlm_cli_cancel(struct lustre_handle *lockh);
int ldlm_cli_cancel_unused(struct ldlm_namespace *, struct ldlm_res_id *,
                           int flags, void *opaque);

/* mds/handler.c */
/* This has to be here because recursive inclusion sucks. */
int intent_disposition(struct ldlm_reply *rep, int flag);
void intent_set_disposition(struct ldlm_reply *rep, int flag);
int mds_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                     void *data, int flag);


/* ioctls for trying requests */
#define IOC_LDLM_TYPE                   'f'
#define IOC_LDLM_MIN_NR                 40

#define IOC_LDLM_TEST                   _IOWR('f', 40, long)
#define IOC_LDLM_DUMP                   _IOWR('f', 41, long)
#define IOC_LDLM_REGRESS_START          _IOWR('f', 42, long)
#define IOC_LDLM_REGRESS_STOP           _IOWR('f', 43, long)
#define IOC_LDLM_MAX_NR                 43

#endif
