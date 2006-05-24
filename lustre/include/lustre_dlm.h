/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * (visit-tags-table FILE)
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _LUSTRE_DLM_H__
#define _LUSTRE_DLM_H__

#if defined(__linux__)
#include <linux/lustre_dlm.h>
#elif defined(__APPLE__)
#include <darwin/lustre_dlm.h>
#elif defined(__WINNT__)
#include <winnt/lustre_dlm.h>
#else
#error Unsupported operating system.
#endif

#include <lustre_lib.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_handles.h>
#include <lustre_export.h> /* for obd_export, for LDLM_DEBUG */

struct obd_ops;
struct obd_device;

#define OBD_LDLM_DEVICENAME  "ldlm"

#define LDLM_DEFAULT_LRU_SIZE (100 * smp_num_cpus)

typedef enum {
        ELDLM_OK = 0,

        ELDLM_LOCK_CHANGED = 300,
        ELDLM_LOCK_ABORTED = 301,
        ELDLM_LOCK_REPLACED = 302,
        ELDLM_NO_LOCK_DATA = 303,

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
#define LDLM_FL_FAILED         0x000800

#define LDLM_FL_HAS_INTENT     0x001000 /* lock request has intent */
#define LDLM_FL_CANCELING      0x002000 /* lock cancel has already been sent */
#define LDLM_FL_LOCAL          0x004000 /* local lock (ie, no srv/cli split) */
#define LDLM_FL_WARN           0x008000 /* see ldlm_cli_cancel_unused */
#define LDLM_FL_DISCARD_DATA   0x010000 /* discard (no writeback) on cancel */

#define LDLM_FL_NO_TIMEOUT     0x020000 /* Blocked by group lock - wait
                                         * indefinitely */

/* file & record locking */
#define LDLM_FL_BLOCK_NOWAIT   0x040000 // server told not to wait if blocked
#define LDLM_FL_TEST_LOCK      0x080000 // return blocking lock

/* XXX FIXME: This is being added to b_size as a low-risk fix to the fact that
 * the LVB filling happens _after_ the lock has been granted, so another thread
 * can match before the LVB has been updated.  As a dirty hack, we set
 * LDLM_FL_CAN_MATCH only after we've done the LVB poop.
 *
 * The proper fix is to do the granting inside of the completion AST, which can
 * be replaced with a LVB-aware wrapping function for OSC locks.  That change is
 * pretty high-risk, though, and would need a lot more testing. */
#define LDLM_FL_CAN_MATCH      0x100000

/* A lock contributes to the kms calculation until it has finished the part
 * of it's cancelation that performs write back on its dirty pages.  It
 * can remain on the granted list during this whole time.  Threads racing
 * to update the kms after performing their writeback need to know to
 * exclude each others locks from the calculation as they walk the granted
 * list. */
#define LDLM_FL_KMS_IGNORE     0x200000

/* Don't drop lock covering mmapped file in LRU */
#define LDLM_FL_NO_LRU         0x400000

/* Immediatelly cancel such locks when they block some other locks. Send
   cancel notification to original lock holder, but expect no reply. */
#define LDLM_FL_CANCEL_ON_BLOCK 0x800000

/* Flags flags inherited from parent lock when doing intents. */
#define LDLM_INHERIT_FLAGS     (LDLM_FL_CANCEL_ON_BLOCK)

/* These are flags that are mapped into the flags and ASTs of blocking locks */
#define LDLM_AST_DISCARD_DATA  0x80000000 /* Add FL_DISCARD to blocking ASTs */
/* Flags sent in AST lock_flags to be mapped into the receiving lock. */
#define LDLM_AST_FLAGS         (LDLM_FL_DISCARD_DATA)

/* The blocking callback is overloaded to perform two functions.  These flags
 * indicate which operation should be performed. */
#define LDLM_CB_BLOCKING    1
#define LDLM_CB_CANCELING   2

/* compatibility matrix */
#define LCK_COMPAT_EX  LCK_NL
#define LCK_COMPAT_PW  (LCK_COMPAT_EX | LCK_CR)
#define LCK_COMPAT_PR  (LCK_COMPAT_PW | LCK_PR)
#define LCK_COMPAT_CW  (LCK_COMPAT_PW | LCK_CW)
#define LCK_COMPAT_CR  (LCK_COMPAT_CW | LCK_PR | LCK_PW)
#define LCK_COMPAT_NL  (LCK_COMPAT_CR | LCK_EX)
#define LCK_COMPAT_GROUP  (LCK_GROUP | LCK_NL)

extern ldlm_mode_t lck_compat_array[];

static inline void lockmode_verify(ldlm_mode_t mode)
{
       LASSERT(mode > LCK_MINMODE && mode < LCK_MAXMODE);
}

static inline int lockmode_compat(ldlm_mode_t exist, ldlm_mode_t new)
{
       return (lck_compat_array[exist] & new);
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
                           int buf_idx, int increase);
};

struct ldlm_namespace {
        char                  *ns_name;
        __u32                  ns_client; /* is this a client-side lock tree? */
        struct list_head      *ns_hash; /* hash table for ns */
        cfs_waitq_t            ns_refcount_waitq; /* for cleanup */
        atomic_t               ns_refcount; /* count of resources in the hash */
        struct list_head       ns_root_list; /* all root resources in ns */
        struct lustre_lock     ns_lock; /* protects hash, refcount, list */
        struct list_head       ns_list_chain; /* position in global NS list */

        struct list_head       ns_unused_list; /* all root resources in ns */
        int                    ns_nr_unused;
        unsigned int           ns_max_unused;
        cfs_time_t             ns_next_dump;   /* next debug dump, jiffies */

        spinlock_t             ns_counter_lock;
        __u64                  ns_locks;
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

        ldlm_mode_t           l_req_mode;
        ldlm_mode_t           l_granted_mode;

        ldlm_completion_callback l_completion_ast;
        ldlm_blocking_callback   l_blocking_ast;
        ldlm_glimpse_callback    l_glimpse_ast;

        struct obd_export    *l_export;
        struct obd_export    *l_conn_export;
        __u32                 l_flags;
        struct lustre_handle  l_remote_handle;
        ldlm_policy_data_t    l_policy_data;

        __u32                 l_readers;
        __u32                 l_writers;
        __u8                  l_destroyed;

        /* If the lock is granted, a process sleeps on this waitq to learn when
         * it's no longer in use.  If the lock is not granted, a process sleeps
         * on this waitq to learn when it becomes granted. */
        cfs_waitq_t           l_waitq;
        struct timeval        l_enqueued_time;

        cfs_time_t            l_last_used;      /* jiffies */
        struct ldlm_extent    l_req_extent;

        /* Client-side-only members */
        __u32                 l_lvb_len;        /* temporary storage for */
        void                 *l_lvb_data;       /* an LVB received during */
        void                 *l_lvb_swabber;    /* an enqueue */
        void                 *l_ast_data;

        /* Server-side-only members */
        struct list_head      l_pending_chain;  /* callbacks pending */
        cfs_time_t            l_callback_timeout; /* jiffies */

        __u32                 l_pid;            /* pid which created this lock */
};

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
        ldlm_type_t            lr_type; /* LDLM_{PLAIN,EXTENT,FLOCK} */
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
                       LPX64" expref: %d pid: %u\n" , ## a, lock,             \
                       lock->l_handle.h_cookie, atomic_read(&lock->l_refc),   \
                       lock->l_readers, lock->l_writers,                      \
                       ldlm_lockname[lock->l_granted_mode],                   \
                       ldlm_lockname[lock->l_req_mode],                       \
                       lock->l_flags, lock->l_remote_handle.cookie,           \
                       lock->l_export ?                                       \
                       atomic_read(&lock->l_export->exp_refcount) : -99,      \
                       lock->l_pid);                                          \
                break;                                                        \
        }                                                                     \
        if (lock->l_resource->lr_type == LDLM_EXTENT) {                       \
                CDEBUG(level, "### " format                                   \
                       " ns: %s lock: %p/"LPX64" lrc: %d/%d,%d mode: %s/%s "  \
                       "res: "LPU64"/"LPU64" rrc: %d type: %s ["LPU64"->"LPU64\
                       "] (req "LPU64"->"LPU64") flags: %x remote: "LPX64     \
                       " expref: %d pid: %u\n" , ## a,                        \
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
                       lock->l_req_extent.start, lock->l_req_extent.end,      \
                       lock->l_flags, lock->l_remote_handle.cookie,           \
                       lock->l_export ?                                       \
                       atomic_read(&lock->l_export->exp_refcount) : -99,      \
                       lock->l_pid);                                          \
                break;                                                        \
        }                                                                     \
        if (lock->l_resource->lr_type == LDLM_FLOCK) {                        \
                CDEBUG(level, "### " format                                   \
                       " ns: %s lock: %p/"LPX64" lrc: %d/%d,%d mode: %s/%s "  \
                       "res: "LPU64"/"LPU64" rrc: %d type: %s pid: %d "       \
                       "["LPU64"->"LPU64"] flags: %x remote: "LPX64           \
                       " expref: %d pid: %u\n" , ## a,                        \
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
                       atomic_read(&lock->l_export->exp_refcount) : -99,      \
                       lock->l_pid);                                          \
                break;                                                        \
        }                                                                     \
        if (lock->l_resource->lr_type == LDLM_IBITS) {                        \
                CDEBUG(level, "### " format                                   \
                       " ns: %s lock: %p/"LPX64" lrc: %d/%d,%d mode: %s/%s "  \
                       "res: "LPU64"/"LPU64" bits "LPX64" rrc: %d type: %s "  \
                       "flags: %x remote: "LPX64" expref: %d "                \
                       "pid %u\n" , ## a,                                     \
                       lock->l_resource->lr_namespace->ns_name,               \
                       lock, lock->l_handle.h_cookie,                         \
                       atomic_read (&lock->l_refc),                           \
                       lock->l_readers, lock->l_writers,                      \
                       ldlm_lockname[lock->l_granted_mode],                   \
                       ldlm_lockname[lock->l_req_mode],                       \
                       lock->l_resource->lr_name.name[0],                     \
                       lock->l_resource->lr_name.name[1],                     \
                       lock->l_policy_data.l_inodebits.bits,                  \
                       atomic_read(&lock->l_resource->lr_refcount),           \
                       ldlm_typename[lock->l_resource->lr_type],              \
                       lock->l_flags, lock->l_remote_handle.cookie,           \
                       lock->l_export ?                                       \
                       atomic_read(&lock->l_export->exp_refcount) : -99,      \
                       lock->l_pid);                                          \
                break;                                                        \
        }                                                                     \
        {                                                                     \
                CDEBUG(level, "### " format                                   \
                       " ns: %s lock: %p/"LPX64" lrc: %d/%d,%d mode: %s/%s "  \
                       "res: "LPU64"/"LPU64" rrc: %d type: %s flags: %x "     \
                       "remote: "LPX64" expref: %d pid: %u\n" , ## a,         \
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
                       atomic_read(&lock->l_export->exp_refcount) : -99,      \
                       lock->l_pid);                                          \
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
                    ldlm_type_t type, ldlm_policy_data_t *, ldlm_mode_t mode,
                    struct lustre_handle *);
struct ldlm_resource *ldlm_lock_convert(struct ldlm_lock *lock, int new_mode,
                                        int *flags);
void ldlm_lock_cancel(struct ldlm_lock *lock);
void ldlm_cancel_locks_for_export(struct obd_export *export);
void ldlm_reprocess_all(struct ldlm_resource *res);
void ldlm_reprocess_all_ns(struct ldlm_namespace *ns);
void ldlm_lock_dump(int level, struct ldlm_lock *lock, int pos);
void ldlm_lock_dump_handle(int level, struct lustre_handle *);

/* resource.c */
struct ldlm_namespace *ldlm_namespace_new(char *name, __u32 local);
int ldlm_namespace_cleanup(struct ldlm_namespace *ns, int flags);
int ldlm_namespace_free(struct ldlm_namespace *ns, int force);
int ldlm_proc_setup(void);
#ifdef LPROCFS
void ldlm_proc_cleanup(void);
#else
static inline void ldlm_proc_cleanup(void) {}
#endif

/* resource.c - internal */
struct ldlm_resource *ldlm_resource_get(struct ldlm_namespace *ns,
                                        struct ldlm_resource *parent,
                                        struct ldlm_res_id, ldlm_type_t type,
                                        int create);
struct ldlm_resource *ldlm_resource_getref(struct ldlm_resource *res);
int ldlm_resource_putref(struct ldlm_resource *res);
void ldlm_resource_add_lock(struct ldlm_resource *res, struct list_head *head,
                            struct ldlm_lock *lock);
void ldlm_resource_unlink_lock(struct ldlm_lock *lock);
void ldlm_res2desc(struct ldlm_resource *res, struct ldlm_resource_desc *desc);
void ldlm_dump_all_namespaces(int level);
void ldlm_namespace_dump(int level, struct ldlm_namespace *);
void ldlm_resource_dump(int level, struct ldlm_resource *);
int ldlm_lock_change_resource(struct ldlm_namespace *, struct ldlm_lock *,
                              struct ldlm_res_id);

struct ldlm_callback_suite {
        ldlm_completion_callback lcs_completion;
        ldlm_blocking_callback   lcs_blocking;
        ldlm_glimpse_callback    lcs_glimpse;
};

/* ldlm_request.c */
int ldlm_expired_completion_wait(void *data);
int ldlm_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                      void *data, int flag);
int ldlm_glimpse_ast(struct ldlm_lock *lock, void *reqp);
int ldlm_completion_ast(struct ldlm_lock *lock, int flags, void *data);
int ldlm_cli_enqueue(struct obd_export *exp,
                     struct ptlrpc_request *req,
                     struct ldlm_namespace *ns,
                     struct ldlm_res_id,
                     ldlm_type_t type,
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
int ldlm_handle_enqueue0(struct ldlm_namespace *ns, struct ptlrpc_request *req,
                         const struct ldlm_request *dlm_req,
                         const struct ldlm_callback_suite *cbs);
int ldlm_server_ast(struct lustre_handle *lockh, struct ldlm_lock_desc *new,
                    void *data, __u32 data_len);
int ldlm_cli_convert(struct lustre_handle *, int new_mode, int *flags);
int ldlm_handle_convert0(struct ptlrpc_request *req,
                         const struct ldlm_request *dlm_req);
int ldlm_cli_cancel(struct lustre_handle *lockh);
int ldlm_cli_cancel_unused(struct ldlm_namespace *, struct ldlm_res_id *,
                           int flags, void *opaque);
int ldlm_cli_join_lru(struct ldlm_namespace *, struct ldlm_res_id *,
                      int join);

/* mds/handler.c */
/* This has to be here because recursive inclusion sucks. */
int intent_disposition(struct ldlm_reply *rep, int flag);
void intent_set_disposition(struct ldlm_reply *rep, int flag);


/* ioctls for trying requests */
#define IOC_LDLM_TYPE                   'f'
#define IOC_LDLM_MIN_NR                 40

#define IOC_LDLM_TEST                   _IOWR('f', 40, long)
#define IOC_LDLM_DUMP                   _IOWR('f', 41, long)
#define IOC_LDLM_REGRESS_START          _IOWR('f', 42, long)
#define IOC_LDLM_REGRESS_STOP           _IOWR('f', 43, long)
#define IOC_LDLM_MAX_NR                 43

#endif
