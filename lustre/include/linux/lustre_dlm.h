/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _LUSTRE_DLM_H__
#define _LUSTRE_DLM_H__

#ifdef __KERNEL__

#include <linux/proc_fs.h>
#include <linux/obd_class.h>
#include <linux/lustre_net.h>

#define OBD_LDLM_DEVICENAME  "ldlm"

typedef enum {
        ELDLM_OK = 0,

        ELDLM_LOCK_CHANGED = 300,
        ELDLM_LOCK_ABORTED = 301,
        ELDLM_RESOURCE_FREED = 302,

        ELDLM_NAMESPACE_EXISTS = 400,
        ELDLM_BAD_NAMESPACE    = 401
} ldlm_error_t;

#define LDLM_NAMESPACE_SERVER 0
#define LDLM_NAMESPACE_CLIENT 1

#define LDLM_FL_LOCK_CHANGED   (1 << 0)
#define LDLM_FL_BLOCK_GRANTED  (1 << 1)
#define LDLM_FL_BLOCK_CONV     (1 << 2)
#define LDLM_FL_BLOCK_WAIT     (1 << 3)
#define LDLM_FL_CBPENDING      (1 << 4)
#define LDLM_FL_AST_SENT       (1 << 5)
#define LDLM_FL_DESTROYED      (1 << 6)
#define LDLM_FL_WAIT_NOREPROC  (1 << 7)

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
       if (exist < LCK_EX || exist > LCK_NL)
              LBUG();
       if (new < LCK_EX || new > LCK_NL)
              LBUG();

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

struct ldlm_namespace {
        char                  *ns_name;
        struct ptlrpc_client   ns_rpc_client;/* used for revocation callbacks */
        __u32                  ns_client; /* is this a client-side lock tree? */
        struct list_head      *ns_hash; /* hash table for ns */
        __u32                  ns_refcount; /* count of resources in the hash */
        struct list_head       ns_root_list; /* all root resources in ns */
        struct lustre_lock     ns_lock; /* protects hash, refcount, list */
        struct list_head       ns_list_chain; /* position in global NS list */
        struct proc_dir_entry *ns_proc_dir;
};

/* 
 * 
 * Resource hash table 
 *
 */

#define RES_HASH_BITS 14
#define RES_HASH_SIZE (1UL << RES_HASH_BITS)
#define RES_HASH_MASK (RES_HASH_SIZE - 1)

struct ldlm_lock;

typedef int (*ldlm_blocking_callback)(struct ldlm_lock *lock,
                                      struct ldlm_lock_desc *new, void *data,
                                      __u32 data_len);

typedef int (*ldlm_completion_callback)(struct ldlm_lock *lock, int flags); 

struct ldlm_lock {
        __u64                  l_random;
        int                   l_refc;
        struct ldlm_resource *l_resource;
        struct ldlm_lock     *l_parent;
        struct list_head      l_children;
        struct list_head      l_childof;
        struct list_head      l_res_link; /*position in one of three res lists*/

        ldlm_mode_t           l_req_mode;
        ldlm_mode_t           l_granted_mode;

        ldlm_completion_callback    l_completion_ast;
        ldlm_blocking_callback    l_blocking_ast;

        struct ptlrpc_connection *l_connection;
        struct ptlrpc_client *l_client;
        struct lustre_handle *l_connh;
        __u32                 l_flags;
        struct lustre_handle    l_remote_handle;
        void                 *l_data;
        __u32                 l_data_len;
        void                 *l_cookie;
        int                   l_cookie_len;
        struct ldlm_extent    l_extent;
        __u32                 l_version[RES_VERSION_SIZE];

        __u32                 l_readers;
        __u32                 l_writers;

        /* If the lock is granted, a process sleeps on this waitq to learn when
         * it's no longer in use.  If the lock is not granted, a process sleeps
         * on this waitq to learn when it becomes granted. */
        wait_queue_head_t     l_waitq;
};

typedef int (*ldlm_res_compat)(struct ldlm_lock *child, struct ldlm_lock *new);
typedef int (*ldlm_res_policy)(struct ldlm_lock *lock, void *req_cookie,
                               ldlm_mode_t mode, void *data);

#define LDLM_PLAIN       10
#define LDLM_EXTENT      11
#define LDLM_MDSINTENT   12

#define LDLM_MIN_TYPE 10
#define LDLM_MAX_TYPE 12

extern ldlm_res_compat ldlm_res_compat_table []; 
extern ldlm_res_policy ldlm_res_policy_table []; 

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
        __u32                  lr_type; /* PLAIN, EXTENT, or MDSINTENT */
        struct ldlm_resource  *lr_root;
        __u64                  lr_name[RES_NAME_SIZE];
        __u32                  lr_version[RES_VERSION_SIZE];
        atomic_t               lr_refcount;
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
        
static inline struct ldlm_extent *ldlm_res2extent(struct ldlm_resource *res)
{
        return (struct ldlm_extent *)(res->lr_name);
}

extern struct obd_ops ldlm_obd_ops;


extern char *ldlm_lockname[];
extern char *ldlm_typename[];
extern char *ldlm_it2str(int it);

#define LDLM_DEBUG(lock, format, a...)                                  \
do {                                                                    \
        if (lock->l_resource == NULL)                                   \
                CDEBUG(D_DLMTRACE, "### " format                        \
                       " (UNKNOWN: lock %p(rc=%d/%d,%d) mode %s/%s on " \
                       "res \?\? (rc=\?\?) type \?\?\? remote %Lx)\n" , \
                       ## a, lock, lock->l_refc, lock->l_readers,       \
                       lock->l_writers,                                 \
                       ldlm_lockname[lock->l_granted_mode],             \
                       ldlm_lockname[lock->l_req_mode],                 \
                       lock->l_remote_handle.addr);                     \
        else                                                            \
                CDEBUG(D_DLMTRACE, "### " format                        \
                       " (%s: lock %p(rc=%d/%d,%d) mode %s/%s on res "  \
                       "%Lu (rc=%d) type %s remote %Lx)\n" , ## a,      \
                       lock->l_resource->lr_namespace->ns_name, lock,   \
                       lock->l_refc, lock->l_readers, lock->l_writers,  \
                       ldlm_lockname[lock->l_granted_mode],             \
                       ldlm_lockname[lock->l_req_mode],                 \
                       lock->l_resource->lr_name[0],                    \
                       atomic_read(&lock->l_resource->lr_refcount),     \
                       ldlm_typename[lock->l_resource->lr_type],        \
                       lock->l_remote_handle.addr);                     \
} while (0)

#define LDLM_DEBUG_NOLOCK(format, a...)                 \
        CDEBUG(D_DLMTRACE, "### " format "\n" , ## a)

/* ldlm_extent.c */
int ldlm_extent_compat(struct ldlm_lock *, struct ldlm_lock *);
int ldlm_extent_policy(struct ldlm_lock *, void *, ldlm_mode_t, void *);

/* ldlm_lockd.c */
int ldlm_handle_enqueue(struct ptlrpc_request *req);
int ldlm_handle_convert(struct ptlrpc_request *req);
int ldlm_handle_cancel(struct ptlrpc_request *req);

/* ldlm_lock.c */
void ldlm_register_intent(int (*arg)(struct ldlm_lock *lock, void *req_cookie,
                                     ldlm_mode_t mode, void *data));
void ldlm_unregister_intent(void);
void ldlm_lock2handle(struct ldlm_lock *lock, struct lustre_handle *lockh);
struct ldlm_lock *ldlm_handle2lock(struct lustre_handle *handle);
void ldlm_lock2handle(struct ldlm_lock *lock, struct lustre_handle *lockh);

#define LDLM_LOCK_PUT(lock)                     \
do {                                            \
        LDLM_DEBUG(lock, "put");                \
        ldlm_lock_put(lock);                    \
} while (0)

#define LDLM_LOCK_GET(lock)                     \
({                                              \
        ldlm_lock_get(lock);                    \
        LDLM_DEBUG(lock, "get");                \
        lock;                                   \
})

void ldlm_lock_put(struct ldlm_lock *lock);
void ldlm_lock_destroy(struct ldlm_lock *lock);
void ldlm_lock2desc(struct ldlm_lock *lock, struct ldlm_lock_desc *desc);
void ldlm_lock_addref(struct lustre_handle *lockh, __u32 mode);
void ldlm_lock_addref_internal(struct ldlm_lock* , __u32 mode);
void ldlm_lock_decref(struct lustre_handle *lockh, __u32 mode);
void ldlm_grant_lock(struct ldlm_lock *lock);
int ldlm_lock_match(struct ldlm_namespace *ns, __u64 *res_id, __u32 type,
                    void *cookie, int cookielen, ldlm_mode_t mode,
                    struct lustre_handle *lockh);
struct ldlm_lock *
ldlm_lock_create(struct ldlm_namespace *ns,
                 struct lustre_handle *parent_lock_handle,
                 __u64 *res_id, __u32 type, ldlm_mode_t mode, void *data,
                 __u32 data_len);
ldlm_error_t ldlm_lock_enqueue(struct ldlm_lock *lock, void *cookie,
                               int cookie_len, int *flags,
                               ldlm_completion_callback completion,
                               ldlm_blocking_callback blocking);
struct ldlm_resource *ldlm_lock_convert(struct ldlm_lock *lock, int new_mode,
                                        int *flags);
void ldlm_lock_cancel(struct ldlm_lock *lock);
void ldlm_run_ast_work(struct list_head *rpc_list);
void ldlm_reprocess_all(struct ldlm_resource *res);
void ldlm_lock_dump(struct ldlm_lock *lock);

/* ldlm_test.c */
int ldlm_test(struct obd_device *device, struct ptlrpc_connection *conn);

/* resource.c */
struct ldlm_namespace *ldlm_namespace_new(char *name, __u32 local);
int ldlm_namespace_free(struct ldlm_namespace *ns);
int ldlm_proc_setup(struct obd_device *obd);
void ldlm_proc_cleanup(struct obd_device *obd);

/* resource.c - internal */
struct ldlm_resource *ldlm_resource_get(struct ldlm_namespace *ns,
                                        struct ldlm_resource *parent,
                                        __u64 *name, __u32 type, int create);
struct ldlm_resource *ldlm_resource_getref(struct ldlm_resource *res);
int ldlm_resource_put(struct ldlm_resource *res);
void ldlm_resource_add_lock(struct ldlm_resource *res, struct list_head *head,
                            struct ldlm_lock *lock);
void ldlm_resource_unlink_lock(struct ldlm_lock *lock);
void ldlm_res2desc(struct ldlm_resource *res, struct ldlm_resource_desc *desc);
void ldlm_dump_all_namespaces(void);
void ldlm_namespace_dump(struct ldlm_namespace *);
void ldlm_resource_dump(struct ldlm_resource *);
int ldlm_lock_change_resource(struct ldlm_lock *, __u64 new_resid[3]);

/* ldlm_request.c */
int ldlm_completion_ast(struct ldlm_lock *lock, int flags);
int ldlm_cli_enqueue(struct lustre_handle *conn,
                     struct ptlrpc_request *req,
                     struct ldlm_namespace *ns,
                     struct lustre_handle *parent_lock_handle,
                     __u64 *res_id,
                     __u32 type,
                     void *cookie, int cookielen,
                     ldlm_mode_t mode,
                     int *flags,
                     ldlm_completion_callback completion,
                     ldlm_blocking_callback callback,
                     void *data,
                     __u32 data_len,
                     struct lustre_handle *lockh);
int ldlm_match_or_enqueue(struct lustre_handle *connh, 
                          struct ptlrpc_request *req,
                          struct ldlm_namespace *ns,
                          struct lustre_handle *parent_lock_handle,
                          __u64 *res_id,
                          __u32 type,
                          void *cookie, int cookielen,
                          ldlm_mode_t mode,
                          int *flags,
                          ldlm_completion_callback completion,
                          ldlm_blocking_callback callback,
                          void *data,
                          __u32 data_len,
                          struct lustre_handle *lockh);
int ldlm_server_ast(struct lustre_handle *lockh, struct ldlm_lock_desc *new,
                    void *data, __u32 data_len);
int ldlm_cli_convert(struct lustre_handle *, int new_mode, int *flags);
int ldlm_cli_cancel(struct lustre_handle *lockh);

/* mds/handler.c */
/* This has to be here because recurisve inclusion sucks. */
int mds_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                     void *data, __u32 data_len);

#endif /* __KERNEL__ */

/* ioctls for trying requests */
#define IOC_LDLM_TYPE                   'f'
#define IOC_LDLM_MIN_NR                 40

#define IOC_LDLM_TEST                   _IOWR('f', 40, long)
#define IOC_LDLM_DUMP                   _IOWR('f', 41, long)
#define IOC_LDLM_MAX_NR                 41

#endif
