/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _LUSTRE_DLM_H__
#define _LUSTRE_DLM_H__

#ifdef __KERNEL__

#include <linux/obd_class.h>
#include <linux/lustre_net.h>

#define OBD_LDLM_DEVICENAME  "ldlm"

typedef int cluster_host;
typedef int cluster_pid;

typedef enum {
        ELDLM_OK = 0,

        ELDLM_LOCK_CHANGED = 300,

        ELDLM_NAMESPACE_EXISTS = 400,
        ELDLM_BAD_NAMESPACE    = 401
} ldlm_error_t;

#define LDLM_FL_LOCK_CHANGED   (1 << 0)
#define LDLM_FL_BLOCK_GRANTED  (1 << 1)
#define LDLM_FL_BLOCK_CONV     (1 << 2)
#define LDLM_FL_BLOCK_WAIT     (1 << 3)

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
        struct list_head      ns_link;      /* in the list of ns's */
        __u32                 ns_id;        /* identifier of ns */
        struct list_head     *ns_hash;      /* hash table for ns */
        atomic_t              ns_refcount;  /* count of resources in the hash */
        struct list_head      ns_root_list; /* all root resources in ns */
        struct obd_device    *ns_obddev;
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

typedef int (*ldlm_lock_callback)(struct ldlm_lock *lock, struct ldlm_lock *new,
                                  void *data, __u32 data_len);

struct ldlm_lock {
        struct ldlm_resource *l_resource;
        struct ldlm_lock     *l_parent;
        struct list_head      l_children;
        struct list_head      l_childof;
        struct list_head      l_res_link; /*position in one of three res lists*/
        ldlm_mode_t           l_req_mode;
        ldlm_mode_t           l_granted_mode;
        ldlm_lock_callback    l_completion_ast;
        ldlm_lock_callback    l_blocking_ast;
        struct lustre_peer    l_peer;
        void                 *l_data;
        __u32                 l_data_len;
        struct ldlm_extent    l_extent;
        struct ldlm_handle    l_remote_handle;
        //void                 *l_event;
        //XXX cluster_host    l_holder;
        __u32                 l_version[RES_VERSION_SIZE];
};

typedef int (*ldlm_res_compat)(struct ldlm_lock *child, struct ldlm_lock *new);
typedef int (*ldlm_res_policy)(struct ldlm_resource *parent,
                               struct ldlm_extent *req_ex,
                               struct ldlm_extent *new_ex,
                               ldlm_mode_t mode, void *data);

#define LDLM_PLAIN       0x0
#define LDLM_EXTENT      0x1
#define LDLM_MDSINTENT   0x2

#define LDLM_MAX_TYPE    0x2
extern ldlm_res_compat ldlm_res_compat_table []; 
extern ldlm_res_policy ldlm_res_policy_table []; 

struct ldlm_resource {
        struct ldlm_namespace *lr_namespace;
        struct list_head       lr_hash;
        struct list_head       lr_rootlink; /* link all root resources in NS */
        struct ldlm_resource  *lr_parent;   /* 0 for a root resource */
        struct list_head       lr_children; /* list head for child resources */
        struct list_head       lr_childof;  /* part of child list of parent */

        struct list_head       lr_granted;
        struct list_head       lr_converting;
        struct list_head       lr_waiting;
        ldlm_mode_t            lr_most_restr;
        atomic_t               lr_refcount;
        __u32                  lr_type; /* PLAIN, EXTENT, or MDSINTENT */
        struct ldlm_resource  *lr_root;
        //XXX cluster_host          lr_master;
        __u64                  lr_name[RES_NAME_SIZE];
        __u32                  lr_version[RES_VERSION_SIZE];
        spinlock_t             lr_lock;
};

static inline struct ldlm_extent *ldlm_res2extent(struct ldlm_resource *res)
{
        return (struct ldlm_extent *)(res->lr_name);
}

static inline void *ldlm_handle2object(struct ldlm_handle *handle)
{
        if (handle) 
                return (void *)(unsigned long)(handle->addr);
        return NULL; 
}

static inline void ldlm_object2handle(void *object, struct ldlm_handle *handle)
{
        handle->addr = (__u64)(unsigned long)object;
}

static inline void ldlm_lock(struct obd_device *obddev)
{
        spin_lock(&obddev->u.ldlm.ldlm_lock);
}

static inline void ldlm_unlock(struct obd_device *obddev)
{
        spin_unlock(&obddev->u.ldlm.ldlm_lock);
}

extern struct obd_ops ldlm_obd_ops;

/* ldlm_extent.c */
int ldlm_extent_compat(struct ldlm_lock *, struct ldlm_lock *);
int ldlm_extent_policy(struct ldlm_resource *, struct ldlm_extent *,
                       struct ldlm_extent *, ldlm_mode_t, void *);

/* ldlm_lock.c */
void ldlm_lock_free(struct ldlm_lock *lock);
void ldlm_lock2desc(struct ldlm_lock *lock, struct ldlm_lock_desc *desc);
ldlm_error_t ldlm_local_lock_enqueue(struct obd_device *obddev,
                                     __u32 ns_id,
                                     struct ldlm_handle *parent_lock_handle,
                                     __u64 *res_id,
                                     __u32 type,
                                     struct ldlm_extent *req_ex,
                                     ldlm_mode_t mode,
                                     int *flags,
                                     ldlm_lock_callback completion,
                                     ldlm_lock_callback blocking,
                                     void *data,
                                     __u32 data_len,
                                     struct ldlm_handle *lockh);
ldlm_error_t ldlm_local_lock_convert(struct obd_device *obddev,
                                     struct ldlm_handle *lockh,
                                     int new_mode, int *flags);
ldlm_error_t ldlm_local_lock_cancel(struct obd_device *obddev,
                                    struct ldlm_handle *lockh);
void ldlm_lock_dump(struct ldlm_lock *lock);

/* ldlm_test.c */
int ldlm_test(struct obd_device *device);

/* resource.c */
struct ldlm_namespace *ldlm_namespace_find(struct obd_device *, __u32 id);
ldlm_error_t ldlm_namespace_new(struct obd_device *, __u32 id,
                                struct ldlm_namespace **);
int ldlm_namespace_free(struct ldlm_namespace *ns);
struct ldlm_resource *ldlm_resource_get(struct ldlm_namespace *ns,
                                        struct ldlm_resource *parent,
                                        __u64 *name, __u32 type, int create);
int ldlm_resource_put(struct ldlm_resource *res);
void ldlm_resource_add_lock(struct ldlm_resource *res, struct list_head *head,
                            struct ldlm_lock *lock);
void ldlm_resource_del_lock(struct ldlm_lock *lock);
void ldlm_res2desc(struct ldlm_resource *res, struct ldlm_resource_desc *desc);
void ldlm_resource_dump(struct ldlm_resource *res);

/* ldlm_request.c */
int ldlm_cli_namespace_new(struct ptlrpc_client *, struct lustre_peer *,
                           __u32 ns_id, struct ptlrpc_request **);
int ldlm_cli_enqueue(struct ptlrpc_client *cl, struct lustre_peer *peer,
                     __u32 ns_id,
                     struct ldlm_handle *parent_lock_handle,
                     __u64 *res_id,
                     __u32 type,
                     struct ldlm_extent *req_ex,
                     ldlm_mode_t mode,
                     int *flags,
                     void *data,
                     __u32 data_len,
                     struct ldlm_handle *lockh,
                     struct ptlrpc_request **request);
int ldlm_cli_callback(struct ldlm_lock *lock, struct ldlm_lock *new,
                      void *data, __u32 data_len);


#endif /* __KERNEL__ */

/* ioctls for trying requests */
#define IOC_LDLM_TYPE                   'f'
#define IOC_LDLM_MIN_NR                 40

#define IOC_LDLM_TEST                   _IOWR('f', 40, long)
#define IOC_LDLM_MAX_NR                 41

#endif
