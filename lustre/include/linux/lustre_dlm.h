/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _LUSTRE_DLM_H__
#define _LUSTRE_DLM_H__

#include <linux/kp30.h>
#include <linux/list.h>

#include <linux/obd_class.h>

#ifdef __KERNEL__

#define OBD_LDLM_DEVICENAME  "ldlm"

typedef  int cluster_host;
typedef  int cluster_pid;

typedef enum {
        ELDLM_OK = 0,
        ELDLM_BLOCK_GRANTED,
        ELDLM_BLOCK_CONV,
        ELDLM_BLOCK_WAIT
} ldlm_error_t;

/* lock types */
typedef enum {
        LCK_EX = 1,
        LCK_PW,
        LCK_PR,
        LCK_CW,
        LCK_CR,
        LCK_NL
} ldlm_mode_t;

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
              BUG();
       if (new < LCK_EX || new > LCK_NL)
              BUG();

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

#define RES_NAME_SIZE 6
#define RES_VERSION_SIZE 4

struct ldlm_lock {
        struct ldlm_resource *l_resource;
        struct ldlm_lock     *l_parent;
        struct list_head      l_children;
        struct list_head      l_childof;
        struct list_head      l_res_link; /*position in one of three res lists*/
        ldlm_mode_t           l_req_mode;
        ldlm_mode_t           l_granted_mode;
        void                 *l_completion_ast;
        void                 *l_blocking_ast;
        void                 *l_event;
        //XXX cluster_host    l_holder;
        __u32                 l_version[RES_VERSION_SIZE];
};

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
        struct ldlm_resource  *lr_root;
        //XXX cluster_host          lr_master;
        __u32                  lr_name[RES_NAME_SIZE];
        __u32                  lr_version[RES_VERSION_SIZE];
        spinlock_t             lr_lock;

        void (*lr_blocking)(struct ldlm_lock *lock, struct ldlm_lock *new);
};

struct ldlm_handle {
        __u64 addr;
        __u64 cookie;
};

static inline void ldlm_lock(struct obd_device *obddev)
{
        spin_lock(&obddev->u.ldlm.ldlm_lock);
}

static inline void ldlm_unlock(struct obd_device *obddev)
{
        spin_unlock(&obddev->u.ldlm.ldlm_lock);
}

extern struct obd_ops ldlm_obd_ops;

/* ldlm_lock.c */
ldlm_error_t ldlm_local_lock_enqueue(struct obd_device *obbdev, __u32 ns_id,
                                     struct ldlm_resource *parent_res,
                                     struct ldlm_lock *parent_lock,
                                     __u32 *res_id, ldlm_mode_t mode, 
                                     struct ldlm_handle *);
void ldlm_lock_dump(struct ldlm_lock *lock);

/* ldlm_test.c */
int ldlm_test(struct obd_device *device);

/* resource.c */
struct ldlm_namespace *ldlm_namespace_find(struct obd_device *obddev, __u32 id);
struct ldlm_namespace *ldlm_namespace_new(struct obd_device *obddev, __u32 id);
void ldlm_resource_dump(struct ldlm_resource *res);
struct ldlm_resource *ldlm_resource_get(struct ldlm_namespace *ns,
                                        struct ldlm_resource *parent,
                                        __u32 *name, int create);
int ldlm_resource_put(struct ldlm_resource *res);

#endif /* __KERNEL__ */

/* ioctls for trying requests */
#define IOC_LDLM_TYPE                   'f'
#define IOC_LDLM_MIN_NR                 40

#define IOC_LDLM_TEST                   _IOWR('f', 40, long)
#define IOC_LDLM_MAX_NR                 41

#endif
