/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _LUSTRE_DLM_H__
#define _LUSTRE_DLM_H__

#include <linux/kp30.h>
#include <linux/list.h>

#define OBD_LDLM_DEVICENAME  "ldlm"

typedef  int cluster_host;
typedef  int cluster_pid;

/* lock types */
typedef enum  { 
        LCK_EX,
       LCK_PW,
       LCK_PR,
       LCK_CW,
       LCK_CR,
       LCK_NL
} ldlm_mode_t;

#define L2B(c) (1<<c)

/* compatibility matrix */
#define LCK_COMPAT_EX  L2B(LCK_NL)
#define LCK_COMPAT_PW  (LCK_COMPAT_EX | L2B(LCK_CR))
#define LCK_COMPAT_PR  (LCK_COMPAT_PW | L2B(LCK_PR))
#define LCK_COMPAT_CW  (LCK_COMPAT_PW | L2B(LCK_CW))
#define LCK_COMPAT_CR  (LCK_COMPAT_CW | L2B(LCK_PR) | L2B(LCK_PW))
#define LCK_COMPAT_NL  (LCK_COMPAT_CR | L2B(LCK_EX))

static ldlm_mode_t lck_compat_array[] = {
       LCK_COMPAT_EX,
       LCK_COMPAT_PW,
       LCK_COMPAT_PR,
       LCK_COMPAT_CW,
       LCK_COMPAT_CR,
       LCK_COMPAT_NL
};

static inline int lockmode_compat(ldlm_mode_t a, ldlm_mode_t b)
{
       if ( 0 <= a && a <= 5 ) { 
              BUG();
       }
       if( 0 <= b && b <= 5 ) { 
              BUG();
       }
    
       return 1 && (lck_compat_array[a] & L2B(b));
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
};

/* 
 * 
 * Resource hash table 
 *
 */

#define RES_HASH_BITS 18
#define RES_HASH_SIZE (1UL << RES_HASH_BITS)
#define RES_HASH_MASK (RES_HASH_SIZE - 1)

#define RES_NAME_SIZE 6
#define RES_VERSION_SIZE 4

struct ldlm_resource {
       struct list_head      lr_hash;
       struct list_head      lr_rootlink; /* link all root resources in NS */
       struct ldlm_resource *lr_parent;   /* 0 for a root resource */
       struct list_head      lr_children; /* list head for child resources */
       struct list_head      lr_childof;  /* part of child list of parent */

       struct list_head      lr_granted;
       struct list_head      lr_converting;
       struct list_head      lr_waiting;
       ldlm_mode_t           lr_most_restr;
       struct ldlm_resource *lr_root;
       //XXX cluster_host          lr_master;
       __u32                 lr_name[RES_NAME_SIZE];
       __u32                 lr_version[RES_VERSION_SIZE];
};

struct ldlm_lock {
       struct ldlm_resource *lb_resource;
       struct ldlm_lock     *lb_parent;
       struct list_head      lb_children;
       struct list_head      lb_childof;
       unsigned long         lb_id;
       ldlm_mode_t           lb_req_mode;
       ldlm_mode_t           lb_granted_mode;
       void                 *lb_completion_ast;
       void                 *lb_blocking_ast;
       void                 *lb_event;
       //XXX cluster_host    lb_holder;
       __u32                 lb_version[RES_VERSION_SIZE];
};

struct ldlm_obd {
        struct list_head ldlm_namespaces;
};

extern struct obd_ops ldlm_obd_ops;

#endif
