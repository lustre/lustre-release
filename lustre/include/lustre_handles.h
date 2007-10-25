#ifndef __LUSTRE_HANDLES_H_
#define __LUSTRE_HANDLES_H_

#if defined(__linux__)
#include <linux/lustre_handles.h>
#elif defined(__APPLE__)
#include <darwin/lustre_handles.h>
#elif defined(__WINNT__)
#include <winnt/lustre_handles.h>
#else
#error Unsupported operating system.
#endif

typedef void (*portals_handle_addref_cb)(void *object);

/* These handles are most easily used by having them appear at the very top of
 * whatever object that you want to make handles for.  ie:
 *
 * struct ldlm_lock {
 *         struct portals_handle handle;
 *         ...
 * };
 *
 * Now you're able to assign the results of cookie2handle directly to an
 * ldlm_lock.  If it's not at the top, you'll want to hack up a macro that
 * uses some offsetof() magic. */

struct portals_handle {
        struct list_head h_link;
        __u64 h_cookie;
        portals_handle_addref_cb h_addref;

        /* newly added fields to handle the RCU issue. -jxiong */
        spinlock_t h_lock;
        void *h_ptr;
        void (*h_free_cb)(void *, size_t);
        struct rcu_head h_rcu;
        unsigned int h_size;
        __u8 h_in:1;
        __u8 h_unused[3];
};
#define RCU2HANDLE(rcu)    container_of(rcu, struct portals_handle, h_rcu)

/* handles.c */

/* Add a handle to the hash table */
void class_handle_hash(struct portals_handle *, portals_handle_addref_cb);
void class_handle_unhash(struct portals_handle *);
void class_handle_hash_back(struct portals_handle *);
void *class_handle2object(__u64 cookie);
void class_handle_free_cb(struct rcu_head *);
int class_handle_init(void);
void class_handle_cleanup(void);

#endif
