#ifndef __LINUX_HANDLES_H_
#define __LINUX_HANDLES_H_

#ifdef __KERNEL__
#include <asm/types.h>
#include <asm/atomic.h>
#include <linux/list.h>
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
};

/* handles.c */

/* Add a handle to the hash table */
void portals_handle_hash(struct portals_handle *, portals_handle_addref_cb);
void portals_handle_unhash(struct portals_handle *);
void *portals_handle2object(__u64 cookie);
int portals_handle_init(void);
void portals_handle_cleanup(void);

#endif
