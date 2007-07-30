#ifndef __LINUX_LUSTRE_HANDLES_H_
#define __LINUX_LUSTRE_HANDLES_H_

#ifndef __LUSTRE_HANDLES_H_
#error Do not #include this file directly. #include <lustre_handles.h> instead
#endif

#ifdef __KERNEL__
#include <asm/types.h>
#include <asm/atomic.h>
#include <linux/list.h>
#include <linux/random.h>
#include <linux/version.h>
#include <linux/spinlock.h>
#include <linux/types.h>

# ifdef HAVE_RCU
#  include <linux/rcupdate.h> /* for rcu_head{} */
# else
struct rcu_head { };
# endif

#endif /* ifdef __KERNEL__ */

#endif
