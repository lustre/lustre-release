#ifndef __LIBCFS_LINUX_PORTALS_UTILS_H__
#define __LIBCFS_LINUX_PORTALS_UTILS_H__

#ifndef __LIBCFS_PORTALS_UTILS_H__
#error Do not #include this file directly. #include <libcfs/portals_utils.h> instead
#endif

#ifdef __KERNEL__
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/smp_lock.h>
#include <linux/poll.h>
#include <linux/random.h>

#include <asm/unistd.h>
#include <asm/semaphore.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
# include <linux/tqueue.h>
#else /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)) */
# include <linux/workqueue.h>
#endif
#include <libcfs/linux/linux-mem.h>
#include <libcfs/linux/linux-prim.h>
#else /* !__KERNEL__ */

#include <endian.h>
#include <libcfs/list.h>

#ifdef HAVE_LINUX_VERSION_H
# include <linux/version.h>

# if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#  define BUG()                            /* workaround for module.h includes */
#  include <linux/module.h>
# endif
#endif /* !HAVE_LINUX_VERSION_H */

#ifndef __CYGWIN__
# include <syscall.h>
#else /* __CYGWIN__ */
# include <windows.h>
# include <windef.h>
# include <netinet/in.h>
#endif /* __CYGWIN__ */

#endif /* !__KERNEL__ */
#endif
