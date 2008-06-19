/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef __LIBCFS_DARWIN_KP30__
#define __LIBCFS_DARWIN_KP30__

#ifndef __LIBCFS_KP30_H__
#error Do not #include this file directly. #include <libcfs/kp30.h> instead
#endif

#ifdef __KERNEL__

#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <mach/mach_types.h>
#include <string.h>
#include <sys/file.h>
#include <sys/conf.h>
#include <miscfs/devfs/devfs.h>
#include <stdarg.h>

#include <libcfs/darwin/darwin-lock.h>
#include <libcfs/darwin/darwin-prim.h>
#include <lnet/lnet.h>

#define our_cond_resched() cfs_schedule_timeout(CFS_TASK_INTERRUPTIBLE, 1)

#ifdef CONFIG_SMP
#define LASSERT_SPIN_LOCKED(lock) do {} while(0) /* XXX */
#else
#define LASSERT_SPIN_LOCKED(lock) do {} while(0)
#endif
#define LASSERT_SEM_LOCKED(sem) do {} while(0) /* XXX */

#define LIBCFS_PANIC(msg) panic(msg)
#error libcfs_register_panic_notifier() missing
#error libcfs_unregister_panic_notifier() missing

/* --------------------------------------------------------------------- */

#define PORTAL_SYMBOL_REGISTER(x)               cfs_symbol_register(#x, &x)
#define PORTAL_SYMBOL_UNREGISTER(x)             cfs_symbol_unregister(#x)

#define PORTAL_SYMBOL_GET(x)                    ((typeof(&x))cfs_symbol_get(#x))
#define PORTAL_SYMBOL_PUT(x)                    cfs_symbol_put(#x)

#define PORTAL_MODULE_USE                       do{int i = 0; i++;}while(0)
#define PORTAL_MODULE_UNUSE                     do{int i = 0; i--;}while(0)

#define num_online_cpus()                       cfs_online_cpus()

/******************************************************************************/
/* XXX Liang: There is no module parameter supporting in OSX */
#define CFS_MODULE_PARM(name, t, type, perm, desc)

#define CFS_SYSFS_MODULE_PARM    0 /* no sysfs access to module parameters */
/******************************************************************************/

#else  /* !__KERNEL__ */
# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <unistd.h>
# include <time.h>
# include <machine/limits.h>
# include <sys/types.h>
#endif

#define BITS_PER_LONG   LONG_BIT
/******************************************************************************/
/* Light-weight trace
 * Support for temporary event tracing with minimal Heisenberg effect. */
#define LWT_SUPPORT  0

typedef struct {
        long long   lwte_when;
        char       *lwte_where;
        void       *lwte_task;
        long        lwte_p1;
        long        lwte_p2;
        long        lwte_p3;
        long        lwte_p4;
} lwt_event_t;

# define LWT_EVENT(p1,p2,p3,p4)     /* no lwt implementation yet */

/* -------------------------------------------------------------------------- */

#define IOCTL_LIBCFS_TYPE struct libcfs_ioctl_data

#define LPU64 "%llu"
#define LPD64 "%lld"
#define LPX64 "%#llx"
#define LPSZ  "%lu"
#define LPSSZ "%ld"
# define LI_POISON ((int)0x5a5a5a5a)
# define LL_POISON ((long)0x5a5a5a5a)
# define LP_POISON ((void *)(long)0x5a5a5a5a)

#endif
