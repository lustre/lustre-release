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
#include <portals/p30.h>

#define our_cond_resched()              schedule_timeout(1);

#ifdef CONFIG_SMP
#define LASSERT_SPIN_LOCKED(lock) do {} while(0) /* XXX */
#else
#define LASSERT_SPIN_LOCKED(lock) do {} while(0)
#endif

#define LBUG_WITH_LOC(file, func, line)         portals_catastrophe = 1

/* --------------------------------------------------------------------- */

#define PORTAL_SYMBOL_REGISTER(x)               cfs_symbol_register(#x, &x)
#define PORTAL_SYMBOL_UNREGISTER(x)             cfs_symbol_unregister(#x)

#define PORTAL_SYMBOL_GET(x)                    ((typeof(&x))cfs_symbol_get(#x))
#define PORTAL_SYMBOL_PUT(x)                    cfs_symbol_put(#x)

#define PORTAL_MODULE_USE                       do{int i = 0; i++;}while(0)
#define PORTAL_MODULE_UNUSE                     do{int i = 0; i--;}while(0)

#define printk(format, args...)                 printf(format, ## args)

#else  /* !__KERNEL__ */
# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <unistd.h>
# include <time.h>
# include <machine/limits.h>
# include <sys/types.h>
#endif

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

#define IOCTL_PORTAL_TYPE struct portal_ioctl_data

#define LPU64 "%llu"
#define LPD64 "%lld"
#define LPX64 "%llx"
#define LPSZ  "%lu"
#define LPSSZ "%ld"
# define LI_POISON ((int)0x5a5a5a5a)
# define LL_POISON ((long)0x5a5a5a5a)
# define LP_POISON ((void *)(long)0x5a5a5a5a)

#endif
