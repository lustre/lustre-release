/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef __PORTALS_LINUX_LIB_TYPES_H__
#define __PORTALS_LINUX_LIB_TYPES_H__

#ifndef __PORTALS_LIB_TYPES_H__
#error Do not #include this file directly. #include <portals/lib-types.h> instead
#endif

#ifdef __KERNEL__
# include <linux/uio.h>
# include <linux/smp_lock.h>
# include <linux/types.h>
#else
# define PTL_USE_LIB_FREELIST
# include <sys/types.h>
#endif

#endif
