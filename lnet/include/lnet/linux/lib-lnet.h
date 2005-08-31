/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef __PORTALS_LINUX_LIB_P30_H__
#define __PORTALS_LINUX_LIB_P30_H__

#ifndef __PORTALS_LIB_P30_H__
#error Do not #include this file directly. #include <lnet/lib-p30.h> instead
#endif

#ifdef __KERNEL__
# include <asm/page.h>
# include <linux/string.h>
#else
# include <libcfs/list.h>
# include <string.h>
# include <pthread.h>
#endif

#endif
