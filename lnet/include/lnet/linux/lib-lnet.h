/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef __LNET_LINUX_LIB_LNET_H__
#define __LNET_LINUX_LIB_LNET_H__

#ifndef __LNET_LIB_LNET_H__
#error Do not #include this file directly. #include <lnet/lib-lnet.h> instead
#endif

#ifdef __KERNEL__
# include <asm/page.h>
# include <linux/string.h>
#else
# include <libcfs/list.h>
# include <string.h>
#ifdef HAVE_LIBPTHREAD
# include <pthread.h>
#endif
#endif

#endif
