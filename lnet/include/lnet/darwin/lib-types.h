/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef __LNET_DARWIN_LIB_TYPES_H__
#define __LNET_DARWIN_LIB_TYPES_H__

#ifndef __LNET_LIB_TYPES_H__
#error Do not #include this file directly. #include <lnet/lib-types.h> instead
#endif

#include <sys/types.h>
#include <libcfs/libcfs.h>
#include <libcfs/list.h>

/*
 * XXX Liang:
 *
 * Temporary fix, because lnet_me_free()->cfs_free->FREE() can be blocked in xnu,
 * at then same time we've taken LNET_LOCK(), which is a spinlock.
 * by using LNET_USE_LIB_FREELIST, we can avoid calling of FREE().
 *
 * A better solution is moving lnet_me_free() out from LNET_LOCK, it's not hard
 * but need to be very careful and take some time.
 */
#define LNET_USE_LIB_FREELIST

#endif
