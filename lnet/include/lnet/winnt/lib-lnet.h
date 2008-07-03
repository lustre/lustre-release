/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef __LNET_WINNT_LIB_LNET_H__
#define __LNET_WINNT_LIB_LNET_H__

#ifndef __LNET_LIB_LNET_H__
#error Do not #include this file directly. #include <lnet/lib-lnet.h> instead
#endif

#ifdef __KERNEL__
# include <libcfs/libcfs.h>

static inline __u64
lnet_page2phys (struct page *p)
{
    return 0;
}

#else  /* __KERNEL__ */

#endif

#endif /* __LNET_WINNT_LIB_LNET_H__ */
