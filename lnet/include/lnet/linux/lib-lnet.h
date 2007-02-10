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
# include <asm/io.h>
# include <libcfs/kp30.h>

static inline __u64
lnet_page2phys (struct page *p)
{
        /* compiler optimizer will elide unused branches */

        switch (sizeof(typeof(page_to_phys(p)))) {
        case 4:
                /* page_to_phys returns a 32 bit physical address.  This must
                 * be a 32 bit machine with <= 4G memory and we must ensure we
                 * don't sign extend when converting to 64 bits. */
                return (unsigned long)page_to_phys(p);

        case 8:
                /* page_to_phys returns a 64 bit physical address :) */
                return page_to_phys(p);
                
        default:
                LBUG();
                return 0;
        }
}

#else  /* __KERNEL__ */
# include <libcfs/list.h>
# include <string.h>
# ifdef HAVE_LIBPTHREAD
#  include <pthread.h>
# endif
#endif

#define LNET_ROUTER

#endif /* __LNET_LINUX_LIB_LNET_H__ */
