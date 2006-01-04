/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _LL_H
#define _LL_H

#if defined(__linux__)
#include <linux/lustre_lite.h>
#elif defined(__APPLE__)
#include <darwin/lustre_lite.h>
#elif defined(__WINNT__)
#include <winnt/lustre_lite.h>
#else
#error Unsupported operating system.
#endif

#include <obd_class.h>
#include <lustre_net.h>
#include <lustre_mds.h>
#include <lustre_ha.h>

#ifdef __KERNEL__

/* careful, this is easy to screw up */
#define PAGE_CACHE_MAXBYTES ((__u64)(~0UL) << CFS_PAGE_SHIFT)

#endif

#define LLAP_FROM_COOKIE(c)                                                    \
        (LASSERT(((struct ll_async_page *)(c))->llap_magic == LLAP_MAGIC),     \
         (struct ll_async_page *)(c))

#define LL_MAX_BLKSIZE          (4UL * 1024 * 1024)

#include <lustre/lustre_user.h>


struct lustre_rw_params {
        int                lrp_lock_mode;
        ldlm_policy_data_t lrp_policy;
        obd_flag           lrp_brw_flags;
        int                lrp_ast_flags;
};

/*
 * XXX nikita: this function lives in the header because it is used by both
 * llite kernel module and liblustre library, and there is no (?) better place
 * to put it in.
 */
static inline void lustre_build_lock_params(int cmd, unsigned long open_flags,
                                            __u64 connect_flags,
                                            loff_t pos, ssize_t len,
                                            struct lustre_rw_params *params)
{
        params->lrp_lock_mode = (cmd == OBD_BRW_READ) ? LCK_PR : LCK_PW;
        params->lrp_brw_flags = 0;

        params->lrp_policy.l_extent.start = pos;
        params->lrp_policy.l_extent.end = pos + len - 1;
        /*
         * for now O_APPEND always takes local locks.
         */
        if (cmd == OBD_BRW_WRITE && (open_flags & O_APPEND)) {
                params->lrp_policy.l_extent.start = 0;
                params->lrp_policy.l_extent.end   = OBD_OBJECT_EOF;
        } else if (LIBLUSTRE_CLIENT && (connect_flags & OBD_CONNECT_SRVLOCK)) {
                /*
                 * liblustre: OST-side locking for all non-O_APPEND
                 * reads/writes.
                 */
                params->lrp_lock_mode = LCK_NL;
                params->lrp_brw_flags = OBD_BRW_SRVLOCK;
        } else {
                /*
                 * nothing special for the kernel. In the future llite may use
                 * OST-side locks for small writes into highly contended
                 * files.
                 */
        }
        params->lrp_ast_flags = (open_flags & O_NONBLOCK) ?
                LDLM_FL_BLOCK_NOWAIT : 0;
}

#endif
