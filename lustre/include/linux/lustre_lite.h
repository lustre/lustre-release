/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:


#ifndef _LL_H
#define _LL_H

#ifdef __KERNEL__

#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <asm/statfs.h>
#endif

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
#include <linux/proc_fs.h>

#include <linux/obd_class.h>
#include <linux/lustre_net.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_ha.h>

#include <linux/rbtree.h>
#include <linux/lustre_compat25.h>
#include <linux/pagemap.h>

/* careful, this is easy to screw up */
#define PAGE_CACHE_MAXBYTES ((__u64)(~0UL) << PAGE_CACHE_SHIFT)

/* lprocfs.c */
enum {
         LPROC_LL_DIRTY_HITS = 0,
         LPROC_LL_DIRTY_MISSES,
         LPROC_LL_WB_WRITEPAGE,
         LPROC_LL_WB_PRESSURE,
         LPROC_LL_WB_OK,
         LPROC_LL_WB_FAIL,
         LPROC_LL_READ_BYTES,
         LPROC_LL_WRITE_BYTES,
         LPROC_LL_BRW_READ,
         LPROC_LL_BRW_WRITE,
         LPROC_LL_IOCTL,
         LPROC_LL_OPEN,
         LPROC_LL_RELEASE,
         LPROC_LL_MAP,
         LPROC_LL_LLSEEK,
         LPROC_LL_FSYNC,
         LPROC_LL_SETATTR,
         LPROC_LL_TRUNC,

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
         LPROC_LL_GETATTR,
#else
         LPROC_LL_REVALIDATE,
#endif
         LPROC_LL_STAFS,
         LPROC_LL_ALLOC_INODE,
         LPROC_LL_SETXATTR,
         LPROC_LL_GETXATTR,

         LPROC_LL_DIRECT_READ,
         LPROC_LL_DIRECT_WRITE,
         LPROC_LL_FILE_OPCODES
};

#else
#include <linux/lustre_idl.h>
#endif /* __KERNEL__ */

#define LLAP_FROM_COOKIE(c)                                                    \
        (LASSERT(((struct ll_async_page *)(c))->llap_magic == LLAP_MAGIC),     \
         (struct ll_async_page *)(c))

#define LL_MAX_BLKSIZE          (4UL * 1024 * 1024)

#include <lustre/lustre_user.h>

#endif

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

/*
 * This is embedded into liblustre and llite super-blocks to keep track of
 * connect flags (capabilities) supported by all imports given mount is
 * connected to.
 */
struct lustre_client_ocd {
        /*
         * This is conjunction of connect_flags across all imports (LOVs) this
         * mount is connected to. This field is updated by ll_ocd_update()
         * under ->lco_lock.
         */
        __u64      lco_flags;
        spinlock_t lco_lock;
};

/*
 * This function is used as an upcall-callback hooked by liblustre and llite
 * clients into obd_notify() listeners chain to handle notifications about
 * change of import connect_flags. See llu_fsswop_mount() and
 * lustre_common_fill_super().
 *
 * Again, it is dumped into this header for the lack of a better place.
 */
static inline int ll_ocd_update(struct obd_device *host,
                                struct obd_device *watched,
                                enum obd_notify_event ev, void *owner)
{
        struct lustre_client_ocd *lco;
        struct client_obd        *cli;
        __u64 flags;
        int   result;

        ENTRY;
        if (!strcmp(watched->obd_type->typ_name, LUSTRE_OSC_NAME)) {
                cli = &watched->u.cli;
                lco = owner;
                flags = cli->cl_import->imp_connect_data.ocd_connect_flags;
                CDEBUG(D_SUPER, "Changing connect_flags: "LPX64" -> "LPX64"\n",
                       lco->lco_flags, flags);
                spin_lock(&lco->lco_lock);
                lco->lco_flags &= flags;
                spin_unlock(&lco->lco_lock);
                result = 0;
        } else {
                CERROR("unexpected notification of %s %s!\n",
                       watched->obd_type->typ_name,
                       watched->obd_name);
                result = -EINVAL;
        }
        RETURN(result);
}

