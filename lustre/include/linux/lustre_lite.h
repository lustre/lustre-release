/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _LINUX_LL_H
#define _LINUX_LL_H

#ifndef _LL_H
#error Do not #include this file directly. #include <lustre_lite.h> instead
#endif

#ifdef __KERNEL__

#include <linux/version.h>

#include <asm/statfs.h>

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/proc_fs.h>

#include <obd_class.h>
#include <lustre_net.h>
#include <lustre_ha.h>

#include <linux/rbtree.h>
#include <linux/lustre_compat25.h>
#include <linux/pagemap.h>

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
         LPROC_LL_LOCKLESS_TRUNC,
         LPROC_LL_FLOCK,
         LPROC_LL_GETATTR,
         LPROC_LL_STAFS,
         LPROC_LL_ALLOC_INODE,
         LPROC_LL_SETXATTR,
         LPROC_LL_GETXATTR,
         LPROC_LL_LISTXATTR,
         LPROC_LL_REMOVEXATTR,
         LPROC_LL_INODE_PERM,
         LPROC_LL_DIRECT_READ,
         LPROC_LL_DIRECT_WRITE,
         LPROC_LL_LOCKLESS_READ,
         LPROC_LL_LOCKLESS_WRITE,
         LPROC_LL_FILE_OPCODES
};

#else
#include <lustre/lustre_idl.h>
#endif /* __KERNEL__ */

#endif
