/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef _OBD_SUPPORT
#define _OBD_SUPPORT

#include <linux/config.h>
#include <linux/autoconf.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/kp30.h>

/* global variables */
extern atomic_t obd_memory;
extern int obd_memmax;
extern unsigned long obd_fail_loc;
extern unsigned long obd_timeout;
extern char obd_recovery_upcall[128];

#define OBD_FAIL_MDS                     0x100
#define OBD_FAIL_MDS_HANDLE_UNPACK       0x101
#define OBD_FAIL_MDS_GETATTR_NET         0x102
#define OBD_FAIL_MDS_GETATTR_PACK        0x103
#define OBD_FAIL_MDS_READPAGE_NET        0x104
#define OBD_FAIL_MDS_READPAGE_PACK       0x105
#define OBD_FAIL_MDS_SENDPAGE            0x106
#define OBD_FAIL_MDS_REINT_NET           0x107
#define OBD_FAIL_MDS_REINT_UNPACK        0x108
#define OBD_FAIL_MDS_REINT_SETATTR       0x109
#define OBD_FAIL_MDS_REINT_SETATTR_WRITE 0x10a
#define OBD_FAIL_MDS_REINT_CREATE        0x10b
#define OBD_FAIL_MDS_REINT_CREATE_WRITE  0x10c
#define OBD_FAIL_MDS_REINT_UNLINK        0x10d
#define OBD_FAIL_MDS_REINT_UNLINK_WRITE  0x10e
#define OBD_FAIL_MDS_REINT_LINK          0x10f
#define OBD_FAIL_MDS_REINT_LINK_WRITE    0x110
#define OBD_FAIL_MDS_REINT_RENAME        0x111
#define OBD_FAIL_MDS_REINT_RENAME_WRITE  0x112
#define OBD_FAIL_MDS_OPEN_NET            0x113
#define OBD_FAIL_MDS_OPEN_PACK           0x114
#define OBD_FAIL_MDS_CLOSE_NET           0x115
#define OBD_FAIL_MDS_CLOSE_PACK          0x116
#define OBD_FAIL_MDS_CONNECT_NET         0x117
#define OBD_FAIL_MDS_CONNECT_PACK        0x118
#define OBD_FAIL_MDS_REINT_NET_REP       0x119
#define OBD_FAIL_MDS_DISCONNECT_NET      0x11a
#define OBD_FAIL_MDS_GETSTATUS_NET       0x11b
#define OBD_FAIL_MDS_GETSTATUS_PACK      0x11c
#define OBD_FAIL_MDS_STATFS_PACK         0x11d
#define OBD_FAIL_MDS_STATFS_NET          0x11e
#define OBD_FAIL_MDS_GETATTR_NAME_NET    0x11f

#define OBD_FAIL_OST                     0x200
#define OBD_FAIL_OST_CONNECT_NET         0x201
#define OBD_FAIL_OST_DISCONNECT_NET      0x202
#define OBD_FAIL_OST_GET_INFO_NET        0x203
#define OBD_FAIL_OST_CREATE_NET          0x204
#define OBD_FAIL_OST_DESTROY_NET         0x205
#define OBD_FAIL_OST_GETATTR_NET         0x206
#define OBD_FAIL_OST_SETATTR_NET         0x207
#define OBD_FAIL_OST_OPEN_NET            0x208
#define OBD_FAIL_OST_CLOSE_NET           0x209
#define OBD_FAIL_OST_BRW_NET             0x20a
#define OBD_FAIL_OST_PUNCH_NET           0x20b
#define OBD_FAIL_OST_STATFS_NET          0x20c
#define OBD_FAIL_OST_HANDLE_UNPACK       0x20d
#define OBD_FAIL_OST_BRW_WRITE_BULK      0x20e
#define OBD_FAIL_OST_BRW_READ_BULK       0x20f

#define OBD_FAIL_LDLM                    0x300
#define OBD_FAIL_LDLM_NAMESPACE_NEW      0x301
#define OBD_FAIL_LDLM_ENQUEUE            0x302
#define OBD_FAIL_LDLM_CONVERT            0x303
#define OBD_FAIL_LDLM_CANCEL             0x304
#define OBD_FAIL_LDLM_BL_CALLBACK        0x305
#define OBD_FAIL_LDLM_CP_CALLBACK        0x306

#define OBD_FAIL_OSC                     0x400
#define OBD_FAIL_OSC_BRW_READ_BULK       0x401
#define OBD_FAIL_OSC_BRW_WRITE_BULK      0x402
#define OBD_FAIL_OSC_LOCK_BL_AST         0x403
#define OBD_FAIL_OSC_LOCK_CP_AST         0x404

/* preparation for a more advanced failure testbed (not functional yet) */
#define OBD_FAIL_MASK_SYS    0x0000FF00
#define OBD_FAIL_MASK_LOC    (0x000000FF | OBD_FAIL_MASK_SYS)
#define OBD_FAIL_ONCE        0x80000000
#define OBD_FAILED           0x40000000
#define OBD_FAIL_MDS_ALL_NET 0x01000000
#define OBD_FAIL_OST_ALL_NET 0x02000000

#define OBD_FAIL_CHECK(id)   ((obd_fail_loc & OBD_FAIL_MASK_LOC) == (id) &&  \
                              ((obd_fail_loc & (OBD_FAILED | OBD_FAIL_ONCE))!=\
                                (OBD_FAILED | OBD_FAIL_ONCE)))

#define OBD_FAIL_RETURN(id, ret)                                             \
do {                                                                         \
        if (OBD_FAIL_CHECK(id)) {                                            \
                CERROR("obd_fail_loc=%x, fail operation rc=%d\n", id, ret);  \
                obd_fail_loc |= OBD_FAILED;                                  \
                if ((id) & OBD_FAIL_ONCE)                                    \
                        obd_fail_loc |= OBD_FAIL_ONCE;                       \
                RETURN(ret);                                                 \
        }                                                                    \
} while(0)

#include <linux/types.h>
#include <linux/blkdev.h>

#define fixme() CDEBUG(D_OTHER, "FIXME\n");

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#define ll_bdevname(a) __bdevname((a))
#define ll_lock_kernel lock_kernel()
#else
#define ll_lock_kernel
#define ll_bdevname(a) bdevname((a))
#endif

static inline void OBD_FAIL_WRITE(int id, kdev_t dev)
{
        if (OBD_FAIL_CHECK(id)) {
#ifdef CONFIG_DEV_RDONLY
                CERROR("obd_fail_loc=%x, fail write operation on %s\n",
                       id, ll_bdevname(dev));
                dev_set_rdonly(dev, 2);
#else
                CERROR("obd_fail_loc=%x, can't fail write operation on %s\n",
                       id, ll_bdevname(dev));
#endif
                /* We set FAIL_ONCE because we never "un-fail" a device */
                obd_fail_loc |= OBD_FAILED | OBD_FAIL_ONCE;
        }
}

#define OBD_ALLOC(ptr, size)                                            \
do {                                                                    \
        void *lptr;                                                     \
        int s = (size);                                                 \
        (ptr) = lptr = kmalloc(s, GFP_KERNEL);                          \
        if (lptr == NULL) {                                             \
                CERROR("kmalloc of '" #ptr "' (%d bytes) failed "       \
                       "at %s:%d\n", s, __FILE__, __LINE__);            \
        } else {                                                        \
                int obd_curmem;                                         \
                memset(lptr, 0, s);                                     \
                atomic_add(s, &obd_memory);                             \
                obd_curmem = atomic_read(&obd_memory);                  \
                if (obd_curmem > obd_memmax)                            \
                        obd_memmax = obd_curmem;                        \
                CDEBUG(D_MALLOC, "kmalloced '" #ptr "': %d at %p "      \
                       "(tot %d)\n", s, lptr, obd_curmem);              \
        }                                                               \
} while (0)

#ifdef CONFIG_DEBUG_SLAB
#define POISON(lptr, s) do {} while (0)
#else
#define POISON(lptr, s) memset(lptr, 0x5a, s)
#endif

#define OBD_FREE(ptr, size)                                             \
do {                                                                    \
        void *lptr = (ptr);                                             \
        int s = (size);                                                 \
        LASSERT(lptr);                                                  \
        POISON(lptr, s);                                                \
        kfree(lptr);                                                    \
        atomic_sub(s, &obd_memory);                                     \
        CDEBUG(D_MALLOC, "kfreed '" #ptr "': %d at %p (tot %d).\n",     \
               s, lptr, atomic_read(&obd_memory));                      \
        (ptr) = (void *)0xdeadbeef;                                     \
} while (0)

#ifdef CONFIG_HIGHMEM
extern void obd_kmap_get(int count, int server);
extern void obd_kmap_put(int count);
#else
#define obd_kmap_get(count, server) do {} while (0)
#define obd_kmap_put(count) do {} while (0)
#endif
#endif
