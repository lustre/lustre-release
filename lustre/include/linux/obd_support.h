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

#include <linux/autoconf.h>
#include <linux/slab.h>
#include <linux/kp30.h>

/* global variables */
extern unsigned long obd_memory;
extern unsigned long obd_fail_loc;

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

#define OBB_FAIL_LDLM                    0x300
#define OBD_FAIL_LDLM_NAMESPACE_NEW      0x301
#define OBD_FAIL_LDLM_ENQUEUE            0x302
#define OBD_FAIL_LDLM_CONVERT            0x303
#define OBD_FAIL_LDLM_CANCEL             0x304
#define OBD_FAIL_LDLM_CALLBACK           0x305

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

static inline void OBD_FAIL_WRITE(int id, kdev_t dev)
{
        if (OBD_FAIL_CHECK(id)) {
#ifdef CONFIG_DEV_RDONLY
                CERROR("obd_fail_loc=%x, fail write operation on %s\n",
                       id, bdevname(dev));
                dev_set_rdonly(dev, 2);
#else
                CERROR("obd_fail_loc=%x, can't fail write operation on %s\n",
                       id, bdevname(dev));
#endif
                /* We set FAIL_ONCE because we never "un-fail" a device */
                obd_fail_loc |= OBD_FAILED | OBD_FAIL_ONCE;
        }
}

#define OBD_ALLOC(ptr, size)                                            \
do {                                                                    \
        long s = (size);                                                \
        (ptr) = kmalloc(s, GFP_KERNEL);                                 \
        if ((ptr) == NULL) {                                            \
                CERROR("kmalloc of '" #ptr "' (%ld bytes) failed "      \
                       "at %s:%d\n", s, __FILE__, __LINE__);            \
        } else {                                                        \
                memset((ptr), 0, s);                                    \
                obd_memory += s;                                        \
                CDEBUG(D_MALLOC, "kmalloced '" #ptr "': %ld at "        \
                       "%p (tot %ld).\n", s, (ptr), obd_memory);        \
        }                                                               \
} while (0)

#define OBD_FREE(ptr, size)                                             \
do {                                                                    \
        int s = (size);                                                 \
        kfree((ptr));                                                   \
        obd_memory -= s;                                                \
        CDEBUG(D_MALLOC, "kfreed '" #ptr "': %d at %p (tot %ld).\n",    \
               s, (ptr), obd_memory);                                   \
} while (0)

#endif
