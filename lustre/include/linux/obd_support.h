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

enum {
        OBD_FAIL_MDS = 0x100,
        OBD_FAIL_MDS_HANDLE_UNPACK,
        OBD_FAIL_MDS_GETATTR_NET,
        OBD_FAIL_MDS_GETATTR_PACK,
        OBD_FAIL_MDS_READPAGE_NET,
        OBD_FAIL_MDS_READPAGE_PACK,
        OBD_FAIL_MDS_READPAGE_BULK_NET,
        OBD_FAIL_MDS_SENDPAGE,
        OBD_FAIL_MDS_REINT_NET,
        OBD_FAIL_MDS_REINT_UNPACK,
        OBD_FAIL_MDS_REINT_SETATTR,
        OBD_FAIL_MDS_REINT_SETATTR_WRITE,
        OBD_FAIL_MDS_REINT_CREATE,
        OBD_FAIL_MDS_REINT_CREATE_WRITE,
        OBD_FAIL_MDS_REINT_UNLINK,
        OBD_FAIL_MDS_REINT_UNLINK_WRITE,
        OBD_FAIL_MDS_REINT_LINK,
        OBD_FAIL_MDS_REINT_LINK_WRITE,
        OBD_FAIL_MDS_REINT_RENAME,
        OBD_FAIL_MDS_REINT_RENAME_WRITE,
        OBD_FAIL_MDS_OPEN_NET,
        OBD_FAIL_MDS_OPEN_PACK,
        OBD_FAIL_MDS_CLOSE_NET,
        OBD_FAIL_MDS_CLOSE_PACK,

        OBD_FAIL_OST = 0x200,
        OBD_FAIL_OST_CONNECT_NET,
        OBD_FAIL_OST_DISCONNECT_NET,
        OBD_FAIL_OST_GET_INFO_NET,
        OBD_FAIL_OST_CREATE_NET,
        OBD_FAIL_OST_DESTROY_NET,
        OBD_FAIL_OST_GETATTR_NET,
        OBD_FAIL_OST_SETATTR_NET,
        OBD_FAIL_OST_OPEN_NET,
        OBD_FAIL_OST_CLOSE_NET,
        OBD_FAIL_OST_BRW_NET,
        OBD_FAIL_OST_PUNCH_NET,

        OBB_FAIL_LDLM = 0x300,
        OBD_FAIL_LDLM_ENQUEUE,
        OBD_FAIL_LDLM_CONVERT,
        OBD_FAIL_LDLM_CANCEL,
        OBD_FAIL_LDLM_CALLBACK,

};

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
                RETURN(ret);                                                 \
        }                                                                    \
} while(0)

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

#define OBD_ALLOC(ptr, size)                                    \
do {                                                            \
        long s = (size);                                        \
        (ptr) = kmalloc(s, GFP_KERNEL);                         \
        if ((ptr) == NULL) {                                    \
                CERROR("kernel malloc of %ld bytes failed at "  \
                       "%s:%d\n", s, __FILE__, __LINE__);       \
        } else {                                                \
                memset((ptr), 0, s);                            \
                obd_memory += s;                                \
        }                                                       \
        CDEBUG(D_MALLOC, "kmalloced: %ld at %x (tot %ld).\n",   \
               s, (int)(ptr), obd_memory);                      \
} while (0)

#define OBD_FREE(ptr, size)                                     \
do {                                                            \
        int s = (size);                                         \
        kfree((ptr));                                           \
        CDEBUG(D_MALLOC, "kfreed: %d at %x (tot %ld).\n",       \
               s, (int)(ptr), obd_memory);                      \
        obd_memory -= s;                                        \
} while (0)

#endif
