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
extern unsigned long obd_drop_packet;

enum {
        OBD_INST_MDS_GETATTR = 1,
        OBD_INST_MDS_READPAGE,
        OBD_INST_MDS_READPAGE_BULK,
        OBD_INST_MDS_REINT,
        OBD_INST_MDS_OPEN,
        OBD_INST_MDS_CLOSE,
        OBD_INST_OST_CONNECT,
        OBD_INST_OST_DISCONNECT,
        OBD_INST_OST_GET_INFO,
        OBD_INST_OST_CREATE,
        OBD_INST_OST_DESTROY,
        OBD_INST_OST_GETATTR,
        OBD_INST_OST_SETATTR,
        OBD_INST_OST_OPEN,
        OBD_INST_OST_CLOSE,
        OBD_INST_OST_BRW,
        OBD_INST_OST_PUNCH
};

#define OBD_CHECK_DROP_PACKET(req, id)                                  \
do {                                                                    \
        if (obd_drop_packet != id)                                      \
                break;                                                  \
                                                                        \
        CDEBUG(D_OTHER, "obd_drop_packet=%d, dropping packet.\n", id);  \
        RETURN(0);                                                      \
} while(0)

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
