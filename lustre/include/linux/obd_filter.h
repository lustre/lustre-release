/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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

#ifndef _OBD_FILTER_H
#define _OBD_FILTER_H

#ifdef __KERNEL__
#include <linux/spinlock.h>
#endif
#include <linux/lustre_handles.h>

#ifndef OBD_FILTER_DEVICENAME
#define OBD_FILTER_DEVICENAME "obdfilter"
#endif

#define FILTER_LR_SERVER_SIZE    512

#define FILTER_LR_CLIENT_START   8192
#define FILTER_LR_CLIENT_SIZE    128

#define FILTER_SUBDIR_COUNT      32            /* set to zero for no subdirs */

#define FILTER_MOUNT_RECOV 2
#define FILTER_RECOVERY_TIMEOUT (obd_timeout * 5 * HZ / 2) /* *waves hands* */

/* Data stored per server at the head of the last_rcvd file.  In le32 order. */
struct filter_server_data {
        __u8  fsd_uuid[37];        /* server UUID */
        __u8  fsd_uuid_padding[3]; /* unused */
        __u64 fsd_last_objid;      /* last created object ID */
        __u64 fsd_last_rcvd;       /* last completed transaction ID */
        __u64 fsd_mount_count;     /* FILTER incarnation number */
        __u32 fsd_feature_compat;  /* compatible feature flags */
        __u32 fsd_feature_rocompat;/* read-only compatible feature flags */
        __u32 fsd_feature_incompat;/* incompatible feature flags */
        __u32 fsd_server_size;     /* size of server data area */
        __u32 fsd_client_start;    /* start of per-client data area */
        __u16 fsd_client_size;     /* size of per-client data area */
        __u16 fsd_subdir_count;    /* number of subdirectories for objects */
        __u8  fsd_padding[FILTER_LR_SERVER_SIZE - 88];
};

/* Data stored per client in the last_rcvd file.  In le32 order. */
struct filter_client_data {
        __u8  fcd_uuid[37];        /* client UUID */
        __u8  fcd_uuid_padding[3]; /* unused */
        __u64 fcd_last_rcvd;       /* last completed transaction ID */
        __u64 fcd_mount_count;     /* FILTER incarnation number */
        __u64 fcd_last_xid;        /* client RPC xid for the last transaction */
        __u8  fcd_padding[FILTER_LR_CLIENT_SIZE - 64];
};

#ifndef OBD_FILTER_SAN_DEVICENAME
#define OBD_FILTER_SAN_DEVICENAME "sanobdfilter"
#endif

/* In-memory access to client data from OST struct */
struct filter_export_data {
        struct list_head  fed_open_head; /* files to close on disconnect */
        spinlock_t        fed_lock;      /* protects fed_open_head */
        struct filter_client_data  *fed_fcd;
        loff_t            fed_lr_off;
        int               fed_lr_idx;
};

/* file data for open files on OST */
struct filter_file_data {
        struct portals_handle ffd_handle;
        atomic_t              ffd_refcount;
        struct list_head      ffd_export_list; /* export open list - fed_lock */
        struct file          *ffd_file;         /* file handle */
};

struct filter_dentry_data {
        obd_id           fdd_objid;
        atomic_t         fdd_open_count;
        int              fdd_flags;
};

#define FILTER_FLAG_DESTROY 0x0001      /* destroy dentry on last file close */


#endif
