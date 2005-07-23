/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
 *   Author: Nathan Rutman <nathan@clusterfs.com>
 *   Author: Lin Song Tao <lincent@clusterfs.com>
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
 *
 * Lustre disk format definitions.
 */

#ifndef _LUSTRE_DISK_H
#define _LUSTRE_DISK_H

#include <linux/types.h>
#include <portals/types.h>

/****************** last_rcvd file *********************/

#define LAST_RCVD "last_rcvd"
#define LR_SERVER_SIZE    512

/* Data stored per server at the head of the last_rcvd file.  In le32 order.
   This should be common to filter_internal.h, lustre_mds.h */
struct lr_server_data {
        __u8  lsd_uuid[40];        /* server UUID */
        __u64 lsd_unused;          /* was lsd_last_objid - don't use for now */
        __u64 lsd_last_transno;    /* last completed transaction ID */
        __u64 lsd_mount_count;     /* FILTER incarnation number */
        __u32 lsd_feature_compat;  /* compatible feature flags */
        __u32 lsd_feature_rocompat;/* read-only compatible feature flags */
        __u32 lsd_feature_incompat;/* incompatible feature flags */
        __u32 lsd_server_size;     /* size of server data area */
        __u32 lsd_client_start;    /* start of per-client data area */
        __u16 lsd_client_size;     /* size of per-client data area */
        __u16 lsd_subdir_count;    /* number of subdirectories for objects */
        __u64 lsd_catalog_oid;     /* recovery catalog object id */
        __u32 lsd_catalog_ogen;    /* recovery catalog inode generation */
        __u8  lsd_peeruuid[40];    /* UUID of MDS associated with this OST */
        __u32 lsd_index;           /* target index (stripe index for ost)*/
        __u8  lsd_padding[LR_SERVER_SIZE - 144];
};


/****************** mount command *********************/

struct host_desc {
        ptl_nid_t primary; 
        ptl_nid_t backup;
};

/* Passed by mount - no persistent info here */
struct lustre_mount_data {
        __u32     lmd_magic;
        __u32     lmd_flags;          /* lustre mount flags */
        struct host_desc lmd_mgmtnid; /* mgmt nid */
        char      lmd_dev[128];       /* device or file system name */
        char      lmd_mtpt[128];      /* mount point (for client overmount) */
        char      lmd_opts[256];      /* lustre mount options (as opposed to 
                                         _device_ mount options) */
};

#define LMD_FLG_FLOCK  0x0001  /* Enable flock */
#define LMD_FLG_MNTCNF 0x1000  /* MountConf compat */
#define LMD_FLG_CLIENT 0x2000  /* Mounting a client only; no real device */

#define lmd_is_client(x) \
        (((x)->lmd_flags & LMD_FLG_CLIENT) || (!((x)->lmd_flags & LMD_FLG_MNTCNF))) 


/****************** persistent mount data *********************/

/* Persistent mount data are stored on the disk in this file.
   Used before the setup llog can be read. */
#define MOUNT_DATA_FILE "CONFIGS/mountdata"

#define LDD_MAGIC 0xbabb0001

#define LDD_SV_TYPE_MDT  0x0001
#define LDD_SV_TYPE_OST  0x0002
#define LDD_SV_TYPE_MGMT 0x0004

#define LDD_FS_TYPE_EXT3     1
#define LDD_FS_TYPE_LDISKFS  2
#define LDD_FS_TYPE_SMFS     3
#define LDD_FS_TYPE_REISERFS 4
        
struct lustre_disk_data {
        __u32     ldd_magic;
        __u32     ldd_flags;
        struct host_desc ldd_mgmtnid;  /* mgmt nid; lmd can override */
        char      ldd_fsname[64];      /* filesystem this server is part of */
        char      ldd_svname[64];      /* this server's name (lustre-mdt0001) */
        __u8      ldd_mount_type;      /* target fs type LDD_FS_TYPE_* */
        char      ldd_mount_opts[128]; /* target fs mount opts */
};
        
#define IS_MDT(data)   ((data)->ldd_flags & LDD_SV_TYPE_MDT)
#define IS_OST(data)   ((data)->ldd_flags & LDD_SV_TYPE_OST)
#define IS_MGMT(data)  ((data)->ldd_flags & LDD_SV_TYPE_MGMT)


/****************** mkfs command *********************/

#define MO_IS_LOOP     0x01
#define MO_FORCEFORMAT 0x02

/* used to describe the options to format the lustre disk, not persistent */
struct mkfs_opts {
        struct lustre_disk_data mo_ldd; /* to be written in MOUNT_DATA_FILE */
        char  mo_mount_type_string[20]; /* "ext3", "ldiskfs", ... */
        char  mo_device[128];           /* disk device name */
        char  mo_mkfsopts[128];         /* options to the backing-store mkfs */
        long  mo_device_sz;
        int   mo_flags; 
        /* Below here is required for mdt,ost,or client logs */
        struct host_desc mo_hostnid;    /* server nid + failover - need to know
                                           for client log */
        int   mo_stripe_sz;
        int   mo_stripe_count;
        int   mo_stripe_pattern;
        int   mo_index;                 /* stripe index for osts, pool index
                                           for pooled mdts.  index will be put
                                           in lr_server_data */
        int   mo_timeout;               /* obd timeout */
};



#endif // _LUSTRE_DISK_H
