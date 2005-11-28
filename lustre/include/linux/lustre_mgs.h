/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *
 * MGS data structures.
 * See also lustre_idl.h for wire formats of requests.
 */

#ifndef _LUSTRE_MGS_H
#define _LUSTRE_MGS_H

#ifdef __KERNEL__
# include <linux/fs.h>
# include <linux/dcache.h>
#endif
#include <linux/lustre_handles.h>
#include <libcfs/kp30.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_log.h>
#include <linux/lustre_export.h>

#define MGS_LR_SERVER_SIZE    512

#define MGS_LR_CLIENT_START  8192
#define MGS_LR_CLIENT_SIZE    128

#define MGS_ROCOMPAT_SUPP       0x00000001
#define MGS_INCOMPAT_SUPP       (0)

/* Data stored per client in the last_rcvd file.  In le32 order. */
struct mgs_client_data {
        __u8 mcd_uuid[40];      /* client UUID */
        __u64 mcd_last_transno; /* last completed transaction ID */
        __u64 mcd_last_xid;     /* xid for the last transaction */
        __u32 mcd_last_result;  /* result from last RPC */
        __u32 mcd_last_data;    /* per-op data (disposition for open &c.) */
        __u8 mcd_padding[MGS_LR_CLIENT_SIZE - 64];
};

/* Data stored per server at the head of the last_rcvd file.  In le32 order.*/
struct mgs_server_data {
        __u8  msd_uuid[40];        /* server UUID */
        __u64 msd_last_transno;    /* last completed transaction ID */
        __u64 msd_mount_count;     /* MDS incarnation number */
        __u64 msd_unused;
        __u32 msd_feature_compat;  /* compatible feature flags */
        __u32 msd_feature_rocompat;/* read-only compatible feature flags */
        __u32 msd_feature_incompat;/* incompatible feature flags */
        __u32 msd_server_size;     /* size of server data area */
        __u32 msd_client_start;    /* start of per-client data area */
        __u16 msd_client_size;     /* size of per-client data area */
        __u16 msd_subdir_count;    /* number of subdirectories for objects */
        __u64 msd_catalog_oid;     /* recovery catalog object id */
        __u32 msd_catalog_ogen;    /* recovery catalog inode generation */
        __u8  msd_peeruuid[40];    /* UUID of LOV/OSC associated with MDS */
        __u8  msd_padding[MGS_LR_SERVER_SIZE - 140];
};

typedef enum {
        MCID = 1,
        OTID = 2,
} llogid_t;

struct mgc_op_data {
        llogid_t   obj_id;
        __u64      obj_version;
};

struct system_db {
        char              fsname[64];
        struct list_head  db_list;
        void*             index_map;
        struct list_head  ost_infos;
};

struct mgc_open_llog {
        struct list_head   mol_list;
        __u64              mol_step;
        llogid_t           mol_id;
        char               mol_fsname[40];
};

int mgs_fs_setup(struct obd_device *obd, struct vfsmount *mnt);
int mgs_fs_cleanup(struct obd_device *obddev);

extern int mgs_iocontrol(unsigned int cmd, struct obd_export *exp, 
                         int len, void *karg, void *uarg);

extern int mgs_mds_register(struct ptlrpc_request*);
#endif
