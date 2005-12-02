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

#define MGS_ROCOMPAT_SUPP       0x00000001
#define MGS_INCOMPAT_SUPP       (0)

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
        int               sdb_flags;
};
#define SDB_NO_LLOG 0x01
#define LOG_IS_EMPTY(db) ((db)->sdb_flags & SDB_NO_LLOG)

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

extern int mgs_mds_register(struct ptlrpc_request *req);
#endif
