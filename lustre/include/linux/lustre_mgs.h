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

#define FSDB_EMPTY 0x0001

struct fs_db {
        char              fsdb_name[8];
        struct list_head  fsdb_list;
        struct semaphore  fsdb_sem;
        void*             fsdb_ost_index_map;
        void*             fsdb_mdt_index_map;
        __u32             fsdb_flags;
        __u32             fsdb_gen;
};

int mgs_fs_setup(struct obd_device *obd, struct vfsmount *mnt);
int mgs_fs_cleanup(struct obd_device *obddev);
int mgs_iocontrol(unsigned int cmd, struct obd_export *exp, 
                  int len, void *karg, void *uarg);

#endif
