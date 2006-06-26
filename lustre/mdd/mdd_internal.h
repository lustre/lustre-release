/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _MDD_INTERNAL_H
#define _MDD_INTERNAL_H

#include <asm/semaphore.h>
#include <md_object.h>

struct dt_device;
struct file;
struct lr_server_data;
struct dentry;
struct llog_handle;

struct mdd_lov_info {
        struct obd_device               *mdd_lov_obd; 
        struct obd_uuid                  mdd_lov_uuid;
        struct lov_desc                  mdd_lov_desc;
        obd_id                          *mdd_lov_objids;
        int                              mdd_lov_objids_size;
        __u32                            mdd_lov_objids_in_file;
        int                              mdd_lov_nextid_set;
        struct lu_fid                    mdd_lov_objid_fid;
        struct dt_object                *mdd_lov_objid_obj;
        unsigned int                     mdd_lov_objids_dirty:1;
};

struct mdd_device {
        struct md_device                 mdd_md_dev;
        struct dt_device                *mdd_child;
        struct mdd_lov_info              mdd_lov_info;
        struct dt_device                 mdd_lov_dev; 
        int                              mdd_max_mdsize;
        int                              mdd_max_cookiesize;
        struct file                     *mdd_rcvd_filp;
        struct lu_fid                    mdd_root_fid;
        spinlock_t                       mdd_transno_lock;
        __u64                            mdd_last_transno;
        __u64                            mdd_mount_count;
        __u64                            mdd_io_epoch;
        unsigned long                    mdd_atime_diff;
        struct lr_server_data           *mdd_server_data;
        struct dentry                   *mdd_pending_dir;
        struct dentry                   *mdd_logs_dir;
        struct dentry                   *mdd_objects_dir;
        struct llog_handle              *mdd_cfg_llh;
        struct file                     *mdd_health_check_filp;
        struct semaphore                 mdd_health_sem;
        unsigned long                    mdd_lov_objids_valid:1,
                                         mdd_fl_user_xattr:1,
                                         mdd_fl_acl:1;
};

struct mdd_object {
        struct md_object  mod_obj;
};

int mdd_lov_init(const struct lu_context *ctxt, struct mdd_device *mdd,
                 struct lustre_cfg *cfg);
int mdd_lov_fini(const struct lu_context *ctxt, struct mdd_device *mdd);
#endif
