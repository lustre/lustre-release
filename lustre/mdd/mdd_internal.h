/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _MDD_INTERNAL_H
#define _MDD_INTERNAL_H

struct osd_device {
	struct lu_device              osd_lu_dev;
	struct osd_device_operations *osd_ops;
}

struct osd_device_operations {
        int (*osd_object_lock)(struct lu_object *lu __u32 mode);
        int (*osd_object_unlock)(struct lu_object *lu, __32 mode);
        int (*osd_trans_start)(struct lu_object *lu); 
        int (*osd_trans_stop)(struct lu_object *lu);
}
#define LUSTRE_MDD_NAME "mdd"
#define LUSTRE_OSD_NAME "osd"

struct mdd_device {
        /* NB this field MUST be first */
        struct md_device                 *mdd_md_device;
        struct osd_device                *mdd_child;
        int                              mdd_max_mddize;
        int                              mdd_max_cookiesize;
        struct file                     *mdd_rcvd_filp;
        spinlock_t                       mdd_transno_lock;
        __u64                            mdd_last_transno;
        __u64                            mdd_mount_count;
        __u64                            mdd_io_epoch;
        unsigned long                    mdd_atime_diff;
        struct semaphore                 mdd_epoch_sem;
        struct ll_fid                    mdd_rootfid;
        struct lr_server_data           *mdd_server_data;
        struct dentry                   *mdd_pending_dir;
        struct dentry                   *mdd_logs_dir;
        struct dentry                   *mdd_objects_dir;
        struct llog_handle              *mdd_cfg_llh;
        struct file                     *mdd_health_check_filp;
        struct lustre_quota_info         mdd_quota_info;
        struct semaphore                 mdd_qonoff_sem;
        struct semaphore                 mdd_health_sem;
        unsigned long                    mdd_lov_objids_valid:1,
                                         mdd_fl_user_xattr:1,
                                         mdd_fl_acl:1;
};
#endif
