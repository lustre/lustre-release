/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _MDD_INTERNAL_H
#define _MDD_INTERNAL_H

#define ROOT_FID_SEQ 0
#define ROOT_FID_OID 2

struct mdd_device {
        struct md_device                 mdd_md_dev;
        struct dt_device                *mdd_child;
        int                              mdd_max_mddize;
        int                              mdd_max_cookiesize;
        struct file                     *mdd_rcvd_filp;
        spinlock_t                       mdd_transno_lock;
        __u64                            mdd_last_transno;
        __u64                            mdd_mount_count;
        __u64                            mdd_io_epoch;
        unsigned long                    mdd_atime_diff;
        struct lu_fid                    mdd_rootfid;
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

int mdd_object_put(struct mdd_device *mdd, struct mdd_object *obj);
void mdd_object_get(struct mdd_device *mdd, struct mdd_object *obj);
#endif
