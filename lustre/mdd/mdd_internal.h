/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _MDD_INTERNAL_H
#define _MDD_INTERNAL_H

#define LUSTRE_MDD_NAME "mdd"
#define LUSTRE_OSD_NAME "osd"

enum {
        WRITE_LOCK = 1,
        READ_LOCK = 2, 
};


struct mdd_device {
        /* NB this field MUST be first */
        struct md_device                 mdd_md_dev;
        struct osd_device                *mdd_child;
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

/*these osd stuff should be moved to somewhere later*/
struct osd_object {
        struct lu_object  oo_lu;
        struct dentry    *oo_dentry;
};

struct osd_device_operations {
        int   (*osd_object_lock)(struct lu_object *lu, __u32 mode);
        int   (*osd_object_unlock)(struct lu_object *lu, __u32 mode);
        void* (*osd_trans_start)(struct lu_object *lu); 
        void  (*osd_trans_stop)(struct lu_object *lu);
        int   (*osd_object_create)(struct lu_object *plu, struct lu_object *child,
                                   struct context *context, void *handle);
        int   (*osd_object_destroy)(struct lu_object *lu, void *handle); 
        void  (*osd_object_get)(struct lu_object *lu);
        int   (*osd_attr_get)(struct lu_object *lu, void *buf, int buf_len, 
                              const char *name, struct context *context); 
        int   (*osd_attr_set)(struct lu_object *lu, void *buf, int buf_len,
                              const char *name, struct context *context,
                              void *handle);
        int   (*osd_object_dec_check)(struct lu_object *lu);
        int   (*osd_index_insert)(struct lu_object *lu, struct lu_fid *fid, 
                                  const char *name, struct context *uctxt, 
                                  void *handle);
        int   (*osd_index_delete)(struct lu_object *lu, struct lu_fid *fid,
                                  const char *name,  struct context *uctxt, 
                                  void *handle);
};

struct osd_device {
	struct lu_device              osd_lu_dev;
	struct osd_device_operations *osd_ops;
};

int mdd_object_put(struct mdd_device *mdd, struct mdd_object *obj);
void mdd_object_get(struct mdd_device *mdd, struct mdd_object *obj);
#endif
