/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#ifndef __OBD_H
#define __OBD_H

#define IOC_OSC_TYPE         'h'
#define IOC_OSC_MIN_NR       20
#define IOC_OSC_REGISTER_LOV _IOWR(IOC_OSC_TYPE, 20, struct obd_device *)
#define IOC_OSC_SET_ACTIVE   _IOWR(IOC_OSC_TYPE, 21, struct obd_device *)
#define IOC_OSC_MAX_NR       50

#define IOC_MDC_TYPE         'i'
#define IOC_MDC_MIN_NR       20
#define IOC_MDC_LOOKUP       _IOWR(IOC_MDC_TYPE, 20, struct obd_device *)
#define IOC_MDC_GETSTRIPE    _IOWR(IOC_MDC_TYPE, 21, struct lov_mds_md *)
#define IOC_MDC_MAX_NR       50

#ifdef __KERNEL__
# include <linux/fs.h>
# include <linux/list.h>
# include <linux/sched.h> /* for struct task_struct, for current.h */
# include <asm/current.h> /* for smp_lock.h */
# include <linux/smp_lock.h>
# include <linux/proc_fs.h>
# include <linux/mount.h>
#endif

#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_export.h>
#include <linux/lustre_otree.h>

struct lov_oinfo { /* per-child structure */
        __u64 loi_id;              /* object ID on the target OST */
        struct lustre_handle *loi_handle; /* open file handle for obj on OST */
        int loi_ost_idx;           /* OST stripe index in lmd_objects array */
        /* tracking offsets per file, per stripe.. */
        struct otree *loi_dirty_ot; /* lets lov stack on osc */
        struct otree loi_dirty_ot_inline;
};

struct lov_stripe_md {
        /* Public members. */
        __u64 lsm_object_id;        /* lov object id */
        __u64 lsm_maxbytes;

        /* LOV-private members start here -- only for use in lov/. */
        __u32 lsm_magic;
        __u32 lsm_stripe_size;      /* size of the stripe */
        unsigned lsm_stripe_offset; /* offset of first stripe in lmd_objects */
        unsigned lsm_stripe_count;  /* how many objects are being striped on */
        struct lov_oinfo lsm_oinfo[0];
};

struct obd_type {
        struct list_head typ_chain;
        struct obd_ops *typ_ops;
        struct proc_dir_entry *typ_procroot;
        char *typ_name;
        int  typ_refcnt;
};

struct brw_page {
        obd_off  off;
        struct page *pg;
        int count;
        obd_flag flag;
};

/* Individual type definitions */

struct ost_server_data;

struct filter_obd {
        const char          *fo_fstype;
        char                *fo_nspath;
        struct super_block  *fo_sb;
        struct vfsmount     *fo_vfsmnt;
        struct obd_run_ctxt  fo_ctxt;
        struct dentry       *fo_dentry_O;
        struct dentry       *fo_dentry_O_mode[16];
        struct dentry      **fo_dentry_O_sub;
        spinlock_t           fo_objidlock; /* protect fo_lastobjid increment */
        spinlock_t           fo_translock; /* protect fsd_last_rcvd increment */
        struct file         *fo_rcvd_filp;
        struct filter_server_data *fo_fsd;
        unsigned long       *fo_last_rcvd_slots;

        struct file_operations *fo_fop;
        struct inode_operations *fo_iop;
        struct address_space_operations *fo_aops;

        struct list_head     fo_export_list;
        spinlock_t           fo_fddlock; /* protect setting dentry->d_fsdata */
        int                  fo_subdir_count;
        spinlock_t           fo_grant_lock;       /* protects tot_granted */
        obd_size             fo_tot_granted;
        obd_size             fo_tot_cached;

        struct llog_handle  *fo_catalog;
        struct obd_import   *fo_mdc_imp;
        struct obd_uuid      fo_mdc_uuid;
        struct lustre_handle fo_mdc_conn;
        struct ptlrpc_client fo_mdc_client;
        struct llog_commit_data *fo_llcd;
        struct semaphore     fo_sem; /* protects fo_llcd */
};

struct mds_server_data;

struct client_obd {
        struct obd_import       *cl_import;
        struct semaphore         cl_sem;
        int                      cl_conn_count;
        /* max_mds_easize is purely a performance thing so we don't have to
         * call obd_size_wiremd() all the time. */
        int                      cl_max_mds_easize;
        int                      cl_max_mds_cookiesize;
        /* XXX can we replace cl_containing_lov with mgmt-events? */
        struct obd_device       *cl_containing_lov;
        kdev_t                   cl_sandev;

        struct llog_commit_data *cl_llcd;
        void                    *cl_llcd_offset;

        struct semaphore         cl_dirty_sem;
        obd_size                 cl_dirty;  /* both in bytes */
        obd_size                 cl_dirty_granted;

        struct obd_device       *cl_mgmtcli_obd;

        /* this is just to keep existing infinitely caching behaviour between
         * clients and OSTs that don't have the grant code in yet.. it can
         * be yanked once everything speaks grants */
        char                     cl_ost_can_grant;
};

/* Like a client, with some hangers-on.  Keep mc_client_obd first so that we
 * can reuse the various client setup/connect functions. */
struct mgmtcli_obd {
        struct client_obd        mc_client_obd; /* nested */
        struct ptlrpc_thread    *mc_ping_thread;
        struct lustre_handle     mc_ping_handle; /* XXX single-target */
        struct list_head         mc_registered;
        void                    *mc_hammer;
};

#define mc_import mc_client_obd.cl_import

struct mds_obd {
        struct ptlrpc_service           *mds_service;
        struct ptlrpc_service           *mds_setattr_service;
        struct ptlrpc_service           *mds_readpage_service;

        struct super_block              *mds_sb;
        struct vfsmount                 *mds_vfsmnt;
        struct dentry                   *mds_fid_de;
        struct obd_run_ctxt              mds_ctxt;
        struct file_operations          *mds_fop;
        struct inode_operations         *mds_iop;
        struct address_space_operations *mds_aops;

        int                              mds_max_mdsize;
        int                              mds_max_cookiesize;
        struct file                     *mds_rcvd_filp;
        spinlock_t                       mds_transno_lock;
        __u64                            mds_last_transno;
        __u64                            mds_mount_count;
        struct ll_fid                    mds_rootfid;
        struct mds_server_data          *mds_server_data;
        struct dentry                   *mds_pending_dir;
        struct dentry                   *mds_logs_dir;

        struct llog_handle              *mds_catalog;
        struct obd_device               *mds_osc_obd;
        struct obd_uuid                  mds_osc_uuid;
        struct lustre_handle             mds_osc_conn;

        int                              mds_has_lov_desc;
        struct lov_desc                  mds_lov_desc;
        unsigned long                   *mds_client_bitmap;
};

struct ldlm_obd {
        struct ptlrpc_service *ldlm_cb_service;
        struct ptlrpc_service *ldlm_cancel_service;
        struct ptlrpc_client *ldlm_client;
        struct ptlrpc_connection *ldlm_server_conn;
};

struct echo_obd {
        struct obdo oa;
        spinlock_t eo_lock;
        __u64 eo_lastino;
        atomic_t eo_getattr;
        atomic_t eo_setattr;
        atomic_t eo_create;
        atomic_t eo_destroy;
        atomic_t eo_prep;
        atomic_t eo_read;
        atomic_t eo_write;
};

/*
 * this struct does double-duty acting as either a client or
 * server instance .. maybe not wise.
 */
struct ptlbd_obd {
        /* server's */
        struct ptlrpc_service *ptlbd_service;
        struct file *filp;
        /* client's */
        struct ptlrpc_client    bd_client;
        struct obd_import       *bd_import;
        struct obd_uuid         bd_server_uuid;
        struct lustre_handle    bd_connect_handle;
        int refcount; /* XXX sigh */
};

struct recovd_obd {
        spinlock_t            recovd_lock;
        struct list_head      recovd_managed_items; /* items managed  */
        struct list_head      recovd_troubled_items; /* items in recovery */

        wait_queue_head_t     recovd_recovery_waitq;
        wait_queue_head_t     recovd_ctl_waitq;
        wait_queue_head_t     recovd_waitq;
        struct task_struct   *recovd_thread;
        __u32                 recovd_state;
};

struct ost_obd {
        struct ptlrpc_service *ost_service;
};

struct echo_client_obd {
        struct lustre_handle ec_conn;   /* the local connection to osc/lov */
        spinlock_t           ec_lock;
        struct list_head     ec_objects;
        int                  ec_lsmsize;
        int                  ec_nstripes;
        __u64                ec_unique;
};

struct cache_obd {
        struct lustre_handle cobd_target;   /* local connection to target obd */
        struct lustre_handle cobd_cache;    /* local connection to cache obd */
};

struct lov_tgt_desc {
        struct obd_uuid uuid;
        struct lustre_handle conn;
        struct llog_handle *ltd_cathandle;
        int active; /* is this target available for requests, etc */
};

struct lov_obd {
        spinlock_t lov_lock;
        struct obd_device *mdcobd;
        struct lov_desc desc;
        int bufsize;
        int refcount;
        int lo_catalog_loaded:1;
        struct lov_tgt_desc *tgts;
};

struct niobuf_local {
        __u64 offset;
        __u32 len;
        __u32 flags;
        __u32 rc;
        struct page *page;
        struct dentry *dentry;
        unsigned long start;
};

/* Don't conflict with on-wire flags OBD_BRW_WRITE, etc */
#define N_LOCAL_TEMP_PAGE 0x10000000

struct obd_trans_info {
        __u64                   oti_transno;
        /* Only used on the server side for tracking acks. */
        struct oti_req_ack_lock {
                struct lustre_handle lock;
                __u32                mode;
        } oti_ack_locks[4];
        void                    *oti_handle;
        struct llog_cookie       oti_onecookie;
        struct llog_cookie      *oti_logcookies;
        int                      oti_numcookies;
};

static inline void oti_alloc_cookies(struct obd_trans_info *oti,int num_cookies)
{
        if (!oti)
                return;

        if (num_cookies == 1)
                oti->oti_logcookies = &oti->oti_onecookie;
        else
                OBD_ALLOC(oti->oti_logcookies,
                          num_cookies * sizeof(oti->oti_onecookie));

        oti->oti_numcookies = num_cookies;
}

static inline void oti_free_cookies(struct obd_trans_info *oti)
{
        if (!oti || !oti->oti_logcookies)
                return;

        if (oti->oti_logcookies == &oti->oti_onecookie)
                LASSERT(oti->oti_numcookies == 1);
        else
                OBD_FREE(oti->oti_logcookies,
                         oti->oti_numcookies * sizeof(oti->oti_onecookie));
        oti->oti_logcookies = NULL;
        oti->oti_numcookies = 0;
}

/* corresponds to one of the obd's */
struct obd_device {
        struct obd_type *obd_type;

        /* common and UUID name of this device */
        char *obd_name;
        struct obd_uuid obd_uuid;

        int obd_minor;
        int obd_attached:1, obd_set_up:1, obd_recovering:1,
            obd_abort_recovery:1, obd_replayable:1, obd_no_transno:1,
            obd_no_recov:1, obd_stopping:1;
        atomic_t obd_refcount;
        wait_queue_head_t obd_refcount_waitq;
        struct proc_dir_entry *obd_proc_entry;
        struct list_head       obd_exports;
        int                    obd_num_exports;
        struct list_head       obd_imports;
        struct ldlm_namespace *obd_namespace;
        struct ptlrpc_client   obd_ldlm_client; /* XXX OST/MDS only */
        /* a spinlock is OK for what we do now, may need a semaphore later */
        spinlock_t             obd_dev_lock;
        __u64                  obd_last_committed;
        struct fsfilt_operations *obd_fsops;
        struct obd_statfs      obd_osfs;
        unsigned long          obd_osfs_age;

        /* XXX encapsulate all this recovery data into one struct */
        svc_handler_t                    obd_recovery_handler;
        int                              obd_recoverable_clients;
        spinlock_t                       obd_processing_task_lock;
        pid_t                            obd_processing_task;
        __u64                            obd_next_recovery_transno;
        wait_queue_head_t                obd_next_transno_waitq;
        wait_queue_head_t                obd_commit_waitq;
        struct timer_list                obd_recovery_timer;
        struct list_head                 obd_recovery_queue;
        struct list_head                 obd_delayed_reply_queue;

        union {
                struct filter_obd filter;
                struct mds_obd mds;
                struct client_obd cli;
                struct ost_obd ost;
                struct echo_client_obd echo_client;
                struct ldlm_obd ldlm;
                struct echo_obd echo;
                struct recovd_obd recovd;
                struct lov_obd lov;
                struct cache_obd cobd;
                struct ptlbd_obd ptlbd;
                struct mgmtcli_obd mgmtcli;
        } u;
       /* Fields used by LProcFS */
        unsigned int           obd_cntr_base;
        struct lprocfs_stats  *obd_stats;
};

#define OBD_OPT_FORCE           0x0001
#define OBD_OPT_FAILOVER        0x0002

#define OBD_LLOG_FL_SENDNOW     0x0001

struct obd_ops {
        struct module *o_owner;
        int (*o_iocontrol)(unsigned int cmd, struct lustre_handle *, int len,
                           void *karg, void *uarg);
        int (*o_get_info)(struct lustre_handle *, __u32 keylen, void *key,
                          __u32 *vallen, void *val);
        int (*o_set_info)(struct lustre_handle *, __u32 keylen, void *key,
                          __u32 vallen, void *val);
        int (*o_attach)(struct obd_device *dev, obd_count len, void *data);
        int (*o_detach)(struct obd_device *dev);
        int (*o_setup) (struct obd_device *dev, obd_count len, void *data);
        int (*o_cleanup)(struct obd_device *dev, int flags);
        int (*o_connect)(struct lustre_handle *conn, struct obd_device *src,
                         struct obd_uuid *cluuid);
        int (*o_disconnect)(struct lustre_handle *conn, int flags);

        int (*o_statfs)(struct obd_device *obd, struct obd_statfs *osfs,
                        unsigned long max_age);
        int (*o_syncfs)(struct obd_export *exp);
        int (*o_packmd)(struct lustre_handle *, struct lov_mds_md **disk_tgt,
                        struct lov_stripe_md *mem_src);
        int (*o_unpackmd)(struct lustre_handle *conn,
                          struct lov_stripe_md **mem_tgt,
                          struct lov_mds_md *disk_src, int disk_len);
        int (*o_preallocate)(struct lustre_handle *, obd_count *req,
                             obd_id *ids);
        int (*o_create)(struct lustre_handle *conn,  struct obdo *oa,
                        struct lov_stripe_md **ea, struct obd_trans_info *oti);
        int (*o_destroy)(struct lustre_handle *conn, struct obdo *oa,
                         struct lov_stripe_md *ea, struct obd_trans_info *oti);
        int (*o_setattr)(struct lustre_handle *conn, struct obdo *oa,
                         struct lov_stripe_md *ea, struct obd_trans_info *oti);
        int (*o_getattr)(struct lustre_handle *conn, struct obdo *oa,
                         struct lov_stripe_md *ea);
        int (*o_getattr_async)(struct lustre_handle *conn, struct obdo *oa,
                               struct lov_stripe_md *ea,
                               struct ptlrpc_request_set *set);
        int (*o_open)(struct lustre_handle *conn, struct obdo *oa,
                      struct lov_stripe_md *ea, struct obd_trans_info *oti,
                      struct obd_client_handle *och);
        int (*o_close)(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *ea, struct obd_trans_info *oti);
        int (*o_brw)(int rw, struct lustre_handle *conn, struct obdo *oa,
                     struct lov_stripe_md *ea, obd_count oa_bufs,
                     struct brw_page *pgarr, struct obd_trans_info *oti);
        int (*o_brw_async)(int rw, struct lustre_handle *conn, struct obdo *oa,
                           struct lov_stripe_md *ea, obd_count oa_bufs,
                           struct brw_page *pgarr, struct ptlrpc_request_set *,
                           struct obd_trans_info *oti);
        int (*o_punch)(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *ea, obd_size count,
                       obd_off offset, struct obd_trans_info *oti);
        int (*o_sync)(struct lustre_handle *conn, struct obdo *oa,
                      obd_size count, obd_off offset);
        int (*o_migrate)(struct lustre_handle *conn, struct lov_stripe_md *dst,
                         struct lov_stripe_md *src, obd_size count,
                         obd_off offset);
        int (*o_copy)(struct lustre_handle *dstconn, struct lov_stripe_md *dst,
                      struct lustre_handle *srconn, struct lov_stripe_md *src,
                      obd_size count, obd_off offset, struct obd_trans_info *);
        int (*o_iterate)(struct lustre_handle *conn,
                         int (*)(obd_id, obd_gr, void *),
                         obd_id *startid, obd_gr group, void *data);
        int (*o_preprw)(int cmd, struct obd_export *exp, struct obdo *oa,
                        int objcount, struct obd_ioobj *obj,
                        int niocount, struct niobuf_remote *remote,
                        struct niobuf_local *local, struct obd_trans_info *oti);
        int (*o_commitrw)(int cmd, struct obd_export *exp, struct obdo *oa,
                          int objcount, struct obd_ioobj *obj,
                          int niocount, struct niobuf_local *local,
                          struct obd_trans_info *oti);
        int (*o_enqueue)(struct lustre_handle *conn, struct lov_stripe_md *md,
                         struct lustre_handle *parent_lock,
                         __u32 type, void *cookie, int cookielen, __u32 mode,
                         int *flags, void *cb, void *data,
                         struct lustre_handle *lockh);
        int (*o_match)(struct lustre_handle *conn, struct lov_stripe_md *md,
                         __u32 type, void *cookie, int cookielen, __u32 mode,
                         int *flags, void *data, struct lustre_handle *lockh);
        int (*o_cancel)(struct lustre_handle *, struct lov_stripe_md *md,
                        __u32 mode, struct lustre_handle *);
        int (*o_cancel_unused)(struct lustre_handle *, struct lov_stripe_md *,
                               int flags, void *opaque);
        int (*o_log_add)(struct lustre_handle *conn,
                         struct llog_handle *cathandle,
                         struct llog_trans_hdr *rec, struct lov_stripe_md *lsm,
                         struct llog_cookie *logcookies, int numcookies);
        int (*o_log_cancel)(struct lustre_handle *, struct lov_stripe_md *,
                            int count, struct llog_cookie *, int flags);
        int (*o_san_preprw)(int cmd, struct obd_export *exp,
                            struct obdo *oa, int objcount,
                            struct obd_ioobj *obj, int niocount,
                            struct niobuf_remote *remote);
        int (*o_mark_page_dirty)(struct lustre_handle *conn,
                                 struct lov_stripe_md *ea,
                                 unsigned long offset);
        int (*o_clear_dirty_pages)(struct lustre_handle *conn,
                                   struct lov_stripe_md *ea,
                                   unsigned long start,
                                   unsigned long end,
                                   unsigned long *cleared);
        int (*o_last_dirty_offset)(struct lustre_handle *conn,
                                   struct lov_stripe_md *ea,
                                   unsigned long *offset);
        void (*o_destroy_export)(struct obd_export *exp);

        /* metadata-only methods */
        int (*o_pin)(struct lustre_handle *, obd_id ino, __u32 gen, int type,
                     struct obd_client_handle *, int flag);
        int (*o_unpin)(struct lustre_handle *, struct obd_client_handle *, int);

        /* If adding ops, also update obdclass/lprocfs_status.c,
         * and include/linux/obd_class.h */
};

static inline void obd_transno_commit_cb(struct obd_device *obd, __u64 transno,
                                         int error)
{
        if (error) {
                CERROR("%s: transno "LPD64" commit error: %d\n",
                       obd->obd_name, transno, error);
                return;
        }
        CDEBUG(D_HA, "%s: transno "LPD64" committed\n",
               obd->obd_name, transno);
        if (transno > obd->obd_last_committed) {
                obd->obd_last_committed = transno;
                wake_up(&obd->obd_commit_waitq);
        }
}

#endif /* __OBD_H */
