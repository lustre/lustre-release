/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef __OBD_H
#define __OBD_H

#if defined(__linux__)
#include <linux/obd.h>
#elif defined(__APPLE__)
#include <darwin/obd.h>
#elif defined(__WINNT__)
#include <winnt/obd.h>
#else
#error Unsupported operating system.
#endif

#define IOC_OSC_TYPE         'h'
#define IOC_OSC_MIN_NR       20
#define IOC_OSC_SET_ACTIVE   _IOWR(IOC_OSC_TYPE, 21, struct obd_device *)
#define IOC_OSC_MAX_NR       50

#define IOC_MDC_TYPE         'i'
#define IOC_MDC_MIN_NR       20
/* Moved to lustre_user.h
#define IOC_MDC_LOOKUP       _IOWR(IOC_MDC_TYPE, 20, struct obd_device *)
#define IOC_MDC_GETSTRIPE    _IOWR(IOC_MDC_TYPE, 21, struct lov_mds_md *) */
#define IOC_MDC_MAX_NR       50

#include <lustre/lustre_idl.h>
#include <lustre_lib.h>
#include <lustre_export.h>
#include <lustre_quota.h>
#include <lustre_fld.h>

/* this is really local to the OSC */
struct loi_oap_pages {
        struct list_head        lop_pending;
        int                     lop_num_pending;
        struct list_head        lop_urgent;
        struct list_head        lop_pending_group;
};

struct osc_async_rc {
        int     ar_rc;
        int     ar_force_sync;
        int     ar_min_xid;
};

struct lov_oinfo {                 /* per-stripe data structure */
        __u64 loi_id;              /* object ID on the target OST */
        __u64 loi_gr;              /* object group on the target OST */
        int loi_ost_idx;           /* OST stripe index in lov_tgt_desc->tgts */
        int loi_ost_gen;           /* generation of this loi_ost_idx */

        /* used by the osc to keep track of what objects to build into rpcs */
        struct loi_oap_pages loi_read_lop;
        struct loi_oap_pages loi_write_lop;
        /* _cli_ is poorly named, it should be _ready_ */
        struct list_head loi_cli_item;
        struct list_head loi_write_item;
        struct list_head loi_read_item;

        unsigned loi_kms_valid:1;
        __u64 loi_kms;             /* known minimum size */
        struct ost_lvb loi_lvb;
        struct osc_async_rc     loi_ar;
};

static inline void loi_init(struct lov_oinfo *loi)
{
        CFS_INIT_LIST_HEAD(&loi->loi_read_lop.lop_pending);
        CFS_INIT_LIST_HEAD(&loi->loi_read_lop.lop_urgent);
        CFS_INIT_LIST_HEAD(&loi->loi_read_lop.lop_pending_group);
        CFS_INIT_LIST_HEAD(&loi->loi_write_lop.lop_pending);
        CFS_INIT_LIST_HEAD(&loi->loi_write_lop.lop_urgent);
        CFS_INIT_LIST_HEAD(&loi->loi_write_lop.lop_pending_group);
        CFS_INIT_LIST_HEAD(&loi->loi_cli_item);
        CFS_INIT_LIST_HEAD(&loi->loi_write_item);
        CFS_INIT_LIST_HEAD(&loi->loi_read_item);
}

/*extent array item for describing the joined file extent info*/
struct lov_extent {
        __u64 le_start;            /* extent start */
        __u64 le_len;              /* extent length */
        int   le_loi_idx;          /* extent #1 loi's index in lsm loi array */
        int   le_stripe_count;     /* extent stripe count*/
};

/*Lov array info for describing joined file array EA info*/
struct lov_array_info {
        struct llog_logid    lai_array_id;    /* MDS med llog object id */
        unsigned             lai_ext_count; /* number of extent count */
        struct lov_extent    *lai_ext_array; /* extent desc array */
};

struct lov_stripe_md {
        spinlock_t       lsm_lock;
        void            *lsm_lock_owner; /* debugging */

        struct {
                /* Public members. */
                __u64 lw_object_id;        /* lov object id */
                __u64 lw_object_gr;        /* lov object group */
                __u64 lw_maxbytes;         /* maximum possible file size */
                unsigned long lw_xfersize; /* optimal transfer size */

                /* LOV-private members start here -- only for use in lov/. */
                __u32 lw_magic;
                __u32 lw_stripe_size;      /* size of the stripe */
                __u32 lw_pattern;          /* striping pattern (RAID0, RAID1) */
                unsigned lw_stripe_count;  /* number of objects being striped over */
        } lsm_wire;

        struct lov_array_info *lsm_array; /*Only for joined file array info*/
        struct lov_oinfo lsm_oinfo[0];
};

#define lsm_object_id    lsm_wire.lw_object_id
#define lsm_object_gr    lsm_wire.lw_object_gr
#define lsm_maxbytes     lsm_wire.lw_maxbytes
#define lsm_xfersize     lsm_wire.lw_xfersize
#define lsm_magic        lsm_wire.lw_magic
#define lsm_stripe_size  lsm_wire.lw_stripe_size
#define lsm_pattern      lsm_wire.lw_pattern
#define lsm_stripe_count lsm_wire.lw_stripe_count

/* compare all relevant fields. */
static inline int lov_stripe_md_cmp(struct lov_stripe_md *m1,
                                    struct lov_stripe_md *m2)
{
        /*
         * ->lsm_wire contains padding, but it should be zeroed out during
         * allocation.
         */
        return memcmp(&m1->lsm_wire, &m2->lsm_wire, sizeof m1->lsm_wire);
}

void lov_stripe_lock(struct lov_stripe_md *md);
void lov_stripe_unlock(struct lov_stripe_md *md);

struct obd_type {
        struct list_head typ_chain;
        struct obd_ops *typ_dt_ops;
        struct md_ops *typ_md_ops;
        struct proc_dir_entry *typ_procroot;
        char *typ_name;
        int  typ_refcnt;
        struct lu_device_type *typ_lu;
};

struct brw_page {
        obd_off  off;
        cfs_page_t *pg;
        int count;
        obd_flag flag;
};

enum async_flags {
        ASYNC_READY = 0x1, /* ap_make_ready will not be called before this
                              page is added to an rpc */
        ASYNC_URGENT = 0x2, /* page must be put into an RPC before return */
        ASYNC_COUNT_STABLE = 0x4, /* ap_refresh_count will not be called
                                     to give the caller a chance to update
                                     or cancel the size of the io */
        ASYNC_GROUP_SYNC = 0x8,  /* ap_completion will not be called, instead
                                    the page is accounted for in the
                                    obd_io_group given to
                                    obd_queue_group_io */
};

struct obd_async_page_ops {
        int  (*ap_make_ready)(void *data, int cmd);
        int  (*ap_refresh_count)(void *data, int cmd);
        void (*ap_fill_obdo)(void *data, int cmd, struct obdo *oa);
        void (*ap_completion)(void *data, int cmd, struct obdo *oa, int rc);
};

/* the `oig' is passed down from a caller of obd rw methods.  the callee
 * records enough state such that the caller can sleep on the oig and
 * be woken when all the callees have finished their work */
struct obd_io_group {
        spinlock_t      oig_lock;
        atomic_t        oig_refcount;
        int             oig_pending;
        int             oig_rc;
        struct list_head oig_occ_list;
        cfs_waitq_t     oig_waitq;
};

/* the oig callback context lets the callee of obd rw methods register
 * for callbacks from the caller. */
struct oig_callback_context {
        struct list_head occ_oig_item;
        /* called when the caller has received a signal while sleeping.
         * callees of this method are encouraged to abort their state
         * in the oig.  This may be called multiple times. */
        void (*occ_interrupted)(struct oig_callback_context *occ);
        unsigned int interrupted:1;
};

/* if we find more consumers this could be generalized */
#define OBD_HIST_MAX 32
struct obd_histogram {
        spinlock_t      oh_lock;
        unsigned long   oh_buckets[OBD_HIST_MAX];
};

/* Individual type definitions */

struct ost_server_data;

/* hold common fields for "target" device */
struct obd_device_target {
        struct super_block       *obt_sb;
        atomic_t                  obt_quotachecking;
        struct lustre_quota_ctxt  obt_qctxt;
};

#define FILTER_GROUP_LLOG 1
#define FILTER_GROUP_ECHO 2

struct filter_ext {
        __u64                fe_start;
        __u64                fe_end;
};

struct filter_obd {
        /* NB this field MUST be first */
        struct obd_device_target fo_obt;
        const char          *fo_fstype;
        struct vfsmount     *fo_vfsmnt;
        cfs_dentry_t        *fo_dentry_O;
        cfs_dentry_t       **fo_dentry_O_groups;
        cfs_dentry_t       **fo_dentry_O_sub;
        spinlock_t           fo_objidlock;      /* protect fo_lastobjid */
        spinlock_t           fo_translock;      /* protect fsd_last_transno */
        struct file         *fo_rcvd_filp;
        struct file         *fo_health_check_filp;
        struct lr_server_data *fo_fsd;
        unsigned long       *fo_last_rcvd_slots;
        __u64                fo_mount_count;

        int                  fo_destroy_in_progress;
        struct semaphore     fo_create_lock;

        struct list_head     fo_export_list;
        int                  fo_subdir_count;

        obd_size             fo_tot_dirty;      /* protected by obd_osfs_lock */
        obd_size             fo_tot_granted;    /* all values in bytes */
        obd_size             fo_tot_pending;

        obd_size             fo_readcache_max_filesize;

        struct obd_import   *fo_mdc_imp;
        struct obd_uuid      fo_mdc_uuid;
        struct lustre_handle fo_mdc_conn;
        struct file        **fo_last_objid_files;
        __u64               *fo_last_objids; /* last created objid for groups,
                                              * protected by fo_objidlock */

        struct semaphore     fo_alloc_lock;

        spinlock_t fo_stats_lock;
        int fo_r_in_flight; /* protected by fo_stats_lock */
        int fo_w_in_flight; /* protected by fo_stats_lock */

        /*
         * per-filter pool of kiobuf's allocated by filter_common_setup() and
         * torn down by filter_cleanup(). Contains OST_NUM_THREADS elements of
         * which ->fo_iobuf_count were allocated.
         *
         * This pool contains kiobuf used by
         * filter_{prep,commit}rw_{read,write}() and is shared by all OST
         * threads.
         *
         * Locking: none, each OST thread uses only one element, determined by
         * its "ordinal number", ->t_id.
         */
        struct filter_iobuf    **fo_iobuf_pool;
        int                      fo_iobuf_count;

        struct obd_histogram     fo_r_pages;
        struct obd_histogram     fo_w_pages;
        struct obd_histogram     fo_read_rpc_hist;
        struct obd_histogram     fo_write_rpc_hist;
        struct obd_histogram     fo_r_io_time;
        struct obd_histogram     fo_w_io_time;
        struct obd_histogram     fo_r_discont_pages;
        struct obd_histogram     fo_w_discont_pages;
        struct obd_histogram     fo_r_discont_blocks;
        struct obd_histogram     fo_w_discont_blocks;
        struct obd_histogram     fo_r_disk_iosize;
        struct obd_histogram     fo_w_disk_iosize;

        struct lustre_quota_ctxt fo_quota_ctxt;
        spinlock_t               fo_quotacheck_lock;
        atomic_t                 fo_quotachecking;
};

#define OSC_MAX_RIF_DEFAULT       8
#define OSC_MAX_RIF_MAX         256
#define OSC_MAX_DIRTY_DEFAULT  (OSC_MAX_RIF_DEFAULT * 4)
#define OSC_MAX_DIRTY_MB_MAX   2048     /* totally arbitrary */

struct mdc_rpc_lock;
struct obd_import;
struct client_obd {
        struct semaphore         cl_sem;
        struct obd_uuid          cl_target_uuid;
        struct obd_import       *cl_import; /* ptlrpc connection state */
        int                      cl_conn_count;
        /* max_mds_easize is purely a performance thing so we don't have to
         * call obd_size_diskmd() all the time. */
        int                      cl_default_mds_easize;
        int                      cl_max_mds_easize;
        int                      cl_max_mds_cookiesize;
        kdev_t                   cl_sandev;

        //struct llog_canceld_ctxt *cl_llcd; /* it's included by obd_llog_ctxt */
        void                    *cl_llcd_offset;

        /* the grant values are protected by loi_list_lock below */
        long                     cl_dirty;         /* all _dirty_ in bytes */
        long                     cl_dirty_max;     /* allowed w/o rpc */
        long                     cl_avail_grant;   /* bytes of credit for ost */
        long                     cl_lost_grant;    /* lost credits (trunc) */
        struct list_head         cl_cache_waiters; /* waiting for cache/grant */

        /* keep track of objects that have lois that contain pages which
         * have been queued for async brw.  this lock also protects the
         * lists of osc_client_pages that hang off of the loi */
        /*
         * ->cl_loi_list_lock protects consistency of
         * ->cl_loi_{ready,read,write}_list. ->ap_make_ready() and
         * ->ap_completion() call-backs are executed under this lock. As we
         * cannot guarantee that these call-backs never block on all platforms
         * (as a matter of fact they do block on Mac OS X), type of
         * ->cl_loi_list_lock is platform dependent: it's a spin-lock on Linux
         * and blocking mutex on Mac OS X. (Alternative is to make this lock
         * blocking everywhere, but we don't want to slow down fast-path of
         * our main platform.)
         *
         * Exact type of ->cl_loi_list_lock is defined in arch/obd.h together
         * with client_obd_list_{un,}lock() and
         * client_obd_list_lock_{init,done}() functions.
         */
        client_obd_lock_t        cl_loi_list_lock;
        struct list_head         cl_loi_ready_list;
        struct list_head         cl_loi_write_list;
        struct list_head         cl_loi_read_list;
        int                      cl_r_in_flight;
        int                      cl_w_in_flight;
        /* just a sum of the loi/lop pending numbers to be exported by /proc */
        int                      cl_pending_w_pages;
        int                      cl_pending_r_pages;
        int                      cl_max_pages_per_rpc;
        int                      cl_max_rpcs_in_flight;
        struct obd_histogram     cl_read_rpc_hist;
        struct obd_histogram     cl_write_rpc_hist;
        struct obd_histogram     cl_read_page_hist;
        struct obd_histogram     cl_write_page_hist;
        struct obd_histogram     cl_read_offset_hist;
        struct obd_histogram     cl_write_offset_hist;

        struct mdc_rpc_lock     *cl_rpc_lock;
        struct mdc_rpc_lock     *cl_setattr_lock;
        struct osc_creator       cl_oscc;

        /* mgc datastruct */
        struct semaphore         cl_mgc_sem;
        struct vfsmount         *cl_mgc_vfsmnt;
        struct dentry           *cl_mgc_configs_dir;
        atomic_t                 cl_mgc_refcount;
        struct obd_export       *cl_mgc_mgsexp;

        /* Flags section */
        unsigned int             cl_checksum:1; /* debug checksums */

        /* also protected by the poorly named _loi_list_lock lock above */
        struct osc_async_rc      cl_ar;

        /* used by quotacheck */
        int                      cl_qchk_stat; /* quotacheck stat of the peer */

        /* sequence manager */
        struct lu_client_seq    *cl_seq;
};
#define obd2cli_tgt(obd) ((char *)(obd)->u.cli.cl_target_uuid.uuid)

#define CL_NOT_QUOTACHECKED 1   /* client->cl_qchk_stat init value */

struct mgs_obd {
        struct ptlrpc_service           *mgs_service;
        struct vfsmount                 *mgs_vfsmnt;
        struct super_block              *mgs_sb;
        struct dentry                   *mgs_configs_dir;
        struct dentry                   *mgs_fid_de;
        struct list_head                 mgs_fs_db_list;
        struct semaphore                 mgs_sem;
};

struct md_lov_info;

struct md_lov_ops {
        int (*ml_read_objids)(struct obd_device *obd, struct md_lov_info *mli, 
                              const void *ctxt);
        int (*ml_write_objids)(struct obd_device *obd, struct md_lov_info *mli,
                               const void *ctxt);
};
struct md_lov_info {
        struct obd_device               *md_lov_obd; /* XXX lov_obd */
        struct obd_uuid                  md_lov_uuid;
        struct obd_export               *md_lov_exp; /* XXX lov_exp */
        struct lov_desc                  md_lov_desc;
        obd_id                          *md_lov_objids;
        int                              md_lov_objids_size;
        __u32                            md_lov_objids_in_file;
        unsigned int                     md_lov_objids_dirty:1;
        int                              md_lov_nextid_set;
        void                            *md_lov_objid_obj;
        struct lu_fid                    md_lov_objid_fid;
        unsigned long                    md_lov_objids_valid:1;
        int                              md_lov_max_mdsize;
        int                              md_lov_max_cookiesize;
        struct semaphore                 md_lov_orphan_recovery_sem;
        struct md_lov_ops                *md_lov_ops;
};

#define mds_osc_obd             mds_lov_info.md_lov_obd
#define mds_lov_uuid            mds_lov_info.md_lov_uuid
#define mds_osc_exp             mds_lov_info.md_lov_exp
#define mds_lov_desc            mds_lov_info.md_lov_desc
#define mds_lov_objids          mds_lov_info.md_lov_objids
#define mds_lov_objids_size     mds_lov_info.md_lov_objids_size
#define mds_lov_objids_in_file  mds_lov_info.md_lov_objids_in_file
#define mds_lov_objids_dirty    mds_lov_info.md_lov_objids_dirty
#define mds_lov_nextid_set      mds_lov_info.md_lov_nextid_set
#define mds_lov_objid_filp      mds_lov_info.md_lov_objid_obj
#define mds_lov_objids_valid    mds_lov_info.md_lov_objids_valid
#define mds_max_mdsize          mds_lov_info.md_lov_max_mdsize
#define mds_max_cookiesize      mds_lov_info.md_lov_max_cookiesize
#define mds_orphan_recovery_sem mds_lov_info.md_lov_orphan_recovery_sem

struct mds_obd {
        /* NB this field MUST be first */
        struct obd_device_target         mds_obt;
        struct ptlrpc_service           *mds_service;
        struct ptlrpc_service           *mds_setattr_service;
        struct ptlrpc_service           *mds_readpage_service;
        struct vfsmount                 *mds_vfsmnt;
        cfs_dentry_t                    *mds_fid_de;
        struct file                     *mds_rcvd_filp;
        spinlock_t                       mds_transno_lock;
        __u64                            mds_last_transno;
        __u64                            mds_mount_count;
        __u64                            mds_io_epoch;
        unsigned long                    mds_atime_diff;
        struct semaphore                 mds_epoch_sem;
        struct ll_fid                    mds_rootfid;
        struct lr_server_data           *mds_server_data;
        cfs_dentry_t                    *mds_pending_dir;
        cfs_dentry_t                    *mds_logs_dir;
        cfs_dentry_t                    *mds_objects_dir;
        struct llog_handle              *mds_cfg_llh;
//        struct llog_handle              *mds_catalog;
        struct md_lov_info              mds_lov_info;
        char                            *mds_profile;
        struct file                     *mds_health_check_filp;
        unsigned long                   *mds_client_bitmap;
        struct upcall_cache             *mds_group_hash;

        struct lustre_quota_info         mds_quota_info;
        struct semaphore                 mds_qonoff_sem;
        struct semaphore                 mds_health_sem;
        unsigned long                    mds_fl_user_xattr:1,
                                         mds_fl_acl:1;
};

struct echo_obd {
        struct obdo          eo_oa;
        spinlock_t           eo_lock;
        __u64                eo_lastino;
        struct lustre_handle eo_nl_lock;
        atomic_t             eo_prep;
};

struct ost_obd {
        struct ptlrpc_service *ost_service;
        struct ptlrpc_service *ost_create_service;
        struct ptlrpc_service *ost_io_service;
        struct semaphore       ost_health_sem;
};

struct echo_client_obd {
        struct obd_export   *ec_exp;   /* the local connection to osc/lov */
        spinlock_t           ec_lock;
        struct list_head     ec_objects;
        int                  ec_nstripes;
        __u64                ec_unique;
};

struct lov_tgt_desc {
        struct obd_uuid          uuid;
        __u32                    ltd_gen;
        struct obd_export       *ltd_exp;
        unsigned int             active:1, /* is this target up for requests */
                                 reap:1;   /* should this target be deleted */
        int                      index;  /* index of target array in lov_obd */
        struct list_head         qos_bavail_list; /* link entry to lov_obd */
};

struct lov_obd {
        struct semaphore lov_lock;
        atomic_t refcount;
        struct lov_desc desc;
        struct obd_connect_data ocd;
        int bufsize;
        int connects;
        int death_row;      /* Do we have tgts scheduled to be deleted?
                               (Make this a linked list?) */
        struct list_head qos_bavail_list; /* tgts list, sorted by available
                                             space, protected by lov_lock */
        struct lov_tgt_desc *tgts;
};

struct lmv_tgt_desc {
        struct obd_uuid         uuid;
        struct obd_export       *ltd_exp;
        int                     active;   /* is this target up for requests */
        int                     idx;
};

struct lmv_obd {
        int                     refcount;
        struct lu_client_fld    lmv_fld;
        spinlock_t              lmv_lock;
        struct lmv_desc         desc;
        struct obd_uuid         cluuid;
        struct obd_export       *exp;

        int                     connected;
        int                     max_easize;
        int                     max_def_easize;
        int                     max_cookiesize;
        int                     server_timeout;
        struct semaphore        init_sem;
        
        struct lmv_tgt_desc     *tgts;
        int                     tgts_size;

        struct obd_connect_data *datas;
        int                     datas_size;

        struct obd_connect_data conn_data;
};

struct niobuf_local {
        __u64 offset;
        __u32 len;
        __u32 flags;
        cfs_page_t    *page;
        cfs_dentry_t  *dentry;
        int lnb_grant_used;
        int rc;
};

#define LUSTRE_OPC_MKDIR     (1 << 0)
#define LUSTRE_OPC_SYMLINK   (1 << 1)
#define LUSTRE_OPC_MKNOD     (1 << 2)
#define LUSTRE_OPC_CREATE    (1 << 3)
        
struct lu_placement_hint {
        struct qstr *ph_pname;
        struct qstr *ph_cname;
        int          ph_opc;
};

#define LUSTRE_FLD_NAME  "fld"
#define LUSTRE_SEQ_NAME  "seq"

/* device types (not names--FIXME) */
/* FIXME all the references to these defines need to be updated */
#define LUSTRE_MDS_NAME  "mds"
#define LUSTRE_MDT_NAME  "mdt"

/* new MDS layers. Prototype */
#define LUSTRE_MDT0_NAME "mdt0"
#define LUSTRE_CMM0_NAME "cmm0"
#define LUSTRE_MDD0_NAME "mdd0"
#define LUSTRE_OSD0_NAME "osd0"
#define LUSTRE_MDC0_NAME "mdc0"

#define LUSTRE_MDC_NAME  "mdc"
#define LUSTRE_LOV_NAME  "lov"
#define LUSTRE_LMV_NAME  "lmv"

/* FIXME just the names need to be changed */
#define LUSTRE_OSS_NAME "ost"       /* FIXME oss */
#define LUSTRE_OST_NAME "obdfilter" /* FIXME ost */
#define LUSTRE_OSTSAN_NAME "sanobdfilter"

#define LUSTRE_OSC_NAME "osc"
#define LUSTRE_FILTER_NAME "filter"
#define LUSTRE_SANOSC_NAME "sanosc"
#define LUSTRE_SANOST_NAME "sanost"
#define LUSTRE_MGS_NAME "mgs"
#define LUSTRE_MGC_NAME "mgc"

#define LUSTRE_ECHO_NAME        "obdecho"
#define LUSTRE_ECHO_CLIENT_NAME "echo_client"

#define LUSTRE_MGS_OBDNAME "MGS"
#define LUSTRE_MGC_OBDNAME "MGC"

/* Don't conflict with on-wire flags OBD_BRW_WRITE, etc */
#define N_LOCAL_TEMP_PAGE 0x10000000

struct obd_trans_info {
        __u64                    oti_transno;
        __u64                   *oti_objid;
        /* Only used on the server side for tracking acks. */
        struct oti_req_ack_lock {
                struct lustre_handle lock;
                __u32                mode;
        }                        oti_ack_locks[4];
        void                    *oti_handle;
        struct llog_cookie       oti_onecookie;
        struct llog_cookie      *oti_logcookies;
        int                      oti_numcookies;

        /* initial thread handling transaction */
        int                      oti_thread_id;
};

static inline void oti_init(struct obd_trans_info *oti,
                            struct ptlrpc_request *req)
{
        if (oti == NULL)
                return;
        memset(oti, 0, sizeof *oti);

        if (req == NULL)
                return;

        if (req->rq_repmsg && req->rq_reqmsg != 0)
                oti->oti_transno = req->rq_repmsg->transno;
        oti->oti_thread_id = req->rq_svc_thread ? req->rq_svc_thread->t_id : -1;
}

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

/* llog contexts */
enum llog_ctxt_id {
        LLOG_CONFIG_ORIG_CTXT  =  0,
        LLOG_CONFIG_REPL_CTXT  =  1,
        LLOG_MDS_OST_ORIG_CTXT =  2,
        LLOG_MDS_OST_REPL_CTXT =  3,
        LLOG_SIZE_ORIG_CTXT    =  4,
        LLOG_SIZE_REPL_CTXT    =  5,
        LLOG_MD_ORIG_CTXT      =  6,
        LLOG_MD_REPL_CTXT      =  7,
        LLOG_RD1_ORIG_CTXT     =  8,
        LLOG_RD1_REPL_CTXT     =  9,
        LLOG_TEST_ORIG_CTXT    = 10,
        LLOG_TEST_REPL_CTXT    = 11,
        LLOG_LOVEA_ORIG_CTXT   = 12,
        LLOG_LOVEA_REPL_CTXT   = 13,
        LLOG_MAX_CTXTS
};

/*
 * Events signalled through obd_notify() upcall-chain.
 */
enum obd_notify_event {
        /* Device activated */
        OBD_NOTIFY_ACTIVE,
        /* Device deactivated */
        OBD_NOTIFY_INACTIVE,
        /* Connect data for import were changed */
        OBD_NOTIFY_OCD,
        /* Sync request */
        OBD_NOTIFY_SYNC_NONBLOCK,
        OBD_NOTIFY_SYNC
};

#include <lu_object.h>
/*
 * Data structure used to pass obd_notify()-event to non-obd listeners (llite
 * and liblustre being main examples).
 */
struct obd_notify_upcall {
        int (*onu_upcall)(struct obd_device *host, struct obd_device *watched,
                          enum obd_notify_event ev, void *owner);
        /* Opaque datum supplied by upper layer listener */
        void *onu_owner;
};

/* corresponds to one of the obd's */
struct obd_device {
        struct obd_type        *obd_type;
        /* common and UUID name of this device */
        char                   *obd_name;
        struct obd_uuid         obd_uuid;

        struct lu_device       *obd_lu_dev;

        int                     obd_minor;
        unsigned int obd_attached:1, obd_set_up:1, obd_recovering:1,
                obd_abort_recovery:1, obd_replayable:1, obd_no_transno:1,
                obd_no_recov:1, obd_stopping:1, obd_starting:1,
                obd_force:1, obd_fail:1, obd_async_recov:1;
        atomic_t obd_refcount;
        cfs_waitq_t             obd_refcount_waitq;
        cfs_proc_dir_entry_t  *obd_proc_entry;
        struct list_head        obd_exports;
        int                     obd_num_exports;
        struct ldlm_namespace  *obd_namespace;
        struct ptlrpc_client    obd_ldlm_client; /* XXX OST/MDS only */
        /* a spinlock is OK for what we do now, may need a semaphore later */
        spinlock_t              obd_dev_lock;
        __u64                   obd_last_committed;
        struct fsfilt_operations *obd_fsops;
        spinlock_t              obd_osfs_lock;
        struct obd_statfs       obd_osfs;       /* locked by obd_osfs_lock */
        cfs_time_t              obd_osfs_age;   
        struct lvfs_run_ctxt    obd_lvfs_ctxt;
        struct llog_ctxt        *obd_llog_ctxt[LLOG_MAX_CTXTS];
        struct obd_device       *obd_observer;
        struct obd_notify_upcall obd_upcall;
        struct obd_export       *obd_self_export;
        /* list of exports in LRU order, for ping evictor, with obd_dev_lock */
        struct list_head        obd_exports_timed;
        time_t                  obd_eviction_timer; /* for ping evictor */

        /* XXX encapsulate all this recovery data into one struct */
        svc_handler_t                    obd_recovery_handler;
        int                              obd_max_recoverable_clients;
        int                              obd_connected_clients;
        int                              obd_recoverable_clients;
        spinlock_t                       obd_processing_task_lock;
        pid_t                            obd_processing_task;
        __u64                            obd_next_recovery_transno;
        int                              obd_replayed_requests;
        int                              obd_requests_queued_for_recovery;
        cfs_waitq_t                      obd_next_transno_waitq;
        struct list_head                 obd_uncommitted_replies;
        spinlock_t                       obd_uncommitted_replies_lock;
        cfs_timer_t                      obd_recovery_timer;
        struct list_head                 obd_recovery_queue;
        struct list_head                 obd_delayed_reply_queue;
        time_t                           obd_recovery_start;
        time_t                           obd_recovery_end;

        union {
                struct obd_device_target obt;
                struct filter_obd filter;
                struct mds_obd mds;
                struct client_obd cli;
                struct ost_obd ost;
                struct echo_client_obd echo_client;
                struct echo_obd echo;
                struct lov_obd lov;
                struct lmv_obd lmv;
                struct mgs_obd mgs;
        } u;
        /* Fields used by LProcFS */
        unsigned int           obd_cntr_base;
        struct lprocfs_stats  *obd_stats;

        unsigned int           md_cntr_base;
        struct lprocfs_stats  *md_stats;
    
        cfs_proc_dir_entry_t  *obd_svc_procroot;
        struct lprocfs_stats  *obd_svc_stats;
};

#define OBD_OPT_FORCE           0x0001
#define OBD_OPT_FAILOVER        0x0002

#define OBD_LLOG_FL_SENDNOW     0x0001

enum obd_cleanup_stage {
/* Special case hack for MDS LOVs */
        OBD_CLEANUP_EARLY,
/* Precleanup stage 1, we must make sure all exports (other than the
   self-export) get destroyed. */
        OBD_CLEANUP_EXPORTS,
/* Precleanup stage 2,  do other type-specific cleanup requiring the
   self-export. */
        OBD_CLEANUP_SELF_EXP,
/* FIXME we should eliminate the "precleanup" function and make them stages
   of the "cleanup" function. */
        OBD_CLEANUP_OBD,
};

/* get/set_info keys */
#define KEY_MDS_CONN "mds_conn"
#define KEY_NEXT_ID  "next_id"
#define KEY_LOVDESC  "lovdesc"
#define KEY_INIT_RECOV "initial_recov"
#define KEY_INIT_RECOV_BACKUP "init_recov_bk"

struct obd_ops {
        struct module *o_owner;
        int (*o_iocontrol)(unsigned int cmd, struct obd_export *exp, int len,
                           void *karg, void *uarg);
        int (*o_get_info)(struct obd_export *, __u32 keylen, void *key,
                          __u32 *vallen, void *val);
        int (*o_set_info_async)(struct obd_export *, __u32 keylen, void *key,
                                __u32 vallen, void *val,
                                struct ptlrpc_request_set *set);
        int (*o_attach)(struct obd_device *dev, obd_count len, void *data);
        int (*o_detach)(struct obd_device *dev);
        int (*o_setup) (struct obd_device *dev, struct lustre_cfg *cfg);
        int (*o_precleanup)(struct obd_device *dev,
                            enum obd_cleanup_stage cleanup_stage);
        int (*o_cleanup)(struct obd_device *dev);
        int (*o_process_config)(struct obd_device *dev, obd_count len,
                                void *data);
        int (*o_postrecov)(struct obd_device *dev);
        int (*o_add_conn)(struct obd_import *imp, struct obd_uuid *uuid,
                          int priority);
        int (*o_del_conn)(struct obd_import *imp, struct obd_uuid *uuid);
        /* connect to the target device with given connection
         * data. @ocd->ocd_connect_flags is modified to reflect flags actually
         * granted by the target, which are guaranteed to be a subset of flags
         * asked for. If @ocd == NULL, use default parameters. */
        int (*o_connect)(struct lustre_handle *conn, struct obd_device *src,
                         struct obd_uuid *cluuid, struct obd_connect_data *ocd);
        int (*o_reconnect)(struct obd_export *exp, struct obd_device *src,
                           struct obd_uuid *cluuid,
                           struct obd_connect_data *ocd);
        int (*o_disconnect)(struct obd_export *exp);

        /* maybe later these should be moved into separate fid_ops */
        int (*o_fid_init)(struct obd_export *exp);
        int (*o_fid_fini)(struct obd_export *exp);

        int (*o_fid_alloc)(struct obd_export *exp, struct lu_fid *fid,
                           struct lu_placement_hint *hint);
        
        int (*o_fid_delete)(struct obd_export *exp, struct lu_fid *fid);
        
        int (*o_statfs)(struct obd_device *obd, struct obd_statfs *osfs,
                        unsigned long max_age);
        int (*o_packmd)(struct obd_export *exp, struct lov_mds_md **disk_tgt,
                        struct lov_stripe_md *mem_src);
        int (*o_unpackmd)(struct obd_export *exp,struct lov_stripe_md **mem_tgt,
                          struct lov_mds_md *disk_src, int disk_len);
        int (*o_checkmd)(struct obd_export *exp, struct obd_export *md_exp,
                         struct lov_stripe_md *mem_tgt);
        int (*o_preallocate)(struct lustre_handle *, obd_count *req,
                             obd_id *ids);
        int (*o_create)(struct obd_export *exp,  struct obdo *oa,
                        struct lov_stripe_md **ea, struct obd_trans_info *oti);
        int (*o_destroy)(struct obd_export *exp, struct obdo *oa,
                         struct lov_stripe_md *ea, struct obd_trans_info *oti,
                         struct obd_export *md_exp);
        int (*o_setattr)(struct obd_export *exp, struct obdo *oa,
                         struct lov_stripe_md *ea, struct obd_trans_info *oti);
        int (*o_setattr_async)(struct obd_export *exp, struct obdo *oa,
                         struct lov_stripe_md *ea, struct obd_trans_info *oti);
        int (*o_getattr)(struct obd_export *exp, struct obdo *oa,
                         struct lov_stripe_md *ea);
        int (*o_getattr_async)(struct obd_export *exp, struct obdo *oa,
                               struct lov_stripe_md *ea,
                               struct ptlrpc_request_set *set);
        int (*o_brw)(int rw, struct obd_export *exp, struct obdo *oa,
                     struct lov_stripe_md *ea, obd_count oa_bufs,
                     struct brw_page *pgarr, struct obd_trans_info *oti);
        int (*o_brw_async)(int rw, struct obd_export *exp, struct obdo *oa,
                           struct lov_stripe_md *ea, obd_count oa_bufs,
                           struct brw_page *pgarr, struct ptlrpc_request_set *,
                           struct obd_trans_info *oti);
        int (*o_prep_async_page)(struct obd_export *exp,
                                 struct lov_stripe_md *lsm,
                                 struct lov_oinfo *loi,
                                 struct page *page, obd_off offset,
                                 struct obd_async_page_ops *ops, void *data,
                                 void **res);
        int (*o_queue_async_io)(struct obd_export *exp,
                                struct lov_stripe_md *lsm,
                                struct lov_oinfo *loi, void *cookie,
                                int cmd, obd_off off, int count,
                                obd_flag brw_flags, obd_flag async_flags);
        int (*o_queue_group_io)(struct obd_export *exp,
                                struct lov_stripe_md *lsm,
                                struct lov_oinfo *loi,
                                struct obd_io_group *oig,
                                void *cookie, int cmd, obd_off off, int count,
                                obd_flag brw_flags, obd_flag async_flags);
        int (*o_trigger_group_io)(struct obd_export *exp,
                                  struct lov_stripe_md *lsm,
                                  struct lov_oinfo *loi,
                                  struct obd_io_group *oig);
        int (*o_set_async_flags)(struct obd_export *exp,
                                struct lov_stripe_md *lsm,
                                struct lov_oinfo *loi, void *cookie,
                                obd_flag async_flags);
        int (*o_teardown_async_page)(struct obd_export *exp,
                                     struct lov_stripe_md *lsm,
                                     struct lov_oinfo *loi, void *cookie);
        int (*o_merge_lvb)(struct obd_export *exp, struct lov_stripe_md *lsm,
                           struct ost_lvb *lvb, int kms_only);
        int (*o_adjust_kms)(struct obd_export *exp, struct lov_stripe_md *lsm,
                            obd_off size, int shrink);
        int (*o_punch)(struct obd_export *exp, struct obdo *oa,
                       struct lov_stripe_md *ea, obd_size start,
                       obd_size end, struct obd_trans_info *oti);
        int (*o_sync)(struct obd_export *exp, struct obdo *oa,
                      struct lov_stripe_md *ea, obd_size start, obd_size end);
        int (*o_migrate)(struct lustre_handle *conn, struct lov_stripe_md *dst,
                         struct lov_stripe_md *src, obd_size start,
                         obd_size end, struct obd_trans_info *oti);
        int (*o_copy)(struct lustre_handle *dstconn, struct lov_stripe_md *dst,
                      struct lustre_handle *srconn, struct lov_stripe_md *src,
                      obd_size start, obd_size end, struct obd_trans_info *);
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
                          struct obd_trans_info *oti, int rc);
        int (*o_enqueue)(struct obd_export *, struct lov_stripe_md *,
                         __u32 type, ldlm_policy_data_t *, __u32 mode,
                         int *flags, void *bl_cb, void *cp_cb, void *gl_cb,
                         void *data, __u32 lvb_len, void *lvb_swabber,
                         struct lustre_handle *lockh);
        int (*o_match)(struct obd_export *, struct lov_stripe_md *, __u32 type,
                       ldlm_policy_data_t *, __u32 mode, int *flags, void *data,
                       struct lustre_handle *lockh);
        int (*o_change_cbdata)(struct obd_export *, struct lov_stripe_md *,
                               ldlm_iterator_t it, void *data);
        int (*o_cancel)(struct obd_export *, struct lov_stripe_md *md,
                        __u32 mode, struct lustre_handle *);
        int (*o_cancel_unused)(struct obd_export *, struct lov_stripe_md *,
                               int flags, void *opaque);
        int (*o_join_lru)(struct obd_export *, struct lov_stripe_md *,
                         int join);
        int (*o_san_preprw)(int cmd, struct obd_export *exp,
                            struct obdo *oa, int objcount,
                            struct obd_ioobj *obj, int niocount,
                            struct niobuf_remote *remote);
        int (*o_init_export)(struct obd_export *exp);
        int (*o_destroy_export)(struct obd_export *exp);

        /* llog related obd_methods */
        int (*o_llog_init)(struct obd_device *obd, struct obd_device *disk_obd,
                           int count, struct llog_catid *logid);
        int (*o_llog_finish)(struct obd_device *obd, int count);

        /* metadata-only methods */
        int (*o_pin)(struct obd_export *, struct lu_fid *fid,
                     struct obd_client_handle *, int flag);
        int (*o_unpin)(struct obd_export *, struct obd_client_handle *, int);

        int (*o_import_event)(struct obd_device *, struct obd_import *,
                              enum obd_import_event);

        int (*o_notify)(struct obd_device *obd, struct obd_device *watched,
                        enum obd_notify_event ev, void *data);

        int (*o_health_check)(struct obd_device *);

        /* quota methods */
        int (*o_quotacheck)(struct obd_export *, struct obd_quotactl *);
        int (*o_quotactl)(struct obd_export *, struct obd_quotactl *);

        /*
         * NOTE: If adding ops, add another LPROCFS_OBD_OP_INIT() line
         * to lprocfs_alloc_obd_stats() in obdclass/lprocfs_status.c.
         * Also, add a wrapper function in include/linux/obd_class.h.
         *
         * Also note that if you add it to the END, you also have to change
         * the num_stats calculation.
         *
         */
};

struct md_ops {
        int (*m_getstatus)(struct obd_export *, struct lu_fid *);
        int (*m_change_cbdata)(struct obd_export *, struct lu_fid *,
                               ldlm_iterator_t, void *);
        int (*m_close)(struct obd_export *, struct md_op_data *,
                       struct obd_client_handle *, struct ptlrpc_request **);
        int (*m_create)(struct obd_export *, struct md_op_data *,
                        const void *, int, int, __u32, __u32, __u32,
                        __u64, struct ptlrpc_request **);
        int (*m_done_writing)(struct obd_export *, struct md_op_data *);
        int (*m_enqueue)(struct obd_export *, int, struct lookup_intent *,
                         int, struct md_op_data *, struct lustre_handle *,
                         void *, int, ldlm_completion_callback,
                         ldlm_blocking_callback, void *, int);
        int (*m_getattr)(struct obd_export *, struct lu_fid *,
                         obd_valid, int, struct ptlrpc_request **);
        int (*m_getattr_name)(struct obd_export *, struct lu_fid *,
                              const char *, int, obd_valid,
                              int, struct ptlrpc_request **);
        int (*m_intent_lock)(struct obd_export *, struct md_op_data *,
                             void *, int, struct lookup_intent *, int,
                             struct ptlrpc_request **,
                             ldlm_blocking_callback, int);
        int (*m_link)(struct obd_export *, struct md_op_data *,
                      struct ptlrpc_request **);
        int (*m_rename)(struct obd_export *, struct md_op_data *,
                        const char *, int, const char *, int,
                        struct ptlrpc_request **);
        int (*m_setattr)(struct obd_export *, struct md_op_data *,
                         struct iattr *, void *, int , void *, int,
                         struct ptlrpc_request **);
        int (*m_sync)(struct obd_export *, struct lu_fid *,
                      struct ptlrpc_request **);
        int (*m_readpage)(struct obd_export *, struct lu_fid *,
                          __u64, struct page *, struct ptlrpc_request **);
        int (*m_unlink)(struct obd_export *, struct md_op_data *,
                        struct ptlrpc_request **);

        int (*m_setxattr)(struct obd_export *, struct lu_fid *,
                          obd_valid, const char *, const char *,
                          int, int, int, struct ptlrpc_request **);

        int (*m_getxattr)(struct obd_export *, struct lu_fid *,
                          obd_valid, const char *, const char *,
                          int, int, int, struct ptlrpc_request **);

        int (*m_init_ea_size)(struct obd_export *, int, int, int);
        
        int (*m_get_lustre_md)(struct obd_export *, struct ptlrpc_request *,
                               int, struct obd_export *, struct lustre_md *);
        
        int (*m_free_lustre_md)(struct obd_export *, struct lustre_md *);
        
        int (*m_set_open_replay_data)(struct obd_export *,
                                      struct obd_client_handle *,
                                      struct ptlrpc_request *);
        int (*m_clear_open_replay_data)(struct obd_export *,
                                        struct obd_client_handle *);
        int (*m_set_lock_data)(struct obd_export *, __u64 *, void *);
        
        int (*m_lock_match)(struct obd_export *, int, struct lu_fid *,
                            ldlm_type_t, ldlm_policy_data_t *, ldlm_mode_t,
                            struct lustre_handle *);
                
        int (*m_cancel_unused)(struct obd_export *, struct lu_fid *,
                               int flags, void *opaque);

        /*
         * NOTE: If adding ops, add another LPROCFS_MD_OP_INIT() line to
         * lprocfs_alloc_md_stats() in obdclass/lprocfs_status.c. Also, add a
         * wrapper function in include/linux/obd_class.h.
         */
};

struct lsm_operations {
        void (*lsm_free)(struct lov_stripe_md *);
        int (*lsm_destroy)(struct lov_stripe_md *, struct obdo *oa,
                           struct obd_export *md_exp);
        void (*lsm_stripe_by_index)(struct lov_stripe_md *, int *, obd_off *,
                                     unsigned long *);
        void (*lsm_stripe_by_offset)(struct lov_stripe_md *, int *, obd_off *,
                                     unsigned long *);
        obd_off (*lsm_stripe_offset_by_index)(struct lov_stripe_md *, int);
        int (*lsm_stripe_index_by_offset)(struct lov_stripe_md *, obd_off);
        int (*lsm_revalidate) (struct lov_stripe_md *, struct obd_device *obd);
        int (*lsm_lmm_verify) (struct lov_mds_md *lmm, int lmm_bytes,
                               int *stripe_count);
        int (*lsm_unpackmd) (struct lov_obd *lov, struct lov_stripe_md *lsm,
                             struct lov_mds_md *lmm);
};

extern struct lsm_operations lsm_plain_ops;
extern struct lsm_operations lsm_join_ops;
static inline struct lsm_operations *lsm_op_find(int magic)
{
        switch(magic) {
        case LOV_MAGIC:
               return &lsm_plain_ops;
        case LOV_MAGIC_JOIN:
               return &lsm_join_ops;
        default:
               CERROR("Cannot recognize lsm_magic %d", magic);
               return NULL;
        }
}

int lvfs_check_io_health(struct obd_device *obd, struct file *file);

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
                ptlrpc_commit_replies (obd);
        }
}

static inline void init_obd_quota_ops(quota_interface_t *interface,
                                      struct obd_ops *obd_ops)
{
        if (!interface)
                return;

        LASSERT(obd_ops);
        obd_ops->o_quotacheck = QUOTA_OP(interface, check);
        obd_ops->o_quotactl = QUOTA_OP(interface, ctl);
}

#endif /* __OBD_H */
