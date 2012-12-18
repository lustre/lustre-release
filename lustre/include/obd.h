/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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
#define IOC_MDC_MAX_NR       50

#include <lustre/lustre_idl.h>
#include <lu_target.h>
#include <lu_ref.h>
#include <lustre_lib.h>
#include <lustre_export.h>
#include <lustre_quota.h>
#include <lustre_fld.h>
#include <lustre_capa.h>

#include <libcfs/bitmap.h>


#define MAX_OBD_DEVICES 8192

/* this is really local to the OSC */
struct loi_oap_pages {
        cfs_list_t              lop_pending;
        cfs_list_t              lop_urgent;
        cfs_list_t              lop_pending_group;
        int                     lop_num_pending;
};

struct osc_async_rc {
        int     ar_rc;
        int     ar_force_sync;
        __u64   ar_min_xid;
};

struct lov_oinfo {                 /* per-stripe data structure */
        struct ost_id   loi_oi;    /* object ID/Sequence on the target OST */
        int loi_ost_idx;           /* OST stripe index in lov_tgt_desc->tgts */
        int loi_ost_gen;           /* generation of this loi_ost_idx */

        /* used by the osc to keep track of what objects to build into rpcs */
        struct loi_oap_pages loi_read_lop;
        struct loi_oap_pages loi_write_lop;
        cfs_list_t loi_ready_item;
        cfs_list_t loi_hp_ready_item;
        cfs_list_t loi_write_item;
        cfs_list_t loi_read_item;

        unsigned long loi_kms_valid:1;
        __u64 loi_kms;             /* known minimum size */
        struct ost_lvb loi_lvb;
        struct osc_async_rc     loi_ar;
};
#define loi_id  loi_oi.oi_id
#define loi_seq loi_oi.oi_seq

static inline void loi_kms_set(struct lov_oinfo *oinfo, __u64 kms)
{
        oinfo->loi_kms = kms;
        oinfo->loi_kms_valid = 1;
}

static inline void loi_init(struct lov_oinfo *loi)
{
        CFS_INIT_LIST_HEAD(&loi->loi_read_lop.lop_pending);
        CFS_INIT_LIST_HEAD(&loi->loi_read_lop.lop_urgent);
        CFS_INIT_LIST_HEAD(&loi->loi_read_lop.lop_pending_group);
        CFS_INIT_LIST_HEAD(&loi->loi_write_lop.lop_pending);
        CFS_INIT_LIST_HEAD(&loi->loi_write_lop.lop_urgent);
        CFS_INIT_LIST_HEAD(&loi->loi_write_lop.lop_pending_group);
        CFS_INIT_LIST_HEAD(&loi->loi_ready_item);
        CFS_INIT_LIST_HEAD(&loi->loi_hp_ready_item);
        CFS_INIT_LIST_HEAD(&loi->loi_write_item);
        CFS_INIT_LIST_HEAD(&loi->loi_read_item);
}

struct lov_stripe_md {
        cfs_spinlock_t   lsm_lock;
        pid_t            lsm_lock_owner; /* debugging */

        /* maximum possible file size, might change as OSTs status changes,
         * e.g. disconnected, deactivated */
        __u64            lsm_maxbytes;
        struct {
                /* Public members. */
                __u64 lw_object_id;        /* lov object id */
                __u64 lw_object_seq;       /* lov object seq */

                /* LOV-private members start here -- only for use in lov/. */
                __u32 lw_magic;
                __u32 lw_stripe_size;      /* size of the stripe */
                __u32 lw_pattern;          /* striping pattern (RAID0, RAID1) */
                unsigned lw_stripe_count;  /* number of objects being striped over */
                char  lw_pool_name[LOV_MAXPOOLNAME]; /* pool name */
        } lsm_wire;

        struct lov_oinfo *lsm_oinfo[0];
};

#define lsm_object_id    lsm_wire.lw_object_id
#define lsm_object_seq   lsm_wire.lw_object_seq
#define lsm_magic        lsm_wire.lw_magic
#define lsm_stripe_size  lsm_wire.lw_stripe_size
#define lsm_pattern      lsm_wire.lw_pattern
#define lsm_stripe_count lsm_wire.lw_stripe_count
#define lsm_pool_name    lsm_wire.lw_pool_name

struct obd_info;

typedef int (*obd_enqueue_update_f)(void *cookie, int rc);

/* obd info for a particular level (lov, osc). */
struct obd_info {
        /* Lock policy. It keeps an extent which is specific for a particular
         * OSC. (e.g. lov_prep_enqueue_set initialises extent of the policy,
         * and osc_enqueue passes it into ldlm_lock_match & ldlm_cli_enqueue. */
        ldlm_policy_data_t      oi_policy;
        /* Flags used for set request specific flags:
           - while lock handling, the flags obtained on the enqueue
           request are set here.
           - while stats, the flags used for control delay/resend.
         */
        int                     oi_flags;
        /* Lock handle specific for every OSC lock. */
        struct lustre_handle   *oi_lockh;
        /* lsm data specific for every OSC. */
        struct lov_stripe_md   *oi_md;
        /* obdo data specific for every OSC, if needed at all. */
        struct obdo            *oi_oa;
        /* statfs data specific for every OSC, if needed at all. */
        struct obd_statfs      *oi_osfs;
        /* An update callback which is called to update some data on upper
         * level. E.g. it is used for update lsm->lsm_oinfo at every recieved
         * request in osc level for enqueue requests. It is also possible to
         * update some caller data from LOV layer if needed. */
        obd_enqueue_update_f    oi_cb_up;
        /* oss capability, its type is obd_capa in client to avoid copy.
         * in contrary its type is lustre_capa in OSS. */
        void                   *oi_capa;
};

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
        cfs_list_t typ_chain;
        struct obd_ops *typ_dt_ops;
        struct md_ops *typ_md_ops;
        cfs_proc_dir_entry_t *typ_procroot;
        char *typ_name;
        int  typ_refcnt;
        struct lu_device_type *typ_lu;
        cfs_spinlock_t obd_type_lock;
};

struct brw_page {
        obd_off  off;
        cfs_page_t *pg;
        int count;
        obd_flag flag;
};

/* Individual type definitions */

struct ost_server_data;

#define OBT_MAGIC       0xBDDECEAE
/* hold common fields for "target" device */
struct obd_device_target {
        __u32                     obt_magic;
        struct super_block       *obt_sb;
        /** last_rcvd file */
        struct file              *obt_rcvd_filp;
        struct lu_target         *obt_lut;
        __u64                     obt_mount_count;
        cfs_semaphore_t           obt_quotachecking;
        struct lustre_quota_ctxt  obt_qctxt;
        lustre_quota_version_t    obt_qfmt;
        cfs_rw_semaphore_t        obt_rwsem;
        struct vfsmount          *obt_vfsmnt;
        struct file              *obt_health_check_filp;
};

/* llog contexts */
enum llog_ctxt_id {
        LLOG_CONFIG_ORIG_CTXT  =  0,
        LLOG_CONFIG_REPL_CTXT,
        LLOG_MDS_OST_ORIG_CTXT,
        LLOG_MDS_OST_REPL_CTXT,
        LLOG_SIZE_ORIG_CTXT,
        LLOG_SIZE_REPL_CTXT,
        LLOG_RD1_ORIG_CTXT,
        LLOG_RD1_REPL_CTXT,
        LLOG_TEST_ORIG_CTXT,
        LLOG_TEST_REPL_CTXT,
        LLOG_LOVEA_ORIG_CTXT,
        LLOG_LOVEA_REPL_CTXT,
        LLOG_CHANGELOG_ORIG_CTXT,      /**< changelog generation on mdd */
        LLOG_CHANGELOG_REPL_CTXT,      /**< changelog access on clients */
        LLOG_CHANGELOG_USER_ORIG_CTXT, /**< for multiple changelog consumers */
        LLOG_MAX_CTXTS
};

#define FILTER_SUBDIR_COUNT      32            /* set to zero for no subdirs */

struct filter_subdirs {
       cfs_dentry_t *dentry[FILTER_SUBDIR_COUNT];
};


struct filter_ext {
        __u64                fe_start;
        __u64                fe_end;
};

struct filter_obd {
        /* NB this field MUST be first */
        struct obd_device_target fo_obt;
        const char          *fo_fstype;

        int                  fo_group_count;
        cfs_dentry_t        *fo_dentry_O;
        cfs_dentry_t       **fo_dentry_O_groups;
        struct filter_subdirs   *fo_dentry_O_sub;
        cfs_semaphore_t      fo_init_lock;      /* group initialization lock */
        int                  fo_committed_group;

        cfs_spinlock_t       fo_objidlock;      /* protect fo_lastobjid */

        unsigned long        fo_destroys_in_progress;
        cfs_semaphore_t      fo_create_locks[FILTER_SUBDIR_COUNT];

        cfs_list_t fo_export_list;
        int                  fo_subdir_count;

        obd_size             fo_tot_dirty;      /* protected by obd_osfs_lock */
        obd_size             fo_tot_granted;    /* all values in bytes */
        obd_size             fo_tot_pending;
        int                  fo_tot_granted_clients;

        obd_size             fo_readcache_max_filesize;
        cfs_spinlock_t       fo_flags_lock;
        int                  fo_read_cache:1,   /**< enable read-only cache */
                             fo_writethrough_cache:1,/**< read cache writes */
                             fo_mds_ost_sync:1, /**< MDS-OST orphan recovery*/
                             fo_raid_degraded:1;/**< RAID device degraded */

        struct obd_import   *fo_mdc_imp;
        struct obd_uuid      fo_mdc_uuid;
        struct lustre_handle fo_mdc_conn;
        struct file        **fo_last_objid_files;
        __u64               *fo_last_objids; /* last created objid for groups,
                                              * protected by fo_objidlock */

        cfs_semaphore_t      fo_alloc_lock;

        cfs_atomic_t         fo_r_in_flight;
        cfs_atomic_t         fo_w_in_flight;

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

        cfs_list_t               fo_llog_list;
        cfs_spinlock_t           fo_llog_list_lock;

        struct brw_stats         fo_filter_stats;
        struct lustre_quota_ctxt fo_quota_ctxt;
        cfs_spinlock_t           fo_quotacheck_lock;
        cfs_atomic_t             fo_quotachecking;

        int                      fo_fmd_max_num; /* per exp filter_mod_data */
        int                      fo_fmd_max_age; /* jiffies to fmd expiry */
        unsigned long            fo_syncjournal:1, /* sync journal on writes */
                                 fo_sync_lock_cancel:2;/* sync on lock cancel */


        /* sptlrpc stuff */
        cfs_rwlock_t             fo_sptlrpc_lock;
        struct sptlrpc_rule_set  fo_sptlrpc_rset;

        /* capability related */
        unsigned int             fo_fl_oss_capa;
        cfs_list_t               fo_capa_keys;
        cfs_hlist_head_t        *fo_capa_hash;
        struct llog_commit_master *fo_lcm;
        int                      fo_sec_level;
};

struct timeout_item {
        enum timeout_event ti_event;
        cfs_time_t         ti_timeout;
        timeout_cb_t       ti_cb;
        void              *ti_cb_data;
        cfs_list_t         ti_obd_list;
        cfs_list_t         ti_chain;
};

#define OSC_MAX_RIF_DEFAULT       8
#define OSC_MAX_RIF_MAX         256
#define OSC_MAX_DIRTY_DEFAULT  (OSC_MAX_RIF_DEFAULT * 4)
#define OSC_MAX_DIRTY_MB_MAX   2048     /* arbitrary, but < MAX_LONG bytes */
#define OSC_DEFAULT_RESENDS      10

/* possible values for fo_sync_lock_cancel */
enum {
        NEVER_SYNC_ON_CANCEL = 0,
        BLOCKING_SYNC_ON_CANCEL = 1,
        ALWAYS_SYNC_ON_CANCEL = 2,
        NUM_SYNC_ON_CANCEL_STATES
};

#define MDC_MAX_RIF_DEFAULT       8
#define MDC_MAX_RIF_MAX         512

struct mdc_rpc_lock;
struct obd_import;
struct client_obd {
        cfs_rw_semaphore_t       cl_sem;
        struct obd_uuid          cl_target_uuid;
        struct obd_import       *cl_import; /* ptlrpc connection state */
        int                      cl_conn_count;
        /* max_mds_easize is purely a performance thing so we don't have to
         * call obd_size_diskmd() all the time. */
        int                      cl_default_mds_easize;
        int                      cl_max_mds_easize;
        int                      cl_max_mds_cookiesize;

        enum lustre_sec_part     cl_sp_me;
        enum lustre_sec_part     cl_sp_to;
        struct sptlrpc_flavor    cl_flvr_mgc;   /* fixed flavor of mgc->mgs */

        //struct llog_canceld_ctxt *cl_llcd; /* it's included by obd_llog_ctxt */
        void                    *cl_llcd_offset;

        /* the grant values are protected by loi_list_lock below */
        long                     cl_dirty;         /* all _dirty_ in bytes */
        long                     cl_dirty_max;     /* allowed w/o rpc */
        long                     cl_dirty_transit; /* dirty synchronous */
        long                     cl_avail_grant;   /* bytes of credit for ost */
        long                     cl_lost_grant;    /* lost credits (trunc) */
        cfs_list_t               cl_cache_waiters; /* waiting for cache/grant */
        cfs_time_t               cl_next_shrink_grant;   /* jiffies */
        cfs_list_t               cl_grant_shrink_list;  /* Timeout event list */
        cfs_semaphore_t          cl_grant_sem;   /*grant shrink list cfs_semaphore*/
        int                      cl_grant_shrink_interval; /* seconds */

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
        cfs_list_t               cl_loi_ready_list;
        cfs_list_t               cl_loi_hp_ready_list;
        cfs_list_t               cl_loi_write_list;
        cfs_list_t               cl_loi_read_list;
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

        /* number of in flight destroy rpcs is limited to max_rpcs_in_flight */
        cfs_atomic_t             cl_destroy_in_flight;
        cfs_waitq_t              cl_destroy_waitq;

        struct mdc_rpc_lock     *cl_rpc_lock;
        struct mdc_rpc_lock     *cl_close_lock;
        struct osc_creator       cl_oscc;

        /* mgc datastruct */
        cfs_semaphore_t          cl_mgc_sem;
        struct vfsmount         *cl_mgc_vfsmnt;
        struct dentry           *cl_mgc_configs_dir;
        cfs_atomic_t             cl_mgc_refcount;
        struct obd_export       *cl_mgc_mgsexp;

        /* checksumming for data sent over the network */
        unsigned int             cl_checksum:1; /* 0 = disabled, 1 = enabled */
        /* supported checksum types that are worked out at connect time */
        __u32                    cl_supp_cksum_types;
        /* checksum algorithm to be used */
        cksum_type_t             cl_cksum_type;

        /* also protected by the poorly named _loi_list_lock lock above */
        struct osc_async_rc      cl_ar;

        /* used by quotacheck */
        int                      cl_qchk_stat; /* quotacheck stat of the peer */

        /* sequence manager */
        struct lu_client_seq    *cl_seq;

        cfs_atomic_t             cl_resends; /* resend count */

        /* hash tables for osc_quota_info */
        cfs_hash_t              *cl_quota_hash[MAXQUOTAS];
};
#define obd2cli_tgt(obd) ((char *)(obd)->u.cli.cl_target_uuid.uuid)

#define CL_NOT_QUOTACHECKED 1   /* client->cl_qchk_stat init value */

struct mgs_obd {
        struct obd_device_target         mgs_obt;
        struct ptlrpc_service           *mgs_service;
        struct vfsmount                 *mgs_vfsmnt;
        struct super_block              *mgs_sb;
        struct dentry                   *mgs_configs_dir;
        cfs_list_t                       mgs_fs_db_list;
        cfs_semaphore_t                  mgs_sem;
        cfs_proc_dir_entry_t            *mgs_proc_live;
};

struct mds_obd {
        /* NB this field MUST be first */
        struct obd_device_target         mds_obt;
        struct ptlrpc_service           *mds_service;
        struct ptlrpc_service           *mds_setattr_service;
        struct ptlrpc_service           *mds_readpage_service;
        int                              mds_max_mdsize;
        int                              mds_max_cookiesize;
        __u64                            mds_io_epoch;
        unsigned long                    mds_atime_diff;
        cfs_semaphore_t                  mds_epoch_sem;
        struct ll_fid                    mds_rootfid;
        cfs_dentry_t                    *mds_pending_dir;
        cfs_dentry_t                    *mds_logs_dir;
        cfs_dentry_t                    *mds_objects_dir;
        struct llog_handle              *mds_cfg_llh;
        struct obd_device               *mds_lov_obd;
        struct obd_uuid                  mds_lov_uuid;
        char                            *mds_profile;
        struct obd_export               *mds_lov_exp;
        struct lov_desc                  mds_lov_desc;
        __u32                            mds_id;

        /* mark pages dirty for write. */
        cfs_bitmap_t                    *mds_lov_page_dirty;
        /* array for store pages with obd_id */
        void                           **mds_lov_page_array;
        /* file for store objid */
        struct file                     *mds_lov_objid_filp;
        __u32                            mds_lov_objid_count;
        __u32                            mds_lov_objid_max_index;
        __u32                            mds_lov_objid_lastpage;
        __u32                            mds_lov_objid_lastidx;


        struct lustre_quota_info         mds_quota_info;
        cfs_rw_semaphore_t               mds_qonoff_sem;
        cfs_semaphore_t                  mds_health_sem;
        unsigned long                    mds_fl_user_xattr:1,
                                         mds_fl_acl:1,
                                         mds_evict_ost_nids:1,
                                         mds_fl_cfglog:1,
                                         mds_fl_synced:1,
                                         mds_quota:1,
                                         mds_fl_target:1; /* mds have one or
                                                           * more targets */

        struct upcall_cache             *mds_identity_cache;

        /* for capability keys update */
        struct lustre_capa_key          *mds_capa_keys;
        cfs_rw_semaphore_t               mds_notify_lock;
};

/* lov objid */
extern __u32 mds_max_ost_index;

#define MDS_LOV_ALLOC_SIZE (CFS_PAGE_SIZE)

#define OBJID_PER_PAGE() (MDS_LOV_ALLOC_SIZE / sizeof(obd_id))

#define MDS_LOV_OBJID_PAGES_COUNT (mds_max_ost_index/OBJID_PER_PAGE())

extern int mds_lov_init_objids(struct obd_device *obd);
extern void mds_lov_destroy_objids(struct obd_device *obd);

struct obd_id_info {
        __u32   idx;
        obd_id  *data;
};

/* */

struct echo_obd {
        struct obdo          eo_oa;
        cfs_spinlock_t       eo_lock;
        __u64                eo_lastino;
        struct lustre_handle eo_nl_lock;
        cfs_atomic_t         eo_prep;
};

struct ost_obd {
        struct ptlrpc_service *ost_service;
        struct ptlrpc_service *ost_create_service;
        struct ptlrpc_service *ost_io_service;
        cfs_semaphore_t        ost_health_sem;
};

struct echo_client_obd {
        struct obd_export   *ec_exp;   /* the local connection to osc/lov */
        cfs_spinlock_t       ec_lock;
        cfs_list_t           ec_objects;
        cfs_list_t           ec_locks;
        int                  ec_nstripes;
        __u64                ec_unique;
};

struct lov_qos_oss {
        struct obd_uuid     lqo_uuid;       /* ptlrpc's c_remote_uuid */
        cfs_list_t          lqo_oss_list;   /* link to lov_qos */
        __u64               lqo_bavail;     /* total bytes avail on OSS */
        __u64               lqo_penalty;    /* current penalty */
        __u64               lqo_penalty_per_obj;/* penalty decrease every obj*/
        time_t              lqo_used;       /* last used time, seconds */
        __u32               lqo_ost_count;  /* number of osts on this oss */
};

struct ltd_qos {
        struct lov_qos_oss *ltq_oss;         /* oss info */
        __u64               ltq_penalty;     /* current penalty */
        __u64               ltq_penalty_per_obj; /* penalty decrease every obj*/
        __u64               ltq_weight;      /* net weighting */
        time_t              ltq_used;        /* last used time, seconds */
        unsigned int        ltq_usable:1;    /* usable for striping */
};

/* Generic subset of OSTs */
struct ost_pool {
        __u32              *op_array;      /* array of index of
                                                   lov_obd->lov_tgts */
        unsigned int        op_count;      /* number of OSTs in the array */
        unsigned int        op_size;       /* allocated size of lp_array */
        cfs_rw_semaphore_t  op_rw_sem;     /* to protect ost_pool use */
};

/* Round-robin allocator data */
struct lov_qos_rr {
        __u32               lqr_start_idx;   /* start index of new inode */
        __u32               lqr_offset_idx;  /* aliasing for start_idx  */
        int                 lqr_start_count; /* reseed counter */
        struct ost_pool     lqr_pool;        /* round-robin optimized list */
        unsigned long       lqr_dirty:1;     /* recalc round-robin list */
};

/* allow statfs data caching for 1 second */
#define OBD_STATFS_CACHE_SECONDS 1

struct lov_statfs_data {
        struct obd_info   lsd_oi;
        struct obd_statfs lsd_statfs;
};
/* Stripe placement optimization */
struct lov_qos {
        cfs_list_t          lq_oss_list; /* list of OSSs that targets use */
        cfs_rw_semaphore_t  lq_rw_sem;
        __u32               lq_active_oss_count;
        unsigned int        lq_prio_free;   /* priority for free space */
        unsigned int        lq_threshold_rr;/* priority for rr */
        struct lov_qos_rr   lq_rr;          /* round robin qos data */
        unsigned long       lq_dirty:1,     /* recalc qos data */
                            lq_same_space:1,/* the ost's all have approx.
                                               the same space avail */
                            lq_reset:1,     /* zero current penalties */
                            lq_statfs_in_progress:1; /* statfs op in
                                                        progress */
        /* qos statfs data */
        struct lov_statfs_data *lq_statfs_data;
        cfs_waitq_t         lq_statfs_waitq; /* waitqueue to notify statfs
                                              * requests completion */
};

struct lov_tgt_desc {
        cfs_list_t          ltd_kill;
        struct obd_uuid     ltd_uuid;
        struct obd_device  *ltd_obd;
        struct obd_export  *ltd_exp;
        struct ltd_qos      ltd_qos;     /* qos info per target */
        __u32               ltd_gen;
        __u32               ltd_index;   /* index in lov_obd->tgts */
        unsigned long       ltd_active:1,/* is this target up for requests */
                            ltd_activate:1,/* should  target be activated */
                            ltd_reap:1;  /* should this target be deleted */
};

/* Pool metadata */
#define pool_tgt_size(_p)   _p->pool_obds.op_size
#define pool_tgt_count(_p)  _p->pool_obds.op_count
#define pool_tgt_array(_p)  _p->pool_obds.op_array
#define pool_tgt_rw_sem(_p) _p->pool_obds.op_rw_sem
#define pool_tgt(_p, _i)    _p->pool_lov->lov_tgts[_p->pool_obds.op_array[_i]]

struct pool_desc {
        char                  pool_name[LOV_MAXPOOLNAME + 1]; /* name of pool */
        struct ost_pool       pool_obds;              /* pool members */
        cfs_atomic_t          pool_refcount;          /* pool ref. counter */
        struct lov_qos_rr     pool_rr;                /* round robin qos */
        cfs_hlist_node_t      pool_hash;              /* access by poolname */
        cfs_list_t            pool_list;              /* serial access */
        cfs_proc_dir_entry_t *pool_proc_entry;        /* file in /proc */
        struct lov_obd       *pool_lov;               /* lov obd to which this
                                                         pool belong */
};

struct lov_obd {
        struct lov_desc         desc;
        struct lov_tgt_desc   **lov_tgts;              /* sparse array */
        struct ost_pool         lov_packed;            /* all OSTs in a packed
                                                          array */
        cfs_semaphore_t         lov_lock;
        struct obd_connect_data lov_ocd;
        struct lov_qos          lov_qos;               /* qos info per lov */
        cfs_atomic_t            lov_refcount;
        __u32                   lov_tgt_count;         /* how many OBD's */
        __u32                   lov_active_tgt_count;  /* how many active */
        __u32                   lov_death_row;/* tgts scheduled to be deleted */
        __u32                   lov_tgt_size;   /* size of tgts array */
        int                     lov_connects;
        int                     lov_pool_count;
        cfs_hash_t             *lov_pools_hash_body; /* used for key access */
        cfs_list_t              lov_pool_list; /* used for sequential access */
        cfs_proc_dir_entry_t   *lov_pool_proc_entry;
        enum lustre_sec_part    lov_sp_me;
};

struct lmv_tgt_desc {
        struct obd_uuid         ltd_uuid;
        struct obd_export      *ltd_exp;
        int                     ltd_active; /* is this target up for requests */
        int                     ltd_idx;
        cfs_semaphore_t         ltd_fid_sem;
};

enum placement_policy {
        PLACEMENT_CHAR_POLICY   = 0,
        PLACEMENT_NID_POLICY    = 1,
        PLACEMENT_INVAL_POLICY  = 2,
        PLACEMENT_MAX_POLICY
};

typedef enum placement_policy placement_policy_t;

struct lmv_obd {
        int                     refcount;
        struct lu_client_fld    lmv_fld;
        cfs_spinlock_t          lmv_lock;
        placement_policy_t      lmv_placement;
        struct lmv_desc         desc;
        struct obd_uuid         cluuid;
        struct obd_export       *exp;

        int                     connected;
        int                     max_easize;
        int                     max_def_easize;
        int                     max_cookiesize;
        int                     server_timeout;
        cfs_semaphore_t         init_sem;

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

#define LUSTRE_FLD_NAME         "fld"
#define LUSTRE_SEQ_NAME         "seq"

#define LUSTRE_CMM_NAME         "cmm"
#define LUSTRE_MDD_NAME         "mdd"
#define LUSTRE_OSD_NAME         "osd-ldiskfs"
#define LUSTRE_VVP_NAME         "vvp"
#define LUSTRE_LMV_NAME         "lmv"
#define LUSTRE_CMM_MDC_NAME     "cmm-mdc"
#define LUSTRE_SLP_NAME         "slp"

/* obd device type names */
 /* FIXME all the references to LUSTRE_MDS_NAME should be swapped with LUSTRE_MDT_NAME */
#define LUSTRE_MDS_NAME         "mds"
#define LUSTRE_MDT_NAME         "mdt"
#define LUSTRE_MDC_NAME         "mdc"
#define LUSTRE_OSS_NAME         "ost"       /* FIXME change name to oss */
#define LUSTRE_OST_NAME         "obdfilter" /* FIXME change name to ost */
#define LUSTRE_OSC_NAME         "osc"
#define LUSTRE_LOV_NAME         "lov"
#define LUSTRE_MGS_NAME         "mgs"
#define LUSTRE_MGC_NAME         "mgc"

#define LUSTRE_CACHEOBD_NAME    "cobd"
#define LUSTRE_ECHO_NAME        "obdecho"
#define LUSTRE_ECHO_CLIENT_NAME "echo_client"

/* Constant obd names (post-rename) */
#define LUSTRE_MDS_OBDNAME "MDS"
#define LUSTRE_OSS_OBDNAME "OSS"
#define LUSTRE_MGS_OBDNAME "MGS"
#define LUSTRE_MGC_OBDNAME "MGC"

/* Don't conflict with on-wire flags OBD_BRW_WRITE, etc */
#define N_LOCAL_TEMP_PAGE 0x10000000

struct obd_trans_info {
        __u64                    oti_transno;
        __u64                    oti_xid;
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
        struct ptlrpc_thread *   oti_thread;
        __u32                    oti_conn_cnt;
        /** VBR: versions */
        __u64                    oti_pre_version;

        struct obd_uuid         *oti_ost_uuid;
};

static inline void oti_init(struct obd_trans_info *oti,
                            struct ptlrpc_request *req)
{
        if (oti == NULL)
                return;
        memset(oti, 0, sizeof(*oti));

        if (req == NULL)
                return;

        oti->oti_xid = req->rq_xid;
        /** VBR: take versions from request */
        if (req->rq_reqmsg != NULL &&
            lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                __u64 *pre_version = lustre_msg_get_versions(req->rq_reqmsg);
                oti->oti_pre_version = pre_version ? pre_version[0] : 0;
                oti->oti_transno = lustre_msg_get_transno(req->rq_reqmsg);
        }

        /** called from mds_create_objects */
        if (req->rq_repmsg != NULL)
                oti->oti_transno = lustre_msg_get_transno(req->rq_repmsg);
        oti->oti_thread = req->rq_svc_thread;
        if (req->rq_reqmsg != NULL)
                oti->oti_conn_cnt = lustre_msg_get_conn_cnt(req->rq_reqmsg);
}

static inline void oti_alloc_cookies(struct obd_trans_info *oti,int num_cookies)
{
        if (!oti)
                return;

        if (num_cookies == 1)
                oti->oti_logcookies = &oti->oti_onecookie;
        else
                OBD_ALLOC_LARGE(oti->oti_logcookies,
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
                OBD_FREE_LARGE(oti->oti_logcookies,
                               oti->oti_numcookies*sizeof(oti->oti_onecookie));
        oti->oti_logcookies = NULL;
        oti->oti_numcookies = 0;
}

/*
 * Events signalled through obd_notify() upcall-chain.
 */
enum obd_notify_event {
        /* target added */
        OBD_NOTIFY_CREATE,
        /* Device connect start */
        OBD_NOTIFY_CONNECT,
        /* Device activated */
        OBD_NOTIFY_ACTIVE,
        /* Device deactivated */
        OBD_NOTIFY_INACTIVE,
        /* Device disconnected */
        OBD_NOTIFY_DISCON,
        /* Connect data for import were changed */
        OBD_NOTIFY_OCD,
        /* Sync request */
        OBD_NOTIFY_SYNC_NONBLOCK,
        OBD_NOTIFY_SYNC,
        /* Configuration event */
        OBD_NOTIFY_CONFIG,
        /* Trigger quota recovery */
        OBD_NOTIFY_QUOTA,
        /* Administratively deactivate/activate event */
        OBD_NOTIFY_DEACTIVATE,
        OBD_NOTIFY_ACTIVATE
};

/* bit-mask flags for config events */
enum config_flags {
        CONFIG_LOG      = 0x1,  /* finished processing config log */
        CONFIG_SYNC     = 0x2,  /* mdt synced 1 ost */
        CONFIG_TARGET   = 0x4   /* one target is added */
};

/*
 * Data structure used to pass obd_notify()-event to non-obd listeners (llite
 * and liblustre being main examples).
 */
struct obd_notify_upcall {
        int (*onu_upcall)(struct obd_device *host, struct obd_device *watched,
                          enum obd_notify_event ev, void *owner, void *data);
        /* Opaque datum supplied by upper layer listener */
        void *onu_owner;
};

struct target_recovery_data {
        svc_handler_t     trd_recovery_handler;
        pid_t             trd_processing_task;
        cfs_completion_t  trd_starting;
        cfs_completion_t  trd_finishing;
};

/**
  * In HEAD for CMD, the object is created in group number which is 3>=
  * or indexing starts from 3. To test this assertions are added to disallow
  * group 0. But to run 2.0 mds server on 1.8.x disk format (i.e. interop_mode)
  * object in group 0 needs to be allowed.
  * So for interop mode following changes needs to be done:
  * 1. No need to assert on group 0 or allow group 0
  * 2. The group number indexing starts from 0 instead of 3
  */

#define LASSERT_SEQ_IS_MDT(seq) LASSERT(fid_seq_is_mdt(seq))

static inline __u64 objseq_to_mdsno(obd_seq seq)
{
        LASSERT_SEQ_IS_MDT(seq);
        if (seq == FID_SEQ_OST_MDT0)
                return 0;
        return seq - FID_SEQ_OST_MDT1 + 1;
}

static inline int mdt_to_obd_objseq(int mdtid)
{
        /**
         * MDS0 uses seq 0 pre FID-on-OST, other MDSes will use seq from
         * FID_SEQ_OST_MDT1
         */
        if (mdtid)
                return FID_SEQ_OST_MDT1 + mdtid - 1;
        return 0;
}

struct obd_llog_group {
        cfs_list_t         olg_list;
        int                olg_seq;
        struct llog_ctxt  *olg_ctxts[LLOG_MAX_CTXTS];
        cfs_waitq_t        olg_waitq;
        cfs_spinlock_t     olg_lock;
        struct obd_export *olg_exp;
        int                olg_initializing;
        cfs_semaphore_t    olg_cat_processing;
};

/* corresponds to one of the obd's */
#define MAX_OBD_NAME 128
#define OBD_DEVICE_MAGIC        0XAB5CD6EF
#define OBD_DEV_BY_DEVNAME      0xffffd0de

struct obd_device {
        struct obd_type        *obd_type;
        __u32                   obd_magic;

        /* common and UUID name of this device */
        char                    obd_name[MAX_OBD_NAME];
        struct obd_uuid         obd_uuid;

        struct lu_device       *obd_lu_dev;

        int                     obd_minor;
        /* bitfield modification is protected by obd_dev_lock */
        unsigned long obd_attached:1,      /* finished attach */
                      obd_set_up:1,        /* finished setup */
                      obd_recovering:1,    /* there are recoverable clients */
                      obd_abort_recovery:1,/* recovery expired */
                      obd_version_recov:1, /* obd uses version checking */
                      obd_replayable:1,    /* recovery is enabled; inform clients */
                      obd_no_transno:1,    /* no committed-transno notification */
                      obd_no_recov:1,      /* fail instead of retry messages */
                      obd_stopping:1,      /* started cleanup */
                      obd_starting:1,      /* started setup */
                      obd_force:1,         /* cleanup with > 0 obd refcount */
                      obd_fail:1,          /* cleanup with failover */
                      obd_async_recov:1,   /* allow asynchronous orphan cleanup */
                      obd_no_conn:1,       /* deny new connections */
                      obd_inactive:1,      /* device active/inactive
                                           * (for /proc/status only!!) */
                      obd_process_conf:1;  /* device is processing mgs config */
        /* use separate field as it is set in interrupt to don't mess with
         * protection of other bits using _bh lock */
        unsigned long obd_recovery_expired:1;
        /* uuid-export hash body */
        cfs_hash_t             *obd_uuid_hash;
        /* nid-export hash body */
        cfs_hash_t             *obd_nid_hash;
        /* nid stats body */
        cfs_hash_t             *obd_nid_stats_hash;
        cfs_list_t              obd_nid_stats;
        cfs_atomic_t            obd_refcount;
        cfs_waitq_t             obd_refcount_waitq;
        cfs_list_t              obd_exports;
        cfs_list_t              obd_unlinked_exports;
        cfs_list_t              obd_delayed_exports;
        int                     obd_num_exports;
        cfs_spinlock_t          obd_nid_lock;
        struct ldlm_namespace  *obd_namespace;
        struct ptlrpc_client    obd_ldlm_client; /* XXX OST/MDS only */
        /* a spinlock is OK for what we do now, may need a semaphore later */
        cfs_spinlock_t          obd_dev_lock; /* protects obd bitfield above */
        cfs_semaphore_t         obd_dev_sem;
        __u64                   obd_last_committed;
        struct fsfilt_operations *obd_fsops;
        cfs_spinlock_t          obd_osfs_lock;
        struct obd_statfs       obd_osfs;       /* locked by obd_osfs_lock */
        __u64                   obd_osfs_age;
        struct lvfs_run_ctxt    obd_lvfs_ctxt;
        struct obd_llog_group   obd_olg; /* default llog group */
        struct obd_device      *obd_observer;
        cfs_rw_semaphore_t      obd_observer_link_sem;
        struct obd_notify_upcall obd_upcall;
        struct obd_export       *obd_self_export;
        /* list of exports in LRU order, for ping evictor, with obd_dev_lock */
        cfs_list_t              obd_exports_timed;
        time_t                  obd_eviction_timer; /* for ping evictor */

        int                              obd_max_recoverable_clients;
        int                              obd_connected_clients;
        int                              obd_stale_clients;
        int                              obd_delayed_clients;
        /* this lock protects all recovery list_heads, timer and
         * obd_next_recovery_transno value */
        cfs_spinlock_t                   obd_recovery_task_lock;
        __u64                            obd_next_recovery_transno;
        int                              obd_replayed_requests;
        int                              obd_requests_queued_for_recovery;
        cfs_waitq_t                      obd_next_transno_waitq;
        /* protected by obd_recovery_task_lock */
        cfs_timer_t                      obd_recovery_timer;
        time_t                           obd_recovery_start; /* seconds */
        time_t                           obd_recovery_end; /* seconds, for lprocfs_status */
        time_t                           obd_recovery_time_hard;
        int                              obd_recovery_timeout;

        /* new recovery stuff from CMD2 */
        struct target_recovery_data      obd_recovery_data;
        int                              obd_replayed_locks;
        cfs_atomic_t                     obd_req_replay_clients;
        cfs_atomic_t                     obd_lock_replay_clients;
        /* all lists are protected by obd_recovery_task_lock */
        cfs_list_t                       obd_req_replay_queue;
        cfs_list_t                       obd_lock_replay_queue;
        cfs_list_t                       obd_final_req_queue;
        int                              obd_recovery_stage;

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

        cfs_proc_dir_entry_t  *obd_proc_entry;
        cfs_proc_dir_entry_t  *obd_proc_exports_entry;
        cfs_proc_dir_entry_t  *obd_svc_procroot;
        struct lprocfs_stats  *obd_svc_stats;
        cfs_atomic_t           obd_evict_inprogress;
        cfs_waitq_t            obd_evict_inprogress_waitq;
        cfs_list_t             obd_evict_list; /* protected with pet_lock */

        /**
         * Ldlm pool part. Save last calculated SLV and Limit.
         */
        cfs_rwlock_t           obd_pool_lock;
        int                    obd_pool_limit;
        __u64                  obd_pool_slv;

        /**
         * A list of outstanding class_incref()'s against this obd. For
         * debugging.
         */
        struct lu_ref          obd_reference;

	int		       obd_conn_inprogress;
};

#define OBD_LLOG_FL_SENDNOW     0x0001
#define OBD_LLOG_FL_EXIT	0x0002

enum obd_cleanup_stage {
/* Special case hack for MDS LOVs */
        OBD_CLEANUP_EARLY,
/* can be directly mapped to .ldto_device_fini() */
        OBD_CLEANUP_EXPORTS,
};

/* get/set_info keys */
#define KEY_ASYNC               "async"
#define KEY_BLOCKSIZE_BITS      "blocksize_bits"
#define KEY_BLOCKSIZE           "blocksize"
#define KEY_CAPA_KEY            "capa_key"
#define KEY_CHANGELOG_CLEAR     "changelog_clear"
#define KEY_FID2PATH            "fid2path"
#define KEY_CHECKSUM            "checksum"
#define KEY_CLEAR_FS            "clear_fs"
#define KEY_CONN_DATA           "conn_data"
#define KEY_EVICT_BY_NID        "evict_by_nid"
#define KEY_FIEMAP              "fiemap"
#define KEY_FLUSH_CTX           "flush_ctx"
#define KEY_GRANT_SHRINK        "grant_shrink"
#define KEY_HSM_COPYTOOL_SEND   "hsm_send"
#define KEY_INIT_RECOV_BACKUP   "init_recov_bk"
#define KEY_INIT_RECOV          "initial_recov"
#define KEY_INTERMDS            "inter_mds"
#define KEY_LAST_ID             "last_id"
#define KEY_LOCK_TO_STRIPE      "lock_to_stripe"
#define KEY_LOVDESC             "lovdesc"
#define KEY_LOV_IDX             "lov_idx"
#define KEY_MAX_EASIZE          "max_easize"
#define KEY_MDS_CONN            "mds_conn"
#define KEY_MGSSEC              "mgssec"
#define KEY_NEXT_ID             "next_id"
#define KEY_READ_ONLY           "read-only"
#define KEY_REGISTER_TARGET     "register_target"
#define KEY_REVIMP_UPD          "revimp_update"
#define KEY_SET_FS              "set_fs"
#define KEY_TGT_COUNT           "tgt_count"
/*      KEY_SET_INFO in lustre_idl.h */
#define KEY_SPTLRPC_CONF        "sptlrpc_conf"
#define KEY_CONNECT_FLAG        "connect_flags"
#define KEY_SYNC_LOCK_CANCEL    "sync_lock_cancel"


struct lu_context;

/* /!\ must be coherent with include/linux/namei.h on patched kernel */
#define IT_OPEN     (1 << 0)
#define IT_CREAT    (1 << 1)
#define IT_READDIR  (1 << 2)
#define IT_GETATTR  (1 << 3)
#define IT_LOOKUP   (1 << 4)
#define IT_UNLINK   (1 << 5)
#define IT_TRUNC    (1 << 6)
#define IT_GETXATTR (1 << 7)
#define IT_EXEC     (1 << 8)
#define IT_PIN      (1 << 9)

static inline int it_to_lock_mode(struct lookup_intent *it)
{
        /* CREAT needs to be tested before open (both could be set) */
        if (it->it_op & IT_CREAT)
                return LCK_CW;
        else if (it->it_op & (IT_READDIR | IT_GETATTR | IT_OPEN | IT_LOOKUP))
                return LCK_CR;

        LASSERTF(0, "Invalid it_op: %d\n", it->it_op);
        return -EINVAL;
}

struct md_op_data {
        struct lu_fid           op_fid1; /* operation fid1 (usualy parent) */
        struct lu_fid           op_fid2; /* operation fid2 (usualy child) */
        struct lu_fid           op_fid3; /* 2 extra fids to find conflicting */
        struct lu_fid           op_fid4; /* to the operation locks. */
        mdsno_t                 op_mds;  /* what mds server open will go to */
        struct lustre_handle    op_handle;
        obd_time                op_mod_time;
        const char             *op_name;
        int                     op_namelen;
        __u32                   op_mode;
        struct lmv_stripe_md   *op_mea1;
        struct lmv_stripe_md   *op_mea2;
        __u32                   op_suppgids[2];
        __u32                   op_fsuid;
        __u32                   op_fsgid;
        cfs_cap_t               op_cap;
        void                   *op_data;

        /* iattr fields and blocks. */
        struct iattr            op_attr;
#ifdef __KERNEL__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
        unsigned int            op_attr_flags;
#endif
#endif
        __u64                   op_valid;
        loff_t                  op_attr_blocks;

        /* Size-on-MDS epoch and flags. */
        __u64                   op_ioepoch;
        __u32                   op_flags;

        /* Capa fields */
        struct obd_capa        *op_capa1;
        struct obd_capa        *op_capa2;

        /* Various operation flags. */
        __u32                   op_bias;

        /* Operation type */
        __u32                   op_opc;
};

struct md_enqueue_info;
/* metadata stat-ahead */
typedef int (* md_enqueue_cb_t)(struct ptlrpc_request *req,
                                struct md_enqueue_info *minfo,
                                int rc);

struct md_enqueue_info {
        struct md_op_data       mi_data;
        struct lookup_intent    mi_it;
        struct lustre_handle    mi_lockh;
        struct dentry          *mi_dentry;
        struct inode           *mi_dir;
        md_enqueue_cb_t         mi_cb;
        unsigned int            mi_generation;
        void                   *mi_cbdata;
};

struct obd_ops {
        cfs_module_t *o_owner;
        int (*o_iocontrol)(unsigned int cmd, struct obd_export *exp, int len,
                           void *karg, void *uarg);
        int (*o_get_info)(struct obd_export *, __u32 keylen, void *key,
                          __u32 *vallen, void *val, struct lov_stripe_md *lsm);
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
        int (*o_connect)(const struct lu_env *env,
                         struct obd_export **exp, struct obd_device *src,
                         struct obd_uuid *cluuid, struct obd_connect_data *ocd,
                         void *localdata);
        int (*o_reconnect)(const struct lu_env *env,
                           struct obd_export *exp, struct obd_device *src,
                           struct obd_uuid *cluuid,
                           struct obd_connect_data *ocd,
                           void *localdata);
        int (*o_disconnect)(struct obd_export *exp);

        /* Initialize/finalize fids infrastructure. */
        int (*o_fid_init)(struct obd_export *exp);
        int (*o_fid_fini)(struct obd_export *exp);

        /* Allocate new fid according to passed @hint. */
        int (*o_fid_alloc)(struct obd_export *exp, struct lu_fid *fid,
                           struct md_op_data *op_data);

        int (*o_statfs)(struct obd_device *obd, struct obd_statfs *osfs,
                        __u64 max_age, __u32 flags);
        int (*o_statfs_async)(struct obd_device *obd, struct obd_info *oinfo,
                              __u64 max_age, struct ptlrpc_request_set *set);
        int (*o_packmd)(struct obd_export *exp, struct lov_mds_md **disk_tgt,
                        struct lov_stripe_md *mem_src);
        int (*o_unpackmd)(struct obd_export *exp,struct lov_stripe_md **mem_tgt,
                          struct lov_mds_md *disk_src, int disk_len);
        int (*o_preallocate)(struct lustre_handle *, obd_count *req,
                             obd_id *ids);
        /* FIXME: add fid capability support for create & destroy! */
        int (*o_precreate)(struct obd_export *exp);
        int (*o_create)(struct obd_export *exp,  struct obdo *oa,
                        struct lov_stripe_md **ea, struct obd_trans_info *oti);
        int (*o_create_async)(struct obd_export *exp,  struct obd_info *oinfo,
                              struct lov_stripe_md **ea,
                              struct obd_trans_info *oti);
        int (*o_destroy)(struct obd_export *exp, struct obdo *oa,
                         struct lov_stripe_md *ea, struct obd_trans_info *oti,
                         struct obd_export *md_exp, void *capa);
        int (*o_setattr)(struct obd_export *exp, struct obd_info *oinfo,
                         struct obd_trans_info *oti);
        int (*o_setattr_async)(struct obd_export *exp, struct obd_info *oinfo,
                               struct obd_trans_info *oti,
                               struct ptlrpc_request_set *rqset);
        int (*o_getattr)(struct obd_export *exp, struct obd_info *oinfo);
        int (*o_getattr_async)(struct obd_export *exp, struct obd_info *oinfo,
                               struct ptlrpc_request_set *set);
        int (*o_brw)(int rw, struct obd_export *exp, struct obd_info *oinfo,
                     obd_count oa_bufs, struct brw_page *pgarr,
                     struct obd_trans_info *oti);
        int (*o_merge_lvb)(struct obd_export *exp, struct lov_stripe_md *lsm,
                           struct ost_lvb *lvb, int kms_only);
        int (*o_adjust_kms)(struct obd_export *exp, struct lov_stripe_md *lsm,
                            obd_off size, int shrink);
        int (*o_punch)(struct obd_export *exp, struct obd_info *oinfo,
                       struct obd_trans_info *oti,
                       struct ptlrpc_request_set *rqset);
        int (*o_sync)(struct obd_export *exp, struct obd_info *oinfo,
                      obd_size start, obd_size end,
                      struct ptlrpc_request_set *set);
        int (*o_migrate)(struct lustre_handle *conn, struct lov_stripe_md *dst,
                         struct lov_stripe_md *src, obd_size start,
                         obd_size end, struct obd_trans_info *oti);
        int (*o_copy)(struct lustre_handle *dstconn, struct lov_stripe_md *dst,
                      struct lustre_handle *srconn, struct lov_stripe_md *src,
                      obd_size start, obd_size end, struct obd_trans_info *);
        int (*o_iterate)(struct lustre_handle *conn,
                         int (*)(obd_id, obd_seq, void *),
                         obd_id *startid, obd_seq seq, void *data);
        int (*o_preprw)(int cmd, struct obd_export *exp, struct obdo *oa,
                        int objcount, struct obd_ioobj *obj,
                        struct niobuf_remote *remote, int *nr_pages,
                        struct niobuf_local *local,
                        struct obd_trans_info *oti,
                        struct lustre_capa *capa);
        int (*o_commitrw)(int cmd, struct obd_export *exp, struct obdo *oa,
                          int objcount, struct obd_ioobj *obj,
                          struct niobuf_remote *remote, int pages,
                          struct niobuf_local *local,
                          struct obd_trans_info *oti, int rc);
        int (*o_enqueue)(struct obd_export *, struct obd_info *oinfo,
                         struct ldlm_enqueue_info *einfo,
                         struct ptlrpc_request_set *rqset);
        int (*o_change_cbdata)(struct obd_export *, struct lov_stripe_md *,
                               ldlm_iterator_t it, void *data);
        int (*o_find_cbdata)(struct obd_export *, struct lov_stripe_md *,
                             ldlm_iterator_t it, void *data);
        int (*o_cancel)(struct obd_export *, struct lov_stripe_md *md,
                        __u32 mode, struct lustre_handle *);
        int (*o_cancel_unused)(struct obd_export *, struct lov_stripe_md *,
                               ldlm_cancel_flags_t flags, void *opaque);
        int (*o_init_export)(struct obd_export *exp);
        int (*o_destroy_export)(struct obd_export *exp);
        int (*o_extent_calc)(struct obd_export *, struct lov_stripe_md *,
                             int cmd, obd_off *);

        /* llog related obd_methods */
        int (*o_llog_init)(struct obd_device *obd, struct obd_llog_group *grp,
                           struct obd_device *disk_obd, int *idx);
        int (*o_llog_finish)(struct obd_device *obd, int count);
        int (*o_llog_connect)(struct obd_export *, struct llogd_conn_body *);

        /* metadata-only methods */
        int (*o_pin)(struct obd_export *, const struct lu_fid *fid,
                     struct obd_capa *, struct obd_client_handle *, int flag);
        int (*o_unpin)(struct obd_export *, struct obd_client_handle *, int);

        int (*o_import_event)(struct obd_device *, struct obd_import *,
                              enum obd_import_event);

        int (*o_notify)(struct obd_device *obd, struct obd_device *watched,
                        enum obd_notify_event ev, void *data);

        int (*o_health_check)(struct obd_device *);
        struct obd_uuid *(*o_get_uuid) (struct obd_export *exp);

        /* quota methods */
        int (*o_quotacheck)(struct obd_device *, struct obd_export *,
                            struct obd_quotactl *);
        int (*o_quotactl)(struct obd_device *, struct obd_export *,
                          struct obd_quotactl *);
        int (*o_quota_adjust_qunit)(struct obd_export *exp,
                                    struct quota_adjust_qunit *oqaq,
                                    struct lustre_quota_ctxt *qctxt,
                                    struct ptlrpc_request_set *rqset);


        int (*o_ping)(struct obd_export *exp);

        /* pools methods */
        int (*o_pool_new)(struct obd_device *obd, char *poolname);
        int (*o_pool_del)(struct obd_device *obd, char *poolname);
        int (*o_pool_add)(struct obd_device *obd, char *poolname,
                          char *ostname);
        int (*o_pool_rem)(struct obd_device *obd, char *poolname,
                          char *ostname);
        void (*o_getref)(struct obd_device *obd);
        void (*o_putref)(struct obd_device *obd);
        /*
         * NOTE: If adding ops, add another LPROCFS_OBD_OP_INIT() line
         * to lprocfs_alloc_obd_stats() in obdclass/lprocfs_status.c.
         * Also, add a wrapper function in include/linux/obd_class.h. */
};

enum {
        LUSTRE_OPC_MKDIR    = (1 << 0),
        LUSTRE_OPC_SYMLINK  = (1 << 1),
        LUSTRE_OPC_MKNOD    = (1 << 2),
        LUSTRE_OPC_CREATE   = (1 << 3),
        LUSTRE_OPC_ANY      = (1 << 4)
};

/* lmv structures */
#define MEA_MAGIC_LAST_CHAR      0xb2221ca1
#define MEA_MAGIC_ALL_CHARS      0xb222a11c
#define MEA_MAGIC_HASH_SEGMENT   0xb222a11b

#define MAX_HASH_SIZE_32         0x7fffffffUL
#define MAX_HASH_SIZE            0x7fffffffffffffffULL
#define MAX_HASH_HIGHEST_BIT     0x1000000000000000ULL

struct lustre_md {
        struct mdt_body         *body;
        struct lov_stripe_md    *lsm;
        struct lmv_stripe_md    *mea;
#ifdef CONFIG_FS_POSIX_ACL
        struct posix_acl        *posix_acl;
#endif
        struct mdt_remote_perm  *remote_perm;
        struct obd_capa         *mds_capa;
        struct obd_capa         *oss_capa;
};

struct md_open_data {
        struct obd_client_handle *mod_och;
        struct ptlrpc_request    *mod_open_req;
        struct ptlrpc_request    *mod_close_req;
        cfs_atomic_t              mod_refcount;
};

struct lookup_intent;

struct md_ops {
        int (*m_getstatus)(struct obd_export *, struct lu_fid *,
                           struct obd_capa **);
        int (*m_change_cbdata)(struct obd_export *, const struct lu_fid *,
                               ldlm_iterator_t, void *);
        int (*m_find_cbdata)(struct obd_export *, const struct lu_fid *,
                             ldlm_iterator_t, void *);
        int (*m_close)(struct obd_export *, struct md_op_data *,
                       struct md_open_data *, struct ptlrpc_request **);
        int (*m_create)(struct obd_export *, struct md_op_data *,
                        const void *, int, int, __u32, __u32, cfs_cap_t,
                        __u64, struct ptlrpc_request **);
        int (*m_done_writing)(struct obd_export *, struct md_op_data  *,
                              struct md_open_data *);
        int (*m_enqueue)(struct obd_export *, struct ldlm_enqueue_info *,
                         struct lookup_intent *, struct md_op_data *,
                         struct lustre_handle *, void *, int,
                         struct ptlrpc_request **, int);
        int (*m_getattr)(struct obd_export *, struct md_op_data *,
                         struct ptlrpc_request **);
        int (*m_getattr_name)(struct obd_export *, struct md_op_data *,
                              struct ptlrpc_request **);
        int (*m_intent_lock)(struct obd_export *, struct md_op_data *,
                             void *, int, struct lookup_intent *, int,
                             struct ptlrpc_request **,
                             ldlm_blocking_callback, int);
        int (*m_link)(struct obd_export *, struct md_op_data *,
                      struct ptlrpc_request **);
        int (*m_rename)(struct obd_export *, struct md_op_data *,
                        const char *, int, const char *, int,
                        struct ptlrpc_request **);
        int (*m_is_subdir)(struct obd_export *, const struct lu_fid *,
                           const struct lu_fid *,
                           struct ptlrpc_request **);
        int (*m_setattr)(struct obd_export *, struct md_op_data *, void *,
                         int , void *, int, struct ptlrpc_request **,
                         struct md_open_data **mod);
        int (*m_sync)(struct obd_export *, const struct lu_fid *,
                      struct obd_capa *, struct ptlrpc_request **);
        int (*m_readpage)(struct obd_export *, const struct lu_fid *,
                          struct obd_capa *, __u64, struct page **,
                          unsigned, struct ptlrpc_request **);

        int (*m_unlink)(struct obd_export *, struct md_op_data *,
                        struct ptlrpc_request **);

        int (*m_setxattr)(struct obd_export *, const struct lu_fid *,
                          struct obd_capa *, obd_valid, const char *,
                          const char *, int, int, int, __u32,
                          struct ptlrpc_request **);

        int (*m_getxattr)(struct obd_export *, const struct lu_fid *,
                          struct obd_capa *, obd_valid, const char *,
                          const char *, int, int, int,
                          struct ptlrpc_request **);

        int (*m_init_ea_size)(struct obd_export *, int, int, int);

        int (*m_get_lustre_md)(struct obd_export *, struct ptlrpc_request *,
                               struct obd_export *, struct obd_export *,
                               struct lustre_md *);

        int (*m_free_lustre_md)(struct obd_export *, struct lustre_md *);

        int (*m_set_open_replay_data)(struct obd_export *,
                                      struct obd_client_handle *,
                                      struct ptlrpc_request *);
        int (*m_clear_open_replay_data)(struct obd_export *,
                                        struct obd_client_handle *);
        int (*m_set_lock_data)(struct obd_export *, __u64 *, void *, __u32 *);

        ldlm_mode_t (*m_lock_match)(struct obd_export *, int,
                                    const struct lu_fid *, ldlm_type_t,
                                    ldlm_policy_data_t *, ldlm_mode_t,
                                    struct lustre_handle *);

        int (*m_cancel_unused)(struct obd_export *, const struct lu_fid *,
                               ldlm_policy_data_t *, ldlm_mode_t,
                               ldlm_cancel_flags_t flags, void *opaque);
        int (*m_renew_capa)(struct obd_export *, struct obd_capa *oc,
                            renew_capa_cb_t cb);
        int (*m_unpack_capa)(struct obd_export *, struct ptlrpc_request *,
                             const struct req_msg_field *, struct obd_capa **);

        int (*m_get_remote_perm)(struct obd_export *, const struct lu_fid *,
                                 struct obd_capa *, __u32,
                                 struct ptlrpc_request **);

        int (*m_intent_getattr_async)(struct obd_export *,
                                      struct md_enqueue_info *,
                                      struct ldlm_enqueue_info *);

        int (*m_revalidate_lock)(struct obd_export *, struct lookup_intent *,
                                 struct lu_fid *);

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
                                    obd_off *);
        void (*lsm_stripe_by_offset)(struct lov_stripe_md *, int *, obd_off *,
                                     obd_off *);
        int (*lsm_lmm_verify) (struct lov_mds_md *lmm, int lmm_bytes,
                               int *stripe_count);
        int (*lsm_unpackmd) (struct lov_obd *lov, struct lov_stripe_md *lsm,
                             struct lov_mds_md *lmm);
};

extern const struct lsm_operations lsm_v1_ops;
extern const struct lsm_operations lsm_v3_ops;
static inline const struct lsm_operations *lsm_op_find(int magic)
{
        switch(magic) {
        case LOV_MAGIC_V1:
               return &lsm_v1_ops;
        case LOV_MAGIC_V3:
               return &lsm_v3_ops;
        default:
               CERROR("Cannot recognize lsm_magic %08x\n", magic);
               return NULL;
        }
}

int lvfs_check_io_health(struct obd_device *obd, struct file *file);

/* Requests for obd_extent_calc() */
#define OBD_CALC_STRIPE_START   1
#define OBD_CALC_STRIPE_END     2

static inline void obd_transno_commit_cb(struct obd_device *obd, __u64 transno,
                                         struct obd_export *exp, int error)
{
        if (error) {
                CERROR("%s: transno "LPU64" commit error: %d\n",
                       obd->obd_name, transno, error);
                return;
        }
        if (exp && transno > exp->exp_last_committed) {
                CDEBUG(D_HA, "%s: transno "LPU64" committed\n",
                       obd->obd_name, transno);
                exp->exp_last_committed = transno;
                ptlrpc_commit_replies(exp);
        } else {
                CDEBUG(D_INFO, "%s: transno "LPU64" committed\n",
                       obd->obd_name, transno);
        }
        if (transno > obd->obd_last_committed)
                obd->obd_last_committed = transno;
}

static inline void init_obd_quota_ops(quota_interface_t *interface,
                                      struct obd_ops *obd_ops)
{
        if (!interface)
                return;

        LASSERT(obd_ops);
        obd_ops->o_quotacheck = QUOTA_OP(interface, check);
        obd_ops->o_quotactl = QUOTA_OP(interface, ctl);
        obd_ops->o_quota_adjust_qunit = QUOTA_OP(interface, adjust_qunit);
}

static inline struct lustre_capa *oinfo_capa(struct obd_info *oinfo)
{
        return oinfo->oi_capa;
}

static inline struct md_open_data *obd_mod_alloc(void)
{
        struct md_open_data *mod;
        OBD_ALLOC_PTR(mod);
        if (mod == NULL)
                return NULL;
        cfs_atomic_set(&mod->mod_refcount, 1);
        return mod;
}

#define obd_mod_get(mod) cfs_atomic_inc(&(mod)->mod_refcount)
#define obd_mod_put(mod)                                        \
({                                                              \
        if (cfs_atomic_dec_and_test(&(mod)->mod_refcount)) {          \
                if ((mod)->mod_open_req)                          \
                        ptlrpc_req_finished((mod)->mod_open_req);   \
                OBD_FREE_PTR(mod);                              \
        }                                                       \
})

extern void obdo_from_inode(struct obdo *dst, struct inode *src,
                            struct lu_fid *parent, obd_flag valid);

/* return 1 if client should be resend request */
static inline int client_should_resend(int resend, struct client_obd *cli)
{
        return cfs_atomic_read(&cli->cl_resends) ?
               cfs_atomic_read(&cli->cl_resends) > resend : 1;
}

/**
 * Return device name for this device
 *
 * XXX: lu_device is declared before obd_device, while a pointer pointing
 * back to obd_device in lu_device, so this helper function defines here
 * instead of in lu_object.h
 */
static inline const char *lu_dev_name(const struct lu_device *lu_dev)
{
        return lu_dev->ld_obd->obd_name;
}

#endif /* __OBD_H */
