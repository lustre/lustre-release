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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
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
/* Moved to lustre_user.h
#define IOC_MDC_LOOKUP       _IOWR(IOC_MDC_TYPE, 20, struct obd_ioctl_data *)
#define IOC_MDC_GETSTRIPE    _IOWR(IOC_MDC_TYPE, 21, struct lov_mds_md *) */
#define IOC_MDC_MAX_NR       50

#include <lustre_lib.h>
#include <lustre/lustre_idl.h>
#include <lustre_export.h>
#include <lustre_quota.h>
#include <class_hash.h>

#include <libcfs/bitmap.h>


#define MAX_OBD_DEVICES 8192

/* this is really local to the OSC */
struct loi_oap_pages {
        struct list_head        lop_pending;
        struct list_head        lop_urgent;
        struct list_head        lop_pending_group;
        int                     lop_num_pending;
};

struct osc_async_rc {
        int     ar_rc;
        int     ar_force_sync;
        __u64   ar_min_xid;
};

struct lov_oinfo {                 /* per-stripe data structure */
        __u64 loi_id;              /* object ID on the target OST */
        __u64 loi_gr;              /* object group on the target OST */
        int loi_ost_idx;           /* OST stripe index in lov_tgt_desc->tgts */
        int loi_ost_gen;           /* generation of this loi_ost_idx */

        /* used by the osc to keep track of what objects to build into rpcs */
        struct loi_oap_pages loi_read_lop;
        struct loi_oap_pages loi_write_lop;
        struct list_head loi_ready_item;
        struct list_head loi_hp_ready_item;
        struct list_head loi_write_item;
        struct list_head loi_read_item;

        unsigned long loi_kms_valid:1;
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
        CFS_INIT_LIST_HEAD(&loi->loi_ready_item);
        CFS_INIT_LIST_HEAD(&loi->loi_hp_ready_item);
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

                /* LOV-private members start here -- only for use in lov/. */
                __u32 lw_magic;
                __u32 lw_stripe_size;      /* size of the stripe */
                __u32 lw_pattern;          /* striping pattern (RAID0, RAID1) */
                unsigned lw_stripe_count;  /* number of objects being striped over */
                char  lw_pool_name[LOV_MAXPOOLNAME]; /* pool name */
        } lsm_wire;

        struct lov_array_info *lsm_array; /*Only for joined file array info*/
        struct lov_oinfo *lsm_oinfo[0];
};

#define lsm_object_id    lsm_wire.lw_object_id
#define lsm_object_gr    lsm_wire.lw_object_gr
#define lsm_maxbytes     lsm_wire.lw_maxbytes
#define lsm_magic        lsm_wire.lw_magic
#define lsm_stripe_size  lsm_wire.lw_stripe_size
#define lsm_pattern      lsm_wire.lw_pattern
#define lsm_stripe_count lsm_wire.lw_stripe_count
#define lsm_pool_name    lsm_wire.lw_pool_name

struct obd_info;

typedef int (*obd_enqueue_update_f)(struct obd_info *oinfo, int rc);

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
};

/* compare all relevant fields. */
static inline int lov_stripe_md_cmp(struct lov_stripe_md *m1,
                                    struct lov_stripe_md *m2)
{
       if ((m1->lsm_magic == LOV_MAGIC_V1 && m2->lsm_magic == LOV_MAGIC_V3) ||
           (m1->lsm_magic == LOV_MAGIC_V3 && m2->lsm_magic == LOV_MAGIC_V1))
                /*
                 * Dowgrade/upgrade case (b=20318) to a version that
                 * doesn't/does OST pools. Compare only objid and stripe
                 * size/count in this case
                 */
                return m1->lsm_object_id != m2->lsm_object_id ||
                       m1->lsm_stripe_size != m2->lsm_stripe_size ||
                       m1->lsm_stripe_count != m2->lsm_stripe_count;

        /*
         * ->lsm_wire contains padding, but it should be zeroed out during
         * allocation.
         */
        return memcmp(&m1->lsm_wire, &m2->lsm_wire, sizeof(m1->lsm_wire));
}

void lov_stripe_lock(struct lov_stripe_md *md);
void lov_stripe_unlock(struct lov_stripe_md *md);

struct obd_type {
        struct list_head typ_chain;
        struct obd_ops *typ_ops;
        cfs_proc_dir_entry_t *typ_procroot;
        char *typ_name;
        int  typ_refcnt;
        spinlock_t obd_type_lock;
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
        ASYNC_HP = 0x10,
};

struct obd_async_page_ops {
        int  (*ap_make_ready)(void *data, int cmd);
        int  (*ap_refresh_count)(void *data, int cmd);
        void (*ap_fill_obdo)(void *data, int cmd, struct obdo *oa);
        void (*ap_update_obdo)(void *data, int cmd, struct obdo *oa,
                               obd_valid valid);
        int  (*ap_completion)(void *data, int cmd, struct obdo *oa, int rc);
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
        unsigned long interrupted:1;
};

/* Individual type definitions */

struct ost_server_data;

/* hold common fields for "target" device */
struct obd_device_target {
        struct super_block       *obt_sb;
        /** last_rcvd file */
        struct file              *obt_rcvd_filp;
        /** server data in last_rcvd file */
        struct lr_server_data    *obt_lsd;
        /** Lock protecting client bitmap */
        spinlock_t                obt_client_bitmap_lock;
        /** Bitmap of known clients */
        unsigned long            *obt_client_bitmap;
        /** Server last transaction number */
        __u64                     obt_last_transno;
        /** Lock protecting last transaction number */
        spinlock_t                obt_translock;
        /** Number of mounts */
        __u64                     obt_mount_count;
        atomic_t                  obt_quotachecking;
        struct lustre_quota_ctxt  obt_qctxt;
        lustre_quota_version_t    obt_qfmt;
        __u32                     obt_stale_export_age;
        spinlock_t                obt_trans_table_lock;
        struct vfsmount          *obt_vfsmnt;
        struct file              *obt_health_check_filp;
};

typedef void (*obd_pin_extent_cb)(void *data);
typedef int (*obd_page_removal_cb_t)(void *data, int discard);
typedef int (*obd_lock_cancel_cb)(struct ldlm_lock *,struct ldlm_lock_desc *,
                                   void *, int);

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
        cfs_dentry_t        *fo_dentry_O;
        cfs_dentry_t       **fo_dentry_O_groups;
        cfs_dentry_t       **fo_dentry_O_sub;
        spinlock_t           fo_objidlock;      /* protect fo_lastobjid */

        int                  fo_destroy_in_progress;
        struct semaphore     fo_create_lock;

        struct list_head     fo_export_list;
        int                  fo_subdir_count;

        obd_size             fo_tot_dirty;      /* protected by obd_osfs_lock */
        obd_size             fo_tot_granted;    /* all values in bytes */
        obd_size             fo_tot_pending;
        int                  fo_tot_granted_clients;

        obd_size             fo_readcache_max_filesize;
        unsigned long        fo_read_cache:1,         /* read-only cache */
                             fo_writethrough_cache:1, /* writetrhough cache */
                             fo_syncjournal:1,      /* sync journal on writes */
                             fo_sync_lock_cancel:2, /* sync on lock cancel */
                             fo_raid_degraded:1,    /* RAID device degraded */
                             fo_mds_ost_sync:1; /**< MDS-OST orphan recovery*/

        struct obd_import   *fo_mdc_imp;
        struct obd_uuid      fo_mdc_uuid;
        struct lustre_handle fo_mdc_conn;
        struct file        **fo_last_objid_files;
        __u64               *fo_last_objids; /* last created objid for groups,
                                              * protected by fo_objidlock */

        struct semaphore     fo_alloc_lock;

        atomic_t             fo_r_in_flight;
        atomic_t             fo_w_in_flight;

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

        struct brw_stats         fo_filter_stats;
        struct lustre_quota_ctxt fo_quota_ctxt;
        spinlock_t               fo_quotacheck_lock;
        atomic_t                 fo_quotachecking;

        int                      fo_fmd_max_num; /* per exp filter_mod_data */
        int                      fo_fmd_max_age; /* jiffies to fmd expiry */
        struct llog_commit_master *fo_lcm;
};

#define fo_translock            fo_obt.obt_translock
#define fo_rcvd_filp            fo_obt.obt_rcvd_filp
#define fo_fsd                  fo_obt.obt_lsd
#define fo_last_rcvd_slots      fo_obt.obt_client_bitmap
#define fo_mount_count          fo_obt.obt_mount_count
#define fo_vfsmnt               fo_obt.obt_vfsmnt

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
struct lustre_cache;

struct timeout_item {
        enum timeout_event ti_event;
        cfs_time_t         ti_timeout;
        timeout_cb_t       ti_cb;
        void              *ti_cb_data;
        struct list_head   ti_obd_list;
        struct list_head   ti_chain;
};

struct lu_client_seq {
        /* Sequence-controller export. */
        struct obd_export      *lcs_exp;
        struct semaphore        lcs_sem;

        /*
         * Range of allowed for allocation sequences. When using lu_client_seq
         * on clients, this contains meta-sequence range. And for servers this
         * contains super-sequence range.
         */
        struct lu_seq_range         lcs_space;

        /* This holds last allocated fid in last obtained seq */
        struct lu_fid           lcs_fid;

        /* LUSTRE_SEQ_METADATA or LUSTRE_SEQ_DATA */
        enum lu_cli_type        lcs_type;
        /*
         * Service uuid, passed from MDT + seq name to form unique seq name to
         * use it with procfs.
         */
        char                    lcs_name[80];

        /*
         * Sequence width, that is how many objects may be allocated in one
         * sequence. Default value for it is LUSTRE_SEQ_MAX_WIDTH.
         */
        __u64                   lcs_width;

};

struct client_obd {
        struct rw_semaphore      cl_sem;
        struct obd_uuid          cl_target_uuid;
        struct obd_import       *cl_import; /* ptlrpc connection state */
        int                      cl_conn_count;
        /* max_mds_easize is purely a performance thing so we don't have to
         * call obd_size_diskmd() all the time. */
        unsigned                 cl_default_mds_easize;
        unsigned                 cl_max_mds_easize;
        unsigned                 cl_max_mds_cookiesize;

        //struct llog_canceld_ctxt *cl_llcd; /* it's included by obd_llog_ctxt */
        void                    *cl_llcd_offset;

        /* the grant values are protected by loi_list_lock below */
        long                     cl_dirty;         /* all _dirty_ in bytes */
        long                     cl_dirty_max;     /* allowed w/o rpc */
        long                     cl_avail_grant;   /* bytes of credit for ost */
        long                     cl_lost_grant;    /* lost credits (trunc) */
        struct list_head         cl_cache_waiters; /* waiting for cache/grant */
        cfs_time_t               cl_next_shrink_grant;   /* jiffies */
        struct list_head         cl_grant_shrink_list;  /* Timeout event list */
        struct semaphore         cl_grant_sem;   /*grant shrink list semaphore*/
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
        struct list_head         cl_loi_ready_list;
        struct list_head         cl_loi_hp_ready_list;
        struct list_head         cl_loi_write_list;
        struct list_head         cl_loi_read_list;
        int                      cl_r_in_flight;
        int                      cl_w_in_flight;
        int                      cl_dio_r_in_flight;
        int                      cl_dio_w_in_flight;
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
        atomic_t                 cl_destroy_in_flight;
        cfs_waitq_t              cl_destroy_waitq;

        struct mdc_rpc_lock     *cl_rpc_lock;
        struct mdc_rpc_lock     *cl_setattr_lock;
        struct mdc_rpc_lock     *cl_close_lock;
        struct osc_creator       cl_oscc;

        /* mgc datastruct */
        struct semaphore         cl_mgc_sem;
        struct vfsmount         *cl_mgc_vfsmnt;
        struct dentry           *cl_mgc_configs_dir;
        atomic_t                 cl_mgc_refcount;
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

        atomic_t                 cl_resends; /* resend count */
        /* Cache of triples */
        struct lustre_cache     *cl_cache;
        obd_lock_cancel_cb       cl_ext_lock_cancel_cb;
};
#define obd2cli_tgt(obd) ((char *)(obd)->u.cli.cl_target_uuid.uuid)

#define CL_NOT_QUOTACHECKED 1   /* client->cl_qchk_stat init value */

struct mgs_obd {
        struct obd_device_target         mgs_obt;
        struct ptlrpc_service           *mgs_service;
        struct vfsmount                 *mgs_vfsmnt;
        struct super_block              *mgs_sb;
        struct dentry                   *mgs_configs_dir;
        struct dentry                   *mgs_fid_de;
        struct list_head                 mgs_fs_db_list;
        struct semaphore                 mgs_sem;
        cfs_proc_dir_entry_t            *mgs_proc_live;
};

struct mds_obd {
        /* NB this field MUST be first */
        struct obd_device_target         mds_obt;
        struct ptlrpc_service           *mds_service;
        struct ptlrpc_service           *mds_setattr_service;
        struct ptlrpc_service           *mds_readpage_service;
        cfs_dentry_t                    *mds_fid_de;
        int                              mds_max_mdsize;
        int                              mds_max_cookiesize;
        __u64                            mds_io_epoch;
        unsigned long                    mds_atime_diff;
        struct semaphore                 mds_epoch_sem;
        struct ll_fid                    mds_rootfid;
        cfs_dentry_t                    *mds_pending_dir;
        cfs_dentry_t                    *mds_logs_dir;
        cfs_dentry_t                    *mds_objects_dir;
        struct llog_handle              *mds_cfg_llh;
//        struct llog_handle              *mds_catalog;
        struct obd_device               *mds_lov_obd;
        struct obd_uuid                  mds_lov_uuid;
        char                            *mds_profile;
        struct obd_export               *mds_lov_exp;
        struct lov_desc                  mds_lov_desc;

        /* mark pages dirty for write. */
        bitmap_t                         *mds_lov_page_dirty;
        /* array for store pages with obd_id */
        void                            **mds_lov_page_array;
        /* file for store objid */
        struct file                     *mds_lov_objid_filp;
        __u32                            mds_lov_objid_count;
        __u32                            mds_lov_objid_max_index;
        __u32                            mds_lov_objid_lastpage;
        __u32                            mds_lov_objid_lastidx;

        struct upcall_cache             *mds_group_hash;

        struct lustre_quota_info         mds_quota_info;
        struct semaphore                 mds_qonoff_sem;
        struct semaphore                 mds_health_sem;
        unsigned long                    mds_fl_user_xattr:1,
                                         mds_fl_acl:1,
                                         mds_fl_cfglog:1,
                                         mds_fl_synced:1,
                                         mds_fl_target:1, /* mds have one or
                                                           * more targets */
                                         mds_evict_ost_nids:1;

        uid_t                            mds_squash_uid;
        gid_t                            mds_squash_gid;
        lnet_nid_t                       mds_nosquash_nid;
        /* do we need permission sync */
        unsigned int                     mds_sync_permission;
};

#define mds_transno_lock         mds_obt.obt_translock
#define mds_rcvd_filp            mds_obt.obt_rcvd_filp
#define mds_server_data          mds_obt.obt_lsd
#define mds_client_bitmap        mds_obt.obt_client_bitmap
#define mds_mount_count          mds_obt.obt_mount_count
#define mds_last_transno         mds_obt.obt_last_transno
#define mds_vfsmnt               mds_obt.obt_vfsmnt

/* lov objid */
#define mds_max_ost_index  (0xFFFF)
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

struct lov_qos_oss {
        struct obd_uuid     lqo_uuid;       /* ptlrpc's c_remote_uuid */
        struct list_head    lqo_oss_list;   /* link to lov_qos */
        __u64               lqo_bavail;     /* total bytes avail on OSS */
        __u64               lqo_penalty;    /* current penalty */
        __u64               lqo_penalty_per_obj; /* penalty decrease every obj*/
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
        __u32              *op_array;        /* array of index of
                                                lov_obd->lov_tgts */
        unsigned int        op_count;        /* number of OSTs in the array */
        unsigned int        op_size;         /* allocated size of lp_array */
        struct rw_semaphore op_rw_sem;       /* to protect ost_pool use */
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
        struct list_head    lq_oss_list;    /* list of OSSs that targets use */
        struct rw_semaphore lq_rw_sem;
        __u32               lq_active_oss_count;
        unsigned int        lq_prio_free;   /* priority for free space */
        unsigned int        lq_threshold_rr;/* priority for rr */
        struct lov_qos_rr   lq_rr;          /* round robin qos data */
        unsigned long       lq_dirty:1,     /* recalc qos data */
                            lq_same_space:1,/* the ost's all have approx.
                                               the same space avail */
                            lq_reset:1,     /* zero current penalties */
                            lq_statfs_in_progress:1; /* statfs op in progress */
        /* qos statfs data */
        struct lov_statfs_data *lq_statfs_data;
        cfs_waitq_t         lq_statfs_waitq; /* waitqueue to notify statfs
                                              * requests completion */
};

struct lov_tgt_desc {
        struct list_head    ltd_kill;
        struct obd_uuid     ltd_uuid;
        struct obd_device  *ltd_obd;
        struct obd_export  *ltd_exp;
        struct ltd_qos      ltd_qos;     /* qos info per target */
        __u32               ltd_gen;
        __u32               ltd_index;   /* index in lov_obd->tgts */
        unsigned long       ltd_active:1,/* is this target up for requests */
                            ltd_activate:1,/* should this target be activated */
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
        atomic_t              pool_refcount;          /* pool ref. counter */
        struct lov_qos_rr     pool_rr;                /* round robin qos */
        struct hlist_node     pool_hash;              /* access by poolname */
        struct list_head      pool_list;              /* serial access */
        cfs_proc_dir_entry_t *pool_proc_entry;        /* file in /proc */
        struct lov_obd       *pool_lov;               /* lov obd to which this
                                                         pool belong */
};

struct lov_obd {
        struct lov_desc         desc;
        struct lov_tgt_desc   **lov_tgts;              /* sparse array */
        struct ost_pool         lov_packed;            /* all OSTs in a packed
                                                          array */
        struct semaphore        lov_lock;
        struct obd_connect_data lov_ocd;
        struct lov_qos          lov_qos;               /* qos info per lov */
        atomic_t                lov_refcount;
        __u32                   lov_tgt_count;         /* how many OBD's */
        __u32                   lov_active_tgt_count;  /* how many active */
        __u32                   lov_death_row;/* tgts scheduled to be deleted */
        __u32                   lov_tgt_size;   /* size of tgts array */
        int                     lov_connects;
        obd_page_removal_cb_t   lov_page_removal_cb;
        obd_pin_extent_cb       lov_page_pin_cb;
        obd_lock_cancel_cb      lov_lock_cancel_cb;
        int                     lov_pool_count;
        lustre_hash_t          *lov_pools_hash_body; /* used for key access */
        struct list_head        lov_pool_list; /* used for sequential access */
        cfs_proc_dir_entry_t   *lov_pool_proc_entry;
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

/* obd device type names */
 /* FIXME all the references to LUSTRE_MDS_NAME should be swapped with LUSTRE_MDT_NAME */
#define LUSTRE_MDS_NAME         "mds"
#define LUSTRE_MDT_NAME         "mdt"
#define LUSTRE_MDC_NAME         "mdc"
#define LUSTRE_OSS_NAME         "ost" /*FIXME change name to oss*/
#define LUSTRE_OST_NAME         "obdfilter" /* FIXME change name to ost*/
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
        /* VBR: versions */
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
        /* VBR: take versions from request */
        if (req->rq_reqmsg != NULL &&
            lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                __u64 *pre_version = lustre_msg_get_versions(req->rq_reqmsg);
                /* b1.6 interoperability check. pre_versions may be NULL */
                oti->oti_pre_version = pre_version ? pre_version[0] : 0;
                oti->oti_transno = lustre_msg_get_transno(req->rq_reqmsg);
        }

        /* called from mds_create_objects */
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
        /* device target is created */
        OBD_NOTIFY_CREATE,
        /* DEVICE connect start */
        OBD_NOTIFY_CONNECT,
        /* Device activated */
        OBD_NOTIFY_ACTIVE,
        /* Device deactivated */
        OBD_NOTIFY_INACTIVE,
        /* Connect data for import were changed */
        OBD_NOTIFY_OCD,
        /* Sync request */
        OBD_NOTIFY_SYNC_NONBLOCK,
        OBD_NOTIFY_SYNC,
        /* Configuration event */
        OBD_NOTIFY_CONFIG,
        /* Administratively deactivate/activate event */
        OBD_NOTIFY_DEACTIVATE,
        OBD_NOTIFY_ACTIVATE
};

#define CONFIG_LOG      0x1  /* finished processing config log */
#define CONFIG_SYNC     0x2  /* mdt synced 1 ost */
#define CONFIG_TARGET   0x4  /* one target is added */

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
#define MAX_OBD_NAME 128
#define OBD_DEVICE_MAGIC        0XAB5CD6EF
#define OBD_DEV_BY_DEVNAME      0xffffd0de
struct obd_device {
        struct obd_type        *obd_type;
        __u32                   obd_magic;

        /* common and UUID name of this device */
        char                    obd_name[MAX_OBD_NAME];
        struct obd_uuid         obd_uuid;

        int                     obd_minor;
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
                      obd_async_recov:1,   /* allow asyncronous orphan cleanup */
                      obd_no_conn:1,       /* deny new connections */
                      obd_inactive:1;      /* device active/inactive
                                            * (for /proc/status only!!) */
        /* uuid-export hash body */
        struct lustre_hash     *obd_uuid_hash;
        /* nid-export hash body */
        struct lustre_hash     *obd_nid_hash;
        /* nid stats body */
        struct lustre_hash     *obd_nid_stats_hash;
        struct list_head        obd_nid_stats;
        atomic_t                obd_refcount;
        cfs_waitq_t             obd_refcount_waitq;
        struct list_head        obd_exports;
        struct list_head        obd_delayed_exports;
        int                     obd_num_exports;
        spinlock_t              obd_nid_lock;
        struct ldlm_namespace  *obd_namespace;
        struct ptlrpc_client    obd_ldlm_client; /* XXX OST/MDS only */
        /* a spinlock is OK for what we do now, may need a semaphore later */
        spinlock_t              obd_dev_lock;
        struct semaphore        obd_dev_sem;
        __u64                   obd_last_committed;
        struct fsfilt_operations *obd_fsops;
        spinlock_t              obd_osfs_lock;
        struct obd_statfs       obd_osfs;       /* locked by obd_osfs_lock */
        __u64                   obd_osfs_age;
        struct lvfs_run_ctxt    obd_lvfs_ctxt;

        struct llog_ctxt        *obd_llog_ctxt[LLOG_MAX_CTXTS];
        struct semaphore        obd_llog_cat_process;
        cfs_waitq_t             obd_llog_waitq;

        struct obd_device       *obd_observer;
        struct rw_semaphore     obd_observer_link_sem;
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
        int                              obd_stale_clients;
        int                              obd_delayed_clients;
        spinlock_t                       obd_processing_task_lock; /* BH lock (timer) */
        pid_t                            obd_processing_task;
        /* thread to handle recovery queue */
        struct ptlrpc_thread            *obd_recovery_thread;
        __u64                            obd_next_recovery_transno;
        int                              obd_replayed_requests;
        int                              obd_requests_queued_for_recovery;
        cfs_waitq_t                      obd_next_transno_waitq;
        cfs_timer_t                      obd_recovery_timer;
        struct list_head                 obd_recovery_queue;
        struct list_head                 obd_delayed_reply_queue;
        time_t                           obd_recovery_start; /* seconds */
        time_t                           obd_recovery_end; /* seconds, for lprocfs_status */
        time_t                           obd_recovery_time_hard;
        int                              obd_recovery_timeout;

        union {
                struct obd_device_target obt;
                struct filter_obd filter;
                struct mds_obd mds;
                struct client_obd cli;
                struct ost_obd ost;
                struct echo_client_obd echo_client;
                struct echo_obd echo;
                struct lov_obd lov;
                struct mgs_obd mgs;
        } u;
        /* Fields used by LProcFS */
        cfs_proc_dir_entry_t  *obd_proc_entry;
        cfs_proc_dir_entry_t  *obd_proc_exports_entry;
        cfs_proc_dir_entry_t  *obd_svc_procroot;
        struct lprocfs_stats  *obd_stats;
        struct lprocfs_stats  *obd_svc_stats;
        unsigned int           obd_cntr_base;
        atomic_t               obd_evict_inprogress;
        cfs_waitq_t            obd_evict_inprogress_waitq;
        struct list_head       obd_evict_list; /* protected with pet_lock */

        /* Ldlm pool part. Save last calculated SLV and Limit. */
        rwlock_t               obd_pool_lock;
        int                    obd_pool_limit;
        __u64                  obd_pool_slv;
};

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
#define KEY_MDS_CONN            "mds_conn"
#define KEY_NEXT_ID             "next_id"
#define KEY_LOVDESC             "lovdesc"
#define KEY_INIT_RECOV          "initial_recov"
#define KEY_INIT_RECOV_BACKUP   "init_recov_bk"
#define KEY_LAST_ID             "last_id"
#define KEY_LOCK_TO_STRIPE      "lock_to_stripe"
#define KEY_CHECKSUM            "checksum"
#define KEY_READONLY            "read-only"
#define KEY_READONLY_166COMPAT  "readonly"
#define KEY_EVICT_BY_NID        "evict_by_nid"
#define KEY_REGISTER_TARGET     "register_target"
#define KEY_SET_FS              "set_fs"
#define KEY_CLEAR_FS            "clear_fs"
#define KEY_SET_INFO            "set_info"
#define KEY_BLOCKSIZE           "blocksize"
#define KEY_BLOCKSIZE_BITS      "blocksize_bits"
#define KEY_MAX_EASIZE          "max_ea_size"
#define KEY_FIEMAP              "fiemap"
#define KEY_CONNECT_FLAG        "connect_flags"
#define KEY_SYNC_LOCK_CANCEL    "sync_lock_cancel"
/* XXX unused */
#define KEY_ASYNC               "async"
#define KEY_CAPA_KEY            "capa_key"
#define KEY_GRANT_SHRINK        "grant_shrink"
#define KEY_OFF_RPCSIZE         "off_rpcsize"

struct obd_ops {
        struct module *o_owner;
        int (*o_iocontrol)(unsigned int cmd, struct obd_export *exp, int len,
                           void *karg, void *uarg);
        int (*o_get_info)(struct obd_export *, __u32 keylen, void *key,
                          __u32 *vallen, void *val, struct lov_stripe_md *lsm);
        int (*o_set_info_async)(struct obd_export *, __u32 keylen, void *key,
                                __u32 vallen, void *val,
                                struct ptlrpc_request_set *set);
        int (*o_attach)(struct obd_device *dev, obd_count len, void *data);
        int (*o_detach)(struct obd_device *dev);
        int (*o_setup) (struct obd_device *dev, obd_count len, void *data);
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
                         struct obd_uuid *cluuid, struct obd_connect_data *ocd,
                         void *localdata);
        int (*o_reconnect)(struct obd_export *exp, struct obd_device *src,
                           struct obd_uuid *cluuid,
                           struct obd_connect_data *ocd,
                           void *localdata);
        int (*o_disconnect)(struct obd_export *exp);

        /* Initialize/finalize fids infrastructure. */
        int (*o_fid_init)(struct obd_export *exp);
        int (*o_fid_fini)(struct obd_export *exp);

        int (*o_statfs)(struct obd_device *obd, struct obd_statfs *osfs,
                        __u64 max_age, __u32 flags);
        int (*o_statfs_async)(struct obd_device *obd, struct obd_info *oinfo,
                              __u64 max_age, struct ptlrpc_request_set *set);
        int (*o_packmd)(struct obd_export *exp, struct lov_mds_md **disk_tgt,
                        struct lov_stripe_md *mem_src);
        int (*o_unpackmd)(struct obd_export *exp,struct lov_stripe_md **mem_tgt,
                          struct lov_mds_md *disk_src, int disk_len);
        int (*o_checkmd)(struct obd_export *exp, struct obd_export *md_exp,
                         struct lov_stripe_md *mem_tgt);
        int (*o_preallocate)(struct lustre_handle *, obd_count *req,
                             obd_id *ids);
        int (*o_precreate)(struct obd_export *exp);
        int (*o_create)(struct obd_export *exp,  struct obdo *oa,
                        struct lov_stripe_md **ea, struct obd_trans_info *oti);
        int (*o_create_async)(struct obd_export *exp,  struct obd_info *oinfo,
                              struct lov_stripe_md **ea,
                              struct obd_trans_info *oti);
        int (*o_destroy)(struct obd_export *exp, struct obdo *oa,
                         struct lov_stripe_md *ea, struct obd_trans_info *oti,
                         struct obd_export *md_exp);
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
        int (*o_brw_async)(int rw, struct obd_export *exp,
                           struct obd_info *oinfo, obd_count oa_bufs,
                           struct brw_page *pgarr, struct obd_trans_info *oti,
                           struct ptlrpc_request_set *, int pshift);
        int (*o_prep_async_page)(struct obd_export *exp,
                                 struct lov_stripe_md *lsm,
                                 struct lov_oinfo *loi,
                                 cfs_page_t *page, obd_off offset,
                                 struct obd_async_page_ops *ops, void *data,
                                 void **res, int flags,
                                 struct lustre_handle *lockh);
        int (*o_get_lock)(struct obd_export *exp, struct lov_stripe_md *lsm,
                          void **res, int rw, obd_off start, obd_off end,
                          struct lustre_handle *lockh, int flags);
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
        int (*o_update_lvb)(struct obd_export *exp, struct lov_stripe_md *lsm,
                            struct ost_lvb *lvb, obd_flag valid);
        int (*o_adjust_kms)(struct obd_export *exp, struct lov_stripe_md *lsm,
                            obd_off size, int shrink);
        int (*o_punch)(struct obd_export *exp, struct obd_info *oinfo,
                       struct obd_trans_info *oti,
                       struct ptlrpc_request_set *rqset);
        int (*o_sync)(struct obd_export *exp, struct obd_info *oinfo,
                      obd_size start, obd_size end,
                      struct ptlrpc_request_set *rqset);
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
                        struct niobuf_remote *remote, int *nr_pages,
                        struct niobuf_local *local,
                        struct obd_trans_info *oti);
        int (*o_commitrw)(int cmd, struct obd_export *exp, struct obdo *oa,
                          int objcount, struct obd_ioobj *obj,
                          struct niobuf_remote *remote, int pages,
                          struct niobuf_local *local,
                          struct obd_trans_info *oti, int rc);
        int (*o_enqueue)(struct obd_export *, struct obd_info *oinfo,
                         struct ldlm_enqueue_info *einfo,
                         struct ptlrpc_request_set *rqset);
        int (*o_match)(struct obd_export *, struct lov_stripe_md *, __u32 type,
                       ldlm_policy_data_t *, __u32 mode, int *flags, void *data,
                       struct lustre_handle *lockh, int *n_matches);
        int (*o_change_cbdata)(struct obd_export *, struct lov_stripe_md *,
                               ldlm_iterator_t it, void *data);
        int (*o_find_cbdata)(struct obd_export *, struct lov_stripe_md *,
                             ldlm_iterator_t it, void *data);
        int (*o_cancel)(struct obd_export *, struct lov_stripe_md *md,
                        __u32 mode, struct lustre_handle *, int flags,
                        obd_off end);
        int (*o_cancel_unused)(struct obd_export *, struct lov_stripe_md *,
                               int flags, void *opaque);
        int (*o_join_lru)(struct obd_export *, struct lov_stripe_md *,
                         int join);
        int (*o_init_export)(struct obd_export *exp);
        int (*o_destroy_export)(struct obd_export *exp);
        int (*o_extent_calc)(struct obd_export *, struct lov_stripe_md *,
                             int cmd, obd_off *);

        /* llog related obd_methods */
        int (*o_llog_init)(struct obd_device *obd, struct obd_device *disk_obd,
                           int *idx);
        int (*o_llog_finish)(struct obd_device *obd, int count);
        int (*o_llog_connect)(struct obd_export *, struct llogd_conn_body *);

        /* metadata-only methods */
        int (*o_pin)(struct obd_export *, struct ll_fid *,
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
        int (*o_quota_adjust_qunit)(struct obd_export *exp,
                                    struct quota_adjust_qunit *oqaq,
                                    struct lustre_quota_ctxt *qctxt);


        int (*o_ping)(struct obd_export *exp);

        int (*o_register_page_removal_cb)(struct obd_device *obd,
                                          obd_page_removal_cb_t cb,
                                          obd_pin_extent_cb pin_cb);
        int (*o_unregister_page_removal_cb)(struct obd_device *obd,
                                            obd_page_removal_cb_t cb);
        int (*o_register_lock_cancel_cb)(struct obd_device *obd,
                                       obd_lock_cancel_cb cb);
        int (*o_unregister_lock_cancel_cb)(struct obd_device *obd,
                                         obd_lock_cancel_cb cb);
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

struct lsm_operations {
        void (*lsm_free)(struct lov_stripe_md *);
        int (*lsm_destroy)(struct lov_stripe_md *, struct obdo *oa,
                           struct obd_export *md_exp);
        void (*lsm_stripe_by_index)(struct lov_stripe_md *, int *, obd_off *,
                                    obd_off *);
        void (*lsm_stripe_by_offset)(struct lov_stripe_md *, int *, obd_off *,
                                     obd_off *);
        obd_off (*lsm_stripe_offset_by_index)(struct lov_stripe_md *, int);
        obd_off (*lsm_stripe_offset_by_offset)(struct lov_stripe_md *, obd_off);
        int (*lsm_stripe_index_by_offset)(struct lov_stripe_md *, obd_off);
        int (*lsm_revalidate) (struct lov_stripe_md *, struct obd_device *obd);
        int (*lsm_lmm_verify) (struct lov_mds_md *lmm, int lmm_bytes,
                               int *stripe_count);
        int (*lsm_unpackmd) (struct lov_obd *lov, struct lov_stripe_md *lsm,
                             struct lov_mds_md *lmm);
};

extern struct lsm_operations lsm_v1_ops;
extern struct lsm_operations lsm_join_ops;
extern struct lsm_operations lsm_v3_ops;
static inline struct lsm_operations *lsm_op_find(int magic)
{
        switch(magic) {
        case LOV_MAGIC_V1:
               return &lsm_v1_ops;
        case LOV_MAGIC_JOIN:
               return &lsm_join_ops;
        case LOV_MAGIC_V3:
               return &lsm_v3_ops;
        default:
               CERROR("Cannot recognize lsm_magic %x\n", magic);
               return NULL;
        }
}

int lvfs_check_io_health(struct obd_device *obd, struct file *file);

/* Requests for obd_extent_calc() */
#define OBD_CALC_STRIPE_START          0x0001
#define OBD_CALC_STRIPE_END            0x0010
#define OBD_CALC_STRIPE_RPC_ALIGN      0x0100

#define OBD_CALC_STRIPE_RPC_START_ALIGN (OBD_CALC_STRIPE_START | \
                                         OBD_CALC_STRIPE_RPC_ALIGN)
#define OBD_CALC_STRIPE_RPC_END_ALIGN (OBD_CALC_STRIPE_END | \
                                       OBD_CALC_STRIPE_RPC_ALIGN)

static inline void obd_transno_commit_cb(struct obd_device *obd, __u64 transno,
                                         struct obd_export *exp, int error)
{
        if (error) {
                CERROR("%s: transno "LPU64" commit error: %d\n",
                       obd->obd_name, transno, error);
                return;
        }
        if (exp && transno > exp->exp_last_committed) {
                CDEBUG(D_INFO, "%s: transno "LPU64" committed\n",
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

/*
 * Checksums
 */

#ifdef HAVE_ADLER
/* Default preferred checksum algorithm to use (if supported by the server) */
#define OSC_DEFAULT_CKSUM OBD_CKSUM_ADLER
/* Adler-32 is supported */
#define CHECKSUM_ADLER OBD_CKSUM_ADLER
#else
#define OSC_DEFAULT_CKSUM OBD_CKSUM_CRC32
#define CHECKSUM_ADLER 0
#endif

#define OBD_CKSUM_ALL (OBD_CKSUM_CRC32 | CHECKSUM_ADLER)

/* Checksum algorithm names. Must be defined in the same order as the
 * OBD_CKSUM_* flags. */
#define DECLARE_CKSUM_NAME char *cksum_name[] = {"crc32", "adler"}

#endif /* __OBD_H */
