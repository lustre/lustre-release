/*
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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __OBD_H
#define __OBD_H

#include <linux/spinlock.h>

#include <lustre/lustre_idl.h>
#include <lustre_lib.h>
#include <libcfs/bitmap.h>
#ifdef HAVE_SERVER_SUPPORT
# include <lu_target.h>
# include <obd_target.h>
#endif
#include <lu_ref.h>
#include <lustre_export.h>
#include <lustre_fid.h>
#include <lustre_fld.h>
#include <lustre_handles.h>
#include <lustre_intent.h>
#include <lvfs.h>
#include <lustre_quota.h>

#define MAX_OBD_DEVICES 8192

struct osc_async_rc {
        int     ar_rc;
        int     ar_force_sync;
        __u64   ar_min_xid;
};

struct lov_oinfo {                 /* per-stripe data structure */
	struct ost_id   loi_oi;    /* object ID/Sequence on the target OST */
	int loi_ost_idx;           /* OST stripe index in lov_tgt_desc->tgts */
	int loi_ost_gen;           /* generation of this loi_ost_idx */

	unsigned long loi_kms_valid:1;
	__u64 loi_kms;             /* known minimum size */
	struct ost_lvb loi_lvb;
	struct osc_async_rc     loi_ar;
};

static inline void loi_kms_set(struct lov_oinfo *oinfo, __u64 kms)
{
        oinfo->loi_kms = kms;
        oinfo->loi_kms_valid = 1;
}

struct lov_stripe_md;
struct obd_info;

typedef int (*obd_enqueue_update_f)(void *cookie, int rc);

/* obd info for a particular level (lov, osc). */
struct obd_info {
	/* OBD_STATFS_* flags */
	__u64                   oi_flags;
        /* statfs data specific for every OSC, if needed at all. */
        struct obd_statfs      *oi_osfs;
        /* An update callback which is called to update some data on upper
	 * level. E.g. it is used for update lsm->lsm_oinfo at every received
         * request in osc level for enqueue requests. It is also possible to
         * update some caller data from LOV layer if needed. */
        obd_enqueue_update_f    oi_cb_up;
};

struct obd_type {
	struct list_head	 typ_chain;
	struct obd_ops		*typ_dt_ops;
	struct md_ops		*typ_md_ops;
	struct proc_dir_entry	*typ_procroot;
	struct proc_dir_entry	*typ_procsym;
	__u32			 typ_sym_filter;
	char			*typ_name;
	int			 typ_refcnt;
	struct lu_device_type	*typ_lu;
	spinlock_t		 obd_type_lock;
};

struct brw_page {
	u64		 off;
	struct page	*pg;
	u32		 count;
	u32		 flag;
};

struct timeout_item {
	enum timeout_event ti_event;
	cfs_time_t         ti_timeout;
	timeout_cb_t       ti_cb;
	void              *ti_cb_data;
	struct list_head   ti_obd_list;
	struct list_head   ti_chain;
};

#define OBD_MAX_RIF_DEFAULT	8
#define OBD_MAX_RIF_MAX		512
#define OSC_MAX_RIF_MAX		256
#define OSC_MAX_DIRTY_DEFAULT	(OBD_MAX_RIF_DEFAULT * 4)
#define OSC_MAX_DIRTY_MB_MAX	2048     /* arbitrary, but < MAX_LONG bytes */
#define OSC_DEFAULT_RESENDS	10

/* possible values for fo_sync_lock_cancel */
enum {
        NEVER_SYNC_ON_CANCEL = 0,
        BLOCKING_SYNC_ON_CANCEL = 1,
        ALWAYS_SYNC_ON_CANCEL = 2,
        NUM_SYNC_ON_CANCEL_STATES
};

/*
 * Limit reply buffer size for striping data to one x86_64 page. This
 * value is chosen to fit the striping data for common use cases while
 * staying well below the limit at which the buffer must be backed by
 * vmalloc(). Excessive use of vmalloc() may cause spinlock contention
 * on the MDS.
 */
#define OBD_MAX_DEFAULT_EA_SIZE		4096

enum obd_cl_sem_lock_class {
	OBD_CLI_SEM_NORMAL,
	OBD_CLI_SEM_MGC,
	OBD_CLI_SEM_MDCOSC,
};

struct mdc_rpc_lock;
struct obd_import;
struct client_obd {
	struct rw_semaphore	 cl_sem;
	struct obd_uuid		 cl_target_uuid;
	struct obd_import	*cl_import; /* ptlrpc connection state */
	size_t			 cl_conn_count;

	/* Cache maximum and default values for easize. This is
	 * strictly a performance optimization to minimize calls to
	 * obd_size_diskmd(). The default values are used to calculate the
	 * initial size of a request buffer. The ptlrpc layer will resize the
	 * buffer as needed to accommodate a larger reply from the
	 * server. The default values should be small enough to avoid wasted
	 * memory and excessive use of vmalloc(), yet large enough to avoid
	 * reallocating the buffer in the common use case. */

	/* Default EA size for striping attributes. It is initialized at
	 * mount-time based on the default stripe width of the filesystem,
	 * then it tracks the largest observed EA size advertised by
	 * the MDT, up to a maximum value of OBD_MAX_DEFAULT_EA_SIZE. */
	__u32			 cl_default_mds_easize;

	/* Maximum possible EA size computed at mount-time based on
	 * the number of OSTs in the filesystem. May be increased at
	 * run-time if a larger observed size is advertised by the MDT. */
	__u32			 cl_max_mds_easize;

	enum lustre_sec_part	 cl_sp_me;
	enum lustre_sec_part	 cl_sp_to;
	struct sptlrpc_flavor	 cl_flvr_mgc; /* fixed flavor of mgc->mgs */

	/* the grant values are protected by loi_list_lock below */
	unsigned long		 cl_dirty_pages;      /* all _dirty_ in pages */
	unsigned long		 cl_dirty_max_pages;  /* allowed w/o rpc */
	unsigned long		 cl_dirty_transit;    /* dirty synchronous */
	unsigned long		 cl_avail_grant;   /* bytes of credit for ost */
	unsigned long		 cl_lost_grant;    /* lost credits (trunc) */
	/* grant consumed for dirty pages */
	unsigned long		 cl_dirty_grant;

	/* since we allocate grant by blocks, we don't know how many grant will
	 * be used to add a page into cache. As a solution, we reserve maximum
	 * grant before trying to dirty a page and unreserve the rest.
	 * See osc_{reserve|unreserve}_grant for details. */
	long			cl_reserved_grant;
	struct list_head	cl_cache_waiters; /* waiting for cache/grant */
	cfs_time_t		cl_next_shrink_grant;   /* jiffies */
	struct list_head	cl_grant_shrink_list;  /* Timeout event list */
	int			cl_grant_shrink_interval; /* seconds */

	/* A chunk is an optimal size used by osc_extent to determine
	 * the extent size. A chunk is max(PAGE_SIZE, OST block size) */
	int			cl_chunkbits;
	/* extent insertion metadata overhead to be accounted in grant,
	 * in bytes */
	unsigned int		cl_grant_extent_tax;
	/* maximum extent size, in number of pages */
	unsigned int		cl_max_extent_pages;

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
	 * NB by Jinshan: though field names are still _loi_, but actually
	 * osc_object{}s are in the list.
	 */
	spinlock_t		cl_loi_list_lock;
	struct list_head	cl_loi_ready_list;
	struct list_head	cl_loi_hp_ready_list;
	struct list_head	cl_loi_write_list;
	struct list_head	cl_loi_read_list;
	__u32			cl_r_in_flight;
	__u32			cl_w_in_flight;
	/* just a sum of the loi/lop pending numbers to be exported by /proc */
	atomic_t		cl_pending_w_pages;
	atomic_t		cl_pending_r_pages;
	__u32			cl_max_pages_per_rpc;
	__u32			cl_max_rpcs_in_flight;
	struct obd_histogram	cl_read_rpc_hist;
	struct obd_histogram	cl_write_rpc_hist;
	struct obd_histogram	cl_read_page_hist;
	struct obd_histogram	cl_write_page_hist;
	struct obd_histogram	cl_read_offset_hist;
	struct obd_histogram	cl_write_offset_hist;

	/** LRU for osc caching pages */
	struct cl_client_cache  *cl_cache;
	/** member of cl_cache->ccc_lru */
	struct list_head         cl_lru_osc;
	/** # of available LRU slots left in the per-OSC cache.
	 * Available LRU slots are shared by all OSCs of the same file system,
	 * therefore this is a pointer to cl_client_cache::ccc_lru_left. */
	atomic_long_t           *cl_lru_left;
	/** # of busy LRU pages. A page is considered busy if it's in writeback
	 * queue, or in transfer. Busy pages can't be discarded so they are not
	 * in LRU cache. */
	atomic_long_t            cl_lru_busy;
	/** # of LRU pages in the cache for this client_obd */
	atomic_long_t            cl_lru_in_list;
	/** # of threads are shrinking LRU cache. To avoid contention, it's not
	 * allowed to have multiple threads shrinking LRU cache. */
	atomic_t                 cl_lru_shrinkers;
	/** The time when this LRU cache was last used. */
	time64_t		 cl_lru_last_used;
	/** stats: how many reclaims have happened for this client_obd.
	 * reclaim and shrink - shrink is async, voluntarily rebalancing;
	 * reclaim is sync, initiated by IO thread when the LRU slots are
	 * in shortage. */
	__u64                    cl_lru_reclaim;
	/** List of LRU pages for this client_obd */
	struct list_head         cl_lru_list;
	/** Lock for LRU page list */
	spinlock_t		 cl_lru_list_lock;
	/** # of unstable pages in this client_obd.
	 * An unstable page is a page state that WRITE RPC has finished but
	 * the transaction has NOT yet committed. */
	atomic_long_t            cl_unstable_count;
	/** Link to osc_shrinker_list */
	struct list_head	 cl_shrink_list;

	/* number of in flight destroy rpcs is limited to max_rpcs_in_flight */
	atomic_t		 cl_destroy_in_flight;
	wait_queue_head_t	 cl_destroy_waitq;

        struct mdc_rpc_lock     *cl_rpc_lock;

	/* modify rpcs in flight
	 * currently used for metadata only */
	spinlock_t		 cl_mod_rpcs_lock;
	__u16			 cl_max_mod_rpcs_in_flight;
	__u16			 cl_mod_rpcs_in_flight;
	__u16			 cl_close_rpcs_in_flight;
	wait_queue_head_t	 cl_mod_rpcs_waitq;
	unsigned long		*cl_mod_tag_bitmap;
	struct obd_histogram	 cl_mod_rpcs_hist;

        /* mgc datastruct */
	struct mutex		  cl_mgc_mutex;
	struct local_oid_storage *cl_mgc_los;
	struct dt_object	 *cl_mgc_configs_dir;
	atomic_t		  cl_mgc_refcount;
	struct obd_export        *cl_mgc_mgsexp;

        /* checksumming for data sent over the network */
	unsigned int		 cl_checksum:1, /* 0 = disabled, 1 = enabled */
				 cl_checksum_dump:1; /* same */
        /* supported checksum types that are worked out at connect time */
        __u32                    cl_supp_cksum_types;
        /* checksum algorithm to be used */
        cksum_type_t             cl_cksum_type;

        /* also protected by the poorly named _loi_list_lock lock above */
        struct osc_async_rc      cl_ar;

	/* sequence manager */
	struct lu_client_seq    *cl_seq;
	struct rw_semaphore	 cl_seq_rwsem;

	atomic_t		 cl_resends; /* resend count */

	/* ptlrpc work for writeback in ptlrpcd context */
	void			*cl_writeback_work;
	void			*cl_lru_work;
	/* hash tables for osc_quota_info */
	struct cfs_hash		*cl_quota_hash[LL_MAXQUOTAS];
	/* Links to the global list of registered changelog devices */
	struct list_head	 cl_chg_dev_linkage;
};
#define obd2cli_tgt(obd) ((char *)(obd)->u.cli.cl_target_uuid.uuid)

struct obd_id_info {
	u32	 idx;
	u64	*data;
};

struct echo_client_obd {
	struct obd_export      *ec_exp;	/* the local connection to osc/lov */
	spinlock_t		ec_lock;
	struct list_head	ec_objects;
	struct list_head	ec_locks;
	__u64			ec_unique;
};

/* Generic subset of OSTs */
struct ost_pool {
        __u32              *op_array;      /* array of index of
                                                   lov_obd->lov_tgts */
        unsigned int        op_count;      /* number of OSTs in the array */
        unsigned int        op_size;       /* allocated size of lp_array */
	struct rw_semaphore op_rw_sem;     /* to protect ost_pool use */
};

/* allow statfs data caching for 1 second */
#define OBD_STATFS_CACHE_SECONDS 1

struct lov_tgt_desc {
	struct list_head    ltd_kill;
        struct obd_uuid     ltd_uuid;
        struct obd_device  *ltd_obd;
        struct obd_export  *ltd_exp;
        __u32               ltd_gen;
        __u32               ltd_index;   /* index in lov_obd->tgts */
        unsigned long       ltd_active:1,/* is this target up for requests */
                            ltd_activate:1,/* should  target be activated */
                            ltd_reap:1;  /* should this target be deleted */
};

struct lov_obd {
	struct lov_desc		desc;
	struct lov_tgt_desc   **lov_tgts;		/* sparse array */
	struct ost_pool		lov_packed;		/* all OSTs in a packed
							   array */
	struct mutex		lov_lock;
	struct obd_connect_data	lov_ocd;
	struct proc_dir_entry  *targets_proc_entry;
	atomic_t		lov_refcount;
	__u32			lov_death_row;	/* tgts scheduled to be deleted */
	__u32			lov_tgt_size;	/* size of tgts array */
	int			lov_connects;
	int			lov_pool_count;
	struct cfs_hash	       *lov_pools_hash_body; /* used for key access */
	struct list_head	lov_pool_list;	/* used for sequential access */
	struct proc_dir_entry  *lov_pool_proc_entry;
	enum lustre_sec_part	lov_sp_me;

	/* Cached LRU and unstable data from upper layer */
	struct cl_client_cache *lov_cache;

	struct rw_semaphore	lov_notify_lock;
};

struct lmv_tgt_desc {
	struct obd_uuid		ltd_uuid;
	struct obd_export	*ltd_exp;
	__u32			ltd_idx;
	struct mutex		ltd_fid_mutex;
	unsigned long		ltd_active:1; /* target up for requests */
};

struct lmv_obd {
	struct lu_client_fld	lmv_fld;
	spinlock_t		lmv_lock;
	struct lmv_desc		desc;
	struct proc_dir_entry	*targets_proc_entry;

	struct mutex		lmv_init_mutex;
	int			connected;
	int			max_easize;
	int			max_def_easize;

	__u32			tgts_size; /* size of tgts array */
	struct lmv_tgt_desc	**tgts;

	struct obd_connect_data	conn_data;
};

struct niobuf_local {
	__u64		lnb_file_offset;
	__u32		lnb_page_offset;
	__u32		lnb_len;
	__u32		lnb_flags;
	int		lnb_rc;
	struct page	*lnb_page;
	void		*lnb_data;
};

struct tgt_thread_big_cache {
	struct niobuf_local	local[PTLRPC_MAX_BRW_PAGES];
};

#define LUSTRE_FLD_NAME         "fld"
#define LUSTRE_SEQ_NAME         "seq"

#define LUSTRE_MDD_NAME         "mdd"
#define LUSTRE_OSD_LDISKFS_NAME	"osd-ldiskfs"
#define LUSTRE_OSD_ZFS_NAME     "osd-zfs"
#define LUSTRE_VVP_NAME         "vvp"
#define LUSTRE_LMV_NAME         "lmv"
#define LUSTRE_SLP_NAME         "slp"
#define LUSTRE_LOD_NAME		"lod"
#define LUSTRE_OSP_NAME		"osp"
#define LUSTRE_LWP_NAME		"lwp"

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

#define LUSTRE_ECHO_NAME        "obdecho"
#define LUSTRE_ECHO_CLIENT_NAME "echo_client"
#define LUSTRE_QMT_NAME         "qmt"

/* Constant obd names (post-rename) */
#define LUSTRE_MDS_OBDNAME "MDS"
#define LUSTRE_OSS_OBDNAME "OSS"
#define LUSTRE_MGS_OBDNAME "MGS"
#define LUSTRE_MGC_OBDNAME "MGC"

static inline int is_lwp_on_mdt(char *name)
{
	char   *ptr;

	ptr = strrchr(name, '-');
	if (ptr == NULL) {
		CERROR("%s is not a obdname\n", name);
		return 0;
	}

	/* LWP name on MDT is fsname-MDTxxxx-lwp-MDTxxxx */

	if (strncmp(ptr + 1, "MDT", 3) != 0)
		return 0;

	while (*(--ptr) != '-' && ptr != name);

	if (ptr == name)
		return 0;

	if (strncmp(ptr + 1, LUSTRE_LWP_NAME, strlen(LUSTRE_LWP_NAME)) != 0)
		return 0;

	return 1;
}

static inline int is_lwp_on_ost(char *name)
{
	char   *ptr;

	ptr = strrchr(name, '-');
	if (ptr == NULL) {
		CERROR("%s is not a obdname\n", name);
		return 0;
	}

	/* LWP name on OST is fsname-MDTxxxx-lwp-OSTxxxx */

	if (strncmp(ptr + 1, "OST", 3) != 0)
		return 0;

	while (*(--ptr) != '-' && ptr != name);

	if (ptr == name)
		return 0;

	if (strncmp(ptr + 1, LUSTRE_LWP_NAME, strlen(LUSTRE_LWP_NAME)) != 0)
		return 0;

	return 1;
}

/*
 * Events signalled through obd_notify() upcall-chain.
 */
enum obd_notify_event {
        /* Device connect start */
        OBD_NOTIFY_CONNECT,
        /* Device activated */
        OBD_NOTIFY_ACTIVE,
        /* Device deactivated */
        OBD_NOTIFY_INACTIVE,
        /* Connect data for import were changed */
        OBD_NOTIFY_OCD,
        /* Administratively deactivate/activate event */
        OBD_NOTIFY_DEACTIVATE,
        OBD_NOTIFY_ACTIVATE
};

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

struct target_recovery_data {
	svc_handler_t		trd_recovery_handler;
	pid_t			trd_processing_task;
	struct completion	trd_starting;
	struct completion	trd_finishing;
};

struct obd_llog_group {
	struct llog_ctxt   *olg_ctxts[LLOG_MAX_CTXTS];
	wait_queue_head_t  olg_waitq;
	spinlock_t	   olg_lock;
	struct mutex	   olg_cat_processing;
};

/* corresponds to one of the obd's */
#define OBD_DEVICE_MAGIC        0XAB5CD6EF

struct obd_device {
	struct obd_type			*obd_type;
	__u32				 obd_magic; /* OBD_DEVICE_MAGIC */
	int				 obd_minor; /* device number: lctl dl */
	struct lu_device		*obd_lu_dev;

	/* common and UUID name of this device */
	struct obd_uuid			 obd_uuid;
	char				 obd_name[MAX_OBD_NAME];

	/* bitfield modification is protected by obd_dev_lock */
	unsigned long
		obd_attached:1,		/* finished attach */
		obd_set_up:1,		/* finished setup */
		obd_recovering:1,	/* there are recoverable clients */
		obd_abort_recovery:1,	/* recovery expired */
		obd_version_recov:1,	/* obd uses version checking */
		obd_replayable:1,	/* recovery enabled; inform clients */
		obd_no_transno:1,	/* no committed-transno notification */
		obd_no_recov:1,		/* fail instead of retry messages */
		obd_stopping:1,		/* started cleanup */
		obd_starting:1,		/* started setup */
		obd_force:1,		/* cleanup with > 0 obd refcount */
		obd_fail:1,		/* cleanup with failover */
		obd_no_conn:1,		/* deny new connections */
		obd_inactive:1,		/* device active/inactive
					 * (for /proc/status only!!) */
		obd_no_ir:1,		/* no imperative recovery. */
		obd_process_conf:1,	/* device is processing mgs config */
		obd_uses_nid_stats:1,	/* maintain per-client OBD stats */
		obd_checksum_dump:1;	/* dump pages upon cksum error */

        /* use separate field as it is set in interrupt to don't mess with
         * protection of other bits using _bh lock */
        unsigned long obd_recovery_expired:1;
        /* uuid-export hash body */
	struct cfs_hash             *obd_uuid_hash;
        /* nid-export hash body */
	struct cfs_hash             *obd_nid_hash;
	/* nid stats body */
	struct cfs_hash             *obd_nid_stats_hash;
	/* client_generation-export hash body */
	struct cfs_hash		    *obd_gen_hash;
	struct list_head	obd_nid_stats;
	struct list_head	obd_exports;
	struct list_head	obd_unlinked_exports;
	struct list_head	obd_delayed_exports;
	struct list_head	obd_lwp_list;
	atomic_t		obd_refcount;
	int                     obd_num_exports;
	spinlock_t		obd_nid_lock;
	struct ldlm_namespace  *obd_namespace;
	struct ptlrpc_client	obd_ldlm_client; /* XXX OST/MDS only */
	/* a spinlock is OK for what we do now, may need a semaphore later */
	spinlock_t		obd_dev_lock; /* protect OBD bitfield above */
	spinlock_t		obd_osfs_lock;
	struct obd_statfs	obd_osfs;       /* locked by obd_osfs_lock */
	__u64			obd_osfs_age;
	__u64			obd_last_committed;
	struct mutex		obd_dev_mutex;
	struct lvfs_run_ctxt	obd_lvfs_ctxt;
	struct obd_llog_group	obd_olg;	/* default llog group */
	struct obd_device	*obd_observer;
	struct rw_semaphore	obd_observer_link_sem;
        struct obd_notify_upcall obd_upcall;
        struct obd_export       *obd_self_export;
	struct obd_export	*obd_lwp_export;
	/* list of exports in LRU order, for ping evictor, with obd_dev_lock */
	struct list_head	obd_exports_timed;
	time_t			obd_eviction_timer;	/* for ping evictor */

	int                     obd_max_recoverable_clients;
	atomic_t                obd_connected_clients;
	int                     obd_stale_clients;
        /* this lock protects all recovery list_heads, timer and
         * obd_next_recovery_transno value */
	spinlock_t		obd_recovery_task_lock;
	__u64			obd_next_recovery_transno;
	int			obd_replayed_requests;
	int			obd_requests_queued_for_recovery;
	wait_queue_head_t	obd_next_transno_waitq;
	/* protected by obd_recovery_task_lock */
	struct timer_list	obd_recovery_timer;
	/* seconds */
	time64_t		obd_recovery_start;
	/* seconds, for lprocfs_status */
	time64_t		obd_recovery_end;
	time64_t		obd_recovery_time_hard;
	time64_t		obd_recovery_timeout;
	int			obd_recovery_ir_factor;

	/* new recovery stuff from CMD2 */
	int				obd_replayed_locks;
	atomic_t			obd_req_replay_clients;
	atomic_t			obd_lock_replay_clients;
	struct target_recovery_data	obd_recovery_data;

	/* all lists are protected by obd_recovery_task_lock */
	struct list_head		obd_req_replay_queue;
	struct list_head		obd_lock_replay_queue;
	struct list_head		obd_final_req_queue;

	union {
#ifdef HAVE_SERVER_SUPPORT
		struct obd_device_target obt;
		struct filter_obd filter;
		struct ost_obd ost;
		struct echo_obd echo;
#endif
		struct client_obd cli;
		struct echo_client_obd echo_client;
		struct lov_obd lov;
		struct lmv_obd lmv;
	} u;

	/* Fields used by LProcFS */
	struct lprocfs_stats		*obd_stats;
	unsigned int			obd_cntr_base;

	unsigned int			 obd_md_cntr_base;
	struct lprocfs_stats		*obd_md_stats;

	struct proc_dir_entry	*obd_proc_entry;
	struct proc_dir_entry	*obd_proc_exports_entry;
	struct proc_dir_entry	*obd_svc_procroot;
	struct lprocfs_stats	*obd_svc_stats;
	struct lprocfs_vars	*obd_vars;
	atomic_t		obd_evict_inprogress;
	wait_queue_head_t	obd_evict_inprogress_waitq;
	struct list_head	obd_evict_list;	/* protected with pet_lock */

	/**
	 * LDLM pool part. Save last calculated SLV and Limit.
	 */
	rwlock_t			obd_pool_lock;
	__u64				obd_pool_slv;
	int				obd_pool_limit;

	int				obd_conn_inprogress;

	/**
	 * List of outstanding class_incref()'s fo this OBD. For debugging. */
	struct lu_ref			obd_reference;
};

/* get/set_info keys */
#define KEY_ASYNC               "async"
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
#define KEY_INTERMDS            "inter_mds"
#define KEY_LAST_ID             "last_id"
#define KEY_LAST_FID		"last_fid"
#define KEY_MAX_EASIZE		"max_easize"
#define KEY_DEFAULT_EASIZE	"default_easize"
#define KEY_MGSSEC              "mgssec"
#define KEY_READ_ONLY           "read-only"
#define KEY_REGISTER_TARGET     "register_target"
#define KEY_SET_FS              "set_fs"
#define KEY_TGT_COUNT           "tgt_count"
/*      KEY_SET_INFO in lustre_idl.h */
#define KEY_SPTLRPC_CONF        "sptlrpc_conf"

#define KEY_CACHE_SET		"cache_set"
#define KEY_CACHE_LRU_SHRINK	"cache_lru_shrink"
#define KEY_OSP_CONNECTED	"osp_connected"

struct lu_context;

static inline int it_to_lock_mode(struct lookup_intent *it)
{
	/* CREAT needs to be tested before open (both could be set) */
	if (it->it_op & IT_CREAT)
		return LCK_CW;
	else if (it->it_op & (IT_GETATTR | IT_OPEN | IT_LOOKUP |
			      IT_LAYOUT))
		return LCK_CR;
	else if (it->it_op &  IT_READDIR)
		return LCK_PR;
	else if (it->it_op &  IT_GETXATTR)
		return LCK_PR;
	else if (it->it_op &  IT_SETXATTR)
		return LCK_PW;

	LASSERTF(0, "Invalid it_op: %d\n", it->it_op);
	return -EINVAL;
}

enum md_op_flags {
	MF_MDC_CANCEL_FID1	= 1 << 0,
	MF_MDC_CANCEL_FID2	= 1 << 1,
	MF_MDC_CANCEL_FID3	= 1 << 2,
	MF_MDC_CANCEL_FID4	= 1 << 3,
	MF_GET_MDT_IDX		= 1 << 4,
};

enum md_cli_flags {
	CLI_SET_MEA     = 1 << 0,
	CLI_RM_ENTRY    = 1 << 1,
	CLI_HASH64      = 1 << 2,
	CLI_API32       = 1 << 3,
	CLI_MIGRATE     = 1 << 4,
};

/**
 * GETXATTR is not included as only a couple of fields in the reply body
 * is filled, but not FID which is needed for common intent handling in
 * mdc_finish_intent_lock()
 */
static inline bool it_has_reply_body(const struct lookup_intent *it)
{
	return it->it_op & (IT_OPEN | IT_UNLINK | IT_LOOKUP | IT_GETATTR);
}

struct md_op_data {
	struct lu_fid		op_fid1; /* operation fid1 (usualy parent) */
	struct lu_fid		op_fid2; /* operation fid2 (usualy child) */
	struct lu_fid		op_fid3; /* 2 extra fids to find conflicting */
	struct lu_fid		op_fid4; /* to the operation locks. */
	u32			op_mds;  /* what mds server open will go to */
	__u32			op_mode;
	struct lustre_handle	op_handle;
	s64			op_mod_time;
	const char		*op_name;
	size_t			op_namelen;
	struct lmv_stripe_md	*op_mea1;
	struct lmv_stripe_md	*op_mea2;
	__u32			op_suppgids[2];
	__u32			op_fsuid;
	__u32			op_fsgid;
	cfs_cap_t		op_cap;
	void			*op_data;
	size_t			op_data_size;

	/* iattr fields and blocks. */
	struct iattr            op_attr;
	loff_t                  op_attr_blocks;
	__u64                   op_valid; /* OBD_MD_* */
	unsigned int		op_attr_flags; /* LUSTRE_{SYNC,..}_FL */

	enum md_op_flags	op_flags;

	/* Various operation flags. */
	enum mds_op_bias        op_bias;

	/* used to transfer info between the stacks of MD client
	 * see enum op_cli_flags */
	enum md_cli_flags	op_cli_flags;

	/* File object data version for HSM release, on client */
	__u64			op_data_version;
	struct lustre_handle	op_lease_handle;

	/* File security context, for creates. */
	const char	       *op_file_secctx_name;
	void		       *op_file_secctx;
	__u32			op_file_secctx_size;

	/* default stripe offset */
	__u32			op_default_stripe_offset;

	__u32			op_projid;

	/* Used by readdir */
	unsigned int		op_max_pages;

};

struct md_callback {
	int (*md_blocking_ast)(struct ldlm_lock *lock,
			       struct ldlm_lock_desc *desc,
			       void *data, int flag);
};

struct md_enqueue_info;
/* metadata stat-ahead */
typedef int (* md_enqueue_cb_t)(struct ptlrpc_request *req,
                                struct md_enqueue_info *minfo,
                                int rc);

struct md_enqueue_info {
	struct md_op_data		mi_data;
	struct lookup_intent		mi_it;
	struct lustre_handle		mi_lockh;
	struct inode		       *mi_dir;
	struct ldlm_enqueue_info	mi_einfo;
	md_enqueue_cb_t			mi_cb;
	void			       *mi_cbdata;
};

struct obd_ops {
	struct module *o_owner;
	int (*o_iocontrol)(unsigned int cmd, struct obd_export *exp, int len,
			   void *karg, void __user *uarg);
	int (*o_get_info)(const struct lu_env *env, struct obd_export *,
			  __u32 keylen, void *key, __u32 *vallen, void *val);
	int (*o_set_info_async)(const struct lu_env *, struct obd_export *,
				__u32 keylen, void *key,
				__u32 vallen, void *val,
				struct ptlrpc_request_set *set);
	int (*o_setup) (struct obd_device *dev, struct lustre_cfg *cfg);
	int (*o_precleanup)(struct obd_device *dev);
	int (*o_cleanup)(struct obd_device *dev);
	int (*o_process_config)(struct obd_device *dev, size_t len, void *data);
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
	int (*o_fid_init)(struct obd_device *obd,
			  struct obd_export *exp, enum lu_cli_type type);
	int (*o_fid_fini)(struct obd_device *obd);

	/* Allocate new fid according to passed @hint. */
	int (*o_fid_alloc)(const struct lu_env *env, struct obd_export *exp,
			   struct lu_fid *fid, struct md_op_data *op_data);

	/*
	 * Object with @fid is getting deleted, we may want to do something
	 * about this.
	 */
	int (*o_statfs)(const struct lu_env *, struct obd_export *exp,
			struct obd_statfs *osfs, __u64 max_age, __u32 flags);
	int (*o_statfs_async)(struct obd_export *exp, struct obd_info *oinfo,
			      __u64 max_age, struct ptlrpc_request_set *set);
	int (*o_create)(const struct lu_env *env, struct obd_export *exp,
			struct obdo *oa);
	int (*o_destroy)(const struct lu_env *env, struct obd_export *exp,
			 struct obdo *oa);
	int (*o_setattr)(const struct lu_env *, struct obd_export *exp,
			 struct obdo *oa);
	int (*o_getattr)(const struct lu_env *env, struct obd_export *exp,
			 struct obdo *oa);
	int (*o_preprw)(const struct lu_env *env, int cmd,
			struct obd_export *exp, struct obdo *oa, int objcount,
			struct obd_ioobj *obj, struct niobuf_remote *remote,
			int *nr_pages, struct niobuf_local *local);
	int (*o_commitrw)(const struct lu_env *env, int cmd,
			  struct obd_export *exp, struct obdo *oa,
			  int objcount, struct obd_ioobj *obj,
			  struct niobuf_remote *remote, int pages,
			  struct niobuf_local *local, int rc);
	int (*o_init_export)(struct obd_export *exp);
	int (*o_destroy_export)(struct obd_export *exp);

	int (*o_import_event)(struct obd_device *, struct obd_import *,
			      enum obd_import_event);

	int (*o_notify)(struct obd_device *obd, struct obd_device *watched,
			enum obd_notify_event ev);

	int (*o_health_check)(const struct lu_env *env, struct obd_device *);
	struct obd_uuid *(*o_get_uuid) (struct obd_export *exp);

	/* quota methods */
	int (*o_quotactl)(struct obd_device *, struct obd_export *,
			  struct obd_quotactl *);

	int (*o_ping)(const struct lu_env *, struct obd_export *exp);

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

/* lmv structures */
struct lustre_md {
	struct mdt_body         *body;
	struct lu_buf		 layout;
	struct lmv_stripe_md    *lmv;
#ifdef CONFIG_FS_POSIX_ACL
	struct posix_acl        *posix_acl;
#endif
};

struct md_open_data {
	struct obd_client_handle	*mod_och;
	struct ptlrpc_request		*mod_open_req;
	struct ptlrpc_request		*mod_close_req;
	atomic_t			 mod_refcount;
	bool				 mod_is_create;
};

struct obd_client_handle {
	struct lustre_handle	 och_fh;
	struct lu_fid		 och_fid;
	struct md_open_data	*och_mod;
	struct lustre_handle	 och_lease_handle; /* open lock for lease */
	__u32			 och_magic;
	int			 och_flags;
};

#define OBD_CLIENT_HANDLE_MAGIC 0xd15ea5ed

struct lookup_intent;
struct cl_attr;

struct md_ops {
	/* Every operation from MD_STATS_FIRST_OP up to and including
	 * MD_STATS_LAST_OP will be counted by EXP_MD_OP_INCREMENT()
	 * and will appear in /proc/fs/lustre/{lmv,mdc}/.../md_stats.
	 * Operations after MD_STATS_LAST_OP are excluded from stats.
	 * There are a few reasons for doing this: we prune the 17
	 * counters which will be of minimal use in understanding
	 * metadata utilization, we save memory by allocating 15
	 * instead of 32 counters, we save cycles by not counting.
	 *
	 * MD_STATS_FIRST_OP must be the first member of md_ops.
	 */
#define MD_STATS_FIRST_OP m_close
	int (*m_close)(struct obd_export *, struct md_op_data *,
		       struct md_open_data *, struct ptlrpc_request **);

	int (*m_create)(struct obd_export *, struct md_op_data *,
			const void *, size_t, umode_t, uid_t, gid_t,
			cfs_cap_t, __u64, struct ptlrpc_request **);

	int (*m_enqueue)(struct obd_export *, struct ldlm_enqueue_info *,
			 const union ldlm_policy_data *, struct md_op_data *,
			 struct lustre_handle *, __u64);

	int (*m_getattr)(struct obd_export *, struct md_op_data *,
			 struct ptlrpc_request **);

	int (*m_intent_lock)(struct obd_export *, struct md_op_data *,
			     struct lookup_intent *,
			     struct ptlrpc_request **,
			     ldlm_blocking_callback, __u64);

	int (*m_link)(struct obd_export *, struct md_op_data *,
		      struct ptlrpc_request **);

	int (*m_rename)(struct obd_export *, struct md_op_data *,
			const char *, size_t, const char *, size_t,
			struct ptlrpc_request **);

	int (*m_setattr)(struct obd_export *, struct md_op_data *, void *,
			 size_t , struct ptlrpc_request **);

	int (*m_fsync)(struct obd_export *, const struct lu_fid *,
		       struct ptlrpc_request **);

	int (*m_read_page)(struct obd_export *, struct md_op_data *,
			   struct md_callback *cb_op, __u64 hash_offset,
			   struct page **ppage);

	int (*m_unlink)(struct obd_export *, struct md_op_data *,
			struct ptlrpc_request **);

	int (*m_setxattr)(struct obd_export *, const struct lu_fid *,
			  u64, const char *, const char *, int, int, int, u32,
			  struct ptlrpc_request **);

	int (*m_getxattr)(struct obd_export *, const struct lu_fid *,
			  u64, const char *, const char *, int, int, int,
			  struct ptlrpc_request **);

	int (*m_intent_getattr_async)(struct obd_export *,
				      struct md_enqueue_info *);

        int (*m_revalidate_lock)(struct obd_export *, struct lookup_intent *,
                                 struct lu_fid *, __u64 *bits);

#define MD_STATS_LAST_OP m_revalidate_lock

	int (*m_get_root)(struct obd_export *, const char *, struct lu_fid *);
	int (*m_null_inode)(struct obd_export *, const struct lu_fid *);

	int (*m_getattr_name)(struct obd_export *, struct md_op_data *,
			      struct ptlrpc_request **);

	int (*m_init_ea_size)(struct obd_export *, __u32, __u32);

	int (*m_get_lustre_md)(struct obd_export *, struct ptlrpc_request *,
			       struct obd_export *, struct obd_export *,
			       struct lustre_md *);

	int (*m_free_lustre_md)(struct obd_export *, struct lustre_md *);

	int (*m_merge_attr)(struct obd_export *,
			    const struct lmv_stripe_md *lsm,
			    struct cl_attr *attr, ldlm_blocking_callback);

	int (*m_set_open_replay_data)(struct obd_export *,
				      struct obd_client_handle *,
				      struct lookup_intent *);

	int (*m_clear_open_replay_data)(struct obd_export *,
					struct obd_client_handle *);

	int (*m_set_lock_data)(struct obd_export *,
			       const struct lustre_handle *, void *, __u64 *);

	enum ldlm_mode (*m_lock_match)(struct obd_export *, __u64,
				       const struct lu_fid *, enum ldlm_type,
				       union ldlm_policy_data *, enum ldlm_mode,
				       struct lustre_handle *);

	int (*m_cancel_unused)(struct obd_export *, const struct lu_fid *,
			       union ldlm_policy_data *, enum ldlm_mode,
			       enum ldlm_cancel_flags flags, void *opaque);

	int (*m_get_fid_from_lsm)(struct obd_export *,
				  const struct lmv_stripe_md *,
				  const char *name, int namelen,
				  struct lu_fid *fid);
	int (*m_unpackmd)(struct obd_export *exp, struct lmv_stripe_md **plsm,
			  const union lmv_mds_md *lmv, size_t lmv_size);
};

static inline struct md_open_data *obd_mod_alloc(void)
{
	struct md_open_data *mod;
	OBD_ALLOC_PTR(mod);
	if (mod == NULL)
		return NULL;
	atomic_set(&mod->mod_refcount, 1);
	return mod;
}

#define obd_mod_get(mod) atomic_inc(&(mod)->mod_refcount)
#define obd_mod_put(mod)                                          \
({                                                                \
	if (atomic_dec_and_test(&(mod)->mod_refcount)) {      	  \
		if ((mod)->mod_open_req)                          \
			ptlrpc_req_finished((mod)->mod_open_req); \
		OBD_FREE_PTR(mod);                                \
	}                                                         \
})

void obdo_from_inode(struct obdo *dst, struct inode *src, u64 valid);
void obdo_set_parent_fid(struct obdo *dst, const struct lu_fid *parent);
void obdo_set_o_projid(struct obdo *dst, u32 projid);

/* return 1 if client should be resend request */
static inline int client_should_resend(int resend, struct client_obd *cli)
{
	return atomic_read(&cli->cl_resends) ?
	       atomic_read(&cli->cl_resends) > resend : 1;
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

static inline bool filename_is_volatile(const char *name, size_t namelen,
					int *idx)
{
	const char	*start;
	char		*end;

	if (strncmp(name, LUSTRE_VOLATILE_HDR, LUSTRE_VOLATILE_HDR_LEN) != 0)
		return false;

	/* caller does not care of idx */
	if (idx == NULL)
		return true;

	/* volatile file, the MDT can be set from name */
	/* name format is LUSTRE_VOLATILE_HDR:[idx]: */
	/* if no MDT is specified, use std way */
	if (namelen < LUSTRE_VOLATILE_HDR_LEN + 2)
		goto bad_format;
	/* test for no MDT idx case */
	if ((*(name + LUSTRE_VOLATILE_HDR_LEN) == ':') &&
	    (*(name + LUSTRE_VOLATILE_HDR_LEN + 1) == ':')) {
		*idx = -1;
		return true;
	}
	/* we have an idx, read it */
	start = name + LUSTRE_VOLATILE_HDR_LEN + 1;
	*idx = simple_strtoul(start, &end, 16);
	/* error cases:
	 * no digit, no trailing :, negative value
	 */
	if (((*idx == 0) && (end == start)) ||
	    (*end != ':') || (*idx < 0))
		goto bad_format;

	return true;
bad_format:
	/* bad format of mdt idx, we cannot return an error
	 * to caller so we use hash algo */
	CERROR("Bad volatile file name format: %s\n",
	       name + LUSTRE_VOLATILE_HDR_LEN);
	return false;
}

static inline int cli_brw_size(struct obd_device *obd)
{
	LASSERT(obd != NULL);
	return obd->u.cli.cl_max_pages_per_rpc << PAGE_SHIFT;
}

/* when RPC size or the max RPCs in flight is increased, the max dirty pages
 * of the client should be increased accordingly to avoid sending fragmented
 * RPCs over the network when the client runs out of the maximum dirty space
 * when so many RPCs are being generated.
 */
static inline void client_adjust_max_dirty(struct client_obd *cli)
{
	 /* initializing */
	if (cli->cl_dirty_max_pages <= 0)
		cli->cl_dirty_max_pages = (OSC_MAX_DIRTY_DEFAULT * 1024 * 1024)
							>> PAGE_SHIFT;
	else {
		unsigned long dirty_max = cli->cl_max_rpcs_in_flight *
					  cli->cl_max_pages_per_rpc;

		if (dirty_max > cli->cl_dirty_max_pages)
			cli->cl_dirty_max_pages = dirty_max;
	}

	if (cli->cl_dirty_max_pages > totalram_pages / 8)
		cli->cl_dirty_max_pages = totalram_pages / 8;
}

#endif /* __OBD_H */
