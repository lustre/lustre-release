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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/osd/osd_internal.h
 *
 * Shared definitions and declarations for osd module
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef _OSD_INTERNAL_H
#define _OSD_INTERNAL_H


/* struct mutex */
#include <linux/mutex.h>
/* struct rw_semaphore */
#include <linux/rwsem.h>
/* struct dentry */
#include <linux/dcache.h>
/* struct dirent64 */
#include <linux/dirent.h>
#include <linux/statfs.h>
#include <linux/bio.h>
#include <ldiskfs/ldiskfs.h>
#include <ldiskfs/ldiskfs_jbd2.h>

/* LUSTRE_OSD_NAME */
#include <obd.h>
/* class_register_type(), class_unregister_type() */
#include <obd_class.h>
#include <lustre_disk.h>
#include <dt_object.h>
#include <lustre_quota.h>

#include "osd_oi.h"
#include "osd_iam.h"
#include "osd_scrub.h"
#include "osd_quota_fmt.h"

struct inode;
extern struct kmem_cache *dynlock_cachep;

#define OSD_COUNTERS (0)

/* ldiskfs special inode::i_state_flags need to be accessed with
 * ldiskfs_{set,clear,test}_inode_state() only */

/* OI scrub should skip this inode. */
#define LDISKFS_STATE_LUSTRE_NOSCRUB	31
#define LDISKFS_STATE_LUSTRE_DESTROY	30

/** Enable thandle usage statistics */
#define OSD_THANDLE_STATS (0)

#define MAX_OBJID_GROUP (FID_SEQ_ECHO + 1)

#define OBJECTS  	"OBJECTS"
#define ADMIN_USR	"admin_quotafile_v2.usr"
#define ADMIN_GRP	"admin_quotafile_v2.grp"

/* Statfs space reservation for fragmentation and local objects */
#define OSD_STATFS_RESERVED		(1ULL << 23) /* 8MB */
#define OSD_STATFS_RESERVED_SHIFT	(7) /* reserve 0.78% of all space */

/* Default extent bytes when declaring write commit */
#define OSD_DEFAULT_EXTENT_BYTES	(1U << 20)

/* check if ldiskfs support project quota */
#ifndef LDISKFS_IOC_FSSETXATTR
#undef HAVE_PROJECT_QUOTA
#endif

#define OBD_BRW_MAPPED	OBD_BRW_LOCAL1

struct osd_directory {
        struct iam_container od_container;
        struct iam_descr     od_descr;
};

/*
 * Object Index (oi) instance.
 */
struct osd_oi {
        /*
         * underlying index object, where fid->id mapping in stored.
         */
        struct inode         *oi_inode;
        struct osd_directory  oi_dir;
};

extern const int osd_dto_credits_noquota[];

struct osd_object {
	struct dt_object        oo_dt;
	/**
	 * Inode for file system object represented by this osd_object. This
	 * inode is pinned for the whole duration of lu_object life.
	 *
	 * Not modified concurrently (either setup early during object
	 * creation, or assigned by osd_create() under write lock).
	 */
	struct inode           *oo_inode;
	/**
	 * to protect index ops.
	 */
	struct htree_lock_head *oo_hl_head;
	struct rw_semaphore	oo_ext_idx_sem;
	struct rw_semaphore	oo_sem;
	struct osd_directory	*oo_dir;
	/** protects inode attributes. */
	spinlock_t		oo_guard;

	/**
	 * Following two members *compat_dot* are used to indicate
	 * the presence of dot and dotdot in the given directory.
	 * This is required for interop mode (b11826).
	 */
	__u32			oo_destroyed:1,
				oo_pfid_in_lma:1,
				oo_compat_dot_created:1,
				oo_compat_dotdot_created:1;

	/* the i_flags in LMA */
	__u32                   oo_lma_flags;

        const struct lu_env    *oo_owner;

	struct list_head	oo_xattr_list;
	struct lu_object_header *oo_header;
	__u64			oo_dirent_count;
};

struct osd_obj_seq {
	/* protects on-fly initialization */
	int		 oos_subdir_count; /* subdir count for each seq */
	struct dentry	 *oos_root;	   /* O/<seq> */
	struct dentry	 **oos_dirs;	   /* O/<seq>/d0-dXX */
	u64		 oos_seq;	   /* seq number */
	struct list_head oos_seq_list;     /* list to seq_list */
};

struct osd_obj_map {
	struct dentry	 *om_root;	  /* dentry for /O */
	rwlock_t	 om_seq_list_lock; /* lock for seq_list */
	struct list_head om_seq_list;      /* list head for seq */
	int		 om_subdir_count;
	struct mutex	 om_dir_init_mutex;
};

struct osd_mdobj {
	struct dentry	*om_root;      /* AGENT/<index> */
	u64		 om_index;     /* mdt index */
	struct list_head om_list;      /* list to omm_list */
};

struct osd_mdobj_map {
	struct dentry	*omm_remote_parent;
};
int osd_ldiskfs_add_entry(struct osd_thread_info *info, struct osd_device *osd,
			  handle_t *handle, struct dentry *child,
			  struct inode *inode, struct htree_lock *hlock);

#define OSD_OTABLE_IT_CACHE_SIZE	64
#define OSD_OTABLE_IT_CACHE_MASK	(~(OSD_OTABLE_IT_CACHE_SIZE - 1))

struct osd_inconsistent_item {
	/* link into lustre_scrub::os_inconsistent_items,
	 * protected by lustre_scrub::os_lock. */
	struct list_head       oii_list;

	/* The right FID <=> ino#/gen mapping. */
	struct osd_idmap_cache oii_cache;

	unsigned int	       oii_insert:1; /* insert or update mapping. */
};

struct osd_otable_cache {
	struct osd_idmap_cache ooc_cache[OSD_OTABLE_IT_CACHE_SIZE];

	/* Index for next cache slot to be filled. */
	int		       ooc_producer_idx;

	/* Index for next cache slot to be returned by it::next(). */
	int		       ooc_consumer_idx;

	/* How many items in ooc_cache. */
	__u64		       ooc_cached_items;

	/* Position for up layer LFSCK iteration pre-loading. */
	__u64		       ooc_pos_preload;
};

struct osd_otable_it {
	struct osd_device       *ooi_dev;
	struct osd_otable_cache  ooi_cache;
	struct osd_iit_param	 ooi_iit_param;

	/* The following bits can be updated/checked w/o lock protection.
	 * If more bits will be introduced in the future and need lock to
	 * protect, please add comment. */
	unsigned long		 ooi_used_outside:1, /* Some user out of OSD
						      * uses the iteration. */
				 ooi_all_cached:1, /* No more entries can be
						    * filled into cache. */
				 ooi_user_ready:1, /* The user out of OSD is
						    * ready to iterate. */
				 ooi_waiting:1; /* it::next is waiting. */
};

struct osd_obj_orphan {
	struct list_head oor_list;
	struct lu_env	*oor_env; /* to identify "own" records */
	__u32 oor_ino;
};

enum osd_t10_type {
	OSD_T10_TYPE_UNKNOWN = 0,
	OSD_T10_TYPE1_CRC,
	OSD_T10_TYPE3_CRC,
	OSD_T10_TYPE1_IP,
	OSD_T10_TYPE3_IP
};

/*
 * osd device.
 */
struct osd_device {
        /* super-class */
        struct dt_device          od_dt_dev;
        /* information about underlying file system */
        struct vfsmount          *od_mnt;
        /* object index */
        struct osd_oi           **od_oi_table;
        /* total number of OI containers */
        int                       od_oi_count;
        /*
         * Fid Capability
         */
	unsigned int              od_fl_capa:1,
				  od_maybe_new:1,
				  od_igif_inoi:1,
				  od_check_ff:1,
				  od_is_ost:1,
				  od_in_init:1,
				  od_index_in_idif:1,
	/* Other flags */
				  od_read_cache:1,
				  od_writethrough_cache:1,
				  od_nonrotational:1;


	__s64			  od_auto_scrub_interval;
	__u32			  od_dirent_journal;
	int			  od_index;
	struct proc_dir_entry	 *od_proc_entry;
	struct lprocfs_stats     *od_stats;

	spinlock_t		  od_osfs_lock;

	int			  od_fallocate_zero_blocks;
	int			  od_connects;
	struct lu_site		  od_site;

	struct osd_obj_map	*od_ost_map;
	struct osd_mdobj_map	*od_mdt_map;

	/* objects with size > od_readcache_max_filesize will be
	 * served bypassing pagecache unless already cached */
	unsigned long long	od_readcache_max_filesize;

	/* reads > od_readcache_max_iosize will be
	 * served bypassing pagecache unless already cached */
	unsigned long		od_readcache_max_iosize;

	/* writes > od_writethough_max_iosize will be
	 * served bypassing pagecache unless already cached */
	unsigned long		od_writethrough_max_iosize;

	struct brw_stats	od_brw_stats;
	atomic_t		od_r_in_flight;
	atomic_t		od_w_in_flight;

	struct mutex		  od_otable_mutex;
	struct osd_otable_it	 *od_otable_it;
	struct osd_scrub	  od_scrub;
	struct list_head		  od_ios_list;

	/* service name associated with the osd device */
	char                      od_svname[MAX_OBD_NAME];
	char                      od_mntdev[MAX_OBD_NAME];
	uuid_t			od_uuid;

	/* quota slave instance for inode */
	struct qsd_instance      *od_quota_slave_md;

	/* quota slave instance for block */
	struct qsd_instance	 *od_quota_slave_dt;

	/* osd seq instance */
	struct lu_client_seq	*od_cl_seq;
	/* If the ratio of "the total OI mappings count" vs
	 * "the bad OI mappings count" is lower than the
	 * osd_device::od_full_scrub_ratio, then trigger
	 * OI scrub to scan the whole the device. */
	__u64			 od_full_scrub_ratio;
	/* If the speed of found bad OI mappings (per minute)
	 * exceeds the osd_device::od_full_scrub_threshold_rate,
	 * then trigger OI scrub to scan the whole device. */
	__u64			 od_full_scrub_threshold_rate;

	/* a list of orphaned agent inodes, protected with od_osfs_lock */
	struct list_head	 od_orphan_list;
	struct list_head	 od_index_backup_list;
	struct list_head	 od_index_restore_list;
	spinlock_t		 od_lock;
	struct inode		*od_index_backup_inode;
	enum lustre_index_backup_policy od_index_backup_policy;
	int			 od_index_backup_stop;
	/* T10PI type, zero if not supported  */
	enum osd_t10_type	 od_t10_type;
	atomic_t		 od_commit_cb_in_flight;
	wait_queue_head_t	 od_commit_cb_done;
	unsigned int __percpu	*od_extent_bytes_percpu;
};

static inline struct qsd_instance *osd_def_qsd(struct osd_device *osd)
{
	if (osd->od_is_ost)
		return osd->od_quota_slave_dt;
	else
		return osd->od_quota_slave_md;
}

enum osd_full_scrub_ratio {
	/* Trigger OI scrub to scan the whole device directly. */
	OFSR_DIRECTLY	= 0,

	/* Because the bad OI mappings count cannot be larger than
	 * the total OI mappints count, then setting OFSR_NEVER means
	 * that the whole device scanning cannot be triggered by auto
	 * detected bad OI mappings during the RPC services. */
	OFSR_NEVER	= 1,
	OFSR_DEFAULT	= 10000,
};

#define FULL_SCRUB_THRESHOLD_RATE_DEFAULT	60

/* There are at most 15 uid/gid/projids are affected in a transaction, and
 * that's rename case:
 * - 3 for source parent uid & gid & projid;
 * - 3 for source child uid & gid & projid ('..' entry update when
 * child is directory);
 * - 3 for target parent uid & gid & projid;
 * - 3 for target child uid & gid & projid(if the target child exists);
 * - 3 for root uid & gid(last_rcvd, llog, etc);
 *
 */
#define OSD_MAX_UGID_CNT        15

enum osd_op_type {
	OSD_OT_ATTR_SET		= 0,
	OSD_OT_PUNCH,
	OSD_OT_XATTR_SET,
	OSD_OT_CREATE,
	OSD_OT_DESTROY,
	OSD_OT_REF_ADD,
	OSD_OT_REF_DEL,
	OSD_OT_WRITE,
	OSD_OT_INSERT,
	OSD_OT_DELETE,
	OSD_OT_QUOTA,
	OSD_OT_PREALLOC,
	OSD_OT_MAX
};

struct osd_access_lock {
	struct list_head	 tl_list;
	struct osd_object	*tl_obj;
	loff_t			 tl_start;
	loff_t			 tl_end;
	int			 tl_mode;
	bool			 tl_shared;
	bool			 tl_truncate;
	bool			 tl_punch;
};

struct osd_thandle {
        struct thandle          ot_super;
        handle_t               *ot_handle;
        struct ldiskfs_journal_cb_entry ot_jcb;
	struct list_head       ot_commit_dcb_list;
	struct list_head       ot_stop_dcb_list;
	/* Link to the device, for debugging. */
	struct lu_ref_link      ot_dev_link;
	unsigned int		ot_credits;
	unsigned int		oh_declared_ext;

	/* quota IDs related to the transaction */
	unsigned short		ot_id_cnt;
	__u8			ot_id_res[OSD_MAX_UGID_CNT];
	__u8			ot_id_types[OSD_MAX_UGID_CNT];
	uid_t			ot_id_array[OSD_MAX_UGID_CNT];
	struct lquota_trans    *ot_quota_trans;

	unsigned int		ot_remove_agents:1;
#if OSD_THANDLE_STATS
        /** time when this handle was allocated */
	ktime_t oth_alloced;

        /** time when this thanle was started */
	ktime_t oth_started;
#endif
	struct list_head	ot_trunc_locks;
};

/**
 * Basic transaction credit op
 */
enum dt_txn_op {
        DTO_INDEX_INSERT,
        DTO_INDEX_DELETE,
        DTO_INDEX_UPDATE,
        DTO_OBJECT_CREATE,
        DTO_OBJECT_DELETE,
        DTO_ATTR_SET_BASE,
        DTO_XATTR_SET,
        DTO_WRITE_BASE,
        DTO_WRITE_BLOCK,
        DTO_ATTR_SET_CHOWN,

        DTO_NR
};

/*
 * osd dev stats
 */

#ifdef CONFIG_PROC_FS
enum {
        LPROC_OSD_READ_BYTES    = 0,
        LPROC_OSD_WRITE_BYTES   = 1,
        LPROC_OSD_GET_PAGE      = 2,
        LPROC_OSD_NO_PAGE       = 3,
        LPROC_OSD_CACHE_ACCESS  = 4,
        LPROC_OSD_CACHE_HIT     = 5,
        LPROC_OSD_CACHE_MISS    = 6,

#if OSD_THANDLE_STATS
        LPROC_OSD_THANDLE_STARTING,
        LPROC_OSD_THANDLE_OPEN,
        LPROC_OSD_THANDLE_CLOSING,
#endif
        LPROC_OSD_LAST,
};
#endif

/**
 * Storage representation for fids.
 *
 * Variable size, first byte contains the length of the whole record.
 */
struct osd_fid_pack {
        unsigned char fp_len;
        char fp_area[sizeof(struct lu_fid)];
};

struct osd_it_ea_dirent {
        struct lu_fid   oied_fid;
        __u64           oied_ino;
        __u64           oied_off;
        unsigned short  oied_namelen;
        unsigned int    oied_type;
        char            oied_name[0];
} __attribute__((packed));

/**
 * as osd_it_ea_dirent (in memory dirent struct for osd) is greater
 * than lu_dirent struct. osd readdir reads less number of dirent than
 * required for mdd dir page. so buffer size need to be increased so that
 * there  would be one ext3 readdir for every mdd readdir page.
 */

#define OSD_IT_EA_BUFSIZE       (PAGE_SIZE + PAGE_SIZE/4)

/**
 * This is iterator's in-memory data structure in interoperability
 * mode (i.e. iterator over ldiskfs style directory)
 */
struct osd_it_ea {
	struct osd_object	*oie_obj;
	/** used in ldiskfs iterator, to stored file pointer */
	struct file		oie_file;
	/** how many entries have been read-cached from storage */
	int			oie_rd_dirent;
	/** current entry is being iterated by caller */
	int			oie_it_dirent;
	/** current processing entry */
	struct osd_it_ea_dirent *oie_dirent;
	/** buffer to hold entries, size == OSD_IT_EA_BUFSIZE */
	void			*oie_buf;
	struct dentry		oie_dentry;
};

/**
 * Iterator's in-memory data structure for IAM mode.
 */
struct osd_it_iam {
        struct osd_object     *oi_obj;
        struct iam_path_descr *oi_ipd;
        struct iam_iterator    oi_it;
};

struct osd_quota_leaf {
	struct list_head	oql_link;
	uint		oql_blk;
};

/**
 * Iterator's in-memory data structure for quota file.
 */
struct osd_it_quota {
	struct osd_object	*oiq_obj;
	/** tree blocks path to where the entry is stored */
	uint			 oiq_blk[LUSTRE_DQTREEDEPTH + 1];
	/** on-disk offset for current key where quota record can be found */
	loff_t			 oiq_offset;
	/** identifier for current quota record */
	__u64			 oiq_id;
	/** the record index in the leaf/index block */
	uint			 oiq_index[LUSTRE_DQTREEDEPTH + 1];
	/** list of already processed leaf blocks */
	struct list_head	 oiq_list;
};

#define MAX_BLOCKS_PER_PAGE (PAGE_SIZE / 512)

struct osd_iobuf {
	wait_queue_head_t  dr_wait;
	atomic_t       dr_numreqs;  /* number of reqs being processed */
	int                dr_max_pages;
	int                dr_npages;
	int                dr_error;
	int                dr_frags;
	unsigned int       dr_elapsed_valid:1; /* we really did count time */
	unsigned int       dr_rw:1;
	struct lu_buf	   dr_pg_buf;
	struct page      **dr_pages;
	struct niobuf_local	**dr_lnbs;
	struct lu_buf	   dr_bl_buf;
	struct lu_buf	   dr_lnb_buf;
	sector_t	  *dr_blocks;
	ktime_t		   dr_start_time;
	ktime_t		   dr_elapsed;	/* how long io took */
	struct osd_device *dr_dev;
	unsigned int	   dr_init_at;	/* the line iobuf was initialized */
};

int osd_security_file_alloc(struct file *file);

#define osd_dirty_inode(inode, flag)  (inode)->i_sb->s_op->dirty_inode((inode), flag)

#ifdef HAVE_INODE_TIMESPEC64
# define osd_timespec			timespec64
#else
# define osd_timespec			timespec
#endif

static inline struct osd_timespec osd_inode_time(struct inode *inode,
						 s64 seconds)
{
	struct osd_timespec ts = { .tv_sec = seconds };

	return ts;
}

#define OSD_INS_CACHE_SIZE	8

struct osd_thread_info {
	const struct lu_env   *oti_env;
	/**
	 * used for index operations.
	 */
	struct dentry          oti_obj_dentry;
	struct dentry          oti_child_dentry;

	/** dentry for Iterator context. */
	struct dentry		oti_it_dentry;

	union {
		/* fake struct file for osd_object_sync */
		struct file		oti_file;
		/* osd_statfs() */
		struct kstatfs		oti_ksfs;
	};

	struct htree_lock     *oti_hlock;

	struct lu_fid          oti_fid;
	struct lu_fid	       oti_fid2;
	struct lu_fid	       oti_fid3;
	struct osd_inode_id    oti_id;
	struct osd_inode_id    oti_id2;
	struct osd_inode_id    oti_id3;
        struct ost_id          oti_ostid;

        /**
         * following ipd and it structures are used for osd_index_iam_lookup()
         * these are defined separately as we might do index operation
         * in open iterator session.
         */

	/** pre-allocated buffer used by oti_it_ea, size OSD_IT_EA_BUFSIZE */
	void			*oti_it_ea_buf;
	unsigned int		oti_it_ea_buf_used:1;

	/* IAM iterator for index operation. */
	struct iam_iterator    oti_idx_it;

        /** union to guarantee that ->oti_ipd[] has proper alignment. */
        union {
		char	       oti_name[48];
                char           oti_it_ipd[DX_IPD_MAX_SIZE];
                long long      oti_alignment_lieutenant;
        };

        union {
                char           oti_idx_ipd[DX_IPD_MAX_SIZE];
                long long      oti_alignment_lieutenant_colonel;
        };

	struct osd_idmap_cache oti_cache;

	/* dedicated OI cache for insert (which needs inum) */
	struct osd_idmap_cache		*oti_ins_cache;
	int				oti_ins_cache_size;
	int				oti_ins_cache_used;
	/* inc by osd_trans_create and dec by osd_trans_stop */
	int				oti_ins_cache_depth;

	int				oti_r_locks;
	int				oti_w_locks;
	int				oti_txns;
	/** used in osd_fid_set() to put xattr */
	struct lu_buf			oti_buf;
	struct lu_buf			oti_big_buf;
	/** used in osd_ea_fid_set() to set fid into common ea */
	union {
		struct lustre_ost_attrs oti_ost_attrs;
		struct filter_fid_18_23	oti_ff_old;
		struct filter_fid	oti_ff;
	};
	/** 0-copy IO */
	struct osd_iobuf		oti_iobuf;
	/* used to access objects in /O */
	struct inode			*oti_inode;
#define OSD_FID_REC_SZ 32
	char				oti_ldp[OSD_FID_REC_SZ];
	char				oti_ldp2[OSD_FID_REC_SZ];

	/* used by quota code */
	union {
#if defined(HAVE_DQUOT_QC_DQBLK)
		struct qc_dqblk		oti_qdq;
#else
		struct fs_disk_quota    oti_fdq;
#endif
		struct if_dqinfo	oti_dqinfo;
	};
	struct lquota_id_info	oti_qi;
	struct lquota_trans	oti_quota_trans;
	union lquota_rec	oti_quota_rec;
	__u64			oti_quota_id;
	struct lu_seq_range	oti_seq_range;

	/* Tracking for transaction credits, to allow debugging and optimizing
	 * cases where a large number of credits are being allocated for
	 * single transaction. */
	unsigned int		oti_credits_before;
	unsigned int		oti_declare_ops[OSD_OT_MAX];
	unsigned int		oti_declare_ops_cred[OSD_OT_MAX];
	unsigned int		oti_declare_ops_used[OSD_OT_MAX];
	struct osd_directory	oti_iam;

	struct page		**oti_dio_pages;
	int			oti_dio_pages_used;
};

extern int ldiskfs_pdo;

/* autoconf test is in lustre-build-ldiskfs.m4 */
#ifdef HAVE_BVEC_ITER_ALL
#define DECLARE_BVEC_ITER_ALL(iter) struct bvec_iter_all iter
#else
#define DECLARE_BVEC_ITER_ALL(iter) int iter
#endif

static inline int __osd_xattr_get(struct inode *inode, struct dentry *dentry,
				  const char *name, void *buf, int len)
{
	if (inode == NULL)
		return -EINVAL;

	dentry->d_inode = inode;
	dentry->d_sb = inode->i_sb;
	return ll_vfs_getxattr(dentry, inode, name, buf, len);
}

static inline int __osd_xattr_set(struct osd_thread_info *info,
				  struct inode *inode, const char *name,
				  const void *buf, int buflen, int fl)
{
	struct dentry *dentry = &info->oti_child_dentry;

	dquot_initialize(inode);
	dentry->d_inode = inode;
	dentry->d_sb = inode->i_sb;
	return ll_vfs_setxattr(dentry, inode, name, buf, buflen, fl);
}

#ifdef CONFIG_PROC_FS
/* osd_lproc.c */
extern struct lprocfs_vars lprocfs_osd_obd_vars[];
int osd_procfs_init(struct osd_device *osd, const char *name);
int osd_procfs_fini(struct osd_device *osd);
void osd_brw_stats_update(struct osd_device *osd, struct osd_iobuf *iobuf);
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 52, 0)
int osd_register_proc_index_in_idif(struct osd_device *osd);
#endif

#endif
int osd_statfs(const struct lu_env *env, struct dt_device *dev,
	       struct obd_statfs *sfs, struct obd_statfs_info *info);
struct inode *osd_iget(struct osd_thread_info *info, struct osd_device *dev,
		       struct osd_inode_id *id);
struct inode *
osd_iget_fid(struct osd_thread_info *info, struct osd_device *dev,
	     struct osd_inode_id *id, struct lu_fid *fid);
int osd_ea_fid_set(struct osd_thread_info *info, struct inode *inode,
		   const struct lu_fid *fid, __u32 compat, __u32 incompat);
int osd_get_lma(struct osd_thread_info *info, struct inode *inode,
		struct dentry *dentry, struct lustre_ost_attrs *loa);
void osd_add_oi_cache(struct osd_thread_info *info, struct osd_device *osd,
		      struct osd_inode_id *id, const struct lu_fid *fid);
int osd_get_idif(struct osd_thread_info *info, struct inode *inode,
		 struct dentry *dentry, struct lu_fid *fid);

int osd_obj_map_init(const struct lu_env *env, struct osd_device *osd);
void osd_obj_map_fini(struct osd_device *dev);
int osd_obj_map_lookup(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, struct osd_inode_id *id);
int osd_obj_map_insert(struct osd_thread_info *info, struct osd_device *osd,
		       const struct lu_fid *fid, const struct osd_inode_id *id,
		       handle_t *th);
int osd_obj_map_delete(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, handle_t *th);
int osd_obj_map_update(struct osd_thread_info *info, struct osd_device *osd,
		       const struct lu_fid *fid, const struct osd_inode_id *id,
		       handle_t *th);
int osd_obj_map_recover(struct osd_thread_info *info, struct osd_device *osd,
			struct inode *src_parent, struct dentry *src_child,
			const struct lu_fid *fid);
int osd_obj_spec_lookup(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, struct osd_inode_id *id,
			enum oi_check_flags flags);
int osd_obj_spec_insert(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, const struct osd_inode_id *id,
			handle_t *th);
int osd_obj_spec_update(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, const struct osd_inode_id *id,
			handle_t *th);

char *osd_lf_fid2name(const struct lu_fid *fid);
int osd_scrub_start(const struct lu_env *env, struct osd_device *dev,
		    __u32 flags);
void osd_scrub_stop(struct osd_device *dev);
int osd_scrub_setup(const struct lu_env *env, struct osd_device *dev,
		    bool restored);
void osd_scrub_cleanup(const struct lu_env *env, struct osd_device *dev);
int osd_oii_insert(struct osd_device *dev, const struct lu_fid *fid,
		   struct osd_inode_id *id, int insert);
int osd_oii_lookup(struct osd_device *dev, const struct lu_fid *fid,
		   struct osd_inode_id *id);
void osd_scrub_dump(struct seq_file *m, struct osd_device *dev);

struct dentry *osd_lookup_one_len_unlocked(struct osd_device *dev,
					   const char *name,
					   struct dentry *base, int len);
struct dentry *osd_lookup_one_len(struct osd_device *dev, const char *name,
				  struct dentry *base, int len);

int osd_fld_lookup(const struct lu_env *env, struct osd_device *osd,
		   u64 seq, struct lu_seq_range *range);

int osd_delete_from_remote_parent(const struct lu_env *env,
				  struct osd_device *osd,
				  struct osd_object *obj,
				  struct osd_thandle *oh, bool destroy);
int osd_add_to_remote_parent(const struct lu_env *env, struct osd_device *osd,
			     struct osd_object *obj, struct osd_thandle *oh);
int osd_lookup_in_remote_parent(struct osd_thread_info *oti,
				struct osd_device *osd,
				const struct lu_fid *fid,
				struct osd_inode_id *id);

int osd_ost_seq_exists(struct osd_thread_info *info, struct osd_device *osd,
		       __u64 seq);
int osd_scrub_refresh_mapping(struct osd_thread_info *info,
			      struct osd_device *dev,
			      const struct lu_fid *fid,
			      const struct osd_inode_id *id,
			      int ops, bool force,
			      enum oi_check_flags flags, bool *exist);

/* osd_quota_fmt.c */
int walk_tree_dqentry(const struct lu_env *env, struct osd_object *obj,
                      int type, uint blk, int depth, uint index,
                      struct osd_it_quota *it);
int walk_block_dqentry(const struct lu_env *env, struct osd_object *obj,
                       int type, uint blk, uint index,
                       struct osd_it_quota *it);
loff_t find_tree_dqentry(const struct lu_env *env,
                         struct osd_object *obj, int type,
                         qid_t dqid, uint blk, int depth,
                         struct osd_it_quota *it);
/* osd_quota.c */
int osd_declare_qid(const struct lu_env *env, struct osd_thandle *oh,
		    struct lquota_id_info *qi, struct osd_object *obj,
		    bool enforce, enum osd_quota_local_flags *local_flags);
int osd_declare_inode_qid(const struct lu_env *env, qid_t uid, qid_t gid,
			  __u32 projid, long long space, struct osd_thandle *oh,
			  struct osd_object *obj,
			  enum osd_quota_local_flags *local_flags,
			  enum osd_qid_declare_flags);
const struct dt_rec *osd_quota_pack(struct osd_object *obj,
				    const struct dt_rec *rec,
				    union lquota_rec *quota_rec);
void osd_quota_unpack(struct osd_object *obj, const struct dt_rec *rec);

#ifdef HAVE_PROJECT_QUOTA
static inline __u32 i_projid_read(struct inode *inode)
{
	return (__u32)from_kprojid(&init_user_ns, LDISKFS_I(inode)->i_projid);
}

static inline void i_projid_write(struct inode *inode, __u32 projid)
{
	kprojid_t kprojid;
	kprojid = make_kprojid(&init_user_ns, (projid_t)projid);
	LDISKFS_I(inode)->i_projid = kprojid;
}
#else
static inline uid_t i_projid_read(struct inode *inode)
{
	return 0;
}
static inline void i_projid_write(struct inode *inode, __u32 projid)
{
	return;
}
#endif

#ifdef HAVE_LDISKFS_IGET_WITH_FLAGS
# define osd_ldiskfs_iget(sb, ino) \
		ldiskfs_iget((sb), (ino), \
			     LDISKFS_IGET_HANDLE | LDISKFS_IGET_SPECIAL)
#else
# define osd_ldiskfs_iget(sb, ino) ldiskfs_iget((sb), (ino))
#endif

#ifdef HAVE_LDISKFS_INFO_JINODE
# define osd_attach_jinode(inode) ldiskfs_inode_attach_jinode(inode)
#else  /* HAVE_LDISKFS_INFO_JINODE */
# define osd_attach_jinode(inode) 0
#endif /* HAVE_LDISKFS_INFO_JINODE */

#ifdef LDISKFS_HT_MISC
# define osd_journal_start_sb(sb, type, nblock) \
		ldiskfs_journal_start_sb(sb, type, nblock)
static inline struct buffer_head *osd_ldiskfs_append(handle_t *handle,
						     struct inode *inode,
						     ldiskfs_lblk_t *nblock)
{
	int rc;

	rc = osd_attach_jinode(inode);
	if (rc)
		return ERR_PTR(rc);
	return ldiskfs_append(handle, inode, nblock);
}

# ifdef HAVE___LDISKFS_FIND_ENTRY
#  define osd_ldiskfs_find_entry(dir, name, de, inlined, lock) \
		(__ldiskfs_find_entry(dir, name, de, inlined, lock) ?: \
		 ERR_PTR(-ENOENT))
# else
#  define osd_ldiskfs_find_entry(dir, name, de, inlined, lock) \
		(ldiskfs_find_entry_locked(dir, name, de, inlined, lock) ?: \
		 ERR_PTR(-ENOENT))
# endif

# define osd_journal_start(inode, type, nblocks) \
		ldiskfs_journal_start(inode, type, nblocks)
# define osd_transaction_size(dev) \
		(osd_journal(dev)->j_max_transaction_buffers / 2)
#else /* ! defined LDISKFS_HT_MISC */
# define LDISKFS_HT_MISC	0
# define osd_journal_start_sb(sb, type, nblock) \
		ldiskfs_journal_start_sb(sb, nblock)

static inline struct buffer_head *osd_ldiskfs_append(handle_t *handle,
						     struct inode *inode,
						     ldiskfs_lblk_t *nblock)
{
	struct buffer_head *bh;
	int err = 0;

	bh = ldiskfs_append(handle, inode, nblock, &err);
	if (bh == NULL)
		bh = ERR_PTR(err);

	return bh;
}

# ifdef HAVE___LDISKFS_FIND_ENTRY
#  define osd_ldiskfs_find_entry(dir, name, de, inlined, lock) \
		(__ldiskfs_find_entry(dir, name, de, lock) ?: \
		 ERR_PTR(-ENOENT))
# else
#  define osd_ldiskfs_find_entry(dir, name, de, inlined, lock) \
		(ldiskfs_find_entry_locked(dir, name, de, lock) ?: \
		 ERR_PTR(-ENOENT))
# endif
# define osd_journal_start(inode, type, nblocks) \
		ldiskfs_journal_start(inode, nblocks)
# define osd_transaction_size(dev) \
		(osd_journal(dev)->j_max_transaction_buffers)
#endif /* LDISKFS_HT_MISC */

#ifndef HAVE___LDISKFS_FIND_ENTRY
# define __ldiskfs_add_entry(handle, child, inode, hlock) \
		ldiskfs_add_entry_locked(handle, child, inode, hlock)
#endif

/*
 * Invariants, assertions.
 */

/*
 * XXX: do not enable this, until invariant checking code is made thread safe
 * in the face of pdirops locking.
 */
#define OSD_INVARIANT_CHECKS (0)

#if OSD_INVARIANT_CHECKS
static inline int osd_invariant(const struct osd_object *obj)
{
        return
                obj != NULL &&
                ergo(obj->oo_inode != NULL,
                     obj->oo_inode->i_sb == osd_sb(osd_obj2dev(obj)) &&
                     atomic_read(&obj->oo_inode->i_count) > 0) &&
                ergo(obj->oo_dir != NULL &&
                     obj->oo_dir->od_conationer.ic_object != NULL,
                     obj->oo_dir->od_conationer.ic_object == obj->oo_inode);
}
#else
#define osd_invariant(obj) (1)
#endif

#define OSD_MAX_CACHE_SIZE OBD_OBJECT_EOF
#define OSD_READCACHE_MAX_IO_MB		8
#define OSD_WRITECACHE_MAX_IO_MB	8

extern const struct dt_index_operations osd_otable_ops;

static inline int osd_oi_fid2idx(struct osd_device *dev,
				 const struct lu_fid *fid)
{
	return fid->f_seq & (dev->od_oi_count - 1);
}

static inline struct osd_oi *osd_fid2oi(struct osd_device *osd,
                                        const struct lu_fid *fid)
{
	LASSERTF(!fid_is_idif(fid), DFID"\n", PFID(fid));
	LASSERTF(!fid_is_last_id(fid), DFID"\n", PFID(fid));
	LASSERTF(osd->od_oi_table != NULL && osd->od_oi_count >= 1,
		 DFID"\n", PFID(fid));
	/* It can work even od_oi_count equals to 1 although it's unexpected,
	 * the only reason we set it to 1 is for performance measurement */
	return osd->od_oi_table[osd_oi_fid2idx(osd, fid)];
}

extern const struct lu_device_operations  osd_lu_ops;

static inline int lu_device_is_osd(const struct lu_device *d)
{
        return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &osd_lu_ops);
}

static inline struct osd_device *osd_dt_dev(const struct dt_device *d)
{
	LASSERT(lu_device_is_osd(&d->dd_lu_dev));
	return container_of(d, struct osd_device, od_dt_dev);
}

static inline struct osd_device *osd_dev(const struct lu_device *d)
{
	LASSERT(lu_device_is_osd(d));
	return osd_dt_dev(container_of(d, struct dt_device, dd_lu_dev));
}

static inline struct osd_device *osd_obj2dev(const struct osd_object *o)
{
        return osd_dev(o->oo_dt.do_lu.lo_dev);
}

static inline struct super_block *osd_sb(const struct osd_device *dev)
{
	return dev->od_mnt->mnt_sb;
}

static inline const char *osd_sb2name(const struct super_block *sb)
{
	/* this is LDISKFS_SB(sb), but preserves "const" */
	const struct ldiskfs_sb_info *sbi = sb->s_fs_info;

	return sbi->s_es->s_volume_name;
}

static inline const char *osd_dev2name(const struct osd_device *dev)
{
	return osd_sb2name(osd_sb(dev));
}

static inline const char *osd_ino2name(const struct inode *inode)
{
	return osd_sb2name(inode->i_sb);
}

/**
 * Put the osd object once done with it.
 *
 * \param obj osd object that needs to be put
 */
static inline void osd_object_put(const struct lu_env *env,
				  struct osd_object *obj)
{
	dt_object_put(env, &obj->oo_dt);
}

static inline int osd_object_is_root(const struct osd_object *obj)
{
	return obj->oo_inode && is_root_inode(obj->oo_inode);
}

static inline struct osd_object *osd_obj(const struct lu_object *o)
{
	LASSERT(lu_device_is_osd(o->lo_dev));
	return container_of(o, struct osd_object, oo_dt.do_lu);
}

static inline struct osd_object *osd_dt_obj(const struct dt_object *d)
{
        return osd_obj(&d->do_lu);
}

static inline struct lu_device *osd2lu_dev(struct osd_device *osd)
{
        return &osd->od_dt_dev.dd_lu_dev;
}

static inline journal_t *osd_journal(const struct osd_device *dev)
{
        return LDISKFS_SB(osd_sb(dev))->s_journal;
}

static inline struct seq_server_site *osd_seq_site(struct osd_device *osd)
{
	return osd->od_dt_dev.dd_lu_dev.ld_site->ld_seq_site;
}

static inline char *osd_name(struct osd_device *osd)
{
	return osd->od_svname;
}

static inline bool osd_is_ea_inode(struct inode *inode)
{
	return !!(LDISKFS_I(inode)->i_flags & LDISKFS_EA_INODE_FL);
}

extern const struct dt_body_operations osd_body_ops;
extern struct lu_context_key osd_key;

static inline struct osd_thread_info *osd_oti_get(const struct lu_env *env)
{
        return lu_context_key_get(&env->le_ctx, &osd_key);
}

extern const struct dt_body_operations osd_body_ops_new;

/**
 * IAM Iterator
 */
static inline
struct iam_path_descr *osd_it_ipd_get(const struct lu_env *env,
                                      const struct iam_container *bag)
{
        return bag->ic_descr->id_ops->id_ipd_alloc(bag,
                                           osd_oti_get(env)->oti_it_ipd);
}

static inline
struct iam_path_descr *osd_idx_ipd_get(const struct lu_env *env,
                                       const struct iam_container *bag)
{
        return bag->ic_descr->id_ops->id_ipd_alloc(bag,
                                           osd_oti_get(env)->oti_idx_ipd);
}

static inline void osd_ipd_put(const struct lu_env *env,
                               const struct iam_container *bag,
                               struct iam_path_descr *ipd)
{
        bag->ic_descr->id_ops->id_ipd_free(ipd);
}

int osd_calc_bkmap_credits(struct super_block *sb, struct inode *inode,
			   const loff_t size, const loff_t pos,
			   const int blocks);

int osd_ldiskfs_read(struct inode *inode, void *buf, int size, loff_t *offs);

static inline
struct dentry *osd_child_dentry_by_inode(const struct lu_env *env,
                                         struct inode *inode,
                                         const char *name, const int namelen)
{
        struct osd_thread_info *info = osd_oti_get(env);
        struct dentry *child_dentry = &info->oti_child_dentry;
        struct dentry *obj_dentry = &info->oti_obj_dentry;

        obj_dentry->d_inode = inode;
        obj_dentry->d_sb = inode->i_sb;
        obj_dentry->d_name.hash = 0;

        child_dentry->d_name.hash = 0;
        child_dentry->d_parent = obj_dentry;
        child_dentry->d_name.name = name;
        child_dentry->d_name.len = namelen;
        return child_dentry;
}

/* build quasi file structure when it is needed to call an inode i_fop */
static inline struct file *osd_quasi_file_init(const struct lu_env *env,
					       struct dentry *dentry,
					       struct inode *inode)
{
	struct osd_thread_info *info = osd_oti_get(env);

	info->oti_file.f_path.dentry = dentry;
	info->oti_file.f_mapping = inode->i_mapping;
	info->oti_file.f_op = inode->i_fop;
	info->oti_file.f_inode = inode;
	info->oti_file.f_pos = 0;
	info->oti_file.private_data = NULL;
	info->oti_file.f_cred = current_cred();
	info->oti_file.f_flags = O_NOATIME;
	info->oti_file.f_mode = FMODE_64BITHASH | FMODE_NONOTIFY;

	return &info->oti_file;
}

static inline struct file *osd_quasi_file(const struct lu_env *env,
					  struct inode *inode)
{
	struct osd_thread_info *info = osd_oti_get(env);

	info->oti_obj_dentry.d_inode = inode;
	info->oti_obj_dentry.d_sb = inode->i_sb;

	return osd_quasi_file_init(env, &info->oti_obj_dentry, inode);
}

static inline struct file *osd_quasi_file_by_dentry(const struct lu_env *env,
						    struct dentry *dentry)
{
	return osd_quasi_file_init(env, dentry, dentry->d_inode);
}

extern int osd_trans_declare_op2rb[];
extern int ldiskfs_track_declares_assert;
void osd_trans_dump_creds(const struct lu_env *env, struct thandle *th);

static inline void osd_trans_declare_op(const struct lu_env *env,
					struct osd_thandle *oh,
					enum osd_op_type op, int credits)
{
	struct osd_thread_info *oti = osd_oti_get(env);

	LASSERT(oh->ot_handle == NULL);
	if (unlikely(op >= OSD_OT_MAX)) {
		if (unlikely(ldiskfs_track_declares_assert)) {
			LASSERT(op < OSD_OT_MAX);
		} else {
			CWARN("%s: Invalid operation index %d\n",
			      osd_name(osd_dt_dev(oh->ot_super.th_dev)), op);
			libcfs_debug_dumpstack(NULL);
		}
	} else {
		oti->oti_declare_ops[op]++;
		oti->oti_declare_ops_cred[op] += credits;
	}
	oh->ot_credits += credits;
}

/* linux: v5.4-rc3-21-g933f1c1e0b75 renamed h_buffer_credits */
#ifdef HAVE_JOURNAL_TOTAL_CREDITS
#define h_buffer_credits h_total_credits
#endif

static inline void osd_trans_exec_op(const struct lu_env *env,
				     struct thandle *th,
				     enum osd_op_type op)
{
	struct osd_thread_info *oti = osd_oti_get(env);
	struct osd_thandle     *oh  = container_of(th, struct osd_thandle,
						   ot_super);
	unsigned int		rb, left;

	LASSERT(oh->ot_handle != NULL);
	if (unlikely(op >= OSD_OT_MAX)) {
		if (unlikely(ldiskfs_track_declares_assert))
			LASSERT(op < OSD_OT_MAX);
		else {
			CWARN("%s: opcode %u: invalid value >= %u\n",
			      osd_name(osd_dt_dev(oh->ot_super.th_dev)),
			      op, OSD_OT_MAX);
			libcfs_debug_dumpstack(NULL);
			return;
		}
	}

	/* find rollback (or reverse) operation for the given one
	 * such an operation doesn't require additional credits
	 * as the same set of blocks are modified */
	rb = osd_trans_declare_op2rb[op];

	/* check whether credits for this operation were reserved at all */
	if (unlikely(oti->oti_declare_ops_cred[op] == 0 &&
		     oti->oti_declare_ops_cred[rb] == 0)) {
		/* the API is not perfect yet: CREATE does REF_ADD internally
		 * while DESTROY does not. To rollback CREATE the callers
		 * needs to call REF_DEL+DESTROY which is hard to detect using
		 * a simple table of rollback operations */
		if (op == OSD_OT_REF_DEL &&
		    oti->oti_declare_ops_cred[OSD_OT_CREATE] > 0)
			goto proceed;
		if (op == OSD_OT_REF_ADD &&
		    oti->oti_declare_ops_cred[OSD_OT_DESTROY] > 0)
			goto proceed;
		CWARN("%s: opcode %u: credits = 0, rollback = %u\n",
		      osd_name(osd_dt_dev(oh->ot_super.th_dev)), op, rb);
		osd_trans_dump_creds(env, th);
		LASSERT(!ldiskfs_track_declares_assert);
	}

proceed:
	/* remember how many credits we have unused before the operation */
	oti->oti_credits_before = oh->ot_handle->h_buffer_credits;
	left = oti->oti_declare_ops_cred[op] - oti->oti_declare_ops_used[op];
	if (unlikely(oti->oti_credits_before < left)) {
		CWARN("%s: opcode %u: before %u < left %u, rollback = %u\n",
		      osd_name(osd_dt_dev(oh->ot_super.th_dev)), op,
		      oti->oti_credits_before, left, rb);
		osd_trans_dump_creds(env, th);
		/* on a very small fs (testing?) it's possible that
		 * the transaction can't fit 1/4 of journal, so we
		 * just request less credits (see osd_trans_start()).
		 * ignore the same case here */
		rb = osd_transaction_size(osd_dt_dev(th->th_dev));
		if (unlikely(oh->ot_credits < rb))
			LASSERT(!ldiskfs_track_declares_assert);
	}
}

static inline void osd_trans_exec_check(const struct lu_env *env,
					struct thandle *th,
					enum osd_op_type op)
{
	struct osd_thread_info *oti = osd_oti_get(env);
	struct osd_thandle     *oh  = container_of(th, struct osd_thandle,
						   ot_super);
	int			used, over, quota;

	/* how many credits have been used by the operation */
	used = oti->oti_credits_before - oh->ot_handle->h_buffer_credits;

	if (unlikely(used < 0)) {
		/* if some block was allocated and released in the same
		 * transaction, then it won't be a part of the transaction
		 * and delta can be negative */
		return;
	}

	if (used == 0) {
		/* rollback operations (e.g. when we destroy just created
		 * object) should not consume any credits. there is no point
		 * to confuse the checks below */
		return;
	}

	oti->oti_declare_ops_used[op] += used;
	if (oti->oti_declare_ops_used[op] <= oti->oti_declare_ops_cred[op])
		return;

	/* we account quota for a whole transaction and any operation can
	 * consume corresponding credits */
	over = oti->oti_declare_ops_used[op] -
		oti->oti_declare_ops_cred[op];
	quota = oti->oti_declare_ops_cred[OSD_OT_QUOTA] -
		oti->oti_declare_ops_used[OSD_OT_QUOTA];
	if (over <= quota) {
		/* probably that credits were consumed by
		 * quota indirectly (in the depths of ldiskfs) */
		oti->oti_declare_ops_used[OSD_OT_QUOTA] += over;
		oti->oti_declare_ops_used[op] -= over;
	} else {
		CWARN("%s: opcode %d: used %u, used now %u, reserved %u\n",
		      osd_name(osd_dt_dev(oh->ot_super.th_dev)), op,
		      oti->oti_declare_ops_used[op], used,
		      oti->oti_declare_ops_cred[op]);
		osd_trans_dump_creds(env, th);
		if (unlikely(ldiskfs_track_declares_assert))
			LBUG();
	}
}

/**
 * Helper function to pack the fid, ldiskfs stores fid in packed format.
 */
static inline
void osd_fid_pack(struct osd_fid_pack *pack, const struct dt_rec *fid,
                  struct lu_fid *befider)
{
        fid_cpu_to_be(befider, (struct lu_fid *)fid);
        memcpy(pack->fp_area, befider, sizeof(*befider));
        pack->fp_len =  sizeof(*befider) + 1;
}

static inline
int osd_fid_unpack(struct lu_fid *fid, const struct osd_fid_pack *pack)
{
        int result;

        result = 0;
        switch (pack->fp_len) {
        case sizeof *fid + 1:
                memcpy(fid, pack->fp_area, sizeof *fid);
                fid_be_to_cpu(fid, fid);
                break;
        default:
                CERROR("Unexpected packed fid size: %d\n", pack->fp_len);
                result = -EIO;
        }
        return result;
}

/**
 * Quota/Accounting handling
 */
extern const struct dt_index_operations osd_acct_index_ops;
int osd_acct_obj_lookup(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, struct osd_inode_id *id);

/* copy from fs/ext4/dir.c */
static inline int is_32bit_api(void)
{
#ifdef CONFIG_COMPAT
	return in_compat_syscall();
#else
	return (BITS_PER_LONG == 32);
#endif
}

static inline loff_t ldiskfs_get_htree_eof(struct file *filp)
{
	if ((filp->f_mode & FMODE_32BITHASH) ||
	    (!(filp->f_mode & FMODE_64BITHASH) && is_32bit_api()))
		return LDISKFS_HTREE_EOF_32BIT;
	else
		return LDISKFS_HTREE_EOF_64BIT;
}

static inline int fid_is_internal(const struct lu_fid *fid)
{
	return (!fid_is_namespace_visible(fid) && !fid_is_idif(fid));
}

static inline bool is_remote_parent_ino(struct osd_device *o, unsigned long ino)
{
	if (o->od_is_ost)
		return false;

	LASSERT(o->od_mdt_map != NULL);

	return ino == o->od_mdt_map->omm_remote_parent->d_inode->i_ino;
}

/**
 * ext4_bread/ldiskfs_bread has either 5 or 4 parameters. The error
 * return code has been removed and integrated into the pointer in the
 * kernel 3.18.
 */
static inline struct buffer_head *__ldiskfs_bread(handle_t *handle,
						  struct inode *inode,
						  ldiskfs_lblk_t block,
						  int create)
{
	int rc = 0;
	struct buffer_head *bh;

	if (create) {
		rc = osd_attach_jinode(inode);
		if (rc)
			return ERR_PTR(rc);
	}
#ifdef HAVE_EXT4_BREAD_4ARGS
	bh = ldiskfs_bread(handle, inode, block, create);
#else

	bh = ldiskfs_bread(handle, inode, block, create, &rc);
	if (bh == NULL && rc != 0)
		bh = ERR_PTR(rc);
#endif
	return bh;
}

#ifndef HAVE_BIO_INTEGRITY_ENABLED
bool bio_integrity_enabled(struct bio *bio);
#endif

#ifdef HAVE_BI_BDEV
# define bio_get_dev(bio)	((bio)->bi_bdev)
# define bio_get_disk(bio)	(bio_get_dev(bio)->bd_disk)
# define bio_get_queue(bio)	bdev_get_queue(bio_get_dev(bio))
# define bio_set_dev(bio, bdev) (bio_get_dev(bio) = (bdev))
#else
# define bio_get_disk(bio)	((bio)->bi_disk)
# define bio_get_queue(bio)	(bio_get_disk(bio)->queue)
#endif

void ldiskfs_inc_count(handle_t *handle, struct inode *inode);
void ldiskfs_dec_count(handle_t *handle, struct inode *inode);

void osd_fini_iobuf(struct osd_device *d, struct osd_iobuf *iobuf);

static inline int
osd_index_register(struct osd_device *osd, const struct lu_fid *fid,
		   __u32 keysize, __u32 recsize)
{
	return lustre_index_register(&osd->od_dt_dev, osd_name(osd),
				     &osd->od_index_backup_list, &osd->od_lock,
				     &osd->od_index_backup_stop,
				     fid, keysize, recsize);
}

static inline void
osd_index_backup(const struct lu_env *env, struct osd_device *osd, bool backup)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct lu_fid *fid = &info->oti_fid3;
	struct osd_inode_id *id = &info->oti_id3;

	lu_local_obj_fid(fid, INDEX_BACKUP_OID);
	osd_id_gen(id, osd->od_index_backup_inode->i_ino,
		   osd->od_index_backup_inode->i_generation);
	osd_add_oi_cache(info, osd, id, fid);

	lustre_index_backup(env, &osd->od_dt_dev, osd_name(osd),
			    &osd->od_index_backup_list, &osd->od_lock,
			    &osd->od_index_backup_stop, backup);
}

#ifdef LDISKFS_HAS_INCOMPAT_FEATURE

# ifdef LDISKFS_FEATURE_INCOMPAT_EXTENTS
# define ldiskfs_has_feature_extents(sb) \
	LDISKFS_HAS_INCOMPAT_FEATURE(sb, LDISKFS_FEATURE_INCOMPAT_EXTENTS)
# endif
# ifdef LDISKFS_FEATURE_INCOMPAT_EA_INODE
# define ldiskfs_has_feature_ea_inode(sb) \
	LDISKFS_HAS_INCOMPAT_FEATURE(sb, LDISKFS_FEATURE_INCOMPAT_EA_INODE)
# endif
# ifdef LDISKFS_FEATURE_INCOMPAT_DIRDATA
# define ldiskfs_has_feature_dirdata(sb) \
	LDISKFS_HAS_INCOMPAT_FEATURE(sb, LDISKFS_FEATURE_INCOMPAT_DIRDATA)
# endif
# ifdef LDISKFS_FEATURE_COMPAT_HAS_JOURNAL
# define ldiskfs_has_feature_journal(sb) \
	LDISKFS_HAS_COMPAT_FEATURE(sb, LDISKFS_FEATURE_COMPAT_HAS_JOURNAL)
# endif
# ifdef LDISKFS_FEATURE_RO_COMPAT_QUOTA
# define ldiskfs_has_feature_quota(sb) \
	LDISKFS_HAS_RO_COMPAT_FEATURE(sb, LDISKFS_FEATURE_RO_COMPAT_QUOTA)
# endif
# ifdef LDISKFS_FEATURE_RO_COMPAT_PROJECT
# define ldiskfs_has_feature_project(sb) \
	LDISKFS_HAS_RO_COMPAT_FEATURE(sb, LDISKFS_FEATURE_RO_COMPAT_PROJECT)
# endif

#endif

int osd_trunc_lock(struct osd_object *obj, struct osd_thandle *oh,
		   bool shared);
void osd_trunc_unlock_all(const struct lu_env *env, struct list_head *list);
void osd_process_truncates(const struct lu_env *env, struct list_head *list);
void osd_execute_truncate(struct osd_object *obj);

#ifdef HAVE_BIO_ENDIO_USES_ONE_ARG
#define osd_dio_complete_routine(bio, error) dio_complete_routine(bio)
#else
#define osd_dio_complete_routine(bio, error) dio_complete_routine(bio, error)
#endif

#ifndef HAVE___BI_CNT
#define __bi_cnt bi_cnt
#endif

#ifndef HAVE_BI_OPF
#define bi_opf bi_rw
#endif

#ifndef HAVE_CLEAN_BDEV_ALIASES
#define clean_bdev_aliases(bdev, block, len)	\
	unmap_underlying_metadata((bdev), (block))
#endif

#ifndef HAVE_BI_STATUS
#define bi_status bi_error
#endif

/*
 * Maximum size of xattr attributes for FEATURE_INCOMPAT_EA_INODE 1Mb
 * This limit is arbitrary, but is reasonable for the xattr API.
 */
#define LDISKFS_XATTR_MAX_LARGE_EA_SIZE    (1024 * 1024)

struct osd_bio_private {
	struct osd_iobuf	*obp_iobuf;
	/* Start page index in the obp_iobuf for the bio */
	int			 obp_start_page_idx;
};

#ifdef HAVE_BIO_INTEGRITY_PREP_FN
int osd_get_integrity_profile(struct osd_device *osd,
			      integrity_gen_fn **generate_fn,
			      integrity_vrfy_fn **verify_fn);
#else
#define integrity_gen_fn void
#define integrity_vrfy_fn int
static inline int osd_get_integrity_profile(struct osd_device *osd,
					    integrity_gen_fn **generate_fn,
					    integrity_vrfy_fn **verify_fn)
{
	return 0;
}

static inline bool bio_integrity_prep_fn(struct bio *bio,
					 integrity_gen_fn *generate_fn,
					 integrity_vrfy_fn *verify_fn)
{
	return bio_integrity_prep(bio);
}
#endif

#ifdef HAVE_BIO_BI_PHYS_SEGMENTS
#define osd_bio_nr_segs(bio)		((bio)->bi_phys_segments)
#else
#define osd_bio_nr_segs(bio)		bio_segments((bio))
#endif /* HAVE_BIO_BI_PHYS_SEGMENTS */

#endif /* _OSD_INTERNAL_H */
