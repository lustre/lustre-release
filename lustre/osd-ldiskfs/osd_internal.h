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
 *
 * Copyright (c) 2011, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd/osd_internal.h
 *
 * Shared definitions and declarations for osd module
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef _OSD_INTERNAL_H
#define _OSD_INTERNAL_H

#if defined(__KERNEL__)

/* struct rw_semaphore */
#include <linux/rwsem.h>
/* struct dentry */
#include <linux/dcache.h>
/* struct dirent64 */
#include <linux/dirent.h>

#include <ldiskfs/ldiskfs.h>
#include <ldiskfs/ldiskfs_jbd2.h>

/* fsfilt_{get|put}_ops */
#include <lustre_fsfilt.h>

/* LUSTRE_OSD_NAME */
#include <obd.h>
/* class_register_type(), class_unregister_type(), class_get_type() */
#include <obd_class.h>
#include <lustre_disk.h>
#include <dt_object.h>
#include <lustre_quota.h>

#include "osd_oi.h"
#include "osd_iam.h"
#include "osd_scrub.h"
#include "osd_quota_fmt.h"

struct inode;

#define OSD_COUNTERS (0)

/* ldiskfs special inode::i_state_flags need to be accessed with
 * ldiskfs_{set,clear,test}_inode_state() only */

/* OI scrub should skip this inode. */
#define LDISKFS_STATE_LUSTRE_NOSCRUB	31

/* Do not add OI mapping for this inode. */
#define LDISKFS_STATE_LUSTRE_NO_OI	30

/** Enable thandle usage statistics */
#define OSD_THANDLE_STATS (0)

#define MAX_OBJID_GROUP (FID_SEQ_ECHO + 1)

#define OBJECTS  	"OBJECTS"
#define ADMIN_USR	"admin_quotafile_v2.usr"
#define ADMIN_GRP	"admin_quotafile_v2.grp"

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
         * creation, or assigned by osd_object_create() under write lock).
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
         * Following two members are used to indicate the presence of dot and
         * dotdot in the given directory. This is required for interop mode
         * (b11826).
         */
        int                     oo_compat_dot_created;
        int                     oo_compat_dotdot_created;

        const struct lu_env    *oo_owner;
#ifdef CONFIG_LOCKDEP
        struct lockdep_map      oo_dep_map;
#endif
};

struct osd_obj_seq {
	/* protects on-fly initialization */
	int		 oos_subdir_count; /* subdir count for each seq */
	struct dentry	 *oos_root;	   /* O/<seq> */
	struct dentry	 **oos_dirs;	   /* O/<seq>/d0-dXX */
	obd_seq		 oos_seq;	   /* seq number */
	cfs_list_t	 oos_seq_list;     /* list to seq_list */
};

struct osd_obj_map {
	struct dentry	 *om_root;	  /* dentry for /O */
	rwlock_t	 om_seq_list_lock; /* lock for seq_list */
	cfs_list_t	 om_seq_list;      /* list head for seq */
	int		 om_subdir_count;
	struct semaphore om_dir_init_sem;
};

struct osd_mdobj {
	struct dentry	*om_root;      /* AGENT/<index> */
	obd_seq		om_index;     /* mdt index */
	cfs_list_t	om_list;      /* list to omm_list */
};

struct osd_mdobj_map {
	struct dentry	*omm_remote_parent;
};

#define osd_ldiskfs_add_entry(handle, child, cinode, hlock) \
        ldiskfs_add_entry(handle, child, cinode, hlock)

#define OSD_OTABLE_IT_CACHE_SIZE	64
#define OSD_OTABLE_IT_CACHE_MASK	(~(OSD_OTABLE_IT_CACHE_SIZE - 1))

struct osd_inconsistent_item {
	/* link into osd_scrub::os_inconsistent_items,
	 * protected by osd_scrub::os_lock. */
	cfs_list_t	       oii_list;

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
	int		       ooc_cached_items;

	/* Position for up layer LFSCK iteration pre-loading. */
	__u32		       ooc_pos_preload;
};

struct osd_otable_it {
	struct osd_device       *ooi_dev;
	struct osd_otable_cache  ooi_cache;

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
				  od_noscrub:1,
				  od_dirent_journal:1,
				  od_igif_inoi:1,
				  od_check_ff:1,
				  od_is_ost:1;

        unsigned long             od_capa_timeout;
        __u32                     od_capa_alg;
        struct lustre_capa_key   *od_capa_keys;
        cfs_hlist_head_t         *od_capa_hash;

        cfs_proc_dir_entry_t     *od_proc_entry;
        struct lprocfs_stats     *od_stats;
        /*
         * statfs optimization: we cache a bit.
         */
        cfs_time_t                od_osfs_age;
        struct obd_statfs         od_statfs;
	spinlock_t		  od_osfs_lock;

	struct fsfilt_operations *od_fsops;
	int			  od_connects;
	struct lu_site		  od_site;

	struct osd_obj_map	*od_ost_map;
	struct osd_mdobj_map	*od_mdt_map;

        unsigned long long        od_readcache_max_filesize;
        int                       od_read_cache;
        int                       od_writethrough_cache;

        struct brw_stats          od_brw_stats;
        cfs_atomic_t              od_r_in_flight;
        cfs_atomic_t              od_w_in_flight;

	struct mutex		  od_otable_mutex;
	struct osd_otable_it	 *od_otable_it;
	struct osd_scrub	  od_scrub;
	cfs_list_t		  od_ios_list;

	/* service name associated with the osd device */
	char                      od_svname[MAX_OBD_NAME];
	char                      od_mntdev[MAX_OBD_NAME];

	/* quota slave instance */
	struct qsd_instance      *od_quota_slave;
};

/* There are at most 10 uid/gids are affected in a transaction, and
 * that's rename case:
 * - 2 for source parent uid & gid;
 * - 2 for source child uid & gid ('..' entry update when child is directory);
 * - 2 for target parent uid & gid;
 * - 2 for target child uid & gid (if the target child exists);
 * - 2 for root uid & gid (last_rcvd, llog, etc);
 *
 * The 0 to (OSD_MAX_UGID_CNT - 1) bits of ot_id_type is for indicating
 * the id type of each id in the ot_id_array.
 */
#define OSD_MAX_UGID_CNT        10

enum {
	OSD_OT_ATTR_SET		= 0,
	OSD_OT_PUNCH		= 1,
	OSD_OT_XATTR_SET	= 2,
	OSD_OT_CREATE		= 3,
	OSD_OT_DESTROY		= 4,
	OSD_OT_REF_ADD		= 5,
	OSD_OT_REF_DEL		= 6,
	OSD_OT_WRITE		= 7,
	OSD_OT_INSERT		= 8,
	OSD_OT_DELETE		= 9,
	OSD_OT_UPDATE		= 10,
	OSD_OT_QUOTA		= 11,
	OSD_OT_MAX		= 12
};

struct osd_thandle {
        struct thandle          ot_super;
        handle_t               *ot_handle;
        struct ldiskfs_journal_cb_entry ot_jcb;
        cfs_list_t              ot_dcb_list;
	/* Link to the device, for debugging. */
	struct lu_ref_link      ot_dev_link;
        unsigned short          ot_credits;
        unsigned short          ot_id_cnt;
        unsigned short          ot_id_type;
        uid_t                   ot_id_array[OSD_MAX_UGID_CNT];
	struct lquota_trans    *ot_quota_trans;
#if OSD_THANDLE_STATS
        /** time when this handle was allocated */
        cfs_time_t oth_alloced;

        /** time when this thanle was started */
        cfs_time_t oth_started;
#endif
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

#ifdef LPROCFS
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

#define OSD_IT_EA_BUFSIZE       (PAGE_CACHE_SIZE + PAGE_CACHE_SIZE/4)

/**
 * This is iterator's in-memory data structure in interoperability
 * mode (i.e. iterator over ldiskfs style directory)
 */
struct osd_it_ea {
        struct osd_object   *oie_obj;
        /** used in ldiskfs iterator, to stored file pointer */
        struct file          oie_file;
        /** how many entries have been read-cached from storage */
        int                  oie_rd_dirent;
        /** current entry is being iterated by caller */
        int                  oie_it_dirent;
        /** current processing entry */
        struct osd_it_ea_dirent *oie_dirent;
        /** buffer to hold entries, size == OSD_IT_EA_BUFSIZE */
        void                *oie_buf;
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
	cfs_list_t	oql_link;
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
	cfs_list_t		 oiq_list;
};

#define MAX_BLOCKS_PER_PAGE (PAGE_CACHE_SIZE / 512)

struct osd_iobuf {
	wait_queue_head_t  dr_wait;
	cfs_atomic_t       dr_numreqs;  /* number of reqs being processed */
	int                dr_max_pages;
	int                dr_npages;
	int                dr_error;
	int                dr_frags;
	unsigned int       dr_ignore_quota:1;
	unsigned int       dr_elapsed_valid:1; /* we really did count time */
	unsigned int       dr_rw:1;
	struct lu_buf	   dr_pg_buf;
	struct page      **dr_pages;
	struct lu_buf	   dr_bl_buf;
	unsigned long     *dr_blocks;
	unsigned long      dr_start_time;
	unsigned long      dr_elapsed;  /* how long io took */
	struct osd_device *dr_dev;
	unsigned int	   dr_init_at;	/* the line iobuf was initialized */
};

struct osd_thread_info {
        const struct lu_env   *oti_env;
        /**
         * used for index operations.
         */
        struct dentry          oti_obj_dentry;
        struct dentry          oti_child_dentry;

        /** dentry for Iterator context. */
        struct dentry          oti_it_dentry;
        struct htree_lock     *oti_hlock;

        struct lu_fid          oti_fid;
	struct lu_fid	       oti_fid2;
	struct lu_fid	       oti_fid3;
	struct osd_inode_id    oti_id;
	struct osd_inode_id    oti_id2;
	struct osd_inode_id    oti_id3;
        struct ost_id          oti_ostid;

        /*
         * XXX temporary: for ->i_op calls.
         */
        struct timespec        oti_time;
        /*
         * XXX temporary: fake struct file for osd_object_sync
         */
        struct file            oti_file;
        /*
         * XXX temporary: for capa operations.
         */
        struct lustre_capa_key oti_capa_key;
        struct lustre_capa     oti_capa;

        /** osd_device reference, initialized in osd_trans_start() and
            used in osd_trans_stop() */
        struct osd_device     *oti_dev;

        /**
         * following ipd and it structures are used for osd_index_iam_lookup()
         * these are defined separately as we might do index operation
         * in open iterator session.
         */

        /** osd iterator context used for iterator session */

	union {
		struct osd_it_iam	oti_it;
		/* ldiskfs iterator data structure,
		 * see osd_it_ea_{init, fini} */
		struct osd_it_ea	oti_it_ea;
		struct osd_it_quota	oti_it_quota;
	};

	/** pre-allocated buffer used by oti_it_ea, size OSD_IT_EA_BUFSIZE */
	void			*oti_it_ea_buf;

	struct kstatfs		oti_ksfs;

        /** IAM iterator for index operation. */
        struct iam_iterator    oti_idx_it;

        /** union to guarantee that ->oti_ipd[] has proper alignment. */
        union {
                char           oti_it_ipd[DX_IPD_MAX_SIZE];
                long long      oti_alignment_lieutenant;
        };

        union {
                char           oti_idx_ipd[DX_IPD_MAX_SIZE];
                long long      oti_alignment_lieutenant_colonel;
        };

	struct osd_idmap_cache oti_cache;

        int                    oti_r_locks;
        int                    oti_w_locks;
        int                    oti_txns;
        /** used in osd_fid_set() to put xattr */
        struct lu_buf          oti_buf;
        /** used in osd_ea_fid_set() to set fid into common ea */
	union {
		struct lustre_mdt_attrs oti_mdt_attrs;
		/* old LMA for compatibility */
		char			oti_mdt_attrs_old[LMA_OLD_SIZE];
	};
	/** 0-copy IO */
	struct osd_iobuf       oti_iobuf;
	struct inode           oti_inode;
#define OSD_FID_REC_SZ 32
	char		       oti_ldp[OSD_FID_REC_SZ];
	char		       oti_ldp2[OSD_FID_REC_SZ];

	/* used by quota code */
	union {
#ifdef HAVE_DQUOT_FS_DISK_QUOTA
		struct fs_disk_quota    oti_fdq;
#else
		struct if_dqblk		oti_dqblk;
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
	unsigned short		oti_declare_ops[OSD_OT_MAX];
	unsigned short		oti_declare_ops_rb[OSD_OT_MAX];
	unsigned short		oti_declare_ops_cred[OSD_OT_MAX];
	bool			oti_rollback;

	char			oti_name[48];
	union {
		struct filter_fid_old	oti_ff;
		struct filter_fid	oti_ff_new;
	};
};

extern int ldiskfs_pdo;

static inline int __osd_xattr_get(struct inode *inode, struct dentry *dentry,
				  const char *name, void *buf, int len)
{
	if (inode == NULL)
		return -EINVAL;

	dentry->d_inode = inode;
	dentry->d_sb = inode->i_sb;
	return inode->i_op->getxattr(dentry, name, buf, len);
}

static inline int __osd_xattr_set(struct osd_thread_info *info,
				  struct inode *inode, const char *name,
				  const void *buf, int buflen, int fl)
{
	struct dentry *dentry = &info->oti_child_dentry;

	ll_vfs_dq_init(inode);
	dentry->d_inode = inode;
	dentry->d_sb = inode->i_sb;
	return inode->i_op->setxattr(dentry, name, buf, buflen, fl);
}

#ifdef LPROCFS
/* osd_lproc.c */
extern struct lprocfs_vars lprocfs_osd_obd_vars[];
extern struct lprocfs_vars lprocfs_osd_module_vars[];
int osd_procfs_init(struct osd_device *osd, const char *name);
int osd_procfs_fini(struct osd_device *osd);
void osd_brw_stats_update(struct osd_device *osd, struct osd_iobuf *iobuf);

#endif
int osd_statfs(const struct lu_env *env, struct dt_device *dev,
               struct obd_statfs *sfs);
int osd_object_auth(const struct lu_env *env, struct dt_object *dt,
                    struct lustre_capa *capa, __u64 opc);
struct inode *osd_iget(struct osd_thread_info *info, struct osd_device *dev,
		       struct osd_inode_id *id);
int osd_ea_fid_set(struct osd_thread_info *info, struct inode *inode,
		   const struct lu_fid *fid, __u32 compat, __u32 incompat);
int osd_get_lma(struct osd_thread_info *info, struct inode *inode,
		struct dentry *dentry, struct lustre_mdt_attrs *lma);
int osd_add_oi_cache(struct osd_thread_info *info, struct osd_device *osd,
		     struct osd_inode_id *id, const struct lu_fid *fid);
int osd_get_idif(struct osd_thread_info *info, struct inode *inode,
		 struct dentry *dentry, struct lu_fid *fid);

int osd_obj_map_init(const struct lu_env *env, struct osd_device *osd);
void osd_obj_map_fini(struct osd_device *dev);
int osd_obj_map_lookup(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, struct osd_inode_id *id);
int osd_obj_map_insert(struct osd_thread_info *info, struct osd_device *osd,
		       const struct lu_fid *fid, const struct osd_inode_id *id,
		       struct thandle *th);
int osd_obj_map_delete(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, struct thandle *th);
int osd_obj_map_update(struct osd_thread_info *info, struct osd_device *osd,
		       const struct lu_fid *fid, const struct osd_inode_id *id,
		       struct thandle *th);
int osd_obj_map_recover(struct osd_thread_info *info, struct osd_device *osd,
			struct inode *src_parent, struct dentry *src_child,
			const struct lu_fid *fid);
int osd_obj_spec_lookup(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, struct osd_inode_id *id);
int osd_obj_spec_insert(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, const struct osd_inode_id *id,
			struct thandle *th);
int osd_obj_spec_update(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, const struct osd_inode_id *id,
			struct thandle *th);

void osd_scrub_file_reset(struct osd_scrub *scrub, __u8 *uuid, __u64 flags);
int osd_scrub_file_store(struct osd_scrub *scrub);
char *osd_lf_fid2name(const struct lu_fid *fid);
int osd_scrub_start(struct osd_device *dev);
int osd_scrub_setup(const struct lu_env *env, struct osd_device *dev);
void osd_scrub_cleanup(const struct lu_env *env, struct osd_device *dev);
int osd_oii_insert(struct osd_device *dev, struct osd_idmap_cache *oic,
		   int insert);
int osd_oii_lookup(struct osd_device *dev, const struct lu_fid *fid,
		   struct osd_inode_id *id);
int osd_scrub_dump(struct osd_device *dev, char *buf, int len);

int osd_fld_lookup(const struct lu_env *env, struct osd_device *osd,
		   obd_seq seq, struct lu_seq_range *range);

int osd_delete_from_remote_parent(const struct lu_env *env,
				  struct osd_device *osd,
				  struct osd_object *obj,
				  struct osd_thandle *oh);
int osd_add_to_remote_parent(const struct lu_env *env, struct osd_device *osd,
			     struct osd_object *obj, struct osd_thandle *oh);
int osd_lookup_in_remote_parent(struct osd_thread_info *oti,
				struct osd_device *osd,
				const struct lu_fid *fid,
				struct osd_inode_id *id);

int osd_ost_seq_exists(struct osd_thread_info *info, struct osd_device *osd,
		       __u64 seq);
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
		    bool enforce, int *flags);
int osd_declare_inode_qid(const struct lu_env *env, qid_t uid, qid_t gid,
			  long long space, struct osd_thandle *oh,
			  struct osd_object *obj, bool is_blk, int *flags,
			  bool force);
const struct dt_rec *osd_quota_pack(struct osd_object *obj,
				    const struct dt_rec *rec,
				    union lquota_rec *quota_rec);
void osd_quota_unpack(struct osd_object *obj, const struct dt_rec *rec);
int osd_quota_migration(const struct lu_env *env, struct dt_object *dt,
			const struct dt_index_features *feat);

static inline bool is_quota_glb_feat(const struct dt_index_features *feat)
{
	return (feat == &dt_quota_iusr_features ||
		feat == &dt_quota_busr_features ||
		feat == &dt_quota_igrp_features ||
		feat == &dt_quota_bgrp_features) ? true : false;
}

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
        return container_of0(d, struct osd_device, od_dt_dev);
}

static inline struct osd_device *osd_dev(const struct lu_device *d)
{
        LASSERT(lu_device_is_osd(d));
        return osd_dt_dev(container_of0(d, struct dt_device, dd_lu_dev));
}

static inline struct osd_device *osd_obj2dev(const struct osd_object *o)
{
        return osd_dev(o->oo_dt.do_lu.lo_dev);
}

static inline struct super_block *osd_sb(const struct osd_device *dev)
{
	return dev->od_mnt->mnt_sb;
}

static inline int osd_object_is_root(const struct osd_object *obj)
{
        return osd_sb(osd_obj2dev(obj))->s_root->d_inode == obj->oo_inode;
}

static inline struct osd_object *osd_obj(const struct lu_object *o)
{
        LASSERT(lu_device_is_osd(o->lo_dev));
        return container_of0(o, struct osd_object, oo_dt.do_lu);
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
	return osd->od_dt_dev.dd_lu_dev.ld_obd->obd_name;
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

int osd_ldiskfs_read(struct inode *inode, void *buf, int size, loff_t *offs);
int osd_ldiskfs_write_record(struct inode *inode, void *buf, int bufsize,
			     int write_NUL, loff_t *offs, handle_t *handle);

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

extern int osd_trans_declare_op2rb[];
extern int ldiskfs_track_declares_assert;

static inline void osd_trans_declare_op(const struct lu_env *env,
					struct osd_thandle *oh,
					unsigned int op, int credits)
{
	struct osd_thread_info *oti = osd_oti_get(env);

	LASSERT(oh->ot_handle == NULL);
	if (unlikely(op >= OSD_OT_MAX)) {
		if (unlikely(ldiskfs_track_declares_assert))
			LASSERT(op < OSD_OT_MAX);
		else {
			CWARN("%s: Invalid operation index %d\n",
			      osd_name(oti->oti_dev), op);
			libcfs_debug_dumpstack(NULL);
		}
	} else {
		oti->oti_declare_ops[op]++;
		oti->oti_declare_ops_cred[op] += credits;
	}
	oh->ot_credits += credits;
}

static inline void osd_trans_exec_op(const struct lu_env *env,
				     struct thandle *th, unsigned int op)
{
	struct osd_thread_info *oti = osd_oti_get(env);
	struct osd_thandle     *oh  = container_of(th, struct osd_thandle,
						   ot_super);
	unsigned int		rb;

	LASSERT(oh->ot_handle != NULL);
	if (unlikely(op >= OSD_OT_MAX)) {
		if (unlikely(ldiskfs_track_declares_assert))
			LASSERT(op < OSD_OT_MAX);
		else {
			CWARN("%s: Invalid operation index %d\n",
			      osd_name(oti->oti_dev), op);
			libcfs_debug_dumpstack(NULL);
			return;
		}
	}

	if (likely(!oti->oti_rollback && oti->oti_declare_ops[op] > 0)) {
		oti->oti_declare_ops[op]--;
		oti->oti_declare_ops_rb[op]++;
	} else {
		/* all future updates are considered rollback */
		oti->oti_rollback = true;
		rb = osd_trans_declare_op2rb[op];
		if (unlikely(rb >= OSD_OT_MAX)) {
			if (unlikely(ldiskfs_track_declares_assert))
				LASSERTF(rb < OSD_OT_MAX, "rb = %u\n", rb);
			else {
				CWARN("%s: Invalid rollback index %d\n",
				      osd_name(oti->oti_dev), rb);
				libcfs_debug_dumpstack(NULL);
				return;
			}
		}
		if (unlikely(oti->oti_declare_ops_rb[rb] == 0)) {
			if (unlikely(ldiskfs_track_declares_assert))
				LASSERTF(oti->oti_declare_ops_rb[rb] > 0,
					 "rb = %u\n", rb);
			else {
				CWARN("%s: Overflow in tracking declares for "
				      "index, rb = %d\n",
				      osd_name(oti->oti_dev), rb);
				libcfs_debug_dumpstack(NULL);
				return;
			}
		}
		oti->oti_declare_ops_rb[rb]--;
	}
}

static inline void osd_trans_declare_rb(const struct lu_env *env,
					struct thandle *th, unsigned int op)
{
	struct osd_thread_info *oti = osd_oti_get(env);
	struct osd_thandle     *oh  = container_of(th, struct osd_thandle,
						   ot_super);

	LASSERT(oh->ot_handle != NULL);
	if (unlikely(op >= OSD_OT_MAX)) {
		if (unlikely(ldiskfs_track_declares_assert))
			LASSERT(op < OSD_OT_MAX);
		else {
			CWARN("%s: Invalid operation index %d\n",
			      osd_name(oti->oti_dev), op);
			libcfs_debug_dumpstack(NULL);
		}

	} else {
		oti->oti_declare_ops_rb[op]++;
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
	return is_compat_task();
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

#ifdef JOURNAL_START_HAS_3ARGS
# define osd_journal_start_sb(sb, type, nblock) \
		ldiskfs_journal_start_sb(sb, type, nblock)
# define osd_ldiskfs_append(handle, inode, nblock, err) \
		ldiskfs_append(handle, inode, nblock)
# define osd_ldiskfs_find_entry(dir, name, de, inlined, lock) \
		ldiskfs_find_entry(dir, name, de, inlined, lock)
# define osd_journal_start(inode, type, nblocks) \
		ldiskfs_journal_start(inode, type, nblocks);
#else
# define LDISKFS_HT_MISC	0
# define osd_journal_start_sb(sb, type, nblock) \
		ldiskfs_journal_start_sb(sb, nblock)
# define osd_ldiskfs_append(handle, inode, nblock, err) \
		ldiskfs_append(handle, inode, nblock, err)
# define osd_ldiskfs_find_entry(dir, name, de, inlined, lock) \
		ldiskfs_find_entry(dir, name, de, lock)
# define osd_journal_start(inode, type, nblocks) \
		ldiskfs_journal_start(inode, nblocks);
#endif

void ldiskfs_inc_count(handle_t *handle, struct inode *inode);
void ldiskfs_dec_count(handle_t *handle, struct inode *inode);

void osd_fini_iobuf(struct osd_device *d, struct osd_iobuf *iobuf);

#endif /* __KERNEL__ */
#endif /* _OSD_INTERNAL_H */
