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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/osd-zfs/osd_internal.h
 * Shared definitions and declarations for zfs/dmu osd
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 * Author: Johann Lombardi <johann@whamcloud.com>
 */

#ifndef _OSD_INTERNAL_H
#define _OSD_INTERNAL_H

#include <dt_object.h>
#include <md_object.h>
#include <lustre_quota.h>
#include <lustre_scrub.h>
#include <obd.h>
#ifdef SHRINK_STOP
#undef SHRINK_STOP
#endif
#include <sys/arc.h>
#include <sys/nvpair.h>
#include <sys/zfs_znode.h>
#include <sys/zap.h>
#include <sys/dbuf.h>
#include <sys/dmu_objset.h>
#include <lustre_scrub.h>

/**
 * By design including kmem.h overrides the Linux slab interfaces to provide
 * the Illumos kmem cache interfaces.  To override this and gain access to
 * the Linux interfaces these preprocessor macros must be undefined.
 */
#ifdef kmem_cache_destroy
#undef kmem_cache_destroy
#endif

#ifdef kmem_cache_create
#undef kmem_cache_create
#endif

#ifdef kmem_cache_alloc
#undef kmem_cache_alloc
#endif

#ifdef kmem_cache_free
#undef kmem_cache_free
#endif

#define ZFS_VERSION_CODE	\
	OBD_OCD_VERSION(ZFS_MAJOR, ZFS_MINOR, ZFS_PATCH, ZFS_FIX)

#define LUSTRE_ROOT_FID_SEQ	0
#define DMU_OSD_SVNAME		"svname"
#define DMU_OSD_OI_NAME_BASE	"oi"

#define OSD_GFP_IO		(GFP_NOFS | __GFP_HIGHMEM)

/* Statfs space reservation for grant, fragmentation, and unlink space. */
#define OSD_STATFS_RESERVED_SIZE	(16ULL << 20) /* reserve 16MB minimum */
#define OSD_STATFS_RESERVED_SHIFT	(7)     /* reserve 0.78% of all space */

/* Statfs {minimum, safe estimate, and maximum} dnodes per block */
#define OSD_DNODE_MIN_BLKSHIFT	(DNODES_PER_BLOCK_SHIFT)
#define OSD_DNODE_EST_BLKSHIFT	(12)     /* est 4KB/dnode */
#define OSD_DNODE_EST_COUNT	4096

#define OSD_GRANT_FOR_LOCAL_OIDS (2ULL << 20) /* 2MB for last_rcvd, ... */

#define OSD_MAX_CACHE_SIZE OBD_OBJECT_EOF

#ifndef HAVE_ZFS_REFCOUNT_ADD
#define zfs_refcount_add	refcount_add
#endif

extern const struct dt_body_operations osd_body_scrub_ops;
extern const struct dt_body_operations osd_body_ops;
extern struct kmem_cache *osd_object_kmem;

/**
 * Iterator's in-memory data structure for quota file.
 */
struct osd_it_quota {
	struct osd_object	*oiq_obj;
	/* DMU accounting object id */
	uint64_t		 oiq_oid;
	/* ZAP cursor */
	zap_cursor_t		*oiq_zc;
	/** identifier for current quota record */
	__u64			 oiq_id;
	unsigned		 oiq_reset:1; /* 1 -- no need to advance */
};

enum osd_zap_pos {
	OZI_POS_INIT = 0,
	OZI_POS_DOT = 1,	/* cursor at . */
	OZI_POS_DOTDOT = 2,	/* cursor at .. */
	OZI_POS_REAL = 3,	/* cursor at real entries */
};

/**
 * Iterator's in-memory data structure for ZAPs
 *
 * ZFS does not store . and .. on a disk, instead they are
 * generated up on request
 * to follow this format we do the same
 */
struct osd_zap_it {
	zap_cursor_t		*ozi_zc;
	struct osd_object	*ozi_obj;
	unsigned		 ozi_reset:1;	/* 1 -- no need to advance */
	/* ozi_pos - position of the cursor */
	enum osd_zap_pos	ozi_pos;
	union {
		char		 ozi_name[MAXNAMELEN]; /* file name for dir */
		__u64		 ozi_key; /* binary key for index files */
	};
};
#define DT_IT2DT(it) (&((struct osd_zap_it *)it)->ozi_obj->oo_dt)

/*
 * regular ZFS direntry
 */
struct zpl_direntry {
	uint64_t	zde_dnode:48,
			zde_pad:12,
			zde_type:4;
} __attribute__((packed));

/*
 * lustre direntry adds a fid to regular ZFS direntry
 */
struct luz_direntry {
	struct zpl_direntry	lzd_reg;
	struct lu_fid		lzd_fid;
} __attribute__((packed));


/* cached SA attributes */
struct osa_attr {
	uint64_t	mode;
	uint64_t	gid;
	uint64_t	uid;
#ifdef ZFS_PROJINHERIT
	uint64_t	projid;
#endif
	uint64_t	nlink;
	uint64_t	rdev;
	uint64_t	flags;
	uint64_t	size;
	uint64_t	atime[2];
	uint64_t	mtime[2];
	uint64_t	ctime[2];
	uint64_t	btime[2];
};


#define OSD_INS_CACHE_SIZE	8

/* OI cache entry */
struct osd_idmap_cache {
	struct osd_device	*oic_dev;
	struct lu_fid		oic_fid;
	/** max 2^48 dnodes per dataset, avoid spilling into another word */
	uint64_t		oic_dnode:DN_MAX_OBJECT_SHIFT,
				oic_remote:1;      /* FID isn't local */
};

struct osd_inconsistent_item {
	/* link into lustre_scrub::os_inconsistent_items,
	 * protected by lustr_scrub::os_lock. */
	struct list_head       oii_list;

	/* The right FID <=> oid mapping. */
	struct osd_idmap_cache oii_cache;

	unsigned int	       oii_insert:1; /* insert or update mapping. */
};

struct osd_otable_it {
	struct osd_device       *ooi_dev;
	struct lu_fid		 ooi_fid;
	__u64			 ooi_pos;
	__u64			 ooi_prefetched_dnode;
	int			 ooi_prefetched;

	/* The following bits can be updated/checked w/o lock protection.
	 * If more bits will be introduced in the future and need lock to
	 * protect, please add comment. */
	unsigned int		 ooi_used_outside:1, /* Some user out of OSD
						      * uses the iteration. */
				 ooi_all_cached:1, /* No more entries can be
						    * filled into cache. */
				 ooi_user_ready:1, /* The user out of OSD is
						    * ready to iterate. */
				 ooi_waiting:1; /* it::next is waiting. */
};

extern const struct dt_index_operations osd_otable_ops;

/* max.number of regular attributes the callers may ask for */
# define OSD_MAX_IN_BULK (sizeof(struct osa_attr)/sizeof(uint64_t))

struct osd_thread_info {
	const struct lu_env	*oti_env;

	struct lu_fid		 oti_fid;

	struct ost_id		 oti_ostid;

	char			 oti_buf[64];

	char			 oti_str[64];
	union {
		char		 oti_key[MAXNAMELEN + 1];
		__u64		 oti_key64[(MAXNAMELEN + 1)/sizeof(__u64)];
		sa_bulk_attr_t	 oti_attr_bulk[OSD_MAX_IN_BULK];
	};
	struct lustre_mdt_attrs  oti_mdt_attrs;
	unsigned int		 oti_in_trans:1;

	struct lu_attr		 oti_la;
	struct osa_attr		 oti_osa;
	zap_attribute_t		 oti_za;
	zap_attribute_t		 oti_za2;
	dmu_object_info_t	 oti_doi;
	struct luz_direntry	 oti_zde;

	struct lquota_id_info	 oti_qi;
	struct lu_seq_range	 oti_seq_range;

	/* dedicated OI cache for insert (which needs inum) */
	struct osd_idmap_cache *oti_ins_cache;
	int		       oti_ins_cache_size;
	int		       oti_ins_cache_used;
	/* inc by osd_trans_create and dec by osd_trans_stop */
	int		       oti_ins_cache_depth;
	struct lu_buf	       oti_xattr_lbuf;
	zap_cursor_t	       oti_zc;
	zap_cursor_t	       oti_zc2;
};

extern struct lu_context_key osd_key;

static inline struct osd_thread_info *osd_oti_get(const struct lu_env *env)
{
	return lu_context_key_get(&env->le_ctx, &osd_key);
}

struct osd_thandle {
	struct thandle		 ot_super;
	struct list_head	 ot_dcb_list;
	struct list_head	 ot_stop_dcb_list;
	struct list_head	 ot_unlinked_list;
	struct list_head	 ot_sa_list;
	dmu_tx_t		*ot_tx;
	struct lquota_trans	 ot_quota_trans;
	__u32			 ot_assigned:1;
};

#define OSD_OI_NAME_SIZE        24

/*
 * Object Index (OI) instance.
 */
struct osd_oi {
	char			oi_name[OSD_OI_NAME_SIZE];
	uint64_t		oi_zapid;
	dnode_t *oi_dn;
};

struct osd_seq {
	uint64_t	 os_oid;
	uint64_t	 *os_compat_dirs;
	int		 os_subdir_count; /* subdir count for each seq */
	u64		 os_seq;	  /* seq number */
	struct list_head os_seq_list;     /* list to seq_list */
};

struct osd_seq_list {
	rwlock_t	 osl_seq_list_lock;	/* lock for seq_list */
	struct list_head osl_seq_list;		/* list head for seq */
	struct semaphore osl_seq_init_sem;
};

#define OSD_OST_MAP_SIZE	32

/*
 * osd device.
 */
struct osd_device {
	/* super-class */
	struct dt_device	 od_dt_dev;
	/* information about underlying file system */
	struct objset		*od_os;
	uint64_t		 od_rootid;  /* id of root znode */
	dnode_t *od_unlinked; /* dnode of unlinked zapobj */
	/* SA attr mapping->id,
	 * name is the same as in ZFS to use defines SA_ZPL_...*/
	sa_attr_type_t		 *z_attr_table;

	struct proc_dir_entry	*od_proc_entry;
	struct lprocfs_stats	*od_stats;

	uint64_t		 od_remote_parent_dir;
	uint64_t		 od_index_backup_id;
	uint64_t		 od_max_blksz;
	uint64_t		 od_root;
	uint64_t		 od_O_id;
	struct osd_oi		**od_oi_table;
	unsigned int		 od_oi_count;
	struct osd_seq_list	od_seq_list;

	unsigned int		 od_dev_set_rdonly:1, /**< osd_ro() called */
				 od_prop_rdonly:1,  /**< ZFS property readonly */
				 od_xattr_in_sa:1,
				 od_is_ost:1,
				 od_in_init:1,
				 od_posix_acl:1,
				 od_nonrotational:1;
	unsigned int		 od_dnsize;
	int			 od_index_backup_stop;

	enum lustre_index_backup_policy od_index_backup_policy;
	char			 od_mntdev[128];
	char			 od_svname[128];
	uuid_t			 od_uuid;

	int			 od_connects;
	int			 od_index;
	__s64			 od_auto_scrub_interval;
	struct lu_site		 od_site;

	dnode_t			*od_groupused_dn;
	dnode_t			*od_userused_dn;
#ifdef ZFS_PROJINHERIT
	dnode_t			*od_projectused_dn;
#endif

	/* quota slave instance for inode */
	struct qsd_instance	*od_quota_slave_md;

	/* quota slave instance for block */
	struct qsd_instance	*od_quota_slave_dt;

	struct brw_stats	od_brw_stats;
	atomic_t		od_r_in_flight;
	atomic_t		od_w_in_flight;

	/* used to debug zerocopy logic: the fields track all
	 * allocated, loaned and referenced buffers in use.
	 * to be removed once the change is tested well. */
	atomic_t		 od_zerocopy_alloc;
	atomic_t		 od_zerocopy_loan;
	atomic_t		 od_zerocopy_pin;

	arc_prune_t		*arc_prune_cb;

	/* osd seq instance */
	struct lu_client_seq	*od_cl_seq;

	struct semaphore	 od_otable_sem;
	struct osd_otable_it	*od_otable_it;
	struct lustre_scrub	 od_scrub;
	struct list_head	 od_ios_list;
	struct list_head	 od_index_backup_list;
	struct list_head	 od_index_restore_list;
	spinlock_t		 od_lock;
	unsigned long long	 od_readcache_max_filesize;
};

static inline struct qsd_instance *osd_def_qsd(struct osd_device *osd)
{
	if (osd->od_is_ost)
		return osd->od_quota_slave_dt;
	else
		return osd->od_quota_slave_md;
}

enum osd_destroy_type {
	OSD_DESTROY_NONE = 0,
	OSD_DESTROY_SYNC = 1,
	OSD_DESTROY_ASYNC = 2,
};

struct osd_object {
	struct dt_object	 oo_dt;
	/*
	 * Inode for file system object represented by this osd_object. This
	 * inode is pinned for the whole duration of lu_object life.
	 *
	 * Not modified concurrently (either setup early during object
	 * creation, or assigned by osd_create() under write lock).
	 */
	dnode_t *oo_dn;
	sa_handle_t		*oo_sa_hdl;
	nvlist_t		*oo_sa_xattr;
	struct list_head	 oo_sa_linkage;

	/* used to implement osd_object_*_{lock|unlock} */
	struct rw_semaphore	 oo_sem;

	/* to serialize some updates: destroy vs. others,
	 * xattr_set, object block size change etc */
	struct rw_semaphore	 oo_guard;

	/* protected by oo_guard */
	struct list_head	 oo_unlinked_linkage;

	/* cached attributes */
	rwlock_t		 oo_attr_lock;
	struct lu_attr		 oo_attr;

	/* external dnode holding large EAs, protected by oo_guard */
	uint64_t		 oo_xattr;
	enum osd_destroy_type	 oo_destroy;

	__u32			 oo_destroyed:1,
				 oo_late_xattr:1,
#ifdef ZFS_PROJINHERIT
				 oo_with_projid:1,
#endif
				 oo_late_attr_set:1,
				 oo_pfid_in_lma:1;

	/* the i_flags in LMA */
	__u32			 oo_lma_flags;
	union {
		int		oo_ea_in_bonus; /* EA bytes we expect */
		struct {
			/* record size for index file */
			unsigned char		 oo_keysize;
			unsigned char		 oo_recsize;
			unsigned char		 oo_recusize;	/* unit size */
		};
		uint64_t	oo_parent; /* used only at object creation */
	};
	struct lu_object_header *oo_header;
};

int osd_statfs(const struct lu_env *, struct dt_device *, struct obd_statfs *,
	       struct obd_statfs_info *);
extern const struct dt_index_operations osd_acct_index_ops;
extern const struct lu_device_operations  osd_lu_ops;
extern const struct dt_index_operations osd_dir_ops;
int osd_declare_quota(const struct lu_env *env, struct osd_device *osd,
		      qid_t uid, qid_t gid, qid_t projid, long long space,
		      struct osd_thandle *oh,
		      enum osd_quota_local_flags *local_flags,
		      enum osd_qid_declare_flags osd_qid_declare_flags);
uint64_t osd_objs_count_estimate(uint64_t refdbytes, uint64_t usedobjs,
				 uint64_t nrblocks, uint64_t est_maxblockshift);
int osd_unlinked_object_free(const struct lu_env *env, struct osd_device *osd,
			 uint64_t oid);

/*
 * Helpers.
 */
static inline int lu_device_is_osd(const struct lu_device *d)
{
	return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &osd_lu_ops);
}

static inline struct osd_object *osd_obj(const struct lu_object *o)
{
	LASSERT(lu_device_is_osd(o->lo_dev));
	return container_of(o, struct osd_object, oo_dt.do_lu);
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

static inline struct osd_object *osd_dt_obj(const struct dt_object *d)
{
	return osd_obj(&d->do_lu);
}

static inline struct osd_device *osd_obj2dev(const struct osd_object *o)
{
	return osd_dev(o->oo_dt.do_lu.lo_dev);
}

static inline struct lu_device *osd2lu_dev(struct osd_device *osd)
{
	return &osd->od_dt_dev.dd_lu_dev;
}

static inline struct objset * osd_dtobj2objset(struct dt_object *o)
{
	return osd_dev(o->do_lu.lo_dev)->od_os;
}

static inline int osd_invariant(const struct osd_object *obj)
{
	return 1;
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

static inline int osd_object_invariant(const struct lu_object *l)
{
	return osd_invariant(osd_obj(l));
}

static inline struct seq_server_site *osd_seq_site(struct osd_device *osd)
{
	return osd->od_dt_dev.dd_lu_dev.ld_site->ld_seq_site;
}

static inline char *osd_name(struct osd_device *osd)
{
	return osd->od_svname;
}

static inline void zfs_set_bit(int nr, __u8 *addr)
{
	set_bit(nr, (unsigned long *)addr);
}

static inline int zfs_test_bit(int nr, __u8 *addr)
{
	return test_bit(nr, (const unsigned long *)addr);
}

static inline int osd_oi_fid2idx(struct osd_device *dev,
				 const struct lu_fid *fid)
{
	return fid->f_seq & (dev->od_oi_count - 1);
}

static inline struct osd_oi *osd_fid2oi(struct osd_device *osd,
					const struct lu_fid *fid)
{
	LASSERTF(osd->od_oi_table && osd->od_oi_count >= 1,
		 "%s: "DFID", oi_count %d\n",
		 osd_name(osd), PFID(fid), osd->od_oi_count);

	return osd->od_oi_table[osd_oi_fid2idx(osd, fid)];
}

#ifdef CONFIG_PROC_FS
enum {
	LPROC_OSD_READ_BYTES = 0,
	LPROC_OSD_WRITE_BYTES = 1,
	LPROC_OSD_GET_PAGE = 2,
	LPROC_OSD_NO_PAGE = 3,
	LPROC_OSD_CACHE_ACCESS = 4,
	LPROC_OSD_CACHE_HIT = 5,
	LPROC_OSD_CACHE_MISS = 6,
	LPROC_OSD_COPY_IO = 7,
	LPROC_OSD_ZEROCOPY_IO = 8,
	LPROC_OSD_TAIL_IO = 9,
	LPROC_OSD_LAST,
};

extern struct kmem_cache *osd_zapit_cachep;
/* osd_lproc.c */
extern struct lprocfs_vars lprocfs_osd_obd_vars[];

int osd_procfs_init(struct osd_device *osd, const char *name);
int osd_procfs_fini(struct osd_device *osd);

/* osd_object.c */
extern char *osd_obj_tag;
int __osd_obj2dnode(objset_t *os, uint64_t oid, dnode_t **dnp);
void osd_object_sa_dirty_rele(const struct lu_env *env, struct osd_thandle *oh);
void osd_object_sa_dirty_add(struct osd_object *obj, struct osd_thandle *oh);
int __osd_obj2dbuf(const struct lu_env *env, objset_t *os,
		   uint64_t oid, dmu_buf_t **dbp);
struct lu_object *osd_object_alloc(const struct lu_env *env,
				   const struct lu_object_header *hdr,
				   struct lu_device *d);
int osd_object_sa_update(struct osd_object *obj, sa_attr_type_t type,
			 void *buf, uint32_t buflen, struct osd_thandle *oh);
int __osd_zap_create(const struct lu_env *env, struct osd_device *osd,
		     dnode_t **zap_dnp, dmu_tx_t *tx, struct lu_attr *la,
		     unsigned dnsize, zap_flags_t flags);
int __osd_object_create(const struct lu_env *env, struct osd_device *osd,
			struct osd_object *obj, const struct lu_fid *fid,
			dnode_t **dnp, dmu_tx_t *tx, struct lu_attr *la);
int __osd_attr_init(const struct lu_env *env, struct osd_device *osd,
		    struct osd_object *obj, sa_handle_t *sa_hdl, dmu_tx_t *tx,
		    struct lu_attr *la, uint64_t parent, nvlist_t *);
int osd_find_new_dnode(const struct lu_env *env, dmu_tx_t *tx,
		       uint64_t oid, dnode_t **dnp);

/* osd_oi.c */
int osd_oi_init(const struct lu_env *env, struct osd_device *o, bool reset);
void osd_oi_fini(const struct lu_env *env, struct osd_device *o);
int osd_fid_lookup(const struct lu_env *env,
		   struct osd_device *, const struct lu_fid *, uint64_t *);
uint64_t osd_get_name_n_idx(const struct lu_env *env, struct osd_device *osd,
			    const struct lu_fid *fid, char *buf, int bufsize,
			    dnode_t **zdn);
int osd_options_init(void);
int osd_ost_seq_exists(const struct lu_env *env, struct osd_device *osd,
		       __u64 seq);
int osd_idc_find_and_init(const struct lu_env *env, struct osd_device *osd,
			  struct osd_object *obj);
struct osd_idmap_cache *osd_idc_find_or_init(const struct lu_env *env,
					     struct osd_device *osd,
					     const struct lu_fid *fid);
struct osd_idmap_cache *osd_idc_find(const struct lu_env *env,
				     struct osd_device *osd,
				     const struct lu_fid *fid);
int osd_idc_find_and_init_with_oid(const struct lu_env *env,
				   struct osd_device *osd,
				   const struct lu_fid *fid,
				   uint64_t oid);
int fid_is_on_ost(const struct lu_env *env, struct osd_device *osd,
		  const struct lu_fid *fid);
int osd_obj_find_or_create(const struct lu_env *env, struct osd_device *o,
			   uint64_t parent, const char *name, uint64_t *child,
			   const struct lu_fid *fid, bool isdir);

extern unsigned int osd_oi_count;

/* osd_index.c */
int osd_get_fid_by_oid(const struct lu_env *env, struct osd_device *osd,
		       uint64_t oid, struct lu_fid *fid);
int osd_index_try(const struct lu_env *env, struct dt_object *dt,
		  const struct dt_index_features *feat);
int osd_fld_lookup(const struct lu_env *env, struct osd_device *osd,
		   u64 seq, struct lu_seq_range *range);
void osd_zap_cursor_init_serialized(zap_cursor_t *zc, struct objset *os,
				    uint64_t id, uint64_t dirhash);
int osd_zap_cursor_init(zap_cursor_t **zc, struct objset *os,
			uint64_t id, uint64_t dirhash);
void osd_zap_cursor_fini(zap_cursor_t *zc);
uint64_t osd_zap_cursor_serialize(zap_cursor_t *zc);
int osd_remote_fid(const struct lu_env *env, struct osd_device *osd,
		   const struct lu_fid *fid);
int osd_add_to_remote_parent(const struct lu_env *env,
			     struct osd_device *osd,
			     struct osd_object *obj,
			     struct osd_thandle *oh);
int osd_delete_from_remote_parent(const struct lu_env *env,
				  struct osd_device *osd,
				  struct osd_object *obj,
				  struct osd_thandle *oh, bool destroy);
int __osd_xattr_load_by_oid(struct osd_device *osd, uint64_t oid,
			    nvlist_t **sa);

/* osd_scrub.c */
int osd_scrub_setup(const struct lu_env *env, struct osd_device *dev,
		    bool resetoi);
void osd_scrub_cleanup(const struct lu_env *env, struct osd_device *dev);
int osd_scrub_start(const struct lu_env *env, struct osd_device *dev,
		    __u32 flags);
void osd_scrub_stop(struct osd_device *dev);
int osd_oii_insert(const struct lu_env *env, struct osd_device *dev,
		   const struct lu_fid *fid, uint64_t oid, bool insert);
int osd_oii_lookup(struct osd_device *dev, const struct lu_fid *fid,
		   uint64_t *oid);

/**
 * Basic transaction credit op
 */
enum dt_txn_op {
	DTO_INDEX_INSERT,
	DTO_INDEX_DELETE,
	DTO_INDEX_UPDATE,
	DTO_NR
};

int osd_scrub_refresh_mapping(const struct lu_env *env,
			      struct osd_device *dev,
			      const struct lu_fid *fid,
			      uint64_t oid, enum dt_txn_op ops,
			      bool force, const char *name);


/* osd_xattr.c */
int __osd_sa_xattr_schedule_update(const struct lu_env *env,
				   struct osd_object *obj,
				   struct osd_thandle *oh);
int __osd_sa_attr_init(const struct lu_env *env, struct osd_object *obj,
		       struct osd_thandle *oh);
int __osd_sa_xattr_update(const struct lu_env *env, struct osd_object *obj,
			  struct osd_thandle *oh);
int __osd_xattr_load(struct osd_device *osd, sa_handle_t *hdl,
		     nvlist_t **sa);
int __osd_xattr_get_large(const struct lu_env *env, struct osd_device *osd,
			  uint64_t xattr, struct lu_buf *buf,
			  const char *name, int *sizep);
int osd_xattr_get_internal(const struct lu_env *env, struct osd_object *obj,
			   struct lu_buf *buf, const char *name, int *sizep);
int osd_xattr_get_lma(const struct lu_env *env, struct osd_object *obj,
		      struct lu_buf *buf);
int osd_xattr_get(const struct lu_env *env, struct dt_object *dt,
		  struct lu_buf *buf, const char *name);
int osd_declare_xattr_set(const struct lu_env *env, struct dt_object *dt,
			  const struct lu_buf *buf, const char *name,
			  int fl, struct thandle *handle);
int osd_xattr_set(const struct lu_env *env, struct dt_object *dt,
		  const struct lu_buf *buf, const char *name, int fl,
		  struct thandle *handle);
int osd_declare_xattr_del(const struct lu_env *env, struct dt_object *dt,
			  const char *name, struct thandle *handle);
int osd_xattr_del(const struct lu_env *env, struct dt_object *dt,
		  const char *name, struct thandle *handle);
void osd_declare_xattrs_destroy(const struct lu_env *env,
				struct osd_object *obj,
				struct osd_thandle *oh);
int osd_xattrs_destroy(const struct lu_env *env,
		       struct osd_object *obj, struct osd_thandle *oh);
int osd_xattr_list(const struct lu_env *env, struct dt_object *dt,
		   const struct lu_buf *lb);
void __osd_xattr_declare_set(const struct lu_env *env, struct osd_object *obj,
			int vallen, const char *name, struct osd_thandle *oh);
int __osd_sa_xattr_set(const struct lu_env *env, struct osd_object *obj,
		       const struct lu_buf *buf, const char *name, int fl,
		       struct osd_thandle *oh);;
int __osd_xattr_set(const struct lu_env *env, struct osd_object *obj,
		    const struct lu_buf *buf, const char *name, int fl,
		    struct osd_thandle *oh);
int __osd_sa_xattr_update(const struct lu_env *env, struct osd_object *obj,
			  struct osd_thandle *oh);

#define OSD_BASE_EA_IN_BONUS	(ZFS_SA_BASE_ATTR_SIZE + \
				 sizeof(__u64) /* VBR VERSION */ + \
				 sizeof(struct lustre_mdt_attrs) /* LMA */)

#ifdef HAVE_DMU_OBJECT_ALLOC_DNSIZE
int osd_find_dnsize(struct osd_device *osd, int ea_in_bonus);
#else
static inline int
osd_find_dnsize(struct osd_device *osd, int ea_in_bonus)
{
	return DN_MAX_BONUSLEN;
}
#endif

static inline int osd_object_is_zap(dnode_t *dn)
{
	return (dn->dn_type == DMU_OT_DIRECTORY_CONTENTS ||
		dn->dn_type == DMU_OT_USERGROUP_USED);
}

/* XXX: f_ver is not counted, but may differ too */
static inline void osd_fid2str(char *buf, const struct lu_fid *fid, int len)
{
	snprintf(buf, len, DFID_NOBRACE, PFID(fid));
}

static inline int
osd_xattr_set_internal(const struct lu_env *env, struct osd_object *obj,
		       const struct lu_buf *buf, const char *name, int fl,
		       struct osd_thandle *oh)
{
	int rc;

	if (unlikely(!dt_object_exists(&obj->oo_dt) || obj->oo_destroyed))
		return -ENOENT;

	LASSERT(obj->oo_dn);
	if (osd_obj2dev(obj)->od_xattr_in_sa) {
		rc = __osd_sa_xattr_set(env, obj, buf, name, fl, oh);
		if (rc == -EFBIG)
			rc = __osd_xattr_set(env, obj, buf, name, fl, oh);
	} else {
		rc = __osd_xattr_set(env, obj, buf, name, fl, oh);
	}

	return rc;
}

static inline uint64_t attrs_fs2zfs(const uint32_t flags)
{
	return (flags & LUSTRE_APPEND_FL	? ZFS_APPENDONLY	: 0) |
		(flags & LUSTRE_NODUMP_FL	? ZFS_NODUMP		: 0) |
#ifdef ZFS_PROJINHERIT
		(flags & LUSTRE_PROJINHERIT_FL	? ZFS_PROJINHERIT	: 0) |
#endif
		(flags & LUSTRE_IMMUTABLE_FL	? ZFS_IMMUTABLE		: 0);
}

static inline uint32_t attrs_zfs2fs(const uint64_t flags)
{
	return (flags & ZFS_APPENDONLY	? LUSTRE_APPEND_FL	: 0) |
		(flags & ZFS_NODUMP	? LUSTRE_NODUMP_FL	: 0) |
#ifdef ZFS_PROJINHERIT
		(flags & ZFS_PROJINHERIT ? LUSTRE_PROJINHERIT_FL : 0) |
#endif
		(flags & ZFS_IMMUTABLE	? LUSTRE_IMMUTABLE_FL	: 0);
}

#endif

#ifndef HAVE_DSL_POOL_CONFIG
static inline void dsl_pool_config_enter(dsl_pool_t *dp, void *name)
{
}

static inline void dsl_pool_config_exit(dsl_pool_t *dp, void *name)
{
}
#endif

#ifdef HAVE_SPA_MAXBLOCKSIZE
#define	osd_spa_maxblocksize(spa)	spa_maxblocksize(spa)
#define	osd_spa_maxblockshift(spa)	fls64(spa_maxblocksize(spa) - 1)
#else
#define	osd_spa_maxblocksize(spa)	SPA_MAXBLOCKSIZE
#define	osd_spa_maxblockshift(spa)	SPA_MAXBLOCKSHIFT
#define	SPA_OLD_MAXBLOCKSIZE		SPA_MAXBLOCKSIZE
#endif

#ifdef HAVE_SA_SPILL_ALLOC
static inline void *
osd_zio_buf_alloc(size_t size)
{
	return sa_spill_alloc(KM_SLEEP);
}

static inline void
osd_zio_buf_free(void *buf, size_t size)
{
	sa_spill_free(buf);
}
#else
#define	osd_zio_buf_alloc(size)		zio_buf_alloc(size)
#define	osd_zio_buf_free(buf, size)	zio_buf_free(buf, size)
#endif

#ifdef HAVE_DMU_OBJECT_ALLOC_DNSIZE
static inline uint64_t
osd_dmu_object_alloc(objset_t *os, dmu_object_type_t objtype, int blocksize,
		     int dnodesize, dmu_tx_t *tx)
{
	if (dnodesize == 0)
		dnodesize = max_t(int, dmu_objset_dnodesize(os),
				  DNODE_MIN_SIZE);

	return dmu_object_alloc_dnsize(os, objtype, blocksize, DMU_OT_SA,
				       DN_BONUS_SIZE(dnodesize), dnodesize, tx);
}

static inline uint64_t
osd_zap_create_flags(objset_t *os, int normflags, zap_flags_t flags,
		     dmu_object_type_t ot, int leaf_blockshift,
		     int indirect_blockshift, int dnodesize, dmu_tx_t *tx)
{
	if (dnodesize == 0)
		dnodesize = max_t(int, dmu_objset_dnodesize(os),
				  DNODE_MIN_SIZE);

	return zap_create_flags_dnsize(os, normflags, flags, ot,
				       leaf_blockshift, indirect_blockshift,
				       DMU_OT_SA, DN_BONUS_SIZE(dnodesize),
				       dnodesize, tx);
}

static inline int
osd_obj_bonuslen(struct osd_object *obj)
{
	int bonuslen = DN_BONUS_SIZE(DNODE_MIN_SIZE);

	if (obj->oo_dn != NULL && obj->oo_dn->dn_num_slots != 0) {
		bonuslen = DN_SLOTS_TO_BONUSLEN(obj->oo_dn->dn_num_slots);
	} else {
		objset_t *os = osd_dtobj2objset(&obj->oo_dt);
		int dnodesize;

		if (os != NULL) {
			dnodesize = dmu_objset_dnodesize(os);
			if (dnodesize != 0)
				bonuslen = DN_BONUS_SIZE(dnodesize);
		}
	}

	return bonuslen;
}
#else
static inline uint64_t
osd_dmu_object_alloc(objset_t *os, dmu_object_type_t objtype, int blocksize,
		     int dnodesize, dmu_tx_t *tx)
{
	return dmu_object_alloc(os, objtype, blocksize, DMU_OT_SA,
				DN_MAX_BONUSLEN, tx);
}

static inline uint64_t
osd_zap_create_flags(objset_t *os, int normflags, zap_flags_t flags,
		     dmu_object_type_t ot, int leaf_blockshift,
		     int indirect_blockshift, int dnodesize, dmu_tx_t *tx)
{
	return zap_create_flags(os, normflags, flags, ot, leaf_blockshift,
				indirect_blockshift, DMU_OT_SA,
				DN_MAX_BONUSLEN, tx);
}

static inline int
osd_obj_bonuslen(struct osd_object *obj)
{
	return DN_MAX_BONUSLEN;
}
#endif /* HAVE_DMU_OBJECT_ALLOC_DNSIZE */

#ifdef HAVE_DMU_PREFETCH_6ARG
#define osd_dmu_prefetch(os, obj, lvl, off, len, pri)	\
	dmu_prefetch((os), (obj), (lvl), (off), (len), (pri))
#else
#define osd_dmu_prefetch(os, obj, lvl, off, len, pri)	\
	dmu_prefetch((os), (obj), (lvl), (off))
#endif

static inline int osd_sa_handle_get(struct osd_object *obj)
{
	struct osd_device *osd = osd_obj2dev(obj);
	dnode_t *dn = obj->oo_dn;
	int rc;

	if (obj->oo_sa_hdl)
		return 0;

	dbuf_read(dn->dn_bonus, NULL, DB_RF_MUST_SUCCEED | DB_RF_NOPREFETCH);
	rc = -sa_handle_get_from_db(osd->od_os, &dn->dn_bonus->db, obj,
				    SA_HDL_PRIVATE, &obj->oo_sa_hdl);
	if (rc)
		return rc;
	zfs_refcount_add(&dn->dn_bonus->db_holds, osd_obj_tag);
	return 0;
}

static inline void osd_dnode_rele(dnode_t *dn)
{
	dmu_buf_impl_t *db;
	LASSERT(dn);
	LASSERT(dn->dn_bonus);
	db = dn->dn_bonus;

	dmu_buf_rele(&db->db, osd_obj_tag);
}

static inline uint64_t osd_db_dirty_txg(dmu_buf_impl_t *db)
{
	dbuf_dirty_record_t *dr;
	uint64_t txg = 0;

	mutex_enter(&db->db_mtx);
#ifdef HAVE_DB_DIRTY_RECORDS_LIST
	dr = list_head(&db->db_dirty_records);
#else
	dr = db->db_last_dirty;
#endif
	if (dr != NULL)
		txg = dr->dr_txg;
	mutex_exit(&db->db_mtx);

	return txg;
}

#ifdef HAVE_DMU_USEROBJ_ACCOUNTING

#define OSD_DMU_USEROBJ_PREFIX		DMU_OBJACCT_PREFIX
#define OSD_DMU_USEROBJ_PREFIX_LEN	DMU_OBJACCT_PREFIX_LEN

static inline bool osd_dmu_userobj_accounting_available(struct osd_device *osd)
{
	return dmu_objset_userobjspace_present(osd->od_os);
}
#else

#define OSD_DMU_USEROBJ_PREFIX		"obj-"
#define OSD_DMU_USEROBJ_PREFIX_LEN	4

static inline bool osd_dmu_userobj_accounting_available(struct osd_device *osd)
{
	return false;
}
#endif /* #ifdef HAVE_DMU_USEROBJ_ACCOUNTING */

static inline int osd_zap_add(struct osd_device *osd, uint64_t zap,
			      dnode_t *dn, const char *key,
			      int int_size, int int_num,
			      const void *val, dmu_tx_t *tx)
{
	LASSERT(zap != 0);

#ifdef HAVE_ZAP_ADD_BY_DNODE
	if (dn)
		return -zap_add_by_dnode(dn, key, int_size, int_num, val, tx);
#endif
	return -zap_add(osd->od_os, zap, key, int_size, int_num, val, tx);
}

static inline int osd_zap_remove(struct osd_device *osd, uint64_t zap,
				 dnode_t *dn, const char *key,
				 dmu_tx_t *tx)
{
	LASSERT(zap != 0);

#ifdef HAVE_ZAP_ADD_BY_DNODE
	if (dn)
		return -zap_remove_by_dnode(dn, key, tx);
#endif
	return -zap_remove(osd->od_os, zap, key, tx);
}


static inline int osd_zap_lookup(struct osd_device *osd, uint64_t zap,
				 dnode_t *dn, const char *key,
				 int int_size, int int_num, void *v)
{
	LASSERT(zap != 0);

#ifdef HAVE_ZAP_ADD_BY_DNODE
	if (dn)
		return -zap_lookup_by_dnode(dn, key, int_size, int_num, v);
#endif
	return -zap_lookup(osd->od_os, zap, key, int_size, int_num, v);
}

static inline void osd_tx_hold_zap(dmu_tx_t *tx, uint64_t zap,
				   dnode_t *dn, int add, const char *name)
{
#ifdef HAVE_DMU_TX_HOLD_ZAP_BY_DNODE
	if (dn) {
		dmu_tx_hold_zap_by_dnode(tx, dn, add, name);
		return;
	}
#endif
	dmu_tx_hold_zap(tx, zap, add, name);
}

static inline void osd_tx_hold_write(dmu_tx_t *tx, uint64_t oid,
				   dnode_t *dn, uint64_t off, int len)
{
#ifdef HAVE_DMU_TX_HOLD_ZAP_BY_DNODE
	if (dn) {
		dmu_tx_hold_write_by_dnode(tx, dn, off, len);
		return;
	}
#endif
	dmu_tx_hold_write(tx, oid, off, len);
}

static inline void osd_dmu_write(struct osd_device *osd, dnode_t *dn,
				 uint64_t offset, uint64_t size,
				 const char *buf, dmu_tx_t *tx)
{
	LASSERT(dn);
#ifdef HAVE_DMU_WRITE_BY_DNODE
	dmu_write_by_dnode(dn, offset, size, buf, tx);
#else
	dmu_write(osd->od_os, dn->dn_object, offset, size, buf, tx);
#endif
}

static inline int osd_dmu_read(struct osd_device *osd, dnode_t *dn,
			       uint64_t offset, uint64_t size,
			       char *buf, int flags)
{
	LASSERT(dn);
#ifdef HAVE_DMU_READ_BY_DNODE
	return -dmu_read_by_dnode(dn, offset, size, buf, flags);
#else
	return -dmu_read(osd->od_os, dn->dn_object, offset, size, buf, flags);
#endif
}

#ifdef HAVE_DMU_OBJSET_OWN_6ARG
#define osd_dmu_objset_own(name, type, ronly, decrypt, tag, os)	\
	dmu_objset_own((name), (type), (ronly), (decrypt), (tag), (os))
#else
#define osd_dmu_objset_own(name, type, ronly, decrypt, tag, os)	\
	dmu_objset_own((name), (type), (ronly), (tag), (os))
#endif

#ifdef HAVE_DMU_OBJSET_DISOWN_3ARG
#define osd_dmu_objset_disown(os, decrypt, tag)	\
	dmu_objset_disown((os), (decrypt), (tag))
#else
#define osd_dmu_objset_disown(os, decrypt, tag)	\
	dmu_objset_disown((os), (tag))
#endif

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
	struct lu_fid *fid = &osd_oti_get(env)->oti_fid;
	int rc;

	lu_local_obj_fid(fid, INDEX_BACKUP_OID);
	rc = osd_idc_find_and_init_with_oid(env, osd, fid,
					    osd->od_index_backup_id);
	if (rc)
		backup = false;

	lustre_index_backup(env, &osd->od_dt_dev, osd_name(osd),
			    &osd->od_index_backup_list, &osd->od_lock,
			    &osd->od_index_backup_stop, backup);
}

#ifndef HAVE_DMU_TX_MARK_NETFREE
#define dmu_tx_mark_netfree(tx)
#endif

#ifndef HAVE_ZFS_INODE_TIMESPEC
#define inode_timespec_t timestruc_t
#endif

#ifdef HAVE_DMU_OFFSET_NEXT
#define osd_dmu_offset_next(os, obj, hole, res) \
	dmu_offset_next((os), (obj), (hole), (res))
#else
#define osd_dmu_offset_next(os, obj, hole, res) (EBUSY)
#endif

#endif /* _OSD_INTERNAL_H */
