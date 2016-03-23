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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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
#ifdef SHRINK_STOP
#undef SHRINK_STOP
#endif
#include <sys/arc.h>
#include <sys/nvpair.h>
#include <sys/zfs_znode.h>
#include <sys/zap.h>
#include <sys/dbuf.h>

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

#define LUSTRE_ROOT_FID_SEQ	0
#define DMU_OSD_SVNAME		"svname"
#define DMU_OSD_OI_NAME_BASE	"oi"

#define OSD_GFP_IO		(GFP_NOFS | __GFP_HIGHMEM)

/* Statfs space reservation for grant, fragmentation, and unlink space. */
#define OSD_STATFS_RESERVED_SIZE	(16ULL << 20) /* reserve 16MB minimum */
#define OSD_STATFS_RESERVED_SHIFT	(7)     /* reserve 0.78% of all space */

/* Statfs {minimum, safe estimate, and maximum} dnodes per block */
#define OSD_DNODE_MIN_BLKSHIFT	(DNODES_PER_BLOCK_SHIFT)
#define OSD_DNODE_EST_BLKSHIFT	(DNODES_PER_BLOCK_SHIFT >> 1)
#define OSD_DNODE_EST_COUNT	1024

#define OSD_GRANT_FOR_LOCAL_OIDS (2ULL << 20) /* 2MB for last_rcvd, ... */

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
	/* ozi_pos - position of the cursor:
	 * 0 - before any record
	 * 1 - "."
	 * 2 - ".."
	 * 3 - real records */
	unsigned		 ozi_pos:3;
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
	uint64_t	nlink;
	uint64_t	rdev;
	uint64_t	flags;
	uint64_t	size;
	uint64_t	atime[2];
	uint64_t	mtime[2];
	uint64_t	ctime[2];
};

struct osd_thread_info {
	const struct lu_env	*oti_env;

	struct lu_fid		 oti_fid;
	/*
	 * XXX temporary: for ->i_op calls.
	 */
	struct timespec		 oti_time;

	struct ost_id		 oti_ostid;

	char			 oti_buf[64];

	char			 oti_str[64];
	union {
		char		 oti_key[MAXNAMELEN + 1];
		__u64		 oti_key64[(MAXNAMELEN + 1)/sizeof(__u64)];
	};
	struct lustre_mdt_attrs oti_mdt_attrs;

	struct lu_attr		 oti_la;
	struct osa_attr		 oti_osa;
	zap_attribute_t		 oti_za;
	dmu_object_info_t	 oti_doi;
	struct luz_direntry	 oti_zde;

	struct lquota_id_info	 oti_qi;
	struct lu_seq_range	 oti_seq_range;
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
	struct semaphore	 ot_sa_lock;
	dmu_tx_t		*ot_tx;
	struct lquota_trans	 ot_quota_trans;
	__u32			 ot_write_commit:1,
				 ot_assigned:1;
};

#define OSD_OI_NAME_SIZE        16

/*
 * Object Index (OI) instance.
 */
struct osd_oi {
	char			oi_name[OSD_OI_NAME_SIZE]; /* unused */
	uint64_t		oi_zapid;
	dmu_buf_t	       *oi_db;
};

struct osd_seq {
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
	uint64_t		 od_unlinkedid; /* id of unlinked zapobj */
	/* SA attr mapping->id,
	 * name is the same as in ZFS to use defines SA_ZPL_...*/
	sa_attr_type_t		 *z_attr_table;

	struct proc_dir_entry	*od_proc_entry;
	struct lprocfs_stats	*od_stats;

	uint64_t		 od_max_blksz;
	uint64_t		 od_root;
	uint64_t		 od_O_id;
	struct osd_oi		**od_oi_table;
	unsigned int		 od_oi_count;
	struct osd_seq_list	od_seq_list;

	unsigned int		 od_dev_set_rdonly:1, /**< osd_ro() called */
				 od_prop_rdonly:1,  /**< ZFS property readonly */
				 od_xattr_in_sa:1,
				 od_quota_iused_est:1,
				 od_is_ost:1,
				 od_posix_acl:1;

	char			 od_mntdev[128];
	char			 od_svname[128];

	int			 od_connects;
	struct lu_site		 od_site;

	/* object IDs of the inode accounting indexes */
	uint64_t		 od_iusr_oid;
	uint64_t		 od_igrp_oid;

	/* quota slave instance */
	struct qsd_instance	*od_quota_slave;

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
};

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
	 * creation, or assigned by osd_object_create() under write lock).
	 */
	dmu_buf_t		*oo_db;
	sa_handle_t		*oo_sa_hdl;
	nvlist_t		*oo_sa_xattr;
	struct list_head	 oo_sa_linkage;

	/* used to implement osd_object_*_{lock|unlock} */
	struct rw_semaphore	 oo_sem;

	/* to serialize some updates: destroy vs. others,
	 * xattr_set, etc */
	struct rw_semaphore	 oo_guard;

	/* protected by oo_guard */
	struct list_head	 oo_unlinked_linkage;

	/* cached attributes */
	rwlock_t		 oo_attr_lock;
	struct lu_attr		 oo_attr;

	/* external dnode holding large EAs, protected by oo_guard */
	uint64_t		 oo_xattr;
	enum osd_destroy_type	 oo_destroy;

	__u32			 oo_destroyed:1;

	/* the i_flags in LMA */
	__u32			 oo_lma_flags;
	/* record size for index file */
	unsigned char		 oo_keysize;
	unsigned char		 oo_recsize;
	unsigned char		 oo_recusize;	/* unit size */
};

int osd_statfs(const struct lu_env *, struct dt_device *, struct obd_statfs *);
extern const struct dt_index_operations osd_acct_index_ops;
uint64_t osd_quota_fid2dmu(const struct lu_fid *fid);
extern struct lu_device_operations  osd_lu_ops;
extern struct dt_index_operations osd_dir_ops;
int osd_declare_quota(const struct lu_env *env, struct osd_device *osd,
		      qid_t uid, qid_t gid, long long space,
		      struct osd_thandle *oh, bool is_blk, int *flags,
		      bool force);
uint64_t osd_objs_count_estimate(uint64_t refdbytes, uint64_t usedobjs,
				 uint64_t nrblocks, uint64_t est_maxblockshift);

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
	return container_of0(o, struct osd_object, oo_dt.do_lu);
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
	return osd->od_dt_dev.dd_lu_dev.ld_obd->obd_name;
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
void osd_object_sa_dirty_rele(struct osd_thandle *oh);
int __osd_obj2dbuf(const struct lu_env *env, objset_t *os,
		   uint64_t oid, dmu_buf_t **dbp);
struct lu_object *osd_object_alloc(const struct lu_env *env,
				   const struct lu_object_header *hdr,
				   struct lu_device *d);
int osd_object_sa_update(struct osd_object *obj, sa_attr_type_t type,
			 void *buf, uint32_t buflen, struct osd_thandle *oh);
int __osd_zap_create(const struct lu_env *env, struct osd_device *osd,
		     dmu_buf_t **zap_dbp, dmu_tx_t *tx, struct lu_attr *la,
		     uint64_t parent, zap_flags_t flags);
int __osd_object_create(const struct lu_env *env, struct osd_object *obj,
			dmu_buf_t **dbp, dmu_tx_t *tx, struct lu_attr *la,
			uint64_t parent);

/* osd_oi.c */
int osd_oi_init(const struct lu_env *env, struct osd_device *o);
void osd_oi_fini(const struct lu_env *env, struct osd_device *o);
int osd_fid_lookup(const struct lu_env *env,
		   struct osd_device *, const struct lu_fid *, uint64_t *);
uint64_t osd_get_name_n_idx(const struct lu_env *env, struct osd_device *osd,
			    const struct lu_fid *fid, char *buf);
int osd_options_init(void);
int osd_ost_seq_exists(const struct lu_env *env, struct osd_device *osd,
		       __u64 seq);
/* osd_index.c */
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

/* osd_xattr.c */
int __osd_xattr_load(struct osd_device *osd, uint64_t dnode,
		     nvlist_t **sa_xattr);
int __osd_xattr_get_large(const struct lu_env *env, struct osd_device *osd,
			  uint64_t xattr, struct lu_buf *buf,
			  const char *name, int *sizep);
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
static inline int
osd_xattr_set_internal(const struct lu_env *env, struct osd_object *obj,
		       const struct lu_buf *buf, const char *name, int fl,
		       struct osd_thandle *oh)
{
	int rc;

	if (unlikely(!dt_object_exists(&obj->oo_dt) || obj->oo_destroyed))
		return -ENOENT;

	LASSERT(obj->oo_db);
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
		(flags & LUSTRE_IMMUTABLE_FL	? ZFS_IMMUTABLE		: 0);
}

static inline uint32_t attrs_zfs2fs(const uint64_t flags)
{
	return (flags & ZFS_APPENDONLY	? LUSTRE_APPEND_FL	: 0) |
		(flags & ZFS_NODUMP	? LUSTRE_NODUMP_FL	: 0) |
		(flags & ZFS_IMMUTABLE	? LUSTRE_IMMUTABLE_FL	: 0);
}

#endif

#ifndef HAVE_DSL_POOL_CONFIG
static inline void dsl_pool_config_enter(dsl_pool_t *dp, char *name)
{
}

static inline void dsl_pool_config_exit(dsl_pool_t *dp, char *name)
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

#endif /* _OSD_INTERNAL_H */
