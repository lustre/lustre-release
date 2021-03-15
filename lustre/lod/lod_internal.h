/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright  2009 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/lod/lod_internal.h
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#ifndef _LOD_INTERNAL_H
#define _LOD_INTERNAL_H

#include <libcfs/libcfs.h>
#include <uapi/linux/lustre/lustre_cfg.h>
#include <obd.h>
#include <dt_object.h>

#define LOV_USES_ASSIGNED_STRIPE        0
#define LOV_USES_DEFAULT_STRIPE         1

/* Special values to remove LOV EA from disk */
#define LOVEA_DELETE_VALUES(size, count, offset, pool)			\
	((size) == 0 && (count) == 0 &&					\
	 (offset) == (typeof(offset))(-1) && (pool) == NULL)

#define LMVEA_DELETE_VALUES(count, offset)				\
	((count) == 0 && (offset) == (typeof(offset))(-1))

struct pool_desc {
	char			 pool_name[LOV_MAXPOOLNAME + 1];
	struct lu_tgt_pool	 pool_obds;	/* pool members */
	atomic_t		 pool_refcount;
	struct lu_qos_rr	 pool_rr;
	struct rhash_head	 pool_hash;	/* access by poolname */
	struct list_head	 pool_list;
	struct rcu_head		 pool_rcu;
	struct proc_dir_entry	*pool_proc_entry;
	struct obd_device	*pool_lobd;	/* owner */
};

int lod_pool_hash_init(struct rhashtable *tbl);
void lod_pool_hash_destroy(struct rhashtable *tbl);

#define pool_tgt_count(p) ((p)->pool_obds.op_count)
#define pool_tgt_array(p)  ((p)->pool_obds.op_array)
#define pool_tgt_rw_sem(p) ((p)->pool_obds.op_rw_sem)

#define lod_tgt_desc	lu_tgt_desc
#define lod_tgt_descs	lu_tgt_descs

#define OST_TGT(lod, index)   LTD_TGT(&lod->lod_ost_descs, index)
#define MDT_TGT(lod, index)   LTD_TGT(&lod->lod_mdt_descs, index)

struct lod_avoid_guide {
	/* ids of OSSs avoid guidance */
	__u32			*lag_oss_avoid_array;
	/* number of filled array items */
	unsigned int		lag_oaa_count;
	/* number of allocated array items */
	unsigned int		lag_oaa_size;
	/* bitmap of OSTs avoid guidance */
	unsigned long		*lag_ost_avoid_bitmap;
	u32			lag_ost_avoid_size;
	/* how many OSTs are available for alloc */
	__u32			lag_ost_avail;
};

#define LOD_DOM_MIN_SIZE_KB (LOV_MIN_STRIPE_SIZE >> 10)
#define LOD_DOM_SFS_MAX_AGE 10

struct lod_device {
	struct dt_device      lod_dt_dev;
	struct obd_export    *lod_child_exp;
	struct dt_device     *lod_child;
	struct lprocfs_stats *lod_stats;
	spinlock_t	      lod_connects_lock;
	int		      lod_connects;
	unsigned int	      lod_recovery_completed:1,
			      lod_initialized:1,
			      lod_lmv_failout:1,
			      lod_child_got_update_log:1;

	/* protect ld_active_tgt_count, ltd_active and lod_md_root */
	spinlock_t	     lod_lock;

	/* Description of OST */
	struct lod_tgt_descs  lod_ost_descs;
	/* Description of MDT */
	struct lod_tgt_descs  lod_mdt_descs;

	/* Recovery thread for lod_child */
	struct task_struct   *lod_child_recovery_task;

	/* maximum EA size underlied OSD may have */
	unsigned int	      lod_osd_max_easize;
	/* maximum size of MDT stripe for Data-on-MDT files. */
	unsigned int          lod_dom_stripesize_max_kb;
	/* current DOM default stripe size adjusted by threshold */
	unsigned int	      lod_dom_stripesize_cur_kb;
	/* Threshold at which DOM default stripe will start decreasing */
	__u64		      lod_dom_threshold_free_mb;

	/* Local OSD statfs cache */
	spinlock_t	      lod_lsfs_lock;
	time64_t	      lod_lsfs_age;
	__u64		      lod_lsfs_total_mb;
	__u64		      lod_lsfs_free_mb;

	/* OST pool data */
	int			lod_pool_count;
	struct rhashtable	lod_pools_hash_body; /* used for key access */
	struct list_head	lod_pool_list; /* used for sequential access */
	struct proc_dir_entry  *lod_pool_proc_entry;

	enum lustre_sec_part   lod_sp_me;

	struct proc_dir_entry *lod_symlink;
	struct dentry	       *lod_debugfs;

	/* ROOT object, used to fetch FS default striping */
	struct lod_object      *lod_md_root;
};

#define lod_ost_bitmap		lod_ost_descs.ltd_tgt_bitmap
#define lod_ost_count		lod_ost_descs.ltd_lov_desc.ld_tgt_count
#define lod_remote_mdt_count	lod_mdt_descs.ltd_lmv_desc.ld_tgt_count

struct lod_layout_component {
	struct lu_extent	  llc_extent;
	__u32			  llc_id;
	__u32			  llc_flags;
	__u32			  llc_stripe_size;
	__u32			  llc_pattern;
	__u16			  llc_layout_gen;
	__u16			  llc_stripe_offset;
	__u16			  llc_stripe_count;
	__u16			  llc_stripes_allocated;
	__u64			  llc_timestamp; /* snapshot time */
	char			 *llc_pool;
	/* ost list specified with LOV_USER_MAGIC_SPECIFIC lum */
	struct lu_tgt_pool	  llc_ostlist;
	struct dt_object	**llc_stripe;
	__u32			 *llc_ost_indices;
};

struct lod_default_striping {
	/* default LOV */
	/* current layout component count */
	__u16				lds_def_comp_cnt;
	__u16				lds_def_mirror_cnt;
	/* the largest comp count ever used */
	__u32				lds_def_comp_size_cnt;
	struct lod_layout_component	*lds_def_comp_entries;
	/* default LMV */
	__u32				lds_dir_def_stripe_count;
	__u32				lds_dir_def_stripe_offset;
	__u32				lds_dir_def_hash_type;
	__u8				lds_dir_def_max_inherit;
	__u8				lds_dir_def_max_inherit_rr;
					/* default file striping flags (LOV) */
	__u32				lds_def_striping_set:1,
					lds_def_striping_is_composite:1,
					/* default dir striping flags (LMV) */
					lds_dir_def_striping_set:1;
};

static inline __u8 lmv_inherit_next(__u8 inherit)
{
	if (inherit == LMV_INHERIT_END || inherit == LMV_INHERIT_NONE)
		return LMV_INHERIT_NONE;

	if (inherit == LMV_INHERIT_UNLIMITED || inherit > LMV_INHERIT_MAX)
		return inherit;

	return inherit - 1;
}

static inline __u8 lmv_inherit_rr_next(__u8 inherit_rr)
{
	if (inherit_rr == LMV_INHERIT_RR_NONE ||
	    inherit_rr == LMV_INHERIT_RR_UNLIMITED ||
	    inherit_rr > LMV_INHERIT_RR_MAX)
		return inherit_rr;

	return inherit_rr - 1;
}

struct lod_mirror_entry {
	__u16	lme_stale:1,
		lme_prefer:1;
	/* mirror id */
	__u16	lme_id;
	/* start,end index of this mirror in ldo_comp_entries */
	__u16	lme_start;
	__u16	lme_end;
};

struct lod_object {
	/* common fields for both files and directories */
	struct dt_object		ldo_obj;
	struct mutex			ldo_layout_mutex;
	union {
		/* file stripe (LOV) */
		struct {
			__u32		ldo_layout_gen;
			/* Layout component count for a regular file.
			 * It equals to 1 for non-composite layout. */
			__u16		ldo_comp_cnt;
			/* Layout mirror count for a PFLR file.
			 * It's 0 for files with non-composite layout. */
			__u16		ldo_mirror_count;
			struct lod_mirror_entry	*ldo_mirrors;
			__u32		ldo_is_composite:1,
					ldo_flr_state:2,
					ldo_comp_cached:1,
					ldo_is_foreign:1;
		};
		/* directory stripe (LMV) */
		struct {
			/* Slave stripe count for striped directory. */
			__u16		ldo_dir_stripe_count;
			/* How many stripes allocated for a striped directory */
			__u16		ldo_dir_stripes_allocated;
			__u32		ldo_dir_stripe_offset;
			__u32		ldo_dir_hash_type;
			__u32		ldo_dir_migrate_offset;
			__u32		ldo_dir_migrate_hash;
			__u32		ldo_dir_layout_version;
			/* Is a slave stripe of striped directory? */
			__u32		ldo_dir_slave_stripe:1,
					ldo_dir_striped:1,
					/* the stripe has been loaded */
					ldo_dir_stripe_loaded:1,
					/* foreign directory */
					ldo_dir_is_foreign;
			/*
			 * This default LMV is parent default LMV, which will be
			 * used in child creation, and it's not cached, so this
			 * field is invalid after create, make sure it's used by
			 * lod_dir_striping_create_internal() only.
			 */
			struct lod_default_striping	*ldo_def_striping;
		};
	};
	union {
		struct {
			/* foreign/raw format LOV */
			char				*ldo_foreign_lov;
			size_t				 ldo_foreign_lov_size;
		};
		struct {
			/* foreign/raw format LMV */
			char				*ldo_foreign_lmv;
			size_t				 ldo_foreign_lmv_size;
		};
		struct {
			/* file stripe (LOV) */
			struct lod_layout_component	*ldo_comp_entries;
			/* slave stripes of striped directory (LMV) */
			struct dt_object		**ldo_stripe;
		};
	};
};

#define ldo_dir_split_offset	ldo_dir_migrate_offset
#define ldo_dir_split_hash	ldo_dir_migrate_hash

#define lod_foreach_mirror_comp(comp, lo, mirror_idx)                      \
for (comp = &lo->ldo_comp_entries[lo->ldo_mirrors[mirror_idx].lme_start];  \
     comp <= &lo->ldo_comp_entries[lo->ldo_mirrors[mirror_idx].lme_end];   \
     comp++)

static inline bool lod_is_flr(const struct lod_object *lo)
{
	if (!lo->ldo_is_composite)
		return false;

	return (lo->ldo_flr_state & LCM_FL_FLR_MASK) != LCM_FL_NONE;
}

static inline bool lod_is_splitting(const struct lod_object *lo)
{
	return lmv_hash_is_splitting(lo->ldo_dir_hash_type);
}

static inline bool lod_is_migrating(const struct lod_object *lo)
{
	return lmv_hash_is_migrating(lo->ldo_dir_hash_type);
}

static inline bool lod_is_layout_changing(const struct lod_object *lo)
{
	return lmv_hash_is_layout_changing(lo->ldo_dir_hash_type);
}

static inline int lod_set_pool(char **pool, const char *new_pool)
{
	int len;

	if (*pool == new_pool)
		return 0;

	if (*pool != NULL) {
		len = strlen(*pool) + 1;
		OBD_FREE(*pool, len);
		*pool = NULL;
	}
	if (new_pool != NULL) {
		len = strlen(new_pool) + 1;
		OBD_ALLOC(*pool, len);
		if (*pool == NULL)
			return -ENOMEM;
		strlcpy(*pool, new_pool, len);
	}
	return 0;
}

static inline int lod_set_def_pool(struct lod_default_striping *lds,
				   int i, const char *new_pool)
{
	return lod_set_pool(&lds->lds_def_comp_entries[i].llc_pool, new_pool);
}

static inline int lod_obj_set_pool(struct lod_object *lo, int i,
				   const char *new_pool)
{
	return lod_set_pool(&lo->ldo_comp_entries[i].llc_pool, new_pool);
}

/**
 * Create new layout generation.
 *
 * The only requirement for layout generation is that it changes when
 * the layout is modified, so a circular counter is sufficient for the
 * low rate of layout modifications.
 *
 * Layout generation is also used to generate unique component ID.
 * To detect generation overflow, we preserve the highest bit of the
 * generation when it wrapped.
 */
static inline void lod_obj_inc_layout_gen(struct lod_object *lo)
{
	__u32 preserve = lo->ldo_layout_gen & ~LCME_ID_MASK;
	lo->ldo_layout_gen++;
	lo->ldo_layout_gen |= preserve;
	/* Zero is not a valid generation */
	if (unlikely((lo->ldo_layout_gen & LCME_ID_MASK) == 0))
		lo->ldo_layout_gen++;
}

struct lod_it {
	struct dt_object	*lit_obj; /* object from the layer below */
	/* stripe offset of iteration */
	__u32			lit_stripe_index;
	__u32			lit_attr;
	struct dt_it		*lit_it;  /* iterator from the layer below */
};

struct lod_thread_info {
	/* per-thread buffer for LOV EA, may be vmalloc'd */
	void			       *lti_ea_store;
	__u32				lti_ea_store_size;
	/* per-thread buffer for LMV EA */
	struct lu_buf			lti_buf;
	struct ost_id			lti_ostid;
	struct lu_fid			lti_fid;
	struct obd_statfs		lti_osfs;
	struct lu_attr			lti_attr;
	struct lod_it			lti_it;
	struct ldlm_res_id		lti_res_id;
	/* used to hold lu_dirent, sizeof(struct lu_dirent) + NAME_MAX */
	char				lti_key[sizeof(struct lu_dirent) +
						NAME_MAX];
	struct dt_object_format		lti_format;
	struct lu_name			lti_name;
	struct lu_buf			lti_linkea_buf;
	struct dt_insert_rec		lti_dt_rec;
	struct llog_catid		lti_cid;
	struct llog_cookie		lti_cookie;
	struct lustre_cfg		lti_lustre_cfg;
	/* used to store parent default striping in create */
	struct lod_default_striping	lti_def_striping;
	struct filter_fid		lti_ff;
	__u32				*lti_comp_idx;
	size_t				lti_comp_size;
	size_t				lti_count;
	struct lu_attr			lti_layout_attr;
	/* object allocation avoid guide info */
	struct lod_avoid_guide		lti_avoid;
	union lmv_mds_md		lti_lmv;
	struct dt_allocation_hint	lti_ah;
};

extern const struct lu_device_operations lod_lu_ops;

static inline int lu_device_is_lod(struct lu_device *d)
{
	return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &lod_lu_ops);
}

static inline struct lod_device* lu2lod_dev(struct lu_device *d)
{
	LASSERT(lu_device_is_lod(d));
	return container_of_safe(d, struct lod_device, lod_dt_dev.dd_lu_dev);
}

static inline struct lu_device *lod2lu_dev(struct lod_device *d)
{
	return &d->lod_dt_dev.dd_lu_dev;
}

static inline struct obd_device *lod2obd(struct lod_device *d)
{
	return d->lod_dt_dev.dd_lu_dev.ld_obd;
}

static inline struct lod_device *dt2lod_dev(struct dt_device *d)
{
	LASSERT(lu_device_is_lod(&d->dd_lu_dev));
	return container_of(d, struct lod_device, lod_dt_dev);
}

static inline struct lod_object *lu2lod_obj(struct lu_object *o)
{
	LASSERT(ergo(o != NULL, lu_device_is_lod(o->lo_dev)));
	return container_of_safe(o, struct lod_object, ldo_obj.do_lu);
}

static inline struct lu_object *lod2lu_obj(struct lod_object *obj)
{
	return &obj->ldo_obj.do_lu;
}

static inline const struct lu_fid *lod_object_fid(struct lod_object *obj)
{
	return lu_object_fid(lod2lu_obj(obj));
}

static inline struct lod_object *lod_obj(const struct lu_object *o)
{
	LASSERT(lu_device_is_lod(o->lo_dev));
	return container_of(o, struct lod_object, ldo_obj.do_lu);
}

static inline struct lod_object *lod_dt_obj(const struct dt_object *d)
{
	return lod_obj(&d->do_lu);
}

static inline struct dt_object* lod_object_child(struct lod_object *o)
{
	return container_of(lu_object_next(lod2lu_obj(o)),
			    struct dt_object, do_lu);
}

static inline bool lod_obj_is_striped(struct dt_object *dt)
{
	struct lod_object *lo = lod_dt_obj(dt);
	int i;

	if (!dt_object_exists(dt_object_child(dt)))
		return false;

	if (S_ISDIR(dt->do_lu.lo_header->loh_attr))
		return lo->ldo_dir_stripe_count != 0;

	if (lo->ldo_is_foreign)
		return false;

	for (i = 0; i < lo->ldo_comp_cnt; i++) {
		if (lo->ldo_comp_entries[i].llc_stripe == NULL)
			continue;
		LASSERT(lo->ldo_comp_entries[i].llc_stripe_count > 0);
		return true;
	}
	return false;
}

extern struct lu_context_key lod_thread_key;

static inline struct lod_thread_info *lod_env_info(const struct lu_env *env)
{
	struct lod_thread_info *info;
	info = lu_context_key_get(&env->le_ctx, &lod_thread_key);
	LASSERT(info);
	return info;
}

static inline struct lu_name *
lod_name_get(const struct lu_env *env, const void *area, int len)
{
	struct lu_name *lname;

	lname = &lod_env_info(env)->lti_name;
	lname->ln_name = area;
	lname->ln_namelen = len;
	return lname;
}

static inline struct lod_default_striping *
lod_lds_buf_get(const struct lu_env *env)
{
	struct lod_thread_info *info = lod_env_info(env);

	info->lti_def_striping.lds_def_striping_set = 0;
	info->lti_def_striping.lds_dir_def_striping_set = 0;
	return &info->lti_def_striping;
}

static inline void lod_layout_get_pool(struct lod_layout_component *entries,
				       int count, char *pool, int len)
{
	int i;

	for (i = 0; i < count; i++) {
		if (entries[i].llc_pool != NULL) {
			strlcpy(pool, entries[i].llc_pool, len);
			break;
		}
	}
}

#define lod_foreach_mdt(lod, mdt) ltd_foreach_tgt(&(lod)->lod_mdt_descs, mdt)
#define lod_foreach_ost(lod, ost) ltd_foreach_tgt(&(lod)->lod_ost_descs, ost)

/* lod_dev.c */
extern struct kmem_cache *lod_object_kmem;
int lod_fld_lookup(const struct lu_env *env, struct lod_device *lod,
		   const struct lu_fid *fid, __u32 *tgt, int *flags);
int lod_sub_init_llog(const struct lu_env *env, struct lod_device *lod,
		      struct dt_device *dt);
void lod_sub_fini_llog(const struct lu_env *env,
		       struct dt_device *dt, struct task_struct **taskp);
int lodname2mdt_index(char *lodname, __u32 *mdt_index);
extern void target_recovery_fini(struct obd_device *obd);

/* lod_lov.c */
void lod_getref(struct lod_tgt_descs *ltd);
void lod_putref(struct lod_device *lod, struct lod_tgt_descs *ltd);
int lod_add_device(const struct lu_env *env, struct lod_device *lod,
		   char *osp, unsigned index, unsigned gen, int mdt_index,
		   char *type, int active);
int lod_del_device(const struct lu_env *env, struct lod_device *lod,
		   struct lod_tgt_descs *ltd, char *osp, unsigned int idx,
		   unsigned int gen);
int validate_lod_and_idx(struct lod_device *lod, __u32 idx);
int lod_fini_tgt(const struct lu_env *env, struct lod_device *lod,
		 struct lod_tgt_descs *ltd);
int lod_striping_load(const struct lu_env *env, struct lod_object *lo);
int lod_striping_reload(const struct lu_env *env, struct lod_object *lo,
			const struct lu_buf *buf);
void lod_dom_stripesize_recalc(struct lod_device *d);

int lod_get_ea(const struct lu_env *env, struct lod_object *lo,
	       const char *name);
static inline int
lod_get_lov_ea(const struct lu_env *env, struct lod_object *lo)
{
	return lod_get_ea(env, lo, XATTR_NAME_LOV);
}

static inline int
lod_get_lmv_ea(const struct lu_env *env, struct lod_object *lo)
{
	return lod_get_ea(env, lo, XATTR_NAME_LMV);
}

static inline int
lod_get_default_lmv_ea(const struct lu_env *env, struct lod_object *lo)
{
	return lod_get_ea(env, lo, XATTR_NAME_DEFAULT_LMV);
}

static inline void
lod_comp_set_init(struct lod_layout_component *entry)
{
	entry->llc_flags |= LCME_FL_INIT;
}

static inline void
lod_comp_unset_init(struct lod_layout_component *entry)
{
	entry->llc_flags &= ~LCME_FL_INIT;
}

static inline bool
lod_comp_inited(const struct lod_layout_component *entry)
{
	return entry->llc_flags & LCME_FL_INIT;
}

/**
 * For a PFL file, some of its component could be un-instantiated, so
 * that their lov_ost_data_v1 array is not needed, we'd use this function
 * to reduce the LOVEA buffer size.
 *
 * Note: if llc_ostlist contains value, we'd need lov_ost_data_v1 array to
 * save the specified OST index list.
 */
static inline void
lod_comp_shrink_stripe_count(struct lod_layout_component *lod_comp,
			     __u16 *stripe_count)
{
	/**
	 * Need one lov_ost_data_v1 to store invalid ost_idx, please refer to
	 * lod_parse_striping()
	 */
	if (!lod_comp_inited(lod_comp) && lod_comp->llc_ostlist.op_count == 0)
		*stripe_count = 1;
}

void lod_fix_desc(struct lov_desc *desc);
void lod_fix_desc_qos_maxage(__u32 *val);
void lod_fix_desc_pattern(__u32 *val);
void lod_fix_desc_stripe_count(__u32 *val);
void lod_fix_desc_stripe_size(__u64 *val);
void lod_fix_lmv_desc_pattern(__u32 *val);
int lod_pools_init(struct lod_device *m, struct lustre_cfg *cfg);
int lod_pools_fini(struct lod_device *m);
int lod_parse_striping(const struct lu_env *env, struct lod_object *mo,
		       const struct lu_buf *buf);
int lod_parse_dir_striping(const struct lu_env *env, struct lod_object *lo,
			   const struct lu_buf *buf);
int lod_initialize_objects(const struct lu_env *env, struct lod_object *mo,
			   struct lov_ost_data_v1 *objs, int index);
int lod_verify_striping(const struct lu_env *env, struct lod_device *d,
			struct lod_object *lo, const struct lu_buf *buf,
			bool is_from_disk);
int lod_generate_lovea(const struct lu_env *env, struct lod_object *lo,
		       struct lov_mds_md *lmm, int *lmm_size, bool is_dir);
int lod_ea_store_resize(struct lod_thread_info *info, size_t size);
int lod_def_striping_comp_resize(struct lod_default_striping *lds, __u16 count);
void lod_free_def_comp_entries(struct lod_default_striping *lds);
void lod_free_comp_entries(struct lod_object *lo);
int lod_alloc_comp_entries(struct lod_object *lo, int mirror_cnt, int comp_cnt);
int lod_fill_mirrors(struct lod_object *lo);

/* lod_pool.c */
struct pool_desc *lod_find_pool(struct lod_device *lod, char *poolname);
void lod_pool_putref(struct pool_desc *pool);
int lod_pool_del(struct obd_device *obd, char *poolname);
int lod_check_index_in_pool(__u32 idx, struct pool_desc *pool);
int lod_pool_new(struct obd_device *obd, char *poolname);
int lod_pool_add(struct obd_device *obd, char *poolname, char *ostname);
int lod_pool_remove(struct obd_device *obd, char *poolname, char *ostname);

struct lod_obj_stripe_cb_data;
typedef int (*lod_obj_stripe_cb_t)(const struct lu_env *env,
				   struct lod_object *lo, struct dt_object *dt,
				   struct thandle *th,
				   int comp_idx, int stripe_idx,
				   struct lod_obj_stripe_cb_data *data);
typedef bool (*lod_obj_comp_skip_cb_t)(const struct lu_env *env,
					struct lod_object *lo, int comp_idx,
					struct lod_obj_stripe_cb_data *data);
typedef int (*lod_obj_comp_cb_t)(const struct lu_env *env,
				struct lod_object *lo, int comp_idx,
				struct lod_obj_stripe_cb_data *data);
struct lod_obj_stripe_cb_data {
	union {
		const struct lu_attr	*locd_attr;
		int			locd_ost_index;
		const struct lu_buf	*locd_buf;
	};
	lod_obj_stripe_cb_t		locd_stripe_cb;
	lod_obj_comp_skip_cb_t		locd_comp_skip_cb;
	lod_obj_comp_cb_t		locd_comp_cb;
	bool				locd_declare;
};

/* lod_qos.c */
int lod_mdt_alloc_qos(const struct lu_env *env, struct lod_object *lo,
		      struct dt_object **stripes, u32 stripe_idx,
		      u32 stripe_count);
int lod_mdt_alloc_rr(const struct lu_env *env, struct lod_object *lo,
		     struct dt_object **stripes, u32 stripe_idx,
		     u32 stripe_count);
int lod_prepare_create(const struct lu_env *env, struct lod_object *lo,
		       struct lu_attr *attr, const struct lu_buf *buf,
		       struct thandle *th);
int lod_use_defined_striping(const struct lu_env *, struct lod_object *,
			     const struct lu_buf *);
int lod_qos_parse_config(const struct lu_env *env, struct lod_object *lo,
			 const struct lu_buf *buf);
int lod_qos_prep_create(const struct lu_env *env, struct lod_object *lo,
			struct lu_attr *attr, struct thandle *th,
			int comp_idx, __u64 reserve);
__u16 lod_comp_entry_stripe_count(struct lod_object *lo,
				  int comp_idx, bool is_dir);
__u16 lod_get_stripe_count(struct lod_device *lod, struct lod_object *lo,
			   int comp_idx, __u16 stripe_count, bool overstriping);
void lod_qos_statfs_update(const struct lu_env *env, struct lod_device *lod,
			   struct lu_tgt_descs *ltd);

/* lproc_lod.c */
int lod_procfs_init(struct lod_device *lod);
void lod_procfs_fini(struct lod_device *lod);

/* lod_object.c */
extern const struct dt_object_operations lod_obj_ops;
extern const struct lu_object_operations lod_lu_obj_ops;

int lod_load_lmv_shards(const struct lu_env *env, struct lod_object *lo,
			struct lu_buf *buf, bool resize);
int lod_declare_striped_create(const struct lu_env *env, struct dt_object *dt,
			       struct lu_attr *attr,
			       const struct lu_buf *lovea, struct thandle *th);
int lod_striped_create(const struct lu_env *env, struct dt_object *dt,
			struct lu_attr *attr, struct dt_object_format *dof,
			struct thandle *th);
int lod_alloc_foreign_lov(struct lod_object *lo, size_t size);
void lod_free_foreign_lov(struct lod_object *lo);
void lod_striping_free_nolock(const struct lu_env *env, struct lod_object *lo);
void lod_striping_free(const struct lu_env *env, struct lod_object *lo);

int lod_obj_for_each_stripe(const struct lu_env *env, struct lod_object *lo,
			    struct thandle *th,
			    struct lod_obj_stripe_cb_data *data);
int lod_comp_copy_ost_lists(struct lod_layout_component *lod_comp,
			    struct lov_user_md_v3 *v3);
void lod_adjust_stripe_size(struct lod_layout_component *comp,
			    __u32 def_stripe_size);

/* lod_sub_object.c */
struct thandle *lod_sub_get_thandle(const struct lu_env *env,
				    struct thandle *th,
				    const struct dt_object *sub_obj,
				    bool *record_update);
int lod_sub_declare_create(const struct lu_env *env, struct dt_object *dt,
			   struct lu_attr *attr,
			   struct dt_allocation_hint *hint,
			   struct dt_object_format *dof, struct thandle *th);
int lod_sub_create(const struct lu_env *env, struct dt_object *dt,
		   struct lu_attr *attr, struct dt_allocation_hint *hint,
		   struct dt_object_format *dof, struct thandle *th);
int lod_sub_declare_ref_add(const struct lu_env *env, struct dt_object *dt,
			    struct thandle *th);
int lod_sub_ref_add(const struct lu_env *env, struct dt_object *dt,
		    struct thandle *th);
int lod_sub_declare_ref_del(const struct lu_env *env, struct dt_object *dt,
			    struct thandle *th);
int lod_sub_ref_del(const struct lu_env *env, struct dt_object *dt,
		    struct thandle *th);
int lod_sub_declare_destroy(const struct lu_env *env, struct dt_object *dt,
			    struct thandle *th);
int lod_sub_destroy(const struct lu_env *env, struct dt_object *dt,
		    struct thandle *th);
int lod_sub_declare_insert(const struct lu_env *env, struct dt_object *dt,
			   const struct dt_rec *rec, const struct dt_key *key,
			   struct thandle *th);
int lod_sub_insert(const struct lu_env *env, struct dt_object *dt,
		   const struct dt_rec *rec, const struct dt_key *key,
		   struct thandle *th);
int lod_sub_declare_delete(const struct lu_env *env, struct dt_object *dt,
			   const struct dt_key *key, struct thandle *th);
int lod_sub_delete(const struct lu_env *env, struct dt_object *dt,
		   const struct dt_key *name, struct thandle *th);
int lod_sub_declare_xattr_set(const struct lu_env *env, struct dt_object *dt,
			      const struct lu_buf *buf, const char *name,
			      int fl, struct thandle *th);
int lod_sub_xattr_set(const struct lu_env *env, struct dt_object *dt,
		      const struct lu_buf *buf, const char *name, int fl,
		      struct thandle *th);
int lod_sub_declare_attr_set(const struct lu_env *env, struct dt_object *dt,
			     const struct lu_attr *attr, struct thandle *th);
int lod_sub_attr_set(const struct lu_env *env, struct dt_object *dt,
		     const struct lu_attr *attr, struct thandle *th);
int lod_sub_declare_xattr_del(const struct lu_env *env, struct dt_object *dt,
			      const char *name, struct thandle *th);
int lod_sub_xattr_del(const struct lu_env *env, struct dt_object *dt,
		      const char *name, struct thandle *th);
int lod_sub_declare_write(const struct lu_env *env, struct dt_object *dt,
			  const struct lu_buf *buf, loff_t pos,
			  struct thandle *th);
ssize_t lod_sub_write(const struct lu_env *env, struct dt_object *dt,
		      const struct lu_buf *buf, loff_t *pos,
		      struct thandle *th);
int lod_sub_declare_punch(const struct lu_env *env, struct dt_object *dt,
			  __u64 start, __u64 end, struct thandle *th);
int lod_sub_punch(const struct lu_env *env, struct dt_object *dt,
		  __u64 start, __u64 end, struct thandle *th);

int lod_sub_prep_llog(const struct lu_env *env, struct lod_device *lod,
		      struct dt_device *dt, int index);
#endif
