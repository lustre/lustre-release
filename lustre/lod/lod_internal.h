/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

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
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lod/lod_internal.h
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#ifndef _LOD_INTERNAL_H
#define _LOD_INTERNAL_H

#include <libcfs/libcfs.h>
#include <obd.h>
#include <dt_object.h>

#define LOV_USES_ASSIGNED_STRIPE        0
#define LOV_USES_DEFAULT_STRIPE         1

struct lod_tgt_desc {
	struct dt_device  *ltd_tgt;
	struct list_head   ltd_kill;
	struct obd_export *ltd_exp;
	struct obd_uuid    ltd_uuid;
	__u32              ltd_gen;
	__u32              ltd_index;
	struct ltd_qos     ltd_qos; /* qos info per target */
	struct obd_statfs  ltd_statfs;
	unsigned long      ltd_active:1,/* is this target up for requests */
			   ltd_activate:1,/* should  target be activated */
			   ltd_reap:1;  /* should this target be deleted */
};

#define TGT_PTRS		256     /* number of pointers at 1st level */
#define TGT_PTRS_PER_BLOCK      256     /* number of pointers at 2nd level */

struct lod_tgt_desc_idx {
	struct lod_tgt_desc *ldi_tgt[TGT_PTRS_PER_BLOCK];
};

#define LTD_TGT(ltd, index)      \
	 ((ltd)->ltd_tgt_idx[(index) / \
	 TGT_PTRS_PER_BLOCK]->ldi_tgt[(index) % TGT_PTRS_PER_BLOCK])

#define OST_TGT(lod, index)   LTD_TGT(&lod->lod_ost_descs, index)
struct lod_tgt_descs {
	/* list of known TGTs */
	struct lod_tgt_desc_idx	*ltd_tgt_idx[TGT_PTRS];
	/* Size of the lod_tgts array, granted to be a power of 2 */
	__u32			ltd_tgts_size;
	/* number of registered TGTs */
	int			ltd_tgtnr;
	/* bitmap of TGTs available */
	cfs_bitmap_t		*ltd_tgt_bitmap;
	/* TGTs scheduled to be deleted */
	__u32			ltd_death_row;
	/* Table refcount used for delayed deletion */
	int			ltd_refcount;
	/* mutex to serialize concurrent updates to the tgt table */
	struct mutex		ltd_mutex;
	/* read/write semaphore used for array relocation */
	struct rw_semaphore	ltd_rw_sem;
};

struct lod_device {
	struct dt_device      lod_dt_dev;
	struct obd_export    *lod_child_exp;
	struct dt_device     *lod_child;
	cfs_proc_dir_entry_t *lod_proc_entry;
	struct lprocfs_stats *lod_stats;
	spinlock_t	      lod_connects_lock;
	int		      lod_connects;
	unsigned int	      lod_recovery_completed:1,
			      lod_initialized:1;

	/* lov settings descriptor storing static information */
	struct lov_desc	      lod_desc;

	/* use to protect ld_active_tgt_count and all ltd_active */
	spinlock_t	     lod_desc_lock;

	/* Description of OST */
	struct lod_tgt_descs  lod_ost_descs;
	/* Description of MDT */
	struct lod_tgt_descs  lod_mdt_descs;

	/* maximum EA size underlied OSD may have */
	unsigned int	      lod_osd_max_easize;

	/*FIXME: When QOS and pool is implemented for MDT, probably these
	 * structure should be moved to lod_tgt_descs as well.
	 */
	/* QoS info per LOD */
	struct lov_qos	      lod_qos; /* qos info per lod */

	/* OST pool data */
	struct ost_pool	      lod_pool_info; /* all OSTs in a packed array */
	int		      lod_pool_count;
	cfs_hash_t	     *lod_pools_hash_body; /* used for key access */
	cfs_list_t	      lod_pool_list; /* used for sequential access */
	cfs_proc_dir_entry_t *lod_pool_proc_entry;

	enum lustre_sec_part   lod_sp_me;

	cfs_proc_dir_entry_t *lod_symlink;
};

#define lod_osts	lod_ost_descs.ltd_tgts
#define lod_ost_bitmap	lod_ost_descs.ltd_tgt_bitmap
#define lod_ostnr	lod_ost_descs.ltd_tgtnr
#define lod_osts_size	lod_ost_descs.ltd_tgts_size
#define ltd_ost		ltd_tgt
#define lod_ost_desc	lod_tgt_desc

/*
 * XXX: shrink this structure, currently it's 72bytes on 32bit arch,
 *      so, slab will be allocating 128bytes
 */
struct lod_object {
	struct dt_object   ldo_obj;

	/* if object is striped, then the next fields describe stripes */
	__u16		   ldo_stripenr;
	__u16		   ldo_layout_gen;
	__u32		   ldo_stripe_size;
	__u32		   ldo_pattern;
	__u16		   ldo_released_stripenr;
	char		  *ldo_pool;
	struct dt_object **ldo_stripe;
	/* to know how much memory to free, ldo_stripenr can be less */
	/* default striping for directory represented by this object
	 * is cached in stripenr/stripe_size */
	unsigned int	   ldo_stripes_allocated:16,
			   ldo_striping_cached:1,
			   ldo_def_striping_set:1;
	__u32		   ldo_def_stripe_size;
	__u16		   ldo_def_stripenr;
	__u16		   ldo_def_stripe_offset;
	mdsno_t		   ldo_mds_num;
};


struct lod_it {
	struct dt_object	*lit_obj; /* object from the layer below */
	struct dt_it		*lit_it;  /* iterator from the layer below */
};

struct lod_thread_info {
	/* per-thread buffer for LOV EA */
	void             *lti_ea_store;
	int               lti_ea_store_size;
	struct lu_buf     lti_buf;
	struct ost_id     lti_ostid;
	struct lu_fid     lti_fid;
	struct obd_statfs lti_osfs;
	struct lu_attr    lti_attr;
	struct lod_it	  lti_it;
};

extern const struct lu_device_operations lod_lu_ops;

static inline int lu_device_is_lod(struct lu_device *d)
{
	return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &lod_lu_ops);
}

static inline struct lod_device* lu2lod_dev(struct lu_device *d)
{
	LASSERT(lu_device_is_lod(d));
	return container_of0(d, struct lod_device, lod_dt_dev.dd_lu_dev);
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
	return container_of0(d, struct lod_device, lod_dt_dev);
}

static inline struct lod_object *lu2lod_obj(struct lu_object *o)
{
	LASSERT(ergo(o != NULL, lu_device_is_lod(o->lo_dev)));
	return container_of0(o, struct lod_object, ldo_obj.do_lu);
}

static inline struct lu_object *lod2lu_obj(struct lod_object *obj)
{
	return &obj->ldo_obj.do_lu;
}

static inline struct lod_object *lod_obj(const struct lu_object *o)
{
	LASSERT(lu_device_is_lod(o->lo_dev));
	return container_of0(o, struct lod_object, ldo_obj.do_lu);
}

static inline struct lod_object *lod_dt_obj(const struct dt_object *d)
{
	return lod_obj(&d->do_lu);
}

static inline struct dt_object* lod_object_child(struct lod_object *o)
{
	return container_of0(lu_object_next(lod2lu_obj(o)),
			struct dt_object, do_lu);
}

static inline struct dt_object *dt_object_child(struct dt_object *o)
{
	return container_of0(lu_object_next(&(o)->do_lu),
			struct dt_object, do_lu);
}

extern struct lu_context_key lod_thread_key;

static inline struct lod_thread_info *lod_env_info(const struct lu_env *env)
{
	struct lod_thread_info *info;
	info = lu_context_key_get(&env->le_ctx, &lod_thread_key);
	LASSERT(info);
	return info;
}

#define lod_foreach_ost(__dev, index)	\
	if ((__dev)->lod_osts_size > 0)	\
		cfs_foreach_bit((__dev)->lod_ost_bitmap, (index))

/* lod_dev.c */
int lod_fld_lookup(const struct lu_env *env, struct lod_device *lod,
		   const struct lu_fid *fid, mdsno_t *tgt, int flags);
/* lod_lov.c */
void lod_getref(struct lod_tgt_descs *ltd);
void lod_putref(struct lod_device *lod, struct lod_tgt_descs *ltd);
int lod_add_device(const struct lu_env *env, struct lod_device *lod,
		   char *osp, unsigned index, unsigned gen, int mdt_index,
		   char *type, int active);
int lod_del_device(const struct lu_env *env, struct lod_device *lod,
		   struct lod_tgt_descs *ltd, char *osp, unsigned idx,
		   unsigned gen);
int lod_fini_tgt(struct lod_device *lod, struct lod_tgt_descs *ltd);
int lod_load_striping(const struct lu_env *env, struct lod_object *mo);
int lod_get_lov_ea(const struct lu_env *env, struct lod_object *mo);
void lod_fix_desc(struct lov_desc *desc);
void lod_fix_desc_qos_maxage(__u32 *val);
void lod_fix_desc_pattern(__u32 *val);
void lod_fix_desc_stripe_count(__u32 *val);
void lod_fix_desc_stripe_size(__u64 *val);
int lod_pools_init(struct lod_device *m, struct lustre_cfg *cfg);
int lod_pools_fini(struct lod_device *m);
int lod_parse_striping(const struct lu_env *env, struct lod_object *mo,
		       const struct lu_buf *buf);
int lod_initialize_objects(const struct lu_env *env, struct lod_object *mo,
			   struct lov_ost_data_v1 *objs);
int lod_store_def_striping(const struct lu_env *env, struct dt_object *dt,
			   struct thandle *th);
int lod_verify_striping(struct lod_device *d, const struct lu_buf *buf,
			bool is_from_disk);
int lod_generate_and_set_lovea(const struct lu_env *env,
			       struct lod_object *mo, struct thandle *th);

/* lod_pool.c */
int lod_ost_pool_add(struct ost_pool *op, __u32 idx, unsigned int min_count);
int lod_ost_pool_remove(struct ost_pool *op, __u32 idx);
int lod_ost_pool_extend(struct ost_pool *op, unsigned int min_count);
struct pool_desc *lod_find_pool(struct lod_device *lod, char *poolname);
void lod_pool_putref(struct pool_desc *pool);
int lod_ost_pool_free(struct ost_pool *op);
int lod_pool_del(struct obd_device *obd, char *poolname);
int lod_ost_pool_init(struct ost_pool *op, unsigned int count);
extern cfs_hash_ops_t pool_hash_operations;
int lod_check_index_in_pool(__u32 idx, struct pool_desc *pool);
int lod_pool_new(struct obd_device *obd, char *poolname);
int lod_pool_add(struct obd_device *obd, char *poolname, char *ostname);
int lod_pool_remove(struct obd_device *obd, char *poolname, char *ostname);

/* lod_qos.c */
int lod_qos_prep_create(const struct lu_env *env, struct lod_object *lo,
			struct lu_attr *attr, const struct lu_buf *buf,
			struct thandle *th);
int qos_add_tgt(struct lod_device*, struct lod_tgt_desc *);
int qos_del_tgt(struct lod_device *, struct lod_tgt_desc *);

/* lproc_lod.c */
void lprocfs_lod_init_vars(struct lprocfs_static_vars *lvars);
int lod_procfs_init(struct lod_device *lod);
void lod_procfs_fini(struct lod_device *lod);

/* lod_object.c */
int lod_object_set_pool(struct lod_object *o, char *pool);
int lod_declare_striped_object(const struct lu_env *env, struct dt_object *dt,
			       struct lu_attr *attr,
			       const struct lu_buf *lovea, struct thandle *th);
int lod_striping_create(const struct lu_env *env, struct dt_object *dt,
			struct lu_attr *attr, struct dt_object_format *dof,
			struct thandle *th);
void lod_object_free_striping(const struct lu_env *env, struct lod_object *lo);

#endif

