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

struct lod_ost_desc {
	struct dt_device  *ltd_ost;
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

#define OST_PTRS                256     /* number of pointers at 1st level */
#define OST_PTRS_PER_BLOCK      256     /* number of pointers at 2nd level */

struct lod_ost_desc_idx {
	struct lod_ost_desc *ldi_ost[OST_PTRS_PER_BLOCK];
};

#define OST_TGT(dev,index)      \
	((dev)->lod_ost_idx[(index) / \
	OST_PTRS_PER_BLOCK]->ldi_ost[(index)%OST_PTRS_PER_BLOCK])

struct lod_device {
	struct dt_device      lod_dt_dev;
	struct obd_export    *lod_child_exp;
	struct dt_device     *lod_child;
	cfs_proc_dir_entry_t *lod_proc_entry;
	struct lprocfs_stats *lod_stats;
	int		      lod_connects;
	int		      lod_recovery_completed;

	/* lov settings descriptor storing static information */
	struct lov_desc	      lod_desc;

	/* use to protect ld_active_tgt_count and all ltd_active */
	cfs_spinlock_t        lod_desc_lock;

	/* list of known OSTs */
	struct lod_ost_desc_idx *lod_ost_idx[OST_PTRS];

	/* Size of the lod_osts array, granted to be a power of 2 */
	__u32		      lod_osts_size;
	/* number of registered OSTs */
	int		      lod_ostnr;
	/* OSTs scheduled to be deleted */
	__u32		      lod_death_row;
	/* bitmap of OSTs available */
	cfs_bitmap_t	     *lod_ost_bitmap;

	/* maximum EA size underlied OSD may have */
	unsigned int	      lod_osd_max_easize;

	/* Table refcount used for delayed deletion */
	int		      lod_refcount;
	/* mutex to serialize concurrent updates to the ost table */
	cfs_mutex_t	      lod_mutex;
	/* read/write semaphore used for array relocation */
	cfs_rw_semaphore_t    lod_rw_sem;

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
	char		  *ldo_pool;
	struct dt_object **ldo_stripe;
	/* to know how much memory to free, ldo_stripenr can be less */
	int		   ldo_stripes_allocated;
	/* default striping for directory represented by this object
	 * is cached in stripenr/stripe_size */
	int		   ldo_striping_cached:1;
	int		   ldo_def_striping_set:1;
	__u32		   ldo_def_stripe_size;
	__u16		   ldo_def_stripenr;
	__u16		   ldo_def_stripe_offset;
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

static inline struct dt_object *lu2dt_obj(struct lu_object *o)
{
	LASSERT(ergo(o != NULL, lu_device_is_dt(o->lo_dev)));
	return container_of0(o, struct dt_object, do_lu);
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

/* lod_lov.c */
void lod_getref(struct lod_device *lod);
void lod_putref(struct lod_device *lod);
int lod_add_device(const struct lu_env *env, struct lod_device *m,
		   char *osp, unsigned index, unsigned gen, int active);
int lod_del_device(const struct lu_env *env, struct lod_device *m,
		   char *osp, unsigned index, unsigned gen);
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
int lod_verify_striping(struct lod_device *d, const struct lu_buf *buf, int specific);

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
int qos_add_tgt(struct lod_device*, struct lod_ost_desc *);
int qos_del_tgt(struct lod_device *, struct lod_ost_desc *);

/* lproc_lod.c */
extern struct file_operations lod_proc_target_fops;
void lprocfs_lod_init_vars(struct lprocfs_static_vars *lvars);

/* lod_object.c */
int lod_object_set_pool(struct lod_object *o, char *pool);

#endif

