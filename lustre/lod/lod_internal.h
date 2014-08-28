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
 * Copyright (c) 2012, 2014, Intel Corporation.
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

/* Special values to remove LOV EA from disk */
#define LOVEA_DELETE_VALUES(size, count, offset, pool)			\
	((size) == 0 && (count) == 0 &&					\
	 (offset) == (typeof(offset))(-1) && (pool) == NULL)

#define LMVEA_DELETE_VALUES(count, offset)				\
	((count) == 0 && (offset) == (typeof(offset))(-1))

#define LOV_OFFSET_DEFAULT		((__u16)-1)

struct lod_qos_rr {
	__u32			 lqr_start_idx;	/* start index of new inode */
	__u32			 lqr_offset_idx; /* aliasing for start_idx */
	int			 lqr_start_count; /* reseed counter */
	struct ost_pool		 lqr_pool;	/* round-robin optimized list */
	unsigned long		 lqr_dirty:1;	/* recalc round-robin list */
};

struct pool_desc {
	char			 pool_name[LOV_MAXPOOLNAME + 1];
	struct ost_pool		 pool_obds;	/* pool members */
	atomic_t		 pool_refcount;
	struct lod_qos_rr	 pool_rr;
	struct hlist_node	 pool_hash;	/* access by poolname */
	struct list_head	 pool_list;
	struct proc_dir_entry	*pool_proc_entry;
	struct obd_device	*pool_lobd;	/* owner */
};

#define pool_tgt_size(p) ((p)->pool_obds.op_size)
#define pool_tgt_count(p) ((p)->pool_obds.op_count)
#define pool_tgt_array(p)  ((p)->pool_obds.op_array)
#define pool_tgt_rw_sem(p) ((p)->pool_obds.op_rw_sem)

struct lod_qos {
	struct list_head	 lq_oss_list;
	struct rw_semaphore	 lq_rw_sem;
	__u32			 lq_active_oss_count;
	unsigned int		 lq_prio_free;   /* priority for free space */
	unsigned int		 lq_threshold_rr;/* priority for rr */
	struct lod_qos_rr	 lq_rr;          /* round robin qos data */
	bool			 lq_dirty:1,     /* recalc qos data */
				 lq_same_space:1,/* the ost's all have approx.
						    the same space avail */
				 lq_reset:1;     /* zero current penalties */
};

struct lod_qos_oss {
	struct obd_uuid		 lqo_uuid;	/* ptlrpc's c_remote_uuid */
	struct list_head	 lqo_oss_list;	/* link to lov_qos */
	__u64			 lqo_bavail;	/* total bytes avail on OSS */
	__u64			 lqo_penalty;	/* current penalty */
	__u64			 lqo_penalty_per_obj; /* penalty decrease
							 every obj*/
	time_t			 lqo_used;	/* last used time, seconds */
	__u32			 lqo_ost_count;	/* number of osts on this oss */
};

struct ltd_qos {
	struct lod_qos_oss	*ltq_oss;	/* oss info */
	__u64			 ltq_penalty;	/* current penalty */
	__u64			 ltq_penalty_per_obj; /* penalty decrease
							 every obj*/
	__u64			 ltq_weight;	/* net weighting */
	time_t			 ltq_used;	/* last used time, seconds */
	bool			 ltq_usable:1;	/* usable for striping */
};

struct lod_tgt_desc {
	struct dt_device  *ltd_tgt;
	struct list_head   ltd_kill;
	struct obd_export *ltd_exp;
	struct obd_uuid    ltd_uuid;
	__u32              ltd_gen;
	__u32              ltd_index;
	struct ltd_qos     ltd_qos; /* qos info per target */
	struct obd_statfs  ltd_statfs;
	struct ptlrpc_thread	*ltd_recovery_thread;
	unsigned long      ltd_active:1,/* is this target up for requests */
			   ltd_activate:1,/* should  target be activated */
			   ltd_reap:1,  /* should this target be deleted */
			   ltd_got_update_log:1; /* Already got update log */
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
#define MDT_TGT(lod, index)   LTD_TGT(&lod->lod_mdt_descs, index)
struct lod_tgt_descs {
	/* list of known TGTs */
	struct lod_tgt_desc_idx	*ltd_tgt_idx[TGT_PTRS];
	/* Size of the lod_tgts array, granted to be a power of 2 */
	__u32			ltd_tgts_size;
	/* number of registered TGTs */
	__u32			ltd_tgtnr;
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
	struct proc_dir_entry *lod_proc_entry;
	struct lprocfs_stats *lod_stats;
	spinlock_t	      lod_connects_lock;
	int		      lod_connects;
	unsigned int	      lod_recovery_completed:1,
			      lod_initialized:1,
			      lod_lmv_failout:1,
			      lod_child_got_update_log:1;

	/* lov settings descriptor storing static information */
	struct lov_desc	      lod_desc;

	/* use to protect ld_active_tgt_count and all ltd_active */
	spinlock_t	     lod_desc_lock;

	/* Description of OST */
	struct lod_tgt_descs  lod_ost_descs;
	/* Description of MDT */
	struct lod_tgt_descs  lod_mdt_descs;

	/* Recovery thread for lod_child */
	struct ptlrpc_thread	lod_child_recovery_thread;

	/* maximum EA size underlied OSD may have */
	unsigned int	      lod_osd_max_easize;

	/*FIXME: When QOS and pool is implemented for MDT, probably these
	 * structure should be moved to lod_tgt_descs as well.
	 */
	/* QoS info per LOD */
	struct lod_qos	      lod_qos; /* qos info per lod */

	/* OST pool data */
	struct ost_pool		lod_pool_info; /* all OSTs in a packed array */
	int			lod_pool_count;
	cfs_hash_t	       *lod_pools_hash_body; /* used for key access */
	struct list_head	lod_pool_list; /* used for sequential access */
	struct proc_dir_entry  *lod_pool_proc_entry;

	enum lustre_sec_part   lod_sp_me;

	struct proc_dir_entry *lod_symlink;
};

#define lod_osts	lod_ost_descs.ltd_tgts
#define lod_ost_bitmap	lod_ost_descs.ltd_tgt_bitmap
#define lod_ostnr	lod_ost_descs.ltd_tgtnr
#define lod_osts_size	lod_ost_descs.ltd_tgts_size
#define ltd_ost		ltd_tgt
#define lod_ost_desc	lod_tgt_desc

#define lod_mdts		lod_mdt_descs.ltd_tgts
#define lod_mdt_bitmap		lod_mdt_descs.ltd_tgt_bitmap
#define lod_remote_mdt_count	lod_mdt_descs.ltd_tgtnr
#define lod_mdts_size		lod_mdt_descs.ltd_tgts_size
#define ltd_mdt			ltd_tgt
#define lod_mdt_desc		lod_tgt_desc

struct lod_dir_stripe_info {
	__u32	ldsi_stripe_offset;
	__u32	ldsi_def_stripenr;
	__u32	ldsi_def_stripe_offset;
	__u32	ldsi_def_hash_type;
	__u32	ldsi_hash_type;

	unsigned int ldsi_def_striping_set:1,
		     ldsi_def_striping_cached:1,
		     ldsi_striped:1;
};

/*
 * XXX: shrink this structure, currently it's 72bytes on 32bit arch,
 *      so, slab will be allocating 128bytes
 */
struct lod_object {
	struct dt_object   ldo_obj;

	/* if object is striped, then the next fields describe stripes */
	/* For striped directory, ldo_stripenr == slave stripe count */
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
			   ldo_def_striping_set:1,
			   ldo_def_striping_cached:1,
	/* ldo_dir_slave_stripe indicate this is a slave stripe of
	 * a striped dir */
			   ldo_dir_slave_stripe:1;
	__u32		   ldo_def_stripe_size;
	__u16		   ldo_def_stripenr;
	__u16		   ldo_def_stripe_offset;
	struct lod_dir_stripe_info	*ldo_dir_stripe;
};

#define ldo_dir_stripe_offset	ldo_dir_stripe->ldsi_stripe_offset
#define ldo_dir_def_stripenr	ldo_dir_stripe->ldsi_def_stripenr
#define ldo_dir_hash_type	ldo_dir_stripe->ldsi_hash_type
#define ldo_dir_def_hash_type	ldo_dir_stripe->ldsi_def_hash_type
#define ldo_dir_striped		ldo_dir_stripe->ldsi_striped
#define ldo_dir_def_striping_set	ldo_dir_stripe->ldsi_def_striping_set
#define ldo_dir_def_striping_cached	ldo_dir_stripe->ldsi_def_striping_cached
#define ldo_dir_def_stripe_offset	ldo_dir_stripe->ldsi_def_stripe_offset

struct lod_it {
	struct dt_object	*lit_obj; /* object from the layer below */
	/* stripe offset of iteration */
	__u32			lit_stripe_index;
	__u32			lit_attr;
	struct dt_it		*lit_it;  /* iterator from the layer below */
};

struct lod_thread_info {
	/* per-thread buffer for LOV EA */
	void             *lti_ea_store;
	__u32             lti_ea_store_size;
	/* per-thread buffer for LMV EA */
	struct lu_buf     lti_buf;
	struct ost_id     lti_ostid;
	struct lu_fid     lti_fid;
	struct obd_statfs lti_osfs;
	struct lu_attr    lti_attr;
	struct lod_it	  lti_it;
	struct ldlm_res_id lti_res_id;
	/* used to hold lu_dirent, sizeof(struct lu_dirent) + NAME_MAX */
	char		  lti_key[sizeof(struct lu_dirent) + NAME_MAX];
	struct dt_object_format lti_format;
	struct lu_name	  lti_name;
	struct lu_buf	  lti_linkea_buf;
	struct dt_insert_rec lti_dt_rec;
	struct llog_catid lti_cid;
	struct llog_cookie lti_cookie;
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

#define lod_foreach_ost(__dev, index)	\
	if ((__dev)->lod_osts_size > 0)	\
		cfs_foreach_bit((__dev)->lod_ost_bitmap, (index))

#define lod_foreach_mdt(mdt_dev, index)	\
	cfs_foreach_bit((mdt_dev)->lod_mdt_bitmap, (index))

/* lod_dev.c */
extern struct kmem_cache *lod_object_kmem;
int lod_fld_lookup(const struct lu_env *env, struct lod_device *lod,
		   const struct lu_fid *fid, __u32 *tgt, int *flags);
int lod_sub_init_llog(const struct lu_env *env, struct lod_device *lod,
		      struct dt_device *dt);
void lod_sub_fini_llog(const struct lu_env *env,
		       struct dt_device *dt, struct ptlrpc_thread *thread);
int lodname2mdt_index(char *lodname, __u32 *mdt_index);

/* lod_lov.c */
void lod_getref(struct lod_tgt_descs *ltd);
void lod_putref(struct lod_device *lod, struct lod_tgt_descs *ltd);
int lod_add_device(const struct lu_env *env, struct lod_device *lod,
		   char *osp, unsigned index, unsigned gen, int mdt_index,
		   char *type, int active);
int lod_del_device(const struct lu_env *env, struct lod_device *lod,
		   struct lod_tgt_descs *ltd, char *osp, unsigned idx,
		   unsigned gen, bool for_ost);
int lod_fini_tgt(const struct lu_env *env, struct lod_device *lod,
		 struct lod_tgt_descs *ltd, bool for_ost);
int lod_load_striping_locked(const struct lu_env *env, struct lod_object *lo);
int lod_load_striping(const struct lu_env *env, struct lod_object *lo);

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

void lod_fix_desc(struct lov_desc *desc);
void lod_fix_desc_qos_maxage(__u32 *val);
void lod_fix_desc_pattern(__u32 *val);
void lod_fix_desc_stripe_count(__u32 *val);
void lod_fix_desc_stripe_size(__u64 *val);
int lod_pools_init(struct lod_device *m, struct lustre_cfg *cfg);
int lod_pools_fini(struct lod_device *m);
int lod_parse_striping(const struct lu_env *env, struct lod_object *mo,
		       const struct lu_buf *buf);
int lod_parse_dir_striping(const struct lu_env *env, struct lod_object *lo,
			   const struct lu_buf *buf);
int lod_initialize_objects(const struct lu_env *env, struct lod_object *mo,
			   struct lov_ost_data_v1 *objs);
int lod_verify_striping(struct lod_device *d, const struct lu_buf *buf,
			bool is_from_disk);
int lod_generate_and_set_lovea(const struct lu_env *env,
			       struct lod_object *mo, struct thandle *th);
int lod_ea_store_resize(struct lod_thread_info *info, size_t size);
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
int lod_procfs_init(struct lod_device *lod);
void lod_procfs_fini(struct lod_device *lod);

/* lod_object.c */
extern struct dt_object_operations lod_obj_ops;
extern struct lu_object_operations lod_lu_obj_ops;
int lod_load_lmv_shards(const struct lu_env *env, struct lod_object *lo,
			struct lu_buf *buf, bool resize);
int lod_object_set_pool(struct lod_object *o, char *pool);
int lod_declare_striped_object(const struct lu_env *env, struct dt_object *dt,
			       struct lu_attr *attr,
			       const struct lu_buf *lovea, struct thandle *th);
int lod_striping_create(const struct lu_env *env, struct dt_object *dt,
			struct lu_attr *attr, struct dt_object_format *dof,
			struct thandle *th);
void lod_object_free_striping(const struct lu_env *env, struct lod_object *lo);

/* lod_sub_object.c */
struct thandle *lod_sub_get_thandle(const struct lu_env *env,
				    struct thandle *th,
				    const struct dt_object *sub_obj,
				    bool *record_update);
int lod_sub_object_declare_create(const struct lu_env *env,
				  struct dt_object *dt,
				  struct lu_attr *attr,
				  struct dt_allocation_hint *hint,
				  struct dt_object_format *dof,
				  struct thandle *th);
int lod_sub_object_create(const struct lu_env *env, struct dt_object *dt,
			  struct lu_attr *attr,
			  struct dt_allocation_hint *hint,
			  struct dt_object_format *dof,
			  struct thandle *th);
int lod_sub_object_declare_ref_add(const struct lu_env *env,
				   struct dt_object *dt,
				   struct thandle *th);
int lod_sub_object_ref_add(const struct lu_env *env, struct dt_object *dt,
			   struct thandle *th);
int lod_sub_object_declare_ref_del(const struct lu_env *env,
				   struct dt_object *dt,
				   struct thandle *th);
int lod_sub_object_ref_del(const struct lu_env *env, struct dt_object *dt,
			   struct thandle *th);
int lod_sub_object_declare_destroy(const struct lu_env *env,
				   struct dt_object *dt,
				   struct thandle *th);
int lod_sub_object_destroy(const struct lu_env *env, struct dt_object *dt,
			   struct thandle *th);
int lod_sub_object_declare_insert(const struct lu_env *env,
				  struct dt_object *dt,
				  const struct dt_rec *rec,
				  const struct dt_key *key,
				  struct thandle *th);
int lod_sub_object_index_insert(const struct lu_env *env, struct dt_object *dt,
				const struct dt_rec *rec,
				const struct dt_key *key, struct thandle *th,
				int ign);
int lod_sub_object_declare_delete(const struct lu_env *env,
				  struct dt_object *dt,
				  const struct dt_key *key,
				  struct thandle *th);
int lod_sub_object_delete(const struct lu_env *env, struct dt_object *dt,
			  const struct dt_key *name, struct thandle *th);
int lod_sub_object_declare_xattr_set(const struct lu_env *env,
				     struct dt_object *dt,
				     const struct lu_buf *buf,
				     const char *name, int fl,
				     struct thandle *th);
int lod_sub_object_xattr_set(const struct lu_env *env, struct dt_object *dt,
			     const struct lu_buf *buf, const char *name, int fl,
			     struct thandle *th);
int lod_sub_object_declare_attr_set(const struct lu_env *env,
				    struct dt_object *dt,
				    const struct lu_attr *attr,
				    struct thandle *th);
int lod_sub_object_attr_set(const struct lu_env *env,
			    struct dt_object *dt,
			    const struct lu_attr *attr,
			    struct thandle *th);
int lod_sub_object_declare_xattr_del(const struct lu_env *env,
				     struct dt_object *dt,
				     const char *name,
				     struct thandle *th);
int lod_sub_object_xattr_del(const struct lu_env *env,
			     struct dt_object *dt,
			     const char *name,
			     struct thandle *th);
int lod_sub_object_declare_write(const struct lu_env *env,
				 struct dt_object *dt,
				 const struct lu_buf *buf, loff_t pos,
				 struct thandle *th);
ssize_t lod_sub_object_write(const struct lu_env *env, struct dt_object *dt,
			     const struct lu_buf *buf, loff_t *pos,
			     struct thandle *th, int rq);
int lod_sub_object_declare_punch(const struct lu_env *env,
				 struct dt_object *dt,
				 __u64 start, __u64 end,
				 struct thandle *th);
int lod_sub_object_punch(const struct lu_env *env, struct dt_object *dt,
			 __u64 start, __u64 end, struct thandle *th);

int lod_sub_prep_llog(const struct lu_env *env, struct lod_device *lod,
		      struct dt_device *dt, int index);
#endif
