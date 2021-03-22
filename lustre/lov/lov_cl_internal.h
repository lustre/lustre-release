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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Internal interfaces of LOV layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 *   Author: Jinshan Xiong <jinshan.xiong@intel.com>
 */

#ifndef LOV_CL_INTERNAL_H
#define LOV_CL_INTERNAL_H

#include <libcfs/libcfs.h>
#include <obd.h>
#include <cl_object.h>
#include "lov_internal.h"

/** \defgroup lov lov
 * Logical object volume layer. This layer implements data striping (raid0).
 *
 * At the lov layer top-entity (object, page, lock, io) is connected to one or
 * more sub-entities: top-object, representing a file is connected to a set of
 * sub-objects, each representing a stripe, file-level top-lock is connected
 * to a set of per-stripe sub-locks, top-page is connected to a (single)
 * sub-page, and a top-level IO is connected to a set of (potentially
 * concurrent) sub-IO's.
 *
 * Sub-object, sub-page, and sub-io have well-defined top-object and top-page
 * respectively, while a single sub-lock can be part of multiple top-locks.
 *
 * Reference counting models are different for different types of entities:
 *
 *     - top-object keeps a reference to its sub-objects, and destroys them
 *       when it is destroyed.
 *
 *     - top-page keeps a reference to its sub-page, and destroys it when it
 *       is destroyed.
 *
 *     - IO's are not reference counted.
 *
 * To implement a connection between top and sub entities, lov layer is split
 * into two pieces: lov ("upper half"), and lovsub ("bottom half"), both
 * implementing full set of cl-interfaces. For example, top-object has vvp and
 * lov layers, and it's sub-object has lovsub and osc layers. lovsub layer is
 * used to track child-parent relationship.
 *
 * @{
 */

struct lovsub_device;
struct lovsub_object;

enum lov_device_flags {
	LOV_DEV_INITIALIZED = BIT(0),
};

/*
 * Upper half.
 */

/* Data-on-MDT array item in lov_device::ld_md_tgts[] */
struct lovdom_device {
	struct cl_device	*ldm_mdc;
	int			 ldm_idx;
};

struct lov_device {
        /*
         * XXX Locking of lov-private data is missing.
         */
        struct cl_device          ld_cl;
        struct lov_obd           *ld_lov;
        /** size of lov_device::ld_target[] array */
        __u32                     ld_target_nr;
        struct lovsub_device    **ld_target;
        __u32                     ld_flags;

	/* Data-on-MDT devices */
	__u32			  ld_md_tgts_nr;
	struct lovdom_device	 *ld_md_tgts;
	struct obd_device	 *ld_lmv;
	/* LU site for subdevices */
	struct lu_site		  ld_site;
};

/**
 * Layout type.
 */
enum lov_layout_type {
	LLT_EMPTY,	/** empty file without body (mknod + truncate) */
	LLT_RELEASED,	/** file with no objects (data in HSM) */
	LLT_COMP,	/** support composite layout */
	LLT_FOREIGN,	/** foreign layout */
	LLT_NR
};

static inline char *llt2str(enum lov_layout_type llt)
{
	switch (llt) {
	case LLT_EMPTY:
		return "EMPTY";
	case LLT_RELEASED:
		return "RELEASED";
	case LLT_COMP:
		return "COMPOSITE";
	case LLT_FOREIGN:
		return "FOREIGN";
	case LLT_NR:
		LBUG();
	}
	LBUG();
	return "";
}

/**
 * Return lov_layout_entry_type associated with a given composite layout
 * entry.
 */
static inline __u32 lov_entry_type(struct lov_stripe_md_entry *lsme)
{
	if ((lov_pattern(lsme->lsme_pattern) & LOV_PATTERN_RAID0) ||
	    (lov_pattern(lsme->lsme_pattern) == LOV_PATTERN_MDT) ||
	    (lov_pattern(lsme->lsme_pattern) == LOV_PATTERN_FOREIGN))
		return lov_pattern(lsme->lsme_pattern &
				   ~LOV_PATTERN_OVERSTRIPING);
	return 0;
}

struct lov_layout_entry;
struct lov_object;
struct lov_lock_sub;

struct lov_comp_layout_entry_ops {
	int (*lco_init)(const struct lu_env *env, struct lov_device *dev,
			struct lov_object *lov, unsigned int index,
			const struct cl_object_conf *conf,
			struct lov_layout_entry *lle);
	void (*lco_fini)(const struct lu_env *env,
			 struct lov_layout_entry *lle);
	int  (*lco_getattr)(const struct lu_env *env, struct lov_object *obj,
			    unsigned int index, struct lov_layout_entry *lle,
			    struct cl_attr **attr);
};

struct lov_layout_raid0 {
	unsigned               lo_nr;
	/**
	 * record the stripe no before the truncate size, used for setting OST
	 * object size for truncate. LU-14128.
	 */
	int                    lo_trunc_stripeno;
	/**
	 * When this is true, lov_object::lo_attr contains
	 * valid up to date attributes for a top-level
	 * object. This field is reset to 0 when attributes of
	 * any sub-object change.
	 */
	bool		       lo_attr_valid;
	/**
	 * Array of sub-objects. Allocated when top-object is
	 * created (lov_init_raid0()).
	 *
	 * Top-object is a strict master of its sub-objects:
	 * it is created before them, and outlives its
	 * children (this later is necessary so that basic
	 * functions like cl_object_top() always
	 * work). Top-object keeps a reference on every
	 * sub-object.
	 *
	 * When top-object is destroyed (lov_delete_raid0())
	 * it releases its reference to a sub-object and waits
	 * until the latter is finally destroyed.
	 */
	struct lovsub_object **lo_sub;
	/**
	 * protect lo_sub
	 */
	spinlock_t		lo_sub_lock;
	/**
	 * Cached object attribute, built from sub-object
	 * attributes.
	 */
	struct cl_attr         lo_attr;
};

struct lov_layout_dom {
	/* keep this always at first place so DOM layout entry
	 * can be addressed also as RAID0 after initialization.
	 */
	struct lov_layout_raid0 lo_dom_r0;
	struct lovsub_object *lo_dom;
	struct lov_oinfo *lo_loi;
};

struct lov_layout_entry {
	__u32				lle_type;
	unsigned int			lle_valid:1;
	struct lu_extent		*lle_extent;
	struct lov_stripe_md_entry	*lle_lsme;
	struct lov_comp_layout_entry_ops *lle_comp_ops;
	union {
		struct lov_layout_raid0	lle_raid0;
		struct lov_layout_dom	lle_dom;
	};
};

struct lov_mirror_entry {
	unsigned short	lre_mirror_id;
	unsigned short	lre_preferred:1,
			lre_stale:1,	/* set if any components is stale */
			lre_valid:1,	/* set if at least one of components
					 * in this mirror is valid */
			lre_foreign:1;	/* set if it is a foreign component */

	unsigned short	lre_start;	/* index to lo_entries, start index of
					 * this mirror */
	unsigned short	lre_end;	/* end index of this mirror */
};

enum lov_object_flags {
	/* Layout is invalid, set when layout lock is lost */
	LO_LAYOUT_INVALID	= 0x1,
};

/**
 * lov-specific file state.
 *
 * lov object has particular layout type, determining how top-object is built
 * on top of sub-objects. Layout type can change dynamically. When this
 * happens, lov_object::lo_type_guard semaphore is taken in exclusive mode,
 * all state pertaining to the old layout type is destroyed, and new state is
 * constructed. All object methods take said semaphore in the shared mode,
 * providing serialization against transition between layout types.
 *
 * To avoid multiple `if' or `switch' statements, selecting behavior for the
 * current layout type, object methods perform double-dispatch, invoking
 * function corresponding to the current layout type.
 */
struct lov_object {
	struct cl_object	lo_cl;
	/**
	 * Serializes object operations with transitions between layout types.
	 *
	 * This semaphore is taken in shared mode by all object methods, and
	 * is taken in exclusive mode when object type is changed.
	 *
	 * \see lov_object::lo_type
	 */
	struct rw_semaphore	lo_type_guard;
	/**
	 * Type of an object. Protected by lov_object::lo_type_guard.
	 */
	enum lov_layout_type	lo_type;
	/**
	 * Object flags.
	 */
	unsigned long		lo_obj_flags;
	/**
	 * How many IOs are on going on this object. Layout can be changed
	 * only if there is no active IO.
	 */
	atomic_t	       lo_active_ios;
	/**
	 * Waitq - wait for no one else is using lo_lsm
	 */
	wait_queue_head_t	lo_waitq;
	/**
	 * Layout metadata. NULL if empty layout.
	 */
	struct lov_stripe_md  *lo_lsm;

	union lov_layout_state {
		struct lov_layout_state_empty {
		} empty;
		struct lov_layout_state_released {
		} released;
		struct lov_layout_composite {
			/**
			 * flags of lov_comp_md_v1::lcm_flags. Mainly used
			 * by FLR.
			 */
			uint32_t        lo_flags;
			/**
			 * For FLR: index of preferred mirror to read.
			 * Preferred mirror is initialized by the preferred
			 * bit of lsme. It can be changed when the preferred
			 * is inaccessible.
			 * In order to make lov_lsm_entry() return the same
			 * mirror in the same IO context, it's only possible
			 * to change the preferred mirror when the
			 * lo_active_ios reaches zero.
			 */
			int             lo_preferred_mirror;
			/**
			 * For FLR: the lock to protect access to
			 * lo_preferred_mirror.
			 */
			spinlock_t      lo_write_lock;
			/**
			 * For FLR: Number of (valid) mirrors.
			 */
			unsigned        lo_mirror_count;
			struct lov_mirror_entry *lo_mirrors;
			/**
			 * Current entry count of lo_entries, include
			 * invalid entries.
			 */
			unsigned int    lo_entry_count;
			struct lov_layout_entry *lo_entries;
		} composite;
	} u;
	/**
	 * Thread that acquired lov_object::lo_type_guard in an exclusive
	 * mode.
	 */
	struct task_struct            *lo_owner;
};

static inline struct lov_layout_raid0 *lov_r0(struct lov_object *lov, int i)
{
	LASSERT(lov->lo_type == LLT_COMP);
	LASSERTF(i < lov->u.composite.lo_entry_count,
		 "entry %d entry_count %d\n", i,
		 lov->u.composite.lo_entry_count);

	return &lov->u.composite.lo_entries[i].lle_raid0;
}

static inline struct lov_stripe_md_entry *lov_lse(struct lov_object *lov, int i)
{
	LASSERT(lov->lo_lsm != NULL);
	LASSERT(i < lov->lo_lsm->lsm_entry_count);

	return lov->lo_lsm->lsm_entries[i];
}

static inline unsigned lov_flr_state(const struct lov_object *lov)
{
	if (lov->lo_type != LLT_COMP)
		return LCM_FL_NONE;

	return lov->u.composite.lo_flags & LCM_FL_FLR_MASK;
}

static inline bool lov_is_flr(const struct lov_object *lov)
{
	return lov_flr_state(lov) != LCM_FL_NONE;
}

static inline struct lov_layout_entry *lov_entry(struct lov_object *lov, int i)
{
	LASSERT(lov->lo_type == LLT_COMP);
	LASSERTF(i < lov->u.composite.lo_entry_count,
		 "entry %d entry_count %d\n", i,
		 lov->u.composite.lo_entry_count);

	return &lov->u.composite.lo_entries[i];
}

#define lov_for_layout_entry(lov, entry, start, end)			\
	for (entry = lov_entry(lov, start);				\
	     entry <= lov_entry(lov, end); entry++)

#define lov_foreach_layout_entry(lov, entry)				\
	lov_for_layout_entry(lov, entry, 0,				\
			     (lov)->u.composite.lo_entry_count - 1)

#define lov_foreach_mirror_layout_entry(lov, entry, lre)		\
	lov_for_layout_entry(lov, entry, (lre)->lre_start, (lre)->lre_end)

static inline struct lov_mirror_entry *
lov_mirror_entry(struct lov_object *lov, int i)
{
	LASSERT(i < lov->u.composite.lo_mirror_count);
	return &lov->u.composite.lo_mirrors[i];
}

#define lov_foreach_mirror_entry(lov, lre)				\
	for (lre = lov_mirror_entry(lov, 0);				\
	     lre <= lov_mirror_entry(lov,				\
				lov->u.composite.lo_mirror_count - 1);	\
	     lre++)

static inline unsigned
lov_layout_entry_index(struct lov_object *lov, struct lov_layout_entry *entry)
{
	struct lov_layout_entry *first = &lov->u.composite.lo_entries[0];
	unsigned index = (unsigned)(entry - first);

	LASSERT(entry >= first);
	LASSERT(index < lov->u.composite.lo_entry_count);

	return index;
}

/**
 * State lov_lock keeps for each sub-lock.
 */
struct lov_lock_sub {
	/** sub-lock itself */
	struct cl_lock		sub_lock;
	/** Set if the sublock has ever been enqueued, meaning it may
	 * hold resources of underlying layers */
	unsigned int		sub_is_enqueued:1,
				sub_initialized:1;
	int			sub_index;
};

/**
 * lov-specific lock state.
 */
struct lov_lock {
	struct cl_lock_slice	lls_cl;
	/** Number of sub-locks in this lock */
	int			lls_nr;
	/** sublock array */
	struct lov_lock_sub	lls_sub[0];
};

struct lov_page {
	struct cl_page_slice	lps_cl;
	/* the layout gen when this page was created */
	__u32			lps_layout_gen;
};

/*
 * Bottom half.
 */

struct lovsub_device {
        struct cl_device   acid_cl;
        struct cl_device  *acid_next;
};

struct lovsub_object {
        struct cl_object_header lso_header;
        struct cl_object        lso_cl;
        struct lov_object      *lso_super;
        int                     lso_index;
};

/**
 * Describe the environment settings for sublocks.
 */
struct lov_sublock_env {
        const struct lu_env *lse_env;
        struct cl_io        *lse_io;
};

struct lov_thread_info {
	struct cl_object_conf   lti_stripe_conf;
	struct lu_fid           lti_fid;
	struct ost_lvb          lti_lvb;
	struct cl_2queue        lti_cl2q;
	struct cl_page_list     lti_plist;
};

/**
 * State that lov_io maintains for every sub-io.
 */
struct lov_io_sub {
	/**
	 * Linkage into a list (hanging off lov_io::lis_subios)
	 */
	struct list_head	sub_list;
	/**
	 * Linkage into a list (hanging off lov_io::lis_active) of all
	 * sub-io's active for the current IO iteration.
	 */
	struct list_head	sub_linkage;
	unsigned int		sub_subio_index;
	/**
	 * sub-io for a stripe. Ideally sub-io's can be stopped and resumed
	 * independently, with lov acting as a scheduler to maximize overall
	 * throughput.
	 */
	struct cl_io		sub_io;
	/**
	 * environment, in which sub-io executes.
	 */
	struct lu_env		*sub_env;
	/**
	 * environment's refcheck.
	 *
	 * \see cl_env_get()
	 */
	__u16			sub_refcheck;
};

/**
 * IO state private for LOV.
 */
struct lov_io {
        /** super-class */
        struct cl_io_slice lis_cl;

	/**
	 * FLR: index to lo_mirrors. Valid only if lov_is_flr() returns true.
	 *
	 * The mirror index of this io. Preserved over cl_io_init()
	 * if io->ci_ndelay_tried is greater than zero.
	 */
	int			lis_mirror_index;
	/**
	 * FLR: the layout gen when lis_mirror_index was cached. The
	 * mirror index makes sense only when the layout gen doesn't
	 * change.
	 */
	int			lis_mirror_layout_gen;

	/**
	 * fields below this will be initialized in lov_io_init().
	 */
	unsigned		lis_preserved;

        /**
         * Pointer to the object slice. This is a duplicate of
         * lov_io::lis_cl::cis_object.
         */
        struct lov_object *lis_object;
        /**
         * Original end-of-io position for this IO, set by the upper layer as
         * cl_io::u::ci_rw::pos + cl_io::u::ci_rw::count. lov remembers this,
         * changes pos and count to fit IO into a single stripe and uses saved
         * value to determine when IO iterations have to stop.
         *
         * This is used only for CIT_READ and CIT_WRITE io's.
         */
        loff_t             lis_io_endpos;

        /**
         * starting position within a file, for the current io loop iteration
         * (stripe), used by ci_io_loop().
         */
	loff_t			lis_pos;
	/**
	 * end position with in a file, for the current stripe io. This is
	 * exclusive (i.e., next offset after last byte affected by io).
	 */
	loff_t			lis_endpos;
	int			lis_nr_subios;

	/**
	 * the index of ls_single_subio in ls_subios array
	 */
	int			lis_single_subio_index;
	struct lov_io_sub	lis_single_subio;

	/**
	 * List of active sub-io's. Active sub-io's are under the range
	 * of [lis_pos, lis_endpos).
	 */
	struct list_head	lis_active;
	/**
	 * All sub-io's created in this lov_io.
	 */
	struct list_head	lis_subios;

};

struct lov_session {
        struct lov_io          ls_io;
        struct lov_sublock_env ls_subenv;
};

extern struct lu_device_type lov_device_type;
extern struct lu_device_type lovsub_device_type;

extern struct lu_context_key lov_key;
extern struct lu_context_key lov_session_key;

extern struct kmem_cache *lov_lock_kmem;
extern struct kmem_cache *lov_object_kmem;
extern struct kmem_cache *lov_thread_kmem;
extern struct kmem_cache *lov_session_kmem;

extern struct kmem_cache *lovsub_object_kmem;

int   lov_lock_init_composite(const struct lu_env *env, struct cl_object *obj,
                           struct cl_lock *lock, const struct cl_io *io);
int   lov_lock_init_empty (const struct lu_env *env, struct cl_object *obj,
                           struct cl_lock *lock, const struct cl_io *io);
int   lov_io_init_composite(const struct lu_env *env, struct cl_object *obj,
                           struct cl_io *io);
int   lov_io_init_empty   (const struct lu_env *env, struct cl_object *obj,
                           struct cl_io *io);
int   lov_io_init_released(const struct lu_env *env, struct cl_object *obj,
                           struct cl_io *io);

struct lov_io_sub *lov_sub_get(const struct lu_env *env, struct lov_io *lio,
                               int stripe);

int   lov_page_init_empty (const struct lu_env *env, struct cl_object *obj,
			   struct cl_page *page, pgoff_t index);
int   lov_page_init_composite(const struct lu_env *env, struct cl_object *obj,
			   struct cl_page *page, pgoff_t index);
int   lov_page_init_foreign(const struct lu_env *env, struct cl_object *obj,
			     struct cl_page *page, pgoff_t index);
struct lu_object *lov_object_alloc   (const struct lu_env *env,
                                      const struct lu_object_header *hdr,
                                      struct lu_device *dev);

struct lu_object *lovsub_object_alloc(const struct lu_env *env,
                                      const struct lu_object_header *hdr,
                                      struct lu_device *dev);

int lov_page_stripe(const struct cl_page *page);
bool lov_page_is_empty(const struct cl_page *page);
int lov_lsm_entry(const struct lov_stripe_md *lsm, __u64 offset);
int lov_io_layout_at(struct lov_io *lio, __u64 offset);

#define lov_foreach_target(lov, var)                    \
        for (var = 0; var < lov_targets_nr(lov); ++var)

static inline struct lu_extent *lov_io_extent(struct lov_io *io, int i)
{
	return &lov_lse(io->lis_object, i)->lsme_extent;
}

/**
 * For layout entries within @ext.
 */
#define lov_foreach_io_layout(ind, lio, ext)				\
	for (ind = lov_io_layout_at(lio, (ext)->e_start);		\
	     ind >= 0 &&						\
	     lu_extent_is_overlapped(lov_io_extent(lio, ind), ext);	\
	     ind = lov_io_layout_at(lio, lov_io_extent(lio, ind)->e_end))

/*****************************************************************************
 *
 * Type conversions.
 *
 * Accessors.
 *
 */

static inline struct lov_session *lov_env_session(const struct lu_env *env)
{
        struct lov_session *ses;

        ses = lu_context_key_get(env->le_ses, &lov_session_key);
        LASSERT(ses != NULL);
        return ses;
}

static inline struct lov_io *lov_env_io(const struct lu_env *env)
{
        return &lov_env_session(env)->ls_io;
}

static inline int lov_is_object(const struct lu_object *obj)
{
        return obj->lo_dev->ld_type == &lov_device_type;
}

static inline int lovsub_is_object(const struct lu_object *obj)
{
        return obj->lo_dev->ld_type == &lovsub_device_type;
}

static inline struct lu_device *lov2lu_dev(struct lov_device *lov)
{
        return &lov->ld_cl.cd_lu_dev;
}

static inline struct lov_device *lu2lov_dev(const struct lu_device *d)
{
	LINVRNT(d->ld_type == &lov_device_type);
	return container_of(d, struct lov_device, ld_cl.cd_lu_dev);
}

static inline struct cl_device *lovsub2cl_dev(struct lovsub_device *lovsub)
{
        return &lovsub->acid_cl;
}

static inline struct lu_device *lovsub2lu_dev(struct lovsub_device *lovsub)
{
        return &lovsub2cl_dev(lovsub)->cd_lu_dev;
}

static inline struct lovsub_device *lu2lovsub_dev(const struct lu_device *d)
{
	LINVRNT(d->ld_type == &lovsub_device_type);
	return container_of(d, struct lovsub_device, acid_cl.cd_lu_dev);
}

static inline struct lovsub_device *cl2lovsub_dev(const struct cl_device *d)
{
	LINVRNT(d->cd_lu_dev.ld_type == &lovsub_device_type);
	return container_of(d, struct lovsub_device, acid_cl);
}

static inline struct lu_object *lov2lu(struct lov_object *lov)
{
        return &lov->lo_cl.co_lu;
}

static inline struct cl_object *lov2cl(struct lov_object *lov)
{
        return &lov->lo_cl;
}

static inline struct lov_object *lu2lov(const struct lu_object *obj)
{
	LINVRNT(lov_is_object(obj));
	return container_of(obj, struct lov_object, lo_cl.co_lu);
}

static inline struct lov_object *cl2lov(const struct cl_object *obj)
{
	LINVRNT(lov_is_object(&obj->co_lu));
	return container_of(obj, struct lov_object, lo_cl);
}

static inline struct lu_object *lovsub2lu(struct lovsub_object *los)
{
	return &los->lso_cl.co_lu;
}

static inline struct cl_object *lovsub2cl(struct lovsub_object *los)
{
	return &los->lso_cl;
}

static inline struct lovsub_object *cl2lovsub(const struct cl_object *obj)
{
	LINVRNT(lovsub_is_object(&obj->co_lu));
	return container_of(obj, struct lovsub_object, lso_cl);
}

static inline struct lovsub_object *lu2lovsub(const struct lu_object *obj)
{
	LINVRNT(lovsub_is_object(obj));
	return container_of(obj, struct lovsub_object, lso_cl.co_lu);
}

static inline struct lov_lock *cl2lov_lock(const struct cl_lock_slice *slice)
{
	LINVRNT(lov_is_object(&slice->cls_obj->co_lu));
	return container_of(slice, struct lov_lock, lls_cl);
}

static inline struct lov_page *cl2lov_page(const struct cl_page_slice *slice)
{
	LINVRNT(lov_is_object(&slice->cpl_obj->co_lu));
	return container_of(slice, struct lov_page, lps_cl);
}

static inline struct lov_io *cl2lov_io(const struct lu_env *env,
                                const struct cl_io_slice *ios)
{
        struct lov_io *lio;

        lio = container_of(ios, struct lov_io, lis_cl);
        LASSERT(lio == lov_env_io(env));
        return lio;
}

static inline int lov_targets_nr(const struct lov_device *lov)
{
        return lov->ld_lov->desc.ld_tgt_count;
}

static inline struct lov_thread_info *lov_env_info(const struct lu_env *env)
{
        struct lov_thread_info *info;

        info = lu_context_key_get(&env->le_ctx, &lov_key);
        LASSERT(info != NULL);
        return info;
}

/* lov_pack.c */
int lov_getstripe(const struct lu_env *env, struct lov_object *obj,
		  struct lov_stripe_md *lsm, struct lov_user_md __user *lump,
		  size_t size);

/** @} lov */

#endif
