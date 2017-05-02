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
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * Client Lustre Object.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 *   Author: Jinshan Xiong <jinshan.xiong@intel.com>
 */

/*
 * Locking.
 *
 *  i_mutex
 *      PG_locked
 *          ->coh_attr_guard
 *          ->ls_guard
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/list.h>
#include <libcfs/libcfs.h>
/* class_put_type() */
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_fid.h>
#include <libcfs/libcfs_hash.h> /* for cfs_hash stuff */
#include <cl_object.h>
#include <lu_object.h>
#include "cl_internal.h"

static struct kmem_cache *cl_env_kmem;

/** Lock class of cl_object_header::coh_attr_guard */
static struct lock_class_key cl_attr_guard_class;

/**
 * Initialize cl_object_header.
 */
int cl_object_header_init(struct cl_object_header *h)
{
	int result;

	ENTRY;
	result = lu_object_header_init(&h->coh_lu);
	if (result == 0) {
		spin_lock_init(&h->coh_attr_guard);
		lockdep_set_class(&h->coh_attr_guard, &cl_attr_guard_class);
		h->coh_page_bufsize = 0;
	}
	RETURN(result);
}
EXPORT_SYMBOL(cl_object_header_init);

/**
 * Finalize cl_object_header.
 */
void cl_object_header_fini(struct cl_object_header *h)
{
        lu_object_header_fini(&h->coh_lu);
}

/**
 * Returns a cl_object with a given \a fid.
 *
 * Returns either cached or newly created object. Additional reference on the
 * returned object is acquired.
 *
 * \see lu_object_find(), cl_page_find(), cl_lock_find()
 */
struct cl_object *cl_object_find(const struct lu_env *env,
                                 struct cl_device *cd, const struct lu_fid *fid,
                                 const struct cl_object_conf *c)
{
	might_sleep();
        return lu2cl(lu_object_find_slice(env, cl2lu_dev(cd), fid, &c->coc_lu));
}
EXPORT_SYMBOL(cl_object_find);

/**
 * Releases a reference on \a o.
 *
 * When last reference is released object is returned to the cache, unless
 * lu_object_header_flags::LU_OBJECT_HEARD_BANSHEE bit is set in its header.
 *
 * \see cl_page_put(), cl_lock_put().
 */
void cl_object_put(const struct lu_env *env, struct cl_object *o)
{
        lu_object_put(env, &o->co_lu);
}
EXPORT_SYMBOL(cl_object_put);

/**
 * Acquire an additional reference to the object \a o.
 *
 * This can only be used to acquire _additional_ reference, i.e., caller
 * already has to possess at least one reference to \a o before calling this.
 *
 * \see cl_page_get(), cl_lock_get().
 */
void cl_object_get(struct cl_object *o)
{
        lu_object_get(&o->co_lu);
}
EXPORT_SYMBOL(cl_object_get);

/**
 * Returns the top-object for a given \a o.
 *
 * \see cl_io_top()
 */
struct cl_object *cl_object_top(struct cl_object *o)
{
        struct cl_object_header *hdr = cl_object_header(o);
        struct cl_object *top;

        while (hdr->coh_parent != NULL)
                hdr = hdr->coh_parent;

        top = lu2cl(lu_object_top(&hdr->coh_lu));
        CDEBUG(D_TRACE, "%p -> %p\n", o, top);
        return top;
}
EXPORT_SYMBOL(cl_object_top);

/**
 * Returns pointer to the lock protecting data-attributes for the given object
 * \a o.
 *
 * Data-attributes are protected by the cl_object_header::coh_attr_guard
 * spin-lock in the top-object.
 *
 * \see cl_attr, cl_object_attr_lock(), cl_object_operations::coo_attr_get().
 */
static spinlock_t *cl_object_attr_guard(struct cl_object *o)
{
	return &cl_object_header(cl_object_top(o))->coh_attr_guard;
}

/**
 * Locks data-attributes.
 *
 * Prevents data-attributes from changing, until lock is released by
 * cl_object_attr_unlock(). This has to be called before calls to
 * cl_object_attr_get(), cl_object_attr_update().
 */
void cl_object_attr_lock(struct cl_object *o)
__acquires(cl_object_attr_guard(o))
{
	spin_lock(cl_object_attr_guard(o));
}
EXPORT_SYMBOL(cl_object_attr_lock);

/**
 * Releases data-attributes lock, acquired by cl_object_attr_lock().
 */
void cl_object_attr_unlock(struct cl_object *o)
__releases(cl_object_attr_guard(o))
{
	spin_unlock(cl_object_attr_guard(o));
}
EXPORT_SYMBOL(cl_object_attr_unlock);

/**
 * Returns data-attributes of an object \a obj.
 *
 * Every layer is asked (by calling cl_object_operations::coo_attr_get())
 * top-to-bottom to fill in parts of \a attr that this layer is responsible
 * for.
 */
int cl_object_attr_get(const struct lu_env *env, struct cl_object *obj,
			struct cl_attr *attr)
{
	struct lu_object_header *top;
	int result;

	assert_spin_locked(cl_object_attr_guard(obj));
	ENTRY;

	top = obj->co_lu.lo_header;
	result = 0;
	list_for_each_entry(obj, &top->loh_layers, co_lu.lo_linkage) {
		if (obj->co_ops->coo_attr_get != NULL) {
			result = obj->co_ops->coo_attr_get(env, obj, attr);
			if (result != 0) {
				if (result > 0)
					result = 0;
				break;
			}
		}
	}
	RETURN(result);
}
EXPORT_SYMBOL(cl_object_attr_get);

/**
 * Updates data-attributes of an object \a obj.
 *
 * Only attributes, mentioned in a validness bit-mask \a v are
 * updated. Calls cl_object_operations::coo_upd_attr() on every layer, bottom
 * to top.
 */
int cl_object_attr_update(const struct lu_env *env, struct cl_object *obj,
			  const struct cl_attr *attr, unsigned v)
{
	struct lu_object_header *top;
	int result;

	assert_spin_locked(cl_object_attr_guard(obj));
	ENTRY;

	top = obj->co_lu.lo_header;
	result = 0;
	list_for_each_entry_reverse(obj, &top->loh_layers, co_lu.lo_linkage) {
		if (obj->co_ops->coo_attr_update != NULL) {
			result = obj->co_ops->coo_attr_update(env, obj, attr,
							      v);
			if (result != 0) {
				if (result > 0)
					result = 0;
				break;
			}
		}
	}
	RETURN(result);
}
EXPORT_SYMBOL(cl_object_attr_update);

/**
 * Notifies layers (bottom-to-top) that glimpse AST was received.
 *
 * Layers have to fill \a lvb fields with information that will be shipped
 * back to glimpse issuer.
 *
 * \see cl_lock_operations::clo_glimpse()
 */
int cl_object_glimpse(const struct lu_env *env, struct cl_object *obj,
                      struct ost_lvb *lvb)
{
        struct lu_object_header *top;
        int result;

        ENTRY;
        top = obj->co_lu.lo_header;
        result = 0;
	list_for_each_entry_reverse(obj, &top->loh_layers, co_lu.lo_linkage) {
                if (obj->co_ops->coo_glimpse != NULL) {
                        result = obj->co_ops->coo_glimpse(env, obj, lvb);
                        if (result != 0)
                                break;
                }
        }
        LU_OBJECT_HEADER(D_DLMTRACE, env, lu_object_top(top),
			 "size: %llu mtime: %llu atime: %llu "
			 "ctime: %llu blocks: %llu\n",
                         lvb->lvb_size, lvb->lvb_mtime, lvb->lvb_atime,
                         lvb->lvb_ctime, lvb->lvb_blocks);
        RETURN(result);
}
EXPORT_SYMBOL(cl_object_glimpse);

/**
 * Updates a configuration of an object \a obj.
 */
int cl_conf_set(const struct lu_env *env, struct cl_object *obj,
                const struct cl_object_conf *conf)
{
        struct lu_object_header *top;
        int result;

        ENTRY;
        top = obj->co_lu.lo_header;
        result = 0;
	list_for_each_entry(obj, &top->loh_layers, co_lu.lo_linkage) {
                if (obj->co_ops->coo_conf_set != NULL) {
                        result = obj->co_ops->coo_conf_set(env, obj, conf);
                        if (result != 0)
                                break;
                }
        }
        RETURN(result);
}
EXPORT_SYMBOL(cl_conf_set);

/**
 * Prunes caches of pages and locks for this object.
 */
int cl_object_prune(const struct lu_env *env, struct cl_object *obj)
{
	struct lu_object_header *top;
	struct cl_object *o;
	int result;
	ENTRY;

	top = obj->co_lu.lo_header;
	result = 0;
	list_for_each_entry(o, &top->loh_layers, co_lu.lo_linkage) {
		if (o->co_ops->coo_prune != NULL) {
			result = o->co_ops->coo_prune(env, o);
			if (result != 0)
				break;
		}
	}

	RETURN(result);
}
EXPORT_SYMBOL(cl_object_prune);

/**
 * Get stripe information of this object.
 */
int cl_object_getstripe(const struct lu_env *env, struct cl_object *obj,
			struct lov_user_md __user *uarg, size_t size)
{
	struct lu_object_header	*top;
	int			result = 0;
	ENTRY;

	top = obj->co_lu.lo_header;
	list_for_each_entry(obj, &top->loh_layers, co_lu.lo_linkage) {
		if (obj->co_ops->coo_getstripe != NULL) {
			result = obj->co_ops->coo_getstripe(env, obj, uarg,
							    size);
			if (result != 0)
				break;
		}
	}
	RETURN(result);
}
EXPORT_SYMBOL(cl_object_getstripe);

/**
 * Get fiemap extents from file object.
 *
 * \param env [in]	lustre environment
 * \param obj [in]	file object
 * \param key [in]	fiemap request argument
 * \param fiemap [out]	fiemap extents mapping retrived
 * \param buflen [in]	max buffer length of @fiemap
 *
 * \retval 0	success
 * \retval < 0	error
 */
int cl_object_fiemap(const struct lu_env *env, struct cl_object *obj,
		     struct ll_fiemap_info_key *key,
		     struct fiemap *fiemap, size_t *buflen)
{
	struct lu_object_header	*top;
	int			result = 0;
	ENTRY;

	top = obj->co_lu.lo_header;
	list_for_each_entry(obj, &top->loh_layers, co_lu.lo_linkage) {
		if (obj->co_ops->coo_fiemap != NULL) {
			result = obj->co_ops->coo_fiemap(env, obj, key, fiemap,
							 buflen);
			if (result != 0)
				break;
		}
	}
	RETURN(result);
}
EXPORT_SYMBOL(cl_object_fiemap);

int cl_object_layout_get(const struct lu_env *env, struct cl_object *obj,
			 struct cl_layout *cl)
{
	struct lu_object_header	*top = obj->co_lu.lo_header;
	ENTRY;

	list_for_each_entry(obj, &top->loh_layers, co_lu.lo_linkage) {
		if (obj->co_ops->coo_layout_get != NULL)
			return obj->co_ops->coo_layout_get(env, obj, cl);
	}

	RETURN(-EOPNOTSUPP);
}
EXPORT_SYMBOL(cl_object_layout_get);

loff_t cl_object_maxbytes(struct cl_object *obj)
{
	struct lu_object_header	*top = obj->co_lu.lo_header;
	loff_t maxbytes = LLONG_MAX;
	ENTRY;

	list_for_each_entry(obj, &top->loh_layers, co_lu.lo_linkage) {
		if (obj->co_ops->coo_maxbytes != NULL)
			maxbytes = min_t(loff_t, obj->co_ops->coo_maxbytes(obj),
					 maxbytes);
	}

	RETURN(maxbytes);
}
EXPORT_SYMBOL(cl_object_maxbytes);

/**
 * Helper function removing all object locks, and marking object for
 * deletion. All object pages must have been deleted at this point.
 *
 * This is called by cl_inode_fini() and lov_object_delete() to destroy top-
 * and sub- objects respectively.
 */
void cl_object_kill(const struct lu_env *env, struct cl_object *obj)
{
	struct cl_object_header *hdr = cl_object_header(obj);

	set_bit(LU_OBJECT_HEARD_BANSHEE, &hdr->coh_lu.loh_flags);
}
EXPORT_SYMBOL(cl_object_kill);

void cache_stats_init(struct cache_stats *cs, const char *name)
{
	int i;

        cs->cs_name = name;
	for (i = 0; i < CS_NR; i++)
		atomic_set(&cs->cs_stats[i], 0);
}

static int cache_stats_print(const struct cache_stats *cs,
			     struct seq_file *m, int h)
{
	int i;

	/*
	 *   lookup    hit    total  cached create
	 * env: ...... ...... ...... ...... ......
	 */
	if (h) {
		const char *names[CS_NR] = CS_NAMES;

		seq_printf(m, "%6s", " ");
		for (i = 0; i < CS_NR; i++)
			seq_printf(m, "%8s", names[i]);
		seq_printf(m, "\n");
	}

	seq_printf(m, "%5.5s:", cs->cs_name);
	for (i = 0; i < CS_NR; i++)
		seq_printf(m, "%8u", atomic_read(&cs->cs_stats[i]));
	return 0;
}

static void cl_env_percpu_refill(void);

/**
 * Initialize client site.
 *
 * Perform common initialization (lu_site_init()), and initialize statistical
 * counters. Also perform global initializations on the first call.
 */
int cl_site_init(struct cl_site *s, struct cl_device *d)
{
	size_t i;
        int result;

        result = lu_site_init(&s->cs_lu, &d->cd_lu_dev);
        if (result == 0) {
                cache_stats_init(&s->cs_pages, "pages");
                for (i = 0; i < ARRAY_SIZE(s->cs_pages_state); ++i)
			atomic_set(&s->cs_pages_state[0], 0);
		cl_env_percpu_refill();
	}
	return result;
}
EXPORT_SYMBOL(cl_site_init);

/**
 * Finalize client site. Dual to cl_site_init().
 */
void cl_site_fini(struct cl_site *s)
{
        lu_site_fini(&s->cs_lu);
}
EXPORT_SYMBOL(cl_site_fini);

static struct cache_stats cl_env_stats = {
        .cs_name    = "envs",
	.cs_stats = { ATOMIC_INIT(0), }
};

/**
 * Outputs client site statistical counters into a buffer. Suitable for
 * ll_rd_*()-style functions.
 */
int cl_site_stats_print(const struct cl_site *site, struct seq_file *m)
{
	static const char *pstate[] = {
		[CPS_CACHED]	= "c",
		[CPS_OWNED]	= "o",
		[CPS_PAGEOUT]	= "w",
		[CPS_PAGEIN]	= "r",
		[CPS_FREEING]	= "f"
	};
	size_t i;

/*
       lookup    hit  total   busy create
pages: ...... ...... ...... ...... ...... [...... ...... ...... ......]
locks: ...... ...... ...... ...... ...... [...... ...... ...... ...... ......]
  env: ...... ...... ...... ...... ......
 */
	lu_site_stats_seq_print(&site->cs_lu, m);
	cache_stats_print(&site->cs_pages, m, 1);
	seq_printf(m, " [");
	for (i = 0; i < ARRAY_SIZE(site->cs_pages_state); ++i)
		seq_printf(m, "%s: %u ", pstate[i],
			   atomic_read(&site->cs_pages_state[i]));
	seq_printf(m, "]\n");
	cache_stats_print(&cl_env_stats, m, 0);
	seq_printf(m, "\n");
	return 0;
}
EXPORT_SYMBOL(cl_site_stats_print);

/*****************************************************************************
 *
 * lu_env handling on client.
 *
 */

/**
 * The most efficient way is to store cl_env pointer in task specific
 * structures. On Linux, it wont' be easy to use task_struct->journal_info
 * because Lustre code may call into other fs which has certain assumptions
 * about journal_info. Currently following fields in task_struct are identified
 * can be used for this purpose:
 *  - cl_env: for liblustre.
 *  - tux_info: ony on RedHat kernel.
 *  - ...
 * \note As long as we use task_struct to store cl_env, we assume that once
 * called into Lustre, we'll never call into the other part of the kernel
 * which will use those fields in task_struct without explicitly exiting
 * Lustre.
 *
 * If there's no space in task_struct is available, hash will be used.
 * bz20044, bz22683.
 */

static unsigned cl_envs_cached_max = 32; /* XXX: prototype: arbitrary limit
					  * for now. */
static struct cl_env_cache {
	rwlock_t		cec_guard;
	unsigned		cec_count;
	struct list_head	cec_envs;
} *cl_envs = NULL;

struct cl_env {
        void             *ce_magic;
        struct lu_env     ce_lu;
        struct lu_context ce_ses;

        /*
         * Linkage into global list of all client environments. Used for
         * garbage collection.
         */
	struct list_head  ce_linkage;
        /*
         *
         */
        int               ce_ref;
        /*
         * Debugging field: address of the caller who made original
         * allocation.
         */
        void             *ce_debug;
};

#ifdef CONFIG_DEBUG_PAGESTATE_TRACKING
#define CL_ENV_INC(counter) atomic_inc(&cl_env_stats.cs_stats[CS_##counter])

#define CL_ENV_DEC(counter) do {                                              \
	LASSERT(atomic_read(&cl_env_stats.cs_stats[CS_##counter]) > 0);   \
	atomic_dec(&cl_env_stats.cs_stats[CS_##counter]);                 \
} while (0)
#else
#define CL_ENV_INC(counter)
#define CL_ENV_DEC(counter)
#endif

static void cl_env_init0(struct cl_env *cle, void *debug)
{
	LASSERT(cle->ce_ref == 0);
	LASSERT(cle->ce_magic == &cl_env_init0);
	LASSERT(cle->ce_debug == NULL);

	cle->ce_ref = 1;
	cle->ce_debug = debug;
	CL_ENV_INC(busy);
}

static struct lu_env *cl_env_new(__u32 ctx_tags, __u32 ses_tags, void *debug)
{
	struct lu_env *env;
	struct cl_env *cle;

	OBD_SLAB_ALLOC_PTR_GFP(cle, cl_env_kmem, GFP_NOFS);
	if (cle != NULL) {
		int rc;

		INIT_LIST_HEAD(&cle->ce_linkage);
		cle->ce_magic = &cl_env_init0;
		env = &cle->ce_lu;
		rc = lu_env_init(env, LCT_CL_THREAD|ctx_tags);
		if (rc == 0) {
			rc = lu_context_init(&cle->ce_ses,
					     LCT_SESSION | ses_tags);
			if (rc == 0) {
				lu_context_enter(&cle->ce_ses);
				env->le_ses = &cle->ce_ses;
				cl_env_init0(cle, debug);
			} else
				lu_env_fini(env);
		}
		if (rc != 0) {
			OBD_SLAB_FREE_PTR(cle, cl_env_kmem);
			env = ERR_PTR(rc);
		} else {
			CL_ENV_INC(create);
			CL_ENV_INC(total);
		}
	} else
		env = ERR_PTR(-ENOMEM);
	return env;
}

static void cl_env_fini(struct cl_env *cle)
{
        CL_ENV_DEC(total);
        lu_context_fini(&cle->ce_lu.le_ctx);
        lu_context_fini(&cle->ce_ses);
        OBD_SLAB_FREE_PTR(cle, cl_env_kmem);
}

static struct lu_env *cl_env_obtain(void *debug)
{
	struct cl_env *cle;
	struct lu_env *env;
	int cpu = get_cpu();

	ENTRY;

	read_lock(&cl_envs[cpu].cec_guard);
	LASSERT(equi(cl_envs[cpu].cec_count == 0,
		list_empty(&cl_envs[cpu].cec_envs)));
	if (cl_envs[cpu].cec_count > 0) {
		int rc;

		cle = container_of(cl_envs[cpu].cec_envs.next, struct cl_env,
				   ce_linkage);
		list_del_init(&cle->ce_linkage);
		cl_envs[cpu].cec_count--;
		read_unlock(&cl_envs[cpu].cec_guard);
		put_cpu();

                env = &cle->ce_lu;
                rc = lu_env_refill(env);
                if (rc == 0) {
                        cl_env_init0(cle, debug);
                        lu_context_enter(&env->le_ctx);
                        lu_context_enter(&cle->ce_ses);
                } else {
                        cl_env_fini(cle);
                        env = ERR_PTR(rc);
                }
        } else {
		read_unlock(&cl_envs[cpu].cec_guard);
		put_cpu();
		env = cl_env_new(lu_context_tags_default,
				 lu_session_tags_default, debug);
	}
	RETURN(env);
}

static inline struct cl_env *cl_env_container(struct lu_env *env)
{
        return container_of(env, struct cl_env, ce_lu);
}

/**
 * Returns lu_env: if there already is an environment associated with the
 * current thread, it is returned, otherwise, new environment is allocated.
 *
 * Allocations are amortized through the global cache of environments.
 *
 * \param refcheck pointer to a counter used to detect environment leaks. In
 * the usual case cl_env_get() and cl_env_put() are called in the same lexical
 * scope and pointer to the same integer is passed as \a refcheck. This is
 * used to detect missed cl_env_put().
 *
 * \see cl_env_put()
 */
struct lu_env *cl_env_get(__u16 *refcheck)
{
        struct lu_env *env;

	env = cl_env_obtain(__builtin_return_address(0));
	if (!IS_ERR(env)) {
		struct cl_env *cle;

		cle = cl_env_container(env);
		*refcheck = cle->ce_ref;
		CDEBUG(D_OTHER, "%d@%p\n", cle->ce_ref, cle);
        }
        return env;
}
EXPORT_SYMBOL(cl_env_get);

/**
 * Forces an allocation of a fresh environment with given tags.
 *
 * \see cl_env_get()
 */
struct lu_env *cl_env_alloc(__u16 *refcheck, __u32 tags)
{
        struct lu_env *env;

        env = cl_env_new(tags, tags, __builtin_return_address(0));
        if (!IS_ERR(env)) {
                struct cl_env *cle;

                cle = cl_env_container(env);
                *refcheck = cle->ce_ref;
                CDEBUG(D_OTHER, "%d@%p\n", cle->ce_ref, cle);
        }
        return env;
}
EXPORT_SYMBOL(cl_env_alloc);

static void cl_env_exit(struct cl_env *cle)
{
        lu_context_exit(&cle->ce_lu.le_ctx);
        lu_context_exit(&cle->ce_ses);
}

/**
 * Finalizes and frees a given number of cached environments. This is done to
 * (1) free some memory (not currently hooked into VM), or (2) release
 * references to modules.
 */
unsigned cl_env_cache_purge(unsigned nr)
{
	struct cl_env *cle;
	unsigned i;

	ENTRY;
	for_each_possible_cpu(i) {
		write_lock(&cl_envs[i].cec_guard);
		for (; !list_empty(&cl_envs[i].cec_envs) && nr > 0; --nr) {
			cle = container_of(cl_envs[i].cec_envs.next,
					   struct cl_env, ce_linkage);
			list_del_init(&cle->ce_linkage);
			LASSERT(cl_envs[i].cec_count > 0);
			cl_envs[i].cec_count--;
			write_unlock(&cl_envs[i].cec_guard);

			cl_env_fini(cle);
			write_lock(&cl_envs[i].cec_guard);
		}
		LASSERT(equi(cl_envs[i].cec_count == 0,
			list_empty(&cl_envs[i].cec_envs)));
		write_unlock(&cl_envs[i].cec_guard);
	}
	RETURN(nr);
}
EXPORT_SYMBOL(cl_env_cache_purge);

/**
 * Release an environment.
 *
 * Decrement \a env reference counter. When counter drops to 0, nothing in
 * this thread is using environment and it is returned to the allocation
 * cache, or freed straight away, if cache is large enough.
 */
void cl_env_put(struct lu_env *env, __u16 *refcheck)
{
        struct cl_env *cle;

        cle = cl_env_container(env);

        LASSERT(cle->ce_ref > 0);
        LASSERT(ergo(refcheck != NULL, cle->ce_ref == *refcheck));

        CDEBUG(D_OTHER, "%d@%p\n", cle->ce_ref, cle);
        if (--cle->ce_ref == 0) {
		int cpu = get_cpu();

                CL_ENV_DEC(busy);
                cle->ce_debug = NULL;
                cl_env_exit(cle);
                /*
                 * Don't bother to take a lock here.
                 *
                 * Return environment to the cache only when it was allocated
                 * with the standard tags.
                 */
		if (cl_envs[cpu].cec_count < cl_envs_cached_max &&
		    (env->le_ctx.lc_tags & ~LCT_HAS_EXIT) == LCT_CL_THREAD &&
		    (env->le_ses->lc_tags & ~LCT_HAS_EXIT) == LCT_SESSION) {
			read_lock(&cl_envs[cpu].cec_guard);
			list_add(&cle->ce_linkage, &cl_envs[cpu].cec_envs);
			cl_envs[cpu].cec_count++;
			read_unlock(&cl_envs[cpu].cec_guard);
		} else
			cl_env_fini(cle);
		put_cpu();
	}
}
EXPORT_SYMBOL(cl_env_put);

/**
 * Converts struct cl_attr to struct ost_lvb.
 *
 * \see cl_lvb2attr
 */
void cl_attr2lvb(struct ost_lvb *lvb, const struct cl_attr *attr)
{
        ENTRY;
        lvb->lvb_size   = attr->cat_size;
        lvb->lvb_mtime  = attr->cat_mtime;
        lvb->lvb_atime  = attr->cat_atime;
        lvb->lvb_ctime  = attr->cat_ctime;
        lvb->lvb_blocks = attr->cat_blocks;
        EXIT;
}

/**
 * Converts struct ost_lvb to struct cl_attr.
 *
 * \see cl_attr2lvb
 */
void cl_lvb2attr(struct cl_attr *attr, const struct ost_lvb *lvb)
{
        ENTRY;
        attr->cat_size   = lvb->lvb_size;
        attr->cat_mtime  = lvb->lvb_mtime;
        attr->cat_atime  = lvb->lvb_atime;
        attr->cat_ctime  = lvb->lvb_ctime;
        attr->cat_blocks = lvb->lvb_blocks;
        EXIT;
}
EXPORT_SYMBOL(cl_lvb2attr);

static struct cl_env cl_env_percpu[NR_CPUS];

static int cl_env_percpu_init(void)
{
	struct cl_env *cle;
	int tags = LCT_REMEMBER | LCT_NOREF;
	int i, j;
	int rc = 0;

	for_each_possible_cpu(i) {
		struct lu_env *env;

		rwlock_init(&cl_envs[i].cec_guard);
		INIT_LIST_HEAD(&cl_envs[i].cec_envs);
		cl_envs[i].cec_count = 0;

		cle = &cl_env_percpu[i];
		env = &cle->ce_lu;

		INIT_LIST_HEAD(&cle->ce_linkage);
		cle->ce_magic = &cl_env_init0;
		rc = lu_env_init(env, LCT_CL_THREAD | tags);
		if (rc == 0) {
			rc = lu_context_init(&cle->ce_ses, LCT_SESSION | tags);
                        if (rc == 0) {
                                lu_context_enter(&cle->ce_ses);
                                env->le_ses = &cle->ce_ses;
			} else {
				lu_env_fini(env);
			}
		}
		if (rc != 0)
			break;
	}
	if (rc != 0) {
		/* Indices 0 to i (excluding i) were correctly initialized,
		 * thus we must uninitialize up to i, the rest are undefined. */
		for (j = 0; j < i; j++) {
			cle = &cl_env_percpu[j];
			lu_context_exit(&cle->ce_ses);
			lu_context_fini(&cle->ce_ses);
			lu_env_fini(&cle->ce_lu);
		}
	}

	return rc;
}

static void cl_env_percpu_fini(void)
{
	int i;

	for_each_possible_cpu(i) {
		struct cl_env *cle = &cl_env_percpu[i];

		lu_context_exit(&cle->ce_ses);
		lu_context_fini(&cle->ce_ses);
		lu_env_fini(&cle->ce_lu);
	}
}

static void cl_env_percpu_refill(void)
{
	int i;

	for_each_possible_cpu(i)
		lu_env_refill(&cl_env_percpu[i].ce_lu);
}

void cl_env_percpu_put(struct lu_env *env)
{
	struct cl_env *cle;
	int cpu;

	cpu = smp_processor_id();
	cle = cl_env_container(env);
	LASSERT(cle == &cl_env_percpu[cpu]);

	cle->ce_ref--;
	LASSERT(cle->ce_ref == 0);

	CL_ENV_DEC(busy);
	cle->ce_debug = NULL;

	put_cpu();
}
EXPORT_SYMBOL(cl_env_percpu_put);

struct lu_env *cl_env_percpu_get()
{
	struct cl_env *cle;

	cle = &cl_env_percpu[get_cpu()];
	cl_env_init0(cle, __builtin_return_address(0));

	return &cle->ce_lu;
}
EXPORT_SYMBOL(cl_env_percpu_get);

/*****************************************************************************
 *
 * Temporary prototype thing: mirror obd-devices into cl devices.
 *
 */

struct cl_device *cl_type_setup(const struct lu_env *env, struct lu_site *site,
                                struct lu_device_type *ldt,
                                struct lu_device *next)
{
        const char       *typename;
        struct lu_device *d;

        LASSERT(ldt != NULL);

        typename = ldt->ldt_name;
        d = ldt->ldt_ops->ldto_device_alloc(env, ldt, NULL);
        if (!IS_ERR(d)) {
                int rc;

                if (site != NULL)
                        d->ld_site = site;
                rc = ldt->ldt_ops->ldto_device_init(env, d, typename, next);
                if (rc == 0) {
                        lu_device_get(d);
                        lu_ref_add(&d->ld_reference,
                                   "lu-stack", &lu_site_init);
                } else {
                        ldt->ldt_ops->ldto_device_free(env, d);
                        CERROR("can't init device '%s', %d\n", typename, rc);
                        d = ERR_PTR(rc);
                }
        } else
                CERROR("Cannot allocate device: '%s'\n", typename);
        return lu2cl_dev(d);
}
EXPORT_SYMBOL(cl_type_setup);

/**
 * Finalize device stack by calling lu_stack_fini().
 */
void cl_stack_fini(const struct lu_env *env, struct cl_device *cl)
{
        lu_stack_fini(env, cl2lu_dev(cl));
}
EXPORT_SYMBOL(cl_stack_fini);

static struct lu_context_key cl_key;

struct cl_thread_info *cl_env_info(const struct lu_env *env)
{
        return lu_context_key_get(&env->le_ctx, &cl_key);
}

/* defines cl_key_{init,fini}() */
LU_KEY_INIT_FINI(cl, struct cl_thread_info);

static struct lu_context_key cl_key = {
        .lct_tags = LCT_CL_THREAD,
        .lct_init = cl_key_init,
        .lct_fini = cl_key_fini,
};

static struct lu_kmem_descr cl_object_caches[] = {
        {
                .ckd_cache = &cl_env_kmem,
                .ckd_name  = "cl_env_kmem",
                .ckd_size  = sizeof (struct cl_env)
        },
        {
                .ckd_cache = NULL
        }
};

struct cfs_ptask_engine *cl_io_engine;

/**
 * Global initialization of cl-data. Create kmem caches, register
 * lu_context_key's, etc.
 *
 * \see cl_global_fini()
 */
int cl_global_init(void)
{
	int result;

	OBD_ALLOC(cl_envs, sizeof(*cl_envs) * num_possible_cpus());
	if (cl_envs == NULL)
		GOTO(out, result = -ENOMEM);

	result = lu_kmem_init(cl_object_caches);
	if (result)
		GOTO(out_envs, result);

	LU_CONTEXT_KEY_INIT(&cl_key);
	result = lu_context_key_register(&cl_key);
	if (result)
		GOTO(out_kmem, result);

	result = cl_env_percpu_init();
	if (result) /* no cl_env_percpu_fini on error */
		GOTO(out_keys, result);

	cl_io_engine = cfs_ptengine_init("clio", cpu_online_mask);
	if (IS_ERR(cl_io_engine)) {
		result = PTR_ERR(cl_io_engine);
		cl_io_engine = NULL;
		GOTO(out_percpu, result);
	}

	return 0;

out_percpu:
	cl_env_percpu_fini();
out_keys:
	lu_context_key_degister(&cl_key);
out_kmem:
	lu_kmem_fini(cl_object_caches);
out_envs:
	OBD_FREE(cl_envs, sizeof(*cl_envs) * num_possible_cpus());
out:
	return result;
}

/**
 * Finalization of global cl-data. Dual to cl_global_init().
 */
void cl_global_fini(void)
{
	cfs_ptengine_fini(cl_io_engine);
	cl_io_engine = NULL;
	cl_env_percpu_fini();
	lu_context_key_degister(&cl_key);
	lu_kmem_fini(cl_object_caches);
	OBD_FREE(cl_envs, sizeof(*cl_envs) * num_possible_cpus());
}
