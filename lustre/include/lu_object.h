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
 */

#ifndef __LUSTRE_LU_OBJECT_H
#define __LUSTRE_LU_OBJECT_H

#include <stdarg.h>
#include <libcfs/libcfs.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <lu_ref.h>
#include <linux/percpu_counter.h>
#include <linux/rhashtable.h>
#include <linux/ctype.h>

struct seq_file;
struct proc_dir_entry;
struct lustre_cfg;
struct lprocfs_stats;
struct obd_type;

/** \defgroup lu lu
 * lu_* data-types represent server-side entities shared by data and meta-data
 * stacks.
 *
 * Design goals:
 *
 * -# support for layering.
 *
 *     Server side object is split into layers, one per device in the
 *     corresponding device stack. Individual layer is represented by struct
 *     lu_object. Compound layered object --- by struct lu_object_header. Most
 *     interface functions take lu_object as an argument and operate on the
 *     whole compound object. This decision was made due to the following
 *     reasons:
 *
 *        - it's envisaged that lu_object will be used much more often than
 *        lu_object_header;
 *
 *        - we want lower (non-top) layers to be able to initiate operations
 *        on the whole object.
 *
 *     Generic code supports layering more complex than simple stacking, e.g.,
 *     it is possible that at some layer object "spawns" multiple sub-objects
 *     on the lower layer.
 *
 * -# fid-based identification.
 *
 *     Compound object is uniquely identified by its fid. Objects are indexed
 *     by their fids (hash table is used for index).
 *
 * -# caching and life-cycle management.
 *
 *     Object's life-time is controlled by reference counting. When reference
 *     count drops to 0, object is returned to cache. Cached objects still
 *     retain their identity (i.e., fid), and can be recovered from cache.
 *
 *     Objects are kept in the global LRU list, and lu_site_purge() function
 *     can be used to reclaim given number of unused objects from the tail of
 *     the LRU.
 *
 * -# avoiding recursion.
 *
 *     Generic code tries to replace recursion through layers by iterations
 *     where possible. Additionally to the end of reducing stack consumption,
 *     data, when practically possible, are allocated through lu_context_key
 *     interface rather than on stack.
 * @{
 */

struct lu_site;
struct lu_object;
struct lu_device;
struct lu_object_header;
struct lu_context;
struct lu_env;
struct lu_name;

/**
 * Operations common for data and meta-data devices.
 */
struct lu_device_operations {
        /**
         * Allocate object for the given device (without lower-layer
         * parts). This is called by lu_object_operations::loo_object_init()
         * from the parent layer, and should setup at least lu_object::lo_dev
         * and lu_object::lo_ops fields of resulting lu_object.
         *
         * Object creation protocol.
         *
         * Due to design goal of avoiding recursion, object creation (see
         * lu_object_alloc()) is somewhat involved:
         *
         *  - first, lu_device_operations::ldo_object_alloc() method of the
         *  top-level device in the stack is called. It should allocate top
         *  level object (including lu_object_header), but without any
         *  lower-layer sub-object(s).
         *
         *  - then lu_object_alloc() sets fid in the header of newly created
         *  object.
         *
         *  - then lu_object_operations::loo_object_init() is called. It has
         *  to allocate lower-layer object(s). To do this,
         *  lu_object_operations::loo_object_init() calls ldo_object_alloc()
         *  of the lower-layer device(s).
         *
         *  - for all new objects allocated by
         *  lu_object_operations::loo_object_init() (and inserted into object
         *  stack), lu_object_operations::loo_object_init() is called again
         *  repeatedly, until no new objects are created.
         *
         * \post ergo(!IS_ERR(result), result->lo_dev == d &&
         *                             result->lo_ops != NULL);
         */
        struct lu_object *(*ldo_object_alloc)(const struct lu_env *env,
                                              const struct lu_object_header *h,
                                              struct lu_device *d);
        /**
         * process config specific for device.
         */
        int (*ldo_process_config)(const struct lu_env *env,
                                  struct lu_device *, struct lustre_cfg *);
        int (*ldo_recovery_complete)(const struct lu_env *,
                                     struct lu_device *);

        /**
         * initialize local objects for device. this method called after layer has
         * been initialized (after LCFG_SETUP stage) and before it starts serving
         * user requests.
         */

        int (*ldo_prepare)(const struct lu_env *,
                           struct lu_device *parent,
                           struct lu_device *dev);


	/**
	 * Allocate new FID for file with @name under @parent
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dev	dt device
	 * \param[out] fid	new FID allocated
	 * \param[in] parent	parent object
	 * \param[in] name	lu_name
	 *
	 * \retval 0		0 FID allocated successfully.
	 * \retval 1		1 FID allocated successfully and new sequence
	 *                      requested from seq meta server
	 * \retval negative	negative errno if FID allocation failed.
	 */
	int (*ldo_fid_alloc)(const struct lu_env *env,
			     struct lu_device *dev,
			     struct lu_fid *fid,
			     struct lu_object *parent,
			     const struct lu_name *name);
};

/**
 * For lu_object_conf flags
 */
typedef enum {
	/* This is a new object to be allocated, or the file
	 * corresponding to the object does not exists. */
	LOC_F_NEW	= 0x00000001,
} loc_flags_t;

/**
 * Object configuration, describing particulars of object being created. On
 * server this is not used, as server objects are full identified by fid. On
 * client configuration contains struct lustre_md.
 */
struct lu_object_conf {
        /**
         * Some hints for obj find and alloc.
         */
        loc_flags_t     loc_flags;
};

/**
 * Type of "printer" function used by lu_object_operations::loo_object_print()
 * method.
 *
 * Printer function is needed to provide some flexibility in (semi-)debugging
 * output: possible implementations: printk, CDEBUG, sysfs/seq_file
 */
typedef int (*lu_printer_t)(const struct lu_env *env,
                            void *cookie, const char *format, ...)
        __attribute__ ((format (printf, 3, 4)));

/**
 * Operations specific for particular lu_object.
 */
struct lu_object_operations {

        /**
         * Allocate lower-layer parts of the object by calling
         * lu_device_operations::ldo_object_alloc() of the corresponding
         * underlying device.
         *
         * This method is called once for each object inserted into object
         * stack. It's responsibility of this method to insert lower-layer
         * object(s) it create into appropriate places of object stack.
         */
        int (*loo_object_init)(const struct lu_env *env,
                               struct lu_object *o,
                               const struct lu_object_conf *conf);
        /**
         * Called (in top-to-bottom order) during object allocation after all
         * layers were allocated and initialized. Can be used to perform
         * initialization depending on lower layers.
         */
        int (*loo_object_start)(const struct lu_env *env,
                                struct lu_object *o);
        /**
         * Called before lu_object_operations::loo_object_free() to signal
         * that object is being destroyed. Dual to
         * lu_object_operations::loo_object_init().
         */
        void (*loo_object_delete)(const struct lu_env *env,
                                  struct lu_object *o);
	/**
	 * Dual to lu_device_operations::ldo_object_alloc(). Called when
	 * object is removed from memory.  Must use call_rcu or kfree_rcu
	 * if the object contains an lu_object_header.
	 */
	void (*loo_object_free)(const struct lu_env *env,
				struct lu_object *o);
        /**
         * Called when last active reference to the object is released (and
         * object returns to the cache). This method is optional.
         */
        void (*loo_object_release)(const struct lu_env *env,
                                   struct lu_object *o);
        /**
         * Optional debugging helper. Print given object.
         */
        int (*loo_object_print)(const struct lu_env *env, void *cookie,
                                lu_printer_t p, const struct lu_object *o);
        /**
         * Optional debugging method. Returns true iff method is internally
         * consistent.
         */
        int (*loo_object_invariant)(const struct lu_object *o);
};

/**
 * Type of lu_device.
 */
struct lu_device_type;

/**
 * Device: a layer in the server side abstraction stacking.
 */
struct lu_device {
	/**
	 * reference count. This is incremented, in particular, on each object
	 * created at this layer.
	 *
	 * \todo XXX which means that atomic_t is probably too small.
	 */
	atomic_t			   ld_ref;
	/**
	 * Pointer to device type. Never modified once set.
	 */
	struct lu_device_type		  *ld_type;
        /**
         * Operation vector for this device.
         */
        const struct lu_device_operations *ld_ops;
        /**
         * Stack this device belongs to.
         */
        struct lu_site                    *ld_site;
        struct proc_dir_entry             *ld_proc_entry;

        /** \todo XXX: temporary back pointer into obd. */
        struct obd_device                 *ld_obd;
        /**
         * A list of references to this object, for debugging.
         */
        struct lu_ref                      ld_reference;
        /**
         * Link the device to the site.
         **/
	struct list_head		   ld_linkage;
};

struct lu_device_type_operations;

/**
 * Tag bits for device type. They are used to distinguish certain groups of
 * device types.
 */
enum lu_device_tag {
	/** this is meta-data device */
	LU_DEVICE_MD = BIT(0),
	/** this is data device */
	LU_DEVICE_DT = BIT(1),
	/** data device in the client stack */
	LU_DEVICE_CL = BIT(2)
};

/**
 * Type of device.
 */
struct lu_device_type {
        /**
         * Tag bits. Taken from enum lu_device_tag. Never modified once set.
         */
        __u32                                   ldt_tags;
        /**
         * Name of this class. Unique system-wide. Never modified once set.
         */
        char                                   *ldt_name;
        /**
         * Operations for this type.
         */
        const struct lu_device_type_operations *ldt_ops;
        /**
         * \todo XXX: temporary: context tags used by obd_*() calls.
         */
        __u32                                   ldt_ctx_tags;
        /**
         * Number of existing device type instances.
         */
	atomic_t				ldt_device_nr;
};

/**
 * Operations on a device type.
 */
struct lu_device_type_operations {
        /**
         * Allocate new device.
         */
        struct lu_device *(*ldto_device_alloc)(const struct lu_env *env,
                                               struct lu_device_type *t,
                                               struct lustre_cfg *lcfg);
        /**
         * Free device. Dual to
         * lu_device_type_operations::ldto_device_alloc(). Returns pointer to
         * the next device in the stack.
         */
        struct lu_device *(*ldto_device_free)(const struct lu_env *,
                                              struct lu_device *);

        /**
         * Initialize the devices after allocation
         */
        int  (*ldto_device_init)(const struct lu_env *env,
                                 struct lu_device *, const char *,
                                 struct lu_device *);
        /**
         * Finalize device. Dual to
         * lu_device_type_operations::ldto_device_init(). Returns pointer to
         * the next device in the stack.
         */
        struct lu_device *(*ldto_device_fini)(const struct lu_env *env,
                                              struct lu_device *);
        /**
         * Initialize device type. This is called on module load.
         */
        int  (*ldto_init)(struct lu_device_type *t);
        /**
         * Finalize device type. Dual to
         * lu_device_type_operations::ldto_init(). Called on module unload.
         */
        void (*ldto_fini)(struct lu_device_type *t);
        /**
         * Called when the first device is created.
         */
        void (*ldto_start)(struct lu_device_type *t);
        /**
         * Called when number of devices drops to 0.
         */
        void (*ldto_stop)(struct lu_device_type *t);
};

static inline int lu_device_is_md(const struct lu_device *d)
{
	return ergo(d != NULL, d->ld_type->ldt_tags & LU_DEVICE_MD);
}

/**
 * Common object attributes.
 */
struct lu_attr {
	/**
	 * valid bits
	 *
	 * \see enum la_valid
	 */
	__u64		la_valid;
        /** size in bytes */
	__u64		la_size;
	/** modification time in seconds since Epoch */
	s64		la_mtime;
	/** access time in seconds since Epoch */
	s64		la_atime;
	/** change time in seconds since Epoch */
	s64		la_ctime;
	/** create time in seconds since Epoch */
	s64		la_btime;
        /** 512-byte blocks allocated to object */
	__u64		la_blocks;
        /** permission bits and file type */
	__u32		la_mode;
        /** owner id */
	__u32		la_uid;
        /** group id */
	__u32		la_gid;
        /** object flags */
	__u32		la_flags;
        /** number of persistent references to this object */
	__u32		la_nlink;
        /** blk bits of the object*/
	__u32		la_blkbits;
        /** blk size of the object*/
	__u32		la_blksize;
        /** real device */
	__u32		la_rdev;
	/** project id */
	__u32		la_projid;
	/** set layout version to OST objects. */
	__u32		la_layout_version;
	/** dirent count */
	__u64		la_dirent_count;
};

#define LU_DIRENT_COUNT_UNSET	~0ULL

/**
 * Layer in the layered object.
 */
struct lu_object {
        /**
         * Header for this object.
         */
        struct lu_object_header           *lo_header;
        /**
         * Device for this layer.
         */
        struct lu_device                  *lo_dev;
        /**
         * Operations for this object.
         */
        const struct lu_object_operations *lo_ops;
        /**
         * Linkage into list of all layers.
         */
	struct list_head		   lo_linkage;
	/**
	 * Link to the device, for debugging.
	 */
	struct lu_ref_link                 lo_dev_ref;
};

enum lu_object_header_flags {
	/**
	 * Don't keep this object in cache. Object will be destroyed as soon
	 * as last reference to it is released. This flag cannot be cleared
	 * once set.
	 */
	LU_OBJECT_HEARD_BANSHEE = 0,
	/**
	 * Mark this object has already been taken out of cache.
	 */
	LU_OBJECT_UNHASHED	= 1,
	/**
	 * Object is initialized, when object is found in cache, it may not be
	 * intialized yet, the object allocator will initialize it.
	 */
	LU_OBJECT_INITED	= 2,
};

enum lu_object_header_attr {
	LOHA_EXISTS		= BIT(0),
	LOHA_REMOTE		= BIT(1),
	LOHA_HAS_AGENT_ENTRY	= BIT(2),
	/**
	 * UNIX file type is stored in S_IFMT bits.
	 */
	LOHA_FT_START		= 001 << 12, /**< S_IFIFO */
	LOHA_FT_END		= 017 << 12, /**< S_IFMT */
};

/**
 * "Compound" object, consisting of multiple layers.
 *
 * Compound object with given fid is unique with given lu_site.
 *
 * Note, that object does *not* necessary correspond to the real object in the
 * persistent storage: object is an anchor for locking and method calling, so
 * it is created for things like not-yet-existing child created by mkdir or
 * create calls. lu_object_operations::loo_exists() can be used to check
 * whether object is backed by persistent storage entity.
 * Any object containing this structre which might be placed in an
 * rhashtable via loh_hash MUST be freed using call_rcu() or rcu_kfree().
 */
struct lu_object_header {
	/**
	 * Fid, uniquely identifying this object.
	 */
	struct lu_fid		loh_fid;
	/**
	 * Object flags from enum lu_object_header_flags. Set and checked
	 * atomically.
	 */
	unsigned long		loh_flags;
	/**
	 * Object reference count. Protected by lu_site::ls_guard.
	 */
	atomic_t		loh_ref;
	/**
	 * Common object attributes, cached for efficiency. From enum
	 * lu_object_header_attr.
	 */
	__u32			loh_attr;
	/**
	 * Linkage into per-site hash table.
	 */
	struct rhash_head	loh_hash;
	/**
	 * Linkage into per-site LRU list. Protected by lu_site::ls_guard.
	 */
	struct list_head	loh_lru;
	/**
	 * Linkage into list of layers. Never modified once set (except lately
	 * during object destruction). No locking is necessary.
	 */
	struct list_head	loh_layers;
	/**
	 * A list of references to this object, for debugging.
	 */
	struct lu_ref		loh_reference;
	/*
	 * Handle used for kfree_rcu() or similar.
	 */
	struct rcu_head		loh_rcu;
};

struct fld;

enum {
	LU_SS_CREATED		= 0,
	LU_SS_CACHE_HIT,
	LU_SS_CACHE_MISS,
	LU_SS_CACHE_RACE,
	LU_SS_CACHE_DEATH_RACE,
	LU_SS_LRU_PURGED,
	LU_SS_LAST_STAT
};

/**
 * lu_site is a "compartment" within which objects are unique, and LRU
 * discipline is maintained.
 *
 * lu_site exists so that multiple layered stacks can co-exist in the same
 * address space.
 *
 * lu_site has the same relation to lu_device as lu_object_header to
 * lu_object.
 */
struct lu_site {
        /**
         * objects hash table
         */
	struct rhashtable	ls_obj_hash;
	/*
	 * buckets for summary data
	 */
	struct lu_site_bkt_data	*ls_bkts;
	int			ls_bkt_cnt;
	u32			ls_bkt_seed;
        /**
         * index of bucket on hash table while purging
         */
	unsigned int		ls_purge_start;
	/**
	 * Top-level device for this stack.
	 */
	struct lu_device	*ls_top_dev;
	/**
	 * Bottom-level device for this stack
	 */
	struct lu_device	*ls_bottom_dev;
	/**
	 * Linkage into global list of sites.
	 */
	struct list_head	ls_linkage;
	/**
	 * List for lu device for this site, protected
	 * by ls_ld_lock.
	 **/
	struct list_head	ls_ld_linkage;
	spinlock_t		ls_ld_lock;
	/**
	 * Lock to serialize site purge.
	 */
	struct mutex		ls_purge_mutex;
	/**
	 * lu_site stats
	 */
	struct lprocfs_stats	*ls_stats;
	/**
	 * XXX: a hack! fld has to find md_site via site, remove when possible
	 */
	struct seq_server_site	*ld_seq_site;
	/**
	 * Pointer to the lu_target for this site.
	 */
	struct lu_target	*ls_tgt;

	/**
	 * Number of objects in lsb_lru_lists - used for shrinking
	 */
	struct percpu_counter   ls_lru_len_counter;
};

wait_queue_head_t *
lu_site_wq_from_fid(struct lu_site *site, struct lu_fid *fid);

static inline struct seq_server_site *lu_site2seq(const struct lu_site *s)
{
	return s->ld_seq_site;
}

/** \name ctors
 * Constructors/destructors.
 * @{
 */

int  lu_site_init         (struct lu_site *s, struct lu_device *d);
void lu_site_fini         (struct lu_site *s);
int  lu_site_init_finish  (struct lu_site *s);
void lu_stack_fini        (const struct lu_env *env, struct lu_device *top);
void lu_device_get        (struct lu_device *d);
void lu_device_put        (struct lu_device *d);
int  lu_device_init       (struct lu_device *d, struct lu_device_type *t);
void lu_device_fini       (struct lu_device *d);
int  lu_object_header_init(struct lu_object_header *h);
void lu_object_header_fini(struct lu_object_header *h);
void lu_object_header_free(struct lu_object_header *h);
int  lu_object_init       (struct lu_object *o,
                           struct lu_object_header *h, struct lu_device *d);
void lu_object_fini       (struct lu_object *o);
void lu_object_add_top    (struct lu_object_header *h, struct lu_object *o);
void lu_object_add        (struct lu_object *before, struct lu_object *o);
struct lu_object *lu_object_get_first(struct lu_object_header *h,
				      struct lu_device *dev);
void lu_dev_add_linkage(struct lu_site *s, struct lu_device *d);
void lu_dev_del_linkage(struct lu_site *s, struct lu_device *d);

/**
 * Helpers to initialize and finalize device types.
 */

int  lu_device_type_init(struct lu_device_type *ldt);
void lu_device_type_fini(struct lu_device_type *ldt);

/** @} ctors */

/** \name caching
 * Caching and reference counting.
 * @{
 */

/**
 * Acquire additional reference to the given object. This function is used to
 * attain additional reference. To acquire initial reference use
 * lu_object_find().
 */
static inline void lu_object_get(struct lu_object *o)
{
	LASSERT(atomic_read(&o->lo_header->loh_ref) > 0);
	atomic_inc(&o->lo_header->loh_ref);
}

/**
 * Return true if object will not be cached after last reference to it is
 * released.
 */
static inline int lu_object_is_dying(const struct lu_object_header *h)
{
	return test_bit(LU_OBJECT_HEARD_BANSHEE, &h->loh_flags);
}

/**
 * Return true if object is initialized.
 */
static inline int lu_object_is_inited(const struct lu_object_header *h)
{
	return test_bit(LU_OBJECT_INITED, &h->loh_flags);
}

void lu_object_put(const struct lu_env *env, struct lu_object *o);
void lu_object_put_nocache(const struct lu_env *env, struct lu_object *o);
void lu_object_unhash(const struct lu_env *env, struct lu_object *o);
int lu_site_purge_objects(const struct lu_env *env, struct lu_site *s, int nr,
			  int canblock);

static inline int lu_site_purge(const struct lu_env *env, struct lu_site *s,
				int nr)
{
	return lu_site_purge_objects(env, s, nr, 1);
}

void lu_site_print(const struct lu_env *env, struct lu_site *s, atomic_t *ref,
		   int msg_flags, lu_printer_t printer);
struct lu_object *lu_object_find(const struct lu_env *env,
                                 struct lu_device *dev, const struct lu_fid *f,
                                 const struct lu_object_conf *conf);
struct lu_object *lu_object_find_at(const struct lu_env *env,
                                    struct lu_device *dev,
                                    const struct lu_fid *f,
                                    const struct lu_object_conf *conf);
struct lu_object *lu_object_find_slice(const struct lu_env *env,
                                       struct lu_device *dev,
                                       const struct lu_fid *f,
                                       const struct lu_object_conf *conf);
/** @} caching */

/** \name helpers
 * Helpers.
 * @{
 */

/**
 * First (topmost) sub-object of given compound object
 */
static inline struct lu_object *lu_object_top(struct lu_object_header *h)
{
	LASSERT(!list_empty(&h->loh_layers));
	return container_of(h->loh_layers.next, struct lu_object, lo_linkage);
}

/**
 * Next sub-object in the layering
 */
static inline struct lu_object *lu_object_next(const struct lu_object *o)
{
	return container_of(o->lo_linkage.next, struct lu_object, lo_linkage);
}

/**
 * Pointer to the fid of this object.
 */
static inline const struct lu_fid *lu_object_fid(const struct lu_object *o)
{
        return &o->lo_header->loh_fid;
}

/**
 * return device operations vector for this object
 */
static const inline struct lu_device_operations *
lu_object_ops(const struct lu_object *o)
{
        return o->lo_dev->ld_ops;
}

/**
 * Given a compound object, find its slice, corresponding to the device type
 * \a dtype.
 */
struct lu_object *lu_object_locate(struct lu_object_header *h,
                                   const struct lu_device_type *dtype);

/**
 * Printer function emitting messages through libcfs_debug_msg().
 */
int lu_cdebug_printer(const struct lu_env *env,
                      void *cookie, const char *format, ...);

/**
 * Print object description followed by a user-supplied message.
 */
#define LU_OBJECT_DEBUG(mask, env, object, format, ...)                   \
do {                                                                      \
        if (cfs_cdebug_show(mask, DEBUG_SUBSYSTEM)) {                     \
                LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, mask, NULL);          \
                lu_object_print(env, &msgdata, lu_cdebug_printer, object);\
                CDEBUG(mask, format "\n", ## __VA_ARGS__);                \
        }                                                                 \
} while (0)

/**
 * Print short object description followed by a user-supplied message.
 */
#define LU_OBJECT_HEADER(mask, env, object, format, ...)                \
do {                                                                    \
        if (cfs_cdebug_show(mask, DEBUG_SUBSYSTEM)) {                   \
                LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, mask, NULL);        \
                lu_object_header_print(env, &msgdata, lu_cdebug_printer,\
                                       (object)->lo_header);            \
                lu_cdebug_printer(env, &msgdata, "\n");                 \
                CDEBUG(mask, format , ## __VA_ARGS__);                  \
        }                                                               \
} while (0)

void lu_object_print       (const struct lu_env *env, void *cookie,
                            lu_printer_t printer, const struct lu_object *o);
void lu_object_header_print(const struct lu_env *env, void *cookie,
                            lu_printer_t printer,
                            const struct lu_object_header *hdr);

/**
 * Check object consistency.
 */
int lu_object_invariant(const struct lu_object *o);


/**
 * Check whether object exists, no matter on local or remote storage.
 * Note: LOHA_EXISTS will be set once some one created the object,
 * and it does not needs to be committed to storage.
 */
#define lu_object_exists(o) ((o)->lo_header->loh_attr & LOHA_EXISTS)

/**
 * Check whether object on the remote storage.
 */
#define lu_object_remote(o) unlikely((o)->lo_header->loh_attr & LOHA_REMOTE)

/**
 * Check whether the object as agent entry on current target
 */
#define lu_object_has_agent_entry(o) \
	unlikely((o)->lo_header->loh_attr & LOHA_HAS_AGENT_ENTRY)

static inline void lu_object_set_agent_entry(struct lu_object *o)
{
	o->lo_header->loh_attr |= LOHA_HAS_AGENT_ENTRY;
}

static inline void lu_object_clear_agent_entry(struct lu_object *o)
{
	o->lo_header->loh_attr &= ~LOHA_HAS_AGENT_ENTRY;
}

static inline int lu_object_assert_exists(const struct lu_object *o)
{
	return lu_object_exists(o);
}

static inline int lu_object_assert_not_exists(const struct lu_object *o)
{
	return !lu_object_exists(o);
}

/**
 * Attr of this object.
 */
static inline __u32 lu_object_attr(const struct lu_object *o)
{
	LASSERT(lu_object_exists(o) != 0);

	return o->lo_header->loh_attr & S_IFMT;
}

static inline void lu_object_ref_add(struct lu_object *o,
				     const char *scope,
				     const void *source)
{
	lu_ref_add(&o->lo_header->loh_reference, scope, source);
}

static inline void lu_object_ref_add_at(struct lu_object *o,
					struct lu_ref_link *link,
					const char *scope,
					const void *source)
{
	lu_ref_add_at(&o->lo_header->loh_reference, link, scope, source);
}

static inline void lu_object_ref_del(struct lu_object *o,
                                     const char *scope, const void *source)
{
        lu_ref_del(&o->lo_header->loh_reference, scope, source);
}

static inline void lu_object_ref_del_at(struct lu_object *o,
                                        struct lu_ref_link *link,
                                        const char *scope, const void *source)
{
        lu_ref_del_at(&o->lo_header->loh_reference, link, scope, source);
}

/** input params, should be filled out by mdt */
struct lu_rdpg {
        /** hash */
        __u64                   rp_hash;
        /** count in bytes */
        unsigned int            rp_count;
        /** number of pages */
        unsigned int            rp_npages;
        /** requested attr */
        __u32                   rp_attrs;
        /** pointers to pages */
        struct page           **rp_pages;
};

enum lu_xattr_flags {
	LU_XATTR_REPLACE = BIT(0),
	LU_XATTR_CREATE  = BIT(1),
	LU_XATTR_MERGE   = BIT(2),
	LU_XATTR_SPLIT   = BIT(3),
	LU_XATTR_PURGE   = BIT(4),
};

/** @} helpers */

/** \name lu_context
 * @{ */

/** For lu_context health-checks */
enum lu_context_state {
        LCS_INITIALIZED = 1,
        LCS_ENTERED,
	LCS_LEAVING,
        LCS_LEFT,
        LCS_FINALIZED
};

/**
 * lu_context. Execution context for lu_object methods. Currently associated
 * with thread.
 *
 * All lu_object methods, except device and device type methods (called during
 * system initialization and shutdown) are executed "within" some
 * lu_context. This means, that pointer to some "current" lu_context is passed
 * as an argument to all methods.
 *
 * All service ptlrpc threads create lu_context as part of their
 * initialization. It is possible to create "stand-alone" context for other
 * execution environments (like system calls).
 *
 * lu_object methods mainly use lu_context through lu_context_key interface
 * that allows each layer to associate arbitrary pieces of data with each
 * context (see pthread_key_create(3) for similar interface).
 *
 * On a client, lu_context is bound to a thread, see cl_env_get().
 *
 * \see lu_context_key
 */
struct lu_context {
        /**
         * lu_context is used on the client side too. Yet we don't want to
         * allocate values of server-side keys for the client contexts and
         * vice versa.
         *
         * To achieve this, set of tags in introduced. Contexts and keys are
         * marked with tags. Key value are created only for context whose set
         * of tags has non-empty intersection with one for key. Tags are taken
         * from enum lu_context_tag.
         */
        __u32                  lc_tags;
	enum lu_context_state  lc_state;
        /**
         * Pointer to the home service thread. NULL for other execution
         * contexts.
         */
        struct ptlrpc_thread  *lc_thread;
        /**
         * Pointer to an array with key values. Internal implementation
         * detail.
         */
	void		      **lc_value;
	/**
	 * Linkage into a list of all remembered contexts. Only
	 * `non-transient' contexts, i.e., ones created for service threads
	 * are placed here.
	 */
	struct list_head	lc_remember;
	/**
	 * Version counter used to skip calls to lu_context_refill() when no
	 * keys were registered.
	 */
	unsigned		lc_version;
        /**
         * Debugging cookie.
         */
	unsigned		lc_cookie;
};

/**
 * lu_context_key interface. Similar to pthread_key.
 */

enum lu_context_tag {
	/**
	 * Thread on md server
	 */
	LCT_MD_THREAD		= BIT(0),
	/**
	 * Thread on dt server
	 */
	LCT_DT_THREAD		= BIT(1),
	/**
	 * Thread on client
	 */
	LCT_CL_THREAD		= BIT(3),
	/**
	 * A per-request session on a server, and a per-system-call session on
	 * a client.
	 */
	LCT_SESSION		= BIT(4),
	/**
	 * A per-request data on OSP device
	 */
	LCT_OSP_THREAD		= BIT(5),
	/**
	 * MGS device thread
	 */
	LCT_MG_THREAD		= BIT(6),
	/**
	 * Context for local operations
	 */
	LCT_LOCAL		= BIT(7),
	/**
	 * session for server thread
	 **/
	LCT_SERVER_SESSION	= BIT(8),
	/**
	 * Set when at least one of keys, having values in this context has
	 * non-NULL lu_context_key::lct_exit() method. This is used to
	 * optimize lu_context_exit() call.
	 */
	LCT_HAS_EXIT		= BIT(28),
	/**
	 * Don't add references for modules creating key values in that context.
	 * This is only for contexts used internally by lu_object framework.
	 */
	LCT_NOREF		= BIT(29),
	/**
	 * Key is being prepared for retiring, don't create new values for it.
	 */
	LCT_QUIESCENT		= BIT(30),
	/**
	 * Context should be remembered.
	 */
	LCT_REMEMBER		= BIT(31),
	/**
	 * Contexts usable in cache shrinker thread.
	 */
	LCT_SHRINKER	= LCT_MD_THREAD|LCT_DT_THREAD|LCT_CL_THREAD|LCT_NOREF,
};

/**
 * Key. Represents per-context value slot.
 *
 * Keys are usually registered when module owning the key is initialized, and
 * de-registered when module is unloaded. Once key is registered, all new
 * contexts with matching tags, will get key value. "Old" contexts, already
 * initialized at the time of key registration, can be forced to get key value
 * by calling lu_context_refill().
 *
 * Every key value is counted in lu_context_key::lct_used and acquires a
 * reference on an owning module. This means, that all key values have to be
 * destroyed before module can be unloaded. This is usually achieved by
 * stopping threads started by the module, that created contexts in their
 * entry functions. Situation is complicated by the threads shared by multiple
 * modules, like ptlrpcd daemon on a client. To work around this problem,
 * contexts, created in such threads, are `remembered' (see
 * LCT_REMEMBER)---i.e., added into a global list. When module is preparing
 * for unloading it does the following:
 *
 *     - marks its keys as `quiescent' (lu_context_tag::LCT_QUIESCENT)
 *       preventing new key values from being allocated in the new contexts,
 *       and
 *
 *     - scans a list of remembered contexts, destroying values of module
 *       keys, thus releasing references to the module.
 *
 * This is done by lu_context_key_quiesce(). If module is re-activated
 * before key has been de-registered, lu_context_key_revive() call clears
 * `quiescent' marker.
 *
 * lu_context code doesn't provide any internal synchronization for these
 * activities---it's assumed that startup (including threads start-up) and
 * shutdown are serialized by some external means.
 *
 * \see lu_context
 */
struct lu_context_key {
        /**
         * Set of tags for which values of this key are to be instantiated.
         */
        __u32 lct_tags;
        /**
         * Value constructor. This is called when new value is created for a
         * context. Returns pointer to new value of error pointer.
         */
        void  *(*lct_init)(const struct lu_context *ctx,
                           struct lu_context_key *key);
        /**
         * Value destructor. Called when context with previously allocated
         * value of this slot is destroyed. \a data is a value that was returned
         * by a matching call to lu_context_key::lct_init().
         */
        void   (*lct_fini)(const struct lu_context *ctx,
                           struct lu_context_key *key, void *data);
        /**
         * Optional method called on lu_context_exit() for all allocated
         * keys. Can be used by debugging code checking that locks are
         * released, etc.
         */
        void   (*lct_exit)(const struct lu_context *ctx,
                           struct lu_context_key *key, void *data);
	/**
	 * Internal implementation detail: index within lu_context::lc_value[]
	 * reserved for this key.
	 */
	int		lct_index;
	/**
	 * Internal implementation detail: number of values created for this
	 * key.
	 */
	atomic_t	lct_used;
	/**
	 * Internal implementation detail: module for this key.
	 */
	struct module	*lct_owner;
	/**
	 * References to this key. For debugging.
	 */
	struct lu_ref	lct_reference;
};

#define LU_KEY_INIT(mod, type)                                    \
	static void *mod##_key_init(const struct lu_context *ctx, \
				    struct lu_context_key *key)   \
	{                                                         \
		type *value;                                      \
                                                                  \
		BUILD_BUG_ON(PAGE_SIZE < sizeof(*value));	  \
                                                                  \
		OBD_ALLOC_PTR(value);                             \
		if (value == NULL)                                \
			value = ERR_PTR(-ENOMEM);                 \
								  \
		return value;                                     \
	}                                                         \
	struct __##mod##__dummy_init { ; } /* semicolon catcher */

#define LU_KEY_FINI(mod, type)                                              \
        static void mod##_key_fini(const struct lu_context *ctx,            \
                                    struct lu_context_key *key, void* data) \
        {                                                                   \
                type *info = data;                                          \
                                                                            \
                OBD_FREE_PTR(info);                                         \
        }                                                                   \
        struct __##mod##__dummy_fini {;} /* semicolon catcher */

#define LU_KEY_INIT_FINI(mod, type)   \
        LU_KEY_INIT(mod,type);        \
        LU_KEY_FINI(mod,type)

#define LU_CONTEXT_KEY_DEFINE(mod, tags)                \
        struct lu_context_key mod##_thread_key = {      \
                .lct_tags = tags,                       \
                .lct_init = mod##_key_init,             \
                .lct_fini = mod##_key_fini              \
        }

#define LU_CONTEXT_KEY_INIT(key)                        \
do {                                                    \
        (key)->lct_owner = THIS_MODULE;                 \
} while (0)

int   lu_context_key_register(struct lu_context_key *key);
void  lu_context_key_degister(struct lu_context_key *key);
void *lu_context_key_get     (const struct lu_context *ctx,
                               const struct lu_context_key *key);
void  lu_context_key_quiesce(struct lu_device_type *t,
			     struct lu_context_key *key);
void  lu_context_key_revive(struct lu_context_key *key);


/*
 * LU_KEY_INIT_GENERIC() has to be a macro to correctly determine an
 * owning module.
 */

#define LU_KEY_INIT_GENERIC(mod)                                        \
        static void mod##_key_init_generic(struct lu_context_key *k, ...) \
        {                                                               \
                struct lu_context_key *key = k;                         \
                va_list args;                                           \
                                                                        \
                va_start(args, k);                                      \
                do {                                                    \
                        LU_CONTEXT_KEY_INIT(key);                       \
                        key = va_arg(args, struct lu_context_key *);    \
                } while (key != NULL);                                  \
                va_end(args);                                           \
        }

#define LU_TYPE_INIT(mod, ...)                                          \
        LU_KEY_INIT_GENERIC(mod)                                        \
        static int mod##_type_init(struct lu_device_type *t)            \
        {                                                               \
                mod##_key_init_generic(__VA_ARGS__, NULL);              \
                return lu_context_key_register_many(__VA_ARGS__, NULL); \
        }                                                               \
        struct __##mod##_dummy_type_init {;}

#define LU_TYPE_FINI(mod, ...)                                          \
        static void mod##_type_fini(struct lu_device_type *t)           \
        {                                                               \
                lu_context_key_degister_many(__VA_ARGS__, NULL);        \
        }                                                               \
        struct __##mod##_dummy_type_fini {;}

#define LU_TYPE_START(mod, ...)                                 \
        static void mod##_type_start(struct lu_device_type *t)  \
        {                                                       \
                lu_context_key_revive_many(__VA_ARGS__, NULL);  \
        }                                                       \
        struct __##mod##_dummy_type_start {;}

#define LU_TYPE_STOP(mod, ...)                                     \
	static void mod##_type_stop(struct lu_device_type *t)      \
	{                                                          \
		lu_context_key_quiesce_many(t, __VA_ARGS__, NULL); \
	}                                                          \
	struct __##mod##_dummy_type_stop { }



#define LU_TYPE_INIT_FINI(mod, ...)             \
        LU_TYPE_INIT(mod, __VA_ARGS__);         \
        LU_TYPE_FINI(mod, __VA_ARGS__);         \
        LU_TYPE_START(mod, __VA_ARGS__);        \
        LU_TYPE_STOP(mod, __VA_ARGS__)

int   lu_context_init  (struct lu_context *ctx, __u32 tags);
void  lu_context_fini  (struct lu_context *ctx);
void  lu_context_enter (struct lu_context *ctx);
void  lu_context_exit  (struct lu_context *ctx);
int   lu_context_refill(struct lu_context *ctx);

/*
 * Helper functions to operate on multiple keys. These are used by the default
 * device type operations, defined by LU_TYPE_INIT_FINI().
 */

int  lu_context_key_register_many(struct lu_context_key *k, ...);
void lu_context_key_degister_many(struct lu_context_key *k, ...);
void lu_context_key_revive_many  (struct lu_context_key *k, ...);
void lu_context_key_quiesce_many(struct lu_device_type *t,
				 struct lu_context_key *k, ...);

/*
 * update/clear ctx/ses tags.
 */
void lu_context_tags_update(__u32 tags);
void lu_context_tags_clear(__u32 tags);
void lu_session_tags_update(__u32 tags);
void lu_session_tags_clear(__u32 tags);

/**
 * Environment.
 */
struct lu_env {
        /**
         * "Local" context, used to store data instead of stack.
         */
        struct lu_context  le_ctx;
        /**
         * "Session" context for per-request data.
         */
        struct lu_context *le_ses;
};

int  lu_env_init  (struct lu_env *env, __u32 tags);
void lu_env_fini  (struct lu_env *env);
int  lu_env_refill(struct lu_env *env);
int  lu_env_refill_by_tags(struct lu_env *env, __u32 ctags, __u32 stags);

static inline void* lu_env_info(const struct lu_env *env,
				const struct lu_context_key *key)
{
	void *info;
	info = lu_context_key_get(&env->le_ctx, key);
	if (!info) {
		if (!lu_env_refill((struct lu_env *)env))
			info = lu_context_key_get(&env->le_ctx, key);
	}
	LASSERT(info);
	return info;
}

struct lu_env *lu_env_find(void);
int lu_env_add(struct lu_env *env);
int lu_env_add_task(struct lu_env *env, struct task_struct *task);
void lu_env_remove(struct lu_env *env);

/** @} lu_context */

/**
 * Output site statistical counters into a buffer. Suitable for
 * ll_rd_*()-style functions.
 */
int lu_site_stats_seq_print(const struct lu_site *s, struct seq_file *m);

/**
 * Common name structure to be passed around for various name related methods.
 */
struct lu_name {
        const char    *ln_name;
        int            ln_namelen;
};

static inline bool name_is_dot_or_dotdot(const char *name, int namelen)
{
	return name[0] == '.' &&
	       (namelen == 1 || (namelen == 2 && name[1] == '.'));
}

static inline bool lu_name_is_dot_or_dotdot(const struct lu_name *lname)
{
	return name_is_dot_or_dotdot(lname->ln_name, lname->ln_namelen);
}

static inline bool lu_name_is_temp_file(const char *name, int namelen,
					bool dot_prefix, int suffixlen)
{
	int lower = 0;
	int upper = 0;
	int digit = 0;
	int len = suffixlen;

	if (dot_prefix && name[0] != '.')
		return false;

	if (namelen < dot_prefix + suffixlen + 2 ||
	    name[namelen - suffixlen - 1] != '.')
		return false;

	while (len) {
		lower += islower(name[namelen - len]);
		upper += isupper(name[namelen - len]);
		digit += isdigit(name[namelen - len]);
		len--;
	}
	/* mktemp() filename suffixes will have a mix of upper- and lower-case
	 * letters and/or numbers, not all numbers, or all upper or lower-case.
	 * About 0.07% of randomly-generated names will slip through,
	 * but this avoids 99.93% of cross-MDT renames for those files.
	 */
	if ((digit >= suffixlen - 1 && !isdigit(name[namelen - suffixlen])) ||
	    upper == suffixlen || lower == suffixlen)
		return false;

	return true;
}

static inline bool lu_name_is_backup_file(const char *name, int namelen,
					  int *suffixlen)
{
	if (namelen > 1 &&
	    name[namelen - 2] != '.' && name[namelen - 1] == '~') {
		if (suffixlen)
			*suffixlen = 1;
		return true;
	}

	if (namelen > 4 && name[namelen - 4] == '.' &&
	    (!strncasecmp(name + namelen - 3, "bak", 3) ||
	     !strncasecmp(name + namelen - 3, "sav", 3))) {
		if (suffixlen)
			*suffixlen = 4;
		return true;
	}

	if (namelen > 5 && name[namelen - 5] == '.' &&
	    !strncasecmp(name + namelen - 4, "orig", 4)) {
		if (suffixlen)
			*suffixlen = 5;
		return true;
	}

	return false;
}

static inline bool lu_name_is_valid_len(const char *name, size_t name_len)
{
	return name != NULL &&
	       name_len > 0 &&
	       name_len < INT_MAX &&
	       strlen(name) == name_len &&
	       memchr(name, '/', name_len) == NULL;
}

/**
 * Validate names (path components)
 *
 * To be valid \a name must be non-empty, '\0' terminated of length \a
 * name_len, and not contain '/'. The maximum length of a name (before
 * say -ENAMETOOLONG will be returned) is really controlled by llite
 * and the server. We only check for something insane coming from bad
 * integer handling here.
 */
static inline bool lu_name_is_valid_2(const char *name, size_t name_len)
{
	return lu_name_is_valid_len(name, name_len) && name[name_len] == '\0';
}

static inline bool lu_name_is_valid(const struct lu_name *ln)
{
	return lu_name_is_valid_2(ln->ln_name, ln->ln_namelen);
}

#define DNAME "%.*s"
#define PNAME(ln)					\
	(lu_name_is_valid(ln) ? (ln)->ln_namelen : 0),	\
	(lu_name_is_valid(ln) ? (ln)->ln_name : "")

/**
 * Common buffer structure to be passed around for various xattr_{s,g}et()
 * methods.
 */
struct lu_buf {
	void   *lb_buf;
	size_t  lb_len;
};

#define DLUBUF "(%p %zu)"
#define PLUBUF(buf) (buf)->lb_buf, (buf)->lb_len

/* read buffer params, should be filled out by out */
struct lu_rdbuf {
	/** number of buffers */
	unsigned int	rb_nbufs;
	/** pointers to buffers */
	struct lu_buf	rb_bufs[];
};

/**
 * One-time initializers, called at obdclass module initialization, not
 * exported.
 */

/**
 * Initialization of global lu_* data.
 */
int lu_global_init(void);

/**
 * Dual to lu_global_init().
 */
void lu_global_fini(void);

struct lu_kmem_descr {
	struct kmem_cache **ckd_cache;
        const char       *ckd_name;
        const size_t      ckd_size;
};

int  lu_kmem_init(struct lu_kmem_descr *caches);
void lu_kmem_fini(struct lu_kmem_descr *caches);

void lu_object_assign_fid(const struct lu_env *env, struct lu_object *o,
			  const struct lu_fid *fid);
struct lu_object *lu_object_anon(const struct lu_env *env,
				 struct lu_device *dev,
				 const struct lu_object_conf *conf);

/** null buffer */
extern struct lu_buf LU_BUF_NULL;

void lu_buf_free(struct lu_buf *buf);
void lu_buf_alloc(struct lu_buf *buf, size_t size);
void lu_buf_realloc(struct lu_buf *buf, size_t size);

int lu_buf_check_and_grow(struct lu_buf *buf, size_t len);
struct lu_buf *lu_buf_check_and_alloc(struct lu_buf *buf, size_t len);

extern __u32 lu_context_tags_default;
extern __u32 lu_session_tags_default;

static inline bool lu_device_is_cl(const struct lu_device *d)
{
	return d->ld_type->ldt_tags & LU_DEVICE_CL;
}

static inline bool lu_object_is_cl(const struct lu_object *o)
{
	return lu_device_is_cl(o->lo_dev);
}

/* Generic subset of tgts */
struct lu_tgt_pool {
	__u32		   *op_array;	/* array of index of
					 * lov_obd->lov_tgts
					 */
	unsigned int	    op_count;	/* number of tgts in the array */
	unsigned int	    op_size;	/* allocated size of op_array */
	struct rw_semaphore op_rw_sem;	/* to protect lu_tgt_pool use */
};

int lu_tgt_pool_init(struct lu_tgt_pool *op, unsigned int count);
int lu_tgt_pool_add(struct lu_tgt_pool *op, __u32 idx, unsigned int min_count);
int lu_tgt_pool_remove(struct lu_tgt_pool *op, __u32 idx);
int lu_tgt_pool_free(struct lu_tgt_pool *op);
int lu_tgt_check_index(int idx, struct lu_tgt_pool *osts);
int lu_tgt_pool_extend(struct lu_tgt_pool *op, unsigned int min_count);

/* bitflags used in rr / qos allocation */
enum lq_flag {
	LQ_DIRTY	= 0, /* recalc qos data */
	LQ_SAME_SPACE,	     /* the OSTs all have approx.
			      * the same space avail */
	LQ_RESET,	     /* zero current penalties */
};

#ifdef HAVE_SERVER_SUPPORT
/* round-robin QoS data for LOD/LMV */
struct lu_qos_rr {
	spinlock_t		 lqr_alloc;	/* protect allocation index */
	__u32			 lqr_start_idx;	/* start index of new inode */
	__u32			 lqr_offset_idx;/* aliasing for start_idx */
	int			 lqr_start_count;/* reseed counter */
	struct lu_tgt_pool	 lqr_pool;	/* round-robin optimized list */
	unsigned long		 lqr_flags;
};

static inline void lu_qos_rr_init(struct lu_qos_rr *lqr)
{
	spin_lock_init(&lqr->lqr_alloc);
	set_bit(LQ_DIRTY, &lqr->lqr_flags);
}

#endif /* HAVE_SERVER_SUPPORT */

/* QoS data per MDS/OSS */
struct lu_svr_qos {
	struct obd_uuid		 lsq_uuid;	/* ptlrpc's c_remote_uuid */
	struct list_head	 lsq_svr_list;	/* link to lq_svr_list */
	__u64			 lsq_bavail;	/* total bytes avail on svr */
	__u64			 lsq_iavail;	/* tital inode avail on svr */
	__u64			 lsq_penalty;	/* current penalty */
	__u64			 lsq_penalty_per_obj; /* penalty decrease
						       * every obj*/
	time64_t		 lsq_used;	/* last used time, seconds */
	__u32			 lsq_tgt_count;	/* number of tgts on this svr */
	__u32			 lsq_id;	/* unique svr id */
};

/* QoS data per MDT/OST */
struct lu_tgt_qos {
	struct lu_svr_qos	*ltq_svr;	/* svr info */
	__u64			 ltq_penalty;	/* current penalty */
	__u64			 ltq_penalty_per_obj; /* penalty decrease
						       * every obj*/
	__u64			 ltq_weight;	/* net weighting */
	time64_t		 ltq_used;	/* last used time, seconds */
	bool			 ltq_usable:1;	/* usable for striping */
};

/* target descriptor */
#define LOV_QOS_DEF_THRESHOLD_RR_PCT	17
#define LMV_QOS_DEF_THRESHOLD_RR_PCT	5

#define LOV_QOS_DEF_PRIO_FREE		90
#define LMV_QOS_DEF_PRIO_FREE		90

struct lu_tgt_desc {
	union {
		struct dt_device	*ltd_tgt;
		struct obd_device	*ltd_obd;
	};
	struct obd_export *ltd_exp;
	struct obd_uuid    ltd_uuid;
	__u32              ltd_index;
	__u32		   ltd_gen;
	struct list_head   ltd_kill;
	struct task_struct *ltd_recovery_task;
	struct mutex	   ltd_fid_mutex;
	struct lu_tgt_qos  ltd_qos; /* qos info per target */
	struct obd_statfs  ltd_statfs;
	time64_t	   ltd_statfs_age;
	unsigned long      ltd_active:1,/* is this target up for requests */
			   ltd_activate:1,/* should target be activated */
			   ltd_reap:1,  /* should this target be deleted */
			   ltd_got_update_log:1, /* Already got update log */
			   ltd_connecting:1; /* target is connecting */
};

/* number of pointers at 2nd level */
#define TGT_PTRS_PER_BLOCK	(PAGE_SIZE / sizeof(void *))
/* number of pointers at 1st level - only need as many as max OST/MDT count */
#define TGT_PTRS		((LOV_ALL_STRIPES + 1) / TGT_PTRS_PER_BLOCK)

struct lu_tgt_desc_idx {
	struct lu_tgt_desc *ldi_tgt[TGT_PTRS_PER_BLOCK];
};

/* QoS data for LOD/LMV */
struct lu_qos {
	struct list_head	 lq_svr_list;	/* lu_svr_qos list */
	struct rw_semaphore	 lq_rw_sem;
	__u32			 lq_active_svr_count;
	unsigned int		 lq_prio_free;   /* priority for free space */
	unsigned int		 lq_threshold_rr;/* priority for rr */
#ifdef HAVE_SERVER_SUPPORT
	struct lu_qos_rr	 lq_rr;          /* round robin qos data */
#endif
	unsigned long		 lq_flags;
#if 0
	unsigned long		 lq_dirty:1,     /* recalc qos data */
				 lq_same_space:1,/* the servers all have approx.
						  * the same space avail */
				 lq_reset:1;     /* zero current penalties */
#endif
};

struct lu_tgt_descs {
	union {
		struct lov_desc	      ltd_lov_desc;
		struct lmv_desc	      ltd_lmv_desc;
	};
	/* list of known TGTs */
	struct lu_tgt_desc_idx	*ltd_tgt_idx[TGT_PTRS];
	/* Size of the lu_tgts array, granted to be a power of 2 */
	__u32			ltd_tgts_size;
	/* bitmap of TGTs available */
	unsigned long		*ltd_tgt_bitmap;
	/* TGTs scheduled to be deleted */
	__u32			ltd_death_row;
	/* Table refcount used for delayed deletion */
	int			ltd_refcount;
	/* mutex to serialize concurrent updates to the tgt table */
	struct mutex		ltd_mutex;
	/* read/write semaphore used for array relocation */
	struct rw_semaphore	ltd_rw_sem;
	/* QoS */
	struct lu_qos		ltd_qos;
	/* all tgts in a packed array */
	struct lu_tgt_pool	ltd_tgt_pool;
	/* true if tgt is MDT */
	bool			ltd_is_mdt;
};

#define LTD_TGT(ltd, index)						\
	 (ltd)->ltd_tgt_idx[(index) / TGT_PTRS_PER_BLOCK]->		\
		ldi_tgt[(index) % TGT_PTRS_PER_BLOCK]

u64 lu_prandom_u64_max(u64 ep_ro);
int lu_qos_add_tgt(struct lu_qos *qos, struct lu_tgt_desc *ltd);
void lu_tgt_qos_weight_calc(struct lu_tgt_desc *tgt);

int lu_tgt_descs_init(struct lu_tgt_descs *ltd, bool is_mdt);
void lu_tgt_descs_fini(struct lu_tgt_descs *ltd);
int ltd_add_tgt(struct lu_tgt_descs *ltd, struct lu_tgt_desc *tgt);
void ltd_del_tgt(struct lu_tgt_descs *ltd, struct lu_tgt_desc *tgt);
int ltd_qos_penalties_calc(struct lu_tgt_descs *ltd);
int ltd_qos_update(struct lu_tgt_descs *ltd, struct lu_tgt_desc *tgt,
		   __u64 *total_wt);

/**
 * Whether MDT inode and space usages are balanced.
 */
static inline bool ltd_qos_is_balanced(struct lu_tgt_descs *ltd)
{
	return !test_bit(LQ_DIRTY, &ltd->ltd_qos.lq_flags) &&
	       test_bit(LQ_SAME_SPACE, &ltd->ltd_qos.lq_flags);
}

/**
 * Whether QoS data is up-to-date and QoS can be applied.
 */
static inline bool ltd_qos_is_usable(struct lu_tgt_descs *ltd)
{
	if (ltd_qos_is_balanced(ltd))
		return false;

	if (ltd->ltd_lov_desc.ld_active_tgt_count < 2)
		return false;

	return true;
}

static inline struct lu_tgt_desc *ltd_first_tgt(struct lu_tgt_descs *ltd)
{
	int index;

	index = find_first_bit(ltd->ltd_tgt_bitmap,
			       ltd->ltd_tgts_size);
	return (index < ltd->ltd_tgts_size) ? LTD_TGT(ltd, index) : NULL;
}

static inline struct lu_tgt_desc *ltd_next_tgt(struct lu_tgt_descs *ltd,
					       struct lu_tgt_desc *tgt)
{
	int index;

	if (!tgt)
		return NULL;

	index = tgt->ltd_index;
	LASSERT(index < ltd->ltd_tgts_size);
	index = find_next_bit(ltd->ltd_tgt_bitmap,
			      ltd->ltd_tgts_size, index + 1);
	return (index < ltd->ltd_tgts_size) ? LTD_TGT(ltd, index) : NULL;
}

#define ltd_foreach_tgt(ltd, tgt) \
	for (tgt = ltd_first_tgt(ltd); tgt; tgt = ltd_next_tgt(ltd, tgt))

#define ltd_foreach_tgt_safe(ltd, tgt, tmp)				  \
	for (tgt = ltd_first_tgt(ltd), tmp = ltd_next_tgt(ltd, tgt); tgt; \
	     tgt = tmp, tmp = ltd_next_tgt(ltd, tgt))

/** @} lu */
#endif /* __LUSTRE_LU_OBJECT_H */
