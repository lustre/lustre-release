/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef __LUSTRE_LU_OBJECT_H
#define __LUSTRE_LU_OBJECT_H

/*
 * struct lu_fid
 */
#include <lustre/lustre_idl.h>

#include <libcfs/list.h>
#include <libcfs/kp30.h>

/*
 * Layered objects support for CMD3/C5.
 */


struct seq_file;
struct proc_dir_entry;
struct lustre_cfg;

/*
 * lu_* data-types represent server-side entities shared by data and meta-data
 * stacks.
 *
 * Design goals:
 *
 * 0. support for layering.
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
 * 1. fid-based identification.
 *
 *     Compound object is uniquely identified by its fid. Objects are indexed
 *     by their fids (hash table is used for index).
 *
 * 2. caching and life-cycle management.
 *
 *     Object's life-time is controlled by reference counting. When reference
 *     count drops to 0, object is returned to cache. Cached objects still
 *     retain their identity (i.e., fid), and can be recovered from cache.
 *
 *     Objects are kept in the global LRU list, and lu_site_purge() function
 *     can be used to reclaim given number of unused objects from the tail of
 *     the LRU.
 *
 * 3. avoiding recursion.
 *
 *     Generic code tries to replace recursion through layers by iterations
 *     where possible. Additionally to the end of reducing stack consumption,
 *     data, when practically possible, are allocated through lu_context_key
 *     interface rather than on stack.
 *
 */

struct lu_site;
struct lu_object;
struct lu_device;
struct lu_object_header;
struct lu_context;
/*
 * Operations common for data and meta-data devices.
 */
struct lu_device_operations {
        /*
         * Object creation protocol.
         *
         * Due to design goal of avoiding recursion, object creation (see
         * lu_object_alloc()) is somewhat involved:
         *
         *  - first, ->ldo_object_alloc() method of the top-level device
         *  in the stack is called. It should allocate top level object
         *  (including lu_object_header), but without any lower-layer
         *  sub-object(s).
         *
         *  - then lu_object_alloc() sets fid in the header of newly created
         *  object.
         *
         *  - then ->loo_object_init() (a method from struct
         *  lu_object_operations) is called. It has to allocate lower-layer
         *  object(s). To do this, ->loo_object_init() calls
         *  ldo_object_alloc() of the lower-layer device(s).
         *
         *  - for all new objects allocated by ->loo_object_init() (and
         *  inserted into object stack), ->loo_object_init() is called again
         *  repeatedly, until no new objects are created.
         *
         */

        /*
         * Allocate object for the given device (without lower-layer
         * parts). This is called by ->loo_object_init() from the parent
         * layer, and should setup at least ->lo_dev and ->lo_ops fields of
         * resulting lu_object.
         *
         * postcondition: ergo(!IS_ERR(result), result->lo_dev ==  d &&
         *                                      result->lo_ops != NULL);
         */
        struct lu_object *(*ldo_object_alloc)(const struct lu_context *ctx,
                                              const struct lu_object_header *h,
                                              struct lu_device *d);
        /*
         * process config specific for device
         */
        int  (*ldo_process_config)(const struct lu_context *ctx,
                                   struct lu_device *, struct lustre_cfg *);
};

/*
 * Operations specific for particular lu_object.
 */
struct lu_object_operations {

        /*
         * Allocate lower-layer parts of the object by calling
         * ->ldo_object_alloc() of the corresponding underlying device.
         *
         * This method is called once for each object inserted into object
         * stack. It's responsibility of this method to insert lower-layer
         * object(s) it create into appropriate places of object stack.
         */
        int (*loo_object_init)(const struct lu_context *ctx,
                               struct lu_object *o);
        /*
         * Called before ->loo_object_free() to signal that object is being
         * destroyed. Dual to ->loo_object_init().
         */
        void (*loo_object_delete)(const struct lu_context *ctx,
                                  struct lu_object *o);

        /*
         * Dual to ->ldo_object_alloc(). Called when object is removed from
         * memory.
         */
        void (*loo_object_free)(const struct lu_context *ctx,
                                struct lu_object *o);

        /*
         * Called when last active reference to the object is released (and
         * object returns to the cache).
         */
        void (*loo_object_release)(const struct lu_context *ctx,
                                   struct lu_object *o);

        /*
         * Return true off object @o exists on a storage.
         */
        int (*loo_object_exists)(const struct lu_context *ctx,
                                 struct lu_object *o);
        /*
         * Debugging helper. Print given object.
         */
        int (*loo_object_print)(const struct lu_context *ctx,
                                struct seq_file *f, const struct lu_object *o);
};

/*
 * Type of lu_device.
 */
struct lu_device_type;

/*
 * Device: a layer in the server side abstraction stacking.
 */
struct lu_device {
        /*
         * reference count. This is incremented, in particular, on each object
         * created at this layer.
         *
         * XXX which means that atomic_t is probably too small.
         */
        atomic_t                     ld_ref;
        /*
         * Pointer to device type. Never modified once set.
         */
        struct lu_device_type       *ld_type;
        /*
         * Operation vector for this device.
         */
        struct lu_device_operations *ld_ops;
        /*
         * Stack this device belongs to.
         */
        struct lu_site              *ld_site;
        struct proc_dir_entry       *ld_proc_entry;

        /* XXX: temporary back pointer into obd. */
        struct obd_device           *ld_obd;
};

struct lu_device_type_operations;

/*
 * Tag bits for device type. They are used to distinguish certain groups of
 * device types.
 */
enum lu_device_tag {
        /* this is meta-data device */
        LU_DEVICE_MD = (1 << 0),
        /* this is data device */
        LU_DEVICE_DT = (1 << 1)
};

/*
 * Type of device.
 */
struct lu_device_type {
        /*
         * Tag bits. Taken from enum lu_device_tag. Never modified once set.
         */
        __u32                             ldt_tags;
        /*
         * Name of this class. Unique system-wide. Never modified once set.
         */
        char                             *ldt_name;
        /*
         * Operations for this type.
         */
        struct lu_device_type_operations *ldt_ops;
        /*
         * XXX: temporary pointer to associated obd_type.
         */
        struct obd_type                  *ldt_obd_type;
};

/*
 * Operations on a device type.
 */
struct lu_device_type_operations {
        /*
         * Allocate new device.
         */
        struct lu_device *(*ldto_device_alloc)(const struct lu_context *ctx,
                                               struct lu_device_type *t,
                                               struct lustre_cfg *lcfg);
        /*
         * Free device. Dual to ->ldto_device_alloc().
         */
        void (*ldto_device_free)(const struct lu_context *ctx,
                                 struct lu_device *d);

        /*
         * Initialize the devices after allocation
         */
        int  (*ldto_device_init)(const struct lu_context *ctx,
                                 struct lu_device *, struct lu_device *);
        /*
         * Finalize device. Dual to ->ldto_device_init(). Returns pointer to
         * the next device in the stack.
         */
        struct lu_device *(*ldto_device_fini)(const struct lu_context *ctx,
                                              struct lu_device *);

        /*
         * Initialize device type. This is called on module load.
         */
        int  (*ldto_init)(struct lu_device_type *t);
        /*
         * Finalize device type. Dual to ->ldto_init(). Called on module
         * unload.
         */
        void (*ldto_fini)(struct lu_device_type *t);
};

/*
 * Flags for the object layers.
 */
enum lu_object_flags {
        /*
         * this flags is set if ->loo_object_init() has been called for this
         * layer. Used by lu_object_alloc().
         */
        LU_OBJECT_ALLOCATED = (1 << 0)
};

/*
 * Common object attributes.
 */
struct lu_attr {
        __u64          la_size;   /* size in bytes */
        __u64          la_mtime;  /* modification time in seconds since Epoch */
        __u64          la_atime;  /* access time in seconds since Epoch */
        __u64          la_ctime;  /* change time in seconds since Epoch */
        __u64          la_blocks; /* 512-byte blocks allocated to object */
        __u32          la_mode;   /* permission bits and file type */
        __u32          la_uid;    /* owner id */
        __u32          la_gid;    /* group id */
        __u32          la_flags;  /* object flags */
        __u32          la_nlink;  /* number of persistent references to this
                                   * object */
};


/*
 * Layer in the layered object.
 */
struct lu_object {
        /*
         * Header for this object.
         */
        struct lu_object_header     *lo_header;
        /*
         * Device for this layer.
         */
        struct lu_device            *lo_dev;
        /*
         * Operations for this object.
         */
        struct lu_object_operations *lo_ops;
        /*
         * Linkage into list of all layers.
         */
        struct list_head             lo_linkage;
        /*
         * Depth. Top level layer depth is 0.
         */
        int                          lo_depth;
        /*
         * Flags from enum lu_object_flags.
         */
        unsigned long                lo_flags;
};

enum lu_object_header_flags {
        /*
         * Don't keep this object in cache. Object will be destroyed as soon
         * as last reference to it is released. This flag cannot be cleared
         * once set.
         */
        LU_OBJECT_HEARD_BANSHEE = 0,
};

/*
 * "Compound" object, consisting of multiple layers.
 *
 * Compound object with given fid is unique with given lu_site.
 *
 * Note, that object does *not* necessary correspond to the real object in the
 * persistent storage: object is an anchor for locking and method calling, so
 * it is created for things like not-yet-existing child created by mkdir or
 * create calls. ->loo_exists() can be used to check whether object is backed
 * by persistent storage entity.
 */
struct lu_object_header {
        /*
         * Object flags from enum lu_object_header_flags. Set and checked
         * atomically.
         */
        unsigned long     loh_flags;
        /*
         * Object reference count. Protected by site guard lock.
         */
        int               loh_ref;
        /*
         * Fid, uniquely identifying this object.
         */
        struct lu_fid     loh_fid;
        /*
         * Linkage into per-site hash table. Protected by site guard lock.
         */
        struct hlist_node loh_hash;
        /*
         * Linkage into per-site LRU list. Protected by site guard lock.
         */
        struct list_head  loh_lru;
        /*
         * Linkage into list of layers. Never modified once set (except lately
         * during object destruction). No locking is necessary.
         */
        struct list_head  loh_layers;
};

struct fld;
/*
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
        /*
         * lock protecting:
         *
         *        - ->ls_hash hash table (and its linkages in objects);
         *
         *        - ->ls_lru list (and its linkages in objects);
         *
         *        - 0/1 transitions of object ->loh_ref reference count;
         *
         * yes, it's heavy.
         */
        spinlock_t         ls_guard;
        /*
         * Hash-table where objects are indexed by fid.
         */
        struct hlist_head *ls_hash;
        /*
         * Bit-mask for hash-table size.
         */
        int                ls_hash_mask;


        /*
         * LRU list, updated on each access to object. Protected by
         * ->ls_guard.
         *
         * "Cold" end of LRU is ->ls_lru.next. Accessed object are moved to
         * the ->ls_lru.prev (this is due to the non-existence of
         * list_for_each_entry_safe_reverse()).
         */
        struct list_head   ls_lru;
        /*
         * Total number of objects in this site. Protected by ->ls_guard.
         */
        unsigned           ls_total;
        /*
         * Total number of objects in this site with reference counter greater
         * than 0. Protected by ->ls_guard.
         */
        unsigned           ls_busy;

        /*
         * Top-level device for this stack.
         */
        struct lu_device  *ls_top_dev;
        /* current server index */
        __u32             ls_node_id;
        /*
         * Fid location database
         */
        struct fld        *ls_fld;

        /* statistical counters. Protected by nothing, races are accepted. */
        struct {
                __u32 s_created;
                __u32 s_cache_hit;
                __u32 s_cache_miss;
                /*
                 * Number of hash-table entry checks made.
                 *
                 *       ->s_cache_check / (->s_cache_miss + ->s_cache_hit)
                 *
                 * is an average number of hash slots inspected during single
                 * lookup.
                 */
                __u32 s_cache_check;
                /* raced cache insertions */
                __u32 s_cache_race;
                __u32 s_lru_purged;
        } ls_stats;
};

/*
 * Constructors/destructors.
 */

/*
 * Initialize site @s, with @d as the top level device.
 */
int  lu_site_init(struct lu_site *s, struct lu_device *d);
/*
 * Finalize @s and release its resources.
 */
void lu_site_fini(struct lu_site *s);

/*
 * Acquire additional reference on device @d
 */
void lu_device_get(struct lu_device *d);
/*
 * Release reference on device @d.
 */
void lu_device_put(struct lu_device *d);

/*
 * Initialize device @d of type @t.
 */
int lu_device_init(struct lu_device *d, struct lu_device_type *t);
/*
 * Finalize device @d.
 */
void lu_device_fini(struct lu_device *d);

/*
 * Initialize compound object.
 */
int lu_object_header_init(struct lu_object_header *h);
/*
 * Finalize compound object.
 */
void lu_object_header_fini(struct lu_object_header *h);

/*
 * Initialize object @o that is part of compound object @h and was created by
 * device @d.
 */
int lu_object_init(struct lu_object *o,
                   struct lu_object_header *h, struct lu_device *d);
/*
 * Finalize object and release its resources.
 */
void lu_object_fini(struct lu_object *o);
/*
 * Add object @o as first layer of compound object @h.
 *
 * This is typically called by the ->ldo_object_alloc() method of top-level
 * device.
 */
void lu_object_add_top(struct lu_object_header *h, struct lu_object *o);
/*
 * Add object @o as a layer of compound object, going after @before.1
 *
 * This is typically called by the ->ldo_object_alloc() method of
 * @before->lo_dev.
 */
void lu_object_add(struct lu_object *before, struct lu_object *o);

/*
 * Caching and reference counting.
 */

/*
 * Acquire additional reference to the given object. This function is used to
 * attain additional reference. To acquire initial reference use
 * lu_object_find().
 */
static inline void lu_object_get(struct lu_object *o)
{
        LASSERT(o->lo_header->loh_ref > 0);
        spin_lock(&o->lo_dev->ld_site->ls_guard);
        o->lo_header->loh_ref ++;
        spin_unlock(&o->lo_dev->ld_site->ls_guard);
}

/*
 * Return true of object will not be cached after last reference to it is
 * released.
 */
static inline int lu_object_is_dying(struct lu_object_header *h)
{
        return test_bit(LU_OBJECT_HEARD_BANSHEE, &h->loh_flags);
}

/*
 * Decrease reference counter on object. If last reference is freed, return
 * object to the cache, unless lu_object_is_dying(o) holds. In the latter
 * case, free object immediately.
 */
void lu_object_put(const struct lu_context *ctxt,
                   struct lu_object *o);

/*
 * Free @nr objects from the cold end of the site LRU list.
 */
void lu_site_purge(const struct lu_context *ctx,
                   struct lu_site *s, int nr);

/*
 * Search cache for an object with the fid @f. If such object is found, return
 * it. Otherwise, create new object, insert it into cache and return it. In
 * any case, additional reference is acquired on the returned object.
 */
struct lu_object *lu_object_find(const struct lu_context *ctxt,
                                 struct lu_site *s, const struct lu_fid *f);

/*
 * Helpers.
 */

/*
 * First (topmost) sub-object of given compound object
 */
static inline struct lu_object *lu_object_top(struct lu_object_header *h)
{
        LASSERT(!list_empty(&h->loh_layers));
        return container_of0(h->loh_layers.next, struct lu_object, lo_linkage);
}

/*
 * Next sub-object in the layering
 */
static inline struct lu_object *lu_object_next(const struct lu_object *o)
{
        return container_of0(o->lo_linkage.next, struct lu_object, lo_linkage);
}

/*
 * Pointer to the fid of this object.
 */
static inline const struct lu_fid *lu_object_fid(const struct lu_object *o)
{
        return &o->lo_header->loh_fid;
}

/*
 * return device operations vector for this object
 */
static inline struct lu_device_operations *
lu_object_ops(const struct lu_object *o)
{
        return o->lo_dev->ld_ops;
}

/*
 * Given a compound object, find its slice, corresponding to the device type
 * @dtype.
 */
struct lu_object *lu_object_locate(struct lu_object_header *h,
                                   struct lu_device_type *dtype);

/*
 * Print human readable representation of the @o to the @f.
 */
int lu_object_print(const struct lu_context *ctxt,
                    struct seq_file *f, const struct lu_object *o);

/*
 * Returns true iff object @o exists on the stable storage.
 */
static inline int lu_object_exists(const struct lu_context *ctx,
                                   struct lu_object *o)
{
        return o->lo_ops->loo_object_exists(ctx, o);
}

/*
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
 */
struct lu_context {
        /*
         * Theoretically we'd want to use lu_objects and lu_contexts on the
         * client side too. On the other hand, we don't want to allocate
         * values of server-side keys for the client contexts and vice versa.
         *
         * To achieve this, set of tags in introduced. Contexts and keys are
         * marked with tags. Key value are created only for context whose set
         * of tags has non-empty intersection with one for key. NOT YET
         * IMPLEMENTED.
         */
        __u32                  lc_tags;
        /*
         * Pointer to the home service thread. NULL for other execution
         * contexts.
         */
        struct ptlrpc_thread  *lc_thread;
        /*
         * Pointer to an array with key values. Internal implementation
         * detail.
         */
        void                 **lc_value;
};

/*
 * lu_context_key interface. Similar to pthread_key.
 */


/*
 * Key. Represents per-context value slot.
 */
struct lu_context_key {
        /*
         * Value constructor. This is called when new value is created for a
         * context. Returns pointer to new value of error pointer.
         */
        void  *(*lct_init)(const struct lu_context *ctx);
        /*
         * Value destructor. Called when context with previously allocated
         * value of this slot is destroyed. @data is a value that was returned
         * by a matching call to ->lct_init().
         */
        void   (*lct_fini)(const struct lu_context *ctx, void *data);
        /*
         * Internal implementation detail: index within ->lc_value[] reserved
         * for this key.
         */
        int      lct_index;
        /*
         * Internal implementation detail: number of values created for this
         * key.
         */
        unsigned lct_used;
};

/*
 * Register new key.
 */
int   lu_context_key_register(struct lu_context_key *key);
/*
 * Deregister key.
 */
void  lu_context_key_degister(struct lu_context_key *key);
/*
 * Return value associated with key @key in context @ctx.
 */
void *lu_context_key_get(const struct lu_context *ctx,
                         struct lu_context_key *key);

/*
 * Initialize context data-structure. Create values for all keys.
 */
int  lu_context_init(struct lu_context *ctx);
/*
 * Finalize context data-structure. Destroy key values.
 */
void lu_context_fini(struct lu_context *ctx);

/*
 * Called before entering context.
 */
void lu_context_enter(struct lu_context *ctx);
/*
 * Called after exiting from @ctx
 */
void lu_context_exit(struct lu_context *ctx);


#endif /* __LUSTRE_LU_OBJECT_H */
