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

#include <stdarg.h>

/*
 * struct lu_fid
 */
#include <lustre/lustre_idl.h>

#include <libcfs/libcfs.h>

/*
 * Layered objects support for CMD3/C5.
 */

struct seq_file;
struct proc_dir_entry;
struct lustre_cfg;
struct lprocfs_stats;

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
struct lu_env;

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
        struct lu_object *(*ldo_object_alloc)(const struct lu_env *env,
                                              const struct lu_object_header *h,
                                              struct lu_device *d);
        /*
         * process config specific for device
         */
        int (*ldo_process_config)(const struct lu_env *env,
                                  struct lu_device *, struct lustre_cfg *);
        int (*ldo_recovery_complete)(const struct lu_env *,
                                     struct lu_device *);

};

/*
 * Type of "printer" function used by ->loo_object_print() method.
 *
 * Printer function is needed to provide some flexibility in (semi-)debugging
 * output: possible implementations: printk, CDEBUG, sysfs/seq_file
 */
typedef int (*lu_printer_t)(const struct lu_env *env,
                            void *cookie, const char *format, ...)
        __attribute__ ((format (printf, 3, 4)));

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
        int (*loo_object_init)(const struct lu_env *env,
                               struct lu_object *o);
        /*
         * Called (in top-to-bottom order) during object allocation after all
         * layers were allocated and initialized. Can be used to perform
         * initialization depending on lower layers.
         */
        int (*loo_object_start)(const struct lu_env *env,
                                struct lu_object *o);
        /*
         * Called before ->loo_object_free() to signal that object is being
         * destroyed. Dual to ->loo_object_init().
         */
        void (*loo_object_delete)(const struct lu_env *env,
                                  struct lu_object *o);

        /*
         * Dual to ->ldo_object_alloc(). Called when object is removed from
         * memory.
         */
        void (*loo_object_free)(const struct lu_env *env,
                                struct lu_object *o);

        /*
         * Called when last active reference to the object is released (and
         * object returns to the cache). This method is optional.
         */
        void (*loo_object_release)(const struct lu_env *env,
                                   struct lu_object *o);
        /*
         * Debugging helper. Print given object.
         */
        int (*loo_object_print)(const struct lu_env *env, void *cookie,
                                lu_printer_t p, const struct lu_object *o);
        /*
         * Optional debugging method. Returns true iff method is internally
         * consistent.
         */
        int (*loo_object_invariant)(const struct lu_object *o);
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
        /*
         * XXX: temporary: context tags used by obd_*() calls.
         */
        __u32                             ldt_ctx_tags;
};

/*
 * Operations on a device type.
 */
struct lu_device_type_operations {
        /*
         * Allocate new device.
         */
        struct lu_device *(*ldto_device_alloc)(const struct lu_env *env,
                                               struct lu_device_type *t,
                                               struct lustre_cfg *lcfg);
        /*
         * Free device. Dual to ->ldto_device_alloc(). Returns pointer to
         * the next device in the stack.
         */
        struct lu_device *(*ldto_device_free)(const struct lu_env *,
                                              struct lu_device *);

        /*
         * Initialize the devices after allocation
         */
        int  (*ldto_device_init)(const struct lu_env *env,
                                 struct lu_device *, const char *,
                                 struct lu_device *);
        /*
         * Finalize device. Dual to ->ldto_device_init(). Returns pointer to
         * the next device in the stack.
         */
        struct lu_device *(*ldto_device_fini)(const struct lu_env *env,
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
/* valid flags */
enum la_valid {
        LA_ATIME = 1 << 0,
        LA_MTIME = 1 << 1,
        LA_CTIME = 1 << 2,
        LA_SIZE  = 1 << 3,
        LA_MODE  = 1 << 4,
        LA_UID   = 1 << 5,
        LA_GID   = 1 << 6,
        LA_BLOCKS = 1 << 7,
        LA_TYPE   = 1 << 8,
        LA_FLAGS  = 1 << 9,
        LA_NLINK  = 1 << 10,
        LA_RDEV   = 1 << 11,
        LA_BLKSIZE = 1 << 12,
};

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
        __u32          la_blkbits; /* blk bits of the object*/
        __u32          la_blksize; /* blk size of the object*/

        __u32          la_rdev;   /* real device */
        __u64          la_valid;  /* valid bits */
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
        LU_OBJECT_HEARD_BANSHEE = 0
};

enum lu_object_header_attr {
        LOHA_EXISTS   = 1 << 0,
        LOHA_REMOTE   = 1 << 1,
        /*
         * UNIX file type is stored in S_IFMT bits.
         */
        LOHA_FT_START = 1 << 12, /* S_IFIFO */
        LOHA_FT_END   = 1 << 15, /* S_IFREG */
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
        atomic_t          loh_ref;
        /*
         * Fid, uniquely identifying this object.
         */
        struct lu_fid     loh_fid;
        /*
         * Common object attributes, cached for efficiency. From enum
         * lu_object_header_attr.
         */
        __u32             loh_attr;
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
        rwlock_t              ls_guard;
        /*
         * Hash-table where objects are indexed by fid.
         */
        struct hlist_head    *ls_hash;
        /*
         * Bit-mask for hash-table size.
         */
        int                   ls_hash_mask;
        /*
         * Order of hash-table.
         */
        int                   ls_hash_bits;
        /*
         * Number of buckets in the hash-table.
         */
        int                   ls_hash_size;

        /*
         * LRU list, updated on each access to object. Protected by
         * ->ls_guard.
         *
         * "Cold" end of LRU is ->ls_lru.next. Accessed object are moved to
         * the ->ls_lru.prev (this is due to the non-existence of
         * list_for_each_entry_safe_reverse()).
         */
        struct list_head      ls_lru;
        /*
         * Total number of objects in this site. Protected by ->ls_guard.
         */
        unsigned              ls_total;
        /*
         * Total number of objects in this site with reference counter greater
         * than 0. Protected by ->ls_guard.
         */
        unsigned              ls_busy;

        /*
         * Top-level device for this stack.
         */
        struct lu_device     *ls_top_dev;
        /*
         * mds number of this site.
         */
        mdsno_t               ls_node_id;
        /*
         * Fid location database
         */
        struct lu_server_fld *ls_server_fld;
        struct lu_client_fld *ls_client_fld;

        /*
         * Server Seq Manager
         */
        struct lu_server_seq *ls_server_seq;

        /*
         * Controller Seq Manager
         */
        struct lu_server_seq *ls_control_seq;
        struct obd_export    *ls_control_exp;

        /*
         * Client Seq Manager
         */
        struct lu_client_seq *ls_client_seq;

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

        /*
         * Linkage into global list of sites.
         */
        struct list_head      ls_linkage;
        struct lprocfs_stats *ls_time_stats;
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
 * Called when initialization of stack for this site is completed.
 */
int lu_site_init_finish(struct lu_site *s);

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
        LASSERT(atomic_read(&o->lo_header->loh_ref) > 0);
        atomic_inc(&o->lo_header->loh_ref);
}

/*
 * Return true of object will not be cached after last reference to it is
 * released.
 */
static inline int lu_object_is_dying(const struct lu_object_header *h)
{
        return test_bit(LU_OBJECT_HEARD_BANSHEE, &h->loh_flags);
}

/*
 * Decrease reference counter on object. If last reference is freed, return
 * object to the cache, unless lu_object_is_dying(o) holds. In the latter
 * case, free object immediately.
 */
void lu_object_put(const struct lu_env *env,
                   struct lu_object *o);

/*
 * Free @nr objects from the cold end of the site LRU list.
 */
int lu_site_purge(const struct lu_env *env, struct lu_site *s, int nr);

/*
 * Print all objects in @s.
 */
void lu_site_print(const struct lu_env *env, struct lu_site *s, void *cookie,
                   lu_printer_t printer);
/*
 * Search cache for an object with the fid @f. If such object is found, return
 * it. Otherwise, create new object, insert it into cache and return it. In
 * any case, additional reference is acquired on the returned object.
 */
struct lu_object *lu_object_find(const struct lu_env *env,
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

struct lu_cdebug_print_info {
        int         lpi_subsys;
        int         lpi_mask;
        const char *lpi_file;
        const char *lpi_fn;
        int         lpi_line;
};

/*
 * Printer function emitting messages through libcfs_debug_msg().
 */
int lu_cdebug_printer(const struct lu_env *env,
                      void *cookie, const char *format, ...);

#define DECLARE_LU_CDEBUG_PRINT_INFO(var, mask) \
        struct lu_cdebug_print_info var = {     \
                .lpi_subsys = DEBUG_SUBSYSTEM,  \
                .lpi_mask   = (mask),           \
                .lpi_file   = __FILE__,         \
                .lpi_fn     = __FUNCTION__,     \
                .lpi_line   = __LINE__          \
        };

/*
 * Print object description followed by user-supplied message.
 */
#define LU_OBJECT_DEBUG(mask, env, object, format, ...)                 \
({                                                                      \
        static DECLARE_LU_CDEBUG_PRINT_INFO(__info, mask);              \
                                                                        \
        lu_object_print(env, &__info, lu_cdebug_printer, object);       \
        CDEBUG(mask, format , ## __VA_ARGS__);                          \
})

/*
 * Print human readable representation of the @o to the @f.
 */
void lu_object_print(const struct lu_env *env, void *cookie,
                     lu_printer_t printer, const struct lu_object *o);

/*
 * Check object consistency.
 */
int lu_object_invariant(const struct lu_object *o);

/*
 * Finalize and free devices in the device stack.
 */
void lu_stack_fini(const struct lu_env *env, struct lu_device *top);

/*
 * Returns 1 iff object @o exists on the stable storage,
 * returns -1 iff object @o is on remote server.
 */
static inline int lu_object_exists(const struct lu_object *o)
{
        __u32 attr;

        attr = o->lo_header->loh_attr;
        if (attr & LOHA_REMOTE)
                return -1;
        else if (attr & LOHA_EXISTS)
                return +1;
        else
                return 0;
}

static inline int lu_object_assert_exists(const struct lu_object *o)
{
        return lu_object_exists(o) != 0;
}

static inline int lu_object_assert_not_exists(const struct lu_object *o)
{
        return lu_object_exists(o) <= 0;
}

/*
 * Attr of this object.
 */
static inline __u32 lu_object_attr(const struct lu_object *o)
{
        LASSERT(lu_object_exists(o) > 0);
        return o->lo_header->loh_attr;
}

struct lu_rdpg {
        /* input params, should be filled out by mdt */
        __u64                   rp_hash;        /* hash */
        int                     rp_count;       /* count in bytes       */
        int                     rp_npages;      /* number of pages      */
        struct page           **rp_pages;       /* pointers to pages    */
};

enum lu_xattr_flags {
        LU_XATTR_REPLACE = (1 << 0),
        LU_XATTR_CREATE  = (1 << 1)
};

/* For lu_context health-checks */
enum lu_context_state {
        LCS_INITIALIZED = 1,
        LCS_ENTERED,
        LCS_LEFT,
        LCS_FINALIZED
};

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
         * of tags has non-empty intersection with one for key. Tags are taken
         * from enum lu_context_tag.
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
        enum lu_context_state  lc_state;
};

/*
 * lu_context_key interface. Similar to pthread_key.
 */

enum lu_context_tag {
        /*
         * Thread on md server
         */
        LCT_MD_THREAD = 1 << 0,
        /*
         * Thread on dt server
         */
        LCT_DT_THREAD = 1 << 1,
        /*
         * Context for transaction handle
         */
        LCT_TX_HANDLE = 1 << 2,
        /*
         * Thread on client
         */
        LCT_CL_THREAD = 1 << 3,
        /*
         * Per-request session on server
         */
        LCT_SESSION   = 1 << 4,
        /*
         * Don't add references for modules creating key values in that context.
         * This is only for contexts used internally by lu_object framework.
         */
        LCT_NOREF     = 1 << 30,
        /*
         * Contexts usable in cache shrinker thread.
         */
        LCT_SHRINKER  = LCT_MD_THREAD|LCT_DT_THREAD|LCT_CL_THREAD|LCT_NOREF
};

/*
 * Key. Represents per-context value slot.
 */
struct lu_context_key {
        /*
         * Set of tags for which values of this key are to be instantiated.
         */
        __u32 lct_tags;
        /*
         * Value constructor. This is called when new value is created for a
         * context. Returns pointer to new value of error pointer.
         */
        void  *(*lct_init)(const struct lu_context *ctx,
                           struct lu_context_key *key);
        /*
         * Value destructor. Called when context with previously allocated
         * value of this slot is destroyed. @data is a value that was returned
         * by a matching call to ->lct_init().
         */
        void   (*lct_fini)(const struct lu_context *ctx,
                           struct lu_context_key *key, void *data);
        /*
         * Optional method called on lu_context_exit() for all allocated
         * keys. Can be used by debugging code checking that locks are
         * released, etc.
         */
        void   (*lct_exit)(const struct lu_context *ctx,
                           struct lu_context_key *key, void *data);
        /*
         * Internal implementation detail: index within ->lc_value[] reserved
         * for this key.
         */
        int      lct_index;
        /*
         * Internal implementation detail: number of values created for this
         * key.
         */
        atomic_t lct_used;
        /*
         * Internal implementation detail: module for this key.
         */
        struct module *lct_owner;
};

#define LU_KEY_INIT(mod, type)                                    \
        static void* mod##_key_init(const struct lu_context *ctx, \
                                    struct lu_context_key *key)   \
        {                                                         \
                type *value;                                      \
                                                                  \
                CLASSERT(CFS_PAGE_SIZE >= sizeof (*value));       \
                                                                  \
                OBD_ALLOC_PTR(value);                             \
                if (value == NULL)                                \
                        value = ERR_PTR(-ENOMEM);                 \
                                                                  \
                return value;                                     \
        }                                                         \
        struct __##mod##__dummy_init {;} /* semicolon catcher */

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


/*
 * Register new key.
 */
int   lu_context_key_register(struct lu_context_key *key);
/*
 * Deregister key.
 */
void  lu_context_key_degister(struct lu_context_key *key);

#define LU_KEY_REGISTER_GENERIC(mod)                                             \
        static int mod##_key_register_generic(struct lu_context_key *k, ...)     \
        {                                                                        \
                struct lu_context_key* key = k;                                  \
                va_list args;                                                    \
                int result;                                                      \
                                                                                 \
                va_start(args, k);                                               \
                                                                                 \
                do {                                                             \
                        LU_CONTEXT_KEY_INIT(key);                                \
                        result = lu_context_key_register(key);                   \
                        if (result)                                              \
                                break;                                           \
                        key = va_arg(args, struct lu_context_key*);              \
                } while (key != NULL);                                           \
                                                                                 \
                va_end(args);                                                    \
                                                                                 \
                if (result) {                                                    \
                        va_start(args, k);                                       \
                        while (k != key) {                                       \
                                lu_context_key_degister(k);                      \
                                k = va_arg(args, struct lu_context_key*);        \
                        }                                                        \
                        va_end(args);                                            \
                }                                                                \
                                                                                 \
                return result;                                                   \
        }

#define LU_KEY_DEGISTER_GENERIC(mod)                                             \
        static void mod##_key_degister_generic(struct lu_context_key *k, ...)    \
        {                                                                        \
                va_list args;                                                    \
                                                                                 \
                va_start(args, k);                                               \
                                                                                 \
                do {                                                             \
                        lu_context_key_degister(k);                              \
                        k = va_arg(args, struct lu_context_key*);                \
                } while (k != NULL);                                             \
                                                                                 \
                va_end(args);                                                    \
        }

#define LU_TYPE_INIT(mod, ...)                                         \
        LU_KEY_REGISTER_GENERIC(mod)                                   \
        static int mod##_type_init(struct lu_device_type *t)           \
        {                                                              \
                return mod##_key_register_generic(__VA_ARGS__, NULL);  \
        }                                                              \
        struct __##mod##_dummy_type_init {;}

#define LU_TYPE_FINI(mod, ...)                                         \
        LU_KEY_DEGISTER_GENERIC(mod)                                   \
        static void mod##_type_fini(struct lu_device_type *t)          \
        {                                                              \
                mod##_key_degister_generic(__VA_ARGS__, NULL);         \
        }                                                              \
        struct __##mod##_dummy_type_fini {;}

#define LU_TYPE_INIT_FINI(mod, ...)                                 \
        LU_TYPE_INIT(mod, __VA_ARGS__);                             \
        LU_TYPE_FINI(mod, __VA_ARGS__)

/*
 * Return value associated with key @key in context @ctx.
 */
void *lu_context_key_get(const struct lu_context *ctx,
                         struct lu_context_key *key);

/*
 * Initialize context data-structure. Create values for all keys.
 */
int  lu_context_init(struct lu_context *ctx, __u32 tags);
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

/*
 * Allocate for context all missing keys that were registered after context
 * creation.
 */
int lu_context_refill(const struct lu_context *ctx);

/*
 * Environment.
 */
struct lu_env {
        /*
         * "Local" context, used to store data instead of stack.
         */
        struct lu_context  le_ctx;
        /*
         * "Session" context for per-request data.
         */
        struct lu_context *le_ses;
};

int  lu_env_init(struct lu_env *env, struct lu_context *ses, __u32 tags);
void lu_env_fini(struct lu_env *env);

/*
 * Common name structure to be passed around for various name related methods.
 */
struct lu_name {
        char    *ln_name;
        int      ln_namelen;
};

/*
 * Common buffer structure to be passed around for various xattr_{s,g}et()
 * methods.
 */
struct lu_buf {
        void   *lb_buf;
        ssize_t lb_len;
};

extern struct lu_buf LU_BUF_NULL; /* null buffer */

#define DLUBUF "(%p %z)"
#define PLUBUF(buf) (buf)->lb_buf, (buf)->lb_len
/*
 * One-time initializers, called at obdclass module initialization, not
 * exported.
 */

/*
 * Initialization of global lu_* data.
 */
int lu_global_init(void);

/*
 * Dual to lu_global_init().
 */
void lu_global_fini(void);

enum {
        LU_TIME_FIND_LOOKUP,
        LU_TIME_FIND_ALLOC,
        LU_TIME_FIND_INSERT,
        LU_TIME_NR
};

extern const char *lu_time_names[LU_TIME_NR];

#endif /* __LUSTRE_LU_OBJECT_H */
