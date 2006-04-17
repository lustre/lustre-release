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

#ifndef __LINUX_LU_OBJECT_H
#define __LINUX_LU_OBJECT_H

/*
 * struct lu_fid
 */
#include <linux/lustre_idl.h>

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
 *     where possible.
 *
 *
 *
 *
 *
 *
 *
 *
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
	 *  - then ->ldo_object_init() is called. It has to allocate
	 *  lower-layer object(s). To do this, ->ldo_object_init() calls
	 *  ldo_object_alloc() of the lower-layer device(s).
	 *
	 *  - for all new objects allocated by ->ldo_object_init() (and
	 *  inserted into object stack), ->ldo_object_init() is called again
	 *  repeatedly, until no new objects are created.
	 *
	 */

	/*
	 * Allocate lower-layer parts of the object by calling
	 * ->ldo_object_alloc() of the corresponding underlying device.
	 *
	 * This method is called once for each object inserted into object
	 * stack. It's responsibility of this method to insert lower-layer
	 * object(s) it create into appropriate places of object stack.
	 */
	int (*ldo_object_init)(struct lu_context *, struct lu_object *);

	/*
	 * Allocate object for the given device (without lower-layer
	 * parts). This is called by ->ldo_object_init() from the parent
	 * layer.
	 */
	struct lu_object *(*ldo_object_alloc)(struct lu_context *,
                                              struct lu_device *);

	/*
	 * Called before ->ldo_object_free() to signal that object is being
	 * destroyed.
	 */
	void (*ldo_object_delete)(struct lu_context *ctx, struct lu_object *o);

	/*
	 * Dual to ->ldo_object_alloc(). Called when object is removed from
	 * memory.
	 */
	void (*ldo_object_free)(struct lu_context *ctx, struct lu_object *o);

	/*
	 * Called when last active reference to the object is released (and
	 * object returns to the cache).
	 */
	void (*ldo_object_release)(struct lu_context *ctx, struct lu_object *o);

	/*
	 * Debugging helper. Print given object.
	 */
	int (*ldo_object_print)(struct lu_context *ctx,
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
        struct lu_device_type       *ld_type;
	struct lu_device_operations *ld_ops;
	struct lu_site              *ld_site;
        struct proc_dir_entry       *ld_proc_entry;

        /* XXX: temporary back pointer into obd. */
        struct obd_device           *ld_obd;
};

struct lu_device_type_operations;

enum {
        /* this is meta-data device */
        LU_DEVICE_MD = (1 << 0),
        /* this is data device */
        LU_DEVICE_DT = (1 << 1)
};

struct lu_device_type {
        __u32                             ldt_tags;
        char                             *ldt_name;
        struct lu_device_type_operations *ldt_ops;
        struct obd_type                  *obd_type;
};

struct lu_device_type_operations {
        struct lu_device *(*ldto_device_alloc)(struct lu_device_type *t,
                                               struct lustre_cfg *lcfg);
        void (*ldto_device_free)(struct lu_device *d);

        /*
         * Initialize the devices after allocation
         * called from top device, when all layers are linked
         */
        int  (*ldto_device_init)(struct lu_device *, struct lu_device *);
        struct lu_device *(*ldto_device_fini)(struct lu_device *);

        int  (*ldto_init)(struct lu_device_type *t);
        void (*ldto_fini)(struct lu_device_type *t);
};

/*
 * Flags for the object layers.
 */
enum lu_object_flags {
	/*
	 * this flags is set if ->ldo_object_init() has been called for this
	 * layer. Used by lu_object_alloc().
	 */
	LU_OBJECT_ALLOCATED = (1 << 0)
};

/* attr */
struct lu_attr {
        __u64          la_size;
        __u64          la_mtime;
        __u64          la_atime;
        __u64          la_ctime;
        __u64          la_blocks;
        __u32          la_mode;
        __u32          la_uid;
        __u32          la_gid;
        __u32          la_flags;
        __u32          la_nlink;
};

/*
 * Layer in the layered object.
 */
struct lu_object {
	/*
	 * Header for this object.
	 */
	struct lu_object_header *lo_header;
	/*
	 * Device for this layer.
	 */
	struct lu_device        *lo_dev;
	/*
	 * Linkage into list of all layers.
	 */
	struct list_head         lo_linkage;
	/*
	 * Depth. Top level layer depth is 0.
	 */
	int                      lo_depth;
	/*
	 * Flags from enum lu_object_flags.
	 */
	unsigned long            lo_flags;
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
        struct lustre_mount_info *ls_lmi;
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
 * Helpers.
 */
static inline struct lu_device_operations *
lu_object_ops(const struct lu_object *o)
{
	return o->lo_dev->ld_ops;
}

static inline struct lu_object *lu_object_next(const struct lu_object *o)
{
	return container_of(o->lo_linkage.next, struct lu_object, lo_linkage);
}

static inline struct lu_fid *lu_object_fid(const struct lu_object *o)
{
	return &o->lo_header->loh_fid;
}

static inline struct lu_object *lu_object_top(struct lu_object_header *h)
{
	LASSERT(!list_empty(&h->loh_layers));
	return container_of(h->loh_layers.next, struct lu_object, lo_linkage);
}

static inline void lu_object_get(struct lu_object *o)
{
	LASSERT(o->lo_header->loh_ref > 0);
	spin_lock(&o->lo_dev->ld_site->ls_guard);
	o->lo_header->loh_ref ++;
	spin_unlock(&o->lo_dev->ld_site->ls_guard);
}

static inline int lu_object_is_dying(struct lu_object_header *h)
{
	return test_bit(LU_OBJECT_HEARD_BANSHEE, &h->loh_flags);
}

void lu_object_put(struct lu_context *ctxt, struct lu_object *o);
void lu_site_purge(struct lu_context *ctx, struct lu_site *s, int nr);
int lu_object_print(struct lu_context *ctxt,
                    struct seq_file *f, const struct lu_object *o);
struct lu_object *lu_object_find(struct lu_context *ctxt,
                                 struct lu_site *s, const struct lu_fid *f);

int  lu_site_init(struct lu_site *, struct lu_device *);
void lu_site_fini(struct lu_site *s);

void lu_device_get(struct lu_device *d);
void lu_device_put(struct lu_device *d);

int lu_device_init(struct lu_device *d, struct lu_device_type *t);
void lu_device_fini(struct lu_device *d);

int lu_object_init(struct lu_object *o,
                   struct lu_object_header *h, struct lu_device *d);
void lu_object_fini(struct lu_object *o);
void lu_object_add_top(struct lu_object_header *h, struct lu_object *o);
void lu_object_add(struct lu_object *before, struct lu_object *o);

int lu_object_header_init(struct lu_object_header *h);
void lu_object_header_fini(struct lu_object_header *h);

struct lu_object *lu_object_locate(struct lu_object_header *h,
                                   struct lu_device_type *dtype);

/*
 * lu_context. Execution context for lu_object methods. Currently associated
 * with thread.
 */
struct lu_context {
        __u32                  lc_tags;
        struct lu_attr         lc_attr;
        struct ptlrpc_thread  *lc_thread;
        void                 **lc_value;
};


struct lu_context_key {
        void  *(*lct_init)(struct lu_context *ctx);
        void   (*lct_fini)(struct lu_context *ctx, void *data);
        int      lct_index;
        unsigned lct_used;
};

int   lu_context_key_register(struct lu_context_key *key);
void  lu_context_key_degister(struct lu_context_key *key);
void *lu_context_key_get(struct lu_context *ctx, struct lu_context_key *key);

int  lu_context_init(struct lu_context *ctx);
void lu_context_fini(struct lu_context *ctx);

void lu_context_enter(struct lu_context *ctx);
void lu_context_exit(struct lu_context *ctx);

/*
 * DT device interface. XXX Probably should go elsewhere.
 */
struct md_params;
struct thandle;
struct txn_param;
struct dt_device;
struct dt_object;

enum dt_lock_mode {
        DT_WRITE_LOCK = 1,
        DT_READ_LOCK  = 2,
};

struct dt_device_operations {
        /* method for getting/setting device wide back stored config data, like
         * last used meta-sequence, etc. */
        int (*dt_config) (struct lu_context *ctx,
                          struct dt_device *dev, const char *name,
                          void *buf, int size, int mode);
        int   (*dt_statfs)(struct lu_context *ctx,
                           struct dt_device *dev, struct kstatfs *sfs);
        struct thandle *(*dt_trans_start)(struct lu_context *ctx,
                                          struct dt_device *dev,
                                          struct txn_param *param);
        void  (*dt_trans_stop)(struct lu_context *ctx, struct thandle *th);
        int   (*dt_root_get)(struct lu_context *ctx,
                             struct dt_device *dev, struct lu_fid *f);
};

struct dt_object_operations {
        void  (*do_object_lock)(struct lu_context *ctx,
                                struct dt_object *dt, enum dt_lock_mode mode);
        void  (*do_object_unlock)(struct lu_context *ctx,
                                  struct dt_object *dt, enum dt_lock_mode mode);

        int   (*do_object_create)(struct lu_context *ctxt,
                                  struct dt_object *dt,
                                  struct dt_object *child,
                                  struct md_params *arg, struct thandle *th);

        int   (*do_object_destroy)(struct lu_context *ctxt,
                                   struct dt_object *dt,
                                   struct thandle *th);

        int   (*do_attr_get)(struct lu_context *ctxt, struct dt_object *dt,
                             struct lu_attr *attr);
        int   (*do_attr_set)(struct lu_context *ctxt, struct dt_object *dt,
                             struct lu_attr *attr, struct thandle *handle);

        int   (*do_xattr_get)(struct lu_context *ctxt, struct dt_object *dt,
                              void *buf, int buf_len, const char *name,
                              struct md_params *arg);

        int   (*do_xattr_set)(struct lu_context *ctxt, struct dt_object *dt,
                              void *buf, int buf_len, const char *name,
                              struct md_params *arg, struct thandle *handle);

        int   (*do_index_insert)(struct lu_context *ctxt,
                                 struct dt_object *dt,
                                 struct lu_fid *fid, const char *name,
                                 struct md_params *arg,
                                 struct thandle *handle);

        int   (*do_index_delete)(struct lu_context *ctxt,
                                 struct dt_object *dt,
                                 struct lu_fid *fid, const char *name,
                                 struct md_params *arg,
                                 struct thandle *handle);
};

struct dt_device {
	struct lu_device             dd_lu_dev;
	struct dt_device_operations *dd_ops;
};

static inline int lu_device_is_dt(const struct lu_device *d)
{
        return d->ld_type->ldt_tags & LU_DEVICE_DT;
}

static inline struct dt_device * lu2dt_dev(struct lu_device *l)
{
        LASSERT(lu_device_is_dt(l));
        return container_of(l, struct dt_device, dd_lu_dev);
}

struct dt_object {
        struct lu_object             do_lu;
	struct dt_object_operations *do_ops;
};

struct txn_param {
        unsigned int tp_credits;
};

struct fld {
        struct dt_device        *fld_dt;
};

extern int fld_server_init(struct fld *fld, struct dt_device *dt);
extern void fld_server_fini(struct fld *fld);
extern int fld_handle(struct fld *fld, __u32 opts, void *mf);

#define TXN_PARAM_INIT(credits) {               \
        .tp_credits = (credits)                 \
}

#define TXN_PARAM(...) ((struct txn_param)TXN_PARAM_INIT(__VA_ARGS__))

#endif /* __LINUX_OBD_CLASS_H */
