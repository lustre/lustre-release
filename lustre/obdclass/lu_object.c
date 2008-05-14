/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Object.
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 *
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices
 */

#define DEBUG_SUBSYSTEM S_CLASS
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#include <linux/seq_file.h>
#include <linux/module.h>
/* nr_free_pages() */
#include <linux/swap.h>
/* hash_long() */
#include <linux/hash.h>
#include <obd_support.h>
#include <lustre_disk.h>
#include <lustre_fid.h>
#include <lu_object.h>
#include <libcfs/list.h>
/* lu_time_global_{init,fini}() */
#include <lu_time.h>

static void lu_object_free(const struct lu_env *env, struct lu_object *o);

/*
 * Decrease reference counter on object. If last reference is freed, return
 * object to the cache, unless lu_object_is_dying(o) holds. In the latter
 * case, free object immediately.
 */
void lu_object_put(const struct lu_env *env, struct lu_object *o)
{
        struct lu_object_header *top;
        struct lu_site          *site;
        struct lu_object        *orig;
        int                      kill_it;

        top = o->lo_header;
        site = o->lo_dev->ld_site;
        orig = o;
        kill_it = 0;
        write_lock(&site->ls_guard);
        if (atomic_dec_and_test(&top->loh_ref)) {
                /*
                 * When last reference is released, iterate over object
                 * layers, and notify them that object is no longer busy.
                 */
                list_for_each_entry_reverse(o, &top->loh_layers, lo_linkage) {
                        if (o->lo_ops->loo_object_release != NULL)
                                o->lo_ops->loo_object_release(env, o);
                }
                -- site->ls_busy;
                if (lu_object_is_dying(top)) {
                        /*
                         * If object is dying (will not be cached), removed it
                         * from hash table and LRU.
                         *
                         * This is done with hash table and LRU lists
                         * locked. As the only way to acquire first reference
                         * to previously unreferenced object is through
                         * hash-table lookup (lu_object_find()), or LRU
                         * scanning (lu_site_purge()), that are done under
                         * hash-table and LRU lock, no race with concurrent
                         * object lookup is possible and we can safely destroy
                         * object below.
                         */
                        hlist_del_init(&top->loh_hash);
                        list_del_init(&top->loh_lru);
                        -- site->ls_total;
                        kill_it = 1;
                }
        }
        write_unlock(&site->ls_guard);
        if (kill_it)
                /*
                 * Object was already removed from hash and lru above, can
                 * kill it.
                 */
                lu_object_free(env, orig);
}
EXPORT_SYMBOL(lu_object_put);

/*
 * Allocate new object.
 *
 * This follows object creation protocol, described in the comment within
 * struct lu_device_operations definition.
 */
static struct lu_object *lu_object_alloc(const struct lu_env *env,
                                         struct lu_site *s,
                                         const struct lu_fid *f)
{
        struct lu_object *scan;
        struct lu_object *top;
        struct list_head *layers;
        int clean;
        int result;
        ENTRY;

        /*
         * Create top-level object slice. This will also create
         * lu_object_header.
         */
        top = s->ls_top_dev->ld_ops->ldo_object_alloc(env,
                                                      NULL, s->ls_top_dev);
        if (top == NULL)
                RETURN(ERR_PTR(-ENOMEM));
        /*
         * This is the only place where object fid is assigned. It's constant
         * after this point.
         */
        LASSERT(fid_is_igif(f) || fid_ver(f) == 0);
        top->lo_header->loh_fid  = *f;
        layers = &top->lo_header->loh_layers;
        do {
                /*
                 * Call ->loo_object_init() repeatedly, until no more new
                 * object slices are created.
                 */
                clean = 1;
                list_for_each_entry(scan, layers, lo_linkage) {
                        if (scan->lo_flags & LU_OBJECT_ALLOCATED)
                                continue;
                        clean = 0;
                        scan->lo_header = top->lo_header;
                        result = scan->lo_ops->loo_object_init(env, scan);
                        if (result != 0) {
                                lu_object_free(env, top);
                                RETURN(ERR_PTR(result));
                        }
                        scan->lo_flags |= LU_OBJECT_ALLOCATED;
                }
        } while (!clean);

        list_for_each_entry_reverse(scan, layers, lo_linkage) {
                if (scan->lo_ops->loo_object_start != NULL) {
                        result = scan->lo_ops->loo_object_start(env, scan);
                        if (result != 0) {
                                lu_object_free(env, top);
                                RETURN(ERR_PTR(result));
                        }
                }
        }

        s->ls_stats.s_created ++;
        RETURN(top);
}

/*
 * Free object.
 */
static void lu_object_free(const struct lu_env *env, struct lu_object *o)
{
        struct list_head splice;
        struct lu_object *scan;

        /*
         * First call ->loo_object_delete() method to release all resources.
         */
        list_for_each_entry_reverse(scan,
                                    &o->lo_header->loh_layers, lo_linkage) {
                if (scan->lo_ops->loo_object_delete != NULL)
                        scan->lo_ops->loo_object_delete(env, scan);
        }

        /*
         * Then, splice object layers into stand-alone list, and call
         * ->loo_object_free() on all layers to free memory. Splice is
         * necessary, because lu_object_header is freed together with the
         * top-level slice.
         */
        CFS_INIT_LIST_HEAD(&splice);
        list_splice_init(&o->lo_header->loh_layers, &splice);
        while (!list_empty(&splice)) {
                o = container_of0(splice.next, struct lu_object, lo_linkage);
                list_del_init(&o->lo_linkage);
                LASSERT(o->lo_ops->loo_object_free != NULL);
                o->lo_ops->loo_object_free(env, o);
        }
}

/*
 * Free @nr objects from the cold end of the site LRU list.
 */
int lu_site_purge(const struct lu_env *env, struct lu_site *s, int nr)
{
        struct list_head         dispose;
        struct lu_object_header *h;
        struct lu_object_header *temp;

        CFS_INIT_LIST_HEAD(&dispose);
        /*
         * Under LRU list lock, scan LRU list and move unreferenced objects to
         * the dispose list, removing them from LRU and hash table.
         */
        write_lock(&s->ls_guard);
        list_for_each_entry_safe(h, temp, &s->ls_lru, loh_lru) {
                /*
                 * Objects are sorted in lru order, and "busy" objects (ones
                 * with h->loh_ref > 0) naturally tend to live near hot end
                 * that we scan last. Unfortunately, sites usually have small
                 * (less then ten) number of busy yet rarely accessed objects
                 * (some global objects, accessed directly through pointers,
                 * bypassing hash table). Currently algorithm scans them over
                 * and over again. Probably we should move busy objects out of
                 * LRU, or we can live with that.
                 */
                if (nr-- == 0)
                        break;
                if (atomic_read(&h->loh_ref) > 0)
                        continue;
                hlist_del_init(&h->loh_hash);
                list_move(&h->loh_lru, &dispose);
                s->ls_total --;
        }
        write_unlock(&s->ls_guard);
        /*
         * Free everything on the dispose list. This is safe against races due
         * to the reasons described in lu_object_put().
         */
        while (!list_empty(&dispose)) {
                h = container_of0(dispose.next,
                                 struct lu_object_header, loh_lru);
                list_del_init(&h->loh_lru);
                lu_object_free(env, lu_object_top(h));
                s->ls_stats.s_lru_purged ++;
        }
        return nr;
}
EXPORT_SYMBOL(lu_site_purge);

/*
 * Object printing.
 *
 * Code below has to jump through certain loops to output object description
 * into libcfs_debug_msg-based log. The problem is that lu_object_print()
 * composes object description from strings that are parts of _lines_ of
 * output (i.e., strings that are not terminated by newline). This doesn't fit
 * very well into libcfs_debug_msg() interface that assumes that each message
 * supplied to it is a self-contained output line.
 *
 * To work around this, strings are collected in a temporary buffer
 * (implemented as a value of lu_cdebug_key key), until terminating newline
 * character is detected.
 *
 */

enum {
        /*
         * Maximal line size.
         *
         * XXX overflow is not handled correctly.
         */
        LU_CDEBUG_LINE = 256
};

struct lu_cdebug_data {
        /*
         * Temporary buffer.
         */
        char lck_area[LU_CDEBUG_LINE];
        /*
         * fid staging area used by dt_store_open().
         */
        struct lu_fid_pack lck_pack;
};

/* context key constructor/destructor: lu_global_key_init, lu_global_key_fini */
LU_KEY_INIT_FINI(lu_global, struct lu_cdebug_data);

/*
 * Key, holding temporary buffer. This key is registered very early by
 * lu_global_init().
 */
struct lu_context_key lu_global_key = {
        .lct_tags = LCT_MD_THREAD|LCT_DT_THREAD|LCT_CL_THREAD,
        .lct_init = lu_global_key_init,
        .lct_fini = lu_global_key_fini
};

/*
 * Printer function emitting messages through libcfs_debug_msg().
 */
int lu_cdebug_printer(const struct lu_env *env,
                      void *cookie, const char *format, ...)
{
        struct lu_cdebug_print_info *info = cookie;
        struct lu_cdebug_data       *key;
        int used;
        int complete;
	va_list args;

        va_start(args, format);

        key = lu_context_key_get(&env->le_ctx, &lu_global_key);
        LASSERT(key != NULL);

        used = strlen(key->lck_area);
        complete = format[strlen(format) - 1] == '\n';
        /*
         * Append new chunk to the buffer.
         */
        vsnprintf(key->lck_area + used,
                  ARRAY_SIZE(key->lck_area) - used, format, args);
        if (complete) {
                libcfs_debug_msg(NULL, info->lpi_subsys, info->lpi_mask,
                                 (char *)info->lpi_file, info->lpi_fn,
                                 info->lpi_line, "%s", key->lck_area);
                key->lck_area[0] = 0;
        }
        va_end(args);
        return 0;
}
EXPORT_SYMBOL(lu_cdebug_printer);

/*
 * Print object header.
 */
static void lu_object_header_print(const struct lu_env *env,
                                   void *cookie, lu_printer_t printer,
                                   const struct lu_object_header *hdr)
{
        (*printer)(env, cookie, "header@%p[%#lx, %d, "DFID"%s%s%s]",
                   hdr, hdr->loh_flags, atomic_read(&hdr->loh_ref),
                   PFID(&hdr->loh_fid),
                   hlist_unhashed(&hdr->loh_hash) ? "" : " hash",
                   list_empty(&hdr->loh_lru) ? "" : " lru",
                   hdr->loh_attr & LOHA_EXISTS ? " exist":"");
}

/*
 * Print human readable representation of the @o to the @printer.
 */
void lu_object_print(const struct lu_env *env, void *cookie,
                     lu_printer_t printer, const struct lu_object *o)
{
        static const char ruler[] = "........................................";
        struct lu_object_header *top;
        int depth;

        top = o->lo_header;
        lu_object_header_print(env, cookie, printer, top);
        (*printer)(env, cookie, "\n");
        list_for_each_entry(o, &top->loh_layers, lo_linkage) {
                depth = o->lo_depth + 4;
                LASSERT(o->lo_ops->loo_object_print != NULL);
                /*
                 * print `.' @depth times.
                 */
                (*printer)(env, cookie, "%*.*s", depth, depth, ruler);
                o->lo_ops->loo_object_print(env, cookie, printer, o);
                (*printer)(env, cookie, "\n");
        }
}
EXPORT_SYMBOL(lu_object_print);

/*
 * Check object consistency.
 */
int lu_object_invariant(const struct lu_object *o)
{
        struct lu_object_header *top;

        top = o->lo_header;
        list_for_each_entry(o, &top->loh_layers, lo_linkage) {
                if (o->lo_ops->loo_object_invariant != NULL &&
                    !o->lo_ops->loo_object_invariant(o))
                        return 0;
        }
        return 1;
}
EXPORT_SYMBOL(lu_object_invariant);

static struct lu_object *htable_lookup(struct lu_site *s,
                                       const struct hlist_head *bucket,
                                       const struct lu_fid *f)
{
        struct lu_object_header *h;
        struct hlist_node *scan;

        hlist_for_each_entry(h, scan, bucket, loh_hash) {
                s->ls_stats.s_cache_check ++;
                if (likely(lu_fid_eq(&h->loh_fid, f) &&
                           !lu_object_is_dying(h))) {
                        /* bump reference count... */
                        if (atomic_add_return(1, &h->loh_ref) == 1)
                                ++ s->ls_busy;
                        /* and move to the head of the LRU */
                        /*
                         * XXX temporary disable this to measure effects of
                         * read-write locking.
                         */
                        /* list_move_tail(&h->loh_lru, &s->ls_lru); */
                        s->ls_stats.s_cache_hit ++;
                        return lu_object_top(h);
                }
        }
        s->ls_stats.s_cache_miss ++;
        return NULL;
}

static __u32 fid_hash(const struct lu_fid *f, int bits)
{
        /* all objects with same id and different versions will belong to same
         * collisions list. */
        return hash_long(fid_flatten(f), bits);
}

/*
 * Search cache for an object with the fid @f. If such object is found, return
 * it. Otherwise, create new object, insert it into cache and return it. In
 * any case, additional reference is acquired on the returned object.
 */
struct lu_object *lu_object_find(const struct lu_env *env,
                                 struct lu_site *s, const struct lu_fid *f)
{
        struct lu_object     *o;
        struct lu_object     *shadow;
        struct hlist_head *bucket;

        /*
         * This uses standard index maintenance protocol:
         *
         *     - search index under lock, and return object if found;
         *     - otherwise, unlock index, allocate new object;
         *     - lock index and search again;
         *     - if nothing is found (usual case), insert newly created
         *       object into index;
         *     - otherwise (race: other thread inserted object), free
         *       object just allocated.
         *     - unlock index;
         *     - return object.
         */

        bucket = s->ls_hash + fid_hash(f, s->ls_hash_bits);

        read_lock(&s->ls_guard);
        o = htable_lookup(s, bucket, f);
        read_unlock(&s->ls_guard);

        if (o != NULL)
                return o;

        /*
         * Allocate new object. This may result in rather complicated
         * operations, including fld queries, inode loading, etc.
         */
        o = lu_object_alloc(env, s, f);
        if (unlikely(IS_ERR(o)))
                return o;

        LASSERT(lu_fid_eq(lu_object_fid(o), f));

        write_lock(&s->ls_guard);
        shadow = htable_lookup(s, bucket, f);
        if (likely(shadow == NULL)) {
                hlist_add_head(&o->lo_header->loh_hash, bucket);
                list_add_tail(&o->lo_header->loh_lru, &s->ls_lru);
                ++ s->ls_busy;
                ++ s->ls_total;
                shadow = o;
                o = NULL;
        } else
                s->ls_stats.s_cache_race ++;
        write_unlock(&s->ls_guard);
        if (o != NULL)
                lu_object_free(env, o);
        return shadow;
}
EXPORT_SYMBOL(lu_object_find);

/*
 * Global list of all sites on this node
 */
static CFS_LIST_HEAD(lu_sites);
static DECLARE_MUTEX(lu_sites_guard);

/*
 * Global environment used by site shrinker.
 */
static struct lu_env lu_shrink_env;

/*
 * Print all objects in @s.
 */
void lu_site_print(const struct lu_env *env, struct lu_site *s, void *cookie,
                   lu_printer_t printer)
{
        int i;

        for (i = 0; i < s->ls_hash_size; ++i) {
                struct lu_object_header *h;
                struct hlist_node       *scan;

                read_lock(&s->ls_guard);
                hlist_for_each_entry(h, scan, &s->ls_hash[i], loh_hash) {

                        if (!list_empty(&h->loh_layers)) {
                                const struct lu_object *obj;

                                obj = lu_object_top(h);
                                lu_object_print(env, cookie, printer, obj);
                        } else
                                lu_object_header_print(env, cookie, printer, h);
                }
                read_unlock(&s->ls_guard);
        }
}
EXPORT_SYMBOL(lu_site_print);

enum {
        LU_CACHE_PERCENT   = 30,
};

/*
 * Return desired hash table order.
 */
static int lu_htable_order(void)
{
        int bits;
        unsigned long cache_size;

        /*
         * Calculate hash table size, assuming that we want reasonable
         * performance when 30% of available memory is occupied by cache of
         * lu_objects.
         *
         * Size of lu_object is (arbitrary) taken as 1K (together with inode).
         */
        cache_size = ll_nr_free_buffer_pages() / 100 *
                LU_CACHE_PERCENT * (CFS_PAGE_SIZE / 1024);

        for (bits = 1; (1 << bits) < cache_size; ++bits) {
                ;
        }
        return bits;
}

/*
 * Initialize site @s, with @d as the top level device.
 */
int lu_site_init(struct lu_site *s, struct lu_device *top)
{
        int bits;
        int size;
        int i;
        ENTRY;

        memset(s, 0, sizeof *s);
        rwlock_init(&s->ls_guard);
        CFS_INIT_LIST_HEAD(&s->ls_lru);
        CFS_INIT_LIST_HEAD(&s->ls_linkage);
        s->ls_top_dev = top;
        top->ld_site = s;
        lu_device_get(top);

        for (bits = lu_htable_order(), size = 1 << bits;
             (s->ls_hash =
              cfs_alloc_large(size * sizeof s->ls_hash[0])) == NULL;
             --bits, size >>= 1) {
                /*
                 * Scale hash table down, until allocation succeeds.
                 */
                ;
        }

        s->ls_hash_size = size;
        s->ls_hash_bits = bits;
        s->ls_hash_mask = size - 1;

        for (i = 0; i < size; i++)
                INIT_HLIST_HEAD(&s->ls_hash[i]);

        RETURN(0);
}
EXPORT_SYMBOL(lu_site_init);

/*
 * Finalize @s and release its resources.
 */
void lu_site_fini(struct lu_site *s)
{
        LASSERT(list_empty(&s->ls_lru));
        LASSERT(s->ls_total == 0);

        down(&lu_sites_guard);
        list_del_init(&s->ls_linkage);
        up(&lu_sites_guard);

        if (s->ls_hash != NULL) {
                int i;
                for (i = 0; i < s->ls_hash_size; i++)
                        LASSERT(hlist_empty(&s->ls_hash[i]));
                cfs_free_large(s->ls_hash);
                s->ls_hash = NULL;
        }
        if (s->ls_top_dev != NULL) {
                s->ls_top_dev->ld_site = NULL;
                lu_device_put(s->ls_top_dev);
                s->ls_top_dev = NULL;
        }
}
EXPORT_SYMBOL(lu_site_fini);

/*
 * Called when initialization of stack for this site is completed.
 */
int lu_site_init_finish(struct lu_site *s)
{
        int result;
        down(&lu_sites_guard);
        result = lu_context_refill(&lu_shrink_env.le_ctx);
        if (result == 0)
                list_add(&s->ls_linkage, &lu_sites);
        up(&lu_sites_guard);
        return result;
}
EXPORT_SYMBOL(lu_site_init_finish);

/*
 * Acquire additional reference on device @d
 */
void lu_device_get(struct lu_device *d)
{
        atomic_inc(&d->ld_ref);
}
EXPORT_SYMBOL(lu_device_get);

/*
 * Release reference on device @d.
 */
void lu_device_put(struct lu_device *d)
{
        atomic_dec(&d->ld_ref);
}
EXPORT_SYMBOL(lu_device_put);

/*
 * Initialize device @d of type @t.
 */
int lu_device_init(struct lu_device *d, struct lu_device_type *t)
{
        memset(d, 0, sizeof *d);
        atomic_set(&d->ld_ref, 0);
        d->ld_type = t;
        return 0;
}
EXPORT_SYMBOL(lu_device_init);

/*
 * Finalize device @d.
 */
void lu_device_fini(struct lu_device *d)
{
        if (d->ld_obd != NULL)
                /* finish lprocfs */
                lprocfs_obd_cleanup(d->ld_obd);

        LASSERTF(atomic_read(&d->ld_ref) == 0,
                 "Refcount is %u\n", atomic_read(&d->ld_ref));
}
EXPORT_SYMBOL(lu_device_fini);

/*
 * Initialize object @o that is part of compound object @h and was created by
 * device @d.
 */
int lu_object_init(struct lu_object *o,
                   struct lu_object_header *h, struct lu_device *d)
{
        memset(o, 0, sizeof *o);
        o->lo_header = h;
        o->lo_dev    = d;
        lu_device_get(d);
        CFS_INIT_LIST_HEAD(&o->lo_linkage);
        return 0;
}
EXPORT_SYMBOL(lu_object_init);

/*
 * Finalize object and release its resources.
 */
void lu_object_fini(struct lu_object *o)
{
        LASSERT(list_empty(&o->lo_linkage));

        if (o->lo_dev != NULL) {
                lu_device_put(o->lo_dev);
                o->lo_dev = NULL;
        }
}
EXPORT_SYMBOL(lu_object_fini);

/*
 * Add object @o as first layer of compound object @h
 *
 * This is typically called by the ->ldo_object_alloc() method of top-level
 * device.
 */
void lu_object_add_top(struct lu_object_header *h, struct lu_object *o)
{
        list_move(&o->lo_linkage, &h->loh_layers);
}
EXPORT_SYMBOL(lu_object_add_top);

/*
 * Add object @o as a layer of compound object, going after @before.1
 *
 * This is typically called by the ->ldo_object_alloc() method of
 * @before->lo_dev.
 */
void lu_object_add(struct lu_object *before, struct lu_object *o)
{
        list_move(&o->lo_linkage, &before->lo_linkage);
}
EXPORT_SYMBOL(lu_object_add);

/*
 * Initialize compound object.
 */
int lu_object_header_init(struct lu_object_header *h)
{
        memset(h, 0, sizeof *h);
        atomic_set(&h->loh_ref, 1);
        INIT_HLIST_NODE(&h->loh_hash);
        CFS_INIT_LIST_HEAD(&h->loh_lru);
        CFS_INIT_LIST_HEAD(&h->loh_layers);
        return 0;
}
EXPORT_SYMBOL(lu_object_header_init);

/*
 * Finalize compound object.
 */
void lu_object_header_fini(struct lu_object_header *h)
{
        LASSERT(list_empty(&h->loh_layers));
        LASSERT(list_empty(&h->loh_lru));
        LASSERT(hlist_unhashed(&h->loh_hash));
}
EXPORT_SYMBOL(lu_object_header_fini);

/*
 * Given a compound object, find its slice, corresponding to the device type
 * @dtype.
 */
struct lu_object *lu_object_locate(struct lu_object_header *h,
                                   struct lu_device_type *dtype)
{
        struct lu_object *o;

        list_for_each_entry(o, &h->loh_layers, lo_linkage) {
                if (o->lo_dev->ld_type == dtype)
                        return o;
        }
        return NULL;
}
EXPORT_SYMBOL(lu_object_locate);



/*
 * Finalize and free devices in the device stack.
 * 
 * Finalize device stack by purging object cache, and calling
 * lu_device_type_operations::ldto_device_fini() and
 * lu_device_type_operations::ldto_device_free() on all devices in the stack.
 */
void lu_stack_fini(const struct lu_env *env, struct lu_device *top)
{
        struct lu_site   *site = top->ld_site;
        struct lu_device *scan;
        struct lu_device *next;

        lu_site_purge(env, site, ~0);
        for (scan = top; scan != NULL; scan = next) {
                next = scan->ld_type->ldt_ops->ldto_device_fini(env, scan);
                lu_device_put(scan);
        }

        /* purge again. */
        lu_site_purge(env, site, ~0);

        if (!list_empty(&site->ls_lru) || site->ls_total != 0) {
                /*
                 * Uh-oh, objects still exist.
                 */
                static DECLARE_LU_CDEBUG_PRINT_INFO(cookie, D_ERROR);

                lu_site_print(env, site, &cookie, lu_cdebug_printer);
        }

        for (scan = top; scan != NULL; scan = next) {
                const struct lu_device_type *ldt = scan->ld_type;
                struct obd_type             *type;

                next = ldt->ldt_ops->ldto_device_free(env, scan);
                type = ldt->ldt_obd_type;
                type->typ_refcnt--;
                class_put_type(type);
        }
}
EXPORT_SYMBOL(lu_stack_fini);

enum {
        /*
         * Maximal number of tld slots.
         */
        LU_CONTEXT_KEY_NR = 16
};

static struct lu_context_key *lu_keys[LU_CONTEXT_KEY_NR] = { NULL, };

static spinlock_t lu_keys_guard = SPIN_LOCK_UNLOCKED;

/*
 * Register new key.
 */
int lu_context_key_register(struct lu_context_key *key)
{
        int result;
        int i;

        LASSERT(key->lct_init != NULL);
        LASSERT(key->lct_fini != NULL);
        LASSERT(key->lct_tags != 0);
        LASSERT(key->lct_owner != NULL);

        result = -ENFILE;
        spin_lock(&lu_keys_guard);
        for (i = 0; i < ARRAY_SIZE(lu_keys); ++i) {
                if (lu_keys[i] == NULL) {
                        key->lct_index = i;
                        atomic_set(&key->lct_used, 1);
                        lu_keys[i] = key;
                        result = 0;
                        break;
                }
        }
        spin_unlock(&lu_keys_guard);
        return result;
}
EXPORT_SYMBOL(lu_context_key_register);

static void key_fini(struct lu_context *ctx, int index)
{
        if (ctx->lc_value[index] != NULL) {
                struct lu_context_key *key;

                key = lu_keys[index];
                LASSERT(key != NULL);
                LASSERT(key->lct_fini != NULL);
                LASSERT(atomic_read(&key->lct_used) > 1);

                key->lct_fini(ctx, key, ctx->lc_value[index]);
                atomic_dec(&key->lct_used);
                LASSERT(key->lct_owner != NULL);
                if (!(ctx->lc_tags & LCT_NOREF)) {
                        LASSERT(module_refcount(key->lct_owner) > 0);
                        module_put(key->lct_owner);
                }
                ctx->lc_value[index] = NULL;
        }
}

/*
 * Deregister key.
 */
void lu_context_key_degister(struct lu_context_key *key)
{
        LASSERT(atomic_read(&key->lct_used) >= 1);
        LASSERT(0 <= key->lct_index && key->lct_index < ARRAY_SIZE(lu_keys));

        key_fini(&lu_shrink_env.le_ctx, key->lct_index);

        if (atomic_read(&key->lct_used) > 1)
                CERROR("key has instances.\n");
        spin_lock(&lu_keys_guard);
        lu_keys[key->lct_index] = NULL;
        spin_unlock(&lu_keys_guard);
}
EXPORT_SYMBOL(lu_context_key_degister);

/*
 * Return value associated with key @key in context @ctx.
 */
void *lu_context_key_get(const struct lu_context *ctx,
                         struct lu_context_key *key)
{
        LASSERT(ctx->lc_state == LCS_ENTERED);
        LASSERT(0 <= key->lct_index && key->lct_index < ARRAY_SIZE(lu_keys));
        return ctx->lc_value[key->lct_index];
}
EXPORT_SYMBOL(lu_context_key_get);

static void keys_fini(struct lu_context *ctx)
{
        int i;

        if (ctx->lc_value != NULL) {
                for (i = 0; i < ARRAY_SIZE(lu_keys); ++i)
                        key_fini(ctx, i);
                OBD_FREE(ctx->lc_value,
                         ARRAY_SIZE(lu_keys) * sizeof ctx->lc_value[0]);
                ctx->lc_value = NULL;
        }
}

static int keys_fill(const struct lu_context *ctx)
{
        int i;

        for (i = 0; i < ARRAY_SIZE(lu_keys); ++i) {
                struct lu_context_key *key;

                key = lu_keys[i];
                if (ctx->lc_value[i] == NULL &&
                    key != NULL && key->lct_tags & ctx->lc_tags) {
                        void *value;

                        LASSERT(key->lct_init != NULL);
                        LASSERT(key->lct_index == i);

                        value = key->lct_init(ctx, key);
                        if (unlikely(IS_ERR(value)))
                                return PTR_ERR(value);
                        LASSERT(key->lct_owner != NULL);
                        if (!(ctx->lc_tags & LCT_NOREF))
                                try_module_get(key->lct_owner);
                        atomic_inc(&key->lct_used);
                        ctx->lc_value[i] = value;
                }
        }
        return 0;
}

static int keys_init(struct lu_context *ctx)
{
        int result;

        OBD_ALLOC(ctx->lc_value, ARRAY_SIZE(lu_keys) * sizeof ctx->lc_value[0]);
        if (likely(ctx->lc_value != NULL))
                result = keys_fill(ctx);
        else
                result = -ENOMEM;

        if (result != 0)
                keys_fini(ctx);
        return result;
}

/*
 * Initialize context data-structure. Create values for all keys.
 */
int lu_context_init(struct lu_context *ctx, __u32 tags)
{
        memset(ctx, 0, sizeof *ctx);
        ctx->lc_state = LCS_INITIALIZED;
        ctx->lc_tags = tags;
        return keys_init(ctx);
}
EXPORT_SYMBOL(lu_context_init);

/*
 * Finalize context data-structure. Destroy key values.
 */
void lu_context_fini(struct lu_context *ctx)
{
        LASSERT(ctx->lc_state == LCS_INITIALIZED || ctx->lc_state == LCS_LEFT);
        ctx->lc_state = LCS_FINALIZED;
        keys_fini(ctx);
}
EXPORT_SYMBOL(lu_context_fini);

/*
 * Called before entering context.
 */
void lu_context_enter(struct lu_context *ctx)
{
        LASSERT(ctx->lc_state == LCS_INITIALIZED || ctx->lc_state == LCS_LEFT);
        ctx->lc_state = LCS_ENTERED;
}
EXPORT_SYMBOL(lu_context_enter);

/*
 * Called after exiting from @ctx
 */
void lu_context_exit(struct lu_context *ctx)
{
        int i;

        LASSERT(ctx->lc_state == LCS_ENTERED);
        ctx->lc_state = LCS_LEFT;
        if (ctx->lc_value != NULL) {
                for (i = 0; i < ARRAY_SIZE(lu_keys); ++i) {
                        if (ctx->lc_value[i] != NULL) {
                                struct lu_context_key *key;

                                key = lu_keys[i];
                                LASSERT(key != NULL);
                                if (key->lct_exit != NULL)
                                        key->lct_exit(ctx,
                                                      key, ctx->lc_value[i]);
                        }
                }
        }
}
EXPORT_SYMBOL(lu_context_exit);

/*
 * Allocate for context all missing keys that were registered after context
 * creation.
 */
int lu_context_refill(const struct lu_context *ctx)
{
        LASSERT(ctx->lc_value != NULL);
        return keys_fill(ctx);
}
EXPORT_SYMBOL(lu_context_refill);

static int lu_env_setup(struct lu_env *env, struct lu_context *ses,
                        __u32 tags, int noref)
{
        int result;

        LASSERT(ergo(!noref, !(tags & LCT_NOREF)));

        env->le_ses = ses;
        result = lu_context_init(&env->le_ctx, tags);
        if (likely(result == 0))
                lu_context_enter(&env->le_ctx);
        return result;
}

static int lu_env_init_noref(struct lu_env *env, struct lu_context *ses,
                             __u32 tags)
{
        return lu_env_setup(env, ses, tags, 1);
}

int lu_env_init(struct lu_env *env, struct lu_context *ses, __u32 tags)
{
        return lu_env_setup(env, ses, tags, 0);
}
EXPORT_SYMBOL(lu_env_init);

void lu_env_fini(struct lu_env *env)
{
        lu_context_exit(&env->le_ctx);
        lu_context_fini(&env->le_ctx);
        env->le_ses = NULL;
}
EXPORT_SYMBOL(lu_env_fini);

static int lu_cache_shrink(int nr, unsigned int gfp_mask)
{
        struct lu_site *s;
        struct lu_site *tmp;
        int cached = 0;
        int remain = nr;
        CFS_LIST_HEAD(splice);

        if (nr != 0 && !(gfp_mask & __GFP_FS))
                return -1;

        down(&lu_sites_guard);
        list_for_each_entry_safe(s, tmp, &lu_sites, ls_linkage) {
                if (nr != 0) {
                        remain = lu_site_purge(&lu_shrink_env, s, remain);
                        /*
                         * Move just shrunk site to the tail of site list to
                         * assure shrinking fairness.
                         */
                        list_move_tail(&s->ls_linkage, &splice);
                }
                read_lock(&s->ls_guard);
                cached += s->ls_total - s->ls_busy;
                read_unlock(&s->ls_guard);
                if (remain <= 0)
                        break;
        }
        list_splice(&splice, lu_sites.prev);
        up(&lu_sites_guard);
        return cached;
}

static struct shrinker *lu_site_shrinker = NULL;

/*
 * Initialization of global lu_* data.
 */
int lu_global_init(void)
{
        int result;

        LU_CONTEXT_KEY_INIT(&lu_global_key);
        result = lu_context_key_register(&lu_global_key);
        if (result == 0) {
                /*
                 * At this level, we don't know what tags are needed, so
                 * allocate them conservatively. This should not be too bad,
                 * because this environment is global.
                 */
                down(&lu_sites_guard);
                result = lu_env_init_noref(&lu_shrink_env, NULL, LCT_SHRINKER);
                up(&lu_sites_guard);
                if (result == 0) {
                        /*
                         * seeks estimation: 3 seeks to read a record from oi,
                         * one to read inode, one for ea. Unfortunately
                         * setting this high value results in lu_object/inode
                         * cache consuming all the memory.
                         */
                        lu_site_shrinker = set_shrinker(DEFAULT_SEEKS,
                                                        lu_cache_shrink);
                        if (result == 0)
                                result = lu_time_global_init();
                }
        }
        return result;
}

/*
 * Dual to lu_global_init().
 */
void lu_global_fini(void)
{
        lu_time_global_fini();
        if (lu_site_shrinker != NULL) {
                remove_shrinker(lu_site_shrinker);
                lu_site_shrinker = NULL;
        }

        lu_context_key_degister(&lu_global_key);

        /*
         * Tear shrinker environment down _after_ de-registering
         * lu_global_key, because the latter has a value in the former.
         */
        down(&lu_sites_guard);
        lu_env_fini(&lu_shrink_env);
        up(&lu_sites_guard);
}

struct lu_buf LU_BUF_NULL = {
        .lb_buf = NULL,
        .lb_len = 0
};
EXPORT_SYMBOL(LU_BUF_NULL);

/*
 * XXX: Functions below logically belong to fid module, but they are used by
 * dt_store_open(). Put them here until better place is found.
 */

void fid_pack(struct lu_fid_pack *pack, const struct lu_fid *fid,
              struct lu_fid *befider)
{
        int recsize;
        __u64 seq;
        __u32 oid;

        seq = fid_seq(fid);
        oid = fid_oid(fid);

        /*
         * Two cases: compact 6 bytes representation for a common case, and
         * full 17 byte representation for "unusual" fid.
         */

        /*
         * Check that usual case is really usual.
         */
        CLASSERT(LUSTRE_SEQ_MAX_WIDTH < 0xffffull);

        if (fid_is_igif(fid) ||
            seq > 0xffffffull || oid > 0xffff || fid_ver(fid) != 0) {
                fid_cpu_to_be(befider, fid);
                recsize = sizeof *befider;
        } else {
                unsigned char *small_befider;

                small_befider = (char *)befider;

                small_befider[0] = seq >> 16;
                small_befider[1] = seq >> 8;
                small_befider[2] = seq;

                small_befider[3] = oid >> 8;
                small_befider[4] = oid;

                recsize = 5;
        }
        memcpy(pack->fp_area, befider, recsize);
        pack->fp_len = recsize + 1;
}
EXPORT_SYMBOL(fid_pack);

int fid_unpack(const struct lu_fid_pack *pack, struct lu_fid *fid)
{
        int result;

        result = 0;
        switch (pack->fp_len) {
        case sizeof *fid + 1:
                memcpy(fid, pack->fp_area, sizeof *fid);
                fid_be_to_cpu(fid, fid);
                break;
        case 6: {
                const unsigned char *area;

                area = pack->fp_area;
                fid->f_seq = (area[0] << 16) | (area[1] << 8) | area[2];
                fid->f_oid = (area[3] << 8) | area[4];
                fid->f_ver = 0;
                break;
        }
        default:
                CERROR("Unexpected packed fid size: %d\n", pack->fp_len);
                result = -EIO;
        }
        return result;
}
EXPORT_SYMBOL(fid_unpack);

const char *lu_time_names[LU_TIME_NR] = {
        [LU_TIME_FIND_LOOKUP] = "find_lookup",
        [LU_TIME_FIND_ALLOC]  = "find_alloc",
        [LU_TIME_FIND_INSERT] = "find_insert"
};
EXPORT_SYMBOL(lu_time_names);
