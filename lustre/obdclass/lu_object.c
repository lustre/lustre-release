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
#include <obd_support.h>
#include <lustre_disk.h>
#include <lustre_fid.h>
#include <lu_object.h>
#include <libcfs/list.h>

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
        spin_lock(&site->ls_guard);
        if (-- top->loh_ref == 0) {
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
                        kill_it = 1;
                }
        }
        spin_unlock(&site->ls_guard);
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
                                         const struct lu_fid *f,
                                         const struct lustre_capa *capa)
{
        struct lu_object *scan;
        struct lu_object *top;
        struct list_head *layers;
        int clean;
        int result;

        /*
         * Create top-level object slice. This will also create
         * lu_object_header.
         */
        top = s->ls_top_dev->ld_ops->ldo_object_alloc(env,
                                                      NULL, s->ls_top_dev);
        if (IS_ERR(top))
                RETURN(top);
        s->ls_total ++;
        /*
         * This is the only place where object fid is assigned. It's constant
         * after this point.
         */
        top->lo_header->loh_fid  = *f;
        if (capa == BYPASS_CAPA)
                lu_object_bypass_capa(top);
        else
                top->lo_header->loh_capa = *capa;
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
        -- o->lo_dev->ld_site->ls_total;
        /*
         * Then, splice object layers into stand-alone list, and call
         * ->loo_object_free() on all layers to free memory. Splice is
         * necessary, because lu_object_header is freed together with the
         * top-level slice.
         */
        INIT_LIST_HEAD(&splice);
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
void lu_site_purge(const struct lu_env *env, struct lu_site *s, int nr)
{
        struct list_head         dispose;
        struct lu_object_header *h;
        struct lu_object_header *temp;

        INIT_LIST_HEAD(&dispose);
        /*
         * Under LRU list lock, scan LRU list and move unreferenced objects to
         * the dispose list, removing them from LRU and hash table.
         */
        spin_lock(&s->ls_guard);
        list_for_each_entry_safe(h, temp, &s->ls_lru, loh_lru) {
                if (nr-- == 0)
                        break;
                if (h->loh_ref > 0)
                        continue;
                hlist_del_init(&h->loh_hash);
                list_move(&h->loh_lru, &dispose);
        }
        spin_unlock(&s->ls_guard);
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
};

static void *lu_cdebug_key_init(const struct lu_context *ctx,
                                struct lu_context_key *key)
{
        struct lu_cdebug_data *value;

        OBD_ALLOC_PTR(value);
        if (value == NULL)
                value = ERR_PTR(-ENOMEM);
        return value;
}

static void lu_cdebug_key_fini(const struct lu_context *ctx,
                               struct lu_context_key *key, void *data)
{
        struct lu_cdebug_data *value = data;
        OBD_FREE_PTR(value);
}

/*
 * Key, holding temporary buffer. This key is registered very early by
 * lu_global_init().
 */
static struct lu_context_key lu_cdebug_key = {
        .lct_tags = LCT_MD_THREAD|LCT_DT_THREAD|LCT_CL_THREAD,
        .lct_init = lu_cdebug_key_init,
        .lct_fini = lu_cdebug_key_fini
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

        key = lu_context_key_get(&env->le_ctx, &lu_cdebug_key);
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
        (*printer)(env, cookie, "header@%p[%#lx, %d, "DFID"%s%s]",
                   hdr, hdr->loh_flags, hdr->loh_ref, PFID(&hdr->loh_fid),
                   hlist_unhashed(&hdr->loh_hash) ? "" : " hash",
                   list_empty(&hdr->loh_lru) ? "" : " lru");
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
                if (lu_fid_eq(&h->loh_fid, f) && !lu_object_is_dying(h)) {
                        /* bump reference count... */
                        if (h->loh_ref ++ == 0)
                                ++ s->ls_busy;
                        /* and move to the head of the LRU */
                        list_move_tail(&h->loh_lru, &s->ls_lru);
                        s->ls_stats.s_cache_hit ++;
                        return lu_object_top(h);
                }
        }
        s->ls_stats.s_cache_miss ++;
        return NULL;
}

static __u32 fid_hash(const struct lu_fid *f)
{
        /* all objects with same id and different versions will belong to same
         * collisions list. */
        return (fid_seq(f) - 1) * LUSTRE_SEQ_MAX_WIDTH + fid_oid(f);
}

/*
 * Search cache for an object with the fid @f. If such object is found, return
 * it. Otherwise, create new object, insert it into cache and return it. In
 * any case, additional reference is acquired on the returned object.
 */
struct lu_object *lu_object_find(const struct lu_env *env,
                                 struct lu_site *s, const struct lu_fid *f,
                                 struct lustre_capa *capa)
{
        struct lu_object  *o;
        struct lu_object  *shadow;
        struct hlist_head *bucket;
        int                rc;

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

        bucket = s->ls_hash + (fid_hash(f) & s->ls_hash_mask);
        spin_lock(&s->ls_guard);
        o = htable_lookup(s, bucket, f);

        spin_unlock(&s->ls_guard);
        if (o != NULL) {
                if (capa == BYPASS_CAPA) {
                        o->lo_header->loh_capa_bypass = 1;
                } else {
                        rc = lu_object_auth(env, o, capa,
                                            CAPA_OPC_INDEX_LOOKUP);
                        if (rc)
                                return ERR_PTR(rc);
                        if (capa)
                                o->lo_header->loh_capa = *capa;
                }
                return o;
        }

        /*
         * Allocate new object. This may result in rather complicated
         * operations, including fld queries, inode loading, etc.
         */
        o = lu_object_alloc(env, s, f, capa);
        if (IS_ERR(o))
                return o;

        LASSERT(lu_fid_eq(lu_object_fid(o), f));

        spin_lock(&s->ls_guard);
        shadow = htable_lookup(s, bucket, f);
        if (shadow == NULL) {
                hlist_add_head(&o->lo_header->loh_hash, bucket);
                list_add_tail(&o->lo_header->loh_lru, &s->ls_lru);
                ++ s->ls_busy;
                shadow = o;
                o = NULL;
        } else
                s->ls_stats.s_cache_race ++;
        spin_unlock(&s->ls_guard);
        if (o != NULL)
                lu_object_free(env, o);
        return shadow;
}
EXPORT_SYMBOL(lu_object_find);

int lu_object_auth(const struct lu_env *env, const struct lu_object *o,
                   struct lustre_capa *capa, __u64 opc)
{
        struct lu_object_header *top = o->lo_header;
        int rc;

        list_for_each_entry(o, &top->loh_layers, lo_linkage) {
                if (o->lo_ops->loo_object_auth) {
                        rc = o->lo_ops->loo_object_auth(env, o, capa, opc);
                        if (rc)
                                return rc;
                }
        }

        return 0;
}
EXPORT_SYMBOL(lu_object_auth);

enum {
        LU_SITE_HTABLE_BITS = 8,
        LU_SITE_HTABLE_SIZE = (1 << LU_SITE_HTABLE_BITS),
        LU_SITE_HTABLE_MASK = LU_SITE_HTABLE_SIZE - 1
};

/*
 * Initialize site @s, with @d as the top level device.
 */
int lu_site_init(struct lu_site *s, struct lu_device *top)
{
        int result;
        ENTRY;

        memset(s, 0, sizeof *s);
        spin_lock_init(&s->ls_guard);
        CFS_INIT_LIST_HEAD(&s->ls_lru);
        s->ls_top_dev = top;
        top->ld_site = s;
        lu_device_get(top);
        /*
         * XXX nikita: fixed size hash-table.
         */
        s->ls_hash_mask = LU_SITE_HTABLE_MASK;
        OBD_ALLOC(s->ls_hash, LU_SITE_HTABLE_SIZE * sizeof s->ls_hash[0]);
        if (s->ls_hash != NULL) {
                int i;
                for (i = 0; i < LU_SITE_HTABLE_SIZE; i++)
                        INIT_HLIST_HEAD(&s->ls_hash[i]);
                result = 0;
        } else {
                result = -ENOMEM;
        }

        RETURN(result);
}
EXPORT_SYMBOL(lu_site_init);

/*
 * Finalize @s and release its resources.
 */
void lu_site_fini(struct lu_site *s)
{
        LASSERT(list_empty(&s->ls_lru));
        LASSERT(s->ls_total == 0);
        LASSERT(s->ls_busy == 0);

        if (s->ls_hash != NULL) {
                int i;
                for (i = 0; i < LU_SITE_HTABLE_SIZE; i++)
                        LASSERT(hlist_empty(&s->ls_hash[i]));
                OBD_FREE(s->ls_hash,
                         LU_SITE_HTABLE_SIZE * sizeof s->ls_hash[0]);
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
        h->loh_ref = 1;
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

/*
 * Deregister key.
 */
void lu_context_key_degister(struct lu_context_key *key)
{
        LASSERT(atomic_read(&key->lct_used) >= 1);
        LASSERT(0 <= key->lct_index && key->lct_index < ARRAY_SIZE(lu_keys));

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
        LASSERT(0 <= key->lct_index && key->lct_index < ARRAY_SIZE(lu_keys));
        return ctx->lc_value[key->lct_index];
}
EXPORT_SYMBOL(lu_context_key_get);

static void keys_fini(struct lu_context *ctx)
{
        int i;

        if (ctx->lc_value != NULL) {
                for (i = 0; i < ARRAY_SIZE(lu_keys); ++i) {
                        if (ctx->lc_value[i] != NULL) {
                                struct lu_context_key *key;

                                key = lu_keys[i];
                                LASSERT(key != NULL);
                                LASSERT(key->lct_fini != NULL);
                                LASSERT(atomic_read(&key->lct_used) > 1);

                                key->lct_fini(ctx, key, ctx->lc_value[i]);
                                atomic_dec(&key->lct_used);
                                ctx->lc_value[i] = NULL;
                        }
                }
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
                        if (IS_ERR(value))
                                return PTR_ERR(value);
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
        if (ctx->lc_value != NULL)
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
        ctx->lc_tags = tags;
        return keys_init(ctx);
}
EXPORT_SYMBOL(lu_context_init);

/*
 * Finalize context data-structure. Destroy key values.
 */
void lu_context_fini(struct lu_context *ctx)
{
        keys_fini(ctx);
}
EXPORT_SYMBOL(lu_context_fini);

/*
 * Called before entering context.
 */
void lu_context_enter(struct lu_context *ctx)
{
}
EXPORT_SYMBOL(lu_context_enter);

/*
 * Called after exiting from @ctx
 */
void lu_context_exit(struct lu_context *ctx)
{
        int i;

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

int lu_env_init(struct lu_env *env, struct lu_context *ses, __u32 tags)
{
        int result;

        env->le_ses = ses;
        result = lu_context_init(&env->le_ctx, tags);
        if (result == 0)
                lu_context_enter(&env->le_ctx);
        return result;
}
EXPORT_SYMBOL(lu_env_init);

void lu_env_fini(struct lu_env *env)
{
        lu_context_exit(&env->le_ctx);
        lu_context_fini(&env->le_ctx);
        env->le_ses = NULL;
}
EXPORT_SYMBOL(lu_env_fini);

/*
 * Initialization of global lu_* data.
 */
int lu_global_init(void)
{
        int result;

        result = lu_context_key_register(&lu_cdebug_key);
        return result;
}

/*
 * Dual to lu_global_init().
 */
void lu_global_fini(void)
{
        lu_context_key_degister(&lu_cdebug_key);
}

struct lu_buf LU_BUF_NULL = {
        .lb_buf = NULL,
        .lb_len = 0
};
EXPORT_SYMBOL(LU_BUF_NULL);
