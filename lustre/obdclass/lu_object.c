/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Object.
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
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
#include <linux/obd_support.h>
#include <linux/lu_object.h>

#include <libcfs/list.h>

static void lu_object_free(struct lu_object *o);

void lu_object_put(struct lu_object *o)
{
	struct lu_object_header *top;
	struct lu_site          *site;

	top = o->lo_header;
	site = o->lo_dev->ld_site;
	spin_lock(&site->ls_guard);
	if (-- top->loh_ref == 0) {
		list_for_each_entry(o, &top->loh_layers, lo_linkage) {
			if (lu_object_ops(o)->ldo_object_release != NULL)
				lu_object_ops(o)->ldo_object_release(o);
		}
		-- site->ls_busy;
		if (lu_object_is_dying(top)) {
			hlist_del_init(&top->loh_hash);
			list_del_init(&top->loh_lru);
		}
	}
	spin_unlock(&site->ls_guard);
	if (lu_object_is_dying(top))
		/*
		 * Object was already removed from hash and lru above, can
		 * kill it.
		 */
		lu_object_free(o);
}
EXPORT_SYMBOL(lu_object_put);

struct lu_object *lu_object_alloc(struct lu_site *s, const struct ll_fid *f)
{
	struct lu_object *scan;
	struct lu_object *top;
	int clean;
	int result;

	top = s->ls_top_dev->ld_ops->ldo_object_alloc(s->ls_top_dev);
	if (IS_ERR(top))
		return top;
        *lu_object_fid(top) = *f;
	do {
		clean = 1;
		list_for_each_entry(scan,
				    &top->lo_header->loh_layers, lo_linkage) {
			if (scan->lo_flags & LU_OBJECT_ALLOCATED)
				continue;
			clean = 0;
			result = lu_object_ops(scan)->ldo_object_init(scan);
			if (result != 0) {
				lu_object_free(top);
				return ERR_PTR(result);
			}
			scan->lo_flags |= LU_OBJECT_ALLOCATED;
		}
	} while (!clean);
	s->ls_stats.s_created ++;
	return top;
}

static void lu_object_free(struct lu_object *o)
{
	struct list_head splice;

	-- o->lo_dev->ld_site->ls_total;
	INIT_LIST_HEAD(&splice);
	list_splice_init(&o->lo_header->loh_layers, &splice);
	while (!list_empty(&splice)) {
		o = container_of(splice.next, struct lu_object, lo_linkage);
		list_del_init(&o->lo_linkage);
		LASSERT(lu_object_ops(o)->ldo_object_free != NULL);
		lu_object_ops(o)->ldo_object_free(o);
	}
}

void lu_site_purge(struct lu_site *s, int nr)
{
	struct list_head         dispose;
	struct lu_object_header *h;
	struct lu_object_header *temp;

	INIT_LIST_HEAD(&dispose);
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
	while (!list_empty(&dispose)) {
		h = container_of(dispose.next,
				 struct lu_object_header, loh_lru);
		list_del_init(&h->loh_lru);
		lu_object_free(lu_object_top(h));
		s->ls_stats.s_lru_purged ++;
	}
}
EXPORT_SYMBOL(lu_site_purge);

int lu_object_print(struct seq_file *f, const struct lu_object *o)
{
        static char ruler[] = "........................................";
	const struct lu_object *scan;
	int nob;
	int depth;

	nob = 0;
        scan = o;
	list_for_each_entry_continue(scan, &o->lo_linkage, lo_linkage) {
		depth = scan->lo_depth;
		if (depth <= o->lo_depth && scan != o)
			break;
		LASSERT(lu_object_ops(scan)->ldo_object_print != NULL);
		nob += seq_printf(f, "%*.*s", depth, depth, ruler);
		nob += lu_object_ops(scan)->ldo_object_print(f, scan);
		nob += seq_printf(f, "\n");
	}
	return nob;
}
EXPORT_SYMBOL(lu_object_print);

static struct lu_object *htable_lookup(struct lu_site *s,
				       const struct hlist_head *bucket,
				       const struct ll_fid *f)
{
	struct lu_object_header *h;
	struct hlist_node *scan;

	hlist_for_each_entry(h, scan, bucket, loh_hash) {
		s->ls_stats.s_cache_check ++;
		if (lfid_eq(&h->loh_fid, f) && !lu_object_is_dying(h)) {
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

static __u32 fid_hash(const struct ll_fid *f)
{
        return f->id + f->generation + f->f_type;
}

struct lu_object *lu_object_find(struct lu_site *s, const struct ll_fid *f)
{
	struct lu_object  *o;
	struct lu_object  *shadow;
	struct hlist_head *bucket;

	bucket = s->ls_hash + (fid_hash(f) & s->ls_hash_mask);
	spin_lock(&s->ls_guard);
	o = htable_lookup(s, bucket, f);
	spin_unlock(&s->ls_guard);
	if (o != NULL)
		return o;

	o = lu_object_alloc(s, f);
	if (IS_ERR(o))
		return o;

	++ s->ls_total;
	LASSERT(lfid_eq(lu_object_fid(o), f));

	spin_lock(&s->ls_guard);
	shadow = htable_lookup(s, bucket, f);
	if (shadow == NULL) {
		hlist_add_head(&o->lo_header->loh_hash, bucket);
		list_add_tail(&s->ls_lru, &o->lo_header->loh_lru);
		shadow = o;
		o = NULL;
	} else
		s->ls_stats.s_cache_race ++;
	spin_unlock(&s->ls_guard);
	if (o != NULL)
		lu_object_free(o);
	return shadow;
}
EXPORT_SYMBOL(lu_object_find);

enum {
        LU_SITE_HTABLE_BITS = 8,
        LU_SITE_HTABLE_SIZE = (1 << LU_SITE_HTABLE_BITS),
        LU_SITE_HTABLE_MASK = LU_SITE_HTABLE_SIZE - 1
};

int lu_site_init(struct lu_site *s, struct lu_device *top)
{
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
                return 0;
        } else
                return -ENOMEM;
}
EXPORT_SYMBOL(lu_site_init);

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
               lu_device_put(s->ls_top_dev);
               s->ls_top_dev = NULL;
       }
 }
EXPORT_SYMBOL(lu_site_fini);

void lu_device_get(struct lu_device *d)
{
        atomic_inc(&d->ld_ref);
}
EXPORT_SYMBOL(lu_device_get);

void lu_device_put(struct lu_device *d)
{
        atomic_dec(&d->ld_ref);
}
EXPORT_SYMBOL(lu_device_put);

int lu_device_init(struct lu_device *d, struct lu_device_type *t)
{
        memset(d, 0, sizeof *d);
        atomic_set(&d->ld_ref, 0);
        d->ld_type = t;
        return 0;
}
EXPORT_SYMBOL(lu_device_init);

void lu_device_fini(struct lu_device *d)
{
        LASSERT(atomic_read(&d->ld_ref) == 0);
}
EXPORT_SYMBOL(lu_device_fini);

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

void lu_object_fini(struct lu_object *o)
{
        LASSERT(list_empty(&o->lo_linkage));

        if (o->lo_dev != NULL) {
                lu_device_get(o->lo_dev);
                o->lo_dev = NULL;
        }
}
EXPORT_SYMBOL(lu_object_fini);

void lu_object_add_top(struct lu_object_header *h, struct lu_object *o)
{
        list_move(&o->lo_linkage, &h->loh_layers);
}
EXPORT_SYMBOL(lu_object_add_top);

void lu_object_add(struct lu_object *before, struct lu_object *o)
{
        list_move(&o->lo_linkage, &before->lo_linkage);
}
EXPORT_SYMBOL(lu_object_add);

int lu_object_header_init(struct lu_object_header *h)
{
        memset(h, 0, sizeof *h);
        INIT_HLIST_NODE(&h->loh_hash);
        CFS_INIT_LIST_HEAD(&h->loh_lru);
        CFS_INIT_LIST_HEAD(&h->loh_layers);
        return 0;
}
EXPORT_SYMBOL(lu_object_header_init);

void lu_object_header_fini(struct lu_object_header *h)
{
        LASSERT(list_empty(&h->loh_layers));
        LASSERT(list_empty(&h->loh_lru));
        LASSERT(hlist_unhashed(&h->loh_hash));
}
EXPORT_SYMBOL(lu_object_header_fini);
