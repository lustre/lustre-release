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
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/lu_ref.c
 *
 * Lustre reference.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <libcfs/libcfs.h>
#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lu_ref.h>

#ifdef USE_LU_REF

/**
 * Asserts a condition for a given lu_ref. Must be called with
 * lu_ref::lf_guard held.
 */
#define REFASSERT(ref, expr) do {					\
	struct lu_ref *__tmp = (ref);					\
									\
	if (unlikely(!(expr))) {					\
		lu_ref_print(__tmp);					\
		spin_unlock(&__tmp->lf_guard);				\
		lu_ref_print_all();					\
		LASSERT(0);						\
		spin_lock(&__tmp->lf_guard);				\
	}								\
} while (0)

static struct kmem_cache *lu_ref_link_kmem;

static struct lu_kmem_descr lu_ref_caches[] = {
        {
                .ckd_cache = &lu_ref_link_kmem,
                .ckd_name  = "lu_ref_link_kmem",
                .ckd_size  = sizeof (struct lu_ref_link)
        },
        {
                .ckd_cache = NULL
        }
};

/**
 * Global list of active (initialized, but not finalized) lu_ref's.
 *
 * Protected by lu_ref_refs_guard.
 */
static LIST_HEAD(lu_ref_refs);
static DEFINE_SPINLOCK(lu_ref_refs_guard);
static struct lu_ref lu_ref_marker = {
	.lf_guard	= __SPIN_LOCK_UNLOCKED(lu_ref_marker.lf_guard),
	.lf_list	= LIST_HEAD_INIT(lu_ref_marker.lf_list),
	.lf_linkage	= LIST_HEAD_INIT(lu_ref_marker.lf_linkage)
};

void lu_ref_print(const struct lu_ref *ref)
{
        struct lu_ref_link *link;

        CERROR("lu_ref: %p %d %d %s:%d\n",
               ref, ref->lf_refs, ref->lf_failed, ref->lf_func, ref->lf_line);
	list_for_each_entry(link, &ref->lf_list, ll_linkage) {
                CERROR("     link: %s %p\n", link->ll_scope, link->ll_source);
        }
}

static int lu_ref_is_marker(const struct lu_ref *ref)
{
        return (ref == &lu_ref_marker);
}

void lu_ref_print_all(void)
{
	struct lu_ref *ref;

	spin_lock(&lu_ref_refs_guard);
	list_for_each_entry(ref, &lu_ref_refs, lf_linkage) {
		if (lu_ref_is_marker(ref))
			continue;

		spin_lock(&ref->lf_guard);
		lu_ref_print(ref);
		spin_unlock(&ref->lf_guard);
	}
	spin_unlock(&lu_ref_refs_guard);
}

void lu_ref_init_loc(struct lu_ref *ref, const char *func, const int line)
{
	ref->lf_refs = 0;
	ref->lf_func = func;
	ref->lf_line = line;
	spin_lock_init(&ref->lf_guard);
	INIT_LIST_HEAD(&ref->lf_list);
	spin_lock(&lu_ref_refs_guard);
	list_add(&ref->lf_linkage, &lu_ref_refs);
	spin_unlock(&lu_ref_refs_guard);
}
EXPORT_SYMBOL(lu_ref_init_loc);

void lu_ref_fini(struct lu_ref *ref)
{
	spin_lock(&ref->lf_guard);
	REFASSERT(ref, list_empty(&ref->lf_list));
	REFASSERT(ref, ref->lf_refs == 0);
	spin_unlock(&ref->lf_guard);
	spin_lock(&lu_ref_refs_guard);
	list_del_init(&ref->lf_linkage);
	spin_unlock(&lu_ref_refs_guard);
}
EXPORT_SYMBOL(lu_ref_fini);

static struct lu_ref_link *lu_ref_add_context(struct lu_ref *ref,
                                              int flags,
                                              const char *scope,
                                              const void *source)
{
        struct lu_ref_link *link;

        link = NULL;
        if (lu_ref_link_kmem != NULL) {
                OBD_SLAB_ALLOC_PTR_GFP(link, lu_ref_link_kmem, flags);
                if (link != NULL) {
                        link->ll_ref    = ref;
                        link->ll_scope  = scope;
                        link->ll_source = source;
			spin_lock(&ref->lf_guard);
			list_add_tail(&link->ll_linkage, &ref->lf_list);
			ref->lf_refs++;
			spin_unlock(&ref->lf_guard);
		}
	}

	if (link == NULL) {
		spin_lock(&ref->lf_guard);
		ref->lf_failed++;
		spin_unlock(&ref->lf_guard);
		link = ERR_PTR(-ENOMEM);
	}

	return link;
}

void lu_ref_add(struct lu_ref *ref, const char *scope, const void *source)
{
	might_sleep();
	lu_ref_add_context(ref, GFP_NOFS, scope, source);
}
EXPORT_SYMBOL(lu_ref_add);

void lu_ref_add_at(struct lu_ref *ref, struct lu_ref_link *link,
		   const char *scope, const void *source)
{
	link->ll_ref = ref;
	link->ll_scope = scope;
	link->ll_source = source;
	spin_lock(&ref->lf_guard);
	list_add_tail(&link->ll_linkage, &ref->lf_list);
	ref->lf_refs++;
	spin_unlock(&ref->lf_guard);
}
EXPORT_SYMBOL(lu_ref_add_at);

/**
 * Version of lu_ref_add() to be used in non-blockable contexts.
 */
void lu_ref_add_atomic(struct lu_ref *ref, const char *scope,
		       const void *source)
{
	lu_ref_add_context(ref, GFP_ATOMIC, scope, source);
}
EXPORT_SYMBOL(lu_ref_add_atomic);

static inline int lu_ref_link_eq(const struct lu_ref_link *link,
                                 const char *scope, const void *source)
{
        return link->ll_source == source && !strcmp(link->ll_scope, scope);
}

/**
 * Maximal chain length seen so far.
 */
static unsigned lu_ref_chain_max_length = 127;

/**
 * Searches for a lu_ref_link with given [scope, source] within given lu_ref.
 */
static struct lu_ref_link *lu_ref_find(struct lu_ref *ref, const char *scope,
                                       const void *source)
{
        struct lu_ref_link *link;
        unsigned            iterations;

        iterations = 0;
	list_for_each_entry(link, &ref->lf_list, ll_linkage) {
                ++iterations;
                if (lu_ref_link_eq(link, scope, source)) {
                        if (iterations > lu_ref_chain_max_length) {
                                CWARN("Long lu_ref chain %d \"%s\":%p\n",
                                      iterations, scope, source);
                                lu_ref_chain_max_length = iterations * 3 / 2;
                        }
                        return link;
                }
        }
        return NULL;
}

void lu_ref_del(struct lu_ref *ref, const char *scope, const void *source)
{
	struct lu_ref_link *link;

	spin_lock(&ref->lf_guard);
	link = lu_ref_find(ref, scope, source);
	if (link != NULL) {
		list_del(&link->ll_linkage);
		ref->lf_refs--;
		spin_unlock(&ref->lf_guard);
		OBD_SLAB_FREE(link, lu_ref_link_kmem, sizeof(*link));
	} else {
		REFASSERT(ref, ref->lf_failed > 0);
		ref->lf_failed--;
		spin_unlock(&ref->lf_guard);
	}
}
EXPORT_SYMBOL(lu_ref_del);

void lu_ref_set_at(struct lu_ref *ref, struct lu_ref_link *link,
		   const char *scope,
		   const void *source0, const void *source1)
{
	spin_lock(&ref->lf_guard);
	REFASSERT(ref, link != NULL && !IS_ERR(link));
	REFASSERT(ref, link->ll_ref == ref);
	REFASSERT(ref, lu_ref_link_eq(link, scope, source0));
	link->ll_source = source1;
	spin_unlock(&ref->lf_guard);
}
EXPORT_SYMBOL(lu_ref_set_at);

void lu_ref_del_at(struct lu_ref *ref, struct lu_ref_link *link,
		   const char *scope, const void *source)
{
	spin_lock(&ref->lf_guard);
	REFASSERT(ref, link != NULL && !IS_ERR(link));
	REFASSERT(ref, link->ll_ref == ref);
	REFASSERT(ref, lu_ref_link_eq(link, scope, source));
	list_del(&link->ll_linkage);
	ref->lf_refs--;
	spin_unlock(&ref->lf_guard);
}
EXPORT_SYMBOL(lu_ref_del_at);

#ifdef CONFIG_PROC_FS

static void *lu_ref_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct lu_ref *ref = seq->private;

	spin_lock(&lu_ref_refs_guard);
	if (list_empty(&ref->lf_linkage))
		ref = NULL;
	spin_unlock(&lu_ref_refs_guard);

	return ref;
}

static void *lu_ref_seq_next(struct seq_file *seq, void *p, loff_t *pos)
{
        struct lu_ref *ref = p;
        struct lu_ref *next;

        LASSERT(seq->private == p);
	LASSERT(!list_empty(&ref->lf_linkage));

	spin_lock(&lu_ref_refs_guard);
	next = list_entry(ref->lf_linkage.next, struct lu_ref, lf_linkage);
	if (&next->lf_linkage == &lu_ref_refs) {
		p = NULL;
	} else {
		(*pos)++;
		list_move(&ref->lf_linkage, &next->lf_linkage);
	}
	spin_unlock(&lu_ref_refs_guard);
	return p;
}

static void lu_ref_seq_stop(struct seq_file *seq, void *p)
{
        /* Nothing to do */
}


static int lu_ref_seq_show(struct seq_file *seq, void *p)
{
	struct lu_ref *ref  = p;
	struct lu_ref *next;

	spin_lock(&lu_ref_refs_guard);
	next = list_entry(ref->lf_linkage.next, struct lu_ref, lf_linkage);
	if ((&next->lf_linkage == &lu_ref_refs) || lu_ref_is_marker(next)) {
		spin_unlock(&lu_ref_refs_guard);
		return 0;
	}

	/* print the entry */
	spin_lock(&next->lf_guard);
        seq_printf(seq, "lu_ref: %p %d %d %s:%d\n",
                   next, next->lf_refs, next->lf_failed,
                   next->lf_func, next->lf_line);
        if (next->lf_refs > 64) {
                seq_printf(seq, "  too many references, skip\n");
        } else {
                struct lu_ref_link *link;
                int i = 0;

		list_for_each_entry(link, &next->lf_list, ll_linkage)
                        seq_printf(seq, "  #%d link: %s %p\n",
                                   i++, link->ll_scope, link->ll_source);
        }
	spin_unlock(&next->lf_guard);
	spin_unlock(&lu_ref_refs_guard);

	return 0;
}

static struct seq_operations lu_ref_seq_ops = {
        .start = lu_ref_seq_start,
        .stop  = lu_ref_seq_stop,
        .next  = lu_ref_seq_next,
        .show  = lu_ref_seq_show
};

static int lu_ref_seq_open(struct inode *inode, struct file *file)
{
	struct lu_ref *marker = &lu_ref_marker;
	int result = 0;

	result = seq_open(file, &lu_ref_seq_ops);
	if (result == 0) {
		spin_lock(&lu_ref_refs_guard);
		if (!list_empty(&marker->lf_linkage))
			result = -EAGAIN;
		else
			list_add(&marker->lf_linkage, &lu_ref_refs);
		spin_unlock(&lu_ref_refs_guard);

                if (result == 0) {
                        struct seq_file *f = file->private_data;
                        f->private = marker;
                } else {
                        seq_release(inode, file);
                }
        }

        return result;
}

static int lu_ref_seq_release(struct inode *inode, struct file *file)
{
	struct lu_ref *ref = ((struct seq_file *)file->private_data)->private;

	spin_lock(&lu_ref_refs_guard);
	list_del_init(&ref->lf_linkage);
	spin_unlock(&lu_ref_refs_guard);

	return seq_release(inode, file);
}

static struct file_operations lu_ref_dump_fops = {
        .owner   = THIS_MODULE,
        .open    = lu_ref_seq_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
        .release = lu_ref_seq_release
};

#endif /* CONFIG_PROC_FS */

int lu_ref_global_init(void)
{
	int result;

	CDEBUG(D_CONSOLE,
	       "lu_ref tracking is enabled. Performance isn't.\n");

        result = lu_kmem_init(lu_ref_caches);

#ifdef CONFIG_PROC_FS
        if (result == 0) {
                result = lprocfs_seq_create(proc_lustre_root, "lu_refs",
                                            0444, &lu_ref_dump_fops, NULL);
                if (result)
                        lu_kmem_fini(lu_ref_caches);
        }
#endif /* CONFIG_PROC_FS */

        return result;
}

void lu_ref_global_fini(void)
{
#ifdef CONFIG_PROC_FS
        lprocfs_remove_proc_entry("lu_refs", proc_lustre_root);
#endif /* CONFIG_PROC_FS */
        lu_kmem_fini(lu_ref_caches);
}

#endif /* USE_LU_REF */
