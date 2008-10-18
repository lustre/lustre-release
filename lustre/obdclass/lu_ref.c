/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
#else
# include <liblustre.h>
#endif

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lu_ref.h>

#ifdef USE_LU_REF

struct lu_ref_link {
        struct lu_ref    *ll_ref;
        struct list_head  ll_linkage;
        const char       *ll_scope;
        const void       *ll_source;
};

static cfs_mem_cache_t *lu_ref_link_kmem;

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

void lu_ref_print(const struct lu_ref *ref)
{
        struct lu_ref_link *link;

        CERROR("lu_ref: %p %d\n", ref, ref->lf_failed);
        list_for_each_entry(link, &ref->lf_list, ll_linkage) {
                CERROR("     link: %s %p\n", link->ll_scope, link->ll_source);
        }
}
EXPORT_SYMBOL(lu_ref_print);

void lu_ref_init(struct lu_ref *ref)
{
        spin_lock_init(&ref->lf_guard);
        CFS_INIT_LIST_HEAD(&ref->lf_list);
}
EXPORT_SYMBOL(lu_ref_init);

void lu_ref_fini(struct lu_ref *ref)
{
        if (!list_empty(&ref->lf_list)) {
                spin_lock(&ref->lf_guard);
                lu_ref_print(ref);
                spin_unlock(&ref->lf_guard);
        }
        LASSERT(list_empty(&ref->lf_list));
}
EXPORT_SYMBOL(lu_ref_fini);
int lu_ref_global_init(void);

static struct lu_ref_link *lu_ref_add_context(struct lu_ref *ref,
                                              enum cfs_alloc_flags flags,
                                              const char *scope,
                                              const void *source)
{
        struct lu_ref_link *link;

        /* this can be called so early in lustre initialization, that
         * lu_ref_link_kmem slab is not yet created. */
        lu_ref_global_init();

        link = NULL;
        if (lu_ref_link_kmem != NULL) {
                OBD_SLAB_ALLOC(link, lu_ref_link_kmem, flags, sizeof(*link));
                if (link != NULL) {
                        link->ll_ref    = ref;
                        link->ll_scope  = scope;
                        link->ll_source = source;
                        spin_lock(&ref->lf_guard);
                        list_add_tail(&link->ll_linkage, &ref->lf_list);
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

struct lu_ref_link *lu_ref_add(struct lu_ref *ref, const char *scope,
                               const void *source)
{
        might_sleep();
        return lu_ref_add_context(ref, CFS_ALLOC_STD, scope, source);
}
EXPORT_SYMBOL(lu_ref_add);

/**
 * Version of lu_ref_add() to be used in non-blockable contexts.
 */
struct lu_ref_link *lu_ref_add_atomic(struct lu_ref *ref, const char *scope,
                                      const void *source)
{
        return lu_ref_add_context(ref, CFS_ALLOC_ATOMIC, scope, source);
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
                                CWARN("Long lu_ref chain %i \"%s\":%p\n",
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
                spin_unlock(&ref->lf_guard);
                OBD_SLAB_FREE(link, lu_ref_link_kmem, sizeof(*link));
        } else {
                LASSERT(ref->lf_failed > 0);
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
        if (link != ERR_PTR(-ENOMEM)) {
                LASSERT(link->ll_ref == ref);
                LASSERT(lu_ref_link_eq(link, scope, source0));
                link->ll_source = source1;
        } else {
                LASSERT(ref->lf_failed > 0);
        }
        spin_unlock(&ref->lf_guard);
}
EXPORT_SYMBOL(lu_ref_set_at);

void lu_ref_del_at(struct lu_ref *ref, struct lu_ref_link *link,
                   const char *scope, const void *source)
{
        if (link != ERR_PTR(-ENOMEM)) {
                LASSERT(link->ll_ref == ref);
                LASSERT(lu_ref_link_eq(link, scope, source));
                spin_lock(&ref->lf_guard);
                list_del(&link->ll_linkage);
                spin_unlock(&ref->lf_guard);
                OBD_SLAB_FREE(link, lu_ref_link_kmem, sizeof(*link));
        } else {
                LASSERT(ref->lf_failed > 0);
                spin_lock(&ref->lf_guard);
                ref->lf_failed--;
                spin_unlock(&ref->lf_guard);
        }
}
EXPORT_SYMBOL(lu_ref_del_at);

static int lu_ref_initialized = 0;
int lu_ref_global_init(void)
{
        int result;

        if (lu_ref_initialized == 0) {
                lu_ref_initialized = 1;
                CDEBUG(D_CONSOLE,
                       "lu_ref tracking is enabled. Performance isn't.\n");
                result = lu_kmem_init(lu_ref_caches);
        } else
                result = 0;
        return result;
}

void lu_ref_global_fini(void)
{
        lu_kmem_fini(lu_ref_caches);
}

#endif /* USE_LU_REF */
