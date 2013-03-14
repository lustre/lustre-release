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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/libcfs/darwin/darwin-mem.c
 *
 * Author: Liang Zhen <liangzhen@clusterfs.com>
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */
#define DEBUG_SUBSYSTEM S_LNET

#include <mach/mach_types.h>
#include <string.h>
#include <sys/malloc.h>

#include <libcfs/libcfs.h>
#include "darwin-internal.h"

#if CFS_INDIVIDUAL_ZONE
extern zone_t zinit( vm_size_t, vm_size_t, vm_size_t, const char *);
extern void * zalloc(zone_t zone);
extern void *zalloc_noblock(zone_t zone);
extern void zfree(zone_t zone, void *addr);

struct cfs_zone_nob {
        struct list_head       *z_nob;  /* Pointer to z_link */
        struct list_head        z_link; /* Do NOT access it directly */       
};

static struct cfs_zone_nob      cfs_zone_nob;
static spinlock_t		cfs_zone_guard;

cfs_mem_cache_t *mem_cache_find(const char *name, size_t objsize)
{
	cfs_mem_cache_t		*walker = NULL;

	LASSERT(cfs_zone_nob.z_nob != NULL);

	spin_lock(&cfs_zone_guard);
	list_for_each_entry(walker, cfs_zone_nob.z_nob, mc_link) {
		if (!strcmp(walker->mc_name, name) && \
		    walker->mc_size == objsize)
			break;
	}
	spin_unlock(&cfs_zone_guard);

	return walker;
}

/*
 * our wrapper around kern/zalloc.c:zinit()
 *
 * Creates copy of name and calls zinit() to do real work. Needed because zone
 * survives kext unloading, so that @name cannot be just static string
 * embedded into kext image.
 */
cfs_mem_cache_t *mem_cache_create(vm_size_t objsize, const char *name)
{
	cfs_mem_cache_t	*mc = NULL;
        char *cname;

	MALLOC(mc, cfs_mem_cache_t *, sizeof(cfs_mem_cache_t), M_TEMP, M_WAITOK|M_ZERO);
	if (mc == NULL){
		CERROR("cfs_mem_cache created fail!\n");
		return NULL;
	}

        cname = _MALLOC(strlen(name) + 1, M_TEMP, M_WAITOK);
        LASSERT(cname != NULL);
        mc->mc_cache = zinit(objsize, (KMEM_MAX_ZONE * objsize), 0, strcpy(cname, name));
        mc->mc_size = objsize;
        CFS_INIT_LIST_HEAD(&mc->mc_link);
        strncpy(mc->mc_name, name, 1 + strlen(name));
        return mc;
}

void mem_cache_destroy(cfs_mem_cache_t *mc)
{
        /*
         * zone can NOT be destroyed after creating, 
         * so just keep it in list.
         *
         * We will not lost a zone after we unload
         * libcfs, it can be found by from libcfs.zone
         */
        return;
}

#define mem_cache_alloc(mc)     zalloc((mc)->mc_cache)
#ifdef __DARWIN8__
# define mem_cache_alloc_nb(mc) zalloc((mc)->mc_cache)
#else
/* XXX Liang: Tiger doesn't export zalloc_noblock() */
# define mem_cache_alloc_nb(mc) zalloc_noblock((mc)->mc_cache)
#endif
#define mem_cache_free(mc, p)   zfree((mc)->mc_cache, p)

#else  /* !CFS_INDIVIDUAL_ZONE */

cfs_mem_cache_t *
mem_cache_find(const char *name, size_t objsize)
{
        return NULL;
}

cfs_mem_cache_t *mem_cache_create(vm_size_t size, const char *name)
{
        cfs_mem_cache_t *mc = NULL;

	MALLOC(mc, cfs_mem_cache_t *, sizeof(cfs_mem_cache_t), M_TEMP, M_WAITOK|M_ZERO);
	if (mc == NULL){
		CERROR("cfs_mem_cache created fail!\n");
		return NULL;
	}
        mc->mc_cache = OSMalloc_Tagalloc(name, OSMT_DEFAULT);
        mc->mc_size = size;
        return mc;
}

void mem_cache_destroy(cfs_mem_cache_t *mc)
{
        OSMalloc_Tagfree(mc->mc_cache);
        FREE(mc, M_TEMP);
}

#define mem_cache_alloc(mc)     OSMalloc((mc)->mc_size, (mc)->mc_cache)
#define mem_cache_alloc_nb(mc)  OSMalloc_noblock((mc)->mc_size, (mc)->mc_cache)
#define mem_cache_free(mc, p)   OSFree(p, (mc)->mc_size, (mc)->mc_cache)

#endif /* !CFS_INDIVIDUAL_ZONE */

cfs_mem_cache_t *
cfs_mem_cache_create (const char *name,
                      size_t objsize, size_t off, unsigned long arg1)
{
        cfs_mem_cache_t *mc;

        mc = mem_cache_find(name, objsize);
        if (mc)
                return mc;
        mc = mem_cache_create(objsize, name);
	return mc;
}

int cfs_mem_cache_destroy (cfs_mem_cache_t *cachep)
{
        mem_cache_destroy(cachep);
        return 0;
}

void *cfs_mem_cache_alloc (cfs_mem_cache_t *cachep, int flags)
{
        void *result;

        /* zalloc_canblock() is not exported... Emulate it. */
        if (flags & CFS_ALLOC_ATOMIC) {
                result = (void *)mem_cache_alloc_nb(cachep);
        } else {
                LASSERT(get_preemption_level() == 0);
                result = (void *)mem_cache_alloc(cachep);
        }
        if (result != NULL && (flags & CFS_ALLOC_ZERO))
                memset(result, 0, cachep->mc_size);

        return result;
}

void cfs_mem_cache_free (cfs_mem_cache_t *cachep, void *objp)
{
        mem_cache_free(cachep, objp);
}

/* ---------------------------------------------------------------------------
 * Page operations
 *
 * --------------------------------------------------------------------------- */

/*
 * "Raw" pages
 */

static unsigned int raw_pages = 0;
static cfs_mem_cache_t  *raw_page_cache = NULL;

static struct xnu_page_ops raw_page_ops;
static struct xnu_page_ops *page_ops[XNU_PAGE_NTYPES] = {
        [XNU_PAGE_RAW] = &raw_page_ops
};

#if defined(LIBCFS_DEBUG)
static int page_type_is_valid(cfs_page_t *page)
{
        LASSERT(page != NULL);
        return 0 <= page->type && page->type < XNU_PAGE_NTYPES;
}

static int page_is_raw(cfs_page_t *page)
{
        return page->type == XNU_PAGE_RAW;
}
#endif

static struct xnu_raw_page *as_raw(cfs_page_t *page)
{
        LASSERT(page_is_raw(page));
        return list_entry(page, struct xnu_raw_page, header);
}

static void *raw_page_address(cfs_page_t *pg)
{
        return (void *)as_raw(pg)->virtual;
}

static void *raw_page_map(cfs_page_t *pg)
{
        return (void *)as_raw(pg)->virtual;
}

static void raw_page_unmap(cfs_page_t *pg)
{
}

static struct xnu_page_ops raw_page_ops = {
        .page_map       = raw_page_map,
        .page_unmap     = raw_page_unmap,
        .page_address   = raw_page_address
};

extern int get_preemption_level(void);

struct list_head page_death_row;
spinlock_t page_death_row_phylax;

static void raw_page_finish(struct xnu_raw_page *pg)
{
        -- raw_pages;
        if (pg->virtual != NULL)
                cfs_mem_cache_free(raw_page_cache, pg->virtual);
        cfs_free(pg);
}

void raw_page_death_row_clean(void)
{
	struct xnu_raw_page *pg;

	spin_lock(&page_death_row_phylax);
	while (!list_empty(&page_death_row)) {
		pg = container_of(page_death_row.next,
				  struct xnu_raw_page, link);
		list_del(&pg->link);
		spin_unlock(&page_death_row_phylax);
		raw_page_finish(pg);
		spin_lock(&page_death_row_phylax);
	}
	spin_unlock(&page_death_row_phylax);
}

/* Free a "page" */
void free_raw_page(struct xnu_raw_page *pg)
{
	if (!atomic_dec_and_test(&pg->count))
		return;
	/*
	 * kmem_free()->vm_map_remove()->vm_map_delete()->lock_write() may
	 * block. (raw_page_done()->upl_abort() can block too) On the other
	 * hand, cfs_free_page() may be called in non-blockable context. To
	 * work around this, park pages on global list when cannot block.
	 */
	if (get_preemption_level() > 0) {
		spin_lock(&page_death_row_phylax);
		list_add(&pg->link, &page_death_row);
		spin_unlock(&page_death_row_phylax);
	} else {
		raw_page_finish(pg);
		raw_page_death_row_clean();
	}
}

cfs_page_t *cfs_alloc_page(u_int32_t flags)
{
        struct xnu_raw_page *page;

        /*
         * XXX nikita: do NOT call libcfs_debug_msg() (CDEBUG/ENTRY/EXIT)
         * from here: this will lead to infinite recursion.
         */

        page = cfs_alloc(sizeof *page, flags);
        if (page != NULL) {
                page->virtual = cfs_mem_cache_alloc(raw_page_cache, flags);
                if (page->virtual != NULL) {
                        ++ raw_pages;
                        page->header.type = XNU_PAGE_RAW;
                        atomic_set(&page->count, 1);
                } else {
                        cfs_free(page);
                        page = NULL;
                }
        }
        return page != NULL ? &page->header : NULL;
}

void cfs_free_page(cfs_page_t *pages)
{
        free_raw_page(as_raw(pages));
}

void cfs_get_page(cfs_page_t *p)
{
        atomic_inc(&as_raw(p)->count);
}

int cfs_put_page_testzero(cfs_page_t *p)
{
	return atomic_dec_and_test(&as_raw(p)->count);
}

int cfs_page_count(cfs_page_t *p)
{
        return atomic_read(&as_raw(p)->count);
}

/*
 * Generic page operations
 */

void *cfs_page_address(cfs_page_t *pg)
{
        /*
         * XXX nikita: do NOT call libcfs_debug_msg() (CDEBUG/ENTRY/EXIT)
         * from here: this will lead to infinite recursion.
         */
        LASSERT(page_type_is_valid(pg));
        return page_ops[pg->type]->page_address(pg);
}

void *cfs_kmap(cfs_page_t *pg)
{
        LASSERT(page_type_is_valid(pg));
        return page_ops[pg->type]->page_map(pg);
}

void cfs_kunmap(cfs_page_t *pg)
{
        LASSERT(page_type_is_valid(pg));
        page_ops[pg->type]->page_unmap(pg);
}

void xnu_page_ops_register(int type, struct xnu_page_ops *ops)
{
        LASSERT(0 <= type && type < XNU_PAGE_NTYPES);
        LASSERT(ops != NULL);
        LASSERT(page_ops[type] == NULL);

        page_ops[type] = ops;
}

void xnu_page_ops_unregister(int type)
{
        LASSERT(0 <= type && type < XNU_PAGE_NTYPES);
        LASSERT(page_ops[type] != NULL);

        page_ops[type] = NULL;
}

/*
 * Portable memory allocator API
 */
#ifdef HAVE_GET_PREEMPTION_LEVEL
extern int get_preemption_level(void);
#else
#define get_preemption_level() (0)
#endif

void *cfs_alloc(size_t nr_bytes, u_int32_t flags)
{
        int mflags;

        mflags = 0;
        if (flags & CFS_ALLOC_ATOMIC) {
                mflags |= M_NOWAIT;
        } else {
                LASSERT(get_preemption_level() == 0);
                mflags |= M_WAITOK;
        }

        if (flags & CFS_ALLOC_ZERO)
                mflags |= M_ZERO;

        return _MALLOC(nr_bytes, M_TEMP, mflags);
}

void cfs_free(void *addr)
{
        return _FREE(addr, M_TEMP);
}

void *cfs_alloc_large(size_t nr_bytes)
{
        LASSERT(get_preemption_level() == 0);
        return _MALLOC(nr_bytes, M_TEMP, M_WAITOK);
}

void  cfs_free_large(void *addr)
{
        LASSERT(get_preemption_level() == 0);
        return _FREE(addr, M_TEMP);
}

/*
 * Lookup cfs_zone_nob by sysctl.zone, if it cannot be 
 * found (first load of * libcfs since boot), allocate 
 * sysctl libcfs.zone.
 */
int cfs_mem_init(void)
{
#if     CFS_INDIVIDUAL_ZONE
        int     rc;
        size_t  len;

        len = sizeof(struct cfs_zone_nob);
        rc = sysctlbyname("libcfs.zone",
                          (void *)&cfs_zone_nob, &len, NULL, 0);
        if (rc == ENOENT) {
                /* zone_nob is not register in libcfs_sysctl */
                struct cfs_zone_nob  *nob;
                struct sysctl_oid       *oid;

                assert(cfs_sysctl_isvalid());

                nob = _MALLOC(sizeof(struct cfs_zone_nob), 
                              M_TEMP, M_WAITOK | M_ZERO);
                CFS_INIT_LIST_HEAD(&nob->z_link);
                nob->z_nob = &nob->z_link;
                oid = cfs_alloc_sysctl_struct(NULL, OID_AUTO, CTLFLAG_RD | CTLFLAG_KERN, 
                                              "zone", nob, sizeof(struct cfs_zone_nob));
                if (oid == NULL) {
                        _FREE(nob, M_TEMP);
                        return -ENOMEM;
                }
                sysctl_register_oid(oid);

                cfs_zone_nob.z_nob = nob->z_nob;
        }
	spin_lock_init(&cfs_zone_guard);
#endif
	CFS_INIT_LIST_HEAD(&page_death_row);
	spin_lock_init(&page_death_row_phylax);
	raw_page_cache = cfs_mem_cache_create("raw-page", CFS_PAGE_SIZE, 0, 0);
	return 0;
}

void cfs_mem_fini(void)
{
	raw_page_death_row_clean();
	spin_lock_done(&page_death_row_phylax);
	cfs_mem_cache_destroy(raw_page_cache);

#if CFS_INDIVIDUAL_ZONE
	cfs_zone_nob.z_nob = NULL;
	spin_lock_done(&cfs_zone_guard);
#endif
}
