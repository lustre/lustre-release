/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 * Author: Liang Zhen <liangzhen@clusterfs.com>
 *         Nikita Danilov <nikita@clusterfs.com>
 *
 * This file is part of Lustre, http://www.lustre.org.
 *
 * Lustre is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * Lustre is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Lustre; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Darwin porting library
 * Make things easy to port
 */
#define DEBUG_SUBSYSTEM S_LNET

#include <mach/mach_types.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/file.h>
#include <sys/conf.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/filedesc.h>
#include <sys/namei.h>
#include <miscfs/devfs/devfs.h>
#include <kern/kalloc.h>
#include <kern/zalloc.h>
#include <kern/thread.h>

#include <libcfs/libcfs.h>
#include <libcfs/kp30.h>

/*
 * Definition of struct zone, copied from osfmk/kern/zalloc.h.
 */
struct zone_hack {
	int		count;		/* Number of elements used now */
	vm_offset_t	free_elements;
	vm_size_t	cur_size;	/* current memory utilization */
	vm_size_t	max_size;	/* how large can this zone grow */
	vm_size_t	elem_size;	/* size of an element */
	vm_size_t	alloc_size;	/* size used for more memory */
	char		*zone_name;	/* a name for the zone */
	unsigned int
	/* boolean_t */ exhaustible :1,	/* (F) merely return if empty? */
	/* boolean_t */	collectable :1,	/* (F) garbage collect empty pages */
	/* boolean_t */	expandable :1,	/* (T) expand zone (with message)? */
	/* boolean_t */ allows_foreign :1,/* (F) allow non-zalloc space */
	/* boolean_t */	doing_alloc :1,	/* is zone expanding now? */
	/* boolean_t */	waiting :1,	/* is thread waiting for expansion? */
	/* boolean_t */	async_pending :1;	/* asynchronous allocation pending? */
	struct zone_hack *	next_zone;	/* Link for all-zones list */
	/*
	 * more fields follow, but we don't need them. We only need
	 * offset from the beginning of struct zone to ->next_zone
	 * field: it allows us to scan the list of all zones.
	 */
};

decl_simple_lock_data(extern, all_zones_lock)

/*
 * returns true iff zone with name @name already exists.
 *
 * XXX nikita: this function is defined in this file only because there is no
 * better place to put it in.
 */
zone_t cfs_find_zone(const char *name)
{
	struct zone_hack *scan;

	/* from osfmk/kern/zalloc.c */
	extern zone_t first_zone;

	LASSERT(name != NULL);

	simple_lock(&all_zones_lock);
	for (scan = (struct zone_hack *)first_zone;
	     scan != NULL; scan = scan->next_zone) {
		if (!strcmp(scan->zone_name, name))
			break;
	}
	simple_unlock(&all_zones_lock);
	return((zone_t)scan);
}

/*
 * our wrapper around kern/zalloc.c:zinit()
 *
 * Creates copy of name and calls zinit() to do real work. Needed because zone
 * survives kext unloading, so that @name cannot be just static string
 * embedded into kext image.
 */
zone_t cfs_zinit(vm_size_t size, vm_size_t max, int alloc, const char *name)
{
        char *cname;

        cname = _MALLOC(strlen(name) + 1, M_TEMP, M_WAITOK);
        LASSERT(cname != NULL);
        return zinit(size, max, alloc, strcpy(cname, name));
}

cfs_mem_cache_t *
cfs_mem_cache_create (const char *name,
                      size_t objsize, size_t off, unsigned long arg1)
{
	cfs_mem_cache_t	*new = NULL;

	MALLOC(new, cfs_mem_cache_t *, objsize, M_TEMP, M_WAITOK|M_ZERO);
	if (new == NULL){
		CERROR("cfs_mem_cache created fail!\n");
		return NULL;
	}
	new->size = objsize;
        CFS_INIT_LIST_HEAD(&new->link);
        strncpy(new->name, name, 1 + strlen(name));
        new->zone = cfs_find_zone(name);
        if (new->zone == NULL) {
                new->zone = cfs_zinit (objsize, KMEM_MAX_ZONE * objsize, 0, name);
                if (new->zone == NULL) {
                        CERROR("zone create fault!\n");
                        FREE (new, M_TEMP);
                        return NULL;
                }
        }
	return new;
}

int cfs_mem_cache_destroy (cfs_mem_cache_t *cachep)
{
        FREE (cachep, M_TEMP);
	return 0;
}

void *cfs_mem_cache_alloc (cfs_mem_cache_t *cachep, int flags)
{
        void *result;

        /* zalloc_canblock() is not exported... Emulate it. */
        if (flags & CFS_ALLOC_ATOMIC) {
                result = (void *)zalloc_noblock(cachep->zone);
        } else {
                LASSERT(get_preemption_level() == 0);
                result = (void *)zalloc(cachep->zone);
        }
        if (result != NULL && (flags & CFS_ALLOC_ZERO))
                memset(result, 0, cachep->size);

        return result;
}

void cfs_mem_cache_free (cfs_mem_cache_t *cachep, void *objp)
{
        zfree (cachep->zone, (vm_address_t)objp);
}

/* ---------------------------------------------------------------------------
 * Page operations
 *
 * --------------------------------------------------------------------------- */

/*
 * "Raw" pages
 */

static unsigned int raw_pages = 0;

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

extern void print_backtrace(struct savearea *);

struct list_head page_death_row;
spinlock_t page_death_row_phylax;

static void raw_page_finish(struct xnu_raw_page *pg)
{
        -- raw_pages;
        if (pg->virtual != NULL)
                cfs_free(pg->virtual);
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
                /*
                 * XXX Liang: we need to use use zalloc() instead of 
                 * cfs_alloc(), cfs_alloc()->_MALLOC() will waste a lot
                 * of memory while allcating memory block at PAGE_SIZE.
                 */
                page->virtual = cfs_alloc(CFS_PAGE_SIZE, flags);
                if (page->virtual != NULL) {
                        ++ raw_pages;
                        page->header.type = XNU_PAGE_RAW;
                        atomic_set(&page->count, 1);
                } else
                        cfs_free(page);
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

void cfs_set_page_count(cfs_page_t *p, int v)
{
        atomic_set(&as_raw(p)->count, v);
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
        return page_ops[pg->type]->page_unmap(pg);
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
