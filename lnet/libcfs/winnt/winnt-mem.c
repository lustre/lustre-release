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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>


cfs_mem_cache_t *cfs_page_t_slab = NULL;
cfs_mem_cache_t *cfs_page_p_slab = NULL;

/*
 * cfs_alloc_page
 *   To allocate the cfs_page_t and also 1 page of memory
 *
 * Arguments:
 *   flags:  the allocation options
 *
 * Return Value:
 *   pointer to the cfs_page_t strcture in success or
 *   NULL in failure case
 *
 * Notes: 
 *   N/A
 */

cfs_page_t * cfs_alloc_page(int flags)
{
    cfs_page_t *pg;
    pg = cfs_mem_cache_alloc(cfs_page_t_slab, 0);
    
    if (NULL == pg) {
        cfs_enter_debugger();
        return NULL;
    }

    memset(pg, 0, sizeof(cfs_page_t));
    pg->addr = cfs_mem_cache_alloc(cfs_page_p_slab, 0);
    atomic_set(&pg->count, 1);

    if (pg->addr) {
        if (cfs_is_flag_set(flags, CFS_ALLOC_ZERO)) {
            memset(pg->addr, 0, CFS_PAGE_SIZE);
        }
    } else {
        cfs_enter_debugger();
        cfs_mem_cache_free(cfs_page_t_slab, pg);
        pg = NULL;
    }

    return pg;
}

/*
 * cfs_free_page
 *   To free the cfs_page_t including the page
 *
 * Arguments:
 *   pg:  pointer to the cfs_page_t strcture
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */
void cfs_free_page(cfs_page_t *pg)
{
    ASSERT(pg != NULL);
    ASSERT(pg->addr  != NULL);
    ASSERT(atomic_read(&pg->count) <= 1);

    cfs_mem_cache_free(cfs_page_p_slab, pg->addr);
    cfs_mem_cache_free(cfs_page_t_slab, pg);
}


/*
 * cfs_alloc
 *   To allocate memory from system pool
 *
 * Arguments:
 *   nr_bytes:  length in bytes of the requested buffer
 *   flags:     flags indiction
 *
 * Return Value:
 *   NULL: if there's no enough memory space in system
 *   the address of the allocated memory in success.
 *
 * Notes: 
 *   This operation can be treated as atomic.
 */

void *
cfs_alloc(size_t nr_bytes, u_int32_t flags)
{
	void *ptr;

    /* Ignore the flags: always allcoate from NonPagedPool */

	ptr = ExAllocatePoolWithTag(NonPagedPool, nr_bytes, 'Lufs');

	if (ptr != NULL && (flags & CFS_ALLOC_ZERO)) {
		memset(ptr, 0, nr_bytes);
    }

    if (!ptr) {
        cfs_enter_debugger();
    }

	return ptr;
}

/*
 * cfs_free
 *   To free the sepcified memory to system pool
 *
 * Arguments:
 *   addr:   pointer to the buffer to be freed
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *    This operation can be treated as atomic.
 */

void
cfs_free(void *addr)
{
	ExFreePool(addr);
}

/*
 * cfs_alloc_large
 *   To allocate large block of memory from system pool
 *
 * Arguments:
 *   nr_bytes:  length in bytes of the requested buffer
 *
 * Return Value:
 *   NULL: if there's no enough memory space in system
 *   the address of the allocated memory in success.
 *
 * Notes: 
 *   N/A
 */

void *
cfs_alloc_large(size_t nr_bytes)
{
	return cfs_alloc(nr_bytes, 0);
}

/*
 * cfs_free_large
 *   To free the sepcified memory to system pool
 *
 * Arguments:
 *   addr:   pointer to the buffer to be freed
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void
cfs_free_large(void *addr)
{
	cfs_free(addr);
}


/*
 * cfs_mem_cache_create
 *   To create a SLAB cache
 *
 * Arguments:
 *   name:   name string of the SLAB cache to be created
 *   size:   size in bytes of SLAB entry buffer
 *   offset: offset in the page
 *   flags:  SLAB creation flags
*
 * Return Value:
 *   The poitner of cfs_memory_cache structure in success.
 *   NULL pointer in failure case.
 *
 * Notes: 
 *   1, offset won't be used here.
 *   2, it could be better to induce a lock to protect the access of the
 *       SLAB structure on SMP if there's not outside lock protection.
 *   3, parameters C/D are removed.
 */

cfs_mem_cache_t *
cfs_mem_cache_create(
    const char * name,
    size_t size,
    size_t offset,
    unsigned long flags
    )
{
    cfs_mem_cache_t * kmc = NULL;

    /*  The name of the SLAB could not exceed 20 chars */

    if (name && strlen(name) >= 20) {
        goto errorout;
    }

    /* Allocate and initialize the SLAB strcture */

    kmc = cfs_alloc (sizeof(cfs_mem_cache_t), 0);

    if (NULL == kmc) {
        goto errorout;
    }

    memset(kmc, 0, sizeof(cfs_mem_cache_t));

    kmc->flags = flags;

    if (name) {
        strcpy(&kmc->name[0], name);
    }

    /* Initialize the corresponding LookAside list */

    ExInitializeNPagedLookasideList(
            &(kmc->npll),
            NULL,
            NULL,
            0,
            size,
            'pnmk',
            0);
 
errorout:

    return kmc;
}

/*
 * cfs_mem_cache_destroy
 *   To destroy the unused SLAB cache
 *
 * Arguments:
 *   kmc: the SLAB cache to be destroied.
 *
 * Return Value:
 *   0: in success case.
 *   1: in failure case.
 *
 * Notes: 
 *   N/A
 */

int cfs_mem_cache_destroy (cfs_mem_cache_t * kmc)
{
    ASSERT(kmc != NULL);

    ExDeleteNPagedLookasideList(&(kmc->npll));

    cfs_free(kmc);

    return 0;
}

/*
 * cfs_mem_cache_alloc
 *   To allocate an object (LookAside entry) from the SLAB
 *
 * Arguments:
 *   kmc:   the SLAB cache to be allocated from.
 *   flags: flags for allocation options
 *
 * Return Value:
 *   object buffer address: in success case.
 *   NULL: in failure case.
 *
 * Notes: 
 *   N/A
 */

void *cfs_mem_cache_alloc(cfs_mem_cache_t * kmc, int flags)
{
    void *buf = NULL;

    buf = ExAllocateFromNPagedLookasideList(&(kmc->npll));

    return buf;
}

/*
 * cfs_mem_cache_free
 *   To free an object (LookAside entry) to the SLAB cache
 *
 * Arguments:
 *   kmc: the SLAB cache to be freed to.
 *   buf: the pointer to the object to be freed.
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

void cfs_mem_cache_free(cfs_mem_cache_t * kmc, void * buf)
{
    ExFreeToNPagedLookasideList(&(kmc->npll), buf);
}
