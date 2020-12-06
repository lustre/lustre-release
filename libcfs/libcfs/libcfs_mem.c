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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * Author: liang@whamcloud.com
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>

struct cfs_var_array {
	unsigned int		va_count;	/* # of buffers */
	unsigned int		va_size;	/* size of each var */
	struct cfs_cpt_table	*va_cptab;	/* cpu partition table */
	void			*va_ptrs[0];	/* buffer addresses */
};

/*
 * free per-cpu data, see more detail in cfs_percpt_free
 */
void
cfs_percpt_free(void *vars)
{
	struct	cfs_var_array *arr;
	int	i;

	arr = container_of(vars, struct cfs_var_array, va_ptrs[0]);

	for (i = 0; i < arr->va_count; i++) {
		if (arr->va_ptrs[i] != NULL)
			LIBCFS_FREE(arr->va_ptrs[i], arr->va_size);
	}

	LIBCFS_FREE(arr, offsetof(struct cfs_var_array,
				  va_ptrs[arr->va_count]));
}
EXPORT_SYMBOL(cfs_percpt_free);

/*
 * allocate per cpu-partition variables, returned value is an array of pointers,
 * variable can be indexed by CPU partition ID, i.e:
 *
 *	arr = cfs_percpt_alloc(cfs_cpu_pt, size);
 *	then caller can access memory block for CPU 0 by arr[0],
 *	memory block for CPU 1 by arr[1]...
 *	memory block for CPU N by arr[N]...
 *
 * cacheline aligned.
 */
void *
cfs_percpt_alloc(struct cfs_cpt_table *cptab, unsigned int size)
{
	struct cfs_var_array	*arr;
	int			count;
	int			i;

	count = cfs_cpt_number(cptab);

	LIBCFS_ALLOC(arr, offsetof(struct cfs_var_array, va_ptrs[count]));
	if (arr == NULL)
		return NULL;

	arr->va_size	= size = L1_CACHE_ALIGN(size);
	arr->va_count	= count;
	arr->va_cptab	= cptab;

	for (i = 0; i < count; i++) {
		LIBCFS_CPT_ALLOC(arr->va_ptrs[i], cptab, i, size);
		if (arr->va_ptrs[i] == NULL) {
			cfs_percpt_free((void *)&arr->va_ptrs[0]);
			return NULL;
		}
	}

	return (void *)&arr->va_ptrs[0];
}
EXPORT_SYMBOL(cfs_percpt_alloc);

/*
 * return number of CPUs (or number of elements in per-cpu data)
 * according to cptab of @vars
 */
int
cfs_percpt_number(void *vars)
{
	struct cfs_var_array *arr;

	arr = container_of(vars, struct cfs_var_array, va_ptrs[0]);

	return arr->va_count;
}
EXPORT_SYMBOL(cfs_percpt_number);

/*
 * free variable array, see more detail in cfs_array_alloc
 */
void
cfs_array_free(void *vars)
{
	struct cfs_var_array	*arr;
	int			i;

	arr = container_of(vars, struct cfs_var_array, va_ptrs[0]);

	for (i = 0; i < arr->va_count; i++) {
		if (arr->va_ptrs[i] == NULL)
			continue;

		LIBCFS_FREE(arr->va_ptrs[i], arr->va_size);
	}
	LIBCFS_FREE(arr, offsetof(struct cfs_var_array,
				  va_ptrs[arr->va_count]));
}
EXPORT_SYMBOL(cfs_array_free);

/*
 * allocate a variable array, returned value is an array of pointers.
 * Caller can specify length of array by @count, @size is size of each
 * memory block in array.
 */
void *
cfs_array_alloc(int count, unsigned int size)
{
	struct cfs_var_array	*arr;
	int			i;

	LIBCFS_ALLOC(arr, offsetof(struct cfs_var_array, va_ptrs[count]));
	if (arr == NULL)
		return NULL;

	arr->va_count	= count;
	arr->va_size	= size;

	for (i = 0; i < count; i++) {
		LIBCFS_ALLOC(arr->va_ptrs[i], size);

		if (arr->va_ptrs[i] == NULL) {
			cfs_array_free((void *)&arr->va_ptrs[0]);
			return NULL;
		}
	}

	return (void *)&arr->va_ptrs[0];
}
EXPORT_SYMBOL(cfs_array_alloc);

#ifdef HAVE_LIBCFS_VFREE_ATOMIC
#include <linux/workqueue.h>
/*
 * This is opencoding of vfree_atomic from Linux kernel added in 4.10 with
 * minimum changes needed to work on some older kernels too.
 * For RHEL6, just use vfree() directly since it is missing too much code.
 */

#ifndef raw_cpu_ptr
#define raw_cpu_ptr(p) __this_cpu_ptr(p)
#endif

#ifndef llist_for_each_safe
#define llist_for_each_safe(pos, n, node)                       \
	for ((pos) = (node); (pos) && ((n) = (pos)->next, true); (pos) = (n))
#endif

struct vfree_deferred {
	struct llist_head list;
	struct work_struct wq;
};
static DEFINE_PER_CPU(struct vfree_deferred, vfree_deferred);

static void free_work(struct work_struct *w)
{
	struct vfree_deferred *p = container_of(w, struct vfree_deferred, wq);
	struct llist_node *t, *llnode;

	llist_for_each_safe(llnode, t, llist_del_all(&p->list))
		vfree((void *)llnode);
}

void libcfs_vfree_atomic(const void *addr)
{
	struct vfree_deferred *p = raw_cpu_ptr(&vfree_deferred);

	if (!addr)
		return;

	if (llist_add((struct llist_node *)addr, &p->list))
		schedule_work(&p->wq);
}
EXPORT_SYMBOL(libcfs_vfree_atomic);

void __init init_libcfs_vfree_atomic(void)
{
	int i;

	for_each_possible_cpu(i) {
		struct vfree_deferred *p;

		p = &per_cpu(vfree_deferred, i);
		init_llist_head(&p->list);
		INIT_WORK(&p->wq, free_work);
	}
}

void __exit exit_libcfs_vfree_atomic(void)
{
	flush_scheduled_work();
}
#endif /* HAVE_LIBCFS_VFREE_ATOMIC */
