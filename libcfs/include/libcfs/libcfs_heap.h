/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2011 Intel Corporation
 */
/*
 * libcfs/include/libcfs/heap.h
 *
 * Author: Eric Barton	<eeb@whamcloud.com>
 *	   Liang Zhen	<liang@whamcloud.com>
 */

#ifndef __LIBCFS_HEAP_H__
#define __LIBCFS_HEAP_H__

/** \defgroup heap Binary heap
 *
 * The binary heap is a scalable data structure created using a binary tree. It
 * is capable of maintaining large sets of elements sorted usually by one or
 * more element properties, but really based on anything that can be used as a
 * binary predicate in order to determine the relevant ordering of any two nodes
 * that belong to the set. There is no search operation, rather the intention is
 * for the element of the lowest priority which will always be at the root of
 * the tree (as this is an implementation of a min-heap) to be removed by users
 * for consumption.
 *
 * Users of the heap should embed a \e struct cfs_binheap_node object instance
 * on every object of the set that they wish the binary heap instance to handle,
 * and (at a minimum) provide a struct cfs_binheap_ops::hop_compare()
 * implementation which is used by the heap as the binary predicate during its
 * internal sorting operations.
 *
 * The current implementation enforces no locking scheme, and so assumes the
 * user caters for locking between calls to insert, delete and lookup
 * operations. Since the only consumer for the data structure at this point
 * are NRS policies, and these operate on a per-CPT basis, binary heap instances
 * are tied to a specific CPT.
 * @{
 */

/**
 * Binary heap node.
 *
 * Objects of this type are embedded into objects of the ordered set that is to
 * be maintained by a \e struct cfs_binheap instance.
 */
struct cfs_binheap_node {
	/** Index into the binary tree */
	unsigned int	chn_index;
};

#define CBH_SHIFT	9
#define CBH_SIZE       (1 << CBH_SHIFT)		    /* # ptrs per level */
#define CBH_MASK       (CBH_SIZE - 1)
#define CBH_NOB        (CBH_SIZE * sizeof(struct cfs_binheap_node *))

#define CBH_POISON	0xdeadbeef

/**
 * Binary heap flags.
 */
enum {
	CBH_FLAG_ATOMIC_GROW	= 1,
};

struct cfs_binheap;

/**
 * Binary heap operations.
 */
struct cfs_binheap_ops {
	/**
	 * Called right before inserting a node into the binary heap.
	 *
	 * Implementing this operation is optional.
	 *
	 * \param[in] h The heap
	 * \param[in] e The node
	 *
	 * \retval 0 success
	 * \retval != 0 error
	 */
	int		(*hop_enter)(struct cfs_binheap *h,
				     struct cfs_binheap_node *e);
	/**
	 * Called right after removing a node from the binary heap.
	 *
	 * Implementing this operation is optional.
	 *
	 * \param[in] h The heap
	 * \param[in] e The node
	 */
	void		(*hop_exit)(struct cfs_binheap *h,
				    struct cfs_binheap_node *e);
	/**
	 * A binary predicate which is called during internal heap sorting
	 * operations, and used in order to determine the relevant ordering of
	 * two heap nodes.
	 *
	 * Implementing this operation is mandatory.
	 *
	 * \param[in] a The first heap node
	 * \param[in] b The second heap node
	 *
	 * \retval 0 Node a > node b
	 * \retval 1 Node a < node b
	 *
	 * \see cfs_binheap_bubble()
	 * \see cfs_biheap_sink()
	 */
	int		(*hop_compare)(struct cfs_binheap_node *a,
				       struct cfs_binheap_node *b);
};

/**
 * Binary heap object.
 *
 * Sorts elements of type \e struct cfs_binheap_node
 */
struct cfs_binheap {
	/** Triple indirect */
	struct cfs_binheap_node  ****cbh_elements3;
	/** double indirect */
	struct cfs_binheap_node   ***cbh_elements2;
	/** single indirect */
	struct cfs_binheap_node    **cbh_elements1;
	/** # elements referenced */
	unsigned int		cbh_nelements;
	/** high water mark */
	unsigned int		cbh_hwm;
	/** user flags */
	unsigned int		cbh_flags;
	/** operations table */
	struct cfs_binheap_ops *cbh_ops;
	/** private data */
	void		       *cbh_private;
	/** associated CPT table */
	struct cfs_cpt_table   *cbh_cptab;
	/** associated CPT id of this struct cfs_binheap::cbh_cptab */
	int			cbh_cptid;
};

void cfs_binheap_destroy(struct cfs_binheap *h);
struct cfs_binheap *
cfs_binheap_create(struct cfs_binheap_ops *ops, unsigned int flags,
		   unsigned count, void *arg, struct cfs_cpt_table *cptab,
		   int cptid);
struct cfs_binheap_node *
cfs_binheap_find(struct cfs_binheap *h, unsigned int idx);
int cfs_binheap_insert(struct cfs_binheap *h, struct cfs_binheap_node *e);
void cfs_binheap_remove(struct cfs_binheap *h, struct cfs_binheap_node *e);
void cfs_binheap_relocate(struct cfs_binheap *h, struct cfs_binheap_node *e);

static inline int
cfs_binheap_size(struct cfs_binheap *h)
{
	return h->cbh_nelements;
}

static inline int
cfs_binheap_is_empty(struct cfs_binheap *h)
{
	return h->cbh_nelements == 0;
}

static inline struct cfs_binheap_node *
cfs_binheap_root(struct cfs_binheap *h)
{
	return cfs_binheap_find(h, 0);
}

static inline struct cfs_binheap_node *
cfs_binheap_remove_root(struct cfs_binheap *h)
{
	struct cfs_binheap_node *e = cfs_binheap_find(h, 0);

	if (e != NULL)
		cfs_binheap_remove(h, e);
	return e;
}

/** @} heap */

#endif /* __LIBCFS_HEAP_H__ */
