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
 * Users of the heap should embed a \e struct binheap_node object instance
 * on every object of the set that they wish the binary heap instance to handle,
 * and (at a minimum) provide a struct binheap_ops::hop_compare()
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

#define CBH_SHIFT	9
#define CBH_SIZE       (1 << CBH_SHIFT)		    /* # ptrs per level */
#define CBH_MASK       (CBH_SIZE - 1)
#define CBH_NOB        (CBH_SIZE * sizeof(struct binheap_node *))

#define CBH_POISON	0xdeadbeef

/**
 * Binary heap flags.
 */
enum {
	CBH_FLAG_ATOMIC_GROW	= 1,
};

struct binheap;

/**
 * Binary heap operations.
 */
struct binheap_ops {
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
	int		(*hop_enter)(struct binheap *h,
				     struct binheap_node *e);
	/**
	 * Called right after removing a node from the binary heap.
	 *
	 * Implementing this operation is optional.
	 *
	 * \param[in] h The heap
	 * \param[in] e The node
	 */
	void		(*hop_exit)(struct binheap *h,
				    struct binheap_node *e);
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
	 * \see binheap_bubble()
	 * \see cfs_biheap_sink()
	 */
	int		(*hop_compare)(struct binheap_node *a,
				       struct binheap_node *b);
};

/**
 * Binary heap object.
 *
 * Sorts elements of type \e struct binheap_node
 */
struct binheap {
	/** Triple indirect */
	struct binheap_node  ****cbh_elements3;
	/** double indirect */
	struct binheap_node   ***cbh_elements2;
	/** single indirect */
	struct binheap_node    **cbh_elements1;
	/** # elements referenced */
	unsigned int		cbh_nelements;
	/** high water mark */
	unsigned int		cbh_hwm;
	/** user flags */
	unsigned int		cbh_flags;
	/** operations table */
	struct binheap_ops *cbh_ops;
	/** private data */
	void		       *cbh_private;
	/** associated CPT table */
	struct cfs_cpt_table   *cbh_cptab;
	/** associated CPT id of this struct binheap::cbh_cptab */
	int			cbh_cptid;
};

void binheap_destroy(struct binheap *h);
struct binheap *
binheap_create(struct binheap_ops *ops, unsigned int flags,
		   unsigned int count, void *arg, struct cfs_cpt_table *cptab,
		   int cptid);
struct binheap_node *
binheap_find(struct binheap *h, unsigned int idx);
int binheap_insert(struct binheap *h, struct binheap_node *e);
void binheap_remove(struct binheap *h, struct binheap_node *e);
void binheap_relocate(struct binheap *h, struct binheap_node *e);

static inline int
binheap_size(struct binheap *h)
{
	return h->cbh_nelements;
}

static inline int
binheap_is_empty(struct binheap *h)
{
	return h->cbh_nelements == 0;
}

static inline struct binheap_node *
binheap_root(struct binheap *h)
{
	return binheap_find(h, 0);
}

static inline struct binheap_node *
binheap_remove_root(struct binheap *h)
{
	struct binheap_node *e = binheap_find(h, 0);

	if (e != NULL)
		binheap_remove(h, e);
	return e;
}

/** @} heap */

#endif /* __LIBCFS_HEAP_H__ */
