/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Various defines for libcfs.
 */

#ifndef __LIBCFS_PRIVATE_H__
#define __LIBCFS_PRIVATE_H__

#ifndef DEBUG_SUBSYSTEM
# define DEBUG_SUBSYSTEM S_UNDEFINED
#endif

#include <linux/slab.h>
#include <linux/vmalloc.h>

#ifdef LIBCFS_DEBUG

/*
 * When this is on, LASSERT macro includes check for assignment used instead
 * of equality check, but doesn't have unlikely(). Turn this on from time to
 * time to make test-builds. This shouldn't be on for production release.
 */
#define LASSERT_CHECKED (0)

#if LASSERT_CHECKED
/*
 * Assertion.
 *
 * Strange construction with empty "then" clause is used to trigger compiler
 * warnings on the assertions of the form LASSERT(a = b);
 *
 * "warning: suggest parentheses around assignment used as truth value"
 *
 * requires -Wall. Unfortunately this rules out use of likely/unlikely.
 */
#define LASSERTF(cond, fmt, ...)					\
do {									\
	if (cond)							\
		;							\
	else {								\
		LIBCFS_DEBUG_MSG_DATA_DECL(__msg_data, D_EMERG, NULL);	\
		libcfs_debug_msg(&__msg_data,				\
				 "ASSERTION( %s ) failed: " fmt, #cond,	\
				 ## __VA_ARGS__);			\
		lbug_with_loc(&__msg_data);				\
	}								\
} while (0)

#define LASSERT(cond) LASSERTF(cond, "\n")

#else /* !LASSERT_CHECKED */

#define LASSERTF(cond, fmt, ...)					\
do {									\
	if (unlikely(!(cond))) {					\
		LIBCFS_DEBUG_MSG_DATA_DECL(__msg_data, D_EMERG, NULL);	\
		libcfs_debug_msg(&__msg_data,				\
				 "ASSERTION( %s ) failed: " fmt, #cond,	\
				 ## __VA_ARGS__);			\
		lbug_with_loc(&__msg_data);				\
	}								\
} while (0)

#define LASSERT(cond) LASSERTF(cond, "\n")
#endif /* !LASSERT_CHECKED */
#else /* !LIBCFS_DEBUG */
/* sizeof is to use expression without evaluating it. */
# define LASSERT(e) ((void)sizeof!!(e))
# define LASSERTF(cond, ...) ((void)sizeof!!(cond))
#endif /* !LIBCFS_DEBUG */

#ifdef CONFIG_LUSTRE_DEBUG_EXPENSIVE_CHECK
/**
 * This is for more expensive checks that one doesn't want to be enabled all
 * the time. LINVRNT() has to be explicitly enabled by --enable-invariants
 * configure option.
 */
# define LINVRNT(exp) LASSERT(exp)
#else
# define LINVRNT(exp) ((void)sizeof!!(exp))
#endif

void
#ifdef HAVE_LBUG_WITH_LOC_IN_OBJTOOL
__noreturn
#endif
lbug_with_loc(struct libcfs_debug_msg_data *msg);

#define LBUG()                                                          \
do {                                                                    \
	LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, D_EMERG, NULL);             \
	lbug_with_loc(&msgdata);                                        \
	break;                                                          \
} while(0)

/*
 * Memory
 */
#ifdef LIBCFS_DEBUG

extern atomic64_t libcfs_kmem;

# define libcfs_kmem_inc(ptr, size)		\
do {						\
	atomic64_add((size), &libcfs_kmem);	\
} while (0)

# define libcfs_kmem_dec(ptr, size)		\
do {						\
	atomic64_sub((size), &libcfs_kmem);	\
} while (0)

# define libcfs_kmem_read()			\
	(long long)atomic64_read(&libcfs_kmem)

#else
# define libcfs_kmem_inc(ptr, size) do {} while (0)
# define libcfs_kmem_dec(ptr, size) do {} while (0)
# define libcfs_kmem_read()	(0)
#endif /* LIBCFS_DEBUG */

#ifndef LIBCFS_VMALLOC_SIZE
#define LIBCFS_VMALLOC_SIZE        (2 << PAGE_SHIFT) /* 2 pages */
#endif

#define LIBCFS_ALLOC_PRE(size, mask)					    \
do {									    \
	LASSERT(!in_interrupt() ||					    \
		(((size) <= LIBCFS_VMALLOC_SIZE) &&			    \
		 ((mask) & GFP_ATOMIC) != 0));				    \
} while (0)

/* message format here needs to match regexp in lustre/tests/leak_finder.pl */
#define LIBCFS_MEM_MSG(ptr, size, name)					      \
	CDEBUG(D_MALLOC, name " '" #ptr "': %d at %p.\n", (int)(size), ptr)

#define LIBCFS_ALLOC_POST(ptr, size, name)				      \
do {									      \
	if (unlikely((ptr) == NULL)) {					      \
		CERROR("LNET: out of memory at %s:%d (tried to alloc '"	      \
		       #ptr "' = %d)\n", __FILE__, __LINE__, (int)(size));    \
		CERROR("LNET: %lld total bytes allocated by lnet\n",	      \
		       libcfs_kmem_read());				      \
	} else {							      \
		libcfs_kmem_inc((ptr), (size));				      \
		LIBCFS_MEM_MSG(ptr, (size), name);			      \
	}                                                                     \
} while (0)

#define LIBCFS_FREE_PRE(ptr, size, name)				\
	libcfs_kmem_dec((ptr), (size));					\
	LIBCFS_MEM_MSG(ptr, (size), name)

/**
 * allocate memory with GFP flags @mask
 * The allocated memory is zeroed-out.
 */
#define LIBCFS_ALLOC_GFP(ptr, size, mask)				    \
do {									    \
	LIBCFS_ALLOC_PRE((size), (mask));				    \
	(ptr) = (size) <= LIBCFS_VMALLOC_SIZE ?				    \
		kzalloc((size), (mask)) : vzalloc(size);		    \
	LIBCFS_ALLOC_POST((ptr), (size), "alloc");			    \
} while (0)

/**
 * default allocator
 */
#define LIBCFS_ALLOC(ptr, size) \
	LIBCFS_ALLOC_GFP(ptr, (size), GFP_NOFS)

/**
 * non-sleeping allocator
 */
#define LIBCFS_ALLOC_ATOMIC(ptr, size) \
	LIBCFS_ALLOC_GFP(ptr, (size), GFP_ATOMIC)

/**
 * allocate memory for specified CPU partition
 *   \a cptab != NULL, \a cpt is CPU partition id of \a cptab
 *   \a cptab == NULL, \a cpt is HW NUMA node id
 * The allocated memory is zeroed-out.
 */
#define LIBCFS_CPT_ALLOC_GFP(ptr, cptab, cpt, size, mask)		    \
do {									    \
	LIBCFS_ALLOC_PRE((size), (mask));				    \
	(ptr) = (size) <= LIBCFS_VMALLOC_SIZE ?				    \
		cfs_cpt_malloc((cptab), (cpt), (size), (mask) | __GFP_ZERO) : \
		cfs_cpt_vzalloc((cptab), (cpt), (size));		    \
	LIBCFS_ALLOC_POST((ptr), (size), "alloc");			    \
} while (0)

/** default numa allocator */
#define LIBCFS_CPT_ALLOC(ptr, cptab, cpt, size)				    \
	LIBCFS_CPT_ALLOC_GFP(ptr, (cptab), (cpt), (size), GFP_NOFS)

#define LIBCFS_FREE(ptr, size)						\
do {									\
	size_t s = (size);						\
	if (likely(ptr)) {						\
		LIBCFS_FREE_PRE(ptr, (size), "kfreed");			\
		if (unlikely(s > LIBCFS_VMALLOC_SIZE))			\
			libcfs_vfree_atomic(ptr);			\
		else							\
			kfree(ptr);					\
	}								\
} while (0)

/******************************************************************************/

void libcfs_debug_dumplog(void);
int libcfs_debug_init(unsigned long bufsize);
int libcfs_debug_cleanup(void);
int libcfs_debug_clear_buffer(void);
int libcfs_debug_mark_buffer(const char *text);

#define CFS_ALLOC_PTR(ptr)      LIBCFS_ALLOC(ptr, sizeof(*(ptr)));
#define CFS_ALLOC_PTR_ARRAY(ptr, count)			\
	LIBCFS_ALLOC(ptr, (count) * sizeof(*(ptr)))

#define CFS_FREE_PTR(ptr)       LIBCFS_FREE(ptr, sizeof(*(ptr)));
#define CFS_FREE_PTR_ARRAY(ptr, count)			\
	LIBCFS_FREE(ptr, (count) * sizeof(*(ptr)))

/* implication */
#define ergo(a, b) (!(a) || (b))
/* logical equivalence */
#define equi(a, b) (!!(a) == !!(b))

#endif
