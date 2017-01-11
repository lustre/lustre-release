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
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/libcfs_private.h
 *
 * Various defines for libcfs.
 *
 */

#ifndef __LIBCFS_PRIVATE_H__
#define __LIBCFS_PRIVATE_H__

#ifndef DEBUG_SUBSYSTEM
# define DEBUG_SUBSYSTEM S_UNDEFINED
#endif

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

#define KLASSERT(e) LASSERT(e)

void lbug_with_loc(struct libcfs_debug_msg_data *) __attribute__((noreturn));

#define LBUG()                                                          \
do {                                                                    \
        LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, D_EMERG, NULL);             \
        lbug_with_loc(&msgdata);                                        \
} while(0)

/*
 * Memory
 */
#ifdef LIBCFS_DEBUG

extern atomic_t libcfs_kmemory;

# define libcfs_kmem_inc(ptr, size)		\
do {						\
	atomic_add(size, &libcfs_kmemory);	\
} while (0)

# define libcfs_kmem_dec(ptr, size)		\
do {						\
	atomic_sub(size, &libcfs_kmemory);	\
} while (0)

# define libcfs_kmem_read()			\
	atomic_read(&libcfs_kmemory)

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
		((size) <= LIBCFS_VMALLOC_SIZE &&			    \
		 ((mask) & GFP_ATOMIC)) != 0);			    \
} while (0)

#define LIBCFS_ALLOC_POST(ptr, size)					    \
do {									    \
	if (unlikely((ptr) == NULL)) {					    \
		CERROR("LNET: out of memory at %s:%d (tried to alloc '"	    \
		       #ptr "' = %d)\n", __FILE__, __LINE__, (int)(size));  \
		CERROR("LNET: %d total bytes allocated by lnet\n",	    \
		       libcfs_kmem_read());				    \
	} else {							    \
		libcfs_kmem_inc((ptr), (size));				    \
		CDEBUG(D_MALLOC, "alloc '" #ptr "': %d at %p (tot %d).\n",  \
		       (int)(size), (ptr), libcfs_kmem_read());		    \
	}                                                                   \
} while (0)

/**
 * allocate memory with GFP flags @mask
 * The allocated memory is zeroed-out.
 */
#define LIBCFS_ALLOC_GFP(ptr, size, mask)				    \
do {									    \
	LIBCFS_ALLOC_PRE((size), (mask));				    \
	(ptr) = (size) <= LIBCFS_VMALLOC_SIZE ?				    \
		kzalloc((size), (mask)) : vzalloc(size);		    \
	LIBCFS_ALLOC_POST((ptr), (size));				    \
} while (0)

/**
 * default allocator
 */
#define LIBCFS_ALLOC(ptr, size) \
	LIBCFS_ALLOC_GFP(ptr, size, GFP_NOFS)

/**
 * non-sleeping allocator
 */
#define LIBCFS_ALLOC_ATOMIC(ptr, size) \
	LIBCFS_ALLOC_GFP(ptr, size, GFP_ATOMIC)

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
	LIBCFS_ALLOC_POST((ptr), (size));				    \
} while (0)

/** default numa allocator */
#define LIBCFS_CPT_ALLOC(ptr, cptab, cpt, size)				    \
	LIBCFS_CPT_ALLOC_GFP(ptr, cptab, cpt, size, GFP_NOFS)

#define LIBCFS_FREE(ptr, size)						\
do {									\
	int s = (size);                                                 \
	if (unlikely((ptr) == NULL)) {                                  \
		CERROR("LIBCFS: free NULL '" #ptr "' (%d bytes) at "    \
		       "%s:%d\n", s, __FILE__, __LINE__);               \
		break;                                                  \
	}                                                               \
	libcfs_kmem_dec((ptr), s);                                      \
	CDEBUG(D_MALLOC, "kfreed '" #ptr "': %d at %p (tot %d).\n",     \
	       s, (ptr), libcfs_kmem_read());				\
	if (unlikely(s > LIBCFS_VMALLOC_SIZE))                          \
		vfree(ptr);						\
	else								\
		kfree(ptr);						\
} while (0)

/******************************************************************************/

struct task_struct;

void libcfs_debug_dumpstack(struct task_struct *tsk);
void libcfs_debug_dumplog(void);
int libcfs_debug_init(unsigned long bufsize);
int libcfs_debug_cleanup(void);
int libcfs_debug_clear_buffer(void);
int libcfs_debug_mark_buffer(const char *text);

/*
 * allocate a variable array, returned value is an array of pointers.
 * Caller can specify length of array by count.
 */
void *cfs_array_alloc(int count, unsigned int size);
void  cfs_array_free(void *vars);

#define LASSERT_ATOMIC_ENABLED          (1)

#if LASSERT_ATOMIC_ENABLED

/** assert value of @a is equal to @v */
#define LASSERT_ATOMIC_EQ(a, v)                                 \
do {                                                            \
	LASSERTF(atomic_read(a) == v,                       \
		 "value: %d\n", atomic_read((a)));          \
} while (0)

/** assert value of @a is unequal to @v */
#define LASSERT_ATOMIC_NE(a, v)                                 \
do {                                                            \
	LASSERTF(atomic_read(a) != v,                       \
		 "value: %d\n", atomic_read((a)));          \
} while (0)

/** assert value of @a is little than @v */
#define LASSERT_ATOMIC_LT(a, v)                                 \
do {                                                            \
	LASSERTF(atomic_read(a) < v,                        \
		 "value: %d\n", atomic_read((a)));          \
} while (0)

/** assert value of @a is little/equal to @v */
#define LASSERT_ATOMIC_LE(a, v)                                 \
do {                                                            \
	LASSERTF(atomic_read(a) <= v,                       \
		 "value: %d\n", atomic_read((a)));          \
} while (0)

/** assert value of @a is great than @v */
#define LASSERT_ATOMIC_GT(a, v)                                 \
do {                                                            \
	LASSERTF(atomic_read(a) > v,                        \
		 "value: %d\n", atomic_read((a)));          \
} while (0)

/** assert value of @a is great/equal to @v */
#define LASSERT_ATOMIC_GE(a, v)                                 \
do {                                                            \
	LASSERTF(atomic_read(a) >= v,                       \
		 "value: %d\n", atomic_read((a)));          \
} while (0)

/** assert value of @a is great than @v1 and little than @v2 */
#define LASSERT_ATOMIC_GT_LT(a, v1, v2)                         \
do {                                                            \
	int __v = atomic_read(a);                           \
	LASSERTF(__v > v1 && __v < v2, "value: %d\n", __v);     \
} while (0)

/** assert value of @a is great than @v1 and little/equal to @v2 */
#define LASSERT_ATOMIC_GT_LE(a, v1, v2)                         \
do {                                                            \
	int __v = atomic_read(a);                           \
	LASSERTF(__v > v1 && __v <= v2, "value: %d\n", __v);    \
} while (0)

/** assert value of @a is great/equal to @v1 and little than @v2 */
#define LASSERT_ATOMIC_GE_LT(a, v1, v2)                         \
do {                                                            \
	int __v = atomic_read(a);                           \
	LASSERTF(__v >= v1 && __v < v2, "value: %d\n", __v);    \
} while (0)

/** assert value of @a is great/equal to @v1 and little/equal to @v2 */
#define LASSERT_ATOMIC_GE_LE(a, v1, v2)                         \
do {                                                            \
	int __v = atomic_read(a);                           \
	LASSERTF(__v >= v1 && __v <= v2, "value: %d\n", __v);   \
} while (0)

#else /* !LASSERT_ATOMIC_ENABLED */

#define LASSERT_ATOMIC_EQ(a, v)                 do {} while (0)
#define LASSERT_ATOMIC_NE(a, v)                 do {} while (0)
#define LASSERT_ATOMIC_LT(a, v)                 do {} while (0)
#define LASSERT_ATOMIC_LE(a, v)                 do {} while (0)
#define LASSERT_ATOMIC_GT(a, v)                 do {} while (0)
#define LASSERT_ATOMIC_GE(a, v)                 do {} while (0)
#define LASSERT_ATOMIC_GT_LT(a, v1, v2)         do {} while (0)
#define LASSERT_ATOMIC_GT_LE(a, v1, v2)         do {} while (0)
#define LASSERT_ATOMIC_GE_LT(a, v1, v2)         do {} while (0)
#define LASSERT_ATOMIC_GE_LE(a, v1, v2)         do {} while (0)

#endif /* LASSERT_ATOMIC_ENABLED */

#define LASSERT_ATOMIC_ZERO(a)                  LASSERT_ATOMIC_EQ(a, 0)
#define LASSERT_ATOMIC_POS(a)                   LASSERT_ATOMIC_GT(a, 0)

#define CFS_ALLOC_PTR(ptr)      LIBCFS_ALLOC(ptr, sizeof (*(ptr)));
#define CFS_FREE_PTR(ptr)       LIBCFS_FREE(ptr, sizeof (*(ptr)));

/** Compile-time assertion.

 * Check an invariant described by a constant expression at compile time by
 * forcing a compiler error if it does not hold.  \a cond must be a constant
 * expression as defined by the ISO C Standard:
 *
 *       6.8.4.2  The switch statement
 *       ....
 *       [#3] The expression of each case label shall be  an  integer
 *       constant   expression  and  no  two  of  the  case  constant
 *       expressions in the same switch statement shall have the same
 *       value  after  conversion...
 *
 */
#define CLASSERT(cond) do {switch (1) {case (cond): case 0: break; } } while (0)

/* implication */
#define ergo(a, b) (!(a) || (b))
/* logical equivalence */
#define equi(a, b) (!!(a) == !!(b))

/* what used to be in portals_lib.h */
#ifndef MIN
# define MIN(a,b) (((a)<(b)) ? (a): (b))
#endif
#ifndef MAX
# define MAX(a,b) (((a)>(b)) ? (a): (b))
#endif

#define MKSTR(ptr) ((ptr))? (ptr) : ""

static inline size_t cfs_size_round4(size_t val)
{
        return (val + 3) & (~0x3);
}

#ifndef HAVE_CFS_SIZE_ROUND
static inline size_t cfs_size_round(size_t val)
{
        return (val + 7) & (~0x7);
}
#define HAVE_CFS_SIZE_ROUND
#endif

static inline size_t cfs_size_round16(size_t val)
{
        return (val + 0xf) & (~0xf);
}

static inline size_t cfs_size_round32(size_t val)
{
        return (val + 0x1f) & (~0x1f);
}

static inline size_t cfs_size_round0(size_t val)
{
        if (!val)
                return 0;
        return (val + 1 + 7) & (~0x7);
}

static inline size_t cfs_round_strlen(char *fset)
{
	return cfs_size_round(strlen(fset) + 1);
}

extern struct cfs_psdev_ops libcfs_psdev_ops;
extern struct miscdevice libcfs_dev;
extern struct cfs_wi_sched *cfs_sched_rehash;

#endif
