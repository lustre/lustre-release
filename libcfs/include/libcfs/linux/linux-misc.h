/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __LIBCFS_LINUX_MISC_H__
#define __LIBCFS_LINUX_MISC_H__

#include <linux/fs.h>
/* Since Commit 2f8b544477e6 ("block,fs: untangle fs.h and blk_types.h")
 * fs.h doesn't include blk_types.h, but we need it.
 */
#include <linux/blk_types.h>
#include <linux/mutex.h>
#include <linux/user_namespace.h>
#include <linux/uio.h>
#include <linux/kallsyms.h>

/*
 * Since 4.20 commit 00e23707442a75b404392cef1405ab4fd498de6b
 * iov_iter: Use accessor functions to access an iterator's type and direction.
 * iter_is_iovec() and iov_iter_is_* are available, supply the missing
 * functionality for older kernels.
 */
#ifdef HAVE_IOV_ITER_TYPE
#ifndef HAVE_ENUM_ITER_PIPE
#define iov_iter_is_pipe(iter)	0
#endif
#else
/*
 * Since 3.15-rc4 commit 71d8e532b1549a478e6a6a8a44f309d050294d00
 * The iov iterator has a type and can iterate over numerous vector types.
 * Prior to this only iovec is supported, so all iov_iter_is_* are false.
 */
#ifdef HAVE_IOV_ITER_HAS_TYPE_MEMBER
#define iter_is_iovec(iter)		((iter)->type & ITER_IOVEC)
#define iov_iter_is_kvec(iter)		((iter)->type & ITER_KVEC)
#define iov_iter_is_bvec(iter)		((iter)->type & ITER_BVEC)
#if defined HAVE_ENUM_ITER_PIPE
#define iov_iter_is_pipe(iter)		((iter)->type & ITER_PIPE)
#else
#define iov_iter_is_pipe(iter)		0
#endif
#define iov_iter_is_discard(iter)	((iter)->type & ITER_DISCARD)
#else
#define iter_is_iovec(iter)		1
#define iov_iter_is_kvec(iter)		0
#define iov_iter_is_bvec(iter)		0
#define iov_iter_is_pipe(iter)		0
#define iov_iter_is_discard(iter)	0
#endif
#endif /* HAVE_IOV_ITER_TYPE */

#ifndef HAVE_USER_BACKED_ITER
#define iter_is_ubuf(iter)		0
#define user_backed_iter(iter)		iter_is_iovec(iter)
#endif /* HAVE_USER_BACKED_ITER */

#ifndef HAVE_IOV_ITER_IS_ALIGNED
static inline bool iov_iter_aligned_iovec(const struct iov_iter *i,
					  unsigned addr_mask, unsigned len_mask)
{
	const struct iovec *iov = iter_iov(i);
	size_t size = i->count;
	size_t skip = i->iov_offset;

	do {
		size_t len = iov->iov_len - skip;

		if (len > size)
			len = size;
		if (len & len_mask)
			return false;
		if ((unsigned long)(iov->iov_base + skip) & addr_mask)
			return false;

		iov++;
		size -= len;
		skip = 0;
	} while (size);

	return true;
}

static inline bool iov_iter_is_aligned(const struct iov_iter *i,
				       unsigned addr_mask, unsigned len_mask)
{
	if (likely(iter_is_ubuf(i))) {
		if (i->count & len_mask)
			return false;
		if ((unsigned long)(iter_iov(i) + i->iov_offset) & addr_mask)
			return false;
		return true;
	}
	if (likely(iter_is_iovec(i) || iov_iter_is_kvec(i)))
		return iov_iter_aligned_iovec(i, addr_mask, len_mask);

	return true;
}
#endif /* HAVE_IOV_ITER_IS_ALIGNED */

int cfs_kernel_write(struct file *filp, const void *buf, size_t count,
		     loff_t *pos);
ssize_t cfs_kernel_read(struct file *file, void *buf, size_t count,
			loff_t *pos);

/*
 * For RHEL6 struct kernel_parm_ops doesn't exist. Also
 * the arguments for .set and .get take different
 * parameters which is handled below
 */
#ifdef HAVE_KERNEL_PARAM_OPS
#define cfs_kernel_param_arg_t const struct kernel_param
#else
#define cfs_kernel_param_arg_t struct kernel_param_ops
#define kernel_param_ops kernel_param
#endif /* ! HAVE_KERNEL_PARAM_OPS */

#ifndef HAVE_KERNEL_PARAM_LOCK
static inline void kernel_param_unlock(struct module *mod)
{
	__kernel_param_unlock();
}

static inline void kernel_param_lock(struct module *mod)
{
	__kernel_param_lock();
}
#endif /* ! HAVE_KERNEL_PARAM_LOCK */

int cfs_apply_workqueue_attrs(struct workqueue_struct *wq,
			      const struct workqueue_attrs *attrs);

#ifndef HAVE_KSTRTOBOOL_FROM_USER

#define kstrtobool strtobool

int kstrtobool_from_user(const char __user *s, size_t count, bool *res);
#endif /* HAVE_KSTRTOBOOL_FROM_USER */

#ifndef HAVE_MATCH_WILDCARD
bool match_wildcard(const char *pattern, const char *str);
#endif /* !HAVE_MATCH_WILDCARD */

#ifndef HAVE_KREF_READ
static inline int kref_read(const struct kref *kref)
{
	return atomic_read(&kref->refcount);
}
#endif /* HAVE_KREF_READ */

int cfs_arch_init(void);
void cfs_arch_exit(void);

#ifndef container_of_safe
/**
 * container_of_safe - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 * If IS_ERR_OR_NULL(ptr), ptr is returned unchanged.
 *
 * Note: Copied from Linux 5.6, with BUILD_BUG_ON_MSG section removed.
 */
#define container_of_safe(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	IS_ERR_OR_NULL(__mptr) ? ERR_CAST(__mptr) :			\
		((type *)(__mptr - offsetof(type, member))); })
#endif

/*
 * Linux v4.15-rc2-5-g4229a470175b added sizeof_field()
 * Linux v5.5-rc4-1-g1f07dcc459d5 removed FIELD_SIZEOF()
 * Proved a sizeof_field in terms of FIELD_SIZEOF() when one is not provided
 */
#ifndef sizeof_field
#define sizeof_field(type, member)	FIELD_SIZEOF(type, member)
#endif

#ifndef HAVE_TASK_IS_RUNNING
#define task_is_running(task)		(task->state == TASK_RUNNING)
#endif

#ifndef HAVE_RB_FIND
/**
 * rb_find() - find @key in tree @tree
 * @key: key to match
 * @tree: tree to search
 * @cmp: operator defining the node order
 *
 * Returns the rb_node matching @key or NULL.
 */
static __always_inline struct rb_node *
rb_find(const void *key, const struct rb_root *tree,
	int (*cmp)(const void *key, const struct rb_node *))
{
	struct rb_node *node = tree->rb_node;

	while (node) {
		int c = cmp(key, node);

		if (c < 0)
			node = node->rb_left;
		else if (c > 0)
			node = node->rb_right;
		else
			return node;
	}

	return NULL;
}

/**
 * rb_add() - insert @node into @tree
 * @node: node to insert
 * @tree: tree to insert @node into
 * @less: operator defining the (partial) node order
 */
static __always_inline void
rb_add(struct rb_node *node, struct rb_root *tree,
       bool (*less)(struct rb_node *, const struct rb_node *))
{
	struct rb_node **link = &tree->rb_node;
	struct rb_node *parent = NULL;

	while (*link) {
		parent = *link;
		if (less(node, parent))
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}

	rb_link_node(node, parent, link);
	rb_insert_color(node, tree);
}

/**
 * rb_find_add() - find equivalent @node in @tree, or add @node
 * @node: node to look-for / insert
 * @tree: tree to search / modify
 * @cmp: operator defining the node order
 *
 * Returns the rb_node matching @node, or NULL when no match is found and @node
 * is inserted.
 */
static __always_inline struct rb_node *
rb_find_add(struct rb_node *node, struct rb_root *tree,
	    int (*cmp)(struct rb_node *, const struct rb_node *))
{
	struct rb_node **link = &tree->rb_node;
	struct rb_node *parent = NULL;
	int c;

	while (*link) {
		parent = *link;
		c = cmp(node, parent);

		if (c < 0)
			link = &parent->rb_left;
		else if (c > 0)
			link = &parent->rb_right;
		else
			return parent;
	}

	rb_link_node(node, parent, link);
	rb_insert_color(node, tree);
	return NULL;
}
#endif /* !HAVE_RB_FIND */

/* interval tree */
#ifdef HAVE_INTERVAL_TREE_CACHED
#define interval_tree_root rb_root_cached
#define interval_tree_first rb_first_cached
#define INTERVAL_TREE_ROOT RB_ROOT_CACHED
#define INTERVAL_TREE_EMPTY(_root) RB_EMPTY_ROOT(&(_root)->rb_root)
#else
#define interval_tree_root rb_root
#define interval_tree_first rb_first
#define INTERVAL_TREE_ROOT RB_ROOT
#define INTERVAL_TREE_EMPTY(_root) RB_EMPTY_ROOT(_root)
#endif /* HAVE_INTERVAL_TREE_CACHED */

/* Linux v5.1-rc5 214d8ca6ee ("stacktrace: Provide common infrastructure")
 * CONFIG_ARCH_STACKWALK indicates that save_stack_trace_tsk symbol is not
 * exported. Use symbol_get() to find if save_stack_trace_tsk is available.
 */
#ifdef CONFIG_ARCH_STACKWALK
int cfs_stack_trace_save_tsk(struct task_struct *task, unsigned long *store,
			     unsigned int size, unsigned int skipnr);
#endif

#ifndef memset_startat
/** from linux 5.19 include/linux/string.h: */
#define memset_startat(obj, v, member)					\
({									\
	u8 *__ptr = (u8 *)(obj);					\
	typeof(v) __val = (v);						\
	memset(__ptr + offsetof(typeof(*(obj)), member), __val,		\
	       sizeof(*(obj)) - offsetof(typeof(*(obj)), member));	\
})
#endif /* memset_startat() */

#ifdef HAVE_KALLSYMS_LOOKUP_NAME
static inline void *cfs_kallsyms_lookup_name(const char *name)
{
	return (void *)kallsyms_lookup_name(name);
}
#else
static inline void *cfs_kallsyms_lookup_name(const char *name)
{
	return NULL;
}
#endif

#ifndef HAVE_STRSCPY
static inline ssize_t strscpy(char *s1, const char *s2, size_t sz)
{
	ssize_t len = strlcpy(s1, s2, sz);

	return (len >= sz) ? -E2BIG : len;
}
#endif

#ifndef HAVE_BITMAP_TO_ARR32
void bitmap_to_arr32(u32 *buf, const unsigned long *bitmap, unsigned int nbits);
#endif

#ifndef HAVE_KOBJ_TYPE_DEFAULT_GROUPS
#define default_groups			default_attrs
#define KOBJ_ATTR_GROUPS(_name)		_name##_attrs
#define KOBJ_ATTRIBUTE_GROUPS(_name)
#else
#define KOBJ_ATTR_GROUPS(_name)		_name##_groups
#define KOBJ_ATTRIBUTE_GROUPS(_name)	ATTRIBUTE_GROUPS(_name)
#endif

#endif /* __LIBCFS_LINUX_MISC_H__ */
