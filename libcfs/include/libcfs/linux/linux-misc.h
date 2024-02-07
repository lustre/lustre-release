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

/* interval tree */
#ifdef HAVE_INTERVAL_TREE_CACHED
#define interval_tree_root rb_root_cached
#define interval_tree_first rb_first_cached
#define INTERVAL_TREE_ROOT RB_ROOT_CACHED
#else
#define interval_tree_root rb_root
#define interval_tree_first rb_first
#define INTERVAL_TREE_ROOT RB_ROOT
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
#define strscpy(s1, s2, sz)    strlcpy((s1), (s2), (sz))
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
