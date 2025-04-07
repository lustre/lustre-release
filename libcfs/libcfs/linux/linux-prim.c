// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2013, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#ifdef HAVE_SCHED_HEADERS
#include <linux/sched/mm.h>
#endif
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <net/netlink.h>

#if defined(CONFIG_KGDB)
#include <asm/kgdb.h>
#endif

#include <lustre_compat.h>
#include <libcfs/linux/linux-time.h>
#include <libcfs/linux/linux-wait.h>
#include <libcfs/linux/linux-misc.h>
#include <libcfs/linux/linux-mem.h>
#include <lustre_compat/linux/xarray.h>
#include <lustre_crypto.h>

#ifndef HAVE_KTIME_GET_TS64
void ktime_get_ts64(struct timespec64 *ts)
{
	struct timespec now;

	ktime_get_ts(&now);
	*ts = timespec_to_timespec64(now);
}
EXPORT_SYMBOL(ktime_get_ts64);
#endif /* HAVE_KTIME_GET_TS64 */

#ifndef HAVE_KTIME_GET_REAL_TS64
void ktime_get_real_ts64(struct timespec64 *ts)
{
	struct timespec now;

	getnstimeofday(&now);
	*ts = timespec_to_timespec64(now);
}
EXPORT_SYMBOL(ktime_get_real_ts64);
#endif /* HAVE_KTIME_GET_REAL_TS64 */

#ifndef HAVE_KTIME_GET_REAL_SECONDS
/*
 * Get the seconds portion of CLOCK_REALTIME (wall clock).
 * This is the clock that can be altered by NTP and is
 * independent of a reboot.
 */
time64_t ktime_get_real_seconds(void)
{
	return (time64_t)get_seconds();
}
EXPORT_SYMBOL(ktime_get_real_seconds);
#endif /* HAVE_KTIME_GET_REAL_SECONDS */

#ifndef HAVE_KTIME_GET_SECONDS
/*
 * Get the seconds portion of CLOCK_MONOTONIC
 * This clock is immutable and is reset across
 * reboots. For older platforms this is a
 * wrapper around get_seconds which is valid
 * until 2038. By that time this will be gone
 * one would hope.
 */
time64_t ktime_get_seconds(void)
{
	struct timespec64 now;

	ktime_get_ts64(&now);
	return now.tv_sec;
}
EXPORT_SYMBOL(ktime_get_seconds);
#endif /* HAVE_KTIME_GET_SECONDS */

static int (*cfs_apply_workqueue_attrs_t)(struct workqueue_struct *wq,
					  const struct workqueue_attrs *attrs);

int cfs_apply_workqueue_attrs(struct workqueue_struct *wq,
			      const struct workqueue_attrs *attrs)
{
	if (cfs_apply_workqueue_attrs_t)
		return cfs_apply_workqueue_attrs_t(wq, attrs);
	return 0;
}
EXPORT_SYMBOL_GPL(cfs_apply_workqueue_attrs);

/* Linux v5.1-rc5 214d8ca6ee ("stacktrace: Provide common infrastructure")
 * CONFIG_ARCH_STACKWALK indicates that save_stack_trace_tsk symbol is not
 * exported. Use symbol_get() to find if save_stack_trace_tsk is available.
 */
#ifdef CONFIG_ARCH_STACKWALK
static unsigned int (*task_dump_stack_t)(struct task_struct *task,
					 unsigned long *store,
					 unsigned int size,
					 unsigned int skipnr);

int cfs_stack_trace_save_tsk(struct task_struct *task, unsigned long *store,
			     unsigned int size, unsigned int skipnr)
{
	if (task_dump_stack_t)
		return task_dump_stack_t(task, store, size, skipnr);

	pr_info("No stack, save_stack_trace_tsk() could not be found\n");

	return 0;
}
#endif

#ifndef HAVE_XARRAY_SUPPORT
struct kmem_cache *xarray_cachep;

static void xarray_node_ctor(void *arg)
{
	struct xa_node *node = arg;

	memset(node, 0, sizeof(*node));
	INIT_LIST_HEAD(&node->private_list);
}
#endif

/*
 * This is opencoding of vfree_atomic from Linux kernel added in 4.10 with
 * minimum changes needed to work on older kernels too.
 */

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

int __init cfs_arch_init(void)
{
	int rc = 0;

	init_libcfs_vfree_atomic();

#ifndef HAVE_WAIT_VAR_EVENT
	wait_bit_init();
#endif
#ifdef CONFIG_ARCH_STACKWALK
	task_dump_stack_t =
		(void *)cfs_kallsyms_lookup_name("stack_trace_save_tsk");
#endif
	cfs_apply_workqueue_attrs_t =
		(void *)cfs_kallsyms_lookup_name("apply_workqueue_attrs");
#ifndef HAVE_XARRAY_SUPPORT
	xarray_cachep = kmem_cache_create("xarray_cache",
					  sizeof(struct xa_node), 0,
					  SLAB_PANIC | SLAB_RECLAIM_ACCOUNT,
					  xarray_node_ctor);
#endif
	rc = shrinker_debugfs_init();
	if (rc < 0)
		goto free_xcache;

#ifdef CONFIG_LL_ENCRYPTION
	rc = llcrypt_init();
	if (rc < 0)
		goto free_shrinker;
#endif
	return rc;

#ifdef CONFIG_LL_ENCRYPTION
free_shrinker:
	shrinker_debugfs_fini();
#endif
free_xcache:
#ifndef HAVE_XARRAY_SUPPORT
	kmem_cache_destroy(xarray_cachep);
#endif
	return rc;
}

void __exit cfs_arch_exit(void)
{
	/* exit_libcfs_vfree_atomic */
	__flush_workqueue(system_wq);

#ifndef HAVE_XARRAY_SUPPORT
	kmem_cache_destroy(xarray_cachep);
#endif
	shrinker_debugfs_fini();
#ifdef CONFIG_LL_ENCRYPTION
	llcrypt_exit();
#endif
}

int cfs_kernel_write(struct file *filp, const void *buf, size_t count,
		     loff_t *pos)
{
#ifdef HAVE_NEW_KERNEL_WRITE
	return kernel_write(filp, buf, count, pos);
#else
	mm_segment_t __old_fs = get_fs();
	int rc;

	set_fs(KERNEL_DS);
	rc = vfs_write(filp, (__force const char __user *)buf, count, pos);
	set_fs(__old_fs);

	return rc;
#endif
}
EXPORT_SYMBOL(cfs_kernel_write);

ssize_t cfs_kernel_read(struct file *file, void *buf, size_t count, loff_t *pos)
{
#ifdef HAVE_KERNEL_READ_LAST_POSP
	return kernel_read(file, buf, count, pos);
#else
	ssize_t size = kernel_read(file, *pos, buf, count);

	if (size > 0)
		*pos += size;
	return size;
#endif
}
EXPORT_SYMBOL(cfs_kernel_read);

#ifndef HAVE_KSET_FIND_OBJ
struct kobject *kset_find_obj(struct kset *kset, const char *name)
{
	struct kobject *ret = NULL;
	struct kobject *k;

	spin_lock(&kset->list_lock);

	list_for_each_entry(k, &kset->list, entry) {
		if (kobject_name(k) && !strcmp(kobject_name(k), name)) {
			if (kref_get_unless_zero(&k->kref))
				ret = k;
			break;
		}
	}

	spin_unlock(&kset->list_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(kset_find_obj);
#endif

#ifndef HAVE_MATCH_WILDCARD
/**
 * match_wildcard: - parse if a string matches given wildcard pattern
 * @pattern: wildcard pattern
 * @str: the string to be parsed
 *
 * Description: Parse the string @str to check if matches wildcard
 * pattern @pattern. The pattern may contain two type wildcardes:
 *   '*' - matches zero or more characters
 *   '?' - matches one character
 * If it's matched, return true, else return false.
 */
bool match_wildcard(const char *pattern, const char *str)
{
	const char *s = str;
	const char *p = pattern;
	bool star = false;

	while (*s) {
		switch (*p) {
		case '?':
			s++;
			p++;
			break;
		case '*':
			star = true;
			str = s;
			if (!*++p)
				return true;
			pattern = p;
			break;
		default:
			if (*s == *p) {
				s++;
				p++;
			} else {
				if (!star)
					return false;
				str++;
				s = str;
				p = pattern;
			}
			break;
		}
	}

	if (*p == '*')
		++p;
	return !*p;
}
EXPORT_SYMBOL(match_wildcard);
#endif /* !HAVE_MATCH_WILDCARD */

#ifndef HAVE_BITMAP_TO_ARR32
/**
 * bitmap_to_arr32 - copy the contents of bitmap to a u32 array of bits
 *	@buf: array of u32 (in host byte order), the dest bitmap
 *	@bitmap: array of unsigned longs, the source bitmap
 *	@nbits: number of bits in @bitmap
 */
void bitmap_to_arr32(u32 *buf, const unsigned long *bitmap, unsigned int nbits)
{
	unsigned int i, halfwords;

	halfwords = DIV_ROUND_UP(nbits, 32);
	for (i = 0; i < halfwords; i++) {
		buf[i] = (u32) (bitmap[i/2] & UINT_MAX);
		if (++i < halfwords)
			buf[i] = (u32) (bitmap[i/2] >> 32);
	}

	/* Clear tail bits in last element of array beyond nbits. */
	if (nbits % BITS_PER_LONG)
		buf[halfwords - 1] &= (u32) (UINT_MAX >> ((-nbits) & 31));
}
EXPORT_SYMBOL(bitmap_to_arr32);
#endif /* !HAVE_BITMAP_TO_ARR32 */

#ifndef HAVE_KSTRTOBOOL_FROM_USER
int kstrtobool_from_user(const char __user *s, size_t count, bool *res)
{
	/* Longest string needed to differentiate, newline, terminator */
	char buf[4];

	count = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, s, count))
		return -EFAULT;
	buf[count] = '\0';
	return strtobool(buf, res);
}
EXPORT_SYMBOL(kstrtobool_from_user);
#endif /* !HAVE_KSTRTOBOOL_FROM_USER */

#ifndef HAVE_NLA_STRDUP
char *nla_strdup(const struct nlattr *nla, gfp_t flags)
{
	size_t srclen = nla_len(nla);
	char *src = nla_data(nla), *dst;

	if (srclen > 0 && src[srclen - 1] == '\0')
		srclen--;

	dst = kmalloc(srclen + 1, flags);
	if (dst != NULL) {
		memcpy(dst, src, srclen);
		dst[srclen] = '\0';
	}
	return dst;
}
EXPORT_SYMBOL(nla_strdup);
#endif /* !HAVE_NLA_STRDUP */
