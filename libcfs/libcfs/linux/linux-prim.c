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
#include <libcfs/linux/linux-misc.h>
#include <libcfs/linux/linux-mem.h>
#include <lustre_compat/linux/xarray.h>
#include <lustre_compat/linux/wait_bit.h>
#include <lustre_compat/linux/wait.h>
#include <lustre_crypto.h>

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

	rc = shrinker_debugfs_init();
	if (rc < 0)
		goto failed;

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
failed:
	return rc;
}

void __exit cfs_arch_exit(void)
{
	/* exit_libcfs_vfree_atomic */
	__flush_workqueue(system_wq);

	shrinker_debugfs_fini();
#ifdef CONFIG_LL_ENCRYPTION
	llcrypt_exit();
#endif
}

static unsigned int libcfs_reserved_cache;
module_param(libcfs_reserved_cache, int, 0644);
MODULE_PARM_DESC(libcfs_reserved_cache, "system page cache reservation in mbytes (for arc cache)");

#ifdef HAVE_TOTALRAM_PAGES_AS_FUNC
  #define _totalram_pages() totalram_pages()
#else
  #define _totalram_pages() totalram_pages
#endif

unsigned long cfs_totalram_pages(void)
{
	if (libcfs_reserved_cache > _totalram_pages()/2)
		libcfs_reserved_cache = _totalram_pages() / 2;

	return _totalram_pages() - libcfs_reserved_cache;
}
EXPORT_SYMBOL(cfs_totalram_pages);
