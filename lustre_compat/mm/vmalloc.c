/* SPDX-License-Identifier: GPL-2.0+ */

#include <lustre_compat/linux/vmalloc.h>
#include <lustre_compat/linux/workqueue.h>

/*
 * This is opencoding of vfree_atomic from Linux kernel added in 4.10 with
 * minimum changes needed to work on older kernels too.
 *
 * We do this because using kallaym_lookup_name() can fail with exporting
 * vfree_atomic() which shows Lustre's days out of tree are numbered. In
 * reality the only reason we do this is because of the poor handling of
 * locking in the ptlrpc layer. Hoepfully a rework of ptlrpc layer will
 * remove the need of this code.
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

void init_compat_vfree_atomic(void)
{
	int i;

	for_each_possible_cpu(i) {
		struct vfree_deferred *p;

		p = &per_cpu(vfree_deferred, i);
		init_llist_head(&p->list);
		INIT_WORK(&p->wq, free_work);
	}
}

void exit_compat_vfree_atomic(void)
{
	/* exit_libcfs_vfree_atomic */
	__flush_workqueue(system_wq);
}

void compat_vfree_atomic(const void *addr)
{
	struct vfree_deferred *p = raw_cpu_ptr(&vfree_deferred);

	if (!addr)
		 return;

	if (llist_add((struct llist_node *)addr, &p->list))
		schedule_work(&p->wq);
}
EXPORT_SYMBOL(compat_vfree_atomic);
