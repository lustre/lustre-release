/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Basic library routines.
 *
 * Author: liang@whamcloud.com
 */

#ifndef __LIBCFS_WORKQUEUE_H__
#define __LIBCFS_WORKQUEUE_H__

#include <linux/workqueue.h>

struct workqueue_attrs *compat_alloc_workqueue_attrs(void);
void compat_free_workqueue_attrs(struct workqueue_attrs *attrs);

int compat_apply_workqueue_attrs(struct workqueue_struct *wq,
				  const struct workqueue_attrs *attrs);

#ifndef COMPAT_BUILD
#ifdef alloc_workqueue_attrs
# define alloc_workqueue_attrs_noprof	compat_alloc_workqueue_attrs
#else
# define alloc_workqueue_attrs		compat_alloc_workqueue_attrs
#endif
#define free_workqueue_attrs(attrs)	compat_free_workqueue_attrs(attrs)
#define	apply_workqueue_attrs(wq, attrs)	\
	compat_apply_workqueue_attrs(wq, attrs)
#endif

#ifndef HAVE_FLUSH___WORKQUEUE
#define __flush_workqueue(wq)  flush_scheduled_work()
#endif

#endif /* __LIBCFS_WORKQUEUE_H__ */
