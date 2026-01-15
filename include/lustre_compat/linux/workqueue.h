/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

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

#ifndef HAVE_FLUSH___WORKQUEUE
#define __flush_workqueue(wq)  flush_scheduled_work()
#endif

#endif /* __LIBCFS_WORKQUEUE_H__ */
