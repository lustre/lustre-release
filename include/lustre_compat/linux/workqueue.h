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

#ifndef HAVE_FLUSH___WORKQUEUE
#define __flush_workqueue(wq)  flush_scheduled_work()
#endif

#endif /* __LIBCFS_WORKQUEUE_H__ */
