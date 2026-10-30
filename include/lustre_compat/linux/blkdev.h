/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __LIBCFS_LINUX_BLKDEV_H__
#define __LIBCFS_LINUX_BLKDEV_H__

#include_next <linux/blkdev.h>

#ifndef blk_queue_rot
#define blk_queue_rot(q)	(!blk_queue_nonrot((q)))
#endif

#endif /* __LIBCFS_LINUX_BLKDEV_H__ */
