/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LIBCFS_LINUX_NETDEV_LOCK_H__
#define __LIBCFS_LINUX_NETDEV_LOCK_H__

#ifndef HAVE_NETDEV_LOCK_OPS
static inline void netdev_lock_ops(struct net_device *dev)
{
}

static inline void netdev_unlock_ops(struct net_device *dev)
{
}
#else
#include <net/netdev_lock.h>
#endif

#endif /* __LIBCFS_LINUX_NETDEV_LOCK_H__ */
