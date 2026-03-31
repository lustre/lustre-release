/* SPDX-License-Identifier: GPL-2.0 */

/* This file is part of Lustre, http://www.lustre.org/ */

#ifndef __LIBCFS_LINUX_INETDEVICE_H__
#define __LIBCFS_LINUX_INETDEIVCE_H__

#include <linux/inetdevice.h>

/*
 * kernel 5.3: commit ef11db3310e272d3d8dbe8739e0770820dd20e52
 * kernel 4.18.0-193.el8:
 * added in_dev_for_each_ifa_rtnl and in_dev_for_each_ifa_rcu
 * and removed for_ifa and endfor_ifa.
 * Use the _rntl variant as the current locking is rtnl.
 */
#ifdef HAVE_IN_DEV_FOR_EACH_IFA_RTNL
#define DECLARE_CONST_IN_IFADDR(ifa)            const struct in_ifaddr *ifa
#define endfor_ifa(in_dev)
#else
#define DECLARE_CONST_IN_IFADDR(ifa)
#define in_dev_for_each_ifa_rtnl(ifa, in_dev)   for_ifa((in_dev))
#define in_dev_for_each_ifa_rcu(ifa, in_dev)    for_ifa((in_dev))
#endif

#endif
