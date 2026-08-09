/* SPDX-License-Identifier: GPL-2.0 */

/* This file is part of Lustre, http://www.lustre.org/ */

#ifndef __LIBCFS_LINUX_DEBUGFS_H__
#define __LIBCFS_LINUX_DEBUGFS_H__

#include <linux/debugfs.h>

#ifndef HAVE_DEBUGFS_LOOKUP_AND_REMOVE
void debugfs_lookup_and_remove(const char *name, struct dentry *parent);
#endif

#endif
