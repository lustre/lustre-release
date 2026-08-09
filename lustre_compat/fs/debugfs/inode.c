// SPDX-License-Identifier: GPL-2.0+

#include <lustre_compat/linux/debugfs.h>

#ifndef HAVE_DEBUGFS_LOOKUP_AND_REMOVE
void debugfs_lookup_and_remove(const char *name, struct dentry *parent)
{
	struct dentry *dentry;

	dentry = debugfs_lookup(name, parent);
	if (!dentry)
		return;

	debugfs_remove(dentry);
	dput(dentry);
}
EXPORT_SYMBOL_GPL(debugfs_lookup_and_remove);
#endif
