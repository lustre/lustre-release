/*
 * Directory operations for SnapFS filesystem
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/locks.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/string.h>

#include <linux/filter.h>
#include <linux/snapfs.h>
#include <linux/snapsupport.h>

/* called when a cache lookup succeeds */

/* XXX PJB: the intent here is to make sure that inodes which are
   currently primary inodes under .snap directories are dropped when
   they are COWED.  It seems hard to me to get semantics that are equally
   good as for mounted snap_clone file systems, but we should try to get
   close 
*/
static int currentfs_dentry_revalidate(struct dentry *de, int flag)
{
//	struct inode *inode = de->d_inode;
	ENTRY;

	/* unless an ancestor is a .snap directory there is nothing to do */
#if 0
	if ( !currentfs_is_under_dotsnap(dentry) ) {
		EXIT;
		return 1;
	}
	/* XXX PJB get this to work guys! */
	if ( de->d_parent == "dotsnap inode" && 
	     inode_is_newer_than(find_time_by_name(de->d_parent->d_name.name))){
		1. drop this dentry 
		2. make sure the VFS does a new lookup
                3. probably all you need to do is 
		return 0;
	}
#else 
	return 1;
#endif
}

struct dentry_operations currentfs_dentry_ops = 
{
	d_revalidate: currentfs_dentry_revalidate
};

