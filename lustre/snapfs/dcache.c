/*
 * Directory operations for SnapFS filesystem
 */

#define DEBUG_SUBSYSTEM S_SNAP

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/unistd.h>
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
#include <linux/snap.h>

#include "snapfs_internal.h" 


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
	RETURN(1);
#endif
}

struct dentry_operations currentfs_dentry_ops = 
{
	d_revalidate: currentfs_dentry_revalidate
};

