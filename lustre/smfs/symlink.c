/*
 *  smfs/symlink.c
 *
 *
 */
#define DEBUG_SUBSYSTEM S_SNAP

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "smfs_internal.h" 

static int smfs_readlink(struct dentry * dentry, char * buffer, int buflen)
{
	struct inode *cache_inode = I2CI(dentry->d_inode);
	int rc = 0;

	if (cache_inode->i_op && cache_inode->i_op->readlink) 	
		rc = cache_inode->i_op->readlink(dentry, buffer, buflen);
	
	return rc;
}

static int smfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *cache_inode = I2CI(dentry->d_inode);
	int rc = 0;

	if (cache_inode->i_op && cache_inode->i_op->follow_link) 	
		rc = cache_inode->i_op->follow_link(dentry, nd);
	
	return rc;

}
struct inode_operations smfs_sym_iops = {
	readlink:	smfs_readlink,
	follow_link:	smfs_follow_link,
};

struct file_operations smfs_sym_fops = {
};
