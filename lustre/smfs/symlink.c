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
	struct dentry *cache_dentry;
	int    rc = 0;

	if (!cache_inode)
		RETURN(-ENOENT);
	
	cache_dentry = d_alloc(NULL, &dentry->d_name);
	d_add(cache_dentry, cache_inode);
	igrab(cache_inode);
		
	if (cache_inode->i_op && cache_inode->i_op->readlink) 	
		rc = cache_inode->i_op->readlink(cache_dentry, buffer, buflen);
	
	d_unalloc(cache_dentry);
	return rc;
}

static int smfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *cache_inode = I2CI(dentry->d_inode);
	struct dentry *cache_dentry;
	int rc = 0;
	if (!cache_inode)
		RETURN(-ENOENT);
	
	cache_dentry = d_alloc(NULL, &dentry->d_name);
	d_add(cache_dentry, cache_inode);
	igrab(cache_inode);

	if (cache_inode->i_op && cache_inode->i_op->follow_link) 	
		rc = cache_inode->i_op->follow_link(cache_dentry, nd);
	
	d_unalloc(cache_dentry);
	return rc;

}
struct inode_operations smfs_sym_iops = {
	readlink:	smfs_readlink,
	follow_link:	smfs_follow_link,
	setxattr:       smfs_setxattr,          /* BKL held */
        getxattr:       smfs_getxattr,          /* BKL held */
        listxattr:      smfs_listxattr,         /* BKL held */
        removexattr:    smfs_removexattr,       /* BKL held */
};

struct file_operations smfs_sym_fops = {
};
