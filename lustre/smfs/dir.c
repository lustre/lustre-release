/*
 * dir.c
 */
#define DEBUG_SUBSYSTEM S_SNAP

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/unistd.h>

#include "smfs_internal.h" 

static void d_unalloc(struct dentry *dentry)
{
        if (dentry) {                                                                                                                                                                                
        	list_del(&dentry->d_hash);
        	INIT_LIST_HEAD(&dentry->d_hash);
        	dput(dentry); 	
	}
}
static struct inode *sm_create_inode(struct super_block *sb,
				     struct inode *cache_inode) 
{
	struct inode *inode;

	inode = new_inode(sb);
	if (inode) {
		/*FIXME there are still some 
		 * other attributes need to
		 * duplicated*/
		inode->i_ino = cache_inode->i_ino;	 		
		inode->i_mode = cache_inode->i_mode;	 		
	}	
	
	return inode;
}
                                                                                                                                                                                                     
static void prepare_parent_dentry(struct dentry *dentry, struct inode *inode)
{
        atomic_set(&dentry->d_count, 1);
        dentry->d_vfs_flags = 0;
        dentry->d_flags = 0;
        dentry->d_inode = inode;
        dentry->d_op = NULL;
        dentry->d_fsdata = NULL;
        dentry->d_mounted = 0;
        INIT_LIST_HEAD(&dentry->d_hash);
        INIT_LIST_HEAD(&dentry->d_lru);
        INIT_LIST_HEAD(&dentry->d_subdirs);
        INIT_LIST_HEAD(&dentry->d_alias);
}

static int smfs_create(struct inode *dir, 
		       struct dentry *dentry, 
		       int mode)
{
	struct	inode *cache_dir; 
	struct	inode *cache_inode, *inode;
	struct  dentry tmp; 
	struct  dentry *cache_dentry;
	int 	rc;
	
	ENTRY;
	
	cache_dir = I2CI(dir);
        if (!cache_dir)
                RETURN(-ENOENT);
       
	prepare_parent_dentry(&tmp, cache_dir);      
	cache_dentry = d_alloc(&tmp, &dentry->d_name);
        
	if (!cache_dentry) 
                RETURN(-ENOENT);
	
	if(cache_dir && cache_dir->i_op->create)
		rc = cache_dir->i_op->create(cache_dir, cache_dentry, mode);
	if (rc)
		GOTO(exit, rc);
 
	cache_inode = cache_dentry->d_inode;
	inode = sm_create_inode(dir->i_sb, cache_inode);	
	
	if (!inode) 
		GOTO(exit, rc);		
	
	sm_setup_inode_ops(cache_inode, inode);
exit:
	d_unalloc(cache_dentry);	
	RETURN(rc);
}

struct inode_operations smfs_dir_fops = {
	create: smfs_create,
};

