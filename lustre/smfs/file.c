/*
 * file.c
 */

#define DEBUG_SUBSYSTEM S_SM

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/unistd.h>
#include <linux/pagemap.h>
#include "smfs_internal.h" 


static int smfs_readpage(struct file *file, 
			 struct page *page)
{
	struct  inode *inode = page->mapping->host;
	struct	inode *cache_inode;
	int 	rc;
	
	ENTRY;
	
	cache_inode = I2CI(inode);
 
        if (!cache_inode)
                RETURN(-ENOENT);

	if (cache_inode->i_mapping->a_ops->readpage)
		rc = cache_inode->i_mapping->a_ops->readpage(file, page);
		
        RETURN(rc);
	
}
static int smfs_writepage(struct page *page)
{

	struct  inode *inode = page->mapping->host;
	struct	inode *cache_inode;
	int 	rc;
	
	ENTRY;
	
	cache_inode = I2CI(inode);
 
        if (!cache_inode)
                RETURN(-ENOENT);

	if (cache_inode->i_mapping->a_ops->writepage)
		rc = cache_inode->i_mapping->a_ops->writepage(page);
		
        RETURN(rc);
	
}
struct address_space_operations smfs_file_aops = {
	readpage:   smfs_readpage,
	writepage:  smfs_writepage,
};
                                                                                                                                                                                                     

static ssize_t smfs_write (struct file *filp, const char *buf, 
			   size_t count, loff_t *ppos)
{
	struct	inode *cache_inode;
	struct  dentry *dentry = filp->f_dentry;
	int 	rc;
	
	ENTRY;
	
	cache_inode = I2CI(dentry->d_inode);
 
        if (!cache_inode)
                RETURN(-ENOENT);

	if (cache_inode->i_fop->write)
		cache_inode->i_fop->write(filp, buf, count, ppos);
		
        RETURN(rc);
}

static ssize_t smfs_read (struct file *filp, char *buf, 
			  size_t count, loff_t *ppos)
{
	struct	inode *cache_inode;
	struct  dentry *dentry = filp->f_dentry;
	ssize_t rc;
	
	ENTRY;
	
	cache_inode = I2CI(dentry->d_inode);
 
        if (!cache_inode)
                RETURN(-ENOENT);

	if (cache_inode->i_fop->read)
		rc = cache_inode->i_fop->read(filp, buf, count, ppos);
		
        RETURN(rc);
}

struct file_operations smfs_file_fops = {
	read:	smfs_read,
	write:  smfs_write,
};

static void smfs_truncate(struct inode * inode)      
{
	struct	inode *cache_inode;

	cache_inode = I2CI(inode);

	if (!cache_inode)
		return;
	
	if (cache_inode->i_op->truncate)
		cache_inode->i_op->truncate(cache_inode);

	duplicate(inode, cache_inode);		
        
	return;	
} 
 
static int smfs_setattr(struct dentry *dentry, struct iattr *attr)      
{
	struct	inode *cache_inode;
	int	rc = 0;

	cache_inode = I2CI(dentry->d_inode);

	if (!cache_inode) 
		RETURN(-ENOENT);
	
	if (cache_inode->i_op->setattr)
		rc = cache_inode->i_op->setattr(dentry, attr);

	RETURN(rc);
} 
                                                                                                                                                                                     
struct inode_operations smfs_file_iops = {
	truncate:       smfs_truncate,          /* BKL held */
        setattr:        smfs_setattr,           /* BKL held */
};

