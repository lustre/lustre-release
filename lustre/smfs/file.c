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
#include <linux/lustre_idl.h>
#include "smfs_internal.h" 
        
/* instantiate a file handle to the cache file */
void smfs_prepare_cachefile(struct inode *inode,
			    struct file *file, 
			    struct inode *cache_inode,
			    struct file *cache_file,
			    struct dentry *cache_dentry)
{
	ENTRY;
	cache_file->f_pos = file->f_pos;
        cache_file->f_mode = file->f_mode;
        cache_file->f_flags = file->f_flags;
        cache_file->f_count  = file->f_count;
        cache_file->f_owner  = file->f_owner;
	cache_file->f_error = file->f_error;
	cache_file->f_op = inode->i_fop;
	cache_file->f_dentry = cache_dentry;
        cache_file->f_dentry->d_inode = cache_inode;
	cache_file->f_vfsmnt = file->f_vfsmnt;
	cache_file->private_data = file->private_data;
	cache_file->f_it = file->f_it;
	cache_file->f_reada = file->f_reada;
	cache_file->f_ramax = file->f_ramax;
	cache_file->f_raend = file->f_raend;
	cache_file->f_ralen = file->f_ralen;
	cache_file->f_rawin = file->f_rawin;
	EXIT;
}
/* update file structs*/
void smfs_update_file(struct file *file, 
		      struct file *cache_file)
{
	ENTRY;
	file->f_pos = cache_file->f_pos;
        file->f_mode = cache_file->f_mode;
        file->f_flags = cache_file->f_flags;
        file->f_count  = cache_file->f_count;
        file->f_owner  = cache_file->f_owner;
 	file->f_reada = cache_file->f_reada;
	file->f_ramax = cache_file->f_ramax;
	file->f_raend = cache_file->f_raend;
	file->f_ralen = cache_file->f_ralen;
	file->f_rawin = cache_file->f_rawin;
	EXIT;
}

static ssize_t smfs_write (struct file *filp, const char *buf, 
			   size_t count, loff_t *ppos)
{
	struct	inode *cache_inode;
	struct  dentry *dentry = filp->f_dentry;
	struct  inode *inode = dentry->d_inode;
        struct  file open_file;
	struct  dentry open_dentry;
	loff_t  tmp_ppos;
	loff_t  *cache_ppos;
	int 	rc = 0;
	
	ENTRY;
	
	cache_inode = I2CI(inode);
 
        if (!cache_inode)
                RETURN(-ENOENT);
	
	if (ppos != &(filp->f_pos)) {
		cache_ppos = &tmp_ppos;	
	} else {
		cache_ppos = &open_file.f_pos; 
	}
	*cache_ppos = *ppos;
	
	smfs_prepare_cachefile(inode, filp, cache_inode, 
			       &open_file, &open_dentry);
	if (cache_inode->i_fop->write)
		rc = cache_inode->i_fop->write(&open_file, buf, count, cache_ppos);
	
	*ppos = *cache_ppos;
	duplicate_inode(cache_inode, inode);
	smfs_update_file(filp, &open_file);

	RETURN(rc);
}

int smfs_ioctl(struct inode * inode, struct file * filp, 
	       unsigned int cmd, unsigned long arg)
{
	struct	inode *cache_inode;
	struct  dentry *dentry = filp->f_dentry;
        struct  file open_file;
	struct  dentry open_dentry;
	ssize_t rc = 0;
	
	ENTRY;
	
	cache_inode = I2CI(dentry->d_inode);
        if (!cache_inode)
                RETURN(-ENOENT);

	smfs_prepare_cachefile(inode, filp, cache_inode, 
			       &open_file, &open_dentry);
	
	if (cache_inode->i_fop->ioctl)
		rc = cache_inode->i_fop->ioctl(cache_inode, &open_file, cmd, arg);
		
	duplicate_inode(cache_inode, inode);
	smfs_update_file(filp, &open_file);
        RETURN(rc);
}

static ssize_t smfs_read (struct file *filp, char *buf, 
			  size_t count, loff_t *ppos)
{
	struct	inode *cache_inode;
	struct  dentry *dentry = filp->f_dentry;
	struct  inode *inode = dentry->d_inode;
        struct  file open_file;
	struct  dentry open_dentry;
	loff_t  tmp_ppos;
	loff_t  *cache_ppos;
	ssize_t rc = 0;
	
	ENTRY;
	
	cache_inode = I2CI(dentry->d_inode);
        if (!cache_inode)
                RETURN(-ENOENT);

	if (ppos != &(filp->f_pos)) {
		cache_ppos = &tmp_ppos;	
	} else {
		cache_ppos = &open_file.f_pos; 
	}
	*cache_ppos = *ppos;
	
	
	smfs_prepare_cachefile(inode, filp, cache_inode, 
			       &open_file, &open_dentry);

	
	if (cache_inode->i_fop->read)
		rc = cache_inode->i_fop->read(&open_file, buf, count, cache_ppos);
    
	*ppos = *cache_ppos;
	duplicate_inode(cache_inode, inode);
	smfs_update_file(filp, &open_file);
	RETURN(rc);
}

static loff_t smfs_llseek(struct file *file, 
		          loff_t offset, 
		          int origin)
{
	struct	inode *cache_inode;
	struct  dentry *dentry = file->f_dentry;
        struct  file open_file;
	struct  dentry open_dentry;
	ssize_t rc = 0;
	
	ENTRY;
	
	cache_inode = I2CI(dentry->d_inode);
        if (!cache_inode)
                RETURN(-ENOENT);

	smfs_prepare_cachefile(dentry->d_inode, file, cache_inode, 
			       &open_file, &open_dentry);
	
	if (cache_inode->i_fop->llseek)
		rc = cache_inode->i_fop->llseek(&open_file, offset, origin);

	duplicate_inode(cache_inode, dentry->d_inode);
	smfs_update_file(file, &open_file);
		
        RETURN(rc);
}

static int smfs_mmap(struct file * file, struct vm_area_struct * vma)
{
        struct inode *inode = file->f_dentry->d_inode;
        struct inode *cache_inode = NULL;
        struct  file open_file;
	struct  dentry open_dentry;
	int    rc = 0;

	cache_inode = I2CI(inode);
        if (!cache_inode)
                RETURN(-ENOENT);

	smfs_prepare_cachefile(inode, file, cache_inode, 
			       &open_file, &open_dentry);
  
	if (cache_inode->i_mapping == &cache_inode->i_data)
                inode->i_mapping = cache_inode->i_mapping;

	if (cache_inode->i_fop->mmap)
		rc = cache_inode->i_fop->mmap(&open_file, vma);
      
	duplicate_inode(cache_inode, inode);
	smfs_update_file(file, &open_file);
	
	RETURN(rc);
}

static int smfs_open(struct inode * inode, struct file * filp)
{
	struct inode *cache_inode = NULL;
        struct  file open_file;
	struct  dentry open_dentry;
	int    rc = 0;

	cache_inode = I2CI(inode);
        if (!cache_inode)
                RETURN(-ENOENT);

	smfs_prepare_cachefile(inode, filp, cache_inode, 
			       &open_file, &open_dentry);
	
	if (cache_inode->i_fop->open)
		rc = cache_inode->i_fop->open(cache_inode, &open_file);
        
	duplicate_inode(cache_inode, inode);
	smfs_update_file(filp, &open_file);
	
	RETURN(rc);

}
static int smfs_release(struct inode * inode, struct file * filp)
{
	struct inode *cache_inode = NULL;
        struct  file open_file;
	struct  dentry open_dentry;
	int    rc = 0;

	cache_inode = I2CI(inode);
        if (!cache_inode)
                RETURN(-ENOENT);
	
	smfs_prepare_cachefile(inode, filp, cache_inode, 
			       &open_file, &open_dentry);

	if (cache_inode->i_fop->release)
		rc = cache_inode->i_fop->release(cache_inode, &open_file);

	duplicate_inode(cache_inode, inode);
	smfs_update_file(filp, &open_file);
        
	RETURN(rc);
}
int smfs_fsync(struct file * file, 
		      struct dentry *dentry, 
		      int datasync)
{
	struct inode *inode = dentry->d_inode;
	struct inode *cache_inode;
        struct  file open_file;
	struct  dentry open_dentry;
	int    rc = 0;

	cache_inode = I2CI(inode);
        if (!cache_inode)
                RETURN(-ENOENT);
	
	smfs_prepare_cachefile(inode, file, cache_inode, 
			       &open_file, &open_dentry);

	if (cache_inode->i_fop->fsync)
		rc = cache_inode->i_fop->fsync(&open_file, &open_dentry, datasync);
	
	duplicate_inode(cache_inode, inode);
	smfs_update_file(file, &open_file);
	
	RETURN(rc);
}

struct file_operations smfs_file_fops = {
	llseek: 	smfs_llseek,
	read:		smfs_read,
	write:  	smfs_write,
	ioctl:  	smfs_ioctl,
	mmap:		smfs_mmap,
	open:		smfs_open,
	release: 	smfs_release,
	fsync:		smfs_fsync,
};

static void smfs_prepare_cache_dentry(struct dentry *dentry, struct inode *inode)
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

static void smfs_truncate(struct inode * inode)      
{
	struct	inode *cache_inode;

	cache_inode = I2CI(inode);

	if (!cache_inode)
		return;
	
	if (cache_inode->i_op->truncate)
		cache_inode->i_op->truncate(cache_inode);

	duplicate_inode(inode, cache_inode);		
        
	return;	
} 
 
int smfs_setattr(struct dentry *dentry, struct iattr *attr)      
{
	struct	inode *cache_inode;
	struct  dentry open_dentry;

	int	rc = 0;

	cache_inode = I2CI(dentry->d_inode);

	if (!cache_inode) 
		RETURN(-ENOENT);
	smfs_prepare_cache_dentry(&open_dentry, cache_inode);
	
	if (cache_inode->i_op->setattr)
		rc = cache_inode->i_op->setattr(&open_dentry, attr);

	duplicate_inode(cache_inode, dentry->d_inode);		
	
	RETURN(rc);
} 
  
int smfs_setxattr(struct dentry *dentry, const char *name,
              	  const void *value, size_t size, int flags)
{
	struct	inode *cache_inode;
	struct  dentry open_dentry;
	int	rc = 0;

	cache_inode = I2CI(dentry->d_inode);

	if (!cache_inode) 
		RETURN(-ENOENT);

	smfs_prepare_cache_dentry(&open_dentry, cache_inode);
	
	if (cache_inode->i_op->setattr)
		rc = cache_inode->i_op->setxattr(&open_dentry, name, value, size, flags);

	duplicate_inode(cache_inode, dentry->d_inode);		
	RETURN(rc);
} 
                        
int smfs_getxattr(struct dentry *dentry, const char *name,
              	  void *buffer, size_t size)
{
	struct	inode *cache_inode;
	struct  dentry open_dentry;
	int	rc = 0;

	cache_inode = I2CI(dentry->d_inode);

	if (!cache_inode) 
		RETURN(-ENOENT);

	smfs_prepare_cache_dentry(&open_dentry, cache_inode);
	
	if (cache_inode->i_op->setattr)
		rc = cache_inode->i_op->getxattr(&open_dentry, name, buffer, size);

	duplicate_inode(cache_inode, dentry->d_inode);		
	RETURN(rc);
}

ssize_t smfs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct	inode *cache_inode;
	struct  dentry open_dentry;
	int	rc = 0;

	cache_inode = I2CI(dentry->d_inode);

	if (!cache_inode) 
		RETURN(-ENOENT);

	smfs_prepare_cache_dentry(&open_dentry, cache_inode);
	
	if (cache_inode->i_op->listxattr)
		rc = cache_inode->i_op->listxattr(&open_dentry, buffer, size);

	duplicate_inode(cache_inode, dentry->d_inode);		
	RETURN(rc);
}                                                                                                                                                           

int smfs_removexattr(struct dentry *dentry, const char *name)
{
	struct	inode *cache_inode;
	struct  dentry open_dentry;
	int	rc = 0;

	cache_inode = I2CI(dentry->d_inode);

	if (!cache_inode) 
		RETURN(-ENOENT);

	smfs_prepare_cache_dentry(&open_dentry, cache_inode);
	
	if (cache_inode->i_op->removexattr)
		rc = cache_inode->i_op->removexattr(&open_dentry, name);

	duplicate_inode(cache_inode, dentry->d_inode);		
	RETURN(rc);
}

struct inode_operations smfs_file_iops = {
	truncate:       smfs_truncate,          /* BKL held */
        setattr:        smfs_setattr,           /* BKL held */
        setxattr:       smfs_setxattr,          /* BKL held */
        getxattr:       smfs_getxattr,          /* BKL held */
        listxattr:      smfs_listxattr,         /* BKL held */
        removexattr:    smfs_removexattr,       /* BKL held */
};

