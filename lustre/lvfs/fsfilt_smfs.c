/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/lib/fsfilt_smfs.c
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Wang Di <wangdi@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/version.h>
#include <linux/kp30.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>
#include <linux/obd.h>
#include <linux/obd_class.h>
#include <linux/module.h>
#include <linux/init.h>

static void *fsfilt_smfs_start(struct inode *inode, int op, 
                               void *desc_private, int logs)
{
	void *handle;
        struct inode *cache_inode = I2CI(inode);
	struct fsfilt_operations *cache_fsfilt = I2FOPS(inode);

        if (cache_fsfilt == NULL)
                return NULL;

        if (!cache_fsfilt->fs_start)
		return ERR_PTR(-ENOSYS);
		
        handle = cache_fsfilt->fs_start(cache_inode, op, 
					desc_private, logs);
        return handle;
}

static void *fsfilt_smfs_brw_start(int objcount, struct fsfilt_objinfo *fso,
                                   int niocount, struct niobuf_local *nb,
                                   void *desc_private, int logs)
{
	struct fsfilt_operations *cache_fsfilt;
        struct dentry *cache_dentry = NULL;
        struct inode *cache_inode = NULL;
        struct fsfilt_objinfo cache_fso;
        void   *rc = NULL;
        
        ENTRY; 
        cache_fsfilt = I2FOPS(fso->fso_dentry->d_inode);
        if (cache_fsfilt == NULL) 
                return NULL;

        cache_inode = I2CI(fso->fso_dentry->d_inode);
 	cache_dentry = pre_smfs_dentry(NULL, cache_inode, fso->fso_dentry);	
    
        if (!cache_dentry)
                GOTO(exit, rc = ERR_PTR(-ENOMEM));
    
        cache_fso.fso_dentry = cache_dentry; 
        cache_fso.fso_bufcnt = fso->fso_bufcnt;
 
        if (!cache_fsfilt->fs_brw_start)
		return ERR_PTR(-ENOSYS);
		
        rc = (cache_fsfilt->fs_brw_start(objcount, &cache_fso, 
                            		 niocount, nb, desc_private,
                                         logs));
exit:
        post_smfs_dentry(cache_dentry); 
        return rc; 
}

static int fsfilt_smfs_commit(struct inode *inode, void *h, 
                              int force_sync)
{
	struct fsfilt_operations *cache_fsfilt = I2FOPS(inode);
        struct inode *cache_inode = NULL;
        int    rc = -EIO;      
 
        cache_inode = I2CI(inode);
 
        if (cache_fsfilt == NULL)
                RETURN(rc);
       
        if (!cache_fsfilt->fs_commit) 
		RETURN(-ENOSYS);
        
	rc = cache_fsfilt->fs_commit(cache_inode, h, force_sync);
        
        RETURN(rc);
}

static int fsfilt_smfs_commit_async(struct inode *inode, void *h,
                                    void **wait_handle)
{
	struct fsfilt_operations *cache_fsfilt = I2FOPS(inode);
        struct inode *cache_inode = NULL;
        int    rc = -EIO;      
 
        cache_inode = I2CI(inode);
        if (cache_fsfilt == NULL)
    		RETURN(-EINVAL);
       
        if (!cache_fsfilt->fs_commit_async)
		RETURN(-ENOSYS);
		
        rc = cache_fsfilt->fs_commit_async(cache_inode, h, wait_handle);
        
        RETURN(rc);
}

static int fsfilt_smfs_commit_wait(struct inode *inode, void *h)
{
	struct fsfilt_operations *cache_fsfilt = I2FOPS(inode);
        struct inode *cache_inode = NULL;
        int    rc = -EIO;      
 
        cache_inode = I2CI(inode);
        if (cache_fsfilt == NULL)
                RETURN(-EINVAL);
       
        if (!cache_fsfilt->fs_commit_wait) 
		RETURN(-ENOSYS);
        
	rc = cache_fsfilt->fs_commit_wait(cache_inode, h);
        
        RETURN(rc);
}

static int fsfilt_smfs_setattr(struct dentry *dentry, void *handle,
                               struct iattr *iattr, int do_trunc)
{
	struct fsfilt_operations *cache_fsfilt = I2FOPS(dentry->d_inode);
        struct dentry *cache_dentry = NULL;
        struct inode *cache_inode = NULL;
        int    rc = -EIO;
 
        if (!cache_fsfilt) 
                RETURN(rc);
 
        cache_inode = I2CI(dentry->d_inode); 
       
	cache_dentry = pre_smfs_dentry(NULL, cache_inode, dentry);	
        if (!cache_dentry)
                GOTO(exit, rc = -ENOMEM);
  
        pre_smfs_inode(dentry->d_inode, cache_inode);
        
        if (!cache_fsfilt->fs_setattr)
		RETURN(-ENOSYS);
		
	rc = cache_fsfilt->fs_setattr(cache_dentry, handle, 
                                      iattr, do_trunc);
        
        post_smfs_inode(dentry->d_inode, cache_inode);
       
exit:
        post_smfs_dentry(cache_dentry);
        RETURN(rc);                    
}

static int fsfilt_smfs_iocontrol(struct inode *inode, struct file *file,
                                 unsigned int cmd, unsigned long arg)
{
	struct fsfilt_operations *cache_fsfilt = I2FOPS(inode);
        struct inode *cache_inode = NULL;
	struct smfs_file_info *sfi = NULL;
        int    rc = -EIO;                                                                                                                                                                                                     
        ENTRY;
                                                                                                                                                                                                     
        if (!cache_fsfilt) 
                RETURN(rc);
        
        cache_inode = I2CI(inode);
       
        if (!cache_inode)
                RETURN(rc);

	if (file != NULL) {
		sfi = F2SMFI(file);
		
		if (sfi->magic != SMFS_FILE_MAGIC) 
			BUG();
	} else {
		sfi = NULL;
	}
        
        if (!cache_fsfilt->fs_iocontrol)
		RETURN(-ENOSYS);
    
	if (sfi) {
		rc = cache_fsfilt->fs_iocontrol(cache_inode,
						sfi->c_file, 
                                    		cmd, arg);
	} else {
		rc = cache_fsfilt->fs_iocontrol(cache_inode,
						NULL, cmd, arg);
	}
	
	/* FIXME-UMKA: Should this be in duplicate_inode()? */
	if (rc == 0 && cmd == EXT3_IOC_SETFLAGS)
		inode->i_flags = cache_inode->i_flags;
		
	post_smfs_inode(inode, cache_inode); 

        RETURN(rc);
}

static int fsfilt_smfs_set_md(struct inode *inode, void *handle,
                              void *lmm, int lmm_size)
{
	struct fsfilt_operations *cache_fsfilt = I2FOPS(inode);
        struct inode *cache_inode = NULL;
        int    rc = -EIO;
  
        if (!cache_fsfilt) 
                RETURN(-EINVAL);
        
        cache_inode = I2CI(inode);
       
        if (!cache_inode)
                RETURN(-ENOENT);
       
        pre_smfs_inode(inode, cache_inode); 
        
        if (!cache_fsfilt->fs_set_md)
		RETURN(-ENOSYS);
		
	down(&cache_inode->i_sem);
		
        rc = cache_fsfilt->fs_set_md(cache_inode, handle,
                                     lmm, lmm_size); 
				     
	up(&cache_inode->i_sem);
	
        post_smfs_inode(inode, cache_inode); 
        
        RETURN(rc); 
}

/* Must be called with i_sem held */
static int fsfilt_smfs_get_md(struct inode *inode, void *lmm, int lmm_size)
{
	struct fsfilt_operations *cache_fsfilt = I2FOPS(inode);
        struct inode *cache_inode = NULL;
        int    rc = -EIO;
  
        if (!cache_fsfilt) 
                RETURN(-EINVAL);
        
        cache_inode = I2CI(inode);
       
        if (!cache_inode)
                RETURN(-ENOENT);
       
        pre_smfs_inode(inode, cache_inode); 
        
        if (!cache_fsfilt->fs_get_md)
		RETURN(-ENOSYS);
		
	down(&cache_inode->i_sem);
	
	rc = cache_fsfilt->fs_get_md(cache_inode, lmm, 
				     lmm_size); 
				     
	up(&cache_inode->i_sem);
        
        post_smfs_inode(inode, cache_inode); 
       
        RETURN(rc); 
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
static int fsfilt_smfs_send_bio(struct inode *inode, 
				struct bio *bio)
#else
static int fsfilt_smfs_send_bio(int rw, struct inode *inode, 
				struct kiobuf *bio)
#endif
{
        struct inode *cache_inode;
	struct fsfilt_operations *cache_fsfilt;
	
        cache_fsfilt = I2FOPS(inode);
        if (!cache_fsfilt) 
                RETURN(-EINVAL);
        
        cache_inode = I2CI(inode);
        if (!cache_inode)
                RETURN(-EINVAL);
        
	if (!cache_fsfilt->fs_send_bio)
		RETURN(-ENOSYS);
		
	return cache_fsfilt->fs_send_bio(rw, cache_inode, bio);
}

static struct page *
fsfilt_smfs_getpage(struct inode *inode, long int index)
{
	struct  fsfilt_operations *cache_fsfilt;
        struct  inode *cache_inode;

        cache_fsfilt = I2FOPS(inode);
        if (!cache_fsfilt) 
                RETURN(ERR_PTR(-EINVAL));
        
        cache_inode = I2CI(inode);
        if (!cache_inode)
                RETURN(ERR_PTR(-EINVAL));
        
	if (!cache_fsfilt->fs_getpage)
		RETURN(ERR_PTR(-ENOSYS));
	
        return cache_fsfilt->fs_getpage(cache_inode, index);
}

static ssize_t fsfilt_smfs_readpage(struct file *file, char *buf,
                                    size_t count, loff_t *off)
{
	struct fsfilt_operations *cache_fsfilt;
	struct smfs_file_info *sfi; 
        struct inode *cache_inode;
        loff_t tmp_ppos;
        loff_t *cache_ppos;
        ssize_t rc = -EIO;

        ENTRY;

        cache_fsfilt = I2FOPS(file->f_dentry->d_inode);
        if (!cache_fsfilt) 
                RETURN(rc);
        
        cache_inode = I2CI(file->f_dentry->d_inode);
        if (!cache_inode)
                RETURN(rc);

	sfi = F2SMFI(file);
	if (sfi->magic != SMFS_FILE_MAGIC)
                BUG();
        
        if (off != &(file->f_pos)) {
                cache_ppos = &tmp_ppos;
        } else {
                cache_ppos = &sfi->c_file->f_pos;
        }
        *cache_ppos = *off;
        
        pre_smfs_inode(file->f_dentry->d_inode, cache_inode);
        
        if (cache_fsfilt->fs_readpage) 
                rc = cache_fsfilt->fs_readpage(sfi->c_file, buf,
                                               count, cache_ppos);
        
        *off = *cache_ppos;
        post_smfs_inode(file->f_dentry->d_inode, cache_inode);
        duplicate_file(file, sfi->c_file);
        
        RETURN(rc);
}

static int fsfilt_smfs_add_journal_cb(struct obd_device *obd,
                                      struct super_block *sb,
                                      __u64 last_rcvd, void *handle,
                                      fsfilt_cb_t cb_func,
                                      void *cb_data)
{
        struct fsfilt_operations *cache_fsfilt = S2SMI(sb)->sm_cache_fsfilt;
        struct super_block *csb = S2CSB(sb);
        int rc = -EIO;

        if (!cache_fsfilt) 
                 RETURN(rc);
        if (cache_fsfilt->fs_add_journal_cb)
                rc = cache_fsfilt->fs_add_journal_cb(obd, csb, last_rcvd,
                                                     handle, cb_func, cb_data);
        RETURN(rc);
}

static int fsfilt_smfs_statfs(struct super_block *sb, struct obd_statfs *osfs)
{
	struct fsfilt_operations *cache_fsfilt = S2SMI(sb)->sm_cache_fsfilt;
        struct super_block *csb = S2CSB(sb);
        int rc = -EIO;

        if (!cache_fsfilt)
                RETURN(rc);
        
        if (!cache_fsfilt->fs_statfs)
		RETURN(-ENOSYS);
		
        rc = cache_fsfilt->fs_statfs(csb, osfs);
        duplicate_sb(csb, sb);
        
        RETURN(rc);
}

static int fsfilt_smfs_sync(struct super_block *sb)
{
	struct fsfilt_operations *cache_fsfilt = S2SMI(sb)->sm_cache_fsfilt;
        struct super_block *csb = S2CSB(sb);
        int    rc = -EIO;
 
        if(!cache_fsfilt)
                RETURN(-EINVAL);
        
        if (!cache_fsfilt->fs_sync)
		RETURN(-ENOSYS);
        
	rc = cache_fsfilt->fs_sync(csb);
        
        RETURN(rc); 
}

int fsfilt_smfs_map_inode_pages(struct inode *inode, struct page **page,
                                int pages, unsigned long *blocks, 
                                int *created, int create,
                                struct semaphore *sem)
{
	struct  fsfilt_operations *cache_fsfilt = I2FOPS(inode);
        struct  inode *cache_inode = NULL;
        int     rc = -EIO;
         
        if (!cache_fsfilt)
                RETURN(-EINVAL);
        
        cache_inode = I2CI(inode);
       
        if (!cache_inode)
                RETURN(rc);

        if (!cache_fsfilt->fs_map_inode_pages) 
		RETURN(-ENOSYS);
	
	down(&cache_inode->i_sem);
        rc = cache_fsfilt->fs_map_inode_pages(cache_inode, page, pages, blocks,
                                              created, create, NULL);
	up(&cache_inode->i_sem);
	
        RETURN(rc);
}

static int fsfilt_smfs_prep_san_write(struct inode *inode, long *blocks,
                                      int nblocks, loff_t newsize)
{
	struct  fsfilt_operations *cache_fsfilt = I2FOPS(inode);
        struct  inode *cache_inode = NULL;
        int     rc = -EIO;
         
        if (!cache_fsfilt)
                RETURN(-EINVAL);
        
        cache_inode = I2CI(inode);
       
        if (!cache_inode)
                RETURN(-EINVAL);

        if (!cache_fsfilt->fs_prep_san_write)
		RETURN(-ENOSYS);
        
	down(&cache_inode->i_sem);
	rc = cache_fsfilt->fs_prep_san_write(cache_inode, blocks, 
                                             nblocks, newsize);
	up(&cache_inode->i_sem);
        
	RETURN(rc);
}

static int fsfilt_smfs_read_record(struct file * file, void *buf,
                                   int size, loff_t *offs)
{
	struct  fsfilt_operations *cache_fsfilt;
        struct  inode *cache_inode;
	struct  smfs_file_info *sfi; 
        loff_t  tmp_ppos;
        loff_t  *cache_ppos;
        ssize_t rc;
        
        ENTRY;
        cache_fsfilt = I2FOPS(file->f_dentry->d_inode); 
        if (!cache_fsfilt) 
                RETURN(-EINVAL);
        
        cache_inode = I2CI(file->f_dentry->d_inode);
        
        if (!cache_inode)
                RETURN(-EINVAL);

	sfi = F2SMFI(file);
	if (sfi->magic != SMFS_FILE_MAGIC) BUG();
        
        if (offs != &(file->f_pos)) {
                cache_ppos = &tmp_ppos;
        } else {
                cache_ppos = &sfi->c_file->f_pos;
        }
        *cache_ppos = *offs;

        pre_smfs_inode(file->f_dentry->d_inode, cache_inode);

        if (!cache_fsfilt->fs_read_record)
		RETURN(-ENOSYS);
		
        rc = cache_fsfilt->fs_read_record(sfi->c_file, buf, 
					  size, cache_ppos);
        
        *offs = *cache_ppos;
        post_smfs_inode(file->f_dentry->d_inode, cache_inode);
        duplicate_file(file, sfi->c_file); 
        
        RETURN(rc);
}

static int fsfilt_smfs_write_record(struct file *file, void *buf, int bufsize,
                                    loff_t *offs, int force_sync)
{
	struct  fsfilt_operations *cache_fsfilt;
        struct  inode *cache_inode;
	struct  smfs_file_info *sfi; 
        loff_t  tmp_ppos;
        loff_t  *cache_ppos;
        ssize_t rc = -EIO;

        ENTRY;

        cache_fsfilt = I2FOPS(file->f_dentry->d_inode); 
        if (!cache_fsfilt) 
                RETURN(-EINVAL);
        
        cache_inode = I2CI(file->f_dentry->d_inode);
        
        if (!cache_inode)
                RETURN(-EINVAL);

	sfi = F2SMFI(file);
	if (sfi->magic != SMFS_FILE_MAGIC) BUG();
        
        if (offs != &(file->f_pos)) {
                cache_ppos = &tmp_ppos;
        } else {
                cache_ppos = &sfi->c_file->f_pos;
        }
        *cache_ppos = *offs;
       
        pre_smfs_inode(file->f_dentry->d_inode, cache_inode);
        
        if (!cache_fsfilt->fs_write_record)
		RETURN(-ENOSYS);
        
	rc = cache_fsfilt->fs_write_record(sfi->c_file, buf, 
                                           bufsize, cache_ppos, force_sync);
        *offs = *cache_ppos; 
        post_smfs_inode(file->f_dentry->d_inode, cache_inode);
        duplicate_file(file, sfi->c_file); 
        
        RETURN(rc);
}

static int fsfilt_smfs_setup(struct super_block *sb)
{
	struct smfs_super_info *smfs_info = S2SMI(sb);
        struct fsfilt_operations *cache_fsfilt;
        struct super_block *csb;
        int rc = 0;

	/* It should be initialized olready by smfs_read_super(). */
	if (!(cache_fsfilt = smfs_info->sm_cache_fsfilt))
    		cache_fsfilt = fsfilt_get_ops(smfs_info->cache_fs_type);

        if (!cache_fsfilt)
                RETURN(-ENOENT);
        
        csb = S2CSB(sb);

        if (cache_fsfilt->fs_setup) 
                rc = cache_fsfilt->fs_setup(csb);
        
        RETURN(rc);
}

static int fsfilt_smfs_set_xattr(struct inode *inode, void *handle,
                                 char *name,  void *buffer, 
                                 int buffer_size)
{
        struct  fsfilt_operations *cache_fsfilt = I2FOPS(inode);
        struct  inode *cache_inode = NULL;
        int     rc = -EIO;
         
        if (!cache_fsfilt)
                RETURN(rc);
        
        cache_inode = I2CI(inode);
        if (!cache_inode)
                RETURN(rc);
        
        pre_smfs_inode(inode, cache_inode); 
       
        if (cache_fsfilt->fs_set_xattr) 
                rc = cache_fsfilt->fs_set_xattr(cache_inode, handle, name, 
                                                buffer, buffer_size);
        post_smfs_inode(inode, cache_inode); 
        
        RETURN(rc);
}

static int fsfilt_smfs_get_xattr(struct inode *inode, char *name,
                                 void *buffer, int buffer_size)
{
        struct fsfilt_operations *cache_fsfilt = I2FOPS(inode);
        struct inode *cache_inode = NULL;
        int    rc = -EIO;

         if (!cache_fsfilt)
                RETURN(rc);
        
        cache_inode = I2CI(inode);
        if (!cache_inode)
                RETURN(rc);
        
        pre_smfs_inode(inode, cache_inode); 
       
        if (cache_fsfilt->fs_get_xattr) 
                rc = cache_fsfilt->fs_get_xattr(cache_inode, name, 
                                                buffer, buffer_size);
        post_smfs_inode(inode, cache_inode); 
        
        RETURN(rc);
}

static struct fsfilt_operations fsfilt_smfs_ops = {
        .fs_type                = "smfs",
        .fs_owner               = THIS_MODULE,
        .fs_start               = fsfilt_smfs_start,
        .fs_brw_start           = fsfilt_smfs_brw_start,
        .fs_commit              = fsfilt_smfs_commit,
        .fs_commit_async        = fsfilt_smfs_commit_async,
        .fs_commit_wait         = fsfilt_smfs_commit_wait,
        .fs_setattr             = fsfilt_smfs_setattr,
        .fs_iocontrol           = fsfilt_smfs_iocontrol,
        .fs_set_md              = fsfilt_smfs_set_md,
        .fs_get_md              = fsfilt_smfs_get_md,
        .fs_readpage            = fsfilt_smfs_readpage,
        .fs_getpage             = fsfilt_smfs_getpage,
        .fs_add_journal_cb      = fsfilt_smfs_add_journal_cb,
        .fs_statfs              = fsfilt_smfs_statfs,
        .fs_sync                = fsfilt_smfs_sync,
        .fs_map_inode_pages     = fsfilt_smfs_map_inode_pages,
        .fs_prep_san_write      = fsfilt_smfs_prep_san_write,
        .fs_write_record        = fsfilt_smfs_write_record,
        .fs_read_record         = fsfilt_smfs_read_record,
        .fs_setup               = fsfilt_smfs_setup,
        .fs_send_bio            = fsfilt_smfs_send_bio,
        .fs_set_xattr           = fsfilt_smfs_set_xattr,
        .fs_get_xattr           = fsfilt_smfs_get_xattr,
        
        /* FIXME-UMKA: probably fsfilt_smfs_get_op_len() should be put here
         * too. */
};

static int __init fsfilt_smfs_init(void)
{
        int rc;
        
        rc = fsfilt_register_ops(&fsfilt_smfs_ops);
        return rc;
}

static void __exit fsfilt_smfs_exit(void)
{
        fsfilt_unregister_ops(&fsfilt_smfs_ops);
}

module_init(fsfilt_smfs_init);
module_exit(fsfilt_smfs_exit);

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre SMFS Filesystem Helper v0.1");
MODULE_LICENSE("GPL");
