/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
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

#define DEBUG_SUBSYSTEM S_LLITE
#include <linux/lustre_lite.h>
#include <linux/file.h>
#include <asm/poll.h>
#include "llite_internal.h"

#define FILE_OPS 0 
#define INODE_OPS 1 

static inline struct file_operations** 
get_save_fops(struct file* filp, int mode)
{
        struct inode *inode = filp->f_dentry->d_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        if (mode == FILE_OPS){
                if (S_ISFIFO(inode->i_mode)){
                        switch (filp->f_mode) {
                        case 1: /*O_RDONLY*/
                                return &(lli->ll_save_ffop);
                        case 2: /*O_WRONLY*/
                                return &(lli->ll_save_wfop);
                        case 3: /* O_RDWR */
                                return &(lli->ll_save_wrfop);
                        default:
                                return NULL;
                        }
                }
                return &(lli->ll_save_ffop);
        } else
                return &(lli->ll_save_ifop);

}
                                          

static inline void save_fops(struct file *filp, struct inode *inode,
                             struct file_operations *sfops) 
{
        struct ll_inode_info *lli = ll_i2info(inode);
        
        if (sfops != filp->f_op) {
                struct file_operations** pfop = get_save_fops (filp, FILE_OPS);
                struct module   *save_module = NULL;

                save_module = filp->f_op->owner;
                *pfop = filp->f_op;
                if (S_ISCHR(inode->i_mode)) {
                        filp->f_op = &ll_special_chr_file_fops;
                }else if (S_ISFIFO(inode->i_mode)){
                        filp->f_op = &ll_special_fifo_file_fops;
                }
                filp->f_op->owner = save_module;
        }
}

static ssize_t ll_special_file_read(struct file *filp, char *buf, 
                                    size_t count, loff_t *ppos)
{
        struct file_operations** pfop = get_save_fops (filp, FILE_OPS);
        int    rc = -EINVAL;

        if (pfop && *pfop && (*pfop)->read) 
                rc = (*pfop)->read(filp, buf, count, ppos);
        
        RETURN(rc);
}

static ssize_t ll_special_file_write(struct file *filp, const char *buf, 
                                     size_t count, loff_t *ppos)
{
        struct file_operations** pfop = get_save_fops (filp, FILE_OPS);
        int    rc = -EINVAL;
        
        if (pfop && *pfop && (*pfop)->write) 
                rc = (*pfop)->write(filp, buf, count, ppos);
        
        RETURN(rc);
}
static int ll_special_file_ioctl(struct inode *inode, struct file *filp, 
                                 unsigned int cmd, unsigned long arg)
{
        struct file_operations** pfop = get_save_fops (filp, FILE_OPS);
        int    rc = -ENOTTY;

        if (pfop && *pfop && (*pfop)->ioctl) { 
                struct file_operations *sfops = filp->f_op;
                
                rc = (*pfop)->ioctl(inode, filp, cmd, arg);
                save_fops(filp, inode, sfops);
        }
        RETURN(rc);
}

static loff_t ll_special_file_seek(struct file *filp, loff_t offset, int origin)
{
        struct file_operations** pfop = get_save_fops (filp, FILE_OPS);
        int    rc = 0;

        if (pfop && *pfop && (*pfop)->llseek)  
                rc = (*pfop)->llseek(filp, offset, origin);
        else
                rc = default_llseek(filp, offset, origin);
       
        RETURN(rc);
}


#define DEFAULT_POLLMASK (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM)

static unsigned int
ll_special_file_poll(struct file *filp, struct poll_table_struct *poll_table) 
{
        struct file_operations** pfop = get_save_fops (filp, FILE_OPS);
        int    rc = DEFAULT_POLLMASK;

        if (pfop && *pfop && (*pfop)->poll)  
                rc = (*pfop)->poll(filp, poll_table);

        RETURN(rc);
}

static int ll_special_file_open(struct inode *inode, struct file *filp)
{
        struct file_operations** pfop = get_save_fops (filp, FILE_OPS);
        int rc = -EINVAL;

        if (pfop && *pfop && (*pfop)->open)  
                rc = (*pfop)->open(inode, filp);
        
        RETURN(rc);
}

static ssize_t ll_special_read(struct file *filp, char *buf, 
                               size_t count, loff_t *ppos)
{
        struct file_operations** pfop = get_save_fops (filp, INODE_OPS);
        int    rc = -EINVAL;

        if (pfop && *pfop && (*pfop)->read)  
                rc = (*pfop)->read(filp, buf, count, ppos);
        
        RETURN(rc);
}

static ssize_t ll_special_write(struct file *filp, const char *buf, 
                                size_t count, loff_t *ppos)
{
        struct file_operations** pfop = get_save_fops (filp, INODE_OPS);
        int    rc = -EINVAL;

        if (pfop && *pfop && (*pfop)->write)  
                rc = (*pfop)->write(filp, buf, count, ppos);
        
        RETURN(rc);
}

static int ll_special_ioctl(struct inode *inode, struct file *filp, 
                            unsigned int cmd, unsigned long arg)
{
        struct file_operations** pfop = get_save_fops (filp, INODE_OPS);
        int    rc = -ENOTTY;

        if (pfop && *pfop && (*pfop)->ioctl) { 
                struct file_operations *sfops = filp->f_op;
                
                rc = (*pfop)->ioctl(inode, filp, cmd, arg);
                /* sometimes, file_operations will be changed in ioctl */
                save_fops(filp, inode, sfops);
        }

        RETURN(rc);
}

static int ll_special_mmap(struct file * filp, struct vm_area_struct * vma)
{
        struct file_operations** pfop = get_save_fops (filp, INODE_OPS);
        int    rc = -ENODEV;

        if (pfop && *pfop && (*pfop)->mmap)  
                rc = (*pfop)->mmap(filp, vma);
        
        RETURN(rc);
}

static loff_t ll_special_seek(struct file *filp, loff_t offset, int origin)
{
        struct file_operations** pfop = get_save_fops (filp, INODE_OPS);
        int    rc = 0;

        if (pfop && *pfop && (*pfop)->llseek)  
                rc = (*pfop)->llseek(filp, offset, origin);
        else
                rc = default_llseek(filp, offset, origin);
       
        RETURN(rc);
}

static int ll_special_fsync(struct file *filp, struct dentry *dentry, int data)
{
        struct file_operations** pfop = get_save_fops (filp, INODE_OPS);
        int    rc = -EINVAL;

        if (pfop && *pfop && (*pfop)->fsync)  
                rc = (*pfop)->fsync(filp, dentry, data);

        RETURN(rc);
}

static int ll_special_file_fasync(int fd, struct file *filp, int on)
{
        struct file_operations** pfop = get_save_fops (filp, FILE_OPS);
        int    rc = -EINVAL;

        if (pfop && *pfop && (*pfop)->fasync)  
                rc = (*pfop)->fasync(fd, filp, on);

        RETURN(rc);
}

static int ll_special_open(struct inode *inode, struct file *filp)
{
        struct ptlrpc_request *req;
        struct file_operations** pfop = get_save_fops (filp, INODE_OPS);
        struct lookup_intent *it;
        int rc = -EINVAL;
        ENTRY;
        
        if (pfop && *pfop && (*pfop)->open) { 
                struct file_operations *sfops = filp->f_op;
                
                rc = (*pfop)->open(inode, filp);
                 /* sometimes the file_operations will be changed in open */
                save_fops(filp, inode, sfops);
        }
        
        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_OPEN);
        
        it = filp->f_it;
        
        rc = ll_local_open(filp, it);
        if (rc)
                RETURN(rc);
        req = it->d.lustre.it_data;
        if (req)
                ptlrpc_req_finished(req);
        
        RETURN(rc);
}

static int ll_special_release(struct inode *inode, struct file *filp)
{
       struct ll_sb_info *sbi = ll_i2sbi(inode);
       struct file_operations** pfop = get_save_fops (filp, INODE_OPS);
       int rc = 0, rc2 = 0;
       ENTRY;

        if (pfop && *pfop && (*pfop)->release) { 
                rc = (*pfop)->release(inode, filp);
        }
        lprocfs_counter_incr(sbi->ll_stats, LPROC_LL_RELEASE);
                
        rc2 = ll_mdc_close(sbi->ll_mdc_exp, inode, filp);
                
        if (rc2 && !rc)
                rc = rc2;
        
        RETURN(rc);
}

static int ll_special_file_release(struct inode *inode, struct file *filp)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct file_operations** pfop = get_save_fops (filp, FILE_OPS);
        int rc = 0, rc2 = 0;
        ENTRY;

        if (pfop && *pfop && (*pfop)->release) { 
                rc = (*pfop)->release(inode, filp);
        }
        lprocfs_counter_incr(sbi->ll_stats, LPROC_LL_RELEASE);
                
        rc2 = ll_mdc_close(sbi->ll_mdc_exp, inode, filp);
                
        if (rc2 && !rc)
               rc = rc2;

        RETURN(rc);

}

struct inode_operations ll_special_inode_operations = {
        setattr_raw:    ll_setattr_raw,
        setattr:        ll_setattr,
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        getattr_it:     ll_getattr,
#else
        revalidate_it:  ll_inode_revalidate_it,
#endif
};

struct file_operations ll_special_chr_inode_fops = {
       open:           ll_special_open,
};

struct file_operations ll_special_blk_inode_fops = {
        read:           ll_special_read,
        write:          ll_special_write,
        ioctl:          ll_special_ioctl,
        open:           ll_special_open,
        release:        ll_special_release,
        mmap:           ll_special_mmap,
        llseek:         ll_special_seek,
        fsync:          ll_special_fsync,
};

struct file_operations ll_special_fifo_inode_fops = {
        open:           ll_special_open,      
};

struct file_operations ll_special_sock_inode_fops = {
        open:           ll_special_open
};

struct file_operations ll_special_chr_file_fops = {
	llseek:		ll_special_file_seek,
	read:		ll_special_file_read,
	write:		ll_special_file_write,
	poll:		ll_special_file_poll,
	ioctl:		ll_special_file_ioctl,
	open:		ll_special_file_open,
	release:	ll_special_file_release,
	fasync:		ll_special_file_fasync,
};

struct file_operations ll_special_fifo_file_fops = {
	llseek:		ll_special_file_seek,
	read:		ll_special_file_read,
	write:		ll_special_file_write,
	poll:		ll_special_file_poll,
	ioctl:		ll_special_file_ioctl,
	open:		ll_special_file_open,
	release:	ll_special_file_release,
};

