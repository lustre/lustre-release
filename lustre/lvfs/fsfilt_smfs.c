/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/lib/fsfilt_smfs.c
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
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

#include <linux/lustre_snap.h>
#include <linux/lustre_smfs.h>
static void *fsfilt_smfs_start(struct inode *inode, int op,
                               void *desc_private, int logs)
{
        void *handle;
        struct inode *cache_inode = I2CI(inode);
        struct fsfilt_operations *cache_fsfilt = I2FOPS(inode);

        if (cache_fsfilt == NULL)
                return NULL;

        SMFS_TRANS_OP(inode, op);

        if (!cache_fsfilt->fs_start)
                return ERR_PTR(-ENOSYS);

        handle = cache_fsfilt->fs_start(cache_inode, op, desc_private, logs);
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

        rc = cache_fsfilt->fs_brw_start(objcount, &cache_fso, niocount, nb,
                                        desc_private, logs);
exit:
        post_smfs_dentry(cache_dentry);
        return rc;
}

/* FIXME-WANGDI: here we can easily have inode == NULL due to
   mds_open() behavior. It passes NULL inode to mds_finish_transno()
   sometimes. Probably we should have spare way to get cache fsfilt
   operations. */
static int fsfilt_smfs_commit(struct super_block *sb, struct inode *inode, 
                              void *h, int force_sync)
{
        struct fsfilt_operations *cache_fsfilt = S2SMI(sb)->sm_cache_fsfilt;
        struct super_block *csb = S2CSB(sb); 
        struct inode *cache_inode = NULL;
        int    rc = -EIO;

        if (inode)
                cache_inode = I2CI(inode);

        if (cache_fsfilt == NULL)
                RETURN(rc);

        if (!cache_fsfilt->fs_commit)
                RETURN(-ENOSYS);

        rc = cache_fsfilt->fs_commit(csb, cache_inode, h, force_sync);

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

        rc = cache_fsfilt->fs_setattr(cache_dentry, handle, iattr, do_trunc);

        post_smfs_inode(dentry->d_inode, cache_inode);

        if (rc == 0) {
                struct super_block *sb = dentry->d_inode->i_sb;

                if (SMFS_DO_REC(S2SMI(sb)) && 
                    SMFS_DO_INODE_REC(dentry->d_inode)) {
                        rc = smfs_rec_setattr(dentry->d_inode, dentry, iattr);
                }
        }
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
                rc = cache_fsfilt->fs_iocontrol(cache_inode, sfi->c_file, cmd,
                                                arg);
        } else {
                rc = cache_fsfilt->fs_iocontrol(cache_inode, NULL, cmd, arg);
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
        rc = cache_fsfilt->fs_set_md(cache_inode, handle, lmm, lmm_size);
        up(&cache_inode->i_sem);

        post_smfs_inode(inode, cache_inode);

        smfs_rec_md(inode, lmm, lmm_size);

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
        rc = cache_fsfilt->fs_get_md(cache_inode, lmm, lmm_size);
        up(&cache_inode->i_sem);

        post_smfs_inode(inode, cache_inode);

        RETURN(rc);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
static int fsfilt_smfs_send_bio(struct inode *inode, struct bio *bio)
#else
static int fsfilt_smfs_send_bio(struct inode *inode, struct kiobuf *bio)
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

        return cache_fsfilt->fs_send_bio(cache_inode, bio);
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

        if (off != &(file->f_pos))
                cache_ppos = &tmp_ppos;
        else
                cache_ppos = &sfi->c_file->f_pos;
        *cache_ppos = *off;

        pre_smfs_inode(file->f_dentry->d_inode, cache_inode);

        if (cache_fsfilt->fs_readpage)
                rc = cache_fsfilt->fs_readpage(sfi->c_file, buf, count,
                                               cache_ppos);

        *off = *cache_ppos;
        post_smfs_inode(file->f_dentry->d_inode, cache_inode);
        duplicate_file(file, sfi->c_file);

        RETURN(rc);
}


static int fsfilt_smfs_add_journal_cb(struct obd_device *obd,
                                      struct super_block *sb, __u64 last_rcvd,
                                      void *handle, fsfilt_cb_t cb_func,
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

        if (!cache_fsfilt)
                RETURN(-EINVAL);

        if (!cache_fsfilt->fs_sync)
                RETURN(-ENOSYS);

        rc = cache_fsfilt->fs_sync(csb);

        RETURN(rc);
}

int fsfilt_smfs_map_inode_pages(struct inode *inode, struct page **page,
                                int pages, unsigned long *blocks, int *created,
                                int create, struct semaphore *sem)
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
                                              created, create, sem);
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
        rc = cache_fsfilt->fs_prep_san_write(cache_inode, blocks, nblocks,
                                             newsize);
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

        if (offs != &(file->f_pos))
                cache_ppos = &tmp_ppos;
        else
                cache_ppos = &sfi->c_file->f_pos;
        *cache_ppos = *offs;

        pre_smfs_inode(file->f_dentry->d_inode, cache_inode);

        if (!cache_fsfilt->fs_read_record)
                RETURN(-ENOSYS);

        rc = cache_fsfilt->fs_read_record(sfi->c_file, buf, size, cache_ppos);

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
        if (sfi->magic != SMFS_FILE_MAGIC)
                BUG();

        if (offs != &(file->f_pos))
                cache_ppos = &tmp_ppos;
        else
                cache_ppos = &sfi->c_file->f_pos;
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

static int fsfilt_smfs_post_setup(struct obd_device *obd, struct vfsmount *mnt)
{
        struct super_block *sb = NULL;
        int rc = 0;

        if (mnt) {
                sb = mnt->mnt_sb;
                S2SMI(sb)->smsi_exp = obd->obd_self_export;
                smfs_post_setup(sb, mnt);
                if (SMFS_DO_REC(S2SMI(sb)))
                        rc = smfs_start_rec(sb, mnt);
#if CONFIG_SNAPFS
                if (SMFS_DO_COW(S2SMI(sb)))
                        rc = smfs_start_cow(sb);
#endif
                if (rc)
                        GOTO(exit, rc);
                if (obd)
                        obd->obd_llog_ctxt[LLOG_REINT_ORIG_CTXT] =
                                        S2SMI(sb)->smsi_rec_log;
        }
exit:
        if (rc)
                CERROR("can not do post setup in obd %p rc=%d", obd, rc);

        RETURN(rc);
}

static int fsfilt_smfs_post_cleanup(struct obd_device *obd,
                                    struct vfsmount *mnt)
{
        struct super_block *sb = NULL;
        int rc = 0;
        ENTRY;
        
        if (mnt) {
                sb = mnt->mnt_sb;
                if (SMFS_DO_REC(S2SMI(sb)))
                        rc = smfs_stop_rec(sb);
#if CONFIG_SNAPFS
                if (SMFS_DO_COW(S2SMI(sb)))
                        rc = smfs_stop_cow(sb);
#endif
                smfs_post_cleanup(sb);
        }
        RETURN(rc);
}

static int fsfilt_smfs_set_fs_flags(struct inode *inode, int flags)
{
        int rc = 0;
        ENTRY;

        if (SMFS_DO_REC(S2SMI(inode->i_sb)) && (flags & SM_DO_REC))
                SMFS_SET_INODE_REC(inode);
        if (SMFS_DO_COW(S2SMI(inode->i_sb)) && (flags & SM_DO_COW))
                SMFS_SET_INODE_COW(inode);
        RETURN(rc);
}

static int fsfilt_smfs_clear_fs_flags(struct inode *inode, int flags)
{
        int rc = 0;
        ENTRY;
        
        if (SMFS_DO_REC(S2SMI(inode->i_sb)) && (flags & SM_DO_REC))
                SMFS_CLEAN_INODE_REC(inode);
        if (SMFS_DO_COW(S2SMI(inode->i_sb)) && (flags & SM_DO_COW))
                SMFS_CLEAN_INODE_COW(inode);
        RETURN(rc);
}

static int fsfilt_smfs_get_fs_flags(struct dentry *de)
{
        struct inode *inode = de->d_inode;
        int flags = 0;
        ENTRY;

        LASSERT(inode);

        if (SMFS_DO_REC(S2SMI(inode->i_sb)) && SMFS_DO_INODE_REC(inode))
                flags |= SM_DO_REC;
        if (SMFS_DO_COW(S2SMI(inode->i_sb)) && SMFS_DO_INODE_COW(inode))
                flags |= SM_DO_COW;
       
        RETURN(flags); 
}
static int fsfilt_smfs_set_ost_flags(struct super_block *sb)
{
        int rc = 0;
        SET_REC_PACK_TYPE_INDEX(S2SMI(sb)->smsi_flags, PACK_OST);
        RETURN(rc);
}

static int fsfilt_smfs_set_mds_flags(struct super_block *sb)
{
        int rc = 0;
        SET_REC_PACK_TYPE_INDEX(S2SMI(sb)->smsi_flags, PACK_MDS);
        RETURN(rc);
}

static int fsfilt_smfs_get_reint_log_ctxt(struct super_block *sb,
                                          struct llog_ctxt **ctxt)
{
        struct smfs_super_info *smfs_info = S2SMI(sb);
        int rc = 0;

        *ctxt = smfs_info->smsi_rec_log;
        RETURN(rc);
}

static int fsfilt_smfs_setup(struct obd_device *obd, struct super_block *sb)
{
        struct smfs_super_info *smfs_info = S2SMI(sb);
        struct fsfilt_operations *cache_fsfilt;
        struct super_block *csb;
        int rc = 0;

        /* It should be initialized olready by smfs_read_super(). */
        if (!(cache_fsfilt = smfs_info->sm_cache_fsfilt))
                    cache_fsfilt = fsfilt_get_ops(smfs_info->smsi_cache_ftype);

        if (!cache_fsfilt)
                RETURN(-ENOENT);

        csb = S2CSB(sb);
        if (cache_fsfilt->fs_setup) 
                rc = cache_fsfilt->fs_setup(obd, csb);
        
        duplicate_sb(sb, csb);
        
        RETURN(rc);
}

static int fsfilt_smfs_set_xattr(struct inode *inode, void *handle, char *name,
                                 void *buffer, int buffer_size)
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

static int fsfilt_smfs_insert_extents_ea(struct inode *inode,
                                         unsigned long from, unsigned long num)
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

        if (cache_fsfilt->fs_insert_extents_ea)
                rc = cache_fsfilt->fs_insert_extents_ea(cache_inode, from, num);

        post_smfs_inode(inode, cache_inode);
        return rc;
}

static int fsfilt_smfs_remove_extents_ea(struct inode *inode,
                                         unsigned long from, unsigned long num)
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

        if (cache_fsfilt->fs_remove_extents_ea)
                rc = cache_fsfilt->fs_remove_extents_ea(cache_inode, from, num);

        post_smfs_inode(inode, cache_inode);
        return rc;
}

static int fsfilt_smfs_init_extents_ea(struct inode *inode)
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

        if (cache_fsfilt->fs_init_extents_ea)
                rc = cache_fsfilt->fs_init_extents_ea(cache_inode);

        post_smfs_inode(inode, cache_inode);
        return rc;
}

static int fsfilt_smfs_free_extents(struct super_block *sb, ino_t ino,
                                    char *pbuf, int size)
{
        OBD_FREE(pbuf, size * (sizeof(struct ldlm_extent)));
        return 0;
}

static int fsfilt_smfs_write_extents(struct dentry *dentry,
                                     unsigned long from, unsigned long num)
{
        int rc = 0;

        if (SMFS_DO_REC(S2SMI(dentry->d_inode->i_sb)))
                rc = smfs_write_extents(dentry->d_inode, dentry, from, num);

        return rc;
}

static int fsfilt_smfs_precreate_rec(struct dentry *dentry, int *count, 
                                     struct obdo *oa)
{
        int rc = 0;

        if (SMFS_DO_REC(S2SMI(dentry->d_inode->i_sb)))
                rc = smfs_rec_precreate(dentry, count, oa);

        return rc;
}

static int fsfilt_smfs_get_ino_write_extents(struct super_block *sb, ino_t ino,
                                             char **pbuf, int *size)
{
        struct fs_extent *fs_extents;
        struct ldlm_extent *extents = NULL;
        struct inode *inode;
        struct inode *cache_inode;
        struct fsfilt_operations *cache_fsfilt = NULL;
        struct lvfs_run_ctxt saved;
        int    rc = 0, fs_ex_size, ex_num, flags;
        char   *buf = NULL, *ex_buf = NULL;

        push_ctxt(&saved, S2SMI(sb)->smsi_ctxt, NULL);

        inode = iget(sb, ino);

        if (!inode || is_bad_inode(inode)) {
                CWARN("Can not get inode %lu ino\n", ino);
                GOTO(out, rc = 0);
        }
        cache_inode = I2CI(inode);
        cache_fsfilt = I2FOPS(inode);

        rc = cache_fsfilt->fs_get_xattr(cache_inode, REINT_EXTENTS_FLAGS,
                                        &flags, sizeof(int));
        if (!(flags & SMFS_OVER_WRITE) && !(flags & SMFS_DIRTY_WRITE)) {
                GOTO(out, rc = 0);
        } else if (flags & SMFS_OVER_WRITE) {
                *size = 1;
                OBD_ALLOC(ex_buf, sizeof(struct ldlm_extent));
                if (!ex_buf)
                        GOTO(out, rc=-ENOMEM);
                extents = (struct ldlm_extent*)(ex_buf);
                extents->start = 0;
                extents->end = 0xffffffff;
        }
        if (rc < 0)
                GOTO(out, rc);
        rc = cache_fsfilt->fs_get_write_extents_num(cache_inode, &fs_ex_size);
        if (rc)
                GOTO(out, rc);
        OBD_ALLOC(buf, fs_ex_size);
        if (!buf)
                GOTO(out, rc=-ENOMEM);

        rc = cache_fsfilt->fs_get_inode_write_extents(cache_inode, &buf,
                                                      &fs_ex_size);
        if (rc < 0)
                GOTO(out, rc);
        rc = 0;
        ex_num = fs_ex_size / sizeof(struct fs_extent);
        *size =  ex_num;
        OBD_ALLOC(ex_buf, ex_num* sizeof(struct ldlm_extent));
        if (!ex_buf)
                GOTO(out, rc=-ENOMEM);

        fs_extents = (struct fs_extent*)(buf);
        extents = (struct ldlm_extent*)(ex_buf);
        while (ex_num > 0) {
                int blk_size = I2CI(inode)->i_blksize;

                extents->start = fs_extents->e_block * blk_size;
                extents->end = extents->start + fs_extents->e_num * blk_size;
                fs_extents++;
                extents++;
                ex_num--;
        }
        *pbuf = ex_buf;
out:
        iput(inode);
        if (buf)
                OBD_FREE(buf, fs_ex_size);
        if (rc && extents)
                OBD_FREE(ex_buf, (*size) * (sizeof(struct ldlm_extent)));
        pop_ctxt(&saved, S2SMI(sb)->smsi_ctxt, NULL);
        return rc;
}

static int fsfilt_smfs_set_snap_item(struct super_block *sb, char *name)
{
        int rc = 0;

        ENTRY;
#if CONFIG_SNAPFS
        rc = smfs_add_snap_item(sb, name);
#endif
        RETURN(rc);        
}
static int fsfilt_smfs_do_write_cow(struct dentry *de, void *extents,
                                    int num_extents)
{
        int rc = 0;
#if CONFIG_SNAPFS
        struct write_extents *w_ext = (struct write_extents *)extents;
        int i = 0;
        ENTRY;
        for (i = 0; i < num_extents; i++) {
               size_t count = w_ext->w_count;
               loff_t off = w_ext->w_pos;
               rc = smfs_cow_write(de->d_inode, de, &count, &off);
               if (rc)
                        RETURN(rc);  
               w_ext ++;
        }
#endif
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
        .fs_post_setup          = fsfilt_smfs_post_setup,
        .fs_post_cleanup        = fsfilt_smfs_post_cleanup,
        .fs_set_fs_flags       = fsfilt_smfs_set_fs_flags,
        .fs_clear_fs_flags     = fsfilt_smfs_clear_fs_flags,
        .fs_get_fs_flags       = fsfilt_smfs_get_fs_flags,
        .fs_set_ost_flags       = fsfilt_smfs_set_ost_flags,
        .fs_set_mds_flags       = fsfilt_smfs_set_mds_flags,
        .fs_precreate_rec       = fsfilt_smfs_precreate_rec,
        .fs_get_reint_log_ctxt  = fsfilt_smfs_get_reint_log_ctxt,
        .fs_send_bio            = fsfilt_smfs_send_bio,
        .fs_set_xattr           = fsfilt_smfs_set_xattr,
        .fs_get_xattr           = fsfilt_smfs_get_xattr,
        .fs_init_extents_ea     = fsfilt_smfs_init_extents_ea,
        .fs_insert_extents_ea   = fsfilt_smfs_insert_extents_ea,
        .fs_remove_extents_ea   = fsfilt_smfs_remove_extents_ea,
        .fs_get_ino_write_extents = fsfilt_smfs_get_ino_write_extents,
        .fs_free_write_extents  = fsfilt_smfs_free_extents,
        .fs_write_extents       = fsfilt_smfs_write_extents,
        .fs_set_snap_item       = fsfilt_smfs_set_snap_item,
        .fs_do_write_cow        = fsfilt_smfs_do_write_cow,
        /* FIXME-UMKA: probably fsfilt_smfs_get_op_len() should be
         * put here too. */
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
