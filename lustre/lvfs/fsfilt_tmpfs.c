/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/lib/fsfilt_tmpfs.c
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2002, 2003, 2004 Cluster File Systems, Inc.
 *   Author: Yury Umanets <umka@clusterfs.com>
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
#include <linux/ext3_fs.h>
#include <linux/ext3_jbd.h>
#include <linux/version.h>
#include <linux/kp30.h>
#include <linux/lustre_fsfilt.h>
#include <linux/obd.h>
#include <linux/obd_class.h>
#include <linux/module.h>
#include <linux/shmem_fs.h>

/* prefix is needed because tmpfs xattr patch deos not support namespaces
 * yet. */
#define XATTR_LUSTRE_MDS_LOV_EA         "trusted.lov"
#define XATTR_LUSTRE_MDS_OBJID          "system.lustre_mds_objid"

/* structure instance of to be returned as a transaction handle. This is not
 * needed for now, but probably we will need to save something during modifying
 * an inode and this is useful for us. */
struct tmpfs_trans {
        int op;
};

static kmem_cache_t *trans_cache;
static atomic_t trans_count = ATOMIC_INIT(0);

/* ext2 directory stuff. It is needed for fs_readpage(), which is used for
 * reading directoris on MDS. Probably this should be moved to somewhere more
 * convenient? */
#define EXT2_NAME_LEN (255)

struct ext2_dirent {
        __u32   inode;
        __u16   rec_len;
        __u8    name_len;
        __u8    file_type;
        char    name[0];
};

typedef struct ext2_dirent ext2_dirent_t;

struct fetch_hint {
	int stop;
        int count;
	__u16 chunk;
	void *dirent;
        __u16 rec_len;
	struct file *file;
};

typedef struct fetch_hint fetch_hint_t;

#define EXT2_ENT_PAD       4
#define EXT2_ENT_ROUND     (EXT2_ENT_PAD - 1)
#define EXT2_ENT_LEN(len)  (((len) + 8 + EXT2_ENT_ROUND) & ~EXT2_ENT_ROUND)

/* starts new transaction on tmpfs for metadata operations. That if for create
 * file, delete it, etc. That is everything except of read/write data. Returns
 * pointer to transaction handle to be used later. What we have to do here? 
 * Seems nothing for a while. */
static void *
fsfilt_tmpfs_mtd_start(struct inode *inode, int op, void *desc_private)
{
        int rc;
        struct kstatfs sfs;
        struct tmpfs_trans *trans;

        CDEBUG(D_INFO, "Metadata operation 0x%x is started on "
               "inode 0x%lx\n", op, inode->i_ino);

        if ((rc = vfs_statfs(inode->i_sb, &sfs)))
                return ERR_PTR(rc);

        if (sfs.f_bfree == 0)
                return ERR_PTR(-ENOSPC);
        
        OBD_SLAB_ALLOC(trans, trans_cache, GFP_NOFS,
                       sizeof(*trans));

        if (trans == NULL)
                return NULL;

        atomic_inc(&trans_count);

        trans->op = op;
        return trans;
}

/* commits changes on passed @inode using passed transaction @handle. Should we
 * do something here? */
static int
fsfilt_tmpfs_mtd_commit(struct inode *inode, void *handle, int force_sync)
{
        struct tmpfs_trans *trans;

        trans = (struct tmpfs_trans *)handle;

        OBD_SLAB_FREE(trans, trans_cache, sizeof(*trans));
        atomic_dec(&trans_count);

        CDEBUG(D_INFO, "Metadata operation 0x%x is "
               "finished on inode 0x%lx\n", trans->op,
               inode->i_ino);

        return 0;
}

/* starts new transaction for read/write operations. Seems, that here we do
 * nothing also. */
static void *
fsfilt_tmpfs_io_start(int objcount, struct fsfilt_objinfo *fso,
                      int niocount, struct niobuf_local *nb,
                      void *desc_private)
{
        int rc;
        struct kstatfs sfs;
        struct tmpfs_trans *trans;

        ENTRY;

        CDEBUG(D_INFO, "IO operation is started on inode 0x%lx\n",
               fso->fso_dentry->d_inode->i_ino);

        /* check if we still have free space on filesystem. */
        if ((rc = vfs_statfs(fso->fso_dentry->d_inode->i_sb, &sfs)))
                RETURN(ERR_PTR(rc));

        if (sfs.f_bfree == 0)
                RETURN(ERR_PTR(-ENOSPC));
        
        OBD_SLAB_ALLOC(trans, trans_cache, GFP_NOFS,
                       sizeof(*trans));

        if (trans == NULL)
                RETURN(NULL);

        atomic_inc(&trans_count);

        trans->op = 0;
        RETURN(trans);
}

/* commits changes on passed @inode using passed transaction @handle. This is
 * called from direct_io() with handle obtained from brw_start(). */
static int
fsfilt_tmpfs_io_commit(struct inode *inode, void *handle, void **wh)
{
        struct tmpfs_trans *trans;

        trans = (struct tmpfs_trans *)handle;

        OBD_SLAB_FREE(trans, trans_cache, sizeof(*trans));
        atomic_dec(&trans_count);

        CDEBUG(D_INFO, "IO operation is finished on inode "
               "0x%lx\n", inode->i_ino);

        /* wait handle is not used. */
        *wh = NULL;

        return 0;
}

/* waits for transaction started by io_commit() to be finished on passed wait
 * handle. What should we do here? Nothing so far. */
static int
fsfilt_tmpfs_commit_wait(struct inode *inode, void *wh)
{
        CDEBUG(D_INFO, "commit wait is called\n");
        return 0;
}

/* implements additional ioctl fucntions. Nothing do here. */
static int
fsfilt_tmpfs_iocontrol(struct inode * inode, struct file *file,
                       unsigned int cmd, unsigned long arg)
{
        int rc = -ENOTTY;
        
        ENTRY;

        if (inode->i_fop->ioctl)
                rc = inode->i_fop->ioctl(inode, file, cmd, arg);

        RETURN(rc);
}

/* fills @osfs by statfs info for tmpfs. Should we do some correcting 
   here? Probably later. */
static int
fsfilt_tmpfs_statfs(struct super_block *sb, struct obd_statfs *osfs)
{
        int rc;
        struct kstatfs sfs;

        if (!sb->s_op->statfs)
                return -ENOSYS;

        memset(&sfs, 0, sizeof(sfs));

        /* trying to be consistent with other parts of tmpfs filter and call
         * sb->s_op->statfs() instead of using vfs_statfs(). */
        lock_kernel();
        rc = sb->s_op->statfs(sb, &sfs);
        unlock_kernel();

        if (rc == 0)
                statfs_pack(osfs, &sfs);

        return rc;
}

/* make sure, that all dirty buffers are stored onto device. This is nothing to
 * do for tmpfs in principle, but we will not aim to be smarter than tmpfs is
 * and call sb->s_op->sync_fs() is any. */
static int
fsfilt_tmpfs_sync(struct super_block *sb)
{
        if (sb->s_op->sync_fs)
                return sb->s_op->sync_fs(sb);
        
        return 0;
}

/* uses inode setattr method if any, or does default actions otherwise. */
static int fsfilt_tmpfs_setattr(struct dentry *dentry, void *handle,
                                struct iattr *iattr, int do_trunc)
{
        int rc;
        struct inode *inode = dentry->d_inode;

        lock_kernel();

        /* preventing vmtruncate() to be called on inode_setattr(). */
        if (iattr->ia_valid & ATTR_SIZE && !do_trunc) {
                iattr->ia_valid &= ~ATTR_SIZE;
                inode->i_size = iattr->ia_size;
        }

        iattr->ia_mode = (inode->i_mode & S_IFMT) |
                (iattr->ia_mode & ~S_IFMT);

        iattr->ia_valid &= ~(ATTR_MTIME_SET | ATTR_ATIME_SET);

        if (inode->i_op->setattr) {
                rc = inode->i_op->setattr(dentry, iattr);
        } else {
                if (!(rc = inode_change_ok(inode, iattr)))
                        rc = inode_setattr(inode, iattr);
        }

        unlock_kernel();

        return rc;
}

/* nothing to do here. */
static int
fsfilt_tmpfs_setup(struct super_block *sb)
{
        return 0;
}

/* sets lmm into inode xattrs using passed transaction @handle. */
static int
fsfilt_tmpfs_set_md(struct inode *inode, void *handle,
                    void *lmm, int lmm_size)
{
        int rc;

        lock_kernel();

        rc = shmem_xattr_set(inode, XATTR_LUSTRE_MDS_LOV_EA,
                             lmm, lmm_size, 0);

        unlock_kernel();

        if (rc) {
                CERROR("error adding MD data to inode %lu: rc = %d\n",
                       inode->i_ino, rc);
        }
        
        return rc;
}

/* gets lmm from inode xattrs. */
static int
fsfilt_tmpfs_get_md(struct inode *inode, void *lmm,
                    int lmm_size)
{
        int rc;

        LASSERT(down_trylock(&inode->i_sem) != 0);

        lock_kernel();

	/* getting new key first. */
        rc = shmem_xattr_get(inode, XATTR_LUSTRE_MDS_LOV_EA,
                             lmm, lmm_size);

	/* check for old one. */
        if (rc == -ENODATA) {
                rc = shmem_xattr_get(inode, XATTR_LUSTRE_MDS_OBJID,
                                     lmm, lmm_size);
        }

        unlock_kernel();

        if (lmm == NULL)
                return (rc == -ENODATA) ? 0 : rc;

        if (rc < 0) {
                CDEBUG(D_INFO, "error getting EA %s from inode %lu: rc = %d\n",
                       XATTR_LUSTRE_MDS_OBJID, inode->i_ino, rc);
                
                memset(lmm, 0, lmm_size);
                return (rc == -ENODATA) ? 0 : rc;
        }

        return rc;
}

/* reads data from passed @file to @buf. */
static ssize_t
fsfilt_tmpfs_read(struct file *file, char *buf,
                  size_t count, loff_t *off)
{
        struct inode *inode = file->f_dentry->d_inode;

        if (!S_ISREG(inode->i_mode))
                return -EINVAL;
        
    	return file->f_op->read(file, buf, count, off);
}

/* writes data to regular @file. */
static ssize_t
fsfilt_tmpfs_write(struct file *file, char *buf,
                   size_t count, loff_t *off)
{
        struct inode *inode = file->f_dentry->d_inode;

        if (!S_ISREG(inode->i_mode))
                return -EINVAL;
        
        return file->f_op->write(file, buf, count, off);
}

/* puts passed page to page cache. */
static int
fsfilt_tmpfs_putpage(struct inode *inode, struct page *page,
                     int lazy_cache)
{
        struct page *shmem_page;
	struct shmem_inode_info *info = SHMEM_I(inode);

	down(&info->sem);

        /* getting page from shmem. It may be read from swap. And this is the
         * reason, why we do not just add passed @page to pacge cache. */
        shmem_page = shmem_getpage_locked(inode, page->index);
        
        if (IS_ERR(shmem_page)) {
                up(&info->sem);
                return PTR_ERR(shmem_page);
        }
        
	up(&info->sem);
        
        copy_page(kmap(shmem_page), kmap(page));
        kunmap(page); kunmap(shmem_page);

        /* taking care about possible cache aliasing. */
        if (inode->i_mapping->i_mmap_shared != NULL)
                flush_dcache_page(shmem_page);
        
        SetPageDirty(shmem_page);
        UnlockPage(shmem_page);
        page_cache_release(shmem_page);
        
        return 0;
}

/* returns inode page by its @index. */
static struct page *
fsfilt_tmpfs_getpage(struct inode *inode, long int index)
{
	struct page *page;

        page = shmem_getpage_unlocked(inode, index);
        
	if (IS_ERR(page))
                return page;

        /* taking care about possible cache aliasing. */
        if (inode->i_mapping->i_mmap_shared != NULL)
                flush_dcache_page(page);
        
	return page;
}

/* fills up passed @buf by entry data. Used from readdir(). */
static int
fillent(void *buf, const char *name, int namlen, 
        loff_t offset, ino_t ino, unsigned int d_type)
{
        __u16 rec_len;
	fetch_hint_t *hint = (fetch_hint_t *)buf;
	ext2_dirent_t *entry = hint->dirent;
	
	rec_len = EXT2_ENT_LEN(namlen);

        if ((hint->stop = (hint->chunk < rec_len)))
		return -ENOENT;

	entry->file_type = 0;

        hint->count++;
        hint->chunk -= rec_len;
        hint->rec_len = rec_len;
        hint->dirent += rec_len;

        entry->name_len = namlen;
	entry->inode = cpu_to_le32(ino);
	memcpy(entry->name, name, namlen);
	entry->rec_len = cpu_to_le16(rec_len);

	return 0;
}

/* this should be the same as in tmpfs. Should it be not hardcoded? */
#define BOGO_ENTRY_SIZE (20)

/* mostly needed for reading directory from @file on MDS. */
static ssize_t
fsfilt_tmpfs_readpage(struct file *file, char *buf,
                      size_t count, loff_t *off)
{
        int rc = 0;
        struct inode *inode = file->f_dentry->d_inode;

        if (S_ISREG(inode->i_mode)) {
    		rc = file->f_op->read(file, buf, count, off);
        } else if (S_ISDIR(inode->i_mode)) {
                int error;
		loff_t offset;
		fetch_hint_t hint;
                ext2_dirent_t *dirent;

                /* positioning to passed @off. */
		offset = *(long int *)off / BOGO_ENTRY_SIZE;
                
		if (file->f_op->llseek(file, offset, 0) != offset)
			return -ENOENT;

                /* reading @count bytesof data. */
		while (count > 0) {
                        hint.count = 0;
                        hint.file = file;
                        hint.dirent = buf;
                        hint.chunk = count;
                        hint.rec_len = count;
				
                        if ((error = vfs_readdir(file, fillent, &hint)) < 0)
                                return error;

                        /* we should have something after vfs_readdir() is
                         * finished. */
                        LASSERT(hint.count != 0);
                        
                        /* last entry should be extended up to free page
                         * size. */
                        if (hint.chunk > 0) {
                                __u16 rec_len;
                                
                                hint.dirent -= hint.rec_len;
                                dirent = (ext2_dirent_t *)hint.dirent;

                                rec_len = le16_to_cpu(dirent->rec_len);
                                dirent->rec_len = cpu_to_le16(rec_len + hint.chunk);
                        }
		
			count -= PAGE_CACHE_SIZE;
			*off += PAGE_CACHE_SIZE;
			rc += PAGE_CACHE_SIZE;
		}

                UPDATE_ATIME(inode);
        } else {
		rc = -EINVAL;
	}

        return rc;
}

static int
fsfilt_tmpfs_add_journal_cb(struct obd_device *obd, __u64 last_rcvd,
                            void *handle, fsfilt_cb_t cb_func,
                            void *cb_data)
{
        cb_func(obd, last_rcvd, cb_data, 0);
        return 0;
}

static int
fsfilt_tmpfs_prep_san_write(struct inode *inode, long *blocks,
                            int nblocks, loff_t newsize)
{
        /* we do not need block numbers and other stuff, as it will not be
         * used. */
        blocks[0] = 0;

        if (newsize > inode->i_size)
                inode->i_size = newsize;
        
        return 0;
}

/* this is used for reading configuration */
static int
fsfilt_tmpfs_read_record(struct file *file, void *buf,
                         int size, loff_t *off)
{
        int error;
	struct inode *inode = file->f_dentry->d_inode;
	
	lock_kernel();
	
	if (inode->i_size < *off + size) {
		size = inode->i_size - *off;
		unlock_kernel();
		
		if (size < 0) {
			return -EIO;
		} else if (size == 0) {
			return 0;
		}
	} else {
		unlock_kernel();
	}
        
        if ((error = fsfilt_tmpfs_read(file, buf, size, off)) < 0)
                return error;
        
        return 0;
}

/* this is used for writing configuration */
static int
fsfilt_tmpfs_write_record(struct file *file, void *buf,
                          int size, loff_t *off, int sync)
{
        int error;
        
        if ((error = fsfilt_tmpfs_write(file, buf, size, off)) < 0)
                return error;
        
        return 0;
}

static struct fsfilt_operations fsfilt_tmpfs_ops = {
        fs_type:                "tmpfs",
        fs_owner:               THIS_MODULE,
        fs_start:               fsfilt_tmpfs_mtd_start,
        fs_commit:              fsfilt_tmpfs_mtd_commit,
        fs_brw_start:           fsfilt_tmpfs_io_start,
        fs_commit_async:        fsfilt_tmpfs_io_commit,
        fs_commit_wait:         fsfilt_tmpfs_commit_wait,
        fs_iocontrol:           fsfilt_tmpfs_iocontrol,
        fs_set_md:              fsfilt_tmpfs_set_md,
        fs_get_md:              fsfilt_tmpfs_get_md,
        fs_readpage:            fsfilt_tmpfs_readpage,
        fs_getpage:             fsfilt_tmpfs_getpage,
        fs_putpage:             fsfilt_tmpfs_putpage,
        fs_add_journal_cb:      fsfilt_tmpfs_add_journal_cb,
        fs_statfs:              fsfilt_tmpfs_statfs,
        fs_sync:                fsfilt_tmpfs_sync,
        fs_prep_san_write:      fsfilt_tmpfs_prep_san_write,
        fs_write_record:        fsfilt_tmpfs_write_record,
        fs_read_record:         fsfilt_tmpfs_read_record,
	fs_setattr:             fsfilt_tmpfs_setattr,
        fs_setup:               fsfilt_tmpfs_setup,
};

static int __init
fsfilt_tmpfs_init(void)
{
        int rc;

        trans_cache = kmem_cache_create("fsfilt_tmpfs_trans",
                                        sizeof(struct tmpfs_trans),
                                        0, 0, NULL, NULL);
        if (!trans_cache) {
                CERROR("error allocating fsfilt transaction handle cache\n");
                GOTO(out, rc = -ENOMEM);
        }

        if ((rc = fsfilt_register_ops(&fsfilt_tmpfs_ops)))
                kmem_cache_destroy(trans_cache);
out:
        return rc;
}

static void __exit
fsfilt_tmpfs_exit(void)
{
        int rc;

        fsfilt_unregister_ops(&fsfilt_tmpfs_ops);
        rc = kmem_cache_destroy(trans_cache);

        if (rc || atomic_read(&trans_count)) {
                CERROR("can't free fsfilt trans cache: count %d, rc = %d\n",
                       atomic_read(&trans_count), rc);
        }
}

module_init(fsfilt_tmpfs_init);
module_exit(fsfilt_tmpfs_exit);

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre tmpfs Filesystem Helper v0.1");
MODULE_LICENSE("GPL");
