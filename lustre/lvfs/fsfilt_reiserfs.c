/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/lib/fsfilt_reiserfs.c
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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

/*
 * NOTE - According to Hans Reiser, this could actually be implemented more
 *        efficiently than creating a directory and putting ASCII objids in it.
 *        Instead, we should return the reiserfs object ID as the lustre objid
 *        (although I'm not sure what impact that would have on backup/restore).
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/version.h>
#include <linux/init.h>
#include <asm/statfs.h>
#include <libcfs/libcfs.h>
#include <lustre_fsfilt.h>
#include <obd.h>
#include <linux/module.h>
#include <linux/init.h>

/* XXX We cannot include linux/reiserfs_fs.h here, because of symbols clash,
   but we need MAX_HEIGHT definition for proper reserve calculations
#include <linux/reiserfs_fs.h>
*/
#define MAX_HEIGHT 5 /* maximal height of a tree. don't change this without
                        changing JOURNAL_PER_BALANCE_CNT */

static void *fsfilt_reiserfs_start(struct inode *inode, int op,
                                   void *desc_private, int logs)
{
        return (void *)0xf00f00be;
}

static void *fsfilt_reiserfs_brw_start(int objcount, struct fsfilt_objinfo *fso,
                                       int niocount, struct niobuf_local *nb,
                                       void *desc_private, int logs)
{
        return (void *)0xf00f00be;
}

static int fsfilt_reiserfs_commit(struct inode *inode, void *handle,
                                  int force_sync)
{
        if (handle != (void *)0xf00f00be) {
                CERROR("bad handle %p", handle);
                return -EINVAL;
        }

        return 0;
}

static int fsfilt_reiserfs_setattr(struct dentry *dentry, void *handle,
                               struct iattr *iattr, int do_trunc)
{
        struct inode *inode = dentry->d_inode;
        int rc;

        lock_kernel();

        /* A _really_ horrible hack to avoid removing the data stored
         * in the block pointers; this is really the "small" stripe MD data.
         * We can avoid further hackery by virtue of the MDS file size being
         * zero all the time (which doesn't invoke block truncate at unlink
         * time), so we assert we never change the MDS file size from zero.
         */
        if (iattr->ia_valid & ATTR_SIZE && !do_trunc) {
                /* ATTR_SIZE would invoke truncate: clear it */
                iattr->ia_valid &= ~ATTR_SIZE;
                i_size_write(inode, iattr->ia_size);

                /* make sure _something_ gets set - so new inode
                 * goes to disk (probably won't work over XFS
                 */
                if (!iattr->ia_valid & ATTR_MODE) {
                        iattr->ia_valid |= ATTR_MODE;
                        iattr->ia_mode = inode->i_mode;
                }
        }

        /* We set these flags on the client, but have already checked perms
         * so don't confuse inode_change_ok. */
        iattr->ia_valid &= ~(ATTR_MTIME_SET | ATTR_ATIME_SET);

        if (inode->i_op->setattr) {
                rc = inode->i_op->setattr(dentry, iattr);
        } else {
                rc = inode_change_ok(inode, iattr);
                if (!rc)
                        rc = inode_setattr(inode, iattr);
        }

        unlock_kernel();

        return rc;
}

static int fsfilt_reiserfs_set_md(struct inode *inode, void *handle,
                                  void *lmm, int lmm_size, const char *name)
{
        /* XXX write stripe data into MDS file itself */
        CERROR("not implemented yet\n");

        return -ENOSYS;
}

static int fsfilt_reiserfs_get_md(struct inode *inode, void *lmm, int lmm_size,
                                  const char *name)
{
        if (lmm == NULL)
                return i_size_read(inode);

        CERROR("not implemented yet\n");
        return -ENOSYS;
}

static ssize_t fsfilt_reiserfs_readpage(struct file *file, char *buf, size_t count,
                                        loff_t *offset)
{
        return file->f_op->read(file, buf, count, offset);
}

static int fsfilt_reiserfs_add_journal_cb(struct obd_device *obd,
                                          __u64 last_rcvd, void *handle,
                                          fsfilt_cb_t cb_func, void *cb_data)
{
        static unsigned long next = 0;

        if (time_after(jiffies, next)) {
                CERROR("no journal callback kernel patch, faking it...\n");
                next = jiffies + 300 * HZ;
        }

        cb_func(obd, last_rcvd, cb_data, 0);

        return 0;
}

static int fsfilt_reiserfs_statfs(struct super_block *sb,
                                  struct obd_statfs *osfs)
{
        struct kstatfs sfs;
        int rc;

        memset(&sfs, 0, sizeof(sfs));

        rc = ll_do_statfs(sb, &sfs);

        statfs_pack(osfs, &sfs);
        return rc;
}

static int fsfilt_reiserfs_sync(struct super_block *sb)
{
        return fsync_dev(sb->s_dev);
}

/* If fso is NULL, op is FSFILT operation, otherwise op is number of fso
   objects. Logs is number of logfiles to update */
static int fsfilt_reiserfs_get_op_len(int op, struct fsfilt_objinfo *fso,
                                      int logs)
{
        if ( !fso ) {
                switch(op) {
                case FSFILT_OP_CREATE:
                                 /* directory leaf, index & indirect & EA*/
                        return MAX_HEIGHT + logs;
                case FSFILT_OP_UNLINK:
                        return MAX_HEIGHT + logs;
                }

        } else {
                int i;
                int needed = MAX_HEIGHT;
                struct super_block *sb = fso->fso_dentry->d_inode->i_sb;
                int blockpp = 1 << (CFS_PAGE_SHIFT - sb->s_blocksize_bits);
                for (i = 0; i < op; i++, fso++) {
                        int nblocks = fso->fso_bufcnt * blockpp;

                        needed += nblocks;
                }
                return needed + logs;
        }

        return 0;
}
static struct fsfilt_operations fsfilt_reiserfs_ops = {
        .fs_type                = "reiserfs",
        .fs_owner               = THIS_MODULE,
        .fs_start               = fsfilt_reiserfs_start,
        .fs_brw_start           = fsfilt_reiserfs_brw_start,
        .fs_commit              = fsfilt_reiserfs_commit,
        .fs_setattr             = fsfilt_reiserfs_setattr,
        .fs_set_md              = fsfilt_reiserfs_set_md,
        .fs_get_md              = fsfilt_reiserfs_get_md,
        .fs_readpage            = fsfilt_reiserfs_readpage,
        .fs_add_journal_cb      = fsfilt_reiserfs_add_journal_cb,
        .fs_statfs              = fsfilt_reiserfs_statfs,
        .fs_sync                = fsfilt_reiserfs_sync,
        .fs_get_op_len          = fsfilt_reiserfs_get_op_len,
};

static int __init fsfilt_reiserfs_init(void)
{
        return fsfilt_register_ops(&fsfilt_reiserfs_ops);
}

static void __exit fsfilt_reiserfs_exit(void)
{
        fsfilt_unregister_ops(&fsfilt_reiserfs_ops);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre reiserfs Filesystem Helper v0.1");
MODULE_LICENSE("GPL");

module_init(fsfilt_reiserfs_init);
module_exit(fsfilt_reiserfs_exit);
