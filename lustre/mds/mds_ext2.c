/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/mds_null.c
 *
 *  Lustre Metadata Server (mds) journal abstraction routines
 *
 *  Copyright (C) 2002  Cluster File Systems, Inc.
 *  author: Andreas Dilger <adilger@clusterfs.com>
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include <linux/lustre_mds.h>

static void *mds_ext2_start(struct inode *inode, int nblocks)
{
        return 0;
}

static int mds_ext2_stop(struct inode *inode, void *handle)
{
        return 0;
}

static int mds_ext2_setattr(struct inode *inode, void *handle,
                            struct iattr *iattr)
{
        /* a _really_ horrible hack to avoid removing the data stored
           in the block pointers; this data is the object id
           this will go into an extended attribute at some point.
        */
        if (iattr->ia_valid & ATTR_SIZE ) {
                /* ATTR_SIZE would invoke truncate: clear it */
                iattr->ia_valid &= ~ATTR_SIZE;
                inode->i_size = iattr->ia_size;

                /* make sure _something_ gets set - so new inode
                   goes to disk (probably won't work over XFS */
                if (!iattr->ia_valid & ATTR_MODE) {
                        iattr->ia_valid |= ATTR_MODE;
                        iattr->ia_mode = inode->i_mode;
                }
        }

        return 0;
}

/*
 * FIXME: nasty hack - store the object id in the first two
 *        direct block spots.  This should be done with EAs...
 */
static int mds_ext2_set_objid(struct inode *inode, void *handle, obd_id id)
{
        memcpy(inode->u.ext2_i.i_data, &id, sizeof(id));
        return 0;
}

static void mds_ext2_get_objid(struct inode *inode, obd_id *id)
{
        memcpy(id, &inode->u.ext2_i.i_data, sizeof(*id));
}

static ssize_t mds_ext2_readpage(struct file *file, char *buf, size_t count,
                                 loff_t *offset)
{
        if (S_ISREG(file->f_dentry->d_inode->i_mode))
                return file->f_op->read(file, buf, count, offset);
        else
                return generic_file_read(file, buf, count, offset);
}

struct mds_fs_operations mds_ext2_fs_ops = {
        fs_start:       mds_ext2_start,
        fs_commit:      mds_ext2_stop,
        fs_setattr:     mds_ext2_setattr,
        fs_set_objid:   mds_ext2_set_objid,
        fs_get_objid:   mds_ext2_get_objid,
        fs_readpage:    mds_ext2_readpage,
};
