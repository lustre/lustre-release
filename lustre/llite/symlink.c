/*
 *  linux/fs/ext2/symlink.c
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/symlink.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 symlink handling code
 *
 * Modified for OBDFS: 
 *  Copyright (C) 1999 Seagate Technology Inc. (author: braam@stelias.com)
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include <linux/locks.h>
#include <linux/obd_support.h> /* for ENTRY and EXIT only */
#include <linux/lustre_light.h>



static int ll_fast_readlink(struct dentry *dentry, char *buffer, int buflen)
{
        char *s = ll_i2info(dentry->d_inode)->lli_inline;
        return vfs_readlink(dentry, buffer, buflen, s);
}

static int ll_fast_follow_link(struct dentry *dentry, struct nameidata *nd)
{
        char *s = ll_i2info(dentry->d_inode)->lli_inline;
        return vfs_follow_link(nd, s); 
}

extern int ll_setattr(struct dentry *de, struct iattr *attr);
struct inode_operations ll_fast_symlink_inode_operations = {
        readlink:       ll_fast_readlink,
        follow_link:    ll_fast_follow_link,
	setattr:        ll_setattr
};

