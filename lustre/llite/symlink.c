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

static int ll_readlink(struct dentry *dentry, char *buffer, int buflen)
{
        struct page *page = NULL;
        int res;

        ENTRY;
        OIDEBUG(dentry->d_inode);
        page = ll_getpage(dentry->d_inode, 0, 0, 0);
        /* PDEBUG(page, "readlink"); */
        if (!page) {
                EXIT;
                return 0;
        }
        res = vfs_readlink(dentry, buffer, buflen, (char *)page_address(page));
        page_cache_release(page);
        EXIT;
        return res;
} /* ll_readlink */

static int ll_follow_link(struct dentry * dentry,
                             struct nameidata *nd)
{
        struct page *page = NULL;
        int res;

        ENTRY;
        OIDEBUG(dentry->d_inode);
        page = ll_getpage(dentry->d_inode, 0, 0, 0);
        /* PDEBUG(page, "follow_link"); */
        if (!page) {
                dput(nd->dentry);
                EXIT;
                return -EIO;
        }
        res = vfs_follow_link(nd, (char *)page_address(page));
        page_cache_release(page);
        EXIT;
        return res;
}

struct inode_operations ll_symlink_inode_operations = {
        readlink:       ll_readlink,
        follow_link:    ll_follow_link,
	setattr:        ll_setattr
};
