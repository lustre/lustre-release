/*
 *  linux/fs/ext2/symlink.c
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

#include <asm/uaccess.h>

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/stat.h>

static int obdfs_readlink (struct dentry *, char *, int);
static struct dentry *obdfs_follow_link(struct dentry *, struct dentry *, unsigned int);

static struct dentry * ext2_follow_link(struct dentry * dentry,
					struct dentry *base,
					unsigned int follow)
{
	struct inode *inode = dentry->d_inode;
	struct page *page = NULL;
	int error;
	char * link;

	link = (char *) inode->u.ext2_i.i_data;
	if (inode->i_blocks) {
		if (!(page = obdfs_getpage(inode, 0, 0, &error))) {
			dput(base);
			return ERR_PTR(-EIO);
		}
		link = bh->b_data;
	}
	UPDATE_ATIME(inode);
	base = lookup_dentry(link, base, follow);
	if (bh)
		brelse(bh);
	return base;
}

static int ext2_readlink (struct dentry * dentry, char * buffer, int buflen)
{
	struct inode *inode = dentry->d_inode;
	struct buffer_head * bh = NULL;
	char * link;
	int i;

	if (buflen > inode->i_sb->s_blocksize - 1)
		buflen = inode->i_sb->s_blocksize - 1;

	link = (char *) inode->u.ext2_i.i_data;
	if (inode->i_blocks) {
		int err;
		bh = ext2_bread (inode, 0, 0, &err);
		if (!bh) {
			if(err < 0) /* indicate type of error */
				return err;
			return 0;
		}
		link = bh->b_data;
	}

	i = 0;
	while (i < buflen && link[i])
		i++;
	if (copy_to_user(buffer, link, i))
		i = -EFAULT;
	if (bh)
		brelse (bh);
	return i;
}
