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
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include <linux/locks.h>

#include <linux/obd_support.h> /* for ENTRY and EXIT only */
#include <linux/obdfs.h>

static struct dentry * obdfs_follow_link(struct dentry * dentry,
					 struct dentry *base,
					 unsigned int follow)
{
	struct inode *inode = dentry->d_inode;
	struct page *page = NULL;
	char * link;

	ENTRY;
	link = obdfs_i2info(inode)->oi_inline;
	if (!obdfs_has_inline(inode)) {
		OIDEBUG(inode);
		page = obdfs_getpage(inode, 0, 0, 0);
		PDEBUG(page, "follow_link");
		if (!page) {
			dput(base);
			EXIT;
			return ERR_PTR(-EIO);
		}
		link = (char *)page_address(page);
	}
	UPDATE_ATIME(inode);
	base = lookup_dentry(link, base, follow);
	if (page) {
		page_cache_release(page);
	}
	EXIT;
	return base;
}

static int obdfs_readlink (struct dentry * dentry, char * buffer, int buflen)
{
	struct inode *inode = dentry->d_inode;
	struct page *page = NULL;
	char * link;
	int i;

	ENTRY;
	if (buflen > inode->i_sb->s_blocksize - 1)
		buflen = inode->i_sb->s_blocksize - 1;

	link = obdfs_i2info(inode)->oi_inline;
	if (!obdfs_has_inline(inode)) {
		OIDEBUG(inode);
		page = obdfs_getpage(inode, 0, 0, 0);
		PDEBUG(page, "readlink");
		if (!page) {
			EXIT;
			return 0;
		}
		link = (char *)page_address(page);
	}

	i = 0;
	while (i < buflen && link[i])
		i++;
	if (copy_to_user(buffer, link, i))
		i = -EFAULT;
	if (page) {
		page_cache_release(page);
	}
	EXIT;
	return i;
} /* obdfs_readlink */

/*
 * symlinks can't do much...
 */
struct inode_operations obdfs_symlink_inode_operations = {
	NULL,			/* no file-operations */
	NULL,			/* create */
	NULL,			/* lookup */
	NULL,			/* link */
	NULL,			/* unlink */
	NULL,			/* symlink */
	NULL,			/* mkdir */
	NULL,			/* rmdir */
	NULL,			/* mknod */
	NULL,			/* rename */
	obdfs_readlink,		/* readlink */
	obdfs_follow_link,	/* follow_link */
	NULL,			/* get_block */
	NULL,			/* readpage */
	NULL,			/* writepage */
	NULL,			/* truncate */
	NULL,			/* permission */
	NULL			/* revalidate */
};

