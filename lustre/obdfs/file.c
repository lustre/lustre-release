/*
 *  linux/fs/ext2/file.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 fs regular file handling primitives
 *
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 * 	(jj@sunsite.ms.mff.cuni.cz)
 */

#include <asm/uaccess.h>
#include <asm/system.h>

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/locks.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>

#include <linux/obd_support.h>
#include <linux/obdfs.h>

static inline void remove_suid(struct inode *inode)
{
	unsigned int mode;

	/* set S_IGID if S_IXGRP is set, and always set S_ISUID */
	mode = (inode->i_mode & S_IXGRP)*(S_ISGID/S_IXGRP) | S_ISUID;

	/* was any of the uid bits set? */
	mode &= inode->i_mode;
	if (mode && !capable(CAP_FSETID)) {
		inode->i_mode &= ~mode;
		mark_inode_dirty(inode);
	}
}

/*
 * Write to a file (through the page cache).
 */
static ssize_t
obdfs_file_write(struct file *file, const char *buf, size_t count, loff_t *ppos)
{
	ssize_t retval;
	CDEBUG(D_INFO, "Writing inode %ld, %d bytes, offset %ld\n",
	       file->f_dentry->d_inode->i_ino, count, (long)*ppos);

	retval = generic_file_write(file, buf, count,
				    ppos, obdfs_write_one_page);
	CDEBUG(D_INFO, "Wrote %d\n", retval);
	if (retval > 0) {
		struct inode *inode = file->f_dentry->d_inode;
		remove_suid(inode);
		inode->i_ctime = inode->i_mtime = CURRENT_TIME;
		mark_inode_dirty(inode);
	}
	EXIT;
	return retval;
}

struct file_operations obdfs_file_operations = {
	NULL,			/* lseek - default */
	generic_file_read,	/* read */
	obdfs_file_write,       /* write  */
	NULL,			/* readdir - bad */
	NULL,			/* poll */
	NULL,			/* ioctl */
	generic_file_mmap,	/* mmap */
	NULL,			/* open */
	NULL,			/* flush */
	NULL,			/* release */
	NULL /* XXX add XXX */,	/* fsync */
	NULL,			/* fasync */
	NULL			/* lock */
};

struct inode_operations obdfs_file_inode_operations = {
	&obdfs_file_operations,	/* default directory file-ops */
	obdfs_create,		/* create */
	obdfs_lookup,		/* lookup */
	obdfs_link,		/* link */
	obdfs_unlink,		/* unlink */
	obdfs_symlink,		/* symlink */
	obdfs_mkdir,		/* mkdir */
	obdfs_rmdir,		/* rmdir */
	obdfs_mknod,		/* mknod */
	obdfs_rename,		/* rename */
	NULL,			/* readlink */
	NULL,			/* follow_link */
	NULL,			/* get_block */
	obdfs_readpage,		/* readpage */
	obdfs_writepage,	/* writepage */
	obdfs_truncate,		/* truncate */
	NULL,			/* permission */
	NULL			/* revalidate */
};

