/*
 *  linux/fs/ext2/dir.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/dir.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 directory handling functions
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 *  Changes for use with Object Based Device File System
 *    
 *  Copyright (C) 1999, Seagate Technology Inc. 
 *   (author Peter J. Braam, braam@stelias.com)
 * 
 */

#include <asm/uaccess.h>

#include <asm/uaccess.h>

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/locks.h>
#include <linux/quotaops.h>
#include <linux/iobuf.h>
#include "obdfs.h"
#include <linux/obd_support.h>

#if 0
static ssize_t obdfs_dir_read (struct file * filp, char * buf,
			      size_t count, loff_t *ppos)
{
	return -EISDIR;
}


int ext2_check_dir_entry (const char * function, struct inode * dir,
			  struct ext2_dir_entry_2 * de,
			  struct buffer_head * bh,
			  unsigned long offset)
{
	const char * error_msg = NULL;

	if (le16_to_cpu(de->rec_len) < EXT2_DIR_REC_LEN(1))
		error_msg = "rec_len is smaller than minimal";
	else if (le16_to_cpu(de->rec_len) % 4 != 0)
		error_msg = "rec_len % 4 != 0";
	else if (le16_to_cpu(de->rec_len) < EXT2_DIR_REC_LEN(de->name_len))
		error_msg = "rec_len is too small for name_len";
	else if (dir && ((char *) de - bh->b_data) + le16_to_cpu(de->rec_len) >
		 dir->i_sb->s_blocksize)
		error_msg = "directory entry across blocks";
	else if (dir && le32_to_cpu(de->inode) > le32_to_cpu(dir->i_sb->u.ext2_sb.s_es->s_inodes_count))
		error_msg = "inode out of bounds";

	if (error_msg != NULL)
		ext2_error (dir->i_sb, function, "bad entry in directory #%lu: %s - "
			    "offset=%lu, inode=%lu, rec_len=%d, name_len=%d",
			    dir->i_ino, error_msg, offset,
			    (unsigned long) le32_to_cpu(de->inode),
			    le16_to_cpu(de->rec_len), de->name_len);
	return error_msg == NULL ? 1 : 0;
}

#endif

int obdfs_readdir(struct file * filp, void * dirent, filldir_t filldir)
{
	int error = 0;
	unsigned long offset;
	int stored;
	struct ext2_dir_entry_2 * de;
	struct super_block * sb;
	struct page *page;
	struct inode *inode = filp->f_dentry->d_inode;

	ENTRY;

	sb = inode->i_sb;

	stored = 0;
	offset = filp->f_pos & (PAGE_SIZE - 1);

	while (!error && !stored && filp->f_pos < inode->i_size) {
		page = obdfs_getpage(inode, offset, 0, NOLOCK);
		if (!page) {
			ext2_error (sb, "ext2_readdir",
				    "directory #%lu contains a hole at offset %lu",
				    inode->i_ino, (unsigned long)filp->f_pos);
			filp->f_pos += PAGE_SIZE - offset;
			continue;
		}

#if 0
		/* XXX need to do read ahead and support stuff below */
revalidate:
		/* If the dir block has changed since the last call to
		 * readdir(2), then we might be pointing to an invalid
		 * dirent right now.  Scan from the start of the block
		 * to make sure. */
		if (filp->f_version != inode->i_version) {
			for (i = 0; i < sb->s_blocksize && i < offset; ) {
				de = (struct ext2_dir_entry_2 *) 
					(bh->b_data + i);
				/* It's too expensive to do a full
				 * dirent test each time round this
				 * loop, but we do have to test at
				 * least that it is non-zero.  A
				 * failure will be detected in the
				 * dirent test below. */
				if (le16_to_cpu(de->rec_len) < EXT2_DIR_REC_LEN(1))
					break;
				i += le16_to_cpu(de->rec_len);
			}
			offset = i;
			filp->f_pos = (filp->f_pos & ~(sb->s_blocksize - 1))
				| offset;
			filp->f_version = inode->i_version;
		}
#endif		
		while (!error && filp->f_pos < inode->i_size 
		       && offset < PAGE_SIZE) {
			de = (struct ext2_dir_entry_2 *) ((char *)page_address(page) + offset);
#if 0
			if (!obdfs_check_dir_entry ("ext2_readdir", inode, de,
						   bh, offset)) {
				/* On error, skip the f_pos to the
                                   next block. */
				filp->f_pos = (filp->f_pos & (sb->s_blocksize - 1))
					      + sb->s_blocksize;
				brelse (bh);
				return stored;
			}
#endif
			offset += le16_to_cpu(de->rec_len);
			if (le32_to_cpu(de->inode)) {
				/* We might block in the next section
				 * if the data destination is
				 * currently swapped out.  So, use a
				 * version stamp to detect whether or
				 * not the directory has been modified
				 * during the copy operation.
				 */
				/* XXX				unsigned long version = inode->i_version;
				 */
				error = filldir(dirent, de->name,
						de->name_len,
						filp->f_pos, le32_to_cpu(de->inode));
				if (error)
					break;
#if 0
				if (version != inode->i_version)
					goto revalidate;
#endif
				stored ++;
			}
			filp->f_pos += le16_to_cpu(de->rec_len);
		}
		offset = 0;
		page_cache_release(page);
	}
	UPDATE_ATIME(inode);
	EXIT;
	return 0;
}
