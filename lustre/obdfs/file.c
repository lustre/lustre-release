/*
 *  linux/fs/ext2/file.c
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
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 fs regular file handling primitives
 *
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 *      (jj@sunsite.ms.mff.cuni.cz)
 */

#include <asm/uaccess.h>
#include <asm/system.h>

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/locks.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>

#define DEBUG_SUBSYSTEM S_OBDFS

#include <linux/obd_support.h>
#include <linux/obdfs.h>

extern int obdfs_setattr(struct dentry *de, struct iattr *attr);
void obdfs_change_inode(struct inode *inode);

static inline void obdfs_remove_suid(struct inode *inode)
{
        unsigned int mode;

        /* set S_IGID if S_IXGRP is set, and always set S_ISUID */
        mode = (inode->i_mode & S_IXGRP)*(S_ISGID/S_IXGRP) | S_ISUID;

        /* was any of the uid bits set? */
        mode &= inode->i_mode;
        if (mode && !capable(CAP_FSETID)) {
                inode->i_mode &= ~mode;
		// XXX careful here - we cannot change the size
                //obdfs_change_inode(inode);
        }
}

/*
 * Write to a file (through the page cache).
 */
static ssize_t
obdfs_file_write(struct file *file, const char *buf, size_t count, loff_t *ppos)
{
        ssize_t retval;
        CDEBUG(D_INFO, "Writing inode %ld, %ld bytes, offset %Ld\n",
               file->f_dentry->d_inode->i_ino, (long)count, *ppos);

        retval = generic_file_write(file, buf, count, ppos);
        CDEBUG(D_INFO, "Wrote %ld\n", (long)retval);

	/* update mtime/ctime/atime here, NOT size */
        if (retval > 0) {
		struct iattr attr;
		attr.ia_valid = ATTR_MTIME | ATTR_CTIME | ATTR_ATIME;
		attr.ia_mtime = attr.ia_ctime = attr.ia_atime =
			CURRENT_TIME;
                obdfs_setattr(file->f_dentry, &attr);
        }
        EXIT;
        return retval;
}


/* XXX this does not need to do anything for data, it _does_ need to
   call setattr */ 
int obdfs_fsync(struct file *file, struct dentry *dentry, int data)
{
	return 0;
}

struct file_operations obdfs_file_operations = {
        read: generic_file_read,
        write: obdfs_file_write,
        mmap: generic_file_mmap,
	fsync: NULL
};


struct inode_operations obdfs_file_inode_operations = {
        truncate: obdfs_truncate,
	setattr: obdfs_setattr
};

