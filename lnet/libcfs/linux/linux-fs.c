# define DEBUG_SUBSYSTEM S_LNET

#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/ctype.h>
#include <asm/uaccess.h>

#include <libcfs/libcfs.h>

cfs_file_t *
cfs_filp_open (const char *name, int flags, int mode, int *err)
{
	/* XXX
	 * Maybe we need to handle flags and mode in the future
	 */
	cfs_file_t	*filp = NULL;

	filp = filp_open(name, flags, mode);
	if (IS_ERR(filp)) {
		int rc;

		rc = PTR_ERR(filp);
		printk(KERN_ERR "LustreError: can't open %s file: err %d\n",
				name, rc);
		if (err)
			*err = rc;
		filp = NULL;
	}
	return filp;
}

/* write a userspace buffer to disk.
 * NOTE: this returns 0 on success, not the number of bytes written. */
ssize_t
cfs_user_write (cfs_file_t *filp, const char *buf, size_t count, loff_t *offset)
{
	mm_segment_t fs;
	ssize_t size = 0;

	fs = get_fs();
	set_fs(KERNEL_DS);
	while (count > 0) {
		size = filp->f_op->write(filp, (char *)buf, count, offset);
		if (size < 0)
			break;
		count -= size;
		size = 0;
	}
	set_fs(fs);

	return size;
}

cfs_rdev_t cfs_rdev_build(cfs_major_nr_t major, cfs_minor_nr_t minor)
{
        return MKDEV(major, minor);
}

cfs_major_nr_t cfs_rdev_major(cfs_rdev_t rdev)
{
        return MAJOR(rdev);
}

cfs_minor_nr_t cfs_rdev_minor(cfs_rdev_t rdev)
{
        return MINOR(rdev);
}

#if !(CFS_O_CREAT == O_CREAT && CFS_O_EXCL == O_EXCL &&	\
     CFS_O_TRUNC == O_TRUNC && CFS_O_APPEND == O_APPEND &&\
     CFS_O_NONBLOCK == O_NONBLOCK && CFS_O_NDELAY == O_NDELAY &&\
     CFS_O_SYNC == O_SYNC && CFS_O_ASYNC == FASYNC &&\
     CFS_O_DIRECT == O_DIRECT && CFS_O_LARGEFILE == O_LARGEFILE &&\
     CFS_O_DIRECTORY == O_DIRECTORY && CFS_O_NOFOLLOW == O_NOFOLLOW)

int cfs_oflags2univ(int flags)
{
	int f; 
	
	f = flags & O_ACCMODE;
	f |= (flags & O_CREAT) ? CFS_O_CREAT: 0;
	f |= (flags & O_EXCL) ? CFS_O_EXCL: 0;
	f |= (flags & O_NOCTTY) ? CFS_O_NOCTTY: 0;
	f |= (flags & O_TRUNC) ? CFS_O_TRUNC: 0;
	f |= (flags & O_APPEND) ? CFS_O_APPEND: 0;
	f |= (flags & O_NONBLOCK) ? CFS_O_NONBLOCK: 0;
	f |= (flags & O_SYNC)? CFS_O_SYNC: 0;
	f |= (flags & FASYNC)? CFS_O_ASYNC: 0;
	f |= (flags & O_DIRECTORY)? CFS_O_DIRECTORY: 0;
	f |= (flags & O_DIRECT)? CFS_O_DIRECT: 0;
	f |= (flags & O_LARGEFILE)? CFS_O_LARGEFILE: 0;
	f |= (flags & O_NOFOLLOW)? CFS_O_NOFOLLOW: 0;
	f |= (flags & O_NOATIME)? CFS_O_NOATIME: 0;
	return f;
}
#else

int cfs_oflags2univ(int flags)
{
	return (flags);
}
#endif

/* 
 * XXX Liang: we don't need cfs_univ2oflags() now.
 */
int cfs_univ2oflags(int flags)
{
	return (flags);
}

EXPORT_SYMBOL(cfs_filp_open);
EXPORT_SYMBOL(cfs_user_write);
EXPORT_SYMBOL(cfs_oflags2univ);
EXPORT_SYMBOL(cfs_univ2oflags);
