#ifndef __LIBCFS_DARWIN_CFS_FS_H__
#define __LIBCFS_DARWIN_CFS_FS_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifdef __KERNEL__

#include <sys/types.h>
#include <sys/systm.h>
/*
 * __APPLE_API_PRIVATE is defined before include user.h
 * Doing this way to get the define of uthread, it's not good
 * but I do need to know what's inside uthread.
 */
#ifndef __APPLE_API_PRIVATE
#define __APPLE_API_PRIVATE
#include <sys/vnode.h>
#undef __APPLE_API_PRIVATE
#else
#include <sys/vnode.h>
#endif

#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/filedesc.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/ubc.h>
#include <sys/mbuf.h>
#include <sys/namei.h>
#include <sys/fcntl.h>
#include <sys/lockf.h>
#include <stdarg.h>

#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <mach/time_value.h>
#include <kern/clock.h>
#include <sys/param.h>
#include <IOKit/system.h>

#include <libcfs/darwin/darwin-types.h>
#include <libcfs/darwin/darwin-lock.h>
#include <libcfs/darwin/darwin-mem.h>
#include <libcfs/list.h>

/*
 * File operating APIs in kernel
 */
typedef struct file cfs_file_t;

int	filp_node_size(cfs_file_t *fp, off_t	*size);
#define cfs_filp_size(fp)			\
	({					\
		off_t		__size;		\
		filp_node_size((fp), &__size);	\
		__size;				\
	 })
#define cfs_filp_poff(fp)               (NULL)

cfs_file_t *filp_open(const char *name, int flags, int mode, int *err);
int filp_close(cfs_file_t *fp);
int filp_read(cfs_file_t *fp, void *buf, size_t nbytes, off_t *pos);
int filp_write(cfs_file_t *fp, void *buf, size_t nbytes, off_t *pos);
int filp_fsync(cfs_file_t *fp);

#define cfs_filp_open(n, f, m, e)	filp_open(n, f, m, e)
#define cfs_filp_close(f)		filp_close(f)
#define cfs_filp_read(f, b, n, p)	filp_read(f, b, n, p)
#define cfs_filp_write(f, b, n, p)	filp_write(f, b, n, p)
#define cfs_filp_fsync(f)		filp_fsync(f)

int ref_file(cfs_file_t *fp);
int rele_file(cfs_file_t *fp);
int file_count(cfs_file_t *fp);
#define cfs_get_file(f)			ref_file(f)
#define cfs_put_file(f)			rele_file(f)
#define cfs_file_count(f)		file_count(f)

#define CFS_INT_LIMIT(x)		(~((x)1 << (sizeof(x)*8 - 1)))
#define CFS_OFFSET_MAX			CFS_INT_LIMIT(loff_t)

typedef struct flock			cfs_flock_t;
#define CFS_FLOCK_TYPE(fl)		((fl)->l_type)
#define CFS_FLOCK_SET_TYPE(fl, type)	do { (fl)->l_type = (type); } while(0)
#define CFS_FLOCK_PID(fl)		((fl)->l_pid)
#define CFS_FLOCK_SET_PID(fl, pid)	do { (fl)->l_pid = (pid); } while(0)
#define CFS_FLOCK_START(fl)		((fl)->l_start)
#define CFS_FLOCK_SET_START(fl, start)	do { (fl)->l_start = (start); } while(0)
#define CFS_FLOCK_END(fl)		((fl)->l_len == 0? CFS_OFFSET_MAX: ((fl)->l_start + (fl)->l_en))
#define CFS_FLOCK_SET_END(fl, end)		\
	do {					\
		if (end == CFS_OFFSET_MAX)	\
			(fl)->l_len = 0;	\
		else				\
			(fl)->l_len = (end) - (fl)->l_start;\
	} while(0)

typedef struct {
	void	*d;
} cfs_dentry_t;
typedef unsigned short umode_t;

#define ATTR_MODE       0x0001
#define ATTR_UID        0x0002
#define ATTR_GID        0x0004
#define ATTR_SIZE       0x0008
#define ATTR_ATIME      0x0010
#define ATTR_MTIME      0x0020
#define ATTR_CTIME      0x0040
#define ATTR_ATIME_SET  0x0080
#define ATTR_MTIME_SET  0x0100
#define ATTR_FORCE      0x0200  /* Not a change, but a change it */
#define ATTR_ATTR_FLAG  0x0400
#define ATTR_RAW        0x0800  /* file system, not vfs will massage attrs */
#define ATTR_FROM_OPEN  0x1000  /* called from open path, ie O_TRUNC */
#define ATTR_CTIME_SET  0x2000

#define in_group_p(x)	(0)

#endif

#define O_SYNC					0
#define O_DIRECTORY				0
#define O_LARGEFILE				0

#endif
