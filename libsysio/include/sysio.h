/*
 *    This Cplant(TM) source code is the property of Sandia National
 *    Laboratories.
 *
 *    This Cplant(TM) source code is copyrighted by Sandia National
 *    Laboratories.
 *
 *    The redistribution of this Cplant(TM) source code is subject to the
 *    terms of the GNU Lesser General Public License
 *    (see cit/LGPL or http://www.gnu.org/licenses/lgpl.html)
 *
 *    Cplant(TM) Copyright 1998-2004 Sandia Corporation. 
 *    Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
 *    license for use of this work by or on behalf of the US Government.
 *    Export of this program may require a license from the United States
 *    Government.
 */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * Questions or comments about this library should be sent to:
 *
 * Lee Ward
 * Sandia National Laboratories, New Mexico
 * P.O. Box 5800
 * Albuquerque, NM 87185-1110
 *
 * lee@sandia.gov
 */

/*
 * System IO common information.
 */

#include <limits.h>
#include <stdarg.h>

#ifndef _IOID_T_DEFINED
#define _IOID_T_DEFINED
/*
 * FIXME:
 *
 * This section about ioid_t and it's failure belong in <sys/types.h>
 */
typedef void *ioid_t;

#define IOID_FAIL			0
#endif

#if !defined(__IS_UNUSED) && defined(__GNUC__)
#define __IS_UNUSED	__attribute__ ((unused))
#else
#define __IS_UNUSED
#endif

#ifndef PATH_SEPARATOR
/*
 * Path separator.
 */
#define PATH_SEPARATOR			'/'
#endif

#ifndef MAX_SYMLINK
/*
 * Max recursion depth allowed when resoving symbolic links.
 */
#define MAX_SYMLINK			250
#endif

#ifndef _LARGEFILE64_SOURCE
/*
 * Not glibc I guess. Define this ourselves.
 */
#define _LARGEFILE64_SOURCE		0
#endif

/*
 * Define internal file-offset type and it's maximum value.
 */
#if _LARGEFILE64_SOURCE
#define _SYSIO_OFF_T			off64_t
#ifdef LLONG_MAX
#define _SYSIO_OFF_T_MAX		(LLONG_MAX)
#else
/*
 * Don't have LLONG_MAX before C99. We'll need to define it ourselves.
 */
#define _SYSIO_OFF_T_MAX		(9223372036854775807LL)
#endif
#else
#define _SYSIO_OFF_T			off_t
#define _SYSIO_OFF_T_MAX		LONG_MAX
#endif

/*
 * Internally, all directory entries are carried in the 64-bit capable
 * structure.
 */
#if _LARGEFILE64_SOURCE
#define intnl_dirent dirent64
#else
#define intnl_dirent dirent
#endif
struct dirent;

/*
 * Internally, all file status is carried in the 64-bit capable
 * structure.
 */
#if _LARGEFILE64_SOURCE
#define intnl_stat stat64
#else
#define intnl_stat stat
#endif
struct stat;

#ifdef _HAVE_STATVFS
#if _LARGEFILE64_SOURCE
#define intnl_statvfs statvfs64
#else
#define intnl_statvfs statvfs
#define INTNL_STATVFS_IS_NATURAL	1
#endif
struct statvfs;
struct intnl_statvfs;
#endif

/*
 * Internally, all file status is carried in the 64-bit capable
 * structure.
 */
#if _LARGEFILE64_SOURCE
#define intnl_xtvec xtvec64
#else
#define intnl_xtvec xtvec
#endif
struct intnl_xtvec;

struct iovec;

struct utimbuf;

struct intnl_stat;

struct pnode;

extern struct pnode *_sysio_cwd;

extern mode_t _sysio_umask;

extern int _sysio_init(void);
extern void _sysio_shutdown(void);
extern int _sysio_boot(const char *buf);

/*
 * SYSIO name label macros
 */
#define XPREPEND(p,x) p ## x
#define PREPEND(p,x) XPREPEND(p,x)
#define SYSIO_LABEL_NAMES 0
#if SYSIO_LABEL_NAMES
#define SYSIO_INTERFACE_NAME(x) PREPEND(sysio__, x)
#else
#define SYSIO_INTERFACE_NAME(x) x
#endif

/*
 * The following should be defined by the system includes, and probably are,
 * but it's not illegal to have multiple externs, so long as they are the
 * same. It helps when building the library in a standalone fashion.
 */
extern int SYSIO_INTERFACE_NAME(access)(const char *path, int amode);
extern int SYSIO_INTERFACE_NAME(chdir)(const char *path);
extern int SYSIO_INTERFACE_NAME(chmod)(const char *path, mode_t mode);
extern int SYSIO_INTERFACE_NAME(fchmod)(int fd, mode_t mode);
extern int SYSIO_INTERFACE_NAME(chown)(const char *path, uid_t owner,
				       gid_t group);
extern int SYSIO_INTERFACE_NAME(fchown)(int fd, uid_t owner, gid_t group);
extern int SYSIO_INTERFACE_NAME(close)(int d);
extern int SYSIO_INTERFACE_NAME(dup)(int oldfd);
extern int SYSIO_INTERFACE_NAME(dup2)(int oldfd, int newfd);
extern int SYSIO_INTERFACE_NAME(fcntl)(int fd, int cmd, ...);
extern int SYSIO_INTERFACE_NAME(fstat)(int fd, struct stat *buf);
extern int SYSIO_INTERFACE_NAME(fsync)(int fd);
extern char *SYSIO_INTERFACE_NAME(getcwd)(char *buf, size_t size);
extern off_t SYSIO_INTERFACE_NAME(lseek)(int fd, off_t offset, int whence);
#if _LARGEFILE64_SOURCE
extern off64_t SYSIO_INTERFACE_NAME(lseek64)(int fd, off64_t offset, 
					     int whence);
#endif
extern int SYSIO_INTERFACE_NAME(lstat)(const char *path, struct stat *buf);
#ifdef BSD
extern int SYSIO_INTERFACE_NAME(getdirentries)(int fd, char *buf, int nbytes , 
					       long *basep);
#else
extern ssize_t SYSIO_INTERFACE_NAME(getdirentries)(int fd, char *buf, 
						   size_t nbytes, off_t *basep);
#if _LARGEFILE64_SOURCE
extern ssize_t SYSIO_INTERFACE_NAME(getdirentries64)(int fd,
						     char *buf,
						     size_t nbytes,
						     off64_t *basep);
#endif
#endif
extern int SYSIO_INTERFACE_NAME(mkdir)(const char *path, mode_t mode);
extern int SYSIO_INTERFACE_NAME(open)(const char *path, int flag, ...);
#if _LARGEFILE64_SOURCE
extern int SYSIO_INTERFACE_NAME(open64)(const char *path, int flag, ...);
#endif
extern int SYSIO_INTERFACE_NAME(creat)(const char *path, mode_t mode);
#if _LARGEFILE64_SOURCE
extern int SYSIO_INTERFACE_NAME(creat64)(const char *path, mode_t mode);
#endif
extern int SYSIO_INTERFACE_NAME(stat)(const char *path, struct stat *buf);
#if _LARGEFILE64_SOURCE
extern int SYSIO_INTERFACE_NAME(stat64)(const char *path, struct stat64 *buf);
#endif
#ifdef _HAVE_STATVFS
extern int SYSIO_INTERFACE_NAME(statvfs)(const char *path, struct statvfs *buf);
#if _LARGEFILE64_SOURCE
extern int SYSIO_INTERFACE_NAME(statvfs64)(const char *path, 
				struct statvfs64 *buf);
#endif
extern int SYSIO_INTERFACE_NAME(fstatvfs)(int fd, struct statvfs *buf);
#if _LARGEFILE64_SOURCE
extern int SYSIO_INTERFACE_NAME(fstatvfs64)(int fd, struct statvfs64 *buf);
#endif
#endif
extern int SYSIO_INTERFACE_NAME(truncate)(const char *path, off_t length);
#if _LARGEFILE64_SOURCE
extern int SYSIO_INTERFACE_NAME(truncate64)(const char *path, off64_t length);
#endif
extern int SYSIO_INTERFACE_NAME(ftruncate)(int fd, off_t length);
#if _LARGEFILE64_SOURCE
extern int SYSIO_INTERFACE_NAME(ftruncate64)(int fd, off64_t length);
#endif
extern int SYSIO_INTERFACE_NAME(rmdir)(const char *path);
extern int SYSIO_INTERFACE_NAME(symlink)(const char *path1, const char *path2);
extern int SYSIO_INTERFACE_NAME(readlink)(const char *path,
				char *buf,
				size_t bufsiz);
extern int SYSIO_INTERFACE_NAME(link)(const char *oldpath, const char *newpath);
extern int SYSIO_INTERFACE_NAME(unlink)(const char *path);
extern int SYSIO_INTERFACE_NAME(rename)(const char *oldpath, 
					const char *newpath);
extern int SYSIO_INTERFACE_NAME(fdatasync)(int fd);
extern int SYSIO_INTERFACE_NAME(ioctl)(int fd, unsigned long request, ...);
extern mode_t SYSIO_INTERFACE_NAME(umask)(mode_t mask);
extern int SYSIO_INTERFACE_NAME(iodone)(ioid_t ioid);
extern ssize_t SYSIO_INTERFACE_NAME(iowait)(ioid_t ioid);
extern ioid_t SYSIO_INTERFACE_NAME(ipreadv)(int fd, const struct iovec *iov, 
				   size_t count, off_t offset);
#if _LARGEFILE64_SOURCE
extern ioid_t SYSIO_INTERFACE_NAME(ipread64v)(int fd, const struct iovec *iov, 
					      size_t count, off64_t offset);
#endif
extern ioid_t SYSIO_INTERFACE_NAME(ipread)(int fd, void *buf, size_t count, 
					   off_t offset);
#if _LARGEFILE64_SOURCE
extern ioid_t SYSIO_INTERFACE_NAME(ipread64)(int fd, void *buf, size_t count, 
					     off64_t offset);
#endif
extern ssize_t SYSIO_INTERFACE_NAME(preadv)(int fd, const struct iovec *iov, 
					    size_t count, off_t offset);
#if _LARGEFILE64_SOURCE
extern ssize_t SYSIO_INTERFACE_NAME(pread64v)(int fd, const struct iovec *iov, 
					      size_t count, off64_t offset);
#endif
extern ssize_t SYSIO_INTERFACE_NAME(pread)(int fd, void *buf, size_t count, 
					   off_t offset);
#if _LARGEFILE64_SOURCE
extern ssize_t SYSIO_INTERFACE_NAME(pread64)(int fd, void *buf, size_t count, 
					     off64_t offset);
#endif
extern ioid_t SYSIO_INTERFACE_NAME(ireadv)(int fd, const struct iovec *iov, 
					   int count);
extern ioid_t SYSIO_INTERFACE_NAME(iread)(int fd, void *buf, size_t count);
extern ssize_t SYSIO_INTERFACE_NAME(readv)(int fd, const struct iovec *iov, 
					   int count);
extern ssize_t SYSIO_INTERFACE_NAME(read)(int fd, void *buf, size_t count);
extern ioid_t SYSIO_INTERFACE_NAME(ipwritev)(int fd, const struct iovec *iov, 
					     size_t count, off_t offset);
#if _LARGEFILE64_SOURCE
extern ioid_t SYSIO_INTERFACE_NAME(ipwrite64v)(int fd, const struct iovec *iov, 
					       size_t count, off64_t offset);
#endif
extern ioid_t SYSIO_INTERFACE_NAME(ipwrite)(int fd, const void *buf, 
					    size_t count, off_t offset);
#if _LARGEFILE64_SOURCE
extern ioid_t SYSIO_INTERFACE_NAME(ipwrite64)(int fd, const void *buf, 
					      size_t count, off64_t offset);
#endif
extern ssize_t SYSIO_INTERFACE_NAME(pwritev)(int fd, const struct iovec *iov, 
					     size_t count, off_t offset);
#if _LARGEFILE64_SOURCE
extern ssize_t SYSIO_INTERFACE_NAME(pwrite64v)(int fd, const struct iovec *iov, 
					       size_t count, off64_t offset);
#endif
extern ssize_t SYSIO_INTERFACE_NAME(pwrite)(int fd, const void *buf, 
					    size_t count, off_t offset);
#if _LARGEFILE64_SOURCE
extern ssize_t SYSIO_INTERFACE_NAME(pwrite64)(int fd, const void *buf, 
					      size_t count, off64_t offset);
#endif
extern ioid_t SYSIO_INTERFACE_NAME(iwritev)(int fd, 
					    const struct iovec *iov, 
					    int count);
extern ioid_t SYSIO_INTERFACE_NAME(iwrite)(int fd, const void *buf, 
					   size_t count);
extern ssize_t SYSIO_INTERFACE_NAME(writev)(int fd, const struct iovec *iov, 
					    int count);
extern ssize_t SYSIO_INTERFACE_NAME(write)(int fd, const void *buf, 
					   size_t count);
extern int SYSIO_INTERFACE_NAME(mknod)(const char *path, 
				       mode_t mode, dev_t dev);
extern int SYSIO_INTERFACE_NAME(utime)(const char *path, 
				       const struct utimbuf *buf);
extern int SYSIO_INTERFACE_NAME(mount)(const char *source, const char *target,
				       const char *filesystemtype,
				       unsigned long mountflags,
				       const void *data);
extern int SYSIO_INTERFACE_NAME(umount)(const char *target);

/* for debugging */
#if 0
#define ASSERT(cond)							\
	if (!(cond)) {							\
		printf("ASSERTION(" #cond ") failed: " __FILE__ ":"	\
			__FUNCTION__ ":%d\n", __LINE__);		\
		abort();						\
	}

#define ERROR(fmt, a...)						\
	do {								\
		printf("ERROR(" __FILE__ ":%d):" fmt, __LINE__, ##a);	\
	while(0)

#else
#define ERROR(fmt) 	do{}while(0)
#define ASSERT		do{}while(0)
#endif

/*
 * SYSIO interface frame macros
 *
 * + DISPLAY_BLOCK; Allocates storage on the stack for use by the set of
 *	macros.
 * + ENTER; Performs entry point work
 * + RETURN; Returns a value and performs exit point work
 *
 * NB: For RETURN, the arguments are the return value and value for errno.
 * If the value for errno is non-zero then that value, *negated*, is set
 * into errno.
 */
#define SYSIO_INTERFACE_DISPLAY_BLOCK \
	int _saved_errno;
#define SYSIO_INTERFACE_ENTER \
	do { \
		_saved_errno = errno; \
		SYSIO_ENTER; \
	} while (0)
#define SYSIO_INTERFACE_RETURN(rtn, err) \
	do { \
		SYSIO_LEAVE; \
		errno = (err) ? -(err) : _saved_errno; \
		return (rtn); \
	} while(0) 

/* syscall enter/leave hook functions  */
#if 0
extern void _sysio_sysenter();
extern void _sysio_sysleave();

#define SYSIO_ENTER							\
	do {								\
		_sysio_sysenter();					\
	} while(0)

#define SYSIO_LEAVE							\
	do {								\
		_sysio_sysleave();					\
	} while(0)
#else
#define SYSIO_ENTER
#define SYSIO_LEAVE

#endif
