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

#ifdef __linux__
#define _BSD_SOURCE
#endif

#include <stdio.h>					/* for NULL */
#include <stdlib.h>
#ifdef __linux__
#include <string.h>
#endif
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#if 0
#include <sys/vfs.h>
#endif
#ifdef _HAVE_STATVFS
#include <sys/statvfs.h>
#include <sys/statfs.h>
#endif
#include <utime.h>
#include <sys/queue.h>
#if !(defined(REDSTORM) || defined(MAX_IOVEC))
#include <limits.h>
#endif

#include "sysio.h"
#include "fs.h"
#include "mount.h"
#include "inode.h"
#include "xtio.h"

#include "fs_native.h"

#ifdef REDSTORM
#include <sys/uio.h>
#endif

#if defined(SYS_getdirentries)
#define DIR_STREAMED 0
#define DIR_CVT_64 0
#elif defined(SYS_getdents64)
#define DIR_STREAMED 1
#define DIR_CVT_64 0
#elif defined(SYS_getdents)
#define DIR_STREAMED 1
#if defined(_LARGEFILE64_SOURCE)
#define DIR_CVT_64 1
/*
 * Kernel version of directory entry.
 */
struct linux_dirent {
	unsigned long ld_ino;
	unsigned long ld_off;
	unsigned short ld_reclen;
	char	ld_name[1];
};
#include <dirent.h>
#else /* !defined(_LARGEFILE64_SOURCE) */
#define DIR_CVT_64 0
#endif /* defined(_LARGEFILE64_SOURCE) */
#else /* catch-none */
#error No usable directory fill entries interface available
#endif

/*
 * Local host file system driver.
 */

#if defined(ALPHA_LINUX)

/* stat struct from asm/stat.h, as returned 
 * by alpha linux kernel
 */
struct __native_stat {
	unsigned int    st_dev;
	unsigned int    st_ino;
	unsigned int    st_mode;
	unsigned int    st_nlink;
	unsigned int    st_uid;
	unsigned int    st_gid;
	unsigned int    st_rdev;
	long            st_size;
	unsigned long   st_atime;
	unsigned long   st_mtime;
	unsigned long   st_ctime;
	unsigned int    st_blksize;
	int             st_blocks;
	unsigned int    st_flags;
	unsigned int    st_gen;
};

#define COPY_STAT(src, dest)                    \
do {                                            \
	memset((dest), 0, sizeof((*dest)));	\
	(dest)->st_dev     = (src)->st_dev;     \
	(dest)->st_ino     = (src)->st_ino;     \
	(dest)->st_mode    = (src)->st_mode;    \
	(dest)->st_nlink   = (src)->st_nlink;   \
	(dest)->st_uid     = (src)->st_uid;     \
	(dest)->st_gid     = (src)->st_gid;     \
	(dest)->st_rdev    = (src)->st_rdev;    \
	(dest)->st_size    = (src)->st_size;    \
	(dest)->st_atime   = (src)->st_atime;   \
	(dest)->st_mtime   = (src)->st_mtime;   \
	(dest)->st_ctime   = (src)->st_ctime;   \
	(dest)->st_blksize = (src)->st_blksize; \
	(dest)->st_blocks  = (src)->st_blocks;  \
	(dest)->st_flags   = (src)->st_flags;   \
	(dest)->st_gen     = (src)->st_gen;     \
} while (0);

#else 
#define __native_stat intnl_stat
#define COPY_STAT(src, dest) *(dest) = *(src) 
#endif

#if defined(USE_NATIVE_STAT)
#define __SYS_STAT SYS_lstat
#define __SYS_FSTAT SYS_fstat
#define __SYS_TRUNCATE SYS_truncate
#define __SYS_FTRUNCATE SYS_ftruncate
#else
#define __SYS_STAT SYS_lstat64
#define __SYS_FSTAT SYS_fstat64
#define __SYS_TRUNCATE SYS_truncate64
#define __SYS_FTRUNCATE SYS_ftruncate64
#endif

#if defined(USE_NATIVE_FDATASYNC)
#define __SYS_FDATASYNC SYS_osf_fdatasync
#else
#define __SYS_FDATASYNC SYS_fdatasync
#endif

#if defined(USE_NATIVE_UTIME)
#define __SYS_UTIME SYS_utimes
#else
#define __SYS_UTIME SYS_utime
#endif

/*
 * Native file identifiers format.
 */
struct native_inode_identifier {
	dev_t	dev;					/* device number */
	ino_t	ino;					/* i-number */
#ifdef HAVE_GENERATION
	unsigned int gen;                               /* generation number */
#endif
};

/*
 * Driver-private i-node information we keep about local host file
 * system objects.
 */
struct native_inode {
	unsigned
		ni_seekok		: 1;		/* can seek? */
	struct native_inode_identifier ni_ident;	/* unique identifier */
	struct file_identifier ni_fileid;		/* ditto */
	int	ni_fd;					/* host fildes */
	int	ni_oflags;				/* flags, from open */
	unsigned ni_nopens;				/* soft ref count */
	_SYSIO_OFF_T ni_fpos;				/* current pos */
};

/*
 * Native IO path arguments.
 */
struct native_io {
	char	nio_op;					/* 'r' or 'w' */
	struct native_inode *nio_nino;			/* native ino */
};

static int native_inop_lookup(struct pnode *pno,
			      struct inode **inop,
			      struct intent *intnt,
			      const char *path);
static int native_inop_getattr(struct pnode *pno,
			       struct inode *ino,
			       struct intnl_stat *stbuf);
static int native_inop_setattr(struct pnode *pno,
			       struct inode *ino,
			       unsigned mask,
			       struct intnl_stat *stbuf);
static ssize_t native_getdirentries(struct inode *ino,
				    char *buf,
				    size_t nbytes,
				    _SYSIO_OFF_T *basep);
static int native_inop_mkdir(struct pnode *pno, mode_t mode);
static int native_inop_rmdir(struct pnode *pno);
static int native_inop_symlink(struct pnode *pno, const char *data);
static int native_inop_readlink(struct pnode *pno, char *buf, size_t bufsiz);
static int native_inop_open(struct pnode *pno, int flags, mode_t mode);
static int native_inop_close(struct inode *ino);
static int native_inop_link(struct pnode *old, struct pnode *new);
static int native_inop_unlink(struct pnode *pno);
static int native_inop_rename(struct pnode *old, struct pnode *new);
static int native_inop_read(struct inode *ino, struct ioctx *ioctx);
static int native_inop_write(struct inode *ino, struct ioctx *ioctx);
static _SYSIO_OFF_T native_inop_pos(struct inode *ino, _SYSIO_OFF_T off);
static int native_inop_iodone(struct ioctx *ioctx);
static int native_inop_fcntl(struct inode *ino, int cmd, va_list ap);
static int native_inop_sync(struct inode *ino);
static int native_inop_datasync(struct inode *ino);
static int native_inop_ioctl(struct inode *ino,
			     unsigned long int request,
			     va_list ap);
static int native_inop_mknod(struct pnode *pno, mode_t mode, dev_t dev);
#ifdef _HAVE_STATVFS
static int native_inop_statvfs(struct pnode *pno,
			       struct inode *ino,
			       struct intnl_statvfs *buf);
#endif
static void native_inop_gone(struct inode *ino);

static struct inode_ops native_i_ops = {
	native_inop_lookup,
	native_inop_getattr,
	native_inop_setattr,
	native_getdirentries,
	native_inop_mkdir,
	native_inop_rmdir,
	native_inop_symlink,
	native_inop_readlink,
	native_inop_open,
	native_inop_close,
	native_inop_link,
	native_inop_unlink,
	native_inop_rename,
	native_inop_read,
	native_inop_write,
	native_inop_pos,
	native_inop_iodone,
	native_inop_fcntl,
	native_inop_sync,
	native_inop_datasync,
	native_inop_ioctl,
	native_inop_mknod,
#ifdef _HAVE_STATVFS
	native_inop_statvfs,
#endif
	native_inop_gone
};

static int native_fsswop_mount(const char *source,
			       unsigned flags,
			       const void *data,
			       struct pnode *tocover,
			       struct mount **mntp);

static struct fssw_ops native_fssw_ops = {
	native_fsswop_mount
};

static void native_fsop_gone(struct filesys *fs);

static struct filesys_ops native_inodesys_ops = {
	native_fsop_gone,
};

/*
 * This example driver plays a strange game. It maintains a private,
 * internal mount -- It's own separate, rooted, name space. The local
 * file system's entire name space is available via this tree.
 *
 * This simplifies the implementation. At mount time, we need to generate
 * a path-node to be used as a root. This allows us to look up the needed
 * node in the host name space and leverage a whole lot of support from
 * the system.
 */
static struct mount *native_internal_mount = NULL;

/*
 * Given i-node, return driver private part.
 */
#define I2NI(ino)	((struct native_inode *)((ino)->i_private))

/*
 * stat -- by path.
 */
static int
native_stat(const char *path, struct intnl_stat *buf)
{
	int	err;
	struct __native_stat stbuf;

	err = syscall(__SYS_STAT, path, &stbuf);
	if (err)
		err = -errno;
	COPY_STAT(&stbuf, buf);

	return err;
}

/*
 * stat -- by fildes
 */
static int
native_fstat(int fd, struct intnl_stat *buf)
{
	int	err;
	struct __native_stat stbuf;

	err = syscall(__SYS_FSTAT, fd, &stbuf);
	if (err)
		err = -errno;
	COPY_STAT(&stbuf, buf);

	return err;
}

/*
 * Introduce an i-node to the system.
 */
static struct inode *
native_i_new(struct filesys *fs, struct intnl_stat *buf)
{
	struct native_inode *nino;
	struct inode *ino;

	nino = malloc(sizeof(struct native_inode));
	if (!nino)
		return NULL;
	bzero(&nino->ni_ident, sizeof(nino->ni_ident));
	nino->ni_ident.dev = buf->st_dev;
	nino->ni_ident.ino = buf->st_ino;
#ifdef HAVE_GENERATION
	nino->ni_ident.gen = buf->st_gen;
#endif
	nino->ni_fileid.fid_data = &nino->ni_ident;
	nino->ni_fileid.fid_len = sizeof(nino->ni_ident);
	nino->ni_fd = -1;
	nino->ni_oflags = 0;
	nino->ni_nopens = 0;
	nino->ni_fpos = 0;
	ino =
	    _sysio_i_new(fs,
			 &nino->ni_fileid,
#ifndef AUTOMOUNT_FILE_NAME
			 buf->st_mode & S_IFMT,
#else
			 buf->st_mode,			/* all of the bits! */
#endif
			 0,
			 0,
			 &native_i_ops,
			 nino);
	if (!ino)
		free(nino);
	return ino;
}

/*
 * Initialize this driver.
 */
int
_sysio_native_init()
{

	/*
	 * Capture current process umask and reset our process umask to
	 * zero. All permission bits to open/creat/setattr are absolute --
	 * They've already had a umask applied, when appropriate.
	 */
	_sysio_umask = syscall(SYS_umask, 0);

	return _sysio_fssw_register("native", &native_fssw_ops);
}

/*
 * Create private, internal, view of the hosts name space.
 */
static int
create_internal_namespace()
{
	int	err;
	struct mount *mnt;
	struct inode *rootino;
	struct pnode_base *rootpb;
	static struct qstr noname = { NULL, 0, 0 };
	struct filesys *fs;
	struct intnl_stat stbuf;

	if (native_internal_mount) {
		/*
		 * Reentered!
		 */
		abort();
	}

	/*
	 * We maintain an artificial, internal, name space in order to
	 * have access to fully qualified path names in the various routines.
	 * Initialize that name space now.
	 */
	mnt = NULL;
	rootino = NULL;
	rootpb = NULL;
	fs = _sysio_fs_new(&native_inodesys_ops, 0, NULL);
	if (!fs) {
		err = -ENOMEM;
		goto error;
	}

	/*
	 * Get root i-node.
	 */
	err = native_stat("/", &stbuf);
	if (err)
		goto error;
	rootino = native_i_new(fs, &stbuf);
	if (!rootino) {
		err = -ENOMEM;
		goto error;
	}

	/*
	 * Generate base path-node for root.
	 */
	rootpb = _sysio_pb_new(&noname, NULL, rootino);
	if (!rootpb) {
		err = -ENOMEM;
		goto error;
	}

	/*
	 * Mount it. This name space is disconnected from the
	 * rest of the system -- Only available within this driver.
	 */
	err = _sysio_do_mount(fs, rootpb, 0, NULL, &mnt);
	if (err)
		goto error;

	native_internal_mount = mnt;
	return 0;
error:
	if (mnt) {
		if (_sysio_do_unmount(mnt) != 0)
			abort();
		fs = NULL;
		rootpb = NULL;
		rootino = NULL;
	}
	if (rootpb)
		_sysio_pb_gone(rootpb);
	if (fs) {
		FS_RELE(fs);
		_sysio_fs_gone(fs);
	}

	return err;
}

static int
native_fsswop_mount(const char *source,
		    unsigned flags,
		    const void *data __IS_UNUSED,
		    struct pnode *tocover,
		    struct mount **mntp)
{
	int	err;
	struct nameidata nameidata;
	struct mount *mnt;

	/*
	 * Caller must use fully qualified path names when specifying
	 * the source.
	 */
	if (*source != '/')
		return -ENOENT;

	if (!native_internal_mount) {
		err = create_internal_namespace();
		if (err)
			return err;
	}

	/*
	 * Lookup the source in the internally maintained name space.
	 */
	ND_INIT(&nameidata, 0, source, native_internal_mount->mnt_root, NULL);
	err = _sysio_path_walk(native_internal_mount->mnt_root, &nameidata);
	if (err)
		return err;

	/*
	 * Have path-node specified by the given source argument. Let the
	 * system finish the job, now.
	 */
	err =
	    _sysio_do_mount(native_internal_mount->mnt_fs,
			    nameidata.nd_pno->p_base,
			    flags,
			    tocover,
			    &mnt);
	/*
	 * Release the internal name space pnode and clean up any
	 * aliases we might have generated. We really don't need to cache them
	 * as they are only used at mount time..
	 */
	P_RELE(nameidata.nd_pno);
	(void )_sysio_p_prune(native_internal_mount->mnt_root);

	if (!err) {
		FS_REF(native_internal_mount->mnt_fs);
		*mntp = mnt;
	}
	return err;
}

static int
native_i_invalid(struct inode *inop, struct intnl_stat stbuf)
{
	/*
	 * Validate passed in inode against stat struct info
	 */
	struct native_inode *nino = I2NI(inop);
	
	if ((nino->ni_ident.dev != stbuf.st_dev ||
	     nino->ni_ident.ino != stbuf.st_ino ||
#ifdef HAVE_GENERATION
	     nino->ni_ident.gen != stbuf.st_gen ||
#endif
	     ((inop)->i_mode & S_IFMT) != (stbuf.st_mode & S_IFMT)) ||
	    (((inop)->i_rdev != stbuf.st_rdev) &&
	       (S_ISCHR((inop)->i_mode) || S_ISBLK((inop)->i_mode))))
		return 1;
	
	return 0;
}

/*
 * Find, and validate, or create i-node by host-relative path. Returned i-node
 * is referenced.
 */
static int
native_iget(struct filesys *fs,
	    const char *path,
	    struct inode **inop,
	    int forced)
{
	int	err;
	struct inode *ino;
	struct intnl_stat stbuf;
	struct native_inode_identifier ident;
	struct file_identifier fileid;

	/*
	 * Get file status.
	 */
	err = native_stat(path, &stbuf);
	if (err) {
		*inop = NULL;
		return err;
	}

	/* 
	 * Validate?
	 */
	if (*inop) {
		if (!native_i_invalid(*inop, stbuf))
			return 0;
		/*
		 * Invalidate.
		 */
		*inop = NULL;
	}

	/*
	 * I-node is not already known. Find or create it.
	 */
	bzero(&ident, sizeof(ident)); 
	ident.dev = stbuf.st_dev;
	ident.ino = stbuf.st_ino;
#ifdef HAVE_GENERATION
	ident.gen = stbuf.st_gen;
#endif
	fileid.fid_data = &ident;
	fileid.fid_len = sizeof(ident);
	ino = _sysio_i_find(fs, &fileid);
	if (ino && forced) {
		/*
		 * Insertion was forced but it's already present!
		 */
		if (native_i_invalid(ino, stbuf)) {
			/* 
			 * Cached inode has stale attrs
			 * make way for the new one
			 */
			I_GONE(ino);
			ino = NULL;
		} else
			/* 
			 * OK to reuse cached inode
			 */
			goto out;
	}

	if (!ino) {
		ino = native_i_new(fs, &stbuf);
		if (!ino)
			err = -ENOMEM;
	}
out:
	if (!err)
		*inop = ino;
	return err;
}

/*
 * Look up named object in host's name space by path.
 */
static int
native_path_lookup(struct filesys *fs, const char *path, struct inode **inop)
{

	return native_iget(fs, path, inop, 0);
}

/*
 * Look up object by it's path node.
 */
static int
native_i_lookup(struct filesys *fs, struct pnode_base *pb, struct inode **inop)
{
	int	err;
	char	*path;

	path = _sysio_pb_path(pb, '/');
	if (!path)
		return -ENOMEM;
	err = native_path_lookup(fs, path, inop);
	free(path);
	return err;
}

static int
native_inop_lookup(struct pnode *pno,
		   struct inode **inop,
		   struct intent *intnt __IS_UNUSED,
		   const char *path __IS_UNUSED)
{
	int	err;

	*inop = pno->p_base->pb_ino;

	/*
	 * Don't have an inode yet. Because we translate everything back to
	 * a single name space for the host, we will assume the object the
	 * caller is looking for has no existing alias in our internal
	 * name space. We don't see the same file on different mounts in the
	 * underlying host FS as the same file.
	 *
	 * The file identifier *will* be unique. It's got to have a different
	 * dev.
	 */
	err = native_i_lookup(pno->p_mount->mnt_fs, pno->p_base, inop);
	if (err)
		*inop = NULL;
	return err;
}

static int
native_inop_getattr(struct pnode *pno, struct inode *ino, struct intnl_stat *stbuf)
{
	char	*path;
	int	err;

	path = NULL;
	if (!ino || I2NI(ino)->ni_fd < 0) {
		path = _sysio_pb_path(pno->p_base, '/');
		if (!path)
			return -ENOMEM;
	}
	err =
	    path
	      ? native_stat(path, stbuf)
	      : native_fstat(I2NI(ino)->ni_fd, stbuf);
	if (path)
		free(path);
	return err;
}

static int
native_inop_setattr(struct pnode *pno,
		    struct inode *ino,
		    unsigned mask,
		    struct intnl_stat *stbuf)
{
	char	*path;
	int	fd;
	struct intnl_stat st;
	int	err;

	path = NULL;
	fd = ino ? I2NI(ino)->ni_fd : -1;
	if (fd < 0 || mask & (SETATTR_MTIME|SETATTR_ATIME)) {
		if (!pno)
			return -EEXIST;
		path = _sysio_pb_path(pno->p_base, '/');
		if (!path)
			return -ENOMEM;
	}

	/*
	 * Get current status for undo.
	 */
	err =
	    fd < 0
	      ? native_stat(path, &st)
	      : native_fstat(fd, &st);
	if (err)
		goto out;

	if (mask & SETATTR_MODE) {
		mode_t	mode;

		/*
		 * Alter permissions attribute.
		 */
		mode = stbuf->st_mode & 07777;
		err =
		    fd < 0
		      ? syscall(SYS_chmod, path, mode)
		      : syscall(SYS_fchmod, fd, mode);
		if (err)
			err = -errno;
	}
	if (err)
		mask &= ~SETATTR_MODE;
	else if (mask & (SETATTR_MTIME|SETATTR_ATIME)) {
		struct utimbuf ut;

		/*
		 * Alter access and/or modify time attributes.
		 */
		ut.actime = st.st_atime;
		ut.modtime = st.st_mtime;
		if (mask & SETATTR_MTIME)
			ut.modtime = stbuf->st_mtime;
		if (mask & SETATTR_ATIME)
			ut.actime = stbuf->st_atime;
		err = syscall(__SYS_UTIME, path, &ut);
		if (err)
			err = -errno;
	}
	if (err)
		mask &= ~(SETATTR_MTIME|SETATTR_ATIME);
	else if (mask & (SETATTR_UID|SETATTR_GID)) {

		/*
		 * Alter owner and/or group identifiers.
		 */
		err =
		    fd < 0
		      ? syscall(SYS_chown,
				path,
				mask & SETATTR_UID
				  ? stbuf->st_uid
				  : (uid_t )-1,
				mask & SETATTR_GID
				  ? stbuf->st_gid
				  : (gid_t )-1)
		      : syscall(SYS_fchown,
				fd,
				mask & SETATTR_UID
				  ? stbuf->st_uid
				  : (uid_t )-1,
				mask & SETATTR_GID
				  ? stbuf->st_gid
				  : (gid_t )-1);
		if (err)
			err = -errno;
	}
	if (err)
		mask &= ~(SETATTR_UID|SETATTR_GID);
	else if (mask & SETATTR_LEN) {
		/*
		 * Do the truncate last. It can't be undone.
		 */
		 (void )(fd < 0
			   ? syscall(__SYS_TRUNCATE, path, stbuf->st_size)
			   : syscall(__SYS_FTRUNCATE, fd, stbuf->st_size));
	}
	if (!err)
		goto out;
	/*
	 * Undo after error. Some or all of this might not work... We
	 * can but try.
	 */
	if (mask & (SETATTR_UID|SETATTR_GID)) {
		 (void )(fd < 0
			   ? syscall(SYS_chown,
				     path,
				     mask & SETATTR_UID
				       ? st.st_uid
				       : (uid_t )-1,
				     mask & SETATTR_GID
				       ? st.st_gid
				       : (gid_t )-1)
			   : syscall(SYS_fchown,
				     fd,
				     mask & SETATTR_UID
				       ? st.st_uid
				       : (uid_t )-1,
				     mask & SETATTR_GID
				       ? st.st_gid
				       : (gid_t )-1));
	}
	if (mask & (SETATTR_MTIME|SETATTR_ATIME)) {
		struct utimbuf ut;

		ut.actime = st.st_atime;
		ut.modtime = st.st_mtime;
		(void )syscall(__SYS_UTIME, path, &ut);
	}
	if (mask & SETATTR_MODE) {
		fd < 0
		  ? syscall(SYS_chmod, path, st.st_mode & 07777)
		  : syscall(SYS_fchmod, fd, st.st_mode & 07777);
	}
out:
	if (path)
		free(path);
	return err;
}

static int
native_pos(int fd, _SYSIO_OFF_T *offset, int whence)
{
	_SYSIO_OFF_T off;

	assert(fd >= 0);
	assert(*offset >= 0);

	off = *offset;
#if _LARGEFILE64_SOURCE && defined(SYS__llseek)
	{
		int	err;
		err =
		    syscall(SYS__llseek,
			    (unsigned int)fd,
			    (unsigned int)(off >> 32),
			    (unsigned int)off,
			    &off,
			    whence);
		if (err == -1)
			return -errno;
	}
#else
	off =
	    syscall(SYS_lseek,
		    fd,
		    off,
		    whence);
	if (off == -1)
		return -errno;
#endif
	*offset = off;

	return 0;
}

static ssize_t
native_filldirentries(struct native_inode *nino,
		      char *buf,
		      size_t nbytes,
		      _SYSIO_OFF_T *basep)
{
	int	err;
	ssize_t	cc;

	if (*basep < 0)
		return -EINVAL;

#if DIR_STREAMED
	/*
	 * Stream-oriented access requires that we reposition prior to the
	 * fill call.
	 */
	if ((err = native_pos(nino->ni_fd, basep, SEEK_SET)) != 0)
		return err;
#endif
	nino->ni_fpos = *basep;

	cc =
#if defined(SYS_getdirentries)
	    syscall(SYS_getdirentries,
		    nino->ni_fd,
		    buf,
		    nbytes,
		    basep);
#elif defined(SYS_getdents64)
	    syscall(SYS_getdents64, nino->ni_fd, buf, nbytes);
#elif defined(SYS_getdents)
	    syscall(SYS_getdents, nino->ni_fd, buf, nbytes);
#endif

	if (cc < 0)
		return -errno;
#if DIR_STREAMED
	/*
	 * Stream-oriented access requires that we discover where we are
	 * after the call.
	 */
	*basep = 0;
	if ((err = native_pos(nino->ni_fd, basep, SEEK_CUR)) != 0)
		return err;
#endif
	nino->ni_fpos = *basep;
	return cc;
}

static ssize_t
native_getdirentries(struct inode *ino,
		     char *buf,
		     size_t nbytes,
		     _SYSIO_OFF_T *basep)
{
	struct native_inode *nino = I2NI(ino);
#if DIR_CVT_64
	char	*bp;
	size_t	count;
	struct linux_dirent *ldp;
	struct dirent64 *d64p;
	size_t	namlen;
	size_t	reclen;
#else
#define bp buf
#define count nbytes
#endif
	ssize_t	cc;

	assert(nino->ni_fd >= 0);

#if DIR_CVT_64
	count = nbytes;
	while (!(bp = malloc(count))) {
		count /= 2;
		if (count < sizeof(struct dirent))
			return -ENOMEM;
	}
#endif
	cc = native_filldirentries(nino, bp, count, basep);
	if (cc < 0) {
#if DIR_CVT_64
		free(bp);
#endif
		return cc;
	}
#if DIR_CVT_64
	ldp = (struct linux_dirent *)bp;
	d64p = (struct dirent64 *)buf;
	for (;;) {
		if (cc < 0 || (size_t )cc <= sizeof(*ldp))
			break;
		namlen = strlen(ldp->ld_name);
		reclen = sizeof(*d64p) - sizeof(d64p->d_name) + namlen + 1;
		if (nbytes < reclen)
			break;
		d64p->d_ino = ldp->ld_ino;
		d64p->d_off = ldp->ld_off;
		d64p->d_reclen = 
		    (((reclen + sizeof(long) - 1)) / sizeof(long)) *
		    sizeof(long);
		if (nbytes < d64p->d_reclen)
			d64p->d_reclen = reclen;
		d64p->d_type = DT_UNKNOWN;		/* you lose -- sorry. */
		(void )strncpy(d64p->d_name, ldp->ld_name, namlen);
		*(d64p->d_name + namlen) = '\0';
		cc -= ldp->ld_reclen;
		ldp = (struct linux_dirent *)((char *)ldp + ldp->ld_reclen);
		nbytes -= d64p->d_reclen;
		d64p = (struct dirent64 *)((char *)d64p + d64p->d_reclen);
	}
	free(bp);
	if (d64p == (struct dirent64 *)buf && cc)
		cc = -EINVAL;				/* buf too small */
	cc = (char *)d64p - buf;
#else
#undef bp
#undef count
#endif
	return cc;
}

static int
native_inop_mkdir(struct pnode *pno, mode_t mode)
{
	char	*path;
	int	err;

	path = _sysio_pb_path(pno->p_base, '/');
	if (!path)
		return -ENOMEM;

	err = syscall(SYS_mkdir, path, mode);
	if (err != 0)
		err = -errno;
	free(path);
	return err;
}

static int
native_inop_rmdir(struct pnode *pno)
{
	char	*path;
	int	err;

	path = _sysio_pb_path(pno->p_base, '/');
	if (!path)
		return -ENOMEM;

	err = syscall(SYS_rmdir, path);
	if (err != 0)
		err = -errno;
	free(path);
	return err;
}

static int
native_inop_symlink(struct pnode *pno, const char *data)
{
	char	*path;
	int	err;

	path = _sysio_pb_path(pno->p_base, '/');
	if (!path)
		return -ENOMEM;

	err = syscall(SYS_symlink, data, path);
	if (err != 0)
		err = -errno;
	free(path);
	return err;
}

static int
native_inop_readlink(struct pnode *pno, char *buf, size_t bufsiz)
{
	char	*path;
	int	i;

	path = _sysio_pb_path(pno->p_base, '/');
	if (!path)
		return -ENOMEM;
	i = syscall(SYS_readlink, path, buf, bufsiz);
	if (i < 0)
		i = -errno;
	free(path);
	return i;
}

static int 
native_inop_open(struct pnode *pno, int flags, mode_t mode)
{
	struct native_inode *nino;
	char	*path;
	int	fd;

	path = _sysio_pb_path(pno->p_base, '/');
	if (!path)
		return -ENOMEM;

	/*
	 * Whether the file is already open, or not, makes no difference.
	 * Want to always give the host OS a chance to authorize in case
	 * something has changed underneath us.
	 */
	if (flags & O_WRONLY) {
		/*
		 * Promote write-only attempt to RW.
		 */
		flags &= ~O_WRONLY;
		flags |= O_RDWR;
	}
#ifdef O_LARGEFILE
	flags |= O_LARGEFILE;
#endif
	fd = syscall(SYS_open, path, flags, mode);
	if (!pno->p_base->pb_ino && fd >= 0) {
		int	err;

		/*
		 * Success but we need to return an i-node.
		 */
		err =
		    native_iget(pno->p_mount->mnt_fs,
				path,
				&pno->p_base->pb_ino,
				1);
		if (err) {
			(void )syscall(SYS_close, fd);
			if (err == -EEXIST)
				abort();
			fd = err;
		}
	}
	free(path);
	if (fd < 0)
		return -errno;

	/*
	 * Remember this new open.
	 */
	nino = I2NI(pno->p_base->pb_ino);
	nino->ni_nopens++;
	assert(nino->ni_nopens);

	if (nino->ni_fd >= 0) {
		if ((nino->ni_oflags & O_RDWR) ||
		    (flags & (O_RDONLY|O_WRONLY|O_RDWR)) == O_RDONLY) {
			/*
			 * Keep existing.
			 */
			(void )syscall(SYS_close, fd);
			return 0;
		}
		(void )syscall(SYS_close, nino->ni_fd);
	}
	/*
	 * Invariant; First open. Must init.
	 */
	nino->ni_fpos = 0;
	nino->ni_fd = fd;
	/*
	 * Need to know whether we can seek on this
	 * descriptor.
	 */
	nino->ni_seekok =
	    native_pos(nino->ni_fd, &nino->ni_fpos, SEEK_CUR) != 0 ? 0 : 1;

	return 0;
}

static int
native_inop_close(struct inode *ino)
{
	struct native_inode *nino = I2NI(ino);
	int	err;

	if (nino->ni_fd < 0)
		abort();

	assert(nino->ni_nopens);
	if (--nino->ni_nopens) {
		/*
		 * Hmmm. We really don't need anything else. However, some
		 * filesystems try to implement a sync-on-close semantic.
		 * As this appears now, that is lost. Might want to change
		 * it somehow in the future?
		 */
		return 0;
	}

	err = syscall(SYS_close, nino->ni_fd);
	if (err)
		return -errno;

	nino->ni_fd = -1;
	nino->ni_fpos = 0;
	return 0;
}

static int
native_inop_link(struct pnode *old, struct pnode *new)
{
	int	err;
	char	*opath, *npath;

	err = 0;

	opath = _sysio_pb_path(old->p_base, '/');
	npath = _sysio_pb_path(new->p_base, '/');
	if (!(opath && npath)) {
		err = -ENOMEM;
		goto out;
	}

	err = syscall(SYS_link, opath, npath);
	if (err != 0)
		err = -errno;

out:
	if (opath)
		free(opath);
	if (npath)
		free(npath);

	return err;
}

static int
native_inop_unlink(struct pnode *pno)
{
	char	*path;
	int	err = 0;

	path = _sysio_pb_path(pno->p_base, '/');
	if (!path)
		return -ENOMEM;

	/*
	 * For this driver, unlink is easy with open files. Since the
	 * file remains open to the system, too, the descriptors are still
	 * valid.
	 *
	 * Other drivers will have some difficulty here as the entry in the
	 * file system name space must be removed without sacrificing access
	 * to the file itself. In NFS this is done with a mechanism referred
	 * to as a `silly delete'. The file is moved to a temporary name
	 * (usually .NFSXXXXXX, where the X's are replaced by the PID and some
	 * unique characters) in order to simulate the proper semantic.
	 */
	if (syscall(SYS_unlink, path) != 0)
		err = -errno;
	free(path);
	return err;
}

static int
native_inop_rename(struct pnode *old, struct pnode *new)
{
	int	err;
	char	*opath, *npath;

	opath = _sysio_pb_path(old->p_base, '/');
	npath = _sysio_pb_path(new->p_base, '/');
	if (!(opath && npath)) {
		err = -ENOMEM;
		goto out;
	}

	err = syscall(SYS_rename, opath, npath);
	if (err != 0)
		err = -errno;

out:
	if (opath)
		free(opath);
	if (npath)
		free(npath);

	return err;
}

static ssize_t
dopio(void *buf, size_t count, _SYSIO_OFF_T off, struct native_io *nio)
{
#if defined(_LARGEFILE64_SOURCE) && \
    defined(SYS_pread64) && \
    defined(SYS_pwrite64)
#define _NATIVE_SYSCALL_PREAD SYS_pread64
#define _NATIVE_SYSCALL_PWRITE SYS_pwrite64
#else
#define _NATIVE_SYSCALL_PREAD SYS_pread
#define _NATIVE_SYSCALL_PWRITE SYS_pwrite
#endif
	ssize_t	cc;

	if (!(off == nio->nio_nino->ni_fpos || nio->nio_nino->ni_seekok))
		return -ESPIPE;
		
	if (!nio->nio_nino->ni_seekok) {
		if (off != nio->nio_nino->ni_fpos) {
			/*
			 * They've done a p{read,write} or somesuch. Can't
			 * seek on this descriptor so we err out now.
			 */
			errno = ESPIPE;
			return -1;
		}
		cc =
		    syscall(nio->nio_op == 'r' ? SYS_read : SYS_write,
			    nio->nio_nino->ni_fd,
			    buf,
			    count);
		if (cc > 0)
			nio->nio_nino->ni_fpos += cc;
	} else
		cc =
		    syscall((nio->nio_op == 'r'
			       ? _NATIVE_SYSCALL_PREAD
			       : _NATIVE_SYSCALL_PWRITE),
			    nio->nio_nino->ni_fd,
			    buf,
			    count,
			    off);

	return cc;
#undef _NATIVE_SYSCALL_PREAD
#undef _NATIVE_SYSCALL_PWRITE
}

static ssize_t
doiov(const struct iovec *iov,
      int count,
      _SYSIO_OFF_T off,
      ssize_t limit,
      struct native_io *nio)
{
	ssize_t	cc;

#if !(defined(REDSTORM) || defined(MAX_IOVEC))
#define MAX_IOVEC	INT_MAX
#endif

	if (count <= 0)
		return -EINVAL;

	/*
	 * Avoid the reposition call if we're already at the right place.
	 * Allows us to access pipes and fifos.
	 */
	if (off != nio->nio_nino->ni_fpos) {
		int	err;

		err = native_pos(nio->nio_nino->ni_fd, &off, SEEK_SET);
		if (err)
			return err;
		nio->nio_nino->ni_fpos = off;
	}

	/*
	 * The {read,write}v is safe as this routine is only ever called
	 * by _sysio_enumerate_extents() and that routine is exact. It never
	 * passes iovectors including tails.
	 */
	cc =
#ifndef REDSTORM
	    count <= MAX_IOVEC
	      ? syscall(nio->nio_op == 'r' ? SYS_readv : SYS_writev,
			nio->nio_nino->ni_fd,
			iov,
			count)
	      :
#endif
	        _sysio_enumerate_iovec(iov,
				       count,
				       off,
				       limit,
				       (ssize_t (*)(void *,
						    size_t,
						    _SYSIO_OFF_T,
						    void *))dopio,
				       nio);
	if (cc < 0)
		cc = -errno;
	else
		nio->nio_nino->ni_fpos += cc;
	return cc;

#if !(defined(REDSTORM) || defined(MAX_IOVEC))
#undef MAX_IOVEC
#endif
}

#if 0
static int
lockop_all(struct native_inode *nino,
	   struct intnl_xtvec *xtv,
	   size_t count,
	   short op)
{
	struct flock flock;
	int	err;

	if (!count)
		return -EINVAL;
	flock.l_type = op;
	flock.l_whence = SEEK_SET;
	while (count--) {
		flock.l_start = xtv->xtv_off;
		flock.l_len = xtv->xtv_len;
		xtv++;
		err =
		    syscall(
#if !_LARGEFILE64_SOURCE
			    SYS_fcntl64
#else
			    SYS_fcntl
#endif
			    ,
			    nino->ni_fd,
			    F_SETLK,
			    &flock);
		if (err != 0)
			return -errno;
	}
	return 0;
}

static int
order_xtv(const struct intnl_xtvec *xtv1, const struct intnl_xtvec *xtv2)
{

	if (xtv1->xtv_off < xtv2->xtv_off)
		return -1;
	if (xtv1->xtv_off > xtv2->xtv_off)
		return 1;
	return 0;
}
#endif

static int
doio(char op, struct ioctx *ioctx)
{
	struct native_inode *nino;
#if 0
	int	dolocks;
	struct intnl_xtvec *oxtv;
	int	err;
#endif
	struct native_io arguments;
	ssize_t	cc;
#if 0
	struct intnl_xtvec *front, *rear, tmp;
#endif

	nino = I2NI(ioctx->ioctx_ino);
#if 0
	dolocks = ioctx->ioctx_xtvlen > 1 && nino->ni_seekok;
	if (dolocks) {
		/*
		 * Must lock the regions (in order!) since we can't do
		 * strided-IO as a single atomic operation.
		 */
		oxtv = malloc(ioctx->ioctx_xtvlen * sizeof(struct intnl_xtvec));
		if (!oxtv)
			return -ENOMEM;
		(void )memcpy(oxtv,
			      ioctx->ioctx_xtv, 
			      ioctx->ioctx_xtvlen * sizeof(struct intnl_xtvec));
		qsort(oxtv,
		      ioctx->ioctx_xtvlen,
		      sizeof(struct intnl_xtvec),
		      (int (*)(const void *, const void *))order_xtv);
		err =
	            lockop_all(nino,
			       oxtv, ioctx->ioctx_xtvlen,
			       op == 'r' ? F_RDLCK : F_WRLCK);
		if (err) {
			free(oxtv);
			return err;
		}
	}
#endif
	arguments.nio_op = op;
	arguments.nio_nino = nino;
	cc =
	    _sysio_enumerate_extents(ioctx->ioctx_xtv, ioctx->ioctx_xtvlen, 
				     ioctx->ioctx_iov, ioctx->ioctx_iovlen,
				     (ssize_t (*)(const struct iovec *,
						  int,
						  _SYSIO_OFF_T,
						  ssize_t,
						  void *))doiov,
				     &arguments);
#if 0
	if (dolocks) {
		/*
		 * Must unlock in reverse order.
		 */
		front = oxtv;
		rear = front + ioctx->ioctx_xtvlen - 1;
		while (front < rear) {
			tmp = *front;
			*front++ = *rear;
			*rear-- = tmp;
		}
		if (lockop_all(nino, oxtv, ioctx->ioctx_xtvlen, F_UNLCK) != 0)
			abort();
		free(oxtv);
	}
#endif
	if ((ioctx->ioctx_cc = cc) < 0) {
		ioctx->ioctx_errno = -ioctx->ioctx_cc;
		ioctx->ioctx_cc = -1;
	}
	return 0;
}

static int
native_inop_read(struct inode *ino __IS_UNUSED, struct ioctx *ioctx)
{

	return doio('r', ioctx);
}

static int
native_inop_write(struct inode *ino __IS_UNUSED, struct ioctx *ioctx)
{

	return doio('w', ioctx);
}

static _SYSIO_OFF_T
native_inop_pos(struct inode *ino, _SYSIO_OFF_T off)
{
	struct native_inode *nino = I2NI(ino);
	int	err;

	err = native_pos(nino->ni_fd, &off, SEEK_SET);
	return err < 0 ? err : off;
}

static int
native_inop_iodone(struct ioctx *ioctxp __IS_UNUSED)
{

	/*
	 * It's always done in this driver. It completed when posted.
	 */
	return 1;
}

static int
native_inop_fcntl(struct inode *ino,
		  int cmd,
		  va_list ap)
{
	struct native_inode *nino = I2NI(ino);
	long	arg;
	int	err;

	if (nino->ni_fd < 0)
		abort();

	switch (cmd) {
	case F_GETFD:
	case F_GETFL:
	case F_GETOWN:
		err = syscall(SYS_fcntl, nino->ni_fd, cmd);
		if (err < 0)
			err = -errno;
	case F_DUPFD:
	case F_SETFD:
	case F_SETFL:
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
	case F_SETOWN:
		arg = va_arg(ap, long);
		err = syscall(SYS_fcntl, nino->ni_fd, cmd, arg);
		if (err)
			err = -errno;
	default:
		err = -EINVAL;
	}
	return err;
}

static int
native_inop_mknod(struct pnode *pno __IS_UNUSED,
		  mode_t mode __IS_UNUSED,
		  dev_t dev __IS_UNUSED)
{

	return -ENOSYS;
}

#ifdef _HAVE_STATVFS
static int
native_inop_statvfs(struct pnode *pno,
		    struct inode *ino,
		    struct intnl_statvfs *buf)
{
	char	*path;
	int    rc;
	struct statfs fs;

	path = NULL;
	if (!ino || I2NI(ino)->ni_fd < 0) {
		path = _sysio_pb_path(pno->p_base, '/');
		if (!path)
			return -ENOMEM;
	}

	/*
	 * The syscall interface does not support SYS_fstatvfs.
	 * Should possibly return ENOSYS, but thought it
	 * better to use SYS_fstatfs and fill in as much of
	 * the statvfs structure as possible.  This allows
	 * for more of a test of the sysio user interface.
	 */
	rc =
	    path
	      ? syscall(SYS_statfs, path, &fs)
	      : syscall(SYS_fstatfs, I2NI(ino)->ni_fd, &fs);
	if (path)
		free(path);
	if (rc < 0)
		return -errno;

	buf->f_bsize = fs.f_bsize;  /* file system block size */
	buf->f_frsize = fs.f_bsize; /* file system fundamental block size */
	buf->f_blocks = fs.f_blocks;
	buf->f_bfree = fs.f_bfree;
	buf->f_bavail = fs.f_bavail;
	buf->f_files = fs.f_files;  /* Total number serial numbers */
	buf->f_ffree = fs.f_ffree;  /* Number free serial numbers */
	buf->f_favail = fs.f_ffree; /* Number free ser num for non-privileged*/
	buf->f_fsid = fs.f_fsid.__val[1];
	buf->f_flag = 0;            /* No equiv in statfs; maybe use type? */
	buf->f_namemax = fs.f_namelen;
	return 0;
}
#endif

static int
native_inop_sync(struct inode *ino)
{
	int	err;

	assert(I2NI(ino)->ni_fd >= 0);

	err = syscall(SYS_fsync, I2NI(ino)->ni_fd);
	if (err)
		err = -errno;
	return err;
}

static int
native_inop_datasync(struct inode *ino)
{
	int	err;

	assert(I2NI(ino)->ni_fd >= 0);

#ifdef NATIVE_FDATASYNC
	err = syscall(NATIVE_FDATASYNC, I2NI(ino)->ni_fd);
#else
#if 0
#warning No fdatasync system call -- Using fsync instead!
#endif
	err = syscall(SYS_fsync, I2NI(ino)->ni_fd);
#endif
	if (err)
		err = -errno;
	return err;
}

static int
native_inop_ioctl(struct inode *ino __IS_UNUSED,
		  unsigned long int request __IS_UNUSED,
		  va_list ap __IS_UNUSED)
{

	/*
	 * I'm lazy. Maybe implemented later.
	 */
	errno = ENOTTY;
	return -1;
}

static void
native_inop_gone(struct inode *ino)
{
	struct native_inode *nino = I2NI(ino);

	if (nino->ni_fd >= 0)
		(void )syscall(SYS_close, nino->ni_fd);
	free(ino->i_private);
}

static void
native_fsop_gone(struct filesys *fs __IS_UNUSED)
{

	/*
	 * Do nothing. There is no private part maintained for the
	 * native file interface.
	 */
}
