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
 *    Cplant(TM) Copyright 1998-2003 Sandia Corporation. 
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
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#if 0
#include <sys/vfs.h>
#endif
#ifdef _HAVE_STATVFS
#include <sys/statvfs.h>
#endif
#include <utime.h>
#include <sys/queue.h>

#include "xtio.h"
#include "sysio.h"
#include "fs.h"
#include "mount.h"
#include "inode.h"

#include "fs_yod.h"

/*
 * Remote file system driver
 * calls are re-directed to the initiating yod
 */
#include "cplant-yod.h"

/* stat struct used by yod, which
 * is not compiled with __USE_FILE_OFFSET64
 */
#define __yod_stat stat
#ifdef ALPHA_LINUX
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
} while (0)
#else
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
} while (0)
#endif

/*
 * Yod file identifiers format.
 */
struct yod_inode_identifier {
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
struct yod_inode {
	unsigned ni_seekok		: 1;		/* can seek? */
	struct yod_inode_identifier ni_ident;	        /* unique identifier */
	struct file_identifier ni_fileid;		/* ditto */
	int	ni_fd;					/* host fildes */
	int	ni_oflags;				/* flags, from open */
	unsigned ni_nopens;				/* soft ref count */
	_SYSIO_OFF_T ni_fpos;				/* current pos */
};

static int yod_inop_lookup(struct pnode *pno,
			      struct inode **inop,
			      struct intent *intnt,
			      const char *path);
static int yod_inop_getattr(struct pnode *pno,
			       struct inode *ino,
			       struct intnl_stat *stbuf);
static int yod_inop_setattr(struct pnode *pno,
			       struct inode *ino,
			       unsigned mask,
			       struct intnl_stat *stbuf);
static ssize_t yod_filldirentries(struct inode *ino,
				  off64_t *posp,
				  char *buf,
				  size_t nbytes);
static int yod_inop_mkdir(struct pnode *pno, mode_t mode);
static int yod_inop_rmdir(struct pnode *pno);
static int yod_inop_symlink(struct pnode *pno, const char *data);
static int yod_inop_readlink(struct pnode *pno, char *buf, size_t bufsiz);
static int yod_inop_open(struct pnode *pno, int flags, mode_t mode);
static int yod_inop_close(struct inode *ino);
static int yod_inop_link(struct pnode *old, struct pnode *new);
static int yod_inop_unlink(struct pnode *pno);
static int yod_inop_rename(struct pnode *old, struct pnode *new);
static _SYSIO_OFF_T yod_inop_pos (struct inode *ino, _SYSIO_OFF_T off);  
static int yod_inop_read(struct inode *ino, struct ioctx *ioctx);
static int yod_inop_write(struct inode *ino, struct ioctx *ioctx);
static int yod_inop_iodone(struct ioctx *ioctx);
static int yod_inop_fcntl(struct inode *ino, int cmd, va_list ap, int *rtn);
static int yod_inop_sync(struct inode *ino);
static int yod_inop_datasync(struct inode *ino);
static int yod_inop_ioctl(struct inode *ino,
			     unsigned long int request,
			     va_list ap);
static int yod_inop_mknod(struct pnode *pno, mode_t mode, dev_t dev);
#ifdef _HAVE_STATVFS
static int yod_inop_statvfs(struct pnode *pno,
			       struct inode *ino,
			       struct intnl_statvfs *buf);
#endif
static void yod_inop_gone(struct inode *ino);

static struct inode_ops yod_i_ops = {
	yod_inop_lookup,
	yod_inop_getattr,
	yod_inop_setattr,
	yod_filldirentries,
	yod_inop_mkdir,
	yod_inop_rmdir,
	yod_inop_symlink,
	yod_inop_readlink,
	yod_inop_open,
	yod_inop_close,
	yod_inop_link,
	yod_inop_unlink,
	yod_inop_rename,
	yod_inop_read,
	yod_inop_write,
	yod_inop_pos,
	yod_inop_iodone,
	yod_inop_fcntl,
	yod_inop_sync,
	yod_inop_datasync,
	yod_inop_ioctl,
	yod_inop_mknod,
#ifdef _HAVE_STATVFS
	yod_inop_statvfs,
#endif
	yod_inop_gone
};

static int yod_fsswop_mount(const char *source,
			       unsigned flags,
			       const void *data,
			       struct pnode *tocover,
			       struct mount **mntp);

static struct fssw_ops yod_fssw_ops = {
	yod_fsswop_mount
};

static void yod_fsop_gone(struct filesys *fs);

static struct filesys_ops yod_inodesys_ops = {
	yod_fsop_gone
};

/* 
 * Placeholder internal mount as in native driver
 */
static struct mount *yod_internal_mount = NULL;

/*
 * Given i-node, return driver private part.
 */
#define I2NI(ino)	((struct yod_inode *)((ino)->i_private))

/*
 * stat -- by path.
 */
static int
yod_stat(const char *path, struct intnl_stat *buf)
{
	int	err;
	struct __yod_stat stbuf;
	
	err = stat_yod(path, &stbuf); 
	if (err)
		err = -errno;
	COPY_STAT(&stbuf, buf);

	return err;
}

/*
 * stat -- by fildes
 */
static int
yod_fstat(int fd, struct intnl_stat *buf)
{
	int	err;
	struct __yod_stat stbuf;

	err = fstat_yod(fd, &stbuf);
	if (err)
		err = -errno;
	COPY_STAT(&stbuf, buf);

	return err;
}

/*
 * Introduce an i-node to the system.
 */
static struct inode *
yod_i_new(struct filesys *fs, struct intnl_stat *buf)
{
	struct yod_inode *nino;
	struct inode *ino;

	nino = malloc(sizeof(struct yod_inode));
	if (!nino)
		return NULL;
	bzero(&nino->ni_ident, sizeof(nino->ni_ident));
	nino->ni_seekok = 0;
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
			 buf,
			 0,
			 &yod_i_ops,
			 nino);
	if (!ino)
		free(nino);
	return ino;
}

/*
 * Initialize this driver.
 */
int
_sysio_yod_init()
{

	/*
	 * Capture current process umask and reset our process umask to
	 * zero. All permission bits to open/creat/setattr are absolute --
	 * They've already had a umask applied, when appropriate.
	 */
	_sysio_umask = syscall(SYS_umask, 0);

	return _sysio_fssw_register("yod", &yod_fssw_ops);
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

	if (yod_internal_mount) {
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
	fs = _sysio_fs_new(&yod_inodesys_ops, 0, NULL);
	if (!fs) {
		err = -ENOMEM;
		goto error;
	}

	/*
	 * Get root i-node.
	 */
	err = yod_stat("/", &stbuf);
	if (err)
		goto error;
	rootino = yod_i_new(fs, &stbuf);
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

	yod_internal_mount = mnt;
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
	}

	return err;
}

static int
yod_fsswop_mount(const char *source,
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

	if (!yod_internal_mount) {
		err = create_internal_namespace();
		if (err)
			return err;
	}

	/*
	 * Lookup the source in the internally maintained name space.
	 */
	ND_INIT(&nameidata, 0, source, yod_internal_mount->mnt_root, NULL);
	err = _sysio_path_walk(yod_internal_mount->mnt_root, &nameidata);
	if (err)
		return err;

	/*
	 * Have path-node specified by the given source argument. Let the
	 * system finish the job, now.
	 */
	err =
	    _sysio_do_mount(yod_internal_mount->mnt_fs,
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
	(void )_sysio_p_prune(yod_internal_mount->mnt_root);

	if (!err) {
		FS_REF(yod_internal_mount->mnt_fs);
		*mntp = mnt;
	}
	return err;
}

static int
yod_i_invalid(struct inode *inop, struct intnl_stat *stat)
{
	/*
	 * Validate passed in inode against stat struct info
	 */
	struct yod_inode *nino = I2NI(inop);
	
	if ((nino->ni_ident.dev != stat->st_dev ||
	     nino->ni_ident.ino != stat->st_ino ||
#ifdef HAVE_GENERATION
	     nino->ni_ident.gen != stat->st_gen ||
#endif
	     ((inop)->i_stbuf.st_mode & S_IFMT) != (stat->st_mode & S_IFMT)) ||
	    (((inop)->i_stbuf.st_rdev != stat->st_rdev) &&
	       (S_ISCHR((inop)->i_stbuf.st_mode) ||
		S_ISBLK((inop)->i_stbuf.st_mode))))
		return 1;
	
	return 0;
}

/*
 * Find, and validate, or create i-node by host-relative path. Returned i-node
 * is referenced.
 */
static int
yod_iget(struct filesys *fs,
	    const char *path,
	    struct inode **inop,
	    int forced)
{
	int	err;
	struct inode *ino;
	struct intnl_stat stbuf;
	struct yod_inode_identifier ident;
	struct file_identifier fileid;

	/*
	 * Get file status.
	 */
	err = yod_stat(path, &stbuf);
	if (err) {
		*inop = NULL;
		return err;
	}

	/*
	 * Validate?
	 */
	if (*inop) {
		if (!yod_i_invalid(*inop, &stbuf))
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
		if (yod_i_invalid(ino, &stbuf)) {
			/* 
			 * Cached inode has stale attrs
			 * make way for the new one
			 */
			I_RELE(ino);
			_sysio_i_undead(ino);
			ino = NULL;
		} else
			/* 
			 * OK to reuse cached inode
			 */
			goto out;
	}

	if (!ino) {
		ino = yod_i_new(fs, &stbuf);
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
yod_path_lookup(struct filesys *fs, const char *path, struct inode **inop)
{

	return yod_iget(fs, path, inop, 0);
}

/*
 * Look up object by it's path node.
 */
static int
yod_i_lookup(struct filesys *fs, struct pnode_base *pb, struct inode **inop)
{
	int	err;
	char	*path;

	path = _sysio_pb_path(pb, '/');
	if (!path)
		return -ENOMEM;
	err = yod_path_lookup(fs, path, inop);
	free(path);
	return err;
}

static int
yod_inop_lookup(struct pnode *pno,
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
	err = yod_i_lookup(pno->p_mount->mnt_fs, pno->p_base, inop);
	if (err)
		*inop = NULL;
	return err;
}

static int
yod_inop_getattr(struct pnode *pno, struct inode *ino, struct intnl_stat *stbuf)
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
	      ? yod_stat(path, stbuf)
	      : yod_fstat(I2NI(ino)->ni_fd, stbuf);
	if (path)
		free(path);
	return err;
}

static int
yod_inop_setattr(struct pnode *pno,
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
	      ? yod_stat(path, &st)
	      : yod_fstat(fd, &st);
	if (err)
		goto out;

	if (mask & SETATTR_MODE) {
		mode_t	mode;

		/*
		 * Alter permissions attribute.
		 */
		mode = stbuf->st_mode & 07777;
		err = chmod_yod(path, mode);
	}
	if (err)
		mask &= ~SETATTR_MODE;

	if (mask & (SETATTR_UID|SETATTR_GID)) {

		/*
		 * Alter owner and/or group identifiers.
		 */
		err = chown_yod(path,
				mask & SETATTR_UID
				  ? stbuf->st_uid
				  : (uid_t )-1,
				mask & SETATTR_GID
				  ? stbuf->st_gid
				  : (gid_t )-1);
	}
	if (err)
		mask &= ~(SETATTR_UID|SETATTR_GID);
	else if (mask & SETATTR_LEN) {
		/*
		 * Do the truncate last. It can't be undone.
		 */
		 (void )(fd < 0
			   ? truncate_yod(path, stbuf->st_size)
			   : ftruncate_yod(fd, stbuf->st_size));
	}
	if (!err)
		goto out;
	/*
	 * Undo after error. Some or all of this might not work... We
	 * can but try.
	 */
	if (mask & (SETATTR_UID|SETATTR_GID)) {
		 (void )chown_yod(path,
				  mask & SETATTR_UID
				    ? st.st_uid
				    : (uid_t )-1,
				  mask & SETATTR_GID
				    ? st.st_gid
				    : (gid_t )-1);
	}
	if (mask & SETATTR_MODE) {
		chmod_yod(path, st.st_mode & 07777);
	}
out:
	if (path)
		free(path);
	return err;
}

static ssize_t
yod_filldirentries(struct inode *ino,
		   char *buf,
		   _SYSIO_OFF_T *posp,
		    size_t nbytes)
{
	struct yod_inode *nino = I2NI(ino);
	_SYSIO_OFF_T result;
	ssize_t	cc;

	assert(nino->ni_fd >= 0);

	result = *basep;
	if (*basep != nino->ni_fpos &&
	    (result = lseek_yod(nino->ni_fd,
				*posp,
				SEEK_SET) == -1))
		return -errno;
	nino->ni_fpos = result;
	memset(buf, 0, nbytes);
	/*
	 * This is almost certainly broken. The resulting position parameter
	 * points to the block just filled, not the next.
	 */
	cc = getdirentries_yod(nino->ni_fd, buf, nbytes, &result);
	if (cc < 0)
		return -errno;
	nino->ni_fpos = *posp = result;
	return cc;
}

static int
yod_inop_mkdir(struct pnode *pno, mode_t mode)
{
	char	*path;
	int	err;

	path = _sysio_pb_path(pno->p_base, '/');
	if (!path)
		return -ENOMEM;

	err = mkdir_yod(path, mode);
	free(path);
	return err;
}

static int
yod_inop_rmdir(struct pnode *pno)
{
	char	*path;
	int	err;

	path = _sysio_pb_path(pno->p_base, '/');
	if (!path)
		return -ENOMEM;

	err = rmdir_yod(path);
	free(path);
	return err;
}

static int
yod_inop_symlink(struct pnode *pno, const char *data)
{
	char	*path;
	int	err;

	path = _sysio_pb_path(pno->p_base, '/');
	if (!path)
		return -ENOMEM;

	err = symlink_yod(data, path);
	free(path);
	return err;
}

static int
yod_inop_readlink(struct pnode *pno __IS_UNUSED, 
		  char *buf __IS_UNUSED, 
		  size_t bufsiz __IS_UNUSED)
{

	return -ENOSYS;
}

static int
yod_inop_open(struct pnode *pno, int flags, mode_t mode)
{
	struct yod_inode *nino;
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
	fd = open_yod(path, flags, mode);
	if (!pno->p_base->pb_ino && fd >= 0) {
		int	err;

		/*
		 * Success but we need to return an i-node.
		 */
		err =
		    yod_iget(pno->p_mount->mnt_fs,
				path,
				&pno->p_base->pb_ino,
				1);
		if (err) {
			(void )close_yod(fd);
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
			(void )close_yod(fd);
			return 0;
		}
		(void )close_yod(nino->ni_fd);
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
            lseek_yod(nino->ni_fd, 0, SEEK_CUR) != 0 ? 0 : 1;

	return 0;
}

static int
yod_inop_close(struct inode *ino)
{
	struct yod_inode *nino = I2NI(ino);
	int	err;

	if (nino->ni_fd < 0)
		abort();

	assert(nino->ni_nopens);
	if (--nino->ni_nopens)
		return 0;

	err = close_yod(nino->ni_fd);
	if (err)
		return -errno;

	nino->ni_fd = -1;
	nino->ni_fpos = 0;
	return 0;
}

static int
yod_inop_link(struct pnode *old, struct pnode *new)
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

	err = link_yod(opath, npath);

out:
	if (opath)
		free(opath);
	if (npath)
		free(npath);

	return err;
}

static int
yod_inop_unlink(struct pnode *pno)
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
	if (unlink_yod(path) != 0)
		err = -errno;
	free(path);
	return err;
}

/*
 * A helper function performing the real IO operation work.
 *
 * We don't really have async IO. We'll just perform the function
 * now.
 */
static int
doio(ssize_t (*f)(void *, size_t, _SYSIO_OFF_T, struct yod_inode *),
	struct ioctx *ioctx)
{
	struct yod_inode *nino = I2NI(ioctx->ioctx_ino);

	ioctx->ioctx_cc =
		_sysio_doio(ioctx->ioctx_xtv, ioctx->ioctx_xtvlen,
			    ioctx->ioctx_iov, ioctx->ioctx_iovlen,
			    (ssize_t (*)(void *, size_t, 
					 _SYSIO_OFF_T, void *))f,
			    nino);
	if (ioctx->ioctx_cc < 0) {
		ioctx->ioctx_errno = -ioctx->ioctx_cc;
		ioctx->ioctx_cc = -1;
		return -1;
	}
	nino->ni_fpos += ioctx->ioctx_cc;
	ioctx->ioctx_done = 1;
	return 0;
}       

static ssize_t
yod_read_simple(void *buf,
	 	size_t nbytes,
		_SYSIO_OFF_T off,
		struct yod_inode *nino)
{
	if (off != nino->ni_fpos) {
		_SYSIO_OFF_T rtn;

		rtn = lseek_yod(nino->ni_fd, off, SEEK_SET);
	 	if (rtn < 0) 
			return -1;
		nino->ni_fpos = rtn;
	}
	return read_yod(nino->ni_fd, buf, nbytes);
}

static int
yod_inop_read(struct inode *ino __IS_UNUSED, struct ioctx *ioctx)
{

	return doio(yod_read_simple, ioctx);
}

static int
yod_inop_rename(struct pnode *old, struct pnode *new)
{
	int	err;
	char	*opath, *npath;

	opath = _sysio_pb_path(old->p_base, '/');
	npath = _sysio_pb_path(new->p_base, '/');
	if (!(opath && npath)) {
		err = -ENOMEM;
		goto out;
	}

	err = rename_yod(opath, npath);

out:
	if (opath)
		free(opath);
	if (npath)
		free(npath);

	return err;
}

static ssize_t
yod_write_simple(void *buf,
	 	size_t nbytes,
		_SYSIO_OFF_T off,
		struct yod_inode *nino)
{

	if (off != nino->ni_fpos) {
		_SYSIO_OFF_T rtn;

		rtn = lseek_yod(nino->ni_fd, off, SEEK_SET);
	 	if (rtn < 0) 
			return -1;
		nino->ni_fpos = rtn;
	}
	return write_yod(nino->ni_fd, buf, nbytes);
}

static int
yod_inop_write(struct inode *ino __IS_UNUSED, struct ioctx *ioctx)
{

	return doio(yod_write_simple, ioctx);
}

static _SYSIO_OFF_T
yod_inop_pos(struct inode *ino, _SYSIO_OFF_T off)
{
	struct yod_inode *nino = I2NI(ino);
	int	err;

	err = lseek_yod(nino->ni_fd, off, SEEK_SET);
	return err < 0 ? err : off;
}

static int
yod_inop_iodone(struct ioctx *ioctxp __IS_UNUSED)
{

	/*
	 * It's always done in this driver. It completed when posted.
	 */
	return 1;
}

static int
yod_inop_fcntl(struct inode *ino, int cmd, va_list ap, int *rtn)
{
	struct yod_inode *nino = I2NI(ino);
	long	arg;
	int	err;

	if (nino->ni_fd < 0)
		abort();

	err = 0;
	switch (cmd) {
	case F_GETFD:
	case F_GETFL:
#ifdef F_GETOWN
	case F_GETOWN:
#endif
		*rtn = syscall(SYS_fcntl, nino->ni_fd, cmd);
		if (*rtn == -1)
			err = -errno;
		break;
	case F_DUPFD:
	case F_SETFD:
	case F_SETFL:
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
#ifdef F_SETOWN
	case F_SETOWN:
#endif
		arg = va_arg(ap, long);
		*rtn = syscall(SYS_fcntl, nino->ni_fd, cmd, arg);
		if (*rtn == -1)
			err = -errno;
		break;
	default:
		*rtn = -1;
		err = -EINVAL;
	}
	return err;
}

static int
yod_inop_mknod(struct pnode *pno __IS_UNUSED,
		  mode_t mode __IS_UNUSED,
		  dev_t dev __IS_UNUSED)
{

	return -ENOSYS;
}

#ifdef _HAVE_STATVFS
static int
yod_inop_statvfs(struct pnode *pno,
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
	      ? statfs_yod(path, &fs)
	      : fstatfs_yod(I2NI(ino)->ni_fd, &fs);
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
yod_inop_sync(struct inode *ino)
{

	assert(I2NI(ino)->ni_fd >= 0);

	return fsync_yod(I2NI(ino)->ni_fd);
}

static int
yod_inop_datasync(struct inode *ino)
{

	assert(I2NI(ino)->ni_fd >= 0);

	return fsync_yod(I2NI(ino)->ni_fd);
}

static int
yod_inop_ioctl(struct inode *ino __IS_UNUSED,
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
yod_inop_gone(struct inode *ino)
{
	struct yod_inode *nino = I2NI(ino);

	if (nino->ni_fd)
		(void )close(nino->ni_fd);
	free(ino->i_private);
}

static void
yod_fsop_gone(struct filesys *fs __IS_UNUSED)
{

	/*
	 * Do nothing. There is no private part maintained for the
	 * yod file interface. 
	 */
}
