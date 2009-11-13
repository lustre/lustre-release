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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/queue.h>

#include "sysio.h"
#include "xtio.h"
#include "file.h"
#include "inode.h"

#include "sysio-symbols.h"

#define IIOXOP_READ(ino)	(ino)->i_ops.inop_read, 0
#define IIOXOP_WRITE(ino)	(ino)->i_ops.inop_write, 1

/*
 * Decoding the interface routine names:
 *
 * Much of this carries legacy from the POSIX world and the Intel ASCI
 * Red programming environment. Routine names are composed of prefix,
 * basic POSIX names, and postfix. The basic POSIX names are read and write.
 * Prefixes, left-to-right:
 *
 *	- 'i' -- asynchronous operation (from ASCI Red)
 *	- 'p' -- positional (POSIX)
 * Posfixes, only one:
 *	- 'v' -- vectored (POSIX)
 *	- 'x' -- extent-based (new for Red Storm)
 *
 * All valid combinations are available and symmetric.
 */

/*
 * Post op using iovec with regions specified by the passed extent vector.
 *
 * NOTE: There are enough parameters that we should really consider
 * passing them in a structure.
 */
static int
_sysio_iiox(int (*f)(struct inode *, struct ioctx *),
	    int wr,
	    struct file *fil,
	    const struct iovec *iov,
	    size_t iov_count,
	    void (*iov_free)(struct ioctx *),
	    const struct intnl_xtvec *xtv,
	    size_t xtv_count,
	    void (*xtv_free)(struct ioctx *),
	    void (*completio)(struct ioctx *, void *),
	    struct ioctx **ioctxp)
{
	struct inode *ino;
	ssize_t	cc;
	struct ioctx *ioctx;
	int	err;
	struct ioctx_callback *cb;

	/*
	 * Check that it was opened with flags supporting the operation.
	 */
	if (!F_CHKRW(fil, wr ? 'w' : 'r'))
		return -EBADF;

	ino = fil->f_ino;
	if (!ino) {
		/*
		 * Huh? It's dead.
		 */
		return -EBADF;
	}
	cc =
	    _sysio_validx(xtv, xtv_count,
			  iov, iov_count,
#if defined(_LARGEFILE64_SOURCE) && defined(O_LARGEFILE)
			  (fil->f_flags & O_LARGEFILE) == 0
			    ? LONG_MAX
			    :
#endif
			  _SYSIO_OFF_T_MAX);
	if (cc < 0)
		return cc;
	ioctx = _sysio_ioctx_new(ino, wr, iov, iov_count, xtv, xtv_count);
	if (!ioctx)
		return -ENOMEM;
	if ((iov_free &&
	     (err = _sysio_ioctx_cb(ioctx,
				    (void (*)(struct ioctx *,
					      void *))iov_free,
				    NULL))) ||
	    (xtv_free &&
	     (err = _sysio_ioctx_cb(ioctx,
				    (void (*)(struct ioctx *,
					      void *))xtv_free,
				    NULL))) ||
	    (completio &&
	     (err = _sysio_ioctx_cb(ioctx,
				    (void (*)(struct ioctx *,
					      void *))completio,
				    fil))) ||
	    (err = (*f)(ino, ioctx))) {
		/*
		 * Release the callback queue. Don't want it run after all.
		 */
		while ((cb = ioctx->ioctx_cbq.tqh_first)) {
			TAILQ_REMOVE(&ioctx->ioctx_cbq,
				     cb,
				     iocb_next);
			_sysio_ioctx_cb_free(cb);
		}
		_sysio_ioctx_complete(ioctx);
		return err;
	}
	*ioctxp = ioctx;
	return 0;
}

/*
 * Sum iovec entries, returning total found or error if range of ssize_t would
 * be exceeded.
 */
static ssize_t
_sysio_sum_iovec(const struct iovec *iov, int count)
{
	ssize_t	tmp, cc;

	if (count <= 0)
		return -EINVAL;

	cc = 0;
	while (count--) {
		tmp = cc;
		cc += iov->iov_len;
		if (tmp && iov->iov_len && cc <= tmp)
			return -EINVAL;
		iov++;
	}
	return cc;
}

/*
 * Asynch IO from/to iovec from/to current file offset.
 */
static int
_sysio_iiov(int (*f)(struct inode *, struct ioctx *),
	    int wr,
	    struct file *fil,
	    const struct iovec *iov,
	    int count,
	    void (*iov_free)(struct ioctx *),
	    struct intnl_xtvec *xtv,
	    void (*xtv_free)(struct ioctx *),
	    struct ioctx **ioctxp)
{
	ssize_t	cc;
	_SYSIO_OFF_T off;
	int	err;

	cc = _sysio_sum_iovec(iov, count);
	if (cc < 0)
		return (int )cc;
	xtv->xtv_off = fil->f_pos;
	xtv->xtv_len = cc;
	off = xtv->xtv_off + xtv->xtv_len;
	if (xtv->xtv_off && off <= xtv->xtv_off) {
		/*
		 * Ouch! The IO vector specifies more bytes than
		 * are addressable. Trim the region to limit how
		 * much of the IO vector is finally transferred.
		 */
		xtv->xtv_len = _SYSIO_OFF_T_MAX - xtv->xtv_off;
	}
	err =
	    _sysio_iiox(f,
			wr,
			fil,
			iov, count, iov_free,
			xtv, 1, xtv_free,
			(void (*)(struct ioctx *, void *))_sysio_fcompletio,
			ioctxp);
	if (err)
		return err;
	return 0;
}

static void
free_xtv(struct ioctx *ioctx)
{

	free((struct iovec *)ioctx->ioctx_xtv);
	ioctx->ioctx_iov = NULL;
}

ioid_t
SYSIO_INTERFACE_NAME(ireadv)(int fd, const struct iovec *iov, int count)
{
	struct file *fil;
	struct intnl_xtvec *xtv;
	struct ioctx *ioctx;
	int	err;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -EBADF);

	xtv = malloc(sizeof(struct intnl_xtvec));
	if (!xtv)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -ENOMEM);

	err =
	    _sysio_iiov(IIOXOP_READ(fil->f_ino),
			fil,
			iov, count, NULL,
			xtv, free_xtv,
			&ioctx);
	if (err) {
		free(xtv);
		SYSIO_INTERFACE_RETURN(IOID_FAIL, err);
	}
	SYSIO_INTERFACE_RETURN(ioctx, 0);
}

ssize_t
SYSIO_INTERFACE_NAME(readv)(int fd, const struct iovec *iov, int count)
{
	struct file *fil;
	struct intnl_xtvec xtvector;
	struct ioctx *ioctx;
	int	err;
	ssize_t	cc;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(-1, -EBADF);

	err =
	    _sysio_iiov(IIOXOP_READ(fil->f_ino),
			fil,
			iov, count, NULL,
			&xtvector, NULL,
			&ioctx);
	if (!err && (cc = _sysio_ioctx_wait(ioctx)) < 0)
		err = (int )cc;

	SYSIO_INTERFACE_RETURN(err ? -1 : cc, err);
}

#if defined(__GLIBC__)
#undef __readv
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(readv), 
		     PREPEND(__, SYSIO_INTERFACE_NAME(readv)))
#undef __libc_readv
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(readv),
		     PREPEND(__, SYSIO_INTERFACE_NAME(libc_readv)))
#endif

static void
free_iov(struct ioctx *ioctx)
{

	free((struct iovec *)ioctx->ioctx_iov);
	ioctx->ioctx_iov = NULL;
}

ioid_t
SYSIO_INTERFACE_NAME(iread)(int fd, void *buf, size_t count)
{
	struct iovec *iov;
	struct file *fil;
	struct intnl_xtvec *xtv;
	struct ioctx *ioctx;
	int	err;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -EBADF);

	iov = malloc(sizeof(struct iovec));
	if (!iov)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -ENOMEM);

	iov->iov_base = buf;
	iov->iov_len = count;
	xtv = malloc(sizeof(struct intnl_xtvec));
	if (!xtv) {
		free(iov);
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -ENOMEM);
	}
	err =
	    _sysio_iiov(IIOXOP_READ(fil->f_ino),
			fil,
			iov, 1, free_iov,
			xtv, free_xtv,
			&ioctx);
	if (err) {
		free(xtv);
		free(iov);
		SYSIO_INTERFACE_RETURN(IOID_FAIL, err);
	}
	SYSIO_INTERFACE_RETURN(ioctx, 0);
}

ssize_t
SYSIO_INTERFACE_NAME(read)(int fd, void *buf, size_t count)
{
	struct file *fil;
	struct iovec iovector;
	struct intnl_xtvec xtvector;
	int	err;
	struct ioctx *ioctx;
	ssize_t	cc;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(-1, -EBADF);

	iovector.iov_base = buf;
	iovector.iov_len = count;
	err =
	    _sysio_iiov(IIOXOP_READ(fil->f_ino),
			fil,
			&iovector, 1, NULL,
			&xtvector, NULL,
			&ioctx);
	if (!err && (cc = _sysio_ioctx_wait(ioctx)) < 0)
		err = (int )cc;
	SYSIO_INTERFACE_RETURN(err ? -1 : cc, err);
}

#ifdef __GLIBC__
#undef __read
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(read),
		     PREPEND(__, SYSIO_INTERFACE_NAME(read)))
#undef __libc_read
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(read),
		     PREPEND(__, SYSIO_INTERFACE_NAME(libc_read)))
#endif

/*
 * Asynch IO between iovec and data at the given offset.
 */
static int
_sysio_ipiov(int (*f)(struct inode *, struct ioctx *),
	     int wr,
	     struct file *fil,
	     const struct iovec *iov,
	     int count,
	     void (*iov_free)(struct ioctx *),
	     _SYSIO_OFF_T off,
	     struct intnl_xtvec *xtv,
	     void (*xtv_free)(struct ioctx *),
	     struct ioctx **ioctxp)
{
	ssize_t	cc;
	int	err;

	SYSIO_ENTER;
	cc = _sysio_sum_iovec(iov, count);
	if (cc < 0) {
		SYSIO_LEAVE;
		return (int )cc;
	}
	xtv->xtv_off = off,
	xtv->xtv_len = cc;
	err =
	    _sysio_iiox(f,
			wr,
			fil,
			iov, count, iov_free,
			xtv, 1, xtv_free,
			NULL,
			ioctxp);
	SYSIO_LEAVE;
	if (err)
		return err;
	return 0;
}

static ioid_t
PREPEND(_, SYSIO_INTERFACE_NAME(ipreadv))(int fd, 
					  const struct iovec *iov, 
					  size_t count, 
					  _SYSIO_OFF_T offset)
{
	struct file *fil;
	struct intnl_xtvec *xtv;
	struct ioctx *ioctx;
	int	err;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -EBADF);

	xtv = malloc(sizeof(struct intnl_xtvec));
	if (!xtv)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -ENOMEM);

	err =
	    _sysio_ipiov(IIOXOP_READ(fil->f_ino),
			 fil,
			 iov, count, NULL,
			 offset,
			 xtv, free_xtv,
			 &ioctx);
	if (err) {
		free(xtv);
		SYSIO_INTERFACE_RETURN(IOID_FAIL, err);
	}
	SYSIO_INTERFACE_RETURN(ioctx, 0);
}

#ifdef _LARGEFILE64_SOURCE
#undef ipread64v
sysio_sym_weak_alias(PREPEND(_, SYSIO_INTERFACE_NAME(ipreadv)),
		     SYSIO_INTERFACE_NAME(ipread64v))
#endif

ioid_t
SYSIO_INTERFACE_NAME(ipreadv)(int fd, 
			      const struct iovec *iov, 
			      size_t count, 
			      off_t offset)
{

	return PREPEND(_, SYSIO_INTERFACE_NAME(ipreadv))(fd, 
							 iov, 
							 count, 
							 offset);
}

static ssize_t
PREPEND(_, SYSIO_INTERFACE_NAME(preadv))(int fd, 
					 const struct iovec *iov, 
					 _SYSIO_PREADV_T count, 
					 _SYSIO_OFF_T offset)
{
	struct file *fil;
	struct intnl_xtvec xtvector;
	struct ioctx *ioctx;
	int	err;
	ssize_t	cc;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(-1, -EBADF);

	err =
	    _sysio_ipiov(IIOXOP_READ(fil->f_ino),
			 fil,
			 iov, count, NULL,
			 offset,
			 &xtvector, NULL,
			 &ioctx);
	if (!err && (cc = _sysio_ioctx_wait(ioctx)) < 0)
		err = (int )cc;

	SYSIO_INTERFACE_RETURN(err ? -1 : cc, err);
}

#ifdef _LARGEFILE64_SOURCE
#undef pread64v
sysio_sym_weak_alias(PREPEND(_, SYSIO_INTERFACE_NAME(preadv)), 
		     SYSIO_INTERFACE_NAME(pread64v))
#endif

ssize_t
SYSIO_INTERFACE_NAME(preadv)(int fd, 
			     const struct iovec *iov, 
			     _SYSIO_PREADV_T count, 
			     off_t offset)
{

	return PREPEND(_, SYSIO_INTERFACE_NAME(preadv))(fd, 
						        iov, 
						        count, 
						        offset);
}

static ioid_t
PREPEND(_, SYSIO_INTERFACE_NAME(ipread))(int fd, 
					 void *buf, 
					 size_t count, 
					 _SYSIO_OFF_T offset)
{
	struct file *fil;
	struct intnl_xtvec *xtv;
	struct iovec *iov;
	struct ioctx *ioctx;
	int	err;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -EBADF);

	xtv = malloc(sizeof(struct intnl_xtvec));
	iov = malloc(sizeof(struct iovec));
	if (!(xtv && iov)) {
		err = -ENOMEM;
		goto error;
	}
	xtv->xtv_off = offset;
	iov->iov_base = buf;
	xtv->xtv_len = iov->iov_len = count;
	err =
	    _sysio_ipiov(IIOXOP_READ(fil->f_ino),
			 fil,
			 iov, 1, free_iov,
			 offset,
			 xtv, free_xtv,
			 &ioctx);
error:
	if (err) {
		if (iov)
			free(iov);
		if (xtv)
			free(xtv);
		SYSIO_INTERFACE_RETURN(IOID_FAIL, err);
	}
	SYSIO_INTERFACE_RETURN(ioctx, 0);
}

#ifdef _LARGEFILE64_SOURCE
#undef ipread64
sysio_sym_weak_alias(PREPEND(_, SYSIO_INTERFACE_NAME(ipread)),
		     SYSIO_INTERFACE_NAME(ipread64))
#endif

ioid_t
SYSIO_INTERFACE_NAME(ipread)(int fd, 
			     void *buf, 
			     size_t count, 
			     off_t offset)
{

	return PREPEND(_, SYSIO_INTERFACE_NAME(ipread))(fd, 
			                                buf, 
						        count, 
						        offset);
}

ssize_t
PREPEND(_, SYSIO_INTERFACE_NAME(pread))(int fd, 
				        void *buf, 
				        size_t count, 
				        _SYSIO_OFF_T offset)
{
	struct file *fil;
	struct intnl_xtvec xtvec;
	struct iovec iovec;
	struct ioctx *ioctx;
	int	err;
	ssize_t	cc;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -EBADF);

	xtvec.xtv_off = offset;
	iovec.iov_base = buf;
	xtvec.xtv_len = iovec.iov_len = count;
	err =
	    _sysio_ipiov(IIOXOP_READ(fil->f_ino),
			 fil,
			 &iovec, 1, NULL,
			 offset,
			 &xtvec, NULL,
			 &ioctx);
	if (!err && (cc = _sysio_ioctx_wait(ioctx)) < 0)
		err = (int )cc;

	SYSIO_INTERFACE_RETURN(err ? -1 : cc, err);
}

#ifdef _LARGEFILE64_SOURCE
#undef pread64
sysio_sym_weak_alias(PREPEND(_, SYSIO_INTERFACE_NAME(pread)),
		     SYSIO_INTERFACE_NAME(pread64))
#if __GLIBC__
#undef __pread64
sysio_sym_weak_alias(PREPEND(_, SYSIO_INTERFACE_NAME(pread)), 
		     PREPEND(__, SYSIO_INTERFACE_NAME(pread64)))
#undef __libc_pread64
sysio_sym_weak_alias(PREPEND(_, SYSIO_INTERFACE_NAME(pread)),
		     PREPEND(__, SYSIO_INTERFACE_NAME(libc_pread64)))
#endif
#endif

ssize_t
SYSIO_INTERFACE_NAME(pread)(int fd, void *buf, size_t count, off_t offset)
{

	return PREPEND(_, SYSIO_INTERFACE_NAME(pread))(fd, 
						       buf, 
						       count, 
						       offset);
}

#if __GLIBC__
#undef __pread
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(pread), 
		     PREPEND(__, SYSIO_INTERFACE_NAME(pread)))
#undef __libc_pread
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(pread),
		     PREPEND(__, SYSIO_INTERFACE_NAME(libc_pread)))
#endif

static ioid_t
PREPEND(_, SYSIO_INTERFACE_NAME(ireadx))(int fd,
					 const struct iovec *iov, 
					 size_t iov_count, 
					 const struct intnl_xtvec *xtv, 
					 size_t xtv_count)
{
	struct file *fil;
	int	err;
	struct ioctx *ioctx;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -EBADF);

	/* Perform a check on the iov_count and xtv_count */
	if ((iov_count == 0) || (xtv_count == 0))
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -EINVAL);

	err =
	    _sysio_iiox(IIOXOP_READ(fil->f_ino),
			fil,
			iov, iov_count, NULL,
			xtv, xtv_count, NULL,
			NULL,
			&ioctx);

	SYSIO_INTERFACE_RETURN(err ? IOID_FAIL : ioctx, err);
}

#ifdef _LARGEFILE64_SOURCE
#undef iread64x
sysio_sym_weak_alias(PREPEND(_, SYSIO_INTERFACE_NAME(ireadx)),
		     SYSIO_INTERFACE_NAME(iread64x))
#endif

#ifdef _LARGEFILE64_SOURCE
ioid_t
SYSIO_INTERFACE_NAME(ireadx)(int fd,
			     const struct iovec *iov, size_t iov_count,
			     const struct xtvec *xtv, size_t xtv_count)
{
	struct file *fil;
	struct intnl_xtvec *ixtv, *ixtvent;
	size_t	count;
	int	err;
	struct ioctx *ioctx;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -EBADF);


	/* Perform a check on the iov_count and xtv_count */
	if ((iov_count == 0) || (xtv_count == 0))
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -EINVAL);

	ixtv = ixtvent = malloc(xtv_count * sizeof(struct intnl_xtvec));
	if (!ixtv)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -ENOMEM);

	count = xtv_count;
	while (count--) {
		ixtvent->xtv_off = xtv->xtv_off;
		ixtvent->xtv_len = xtv->xtv_len;
		ixtvent++;
		xtv++;
	}

	err =
	    _sysio_iiox(IIOXOP_READ(fil->f_ino),
			fil,
			iov, iov_count, NULL,
			ixtv, xtv_count, free_xtv,
			NULL,
			&ioctx);
	if (err) {
		free(ixtv);
		SYSIO_INTERFACE_RETURN(IOID_FAIL, err);
	}
	SYSIO_INTERFACE_RETURN(ioctx, 0);
}
#else
#undef ireadx
sysio_sym_weak_alias(PREPEND(_, SYSIO_INTERFACE_NAME(ireadx)),
		     SYSIO_INTERFACE_NAME(ireadx))
#endif

ssize_t
SYSIO_INTERFACE_NAME(readx)(int fd,
			    const struct iovec *iov, size_t iov_count,
			    const struct xtvec *xtv, size_t xtv_count)
{
	ioid_t	ioid;

	if ((ioid = SYSIO_INTERFACE_NAME(ireadx)(fd, 
						 iov, 
						 iov_count, 
						 xtv, 
						 xtv_count)) == IOID_FAIL)
		return -1;
	return SYSIO_INTERFACE_NAME(iowait)(ioid);
}

#ifdef _LARGEFILE64_SOURCE
#undef iread64x
ssize_t
SYSIO_INTERFACE_NAME(read64x)(int fd,
			      const struct iovec *iov, size_t iov_count,
			      const struct xtvec64 *xtv, size_t xtv_count)
{
	ioid_t	ioid;

	if ((ioid = SYSIO_INTERFACE_NAME(iread64x)(fd, 
						   iov, 
						   iov_count, 
						   xtv, 
						   xtv_count)) == IOID_FAIL)
		return -1;
	return SYSIO_INTERFACE_NAME(iowait)(ioid);
}
#endif

#ifdef notdef
int
read_list(int fd,
	  int mem_list_count,
	  char *mem_offsets[],
	  int mem_lengths[],
	  int file_list_count,
	  int64_t file_offsets[],
	  int32_t file_lengths[])
{
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	SYSIO_INTERFACE_RETURN(-1, -ENOSYS);
}
#endif

ioid_t
SYSIO_INTERFACE_NAME(iwritev)(int fd, 
			      const struct iovec *iov, 
			      int count)
{
	struct file *fil;
	struct intnl_xtvec *xtv;
	struct ioctx *ioctx;
	int	err;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -EBADF);

	xtv = malloc(sizeof(struct intnl_xtvec));
	if (!xtv)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -ENOMEM);

	err =
	    _sysio_iiov(IIOXOP_WRITE(fil->f_ino),
			fil,
			iov, count, NULL,
			xtv, free_xtv,
			&ioctx);
	if (err) {
		free(xtv);
		SYSIO_INTERFACE_RETURN(IOID_FAIL, err);
	}
	SYSIO_INTERFACE_RETURN(ioctx, 0);
}

ssize_t
SYSIO_INTERFACE_NAME(writev)(int fd, const struct iovec *iov,
			     int count)
{
	struct file *fil;
	struct intnl_xtvec xtvector;
	struct ioctx *ioctx;
	int	err;
	ssize_t	cc;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(-1, -EBADF);

	err =
	    _sysio_iiov(IIOXOP_WRITE(fil->f_ino),
			fil,
			iov, count, NULL,
			&xtvector, NULL,
			&ioctx);
	if (!err && (cc = _sysio_ioctx_wait(ioctx)) < 0)
		err = (int )cc;

	SYSIO_INTERFACE_RETURN(err < 0 ? -1 : cc, err);
}

#ifdef __GLIBC__
#undef __writev
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(writev),
		     PREPEND(__, SYSIO_INTERFACE_NAME(writev)))
#undef __libc_writev
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(writev),
		     PREPEND(__, SYSIO_INTERFACE_NAME(libc_writev)))
#endif

ioid_t
SYSIO_INTERFACE_NAME(iwrite)(int fd, const void *buf, size_t count)
{
	struct iovec *iov;
	struct file *fil;
	struct intnl_xtvec *xtv;
	struct ioctx *ioctx;
	int	err;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -EBADF);

	iov = malloc(sizeof(struct iovec));
	if (!iov)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -ENOMEM);

	iov->iov_base = (void *)buf;
	iov->iov_len = count;
	xtv = malloc(sizeof(struct intnl_xtvec));
	if (!xtv) {
		free(iov);
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -ENOMEM);
	}
	err =
	    _sysio_iiov(IIOXOP_WRITE(fil->f_ino),
			fil,
			iov, 1, free_iov,
			xtv, free_xtv,
			&ioctx);
	if (err) {
		free(xtv);
		free(iov);
		SYSIO_INTERFACE_RETURN(IOID_FAIL, err);
	}
	SYSIO_INTERFACE_RETURN(ioctx, 0);
}

ssize_t
SYSIO_INTERFACE_NAME(write)(int fd, const void *buf, size_t count)
{
	struct file *fil;
	struct iovec iovector;
	struct intnl_xtvec xtvector;
	int	err;
	struct ioctx *ioctx;
	ssize_t	cc;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(-1, -EBADF);

	iovector.iov_base = (void *)buf;
	iovector.iov_len = count;
	err =
	    _sysio_iiov(IIOXOP_WRITE(fil->f_ino),
			fil,
			&iovector, 1, NULL,
			&xtvector, NULL,
			&ioctx);
	if (!err && (cc = _sysio_ioctx_wait(ioctx)) < 0)
		err = (int )cc;

	SYSIO_INTERFACE_RETURN(err < 0 ? -1 : cc, err);
}

#ifdef __GLIBC__
#undef __write
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(write),
		     PREPEND(__, SYSIO_INTERFACE_NAME(write)))
#undef __libc_write
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(write),
		     PREPEND(__, SYSIO_INTERFACE_NAME(libc_write)))
#endif 

static ioid_t
PREPEND(_, SYSIO_INTERFACE_NAME(ipwritev))(int fd, 
					   const struct iovec *iov, 
					   size_t count, 
					   _SYSIO_OFF_T offset)
{
	struct file *fil;
	struct intnl_xtvec *xtv;
	struct ioctx *ioctx;
	int	err;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -EBADF);

	xtv = malloc(sizeof(struct intnl_xtvec));
	if (!xtv)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -ENOMEM);

	err =
	    _sysio_ipiov(IIOXOP_WRITE(fil->f_ino),
			 fil,
			 iov, count, NULL,
			 offset,
			 xtv, free_xtv,
			 &ioctx);
	if (err) {
		free(xtv);
		SYSIO_INTERFACE_RETURN(IOID_FAIL, err);
	}
	SYSIO_INTERFACE_RETURN(ioctx, 0);
}

#ifdef _LARGEFILE64_SOURCE
#undef ipwrite64v
sysio_sym_weak_alias(PREPEND(_, SYSIO_INTERFACE_NAME(ipwritev)),
		     SYSIO_INTERFACE_NAME(ipwrite64v))
#endif

ioid_t
SYSIO_INTERFACE_NAME(ipwritev)(int fd, 
			       const struct iovec *iov, 
			       size_t count, 
			       off_t offset)
{

	return PREPEND(_, SYSIO_INTERFACE_NAME(ipwritev))(fd, 
							  iov, 
							  count, 
							  offset);
}

static ssize_t
PREPEND(_, SYSIO_INTERFACE_NAME(pwritev))(int fd, 
					  const struct iovec *iov, 
					  _SYSIO_PREADV_T count, 
					  _SYSIO_OFF_T offset)
{
	struct file *fil;
	struct intnl_xtvec xtvector;
	struct ioctx *ioctx;
	int	err;
	ssize_t	cc;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(-1, -EBADF);

	err =
	    _sysio_ipiov(IIOXOP_WRITE(fil->f_ino),
			 fil,
			 iov, count, NULL,
			 offset,
			 &xtvector, NULL,
			 &ioctx);
	if (!err && (cc = _sysio_ioctx_wait(ioctx)) < 0)
		err = (int )cc;

	SYSIO_INTERFACE_RETURN(err ? -1 : cc, err);
}

#ifdef _LARGEFILE64_SOURCE
#undef pwrite64v
sysio_sym_weak_alias(PREPEND(_, SYSIO_INTERFACE_NAME(pwritev)),
		     SYSIO_INTERFACE_NAME(pwrite64v))
#endif

ssize_t
SYSIO_INTERFACE_NAME(pwritev)(int fd, 
			      const struct iovec *iov, 
			      _SYSIO_PREADV_T count, 
			      off_t offset)
{

	return PREPEND(_, SYSIO_INTERFACE_NAME(pwritev))(fd, 
							 iov, 
							 count, 
							 offset);
}

static ioid_t
PREPEND(_, SYSIO_INTERFACE_NAME(ipwrite))(int fd, 
					  const void *buf, 
					  size_t count, 
					  _SYSIO_OFF_T offset)
{
	struct file *fil;
	struct intnl_xtvec *xtv;
	struct iovec *iov;
	struct ioctx *ioctx;
	int	err;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -EBADF);

	xtv = malloc(sizeof(struct intnl_xtvec));
	iov = malloc(sizeof(struct iovec));
	if (!(xtv && iov)) {
		err = -errno;
		goto error;
	}
	xtv->xtv_off = offset;
	iov->iov_base = (void *)buf;
	xtv->xtv_len = iov->iov_len = count;
	err =
	    _sysio_ipiov(IIOXOP_WRITE(fil->f_ino),
			 fil,
			 iov, 1, free_iov,
			 offset,
			 xtv, free_xtv,
			 &ioctx);
error:
	if (err) {
		if (iov)
			free(iov);
		if (xtv)
			free(xtv);
		SYSIO_INTERFACE_RETURN(IOID_FAIL, err);
	}
	SYSIO_INTERFACE_RETURN(ioctx, 0);
}

#ifdef _LARGEFILE64_SOURCE
#undef ipwrite64
sysio_sym_weak_alias(PREPEND(_, SYSIO_INTERFACE_NAME(ipwrite)),
		     SYSIO_INTERFACE_NAME(ipwrite64))
#endif

ioid_t
SYSIO_INTERFACE_NAME(ipwrite)(int fd, 
			      const void *buf, 
			      size_t count, 
			      off_t offset)
{

	return PREPEND(_, SYSIO_INTERFACE_NAME(ipwrite))(fd, 
						 	 buf, 
						 	 count, 
							 offset);
}

ssize_t
PREPEND(_, SYSIO_INTERFACE_NAME(pwrite))(int fd, 
					 const void *buf, 
					 size_t count, 
					 _SYSIO_OFF_T offset)
{
	struct file *fil;
	struct intnl_xtvec xtvec;
	struct iovec iovec;
	struct ioctx *ioctx;
	int	err;
	ssize_t	cc;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(-1, -EBADF);

	xtvec.xtv_off = offset;
	iovec.iov_base = (void *)buf;
	xtvec.xtv_len = iovec.iov_len = count;
	err =
	    _sysio_ipiov(IIOXOP_WRITE(fil->f_ino),
			 fil,
			 &iovec, 1, NULL,
			 offset,
			 &xtvec, NULL,
			 &ioctx);
	if (!err && (cc = _sysio_ioctx_wait(ioctx)) < 0)
		err = (int )cc;

	SYSIO_INTERFACE_RETURN(err ? -1 : cc, err);
}

#ifdef _LARGEFILE64_SOURCE
#undef pwrite64
sysio_sym_weak_alias(PREPEND(_, SYSIO_INTERFACE_NAME(pwrite)),
		     SYSIO_INTERFACE_NAME(pwrite64))
#ifdef __GLIBC
#undef __pwrite64
sysio_sym_weak_alias(PREPEND(_, SYSIO_INTERFACE_NAME(pwrite)),
		     PREPEND(__, SYSIO_INTERFACE_NAME(pwrite64)))
#undef __libc_pwrite64
sysio_sym_weak_alias(PREPEND(_, SYSIO_INTERFACE_NAME(pwrite)),
		     PREPEND(__, SYSIO_INTERFACE_NAME(libc_pwrite64)))
#endif
#endif

ssize_t
SYSIO_INTERFACE_NAME(pwrite)(int fd, 
			     const void *buf, 
			     size_t count, 
			     off_t offset)
{

	return PREPEND(_, SYSIO_INTERFACE_NAME(pwrite))(fd, 
						        buf, 
						        count, 
						        offset);
}

#ifdef __GLIBC
#undef __libc_pwrite
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(pwrite), __libc_pwrite)
		     PREPEND(__, SYSIO_INTERFACE_NAME(libc_pwrite)))
#endif

static ioid_t
PREPEND(_, SYSIO_INTERFACE_NAME(iwritex))(int fd,
	 				  const struct iovec *iov, 
					  size_t iov_count, 
					  const struct intnl_xtvec *xtv, 
					  size_t xtv_count)
{
	struct file *fil;
	int	err;
	struct ioctx *ioctx;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!(fil && xtv_count))
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -EBADF);

	err =
	    _sysio_iiox(IIOXOP_WRITE(fil->f_ino),
			fil,
			iov, iov_count, NULL,
			xtv, xtv_count, NULL,
			NULL,
			&ioctx);

	SYSIO_INTERFACE_RETURN(err ? IOID_FAIL : ioctx, err);
}

#ifdef _LARGEFILE64_SOURCE
#undef iwrite64x
sysio_sym_weak_alias(PREPEND(_, SYSIO_INTERFACE_NAME(iwritex)),
		     SYSIO_INTERFACE_NAME(iwrite64x))
#endif

#ifdef _LARGEFILE64_SOURCE
ioid_t
SYSIO_INTERFACE_NAME(iwritex)(int fd,
			      const struct iovec *iov, size_t iov_count,
			      const struct xtvec *xtv, size_t xtv_count)
{
	struct file *fil;
	struct intnl_xtvec *ixtv, *ixtvent;
	size_t	count;
	int	err;
	struct ioctx *ioctx;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	fil = _sysio_fd_find(fd);
	if (!fil)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -EBADF);

	/* Perform a check on the iov_count and xtv_count */
	if ((iov_count == 0) || (xtv_count == 0))
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -EINVAL);

	ixtv = ixtvent = malloc(xtv_count * sizeof(struct intnl_xtvec));
	if (!ixtv)
		SYSIO_INTERFACE_RETURN(IOID_FAIL, -ENOMEM);

	count = xtv_count;
	while (count--) {
		ixtvent->xtv_off = xtv->xtv_off;
		ixtvent->xtv_len = xtv->xtv_len;
		ixtvent++;
		xtv++;
	}

	err =
	    _sysio_iiox(IIOXOP_WRITE(fil->f_ino),
			fil,
			iov, iov_count, NULL,
			ixtv, xtv_count, free_xtv,
			NULL,
			&ioctx);
	if (err) {
		free(ixtv);
		SYSIO_INTERFACE_RETURN(IOID_FAIL, err);
	}
	SYSIO_INTERFACE_RETURN(ioctx, 0);
}
#else
#undef iwritex
sysio_sym_weak_alias(PREPEND(_, SYSIO_INTERFACE_NAME(iwritex)),
		     SYSIO_INTERFACE_NAME(iwritex))
#endif

#undef writex
ssize_t
SYSIO_INTERFACE_NAME(writex)(int fd,
			     const struct iovec *iov, size_t iov_count,
			     const struct xtvec *xtv, size_t xtv_count)
{
	ioid_t	ioid;

	if ((ioid = 
	     SYSIO_INTERFACE_NAME(iwritex)(fd, 
				 	   iov, 
					   iov_count, 
					   xtv, 
					   xtv_count)) == IOID_FAIL)
		return -1;
	return SYSIO_INTERFACE_NAME(iowait)(ioid);
}

#ifdef _LARGEFILE64_SOURCE
#undef write64x
ssize_t
SYSIO_INTERFACE_NAME(write64x)(int fd,
	 const struct iovec *iov, size_t iov_count,
	 const struct xtvec64 *xtv, size_t xtv_count)
{
	ioid_t	ioid;

	if ((ioid = SYSIO_INTERFACE_NAME(iwrite64x)(fd, 
		     				    iov, 
						    iov_count, 
						    xtv, 
						    xtv_count)) == IOID_FAIL)
		return -1;
	return SYSIO_INTERFACE_NAME(iowait)(ioid);
}
#endif

#ifdef notdef
int
write_list(int fd,
	   int mem_list_count,
	   char *mem_offsets[],
	   int mem_lengths[],
	   int file_list_count,
	   int64_t file_offsets[],
	   int32_t file_lengths[])
{
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	SYSIO_INTERFACE_RETURN(-1, -ENOSYS);
}
#endif
