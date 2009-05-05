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

#include <errno.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include "sysio.h"
#include "xtio.h"
#include "native.h"
#include "inode.h"
#include "dev.h"

#include "stdfd.h"

#ifdef CPLANT_YOD
#include <sys/statfs.h>
#include "cplant-yod.h"
#define dowrite(f, b, n) write_yod(f, b, n)
#define doread(f, b, n) read_yod(f, b, n)
#else
#define dowrite(f, b, n) syscall(SYSIO_SYS_write, f, b, n)
#define doread(f, b, n) syscall(SYSIO_SYS_read, f, b, n)
#endif

/*
 * Pre-opened standard file descriptors driver.
 */

static int stdfd_open(struct pnode *pno, int flags, mode_t mode);
static int stdfd_close(struct inode *ino);
static int stdfd_read(struct inode *ino, struct ioctx *ioctx);
static int stdfd_write(struct inode *ino, struct ioctx *ioctx);
static int stdfd_iodone(struct ioctx *ioctx);
static int stdfd_datasync(struct inode *ino);
static int stdfd_fcntl(struct inode *ino, int cmd, va_list ap, int *rtn);
static int stdfd_ioctl(struct inode *ino,
		       unsigned long int request,
		       va_list ap);

int
_sysio_stdfd_init()
{
	struct inode_ops stdfd_operations;

	stdfd_operations = _sysio_nodev_ops;
	stdfd_operations.inop_open = stdfd_open;
	stdfd_operations.inop_close = stdfd_close;
	stdfd_operations.inop_read = stdfd_read;
	stdfd_operations.inop_write = stdfd_write;
	stdfd_operations.inop_iodone = stdfd_iodone;
	stdfd_operations.inop_fcntl = stdfd_fcntl;
	stdfd_operations.inop_datasync = stdfd_datasync;
	stdfd_operations.inop_ioctl = stdfd_ioctl;

	return _sysio_char_dev_register(SYSIO_C_STDFD_MAJOR,
					"stdfd",
					&stdfd_operations);
}

static int
stdfd_open(struct pnode *pno __IS_UNUSED,
	   int flags __IS_UNUSED,
	   mode_t mode __IS_UNUSED)
{

	return 0;
}

static int
stdfd_close(struct inode *ino __IS_UNUSED)
{

	return 0;
}

static int
doio(ssize_t (*f)(void *, size_t, _SYSIO_OFF_T, struct inode *),
     struct inode *ino,
     struct ioctx *ioctx)
{

	if (ioctx->ioctx_xtvlen != 1) {
		/*
		 * No scatter/gather to "file" address space (we're not
		 * seekable) and "nowhere" makes no sense.
		 */
		return -EINVAL;
	}
	ioctx->ioctx_cc =
	    _sysio_doio(ioctx->ioctx_xtv, ioctx->ioctx_xtvlen,
			ioctx->ioctx_iov, ioctx->ioctx_iovlen,
			(ssize_t (*)(void *, size_t, _SYSIO_OFF_T, void *))f,
			ino);
	if (ioctx->ioctx_cc < 0) {
		ioctx->ioctx_errno = -ioctx->ioctx_cc;
		ioctx->ioctx_cc = -1;
	}
	return 0;
}

static ssize_t
stdfd_read_simple(void *buf,
		  size_t nbytes,
		  _SYSIO_OFF_T off __IS_UNUSED,
		  struct inode *ino)
{
	int	fd = SYSIO_MINOR_DEV(ino->i_stbuf.st_rdev);
	int	cc;

	cc = doread(fd, buf, nbytes);
	if (cc < 0)
		cc = -errno;
	return cc;
}

static int
stdfd_read(struct inode *ino, struct ioctx *ioctx)
{

	return doio(stdfd_read_simple, ino, ioctx);
}

static ssize_t
stdfd_write_simple(const void *buf,
		   size_t nbytes,
		   _SYSIO_OFF_T off __IS_UNUSED,
		   struct inode *ino)
{
	int	fd = SYSIO_MINOR_DEV(ino->i_stbuf.st_rdev);
	int	cc;

	cc = dowrite(fd, buf, nbytes);
	if (cc < 0)
		cc = -errno;
	return cc;
}

static int
stdfd_write(struct inode *ino, struct ioctx *ioctx)
{

	return doio((ssize_t (*)(void *,
				 size_t,
				 _SYSIO_OFF_T,
				 struct inode *))stdfd_write_simple,
		    ino,
		    ioctx);
}

static int
stdfd_iodone(struct ioctx *iocp __IS_UNUSED)
{

	/*
	 * It's always done in this driver. It completed when posted.
	 */
	return 1;
}

static int
stdfd_fcntl(struct inode *ino,
	    int cmd,
	    va_list ap,
	    int *rtn)
{
	int	err;
	int	fd = SYSIO_MINOR_DEV(ino->i_stbuf.st_rdev);
	long	arg;

	err = 0;
	switch (cmd) {
	case F_GETFL:
		*rtn = syscall(SYS_fcntl, fd, cmd);
		if (*rtn == -1)
			err = -errno;
		break;
	case F_SETFL:
		arg = va_arg(ap, long);
		*rtn = syscall(SYS_fcntl, fd, cmd, arg);
		if (*rtn == -1)
			err = -errno;
		va_end(ap);
		break;
	default:
		*rtn = -1;
		err = -EINVAL;
	}
	return err;
}

static int
stdfd_datasync(struct inode *ino __IS_UNUSED)
{

	/*
	 * We don't buffer, so nothing to do.
	 */
	return 0;
}

static int
stdfd_ioctl(struct inode *ino __IS_UNUSED,
	    unsigned long int request __IS_UNUSED,
	    va_list ap __IS_UNUSED)
{

	return -ENOTTY;
}
