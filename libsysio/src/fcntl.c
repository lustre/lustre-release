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

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/queue.h>

#include "sysio.h"
#include "inode.h"
#include "file.h"

#include "sysio-symbols.h"

#ifdef HAVE_LUSTRE_HACK
#include <syscall.h>

static int
_sysio_fcntl(int fd, int cmd, va_list ap)
{
	int	err;
	long	arg;

	switch (cmd) {
	case F_GETFD:
	case F_GETFL:
	case F_GETOWN:
		return syscall(SYS_fcntl, fd, cmd);
	case F_DUPFD:
	case F_SETFD:
	case F_SETFL:
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
	case F_SETOWN:
		arg = va_arg(ap, long);
		return syscall(SYS_fcntl, fd, cmd, arg);
	}

	errno = ENOSYS;
	return -1;
}
#endif

int
SYSIO_INTERFACE_NAME(fcntl)(int fd, int cmd, ...)
{
	int	err;
	struct file *fil;
	va_list	ap;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	err = 0;
	fil = _sysio_fd_find(fd);
	if (!fil) {
#ifdef HAVE_LUSTRE_HACK
		va_start(ap, cmd);
		err = _sysio_fcntl(fd, cmd, ap);
		va_end(ap);
		if (err == -1)
			err = -errno;
		goto out;
#else
		err = -EBADF;
		goto out;
#endif
	}

	switch (cmd) {

	    case F_DUPFD:
		{
			long	newfd;

			va_start(ap, cmd);
			newfd = va_arg(ap, long);
			va_end(ap);
			if (newfd != (int )newfd || newfd < 0) {
				err = -EBADF;
				goto out;
			}
			err = _sysio_fd_dup2(fd, (int )newfd);
		}
		break;
	    default:
		va_start(ap, cmd);
		err = fil->f_ino->i_ops.inop_fcntl(fil->f_ino, cmd, ap);
		va_end(ap);
		break;
	}

out:
	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}

#ifdef __GLIBC__
#undef __fcntl
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(fcntl), 
		     PREPEND(__, SYSIO_INTERFACE_NAME(fcntl)))
#endif

#ifdef BSD
#undef _fcntl
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(fcntl), 
		     PREPEND(_, SYSIO_INTERFACE_NAME(fcntl)))
#endif
