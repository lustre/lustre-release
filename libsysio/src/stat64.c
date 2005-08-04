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

#ifdef _LARGEFILE64_SOURCE

#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/queue.h>

#include "sysio.h"
#include "inode.h"
#include "file.h"

#ifndef REDSTORM
#undef fstat64
#undef stat64
#undef lstat64
#endif

#undef __fxstat64
#undef __xstat64
#undef __lxstat64

int
PREPEND(__, SYSIO_INTERFACE_NAME(fxstat64))(int __ver,
					    int __fildes,
					    struct stat64 *__stat_buf)
{
	struct file *fil;
	int	err;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	if (__ver != _STAT_VER) {
		err = -ENOSYS;
		goto out;
	}

	err = 0;
	fil = _sysio_fd_find(__fildes);
	if (!fil) {
		err = -EBADF;
		goto out;
	}
	/*
	 * Never use the attributes cached in the inode record. Give
	 * the driver a chance to refresh them.
	 */
	err = fil->f_ino->i_ops.inop_getattr(NULL, fil->f_ino, __stat_buf);
out:
	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}

#ifndef REDSTORM
int
SYSIO_INTERFACE_NAME(fstat64)(int fd, struct stat64 *buf)
{

	return PREPEND(__, SYSIO_INTERFACE_NAME(fxstat64))(_STAT_VER, fd, buf);
}
#endif

int
PREPEND(__, SYSIO_INTERFACE_NAME(xstat64))(int __ver,
					   const char *__filename,
					   struct stat64 *__stat_buf)
{
	struct intent intent;
	int     err;
	struct pnode *pno;
	struct inode *ino;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	if (__ver != _STAT_VER) {
		err = -ENOSYS;
		goto out;
	}

	INTENT_INIT(&intent, INT_GETATTR, NULL, NULL);
	err = _sysio_namei(_sysio_cwd, __filename, 0, &intent, &pno);
	if (err)
		goto out;
	/*
	 * Leverage the INT_GETATTR intent above. We are counting
	 * on the FS driver to either make sure the attributes cached in
	 * the inode are always correct or refresh them in the lookup, above.
	 */
	ino = pno->p_base->pb_ino;
	(void )memcpy(__stat_buf, &ino->i_stbuf, sizeof(struct intnl_stat));
	P_RELE(pno);
out:
	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}

#ifndef REDSTORM
int
SYSIO_INTERFACE_NAME(stat64)(const char *filename, struct stat64 *buf)
{

	return PREPEND(__, SYSIO_INTERFACE_NAME(xstat64))(_STAT_VER,
							  filename,
							  buf);
}
#endif

int
PREPEND(__, SYSIO_INTERFACE_NAME(lxstat64))(int __ver,
					    const char *__filename,
					    struct stat64 *__stat_buf)
{
	struct intent intent;
	int     err;
	struct pnode *pno;
	struct inode *ino;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	if (__ver != _STAT_VER) {
		err = -ENOSYS;
		goto out;
	}

	INTENT_INIT(&intent, INT_GETATTR, NULL, NULL);
	err = _sysio_namei(_sysio_cwd, __filename, ND_NOFOLLOW, &intent, &pno);
	if (err)
		goto out;
	/*
	 * Leverage the INT_GETATTR intent above. We are counting
	 * on the FS driver to either make sure the attributes cached in
	 * the inode are always correct or refresh them in the lookup, above.
	 */
	ino = pno->p_base->pb_ino;
	(void )memcpy(__stat_buf, &ino->i_stbuf, sizeof(struct intnl_stat));
	P_RELE(pno);
out:
	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}

#ifndef REDSTORM
int
SYSIO_INTERFACE_NAME(lstat64)(const char *filename, struct stat64 *buf)
{

	return PREPEND(__, SYSIO_INTERFACE_NAME(lxstat64))(_STAT_VER,
							   filename,
							   buf);
}
#endif
#endif /* !_LARGEFILE64_SOURCE */
