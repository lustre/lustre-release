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

#ifndef BSD
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/queue.h>

#include "sysio.h"
#include "inode.h"
#include "file.h"
#include "sysio-symbols.h"

int
SYSIO_INTERFACE_NAME(statvfs64)(const char *path, struct statvfs64 *buf)
{
	int	err;
	struct pnode *pno;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	err = _sysio_namei(_sysio_cwd, path, 0, NULL, &pno);
	if (err)
		goto out;

	err = pno->p_base->pb_ino->i_ops.inop_statvfs(pno, NULL, buf);
	P_RELE(pno);
out:
	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}

#ifdef REDSTORM
#undef __statvfs64
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(statvfs64),
		     PREPEND(__, SYSIO_INTERFACE_NAME(statvfs64)))
#endif

int
SYSIO_INTERFACE_NAME(fstatvfs64)(int fd, struct statvfs64 *buf)
{
	int	err;
	struct file *filp;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	err = 0;
	filp = _sysio_fd_find(fd);
	if (!filp) {
		err = -EBADF;
		goto out;
	}

	err = filp->f_ino->i_ops.inop_statvfs(NULL, filp->f_ino, buf);
out:
	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}

#ifdef REDSTORM
#undef __fstatvfs64
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(fstatvfs64),
		     PREPEND(__, SYSIO_INTERFACE_NAME(fstatvfs64)))
#endif

#endif /* ifndef BSD */
