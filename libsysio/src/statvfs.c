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
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/queue.h>

#include "sysio.h"
#include "inode.h"
#include "file.h"
#include "sysio-symbols.h"

#undef statvfs
#undef fstatvfs

#ifndef INTNL_STATVFS_IS_NATURAL
static void
convstatvfs(struct statvfs *stvfsbuf, struct intnl_statvfs *istvfsbuf)
{
	stvfsbuf->f_bsize = istvfsbuf->f_bsize;
	stvfsbuf->f_frsize = istvfsbuf->f_frsize;
	stvfsbuf->f_blocks = (unsigned long )istvfsbuf->f_blocks;
	stvfsbuf->f_bfree = (unsigned long )istvfsbuf->f_bfree;
	stvfsbuf->f_bavail = (unsigned long )istvfsbuf->f_bavail;
	stvfsbuf->f_files = (unsigned long )istvfsbuf->f_files;
	stvfsbuf->f_ffree = (unsigned long )istvfsbuf->f_ffree;
	stvfsbuf->f_favail = (unsigned long )istvfsbuf->f_favail;
	stvfsbuf->f_fsid = istvfsbuf->f_fsid;
	stvfsbuf->f_flag = istvfsbuf->f_flag;
	stvfsbuf->f_namemax = istvfsbuf->f_namemax;
}
#endif

int
SYSIO_INTERFACE_NAME(statvfs)(const char *path, struct statvfs *buf)
{
	int	err;
	struct pnode *pno;
#ifdef INTNL_STATVFS_IS_NATURAL
#define _call_buf buf
#else
	struct intnl_statvfs _call_buffer;
	struct intnl_statvfs *_call_buf = &_call_buffer;
#endif
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	err = _sysio_namei(_sysio_cwd, path, 0, NULL, &pno);
	if (err)
		goto out;

	err = pno->p_base->pb_ino->i_ops.inop_statvfs(pno, NULL, _call_buf);
	P_RELE(pno);
	if (err)
		goto err;
#ifndef INTNL_STATVFS_IS_NATURAL
	convstatvfs(buf, _call_buf);
#endif
	goto out;
err:
out:
	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}

#ifdef REDSTORM
#undef __statvfs
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(statvfs),
		     PREPEND(__, SYSIO_INTERFACE_NAME(statvfs)))
#endif

int
SYSIO_INTERFACE_NAME(fstatvfs)(int fd, struct statvfs *buf)
{
	int	err;
	struct file *filp;
#ifdef INTNL_STATVFS_IS_NATURAL
#define _call_buf buf
#else
	struct intnl_statvfs _call_buffer;
	struct intnl_statvfs *_call_buf = &_call_buffer;
#endif
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	err = 0;
	filp = _sysio_fd_find(fd);
	if (!filp) {
		err = -EBADF;
		goto out;
	}

	err = filp->f_ino->i_ops.inop_statvfs(NULL, filp->f_ino, _call_buf);
	if (err)
		goto err;
#ifndef INTNL_STATVFS_IS_NATURAL
	convstatvfs(buf, _call_buf);
#endif
	goto out;
err:
out:
	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}

#ifdef REDSTORM
#undef __fstatvfs
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(fstatvfs),
		     PREPEND(__, SYSIO_INTERFACE_NAME(fstatvfs)))
#endif

#endif /* ifndef BSD */
