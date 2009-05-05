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
 *    Cplant(TM) Copyright 1998-2006 Sandia Corporation. 
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
 * Incorporate the GNU flags for open if we can.
 */
#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/queue.h>

#include "sysio.h"
#include "inode.h"
#include "file.h"
#include "fs.h"
#include "mount.h"
#include "sysio-symbols.h"

/*
 * Open file support.
 */

mode_t	_sysio_umask = 0;				/* process umask. */

/*
 * Internal form of open.
 */
int
_sysio_open(struct pnode *pno, int flags, mode_t mode)
{
	int	ro;
	int	w;
	int	err;
	struct inode *ino;

	ro = IS_RDONLY(pno);
	w = flags & (O_WRONLY|O_RDWR);
	if (w == (O_WRONLY|O_RDWR)) {
		/*
		 * Huh?
		 */
		return -EINVAL;
	}
	if (w && ro)
		return -EROFS;
	ino = pno->p_base->pb_ino;
	if ((flags & O_CREAT) && !ino) {
		struct pnode *parent;

		/*
		 * Must create it.
		 */
		if (ro)
			return -EROFS;
		parent = pno->p_parent;
		err = _sysio_p_validate(parent, NULL, NULL);
		if (!err) {
			ino = parent->p_base->pb_ino;
			assert(ino);
			err = (*ino->i_ops.inop_open)(pno, flags, mode);
		}
	} else if ((flags & (O_CREAT|O_EXCL)) == (O_CREAT|O_EXCL))
		err = -EEXIST;
	else if (!ino)
		err = _sysio_p_validate(pno, NULL, NULL);
#ifdef O_NOFOLLOW
	else if (flags & O_NOFOLLOW && S_ISLNK(ino->i_stbuf.st_mode))
		err = -ELOOP;
#endif
	else {
		/*
		 * Simple open of pre-existing file.
		 */
		err = (*ino->i_ops.inop_open)(pno, flags, mode);
	}

	return err;
}

#undef open

int
SYSIO_INTERFACE_NAME(open)(const char *path, int flags, ...)
{
	mode_t	mode;
	unsigned ndflags;
	struct intent intent;
	int	rtn;
	struct pnode *pno;
	struct file *fil;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	/*
	 * Get mode argument and determine parameters for namei
	 */
	mode = 0;
	ndflags = 0;
	intent.int_opmask = INT_OPEN;
	if (flags & O_CREAT) {
		va_list	ap;

		/*
		 * Set ndflags to indicate return of negative alias is OK.
		 */
		ndflags |= ND_NEGOK;

		/*
		 * Will need mode too.
		 */
		va_start(ap, flags);
		mode =
#ifndef REDSTORM
		    va_arg(ap, mode_t);
#else
		    va_arg(ap, int);
#endif
		va_end(ap);
		mode &= ~(_sysio_umask & 0777) | 07000;	/* apply umask */
		intent.int_opmask |= INT_CREAT;
	}
#ifdef O_NOFOLLOW
	if (flags & O_NOFOLLOW)
		ndflags |= ND_NOFOLLOW;
#endif

	/*
	 * Find the file.
	 */
	fil = NULL;
	INTENT_INIT(&intent, intent.int_opmask, &mode, &flags);
	pno = NULL;
	rtn = _sysio_namei(_sysio_cwd, path, ndflags, &intent, &pno);
	if (rtn)
		goto error;
	/*
	 * Ask for the open/creat.
	 */
	rtn = _sysio_open(pno, flags, mode);
	if (rtn)
		goto error;
	/*
	 * Get a file descriptor.
	 */
	fil = _sysio_fnew(pno->p_base->pb_ino, flags);
	if (!fil) {
		rtn = -ENOMEM;
		goto error;
	}
	rtn = _sysio_fd_set(fil, -1, 0);
	if (rtn < 0)
		goto error;

	P_RELE(pno);

	SYSIO_INTERFACE_RETURN(rtn, 0);

error:
	if (fil)
		F_RELE(fil);
	if (pno)
		P_RELE(pno);
	SYSIO_INTERFACE_RETURN(-1, rtn);
}

#ifdef __GLIBC__
#undef __open
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(open),
		     PREPEND(__, SYSIO_INTERFACE_NAME(open)))
#undef open64
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(open), SYSIO_INTERFACE_NAME(open64))
#undef __open64
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(open),
		     PREPEND(__, SYSIO_INTERFACE_NAME(open64)))
#endif

#ifdef REDSTORM
#undef __libc_open64
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(open),
		     PREPEND(__, SYSIO_INTERFACE_NAME(libc_open64)))
#endif

#ifdef BSD
#undef _open
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(open),
		     PREPEND(_, SYSIO_INTERFACE_NAME(open)))
#endif

int
SYSIO_INTERFACE_NAME(close)(int fd)
{
	int	err;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	err = _sysio_fd_close(fd);
	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}

#ifdef __GLIBC__
#undef __close
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(close),
		     PREPEND(__, SYSIO_INTERFACE_NAME(close)))
#endif

#ifdef BSD
#undef _close
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(close),
		     PREPEND(_, SYSIO_INTERFACE_NAME(close)))
#endif

int
SYSIO_INTERFACE_NAME(creat)(const char *path, mode_t mode)
{

	return SYSIO_INTERFACE_NAME(open)(path, O_CREAT|O_WRONLY|O_TRUNC, mode);
}

#ifdef __GLIBC__
#undef __creat
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(creat),
		     PREPEND(__, SYSIO_INTERFACE_NAME(creat)))
#undef creat64
#ifndef HAVE_LUSTRE_HACK
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(creat), SYSIO_INTERFACE_NAME(creat64))
#else
/* XXX workaround SuSE SLES 8, glibc-2.2.5 */
sysio_sym_strong_alias(SYSIO_INTERFACE_NAME(creat),
		       SYSIO_INTERFACE_NAME(creat64))
#endif
#undef __creat64
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(creat),
		     PREPEND(__, SYSIO_INTERFACE_NAME(creat64)))
#endif

#ifdef REDSTORM
#undef __libc_creat
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(creat),
		     PREPEND(__, SYSIO_INTERFACE_NAME(libc_creat)))
#endif

#ifdef BSD
#undef _creat
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(creat),
		     PREPEND(_, SYSIO_INTERFACE_NAME(creat)))
#endif

mode_t
SYSIO_INTERFACE_NAME(umask)(mode_t mask)
{
	mode_t	omask;

	omask = _sysio_umask;
	_sysio_umask = mask & 0777;
	return omask;
}

#ifdef REDSTORM
#undef __umask
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(umask),
		     PREPEND(__, SYSIO_INTERFACE_NAME(umask)))
#endif
