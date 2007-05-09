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

#include <unistd.h>
#include <stdlib.h>
#ifdef __GLIBC__
#include <alloca.h>
#endif
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/queue.h>

#include "sysio.h"
#include "inode.h"
#include "file.h"
#include "sysio-symbols.h"

#ifndef __GNUC__
#define __restrict
#endif

static ssize_t
filldirents(struct file *fil,
	    char *buf, size_t nbytes,
	    _SYSIO_OFF_T *__restrict basep)
{
	_SYSIO_OFF_T opos;
	ssize_t	cc;

	if (!S_ISDIR(fil->f_ino->i_stbuf.st_mode))
		return -ENOTDIR;

	opos = fil->f_pos;
	cc =
	    (*fil->f_ino->i_ops.inop_filldirentries)(fil->f_ino,
						     &fil->f_pos,
						     buf, nbytes);
	if (cc < 0)
		return cc;
	*basep = opos;
	return cc;
}

static ssize_t
PREPEND(_, SYSIO_INTERFACE_NAME(getdirentries64))(int fd,
						  char *buf,
						  size_t nbytes,
						  _SYSIO_OFF_T * __restrict
						   basep)
{
	struct file *fil;
	ssize_t	cc;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;

	fil = _sysio_fd_find(fd);
	if (!(fil && fil->f_ino)) {
		SYSIO_INTERFACE_RETURN(-1, -EBADF);
	}

	cc = filldirents(fil, buf, nbytes, basep);
	SYSIO_INTERFACE_RETURN(cc < 0 ? -1 : cc, cc < 0 ? (int )cc : 0);
}

#ifdef _LARGEFILE64_SOURCE
#undef getdirentries64
sysio_sym_strong_alias(PREPEND(_, SYSIO_INTERFACE_NAME(getdirentries64)),
		       SYSIO_INTERFACE_NAME(getdirentries64))
#endif

#undef getdirentries

#ifndef DIRENT64_IS_NATURAL

#ifndef EOVERFLOW
#define EOVERFLOW	ERANGE
#endif

#ifdef _DIRENT_HAVE_D_NAMLEN
#define _namlen(dp)	((dp)->d_namlen)
#else
#define _namlen(dp)	(strlen((dp)->d_name))
#endif

#ifndef _rndup
#define _rndup(n, boundary) \
	((((n) + (boundary) - 1 ) / (boundary)) * (boundary))
#endif

#define _dbaselen	((size_t )&((struct dirent *)0)->d_name[0])

#ifdef __GLIBC__
#define _dreclen(namlen) \
	((_dbaselen + (namlen) + __alignof__ (struct dirent)) & \
	 ~(__alignof__ (struct dirent) - 1))
#else /* !defined(__GLIBC__) */
#define _dreclen(namlen) \
	_rndup(_dbaselen + (namlen) + 1, sizeof(int))
#endif

#ifndef BSD
ssize_t
SYSIO_INTERFACE_NAME(getdirentries)(int fd,
				    char *buf,
				    size_t nbytes,
				    off_t * __restrict basep)
#else
int
SYSIO_INTERFACE_NAME(getdirentries)(int fd,
				    char *buf,
				    int nbytes,
				    long * __restrict basep)
#endif
{
	struct file *fil;
	_SYSIO_OFF_T b;
	ssize_t	cc, count;
	struct dirent64 *d64p, d64;
	struct dirent *dp;
	size_t	n, reclen;
	void	*p;
	char	*cp;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;

	fil = _sysio_fd_find(fd);
	if (!(fil && fil->f_ino)) {
		SYSIO_INTERFACE_RETURN(-1, -EBADF);
	}

	count = cc = filldirents(fil, buf, nbytes, &b);
	d64p = (void *)buf;
	dp = (void *)buf;
	reclen = 0;
	while (cc > 0) {
		n = _namlen(d64p);
		reclen = _dreclen(n);
		d64.d_ino = d64p->d_ino;
		d64.d_off = d64p->d_off;
		d64.d_type = d64p->d_type;
		d64.d_reclen = d64p->d_reclen;
		/*
		 * Copy name first.
		 */
		(void )memcpy(dp->d_name, d64p->d_name, n);
		/*
		 * Then, the rest.
		 */
		dp->d_ino = d64.d_ino;
		dp->d_off = d64.d_off;
		if (dp->d_ino != d64.d_ino ||
		    dp->d_off != d64.d_off) {
			/*
			 * If conversion failure then we are done.
			 */
		    	if (cc == count) {
				/*
				 * Couldn't process any entries. We return
				 * the error now.
				 */
				cc = - EOVERFLOW;
			}
			break;
		}
		fil->f_pos = dp->d_off;
		dp->d_type = d64.d_type;
		dp->d_reclen = reclen;
		/*
		 * Fill the remainder with zeros.
		 */
		p = (char *)dp + dp->d_reclen;
#ifdef HAVE_D_NAMLEN
		dp->d_namlen = n;
#endif
		cp = dp->d_name + n;
		do {
			*cp++ = 0;
		} while (cp < (char *)p);
		/*
		 * Advance.
		 */
		dp = p;
		cc -= d64.d_reclen;
		d64p = (struct dirent64 *)((char *)d64p + d64.d_reclen);
	}

	if (cc < 0)
		SYSIO_INTERFACE_RETURN(-1, cc);
	cc = (char *)dp - buf;
	*basep = b;
	SYSIO_INTERFACE_RETURN(cc, 0);
}
#else /* !defined(DIRENT64_IS_NATURAL) */
sysio_sym_strong_alias(PREPEND(_, SYSIO_INTERFACE_NAME(getdirentries64),
		       SYSIO_INTERFACE_NAME(getdirentries)))
#endif

#ifdef REDSTORM
#undef __getdirentries
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(getdirentries),
		     PREPEND(__, SYSIO_INTERFACE_NAME(getdirentries)))
#endif
#if defined(BSD) || defined(REDSTORM)
#undef _getdirentries
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(getdirentries),
		     PREPEND(_, SYSIO_INTERFACE_NAME(getdirentries)))
#endif
