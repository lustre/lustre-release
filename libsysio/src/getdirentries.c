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
 * #############################################################################
 * #
 * #     This Cplant(TM) source code is the property of Sandia National
 * #     Laboratories.
 * #
 * #     This Cplant(TM) source code is copyrighted by Sandia National
 * #     Laboratories.
 * #
 * #     The redistribution of this Cplant(TM) source code is subject to the
 * #     terms of the GNU Lesser General Public License
 * #     (see cit/LGPL or http://www.gnu.org/licenses/lgpl.html)
 * #
 * #     Cplant(TM) Copyright 1998-2004 Sandia Corporation. 
 * #     Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
 * #     license for use of this work by or on behalf of the US Government.
 * #     Export of this program may require a license from the United States
 * #     Government.
 * #
 * #############################################################################
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
	if (!(fil && fil->f_ino))
		SYSIO_INTERFACE_RETURN(-1, -EBADF);

	if (!S_ISDIR(fil->f_ino->i_mode))
		SYSIO_INTERFACE_RETURN(-1, -ENOTDIR);

	cc =
	    (*fil->f_ino->i_ops.inop_getdirentries)(fil->f_ino,
						    buf,
						    nbytes,
						    basep);
	SYSIO_INTERFACE_RETURN(cc < 0 ? -1 : cc, cc < 0 ? (int )cc : 0);
}

#if _LARGEFILE64_SOURCE
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
	size_t inbytes;
	void	*ibuf;
	_SYSIO_OFF_T ibase;
	ssize_t	cc;
	struct dirent *dp, *nxtdp;
#if defined(BSD)
	int	off;
#endif
	struct intnl_dirent *od64p, *d64p;
	size_t	n;
	size_t	reclen;
	char	*cp;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

#define _dbaselen	((size_t )&((struct dirent *)0)->d_name[0])

#ifdef __GLIBC__
#define _dreclen(namlen) \
	((_dbaselen + (namlen) + __alignof__ (struct dirent)) & \
	 ~(__alignof__ (struct dirent) - 1))
#else /* !defined(__GLIBC__) */
#define _dreclen(namlen) \
	_rndup(_dbaselen + (namlen) + 1, sizeof(int))
#endif

#if defined(__GLIBC__)
#define _fast_alloc(n)	alloca(n)
#define _fast_free(p)
#else /* !defined(__GLIBC__) */
#define _fast_alloc(n)	malloc(n)
#define _fast_free(p)	free(p)
#endif

	SYSIO_INTERFACE_ENTER;
#if defined(BSD)
	if (nbytes < 0)
		SYSIO_INTERFACE_RETURN(-1, -EINVAL);
#endif

	inbytes = nbytes;
	if (inbytes > 8 * 1024) {
		/*
		 * Limit stack use.
		 */
		inbytes = 8 * 1024;
	}
	ibuf = _fast_alloc(inbytes);
	if (!ibuf)
		SYSIO_INTERFACE_RETURN(-1, -ENOMEM);

	dp = (struct dirent *)buf;

	ibase = *basep;
	cc =
	    PREPEND(_, SYSIO_INTERFACE_NAME(getdirentries64))(fd,
					    ibuf,
					    inbytes,
					    &ibase);
	if (cc < 0) {
		cc = -errno;
		goto out;
	}
	*basep = (off_t )ibase;
	if (sizeof(*basep) != sizeof(ibase) && *basep != ibase) {
		cc = -EOVERFLOW;
		goto out;
	}

#if defined(BSD)
	off = *basep;
#endif
	od64p = NULL;
	d64p = ibuf;
	for (;;) {
		if (!cc)
			break;
#ifdef HAVE_D_NAMLEN
		n = d64p->d_namlen;
#else
		n = strlen(d64p->d_name);
#endif
		reclen = _dreclen(n);
		if (reclen >= (unsigned )nbytes)
			break;
		dp->d_ino = (ino_t )d64p->d_ino;
#if !(defined(BSD))
		dp->d_off = (off_t )d64p->d_off;
#endif
		if ((sizeof(dp->d_ino) != sizeof(d64p->d_ino) &&
		     dp->d_ino != d64p->d_ino)
				||
#if !(defined(BSD))
		    (sizeof(dp->d_off) != sizeof(d64p->d_off) &&
		     dp->d_off != d64p->d_off)
#else
		    (off + (int )reclen < off)
#endif
		    ) {
			cc = -EOVERFLOW;
			break;
		}
		dp->d_type = d64p->d_type;
		dp->d_reclen = reclen;
		nxtdp = (struct dirent *)((char *)dp + dp->d_reclen);
		(void )memcpy(dp->d_name, d64p->d_name, n);
		for (cp = dp->d_name + n; cp < (char *)nxtdp; *cp++ = '\0')
			;
		cc -= d64p->d_reclen;
		od64p = d64p;
		d64p = (struct dirent64 *)((char *)d64p + d64p->d_reclen);
		nbytes -= reclen;
#if defined(BSD)
		off += reclen;
#endif
		dp = nxtdp;
	}

out:
	_fast_free(ibuf);

	if (dp == (struct dirent *)buf && cc < 0)
		SYSIO_INTERFACE_RETURN(-1, (int )cc);
	cc = (char *)dp - buf;
	if (cc)
		*basep =
#if !(defined(BSD))
		    od64p->d_off;
#else
		    off;
#endif
	SYSIO_INTERFACE_RETURN(cc, 0);

#ifdef __GLIBC__
#undef _fast_alloc
#undef _fast_free
#endif
#undef _dreclen
#undef _dbaselen
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
