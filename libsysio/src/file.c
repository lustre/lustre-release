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

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/queue.h>

#include "sysio.h"
#include "file.h"
#include "inode.h"
#include "xtio.h"

/*
 * Support for file IO.
 */

/*
 * The open files table and it's size.
 */
static struct file **_sysio_oftab = NULL;
static size_t _sysio_oftab_size = 0;

/*
 * Create and initialize open file record.
 */
struct file *
_sysio_fnew(struct inode *ino, int flags)
{
	struct file *fil;

	fil = malloc(sizeof(struct file));
	if (!fil)
		return NULL;

	_SYSIO_FINIT(fil, ino, flags);
	I_REF(ino);

	return fil;
}

/*
 * Destroy open file record.
 */
void
_sysio_fgone(struct file *fil)
{
	int	err;

	assert(!fil->f_ref);
	assert(fil->f_ino);
	err = (*fil->f_ino->i_ops.inop_close)(fil->f_ino);
	assert(!err);
	free(fil);
}

/*
 * IO operation completion handler.
 */
void
_sysio_fcompletio(struct ioctx *ioctx, struct file *fil)
{
	_SYSIO_OFF_T off;

	if (ioctx->ioctx_cc <= 0)
		return;

	assert(ioctx->ioctx_ino == fil->f_ino);
	off = fil->f_pos + ioctx->ioctx_cc;
	if (fil->f_pos && off <= fil->f_pos)
		abort();
	fil->f_pos = off;
}

/*
 * Grow (or truncate) the file descriptor table.
 */
static int
fd_grow(size_t n)
{
	int	fd;
	size_t	count;
	struct file **noftab, **filp;

	/*
	 * Sanity check the new size.
	 */
	fd = (int )n;
	if ((size_t )fd != n)
		return -EMFILE;

	if (n < 8)
		n = 8;
	if (n >= _sysio_oftab_size && n - _sysio_oftab_size < _sysio_oftab_size)
		n = (n + 1) * 2;
	noftab = realloc(_sysio_oftab, n * sizeof(struct file *));
	if (!noftab)
		return -ENOMEM;
	_sysio_oftab = noftab;
	count = _sysio_oftab_size;
	_sysio_oftab_size = n;
	if (n < count)
		return 0;
	filp = _sysio_oftab + count;
	n -= count;
	while (n--)
		*filp++ = NULL;
	return 0;
}

#if ZERO_SUM_MEMORY
void
_sysio_fd_shutdown()
{

	free(_sysio_oftab);
	_sysio_oftab_size = 0;
}
#endif

/*
 * Find a free slot in the open files table.
 */
static int
find_free_fildes()
{
	size_t	n;
	int	err;
	struct file **filp;

	for (n = 0, filp = _sysio_oftab;
	     n < _sysio_oftab_size && *filp;
	     n++, filp++)
		;
	if (n >= _sysio_oftab_size) {
		err = fd_grow(n);
		if (err)
			return err;
		filp = &_sysio_oftab[n];
		assert(!*filp);
	}

	return n;
}

/*
 * Find open file record from file descriptor.
 */
struct file *
_sysio_fd_find(int fd)
{
	if (fd < 0 || (unsigned )fd >= _sysio_oftab_size)
		return NULL;

	return _sysio_oftab[fd];
}

/*
 * Close an open descriptor.
 */
int
_sysio_fd_close(int fd)
{
	struct file *fil;

	fil = _sysio_fd_find(fd);
	if (!fil)
		return -EBADF;

	_sysio_oftab[fd] = NULL;

	F_RELE(fil);

	return 0;
}

/*
 * Associate open file record with given file descriptor or any available
 * file descriptor if less than zero.
 */
int
_sysio_fd_set(struct file *fil, int fd)
{
	int	err;
	struct file *ofil;

	/*
	 * New fd < 0 => any available descriptor.
	 */
	if (fd < 0) {
		fd = find_free_fildes();
		if (fd < 0)
			return fd;
	}

	if ((unsigned )fd >= _sysio_oftab_size) {
		err = fd_grow(fd);
		if (err)
			return err;
	}

	/*
	 * Remember old.
	 */
	ofil = _sysio_fd_find(fd);
	/*
	 * Take the entry.
	 */
	_sysio_oftab[fd] = fil;
	if (ofil)
		F_RELE(ofil);

	return fd;
}

/*
 * Duplicate old file descriptor.
 *
 * If the new file descriptor is less than zero, the new file descriptor
 * is chosen freely.
 */
int
_sysio_fd_dup2(int oldfd, int newfd)
{
	struct file *fil;
	int	fd;

	if (oldfd == newfd)
		return 0;

	fil = _sysio_fd_find(oldfd);
	if (!fil)
		return -EBADF;

	fd = _sysio_fd_set(fil, newfd);
	if (fd >= 0)
		F_REF(fil);
	return fd;
}

int
_sysio_fd_close_all()
{
	int	fd;
	struct file **filp;

	/*
	 * Close all open descriptors.
	 */
	for (fd = 0, filp = _sysio_oftab;
	     (size_t )fd < _sysio_oftab_size;
	     fd++, filp++) {
		if (!*filp)
			continue;
		F_RELE(*filp);
		*filp = NULL;
	}

	/*
	 * Release current working directory.
	 */
	if (_sysio_cwd) {
		P_RELE(_sysio_cwd);
		_sysio_cwd = NULL;
	}

	return 0;
}
