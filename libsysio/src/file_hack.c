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
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include "sysio.h"
#include "file.h"
#include "inode.h"

/*
 * Support for file IO.
 */

/*
 * The open files table
 */
typedef struct oftab {
	struct file   **table;	/* table array */
	size_t		size;	/* current table size */
	int		offset;	/* base fd number */
	int		max;	/* max size */
} oftab_t;

#define OFTAB_NATIVE	(0)
#define OFTAB_VIRTUAL	(1)

static oftab_t _sysio_oftab[2] = {
	{NULL, 0, 0, 0},
	{NULL, 0, 0, 1024*1024},
};

static int native_max_fds = 0;

static inline void init_oftab()
{
	if (!native_max_fds) {
		native_max_fds = sysconf(_SC_OPEN_MAX);
		if (native_max_fds <= 0)
			abort();
		_sysio_oftab[OFTAB_NATIVE].max = native_max_fds - 1;
		_sysio_oftab[OFTAB_VIRTUAL].offset = native_max_fds;
	}
}

static inline oftab_t *select_oftab(int fd)
{
	return & _sysio_oftab[fd >= native_max_fds || fd < 0];
}

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
	F_REF(fil);
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
	I_RELE(fil->f_ino);
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
fd_grow(oftab_t *oftab, size_t n)
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

	n++;	/* index -> size */
	assert(n > oftab->size);

	if (n > oftab->max)
		return -ERANGE;

	if (n < 8)
		n = 8;
	if (n - oftab->size < oftab->size)
		n = (n + 1) * 2;
	noftab = realloc(oftab->table, n * sizeof(struct file *));
	if (!noftab)
		return -ENOMEM;
	oftab->table = noftab;
	count = oftab->size;
	oftab->size = n;
	if (n < count)
		return 0;
	filp = oftab->table + count;
	n -= count;
	while (n--)
		*filp++ = NULL;
	return 0;
}

#ifdef ZERO_SUM_MEMORY
static void free_oftab(oftab_t *ot)
{
	if (ot->table) {
		free(ot->table);
		ot->size = 0;
	}
}

void
_sysio_fd_shutdown()
{
	free_oftab(&_sysio_oftab[OFTAB_NATIVE]);
	free_oftab(&_sysio_oftab[OFTAB_VIRTUAL]);
}
#endif

/*
 * Find a free slot in the open files table which >= @low
 * low < 0 means any
 */
static int
find_free_fildes(oftab_t *oftab, int low)
 {
	int	n;
 	int	err;
 	struct file **filp;
 
	if (low < 0)
		low = oftab->offset;

	n = low - oftab->offset;
	if (n < 0)
		return -ENFILE;

	for (filp = oftab->table + n;
	     n < oftab->size && *filp;
	     n++, filp++)
		;

	if (n >= oftab->size) {
		err = fd_grow(oftab, n);
 		if (err)
 			return err;
		filp = &oftab->table[n];
 		assert(!*filp);
 	}
 
	return oftab->offset + n;
}

/*
 * Find open file record from file descriptor.
 * clear this entry if 'clear' is non-zero
 */
static struct file *
__sysio_fd_get(int fd, int clear)
{
	oftab_t *oftab;
	struct file *file;

	init_oftab();

	if (fd < 0)
		return NULL;

	oftab = select_oftab(fd);
	if (!oftab->table || fd >= oftab->offset + oftab->size)
		return NULL;

	file = oftab->table[fd - oftab->offset];
	if (clear)
		oftab->table[fd - oftab->offset] = NULL;

	return file;
}

/*
 * Find open file record from file descriptor.
 */
struct file *
_sysio_fd_find(int fd)
{
	return __sysio_fd_get(fd, 0);
}

/*
 * Close an open descriptor.
 */
int
_sysio_fd_close(int fd)
{
	struct file *fil;

	fil = fil = __sysio_fd_get(fd, 1);
	if (!fil)
		return -EBADF;

	F_RELE(fil);

	return 0;
}

/*
 * Associate open file record with given file descriptor (if forced), or any
 * available file descriptor if less than zero, or any available descriptor
 * greater than or equal to the given one if not forced.
 */
int
_sysio_fd_set(struct file *fil, int fd, int force)
{
	int	err;
	struct file *ofil;
	oftab_t *oftab;

	if (force && fd < 0)
		abort();

	init_oftab();

	oftab = select_oftab(fd);

	/*
	 * Search for a free descriptor if needed.
	 */
	if (!force) {
		fd = find_free_fildes(oftab, fd);
		if (fd < 0)
			return fd;
	}

	if (fd - oftab->offset >= oftab->size) {
		err = fd_grow(oftab, fd - oftab->offset);
		if (err)
			return err;
	}

	/*
	 * Remember old.
	 */
	ofil = __sysio_fd_get(fd, 1);
	if (ofil) {
		/* FIXME sometimes we could intercept open/socket to create
		 * a fd, but missing close()? currently we have this problem
		 * with resolv lib. as a workaround simply destroy the file
		 * struct here. And this hack will break the behavior of
		 * DUPFD.
		 */
		if (fd >= 0 && oftab == &_sysio_oftab[0])
			free(ofil);
		else
			F_RELE(ofil);
	}

	oftab->table[fd - oftab->offset] = fil;

	return fd;
}

/*
 * Duplicate old file descriptor.
 *
 * If the new file descriptor is less than zero, the new file descriptor
 * is chosen freely. Otherwise, choose an available descriptor greater
 * than or equal to the new, if not forced. Otherwise, if forced, (re)use
 * the new.
 */
int
_sysio_fd_dup(int oldfd, int newfd, int force)
{
	struct file *fil;
	int	fd;

	init_oftab();

	if (oldfd == newfd && oldfd >= 0)
		return newfd;

	fil = _sysio_fd_find(oldfd);
	if (!fil)
		return -EBADF;

	/* old & new must belong to the same oftab */
	if (select_oftab(oldfd) != select_oftab(newfd))
		return -EINVAL;

	fd = _sysio_fd_set(fil, newfd, force);
	if (fd >= 0)
		F_REF(fil);
	return fd;
}

void
_sysio_oftable_close_all(oftab_t *oftab)
{
	struct file **filp;
	int fd;

	for (fd = 0, filp = oftab->table;
	     (size_t )fd < oftab->size;
	     fd++, filp++) {
		if (!*filp)
			continue;
		F_RELE(*filp);
		*filp = NULL;
	}
}

int
_sysio_fd_close_all()
{
	int	fd;
	struct file **filp;
	oftab_t *oftab;
	int i;

	/*
	 * Close all open descriptors.
	 */
	_sysio_oftable_close_all(&_sysio_oftab[OFTAB_VIRTUAL]);
	/* XXX see liblustre/llite_lib.c for explaination */
#if 0
	_sysio_oftable_close_all(&_sysio_oftab[OFTAB_NATIVE]);
#endif

	/*
	 * Release current working directory.
	 */
	if (_sysio_cwd) {
		P_RELE(_sysio_cwd);
		_sysio_cwd = NULL;
	}

	return 0;
}
