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
 */

/*
 * stdlib.c
 *
 * The only purpose of this file is help liblustre adaptive to more
 * applications, and specifically for running on Linux. The ideal
 * final solution would be remove this completely and only rely on
 * system call interception. Unfortunately we failed to find that
 * way at the moment.
 *
 * Initially we try the simplest implementation here, just get a confidence
 * it could work.
 *
 */
#if !(defined(BSD) || defined(REDSTORM))

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#include <sysio.h>

#include "sysio-symbols.h"

#if !defined(__USE_LARGEFILE64)
#error "__LARGEFILE64_SOURCE must be defined"
#endif


/***********************************************************
 * dir series functions                                    *
 ***********************************************************/

#undef  BUFSIZE
#define BUFSIZE	4096

struct __dirstream {
	int               fd;
	loff_t		  base;
	loff_t            filepos;       /* current pos in dir file stream */
	struct dirent    *curent;        /* current dirent pointer */
	struct dirent64  *curent64;      /* current dirent64 pointer */
	struct dirent    *retent;        /* ent returned to caller */
	struct dirent64  *retent64;      /* ent64 returned to caller */
	unsigned int      effective;     /* effective data size in buffer */
	char              buf[BUFSIZE];
};

DIR* opendir(const char *name)
{
	DIR *dir;

	dir = (DIR *) malloc(sizeof(*dir));
	if (!dir) {
		errno = ENOMEM;
		return NULL;
	}

#if __USE_LARGEFILE64
	dir->fd = open64(name, O_RDONLY);
#else
	dir->fd = open(name, O_RDONLY);
#endif
	if (dir->fd < 0)
		goto err_out;

	dir->base = 0;
	dir->filepos = 0;
	dir->curent = (struct dirent *) dir->buf;
	dir->curent64 = (struct dirent64 *) dir->buf;
	dir->retent = NULL;
	dir->retent64 = NULL;
	dir->effective = 0;

	return dir;
err_out:
	free(dir);
	return NULL;
}

sysio_sym_weak_alias(opendir, __opendir);

struct dirent64 *readdir64(DIR *dir)
{
	int rc, reclen;

	/* need to read new data? */
	if ((char*)dir->curent64 - dir->buf >= dir->effective) {
		rc = getdirentries64(dir->fd, dir->buf, BUFSIZE, &dir->base);
		/* error or end-of-file */
		if (rc <= 0)
			return NULL;

		dir->curent64 = (struct dirent64 *) dir->buf;
		dir->effective = rc;
	}

	dir->retent64 = dir->curent64;
	dir->curent64 = (struct dirent64*) ((char *)(dir->curent64) +
				dir->curent64->d_reclen);
#ifdef _DIRENT_HAVE_D_OFF
	dir->filepos = dir->curent64->d_off;
#else
	dir->filepos += dir->curent64->d_reclen;
#endif
	return dir->retent64;
}

sysio_sym_weak_alias(readdir64, __readdir64);

/* XXX probably the following assumption is not true */
#if __WORDSIZE == 64
#define NATURAL_READDIR64
#else
#undef  NATURAL_READDIR64
#endif

#ifndef NATURAL_READDIR64

struct dirent *readdir(DIR *dir)
{
	int rc, reclen;

	/* need to read new data? */
	if ((char*)dir->curent - dir->buf >= dir->effective) {
		rc = getdirentries(dir->fd, dir->buf, BUFSIZE, (off_t*) &dir->base);
		/* error or end-of-file */
		if (rc <= 0)
			return NULL;

		dir->curent = (struct dirent *) dir->buf;
		dir->effective = rc;
	}

	dir->retent = dir->curent;
	dir->curent = (struct dirent*) ((char *)(dir->curent) +
				dir->curent->d_reclen);
#ifdef _DIRENT_HAVE_D_OFF
	dir->filepos = dir->curent->d_off;
#else
	dir->filepos += dir->curent->d_reclen;
#endif
	return dir->retent;
}
sysio_sym_weak_alias(readdir, __readdir);

#else /* NATURAL_READDIR64 */

struct dirent *readdir(DIR *dir) {
	return (struct dirent *) readdir64(dir);
}
sysio_sym_weak_alias(readdir, __readdir);

#endif /* NATURAL_READDIR64 */

int closedir(DIR *dir)
{
	int rc;

	rc = close(dir->fd);

	free(dir);
	return rc;
}

sysio_sym_weak_alias(closedir, __closedir);

int dirfd(DIR *dir)
{
	return dir->fd;
}

off_t telldir(DIR *dir)
{
	return (dir->filepos);
}

void seekdir(DIR *dir, off_t offset)
{
	dir->filepos = offset;

	dir->base = offset;
	dir->curent64 = (struct dirent64 *) dir->buf;
	dir->retent64 = NULL;
	dir->effective = 0;
	dir->curent = (struct dirent *) dir->buf;
	dir->retent = NULL;
}

void rewinddir(DIR *dir)
{
	dir->base = 0;
	dir->filepos = 0;
	dir->curent64 = (struct dirent64 *) dir->buf;
	dir->retent64 = NULL;
	dir->curent = (struct dirent *) dir->buf;
	dir->retent = NULL;
	dir->effective = 0;
}

#if 0
int scandir(const char *dir, struct dirent ***namelist,
            int(*select)(const struct dirent *),
            int(*compar)(const void *, const void *))
{
	errno = ENOSYS;
	return -1;
}

int scandir64(const char *dir, struct dirent64 ***namelist,
              int(*select)(const struct dirent64 *),
              int(*compar)(const void *, const void *))
{
	errno = ENOSYS;
	return -1;
}
#endif

/***********************************************************
 * FIXME workaround for linux only                         *
 ***********************************************************/

#define LINUX
#if defined(LINUX)
ssize_t getxattr(char *path, char *name, void *value, size_t size)
{
	errno = ENOSYS;
	return -1;
}

ssize_t lgetxattr(char *path, char *name, void *value, size_t size)
{
	errno = ENOSYS;
	return -1;
}

ssize_t fgetxattr(int fd, char *name, void *value, size_t size)
{
	errno = ENOSYS;
	return -1;
}

long setxattr(char *path, char *name, void *value, size_t size, int flags)
{
	errno = ENOSYS;
	return -1;
}

long lsetxattr(char *path, char *name, void *value, size_t size, int flags)
{
	errno = ENOSYS;
	return -1;
}

long fsetxattr(int fd, char *name, void *value, size_t size, int flags)
{
	errno = ENOSYS;
	return -1;
}

long listxattr(char *path, char *list, size_t size)
{
	errno = ENOSYS;
	return -1;
}

long llistxattr(char *path, char *list, size_t size)
{
	errno = ENOSYS;
	return -1;
}

long flistxattr(int fd, char *list, size_t size)
{
	errno = ENOSYS;
	return -1;
}

long removexattr(char *path, char *name)
{
	errno = ENOSYS;
	return -1;
}

long lremovexattr(char *path, char *name)
{
	errno = ENOSYS;
	return -1;
}

long fremovexattr(int fd, char *name)
{
	errno = ENOSYS;
	return -1;
}
#endif

#endif
