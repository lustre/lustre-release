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
