/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <utime.h>
#include <stdarg.h>

#include <liblustre.h>

#include "test_common.h"

int exit_on_err = 1;

/******************************************************************
 * util functions
 ******************************************************************/

#ifdef EXIT
#undef EXIT
#endif

#define EXIT(err)					\
	do {						\
		if (exit_on_err)			\
			exit(err);			\
	} while (0)

#define EXIT_RET(err)					\
	do {						\
		if (exit_on_err)			\
			exit(err);			\
		else					\
			return (err);			\
	} while (0)


void t_touch(const char *path)
{
        int fd, rc;

        fd = open(path, O_RDWR|O_CREAT, 0644);
        if (fd < 0) {
                printf("open(%s) error: %s\n", path, strerror(errno));
                EXIT(fd);
        }

        rc = close(fd);
        if (rc) {
                printf("close(%s) error: %s\n", path, strerror(errno));
                EXIT(rc);
        }
}

/* XXX Now libsysio don't support mcreate */
void t_create(const char *path)
{
        return t_touch(path);
#if 0
        int rc;

        rc = mknod(path, S_IFREG | 0644, 0);
        if (rc) {
                printf("mknod(%s) error: %s\n", path, strerror(errno));
                exit(-1);
        }
#endif
}

void t_link(const char *src, const char *dst)
{
	int rc;

	rc = link(src, dst);
	if (rc) {
		printf("link(%s -> %s) error: %s\n", src, dst, strerror(errno));
		EXIT(1);
	}
}

void t_unlink(const char *path)
{
        int rc;

        rc = unlink(path);
        if (rc) {
                printf("unlink(%s) error: %s\n", path, strerror(errno));
                EXIT(-1);
        }
}

void t_mkdir(const char *path)
{
        int rc;

        rc = mkdir(path, 00755);
        if (rc < 0) {
                printf("mkdir(%s) error: %s\n", path, strerror(errno));
                EXIT(1);
        }
}

void t_rmdir(const char *path)
{
        int rc;

        rc = rmdir(path);
        if (rc) {
                printf("rmdir(%s) error: %s\n", path, strerror(errno));
                EXIT(1);
        }
}

void t_symlink(const char *src, const char *new)
{
	int rc;

	rc = symlink(src, new);
	if (rc) {
		printf("symlink(%s<-%s) error: %s\n", src, new, strerror(errno));
		EXIT(1);
	}
}

#define MKDEV(a,b) (((a) << 8) | (b))
void t_mknod(const char *path, mode_t mode, int major, int minor)
{
	int rc;

        rc = mknod(path, mode, MKDEV(5, 4));
        if (rc) {
                printf("mknod(%s) error: %s\n", path, strerror(errno));
                EXIT(1);
        }
}

void t_chmod_raw(const char *path, mode_t mode)
{
	int rc;
	
	rc = chmod(path, mode);
	if (rc) {
                printf("chmod(%s) error: %s\n", path, strerror(errno));
                EXIT(1);
        }
}

void t_chmod(const char *path, const char *format, ...)
{
}

void t_rename(const char *oldpath, const char *newpath)
{
        int rc;

        rc = rename(oldpath, newpath);
        if (rc) {
                printf("rename(%s -> %s) error: %s\n",
		       oldpath, newpath, strerror(errno));
                EXIT(1);
        }
}

int t_open_readonly(const char *path)
{
        int fd;

        fd = open(path, O_RDONLY);
        if (fd < 0) {
                printf("open(%s) error: %s\n", path, strerror(errno));
                EXIT_RET(fd);
        }
        return fd;
}

int t_open(const char *path)
{
        int fd;

        fd = open(path, O_RDWR | O_LARGEFILE);
        if (fd < 0) {
                printf("open(%s) error: %s\n", path, strerror(errno));
                EXIT_RET(fd);
        }
        return fd;
}

int t_chdir(const char *path)
{
        int rc = chdir(path);
        if (rc < 0) {
                printf("chdir(%s) error: %s\n", path, strerror(errno));
                EXIT_RET(rc);
        }
        return rc;
}

int t_utime(const char *path, const struct utimbuf *buf)
{
        int rc = utime(path, buf);
        if (rc < 0) {
                printf("utime(%s, %p) error: %s\n", path, buf,
                       strerror(errno));
                EXIT_RET(rc);
        }
        return rc;
}

int t_opendir(const char *path)
{
        int fd;

        fd = open(path, O_RDONLY);
        if (fd < 0) {
                printf("opendir(%s) error: %s\n", path, strerror(errno));
                EXIT_RET(fd);
        }
        return fd;
}

void t_close(int fd)
{
        int rc;

        rc = close(fd);
        if (rc < 0) {
                printf("close(%d) error: %s\n", fd, strerror(errno));
                EXIT(1);
        }
}

int t_check_stat(const char *name, struct stat *buf)
{
	struct stat stat;
        int rc;

        memset(&stat, 0, sizeof(stat));

	rc = lstat(name, &stat);
        if (rc) {
		printf("error %d stat %s\n", rc, name);
		EXIT_RET(rc);
	}
        if (buf)
                memcpy(buf, &stat, sizeof(*buf));
        if (stat.st_blksize == 0) {
                printf("error: blksize is 0\n");
                EXIT_RET(-EINVAL);
        }

	return 0;
}

int t_check_stat_fail(const char *name)
{
	struct stat stat;
        int rc;

	rc = lstat(name, &stat);
        if (!rc) {
		printf("%s still exists\n", name);
		EXIT(-1);
	}

	return 0;
}

void t_echo_create(const char *path, const char *str)
{
        int fd, rc;

        fd = open(path, O_RDWR|O_CREAT, 0644);
        if (fd < 0) {
                printf("open(%s) error: %s\n", path, strerror(errno));
                EXIT(fd);
        }

	if (write(fd, str, strlen(str)+1) != strlen(str)+1) {
                printf("write(%s) error: %s\n", path, strerror(errno));
                EXIT(fd);
	}

        rc = close(fd);
        if (rc) {
                printf("close(%s) error: %s\n", path, strerror(errno));
                EXIT(rc);
        }
}

static void _t_grep(const char *path, char *str, int should_contain)
{
	char buf[1024];
	int fd;
	int rc;
	
	fd = t_open_readonly(path);
	if (lseek(fd, 0, SEEK_SET) == -1) {
		printf("pread_once: seek to 0 error: %s\n", strerror(errno));
		EXIT(fd);
	}

	rc = read(fd, buf, 1023);
	if (rc < 0) {
		printf("grep: read error: %s\n", strerror(errno));
		EXIT(-1);
	}
	close(fd);
	buf[rc] = 0;

	if ((strstr(buf, str) != 0) ^ should_contain) {
		printf("grep: can't find string %s\n", str);
		EXIT(-1);
	}
}

void t_grep(const char *path, char *str)
{
	_t_grep(path, str, 1);
}

void t_grep_v(const char *path, char *str)
{
	_t_grep(path, str, 0);
}

void t_ls(int fd, char *buf, int size)
{
	struct dirent64 *ent;
	int rc, pos;
	loff_t base = 0;

	printf("dir entries listing...\n");
	while ((rc = getdirentries64(fd, buf, size, &base)) > 0) {
		pos = 0;
		while (pos < rc) {
			ent = (struct dirent64 *)((char *)buf + pos);
			printf("%s\n", ent->d_name);
			pos += ent->d_reclen;
		}
	}

	if (rc < 0) {
		printf("getdents error %d\n", rc);
		EXIT(-1);
	}
}

int t_fcntl(int fd, int cmd, ...)
{
	va_list ap;
	long arg;
	struct flock *lock;
	int rc = -1;

	va_start(ap, cmd);
	switch (cmd) {
	case F_GETFL:
		va_end(ap);
		rc = fcntl(fd, cmd);
		if (rc == -1) {
			printf("fcntl GETFL failed: %s\n",
				 strerror(errno));
			EXIT(1);
		}
		break;
	case F_SETFL:
		arg = va_arg(ap, long);
		va_end(ap);
		rc = fcntl(fd, cmd, arg);
		if (rc == -1) {
			printf("fcntl SETFL %ld failed: %s\n",
				 arg, strerror(errno));
			EXIT(1);
		}
		break;
	case F_GETLK:
#ifdef F_GETLK64
#if F_GETLK64 != F_GETLK
        case F_GETLK64:
#endif
#endif
	case F_SETLK:
#ifdef F_SETLK64
#if F_SETLK64 != F_SETLK
        case F_SETLK64:
#endif
#endif
	case F_SETLKW:
#ifdef F_SETLKW64
#if F_SETLKW64 != F_SETLKW
        case F_SETLKW64:
#endif
#endif
		lock = va_arg(ap, struct flock *);
		va_end(ap);
		rc = fcntl(fd, cmd, lock);
		if (rc == -1) {
			printf("fcntl cmd %d failed: %s\n",
				 cmd, strerror(errno));
			EXIT(1);
		}
		break;
	case F_DUPFD:
		arg = va_arg(ap, long);
		va_end(ap);
		rc = fcntl(fd, cmd, arg);
		if (rc == -1) {
			printf("fcntl F_DUPFD %d failed: %s\n",
				 (int)arg, strerror(errno));
			EXIT(1);
		}
		break;
	default:
		va_end(ap);
		printf("fcntl cmd %d not supported\n", cmd);
		EXIT(1);
	}
	return rc;
}

char *safe_strncpy(char *dst, char *src, int max_size)
{
       int src_size;
       src_size=strlen(src);
       if (src_size >= max_size) {
	 src_size=max_size-1;
       }
       memcpy(dst, src, src_size);
       dst[src_size]=0;

       return(dst);
}
