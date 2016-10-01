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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/tests/flock.c
 *
 * Lustre Light user test program
 */

#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/queue.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <stdarg.h>

static char lustre_path[] = "/mnt/lustre";

#define ENTRY(str)                                                      \
        do {                                                            \
                char buf[100];                                          \
                int len;                                                \
                sprintf(buf, "===== START %s: %s ", __FUNCTION__, (str)); \
                len = strlen(buf);                                      \
                if (len < 79) {                                         \
                        memset(buf+len, '=', 100-len);                  \
                        buf[79] = '\n';                                 \
                        buf[80] = 0;                                    \
                }                                                       \
                printf("%s", buf);                                      \
        } while (0)

#define LEAVE()                                                         \
        do {                                                            \
                char buf[100];                                          \
                int len;                                                \
                sprintf(buf, "===== END TEST %s: successfully ",        \
                        __FUNCTION__);                                  \
                len = strlen(buf);                                      \
                if (len < 79) {                                         \
                        memset(buf+len, '=', 100-len);                  \
                        buf[79] = '\n';                                 \
                        buf[80] = 0;                                    \
                }                                                       \
                printf("%s", buf);                                      \
        } while (0)

#define EXIT return

#define MAX_PATH_LENGTH 4096


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
	case F_SETLK:
	case F_SETLKW:
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
        printf("fcntl %d = %d, ltype = %d\n", cmd, rc, lock->l_type);
	return rc;
}

int t_unlink(const char *path)
{
        int rc;

        rc = unlink(path);
        if (rc) {
                printf("unlink(%s) error: %s\n", path, strerror(errno));
                EXIT(-1);
        }
        return rc;
}

void t21()
{
        char file[MAX_PATH_LENGTH] = "";
        int fd, ret;
	struct flock lock = {
		.l_type = F_RDLCK,
		.l_whence = SEEK_SET,
	};

        ENTRY("basic fcntl support");
        snprintf(file, MAX_PATH_LENGTH, "%s/test_t21_file", lustre_path);

        fd = open(file, O_RDWR|O_CREAT, (mode_t)0666);
        if (fd < 0) {
		printf("open(%s) error: %s\n", file, strerror(errno));
                exit(-1);
        }

        t_fcntl(fd, F_SETFL, O_APPEND);
        if (!(ret = t_fcntl(fd, F_GETFL)) & O_APPEND) {
                printf("error get flag: ret %x\n", ret);
                exit(-1);
        }

	t_fcntl(fd, F_SETLK, &lock);
	t_fcntl(fd, F_GETLK, &lock);
	lock.l_type = F_WRLCK;
	t_fcntl(fd, F_SETLKW, &lock);
	t_fcntl(fd, F_GETLK, &lock);
	lock.l_type = F_UNLCK;
	t_fcntl(fd, F_SETLK, &lock);

        close(fd);
        t_unlink(file);
        LEAVE();
}


int main(int argc, char * const argv[])
{
        /* Set D_VFSTRACE to see messages from ll_file_flock.
           The test passes either with -o flock or -o noflock 
           mount -o flock -t lustre uml1:/mds1/client /mnt/lustre */
        t21();

	printf("completed successfully\n");
	return 0;
}
