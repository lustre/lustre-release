/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <stdarg.h>

#define MAX_PATH_LENGTH 4096
/**
 * helper functions
 */
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
                        fprintf(stderr, "fcntl GETFL failed: %s\n",
                                strerror(errno));
                        return(1);
                }
                break;
        case F_SETFL:
                arg = va_arg(ap, long);
                va_end(ap);
                rc = fcntl(fd, cmd, arg);
                if (rc == -1) {
                        fprintf(stderr, "fcntl SETFL %ld failed: %s\n",
                                arg, strerror(errno));
                        return(1);
                }
                break;
        case F_GETLK:
        case F_SETLK:
        case F_SETLKW:
                lock = va_arg(ap, struct flock *);
                va_end(ap);
                rc = fcntl(fd, cmd, lock);
                if (rc == -1) {
                        fprintf(stderr, "fcntl cmd %d failed: %s\n",
                                cmd, strerror(errno));
                        return(1);
                }
                break;
        case F_DUPFD:
                arg = va_arg(ap, long);
                va_end(ap);
                rc = fcntl(fd, cmd, arg);
                if (rc == -1) {
                        fprintf(stderr, "fcntl F_DUPFD %d failed: %s\n",
                                (int)arg, strerror(errno));
                        return(1);
                }
                break;
        default:
                va_end(ap);
                fprintf(stderr, "fcntl cmd %d not supported\n", cmd);
                return(1);
        }
        return rc;
}

int t_unlink(const char *path)
{
        int rc;

        rc = unlink(path);
        if (rc)
                fprintf(stderr, "unlink(%s) error: %s\n", path, strerror(errno));
        return rc;
}

/** =================================================================
 * test number 1
 * 
 * normal flock test
 */
void t1_usage(void)
{
        fprintf(stderr, "usage: ./flocks_test 1 on|off -c|-f|-l /path/to/file\n");
}

int t1(int argc, char *argv[])
{
        int fd;
        int mount_with_flock = 0;
        int error = 0;

        if (argc != 5) {
                t1_usage();
                return EXIT_FAILURE;
        }

        if (!strncmp(argv[2], "on", 3)) {
                mount_with_flock = 1;
        } else if (!strncmp(argv[2], "off", 4)) {
                mount_with_flock = 0;
        } else {
                t1_usage();
                return EXIT_FAILURE;
        }

        if ((fd = open(argv[4], O_RDWR)) < 0) {
                fprintf(stderr, "Couldn't open file: %s\n", argv[3]);
                return EXIT_FAILURE;
        }

        if (!strncmp(argv[3], "-c", 3)) {
                struct flock fl;

                fl.l_type = F_RDLCK;
                fl.l_whence = SEEK_SET;
                fl.l_start = 0;
                fl.l_len = 1;

                error = fcntl(fd, F_SETLK, &fl);
        } else if (!strncmp(argv[3], "-l", 3)) {
                error = lockf(fd, F_LOCK, 1);
        } else if (!strncmp(argv[3], "-f", 3)) {
                error = flock(fd, LOCK_EX);
        } else {
                t1_usage();
                return EXIT_FAILURE;
        }

        if (mount_with_flock)
                return((error == 0) ? EXIT_SUCCESS : EXIT_FAILURE);
        else
                return((error == 0) ? EXIT_FAILURE : EXIT_SUCCESS);
}

/** ===============================================================
 * test number 2
 * 
 * 2 threads flock ops interweave
 */
typedef struct {
        struct flock* lock;
        int fd;
} th_data;

void* t2_thread1(void *arg)
{
        struct flock *lock = ((th_data *)arg)->lock;
        int fd             = ((th_data *)arg)->fd;

        printf("thread 1: set write lock (blocking)\n");
        lock->l_type = F_WRLCK;
        t_fcntl(fd, F_SETLKW, lock);
        printf("thread 1: set write lock done\n");
        t_fcntl(fd, F_GETLK, lock);
        printf("thread 1: unlock\n");
        lock->l_type = F_UNLCK;
        t_fcntl(fd, F_SETLK, lock);
        printf("thread 1: unlock done\n");
        return 0;
}

void* t2_thread2(void *arg)
{
        struct flock *lock = ((th_data *)arg)->lock;
        int fd             = ((th_data *)arg)->fd;

        sleep(2);
        printf("thread 2: unlock\n");
        lock->l_type = F_UNLCK;
        t_fcntl(fd, F_SETLK, lock);
        printf("thread 2: unlock done\n");
        printf("thread 2: set write lock (non-blocking)\n");
        lock->l_type = F_WRLCK;
        t_fcntl(fd, F_SETLK, lock);
        printf("thread 2: set write lock done\n");
        t_fcntl(fd, F_GETLK, lock);
        return 0;
}

int t2(int argc, char* argv[])
{
        struct flock lock = {
                .l_type = F_RDLCK,
                .l_whence = SEEK_SET,
        };
        char file[MAX_PATH_LENGTH] = "";
        int  fd, rc;
        pthread_t th1, th2;
        th_data   ta;

        snprintf(file, MAX_PATH_LENGTH, "%s/test_t2_file", argv[2]);

        fd = open(file, O_RDWR|O_CREAT, (mode_t)0666);
        if (fd < 0) {
                fprintf(stderr, "error open file: %s\n", file);
                return EXIT_FAILURE;
        }

        t_fcntl(fd, F_SETFL, O_APPEND);
        rc = t_fcntl(fd, F_GETFL);
        if ((rc & O_APPEND) == 0) {
                fprintf(stderr, "error get flag: ret %x\n", rc);
                return EXIT_FAILURE;
        }

        ta.lock = &lock;
        ta.fd   = fd;
        rc = pthread_create(&th1, NULL, t2_thread1, &ta);
        if (rc) {
                fprintf(stderr, "error create thread 1\n");
                rc = EXIT_FAILURE;
                goto out;
        }
        rc = pthread_create(&th2, NULL, t2_thread2, &ta);
        if (rc) {
                fprintf(stderr, "error create thread 2\n");
                rc = EXIT_FAILURE;
                goto out;
        }
        (void)pthread_join(th1, NULL);
        (void)pthread_join(th2, NULL);
out:
        t_unlink(file);
        close(fd);
        return rc;
}

/** =================================================================
 * test number 3
 *
 * Bug 24040: Two conflicting flocks from same process different fds should fail
 *            two conflicting flocks from different processes but same fs
 *            should succeed.
 */
int t3(int argc, char *argv[])
{
        int fd, fd2;
        int pid;
        int rc = EXIT_SUCCESS;

        if (argc != 3) {
                fprintf(stderr, "Usage: ./flocks_test 3 filename\n");
                return EXIT_FAILURE;
        }

        if ((fd = open(argv[2], O_RDWR)) < 0) {
                fprintf(stderr, "Couldn't open file: %s\n", argv[1]);
                return EXIT_FAILURE;
        }
        if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
                perror("first flock failed");
                rc = EXIT_FAILURE;
                goto out;
        }
        if ((fd2 = open(argv[2], O_RDWR)) < 0) {
                fprintf(stderr, "Couldn't open file: %s\n", argv[1]);
                rc = EXIT_FAILURE;
                goto out;
        }
        if (flock(fd2, LOCK_EX | LOCK_NB) >= 0) {
                fprintf(stderr, "Second flock succeeded - FAIL\n");
                rc = EXIT_FAILURE;
                close(fd2);
                goto out;
        }

        close(fd2);

        pid = fork();
        if (pid == -1) {
                perror("fork");
                rc = EXIT_FAILURE;
                goto out;
        }

        if (pid == 0) {
                if ((fd2 = open(argv[2], O_RDWR)) < 0) {
                        fprintf(stderr, "Couldn't open file: %s\n", argv[1]);
                        rc = EXIT_FAILURE;
                        exit(rc);
                }
                if (flock(fd2, LOCK_EX | LOCK_NB) >= 0) {
                        fprintf(stderr, "Second flock succeeded - FAIL\n");
                        rc = EXIT_FAILURE;
                        goto out_child;
                }
                if (flock(fd, LOCK_UN) == -1) {
                        fprintf(stderr, "Child unlock on parent fd failed\n");
                        rc = EXIT_FAILURE;
                        goto out_child;
                }
                if (flock(fd2, LOCK_EX | LOCK_NB) == -1) {
                        fprintf(stderr, "Relock after parent unlock failed!\n");
                        rc = EXIT_FAILURE;
                        goto out_child;
                }
        out_child:
                close(fd2);
                exit(rc);
        }

        waitpid(pid, &rc, 0);
out:
        close(fd);
        return rc;
}


/** ==============================================================
 * program entry
 */
void usage(void)
{
        fprintf(stderr, "usage: ./flocks_test test# [corresponding arguments]\n");
}

int main(int argc, char* argv[])
{
        int test_no;
        int rc = EXIT_SUCCESS;

        if (argc < 1) {
                usage();
                exit(EXIT_FAILURE);
        }
        test_no = atoi(argv[1]);

        switch(test_no) {
        case 1:
                rc = t1(argc, argv);
                break;
        case 2:
                rc = t2(argc, argv);
                break;
        case 3:
                rc = t3(argc, argv);
                break;
        default:
                fprintf(stderr, "unknow test number %s\n", argv[1]);
                break;
        }
        return rc;
}
