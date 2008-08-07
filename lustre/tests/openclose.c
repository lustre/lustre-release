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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

/* for O_DIRECT */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include <libcfs/libcfs.h>
#include <lustre/lustre_user.h>
#ifndef O_DIRECT
#define O_DIRECT 0
#endif

int main(int argc, char *argv[])
{
        char filename[1024];
        unsigned long count, i;
        int thread = 0;
        int threads = 0;
        int rc = 0;
        int fd, ioctl_flags = 0;

        if (argc < 3 || argc > 4) {
                fprintf(stderr, "usage: %s <filename> <iterations> [threads]\n",
                        argv[0]);
                exit(1);
        }

        count = strtoul(argv[2], NULL, 0);
        if (argc == 4)
                threads = strtoul(argv[3], NULL, 0);

        for (i = 1; i <= threads; i++) {
                rc = fork();
                if (rc < 0) {
                        fprintf(stderr, "error: %s: #%ld - %s\n", argv[0], i,
                                strerror(rc = errno));
                        break;
                } else if (rc == 0) {
                        thread = i;
                        argv[2] = "--device";
                        break;
                } else
                        printf("%s: thread #%ld (PID %d) started\n",
                               argv[0], i, rc);
                rc = 0;
        }

        if (threads && thread == 0) {        /* parent process */
                int live_threads = threads;

                while (live_threads > 0) {
                        int status;
                        pid_t ret;

                        ret = waitpid(0, &status, 0);
                        if (ret == 0)
                                continue;

                        if (ret < 0) {
                                if (!rc)
                                        rc = errno;
                                fprintf(stderr, "error: %s: wait - %s\n",
                                        argv[0], strerror(rc));
                        } else {
                                /*
                                 * This is a hack.  We _should_ be able to use
                                 * WIFEXITED(status) to see if there was an
                                 * error, but it appears to be broken and it
                                 * always returns 1 (OK).  See wait(2).
                                 */
                                int err = WEXITSTATUS(status);
                                if (err || WIFSIGNALED(status))
                                        fprintf(stderr,
                                                "%s: PID %d had rc=%d\n",
                                                argv[0], ret, err);
                                if (!rc)
                                        rc = err;
                        }
                        live_threads--;
                }
        } else {
                if (threads)
                        sprintf(filename, "%s-%d", argv[1], thread);
                else
                        strcpy(filename, argv[1]);

                fd = open(filename, O_RDWR|O_CREAT, 0644);
                if (fd < 0) {
                        rc = errno;
                        fprintf(stderr, "open(%s, O_CREAT): %s\n", filename,
                                strerror(rc));
                        exit(rc);
                }
                if (close(fd) < 0) {
                        rc = errno;
                        fprintf(stderr, "close(): %s\n", strerror(rc));
                        goto unlink;
                }

                for (i = 0; i < count; i++) {
                        fd = open(filename, O_RDWR|O_LARGEFILE|O_DIRECT);
                        if (fd < 0) {
                                rc = errno;
                                fprintf(stderr, "open(%s, O_RDWR): %s\n",
                                        filename, strerror(rc));
                                break;
                        }
                        if (ioctl(fd, LL_IOC_SETFLAGS, &ioctl_flags) < 0 &&
                            errno != ENOTTY) {
                                rc = errno;
                                fprintf(stderr, "ioctl(): %s\n", strerror(rc));
                                break;
                        }
                        if (close(fd) < 0) {
                                rc = errno;
                                fprintf(stderr, "close(): %s\n", strerror(rc));
                                break;
                        }
                }
        unlink:
                if (unlink(filename) < 0) {
                        rc = errno;
                        fprintf(stderr, "unlink(%s): %s\n", filename,
                                strerror(rc));
                }
                if (threads)
                        printf("Thread %d done: rc = %d\n", thread, rc);
                else
                        printf("Done: rc = %d\n", rc);
        }
        return rc;
}
