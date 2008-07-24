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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/time.h>

int thread;

#define BAD_VERBOSE (-999999999)

#define difftime(a, b)                                          \
        ((double)(a)->tv_sec - (b)->tv_sec +                    \
         ((double)((a)->tv_usec - (b)->tv_usec) / 1000000))

static char *cmdname(char *func)
{
        static char buf[512];

        if (thread) {
                sprintf(buf, "%s-%d", func, thread);
                return buf;
        }

        return func;
}

static int be_verbose(int verbose, struct timeval *next_time,
                      unsigned long num, unsigned long *next_num, int num_total)
{
        struct timeval now;

        if (!verbose)
                return 0;

        if (next_time != NULL)
                gettimeofday(&now, NULL);

        /* A positive verbosity means to print every X iterations */
        if (verbose > 0 && (num >= *next_num || num >= num_total)) {
                *next_num += verbose;
                if (next_time) {
                        next_time->tv_sec = now.tv_sec - verbose;
                        next_time->tv_usec = now.tv_usec;
                }
                return 1;
        }

        /* A negative verbosity means to print at most each X seconds */
        if (verbose < 0 && next_time != NULL && difftime(&now, next_time) >= 0){
                next_time->tv_sec = now.tv_sec - verbose;
                next_time->tv_usec = now.tv_usec;
                *next_num = num;
                return 1;
        }

        return 0;
}

static int get_verbose(char *func, const char *arg)
{
        int verbose;
        char *end;

        if (!arg || arg[0] == 'v')
                verbose = 1;
        else if (arg[0] == 's' || arg[0] == 'q')
                verbose = 0;
        else {
                verbose = (int)strtoul(arg, &end, 0);
                if (*end) {
                        fprintf(stderr, "%s: error: bad verbose option '%s'\n",
                                func, arg);
                        return BAD_VERBOSE;
                }
        }

        if (verbose < 0)
                printf("Print status every %d seconds\n", -verbose);
        else if (verbose == 1)
                printf("Print status every operation\n");
        else if (verbose > 1)
                printf("Print status every %d operations\n", verbose);

        return verbose;
}

int main(int argc, char *argv[])
{
        char filename[1024];
        int verbose = 0;
        unsigned long count, i;
        int threads = 0;
        char *end;
        int rc = 0;

        if (argc < 3 || argc > 5) {
                fprintf(stderr,
                        "usage: %s <filename> <count> [verbose [threads]]\n",
                        argv[0]);
                exit(1);
        }

        count = strtoul(argv[2], &end, 0);
        if (*end) {
                fprintf(stderr, "%s: error: bad iteration count '%s'\n",
                        argv[0], argv[1]);
                exit(2);
        }
        if (argc == 4) {
                verbose = get_verbose(argv[0], argv[3]);
                if (verbose == BAD_VERBOSE)
                        exit(2);
        }
        if (argc == 5) {
                threads = strtoul(argv[4], &end, 0);
                if (*end) {
                        fprintf(stderr, "%s: error: bad thread count '%s'\n",
                                argv[0], argv[1]);
                        exit(2);
                }
        }

        for (i = 1; i <= threads; i++) {
                rc = fork();
                if (rc < 0) {
                        fprintf(stderr, "%s: error: #%ld - %s\n",
                                cmdname(argv[0]), i, strerror(rc = errno));
                        break;
                } else if (rc == 0) {
                        thread = i;
                        break;
                } else
                        printf("%s: thread #%ld (PID %d) started\n",
                               cmdname(argv[0]), i, rc);
                rc = 0;
        }

        if (threads && thread == 0) {   /* parent process */
                int live_threads = threads;

                while (live_threads > 0) {
                        int status;
                        pid_t ret;

                        ret = waitpid(0, &status, 0);
                        if (ret == 0) {
                                continue;
                        }

                        if (ret < 0) {
                                fprintf(stderr, "%s: error: wait - %s\n",
                                        argv[0], strerror(errno));
                                if (!rc)
                                        rc = errno;
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
                                                "%s: error: PID %d had rc=%d\n",
                                                argv[0], ret, err);
                                if (!rc)
                                        rc = err;

                                live_threads--;
                        }
                }
        } else {
                struct timeval start, end, next_time;
                unsigned long next_count;
                double diff;

                gettimeofday(&start, NULL);
                next_time.tv_sec = start.tv_sec - verbose;
                next_time.tv_usec = start.tv_usec;

                for (i = 0, next_count = verbose; i < count; i++) {
                        if (threads)
                                sprintf(filename, "%s-%d-%ld",
                                        argv[1], thread, i);
                        else
                                sprintf(filename, "%s-%ld", argv[1], i);

                        rc = mknod(filename, S_IFREG, 0);
                        if (rc < 0) {
                                fprintf(stderr, "%s: error: mknod(%s): %s\n",
                                        cmdname(argv[0]), filename,
                                        strerror(errno));
                                rc = errno;
                                break;
                        }
                        if (unlink(filename) < 0) {
                                fprintf(stderr, "%s: error: unlink(%s): %s\n",
                                        cmdname(argv[0]), filename,
                                        strerror(errno));
                                rc = errno;
                                break;
                        }
                        if (be_verbose(verbose, &next_time,i,&next_count,count))
                                printf("%s: number %ld\n", cmdname(argv[0]), i);
                }

                gettimeofday(&end, NULL);
                diff = difftime(&end, &start);

                printf("%s: %ldx2 files in %.4gs (%.4g ops/s): rc = %d: %s",
                       cmdname(argv[0]), i, diff, (double)i * 2 / diff,
                       rc, ctime(&end.tv_sec));
        }
        return rc;
}
