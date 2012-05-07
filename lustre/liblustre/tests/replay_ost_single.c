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
 *
 * lustre/liblustre/tests/replay_ost_single.c
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

#include <sysio.h>
#include <mount.h>

#include "test_common.h"



static char mds_server[1024] = {0,};
static char barrier_script[1024] = {0,};
static char failover_script[1024] = {0,};
static char barrier_cmd[1024] = {0,};
static char failover_cmd[1024] = {0,};

static void replay_barrier()
{
        int rc;

        if ((rc = system(barrier_cmd))) {
                printf("excute barrier error: %d\n", rc);
                exit(rc);
        }
}

static void mds_failover()
{
        int rc;

        if ((rc = system(failover_cmd))) {
                printf("excute failover error: %d\n", rc);
                exit(rc);
        }
}


#define ENTRY(str)                                                      \
        do {                                                            \
                char buf[100];                                          \
                int len;                                                \
                sprintf(buf, "===== START: %s ", (str));                \
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
                printf("----- END TEST successfully ---");              \
                printf("-----------------------------");                \
                printf("-------------------\n");                        \
        } while (0)

void t0()
{
        const int bufsize = 4096;
        char *path = "/mnt/lustre/rp_ost_t0_file";
        char buf[bufsize];
        int fd, i, j, rc;
        ENTRY("open-failover-write-verification (no ping involved)");

        printf("create/open file...\n");
        t_touch(path);
        fd = t_open(path);
        printf("OST failover...\n");
        replay_barrier();
        mds_failover();

        printf("write file...\n");
        for (i = 0; i < 20; i++) {
                memset(buf, i, bufsize);
                if ((rc = write(fd, buf, bufsize)) != bufsize) {
                        perror("write error after failover");
                        printf("i = %d, rc = %d\n", i, rc);
                        exit(-1);
                }
        }

        /* verify */
        printf("read & verify...\n");
        lseek(fd, 0, SEEK_SET);
        for (i = 0; i < 20; i++) {
                memset(buf, -1, bufsize);
                if ((rc = read(fd, buf, bufsize)) != bufsize) {
                        perror("read error rc");
                        printf("i = %d, rc = %d\n", i, rc);
                        exit(-1);
                }
                for (j = 0; j < bufsize; j++) {
                        if (buf[j] != i) {
                                printf("verify error!\n");
                                exit(-1);
                        }
                }
        }
        t_close(fd);
        t_unlink(path);
        LEAVE();
}

void t1()
{
        const int bufsize = 4096;
        char *path = "/mnt/lustre/rp_ost_t1_file";
        char buf[bufsize];
        int fd, i, j;
        ENTRY("open-write-close-open-failover-read (no ping involved)");

        printf("create/open file...\n");
        t_touch(path);
        fd = t_open(path);
        printf("write file...\n");
        for (i = 0; i < 20; i++) {
                memset(buf, i, bufsize);
                if (write(fd, buf, bufsize) != bufsize) {
                        perror("write error");
                        exit(-1);
                }
        }
        printf("close/reopen...\n");
        t_close(fd);
        fd = t_open(path);
        lseek(fd, 0, SEEK_SET);

        printf("OST failover...\n");
        replay_barrier();
        mds_failover();

        printf("read & verify...\n");
        for (i = 0; i < 20; i++) {
                memset(buf, -1, bufsize);
                if (read(fd, buf, bufsize) != bufsize) {
                        perror("read error after failover");
                        exit(-1);
                }
                for (j = 0; j < bufsize; j++) {
                        if (buf[j] != i) {
                                printf("verify error after failover\n");
                                exit(-1);
                        }
                }
        }

        t_close(fd);
        t_unlink(path);
        LEAVE();
}

void t2()
{
        char *path = "/mnt/lustre/rp_ost_t2_file";
        char *str = "xxxxjoiwlsdf98lsjdfsjfoajflsjfajfoaidfojaj08eorje;";
        ENTRY("empty replay");

        replay_barrier();
        mds_failover();

        t_echo_create(path, str);
        t_grep(path, str);
        t_unlink(path);
}

void t3()
{
        char *path = "/mnt/lustre/rp_ost_t3_file";
        char *str = "xxxxjoiwlsdf98lsjdfsjfoajflsjfajfoaidfojaj08eorje;";
        ENTRY("touch");

        printf("touch to create a file\n");
        t_echo_create(path, str);
        replay_barrier();
        mds_failover();

        printf("read & verify\n");
        t_grep(path, str);
        t_unlink(path);
        /* XXX have problem without this, seems server side problem XXX */
        sleep(5);
}

void t4()
{
        char *path = "/mnt/lustre/rp_ost_t4_file";
        char namebuf[1024];
        char str[1024];
        int count = 10, i;
        ENTRY("|X| 10 open(CREAT)s (ping involved)");

        printf("create %d files\n", count);
        for (i = 0; i < count; i++) {
                sprintf(namebuf, "%s%02d", path, i);
                sprintf(str, "%s-%08d-%08x-AAAAA", "content", i, i);
                t_echo_create(namebuf, str);
        }
        replay_barrier();
        mds_failover();

        printf("read & verify\n");
        for (i = 0; i < count; i++) {
                sprintf(namebuf, "%s%02d", path, i);
                sprintf(str, "%s-%08d-%08x-AAAAA", "content", i, i);
                t_grep(namebuf, str);
                t_unlink(namebuf);
        }
}

extern int libcfs_debug;
extern int libcfs_subsystem_debug;

extern void __liblustre_setup_(void);
extern void __liblustre_cleanup_(void);

void usage(const char *cmd)
{
        printf("Usage: \t%s --target mdsnid:/mdsname/profile -s ost_hostname "
                "-b \"barrier cmd\" -f \"failover cmd\"\n", cmd);
        printf("       \t%s --dumpfile dumpfile -s ost_hostname -b \"barrier cmd\" "
                "-f \"failover cmd\"\n", cmd);
        exit(-1);
}

void test_ssh()
{
        char cmd[1024];

        sprintf(cmd, "ssh %s cat /dev/null", mds_server);
        if (system(cmd)) {
                printf("ssh can't access server node: %s\n", mds_server);
                exit(-1);
        }
}

int main(int argc, char * const argv[])
{
        int opt_index, c;
        static struct option long_opts[] = {
                {"target", 1, 0, 0},
                {"dumpfile", 1, 0, 0},
                {0, 0, 0, 0}
        };

        if (argc < 4)
                usage(argv[0]);

        while ((c = getopt_long(argc, argv, "s:b:f:", long_opts, &opt_index)) != -1) {
                switch (c) {
                case 0: {
                        if (!optarg[0])
                                usage(argv[0]);

                        if (!strcmp(long_opts[opt_index].name, "target")) {
                                setenv(ENV_LUSTRE_MNTTGT, optarg, 1);
                        } else if (!strcmp(long_opts[opt_index].name, "dumpfile")) {
                                setenv(ENV_LUSTRE_DUMPFILE, optarg, 1);
                        } else
                                usage(argv[0]);
                        break;
                }
                case 's':
                        strcpy(mds_server, optarg);
                        break;
                case 'b':
                        strcpy(barrier_script, optarg);
                        break;
                case 'f':
                        strcpy(failover_script, optarg);
                        break;
                default:
                        usage(argv[0]);
                }
        }

        if (optind != argc)
                usage(argv[0]);
        if (!strlen(mds_server) || !strlen(barrier_script) ||
            !strlen(failover_script))
                usage(argv[0]);

        test_ssh();

        /* prepare remote command */
        sprintf(barrier_cmd, "ssh %s \"%s\"", mds_server, barrier_script);
        sprintf(failover_cmd, "ssh %s \"%s\"", mds_server, failover_script);

        setenv(ENV_LUSTRE_TIMEOUT, "5", 1);

        __liblustre_setup_();

        t0();
        t1();
        t2();
        t3();
        t4();

	printf("liblustre is about shutdown\n");
        __liblustre_cleanup_();

	printf("complete successfully\n");
	return 0;
}
