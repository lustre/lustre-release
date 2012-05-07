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
 * lustre/liblustre/tests/replay_single.c
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

#define MAX_STRING_SIZE 2048

static char mds_server[MAX_STRING_SIZE] = {0,};
static char barrier_script[MAX_STRING_SIZE] = {0,};
static char failover_script[MAX_STRING_SIZE] = {0,};
static char barrier_cmd[MAX_STRING_SIZE] = {0,};
static char failover_cmd[MAX_STRING_SIZE] = {0,};
static char ssh_cmd[MAX_STRING_SIZE] = {0,};

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
        char *path="/mnt/lustre/f0";
        ENTRY("empty replay");

        replay_barrier();
        mds_failover();
        t_check_stat_fail(path);
        LEAVE();
}

void t1()
{
        char *path="/mnt/lustre/f1";
        ENTRY("simple create");

        replay_barrier();
        t_create(path);
        mds_failover();
        t_check_stat(path, NULL);
        t_unlink(path);
        LEAVE();
}

void t2a()
{
        char *path="/mnt/lustre/f2a";
        ENTRY("touch");

        replay_barrier();
        t_touch(path);
        mds_failover();
        t_check_stat(path, NULL);
        t_unlink(path);
        LEAVE();
}

void t2b()
{
        char *path="/mnt/lustre/f2b";
        ENTRY("mcreate+touch");

        t_create(path);
        replay_barrier();
        t_touch(path);
        mds_failover();
        t_check_stat(path, NULL);
        t_unlink(path);
        LEAVE();
}


void n_create_delete(int nfiles)
{
        char *base="/mnt/lustre/f3_";
        char path[100];
        char str[100];
        int i;

        replay_barrier();
        for (i = 0; i < nfiles; i++) {
                sprintf(path, "%s%d\n", base, i);
                sprintf(str, "TEST#%d CONTENT\n", i);
                t_echo_create(path, str);
        }
        mds_failover();
        for (i = 0; i < nfiles; i++) {
                sprintf(path, "%s%d\n", base, i);
                sprintf(str, "TEST#%d CONTENT\n", i);
                t_grep(path, str);
        }
        replay_barrier();
        for (i = 0; i < nfiles; i++) {
                sprintf(path, "%s%d\n", base, i);
                t_unlink(path);
        }
        mds_failover();
        for (i = 0; i < nfiles; i++) {
                sprintf(path, "%s%d\n", base, i);
                t_check_stat_fail(path);
        }
        LEAVE();
}

void t3a()
{
        ENTRY("10 create/delete");
        n_create_delete(10);
        LEAVE();
}

void t3b()
{
        ENTRY("30 create/delete(>1'st block precreated)");
        n_create_delete(30);
        LEAVE();
}

void t4()
{
        char *dir="/mnt/lustre/d4";
        char *path="/mnt/lustre/d4/f1";
        ENTRY("mkdir + contained create");

        replay_barrier();
        t_mkdir(dir);
        t_create(path);
        mds_failover();
        t_check_stat(dir, NULL);
        t_check_stat(path, NULL);
        sleep(2); /* wait for log process thread */

        replay_barrier();
        t_unlink(path);
        t_rmdir(dir);
        mds_failover();
        t_check_stat_fail(dir);
        t_check_stat_fail(path);
        LEAVE();
}

void t5()
{
        char *dir="/mnt/lustre/d5";
        char *path="/mnt/lustre/d5/f1";
        ENTRY("mkdir |X| contained create");

        t_mkdir(dir);
        replay_barrier();
        t_create(path);
        mds_failover();
        t_check_stat(dir, NULL);
        t_check_stat(path, NULL);
        t_unlink(path);
        t_rmdir(dir);
        LEAVE();
}

void t6()
{
        char *path="/mnt/lustre/f6";
        int fd;
        ENTRY("open |X| close");

        replay_barrier();
        t_create(path);
        fd = t_open(path);
        sleep(1);
        mds_failover();
        t_check_stat(path, NULL);
        t_close(fd);
        t_unlink(path);
        LEAVE();
}

void t7()
{
        char *path="/mnt/lustre/f7";
        char *path2="/mnt/lustre/f7-2";
        ENTRY("create |X| rename unlink");

        t_create(path);
        replay_barrier();
        t_rename(path, path2);
        mds_failover();
        t_check_stat_fail(path);
        t_check_stat(path2, NULL);
        t_unlink(path2);
}

void t8()
{
        char *path="/mnt/lustre/f8";
        char *path2="/mnt/lustre/f8-2";
        ENTRY("create open write rename |X| create-old-name read");

        t_create(path);
        t_echo_create(path, "old");
        t_rename(path, path2);
        replay_barrier();
        t_echo_create(path, "new");
        mds_failover();
        t_grep(path, "new");
        t_grep(path2, "old");
        t_unlink(path);
        t_unlink(path2);
}

void t9()
{
        char *path="/mnt/lustre/f9";
        char *path2="/mnt/lustre/f9-2";
        ENTRY("|X| open(O_CREAT), unlink, touch new, unlink new");

        replay_barrier();
        t_create(path);
        t_unlink(path);
        t_create(path2);
        mds_failover();
        t_check_stat_fail(path);
        t_check_stat(path2, NULL);
        t_unlink(path2);
}

void t10()
{
        char *path="/mnt/lustre/f10";
        char *path2="/mnt/lustre/f10-2";
        ENTRY("|X| mcreate, open write, rename");

        replay_barrier();
        t_create(path);
        t_echo_create(path, "old");
        t_rename(path, path2);
        t_grep(path2, "old");
        mds_failover();
        t_grep(path2, "old");
        t_unlink(path2);
}

extern int libcfs_debug;
extern int libcfs_subsystem_debug;

extern void __liblustre_setup_(void);
extern void __liblustre_cleanup_(void);

void usage(const char *cmd)
{
        printf("Usage: \t%s --target mdsnid:/mdsname/profile -s mds_hostname "
                "-b \"barrier cmd\" -f \"failover cmd\" [--rsh \"rsh_cmd\"]\n", cmd);
        printf("       \t%s --dumpfile dumpfile -s mds_hostname -b \"barrier cmd\" "
                "-f \"failover cmd\" [--rsh \"rsh_cmd\"]\n", cmd);
        exit(-1);
}

void test_ssh()
{
        char cmd[MAX_STRING_SIZE];

        sprintf(cmd, "%s %s cat /dev/null", ssh_cmd, mds_server);
        if (system(cmd)) {
                printf("Can't access server node: %s using method: %s\n", mds_server, ssh_cmd);
                exit(-1);
        }
}

int main(int argc, char * const argv[])
{
        int opt_index, c;
        static struct option long_opts[] = {
                {"target", 1, 0, 0},
                {"dumpfile", 1, 0, 0},
                {"ssh", 1, 0, 0},
                {0, 0, 0, 0}
        };

        if (argc < 4 - (getenv(ENV_LUSTRE_MNTTGT)||getenv(ENV_LUSTRE_DUMPFILE)))
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
                        } else if (!strcmp(long_opts[opt_index].name, "ssh")) {
                                safe_strncpy(ssh_cmd, optarg, MAX_STRING_SIZE);
                        } else
                                usage(argv[0]);
                        break;
                }
                case 's':
                        safe_strncpy(mds_server, optarg, MAX_STRING_SIZE);
                        break;
                case 'b':
                        safe_strncpy(barrier_script, optarg, MAX_STRING_SIZE);
                        break;
                case 'f':
                        safe_strncpy(failover_script, optarg, MAX_STRING_SIZE);
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

        /* default to using ssh */
        if (!strlen(ssh_cmd)) {
                safe_strncpy(ssh_cmd, "ssh", MAX_STRING_SIZE);
        }

        test_ssh();

        /* prepare remote command */
        sprintf(barrier_cmd, "%s %s \"%s\"", 
                ssh_cmd, mds_server, barrier_script);
        sprintf(failover_cmd, "%s %s \"%s\"", 
                ssh_cmd, mds_server, failover_script);

        setenv(ENV_LUSTRE_TIMEOUT, "10", 1);

        __liblustre_setup_();

        t0();
        t1();
        t2a();
        t2b();
        t3a();
        t3b();
        t4();
        t5();
        t6();
        t7();
        t8();
        t9();
        t10();

	printf("liblustre is about shutdown\n");
        __liblustre_cleanup_();

	printf("complete successfully\n");
	return 0;
}
