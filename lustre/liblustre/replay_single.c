/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light user test program
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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



static char mds_server[1024];
static char barrier_script[1024];
static char failover_script[1024];
static char barrier_cmd[1024];
static char failover_cmd[1024];

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

void t1a()
{
        char *path="/mnt/lustre/f1a";
        ENTRY("touch");

        replay_barrier();
        t_touch(path);
        mds_failover();
        t_check_stat(path, NULL);
        t_unlink(path);
        LEAVE();
}

void t2()
{
        char *dir="/mnt/lustre/d2";
        char *path="/mnt/lustre/d2/f2";
        ENTRY("mkdir + contained create");

        replay_barrier();
        t_mkdir(dir);
        t_create(path);
        mds_failover();
        t_check_stat(dir, NULL);
        t_check_stat(path, NULL);
        t_unlink(path);
        t_rmdir(dir);
        LEAVE();
}

void t3()
{
        char *dir="/mnt/lustre/d3";
        char *path="/mnt/lustre/d3/f3";
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

void t4()
{
        char *path="/mnt/lustre/f4";
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
}

extern int portal_debug;
extern int portal_subsystem_debug;

extern void __liblustre_setup_(void);
extern void __liblustre_cleanup_(void);

void usage(const char *cmd)
{
        printf("Usage: %s -s server_name -b \"barrier cmd\" -f \"failover cmd\" [-c config_file]\n", cmd);
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
        int c;

        while ((c = getopt(argc, argv, "s:b:f:c:")) != -1) {
                switch (c) {
                case 's':
                        strcpy(mds_server, optarg);
                        break;
                case 'b':
                        strcpy(barrier_script, optarg);
                        break;
                case 'f':
                        strcpy(failover_script, optarg);
                        break;
                case 'c':
                        setenv("LUSTRE_CONFIG_FILE", optarg, 1);
                        break;
                default:
                        usage(argv[0]);
                        exit(-1);
                }
        }

        if (argc < 4 || optind != argc) {
                usage(argv[0]);
                exit(-1);
        }

        test_ssh();

        /* prepare remote command */
        sprintf(barrier_cmd, "ssh %s \"%s\"", mds_server, barrier_script);
        sprintf(failover_cmd, "ssh %s \"%s\"", mds_server, failover_script);

        __liblustre_setup_();

        t1();
        t1a();
        t2();
        t3();
        t4();

	printf("liblustre is about shutdown\n");
        __liblustre_cleanup_();

	printf("complete successfully\n");
	return 0;
}
