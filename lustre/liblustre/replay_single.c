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

extern errno;



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

/******************************************************************
 * util functions
 ******************************************************************/

static void touch(const char *filename)
{
        int fd, rc;

        fd = open(filename, O_RDWR|O_CREAT, 0644);
        if (fd < 0) {
                printf("open(%s) error: %s\n", filename, strerror(errno));
                exit(1);
        }

        rc = close(fd);
        if (rc) {
                printf("close(%s) error: %s\n", filename, strerror(errno));
                exit(1);
        }
}

/* XXX Now libsysio don't support mcreate */
static void mcreate(const char *filename)
{
        return touch(filename);
#if 0
        int rc;

        rc = mknod(filename, S_IFREG | 0644, 0);
        if (rc) {
                printf("mknod(%s) error: %s\n", filename, strerror(errno));
                exit(-1);
        }
#endif
}

static void munlink(const char *filename)
{
        int rc;

        rc = unlink(filename);
        if (rc) {
                printf("unlink(%s) error: %s\n", filename, strerror(errno));
                exit(-1);
        }
}

static void mmkdir(const char *filename)
{
        int rc;

        rc = mkdir(filename, 00644);
        if (rc < 0) {
                printf("mkdir(%s) error: %s\n", filename, strerror(errno));
                exit(1);
        }
}

static void mrmdir(const char *filename)
{
        int rc;

        rc = rmdir(filename);
        if (rc) {
                printf("rmdir(%s) error: %s\n", filename, strerror(errno));
                exit(1);
        }
}

static int mopen(const char *filename)
{
        int fd;

        fd = open(filename, O_RDONLY);
        if (fd < 0) {
                printf("open(%s) error: %s\n", filename, strerror(errno));
                exit(1);
        }
        return fd;
}

static void mclose(int fd)
{
        int rc;

        rc = close(fd);
        if (rc < 0) {
                printf("close(%d) error: %s\n", fd, strerror(errno));
                exit(1);
        }
}

static int check_stat(const char *name, struct stat *buf)
{
	struct stat stat;
        int rc;

	rc = lstat(name, &stat);
        if (rc) {
		printf("error %d stat %s\n", rc, name);
		exit(1);
	}
        if (buf)
                memcpy(buf, &stat, sizeof(*buf));

	return 0;
}



#define ENTRY(str)                                              \
        do {                                                    \
                printf("===== start test (%s) =====", (str));   \
                printf("===========================\n");        \
        } while (0)

#define LEAVE()                                                 \
        do {                                                    \
                printf("--- end test successfully ---");        \
                printf("-----------------------------\n");      \
        } while (0)

void t1()
{
        char *path="/mnt/lustre/f1";
        ENTRY("simple create");

        replay_barrier();
        mcreate(path);
        mds_failover();
        check_stat(path, NULL);
        munlink(path);
        LEAVE();
}

void t1a()
{
        char *path="/mnt/lustre/f1a";
        ENTRY("touch");

        replay_barrier();
        touch(path);
        mds_failover();
        check_stat(path, NULL);
        munlink(path);
        LEAVE();
}

void t2()
{
        char *dir="/mnt/lustre/d2";
        char *path="/mnt/lustre/d2/f2";
        ENTRY("mkdir + contained create");

        replay_barrier();
        mmkdir(dir);
        mcreate(path);
        mds_failover();
        check_stat(dir, NULL);
        check_stat(path, NULL);
        munlink(path);
        mrmdir(dir);
        LEAVE();
}

void t3()
{
        char *dir="/mnt/lustre/d3";
        char *path="/mnt/lustre/d3/f3";
        ENTRY("mkdir |X| contained create");

        mmkdir(dir);
        replay_barrier();
        mcreate(path);
        mds_failover();
        check_stat(dir, NULL);
        check_stat(path, NULL);
        munlink(path);
        mrmdir(dir);
        LEAVE();
}

void t4()
{
        char *path="/mnt/lustre/f4";
        int fd;
        ENTRY("open |X| close");

        replay_barrier();
        mcreate(path);
        fd = mopen(path);
        sleep(1);
        mds_failover();
        check_stat(path, NULL);
        mclose(fd);
        munlink(path);
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

#ifndef __CYGWIN__
        t1();
        t1a();
        t2();
        t3();
        t4();
#endif

	printf("liblustre is about shutdown\n");
        __liblustre_cleanup_();

	printf("complete successfully\n");
	return 0;
}
