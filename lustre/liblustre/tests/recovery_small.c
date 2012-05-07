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
 * lustre/liblustre/tests/recovery_small.c
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
#include <getopt.h>
#include <sys/wait.h>

#include <sysio.h>
#include <mount.h>

#include "test_common.h"

#define MAX_STRING_SIZE 2048

static struct {
        const char   *name;
        unsigned long code;
} drop_arr [] =
{
        {"MDS_REQUEST", 0x123},
        {"MDS_REPLY", 0x122},
        {NULL, 0}
};

static int drop_index = 0;

static char mds_server[1024] = {0, };
static char ssh_cmd[MAX_STRING_SIZE] = {0,};

int do_stat(const char *name, struct stat *buf)
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

void prepare_reg(const char *path)
{
        int fd, rc;

        fd = open(path, O_RDWR|O_CREAT, 00644);
        if (fd < 0) {
                printf("error %d create %s\n", fd, path);
                exit(1);
        }

        rc = close(fd);
        if (rc) {
                printf("error %d close %s\n", rc, path);
                exit(1);
        }
}

void cleanup_reg(const char *path)
{
        int rc;

        rc = unlink(path);
        if (rc) {
                printf("error %d unlink %s\n", rc, path);
                exit(1);
        }
}

void prepare_dir(const char *path)
{
        int rc;

        rc = mkdir(path, 00644);
        if (rc < 0) {
                printf("error %d mkdir %s\n", rc, path);
                exit(1);
        }
}

void cleanup_dir(const char *path)
{
        int rc;

        rc = rmdir(path);
        if (rc) {
                printf("error %d unlink %s\n", rc, path);
                exit(1);
        }
}

#define FAIL()                                                             \
    do {                                                                   \
        char cmd[MAX_STRING_SIZE];                                         \
        int rc;                                                            \
                                                                           \
        if (drop_arr[drop_index].name) {                                   \
            printf("server drops next %s\n", drop_arr[drop_index].name);   \
            sprintf(cmd,                                                   \
                    "%s %s \"lctl set_param fail_loc=%lu\"",               \
                    ssh_cmd, mds_server, drop_arr[drop_index].code);       \
            if ((rc = system(cmd)) != 0) {                                 \
                rc = WEXITSTATUS(rc);                                      \
                printf("error excuting remote command: %d\n", rc);         \
                exit(rc);                                                  \
            }                                                              \
        }                                                                  \
    } while (0)

#define RECOVER()                                                          \
    do {                                                                   \
        char cmd[1024];                                                    \
                                                                           \
        if (drop_arr[drop_index].name) {                                   \
            sprintf(cmd, "%s %s \"lctl set_param fail_loc=0\"",            \
                    ssh_cmd, mds_server);                                  \
            if (!system(cmd)) {}                                           \
        }                                                                  \
    } while (0)

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
        char *path="/mnt/lustre/test_t1";
        ENTRY("create/delete");

        FAIL();
        t_touch(path);
        RECOVER();
        FAIL();
        t_unlink(path);
        RECOVER();
        LEAVE();
}

void t2()
{
        char *path="/mnt/lustre/test_t2";
        ENTRY("mkdir/rmdir");

        FAIL();
        t_mkdir(path);
        RECOVER();
        FAIL();
        t_rmdir(path);
        RECOVER();
        LEAVE();
}

void t3()
{
        char *path="/mnt/lustre/test_t3";
        ENTRY("regular stat");

        t_touch(path);
        FAIL();
        t_check_stat(path, NULL);
        RECOVER();
        t_unlink(path);
        LEAVE();
}

void t4()
{
        char *path="/mnt/lustre/test_t4";
        ENTRY("dir stat");

        t_mkdir(path);
        FAIL();
        t_check_stat(path, NULL);
        RECOVER();
        t_rmdir(path);
        LEAVE();
}

void t5()
{
        char *path="/mnt/lustre/test_t5";
        const int bufsize = 4096;
	char wbuf[bufsize], rbuf[bufsize];
        int npages = 100;
        int fd, rc, i;
        ENTRY("sequential page aligned file I/O");

        t_touch(path);

	fd = t_open(path);

	for (i = 0; i < npages; i++ ) {
                memset(wbuf, i, bufsize);
		rc = write(fd, wbuf, bufsize);
                if (rc != bufsize) {
                        printf("write error %d (i = %d)\n", rc, i);
                        exit(1);
                }
	}
        printf("succefully write %d pages\n", npages);

	lseek(fd, 0, SEEK_SET);

	for (i = 0; i < npages; i++ ) {
		memset(rbuf, 0, bufsize);
		rc = read(fd, rbuf, bufsize);
                if (rc != bufsize) {
                        printf("read error %d (i = %d)\n", rc, i);
                        exit(1);
                }
	}
        printf("succefully read & verified %d pages\n", npages);

        t_close(fd);

        t_unlink(path);
        LEAVE();
}

void t6()
{
        char *path="/mnt/lustre/test_t6";
        char *path2="/mnt/lustre/test_t6_link";
        ENTRY("symlink");

        t_touch(path);
        FAIL();
        t_symlink(path, path2);
        RECOVER();
        t_check_stat(path2, NULL);
        t_unlink(path2);
        t_unlink(path);
        LEAVE();
}

void t7()
{
        char *path="/mnt/lustre/test_t7";
        ENTRY("mknod");

        FAIL();
        t_mknod(path, S_IFCHR | 0644, 5, 4);
        RECOVER();
        t_check_stat(path, NULL);
        t_unlink(path);
        LEAVE();
}

extern int libcfs_debug;
extern int libcfs_subsystem_debug;

extern void __liblustre_setup_(void);
extern void __liblustre_cleanup_(void);

void usage(const char *cmd)
{
        printf("Usage: \t%s -s mds_hostname --target mdsnid:/mdsname/profile\n", cmd);
        printf("       \t%s -s mds_hostname --dumpfile dumpfile\n", cmd);
        exit(-1);
}

int main(int argc, char * argv[])
{
        int opt_index, c;
        char cmd[1024];
        static struct option long_opts[] = {
                {"target", 1, 0, 0},
                {"dumpfile", 1, 0, 0},
                {"ssh", 1, 0, 0},
                {0, 0, 0, 0}
        };

        if (argc < 3 - (getenv(ENV_LUSTRE_MNTTGT)||getenv(ENV_LUSTRE_DUMPFILE)))
                usage(argv[0]);

        while ((c = getopt_long(argc, argv, "s:", long_opts, &opt_index)) != -1) {
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
                default:
                        usage(argv[0]);
                }
        }

        if (optind != argc)
                usage(argv[0]);

        if (strlen(mds_server) == 0)
                usage(argv[0]);

        /* default to using ssh */
        if (!strlen(ssh_cmd)) {
                safe_strncpy(ssh_cmd, "ssh", MAX_STRING_SIZE);
        }

        sprintf(cmd, "%s %s cat /dev/null", ssh_cmd, mds_server);
        if (system(cmd)) {
                printf("Can't access server node: %s using method: %s\n", mds_server, ssh_cmd);
                exit(-1);
        }

        setenv(ENV_LUSTRE_TIMEOUT, "5", 1);

        __liblustre_setup_();

        while (drop_arr[drop_index].name) {
                t1();
                t2();
                t3();
                t4();
#if 0
                t5();
#endif
                t6();
                t7();

                drop_index++;
        }

	printf("liblustre is about shutdown\n");
        __liblustre_cleanup_();

	printf("complete successfully\n");
        return (0);
}
