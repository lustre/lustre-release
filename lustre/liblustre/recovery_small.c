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
#include <getopt.h>

#include <sysio.h>
#include <mount.h>


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

char mds_server[1024];

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
        char cmd[1024];                                                    \
        int rc;                                                            \
                                                                           \
        if (drop_arr[drop_index].name) {                                   \
            printf("server drops next %s\n", drop_arr[drop_index].name);   \
            sprintf(cmd,                                                   \
                    "ssh %s \"echo %lu > /proc/sys/lustre/fail_loc\"",     \
                    mds_server, drop_arr[drop_index].code);                \
            if (system(cmd)) {                                             \
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
            sprintf(cmd, "ssh %s \"echo 0 > /proc/sys/lustre/fail_loc\"",  \
                    mds_server);                                           \
            system(cmd);                                                   \
        }                                                                  \
    } while (0)

#define ENTRY(str)                                                         \
    do {                                                                   \
        printf("+++++ start test (%s) +++++\n", (str));                    \
    } while (0)

#define LEAVE()                                                            \
    do {                                                                   \
        printf("----- end test successfully -----\n");                     \
    } while (0)

void t1()
{
        char *path="/mnt/lustre/test_t1";
        ENTRY("create/delete");

        FAIL();
        prepare_reg(path);
        RECOVER();
        FAIL();
        cleanup_reg(path);
        RECOVER();
        LEAVE();
}

void t2()
{
        char *path="/mnt/lustre/test_t2";
        ENTRY("mkdir/rmdir");

        FAIL();
        prepare_dir(path);
        RECOVER();
        FAIL();
        cleanup_dir(path);
        RECOVER();
        LEAVE();
}

void t3()
{
        char *path="/mnt/lustre/test_t3";
        ENTRY("regular stat");

        prepare_reg(path);
        FAIL();
        do_stat(path, NULL);
        RECOVER();
        cleanup_reg(path);
        LEAVE();
}

void t4()
{
        char *path="/mnt/lustre/test_t4";
        ENTRY("dir stat");

        prepare_dir(path);
        FAIL();
        do_stat(path, NULL);
        RECOVER();
        cleanup_dir(path);
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

        prepare_reg(path);

	fd = open(path, O_RDWR, 00664);
        if (fd < 0) {
                printf("error %d open %s\n", fd, path);
                exit(1);
        }

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

        rc = close(fd);
        if (rc) {
                printf("close() err %d\n", rc);
                exit(1);
        }

        cleanup_reg(path);
        LEAVE();
}

void t6()
{
        char *path="/mnt/lustre/test_t6";
        char *path2="/mnt/lustre/test_t6_link";
        int rc;
        ENTRY("symlink");

        prepare_reg(path);
        FAIL();
        rc = symlink(path, path2);
        if (rc) {
                printf("error %d symlink %s -< %s\n", rc, path, path2);
                exit(1);
        }
        RECOVER();
        do_stat(path2, NULL);
        rc = unlink(path2);
        if (rc) {
                printf("error %d sym unlink %s\n", rc, path2);
                exit(1);
        }
        cleanup_reg(path);
        LEAVE();
}

void t7()
{
        char *path="/mnt/lustre/test_t7";
        int rc;
        ENTRY("mknod");

#define MKDEV(a,b) (((a) << 8) | (b))

        FAIL();
        rc = mknod(path, S_IFCHR | 0644, MKDEV(5, 4));
        if (rc < 0) {
                printf("error %d mknod %s\n", rc, path);
                exit(1);
        }
        RECOVER();
        do_stat(path, NULL);
        rc = unlink(path);
        if (rc) {
                printf("error %d node unlink %s\n", rc, path);
                exit(1);
        }
        LEAVE();
}

extern int portal_debug;
extern int portal_subsystem_debug;

extern void __liblustre_setup_(void);
extern void __liblustre_cleanup_(void);

void usage(const char *cmd)
{
        printf("Usage: %s -s server_name [-c config_file]\n", cmd);
}

int main(int argc, char * argv[])
{
        int c;
        char cmd[1024];

        while ((c = getopt(argc, argv, "c:s:")) != -1) {
                switch (c) {
                case 'c':
                        setenv("LUSTRE_CONFIG_FILE", optarg, 1);
                        break;
                case 's':
                        strcpy(mds_server, optarg);
                        break;
                default:
                        usage(argv[0]);
                        exit(-1);
                }
        }

        if (argc < 2 || optind != argc) {
                usage(argv[0]);
                exit(-1);
        }

        sprintf(cmd, "ssh %s cat /dev/null", mds_server);
        if (system(cmd)) {
                printf("can't access server node: %s\n", mds_server);
                exit(-1);
        }

        __liblustre_setup_();

        while (drop_arr[drop_index].name) {
                t1();
                t2();
                t3();
                t4();
                t5();
                t6();
                t7();

                drop_index++;
        }

	printf("liblustre is about shutdown\n");
        __liblustre_cleanup_();

	printf("complete successfully\n");
        return (0);
}
