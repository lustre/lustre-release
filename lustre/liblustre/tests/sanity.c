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

        t_touch(path);
        t_unlink(path);
        LEAVE();
}

void t2()
{
        char *path="/mnt/lustre/test_t2";
        ENTRY("mkdir/rmdir");

        t_mkdir(path);
        t_rmdir(path);
        LEAVE();
}

void t3()
{
        char *path="/mnt/lustre/test_t3";
        ENTRY("regular stat");

        t_touch(path);
        t_check_stat(path, NULL);
        t_unlink(path);
        LEAVE();
}

void t4()
{
        char *path="/mnt/lustre/test_t4";
        ENTRY("dir stat");

        t_mkdir(path);
        t_check_stat(path, NULL);
        t_rmdir(path);
        LEAVE();
}

#define PAGE_SIZE (4096)
#define _npages (512)

static int _buffer[_npages][PAGE_SIZE/sizeof(int)];

/* pos:   i/o start from
 * xfer:  npages per transfer
 */
static void pages_io(int xfer, loff_t pos)
{
        char *path="/mnt/lustre/test_t5";
        int check_sum[_npages] = {0,};
        int fd, rc, i, j;

        memset(_buffer, 0, sizeof(_buffer));

        /* create sample data */
        for (i = 0; i < _npages; i++) {
                for (j = 0; j < PAGE_SIZE/sizeof(int); j++) {
                        _buffer[i][j] = rand();
                }
        }

        /* compute checksum */
        for (i = 0; i < _npages; i++) {
                for (j = 0; j < PAGE_SIZE/sizeof(int); j++) {
                        check_sum[i] += _buffer[i][j];
                }
        }

        t_touch(path);

	fd = t_open(path);

        /* write */
	lseek(fd, pos, SEEK_SET);
	for (i = 0; i < _npages; i += xfer) {
		rc = write(fd, _buffer[i], PAGE_SIZE * xfer);
                if (rc != PAGE_SIZE * xfer) {
                        printf("write error %d (i = %d)\n", rc, i);
                        exit(1);
                }
	}
        printf("succefully write %d pages\n", _npages);

        memset(_buffer, 0, sizeof(_buffer));

        /* read */
	lseek(fd, pos, SEEK_SET);
	for (i = 0; i < _npages; i += xfer) {
		rc = read(fd, _buffer[i], PAGE_SIZE * xfer);
                if (rc != PAGE_SIZE * xfer) {
                        printf("read error %d (i = %d)\n", rc, i);
                        exit(1);
                }
	}
        printf("succefully read %d pages\n", _npages);

        /* compute checksum */
        for (i = 0; i < _npages; i++) {
                int sum = 0;
                for (j = 0; j < PAGE_SIZE/sizeof(int); j++) {
                        sum += _buffer[i][j];
                }
                if (sum != check_sum[i]) {
                        printf("chunk %d checksum error: expected 0x%x, get 0x%x\n",
                                i, check_sum[i], sum);
                }
        }
        printf("checksum verified OK!\n");

	t_close(fd);
        t_unlink(path);
}

void t5()
{
        char text[256];
        loff_t off_array[] = {1, 4, 17, 255, 258, 4095, 4097, 8191, 1024*1024*1024};
        int np = 1, i;
        loff_t offset = 0;

        while (np <= _npages) {
                sprintf(text, "pages_io: %d per transfer, offset %lld",
                        np, offset);
                ENTRY(text);
                pages_io(np, offset);
                LEAVE();
                np += np;
        }

        for (i = 0; i < sizeof(off_array)/sizeof(loff_t); i++) {
                offset = off_array[i];
                sprintf(text, "pages_io: 16 per transfer, offset %lld",
                        offset);
                ENTRY(text);
                pages_io(16, offset);
                LEAVE();
        }
}

void t6()
{
        char *path="/mnt/lustre/test_t6";
        char *path2="/mnt/lustre/test_t6_link";
        ENTRY("symlink");

        t_touch(path);
        t_symlink(path, path2);
        t_check_stat(path2, NULL);
        t_unlink(path2);
        t_unlink(path);
        LEAVE();
}

void t7()
{
        char *path="/mnt/lustre/test_t7";
        ENTRY("mknod");

        t_mknod(path, S_IFCHR | 0644, 5, 4);
        t_check_stat(path, NULL);
        t_unlink(path);
        LEAVE();
}

void t8()
{
        char *path="/mnt/lustre/test_t8";
        ENTRY("chmod");

        t_touch(path);
        t_chmod_raw(path, 0700);
        t_check_stat(path, NULL);
        t_unlink(path);
        LEAVE();
}

void t9()
{
        char *path="/mnt/lustre/test_t9";
        char *path2="/mnt/lustre/test_t9_link";
        ENTRY("hard link");

        t_touch(path);
        t_link(path, path2);
        t_check_stat(path, NULL);
        t_check_stat(path2, NULL);
        t_unlink(path);
        t_unlink(path2);
        LEAVE();
}

void t10()
{
        char *dir1="/mnt/lustre/test_t10_dir1";
        char *dir2="/mnt/lustre/test_t10_dir2";
        char *path1="/mnt/lustre/test_t10_reg1";
        char *path2="/mnt/lustre/test_t10_reg2";
        char *rename1="/mnt/lustre/test_t10_dir1/rename1";
        char *rename2="/mnt/lustre/test_t10_dir2/rename2";
        char *rename3="/mnt/lustre/test_t10_dir2/rename3";
        ENTRY("rename");

        t_mkdir(dir1);
        t_mkdir(dir2);
        t_touch(path1);
        t_touch(path2);
        t_rename(path1, rename1);
        t_rename(path2, rename2);
        t_rename(rename1, rename2);
        t_rename(dir1, rename3);
        t_unlink(rename2);
        t_rmdir(rename3);
        t_rmdir(dir2);
        LEAVE();
}

void t100()
{
        char *base="/mnt/lustre";
        char path[4096], path2[4096];
        int i, j, level = 5, nreg = 5;
        ENTRY("deep tree");

        strcpy(path, base);

        for (i = 0; i < level; i++) {
                for (j = 0; j < nreg; j++) {
                        sprintf(path2, "%s/file%d", path, j);
                        t_touch(path2);
                }

                strcat(path, "/dir");
                t_mkdir(path);
        }

        for (i = level; i > 0; i--) {
                strcpy(path, base);
                for (j = 1; j < i; j++)
                        strcat(path, "/dir");
                
                for (j = 0; j < nreg; j++) {
                        sprintf(path2, "%s/file%d", path, j);
                        t_unlink(path2);
                }

                strcat(path, "/dir");
                t_rmdir(path);
        }

        LEAVE();
}

extern void __liblustre_setup_(void);
extern void __liblustre_cleanup_(void);

void usage(char *cmd)
{
        printf("Usage: \t%s --target mdsnid:/mdsname/profile\n", cmd);
        printf("       \t%s --dumpfile dumpfile\n", cmd);
        exit(-1);
}

int main(int argc, char * const argv[])
{
        int opt_index, c;
        static struct option long_opts[] = {
                {"target", 1, 0, 0},
                {"dumpfile", 1, 0, 0},
                {0, 0, 0, 0}
        };

        if (argc <= 1)
                usage(argv[0]);

        while ((c = getopt_long(argc, argv, "", long_opts, &opt_index)) != -1) {
                switch (c) {
                case 0: {
                        printf("optindex %d\n", opt_index);
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
                default:
                        usage(argv[0]);
                }
        }

        if (optind != argc)
                usage(argv[0]);

        __liblustre_setup_();

#ifndef __CYGWIN__
        t1();
        t2();
        t3();
        t4();
        t5();
        t6();
        t7();
        t8();
        t9();
        t10();

        t100();
#endif

	printf("liblustre is about shutdown\n");
        __liblustre_cleanup_();

	printf("complete successfully\n");
	return 0;
}
