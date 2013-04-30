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
 *
 * Copyright (c) 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/liblustre/tests/sanity.c
 *
 * Lustre Light user test program
 */

#define _BSD_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <time.h>

#include <liblustre.h>
#include "test_common.h"
#include <lustre/lustreapi.h>

#define _npages (2048)

void *buf_alloc;
int buf_size;
int opt_verbose;
struct timeval start;

extern char *lustre_path;

#define ENTER(str)                                                      \
        do {                                                            \
                char buf[100];                                          \
                int len;                                                \
                gettimeofday(&start, NULL);                             \
                sprintf(buf, "===== START %s: %s %ld", __FUNCTION__,    \
                        (str), (long)start.tv_sec);                     \
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
                struct timeval stop;                                    \
                char buf[100] = { '\0' };                               \
                int len = sizeof(buf) - 1;                              \
                long usec;                                              \
                gettimeofday(&stop, NULL);                              \
                usec = (stop.tv_sec - start.tv_sec) * 1000000 +         \
                       (stop.tv_usec - start.tv_usec);                  \
                len = snprintf(buf, len,                                \
                               "===== END TEST %s: successfully (%gs)", \
                               __FUNCTION__, (double)usec / 1000000);   \
                if (len < 79) {                                         \
                        memset(buf+len, '=', sizeof(buf) - len);        \
                        buf[79] = '\n';                                 \
                        buf[80] = 0;                                    \
                }                                                       \
                printf("%s", buf);                                      \
                return 0;                                               \
        } while (0)

#define MAX_PATH_LENGTH 4096

int t1(char *name)
{
        char path[MAX_PATH_LENGTH] = "";

        ENTER("touch+unlink");
        snprintf(path, MAX_PATH_LENGTH, "%s/test_t1", lustre_path);

        if (opt_verbose)
                printf("touch+unlink %s\n", path);

        t_touch(path);
        t_unlink(path);
        LEAVE();
}

int t2(char *name)
{
        char path[MAX_PATH_LENGTH] = "";

        ENTER("mkdir/rmdir");
        snprintf(path, MAX_PATH_LENGTH, "%s/test_t2", lustre_path);

        t_mkdir(path);
        t_rmdir(path);
        LEAVE();
}

int t3(char *name)
{
        char path[MAX_PATH_LENGTH] = "";

        ENTER("regular stat");
        snprintf(path, MAX_PATH_LENGTH, "%s/test_t3", lustre_path);

        t_touch(path);
        t_check_stat(path, NULL);
        t_unlink(path);
        LEAVE();
}

int t4(char *name)
{
        char path[MAX_PATH_LENGTH] = "";

        ENTER("dir stat");
        snprintf(path, MAX_PATH_LENGTH, "%s/test_t4", lustre_path);

        t_mkdir(path);
        t_check_stat(path, NULL);
        t_rmdir(path);
        LEAVE();
}

int t6(char *name)
{
        char path[MAX_PATH_LENGTH] = "";
        char path2[MAX_PATH_LENGTH] = "";

        ENTER("symlink");
        snprintf(path, MAX_PATH_LENGTH, "%s/test_t6", lustre_path);
        snprintf(path2, MAX_PATH_LENGTH, "%s/test_t6_link", lustre_path);

        t_touch(path);
        t_symlink(path, path2);
        t_check_stat(path2, NULL);
        t_unlink(path2);
        t_unlink(path);
        LEAVE();
}

int t6b(char *name)
{
        char path[MAX_PATH_LENGTH] = "";
        char path2[MAX_PATH_LENGTH] = "";
        char cwd[MAX_PATH_LENGTH] = "";
        char *tmp;
        int fd;

        ENTER("symlink + chdir and open");
        snprintf(path, MAX_PATH_LENGTH, "%s/test_t6b", lustre_path);
        snprintf(path2, MAX_PATH_LENGTH, "%s/test_t6b_link", lustre_path);

        t_mkdir(path);
        t_symlink(path, path2);
        t_check_stat(path2, NULL);

        tmp = getcwd(cwd, MAX_PATH_LENGTH);
        if (tmp == NULL) {
                fprintf(stderr, "current path too long to fit in "
                        "MAX_PATH_LENGTH?\n");
                LEAVE();
        }
        t_chdir(path2);
        t_chdir(cwd);
        t_rmdir(path);
        t_touch(path);

        fd = t_open(path2);
        t_close(fd);

        t_unlink(path2);
        t_unlink(path);
        LEAVE();
}

int t7(char *name)
{
        char path[MAX_PATH_LENGTH] = "";
        int rc;

        ENTER("mknod");
        snprintf(path, MAX_PATH_LENGTH, "%s/test_t7", lustre_path);

        if (geteuid() != 0) {
                rc = mknod(path, S_IFCHR | 0644, (5<<8 | 4));
                if (rc != -1 || errno != EPERM) {
                        printf("mknod shouldn't success: rc %d, errno %d\n",
                                rc, errno);
                }
        } else {
                t_mknod(path, S_IFCHR | 0644, 5, 4);
                t_check_stat(path, NULL);
                t_unlink(path);
        }
        LEAVE();
}

int t8(char *name)
{
        char path[MAX_PATH_LENGTH] = "";

        ENTER("chmod");
        snprintf(path, MAX_PATH_LENGTH, "%s/test_t8", lustre_path);

        /* Check file. */
        t_touch(path);
        t_chmod_raw(path, 0700);
        t_check_stat(path, NULL);
        t_unlink(path);

        /* Check dir. */
        t_mkdir(path);
        t_chmod_raw(path, 0700);
        t_check_stat(path, NULL);
        t_rmdir(path);

        LEAVE();
}

int t9(char *name)
{
        char path[MAX_PATH_LENGTH] = "";
        char path2[MAX_PATH_LENGTH] = "";

        ENTER("hard link");
        snprintf(path, MAX_PATH_LENGTH, "%s/test_t9", lustre_path);
        snprintf(path2, MAX_PATH_LENGTH, "%s/test_t9_link", lustre_path);

        t_touch(path);
        t_link(path, path2);
        t_check_stat(path, NULL);
        t_check_stat(path2, NULL);
        t_unlink(path);
        t_unlink(path2);
        LEAVE();
}

int t10(char *name)
{
        char dir1[MAX_PATH_LENGTH] = "";
        char dir2[MAX_PATH_LENGTH] = "";
        char path1[MAX_PATH_LENGTH] = "";
        char path2[MAX_PATH_LENGTH] = "";
        char rename1[MAX_PATH_LENGTH] = "";
        char rename2[MAX_PATH_LENGTH] = "";
        char rename3[MAX_PATH_LENGTH] = "";

        ENTER("rename");
        snprintf(dir1, MAX_PATH_LENGTH, "%s/test_t10_dir1", lustre_path);
        snprintf(dir2, MAX_PATH_LENGTH, "%s/test_t10_dir2", lustre_path);
        snprintf(path1, MAX_PATH_LENGTH, "%s/test_t10_reg1", lustre_path);
        snprintf(path2, MAX_PATH_LENGTH, "%s/test_t10_reg2", lustre_path);
        snprintf(rename1, MAX_PATH_LENGTH, "%s/test_t10_dir1/rename1", lustre_path);
        snprintf(rename2, MAX_PATH_LENGTH, "%s/test_t10_dir2/rename2", lustre_path);
        snprintf(rename3, MAX_PATH_LENGTH, "%s/test_t10_dir2/rename3", lustre_path);

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

int t11(char *name)
{
        char *base=lustre_path;
        char path[MAX_PATH_LENGTH], path2[MAX_PATH_LENGTH];
        int i, j, level = 5, nreg = 5;
        ENTER("deep tree");

        safe_strncpy(path, base, MAX_PATH_LENGTH);

        for (i = 0; i < level; i++) {
                for (j = 0; j < nreg; j++) {
                        sprintf(path2, "%s/file%d", path, j);
                        t_touch(path2);
                }

                strcat(path, "/dir");
                t_mkdir(path);
        }

        for (i = level; i > 0; i--) {
                safe_strncpy(path, base, MAX_PATH_LENGTH);
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

int t12(char *name)
{
        char dir[MAX_PATH_LENGTH] = "";
        char buf[1024*128];
        int fd;
        ENTER("empty directory readdir");
        snprintf(dir, MAX_PATH_LENGTH, "%s/test_t12_dir", lustre_path);

        t_mkdir(dir);
        fd = t_opendir(dir);
        t_ls(fd, buf, sizeof(buf));
        t_close(fd);
        t_rmdir(dir);
        LEAVE();
}

int t13(char *name)
{
        char dir[MAX_PATH_LENGTH] = "";
        char path[1024];
        char buf[1024];
        const int nfiles = 20;
        char *prefix = "test13_filename_prefix_";
        int fd, i;
        ENTER("multiple entries directory readdir");
        snprintf(dir, MAX_PATH_LENGTH, "%s/test_t13_dir/", lustre_path);

        t_mkdir(dir);
        printf("Creating %d files...\n", nfiles);
        for (i = 0; i < nfiles; i++) {
                sprintf(path, "%s%s%05d", dir, prefix, i);
                t_touch(path);
        }
        fd = t_opendir(dir);
        t_ls(fd, buf, sizeof(buf));
        t_close(fd);
        printf("Cleanup...\n");
        for (i = 0; i < nfiles; i++) {
                sprintf(path, "%s%s%05d", dir, prefix, i);
                t_unlink(path);
        }
        t_rmdir(dir);
        LEAVE();
}

int t14(char *name)
{
        char dir[MAX_PATH_LENGTH] = "";
        char path[1024];
        char buf[1024];
        const int nfiles = 256;
        char *prefix = "test14_filename_long_prefix_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA___";
	struct dirent64 *ent;
        int fd, i, rc, pos, index;
        loff_t base = 0;
        ENTER(">1 block(4k) directory readdir");
        snprintf(dir, MAX_PATH_LENGTH, "%s/test_t14_dir/", lustre_path);

        rc = mkdir(dir, 0755);
        if (rc < 0 && errno != EEXIST) {
                printf("mkdir(%s) error: %s\n", dir, strerror(errno));
                exit(1);
        }
        printf("Creating %d files...\n", nfiles);
        for (i = 0; i < nfiles; i++) {
                sprintf(path, "%s%s%05d", dir, prefix, i);
                t_touch(path);
        }
        fd = t_opendir(dir);
        printf("Listing...\n");
        index = 0;
        while ((rc = getdirentries64(fd, buf, 1024, &base)) > 0) {
                pos = 0;
                while (pos < rc) {
                        char *item;

                        ent = (void *) buf + pos;
                        item = (char *) ent->d_name;
                        if (!strcmp(item, ".") || !strcmp(item, ".."))
                                goto iter;
                        if (strstr(item, prefix) != item) {
                                printf("found bad name %s\n", item);
                                return(-1);
                        }
                        printf("[%03d]: %s\t",
                                index++, item + strlen(prefix));
iter:
                        pos += ent->d_reclen;
                }
        }
        printf("\n");
        if (rc < 0) {
                printf("getdents error %d\n", rc);
                return(-1);
        }
        if (index != nfiles) {
                printf("get %d files != %d\n", index, nfiles);
                return(-1);
        }
        t_close(fd);
        printf("Cleanup...\n");
        for (i = 0; i < nfiles; i++) {
                sprintf(path, "%s%s%05d", dir, prefix, i);
                t_unlink(path);
        }
        t_rmdir(dir);
        LEAVE();
}

int t15(char *name)
{
        char file[MAX_PATH_LENGTH] = "";
        int fd;
        ENTER("open-stat-close");
        snprintf(file, MAX_PATH_LENGTH, "%s/test_t15_file", lustre_path);

        t_touch(file);
        fd = t_open(file);
        t_check_stat(file, NULL);
        t_close(fd);
        t_unlink(file);
        LEAVE();
}

int t16(char *name)
{
        char file[MAX_PATH_LENGTH] = "";
        ENTER("small-write-read");
        snprintf(file, MAX_PATH_LENGTH, "%s/test_t16_file", lustre_path);

        t_echo_create(file, "aaaaaaaaaaaaaaaaaaaaaa");
        t_grep(file, "aaaaaaaaaaaaaaaaaaaaaa");
        t_unlink(file);
        LEAVE();
}

int t17(char *name)
{
        char file[MAX_PATH_LENGTH] = "";
        int fd;
        ENTER("open-unlink without close");
        snprintf(file, MAX_PATH_LENGTH, "%s/test_t17_file", lustre_path);

        fd = open(file, O_WRONLY | O_CREAT, 0666);
        if (fd < 0) {
                printf("failed to create file: %s\n", strerror(errno));
                return(-1);
        }
        t_unlink(file);
        LEAVE();
}

int t18(char *name)
{
        char file[MAX_PATH_LENGTH] = "";
        char buf[128];
        int fd, i;
        struct stat statbuf[3];
        ENTER("write should change mtime/ctime");
        snprintf(file, MAX_PATH_LENGTH, "%s/test_t18_file", lustre_path);

        for (i = 0; i < 3; i++) {
                fd = open(file, O_RDWR|O_CREAT|O_APPEND, (mode_t)0666);
                if (fd < 0) {
                        printf("error open file: %s\n", strerror(errno));
                        return(-1);
                }
                if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
                        printf("error write file\n");
                        return(-1);
                }
                close(fd);
                if(stat(file, &statbuf[i]) != 0) {
                        printf("Error stat\n");
                        return(1);
                }
                printf("ctime %lu, mtime %lu\n",
                        statbuf[i].st_ctime, statbuf[i].st_mtime);
                sleep(2);
        }

        for (i = 1; i < 3; i++) {
                if ((statbuf[i].st_ctime <= statbuf[i-1].st_ctime) ||
                    (statbuf[i].st_mtime <= statbuf[i-1].st_mtime)) {
                        printf("time error\n");
                        return(-1);
                }
        }
        t_unlink(file);
        LEAVE();
}

int t18b(char *name)
{
        char file[MAX_PATH_LENGTH] = "";
        int i;
        struct stat statbuf[3];
        ENTER("utime should change mtime/atime/ctime");
        snprintf(file, MAX_PATH_LENGTH, "%s/test_t18b_file", lustre_path);
        t_touch(file);

        for (i = 0; i < 3; i++) {
                t_utime(file, NULL);
                if(stat(file, &statbuf[i]) != 0) {
                        printf("Error stat\n");
                        return(1);
                }
                printf("atime %lu, mtime %lu, ctime %lu\n",
                       statbuf[i].st_atime, statbuf[i].st_mtime,
                       statbuf[i].st_ctime);
                sleep(2);
        }

        for (i = 1; i < 3; i++) {
                if ((statbuf[i].st_atime <= statbuf[i-1].st_atime) ||
                    (statbuf[i].st_mtime <= statbuf[i-1].st_mtime) ||
                    (statbuf[i].st_ctime <= statbuf[i-1].st_ctime)) {
                        printf("time error\n");
                        return(-1);
                }
        }
        t_unlink(file);
        LEAVE();
}

static int check_file_size(char *file, long long size)
{
        struct stat statbuf;

        if (stat(file, &statbuf) != 0) {
                printf("Error stat(%s)\n", file);
                return(1);
        }
        if (statbuf.st_size != size) {
                printf("size of %s: %lld != %lld\n", file,
                       (long long)statbuf.st_size, (long long )size);
                return(-1);
        }
        return 0;
}

int t19(char *name)
{
        char file[MAX_PATH_LENGTH] = "";
        int fd;
        int result;
        ENTER("open(O_TRUNC) should truncate file to 0-length");
        snprintf(file, MAX_PATH_LENGTH, "%s/test_t19_file", lustre_path);

        t_echo_create(file, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        fd = open(file, O_RDWR|O_CREAT|O_TRUNC, (mode_t)0666);
        if (fd < 0) {
                printf("error open file: %s\n", strerror(errno));
                return(-1);
        }
        close(fd);
        result = check_file_size(file, 0);
        if (result != 0)
                return result;
        t_unlink(file);
        LEAVE();
}

int t20(char *name)
{
        char file[MAX_PATH_LENGTH] = "";
        int fd;
        struct iovec iov[2];
        char buf[100];
        long ret;
        ENTER("trap app's general bad pointer for file i/o");
        snprintf(file, MAX_PATH_LENGTH, "%s/test_t20_file", lustre_path);

        fd = open(file, O_RDWR|O_CREAT, (mode_t)0666);
        if (fd < 0) {
                printf("error open file: %s\n", strerror(errno));
                return(-1);
        }

        ret = write(fd, NULL, 20);
        if (ret != -1 || errno != EFAULT) {
                printf("write 1: ret %lld, errno %d\n", (long long)ret, errno);
                return(1);
        }
        ret = write(fd, (void *)-1, 20);
        if (ret != -1 || errno != EFAULT) {
                printf("write 2: ret %lld, errno %d\n", (long long)ret, errno);
                return(1);
        }
        iov[0].iov_base = NULL;
        iov[0].iov_len = 10;
        iov[1].iov_base = (void *)-1;
        iov[1].iov_len = 10;
        ret = writev(fd, iov, 2);
        if (ret != -1 || errno != EFAULT) {
                printf("writev 1: ret %lld, errno %d\n", (long long)ret, errno);
                return(1);
        }
        iov[0].iov_base = NULL;
        iov[0].iov_len = 0;
        iov[1].iov_base = buf;
        iov[1].iov_len = sizeof(buf);
        ret = writev(fd, iov, 2);
        if (ret != sizeof(buf)) {
                printf("writev 2: ret %lld, error %d\n", (long long)ret, errno);
                return(1);
        }
        lseek(fd, 0, SEEK_SET);

        ret = read(fd, NULL, 20);
        if (ret != -1 || errno != EFAULT) {
                printf("read 1: ret %lld, errno %d\n", (long long)ret, errno);
                return(1);
        }
        ret = read(fd, (void *)-1, 20);
        if (ret != -1 || errno != EFAULT) {
                printf("read 2: ret %lld, error %d\n", (long long)ret, errno);
                return(1);
        }
        iov[0].iov_base = NULL;
        iov[0].iov_len = 10;
        iov[1].iov_base = (void *)-1;
        iov[1].iov_len = 10;
        ret = readv(fd, iov, 2);
        if (ret != -1 || errno != EFAULT) {
                printf("readv 1: ret %lld, error %d\n", (long long)ret, errno);
                return(1);
        }
        iov[0].iov_base = NULL;
        iov[0].iov_len = 0;
        iov[1].iov_base = buf;
        iov[1].iov_len = sizeof(buf);
        ret = readv(fd, iov, 2);
        if (ret != sizeof(buf)) {
                printf("readv 2: ret %lld, error %d\n", (long long)ret, errno);
                return(1);
        }

        close(fd);
        t_unlink(file);
        LEAVE();
}

int t21(char *name)
{
        char file[MAX_PATH_LENGTH] = "";
        int fd, ret;
        struct flock lock = {
                .l_type = F_RDLCK,
                .l_whence = SEEK_SET,
        };

        ENTER("basic fcntl support");
        snprintf(file, MAX_PATH_LENGTH, "%s/test_t21_file", lustre_path);

        fd = open(file, O_RDWR|O_CREAT, (mode_t)0666);
        if (fd < 0) {
                printf("error open file: %s\n", file);
                return(-1);
        }

        t_fcntl(fd, F_SETFL, O_APPEND);
        ret = t_fcntl(fd, F_GETFL);
        if ((ret & O_APPEND) == 0) {
                printf("error get flag: ret %o\n", ret);
                return(-1);
        }

        t_fcntl(fd, F_SETLK, &lock);
        t_fcntl(fd, F_GETLK, &lock);
        lock.l_type = F_WRLCK;
        t_fcntl(fd, F_SETLKW, &lock);
        t_fcntl(fd, F_GETLK, &lock);
        lock.l_type = F_UNLCK;
        t_fcntl(fd, F_SETLK, &lock);

        close(fd);
        t_unlink(file);
        LEAVE();
}

int t22(char *name)
{
        char file[MAX_PATH_LENGTH] = "";
        int fd;
        char *str = "1234567890";
        char buf[100];
        long ret;
        ENTER("make sure O_APPEND take effect");
        snprintf(file, MAX_PATH_LENGTH, "%s/test_t22_file", lustre_path);

        fd = open(file, O_TRUNC|O_RDWR|O_CREAT|O_APPEND, (mode_t)0666);
        if (fd < 0) {
                printf("error open file: %s\n", strerror(errno));
                return(-1);
        }

        lseek(fd, 100, SEEK_SET);
        ret = write(fd, str, strlen(str));
        if (ret != strlen(str)) {
                printf("write 1: ret %lld, errno %d\n", (long long)ret, errno);
                return(1);
        }

        lseek(fd, 0, SEEK_SET);
        ret = read(fd, buf, sizeof(buf));
        if (ret != strlen(str)) {
                printf("read 1: ret %lld\n", (long long)ret);
                return(1);
        }

        if (memcmp(buf, str, strlen(str))) {
                printf("read 1 data err\n");
                return(1);
        }

        if (fcntl(fd, F_SETFL, 0)) {
                printf("fcntl err: %s\n", strerror(errno));
                return(1);
        }

        lseek(fd, 100, SEEK_SET);
        ret = write(fd, str, strlen(str));
        if (ret != strlen(str)) {
                printf("write 2: ret %lld, errno %d\n", (long long)ret, errno);
                return(1);
        }

        lseek(fd, 100, SEEK_SET);
        ret = read(fd, buf, sizeof(buf));
        if (ret != strlen(str)) {
                printf("read 2: ret %lld\n", (long long)ret);
                return(1);
        }

        if (memcmp(buf, str, strlen(str))) {
                printf("read 2 data err\n");
                return(1);
        }

        close(fd);
        t_unlink(file);
        LEAVE();
}

int t23(char *name)
{
        char path[MAX_PATH_LENGTH];
        int fd;
        long long ret;
        loff_t off;

        ENTER("handle seek > 2GB");
        snprintf(path, MAX_PATH_LENGTH, "%s/f%s", lustre_path, name);

        fd = open(path, O_WRONLY | O_CREAT | O_LARGEFILE, 0666);
        if (fd < 0) {
                printf("failed to create file %s: %s\n", path, strerror(errno));
                return(-1);
        }

        off = 2048ULL * 1024 * 1024 - buf_size / 2;
        ret = lseek(fd, off, SEEK_SET);
        if (ret != off) {
                printf("seek error for initial %llu != %llu\n",
                       ret, (long long)off);
                return -1;
        }

        ret = write(fd, buf_alloc, buf_size);
        if (ret != buf_size) {
                printf("write error for %d != %llubytes @ %llu\n",
                       buf_size, ret, (long long)off);
                if (ret == -1)
                        perror("write");
                return -1;
        }

        ret = lseek(fd, off, SEEK_SET);
        if (ret != off) {
                printf("seek < 2GB error for %llu != %llu\n",
                       ret, (long long)off);
                if (ret == -1)
                        perror("seek < 2GB");
                return -1;
        }

        ret = lseek(fd, off + buf_size - 2, SEEK_SET);
        if (ret != off + buf_size - 2) {
                printf("seek > 2GB error for %llu != %llu\n",
                       ret, (long long)off);
                if (ret == -1)
                        perror("seek > 2GB");
                return -1;
        }

        ret = lseek(fd, -buf_size + 2, SEEK_CUR);
        if (ret != off) {
                printf("relative seek error for %d %llu != %llu\n",
                       -buf_size + 2, ret, (unsigned long long) off);
                if (ret == -1)
                        perror("relative seek");
                return -1;
        }

        ret = lseek(fd, 0, SEEK_END);
        if (ret != off + buf_size) {
                printf("end seek error for %llu != %llu\n",
                       ret, (long long)off + buf_size);
                if (ret == -1)
                        perror("end seek");
                return -1;
        }

        ret = lseek(fd, 0, SEEK_SET);
        if (ret != 0) {
                printf("seek 0 error for %llu != 0\n", ret);
                if (ret == -1)
                        perror("seek 0");
                return -1;
        }

        off = 2048ULL * 1024 * 1024, SEEK_SET;
        ret = lseek(fd, off, SEEK_SET);
        if (ret != off) {
                printf("seek 2GB error for %llu != %llu\n", ret, (unsigned long long) off);
                if (ret == -1)
                        perror("seek 2GB");
                return -1;
        }

        close(fd);
        t_unlink(path);
        LEAVE();
}

/* pos:   i/o start from
 * xfer:  npages per transfer
 */
static int pages_io(int xfer, loff_t pos)
{
        char path[MAX_PATH_LENGTH] = "";

        int check_sum[_npages] = {0,}, *buf;
        int fd, rc, i, j, data_error = 0;
        struct timeval tw1, tw2, tr1, tr2;
        double tw, tr;
        loff_t ret;

        snprintf(path, MAX_PATH_LENGTH, "%s/test_t50", lustre_path);

        memset(buf_alloc, 0, buf_size);

        /* create sample data */
        for (i = 0, buf = buf_alloc; i < _npages; i++) {
                for (j = 0; j < CFS_PAGE_SIZE/sizeof(int); j++, buf++) {
                        *buf = rand();
                }
        }

        /* compute checksum */
        for (i = 0, buf = buf_alloc; i < _npages; i++) {
                for (j = 0; j < CFS_PAGE_SIZE/sizeof(int); j++, buf++) {
                        check_sum[i] += *buf;
                }
        }

        unlink(path);
        t_touch(path);

        fd = t_open(path);

        /* write */
        ret = lseek(fd, pos, SEEK_SET);
        if (ret != pos) {
                perror("write seek");
                return 1;
        }
        gettimeofday(&tw1, NULL);
        for (i = 0, buf = buf_alloc; i < _npages;
             i += xfer, buf += xfer * CFS_PAGE_SIZE / sizeof(int)) {
                rc = write(fd, buf, CFS_PAGE_SIZE * xfer);
                if (rc != CFS_PAGE_SIZE * xfer) {
                        printf("write error (i %d, rc %d): %s\n", i, rc,
                               strerror(errno));
                        return(1);
                }
        }
        gettimeofday(&tw2, NULL);

        memset(buf_alloc, 0, buf_size);

        /* read */
        ret = lseek(fd, pos, SEEK_SET);
        if (ret != pos) {
                perror("read seek");
                return 1;
        }
        gettimeofday(&tr1, NULL);
        for (i = 0, buf = buf_alloc; i < _npages;
             i += xfer, buf += xfer * CFS_PAGE_SIZE / sizeof(int)) {
                rc = read(fd, buf, CFS_PAGE_SIZE * xfer);
                if (rc != CFS_PAGE_SIZE * xfer) {
                        printf("read error (i %d, rc %d): %s\n", i, rc,
                               strerror(errno));
                        return(1);
                }
        }
        gettimeofday(&tr2, NULL);

        /* compute checksum */
        for (i = 0, buf = buf_alloc; i < _npages; i++) {
                int sum = 0;
                for (j = 0; j < CFS_PAGE_SIZE/sizeof(int); j++, buf++) {
                        sum += *buf;
                }
                if (sum != check_sum[i]) {
                        data_error = 1;
                        printf("chunk %d checksum error expected %#x got %#x\n",
                                i, check_sum[i], sum);
                }
        }

        t_close(fd);
        t_unlink(path);
        tw = (tw2.tv_sec - tw1.tv_sec) * 1000000 + (tw2.tv_usec - tw1.tv_usec);
        tr = (tr2.tv_sec - tr1.tv_sec) * 1000000 + (tr2.tv_usec - tr1.tv_usec);
        printf(" (R:%.3fM/s, W:%.3fM/s)\n",
                (_npages * CFS_PAGE_SIZE) / (tw / 1000000.0) / (1024 * 1024),
                (_npages * CFS_PAGE_SIZE) / (tr / 1000000.0) / (1024 * 1024));

        if (data_error)
                return 1;

        return 0;
}

int t50(char *name)
{
        int np = 1;
        loff_t offset = 0;

        ENTER("4k aligned i/o sanity");
        while (np <= _npages) {
                printf("%3d per xfer(total %d)...\t", np, _npages);
                fflush(stdout);
                if (pages_io(np, offset) != 0)
                        return 1;
                np += np;
        }
        LEAVE();
}

int t50b(char *name)
{
        loff_t off_array[] = {1, 17, 255, 258, 4095, 4097, 8191,
                              1024*1024*1024*1024ULL};
        int i;
        long long offset;

        ENTER("4k un-aligned i/o sanity");
        for (i = 0; i < sizeof(off_array)/sizeof(loff_t); i++) {
                offset = off_array[i];
                printf("16 per xfer(total %d), offset %10lld...\t",
                        _npages, offset);
                if (pages_io(16, offset) != 0)
                        return 1;
        }

        LEAVE();
}

enum {
        T51_STEP = 42,
        T51_NR   = 1000
};

/*
 * truncate(2) checks.
 */
int t51(char *name)
{
        char file[MAX_PATH_LENGTH] = "";
        int fd;
        long long size;
        int result;

        ENTER("truncate() should truncate file to proper length");
        snprintf(file, MAX_PATH_LENGTH, "%s/test_t51_file", lustre_path);

        for (size = 0; size < T51_NR * T51_STEP; size += T51_STEP) {
                t_echo_create(file, "");
                if (truncate(file, size) != 0) {
                        printf("\nerror truncating file: %s\n",strerror(errno));
                        return(-1);
                }
                result = check_file_size(file, size);
                if (result != 0)
                        return result;
                t_unlink(file);

                t_echo_create(file, "");
                fd = open(file, O_RDWR|O_CREAT, (mode_t)0666);
                if (fd < 0) {
                        printf("\nerror open file: %s\n", strerror(errno));
                        return(-1);
                }
                if (ftruncate(fd, size) != 0) {
                        printf("\nerror ftruncating file:%s\n",strerror(errno));
                        return(-1);
                }
                close(fd);
                result = check_file_size(file, size);
                if (result != 0)
                        return result;
                t_unlink(file);
                if (size % (T51_STEP * (T51_NR / 75)) == 0) {
                        printf(".");
                        fflush(stdout);
                }
        }
        printf("\n");
        LEAVE();
}
/*
 * check atime update during read
 */
int t52(char *name)
{
        char file[MAX_PATH_LENGTH] = "";
        char buf[16];
        struct stat statbuf;
        time_t atime;
        time_t diff;
        int fd, i;

        ENTER("atime should be updated during read");
        snprintf(file, MAX_PATH_LENGTH, "%s/test_t52_file", lustre_path);

        t_echo_create(file, "check atime update during read");
        fd = open(file, O_RDONLY);
        if (fd < 0) {
                printf("\nerror open file: %s\n", strerror(errno));
                return(-1);
        }
        stat(file, &statbuf);
        printf("st_atime=%s", ctime(&statbuf.st_atime));
        atime = statbuf.st_atime;
        for (i = 0; i < 3; i++) {
                ssize_t num_read;
                sleep(2);
                /* should not ignore read(2)'s return value */
                num_read = read(fd, buf, sizeof(buf));
                if (num_read < 0 ) {
                        printf("read from %s: %s\n", file, strerror(errno));
                        return -1;
                }
                stat(file, &statbuf);
                printf("st_atime=%s", ctime(&statbuf.st_atime));
                diff = statbuf.st_atime - atime;
                if (diff <= 0) {
                        printf("atime doesn't updated! failed!\n");
                        close(fd);
                        t_unlink(file);
                        return -1;
                }
                atime = statbuf.st_atime;
        }
        close(fd);
        t_unlink(file);
        LEAVE();
}

#define NEW_TIME        10000
int t53(char *name)
{
        char file[MAX_PATH_LENGTH] = "";
        struct utimbuf times;   /* struct. buffer for utime() */
        struct stat stat_buf;   /* struct buffer to hold file info. */
        time_t mtime, atime;

        ENTER("mtime/atime should be updated by utime() call");
        snprintf(file, MAX_PATH_LENGTH, "%s/test_t53_file", lustre_path);

        t_echo_create(file, "check mtime/atime update by utime() call");

        /* Initialize the modification and access time in the times arg */
        times.actime = NEW_TIME+10;
        times.modtime = NEW_TIME;

        /* file modification/access time */
        utime(file, &times);

        if (stat(file, &stat_buf) < 0) {
                printf("stat(2) of %s failed, error:%d %s\n",
                        file, errno, strerror(errno));
        }
        mtime = stat_buf.st_mtime;
        atime = stat_buf.st_atime;

        if ((mtime == NEW_TIME) && (atime == NEW_TIME + 10)) {
                t_unlink(file);
                LEAVE();
        }

        printf("mod time %ld, expected %ld\n", mtime, (long)NEW_TIME);
        printf("acc time %ld, expected %ld\n", atime, (long)NEW_TIME + 10);

        t_unlink(file);
        return (-1);
}

int t54(char *name)
{
        char file[MAX_PATH_LENGTH] = "";
        struct flock lock;
        int fd, err;

        ENTER("fcntl should return 0 when succeed in getting flock");
        snprintf(file, MAX_PATH_LENGTH, "%s/test_t54_file", lustre_path);

        t_echo_create(file, "fcntl should return 0 when succeed");

        fd = open(file, O_RDWR);
        if (fd < 0) {
                printf("\nerror open file: %s\n", strerror(errno));
                return(-1);
        }
        lock.l_type   = F_WRLCK;
        lock.l_start  = 0;
        lock.l_whence = 0;
        lock.l_len    = 1;
        if ((err = t_fcntl(fd, F_SETLKW, &lock)) != 0) {
                fprintf(stderr, "fcntl returned: %d (%s)\n",
                        err, strerror(err));
                close(fd);
                t_unlink(file);
                return (-1);
        }

        lock.l_type   = F_UNLCK;
        t_fcntl(fd, F_SETLKW, &lock);
        close(fd);
        t_unlink(file);
        LEAVE();
}

/* for O_DIRECTORY */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define STRIPE_SIZE       (2048 * 2048)
#define STRIPE_OFFSET           0
#define STRIPE_COUNT            1
int t55(char *name)
{
        char path[MAX_PATH_LENGTH] = "";
        char file[MAX_PATH_LENGTH] = "";
        struct lov_user_md *lum = NULL;
        struct lov_user_ost_data *lo = NULL;
        int index, fd, buflen, rc;

        ENTER("setstripe/getstripe");
        snprintf(path, MAX_PATH_LENGTH, "%s/test_t55", lustre_path);
        snprintf(file, MAX_PATH_LENGTH, "%s/test_t55/file_t55", lustre_path);

        buflen = sizeof(struct lov_user_md);
        buflen += STRIPE_COUNT * sizeof(struct lov_user_ost_data);
        lum = (struct lov_user_md *)malloc(buflen);
        if (!lum) {
                printf("out of memory!\n");
                return -1;
        }
        memset(lum, 0, buflen);

        t_mkdir(path);
        rc = llapi_file_create(path, STRIPE_SIZE, STRIPE_OFFSET,
                               STRIPE_COUNT, LOV_PATTERN_RAID0);
        if (rc) {
                printf("llapi_file_create failed: rc = %d (%s) \n",
                       rc, strerror(-rc));
                t_rmdir(path);
                free(lum);
                return -1;
        }

        fd = open(file, O_CREAT | O_RDWR, 0644);
        if (fd < 0) {
                printf("open file(%s) failed: rc = %d (%s) \n)",
                       file, fd, strerror(errno));
                t_rmdir(path);
                free(lum);
                return -1;
        }

        lum->lmm_magic = LOV_USER_MAGIC;
        lum->lmm_stripe_count = STRIPE_COUNT;
        rc = ioctl(fd, LL_IOC_LOV_GETSTRIPE, lum);
        if (rc) {
                printf("dir:ioctl(LL_IOC_LOV_GETSTRIPE) failed: rc = %d(%s)\n",
                       rc, strerror(errno));
                close(fd);
                t_unlink(file);
                t_rmdir(path);
                free(lum);
                return -1;
        }

        close(fd);

        if (opt_verbose) {
		printf("lmm_magic:          0x%08X\n",  lum->lmm_magic);
		printf("lmm_object_id:      "LPX64"\n",
						lmm_oi_id(&lum->lmm_oi));
		printf("lmm_object_seq:     "LPX64"\n",
						lmm_oi_seq(&lum->lmm_oi));
		printf("lmm_stripe_count:   %u\n", (int)lum->lmm_stripe_count);
		printf("lmm_stripe_size:    %u\n",      lum->lmm_stripe_size);
		printf("lmm_stripe_pattern: %x\n",      lum->lmm_pattern);

		for (index = 0; index < lum->lmm_stripe_count; index++) {
			lo = lum->lmm_objects + index;
			printf("object %d:\n", index);
			printf("\tobject_oid:   "DOSTID"\n",
			       POSTID(&lo->l_ost_oi));
			printf("\tost_gen:      %#x\n", lo->l_ost_gen);
			printf("\tost_idx:      %u\n", lo->l_ost_idx);
		}
        }

        if (lum->lmm_magic != LOV_USER_MAGIC ||
            lum->lmm_pattern != LOV_PATTERN_RAID0 ||
            lum->lmm_stripe_size != STRIPE_SIZE ||
            lum->lmm_objects[0].l_ost_idx != STRIPE_OFFSET ||
            lum->lmm_stripe_count != STRIPE_COUNT) {
                printf("incorrect striping information!\n");
                t_unlink(file);
                t_rmdir(path);
                free(lum);
                return -1;
        }
        t_unlink(file);

        /* setstripe on regular file */
        rc = llapi_file_create(file, STRIPE_SIZE, STRIPE_OFFSET,
                               STRIPE_COUNT, LOV_PATTERN_RAID0);
        if (rc) {
                printf("llapi_file_create failed: rc = %d (%s) \n",
                       rc, strerror(-rc));
                t_unlink(file);
                t_rmdir(path);
                free(lum);
                return -1;
        }
        fd = open(file, O_RDWR, 0644);
        if (fd < 0) {
                printf("failed to open(%s): rc = %d (%s)\n",
                       file, fd, strerror(errno));
                t_unlink(file);
                t_rmdir(path);
                free(lum);
                return -1;
        }

        lum->lmm_magic = LOV_USER_MAGIC;
        lum->lmm_stripe_count = STRIPE_COUNT;
        rc = ioctl(fd, LL_IOC_LOV_GETSTRIPE, lum);
        if (rc) {
                printf("file:ioctl(LL_IOC_LOV_GETSTRIPE) failed: rc = %d(%s)\n",
                       rc, strerror(errno));
                close(fd);
                t_unlink(file);
                t_rmdir(path);
                free(lum);
                return -1;
        }
        close(fd);

	if (opt_verbose) {
		printf("lmm_magic:          0x%08X\n",  lum->lmm_magic);
		printf("lmm_object_id:      "LPX64"\n",
						lmm_oi_id(&lum->lmm_oi));
		printf("lmm_object_seq:     "LPX64"\n",
						lmm_oi_seq(&lum->lmm_oi));
		printf("lmm_stripe_count:   %u\n", (int)lum->lmm_stripe_count);
		printf("lmm_stripe_size:    %u\n",      lum->lmm_stripe_size);
		printf("lmm_stripe_pattern: %x\n",      lum->lmm_pattern);

		for (index = 0; index < lum->lmm_stripe_count; index++) {
			lo = lum->lmm_objects + index;
			printf("object %d:\n", index);
			printf("\tobject_oid:   "DOSTID"\n",
			       POSTID(&lo->l_ost_oi));
			printf("\tost_gen:      %#x\n", lo->l_ost_gen);
			printf("\tost_idx:      %u\n", lo->l_ost_idx);
		}
        }

        if (lum->lmm_magic != LOV_USER_MAGIC ||
            lum->lmm_pattern != LOV_PATTERN_RAID0 ||
            lum->lmm_stripe_size != STRIPE_SIZE ||
            lum->lmm_objects[0].l_ost_idx != STRIPE_OFFSET ||
            lum->lmm_stripe_count != STRIPE_COUNT) {
                printf("incorrect striping information!\n");
                t_unlink(file);
                t_rmdir(path);
                free(lum);
                return -1;
        }

        t_unlink(file);
        t_rmdir(path);
        free(lum);
        LEAVE();
}

/*
 * getdirentries should return -1 and set errno to EINVAL when the size
 * specified as an argument is too small to contain at least one entry
 * (see bugzilla ticket 12229)
 */
int t56(char *name)
{
	int fd;
	size_t nbytes;
	off_t basep = 0;
	long rc = 0;
	struct dirent64 dir;

        ENTER("getdirentries should fail if nbytes is too small");

        /* Set count to be very small.  The result should be EINVAL */
        nbytes = 8;

        /* open the directory and call getdirentries */
        fd = t_opendir(lustre_path);

        rc = getdirentries(fd, (char *)&dir, nbytes, &basep);

        if (rc != -1) {
                printf("Test failed: getdirentries returned %lld\n",
                       (long long)rc);
                t_close(fd);
                return -1;
        }
        if (errno != EINVAL) {
                printf("Test failed: getdirentries returned %lld but errno is "
                       "set to %d (should be EINVAL)\n", (long long)rc, errno);
                t_close(fd);
                return -1;
        }
        t_close(fd);

        LEAVE();
}

extern void __liblustre_setup_(void);
extern void __liblustre_cleanup_(void);


void usage(char *cmd)
{
        printf("\n"
             "usage: %s [-o test][-e test][-v] --target mgsnid:/fsname\n",
             cmd);
        printf("       %s --dumpfile dumpfile\n", cmd);
        exit(-1);
}

struct testlist {
        int (*test)(char *name);
        char *name;
} testlist[] = {
        { t1, "1" },
        { t2, "2" },
        { t3, "3" },
        { t4, "4" },
        { t6, "6" },
        { t6b, "6b" },
        { t7, "7" },
        { t8, "8" },
        { t9, "9" },
        { t10, "10" },
        { t11, "11" },
        { t12, "12" },
        { t13, "13" },
        { t14, "14" },
        { t15, "15" },
        { t16, "16" },
        { t17, "17" },
        { t18, "18" },
        { t18b, "t8b" },
        { t19, "19" },
        { t20, "20" },
        { t21, "21" },
        { t22, "22" },
        { t23, "23" },
        { t50, "50" },
        { t50b, "50b" },
        { t51, "51" },
        { t53, "53" },
        { t54, "54" },
        { t55, "55" },
        { t56, "56" },
        { NULL, NULL }
};

int main(int argc, char * const argv[])
{
        struct testlist *test;
        int opt_index, c, rc = 0, numonly = 0, numexcept = 0;
        char *only[100], *except[100];
        static struct option long_opts[] = {
                {"dumpfile", 1, 0, 'd'},
                {"only", 1, 0, 'o'},
                {"except", 1, 0, 'e'},
                {"target", 1, 0, 't'},
                {"verbose", 1, 0, 'v'},
                {0, 0, 0, 0}
        };

        while ((c = getopt_long(argc, argv, "d:e:o:t:v", long_opts, &opt_index)) != -1) {
                switch (c) {
                case 'd':
                        setenv(ENV_LUSTRE_DUMPFILE, optarg, 1);
                        break;
                case 'e':
                        if (numexcept == 0)
                                printf("Not running test(s): ");
                        printf("%s ", optarg);
                        except[numexcept++] = optarg;
                        break;
                case 'o':
                        if (numonly == 0)
                                printf("Only running test(s): ");
                        printf("%s ", optarg);
                        only[numonly++] = optarg;
                        break;
                case 't':
                        setenv(ENV_LUSTRE_MNTTGT, optarg, 1);
                        break;
                case 'v':
                        opt_verbose++;
                        break;
                default:
                        usage(argv[0]);
                        break;
                }
        }

        if (getenv(ENV_LUSTRE_MNTTGT) == NULL &&
            getenv(ENV_LUSTRE_DUMPFILE) == NULL)
                usage(argv[0]);

        if (optind != argc)
                usage(argv[0]);

        printf("\n");

        __liblustre_setup_();

        buf_size = _npages * CFS_PAGE_SIZE;
        if (opt_verbose)
                printf("allocating %d bytes buffer\n", buf_size);
        buf_alloc = calloc(1, buf_size);
        if (buf_alloc == NULL) {
                fprintf(stderr, "error allocating %d\n", buf_size);
                exit(-ENOMEM);
        }

        for (test = testlist; test->test != NULL; test++) {
                int run = 1, i;
                int len, olen;

                if (numexcept > 0) {
                        len = strlen(test->name);
                        for (i = 0; i < numexcept; i++) {
                                olen = strlen(except[i]);

                                if (len < olen)
                                        continue;

                                if (strncmp(except[i], test->name, olen) == 0) {
                                        switch(test->name[olen]) {
                                        case '0': case '1': case '2': case '3':
                                        case '4': case '5': case '6': case '7':
                                        case '8': case '9':
                                                break;
                                        default:
                                                run = 0;
                                                break;
                                        }
                                }
                        }
                }

                if (numonly > 0) {
                        run = 0;
                        len = strlen(test->name);
                        for (i = 0; i < numonly; i++) {
                                olen = strlen(only[i]);

                                if (len < olen)
                                        continue;

                                if (strncmp(only[i], test->name, olen) == 0) {
                                        switch(test->name[olen]) {
                                        case '0': case '1': case '2': case '3':
                                        case '4': case '5': case '6': case '7':
                                        case '8': case '9':
                                                break;
                                        default:
                                                run = 1;
                                                break;
                                        }
                                }
                        }
                }
                if (run && (rc = (test->test)(test->name)) != 0)
                        break;
        }

        free(buf_alloc);

        printf("liblustre is about to shutdown\n");
        __liblustre_cleanup_();

        printf("complete successfully\n");
        return rc;
}
