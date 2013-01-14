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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/utils/liblustreapi.c
 *
 * Author: Peter J. Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Robert Read <rread@clusterfs.com>
 */

/* for O_DIRECTORY */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/param.h>
#include <fnmatch.h>
#include <glob.h>
#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#endif
#ifdef HAVE_LINUX_UNISTD_H
#include <linux/unistd.h>
#else
#include <unistd.h>
#endif

#include <liblustre.h>
#include <lnet/lnetctl.h>
#include <obd.h>
#include <lustre_lib.h>
#include <lustre/liblustreapi.h>
#include <obd_lov.h>

static unsigned llapi_dir_filetype_table[] = {
        [DT_UNKNOWN]= 0,
        [DT_FIFO]= S_IFIFO,
        [DT_CHR] = S_IFCHR,
        [DT_DIR] = S_IFDIR,
        [DT_BLK] = S_IFBLK,
        [DT_REG] = S_IFREG,
        [DT_LNK] = S_IFLNK,
        [DT_SOCK]= S_IFSOCK,
#if defined(DT_DOOR) && defined(S_IFDOOR)
        [DT_DOOR]= S_IFDOOR,
#endif
};

#if defined(DT_DOOR) && defined(S_IFDOOR)
static const int DT_MAX = DT_DOOR;
#else
static const int DT_MAX = DT_SOCK;
#endif

static unsigned llapi_filetype_dir_table[] = {
        [0]= DT_UNKNOWN,
        [S_IFIFO]= DT_FIFO,
        [S_IFCHR] = DT_CHR,
        [S_IFDIR] = DT_DIR,
        [S_IFBLK] = DT_BLK,
        [S_IFREG] = DT_REG,
        [S_IFLNK] = DT_LNK,
        [S_IFSOCK]= DT_SOCK,
#if defined(DT_DOOR) && defined(S_IFDOOR)
        [S_IFDOOR]= DT_DOOR,
#endif
};

#if defined(DT_DOOR) && defined(S_IFDOOR)
static const int S_IFMAX = DT_DOOR;
#else
static const int S_IFMAX = DT_SOCK;
#endif

/* liblustreapi message level */
static int llapi_msg_level = LLAPI_MSG_MAX;

void llapi_msg_set_level(int level)
{
        /* ensure level is in the good range */
        if (level < LLAPI_MSG_OFF)
                llapi_msg_level = LLAPI_MSG_OFF;
        else if (level > LLAPI_MSG_MAX)
                llapi_msg_level = LLAPI_MSG_MAX;
        else
                llapi_msg_level = level;
}

/* llapi_error will preserve errno */
void llapi_error(int level, int _rc, char *fmt, ...)
{
        va_list args;
        int tmp_errno = errno;
        /* to protect using errno as _rc argument */
        int rc = abs(_rc);

        if ((level & LLAPI_MSG_MASK) > llapi_msg_level)
                return;

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);

        if (level & LLAPI_MSG_NO_ERRNO)
                fprintf(stderr, "\n");
        else
                fprintf(stderr, ": %s (%d)\n", strerror(rc), rc);
        errno = tmp_errno;
}

/* llapi_printf will preserve errno */
void llapi_printf(int level, char *fmt, ...)
{
        va_list args;
        int tmp_errno = errno;

        if ((level & LLAPI_MSG_MASK) > llapi_msg_level)
                return;

        va_start(args, fmt);
        vfprintf(stdout, fmt, args);
        va_end(args);
        errno = tmp_errno;
}

/* size_units is unchanged if no specifier used */
int parse_size(char *optarg, unsigned long long *size,
               unsigned long long *size_units, int bytes_spec)
{
        char *end;

        *size = strtoull(optarg, &end, 0);

        if (*end != '\0') {
                if ((*end == 'b') && *(end+1) == '\0' &&
                    (*size & (~0ULL << (64 - 9))) == 0 &&
                    !bytes_spec) {
                        *size <<= 9;
                        *size_units = 1 << 9;
                } else if ((*end == 'b') && *(end+1) == '\0' &&
                           bytes_spec) {
                        *size_units = 1;
                } else if ((*end == 'k' || *end == 'K') &&
                           *(end+1) == '\0' && (*size &
                           (~0ULL << (64 - 10))) == 0) {
                        *size <<= 10;
                        *size_units = 1 << 10;
                } else if ((*end == 'm' || *end == 'M') &&
                           *(end+1) == '\0' && (*size &
                           (~0ULL << (64 - 20))) == 0) {
                        *size <<= 20;
                        *size_units = 1 << 20;
                } else if ((*end == 'g' || *end == 'G') &&
                           *(end+1) == '\0' && (*size &
                           (~0ULL << (64 - 30))) == 0) {
                        *size <<= 30;
                        *size_units = 1 << 30;
                } else if ((*end == 't' || *end == 'T') &&
                           *(end+1) == '\0' && (*size &
                           (~0ULL << (64 - 40))) == 0) {
                        *size <<= 40;
                        *size_units = 1ULL << 40;
                } else if ((*end == 'p' || *end == 'P') &&
                           *(end+1) == '\0' && (*size &
                           (~0ULL << (64 - 50))) == 0) {
                        *size <<= 50;
                        *size_units = 1ULL << 50;
                } else if ((*end == 'e' || *end == 'E') &&
                           *(end+1) == '\0' && (*size &
                           (~0ULL << (64 - 60))) == 0) {
                        *size <<= 60;
                        *size_units = 1ULL << 60;
                } else {
                        return -1;
                }
        }

        return 0;
}

int llapi_stripe_limit_check(unsigned long long stripe_size, int stripe_offset,
                             int stripe_count, int stripe_pattern)
{
        int page_size, rc;

        /* 64 KB is the largest common page size I'm aware of (on ia64), but
         * check the local page size just in case. */
        page_size = LOV_MIN_STRIPE_SIZE;
        if (getpagesize() > page_size) {
                page_size = getpagesize();
                llapi_err_noerrno(LLAPI_MSG_WARN,
                                  "warning: your page size (%u) is "
                                  "larger than expected (%u)", page_size,
                                  LOV_MIN_STRIPE_SIZE);
        }
        if (stripe_size < 0 || (stripe_size & (LOV_MIN_STRIPE_SIZE - 1))) {
                rc = -EINVAL;
                llapi_error(LLAPI_MSG_ERROR, rc, "error: bad stripe_size %lu, "
                            "must be an even multiple of %d bytes",
                            stripe_size, page_size);
                return rc;
        }
        if (stripe_offset < -1 || stripe_offset > MAX_OBD_DEVICES) {
                rc = -EINVAL;
                llapi_error(LLAPI_MSG_ERROR, rc, "error: bad stripe offset %d",
                            stripe_offset);
                return rc;
        }
        if (stripe_count < -1 || stripe_count > LOV_MAX_STRIPE_COUNT) {
                rc = -EINVAL;
                llapi_error(LLAPI_MSG_ERROR, rc, "error: bad stripe count %d",
                            stripe_count);
                return rc;
        }
        if (stripe_size >= (1ULL << 32)) {
                rc = -EINVAL;
                llapi_error(LLAPI_MSG_ERROR, rc,
                            "warning: stripe size larger than 4G "
                            "is not currently supported and would wrap");
                return rc;
        }
        return 0;
}

static int find_target_obdpath(char *fsname, char *path)
{
        glob_t glob_info;
        char pattern[PATH_MAX + 1];
        int rc;

        snprintf(pattern, PATH_MAX,
                 "/proc/fs/lustre/lov/%s-*/target_obd",
                 fsname);
        rc = glob(pattern, GLOB_BRACE, NULL, &glob_info);
        if (rc == GLOB_NOMATCH)
                return -ENODEV;
        else if (rc)
                return -EINVAL;

        strcpy(path, glob_info.gl_pathv[0]);
        globfree(&glob_info);
        return 0;
}

static int find_poolpath(char *fsname, char *poolname, char *poolpath)
{
        glob_t glob_info;
        char pattern[PATH_MAX + 1];
        int rc;

        snprintf(pattern, PATH_MAX,
                 "/proc/fs/lustre/lov/%s-*/pools/%s",
                 fsname, poolname);
        rc = glob(pattern, GLOB_BRACE, NULL, &glob_info);
        /* If no pools, make sure the lov is available */
        if ((rc == GLOB_NOMATCH) &&
            (find_target_obdpath(fsname, poolpath) == -ENODEV))
                return -ENODEV;
        if (rc)
                return -EINVAL;

        strcpy(poolpath, glob_info.gl_pathv[0]);
        globfree(&glob_info);
        return 0;
}

/*
 * if pool is NULL, search ostname in target_obd
 * if pool is not NULL:
 *  if pool not found returns errno < 0
 *  if ostname is NULL, returns 1 if pool is not empty and 0 if pool empty
 *  if ostname is not NULL, returns 1 if OST is in pool and 0 if not
 */
int llapi_search_ost(char *fsname, char *poolname, char *ostname)
{
        FILE *fd;
        char buffer[PATH_MAX + 1];
        int len = 0, rc;

        if (ostname != NULL)
                len = strlen(ostname);

        if (poolname == NULL)
                rc = find_target_obdpath(fsname, buffer);
        else
                rc = find_poolpath(fsname, poolname, buffer);
        if (rc)
                return rc;

        if ((fd = fopen(buffer, "r")) == NULL)
                return -errno;

        while (fgets(buffer, sizeof(buffer), fd) != NULL) {
                if (poolname == NULL) {
                        char *ptr;
                        /* Search for an ostname in the list of OSTs
                         Line format is IDX: fsname-OSTxxxx_UUID STATUS */
                        ptr = strchr(buffer, ' ');
                        if ((ptr != NULL) &&
                            (strncmp(ptr + 1, ostname, len) == 0)) {
                                fclose(fd);
                                return 1;
                        }
                } else {
                        /* Search for an ostname in a pool,
                         (or an existing non-empty pool if no ostname) */
                        if ((ostname == NULL) ||
                            (strncmp(buffer, ostname, len) == 0)) {
                                fclose(fd);
                                return 1;
                        }
                }
        }
        fclose(fd);
        return 0;
}

int llapi_file_open_pool(const char *name, int flags, int mode,
                         unsigned long long stripe_size, int stripe_offset,
                         int stripe_count, int stripe_pattern, char *pool_name)
{
        struct lov_user_md_v3 lum = { 0 };
        int fd, rc = 0;
        int isdir = 0;

        /* Make sure we have a good pool */
        if (pool_name != NULL) {
                char fsname[MAX_OBD_NAME + 1], *ptr;

                rc = llapi_search_fsname(name, fsname);
                if (rc) {
                        llapi_error(LLAPI_MSG_ERROR, rc,
                                    "'%s' is not on a Lustre filesystem",
                                    name);
                        return rc;
                }

                /* in case user gives the full pool name <fsname>.<poolname>,
                 * strip the fsname */
                ptr = strchr(pool_name, '.');
                if (ptr != NULL) {
                        *ptr = '\0';
                        if (strcmp(pool_name, fsname) != 0) {
                                *ptr = '.';
                                llapi_err_noerrno(LLAPI_MSG_ERROR,
                                          "Pool '%s' is not on filesystem '%s'",
                                          pool_name, fsname);
                                return -EINVAL;
                        }
                        pool_name = ptr + 1;
                }

                /* Make sure the pool exists and is non-empty */
                rc = llapi_search_ost(fsname, pool_name, NULL);
                if (rc < 1) {
                        llapi_err_noerrno(LLAPI_MSG_ERROR,
                                          "pool '%s.%s' %s", fsname, pool_name,
                                          rc == 0 ? "has no OSTs" :
                                                    "does not exist");
                        return -EINVAL;
                }
        }

        fd = open(name, flags | O_LOV_DELAY_CREATE, mode);
        if (fd < 0 && errno == EISDIR) {
                fd = open(name, O_DIRECTORY | O_RDONLY);
                isdir++;
        }

        if (fd < 0) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "unable to open '%s'", name);
                return rc;
        }

        rc = llapi_stripe_limit_check(stripe_size, stripe_offset, stripe_count,
                                      stripe_pattern);
        if (rc != 0)
                goto out;

        /*  Initialize IOCTL striping pattern structure */
        lum.lmm_magic = LOV_USER_MAGIC_V3;
        lum.lmm_pattern = stripe_pattern;
        lum.lmm_stripe_size = stripe_size;
        lum.lmm_stripe_count = stripe_count;
        lum.lmm_stripe_offset = stripe_offset;
        if (pool_name != NULL) {
                strncpy(lum.lmm_pool_name, pool_name, LOV_MAXPOOLNAME);
        } else {
                /* If no pool is specified at all, use V1 request */
                lum.lmm_magic = LOV_USER_MAGIC_V1;
        }

        if (ioctl(fd, LL_IOC_LOV_SETSTRIPE, &lum)) {
                char *errmsg = "stripe already set";
                rc = -errno;
                if (errno != EEXIST && errno != EALREADY)
                        errmsg = strerror(errno);

                llapi_err_noerrno(LLAPI_MSG_ERROR,
                                  "error on ioctl "LPX64" for '%s' (%d): %s",
                                  (__u64)LL_IOC_LOV_SETSTRIPE, name, fd,errmsg);
        }
out:
        if (rc) {
                close(fd);
                fd = rc;
        }

        return fd;
}

int llapi_file_open(const char *name, int flags, int mode,
                    unsigned long long stripe_size, int stripe_offset,
                    int stripe_count, int stripe_pattern)
{
        return llapi_file_open_pool(name, flags, mode, stripe_size,
                                    stripe_offset, stripe_count,
                                    stripe_pattern, NULL);
}

int llapi_file_create(const char *name, unsigned long long stripe_size,
                      int stripe_offset, int stripe_count, int stripe_pattern)
{
        int fd;

        fd = llapi_file_open_pool(name, O_CREAT | O_WRONLY, 0644, stripe_size,
                                  stripe_offset, stripe_count, stripe_pattern,
                                  NULL);
        if (fd < 0)
                return fd;

        close(fd);
        return 0;
}

int llapi_file_create_pool(const char *name, unsigned long long stripe_size,
                           int stripe_offset, int stripe_count,
                           int stripe_pattern, char *pool_name)
{
        int fd;

        fd = llapi_file_open_pool(name, O_CREAT | O_WRONLY, 0644, stripe_size,
                                  stripe_offset, stripe_count, stripe_pattern,
                                  pool_name);
        if (fd < 0)
                return fd;

        close(fd);
        return 0;
}

/*
 * Find the fsname, the full path, and/or an open fd.
 * Either the fsname or path must not be NULL
 */
#define WANT_PATH   0x1
#define WANT_FSNAME 0x2
#define WANT_FD     0x4
#define WANT_INDEX  0x8
#define WANT_ERROR  0x10
static int get_root_path(int want, char *fsname, int *outfd, char *path,
                         int index)
{
        struct mntent mnt;
        char buf[PATH_MAX], mntdir[PATH_MAX];
        char *ptr;
        FILE *fp;
        int idx = 0, len = 0, mntlen, fd;
        int rc = -ENODEV;

        /* get the mount point */
        fp = setmntent(MOUNTED, "r");
        if (fp == NULL) {
                rc = -EIO;
                llapi_error(LLAPI_MSG_ERROR, rc,
                            "setmntent(%s) failed", MOUNTED);
                return rc;
        }
        while (1) {
                if (getmntent_r(fp, &mnt, buf, sizeof(buf)) == NULL)
                        break;

                if (!llapi_is_lustre_mnt(&mnt))
                        continue;

                if ((want & WANT_INDEX) && (idx++ != index))
                        continue;

                mntlen = strlen(mnt.mnt_dir);
                ptr = strrchr(mnt.mnt_fsname, '/');
                if (!ptr && !len) {
                        rc = -EINVAL;
                        break;
                }
                ptr++;

                /* Check the fsname for a match, if given */
                if (!(want & WANT_FSNAME) && fsname != NULL &&
                    (strlen(fsname) > 0) && (strcmp(ptr, fsname) != 0))
                        continue;

                /* If the path isn't set return the first one we find */
                if (path == NULL || strlen(path) == 0) {
                        strcpy(mntdir, mnt.mnt_dir);
                        if ((want & WANT_FSNAME) && fsname != NULL)
                                strcpy(fsname, ptr);
                        rc = 0;
                        break;
                /* Otherwise find the longest matching path */
                } else if ((strlen(path) >= mntlen) && (mntlen >= len) &&
                           (strncmp(mnt.mnt_dir, path, mntlen) == 0)) {
                        strcpy(mntdir, mnt.mnt_dir);
                        len = mntlen;
                        if ((want & WANT_FSNAME) && fsname != NULL)
                                strcpy(fsname, ptr);
                        rc = 0;
                }
        }
        endmntent(fp);

        /* Found it */
        if (rc == 0) {
                if ((want & WANT_PATH) && path != NULL)
                        strcpy(path, mntdir);
                if (want & WANT_FD) {
                        fd = open(mntdir, O_RDONLY | O_DIRECTORY | O_NONBLOCK);
                        if (fd < 0) {
                                rc = -errno;
                                llapi_error(LLAPI_MSG_ERROR, rc,
                                            "error opening '%s'\n", mntdir);
                        } else {
                                *outfd = fd;
                        }
                }
        } else if (want & WANT_ERROR)
                llapi_err_noerrno(LLAPI_MSG_ERROR,
                                  "can't find fs root for '%s': %d",
                                  (want & WANT_PATH) ? fsname : path, rc);
        return rc;
}

/*
 * search lustre mounts
 *
 * Calling this function will return to the user the mount point, mntdir, and
 * the file system name, fsname, if the user passed a buffer to this routine.
 *
 * The user inputs are pathname and index. If the pathname is supplied then
 * the value of the index will be ignored. The pathname will return data if
 * the pathname is located on a lustre mount. Index is used to pick which
 * mount point you want in the case of multiple mounted lustre file systems.
 * See function lfs_osts in lfs.c for a example of the index use.
 */
int llapi_search_mounts(const char *pathname, int index, char *mntdir,
                        char *fsname)
{
        int want = WANT_PATH, idx = -1;

        if (!pathname || pathname[0] == '\0') {
                want |= WANT_INDEX;
                idx = index;
        } else
                strcpy(mntdir, pathname);

        if (fsname)
                want |= WANT_FSNAME;
        return get_root_path(want, fsname, NULL, mntdir, idx);
}

int llapi_search_fsname(const char *pathname, char *fsname)
{
        char *path;
        int rc;

        path = realpath(pathname, NULL);
        if (path == NULL) {
                char buf[PATH_MAX + 1], *ptr;

                buf[0] = 0;
                if (pathname[0] != '/') {
                        /* Need an absolute path, but realpath() only works for
                         * pathnames that actually exist.  We go through the
                         * extra hurdle of dirname(getcwd() + pathname) in
                         * case the relative pathname contains ".." in it. */
                        if (getcwd(buf, sizeof(buf) - 1) == NULL)
                                return -errno;
                        strcat(buf, "/");
                }
                strncat(buf, pathname, sizeof(buf) - strlen(buf));
                path = realpath(buf, NULL);
                if (path == NULL) {
                        ptr = strrchr(buf, '/');
                        if (ptr == NULL)
                                return -ENOENT;
                        *ptr = '\0';
                        path = realpath(buf, NULL);
                        if (path == NULL) {
                                rc = -errno;
                                llapi_error(LLAPI_MSG_ERROR, rc,
                                            "pathname '%s' cannot expand",
                                            pathname);
                                return rc;
                        }
                }
        }
        rc = get_root_path(WANT_FSNAME | WANT_ERROR, fsname, NULL, path, -1);
        free(path);
        return rc;
}

/* return the first file matching this pattern */
static int first_match(char *pattern, char *buffer)
{
        glob_t glob_info;

        if (glob(pattern, GLOB_BRACE, NULL, &glob_info))
                return -ENOENT;

        if (glob_info.gl_pathc < 1) {
                globfree(&glob_info);
                return -ENOENT;
        }

        strcpy(buffer, glob_info.gl_pathv[0]);

        globfree(&glob_info);
        return 0;
}

/*
 * find the pool directory path under /proc
 * (can be also used to test if a fsname is known)
 */
static int poolpath(char *fsname, char *pathname, char *pool_pathname)
{
        int rc = 0;
        char pattern[PATH_MAX + 1];
        char buffer[PATH_MAX];

        if (fsname == NULL) {
                rc = llapi_search_fsname(pathname, buffer);
                if (rc != 0)
                        return rc;
                fsname = buffer;
                strcpy(pathname, fsname);
        }

        snprintf(pattern, PATH_MAX, "/proc/fs/lustre/lov/%s-*/pools", fsname);
        rc = first_match(pattern, buffer);
        if (rc)
                return rc;

        /* in fsname test mode, pool_pathname is NULL */
        if (pool_pathname != NULL)
                strcpy(pool_pathname, buffer);

        return 0;
}

/**
 * Get the list of pool members.
 * \param poolname    string of format \<fsname\>.\<poolname\>
 * \param members     caller-allocated array of char*
 * \param list_size   size of the members array
 * \param buffer      caller-allocated buffer for storing OST names
 * \param buffer_size size of the buffer
 *
 * \return number of members retrieved for this pool
 * \retval -error failure
 */
int llapi_get_poolmembers(const char *poolname, char **members,
                          int list_size, char *buffer, int buffer_size)
{
        char fsname[PATH_MAX + 1];
        char *pool, *tmp;
        char pathname[PATH_MAX + 1];
        char path[PATH_MAX + 1];
        char buf[1024];
        FILE *fd;
        int rc = 0;
        int nb_entries = 0;
        int used = 0;

        /* name is FSNAME.POOLNAME */
        if (strlen(poolname) > PATH_MAX)
                return -EOVERFLOW;
        strcpy(fsname, poolname);
        pool = strchr(fsname, '.');
        if (pool == NULL)
                return -EINVAL;

        *pool = '\0';
        pool++;

        rc = poolpath(fsname, NULL, pathname);
        if (rc != 0) {
                llapi_error(LLAPI_MSG_ERROR, rc,
                            "Lustre filesystem '%s' not found",
                            fsname);
                return rc;
        }

        llapi_printf(LLAPI_MSG_NORMAL, "Pool: %s.%s\n", fsname, pool);
        sprintf(path, "%s/%s", pathname, pool);
        if ((fd = fopen(path, "r")) == NULL) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "Cannot open %s", path);
                return rc;
        }

        rc = 0;
        while (fgets(buf, sizeof(buf), fd) != NULL) {
                if (nb_entries >= list_size) {
                        rc = -EOVERFLOW;
                        break;
                }
                /* remove '\n' */
                if ((tmp = strchr(buf, '\n')) != NULL)
                        *tmp='\0';
                if (used + strlen(buf) + 1 > buffer_size) {
                        rc = -EOVERFLOW;
                        break;
                }

                strcpy(buffer + used, buf);
                members[nb_entries] = buffer + used;
                used += strlen(buf) + 1;
                nb_entries++;
                rc = nb_entries;
        }

        fclose(fd);
        return rc;
}

/**
 * Get the list of pools in a filesystem.
 * \param name        filesystem name or path
 * \param poollist    caller-allocated array of char*
 * \param list_size   size of the poollist array
 * \param buffer      caller-allocated buffer for storing pool names
 * \param buffer_size size of the buffer
 *
 * \return number of pools retrieved for this filesystem
 * \retval -error failure
 */
int llapi_get_poollist(const char *name, char **poollist, int list_size,
                       char *buffer, int buffer_size)
{
        char fsname[PATH_MAX + 1], rname[PATH_MAX + 1], pathname[PATH_MAX + 1];
        char *ptr;
        DIR *dir;
        struct dirent pool;
        struct dirent *cookie = NULL;
        int rc = 0;
        unsigned int nb_entries = 0;
        unsigned int used = 0;
        unsigned int i;

        /* initilize output array */
        for (i = 0; i < list_size; i++)
                poollist[i] = NULL;

        /* is name a pathname ? */
        ptr = strchr(name, '/');
        if (ptr != NULL) {
                /* only absolute pathname is supported */
                if (*name != '/')
                        return -EINVAL;

                if (!realpath(name, rname)) {
                        rc = -errno;
                        llapi_error(LLAPI_MSG_ERROR, rc, "invalid path '%s'",
                                    name);
                        return rc;
                }

                rc = poolpath(NULL, rname, pathname);
                if (rc != 0) {
                        llapi_error(LLAPI_MSG_ERROR, rc, "'%s' is not"
                                    " a Lustre filesystem", name);
                        return rc;
                }
                strcpy(fsname, rname);
        } else {
                /* name is FSNAME */
                strcpy(fsname, name);
                rc = poolpath(fsname, NULL, pathname);
        }
        if (rc != 0) {
                llapi_error(LLAPI_MSG_ERROR, rc,
                            "Lustre filesystem '%s' not found", name);
                return rc;
        }

        llapi_printf(LLAPI_MSG_NORMAL, "Pools from %s:\n", fsname);
        if ((dir = opendir(pathname)) == NULL) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc,
                            "Could not open pool list for '%s'",
                            name);
                return rc;
        }

        while(1) {
                rc = readdir_r(dir, &pool, &cookie);

                if (rc != 0) {
                        rc = -errno;
                        llapi_error(LLAPI_MSG_ERROR, rc,
                                    "Error reading pool list for '%s'", name);
                        return rc;
                } else if ((rc == 0) && (cookie == NULL)) {
                        /* end of directory */
                        break;
                }

                /* ignore . and .. */
                if (!strcmp(pool.d_name, ".") || !strcmp(pool.d_name, ".."))
                        continue;

                /* check output bounds */
                if (nb_entries >= list_size)
                        return -EOVERFLOW;

                /* +2 for '.' and final '\0' */
                if (used + strlen(pool.d_name) + strlen(fsname) + 2
                    > buffer_size)
                        return -EOVERFLOW;

                sprintf(buffer + used, "%s.%s", fsname, pool.d_name);
                poollist[nb_entries] = buffer + used;
                used += strlen(pool.d_name) + strlen(fsname) + 2;
                nb_entries++;
        }

        closedir(dir);
        return nb_entries;
}

/* wrapper for lfs.c and obd.c */
int llapi_poollist(const char *name)
{
        /* list of pool names (assume that pool count is smaller
           than OST count) */
        char *list[FIND_MAX_OSTS];
        char *buffer;
        /* fsname-OST0000_UUID < 32 char, 1 per OST */
        int bufsize = FIND_MAX_OSTS * 32;
        int i, nb;

        buffer = malloc(bufsize);
        if (buffer == NULL)
                return -ENOMEM;

        if ((name[0] == '/') || (strchr(name, '.') == NULL))
                /* name is a path or fsname */
                nb = llapi_get_poollist(name, list, FIND_MAX_OSTS, buffer,
                                        bufsize);
        else
                /* name is a pool name (<fsname>.<poolname>) */
                nb = llapi_get_poolmembers(name, list, FIND_MAX_OSTS, buffer,
                                           bufsize);

        for (i = 0; i < nb; i++)
                llapi_printf(LLAPI_MSG_NORMAL, "%s\n", list[i]);

        free(buffer);
        return (nb < 0 ? nb : 0);
}

typedef int (semantic_func_t)(char *path, DIR *parent, DIR *d,
                              void *data, struct dirent64 *de);

#define MAX_LOV_UUID_COUNT      max(LOV_MAX_STRIPE_COUNT, 1000)
#define OBD_NOT_FOUND           (-1)

static int common_param_init(struct find_param *param)
{
        param->lumlen = lov_mds_md_size(MAX_LOV_UUID_COUNT, LOV_MAGIC_V3);
        param->lmd = malloc(sizeof(lstat_t) + param->lumlen);
        if (param->lmd == NULL) {
                llapi_error(LLAPI_MSG_ERROR, -ENOMEM,
                            "error: allocation of %d bytes for ioctl",
                            sizeof(lstat_t) + param->lumlen);
                return -ENOMEM;
        }

        param->got_uuids = 0;
        param->obdindexes = NULL;
        param->obdindex = OBD_NOT_FOUND;
        return 0;
}

static void find_param_fini(struct find_param *param)
{
        if (param->obdindexes)
                free(param->obdindexes);

        if (param->lmd)
                free(param->lmd);
}

static int cb_common_fini(char *path, DIR *parent, DIR *d, void *data,
                          struct dirent64 *de)
{
        struct find_param *param = (struct find_param *)data;
        param->depth--;
        return 0;
}

/* set errno upon failure */
static DIR *opendir_parent(char *path)
{
        DIR *parent;
        char *fname;
        char c;

        fname = strrchr(path, '/');
        if (fname == NULL)
                return opendir(".");

        c = fname[1];
        fname[1] = '\0';
        parent = opendir(path);
        fname[1] = c;
        return parent;
}

int llapi_mds_getfileinfo(char *path, DIR *parent,
                          struct lov_user_mds_data *lmd)
{
        lstat_t *st = &lmd->lmd_st;
        char *fname = strrchr(path, '/');
        int ret = 0;

        if (parent == NULL)
                return -EINVAL;

        fname = (fname == NULL ? path : fname + 1);
        /* retrieve needed file info */
        strncpy((char *)lmd, fname, lov_mds_md_size(MAX_LOV_UUID_COUNT,
                LOV_MAGIC));
        ret = ioctl(dirfd(parent), IOC_MDC_GETFILEINFO, (void *)lmd);

        if (ret) {
                if (errno == ENOTTY) {
                        /* ioctl is not supported, it is not a lustre fs.
                         * Do the regular lstat(2) instead. */
                        ret = lstat_f(path, st);
                        if (ret) {
                                ret = -errno;
                                llapi_error(LLAPI_MSG_ERROR, ret,
                                            "error: %s: lstat failed for %s",
                                            __func__, path);
                                return ret;
                        }
                } else if (errno == ENOENT) {
                        ret = -errno;
                        llapi_error(LLAPI_MSG_WARN, ret,
                                    "warning: %s: %s does not exist",
                                    __func__, path);
                        return ret;
                } else {
                        ret = -errno;
                        llapi_error(LLAPI_MSG_ERROR, ret,
                                   "error: %s: IOC_MDC_GETFILEINFO failed for %s",
                                   __func__, path);
                        return ret;
                }
        }

        return 0;
}

static int llapi_semantic_traverse(char *path, int size, DIR *parent,
                                   semantic_func_t sem_init,
                                   semantic_func_t sem_fini, void *data,
                                   struct dirent64 *de)
{
        struct dirent64 *dent;
        int len, ret;
        DIR *d, *p = NULL;

        ret = 0;
        len = strlen(path);

        d = opendir(path);
        if (!d && errno != ENOTDIR) {
                ret = -errno;
                llapi_error(LLAPI_MSG_ERROR, ret, "%s: Failed to open '%s'",
                            __func__, path);
                return ret;
        } else if (!d && !parent) {
                /* ENOTDIR. Open the parent dir. */
                p = opendir_parent(path);
                if (!p)
                        GOTO(out, ret = -errno);
        }

        if (sem_init && (ret = sem_init(path, parent ?: p, d, data, de)))
                goto err;

        if (!d)
                GOTO(out, ret = 0);

        while ((dent = readdir64(d)) != NULL) {
                ((struct find_param *)data)->have_fileinfo = 0;

                if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
                        continue;

                path[len] = 0;
                if ((len + dent->d_reclen + 2) > size) {
                        llapi_err_noerrno(LLAPI_MSG_ERROR,
                                          "error: %s: string buffer is too small",
                                          __func__);
                        break;
                }

                if (path[len-1] != '/')
                        strcat(path, "/");
                strcat(path, dent->d_name);

                if (dent->d_type == DT_UNKNOWN) {
                        lstat_t *st = &((struct find_param *)data)->lmd->lmd_st;

                        ret = llapi_mds_getfileinfo(path, d,
                                             ((struct find_param *)data)->lmd);
                        if (ret == 0) {
                                ((struct find_param *)data)->have_fileinfo = 1;
                                dent->d_type =
                                        llapi_filetype_dir_table[st->st_mode &
                                                                 S_IFMT];
                        }
                        if (ret == -ENOENT)
                                continue;
                }

                switch (dent->d_type) {
                case DT_UNKNOWN:
                        llapi_err_noerrno(LLAPI_MSG_ERROR,
                                          "error: %s: '%s' is UNKNOWN type %d",
                                          __func__, dent->d_name, dent->d_type);
                        break;
                case DT_DIR:
                        ret = llapi_semantic_traverse(path, size, d, sem_init,
                                                      sem_fini, data, dent);
                        if (ret < 0)
                                goto out;
                        break;
                default:
                        ret = 0;
                        if (sem_init) {
                                ret = sem_init(path, d, NULL, data, dent);
                                if (ret < 0)
                                        goto out;
                        }
                        if (sem_fini && ret == 0)
                                sem_fini(path, d, NULL, data, dent);
                }
        }

out:
        path[len] = 0;

        if (sem_fini)
                sem_fini(path, parent, d, data, de);
err:
        if (d)
                closedir(d);
        if (p)
                closedir(p);
        return ret;
}

static int param_callback(char *path, semantic_func_t sem_init,
                          semantic_func_t sem_fini, struct find_param *param)
{
        int ret, len = strlen(path);
        char *buf;

        if (len > PATH_MAX) {
                ret = -EINVAL;
                llapi_error(LLAPI_MSG_ERROR, ret,
                            "Path name '%s' is too long", path);
                return ret;
        }

        buf = (char *)malloc(PATH_MAX + 1);
        if (!buf)
                return -ENOMEM;

        ret = common_param_init(param);
        if (ret)
                goto out;
        param->depth = 0;

        strncpy(buf, path, PATH_MAX + 1);
        ret = llapi_semantic_traverse(buf, PATH_MAX + 1, NULL, sem_init,
                                      sem_fini, param, NULL);
out:
        find_param_fini(param);
        free(buf);
        return ret < 0 ? ret : 0;
}

int llapi_file_fget_lov_uuid(int fd, struct obd_uuid *lov_name)
{
        int rc = ioctl(fd, OBD_IOC_GETNAME, lov_name);
        if (rc) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "error: can't get lov name.");
        }
        return rc;
}

int llapi_file_get_lov_uuid(const char *path, struct obd_uuid *lov_uuid)
{
        int fd, rc;

        fd = open(path, O_RDONLY);
        if (fd < 0) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "error opening %s", path);
                return rc;
        }

        rc = llapi_file_fget_lov_uuid(fd, lov_uuid);

        close(fd);
        return rc;
}

/*
 * If uuidp is NULL, return the number of available obd uuids.
 * If uuidp is non-NULL, then it will return the uuids of the obds. If
 * there are more OSTs then allocated to uuidp, then an error is returned with
 * the ost_count set to number of available obd uuids.
 */
int llapi_lov_get_uuids(int fd, struct obd_uuid *uuidp, int *ost_count)
{
        struct obd_uuid lov_name;
        char buf[1024];
        FILE *fp;
        int rc = 0, index = 0;

        /* Get the lov name */
        rc = llapi_file_fget_lov_uuid(fd, &lov_name);
        if (rc)
                return rc;

        /* Now get the ost uuids from /proc */
        snprintf(buf, sizeof(buf), "/proc/fs/lustre/lov/%s/target_obd",
                 lov_name.uuid);
        fp = fopen(buf, "r");
        if (fp == NULL) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "error: opening '%s'", buf);
                return rc;
        }

        while (fgets(buf, sizeof(buf), fp) != NULL) {
                if (uuidp && (index < *ost_count)) {
                        if (sscanf(buf, "%d: %s", &index, uuidp[index].uuid) <2)
                                break;
                }
                index++;
        }

        fclose(fp);

        if (uuidp && (index >= *ost_count))
                return -EOVERFLOW;

        *ost_count = index;
        return 0;
}

/* Check if user specified value matches a real uuid.  Ignore _UUID,
 * -osc-4ba41334, other trailing gunk in comparison.
 * @param real_uuid ends in "_UUID"
 * @param search_uuid may or may not end in "_UUID"
 */
int llapi_uuid_match(char *real_uuid, char *search_uuid)
{
        int cmplen = strlen(real_uuid);
        int searchlen = strlen(search_uuid);

        if (cmplen > 5 && strcmp(real_uuid + cmplen - 5, "_UUID") == 0)
                cmplen -= 5;
        if (searchlen > 5 && strcmp(search_uuid + searchlen - 5, "_UUID") == 0)
                searchlen -= 5;

        /* The UUIDs may legitimately be different lengths, if
         * the system was upgraded from an older version. */
        if (cmplen != searchlen)
                return 0;

        return (strncmp(search_uuid, real_uuid, cmplen) == 0);
}

/* Here, param->obduuid points to a single obduuid, the index of which is
 * returned in param->obdindex */
static int setup_obd_uuid(DIR *dir, char *dname, struct find_param *param)
{
        struct obd_uuid lov_uuid;
        char uuid[sizeof(struct obd_uuid)];
        char buf[1024];
        FILE *fp;
        int rc = 0, index;

        if (param->got_uuids)
                return rc;

        /* Get the lov name */
        rc = llapi_file_fget_lov_uuid(dirfd(dir), &lov_uuid);
        if (rc) {
                if (rc != -ENOTTY) {
                        llapi_error(LLAPI_MSG_ERROR, rc,
                                    "error: can't get lov name: %s", dname);
                } else {
                        rc = 0;
                }
                return rc;
        }

        param->got_uuids = 1;

        /* Now get the ost uuids from /proc */
        snprintf(buf, sizeof(buf), "/proc/fs/lustre/lov/%s/target_obd",
                 lov_uuid.uuid);
        fp = fopen(buf, "r");
        if (fp == NULL) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "error: opening '%s'", buf);
                return rc;
        }

        if (!param->obduuid && !param->quiet && !param->obds_printed)
                llapi_printf(LLAPI_MSG_NORMAL, "OBDS:\n");

        while (fgets(buf, sizeof(buf), fp) != NULL) {
                if (sscanf(buf, "%d: %s", &index, uuid) < 2)
                        break;

                if (param->obduuid) {
                        if (llapi_uuid_match(uuid, param->obduuid->uuid)) {
                                param->obdindex = index;
                                break;
                        }
                } else if (!param->quiet && !param->obds_printed) {
                        /* Print everything */
                        llapi_printf(LLAPI_MSG_NORMAL, "%s", buf);
                }
        }
        param->obds_printed = 1;

        fclose(fp);

        if (param->obduuid && (param->obdindex == OBD_NOT_FOUND)) {
                llapi_err_noerrno(LLAPI_MSG_ERROR,
                                  "error: %s: unknown obduuid: %s",
                                  __FUNCTION__, param->obduuid->uuid);
                rc = -EINVAL;
        }

        return (rc);
}

/* In this case, param->obduuid will be an array of obduuids and
 * obd index for all these obduuids will be returned in
 * param->obdindexes */
static int setup_obd_indexes(DIR *dir, struct find_param *param)
{
        struct obd_uuid *uuids = NULL;
        int obdcount = INIT_ALLOC_NUM_OSTS;
        int ret, obd_valid = 0, obdnum, i;

        uuids = (struct obd_uuid *)malloc(INIT_ALLOC_NUM_OSTS *
                                          sizeof(struct obd_uuid));
        if (uuids == NULL)
                return -ENOMEM;

retry_get_uuids:
        ret = llapi_lov_get_uuids(dirfd(dir), uuids,
                                  &obdcount);
        if (ret) {
                struct obd_uuid *uuids_temp;

                if (ret == -EOVERFLOW) {
                        uuids_temp = realloc(uuids, obdcount *
                                             sizeof(struct obd_uuid));
                        if (uuids_temp != NULL)
                                goto retry_get_uuids;
                        else
                                ret = -ENOMEM;
                }

                llapi_error(LLAPI_MSG_ERROR, ret, "get ost uuid failed");
                return ret;
        }

        param->obdindexes = malloc(param->num_obds * sizeof(param->obdindex));
        if (param->obdindexes == NULL)
                return -ENOMEM;

        for (obdnum = 0; obdnum < param->num_obds; obdnum++) {
                for (i = 0; i < obdcount; i++) {
                        if (llapi_uuid_match(uuids[i].uuid,
                                             param->obduuid[obdnum].uuid)) {
                                param->obdindexes[obdnum] = i;
                                obd_valid++;
                                break;
                        }
                }
                if (i >= obdcount) {
                        param->obdindexes[obdnum] = OBD_NOT_FOUND;
                        llapi_err_noerrno(LLAPI_MSG_ERROR,
                                          "error: %s: unknown obduuid: %s",
                                          __FUNCTION__,
                                          param->obduuid[obdnum].uuid);
                        ret = -EINVAL;
                }
        }

        if (obd_valid == 0)
                param->obdindex = OBD_NOT_FOUND;
        else
                param->obdindex = obd_valid;

        param->got_uuids = 1;

        return ret;
}


int llapi_ostlist(char *path, struct find_param *param)
{
        DIR *dir;
        int ret;

        dir = opendir(path);
        if (dir == NULL)
                return -errno;

        ret = setup_obd_uuid(dir, path, param);
        closedir(dir);

        return ret;
}

/*
 * Given a filesystem name, or a pathname of a file on a lustre filesystem,
 * tries to determine the path to the filesystem's clilov directory under /proc
 *
 * fsname is limited to MTI_NAME_MAXLEN in lustre_idl.h
 * The NUL terminator is compensated by the additional "%s" bytes. */
#define LOV_LEN (sizeof("/proc/fs/lustre/lov/%s-clilov-*") + MTI_NAME_MAXLEN)
static int clilovpath(const char *fsname, const char *const pathname,
                      char *clilovpath)
{
        int rc;
        char pattern[LOV_LEN];
        char buffer[PATH_MAX + 1];

        if (fsname == NULL) {
                if ((rc = llapi_search_fsname(pathname, buffer)) != 0)
                        return rc;
                fsname = buffer;
        }

        snprintf(pattern, sizeof(pattern), "/proc/fs/lustre/lov/%s-clilov-*",
                 fsname);

        if ((rc = first_match(pattern, buffer)) != 0)
                return rc;

        strncpy(clilovpath, buffer, sizeof(buffer));

        return 0;
}

/*
 * Given the path to a stripe attribute proc file, tries to open and
 * read the attribute and return the value using the attr parameter
 */
static int sattr_read_attr(const char *const fpath,
                           unsigned int *attr)
{

        FILE *f;
        char line[PATH_MAX + 1];
        int rc = 0;

        if ((f = fopen(fpath, "r")) == NULL) {
                llapi_err(LLAPI_MSG_ERROR, "Cannot open '%s'", fpath);
                return errno;
        }

        if (fgets(line, sizeof(line), f) != NULL) {
                *attr = atoi(line);
        } else {
                llapi_err(LLAPI_MSG_ERROR, "Cannot read from '%s'", fpath);
                rc = 1;
        }

        fclose(f);
        return rc;
}

/*
 * Tries to determine the default stripe attributes for a given filesystem. The
 * filesystem to check should be specified by fsname, or will be determined
 * using pathname.
 */
static int sattr_get_defaults(const char *const fsname,
                              const char *const pathname,
                              unsigned int *scount,
                              unsigned int *ssize,
                              unsigned int *soffset)
{
        int rc;
        char dpath[PATH_MAX + 1];
        char fpath[PATH_MAX + 1];

        if ((rc = clilovpath(fsname, pathname, dpath)) != 0)
                return rc;

        if (scount) {
                snprintf(fpath, PATH_MAX, "%s/stripecount", dpath);
                if ((rc = sattr_read_attr(fpath, scount)) != 0)
                        return rc;
        }

        if (ssize) {
                snprintf(fpath, PATH_MAX, "%s/stripesize", dpath);
                if ((rc = sattr_read_attr(fpath, ssize)) != 0)
                        return rc;
        }

        if (soffset) {
                snprintf(fpath, PATH_MAX, "%s/stripeoffset", dpath);
                if ((rc = sattr_read_attr(fpath, soffset)) != 0)
                        return rc;
        }

        return 0;
}

/*
 * Tries to gather the default stripe attributes for a given filesystem. If
 * the attributes can be determined, they are cached for easy retreival the
 * next time they are needed. Only a single filesystem's attributes are
 * cached at a time.
 */
static int sattr_cache_get_defaults(const char *const fsname,
                                    const char *const pathname,
                                    unsigned int *scount,
                                    unsigned int *ssize,
                                    unsigned int *soffset)
{
        static struct {
                char fsname[PATH_MAX + 1];
                unsigned int stripecount;
                unsigned int stripesize;
                unsigned int stripeoffset;
        } cache = {
                .fsname = {'\0'}
        };

        int rc;
        char fsname_buf[PATH_MAX + 1];
        unsigned int tmp[3];

        if (fsname == NULL)
                llapi_search_fsname(pathname, fsname_buf);
        else
                strncpy(fsname_buf, fsname, PATH_MAX);

        if (strncmp(fsname_buf, cache.fsname, PATH_MAX) != 0) {
                /*
                 * Ensure all 3 sattrs (count, size, and offset) are
                 * successfully retrieved and stored in tmp before writing to
                 * cache.
                 */
                if ((rc = sattr_get_defaults(fsname_buf, NULL, &tmp[0],
                                             &tmp[1], &tmp[2])) != 0)
                        return rc;

                cache.stripecount = tmp[0];
                cache.stripesize = tmp[1];
                cache.stripeoffset = tmp[2];
                strncpy(cache.fsname, fsname_buf, PATH_MAX);
        }

        if (scount)
                *scount = cache.stripecount;
        if (ssize)
                *ssize = cache.stripesize;
        if (soffset)
                *soffset = cache.stripeoffset;

        return 0;
}

static void lov_dump_user_lmm_header(struct lov_user_md *lum, char *path,
                                     int is_dir, int verbose, int depth,
                                     int raw, char *pool_name)
{
        char *prefix = is_dir ? "" : "lmm_";
        char *nl = is_dir ? "" : "\n";
        char *sp = "";

        if (is_dir && lum->lmm_object_gr == LOV_OBJECT_GROUP_DEFAULT) {
                lum->lmm_object_gr = LOV_OBJECT_GROUP_CLEAR;
                if (verbose & VERBOSE_DETAIL)
                        llapi_printf(LLAPI_MSG_NORMAL, "(Default) ");
        }

        if (depth && path && ((verbose != VERBOSE_OBJID) || !is_dir))
                llapi_printf(LLAPI_MSG_NORMAL, "%s\n", path);

        if ((verbose & VERBOSE_DETAIL) && !is_dir) {
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_magic:          0x%08X\n",
                             lum->lmm_magic);
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_object_gr:      "LPX64"\n",
                             lum->lmm_object_gr);
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_object_id:      "LPX64"\n",
                             lum->lmm_object_id);
        }

        if (verbose & VERBOSE_COUNT) {
                if (verbose & ~VERBOSE_COUNT) {
                        llapi_printf(LLAPI_MSG_NORMAL, "%sstripe_count:   ",
                                     prefix);
                        sp = is_dir ? " " : "";
                }
                if (is_dir) {
                        if (!raw && lum->lmm_stripe_count == 0) {
                                unsigned int scount;
                                if (sattr_cache_get_defaults(NULL, path,
                                                             &scount, NULL,
                                                             NULL) == 0)
                                        llapi_printf(LLAPI_MSG_NORMAL, "%u%s",
                                                     scount, nl);
                                else
                                        llapi_err(LLAPI_MSG_ERROR,
                                                "Cannot determine default"
                                                " stripe count.");
                        } else {
                                llapi_printf(LLAPI_MSG_NORMAL, "%d%s",
                                             lum->lmm_stripe_count ==
                                             (typeof(lum->lmm_stripe_count))(-1)
                                             ? -1 : lum->lmm_stripe_count, nl);
                        }
                } else {
                        llapi_printf(LLAPI_MSG_NORMAL, "%d%s",
                                     lum->lmm_stripe_count, nl);
                }
        }

        if (verbose & VERBOSE_SIZE) {
                if (verbose & ~VERBOSE_SIZE) {
                        llapi_printf(LLAPI_MSG_NORMAL, "%s%sstripe_size:    ",
                                     sp, prefix);
                        sp = is_dir ? " " : "";
                }
                if (is_dir && !raw && lum->lmm_stripe_size == 0) {
                        unsigned int ssize;
                        if (sattr_cache_get_defaults(NULL, path, NULL, &ssize,
                                                     NULL) == 0)
                                llapi_printf(LLAPI_MSG_NORMAL, "%u%s", ssize,
                                             nl);
                        else
                                llapi_err(LLAPI_MSG_ERROR,
                                          "Cannot determine default"
                                          " stripe size.");
                } else {
                        llapi_printf(LLAPI_MSG_NORMAL, "%u%s",
                                     lum->lmm_stripe_size, nl);
                }
        }

        if ((verbose & VERBOSE_DETAIL) && !is_dir) {
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_stripe_pattern: %x%s",
                             lum->lmm_pattern, nl);
        }

        if (verbose & VERBOSE_OFFSET) {
                if (verbose & ~VERBOSE_OFFSET) {
                        llapi_printf(LLAPI_MSG_NORMAL, "%s%sstripe_offset:  ",
                                     sp, prefix);
                        sp = is_dir ? " " : "";
                }
                if (is_dir)
                        llapi_printf(LLAPI_MSG_NORMAL, "%d%s",
                                     lum->lmm_stripe_offset ==
                                     (typeof(lum->lmm_stripe_offset))(-1) ? -1 :
                                     lum->lmm_stripe_offset, nl);
                else
                        llapi_printf(LLAPI_MSG_NORMAL, "%u%s",
                                     lum->lmm_objects[0].l_ost_idx, nl);
        }

        if ((verbose & VERBOSE_POOL) && (pool_name != NULL)) {
                llapi_printf(LLAPI_MSG_NORMAL, "%spool: %s", sp, pool_name);
                is_dir = 1;
        }

        if (is_dir && (verbose != VERBOSE_OBJID))
                llapi_printf(LLAPI_MSG_NORMAL, "\n");
}

static void lov_dump_user_lmm_join(struct lov_user_md_v1 *lum, int is_dir,
                                   int obdstripe, int obdindex, int header)
{
        struct lov_user_md_join *lumj = (struct lov_user_md_join *)lum;
        int i;

        if (header && (obdstripe == 1))
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_extent_count:   %x\n",
                             lumj->lmm_extent_count);

        if (!is_dir && (header & VERBOSE_OBJID)) {
                unsigned long long start = -1, end = 0;

                if (obdstripe == 1)
                        llapi_printf(LLAPI_MSG_NORMAL,
                                     "joined\tobdidx\t\t objid\t\tobjid\t\t "
                                     "group\t\tstart\t\tend\n");
                for (i = 0; i < lumj->lmm_stripe_count; i++) {
                        int idx = lumj->lmm_objects[i].l_ost_idx;
                        long long oid = lumj->lmm_objects[i].l_object_id;
                        long long gr = lumj->lmm_objects[i].l_object_gr;
                        if (obdindex == OBD_NOT_FOUND || obdindex == idx)
                                llapi_printf(LLAPI_MSG_NORMAL,
                                             "\t%6u\t%14llu\t%#13llx\t%14llu%s",
                                             idx, oid, oid, gr,
                                             obdindex == idx ? " *" : "");
                        if (start != lumj->lmm_objects[i].l_extent_start ||
                            end != lumj->lmm_objects[i].l_extent_end) {
                                start = lumj->lmm_objects[i].l_extent_start;
                                llapi_printf(LLAPI_MSG_NORMAL,"\t%14llu",start);
                                end = lumj->lmm_objects[i].l_extent_end;
                                if (end == (unsigned long long)-1)
                                        llapi_printf(LLAPI_MSG_NORMAL,
                                                     "\t\tEOF\n");
                                else
                                        llapi_printf(LLAPI_MSG_NORMAL,
                                                     "\t\t%llu\n", end);
                        } else {
                                llapi_printf(LLAPI_MSG_NORMAL, "\t\t\t\t\n");
                        }
                }
                llapi_printf(LLAPI_MSG_NORMAL, "\n");
        }
}

static void lov_dump_user_lmm_v1v3(struct lov_user_md *lum,
                                   struct lov_user_ost_data_v1 *objects,
                                   int is_dir, int obdstripe,
                                   int obdindex, int header)
{
        int i;

        if (!is_dir && (header & VERBOSE_OBJID)) {
                if (obdstripe == 1)
                        llapi_printf(LLAPI_MSG_NORMAL,
                                     "\tobdidx\t\t objid\t\tobjid\t\t group\n");

                for (i = 0; i < lum->lmm_stripe_count; i++) {
                        int idx = objects[i].l_ost_idx;
                        long long oid = objects[i].l_object_id;
                        long long gr = objects[i].l_object_gr;
                        if ((obdindex == OBD_NOT_FOUND) || (obdindex == idx))
                                llapi_printf(LLAPI_MSG_NORMAL,
                                           "\t%6u\t%14llu\t%#13llx\t%14llu%s\n",
                                           idx, oid, oid, gr,
                                           obdindex == idx ? " *" : "");
                }
                llapi_printf(LLAPI_MSG_NORMAL, "\n");
        }
}

void llapi_lov_dump_user_lmm(struct find_param *param,
                             char *path, int is_dir)
{
        int i, obdstripe = (param->obdindex != OBD_NOT_FOUND) ? 0 : 1;
        struct lov_user_md *lum = &param->lmd->lmd_lmm;

        if (!obdstripe) {
                for (i = 0; !is_dir && i < lum->lmm_stripe_count; i++) {
                        if (param->obdindex == lum->lmm_objects[i].l_ost_idx) {
                                obdstripe = 1;
                                break;
                        }
                }
        }

        switch(*(__u32 *)&param->lmd->lmd_lmm) { /* lum->lmm_magic */
        case LOV_USER_MAGIC_V1:
                if (param->verbose && (obdstripe == 1))
                        lov_dump_user_lmm_header(lum, path, is_dir,
                                                 param->verbose,
                                                 param->maxdepth,
                                                 param->raw, NULL);
                lov_dump_user_lmm_v1v3(&param->lmd->lmd_lmm,
                                       param->lmd->lmd_lmm.lmm_objects,
                                       is_dir, obdstripe,
                                       param->obdindex,
                                       param->verbose);
                break;
        case LOV_USER_MAGIC_JOIN:
                if (param->verbose && (obdstripe == 1))
                        lov_dump_user_lmm_header(lum, path, is_dir,
                                                 param->verbose,
                                                 param->maxdepth,
                                                 param->raw, NULL);
                lov_dump_user_lmm_join(&param->lmd->lmd_lmm, is_dir,
                                       obdstripe, param->obdindex,
                                       param->verbose);
                break;
        case LOV_USER_MAGIC_V3: {
                char pool_name[LOV_MAXPOOLNAME + 1];
                struct lov_user_ost_data_v1 *objects;
                struct lov_user_md_v3 *lmmv3 = (void *)&param->lmd->lmd_lmm;

                strncpy(pool_name, lmmv3->lmm_pool_name, LOV_MAXPOOLNAME);
                pool_name[LOV_MAXPOOLNAME] = '\0';
                objects = lmmv3->lmm_objects;
                if (param->verbose && (obdstripe == 1))
                        lov_dump_user_lmm_header(lum, path, is_dir,
                                                 param->verbose,
                                                 param->maxdepth,
                                                 param->raw, pool_name);
                lov_dump_user_lmm_v1v3(&param->lmd->lmd_lmm, objects, is_dir,
                                       obdstripe, param->obdindex,
                                       param->verbose);
                break;
        }
        default:
                llapi_printf(LLAPI_MSG_NORMAL, "unknown lmm_magic:  %#x "
                             "(expecting one of %#x %#x %#x)\n",
                             param->lmd->lmd_lmm.lmm_magic,
                             LOV_USER_MAGIC_V1, LOV_USER_MAGIC_JOIN,
                             LOV_USER_MAGIC_V3);
                return;
        }
}

int llapi_file_get_stripe(const char *path, struct lov_user_md *lum)
{
        const char *fname;
        char *dname;
        int fd, rc = 0;

        fname = strrchr(path, '/');

        /* It should be a file (or other non-directory) */
        if (fname == NULL) {
                dname = (char *)malloc(2);
                if (dname == NULL)
                        return ENOMEM;
                strcpy(dname, ".");
                fname = (char *)path;
        } else {
                dname = (char *)malloc(fname - path + 1);
                if (dname == NULL)
                        return ENOMEM;
                strncpy(dname, path, fname - path);
                dname[fname - path] = '\0';
                fname++;
        }

        if ((fd = open(dname, O_RDONLY)) == -1) {
                rc = -errno;
                free(dname);
                return rc;
        }

        strcpy((char *)lum, fname);
        if (ioctl(fd, IOC_MDC_GETFILESTRIPE, (void *)lum) == -1)
                rc = -errno;

        if (close(fd) == -1 && rc == 0)
                rc = -errno;

        free(dname);
        return rc;
}

int llapi_file_lookup(int dirfd, const char *name)
{
        struct obd_ioctl_data data = { 0 };
        char rawbuf[8192];
        char *buf = rawbuf;
        int rc;

        if (dirfd < 0 || name == NULL)
                return -EINVAL;

        data.ioc_version = OBD_IOCTL_VERSION;
        data.ioc_len = sizeof(data);
        data.ioc_inlbuf1 = (char *)name;
        data.ioc_inllen1 = strlen(name) + 1;

        rc = obd_ioctl_pack(&data, &buf, sizeof(rawbuf));
        if (rc) {
                llapi_error(LLAPI_MSG_ERROR, rc,
                            "error: IOC_MDC_LOOKUP pack failed for '%s': rc %d",
                            name, rc);
                return rc;
        }

        rc = ioctl(dirfd, IOC_MDC_LOOKUP, buf);
        if (rc < 0)
                rc = -errno;
        return rc;
}

/* Check if the value matches 1 of the given criteria (e.g. --atime +/-N).
 * @mds indicates if this is MDS timestamps and there are attributes on OSTs.
 *
 * The result is -1 if it does not match, 0 if not yet clear, 1 if matches.
 * The table below gives the answers for the specified parameters (value and
 * sign), 1st column is the answer for the MDS value, the 2nd is for the OST:
 * --------------------------------------
 * 1 | file > limit; sign > 0 | -1 / -1 |
 * 2 | file = limit; sign > 0 |  ? /  1 |
 * 3 | file < limit; sign > 0 |  ? /  1 |
 * 4 | file > limit; sign = 0 | -1 / -1 |
 * 5 | file = limit; sign = 0 |  ? /  1 |  <- (see the Note below)
 * 6 | file < limit; sign = 0 |  ? / -1 |
 * 7 | file > limit; sign < 0 |  1 /  1 |
 * 8 | file = limit; sign < 0 |  ? / -1 |
 * 9 | file < limit; sign < 0 |  ? / -1 |
 * --------------------------------------
 * Note: 5th actually means that the value is within the interval
 * (limit - margin, limit]. */
static int find_value_cmp(unsigned long long file, unsigned long long limit,
                          int sign, int negopt, unsigned long long margin,
                          int mds)
{
        int ret = -1;

        if (sign > 0) {
                if (file <= limit)
                        ret = mds ? 0 : 1;
        } else if (sign == 0) {
                if (file <= limit && file + margin >= limit)
                        ret = mds ? 0 : 1;
                else if (file + margin <= limit)
                        ret = mds ? 0 : -1;
        } else if (sign < 0) {
                if (file >= limit)
                        ret = 1;
                else if (mds)
                        ret = 0;
        }

        return negopt ? ~ret + 1 : ret;
}

/* Check if the file time matches all the given criteria (e.g. --atime +/-N).
 * Return -1 or 1 if file timestamp does not or does match the given criteria
 * correspondingly. Return 0 if the MDS time is being checked and there are
 * attributes on OSTs and it is not yet clear if the timespamp matches.
 *
 * If 0 is returned, we need to do another RPC to the OSTs to obtain the
 * updated timestamps. */
static int find_time_check(lstat_t *st, struct find_param *param, int mds)
{
        int ret;
        int rc = 0;

        /* Check if file is accepted. */
        if (param->atime) {
                ret = find_value_cmp(st->st_atime, param->atime,
                                     param->asign, param->exclude_atime,
                                     24 * 60 * 60, mds);
                if (ret < 0)
                        return ret;
                rc = ret;
        }

        if (param->mtime) {
                ret = find_value_cmp(st->st_mtime, param->mtime,
                                     param->msign, param->exclude_mtime,
                                     24 * 60 * 60, mds);
                if (ret < 0)
                        return ret;

                /* If the previous check matches, but this one is not yet clear,
                 * we should return 0 to do an RPC on OSTs. */
                if (rc == 1)
                        rc = ret;
        }

        if (param->ctime) {
                ret = find_value_cmp(st->st_ctime, param->ctime,
                                     param->csign, param->exclude_ctime,
                                     24 * 60 * 60, mds);
                if (ret < 0)
                        return ret;

                /* If the previous check matches, but this one is not yet clear,
                 * we should return 0 to do an RPC on OSTs. */
                if (rc == 1)
                        rc = ret;
        }

        return rc;
}

static int cb_find_init(char *path, DIR *parent, DIR *dir,
                        void *data, struct dirent64 *de)
{
        struct find_param *param = (struct find_param *)data;
        struct lov_user_md_v3 *lmmv3 = (void *)&param->lmd->lmd_lmm;
        int decision = 1; /* 1 is accepted; -1 is rejected. */
        lstat_t *st = &param->lmd->lmd_st;
        int lustre_fs = 1;
        int checked_type = 0;
        int ret = 0;

        LASSERT(parent != NULL || dir != NULL);

        param->lmd->lmd_lmm.lmm_stripe_count = 0;

        /* If a regular expression is presented, make the initial decision */
        if (param->pattern != NULL) {
                char *fname = strrchr(path, '/');
                fname = (fname == NULL ? path : fname + 1);
                ret = fnmatch(param->pattern, fname, 0);
                if ((ret == FNM_NOMATCH && !param->exclude_pattern) ||
                    (ret == 0 && param->exclude_pattern))
                        goto decided;
        }

        /* See if we can check the file type from the dirent. */
        if (param->type && de != NULL && de->d_type != DT_UNKNOWN &&
            de->d_type <= DT_MAX) {
                checked_type = 1;
                if (llapi_dir_filetype_table[de->d_type] == param->type) {
                        if (param->exclude_type)
                                goto decided;
                } else {
                        if (!param->exclude_type)
                                goto decided;
                }
        }


        /* If a time or OST should be checked, the decision is not taken yet. */
        if (param->atime || param->ctime || param->mtime || param->obduuid ||
            param->size_check)
                decision = 0;

        ret = 0;
        /* Request MDS for the stat info. */
        if (param->have_fileinfo == 0) {
                if (dir) {
                        /* retrieve needed file info */
                        ret = ioctl(dirfd(dir), LL_IOC_MDC_GETINFO,
                                    (void *)param->lmd);
                } else {
                        char *fname = strrchr(path, '/');
                        fname = (fname == NULL ? path : fname + 1);

                        /* retrieve needed file info */
                        strncpy((char *)param->lmd, fname, param->lumlen);
                        ret = ioctl(dirfd(parent), IOC_MDC_GETFILEINFO,
                                   (void *)param->lmd);
                }
        }

        if (ret) {
                if (errno == ENOTTY) {
                        /* ioctl is not supported, it is not a lustre fs.
                         * Do the regular lstat(2) instead. */
                        lustre_fs = 0;
                        ret = lstat_f(path, st);
                        if (ret) {
                                ret = -errno;
                                llapi_error(LLAPI_MSG_ERROR, ret,
                                            "error: %s: lstat failed for %s",
                                            __func__, path);
                                return ret;
                        }
                } else if (errno == ENOENT) {
                        llapi_error(LLAPI_MSG_WARN, -ENOENT,
                                  "warning: %s: %s does not exist",
                                  __func__, path);
                        goto decided;
                } else {
                        ret = -errno;
                        llapi_error(LLAPI_MSG_ERROR, ret,
                                    "error: %s: %s failed for %s",
                                    __func__, dir ? "LL_IOC_MDC_GETINFO" :
                                  "IOC_MDC_GETFILEINFO", path);
                        return ret;
                }
        }

        if (param->check_uid) {
                if (st->st_uid == param->uid) {
                        if (param->exclude_uid)
                                goto decided;
                } else {
                        if (!param->exclude_uid)
                                goto decided;
                }
        }

        if (param->check_gid) {
                if (st->st_gid == param->gid) {
                        if (param->exclude_gid)
                                goto decided;
                } else {
                        if (!param->exclude_gid)
                                goto decided;
                }
        }

        if (param->check_pool) {
                /* empty requested pool is taken as no pool search => V1 */
                if ((param->lmd->lmd_lmm.lmm_magic == LOV_USER_MAGIC_V1 &&
                     param->poolname[0] == '\0') ||
                    (param->lmd->lmd_lmm.lmm_magic == LOV_USER_MAGIC_V3 &&
                     (strncmp(lmmv3->lmm_pool_name, param->poolname,
                              LOV_MAXPOOLNAME) == 0 ||
                      strcmp(param->poolname, "*") == 0))) {
                        if (param->exclude_pool)
                                goto decided;
                } else {
                        if (!param->exclude_pool)
                                goto decided;
                }
        }

        /* Check the time on mds. */
        if (!decision) {
                int for_mds;

                for_mds = lustre_fs ? (S_ISREG(st->st_mode) &&
                                       param->lmd->lmd_lmm.lmm_stripe_count)
                                    : 0;
                decision = find_time_check(st, param, for_mds);
                if (decision == -1)
                        goto decided;
        }

        if (param->type && !checked_type) {
                if ((st->st_mode & S_IFMT) == param->type) {
                        if (param->exclude_type)
                                goto decided;
                } else {
                        if (!param->exclude_type)
                                goto decided;
                }
        }

        /* Prepare odb. */
        if (param->obduuid) {
                if (lustre_fs && param->got_uuids &&
                    param->st_dev != st->st_dev) {
                        /* A lustre/lustre mount point is crossed. */
                        param->got_uuids = 0;
                        param->obds_printed = 0;
                        param->obdindex = OBD_NOT_FOUND;
                }

                if (lustre_fs && !param->got_uuids) {
                        ret = setup_obd_indexes(dir ? dir : parent, param);
                        if (ret)
                                return ret;

                        param->st_dev = st->st_dev;
                } else if (!lustre_fs && param->got_uuids) {
                        /* A lustre/non-lustre mount point is crossed. */
                        param->got_uuids = 0;
                        param->obdindex = OBD_NOT_FOUND;
                }
        }

        /* If an OBD UUID is specified but no one matches, skip this file. */
        if (param->obduuid && param->obdindex == OBD_NOT_FOUND)
                goto decided;

        /* If a OST UUID is given, and some OST matches, check it here. */
        if (param->obdindex != OBD_NOT_FOUND) {
                if (!S_ISREG(st->st_mode))
                        goto decided;

                /* Only those files should be accepted, which have a
                 * stripe on the specified OST. */
                if (!param->lmd->lmd_lmm.lmm_stripe_count) {
                        goto decided;
                } else {
                        int i, j;
                        struct lov_user_ost_data_v1 *lmm_objects;

                        if (param->lmd->lmd_lmm.lmm_magic == LOV_USER_MAGIC_V3)
                                lmm_objects = lmmv3->lmm_objects;
                        else
                                lmm_objects = param->lmd->lmd_lmm.lmm_objects;

                        for (i = 0;
                             i < param->lmd->lmd_lmm.lmm_stripe_count; i++) {
                                for (j = 0; j < param->num_obds; j++) {
                                        if (param->obdindexes[j] ==
                                            lmm_objects[i].l_ost_idx) {
                                                if (param->exclude_obd)
                                                        goto decided;
                                                goto obd_matches;
                                        }
                                }
                        }

                        if (i == param->lmd->lmd_lmm.lmm_stripe_count) {
                                if (param->exclude_obd)
                                        goto obd_matches;
                                goto decided;
                        }
                }
        }

obd_matches:

        /* If file still fits the request, ask osd for updated info.
           The regulat stat is almost of the same speed as some new
           'glimpse-size-ioctl'. */
        if (!decision && S_ISREG(st->st_mode) &&
            param->lmd->lmd_lmm.lmm_stripe_count &&
            (param->size_check ||param->atime ||param->mtime ||param->ctime)) {
                if (dir) {
                        ret = ioctl(dirfd(dir), IOC_LOV_GETINFO,
                                    (void *)param->lmd);
                } else if (parent) {
                        ret = ioctl(dirfd(parent), IOC_LOV_GETINFO,
                                    (void *)param->lmd);
                }

                if (ret) {
                        if (errno == ENOENT) {
                                llapi_error(LLAPI_MSG_ERROR, -ENOENT,
                                            "warning: %s: %s does not exist",
                                            __func__, path);
                                goto decided;
                        } else {
                                ret = -errno;
                                llapi_error(LLAPI_MSG_ERROR, ret,
                                            "%s: IOC_LOV_GETINFO on %s failed",
                                            __func__, path);
                                return ret;
                        }
                }

                /* Check the time on osc. */
                decision = find_time_check(st, param, 0);
                if (decision == -1)
                        goto decided;
        }

        if (param->size_check) {
                decision = find_value_cmp(st->st_size, param->size,
                                          param->size_sign, param->exclude_size,
                                          param->size_units, 0);
        }

        if (decision != -1) {
                llapi_printf(LLAPI_MSG_NORMAL, "%s", path);
                if (param->zeroend)
                        llapi_printf(LLAPI_MSG_NORMAL, "%c", '\0');
                else
                        llapi_printf(LLAPI_MSG_NORMAL, "\n");
        }

decided:
        /* Do not get down anymore? */
        if (param->depth == param->maxdepth)
                return 1;

        param->depth++;
        return 0;
}

int llapi_find(char *path, struct find_param *param)
{
        return param_callback(path, cb_find_init, cb_common_fini, param);
}

static int cb_getstripe(char *path, DIR *parent, DIR *d, void *data,
                        struct dirent64 *de)
{
        struct find_param *param = (struct find_param *)data;
        int ret = 0;

        LASSERT(parent != NULL || d != NULL);

        if (param->obduuid) {
                param->quiet = 1;
                ret = setup_obd_uuid(d ? d : parent, path, param);
                if (ret)
                        return ret;
        }

        if (d) {
                ret = ioctl(dirfd(d), LL_IOC_LOV_GETSTRIPE,
                            (void *)&param->lmd->lmd_lmm);
        } else if (parent) {
                char *fname = strrchr(path, '/');
                fname = (fname == NULL ? path : fname + 1);

                strncpy((char *)&param->lmd->lmd_lmm, fname, param->lumlen);
                ret = ioctl(dirfd(parent), IOC_MDC_GETFILESTRIPE,
                            (void *)&param->lmd->lmd_lmm);
        }

        if (ret) {
                if (errno == ENODATA && d != NULL) {
                        /* We need to "fake" the "use the default" values
                         * since the lmm struct is zeroed out at this point.
                         * The magic needs to be set in order to satisfy
                         * a check later on in the code path.
                         * The object_seq needs to be set for the "(Default)"
                         * prefix to be displayed. */
                        struct lov_user_md *lmm = &param->lmd->lmd_lmm;
                        lmm->lmm_magic = LOV_MAGIC_V1;
                        lmm->lmm_object_gr = LOV_OBJECT_GROUP_DEFAULT;
                        lmm->lmm_stripe_count = 0;
                        lmm->lmm_stripe_size = 0;
                        lmm->lmm_stripe_offset = -1;
                        goto dump;

                } else if (errno == ENODATA && parent != NULL) {
                        if (!param->obduuid)
                                llapi_printf(LLAPI_MSG_NORMAL,
                                             "%s has no stripe info\n", path);
                        goto out;
                } else if (errno == ENOENT) {
                        llapi_error(LLAPI_MSG_WARN, -ENOENT,
                                    "warning: %s: %s does not exist",
                                    __func__, path);
                        goto out;
                } else if (errno == ENOTTY) {
                        ret = -errno;
                        llapi_error(LLAPI_MSG_ERROR, ret,
                                    "%s: '%s' not on a Lustre fs?",
                                    __func__, path);
                } else {
                        ret = -errno;
                        llapi_error(LLAPI_MSG_ERROR, ret,
                                    "error: %s: %s failed for %s",
                                     __func__, d ? "LL_IOC_LOV_GETSTRIPE" :
                                    "IOC_MDC_GETFILESTRIPE", path);
                }

                return ret;
        }

dump:
        llapi_lov_dump_user_lmm(param, path, d ? 1 : 0);
out:
        /* Do not get down anymore? */
        if (param->depth == param->maxdepth)
                return 1;

        param->depth++;
        return 0;
}

int llapi_getstripe(char *path, struct find_param *param)
{
        return param_callback(path, cb_getstripe, cb_common_fini, param);
}

int llapi_obd_statfs(char *path, __u32 type, __u32 index,
                     struct obd_statfs *stat_buf,
                     struct obd_uuid *uuid_buf)
{
        int fd;
        char raw[OBD_MAX_IOCTL_BUFFER] = {'\0'};
        char *rawbuf = raw;
        struct obd_ioctl_data data = { 0 };
        int rc = 0;

        data.ioc_inlbuf1 = (char *)&type;
        data.ioc_inllen1 = sizeof(__u32);
        data.ioc_inlbuf2 = (char *)&index;
        data.ioc_inllen2 = sizeof(__u32);
        data.ioc_pbuf1 = (char *)stat_buf;
        data.ioc_plen1 = sizeof(struct obd_statfs);
        data.ioc_pbuf2 = (char *)uuid_buf;
        data.ioc_plen2 = sizeof(struct obd_uuid);

        rc = obd_ioctl_pack(&data, &rawbuf, sizeof(raw));
        if (rc != 0) {
                llapi_error(LLAPI_MSG_ERROR, rc,
                            "llapi_obd_statfs: error packing ioctl data");
                return rc;
        }

        fd = open(path, O_RDONLY);
        if (errno == EISDIR)
                fd = open(path, O_DIRECTORY | O_RDONLY);

        if (fd < 0) {
                rc = errno ? -errno : -EBADF;
                llapi_error(LLAPI_MSG_ERROR, rc, "error: %s: opening '%s'",
                            __func__, path);
                return rc;
        }
        rc = ioctl(fd, IOC_OBD_STATFS, (void *)rawbuf);
        if (rc)
                rc = errno ? -errno : -EINVAL;

        close(fd);
        return rc;
}

#define MAX_STRING_SIZE 128
#define DEVICES_LIST "/proc/fs/lustre/devices"

int llapi_ping(char *obd_type, char *obd_name)
{
        char path[MAX_STRING_SIZE];
        char buf[1];
        int rc, fd;

        snprintf(path, MAX_STRING_SIZE, "/proc/fs/lustre/%s/%s/ping",
                 obd_type, obd_name);

        fd = open(path, O_WRONLY);
        if (fd < 0) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "error opening %s", path);
                return rc;
        }

        rc = write(fd, buf, 1);
        if (rc < 0)
                rc = -errno;
        close(fd);

        if (rc == 1)
                return 0;
        return rc;
}

int llapi_target_iterate(int type_num, char **obd_type,
                         void *args, llapi_cb_t cb)
{
        char buf[MAX_STRING_SIZE];
        FILE *fp = fopen(DEVICES_LIST, "r");
        int i, rc = 0;

        if (fp == NULL) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "error: opening "DEVICES_LIST);
                return rc;
        }

        while (fgets(buf, sizeof(buf), fp) != NULL) {
                char *obd_type_name = NULL;
                char *obd_name = NULL;
                char *obd_uuid = NULL;
                char rawbuf[OBD_MAX_IOCTL_BUFFER];
                char *bufl = rawbuf;
                char *bufp = buf;
                struct obd_ioctl_data datal = { 0, };
                struct obd_statfs osfs_buffer;

                while(bufp[0] == ' ')
                        ++bufp;

                for(i = 0; i < 3; i++) {
                        obd_type_name = strsep(&bufp, " ");
                }
                obd_name = strsep(&bufp, " ");
                obd_uuid = strsep(&bufp, " ");

                memset(&osfs_buffer, 0, sizeof (osfs_buffer));

                memset(bufl, 0, sizeof(rawbuf));
                datal.ioc_pbuf1 = (char *)&osfs_buffer;
                datal.ioc_plen1 = sizeof(osfs_buffer);

                for (i = 0; i < type_num; i++) {
                        if (strcmp(obd_type_name, obd_type[i]) != 0)
                                continue;

                        cb(obd_type_name, obd_name, obd_uuid, args);
                }
        }
        fclose(fp);
        return 0;
}

static void do_target_check(char *obd_type_name, char *obd_name,
                            char *obd_uuid, void *args)
{
        int rc;

        rc = llapi_ping(obd_type_name, obd_name);
        if (rc == ENOTCONN) {
                llapi_printf(LLAPI_MSG_NORMAL, "%s inactive.\n", obd_name);
        } else if (rc) {
                llapi_error(LLAPI_MSG_ERROR, rc, "error: check '%s'", obd_name);
        } else {
                llapi_printf(LLAPI_MSG_NORMAL, "%s active.\n", obd_name);
        }
}

int llapi_target_check(int type_num, char **obd_type, char *dir)
{
        return llapi_target_iterate(type_num, obd_type, NULL, do_target_check);
}

#undef MAX_STRING_SIZE

int llapi_catinfo(char *dir, char *keyword, char *node_name)
{
        char raw[OBD_MAX_IOCTL_BUFFER];
        char out[LLOG_CHUNK_SIZE];
        char *buf = raw;
        struct obd_ioctl_data data = { 0 };
        char key[30];
        DIR *root;
        int rc;

        sprintf(key, "%s", keyword);
        memset(raw, 0, sizeof(raw));
        memset(out, 0, sizeof(out));
        data.ioc_inlbuf1 = key;
        data.ioc_inllen1 = strlen(key) + 1;
        if (node_name) {
                data.ioc_inlbuf2 = node_name;
                data.ioc_inllen2 = strlen(node_name) + 1;
        }
        data.ioc_pbuf1 = out;
        data.ioc_plen1 = sizeof(out);
        rc = obd_ioctl_pack(&data, &buf, sizeof(raw));
        if (rc)
                return rc;

        root = opendir(dir);
        if (root == NULL) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "open %s failed", dir);
                return rc;
        }

        rc = ioctl(dirfd(root), OBD_IOC_LLOG_CATINFO, buf);
        if (rc) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc,
                            "ioctl OBD_IOC_CATINFO failed");
        } else {
                llapi_printf(LLAPI_MSG_NORMAL, "%s", data.ioc_pbuf1);
        }

        closedir(root);
        return rc;
}

/* Is this a lustre fs? */
int llapi_is_lustre_mnttype(const char *type)
{
        return (strcmp(type, "lustre") == 0 || strcmp(type,"lustre_lite") == 0);
}

/* Is this a lustre client fs? */
int llapi_is_lustre_mnt(struct mntent *mnt)
{
        return (llapi_is_lustre_mnttype(mnt->mnt_type) &&
                strstr(mnt->mnt_fsname, ":/") != NULL);
}

int llapi_quotacheck(char *mnt, int check_type)
{
        DIR *root;
        int rc;

        root = opendir(mnt);
        if (!root) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "open %s failed", mnt);
                return rc;
        }

        rc = ioctl(dirfd(root), LL_IOC_QUOTACHECK, check_type);
        if (rc < 0)
                rc = -errno;

        closedir(root);
        return rc;
}

int llapi_poll_quotacheck(char *mnt, struct if_quotacheck *qchk)
{
        DIR *root;
        int poll_intvl = 2;
        int rc;

        root = opendir(mnt);
        if (!root) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "open %s failed", mnt);
                return rc;
        }

        while (1) {
                rc = ioctl(dirfd(root), LL_IOC_POLL_QUOTACHECK, qchk);
                if (!rc)
                        break;
                sleep(poll_intvl);
                if (poll_intvl < 30)
                        poll_intvl *= 2;
        }

        closedir(root);
        return 0;
}

int llapi_quotactl(char *mnt, struct if_quotactl *qctl)
{
        DIR *root;
        int rc;

        root = opendir(mnt);
        if (!root) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "open %s failed", mnt);
                return rc;
        }

        rc = ioctl(dirfd(root), LL_IOC_QUOTACTL, qctl);
        if (rc < 0)
                rc = -errno;

        closedir(root);
        return rc;
}

static int cb_quotachown(char *path, DIR *parent, DIR *d, void *data,
                         struct dirent64 *de)
{
        struct find_param *param = (struct find_param *)data;
        lstat_t *st;
        int rc;

        LASSERT(parent != NULL || d != NULL);

        if (d) {
                rc = ioctl(dirfd(d), LL_IOC_MDC_GETINFO,
                           (void *)param->lmd);
        } else if (parent) {
                char *fname = strrchr(path, '/');
                fname = (fname == NULL ? path : fname + 1);

                strncpy((char *)param->lmd, fname, param->lumlen);
                rc = ioctl(dirfd(parent), IOC_MDC_GETFILEINFO,
                           (void *)param->lmd);
        } else {
                return 0;
        }

        if (rc) {
                if (errno == ENODATA) {
                        if (!param->obduuid && !param->quiet)
                                llapi_error(LLAPI_MSG_ERROR, -ENODATA,
                                            "%s has no stripe info", path);
                        rc = 0;
                } else if (errno == ENOENT) {
                        llapi_error(LLAPI_MSG_ERROR, -ENOENT,
                                    "warning: %s: %s does not exist",
                                    __func__, path);
                        rc = 0;
                } else if (errno != EISDIR) {
                        rc = -errno;
                        llapi_error(LLAPI_MSG_ERROR, rc, "%s ioctl failed for %s.",
                                    d ? "LL_IOC_MDC_GETINFO" :
                                    "IOC_MDC_GETFILEINFO", path);
                }
                return rc;
        }

        st = &param->lmd->lmd_st;

        /* libc chown() will do extra check, and if the real owner is
         * the same as the ones to set, it won't fall into kernel, so
         * invoke syscall directly. */
        rc = syscall(SYS_chown, path, -1, -1);
        if (rc)
                llapi_error(LLAPI_MSG_ERROR, errno,
                            "error: chown %s", path);

        rc = chmod(path, st->st_mode);
        if (rc) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "error: chmod %s (%hu)",
                            path, st->st_mode);
        }

        return rc;
}

int llapi_quotachown(char *path, int flag)
{
        struct find_param param;

        memset(&param, 0, sizeof(param));
        param.recursive = 1;
        param.verbose = 0;
        param.quiet = 1;

        return param_callback(path, cb_quotachown, NULL, &param);
}

int llapi_path2fid(const char *path, lustre_fid *fid)
{
        int fd, rc;

        fd = open(path, O_RDONLY);
        if (fd < 0)
                return -errno;

        rc = ioctl(fd, LL_IOC_PATH2FID, fid);
        if (rc)
                rc = -errno;
        close(fd);
        return rc;
}

int llapi_get_connect_flags(const char *mnt, __u64 *flags)
{
        DIR *root;
        int rc;

        root = opendir(mnt);
        if (!root) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "open %s failed", mnt);
                return rc;
        }

        rc = ioctl(dirfd(root), LL_IOC_GET_CONNECT_FLAGS, flags);
        if (rc < 0) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc,
                            "ioctl on %s for getting connect flags failed", mnt);
        }
        closedir(root);
        return rc;
}

int llapi_get_version(char *buffer, int buffer_size,
                      char **version)
{
        int rc;
        int fd;
        struct obd_ioctl_data *data = (struct obd_ioctl_data *)buffer;

        fd = open(OBD_DEV_PATH, O_RDONLY);
        if (fd == -1)
                return -errno;

        memset(buffer, 0, buffer_size);
        data->ioc_version = OBD_IOCTL_VERSION;
        data->ioc_inllen1 = buffer_size - size_round(sizeof(*data));
        data->ioc_inlbuf1 = buffer + size_round(sizeof(*data));
        data->ioc_len = obd_ioctl_packlen(data);

        rc = ioctl(fd, OBD_GET_VERSION, buffer);
        if (rc == -1) {
                rc = -errno;
                close(fd);
                return rc;
        }
        close(fd);
        *version = data->ioc_bulk;
        return 0;
}
