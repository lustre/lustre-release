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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <fnmatch.h>
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

void llapi_err(int level, char *fmt, ...)
{
        va_list args;
        int tmp_errno = abs(errno);

        if ((level & LLAPI_MSG_MASK) > llapi_msg_level)
                return;

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);

        if (level & LLAPI_MSG_NO_ERRNO)
                fprintf(stderr, "\n");
        else
                fprintf(stderr, ": %s (%d)\n", strerror(tmp_errno), tmp_errno);
}

#define llapi_err_noerrno(level, fmt, a...)                             \
        llapi_err((level) | LLAPI_MSG_NO_ERRNO, fmt, ## a)

void llapi_printf(int level, char *fmt, ...)
{
        va_list args;

        if ((level & LLAPI_MSG_MASK) > llapi_msg_level)
                return;

        va_start(args, fmt);
        vfprintf(stdout, fmt, args);
        va_end(args);
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

int llapi_file_open(const char *name, int flags, int mode,
                    unsigned long stripe_size, int stripe_offset,
                    int stripe_count, int stripe_pattern)
{
        struct lov_user_md lum = { 0 };
        int fd, rc = 0;
        int isdir = 0;
        int page_size;

        fd = open(name, flags | O_LOV_DELAY_CREATE, mode);
        if (fd < 0 && errno == EISDIR) {
                fd = open(name, O_DIRECTORY | O_RDONLY);
                isdir++;
        }

        if (fd < 0) {
                rc = -errno;
                llapi_err(LLAPI_MSG_ERROR, "unable to open '%s'", name);
                return rc;
        }

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
                errno = rc = -EINVAL;
                llapi_err(LLAPI_MSG_ERROR, "error: bad stripe_size %lu, "
                          "must be an even multiple of %d bytes", 
                          stripe_size, page_size);
                goto out;
        }
        if (stripe_offset < -1 || stripe_offset > MAX_OBD_DEVICES) {
                errno = rc = -EINVAL;
                llapi_err(LLAPI_MSG_ERROR, "error: bad stripe offset %d", 
                          stripe_offset);
                goto out;
        }
        if (stripe_count < -1 || stripe_count > LOV_MAX_STRIPE_COUNT) {
                errno = rc = -EINVAL;
                llapi_err(LLAPI_MSG_ERROR, "error: bad stripe count %d", 
                          stripe_count);
                goto out;
        }
        if (stripe_count > 0 && (__u64)stripe_size * stripe_count > 0xffffffff){
                errno = rc = -EINVAL;
                llapi_err(LLAPI_MSG_ERROR, "error: stripe_size %lu * "
                          "stripe_count %u exceeds 4GB", stripe_size, 
                          stripe_count);
                goto out;
        }

        /*  Initialize IOCTL striping pattern structure */
        lum.lmm_magic = LOV_USER_MAGIC;
        lum.lmm_pattern = stripe_pattern;
        lum.lmm_stripe_size = stripe_size;
        lum.lmm_stripe_count = stripe_count;
        lum.lmm_stripe_offset = stripe_offset;

        if (ioctl(fd, LL_IOC_LOV_SETSTRIPE, &lum)) {
                char *errmsg = "stripe already set";
                rc = -errno;
                if (errno != EEXIST && errno != EALREADY)
                        errmsg = strerror(errno);

                llapi_err_noerrno(LLAPI_MSG_ERROR,
                                  "error on ioctl "LPX64" for '%s' (%d): %s",
                                  (__u64)LL_IOC_LOV_SETSTRIPE, name, fd, errmsg);
        }
out:
        if (rc) {
                close(fd);
                fd = rc;
        }

        return fd;
}

int llapi_file_create(const char *name, unsigned long stripe_size,
                      int stripe_offset, int stripe_count, int stripe_pattern)
{
        int fd;

        fd = llapi_file_open(name, O_CREAT | O_WRONLY, 0644, stripe_size,
                             stripe_offset, stripe_count, stripe_pattern);
        if (fd < 0)
                return fd;

        close(fd);
        return 0;
}

typedef int (semantic_func_t)(char *path, DIR *parent, DIR *d,
                              void *data, struct dirent64 *de);

#define MAX_LOV_UUID_COUNT      max(LOV_MAX_STRIPE_COUNT, 1000)
#define OBD_NOT_FOUND           (-1)

static int common_param_init(struct find_param *param)
{
        param->lumlen = lov_mds_md_size(MAX_LOV_UUID_COUNT);
        if ((param->lmd = malloc(sizeof(lstat_t) + param->lumlen)) == NULL) {
                llapi_err(LLAPI_MSG_ERROR, 
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

int llapi_file_fget_lov_uuid(int fd, struct obd_uuid *lov_name)
{
        int rc = ioctl(fd, OBD_IOC_GETNAME, lov_name);
        if (rc) {
                rc = errno;
                llapi_err(LLAPI_MSG_ERROR, "error: can't get lov name.");
        }
        return rc;
}

/* deprecated in favour of llapi_file_fget_lov_uuid() in 1.8 and 2.0 */
int llapi_file_get_lov_fuuid(int fd, struct obd_uuid *lov_name)
{
        return llapi_file_fget_lov_uuid(fd, lov_name);
}

int llapi_file_get_lov_uuid(const char *path, struct obd_uuid *lov_uuid)
{
        int fd, rc;

        fd = open(path, O_RDONLY);
        if (fd < 0) {
                rc = errno;
                llapi_err(LLAPI_MSG_ERROR, "error opening %s\n", path);
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
                rc = errno;
                llapi_err(LLAPI_MSG_ERROR, "error: opening '%s'", buf);
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
        return rc;
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

        /* Get the lov name */
        rc = llapi_file_fget_lov_uuid(dirfd(dir), &lov_uuid);
        if (rc) {
                if (errno != ENOTTY) {
                        rc = errno;
                        llapi_err(LLAPI_MSG_ERROR, 
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
                rc = errno;
                llapi_err(LLAPI_MSG_ERROR, "error: opening '%s'", buf);
                return rc;
        }

        if (!param->obduuid && !param->quiet && !param->obds_printed)
                llapi_printf(LLAPI_MSG_NORMAL, "OBDS:\n");

        while (fgets(buf, sizeof(buf), fp) != NULL) {
                if (sscanf(buf, "%d: %s", &index, uuid) < 2)
                        break;

                if (param->obduuid) {
                        if (strncmp((char *)param->obduuid->uuid, uuid,
                                    sizeof(uuid)) == 0) {
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

        if (!param->quiet && param->obduuid &&
            (param->obdindex == OBD_NOT_FOUND)) {
                llapi_err_noerrno(LLAPI_MSG_ERROR, 
                                  "error: %s: unknown obduuid: %s",
                                  __FUNCTION__, param->obduuid->uuid);
                //rc = EINVAL;
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

                llapi_err(LLAPI_MSG_ERROR, "get ost uuid failed");
                return ret;
        }

        param->obdindexes = malloc(param->num_obds * sizeof(param->obdindex));
        if (param->obdindexes == NULL)
                return -ENOMEM;

        for (obdnum = 0; obdnum < param->num_obds; obdnum++) {
                for (i = 0; i <= obdcount; i++) {
                        if (strcmp((char *)&param->obduuid[obdnum].uuid,
                                   (char *)&uuids[i]) == 0) {
                                param->obdindexes[obdnum] = i;
                                obd_valid++;
                                break;
                        }
                }
                if (i == obdcount)
                        param->obdindexes[obdnum] = OBD_NOT_FOUND;
        }

        if (obd_valid == 0)
                param->obdindex = OBD_NOT_FOUND;
        else
                param->obdindex = obd_valid;

        param->got_uuids = 1;

        return 0;
}

void lov_dump_user_lmm_v1(struct lov_user_md_v1 *lum, char *path, int is_dir,
                          int obdindex, int quiet, int header, int body)
{
        int i, obdstripe = 0;

        if (obdindex != OBD_NOT_FOUND) {
                for (i = 0; !is_dir && i < lum->lmm_stripe_count; i++) {
                        if (obdindex == lum->lmm_objects[i].l_ost_idx) {
                                llapi_printf(LLAPI_MSG_NORMAL, "%s\n", path);
                                obdstripe = 1;
                                break;
                        }
                }
        } else if (!quiet) {
                llapi_printf(LLAPI_MSG_NORMAL, "%s\n", path);
                obdstripe = 1;
        }

        /* if it's a directory */
        if (is_dir) {
                if (obdstripe == 1) {
                        if (lum->lmm_object_gr == LOV_OBJECT_GROUP_DEFAULT) {
                                llapi_printf(LLAPI_MSG_NORMAL, "(Default) ");
                                lum->lmm_object_gr = LOV_OBJECT_GROUP_CLEAR;
                        }
                        llapi_printf(LLAPI_MSG_NORMAL, 
                                     "stripe_count: %d stripe_size: %u "
                                     "stripe_offset: %d\n",
                                     lum->lmm_stripe_count == (__u16)-1 ? -1 :
                                     lum->lmm_stripe_count,
                                     lum->lmm_stripe_size,
                                     lum->lmm_stripe_offset == (__u16)-1 ? -1 :
                                     lum->lmm_stripe_offset);
                }
                return;
        }

        if (header && (obdstripe == 1)) {
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_magic:          0x%08X\n",
                             lum->lmm_magic);
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_object_gr:      "LPX64"\n",
                             lum->lmm_object_gr);
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_object_id:      "LPX64"\n",
                             lum->lmm_object_id);
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_stripe_count:   %u\n",
                             (int)lum->lmm_stripe_count);
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_stripe_size:    %u\n",
                             lum->lmm_stripe_size);
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_stripe_pattern: %x\n",
                             lum->lmm_pattern);
        }

        if (body) {
                if ((!quiet) && (obdstripe == 1))
                        llapi_printf(LLAPI_MSG_NORMAL, 
                                     "\tobdidx\t\t objid\t\tobjid\t\t group\n");

                for (i = 0; i < lum->lmm_stripe_count; i++) {
                        int idx = lum->lmm_objects[i].l_ost_idx;
                        long long oid = lum->lmm_objects[i].l_object_id;
                        long long gr = lum->lmm_objects[i].l_object_gr;
                        if ((obdindex == OBD_NOT_FOUND) || (obdindex == idx))
                                llapi_printf(LLAPI_MSG_NORMAL, 
                                             "\t%6u\t%14llu\t%#13llx\t%14llu%s\n",
                                             idx, oid, oid, gr,
                                             obdindex == idx ? " *" : "");
                }
                llapi_printf(LLAPI_MSG_NORMAL, "\n");
        }
}

void lov_dump_user_lmm_join(struct lov_user_md_v1 *lum, char *path,
                            int is_dir, int obdindex, int quiet,
                            int header, int body)
{
        struct lov_user_md_join *lumj = (struct lov_user_md_join *)lum;
        int i, obdstripe = 0;

        if (obdindex != OBD_NOT_FOUND) {
                for (i = 0; i < lumj->lmm_stripe_count; i++) {
                        if (obdindex == lumj->lmm_objects[i].l_ost_idx) {
                                llapi_printf(LLAPI_MSG_NORMAL, "%s\n", path);
                                obdstripe = 1;
                                break;
                        }
                }
        } else if (!quiet) {
                llapi_printf(LLAPI_MSG_NORMAL, "%s\n", path);
                obdstripe = 1;
        }

        if (header && obdstripe == 1) {
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_magic:          0x%08X\n",  
                             lumj->lmm_magic);
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_object_gr:      "LPX64"\n", 
                             lumj->lmm_object_gr);
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_object_id:      "LPX64"\n", 
                             lumj->lmm_object_id);
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_stripe_count:   %u\n", 
                             (int)lumj->lmm_stripe_count);
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_stripe_size:    %u\n",
                             lumj->lmm_stripe_size);
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_stripe_pattern: %x\n",
                             lumj->lmm_pattern);
                llapi_printf(LLAPI_MSG_NORMAL, "lmm_extent_count:   %x\n",
                             lumj->lmm_extent_count);
        }

        if (body) {
                unsigned long long start = -1, end = 0;
                if (!quiet && obdstripe == 1)
                        llapi_printf(LLAPI_MSG_NORMAL, 
                                     "joined\tobdidx\t\t objid\t\tobjid\t\t group"
                                     "\t\tstart\t\tend\n");
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
                                llapi_printf(LLAPI_MSG_NORMAL, "\t%14llu", start);
                                end = lumj->lmm_objects[i].l_extent_end;
                                if (end == (unsigned long long)-1)
                                        llapi_printf(LLAPI_MSG_NORMAL, "\t\tEOF\n");
                                else
                                        llapi_printf(LLAPI_MSG_NORMAL, "\t\t%llu\n",
                                                  end);
                        } else {
                                llapi_printf(LLAPI_MSG_NORMAL, "\t\t\t\t\n");
                        }
                }
                llapi_printf(LLAPI_MSG_NORMAL, "\n");
        }
}

void llapi_lov_dump_user_lmm(struct find_param *param,
                             char *path, int is_dir)
{
        switch(*(__u32 *)&param->lmd->lmd_lmm) { /* lum->lmm_magic */
        case LOV_USER_MAGIC_V1:
                lov_dump_user_lmm_v1(&param->lmd->lmd_lmm, path, is_dir,
                                      param->obdindex, param->quiet,
                                      param->verbose,
                                      (param->verbose || !param->obduuid));
                break;
        case LOV_USER_MAGIC_JOIN:
                lov_dump_user_lmm_join(&param->lmd->lmd_lmm, path, is_dir,
                                       param->obdindex, param->quiet,
                                       param->verbose,
                                       (param->verbose || !param->obduuid));
                break;
        default:
                llapi_printf(LLAPI_MSG_NORMAL, 
                             "unknown lmm_magic:  %#x (expecting %#x)\n",
                       *(__u32 *)&param->lmd->lmd_lmm, LOV_USER_MAGIC_V1);
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
                rc = errno;
                free(dname);
                return rc;
        }

        strcpy((char *)lum, fname);
        if (ioctl(fd, IOC_MDC_GETFILESTRIPE, (void *)lum) == -1)
                rc = errno;

        if (close(fd) == -1 && rc == 0)
                rc = errno;

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
                llapi_err(LLAPI_MSG_ERROR,
                          "error: IOC_MDC_LOOKUP pack failed for '%s': rc %d",
                          name, rc);
                return rc;
        }

        return ioctl(dirfd, IOC_MDC_LOOKUP, buf);
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
        strncpy((char *)lmd, fname, lov_mds_md_size(MAX_LOV_UUID_COUNT));
        ret = ioctl(dirfd(parent), IOC_MDC_GETFILEINFO, (void *)lmd);

        if (ret) {
                if (errno == ENOTTY) {
                        /* ioctl is not supported, it is not a lustre fs.
                         * Do the regular lstat(2) instead. */
                        ret = lstat_f(path, st);
                        if (ret) {
                                llapi_err(LLAPI_MSG_ERROR, 
                                          "error: %s: lstat failed for %s",
                                          __FUNCTION__, path);
                                return ret;
                        }
                } else if (errno == ENOENT) {
                        llapi_err(LLAPI_MSG_WARN, 
                                  "warning: %s: %s does not exist", 
                                  __FUNCTION__, path);
                        return -ENOENT;
                } else {
                        llapi_err(LLAPI_MSG_ERROR, 
                                  "error: %s: IOC_MDC_GETFILEINFO failed for %s",
                                  __FUNCTION__, path);
                        return ret;
                }
        }

        return 0;
}

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
                llapi_err(LLAPI_MSG_ERROR, "%s: Failed to open '%s'",
                          __FUNCTION__, path);
                return -EINVAL;
        } else if (!d && !parent) {
                /* ENOTDIR. Open the parent dir. */
                p = opendir_parent(path);
                if (!p)
                        GOTO(out, ret = -EINVAL);
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
                        llapi_err(LLAPI_MSG_ERROR,
                                  "error: %s: string buffer is too small",
                                  __FUNCTION__);
                        break;
                }
                strcat(path, "/");
                strcat(path, dent->d_name);

                if (dent->d_type == DT_UNKNOWN) {
                        lstat_t *st = &((struct find_param *)data)->lmd->lmd_st;

                        ret = llapi_mds_getfileinfo(path, d,
                                             ((struct find_param *)data)->lmd);
                        if (ret == 0) {
                                ((struct find_param *)data)->have_fileinfo = 1;
                                dent->d_type = llapi_filetype_dir_table[st->st_mode &
                                                                        S_IFMT];
                        }
                        if (ret == -ENOENT)
                                continue;
                }

                switch (dent->d_type) {
                case DT_UNKNOWN:
                        llapi_err(LLAPI_MSG_ERROR, 
                                  "error: %s: '%s' is UNKNOWN type %d",
                                  __FUNCTION__, dent->d_name, dent->d_type);
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
static int find_value_cmp(unsigned int file, unsigned int limit, int sign,
                          unsigned long long margin, int mds)
{
        if (sign > 0) {
                if (file < limit)
                        return mds ? 0 : 1;
        }

        if (sign == 0) {
                if (file <= limit && file + margin > limit)
                        return mds ? 0 : 1;
                if (file + margin <= limit)
                        return mds ? 0 : -1;
        }

        if (sign < 0) {
                if (file > limit)
                        return 1;
                if (mds)
                        return 0;
        }

        return -1;
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
                                     param->asign, 24 * 60 * 60, mds);
                if (ret < 0)
                        return ret;
                rc = ret;
        }

        if (param->mtime) {
                ret = find_value_cmp(st->st_mtime, param->mtime,
                                     param->msign, 24 * 60 * 60, mds);
                if (ret < 0)
                        return ret;

                /* If the previous check matches, but this one is not yet clear,
                 * we should return 0 to do an RPC on OSTs. */
                if (rc == 1)
                        rc = ret;
        }

        if (param->ctime) {
                ret = find_value_cmp(st->st_ctime, param->ctime,
                                     param->csign, 24 * 60 * 60, mds);
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
                                llapi_err(LLAPI_MSG_ERROR, 
                                          "error: %s: lstat failed for %s",
                                          __FUNCTION__, path);
                                return ret;
                        }
                } else if (errno == ENOENT) {
                        llapi_err(LLAPI_MSG_WARN, 
                                  "warning: %s: %s does not exist",
                                  __FUNCTION__, path);
                        goto decided;
                } else {
                        llapi_err(LLAPI_MSG_ERROR, "error: %s: %s failed for %s",
                                  __FUNCTION__, dir ? "LL_IOC_MDC_GETINFO" :
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
                        for (i = 0;
                             i < param->lmd->lmd_lmm.lmm_stripe_count; i++) {
                                for (j = 0; j < param->num_obds; j++) {
                                        if (param->obdindexes[j] ==
                                            param->lmd->lmd_lmm.lmm_objects[i].l_ost_idx)
                                                goto obd_matches;
                                }
                        }

                        if (i == param->lmd->lmd_lmm.lmm_stripe_count)
                                goto decided;
                }
        }

obd_matches:

        /* If file still fits the request, ask osd for updated info.
           The regulat stat is almost of the same speed as some new
           'glimpse-size-ioctl'. */
        if (!decision && S_ISREG(st->st_mode) &&
            (param->lmd->lmd_lmm.lmm_stripe_count || param->size_check)) {
                if (dir) {
                        ret = ioctl(dirfd(dir), IOC_LOV_GETINFO,
                                    (void *)param->lmd);
                } else if (parent) {
                        ret = ioctl(dirfd(parent), IOC_LOV_GETINFO,
                                    (void *)param->lmd);
                }

                if (ret) {
                        if (errno == ENOENT) {
                                llapi_err(LLAPI_MSG_ERROR, 
                                          "warning: %s: %s does not exist",
                                          __FUNCTION__, path);
                                goto decided;
                        } else {
                                llapi_err(LLAPI_MSG_ERROR, 
                                          "%s: IOC_LOV_GETINFO on %s failed",
                                          __FUNCTION__, path);
                                return ret;
                        }
                }

                /* Check the time on osc. */
                decision = find_time_check(st, param, 0);
                if (decision == -1)
                        goto decided;
        }

        if (param->size_check)
                decision = find_value_cmp(st->st_size, param->size,
                                          param->size_sign, param->size_units,
                                          0);

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

static int cb_common_fini(char *path, DIR *parent, DIR *d, void *data,
                          struct dirent64 *de)
{
        struct find_param *param = (struct find_param *)data;
        param->depth--;
        return 0;
}

int llapi_find(char *path, struct find_param *param)
{
        char *buf;
        int ret, len = strlen(path);

        if (len > PATH_MAX) {
                llapi_err(LLAPI_MSG_ERROR, "%s: Path name '%s' is too long",
                          __FUNCTION__, path);
                return -EINVAL;
        }

        buf = (char *)malloc(PATH_MAX + 1);
        if (!buf)
                return -ENOMEM;

        ret = common_param_init(param);
        if (ret) {
                free(buf);
                return ret;
        }

        param->depth = 0;

        strncpy(buf, path, PATH_MAX + 1);
        ret = llapi_semantic_traverse(buf, PATH_MAX + 1, NULL, cb_find_init,
                                      cb_common_fini, param, NULL);

        find_param_fini(param);
        free(buf);
        return ret < 0 ? ret : 0;
}

static int cb_getstripe(char *path, DIR *parent, DIR *d, void *data,
                        struct dirent64 *de)
{
        struct find_param *param = (struct find_param *)data;
        int ret = 0;

        LASSERT(parent != NULL || d != NULL);

        /* Prepare odb. */
        if (!param->got_uuids) {
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
                if (errno == ENODATA) {
                        if (!param->obduuid && !param->quiet)
                                llapi_printf(LLAPI_MSG_NORMAL, 
                                             "%s has no stripe info\n", path);
                        goto out;
                } else if (errno == ENOTTY) {
                        llapi_err(LLAPI_MSG_ERROR, 
                                  "%s: '%s' not on a Lustre fs?",
                                  __FUNCTION__, path);
                } else if (errno == ENOENT) {
                        llapi_err(LLAPI_MSG_WARN, 
                                  "warning: %s: %s does not exist",
                                  __FUNCTION__, path);
                        goto out;
                } else {
                        llapi_err(LLAPI_MSG_ERROR, 
                                  "error: %s: %s failed for %s",
                                   __FUNCTION__, d ? "LL_IOC_LOV_GETSTRIPE" :
                                  "IOC_MDC_GETFILESTRIPE", path);
                }

                return ret;
        }

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
        char *buf;
        int ret = 0, len = strlen(path);

        if (len > PATH_MAX) {
                llapi_err(LLAPI_MSG_ERROR, 
                          "%s: Path name '%s' is too long",
                          __FUNCTION__, path);
                return -EINVAL;
        }

        buf = (char *)malloc(PATH_MAX + 1);
        if (!buf)
                return -ENOMEM;

        ret = common_param_init(param);
        if (ret) {
                free(buf);
                return ret;
        }

        param->depth = 0;

        strncpy(buf, path, PATH_MAX + 1);
        ret = llapi_semantic_traverse(buf, PATH_MAX + 1, NULL, cb_getstripe,
                                      cb_common_fini, param, NULL);
        find_param_fini(param);
        free(buf);
        return ret < 0 ? ret : 0;
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

        if ((rc = obd_ioctl_pack(&data, &rawbuf, sizeof(raw))) != 0) {
                llapi_err(LLAPI_MSG_ERROR, 
                          "llapi_obd_statfs: error packing ioctl data");
                return rc;
        }

        fd = open(path, O_RDONLY);
        if (errno == EISDIR)
                fd = open(path, O_DIRECTORY | O_RDONLY);

        if (fd < 0) {
                rc = errno ? -errno : -EBADF;
                llapi_err(LLAPI_MSG_ERROR, "error: %s: opening '%s'", 
                          __FUNCTION__, path);
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
                rc = errno;
                llapi_err(LLAPI_MSG_ERROR, "error opening %s", path);
                return rc;
        }

        rc = write(fd, buf, 1);
        close(fd);

        if (rc == 1)
                return 0;
        return rc;
}

int llapi_target_iterate(int type_num, char **obd_type, void *args, llapi_cb_t cb)
{
        char buf[MAX_STRING_SIZE];
        FILE *fp = fopen(DEVICES_LIST, "r");
        int i, rc = 0;

        if (fp == NULL) {
                rc = errno;
                llapi_err(LLAPI_MSG_ERROR, "error: opening "DEVICES_LIST);
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
        return rc;
}

static void do_target_check(char *obd_type_name, char *obd_name,
                            char *obd_uuid, void *args)
{
        int rc;

        rc = llapi_ping(obd_type_name, obd_name);
        if (rc) {
                llapi_err(LLAPI_MSG_ERROR, "error: check '%s'", obd_name);
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
                rc = errno;
                llapi_err(LLAPI_MSG_ERROR, "open %s failed", dir);
                return rc;
        }

        rc = ioctl(dirfd(root), OBD_IOC_LLOG_CATINFO, buf);
        if (rc)
                llapi_err(LLAPI_MSG_ERROR, "ioctl OBD_IOC_CATINFO failed");
        else
                llapi_printf(LLAPI_MSG_NORMAL, "%s", data.ioc_pbuf1);

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
                llapi_err(LLAPI_MSG_ERROR, "open %s failed", mnt);
                return -1;
        }

        rc = ioctl(dirfd(root), LL_IOC_QUOTACHECK, check_type);

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
                llapi_err(LLAPI_MSG_ERROR, "open %s failed", mnt);
                return -1;
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
        return rc;
}

int llapi_quotactl(char *mnt, struct if_quotactl *qctl)
{
        DIR *root;
        int rc;

        root = opendir(mnt);
        if (!root) {
                llapi_err(LLAPI_MSG_ERROR, "open %s failed", mnt);
                return -1;
        }

        rc = ioctl(dirfd(root), LL_IOC_QUOTACTL, qctl);

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
                                llapi_err(LLAPI_MSG_ERROR, 
                                          "%s has no stripe info", path);
                        rc = 0;
                } else if (errno == ENOENT) {
                        llapi_err(LLAPI_MSG_ERROR, 
                                  "warning: %s: %s does not exist",
                                  __FUNCTION__, path);
                        rc = 0;
                } else if (errno != EISDIR) {
                        rc = errno;
                        llapi_err(LLAPI_MSG_ERROR, "%s ioctl failed for %s.",
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
                llapi_err(LLAPI_MSG_ERROR, "error: chown %s", path);

        rc = chmod(path, st->st_mode);
        if (rc)
                llapi_err(LLAPI_MSG_ERROR, "error: chmod %s (%hu)", 
                          path, st->st_mode);

        return rc;
}

int llapi_quotachown(char *path, int flag)
{
        struct find_param param;
        char *buf;
        int ret = 0, len = strlen(path);

        if (len > PATH_MAX) {
                llapi_err(LLAPI_MSG_ERROR, "%s: Path name '%s' is too long",
                          __FUNCTION__, path);
                return -EINVAL;
        }

        buf = (char *)malloc(PATH_MAX + 1);
        if (!buf)
                return -ENOMEM;

        memset(&param, 0, sizeof(param));
        param.recursive = 1;
        param.verbose = 0;
        param.quiet = 1;

        ret = common_param_init(&param);
        if (ret)
                goto out;

        strncpy(buf, path, PATH_MAX + 1);
        ret = llapi_semantic_traverse(buf, PATH_MAX + 1, NULL, cb_quotachown,
                                      NULL, &param, NULL);
out:
        find_param_fini(&param);
        free(buf);
        return ret;
}
