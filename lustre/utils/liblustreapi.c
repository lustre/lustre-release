/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Robert Read <rread@clusterfs.com>
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
 *
 */

/* for O_DIRECTORY */
#define _GNU_SOURCE

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
#include <obd_lov.h>
#include <lustre/liblustreapi.h>

static void err_msg(char *fmt, ...)
{
        va_list args;
        int tmp_errno = abs(errno);

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
        fprintf(stderr, ": %s (%d)\n", strerror(tmp_errno), tmp_errno);
}

int parse_size(char *optarg, unsigned long long *size,
               unsigned long long *size_units)
{
        char *end;

        *size = strtoul(optarg, &end, 0);

        if (*end != '\0') {
                if ((*end == 'b') && *(end+1) == '\0' &&
                    (*size & (~0ULL << (64 - 9))) == 0) {
                        *size <<= 9;
                        *size_units = 1 << 9;
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
                err_msg("unable to open '%s'", name);
                return rc;
        }

        /* 64 KB is the largest common page size I'm aware of (on ia64), but
         * check the local page size just in case. */
        page_size = LOV_MIN_STRIPE_SIZE;
        if (getpagesize() > page_size) {
                page_size = getpagesize();
                fprintf(stderr, "warning: your page size (%u) is larger than "
                        "expected (%u).\n", page_size, LOV_MIN_STRIPE_SIZE);
        }
        if (stripe_size < 0 || (stripe_size & (LOV_MIN_STRIPE_SIZE - 1))) {
                errno = rc = -EINVAL;
                err_msg("error: bad stripe_size %lu, must be an even "
                        "multiple of %d bytes", stripe_size, page_size);
                goto out;
        }
        if (stripe_offset < -1 || stripe_offset > MAX_OBD_DEVICES) {
                errno = rc = -EINVAL;
                err_msg("error: bad stripe offset %d", stripe_offset);
                goto out;
        }
        if (stripe_count < -1 || stripe_count > LOV_MAX_STRIPE_COUNT) {
                errno = rc = -EINVAL;
                err_msg("error: bad stripe count %d", stripe_count);
                goto out;
        }
        if (stripe_count > 0 && (__u64)stripe_size * stripe_count > 0xffffffff){
                errno = rc = -EINVAL;
                err_msg("error: stripe_size %lu * stripe_count %u "
                        "exceeds 4GB", stripe_size, stripe_count);
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

                fprintf(stderr, "error on ioctl "LPX64" for '%s' (%d): %s\n",
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
                err_msg("error: allocation of %d bytes for ioctl",
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

/*
 * If uuidp is NULL, return the number of available obd uuids.
 * If uuidp is non-NULL, then it will return the uuids of the obds. If
 * there are more OSTs then allocated to uuidp, then an error is returned with
 * the ost_count set to number of available obd uuids.
 */
int llapi_lov_get_uuids(int fd, struct obd_uuid *uuidp, int *ost_count)
{
        char lov_name[sizeof(struct obd_uuid)];
        char buf[1024];
        FILE *fp;
        int rc = 0, index = 0;

        /* Get the lov name */
        rc = ioctl(fd, OBD_IOC_GETNAME, (void *) lov_name);
        if (rc) {
                rc = errno;
                err_msg("error: can't get lov name.");
                return rc;
        }

        /* Now get the ost uuids from /proc */
        snprintf(buf, sizeof(buf), "/proc/fs/lustre/lov/%s/target_obd",
                 lov_name);
        fp = fopen(buf, "r");
        if (fp == NULL) {
                rc = errno;
                err_msg("error: opening '%s'", buf);
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
        char uuid[sizeof(struct obd_uuid)];
        char buf[1024];
        FILE *fp;
        int rc = 0, index;

        /* Get the lov name */
        rc = ioctl(dirfd(dir), OBD_IOC_GETNAME, (void *)uuid);
        if (rc) {
                if (errno != ENOTTY) {
                        rc = errno;
                        err_msg("error: can't get lov name: %s", dname);
                } else {
                        rc = 0;
                }
                return rc;
        }

        param->got_uuids = 1;

        /* Now get the ost uuids from /proc */
        snprintf(buf, sizeof(buf), "/proc/fs/lustre/lov/%s/target_obd",
                 uuid);
        fp = fopen(buf, "r");
        if (fp == NULL) {
                rc = errno;
                err_msg("error: opening '%s'", buf);
                return rc;
        }

        if (!param->obduuid && !param->quiet && !param->obds_printed)
                printf("OBDS:\n");

        while (fgets(buf, sizeof(buf), fp) != NULL) {
                if (sscanf(buf, "%d: %s", &index, uuid) < 2)
                        break;

                if (param->obduuid) {
                        if (strncmp(param->obduuid->uuid, uuid,
                                    sizeof(uuid)) == 0) {
                                param->obdindex = index;
                                break;
                        }
                } else if (!param->quiet && !param->obds_printed) {
                        /* Print everything */
                        printf("%s", buf);
                }
        }
        param->obds_printed = 1;

        fclose(fp);

        if (!param->quiet && param->obduuid &&
            (param->obdindex == OBD_NOT_FOUND)) {
                fprintf(stderr, "error: %s: unknown obduuid: %s\n",
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

                fprintf(stderr, "get ost uuid failed: %s\n", strerror(errno));
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
                                printf("%s\n", path);
                                obdstripe = 1;
                                break;
                        }
                }
        } else if (!quiet) {
                printf("%s\n", path);
                obdstripe = 1;
        }

        /* if it's a directory */
        if (is_dir) {
                if (obdstripe == 1) {
                        printf("default stripe_count: %d stripe_size: %u "
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
                printf("lmm_magic:          0x%08X\n",  lum->lmm_magic);
                printf("lmm_object_gr:      "LPX64"\n", lum->lmm_object_gr);
                printf("lmm_object_id:      "LPX64"\n", lum->lmm_object_id);
                printf("lmm_stripe_count:   %u\n", (int)lum->lmm_stripe_count);
                printf("lmm_stripe_size:    %u\n",      lum->lmm_stripe_size);
                printf("lmm_stripe_pattern: %x\n",      lum->lmm_pattern);
        }

        if (body) {
                if ((!quiet) && (obdstripe == 1))
                        printf("\tobdidx\t\t objid\t\tobjid\t\t group\n");

                for (i = 0; i < lum->lmm_stripe_count; i++) {
                        int idx = lum->lmm_objects[i].l_ost_idx;
                        long long oid = lum->lmm_objects[i].l_object_id;
                        long long gr = lum->lmm_objects[i].l_object_gr;
                        if ((obdindex == OBD_NOT_FOUND) || (obdindex == idx))
                                printf("\t%6u\t%14llu\t%#13llx\t%14llu%s\n",
                                       idx, oid, oid, gr,
                                       obdindex == idx ? " *" : "");
                }
                printf("\n");
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
                                printf("%s\n", path);
                                obdstripe = 1;
                                break;
                        }
                }
        } else if (!quiet) {
                printf("%s\n", path);
                obdstripe = 1;
        }

        if (header && obdstripe == 1) {
                printf("lmm_magic:          0x%08X\n",  lumj->lmm_magic);
                printf("lmm_object_gr:      "LPX64"\n", lumj->lmm_object_gr);
                printf("lmm_object_id:      "LPX64"\n", lumj->lmm_object_id);
                printf("lmm_stripe_count:   %u\n", (int)lumj->lmm_stripe_count);
                printf("lmm_stripe_size:    %u\n",      lumj->lmm_stripe_size);
                printf("lmm_stripe_pattern: %x\n",      lumj->lmm_pattern);
                printf("lmm_extent_count:   %x\n",      lumj->lmm_extent_count);
        }

        if (body) {
                unsigned long long start = -1, end = 0;
                if (!quiet && obdstripe == 1)
                        printf("joined\tobdidx\t\t objid\t\tobjid\t\t group"
                               "\t\tstart\t\tend\n");
                for (i = 0; i < lumj->lmm_stripe_count; i++) {
                        int idx = lumj->lmm_objects[i].l_ost_idx;
                        long long oid = lumj->lmm_objects[i].l_object_id;
                        long long gr = lumj->lmm_objects[i].l_object_gr;
                        if (obdindex == OBD_NOT_FOUND || obdindex == idx)
                                printf("\t%6u\t%14llu\t%#13llx\t%14llu%s",
                                       idx, oid, oid, gr,
                                       obdindex == idx ? " *" : "");
                        if (start != lumj->lmm_objects[i].l_extent_start ||
                            end != lumj->lmm_objects[i].l_extent_end) {
                                start = lumj->lmm_objects[i].l_extent_start;
                                printf("\t%14llu", start);
                                end = lumj->lmm_objects[i].l_extent_end;
                                if (end == (unsigned long long)-1)
                                        printf("\t\tEOF\n");
                                else
                                        printf("\t\t%llu\n", end);
                        } else {
                                printf("\t\t\t\t\n");
                        }
                }
                printf("\n");
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
                printf("unknown lmm_magic:  %#x (expecting %#x)\n",
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
                fprintf(stderr,
                        "error: IOC_MDC_LOOKUP pack failed for '%s': rc %d\n",
                        name, rc);
                return rc;
        }

        return ioctl(dirfd, IOC_MDC_LOOKUP, buf);
}

/* some 64bit libcs implement readdir64() by calling sys_getdents().  the
 * kernel's sys_getdents() doesn't return d_type.  */
unsigned char handle_dt_unknown(char *path)
{
        int fd;

        fd = open(path, O_DIRECTORY|O_RDONLY);
        if (fd < 0) {
                if (errno == ENOTDIR)
                        return DT_REG; /* kind of a lie */
                return DT_UNKNOWN;
        }
        close(fd);
        return DT_DIR;
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
                fprintf(stderr, "%s: Failed to open '%s': %s.",
                        __FUNCTION__, path, strerror(errno));
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
                if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
                        continue;

                path[len] = 0;
                if ((len + dent->d_reclen + 2) > size) {
                        fprintf(stderr,
                                "error: %s: string buffer is too small\n",
                                __FUNCTION__);
                        break;
                }
                strcat(path, "/");
                strcat(path, dent->d_name);

                if (dent->d_type == DT_UNKNOWN)
                        dent->d_type = handle_dt_unknown(path);

                switch (dent->d_type) {
                case DT_UNKNOWN:
                        fprintf(stderr, "error: %s: '%s' is UNKNOWN type %d",
                                __FUNCTION__, dent->d_name, dent->d_type);
                        /* If we cared we could stat the file to determine
                         * type and continue on here, but we don't since we
                         * know d_type should be valid for lustre and this
                         * tool only makes sense for lustre filesystems. */
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
 * The table bolow gives the answers for the specified parameters (value and
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

static int cb_find_init(char *path, DIR *parent, DIR *dir,
                        void *data, struct dirent64 *de)
{
        struct find_param *param = (struct find_param *)data;
        int decision = 1; /* 1 is accepted; -1 is rejected. */
        lstat_t *st = &param->lmd->lmd_st;
        int lustre_fs = 1;
        int checked_type = 0;
        int ret;

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
            de->d_type < DT_MAX) {
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
            param->size)
                decision = 0;

        /* Request MDS for the stat info. */
        if (dir) {
                /* retrieve needed file info */
                ret = ioctl(dirfd(dir), LL_IOC_MDC_GETINFO,
                            (void *)param->lmd);
        } else /* if (parent) LASSERT() above makes always true */ {
                char *fname = strrchr(path, '/');
                fname = (fname == NULL ? path : fname + 1);

                /* retrieve needed file info */
                strncpy((char *)param->lmd, fname, param->lumlen);
                ret = ioctl(dirfd(parent), IOC_MDC_GETFILEINFO,
                           (void *)param->lmd);
        }

        if (ret) {
                if (errno == ENOTTY) {
                        /* ioctl is not supported, it is not a lustre fs.
                         * Do the regular lstat(2) instead. */
                        lustre_fs = 0;
                        ret = lstat_f(path, st);
                        if (ret) {
                                err_msg("error: %s: lstat failed for %s",
                                        __FUNCTION__, path);
                                return ret;
                        }
                } else if (errno == ENOENT) {
                        err_msg("warning: %s: %s does not exist",
                                __FUNCTION__, path);
                        goto decided;
                } else {
                        err_msg("error: %s: %s failed for %s", __FUNCTION__,
                                dir ? "LL_IOC_MDC_GETINFO" :
                                "IOC_MDC_GETFILEINFO", path);
                        return ret;
                }
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

        /* Check the time on mds. */
        if (!decision) {
                int for_mds;

                for_mds = lustre_fs ? (S_ISREG(st->st_mode) &&
                                       param->lmd->lmd_lmm.lmm_stripe_count)
                                    : 0;
                decision = find_time_check(st, param, for_mds);
        }

obd_matches:
        /* If file still fits the request, ask osd for updated info.
           The regulat stat is almost of the same speed as some new
           'glimpse-size-ioctl'. */
        if (!decision && S_ISREG(st->st_mode) &&
            (param->lmd->lmd_lmm.lmm_stripe_count || param->size)) {
                if (param->obdindex != OBD_NOT_FOUND) {
                        /* Check whether the obd is active or not, if it is
                         * not active, just print the object affected by this
                         * failed ost 
                         * */
                        struct obd_statfs stat_buf;
                        struct obd_uuid uuid_buf;

                        memset(&stat_buf, 0, sizeof(struct obd_statfs));
                        memset(&uuid_buf, 0, sizeof(struct obd_uuid));
                        ret = llapi_obd_statfs(path, LL_STATFS_LOV,
                                               param->obdindex, &stat_buf, 
                                               &uuid_buf);
                        if (ret) {
                                if (ret == -ENODATA || ret == -ENODEV 
                                    || ret == -EIO)
                                        errno = EIO;
                                printf("obd_uuid: %s failed %s ",
                                        param->obduuid->uuid, strerror(errno));
                                goto print_path;
                        }
                }
                if (dir) {
                        ret = ioctl(dirfd(dir), IOC_LOV_GETINFO,
                                    (void *)param->lmd);
                } else if (parent) {
                        ret = ioctl(dirfd(parent), IOC_LOV_GETINFO,
                                    (void *)param->lmd);
                }

                if (ret) {
                        if (errno == ENOENT) {
                                err_msg("warning: %s: %s does not exist",
                                        __FUNCTION__, path);
                                goto decided;
                        } else {
                                fprintf(stderr, "%s: IOC_LOV_GETINFO on %s failed: "
                                        "%s.\n", __FUNCTION__, path, strerror(errno));
                                return ret;
                        }
                }

                /* Check the time on osc. */
                decision = find_time_check(st, param, 0);
                if (decision == -1)
                        goto decided;
        }

        if (param->size)
                decision = find_value_cmp(st->st_size, param->size,
                                          param->size_sign, param->size_units,
                                          0);

print_path:
        if (decision != -1) {
                printf("%s", path);
                if (param->zeroend)
                        printf("%c", '\0');
                else
                        printf("\n");
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
                fprintf(stderr, "%s: Path name '%s' is too long.\n",
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
                                printf("%s has no stripe info\n", path);
                        goto out;
                } else if (errno == ENOTTY) {
                        fprintf(stderr, "%s: '%s' not on a Lustre fs?\n",
                                __FUNCTION__, path);
                } else if (errno == ENOENT) {
                        err_msg("warning: %s: %s does not exist",
                                __FUNCTION__, path);
                        goto out;
                } else {
                        err_msg("error: %s: %s failed for %s", __FUNCTION__,
                                d ? "LL_IOC_LOV_GETSTRIPE" :
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
                fprintf(stderr, "%s: Path name '%s' is too long.\n",
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
                fprintf(stderr, "llapi_obd_statfs: error packing ioctl data\n");
                return rc;
        }

        fd = open(path, O_RDONLY);
        if (errno == EISDIR)
                fd = open(path, O_DIRECTORY | O_RDONLY);

        if (fd < 0) {
                rc = errno ? -errno : -EBADF;
                err_msg("error: %s: opening '%s'", __FUNCTION__, path);
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
                fprintf(stderr, "error opening %s: %s\n", path, strerror(errno));
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
                fprintf(stderr, "error: %s opening "DEVICES_LIST"\n",
                        strerror(errno));
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
                err_msg("error: check '%s'", obd_name);
        } else {
                printf("%s active.\n", obd_name);
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
                err_msg("open %s failed", dir);
                return rc;
        }

        rc = ioctl(dirfd(root), OBD_IOC_LLOG_CATINFO, buf);
        if (rc)
                err_msg("ioctl OBD_IOC_CATINFO failed");
        else
                fprintf(stdout, "%s", data.ioc_pbuf1);

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
                err_msg("open %s failed", mnt);
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
                err_msg("open %s failed", mnt);
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
                err_msg("open %s failed", mnt);
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
                                fprintf(stderr, "%s has no stripe info\n",
                                        path);
                        rc = 0;
                } else if (errno == ENOENT) {
                        err_msg("warning: %s: %s does not exist",
                                __FUNCTION__, path);
                        rc = 0;
                } else if (errno != EISDIR) {
                        rc = errno;
                        err_msg("%s ioctl failed for %s.",
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
                err_msg("error: chown %s (%u,%u)", path);

        rc = chmod(path, st->st_mode);
        if (rc)
                err_msg("error: chmod %s (%hu)", path, st->st_mode);

        return rc;
}

int llapi_quotachown(char *path, int flag)
{
        struct find_param param;
        char *buf;
        int ret = 0, len = strlen(path);

        if (len > PATH_MAX) {
                fprintf(stderr, "%s: Path name '%s' is too long.\n",
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

int llapi_getfacl(char *fname, char *cmd)
{
        struct rmtacl_ioctl_data data;
        char out[RMTACL_SIZE_MAX] = "";
        int fd, rc;

        data.cmd = cmd;
        data.cmd_len = strlen(cmd) + 1;
        data.res = out;
        data.res_len = sizeof(out);

        fd = open(fname, 0);
        if (fd == -1) {
                err_msg("open %s failed", fname);
                return -1;
        }

        rc = ioctl(fd, LL_IOC_GETFACL, &data);
        close(fd);
        if (errno == EBADE) {
                fprintf(stderr, "Please use getfacl directly!\n");
                rc = 1;
        } else if (rc) {
                err_msg("getfacl %s failed", fname);
        } else {
                printf("%s", out);
        }

        return rc;
}

int llapi_setfacl(char *fname, char *cmd)
{
        struct rmtacl_ioctl_data data;
        char out[RMTACL_SIZE_MAX] = "";
        int fd, rc;

        data.cmd = cmd;
        data.cmd_len = strlen(cmd) + 1;
        data.res = out;
        data.res_len = sizeof(out);

        fd = open(fname, 0);
        if (fd == -1) {
                err_msg("open %s failed", fname);
                return -1;
        }

        rc = ioctl(fd, LL_IOC_SETFACL, &data);
        close(fd);
        if (errno == EBADE) {
                fprintf(stderr, "Please use setfacl directly!\n");
                rc = 1;
        } else if (errno == EOPNOTSUPP) {
                fprintf(stderr, "setfacl: %s: %s\n", fname, strerror(errno));
                rc = 1;
        } else if (rc) {
                err_msg("setfacl %s failed", fname);
        } else {
                printf("%s", out);
        }

        return rc;
}
