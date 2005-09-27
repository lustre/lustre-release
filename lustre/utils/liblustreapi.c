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
#ifdef HAVE_LINUX_TYPES_H
#include <linux/types.h>
#endif
#ifdef HAVE_LINUX_UNISTD_H
#include <linux/unistd.h>
#else
#include <unistd.h>
#endif

#include <portals/ptlctl.h>

#include <liblustre.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <lustre/liblustreapi.h>
#include <linux/obd_lov.h>

static void err_msg(char *fmt, ...)
{
        va_list args;
        int tmp_errno = abs(errno);

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
        fprintf(stderr, ": %s (%d)\n", strerror(tmp_errno), tmp_errno);
}

int llapi_file_create(char *name, long stripe_size, int stripe_offset,
                      int stripe_count, int stripe_pattern)
{
        struct lov_user_md lum = { 0 };
        int fd, rc = 0;
        int isdir = 0;
        int page_size;

        fd = open(name, O_CREAT | O_RDWR | O_LOV_DELAY_CREATE, 0644);
        if (errno == EISDIR) {
                fd = open(name, O_DIRECTORY | O_RDONLY);
                isdir++;
        }

        if (fd < 0) {
                err_msg("unable to open '%s'",name);
                rc = -errno;
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
                err_msg("error: stripe_size must be an even "
                        "multiple of %d bytes", page_size);
                goto out;
        }
        if (stripe_offset < -1 || stripe_offset > LOV_MAX_STRIPE_COUNT) {
                errno = rc = -EINVAL;
                err_msg("error: bad stripe offset %d", stripe_offset);
                goto out;
        }
        if (stripe_count < -1 || stripe_count > LOV_MAX_STRIPE_COUNT) {
                errno = rc = -EINVAL;
                err_msg("error: bad stripe count %d", stripe_count);
                goto out;
        }
        if (stripe_count > 0 && (__u64)stripe_size * stripe_count > ~0UL) {
                errno = rc = -EINVAL;
                err_msg("error: stripe_size %ld * stripe_count %d "
                        "exceeds %lu bytes", ~0UL);
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
                if (errno != EEXIST && errno != EALREADY)
                        errmsg = strerror(errno);

                fprintf(stderr, "error on ioctl "LPX64" for '%s' (%d): %s\n",
                        (__u64)LL_IOC_LOV_SETSTRIPE, name, fd, errmsg);
                rc = -errno;
        }
out:
        if (close(fd) < 0) {
                err_msg("error on close for '%s' (%d)", name, fd);
                if (rc == 0)
                        rc = -errno;
        }
        return rc;
}

/* short term backwards compat only */
int op_create_file(char *name, long stripe_size, int stripe_offset,
                   int stripe_count)
{
        return llapi_file_create(name, stripe_size, stripe_offset,
                                 stripe_count, 0);
}

struct find_param {
        int     recursive;
        int     verbose;
        int     quiet;
        struct  obd_uuid        *obduuid;
        int     lumlen;
        struct  lov_user_mds_data *lmd;
/*        struct  lov_user_md     *lum;*/
        int     got_uuids;
        int     obdindex;
        int     (* process_file)(DIR *dir, char *dname, char *fname,
                        struct find_param *param);
};

#define MAX_LOV_UUID_COUNT      max(LOV_MAX_STRIPE_COUNT, 1000)
#define OBD_NOT_FOUND           (-1)

static int prepare_find(struct find_param *param)
{
        param->lumlen = lov_mds_md_size(MAX_LOV_UUID_COUNT);
        if ((param->lmd = malloc(sizeof(lstat_t) + param->lumlen)) == NULL) {
                err_msg("unable to allocate %d bytes of memory for ioctl",
                        sizeof(lstat_t) + param->lumlen);
                return ENOMEM;
        }

        param->got_uuids = 0;
        param->obdindex = OBD_NOT_FOUND;

        return 0;
}

static void cleanup_find(struct find_param *param)
{
        if (param->obduuid)
                free(param->obduuid);
        if (param->lmd)
                free(param->lmd);
}

int llapi_lov_get_uuids(int fd, struct obd_uuid *uuidp, int *ost_count)
{
        struct obd_ioctl_data data = { 0, };
        struct lov_desc desc = { 0, };
        char *buf = NULL;
        int max_ost_count, rc;
        __u32 *obdgens;

        max_ost_count = (OBD_MAX_IOCTL_BUFFER - size_round(sizeof(data)) -
                         size_round(sizeof(desc))) /
                        (sizeof(*uuidp) + sizeof(*obdgens));
        if (max_ost_count > *ost_count)
                max_ost_count = *ost_count;

        obdgens = malloc(size_round(max_ost_count * sizeof(*obdgens)));
        if (!obdgens) {
                err_msg("no memory for %d generation #'s", max_ost_count);
                return(-ENOMEM);
        }

        data.ioc_inllen1 = sizeof(desc);
        data.ioc_inlbuf1 = (char *)&desc;
        data.ioc_inllen2 = size_round(max_ost_count * sizeof(*uuidp));
        data.ioc_inlbuf2 = (char *)uuidp;
        data.ioc_inllen3 = size_round(max_ost_count * sizeof(*obdgens));
        data.ioc_inlbuf3 = (char *)obdgens;

        desc.ld_tgt_count = max_ost_count;

        if (obd_ioctl_pack(&data, &buf, OBD_MAX_IOCTL_BUFFER)) {
                fprintf(stderr, "internal buffer error packing\n");
                rc = EINVAL;
                goto out;
        }

        rc = ioctl(fd, OBD_IOC_LOV_GET_CONFIG, buf);
        if (rc) {
                err_msg("error getting LOV config");
                rc = errno;
                goto out;
        }

        if (obd_ioctl_unpack(&data, buf, OBD_MAX_IOCTL_BUFFER)) {
                fprintf(stderr, "invalid reply from ioctl");
                rc = EINVAL;
                goto out;
        }

        *ost_count = desc.ld_tgt_count;
out:
        free(buf);
        free(obdgens);

        return rc;
}

static int setup_obd_uuids(DIR *dir, char *dname, struct find_param *param)
{
        char uuid[sizeof(struct obd_uuid)];
        char buf[1024];
        FILE *fp;
        int rc = 0, index;

        param->got_uuids = 1;

        /* Get the lov name */
        rc = ioctl(dirfd(dir), OBD_IOC_GETNAME, (void *)uuid);
        if (rc) {
                fprintf(stderr, "error: can't get lov name: %s\n",
                        strerror(rc = errno));
                return rc;
        }

        /* Now get the ost uuids from /proc */
        snprintf(buf, sizeof(buf), "/proc/fs/lustre/lov/%s/target_obd",
                 uuid);
        fp = fopen(buf, "r");
        if (fp == NULL) {
                fprintf(stderr, "error: %s opening %s\n",
                        strerror(rc = errno), buf);
                return rc;
        }

        if (!param->obduuid && !param->quiet)
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
                } else if (!param->quiet) {
                        /* Print everything */
                        printf("%s", buf);
                }
        }

        fclose(fp);

        if (param->obduuid && (param->obdindex == OBD_NOT_FOUND)) {
                printf("unknown obduuid: %s\n", param->obduuid->uuid);
                rc =  EINVAL;
        }

        return (rc);
}

void lov_dump_user_lmm_v1(struct lov_user_md_v1 *lum, char *dname, char *fname,
                          int obdindex, int quiet, int header, int body)
{
        int i, obdstripe = 0;

        if (*fname != '\0' && obdindex != OBD_NOT_FOUND) {
                for (i = 0; i < lum->lmm_stripe_count; i++) {
                        if (obdindex == lum->lmm_objects[i].l_ost_idx) {
                                printf("%s/%s\n", dname, fname);
                                obdstripe = 1;
                                break;
                        }
                }
        } else if (!quiet) {
                printf("%s/%s\n", dname, fname);
                obdstripe = 1;
        }

        /* if it's a directory */
        if (*fname == '\0') {
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

void llapi_lov_dump_user_lmm(struct find_param *param, char *dname, char *fname)
{
        switch(*(__u32 *)&param->lmd->lmd_lmm) { /* lum->lmm_magic */
        case LOV_USER_MAGIC_V1:
                lov_dump_user_lmm_v1(&param->lmd->lmd_lmm, dname, fname, param->obdindex,
                                     param->quiet, param->verbose,
                                     (param->verbose || !param->obduuid));
                break;
        default:
                printf("unknown lmm_magic:  %#x (expecting %#x)\n",
                       *(__u32 *)&param->lmd->lmd_lmm, LOV_USER_MAGIC_V1);
                return;
        }
}

int llapi_file_get_stripe(char *path, struct lov_user_md *lum)
{
        char *dname, *fname;
        int fd, rc = 0;

        fname = strrchr(path, '/');

        /* It should be a file (or other non-directory) */
        if (fname == NULL) {
                dname = (char *)malloc(2);
                if (dname == NULL)
                        return ENOMEM;
                strcpy(dname, ".");
                fname = path;
        } else {
                dname = (char *)malloc(fname - path + 1);
                if (dname == NULL)
                        return ENOMEM;
                strncpy(dname, path, fname - path);
                dname[fname - path] = '\0';
                fname++;
        }

        if ((fd = open(dname, O_RDONLY)) == -1) {
                free(dname);
                return errno;
        }

        strcpy((char *)lum, fname);
        if (ioctl(fd, IOC_MDC_GETSTRIPE, (void *)lum) == -1) {
                close(fd);
                free(dname);
                return errno;
        }

        if (close(fd) == -1)
                rc = errno;

        free(dname);

        return rc;
}

/* short term backwards compat only */
int op_get_file_stripe(char *path, struct lov_user_md *lum)
{
        return llapi_file_get_stripe(path, lum);
}

static int find_process_file(DIR *dir, char *dname, char *fname,
                        struct find_param *param)
{
        int rc;

        strncpy((char *)&param->lmd->lmd_lmm, fname, param->lumlen);

        rc = ioctl(dirfd(dir), IOC_MDC_GETSTRIPE, (void *)&param->lmd->lmd_lmm);
        if (rc) {
                if (errno == ENODATA) {
                        if (!param->obduuid && !param->quiet)
                                fprintf(stderr,
                                        "%s/%s has no stripe info\n",
                                        dname, fname);
                        rc = 0;
                } else if (errno == EISDIR) {
                        fprintf(stderr, "process_file on directory %s/%s!\n",
                                dname, fname);
                        /* add fname to directory list; */
                        rc = errno;
                } else {
                        err_msg("IOC_MDC_GETSTRIPE ioctl failed for '%s/%s'",
                                dname, fname);
                        rc = errno;
                }
                return rc;
        }

        llapi_lov_dump_user_lmm(param, dname, fname);

        return 0;
}

/* some 64bit libcs implement readdir64() by calling sys_getdents().  the
 * kernel's sys_getdents() doesn't return d_type.  */
unsigned char handle_dt_unknown(char *parent, char *entry)
{
        char path[PATH_MAX + 1];
        int fd, ret;

        ret = snprintf(path, PATH_MAX, "%s/%s", parent, entry);
        if (ret >= PATH_MAX)
                return DT_UNKNOWN;

        fd = open(path, O_DIRECTORY|O_RDONLY);
        if (fd < 0) {
                if (errno == ENOTDIR)
                        return DT_REG; /* kind of a lie */
                return DT_UNKNOWN;
        }
        close(fd);
        return DT_DIR;
}

static int process_dir(DIR *dir, char *dname, struct find_param *param)
{
        struct dirent64 *dirp;
        DIR *subdir;
        char path[1024];
        int rc;

        if (!param->got_uuids) {
                rc = setup_obd_uuids(dir, dname, param);
                if (rc)
                        return rc;
        }

        /* retrieve dir's stripe info */
        strncpy((char *)&param->lmd->lmd_lmm, dname, param->lumlen);
        rc = ioctl(dirfd(dir), LL_IOC_LOV_GETSTRIPE, (void *)&param->lmd->lmd_lmm);
        if (rc) {
                if (errno == ENODATA) {
                        if (!param->obduuid && param->verbose)
                                printf("%s/%s has no stripe info\n", dname, "");
                        rc = 0;
                } else {
                        err_msg("GETSTRIPE failed for %s", dname);
                }
        } else {
               llapi_lov_dump_user_lmm(param, dname, "");
        }

        /* Handle the contents of the directory */
        while ((dirp = readdir64(dir)) != NULL) {
                if (!strcmp(dirp->d_name, ".") || !strcmp(dirp->d_name, ".."))
                        continue;

                if (dirp->d_type == DT_UNKNOWN)
                        dirp->d_type = handle_dt_unknown(dname, dirp->d_name);

                switch (dirp->d_type) {
                case DT_UNKNOWN:
                        err_msg("\"%s\" is UNKNOWN type %d", dirp->d_name,
                                dirp->d_type);
                        /* If we cared we could stat the file to determine
                         * type and continue on here, but we don't since we
                         * know d_type should be valid for lustre and this
                         * tool only makes sense for lustre filesystems. */
                        break;
                case DT_DIR:
                        if (!param->recursive)
                                break;
                        strcpy(path, dname);
                        strcat(path, "/");
                        strcat(path, dirp->d_name);
                        subdir = opendir(path);
                        if (subdir == NULL) {
                                err_msg("\"%.40s\" opendir failed", path);
                                return errno;
                        }
                        rc = process_dir(subdir, path, param);
                        closedir(subdir);
                        break;
                case DT_REG:
                        rc = param->process_file(dir,dname,dirp->d_name,param);
                        break;
                default:
                        break;
                }
        }

        return 0;
}

static int process_path(char *path, struct find_param *param)
{
        char *fname, *dname;
        DIR *dir;
        int rc = 0;

        fname = strrchr(path, '/');
        if (fname != NULL && fname[1] == '\0') {
                /* Trailing '/', it must be a dir */
                *fname = '\0';
                dir = opendir(path);
                if (dir == NULL) {
                        err_msg("\"%.40s\" opendir failed", path);
                        rc = errno;
                } else {
                        rc = process_dir(dir, path, param);
                        closedir(dir);
                }
        } else if ((dir = opendir(path)) != NULL) {
                /* No trailing '/', but it is still a dir */
                rc = process_dir(dir, path, param);
                closedir(dir);
        } else {
                /* It must be a file (or other non-directory) */
                if (fname == NULL) {
                        dname = ".";
                        fname = path;
                } else {
                        *fname = '\0';
                        fname++;
                        dname = path;
                }
                dir = opendir(dname);
                if (dir == NULL) {
                        err_msg("\"%.40s\" opendir failed", dname);
                        rc = errno;
                } else {
                        if (!param->got_uuids)
                                rc = setup_obd_uuids(dir, dname, param);
                        if (rc == 0)
                                rc = param->process_file(dir, dname, fname, param);
                        closedir(dir);
                }
        }

        return rc;
}

int llapi_find(char *path, struct obd_uuid *obduuid, int recursive,
               int verbose, int quiet)
{
        struct find_param param;
        int ret = 0;

        memset(&param, 0, sizeof(param));
        param.recursive = recursive;
        param.verbose = verbose;
        param.quiet = quiet;
        param.process_file = find_process_file;
        if (obduuid) {
                param.obduuid = malloc(sizeof(*obduuid));
                if (param.obduuid == NULL) {
                        ret = ENOMEM;
                        goto out;
                }
                memcpy(param.obduuid, obduuid, sizeof(*obduuid));
        }

        ret = prepare_find(&param);
        if (ret)
                goto out;

        process_path(path, &param);
out:
        cleanup_find(&param);
        return ret;
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
                fprintf(stderr, "error opening %s: %s\n", path, strerror(errno));
                return errno;
        }

        rc = write(fd, buf, 1);
        close(fd);

        if (rc == 1)
                return 0;
        return rc;
}

int llapi_target_check(int type_num, char **obd_type, char *dir)
{
        char buf[MAX_STRING_SIZE];
        FILE *fp = fopen(DEVICES_LIST, "r");
        int i, rc = 0;

        if (fp == NULL) {
                fprintf(stderr, "error: %s opening "DEVICES_LIST"\n",
                        strerror(rc =  errno));
                return rc;
        }

        while (fgets(buf, sizeof(buf), fp) != NULL) {
                char *obd_type_name = NULL;
                char *obd_name = NULL;
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

                memset(&osfs_buffer, 0, sizeof (osfs_buffer));

                memset(bufl, 0, sizeof(rawbuf));
                datal.ioc_pbuf1 = (char *)&osfs_buffer;
                datal.ioc_plen1 = sizeof(osfs_buffer);

                for (i = 0; i < type_num; i++) {
                        if (strcmp(obd_type_name, obd_type[i]) != 0)
                                continue;

                        rc = llapi_ping(obd_type_name, obd_name);
                        if (rc) {
                                fprintf(stderr, "error: check %s: %s\n",
                                        obd_name, strerror(rc = errno));
                        } else {
                                printf("%s active.\n", obd_name);
                        }
                }
        }
        fclose(fp);
        return rc;
}

#undef MAX_STRING_SIZE

int llapi_catinfo(char *dir, char *keyword, char *node_name)
{
        char raw[OBD_MAX_IOCTL_BUFFER];
        char out[LLOG_CHUNK_SIZE];
        char *buf = raw;
        struct obd_ioctl_data data;
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
                err_msg("open %s failed", dir);
                return errno;
        }

        rc = ioctl(dirfd(root), OBD_IOC_LLOG_CATINFO, buf);
        if (rc)
                err_msg("ioctl OBD_IOC_CATINFO failed");
        else
                fprintf(stdout, "%s", data.ioc_pbuf1);

        closedir(root);
        return rc;
}

int llapi_is_lustre_mnttype(char *type)
{
        return (strcmp(type,"lustre") == 0 || strcmp(type,"lustre_lite") == 0);
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
                if (!rc || errno != ENODATA)
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

static int quotachog_process_file(DIR *dir, char *dname, char *fname,
                        struct find_param *param)
{
        lstat_t *st;
        char pathname[PATH_MAX + 1] = "";
        int rc;

        strncpy((char *)param->lmd, fname, param->lumlen);

        rc = ioctl(dirfd(dir), IOC_MDC_GETFILEINFO, (void *)param->lmd);
        if (rc) {
                if (errno == ENODATA) {
                        if (!param->obduuid && !param->quiet)
                                fprintf(stderr,
                                        "%s/%s has no stripe info\n",
                                        dname, fname);
                        rc = 0;
                } else if (errno != EISDIR) {
                        err_msg("IOC_MDC_GETFILEINFO ioctl failed");
                        rc = errno;
                }
                return rc;
        }

        st = &param->lmd->lmd_st;
        snprintf(pathname, sizeof(pathname), "%s/%s", dname, fname);
        rc = syscall(SYS_chown, pathname, st->st_uid, st->st_gid);
        if (rc)
                fprintf(stderr, "chown %s (%u,%u) fail: %s\n",
                        pathname, st->st_uid, st->st_gid, strerror(errno));
        return rc;
}

int llapi_quotachog(char *path, int flag)
{
        struct find_param param;
        int ret = 0;

        memset(&param, 0, sizeof(param));
        param.recursive = 1;
        param.verbose = 0;
        param.quiet = 1;
        param.process_file = quotachog_process_file;

        ret = prepare_find(&param);
        if (ret)
                goto out;

        process_path(path, &param);
out:
        cleanup_find(&param);
        return ret;
}

