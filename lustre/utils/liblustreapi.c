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
#include <linux/types.h>
#include <linux/unistd.h>

#include <liblustre.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <lustre/lustre_user.h>
#include <linux/obd_lov.h>

#include <portals/ptlctl.h>

static void err_msg(char *fmt, ...)
{
        va_list args;
        int tmp_errno = errno;

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
        fprintf(stderr, ": %s (%d)\n", strerror(tmp_errno), tmp_errno);
}

int op_create_file(char *name, long stripe_size, int stripe_offset,
                   int stripe_count)
{
        struct lov_user_md lum = { 0 };
        int fd, rc = 0;

        /*  Initialize IOCTL striping pattern structure  */
        lum.lmm_magic = LOV_USER_MAGIC;
        lum.lmm_stripe_size = stripe_size;
        lum.lmm_stripe_offset = stripe_offset;
        lum.lmm_stripe_count = stripe_count;

        fd = open(name, O_CREAT | O_RDWR | O_LOV_DELAY_CREATE, 0644);
        if (fd < 0) {
                err_msg("unable to open '%s'",name);
                rc = -errno;
                return rc;
        }
        if (ioctl(fd, LL_IOC_LOV_SETSTRIPE, &lum)) {
                char *errmsg = "stripe already set";
                if (errno != EEXIST && errno != EALREADY)
                        errmsg = strerror(errno);

                fprintf(stderr, "error on ioctl for '%s' (%d): %s\n",
                        name, fd, errmsg);
                rc = -errno;
        }
        if (close(fd) < 0) {
                err_msg("error on close for '%s' (%d)", name, fd);
                if (rc == 0)
                        rc = -errno;
        }
        return rc;
}

int op_setstripe_dir(char *path, long stripe_size, int stripe_offset,
                     int stripe_count)
{
        struct lov_user_md lum = { 0 };
        int rc = 0;
        DIR * dir;

        /*  Initialize IOCTL striping pattern structure  */
        lum.lmm_magic = LOV_USER_MAGIC;
        lum.lmm_stripe_size = stripe_size;
        lum.lmm_stripe_offset = stripe_offset;
        lum.lmm_stripe_count = stripe_count;

        dir = opendir(path);
        if (dir == NULL) {
                err_msg("\"%.40s\" opendir failed", path);
                rc = -errno;
        } else {
                if (ioctl(dirfd(dir), LL_IOC_LOV_SETSTRIPE, &lum)) {
                        fprintf(stderr, "error on ioctl for '%s': %s\n",
                                path, strerror(errno));
                        rc = -errno;
                }
                close(dir);
        }

        return rc;
}

struct find_param {
        int     recursive;
        int     verbose;
        int     quiet;
        struct  obd_uuid        *obduuid;
        struct  obd_ioctl_data  data;
        struct  lov_desc        desc;
        int     uuidslen;
        char    *buf;
        int     buflen;
        struct  obd_uuid        *uuids;
        struct  lov_user_md     *lum;
        int     got_uuids;
        int     obdindex;
        int     max_ost_count;
};

/* XXX Max obds per lov currently hardcoded to 1000 in lov/lov_obd.c */
#define MAX_LOV_UUID_COUNT      1000
#define OBD_NOT_FOUND           (-1)

static int prepare_find(struct find_param *param)
{
        int datalen, desclen;
        int cfglen, lumlen;
        int max_ost_count = MAX_LOV_UUID_COUNT;

        datalen = size_round(sizeof(param->data));
        desclen = size_round(sizeof(param->desc));
        param->uuidslen = size_round(max_ost_count * sizeof(*param->uuids));
        cfglen = datalen + desclen + param->uuidslen;
        lumlen = lov_mds_md_size(max_ost_count);
        if (cfglen > lumlen)
                param->buflen = cfglen;
        else
                param->buflen = lumlen;

        /* XXX max ioctl buffer size currently hardcoded to 8192 */
        if (param->buflen > 8192) {
                int nuuids, remaining;

                param->buflen = 8192;
                nuuids = (param->buflen - datalen - desclen) /
                        sizeof(*param->uuids);
                param->uuidslen = size_round(nuuids * sizeof(*param->uuids));
                remaining = nuuids * sizeof(*param->uuids);
                if (param->uuidslen > remaining)
                        nuuids--;
                max_ost_count = nuuids;
                while ((lumlen=lov_mds_md_size(max_ost_count)) > param->buflen)
                        --max_ost_count;

                cfglen = datalen + desclen + param->uuidslen;
        }

        if ((param->buf = malloc(param->buflen)) == NULL) {
                err_msg("unable to allocate %d bytes of memory for ioctl's",
                        param->buflen);
                return ENOMEM;
        }

        param->lum = (struct lov_user_md *)param->buf;
        param->uuids = (struct obd_uuid *)param->buf;
        param->got_uuids = 0;
        param->obdindex = OBD_NOT_FOUND;
        param->max_ost_count = max_ost_count;

        return 0;
}

static void cleanup_find(struct find_param *param)
{
        if (param->obduuid)
                free(param->obduuid);
        if (param->buf)
                free(param->buf);
}

static int get_obd_uuids(DIR *dir, char *dname, struct find_param *param)
{
        int obdcount;
        struct obd_uuid *uuidp;
        int rc, i;

        param->got_uuids = 1;
        memset(&param->data, 0, sizeof(param->data));
        param->data.ioc_inllen1 = sizeof(struct lov_desc);
        param->data.ioc_inlbuf1 = (char *)&param->desc;
        param->data.ioc_inllen2 = param->uuidslen;
        param->data.ioc_inlbuf2 = (char *)param->uuids;

        memset(&param->desc, 0, sizeof(struct lov_desc));
        param->desc.ld_tgt_count = param->max_ost_count;

        if (obd_ioctl_pack(&param->data, &param->buf, param->buflen)) {
                fprintf(stderr, "internal buffer error from %s\n", dname);
                return (param->obduuid ? EINVAL : 0);
        }

        rc = ioctl(dirfd(dir), OBD_IOC_LOV_GET_CONFIG, param->buf);
        if (rc) {
                err_msg("error getting LOV config from %s", dname);
                return (param->obduuid ? errno : 0);
        }

        if (obd_ioctl_unpack(&param->data, param->buf, param->buflen)) {
                err_msg("invalid reply from ioctl from %s", dname);
                return (param->obduuid ? EINVAL : 0);
        }

        obdcount = param->desc.ld_tgt_count;
        if (obdcount == 0)
                return 0;

        if (param->obduuid) {
                for (i = 0, uuidp = param->uuids; i < obdcount; i++, uuidp++) {
                        if (strncmp(param->obduuid->uuid, uuidp->uuid,
                                    sizeof(*uuidp)) == 0) {
                                param->obdindex = i;
                                break;
                        }
                }
                if (param->obdindex == OBD_NOT_FOUND) {
                        printf("unknown obduuid: %s\n", param->obduuid->uuid);
                        return EINVAL;
                }
        } else if (!param->quiet) {
                printf("OBDS:\n");
                for (i = 0, uuidp = param->uuids; i < obdcount; i++, uuidp++)
                        printf("%4d: %s\n", i, uuidp->uuid);
        }

        return 0;
}

void lov_dump_user_lmm_v1(struct lov_user_md_v1 *lum, char *dname, char *fname,
                          int obdindex, int quiet, int header, int body)
{
        int i, obdstripe = 0;

        if (obdindex != OBD_NOT_FOUND) {
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
                if (header && (obdstripe == 1)) {
                        printf("count: %d, size: %d, offset: %d\n\n",
                               lum->lmm_stripe_count, lum->lmm_stripe_size,
                               (short int)lum->lmm_stripe_offset);
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
                long long oid;

                if ((!quiet) && (obdstripe == 1))
                        printf("\tobdidx\t\t objid\t\tobjid\t\t group\n");

                for (i = 0; i < lum->lmm_stripe_count; i++) {
                        int idx = lum->lmm_objects[i].l_ost_idx;
                        oid = lum->lmm_objects[i].l_object_id;
                        if ((obdindex == OBD_NOT_FOUND) || (obdindex == idx))
                                printf("\t%6u\t%14llu\t%#13llx\t%14lld%s\n",
                                       idx, oid, oid, 
                                       (long long)lum->lmm_objects[i].l_object_gr,
                                       obdindex == idx ? " *" : "");
                }
                printf("\n");
        }
}

void lov_dump_user_lmm(struct find_param *param, char *dname, char *fname)
{
        switch(*(__u32 *)param->lum) { /* lum->lmm_magic */
        case LOV_USER_MAGIC_V1:
                lov_dump_user_lmm_v1(param->lum, dname, fname, param->obdindex,
                                     param->quiet, param->verbose,
                                     (param->verbose || !param->obduuid));
                break;
        default:
                printf("unknown lmm_magic:  0x%08X\n", *(__u32 *)param->lum);
                return;
        }
}

static int process_file(DIR *dir, char *dname, char *fname,
                         struct find_param *param)
{
        int rc;

        strncpy((char *)param->lum, fname, param->buflen);

        rc = ioctl(dirfd(dir), IOC_MDC_GETSTRIPE, (void *)param->lum);
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
                        err_msg("IOC_MDC_GETSTRIPE ioctl failed");
                        rc = errno;
                }
                return rc;
        }

        lov_dump_user_lmm(param, dname, fname);

        return 0;
}


static int process_dir(DIR *dir, char *dname, struct find_param *param)
{
        struct dirent64 *dirp;
        DIR *subdir;
        char path[1024];
        int rc;

        if (!param->got_uuids) {
                rc = get_obd_uuids(dir, dname, param);
                if (rc)
                        return rc;
        }

        /* retrieve dir's stripe info */
        strncpy((char *)param->lum, dname, param->buflen);
        rc = ioctl(dirfd(dir), LL_IOC_LOV_GETSTRIPE, (void *)param->lum);
        if (rc) {
                if (errno == ENODATA) {
                        if (!param->obduuid && !param->quiet)
                                printf("%s/%s has no stripe info\n", 
                                       dname, "");
                        rc = 0;
                } else {
                        err_msg("IOC_MDC_GETSTRIPE ioctl failed");
                        return errno;
                }
        } else {
               lov_dump_user_lmm(param, dname, "");
        }

        /* Handle the contents of the directory */
        while ((dirp = readdir64(dir)) != NULL) {
                if (!strcmp(dirp->d_name, ".") || !strcmp(dirp->d_name, ".."))
                        continue;

                switch (dirp->d_type) {
                case DT_UNKNOWN:
                        err_msg("\"%s\" is UNKNOWN type %d", dirp->d_name,
                                dirp->d_type);
                        /* If we cared we could stat the file to determine
                         * type and continue on here, but we don't since we
                         * know d_type should be valid for lustre and this
                         * tool only makes sense for lustre filesystems. */
                        return EINVAL;
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
                        if (rc)
                                return rc;
                        break;
                case DT_REG:
                        rc = process_file(dir, dname, dirp->d_name, param);
                        if (rc)
                                return rc;
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
                                rc = get_obd_uuids(dir, dname, param);
                        if (rc == 0)
                                rc = process_file(dir, dname, fname, param);
                        closedir(dir);
                }
        }

        return rc;
}


int op_find(char *path, struct obd_uuid *obduuid, int recursive,
            int verbose, int quiet)
{
        struct find_param param;
        int ret = 0;

        memset(&param, 0, sizeof(param));
        param.recursive = recursive;
        param.verbose = verbose;
        param.quiet = quiet;
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

int op_check(int type_num, char **obd_type, char *dir)
{
        int rc=0;
        int i=0,j=0,k;
        char buf[OBD_MAX_IOCTL_BUFFER];
        char *buf2;
        struct obd_ioctl_data *data = (struct obd_ioctl_data *)buf;
                                                                                                                     
        memset(buf, 0, sizeof(buf));
        data->ioc_version = OBD_IOCTL_VERSION;
        data->ioc_inllen1 = sizeof(buf) - size_round(sizeof(*data));
        data->ioc_len = obd_ioctl_packlen(data);
                                                                                                                             
        rc = l_ioctl(OBD_DEV_ID, OBD_IOC_LIST, data);
                   
        buf2 = data->ioc_bulk;

        if (!data->ioc_inlbuf1) {
                err_msg("No buffer passed!\n");
                rc = errno;
        }

        do {
                char status[3];
                char obd_type_name[sizeof(struct obd_type)];
                char obd_name[MAX_STRING_SIZE];
                char obd_uuid[sizeof(struct obd_uuid)];
                int obd_type_refcnt;

                char rawbuf[OBD_MAX_IOCTL_BUFFER];
                char *bufl = rawbuf;
                int max = sizeof(rawbuf);
                struct obd_ioctl_data datal;
                struct obd_statfs osfs_buffer;
                                                                                
                memset (&osfs_buffer, 0, sizeof (osfs_buffer));

                memset(bufl, 0, sizeof(rawbuf));
                datal.ioc_pbuf1 = (char *)&osfs_buffer;
                datal.ioc_plen1 = sizeof (osfs_buffer);

                j = sscanf(buf2,"%d %s %s %s %s %d",&j,
                             status,obd_type_name,
                             obd_name, obd_uuid,
                             &obd_type_refcnt);

                if (j != 6) break;

                for (k=0;k<type_num;k++) 
                        if (strcmp(obd_type_name, obd_type[k]) == 0) {
                                datal.ioc_inlbuf1 = obd_name;
                                datal.ioc_inllen1 = strlen(obd_name) + 1; 

                                obd_ioctl_pack(&datal,&bufl,max);

                                rc = ioctl(dirfd(opendir(dir)), OBD_IOC_PING,bufl);

                                if (rc) {
                                        fprintf(stderr, "error: check %s: %s\n", 
                                                obd_name, strerror(rc = errno));
                                } else {
                                        printf("%s active.\n",obd_name);
                                }
                        }

                if (j==6)
                        for (i=0;buf2[i]!= '\n';i++);

                buf2 +=(i+1);

        } while (j==6);                                                                                                     

        return rc;
}

#undef MAX_STRING_SIZE

int op_catinfo(char *dir, char *keyword, char *node_name)
{
        char raw[OBD_MAX_IOCTL_BUFFER];
        char out[LLOG_CHUNK_SIZE];
        char *buf = raw;
        struct obd_ioctl_data data;
        char key[30];
        DIR *root;
        int rc;
        
        sprintf(key, "%s", keyword);
        memset(raw, 0, sizeof(buf));
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
        
