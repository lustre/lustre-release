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
#include <linux/lustre_lite.h>
#include <linux/lustre_idl.h>
#include <linux/obd_lov.h>

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
	struct lov_mds_md a_striping;
	int fd, result = 0;

	/*  Initialize IOCTL striping pattern structure  */
	a_striping.lmm_magic = LOV_MAGIC;
	a_striping.lmm_stripe_size = stripe_size;
	a_striping.lmm_stripe_offset = stripe_offset;
	a_striping.lmm_stripe_count = stripe_count;

	fd = open(name, O_CREAT | O_RDWR | O_LOV_DELAY_CREATE, 0644);
	if (fd < 0) {
		err_msg("unable to open '%s'",name);
		result = -errno;
	} 
        else if (ioctl(fd, LL_IOC_LOV_SETSTRIPE, &a_striping)) {
		char *errmsg = "stripe already set";
		if (errno != EEXIST && errno != EALREADY)
			errmsg = strerror(errno);

		fprintf(stderr, "error on ioctl for '%s' (%d): %s\n",
			name, fd, errmsg);
		result = -errno;
	} 
        else if (close(fd) < 0) {
		err_msg("error on close for '%s' (%d)", name, fd);
		result = -errno;
	}
	return result;
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
        struct  lov_mds_md      *lmm;
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
        int cfglen, lmmlen;
        int max_ost_count = MAX_LOV_UUID_COUNT;
        
	datalen = size_round(sizeof(struct obd_ioctl_data));
	desclen = size_round(sizeof(struct lov_desc));
	param->uuidslen = size_round(max_ost_count * sizeof(struct obd_uuid));
	cfglen = datalen + desclen + param->uuidslen;
	lmmlen = lov_mds_md_size(max_ost_count);
	if (cfglen > lmmlen)
		param->buflen = cfglen;
	else
		param->buflen = lmmlen;

	/* XXX max ioctl buffer size currently hardcoded to 8192 */
	if (param->buflen > 8192) {
		int nuuids, remaining, nluoinfos;

		param->buflen = 8192;
		nuuids = (param->buflen - datalen - desclen) / sizeof(struct obd_uuid);
		param->uuidslen = size_round(nuuids * sizeof(struct obd_uuid));
		remaining = nuuids * sizeof(struct obd_uuid);
		if (param->uuidslen > remaining)
			nuuids--;
		nluoinfos = (param->buflen - sizeof(struct lov_mds_md)) / 
                        sizeof(*(param->lmm->lmm_objects));
		if (nuuids > nluoinfos)
			max_ost_count = nluoinfos;
		else
			max_ost_count = nuuids;

		cfglen = datalen + desclen + param->uuidslen;
		lmmlen = lov_mds_md_size(max_ost_count);
	}

	if ((param->buf = malloc(param->buflen)) == NULL) {
		err_msg("unable to allocate %d bytes of memory for ioctl's",
                                param->buflen);
		return 1;
	}

	param->lmm = (struct lov_mds_md *)param->buf;
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

static void get_obd_uuids(DIR *dir, char *dname, struct find_param *param)
{
	int obdcount;
	struct obd_uuid *uuidp;
	int rc, i;

        param->got_uuids = 1;
        memset(&param->data, 0, sizeof(struct obd_ioctl_data));
        param->data.ioc_inllen1 = sizeof(struct lov_desc);
        param->data.ioc_inlbuf1 = (char *)&param->desc;
        param->data.ioc_inllen2 = param->uuidslen;
        param->data.ioc_inlbuf2 = (char *)param->uuids;

        memset(&param->desc, 0, sizeof(struct lov_desc));
        param->desc.ld_tgt_count = param->max_ost_count;

        if (obd_ioctl_pack(&param->data, &param->buf, param->buflen)) {
                fprintf(stderr, "internal buffer error from %s\n", dname);
                return;
        }

        rc = ioctl(dirfd(dir), OBD_IOC_LOV_GET_CONFIG, param->buf);
        if (rc) {
                err_msg("error getting LOV config from %s", dname);
                return;
        }

        if (obd_ioctl_unpack(&param->data, param->buf, param->buflen)) {
                err_msg("invalid reply from ioctl from %s", dname);
                return;
        }

        obdcount = param->desc.ld_tgt_count;
        if (obdcount == 0)
                return;

        if (param->obduuid) {
                for (i = 0, uuidp = param->uuids; i < obdcount; i++, uuidp++) {
                        if (strncmp(param->obduuid->uuid, uuidp->uuid,
                                    sizeof(*uuidp)) == 0) {
                                param->obdindex = i;
                                break;
                        }
                }

                if (param->obdindex == OBD_NOT_FOUND)
                        return;
        } else if (!param->quiet) {
                printf("OBDS:\n");
                for (i = 0, uuidp = param->uuids; i < obdcount; i++, uuidp++)
                        printf("%4d: %s\n", i, uuidp->uuid);
        }
}

static void process_file(DIR *dir, char *dname, char *fname, struct find_param *param)
{
	int rc, i;

	strncpy((char *)param->lmm, fname, param->buflen);

	rc = ioctl(dirfd(dir), IOC_MDC_GETSTRIPE, (void *)param->lmm);
	if (rc) {
		if (errno == ENODATA) {
			if (!param->obduuid && !param->quiet)
				fprintf(stderr,
                                        "%s/%s has no stripe info\n",
					dname, fname);
		} else if (errno == EISDIR) {
			fprintf(stderr, "process_file on directory %s/%s!\n",
				dname, fname);
			/*
			  add fname to directory list;
                        */
                } else {
			err_msg("IOC_MDC_GETSTRIPE ioctl failed");
		}
		return;
	}

	if ((param->obduuid && param->lmm->lmm_objects[param->obdindex].l_object_id) ||
	    (!param->obduuid && !param->quiet))
                printf("%s/%s\n", dname, fname);

        if (param->verbose) {
                printf("lmm_magic:          0x%x\n", param->lmm->lmm_magic);
                printf("lmm_object_id:      "LPX64"\n", param->lmm->lmm_object_id);
                printf("lmm_stripe_offset:  %u\n", (int)param->lmm->lmm_stripe_offset);
                printf("lmm_stripe_count:   %u\n", (int)param->lmm->lmm_stripe_count);
                printf("lmm_stripe_size:    %u\n", (int)param->lmm->lmm_stripe_size);
                printf("lmm_ost_count:      %u\n", param->lmm->lmm_ost_count);
                printf("lmm_stripe_pattern: %d\n", param->lmm->lmm_magic & 0xf);
        }

	if (param->verbose || !param->obduuid) {
		long long oid;
		int ost = param->lmm->lmm_stripe_offset;
		int header = !param->quiet;

		/* FIXME: temporary fix for bug 1612 */
		if (param->lmm->lmm_ost_count == 0) {
			oid = param->lmm->lmm_object_id;
			if (header)
				printf("\tobdidx\t\t objid\t\tobjid\n");
			printf("\t%6u\t%14llu\t%13llx\n", 0, oid, oid);
		} else
		for (i = 0; i < param->lmm->lmm_ost_count; i++, ost++) {
			ost %= param->lmm->lmm_ost_count;
			if ((oid = param->lmm->lmm_objects[ost].l_object_id)) {
				if (header) {
					printf("\tobdidx\t\t objid\t\tobjid\n");
					header = 0;
				}
				printf("\t%6u\t%14llu\t%13llx%s\n", ost,
				       oid, oid, param->obdindex == ost ? " *" : "");
			}
		}
		printf("\n");
	}
}


static void process_dir(DIR *dir, char *dname, struct find_param *param)
{
	struct dirent64 *dirp;
        DIR *subdir;
	char path[1024];

	if (!param->got_uuids)
                get_obd_uuids(dir, dname, param);

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
                        return;
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
                                break;
                        }
                        process_dir(subdir, path, param);
                        closedir(subdir);
                        break;
                case DT_REG:
                        process_file(dir, dname, dirp->d_name, param);
                        break;
                default:
                        break;
                }
        }
}

static void process_path(char *path, struct find_param *param)
{
        char *fname, *dname;
        DIR *dir;

        fname = strrchr(path, '/');
        if (fname != NULL && fname[1] == '\0') {
                /* Trailing '/', it must be a dir */
                *fname = '\0';
                dir = opendir(path);
                if (dir == NULL) {
                        err_msg("\"%.40s\" opendir failed", path);
                } else {
                        process_dir(dir, path, param);
                        closedir(dir);
                }
        } else if ((dir = opendir(path)) != NULL) {
                /* No trailing '/', but it is still a dir */
                process_dir(dir, path, param);
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
                } else {
                        if (!param->got_uuids)
                                get_obd_uuids(dir, dname, param);
                        process_file(dir, dname, fname, param);
                        closedir(dir);
                }
        }
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
                param.obduuid = (struct obd_uuid*)malloc(sizeof(struct obd_uuid));
                if (param.obduuid == NULL) {
                        ret = 1;
                        goto out;
                }
                memcpy(param.obduuid, obduuid, sizeof(struct obd_uuid));
        }

        ret = prepare_find(&param);
        if (ret)
                goto out;

        process_path(path, &param);
out:
        cleanup_find(&param);
        return ret;
}
        
