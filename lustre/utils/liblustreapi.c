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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
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

#include <ctype.h>
#include <mntent.h>
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
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <fnmatch.h>
#include <libgen.h> /* for dirname() */
#ifdef HAVE_LINUX_UNISTD_H
#include <linux/unistd.h>
#else
#include <unistd.h>
#endif
#include <poll.h>

#include <libcfs/util/ioctl.h>
#include <libcfs/util/param.h>
#include <libcfs/util/string.h>
#include <lnet/lnetctl.h>
#include <lustre/lustreapi.h>
#include <linux/lustre_ostid.h>
#include <linux/lustre_ioctl.h>
#include "lustreapi_internal.h"

static int llapi_msg_level = LLAPI_MSG_MAX;

char *mdt_hash_name[] = { "none",
			  LMV_HASH_NAME_ALL_CHARS,
			  LMV_HASH_NAME_FNV_1A_64 };

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

int llapi_msg_get_level(void)
{
	return llapi_msg_level;
}

static void error_callback_default(enum llapi_message_level level, int err,
				   const char *fmt, va_list ap)
{
	vfprintf(stderr, fmt, ap);
	if (level & LLAPI_MSG_NO_ERRNO)
		fprintf(stderr, "\n");
	else
		fprintf(stderr, ": %s (%d)\n", strerror(err), err);
}

static void info_callback_default(enum llapi_message_level level, int err,
				  const char *fmt, va_list ap)
{
	vfprintf(stdout, fmt, ap);
}

static llapi_log_callback_t llapi_error_callback = error_callback_default;
static llapi_log_callback_t llapi_info_callback = info_callback_default;


/* llapi_error will preserve errno */
void llapi_error(enum llapi_message_level level, int err, const char *fmt, ...)
{
	va_list	 args;
	int	 tmp_errno = errno;

	if ((level & LLAPI_MSG_MASK) > llapi_msg_level)
		return;

	va_start(args, fmt);
	llapi_error_callback(level, abs(err), fmt, args);
	va_end(args);
	errno = tmp_errno;
}

/* llapi_printf will preserve errno */
void llapi_printf(enum llapi_message_level level, const char *fmt, ...)
{
	va_list	 args;
	int	 tmp_errno = errno;

	if ((level & LLAPI_MSG_MASK) > llapi_msg_level)
		return;

	va_start(args, fmt);
	llapi_info_callback(level, 0, fmt, args);
	va_end(args);
	errno = tmp_errno;
}

/**
 * Set a custom error logging function. Passing in NULL will reset the logging
 * callback to its default value.
 *
 * This function returns the value of the old callback.
 */
llapi_log_callback_t llapi_error_callback_set(llapi_log_callback_t cb)
{
	llapi_log_callback_t	old = llapi_error_callback;

	if (cb != NULL)
		llapi_error_callback = cb;
	else
		llapi_error_callback = error_callback_default;

	return old;
}

/**
 * Set a custom info logging function. Passing in NULL will reset the logging
 * callback to its default value.
 *
 * This function returns the value of the old callback.
 */
llapi_log_callback_t llapi_info_callback_set(llapi_log_callback_t cb)
{
	llapi_log_callback_t	old = llapi_info_callback;

	if (cb != NULL)
		llapi_info_callback = cb;
	else
		llapi_info_callback = info_callback_default;

	return old;
}

/**
 * size_units is to be initialized (or zeroed) by caller.
 */
int llapi_parse_size(const char *optarg, unsigned long long *size,
		     unsigned long long *size_units, int bytes_spec)
{
	char *end;
	char *argbuf = (char *)optarg;
	unsigned long long frac = 0, frac_d = 1;

	if (strncmp(optarg, "-", 1) == 0)
		return -1;

	if (*size_units == 0)
		*size_units = 1;

	*size = strtoull(argbuf, &end, 0);
	if (end != NULL && *end == '.') {
		int i;

		argbuf = end + 1;
		frac = strtoull(argbuf, &end, 10);
		/* count decimal places */
		for (i = 0; i < (end - argbuf); i++)
			frac_d *= 10;
	}

	if (*end != '\0') {
		if ((*end == 'b') && *(end + 1) == '\0' &&
		    (*size & (~0ULL << (64 - 9))) == 0 &&
		    !bytes_spec) {
			*size_units = 1 << 9;
		} else if ((*end == 'b') &&
			   *(end + 1) == '\0' &&
			   bytes_spec) {
			*size_units = 1;
		} else if ((*end == 'k' || *end == 'K') &&
			   *(end + 1) == '\0' &&
			   (*size & (~0ULL << (64 - 10))) == 0) {
			*size_units = 1 << 10;
		} else if ((*end == 'm' || *end == 'M') &&
			   *(end + 1) == '\0' &&
			   (*size & (~0ULL << (64 - 20))) == 0) {
			*size_units = 1 << 20;
		} else if ((*end == 'g' || *end == 'G') &&
			   *(end + 1) == '\0' &&
			   (*size & (~0ULL << (64 - 30))) == 0) {
			*size_units = 1 << 30;
		} else if ((*end == 't' || *end == 'T') &&
			   *(end + 1) == '\0' &&
			   (*size & (~0ULL << (64 - 40))) == 0) {
			*size_units = 1ULL << 40;
		} else if ((*end == 'p' || *end == 'P') &&
			   *(end + 1) == '\0' &&
			   (*size & (~0ULL << (64 - 50))) == 0) {
			*size_units = 1ULL << 50;
		} else if ((*end == 'e' || *end == 'E') &&
			   *(end + 1) == '\0' &&
			   (*size & (~0ULL << (64 - 60))) == 0) {
			*size_units = 1ULL << 60;
		} else {
			return -1;
		}
	}
	*size = *size * *size_units + frac * *size_units / frac_d;

	return 0;
}

int obd_ioctl_pack(struct obd_ioctl_data *data, char **pbuf, int max_len)
{
	struct obd_ioctl_data *overlay;
	char *ptr;

	data->ioc_len = obd_ioctl_packlen(data);
	data->ioc_version = OBD_IOCTL_VERSION;

	if (*pbuf != NULL && data->ioc_len > max_len) {
		fprintf(stderr, "pbuf = %p, ioc_len = %u, max_len = %d\n",
			*pbuf, data->ioc_len, max_len);
		return -EINVAL;
	}

	if (*pbuf == NULL)
		*pbuf = malloc(data->ioc_len);

	if (*pbuf == NULL)
		return -ENOMEM;

	overlay = (struct obd_ioctl_data *)*pbuf;
	memcpy(*pbuf, data, sizeof(*data));

	ptr = overlay->ioc_bulk;
	if (data->ioc_inlbuf1) {
		memcpy(ptr, data->ioc_inlbuf1, data->ioc_inllen1);
		ptr += cfs_size_round(data->ioc_inllen1);
	}

	if (data->ioc_inlbuf2) {
		memcpy(ptr, data->ioc_inlbuf2, data->ioc_inllen2);
		ptr += cfs_size_round(data->ioc_inllen2);
	}

	if (data->ioc_inlbuf3) {
		memcpy(ptr, data->ioc_inlbuf3, data->ioc_inllen3);
		ptr += cfs_size_round(data->ioc_inllen3);
	}

	if (data->ioc_inlbuf4) {
		memcpy(ptr, data->ioc_inlbuf4, data->ioc_inllen4);
		ptr += cfs_size_round(data->ioc_inllen4);
	}

	return 0;
}

int obd_ioctl_unpack(struct obd_ioctl_data *data, char *pbuf, int max_len)
{
	struct obd_ioctl_data *overlay;
	char *ptr;

	if (pbuf == NULL)
		return 1;

	overlay = (struct obd_ioctl_data *)pbuf;

	/* Preserve the caller's buffer pointers */
	overlay->ioc_inlbuf1 = data->ioc_inlbuf1;
	overlay->ioc_inlbuf2 = data->ioc_inlbuf2;
	overlay->ioc_inlbuf3 = data->ioc_inlbuf3;
	overlay->ioc_inlbuf4 = data->ioc_inlbuf4;

	memcpy(data, pbuf, sizeof(*data));

	ptr = overlay->ioc_bulk;
	if (data->ioc_inlbuf1) {
		memcpy(data->ioc_inlbuf1, ptr, data->ioc_inllen1);
		ptr += cfs_size_round(data->ioc_inllen1);
	}

	if (data->ioc_inlbuf2) {
		memcpy(data->ioc_inlbuf2, ptr, data->ioc_inllen2);
		ptr += cfs_size_round(data->ioc_inllen2);
	}

	if (data->ioc_inlbuf3) {
		memcpy(data->ioc_inlbuf3, ptr, data->ioc_inllen3);
		ptr += cfs_size_round(data->ioc_inllen3);
	}

	if (data->ioc_inlbuf4) {
		memcpy(data->ioc_inlbuf4, ptr, data->ioc_inllen4);
		ptr += cfs_size_round(data->ioc_inllen4);
	}

	return 0;
}

/* XXX: llapi_xxx() functions return negative values upon failure */

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
	if (!llapi_stripe_size_is_aligned(stripe_size)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: bad stripe_size %llu, "
				"must be an even multiple of %d bytes",
				stripe_size, page_size);
		return rc;
	}
	if (!llapi_stripe_index_is_valid(stripe_offset)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: bad stripe offset %d",
				stripe_offset);
		return rc;
	}
	if (!llapi_stripe_count_is_valid(stripe_count)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: bad stripe count %d",
				stripe_count);
		return rc;
	}
	if (llapi_stripe_size_is_too_big(stripe_size)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
				"warning: stripe size 4G or larger "
				"is not currently supported and would wrap");
		return rc;
	}
	return 0;
}

/*
 * Trim a trailing newline from a string, if it exists.
 */
int llapi_chomp_string(char *buf)
{
	if (!buf || !*buf)
		return 0;

	while (buf[1])
		buf++;

	if (*buf != '\n')
		return 0;

	*buf = '\0';
	return '\n';
}

/*
 * Wrapper to grab parameter settings for lov.*-clilov-*.* values
 */
static int get_param_lov(const char *path, const char *param,
			 char *buf, size_t buf_size)
{
	struct obd_uuid uuid;
	int rc;

	rc = llapi_file_get_lov_uuid(path, &uuid);
	if (rc != 0)
		return rc;

	return get_lustre_param_value("lov", uuid.uuid, FILTER_BY_EXACT, param,
				      buf, buf_size);
}

/*
 * Wrapper to grab parameter settings for lmv.*-clilov-*.* values
 */
static int get_param_lmv(const char *path, const char *param,
			 char *buf, size_t buf_size)
{
	struct obd_uuid uuid;
	int rc;

	rc = llapi_file_get_lmv_uuid(path, &uuid);
	if (rc != 0)
		return rc;

	return get_lustre_param_value("lmv", uuid.uuid, FILTER_BY_EXACT, param,
			       buf, buf_size);
}

static int get_mds_md_size(const char *path)
{
	char buf[PATH_MAX], inst[PATH_MAX];
	int md_size = lov_user_md_size(LOV_MAX_STRIPE_COUNT, LOV_USER_MAGIC_V3);
	int rc;

	rc = llapi_getname(path, inst, sizeof(inst));
	if (rc != 0)
		return md_size;

	/* Get the max ea size from llite parameters. */
	rc = get_lustre_param_value("llite", inst, FILTER_BY_EXACT,
				    "max_easize", buf, sizeof(buf));
	if (rc != 0)
		return md_size;

	rc = atoi(buf);

	return rc > 0 ? rc : md_size;
}

int llapi_get_agent_uuid(char *path, char *buf, size_t bufsize)
{
	return get_param_lmv(path, "uuid", buf, bufsize);
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
	char buffer[PATH_MAX];
	size_t len = 0;
	glob_t param;
	FILE *fd;
	int rc;

	/* You need one or the other */
	if (poolname == NULL && fsname == NULL)
		return -EINVAL;

	if (ostname != NULL)
		len = strlen(ostname);

	if (poolname == NULL && len == 0)
		return -EINVAL;

	/* Search by poolname and fsname if is not NULL */
	if (poolname != NULL) {
		rc = poolpath(&param, fsname, NULL);
		if (rc == 0) {
			snprintf(buffer, sizeof(buffer), "%s/%s",
				 param.gl_pathv[0], poolname);
		}
	} else if (fsname != NULL) {
		rc = get_lustre_param_path("lov", fsname,
					   FILTER_BY_FS_NAME,
					   "target_obd", &param);
		if (rc == 0) {
			strncpy(buffer, param.gl_pathv[0],
				sizeof(buffer));
		}
	} else {
		return -EINVAL;
	}
	cfs_free_param_data(&param);
	if (rc)
		return rc;

        fd = fopen(buffer, "r");
        if (fd == NULL)
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

/**
 * Open a Lustre file.
 *
 * \param name     the name of the file to be opened
 * \param flags    access mode, see flags in open(2)
 * \param mode     permission of the file if it is created, see mode in open(2)
 * \param param    stripe pattern of the newly created file
 *
 * \retval         file descriptor of opened file
 * \retval         negative errno on failure
 */
int llapi_file_open_param(const char *name, int flags, mode_t mode,
			  const struct llapi_stripe_param *param)
{
	char fsname[MAX_OBD_NAME + 1] = { 0 };
	char *pool_name = param->lsp_pool;
	struct lov_user_md *lum = NULL;
	size_t lum_size = sizeof(*lum);
	int fd, rc;

	/* Make sure we are on a Lustre file system */
	rc = llapi_search_fsname(name, fsname);
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "'%s' is not on a Lustre filesystem",
			    name);
		return rc;
	}

	/* Check if the stripe pattern is sane. */
	rc = llapi_stripe_limit_check(param->lsp_stripe_size,
				      param->lsp_stripe_offset,
				      param->lsp_stripe_count,
				      param->lsp_stripe_pattern);
	if (rc != 0)
		return rc;

	/* Make sure we have a good pool */
	if (pool_name != NULL) {
		/* in case user gives the full pool name <fsname>.<poolname>,
		 * strip the fsname */
		char *ptr = strchr(pool_name, '.');
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
			char *err = rc == 0 ? "has no OSTs" : "does not exist";

			llapi_err_noerrno(LLAPI_MSG_ERROR, "pool '%s.%s' %s",
					  fsname, pool_name, err);
			return -EINVAL;
		}

		lum_size = sizeof(struct lov_user_md_v3);
	}

	/* sanity check of target list */
	if (param->lsp_is_specific) {
		char ostname[MAX_OBD_NAME + 1];
		bool found = false;
		int i;

		for (i = 0; i < param->lsp_stripe_count; i++) {
			snprintf(ostname, sizeof(ostname), "%s-OST%04x_UUID",
				 fsname, param->lsp_osts[i]);
			rc = llapi_search_ost(fsname, pool_name, ostname);
			if (rc <= 0) {
				if (rc == 0)
					rc = -ENODEV;

				llapi_error(LLAPI_MSG_ERROR, rc,
					    "%s: cannot find OST %s in %s",
					    __func__, ostname,
					    pool_name != NULL ?
					    "pool" : "system");
				return rc;
			}

			/* Make sure stripe offset is in OST list. */
			if (param->lsp_osts[i] == param->lsp_stripe_offset)
				found = true;
		}
		if (!found) {
			llapi_error(LLAPI_MSG_ERROR, -EINVAL,
				    "%s: stripe offset '%d' is not in the "
				    "target list",
				    __func__, param->lsp_stripe_offset);
			return -EINVAL;
		}

		lum_size = lov_user_md_size(param->lsp_stripe_count,
					    LOV_USER_MAGIC_SPECIFIC);
	}

	lum = calloc(1, lum_size);
	if (lum == NULL)
		return -ENOMEM;

retry_open:
	fd = open(name, flags | O_LOV_DELAY_CREATE, mode);
	if (fd < 0) {
		if (errno == EISDIR && !(flags & O_DIRECTORY)) {
			flags = O_DIRECTORY | O_RDONLY;
			goto retry_open;
		}
	}

	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "unable to open '%s'", name);
		free(lum);
		return rc;
	}

	/*  Initialize IOCTL striping pattern structure */
	lum->lmm_magic = LOV_USER_MAGIC_V1;
	lum->lmm_pattern = param->lsp_stripe_pattern;
	lum->lmm_stripe_size = param->lsp_stripe_size;
	lum->lmm_stripe_count = param->lsp_stripe_count;
	lum->lmm_stripe_offset = param->lsp_stripe_offset;
	if (pool_name != NULL) {
		struct lov_user_md_v3 *lumv3 = (void *)lum;

		lumv3->lmm_magic = LOV_USER_MAGIC_V3;
		strncpy(lumv3->lmm_pool_name, pool_name, LOV_MAXPOOLNAME);
	}
	if (param->lsp_is_specific) {
		struct lov_user_md_v3 *lumv3 = (void *)lum;
		int i;

		lumv3->lmm_magic = LOV_USER_MAGIC_SPECIFIC;
		if (pool_name == NULL) {
			/* LOV_USER_MAGIC_SPECIFIC uses v3 format plus specified
			 * OST list, therefore if pool is not specified we have
			 * to pack a null pool name for placeholder. */
			memset(lumv3->lmm_pool_name, 0, LOV_MAXPOOLNAME);
		}

		for (i = 0; i < param->lsp_stripe_count; i++)
			lumv3->lmm_objects[i].l_ost_idx = param->lsp_osts[i];
	}

	if (ioctl(fd, LL_IOC_LOV_SETSTRIPE, lum) != 0) {
		char *errmsg = "stripe already set";

		rc = -errno;
		if (errno != EEXIST && errno != EALREADY)
			errmsg = strerror(errno);

		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "error on ioctl %#jx for '%s' (%d): %s",
				  (uintmax_t)LL_IOC_LOV_SETSTRIPE, name, fd,
				  errmsg);

		close(fd);
		fd = rc;
	}

	free(lum);

	return fd;
}

int llapi_file_open_pool(const char *name, int flags, int mode,
			 unsigned long long stripe_size, int stripe_offset,
			 int stripe_count, int stripe_pattern, char *pool_name)
{
	const struct llapi_stripe_param param = {
		.lsp_stripe_size = stripe_size,
		.lsp_stripe_count = stripe_count,
		.lsp_stripe_pattern = stripe_pattern,
		.lsp_stripe_offset = stripe_offset,
		.lsp_pool = pool_name
	};
	return llapi_file_open_param(name, flags, mode, &param);
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

int llapi_dir_set_default_lmv_stripe(const char *name, int stripe_offset,
				     int stripe_count, int stripe_pattern,
				     const char *pool_name)
{
	struct lmv_user_md	lum = { 0 };
	int			fd;
	int			rc = 0;

	lum.lum_magic = LMV_USER_MAGIC;
	lum.lum_stripe_offset = stripe_offset;
	lum.lum_stripe_count = stripe_count;
	lum.lum_hash_type = stripe_pattern;
	if (pool_name != NULL) {
		if (strlen(pool_name) >= sizeof(lum.lum_pool_name)) {
			llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "error LL_IOC_LMV_SET_DEFAULT_STRIPE '%s'"
				  ": too large pool name: %s", name, pool_name);
			return -E2BIG;
		}
		strncpy(lum.lum_pool_name, pool_name,
			sizeof(lum.lum_pool_name));
	}

	fd = open(name, O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "unable to open '%s'", name);
		return rc;
	}

	rc = ioctl(fd, LL_IOC_LMV_SET_DEFAULT_STRIPE, &lum);
	if (rc < 0) {
		char *errmsg = "stripe already set";
		rc = -errno;
		if (errno != EEXIST && errno != EALREADY)
			errmsg = strerror(errno);

		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "error on LL_IOC_LMV_SETSTRIPE '%s' (%d): %s",
				  name, fd, errmsg);
	}
	close(fd);
	return rc;
}

int llapi_dir_create_pool(const char *name, int mode, int stripe_offset,
			  int stripe_count, int stripe_pattern,
			  const char *pool_name)
{
	struct lmv_user_md lmu = { 0 };
	struct obd_ioctl_data data = { 0 };
	char rawbuf[8192];
	char *buf = rawbuf;
	char *dirpath = NULL;
	char *namepath = NULL;
	char *dir;
	char *filename;
	int fd = -1;
	int rc;

	dirpath = strdup(name);
	namepath = strdup(name);
	if (!dirpath || !namepath)
		return -ENOMEM;

	lmu.lum_magic = LMV_USER_MAGIC;
	lmu.lum_stripe_offset = stripe_offset;
	lmu.lum_stripe_count = stripe_count;
	lmu.lum_hash_type = stripe_pattern;
	if (pool_name != NULL) {
		if (strlen(pool_name) > LOV_MAXPOOLNAME) {
			llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "error LL_IOC_LMV_SETSTRIPE '%s' : too large"
				  "pool name: %s", name, pool_name);
			rc = -E2BIG;
			goto out;
		}
		memcpy(lmu.lum_pool_name, pool_name, strlen(pool_name));
	}

	filename = basename(namepath);
	dir = dirname(dirpath);

	data.ioc_inlbuf1 = (char *)filename;
	data.ioc_inllen1 = strlen(filename) + 1;
	data.ioc_inlbuf2 = (char *)&lmu;
	data.ioc_inllen2 = sizeof(struct lmv_user_md);
	data.ioc_type = mode;
	rc = obd_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: LL_IOC_LMV_SETSTRIPE pack failed '%s'.",
			    name);
		goto out;
	}

	fd = open(dir, O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "unable to open '%s'", name);
		goto out;
	}

	if (ioctl(fd, LL_IOC_LMV_SETSTRIPE, buf)) {
		char *errmsg = "stripe already set";
		rc = -errno;
		if (errno != EEXIST && errno != EALREADY)
			errmsg = strerror(errno);

		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "error on LL_IOC_LMV_SETSTRIPE '%s' (%d): %s",
				  name, fd, errmsg);
	}
	close(fd);
out:
	free(dirpath);
	free(namepath);
	return rc;
}

int llapi_direntry_remove(char *dname)
{
	char *dirpath = NULL;
	char *namepath = NULL;
	char *dir;
	char *filename;
	int fd = -1;
	int rc = 0;

	dirpath = strdup(dname);
	namepath = strdup(dname);
	if (!dirpath || !namepath)
		return -ENOMEM;

	filename = basename(namepath);

	dir = dirname(dirpath);

	fd = open(dir, O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "unable to open '%s'",
			    filename);
		goto out;
	}

	if (ioctl(fd, LL_IOC_REMOVE_ENTRY, filename)) {
		char *errmsg = strerror(errno);
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "error on ioctl %#jx for '%s' (%d): %s",
				  (uintmax_t)LL_IOC_LMV_SETSTRIPE, filename,
				  fd, errmsg);
	}
out:
	free(dirpath);
	free(namepath);
	if (fd != -1)
		close(fd);
	return rc;
}

/*
 * Find the fsname, the full path, and/or an open fd.
 * Either the fsname or path must not be NULL
 */
int get_root_path(int want, char *fsname, int *outfd, char *path, int index)
{
	struct mntent mnt;
	char buf[PATH_MAX], mntdir[PATH_MAX];
	char *ptr, *ptr_end;
	FILE *fp;
	int idx = 0, len = 0, mntlen, fd;
	int rc = -ENODEV;

        /* get the mount point */
	fp = setmntent(PROC_MOUNTS, "r");
	if (fp == NULL) {
		rc = -EIO;
		llapi_error(LLAPI_MSG_ERROR, rc,
                            "setmntent(%s) failed", PROC_MOUNTS);
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
		ptr = strchr(mnt.mnt_fsname, '/');
		while (ptr && *ptr == '/')
			ptr++;
		/* thanks to the call to llapi_is_lustre_mnt() above,
		 * we are sure that mnt.mnt_fsname contains ":/",
		 * so ptr should never be NULL */
		if (ptr == NULL)
			continue;
		ptr_end = ptr;
		while (*ptr_end != '/' && *ptr_end != '\0')
			ptr_end++;

		/* Check the fsname for a match, if given */
                if (!(want & WANT_FSNAME) && fsname != NULL &&
		    (strlen(fsname) > 0) &&
		    (strncmp(ptr, fsname, ptr_end - ptr) != 0))
                        continue;

                /* If the path isn't set return the first one we find */
		if (path == NULL || strlen(path) == 0) {
			strncpy(mntdir, mnt.mnt_dir, strlen(mnt.mnt_dir));
			mntdir[strlen(mnt.mnt_dir)] = '\0';
			if ((want & WANT_FSNAME) && fsname != NULL) {
				strncpy(fsname, ptr, ptr_end - ptr);
				fsname[ptr_end - ptr] = '\0';
			}
			rc = 0;
			break;
		/* Otherwise find the longest matching path */
		} else if ((strlen(path) >= mntlen) && (mntlen >= len) &&
			   (strncmp(mnt.mnt_dir, path, mntlen) == 0)) {
			strncpy(mntdir, mnt.mnt_dir, strlen(mnt.mnt_dir));
			mntdir[strlen(mnt.mnt_dir)] = '\0';
			len = mntlen;
			if ((want & WANT_FSNAME) && fsname != NULL) {
				strncpy(fsname, ptr, ptr_end - ptr);
				fsname[ptr_end - ptr] = '\0';
			}
			rc = 0;
		}
	}
	endmntent(fp);

	/* Found it */
	if (rc == 0) {
		if ((want & WANT_PATH) && path != NULL) {
			strncpy(path, mntdir, strlen(mntdir));
			path[strlen(mntdir)] = '\0';
		}
		if (want & WANT_FD) {
			fd = open(mntdir, O_RDONLY | O_DIRECTORY | O_NONBLOCK);
			if (fd < 0) {
				rc = -errno;
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "error opening '%s'", mntdir);

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
 * See function lfs_osts in lfs.c for an example of the index use.
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

/* Given a path, find the corresponding Lustre fsname */
int llapi_search_fsname(const char *pathname, char *fsname)
{
        char *path;
        int rc;

        path = realpath(pathname, NULL);
        if (path == NULL) {
		char buf[PATH_MAX], *ptr;

		buf[0] = '\0';
		if (pathname[0] != '/') {
			/* Need an absolute path, but realpath() only works for
			 * pathnames that actually exist.  We go through the
			 * extra hurdle of dirname(getcwd() + pathname) in
			 * case the relative pathname contains ".." in it. */
			if (getcwd(buf, sizeof(buf) - 2) == NULL)
				return -errno;
			rc = strlcat(buf, "/", sizeof(buf));
			if (rc >= sizeof(buf))
				return -E2BIG;
		}
		rc = strlcat(buf, pathname, sizeof(buf));
		if (rc >= sizeof(buf))
			return -E2BIG;
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

int llapi_search_rootpath(char *pathname, const char *fsname)
{
	return get_root_path(WANT_PATH, (char *)fsname, NULL, pathname, -1);
}

int llapi_getname(const char *path, char *buf, size_t size)
{
        struct obd_uuid uuid_buf;
        char *uuid = uuid_buf.uuid;
        int rc, nr;

        memset(&uuid_buf, 0, sizeof(uuid_buf));
        rc = llapi_file_get_lov_uuid(path, &uuid_buf);
        if (rc)
                return rc;

        /* We want to turn lustre-clilov-ffff88002738bc00 into
         * lustre-ffff88002738bc00. */

        nr = snprintf(buf, size, "%.*s-%s",
                      (int) (strlen(uuid) - 24), uuid,
                      uuid + strlen(uuid) - 16);

        if (nr >= size)
                rc = -ENAMETOOLONG;

        return rc;
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
	char fsname[PATH_MAX];
	char *pool, *tmp;
	glob_t pathname;
	char buf[PATH_MAX];
	FILE *fd;
	int rc = 0;
	int nb_entries = 0;
	int used = 0;

	/* name is FSNAME.POOLNAME */
	if (strlen(poolname) >= sizeof(fsname))
		return -EOVERFLOW;
	strlcpy(fsname, poolname, sizeof(fsname));
	pool = strchr(fsname, '.');
	if (pool == NULL)
		return -EINVAL;

	*pool = '\0';
	pool++;

	rc = poolpath(&pathname, fsname, NULL);
	if (rc != 0) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Lustre filesystem '%s' not found",
			    fsname);
		return rc;
	}

	llapi_printf(LLAPI_MSG_NORMAL, "Pool: %s.%s\n", fsname, pool);
	rc = snprintf(buf, sizeof(buf), "%s/%s", pathname.gl_pathv[0], pool);
	cfs_free_param_data(&pathname);
	if (rc >= sizeof(buf))
		return -EOVERFLOW;
	fd = fopen(buf, "r");
	if (fd == NULL) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot open %s", buf);
		return rc;
	}

        rc = 0;
        while (fgets(buf, sizeof(buf), fd) != NULL) {
                if (nb_entries >= list_size) {
                        rc = -EOVERFLOW;
                        break;
                }
		buf[sizeof(buf) - 1] = '\0';
                /* remove '\n' */
                tmp = strchr(buf, '\n');
                if (tmp != NULL)
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
	char rname[PATH_MAX];
	glob_t pathname;
	char *fsname;
        char *ptr;
        DIR *dir;
	struct dirent *pool;
        int rc = 0;
        unsigned int nb_entries = 0;
        unsigned int used = 0;
        unsigned int i;

	/* initialize output array */
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

		fsname = strdup(rname);
		if (!fsname)
			return -ENOMEM;

		rc = poolpath(&pathname, NULL, rname);
	} else {
		/* name is FSNAME */
		fsname = strdup(name);
		if (!fsname)
			return -ENOMEM;
		rc = poolpath(&pathname, fsname, NULL);
	}
	if (rc != 0) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Lustre filesystem '%s' not found", name);
		goto free_path;
	}

	llapi_printf(LLAPI_MSG_NORMAL, "Pools from %s:\n", fsname);
	dir = opendir(pathname.gl_pathv[0]);
	if (dir == NULL) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Could not open pool list for '%s'",
			    name);
		goto free_path;
	}

	do {
		errno = 0;
		pool = readdir(dir);
		if (pool == NULL) {
			rc = -errno;
			goto free_dir;
		}

                /* ignore . and .. */
		if (!strcmp(pool->d_name, ".") || !strcmp(pool->d_name, ".."))
                        continue;

                /* check output bounds */
		if (nb_entries >= list_size) {
			rc = -EOVERFLOW;
			goto free_dir;
		}

                /* +2 for '.' and final '\0' */
		if (used + strlen(pool->d_name) + strlen(fsname) + 2
		    > buffer_size) {
			rc = -EOVERFLOW;
			goto free_dir;
		}

		sprintf(buffer + used, "%s.%s", fsname, pool->d_name);
                poollist[nb_entries] = buffer + used;
		used += strlen(pool->d_name) + strlen(fsname) + 2;
                nb_entries++;
	} while (1);

free_dir:
	if (rc)
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Error reading pool list for '%s'", name);
	closedir(dir);
free_path:
	cfs_free_param_data(&pathname);
	if (fsname)
		free(fsname);
	return rc != 0 ? rc : nb_entries;
}

/* wrapper for lfs.c and obd.c */
int llapi_poollist(const char *name)
{
	/* list of pool names (assume that pool count is smaller
	   than OST count) */
	char **list, *buffer = NULL, *fsname = (char *)name;
	char *poolname = NULL, *tmp = NULL, data[16];
	enum param_filter type = FILTER_BY_PATH;
	int obdcount, bufsize, rc, nb, i;

	if (name == NULL)
		return -EINVAL;

	if (name[0] != '/') {
		fsname = strdup(name);
		if (fsname == NULL)
			return -ENOMEM;

		poolname = strchr(fsname, '.');
		if (poolname)
			*poolname = '\0';
		type = FILTER_BY_FS_NAME;
	}

	rc = get_lustre_param_value("lov", fsname, type, "numobd",
				    data, sizeof(data));
	if (rc < 0)
		goto err;
	obdcount = atoi(data);

        /* Allocate space for each fsname-OST0000_UUID, 1 per OST,
         * and also an array to store the pointers for all that
         * allocated space. */
retry_get_pools:
        bufsize = sizeof(struct obd_uuid) * obdcount;
        buffer = realloc(tmp, bufsize + sizeof(*list) * obdcount);
        if (buffer == NULL) {
                rc = -ENOMEM;
                goto err;
        }
        list = (char **) (buffer + bufsize);

        if (!poolname) {
                /* name is a path or fsname */
                nb = llapi_get_poollist(name, list, obdcount,
                                        buffer, bufsize);
        } else {
                /* name is a pool name (<fsname>.<poolname>) */
                nb = llapi_get_poolmembers(name, list, obdcount,
                                           buffer, bufsize);
        }

        if (nb == -EOVERFLOW) {
                obdcount *= 2;
                tmp = buffer;
                goto retry_get_pools;
        }

        for (i = 0; i < nb; i++)
                llapi_printf(LLAPI_MSG_NORMAL, "%s\n", list[i]);
        rc = (nb < 0 ? nb : 0);
err:
        if (buffer)
                free(buffer);
	if (fsname != NULL && type == FILTER_BY_FS_NAME)
		free(fsname);
	return rc;
}

typedef int (semantic_func_t)(char *path, DIR *parent, DIR **d,
			      void *data, struct dirent64 *de);

#define OBD_NOT_FOUND           (-1)

static int common_param_init(struct find_param *param, char *path)
{
	int lum_size = get_mds_md_size(path);

	if (lum_size < PATH_MAX + 1)
		lum_size = PATH_MAX + 1;

	param->fp_lum_size = lum_size;
	param->fp_lmd = calloc(1, sizeof(lstat_t) + param->fp_lum_size);
	if (param->fp_lmd == NULL) {
		llapi_error(LLAPI_MSG_ERROR, -ENOMEM,
			    "error: allocation of %zu bytes for ioctl",
			    sizeof(lstat_t) + param->fp_lum_size);
		return -ENOMEM;
	}

	param->fp_lmv_stripe_count = 256;
	param->fp_lmv_md = calloc(1,
				  lmv_user_md_size(param->fp_lmv_stripe_count,
						   LMV_MAGIC_V1));
	if (param->fp_lmv_md == NULL) {
		llapi_error(LLAPI_MSG_ERROR, -ENOMEM,
			    "error: allocation of %d bytes for ioctl",
			    lmv_user_md_size(param->fp_lmv_stripe_count,
					     LMV_MAGIC_V1));
		return -ENOMEM;
	}

	param->fp_got_uuids = 0;
	param->fp_obd_indexes = NULL;
	param->fp_obd_index = OBD_NOT_FOUND;
	if (!param->fp_migrate)
		param->fp_mdt_index = OBD_NOT_FOUND;
	return 0;
}

static void find_param_fini(struct find_param *param)
{
	if (param->fp_obd_indexes)
		free(param->fp_obd_indexes);

	if (param->fp_lmd)
		free(param->fp_lmd);

	if (param->fp_lmv_md)
		free(param->fp_lmv_md);
}

static int cb_common_fini(char *path, DIR *parent, DIR **dirp, void *data,
			  struct dirent64 *de)
{
	struct find_param *param = data;
	param->fp_depth--;

	return 0;
}

/* set errno upon failure */
static DIR *opendir_parent(const char *path)
{
	char *path_copy;
	char *parent_path;
	DIR *parent;

	path_copy = strdup(path);
	if (path_copy == NULL)
		return NULL;

	parent_path = dirname(path_copy);
	parent = opendir(parent_path);
	free(path_copy);

	return parent;
}

static int cb_get_dirstripe(char *path, DIR *d, struct find_param *param)
{
	int ret;

again:
	param->fp_lmv_md->lum_stripe_count = param->fp_lmv_stripe_count;
	if (param->fp_get_default_lmv)
		param->fp_lmv_md->lum_magic = LMV_USER_MAGIC;
	else
		param->fp_lmv_md->lum_magic = LMV_MAGIC_V1;

	ret = ioctl(dirfd(d), LL_IOC_LMV_GETSTRIPE, param->fp_lmv_md);
	if (errno == E2BIG && ret != 0) {
		int stripe_count;
		int lmv_size;

		stripe_count = (__u32)param->fp_lmv_md->lum_stripe_count;
		if (stripe_count <= param->fp_lmv_stripe_count)
			return ret;

		free(param->fp_lmv_md);
		param->fp_lmv_stripe_count = stripe_count;
		lmv_size = lmv_user_md_size(stripe_count, LMV_MAGIC_V1);
		param->fp_lmv_md = malloc(lmv_size);
		if (param->fp_lmv_md == NULL) {
			llapi_error(LLAPI_MSG_ERROR, -ENOMEM,
				    "error: allocation of %d bytes for ioctl",
				    lmv_user_md_size(param->fp_lmv_stripe_count,
						     LMV_MAGIC_V1));
			return -ENOMEM;
		}
		goto again;
	}
	return ret;
}

static int get_lmd_info(char *path, DIR *parent, DIR *dir,
                 struct lov_user_mds_data *lmd, int lumlen)
{
        lstat_t *st = &lmd->lmd_st;
        int ret = 0;

        if (parent == NULL && dir == NULL)
                return -EINVAL;

        if (dir) {
                ret = ioctl(dirfd(dir), LL_IOC_MDC_GETINFO, (void *)lmd);
        } else if (parent) {
		char *fname = strrchr(path, '/');

		/* To avoid opening, locking, and closing each file on the
		 * client if that is not needed. The GETFILEINFO ioctl can
		 * be done on the patent dir with a single open for all
		 * files in that directory, and it also doesn't pollute the
		 * client dcache with millions of dentries when traversing
		 * a large filesystem.  */
		fname = (fname == NULL ? path : fname + 1);
		/* retrieve needed file info */
		strlcpy((char *)lmd, fname, lumlen);
		ret = ioctl(dirfd(parent), IOC_MDC_GETFILEINFO, (void *)lmd);
        }

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
                        }
                } else if (errno == ENOENT) {
                        ret = -errno;
                        llapi_error(LLAPI_MSG_WARN, ret,
                                    "warning: %s: %s does not exist",
                                    __func__, path);
                } else if (errno != EISDIR) {
                        ret = -errno;
                        llapi_error(LLAPI_MSG_ERROR, ret,
                                    "%s ioctl failed for %s.",
                                    dir ? "LL_IOC_MDC_GETINFO" :
                                    "IOC_MDC_GETFILEINFO", path);
		} else {
			ret = -errno;
			llapi_error(LLAPI_MSG_ERROR, ret,
				 "error: %s: IOC_MDC_GETFILEINFO failed for %s",
				   __func__, path);
		}
	}
	return ret;
}

static int llapi_semantic_traverse(char *path, int size, DIR *parent,
				   semantic_func_t sem_init,
				   semantic_func_t sem_fini, void *data,
				   struct dirent64 *de)
{
	struct find_param *param = (struct find_param *)data;
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
		if (!p) {
			ret = -errno;
			goto out;
		}
        }

	if (sem_init && (ret = sem_init(path, parent ?: p, &d, data, de)))
		goto err;

	if (d == NULL)
		goto out;

	while ((dent = readdir64(d)) != NULL) {
		int rc;

                if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
                        continue;

                /* Don't traverse .lustre directory */
                if (!(strcmp(dent->d_name, dot_lustre_name)))
                        continue;

                path[len] = 0;
                if ((len + dent->d_reclen + 2) > size) {
                        llapi_err_noerrno(LLAPI_MSG_ERROR,
                                          "error: %s: string buffer is too small",
                                          __func__);
                        break;
                }
                strcat(path, "/");
                strcat(path, dent->d_name);

                if (dent->d_type == DT_UNKNOWN) {
			lstat_t *st = &param->fp_lmd->lmd_st;

			rc = get_lmd_info(path, d, NULL, param->fp_lmd,
					   param->fp_lum_size);
			if (rc == 0)
				dent->d_type = IFTODT(st->st_mode);
			else if (ret == 0)
				ret = rc;

			if (rc == -ENOENT)
				continue;
		}
                switch (dent->d_type) {
                case DT_UNKNOWN:
                        llapi_err_noerrno(LLAPI_MSG_ERROR,
                                          "error: %s: '%s' is UNKNOWN type %d",
                                          __func__, dent->d_name, dent->d_type);
                        break;
		case DT_DIR:
			rc = llapi_semantic_traverse(path, size, d, sem_init,
						      sem_fini, data, dent);
			if (rc != 0 && ret == 0)
				ret = rc;
			break;
		default:
			rc = 0;
			if (sem_init) {
				rc = sem_init(path, d, NULL, data, dent);
				if (rc < 0 && ret == 0)
					ret = rc;
			}
			if (sem_fini && rc == 0)
				sem_fini(path, d, NULL, data, dent);
                }
        }

out:
        path[len] = 0;

	if (sem_fini)
		sem_fini(path, parent, &d, data, de);
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

	strlcpy(buf, path, PATH_MAX + 1);
        ret = common_param_init(param, buf);
        if (ret)
                goto out;

	param->fp_depth = 0;

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

int llapi_file_fget_lmv_uuid(int fd, struct obd_uuid *lov_name)
{
        int rc = ioctl(fd, OBD_IOC_GETMDNAME, lov_name);
        if (rc) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "error: can't get lmv name.");
        }
        return rc;
}

int llapi_file_get_lov_uuid(const char *path, struct obd_uuid *lov_uuid)
{
	int fd, rc;

	fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error opening %s", path);
		return rc;
	}

	rc = llapi_file_fget_lov_uuid(fd, lov_uuid);

	close(fd);
	return rc;
}

int llapi_file_get_lmv_uuid(const char *path, struct obd_uuid *lov_uuid)
{
	int fd, rc;

	fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error opening %s", path);
		return rc;
	}

	rc = llapi_file_fget_lmv_uuid(fd, lov_uuid);

	close(fd);
	return rc;
}

enum tgt_type {
        LOV_TYPE = 1,
        LMV_TYPE
};

/*
 * If uuidp is NULL, return the number of available obd uuids.
 * If uuidp is non-NULL, then it will return the uuids of the obds. If
 * there are more OSTs than allocated to uuidp, then an error is returned with
 * the ost_count set to number of available obd uuids.
 */
static int llapi_get_target_uuids(int fd, struct obd_uuid *uuidp,
                                  int *ost_count, enum tgt_type type)
{
	char buf[PATH_MAX], format[32];
	int rc = 0, index = 0;
	struct obd_uuid name;
	glob_t param;
	FILE *fp;

	/* Get the lov name */
	if (type == LOV_TYPE)
		rc = llapi_file_fget_lov_uuid(fd, &name);
	else
		rc = llapi_file_fget_lmv_uuid(fd, &name);
	if (rc != 0)
		return rc;

	/* Now get the ost uuids */
	rc = get_lustre_param_path(type == LOV_TYPE ? "lov" : "lmv", name.uuid,
				   FILTER_BY_EXACT, "target_obd", &param);
	if (rc != 0)
		return -ENOENT;

	fp = fopen(param.gl_pathv[0], "r");
	if (fp == NULL) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: opening '%s'",
			    param.gl_pathv[0]);
		goto free_param;
	}

	snprintf(format, sizeof(format),
		 "%%d: %%%zus", sizeof(uuidp[0].uuid) - 1);
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (uuidp && (index < *ost_count)) {
			if (sscanf(buf, format, &index, uuidp[index].uuid) < 2)
                                break;
                }
                index++;
        }

        fclose(fp);

        if (uuidp && (index > *ost_count))
                rc = -EOVERFLOW;

	*ost_count = index;
free_param:
	cfs_free_param_data(&param);
	return rc;
}

int llapi_lov_get_uuids(int fd, struct obd_uuid *uuidp, int *ost_count)
{
        return llapi_get_target_uuids(fd, uuidp, ost_count, LOV_TYPE);
}

int llapi_get_obd_count(char *mnt, int *count, int is_mdt)
{
	int root;
	int rc;

	root = open(mnt, O_RDONLY | O_DIRECTORY);
	if (root < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "open %s failed", mnt);
		return rc;
	}

	*count = is_mdt;
	rc = ioctl(root, LL_IOC_GETOBDCOUNT, count);
	if (rc < 0)
		rc = -errno;

	close(root);
	return rc;
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

/* Here, param->fp_obd_uuid points to a single obduuid, the index of which is
 * returned in param->fp_obd_index */
static int setup_obd_uuid(int fd, char *dname, struct find_param *param)
{
	struct obd_uuid obd_uuid;
	char buf[PATH_MAX];
	glob_t param_data;
	char format[32];
	int rc = 0;
	FILE *fp;

	if (param->fp_got_uuids)
		return rc;

	/* Get the lov/lmv name */
	if (param->fp_get_lmv)
		rc = llapi_file_fget_lmv_uuid(fd, &obd_uuid);
	else
		rc = llapi_file_fget_lov_uuid(fd, &obd_uuid);
	if (rc) {
		if (rc != -ENOTTY) {
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "error: can't get %s name: %s",
				    param->fp_get_lmv ? "lmv" : "lov",
				    dname);
		} else {
			rc = 0;
		}
		return rc;
	}

	param->fp_got_uuids = 1;

	/* Now get the ost uuids */
	rc = get_lustre_param_path(param->fp_get_lmv ? "lmv" : "lov",
				   obd_uuid.uuid, FILTER_BY_EXACT,
				   "target_obd", &param_data);
	if (rc != 0)
		return -ENOENT;

	fp = fopen(param_data.gl_pathv[0], "r");
	if (fp == NULL) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: opening '%s'",
			    param_data.gl_pathv[0]);
		goto free_param;
	}

	if (!param->fp_obd_uuid && !param->fp_quiet && !param->fp_obds_printed)
		llapi_printf(LLAPI_MSG_NORMAL, "%s:\n",
			     param->fp_get_lmv ? "MDTS" : "OBDS");

	snprintf(format, sizeof(format),
		 "%%d: %%%zus", sizeof(obd_uuid.uuid) - 1);
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		int index;

		if (sscanf(buf, format, &index, obd_uuid.uuid) < 2)
			break;

		if (param->fp_obd_uuid) {
			if (llapi_uuid_match(obd_uuid.uuid,
					     param->fp_obd_uuid->uuid)) {
				param->fp_obd_index = index;
				break;
			}
		} else if (!param->fp_quiet && !param->fp_obds_printed) {
			/* Print everything */
			llapi_printf(LLAPI_MSG_NORMAL, "%s", buf);
		}
	}
	param->fp_obds_printed = 1;

        fclose(fp);

	if (param->fp_obd_uuid && (param->fp_obd_index == OBD_NOT_FOUND)) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "error: %s: unknown obduuid: %s",
				  __func__, param->fp_obd_uuid->uuid);
		rc = -EINVAL;
	}
free_param:
	cfs_free_param_data(&param_data);
	return rc;
}

/* In this case, param->fp_obd_uuid will be an array of obduuids and
 * obd index for all these obduuids will be returned in
 * param->fp_obd_indexes */
static int setup_indexes(DIR *dir, char *path, struct obd_uuid *obduuids,
                         int num_obds, int **obdindexes, int *obdindex,
                         enum tgt_type type)
{
	int ret, obdcount, obd_valid = 0, obdnum;
	long i;
        struct obd_uuid *uuids = NULL;
        char buf[16];
        int *indexes;

	if (type == LOV_TYPE)
		ret = get_param_lov(path, "numobd", buf, sizeof(buf));
	else
		ret = get_param_lmv(path, "numobd", buf, sizeof(buf));
	if (ret != 0)
		return ret;

	obdcount = atoi(buf);
	uuids = malloc(obdcount * sizeof(struct obd_uuid));
	if (uuids == NULL)
		return -ENOMEM;

retry_get_uuids:
	ret = llapi_get_target_uuids(dirfd(dir), uuids, &obdcount, type);
	if (ret) {
		if (ret == -EOVERFLOW) {
			struct obd_uuid *uuids_temp;

			uuids_temp = realloc(uuids, obdcount *
					     sizeof(struct obd_uuid));
			if (uuids_temp != NULL) {
				uuids = uuids_temp;
				goto retry_get_uuids;
			}
			ret = -ENOMEM;
		}

                llapi_error(LLAPI_MSG_ERROR, ret, "get ost uuid failed");
                goto out_free;
        }

        indexes = malloc(num_obds * sizeof(*obdindex));
        if (indexes == NULL) {
                ret = -ENOMEM;
                goto out_free;
        }

        for (obdnum = 0; obdnum < num_obds; obdnum++) {
                char *end = NULL;

                /* The user may have specified a simple index */
                i = strtol(obduuids[obdnum].uuid, &end, 0);
                if (end && *end == '\0' && i < obdcount) {
                        indexes[obdnum] = i;
                        obd_valid++;
                } else {
                        for (i = 0; i < obdcount; i++) {
                                if (llapi_uuid_match(uuids[i].uuid,
                                                     obduuids[obdnum].uuid)) {
                                        indexes[obdnum] = i;
                                        obd_valid++;
                                        break;
                                }
                        }
                }
                if (i >= obdcount) {
                        indexes[obdnum] = OBD_NOT_FOUND;
                        llapi_err_noerrno(LLAPI_MSG_ERROR,
                                          "error: %s: unknown obduuid: %s",
                                          __func__, obduuids[obdnum].uuid);
                        ret = -EINVAL;
                }
        }

        if (obd_valid == 0)
                *obdindex = OBD_NOT_FOUND;
        else
                *obdindex = obd_valid;

        *obdindexes = indexes;
out_free:
        if (uuids)
                free(uuids);

        return ret;
}

static int setup_target_indexes(DIR *dir, char *path, struct find_param *param)
{
        int ret = 0;

	if (param->fp_mdt_uuid) {
		ret = setup_indexes(dir, path, param->fp_mdt_uuid,
				    param->fp_num_mdts,
				    &param->fp_mdt_indexes,
				    &param->fp_mdt_index, LMV_TYPE);
		if (ret)
			return ret;
	}

	if (param->fp_obd_uuid) {
		ret = setup_indexes(dir, path, param->fp_obd_uuid,
				    param->fp_num_obds,
				    &param->fp_obd_indexes,
				    &param->fp_obd_index, LOV_TYPE);
		if (ret)
			return ret;
	}

	param->fp_got_uuids = 1;

	return ret;
}

int llapi_ostlist(char *path, struct find_param *param)
{
	int fd;
	int ret;

	fd = open(path, O_RDONLY | O_DIRECTORY);
	if (fd < 0)
		return -errno;

	ret = setup_obd_uuid(fd, path, param);
	close(fd);

	return ret;
}

/*
 * Tries to determine the default stripe attributes for a given filesystem. The
 * filesystem to check should be specified by fsname, or will be determined
 * using pathname.
 */
static int sattr_get_defaults(const char *const fsname,
                              unsigned int *scount,
                              unsigned int *ssize,
                              unsigned int *soffset)
{
	char val[PATH_MAX];
	int rc;

	if (scount) {
		rc = get_lustre_param_value("lov", fsname, FILTER_BY_FS_NAME,
					    "stripecount", val, sizeof(val));
		if (rc != 0)
			return rc;
		*scount = atoi(val);
	}

	if (ssize) {
		rc = get_lustre_param_value("lov", fsname, FILTER_BY_FS_NAME,
					    "stripesize", val, sizeof(val));
		if (rc != 0)
			return rc;
		*ssize = atoi(val);
	}

	if (soffset) {
		rc = get_lustre_param_value("lov", fsname, FILTER_BY_FS_NAME,
					    "stripeoffset", val, sizeof(val));
		if (rc != 0)
			return rc;
		*soffset = atoi(val);
	}

	return 0;
}

/*
 * Tries to gather the default stripe attributes for a given filesystem. If
 * the attributes can be determined, they are cached for easy retreival the
 * next time they are needed. Only a single filesystem's attributes are
 * cached at a time.
 */
int sattr_cache_get_defaults(const char *const fsname,
			     const char *const pathname, unsigned int *scount,
			     unsigned int *ssize, unsigned int *soffset)
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

        if (fsname == NULL) {
                rc = llapi_search_fsname(pathname, fsname_buf);
                if (rc)
                        return rc;
        } else {
		strlcpy(fsname_buf, fsname, sizeof(fsname_buf));
        }

	if (strncmp(fsname_buf, cache.fsname, sizeof(fsname_buf) - 1) != 0) {
                /*
                 * Ensure all 3 sattrs (count, size, and offset) are
                 * successfully retrieved and stored in tmp before writing to
                 * cache.
                 */
		rc = sattr_get_defaults(fsname_buf, &tmp[0], &tmp[1], &tmp[2]);
                if (rc != 0)
                        return rc;

                cache.stripecount = tmp[0];
                cache.stripesize = tmp[1];
                cache.stripeoffset = tmp[2];
		strlcpy(cache.fsname, fsname_buf, sizeof(cache.fsname));
        }

        if (scount)
                *scount = cache.stripecount;
        if (ssize)
                *ssize = cache.stripesize;
        if (soffset)
                *soffset = cache.stripeoffset;

        return 0;
}

enum lov_dump_flags {
	LDF_IS_DIR	= 0x0001,
	LDF_IS_RAW	= 0x0002,
	LDF_INDENT	= 0x0004,
	LDF_SKIP_OBJS	= 0x0008,
	LDF_YAML	= 0x0010,
};

static void lov_dump_user_lmm_header(struct lov_user_md *lum, char *path,
				     struct lov_user_ost_data_v1 *objects,
				     int verbose, int depth, char *pool_name,
				     enum lov_dump_flags flags)
{
	bool is_dir = flags & LDF_IS_DIR;
	bool is_raw = flags & LDF_IS_RAW;
	bool indent = flags & LDF_INDENT;
	bool yaml = flags & LDF_YAML;
	bool skip_objs = flags & LDF_SKIP_OBJS;
	char *prefix = is_dir ? "" : "lmm_";
	char *separator = "";
	char *space = indent ? "      " : "";
	int rc;

	if (is_dir && lmm_oi_seq(&lum->lmm_oi) == FID_SEQ_LOV_DEFAULT) {
		lmm_oi_set_seq(&lum->lmm_oi, 0);
		if (!indent && (verbose & VERBOSE_DETAIL))
			llapi_printf(LLAPI_MSG_NORMAL, "%s(Default) ", space);
	}

	if (!yaml && !indent && depth && path &&
	    ((verbose != VERBOSE_OBJID) || !is_dir))
		llapi_printf(LLAPI_MSG_NORMAL, "%s\n", path);

	if ((verbose & VERBOSE_DETAIL) && !is_dir) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s%smagic:         0x%08X\n",
			     space, prefix, lum->lmm_magic);
		llapi_printf(LLAPI_MSG_NORMAL, "%s%sseq:           %#jx\n",
			     space, prefix,
			     (uintmax_t)lmm_oi_seq(&lum->lmm_oi));
		llapi_printf(LLAPI_MSG_NORMAL, "%s%sobject_id:     %#jx\n",
			     space, prefix,
			     (uintmax_t)lmm_oi_id(&lum->lmm_oi));
	}
	if ((verbose & (VERBOSE_DETAIL | VERBOSE_DFID)) && !is_dir) {
		__u64 seq;
		__u32 oid;
		__u32 ver;

		if (verbose & ~VERBOSE_DFID)
			llapi_printf(LLAPI_MSG_NORMAL, "%slmm_fid:           ",
				     space);
		/* This needs a bit of hand-holding since old 1.x lmm_oi
		 * have { oi.oi_id = mds_inum, oi.oi_seq = 0 } and 2.x lmm_oi
		 * have { oi.oi_id = mds_oid, oi.oi_seq = mds_seq } instead of
		 * a real FID.  Ideally the 2.x code would have stored this
		 * like a FID with { oi_id = mds_seq, oi_seq = mds_oid } so the
		 * ostid union lu_fid { f_seq = mds_seq, f_oid = mds_oid }
		 * worked properly (especially since IGIF FIDs use mds_inum as
		 * the FID SEQ), but unfortunately that didn't happen.
		 *
		 * Print it to look like an IGIF FID, even though the fields
		 * are reversed on disk, so that it makes sense to userspace.
		 *
		 * Don't use ostid_id() and ostid_seq(), since they assume the
		 * oi_fid fields are in the right order.  This is why there are
		 * separate lmm_oi_seq() and lmm_oi_id() routines for this.
		 *
		 * For newer layout types hopefully this will be a real FID. */
		seq = lmm_oi_seq(&lum->lmm_oi) == 0 ?
			lmm_oi_id(&lum->lmm_oi) : lmm_oi_seq(&lum->lmm_oi);
		oid = lmm_oi_seq(&lum->lmm_oi) == 0 ?
			0 : (__u32)lmm_oi_id(&lum->lmm_oi);
		ver = (__u32)(lmm_oi_id(&lum->lmm_oi) >> 32);
		if (yaml)
			llapi_printf(LLAPI_MSG_NORMAL, DFID_NOBRACE"\n",
				     seq, oid, ver);
		else
			llapi_printf(LLAPI_MSG_NORMAL, DFID"\n",
				     seq, oid, ver);
	}

	if (verbose & VERBOSE_COUNT) {
		if (verbose & ~VERBOSE_COUNT)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%sstripe_count:  ",
				     space, prefix);
		if (is_dir) {
			if (!is_raw && lum->lmm_stripe_count == 0) {
				unsigned int scount;
				rc = sattr_cache_get_defaults(NULL, path,
							      &scount, NULL,
							      NULL);
				if (rc == 0)
					llapi_printf(LLAPI_MSG_NORMAL, "%d",
						     scount);
				else
					llapi_error(LLAPI_MSG_ERROR, rc,
						    "Cannot determine default"
						    " stripe count.");
			} else {
				llapi_printf(LLAPI_MSG_NORMAL, "%d",
					     lum->lmm_stripe_count ==
					     (typeof(lum->lmm_stripe_count))(-1)
					     ? -1 : lum->lmm_stripe_count);
			}
		} else {
			llapi_printf(LLAPI_MSG_NORMAL, "%hd",
				     (__s16)lum->lmm_stripe_count);
		}
		if (!yaml && is_dir)
			separator = " ";
		else
			separator = "\n";
	}

	if (verbose & VERBOSE_SIZE) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_SIZE)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%sstripe_size:   ",
				     space, prefix);
		if (is_dir && !is_raw && lum->lmm_stripe_size == 0) {
			unsigned int ssize;
			rc = sattr_cache_get_defaults(NULL, path, NULL, &ssize,
						      NULL);
			if (rc == 0)
				llapi_printf(LLAPI_MSG_NORMAL, "%u", ssize);
			else
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "Cannot determine default"
					    " stripe size.");
		} else {
			llapi_printf(LLAPI_MSG_NORMAL, "%u",
				     lum->lmm_stripe_size);
		}
		if (!yaml && is_dir)
			separator = " ";
		else
			separator = "\n";
	}

	if ((verbose & VERBOSE_LAYOUT) && !is_dir) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_LAYOUT)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%spattern:       ",
				     space, prefix);
		llapi_printf(LLAPI_MSG_NORMAL, "%.x", lum->lmm_pattern);
		separator = "\n";
	}

	if ((verbose & VERBOSE_GENERATION) && !is_dir) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_GENERATION)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%slayout_gen:    ",
				     space, prefix);
		llapi_printf(LLAPI_MSG_NORMAL, "%u",
			     (int)lum->lmm_layout_gen);
		separator = "\n";
	}

	if (verbose & VERBOSE_OFFSET) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_OFFSET)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%sstripe_offset: ",
				     space, prefix);
		if (is_dir || skip_objs)
			llapi_printf(LLAPI_MSG_NORMAL, "%d",
				     lum->lmm_stripe_offset ==
				     (typeof(lum->lmm_stripe_offset))(-1) ? -1 :
				     lum->lmm_stripe_offset);
		else
			llapi_printf(LLAPI_MSG_NORMAL, "%u",
				     objects[0].l_ost_idx);
		if (!yaml && is_dir)
			separator = " ";
		else
			separator = "\n";
	}

	if ((verbose & VERBOSE_POOL) && pool_name && (pool_name[0] != '\0')) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_POOL)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%spool:          ",
				     space, prefix);
		llapi_printf(LLAPI_MSG_NORMAL, "%s", pool_name);
		if (!yaml && is_dir)
			separator = " ";
		else
			separator = "\n";
	}

	if (strlen(separator) != 0)
		llapi_printf(LLAPI_MSG_NORMAL, "\n");
}

void lov_dump_user_lmm_v1v3(struct lov_user_md *lum, char *pool_name,
			    struct lov_user_ost_data_v1 *objects,
			    char *path, int obdindex, int depth,
			    int header, enum lov_dump_flags flags)
{
	bool is_dir = flags & LDF_IS_DIR;
	bool indent = flags & LDF_INDENT;
	bool skip_objs = flags & LDF_SKIP_OBJS;
	bool yaml = flags & LDF_YAML;
	int i, obdstripe = (obdindex != OBD_NOT_FOUND) ? 0 : 1;

	if (!obdstripe) {
		for (i = 0; !is_dir && i < lum->lmm_stripe_count; i++) {
			if (obdindex == objects[i].l_ost_idx) {
				obdstripe = 1;
				break;
			}
		}
	}

	if (obdstripe == 0)
		return;

	lov_dump_user_lmm_header(lum, path, objects, header, depth, pool_name,
				 flags);

	if (!is_dir && !skip_objs && (header & VERBOSE_OBJID) &&
	    !(lum->lmm_pattern & LOV_PATTERN_F_RELEASED)) {
		char *space = "      - ";

		if (indent)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%6slmm_objects:\n", " ");
		else if (yaml)
			llapi_printf(LLAPI_MSG_NORMAL, "lmm_objects:\n");
		else
			llapi_printf(LLAPI_MSG_NORMAL,
				"\tobdidx\t\t objid\t\t objid\t\t group\n");

		for (i = 0; i < lum->lmm_stripe_count; i++) {
			int idx = objects[i].l_ost_idx;
			long long oid = ostid_id(&objects[i].l_ost_oi);
			long long gr = ostid_seq(&objects[i].l_ost_oi);

			if (obdindex != OBD_NOT_FOUND && obdindex != idx)
				continue;

			if (yaml) {
				struct lu_fid fid = { 0 };

				ostid_to_fid(&fid, &objects[i].l_ost_oi, idx);
				llapi_printf(LLAPI_MSG_NORMAL,
				    "%sl_ost_idx: %d\n", space, idx);
				llapi_printf(LLAPI_MSG_NORMAL,
				    "%8sl_fid:     "DFID_NOBRACE"\n",
				    " ", PFID(&fid));
			} else if (indent) {
				struct lu_fid fid = { 0 };

				ostid_to_fid(&fid, &objects[i].l_ost_oi, idx);
				llapi_printf(LLAPI_MSG_NORMAL,
				    "%s%d: { l_ost_idx: %d, l_fid: "DFID" }\n",
				    space, i, idx, PFID(&fid));
			} else {
				char fmt[48];
				sprintf(fmt, "%s%s%s\n",
					"\t%6u\t%14llu\t%#13llx\t",
					(fid_seq_is_rsvd(gr) ||
					 fid_seq_is_mdt0(gr)) ?
					 "%14llu" : "%#14llx", "%s");
				llapi_printf(LLAPI_MSG_NORMAL, fmt, idx, oid,
					     oid, gr,
					     obdindex == idx ? " *" : "");
			}
		}
		llapi_printf(LLAPI_MSG_NORMAL, "\n");
	}
}

void lmv_dump_user_lmm(struct lmv_user_md *lum, char *pool_name,
		       char *path, int obdindex, int depth, int verbose,
		       enum lov_dump_flags flags)
{
	struct lmv_user_mds_data *objects = lum->lum_objects;
	char *prefix = lum->lum_magic == LMV_USER_MAGIC ? "(Default)" : "";
	int i, obdstripe = 0;
	char *separator = "";
	bool yaml = flags & LDF_YAML;

	if (obdindex != OBD_NOT_FOUND) {
		if (lum->lum_stripe_count == 0) {
			if (obdindex == lum->lum_stripe_offset)
				obdstripe = 1;
		} else {
			for (i = 0; i < lum->lum_stripe_count; i++) {
				if (obdindex == objects[i].lum_mds) {
					llapi_printf(LLAPI_MSG_NORMAL,
						     "%s%s\n", prefix,
						     path);
					obdstripe = 1;
					break;
				}
			}
		}
	} else {
		obdstripe = 1;
	}

	if (!obdstripe)
		return;

	/* show all information default */
	if (!verbose) {
		if (lum->lum_magic == LMV_USER_MAGIC)
			verbose = VERBOSE_POOL | VERBOSE_COUNT |
				  VERBOSE_OFFSET | VERBOSE_HASH_TYPE;
		else
			verbose = VERBOSE_OBJID;
	}

	if (depth && path && ((verbose != VERBOSE_OBJID)))
		llapi_printf(LLAPI_MSG_NORMAL, "%s%s\n", prefix, path);

	if (verbose & VERBOSE_COUNT) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_COUNT)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_stripe_count: ");
		llapi_printf(LLAPI_MSG_NORMAL, "%u",
			     (int)lum->lum_stripe_count);
		if ((verbose & VERBOSE_OFFSET) && !yaml)
			separator = " ";
		else
			separator = "\n";
	}

	if (verbose & VERBOSE_OFFSET) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_OFFSET)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_stripe_offset: ");
		llapi_printf(LLAPI_MSG_NORMAL, "%d",
			     (int)lum->lum_stripe_offset);
		if (verbose & VERBOSE_HASH_TYPE && !yaml)
			separator = " ";
		else
			separator = "\n";
	}

	if (verbose & VERBOSE_HASH_TYPE) {
		unsigned int type = lum->lum_hash_type;

		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_HASH_TYPE)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_hash_type: ");
		if (type < LMV_HASH_TYPE_MAX)
			llapi_printf(LLAPI_MSG_NORMAL, "%s",
				     mdt_hash_name[type]);
		else
			llapi_printf(LLAPI_MSG_NORMAL, "%d",
				     (int)type);
		separator = "\n";
	}

	if (verbose & VERBOSE_OBJID && lum->lum_magic != LMV_USER_MAGIC) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (obdstripe == 1 && lum->lum_stripe_count > 0)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "mdtidx\t\t FID[seq:oid:ver]\n");
		for (i = 0; i < lum->lum_stripe_count; i++) {
			int idx = objects[i].lum_mds;
			struct lu_fid *fid = &objects[i].lum_fid;
			if ((obdindex == OBD_NOT_FOUND) || (obdindex == idx))
				llapi_printf(LLAPI_MSG_NORMAL,
					     "%6u\t\t "DFID"\t\t%s\n",
					    idx, PFID(fid),
					    obdindex == idx ? " *" : "");
		}

	}

	if ((verbose & VERBOSE_POOL) && pool_name != NULL &&
	     pool_name[0] != '\0') {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_POOL)
			llapi_printf(LLAPI_MSG_NORMAL, "%slmv_pool:           ",
				     prefix);
		llapi_printf(LLAPI_MSG_NORMAL, "%s%c ", pool_name, ' ');
		separator = "\n";
	}

	if (!(verbose & VERBOSE_OBJID) || lum->lum_magic == LMV_USER_MAGIC)
		llapi_printf(LLAPI_MSG_NORMAL, "\n");
}

static void lov_dump_comp_v1_header(struct find_param *param, char *path,
				    enum lov_dump_flags flags)
{
	struct lov_comp_md_v1 *comp_v1 = (void *)&param->fp_lmd->lmd_lmm;
	int depth = param->fp_max_depth;
	int verbose = param->fp_verbose;
	bool yaml = flags & LDF_YAML;

	if (depth && path && ((verbose != VERBOSE_OBJID) ||
			      !(flags & LDF_IS_DIR)) && !yaml)
		llapi_printf(LLAPI_MSG_NORMAL, "%s\n", path);

	if (verbose & VERBOSE_DETAIL) {
		llapi_printf(LLAPI_MSG_NORMAL, "composite_header:\n");
		llapi_printf(LLAPI_MSG_NORMAL, "%2slcm_magic:       0x%08X\n",
			     " ", comp_v1->lcm_magic);
		llapi_printf(LLAPI_MSG_NORMAL, "%2slcm_size:        %u\n",
			     " ", comp_v1->lcm_size);
		llapi_printf(LLAPI_MSG_NORMAL, "%2slcm_flags:       %u\n",
			     " ", comp_v1->lcm_flags);
	}

	if (verbose & VERBOSE_GENERATION) {
		if (verbose & ~VERBOSE_GENERATION)
			llapi_printf(LLAPI_MSG_NORMAL, "%2slcm_layout_gen:  ",
				     " ");
		llapi_printf(LLAPI_MSG_NORMAL, "%u\n", comp_v1->lcm_layout_gen);
	}

	if (verbose & VERBOSE_COMP_COUNT) {
		if (verbose & ~VERBOSE_COMP_COUNT)
			llapi_printf(LLAPI_MSG_NORMAL, "%2slcm_entry_count: ",
				     " ");
		llapi_printf(LLAPI_MSG_NORMAL, "%u\n",
			     comp_v1->lcm_magic == LOV_USER_MAGIC_COMP_V1 ?
			     comp_v1->lcm_entry_count : 0);
	}

	if (verbose & VERBOSE_DETAIL && !yaml)
		llapi_printf(LLAPI_MSG_NORMAL, "components:\n");
}

static void comp_flags2str(__u32 comp_flags)
{
	bool found = false;
	int i = 0;

	if (!comp_flags) {
		llapi_printf(LLAPI_MSG_NORMAL, "0");
		return;
	}
	for (i = 0; i < ARRAY_SIZE(comp_flags_table); i++) {
		if (comp_flags & comp_flags_table[i].cfn_flag) {
			if (found)
				llapi_printf(LLAPI_MSG_NORMAL, ",");
			llapi_printf(LLAPI_MSG_NORMAL, "%s",
				     comp_flags_table[i].cfn_name);
			comp_flags &= ~comp_flags_table[i].cfn_flag;
			found = true;
		}
	}
	if (comp_flags) {
		if (found)
			llapi_printf(LLAPI_MSG_NORMAL, ",");
		llapi_printf(LLAPI_MSG_NORMAL, "%#x", comp_flags);
	}
}

static void lov_dump_comp_v1_entry(struct find_param *param,
				   enum lov_dump_flags flags, int index)
{
	struct lov_comp_md_v1 *comp_v1 = (void *)&param->fp_lmd->lmd_lmm;
	struct lov_comp_md_entry_v1 *entry;
	char *separator = "";
	int verbose = param->fp_verbose;
	bool yaml = flags & LDF_YAML;

	entry = &comp_v1->lcm_entries[index];

	if (yaml)
		llapi_printf(LLAPI_MSG_NORMAL, "%2scomponent%d:\n", " ", index);

	if (verbose & VERBOSE_COMP_ID) {
		if (verbose & VERBOSE_DETAIL && !yaml)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%slcme_id:             ", "  - ");
		else if (verbose & ~VERBOSE_COMP_ID)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%4slcme_id:             ", " ");
		if (entry->lcme_id != LCME_ID_INVAL)
			llapi_printf(LLAPI_MSG_NORMAL, "%u", entry->lcme_id);
		else
			llapi_printf(LLAPI_MSG_NORMAL, "N/A");
		separator = "\n";
	}

	if (verbose & VERBOSE_COMP_FLAGS) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_COMP_FLAGS)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%4slcme_flags:          ", " ");
		comp_flags2str(entry->lcme_flags);
		separator = "\n";
	}

	if (verbose & VERBOSE_COMP_START) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_COMP_START)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%4slcme_extent.e_start: ", " ");
		llapi_printf(LLAPI_MSG_NORMAL, "%llu",
			     entry->lcme_extent.e_start);
		separator = "\n";
	}

	if (verbose & VERBOSE_COMP_END) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_COMP_END)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%4slcme_extent.e_end:   ", " ");
		if (entry->lcme_extent.e_end == LUSTRE_EOF)
			llapi_printf(LLAPI_MSG_NORMAL, "%s", "EOF");
		else
			llapi_printf(LLAPI_MSG_NORMAL, "%llu",
					entry->lcme_extent.e_end);
		separator = "\n";
	}

	if (yaml) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		llapi_printf(LLAPI_MSG_NORMAL, "%4ssub_layout:\n", " ");
	} else if (verbose & VERBOSE_DETAIL) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		llapi_printf(LLAPI_MSG_NORMAL, "%4slcme_offset:         %u\n",
			     " ", entry->lcme_offset);
		llapi_printf(LLAPI_MSG_NORMAL, "%4slcme_size:           %u\n",
			     " ", entry->lcme_size);
		llapi_printf(LLAPI_MSG_NORMAL, "%4ssub_layout:\n", " ");
	} else {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
	}
}

/* Check if the value matches 1 of the given criteria (e.g. --atime +/-N).
 * @mds indicates if this is MDS timestamps and there are attributes on OSTs.
 *
 * The result is -1 if it does not match, 0 if not yet clear, 1 if matches.
 * The table below gives the answers for the specified parameters (value and
 * sign), 1st column is the answer for the MDS value, the 2nd is for the OST:
 * --------------------------------------
 * 1 | file > limit; sign > 0 | -1 / -1 |
 * 2 | file = limit; sign > 0 | -1 / -1 |
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
		/* Drop the fraction of margin (of days). */
		if (file + margin <= limit)
			ret = mds ? 0 : 1;
	} else if (sign == 0) {
		if (file <= limit && file + margin > limit)
			ret = mds ? 0 : 1;
		else if (file + margin <= limit)
			ret = mds ? 0 : -1;
	} else if (sign < 0) {
		if (file > limit)
			ret = 1;
		else if (mds)
			ret = 0;
	}

	return negopt ? ~ret + 1 : ret;
}

static inline struct lov_user_md *
lov_comp_entry(struct lov_comp_md_v1 *comp_v1, int ent_idx)
{
	return (struct lov_user_md *)((char *)comp_v1 +
			comp_v1->lcm_entries[ent_idx].lcme_offset);
}

static inline struct lov_user_ost_data_v1 *
lov_v1v3_objects(struct lov_user_md *v1)
{
	if (v1->lmm_magic == LOV_USER_MAGIC_V3)
		return ((struct lov_user_md_v3 *)v1)->lmm_objects;
	else
		return v1->lmm_objects;
}

static inline void
lov_v1v3_pool_name(struct lov_user_md *v1, char *pool_name)
{
	if (v1->lmm_magic == LOV_USER_MAGIC_V3)
		strlcpy(pool_name, ((struct lov_user_md_v3 *)v1)->lmm_pool_name,
			LOV_MAXPOOLNAME);
	else
		pool_name[0] = '\0';
}

static inline bool
print_last_init_comp(struct find_param *param)
{
	/* print all component info */
	if ((param->fp_verbose & VERBOSE_DEFAULT) == VERBOSE_DEFAULT)
		return false;

	/* print specific component info */
	if (param->fp_check_comp_id || param->fp_check_comp_flags ||
	    param->fp_check_comp_start || param->fp_check_comp_end)
		return false;

	return true;
}

static int find_comp_end_cmp(unsigned long long end, struct find_param *param)
{
	int match;

	if (param->fp_comp_end == LUSTRE_EOF) {
		if (param->fp_comp_end_sign == 0) /* equal to EOF */
			match = end == LUSTRE_EOF ? 1 : -1;
		else if (param->fp_comp_end_sign > 0) /* at most EOF */
			match = end == LUSTRE_EOF ? -1 : 1;
		else /* at least EOF */
			match = -1;
		if (param->fp_exclude_comp_end)
			match = ~match + 1;
	} else {
		unsigned long long margin;

		margin = end == LUSTRE_EOF ? 0 : param->fp_comp_end_units;
		match = find_value_cmp(end, param->fp_comp_end,
				       param->fp_comp_end_sign,
				       param->fp_exclude_comp_end, margin, 0);
	}

	return match;
}

/**
 * An example of "getstripe -v" for a two components PFL file:
 *
 * composite_header:
 * lcm_magic:       0x0BD60BD0
 * lcm_size:        264
 * lcm_flags:       0
 * lcm_layout_gen:  2
 * lcm_entry_count: 2
 * components:
 * - lcme_id:             1
 *   lcme_flags:          0x10
 *   lcme_extent.e_start: 0
 *   lcme_extent.e_end:   1048576
 *   lcme_offset:         128
 *   lcme_size:           56
 *   sub_layout:
 *     lmm_magic:         0x0BD10BD0
 *     lmm_seq:           0x200000401
 *     lmm_object_id:     0x1
 *     lmm_fid:           [0x200000401:0x1:0x0]
 *     lmm_stripe_count:  1
 *     lmm_stripe_size:   1048576
 *     lmm_pattern:       1
 *     lmm_layout_gen:    0
 *     lmm_stripe_offset: 0
 *     lmm_objects:
 *     - 0: { l_ost_idx: 0, l_fid: [0x100000000:0x2:0x0] }
 *
 * - lcme_id:             2
 *   lcme_flags:          0x10
 *   lcme_extent.e_start: 1048576
 *   lcme_extent.e_end:   EOF
 *   lcme_offset:         184
 *   lcme_size:           80
 *     sub_layout:
 *     lmm_magic:         0x0BD10BD0
 *     lmm_seq:           0x200000401
 *     lmm_object_id:     0x1
 *     lmm_fid:           [0x200000401:0x1:0x0]
 *     lmm_stripe_count:  2
 *     lmm_stripe_size:   1048576
 *     lmm_pattern:       1
 *     lmm_layout_gen:    0
 *     lmm_stripe_offset: 1
 *     lmm_objects:
 *     - 0: { l_ost_idx: 1, l_fid: [0x100010000:0x2:0x0] }
 *     - 1: { l_ost_idx: 0, l_fid: [0x100000000:0x3:0x0] }
 */
static void lov_dump_comp_v1(struct find_param *param, char *path,
			     enum lov_dump_flags flags)
{
	struct lov_comp_md_entry_v1 *entry;
	struct lov_user_ost_data_v1 *objects;
	struct lov_comp_md_v1 *comp_v1 = (void *)&param->fp_lmd->lmd_lmm;
	struct lov_user_md_v1 *v1;
	char pool_name[LOV_MAXPOOLNAME + 1];
	int obdindex = param->fp_obd_index;
	int i, j, match, obdstripe = 0;

	if (obdindex != OBD_NOT_FOUND) {
		for (i = 0; !(flags & LDF_IS_DIR) &&
			    i < comp_v1->lcm_entry_count; i++) {
			if (!(comp_v1->lcm_entries[i].lcme_flags &
			      LCME_FL_INIT))
				continue;

			v1 = lov_comp_entry(comp_v1, i);
			objects = lov_v1v3_objects(v1);

			for (j = 0; j < v1->lmm_stripe_count; j++) {
				if (obdindex == objects[j].l_ost_idx) {
					obdstripe = 1;
					break;
				}
			}
		}
	} else {
		obdstripe = 1;
	}

	if (obdstripe == 0)
		return;

	lov_dump_comp_v1_header(param, path, flags);

	flags |= LDF_INDENT;

	for (i = 0; i < comp_v1->lcm_entry_count; i++) {
		entry = &comp_v1->lcm_entries[i];

		if (param->fp_check_comp_flags) {
			if ((param->fp_exclude_comp_flags &&
			     (param->fp_comp_flags & entry->lcme_flags)) ||
			    (!param->fp_exclude_comp_flags &&
			     !(param->fp_comp_flags & entry->lcme_flags)))
				continue;
		}

		if (param->fp_check_comp_id &&
		    param->fp_comp_id != entry->lcme_id)
			continue;

		if (param->fp_check_comp_start) {
			match = find_value_cmp(entry->lcme_extent.e_start,
					       param->fp_comp_start,
					       param->fp_comp_start_sign,
					       0,
					       param->fp_comp_start_units, 0);
			if (match == -1)
				continue;
		}

		if (param->fp_check_comp_end) {
			match = find_comp_end_cmp(entry->lcme_extent.e_end,
						  param);
			if (match == -1)
				continue;
		}

		if (print_last_init_comp(param)) {
			/**
			 * if part of stripe info is needed, we'd print only
			 * the last instantiated component info.
			 */
			if (entry->lcme_flags & LCME_FL_INIT)
				continue;
			else
				break;
		}

		if (entry->lcme_flags & LCME_FL_INIT)
			flags &= ~LDF_SKIP_OBJS;
		else
			flags |= LDF_SKIP_OBJS;

		lov_dump_comp_v1_entry(param, flags, i);

		v1 = lov_comp_entry(comp_v1, i);
		objects = lov_v1v3_objects(v1);
		lov_v1v3_pool_name(v1, pool_name);

		lov_dump_user_lmm_v1v3(v1, pool_name, objects, path, obdindex,
				       param->fp_max_depth, param->fp_verbose,
				       flags);
	}
	if (print_last_init_comp(param)) {
		/**
		 * directory layout contains only layout template, print the
		 * last component.
		 */
		if (i == 0)
			i = comp_v1->lcm_entry_count - 1;
		else
			i--;
		flags &= ~LDF_SKIP_OBJS;

		lov_dump_comp_v1_entry(param, flags, i);

		v1 = lov_comp_entry(comp_v1, i);
		objects = lov_v1v3_objects(v1);
		lov_v1v3_pool_name(v1, pool_name);

		lov_dump_user_lmm_v1v3(v1, pool_name, objects, path, obdindex,
				       param->fp_max_depth, param->fp_verbose,
				       flags);
	}
}

#define VERBOSE_COMP_OPTS	(VERBOSE_COMP_COUNT | VERBOSE_COMP_ID | \
				 VERBOSE_COMP_START | VERBOSE_COMP_END | \
				 VERBOSE_COMP_FLAGS)

static inline bool has_any_comp_options(struct find_param *param)
{
	int verbose = param->fp_verbose;

	if (param->fp_check_comp_id || param->fp_check_comp_count ||
	    param->fp_check_comp_start || param->fp_check_comp_end ||
	    param->fp_check_comp_flags)
		return true;

	/* show full layout information, not component specific */
	if ((verbose & ~VERBOSE_DETAIL) == VERBOSE_DEFAULT)
		return false;

	return verbose & VERBOSE_COMP_OPTS;
}

struct lov_user_mds_data *lov_forge_comp_v1(struct lov_user_mds_data *orig,
					    bool is_dir)
{
	struct lov_user_md *lum = &orig->lmd_lmm;
	struct lov_user_mds_data *new;
	struct lov_comp_md_v1 *comp_v1;
	struct lov_comp_md_entry_v1 *ent;
	int lum_off = sizeof(*comp_v1) + sizeof(*ent);
	int lum_size = lov_user_md_size(is_dir ? 0 : lum->lmm_stripe_count,
					lum->lmm_magic);

	new = malloc(sizeof(lstat_t) + lum_off + lum_size);
	if (new == NULL) {
		llapi_printf(LLAPI_MSG_NORMAL, "out of memory\n");
		return new;
	}

	memcpy(new, orig, sizeof(lstat_t));

	comp_v1 = (struct lov_comp_md_v1 *)&new->lmd_lmm;
	comp_v1->lcm_magic = lum->lmm_magic;
	comp_v1->lcm_size = lum_off + lum_size;
	comp_v1->lcm_layout_gen = is_dir ? 0 : lum->lmm_layout_gen;
	comp_v1->lcm_flags = 0;
	comp_v1->lcm_entry_count = 1;

	ent = &comp_v1->lcm_entries[0];
	ent->lcme_id = 0;
	ent->lcme_flags = is_dir ? 0 : LCME_FL_INIT;
	ent->lcme_extent.e_start = 0;
	ent->lcme_extent.e_end = LUSTRE_EOF;
	ent->lcme_offset = lum_off;
	ent->lcme_size = lum_size;

	memcpy((char *)comp_v1 + lum_off, lum, lum_size);

	return new;
}

static void lov_dump_plain_user_lmm(struct find_param *param, char *path,
				    enum lov_dump_flags flags)
{
	__u32 magic = *(__u32 *)&param->fp_lmd->lmd_lmm;

	if (has_any_comp_options(param)) {
		struct lov_user_mds_data *new_lmd, *orig_lmd;

		orig_lmd = param->fp_lmd;
		new_lmd = lov_forge_comp_v1(orig_lmd, flags & LDF_IS_DIR);
		if (new_lmd != NULL) {
			param->fp_lmd = new_lmd;
			lov_dump_comp_v1(param, path, flags);
			param->fp_lmd = orig_lmd;
			free(new_lmd);
		}
		return;
	}

	if (magic == LOV_USER_MAGIC_V1) {
		lov_dump_user_lmm_v1v3(&param->fp_lmd->lmd_lmm, NULL,
				       param->fp_lmd->lmd_lmm.lmm_objects,
				       path, param->fp_obd_index,
				       param->fp_max_depth, param->fp_verbose,
				       flags);
	} else {
		char pool_name[LOV_MAXPOOLNAME + 1];
		struct lov_user_ost_data_v1 *objects;
		struct lov_user_md_v3 *lmmv3 = (void *)&param->fp_lmd->lmd_lmm;

		strlcpy(pool_name, lmmv3->lmm_pool_name, sizeof(pool_name));
		objects = lmmv3->lmm_objects;
		lov_dump_user_lmm_v1v3(&param->fp_lmd->lmd_lmm, pool_name,
				       objects, path, param->fp_obd_index,
				       param->fp_max_depth, param->fp_verbose,
				       flags);
	}
}

static void llapi_lov_dump_user_lmm(struct find_param *param, char *path,
				    enum lov_dump_flags flags)
{
	__u32 magic;

	if (param->fp_get_lmv || param->fp_get_default_lmv)
		magic = (__u32)param->fp_lmv_md->lum_magic;
	else
		magic = *(__u32 *)&param->fp_lmd->lmd_lmm; /* lum->lmm_magic */

	if (param->fp_raw)
		flags |= LDF_IS_RAW;
	if (param->fp_yaml)
		flags |= LDF_YAML;

	switch (magic) {
	case LOV_USER_MAGIC_V1:
	case LOV_USER_MAGIC_V3:
		lov_dump_plain_user_lmm(param, path, flags);
		break;
	case LMV_MAGIC_V1:
	case LMV_USER_MAGIC: {
		char pool_name[LOV_MAXPOOLNAME + 1];
		struct lmv_user_md *lum;

		lum = (struct lmv_user_md *)param->fp_lmv_md;
		strlcpy(pool_name, lum->lum_pool_name, sizeof(pool_name));
		lmv_dump_user_lmm(lum, pool_name, path, param->fp_obd_index,
				  param->fp_max_depth, param->fp_verbose,
				  flags);
		break;
	}
	case LOV_USER_MAGIC_COMP_V1:
		lov_dump_comp_v1(param, path, flags);
		break;
	default:
		llapi_printf(LLAPI_MSG_NORMAL, "unknown lmm_magic:  %#x "
			     "(expecting one of %#x %#x %#x %#x)\n",
			     *(__u32 *)&param->fp_lmd->lmd_lmm,
			     LOV_USER_MAGIC_V1, LOV_USER_MAGIC_V3,
			     LMV_USER_MAGIC, LMV_MAGIC_V1);
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
			return -ENOMEM;
		strcpy(dname, ".");
		fname = (char *)path;
	} else {
		dname = (char *)malloc(fname - path + 1);
		if (dname == NULL)
			return -ENOMEM;
		strncpy(dname, path, fname - path);
		dname[fname - path] = '\0';
		fname++;
	}

	fd = open(dname, O_RDONLY | O_NONBLOCK);
	if (fd == -1) {
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

/* Check if the file time matches all the given criteria (e.g. --atime +/-N).
 * Return -1 or 1 if file timestamp does not or does match the given criteria
 * correspondingly. Return 0 if the MDS time is being checked and there are
 * attributes on OSTs and it is not yet clear if the timespamp matches.
 *
 * If 0 is returned, we need to do another RPC to the OSTs to obtain the
 * updated timestamps. */
static int find_time_check(lstat_t *st, struct find_param *param, int mds)
{
	int rc = 1;
	int rc2;

	/* Check if file is accepted. */
	if (param->fp_atime) {
		rc2 = find_value_cmp(st->st_atime, param->fp_atime,
				     param->fp_asign, param->fp_exclude_atime,
				     24 * 60 * 60, mds);
		if (rc2 < 0)
			return rc2;
		rc = rc2;
	}

	if (param->fp_mtime) {
		rc2 = find_value_cmp(st->st_mtime, param->fp_mtime,
				     param->fp_msign, param->fp_exclude_mtime,
				     24 * 60 * 60, mds);
		if (rc2 < 0)
			return rc2;

		/* If the previous check matches, but this one is not yet clear,
		 * we should return 0 to do an RPC on OSTs. */
		if (rc == 1)
			rc = rc2;
	}

	if (param->fp_ctime) {
		rc2 = find_value_cmp(st->st_ctime, param->fp_ctime,
				     param->fp_csign, param->fp_exclude_ctime,
				     24 * 60 * 60, mds);
		if (rc2 < 0)
			return rc2;

		/* If the previous check matches, but this one is not yet clear,
		 * we should return 0 to do an RPC on OSTs. */
		if (rc == 1)
			rc = rc2;
	}

	return rc;
}

/**
 * Check whether the stripes matches the indexes user provided
 *       1   : matched
 *       0   : Unmatched
 */
static int check_obd_match(struct find_param *param)
{
	struct lov_user_ost_data_v1 *objects;
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_user_md_v1 *v1 = &param->fp_lmd->lmd_lmm;
	lstat_t *st = &param->fp_lmd->lmd_st;
	int i, j, k, count = 1;

	if (param->fp_obd_uuid && param->fp_obd_index == OBD_NOT_FOUND)
		return 0;

	if (!S_ISREG(st->st_mode))
		return 0;

	/* Only those files should be accepted, which have a
	 * stripe on the specified OST. */
	if (v1->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
		count = comp_v1->lcm_entry_count;
	}

	for (i = 0; i < count; i++) {
		if (comp_v1)
			v1 = lov_comp_entry(comp_v1, i);

		objects = lov_v1v3_objects(v1);

		for (j = 0; j < v1->lmm_stripe_count; j++) {
			for (k = 0; k < param->fp_num_obds; k++) {
				if (param->fp_obd_indexes[k] ==
				    objects[j].l_ost_idx)
					return !param->fp_exclude_obd;
			}
		}
	}

	return param->fp_exclude_obd;
}

static int check_mdt_match(struct find_param *param)
{
	int i;

	if (param->fp_mdt_uuid && param->fp_mdt_index == OBD_NOT_FOUND)
		return 0;

	/* FIXME: For striped dir, we should get stripe information and check */
	for (i = 0; i < param->fp_num_mdts; i++) {
		if (param->fp_mdt_indexes[i] == param->fp_file_mdt_index)
			return !param->fp_exclude_mdt;
	}

	if (param->fp_exclude_mdt)
		return 1;

	return 0;
}

/**
 * Check whether the obd is active or not, if it is
 * not active, just print the object affected by this
 * failed target
 **/
static int print_failed_tgt(struct find_param *param, char *path, int type)
{
        struct obd_statfs stat_buf;
        struct obd_uuid uuid_buf;
	int ret;

	if (type != LL_STATFS_LOV && type != LL_STATFS_LMV)
		return -EINVAL;

        memset(&stat_buf, 0, sizeof(struct obd_statfs));
        memset(&uuid_buf, 0, sizeof(struct obd_uuid));
	ret = llapi_obd_statfs(path, type,
			       param->fp_obd_index, &stat_buf,
			       &uuid_buf);
	if (ret) {
		llapi_printf(LLAPI_MSG_NORMAL,
			     "obd_uuid: %s failed %s ",
			     param->fp_obd_uuid->uuid,
			     strerror(errno));
	}

	return ret;
}

static int find_check_stripe_size(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_user_md_v1 *v1 = &param->fp_lmd->lmd_lmm;
	int ret, i, count = 1;

	if (v1->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
		count = comp_v1->lcm_entry_count;
		ret = param->fp_exclude_stripe_size ? 1 : -1;
	}

	for (i = 0; i < count; i++) {
		if (comp_v1)
			v1 = lov_comp_entry(comp_v1, i);

		ret = find_value_cmp(v1->lmm_stripe_size, param->fp_stripe_size,
				     param->fp_stripe_size_sign,
				     param->fp_exclude_stripe_size,
				     param->fp_stripe_size_units, 0);
		/* If any stripe_size matches */
		if (ret != -1)
			break;
	}

	return ret;
}

static __u32 find_get_stripe_count(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_user_md_v1 *v1 = &param->fp_lmd->lmd_lmm;
	int i, count = 1;
	__u32 stripe_count = 0;

	if (v1->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
		count = comp_v1->lcm_entry_count;
	}

	for (i = 0; i < count; i++) {
		if (comp_v1)
			v1 = lov_comp_entry(comp_v1, i);
		stripe_count += v1->lmm_stripe_count;
	}

	return stripe_count;
}

#define LOV_PATTERN_INVALID	0xFFFFFFFF

static int find_check_layout(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_user_md_v1 *v1 = &param->fp_lmd->lmd_lmm;
	int i, count = 1;
	bool found = false, valid = false;

	if (v1->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
		count = comp_v1->lcm_entry_count;
	}

	for (i = 0; i < count; i++) {
		if (comp_v1)
			v1 = lov_comp_entry(comp_v1, i);

		if (v1->lmm_pattern == LOV_PATTERN_INVALID)
			continue;

		valid = true;
		if (v1->lmm_pattern & param->fp_layout) {
			found = true;
			break;
		}
	}

	if (!valid)
		return -1;

	if ((found && !param->fp_exclude_layout) ||
	    (!found && param->fp_exclude_layout))
		return 1;

	return -1;
}

static int find_check_pool(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_user_md_v1 *v1 = &param->fp_lmd->lmd_lmm;
	struct lov_user_md_v3 *v3 = (void *)v1;
	int i, count = 1;
	bool found = false;

	if (v1->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
		count = comp_v1->lcm_entry_count;
		/* empty requested pool is taken as no pool search */
		if (count == 0 && param->fp_poolname[0] == '\0')
			found = true;
	}

	for (i = 0; i < count; i++) {
		if (comp_v1 != NULL)
			v1 = lov_comp_entry(comp_v1, i);

		if (((v1->lmm_magic == LOV_USER_MAGIC_V1) &&
		     (param->fp_poolname[0] == '\0')) ||
		    ((v1->lmm_magic == LOV_USER_MAGIC_V3) &&
		     (strncmp(v3->lmm_pool_name,
			      param->fp_poolname, LOV_MAXPOOLNAME) == 0)) ||
		    ((v1->lmm_magic == LOV_USER_MAGIC_V3) &&
		     (strcmp(param->fp_poolname, "*") == 0))) {
			found = true;
			break;
		}
	}

	if ((found && !param->fp_exclude_pool) ||
	    (!found && param->fp_exclude_pool))
		return 1;

	return -1;
}

static int find_check_comp_options(struct find_param *param)
{
	lstat_t *st = &param->fp_lmd->lmd_st;
	struct lov_comp_md_v1 *comp_v1, *forged_v1 = NULL;
	struct lov_user_md_v1 *v1 = &param->fp_lmd->lmd_lmm;
	struct lov_comp_md_entry_v1 *entry;
	int i, ret = 0;

	if (v1->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
	} else {
		forged_v1 = malloc(sizeof(*forged_v1) + sizeof(*entry));
		if (forged_v1 == NULL)
			return -1;
		comp_v1 = forged_v1;
		comp_v1->lcm_entry_count = 1;
		entry = &comp_v1->lcm_entries[0];
		entry->lcme_flags = S_ISDIR(st->st_mode) ? 0 : LCME_FL_INIT;
		entry->lcme_extent.e_start = 0;
		entry->lcme_extent.e_end = LUSTRE_EOF;
	}

	/* invalid case, don't match for any kind of search. */
	if (comp_v1->lcm_entry_count == 0) {
		ret = -1;
		goto out;
	}

	if (param->fp_check_comp_count) {
		ret = find_value_cmp(forged_v1 ? 0 : comp_v1->lcm_entry_count,
				     param->fp_comp_count,
				     param->fp_comp_count_sign,
				     param->fp_exclude_comp_count, 1, 0);
		if (ret == -1)
			goto out;
	}

	ret = 1;
	for (i = 0; i < comp_v1->lcm_entry_count; i++) {
		entry = &comp_v1->lcm_entries[i];

		if (param->fp_check_comp_flags) {
			if (((entry->lcme_flags & param->fp_comp_flags) &&
			     param->fp_exclude_comp_flags) ||
			    (!(entry->lcme_flags & param->fp_comp_flags) &&
			     !param->fp_exclude_comp_flags))
				ret = -1;
			else
				ret = 1;

			if (ret == -1)
				continue;
		}

		if (param->fp_check_comp_start) {
			ret = find_value_cmp(entry->lcme_extent.e_start,
					     param->fp_comp_start,
					     param->fp_comp_start_sign,
					     param->fp_exclude_comp_start,
					     param->fp_comp_start_units, 0);
			if (ret == -1)
				continue;
		}

		if (param->fp_check_comp_end) {
			ret = find_comp_end_cmp(entry->lcme_extent.e_end,
						param);
			if (ret == -1)
				continue;
		}

		/* the component matches all criteria */
		break;
	}
out:
	if (forged_v1 != NULL)
		free(forged_v1);
	return ret;
}

static bool find_check_lmm_info(struct find_param *param)
{
	return param->fp_check_pool || param->fp_check_stripe_count ||
	       param->fp_check_stripe_size || param->fp_check_layout ||
	       param->fp_check_comp_count || param->fp_check_comp_end ||
	       param->fp_check_comp_start || param->fp_check_comp_flags ||
	       param->fp_check_projid;
}

/*
 * Get file/directory project id.
 * by the open fd resides on.
 * Return 0 and project id on success, or -ve errno.
 */
static int fget_projid(int fd, int *projid)
{
	struct fsxattr fsx;
	int rc;

	rc = ioctl(fd, LL_IOC_FSGETXATTR, &fsx);
	if (rc)
		return -errno;

	*projid = fsx.fsx_projid;
	return 0;
}

static int cb_find_init(char *path, DIR *parent, DIR **dirp,
			void *data, struct dirent64 *de)
{
	struct find_param *param = (struct find_param *)data;
	DIR *dir = dirp == NULL ? NULL : *dirp;
	int decision = 1; /* 1 is accepted; -1 is rejected. */
	lstat_t *st = &param->fp_lmd->lmd_st;
	int lustre_fs = 1;
	int checked_type = 0;
	int ret = 0;
	__u32 stripe_count = 0;
	int fd = -2;

	if (parent == NULL && dir == NULL)
		return -EINVAL;

	/* If a regular expression is presented, make the initial decision */
	if (param->fp_pattern != NULL) {
		char *fname = strrchr(path, '/');
		fname = (fname == NULL ? path : fname + 1);
		ret = fnmatch(param->fp_pattern, fname, 0);
		if ((ret == FNM_NOMATCH && !param->fp_exclude_pattern) ||
		    (ret == 0 && param->fp_exclude_pattern))
			goto decided;
	}

	/* See if we can check the file type from the dirent. */
	if (param->fp_type != 0 && de != NULL && de->d_type != DT_UNKNOWN) {
		checked_type = 1;

		if (DTTOIF(de->d_type) == param->fp_type) {
			if (param->fp_exclude_type)
				goto decided;
		} else {
			if (!param->fp_exclude_type)
				goto decided;
		}
	}

	ret = 0;

	/* Request MDS for the stat info if some of these parameters need
	 * to be compared. */
	if (param->fp_obd_uuid || param->fp_mdt_uuid ||
	    param->fp_check_uid || param->fp_check_gid ||
	    param->fp_atime || param->fp_mtime || param->fp_ctime ||
	    param->fp_check_size || find_check_lmm_info(param) ||
	    param->fp_check_mdt_count || param->fp_check_hash_type)
		decision = 0;

	if (param->fp_type != 0 && checked_type == 0)
                decision = 0;

	if (decision == 0) {
		if (param->fp_check_mdt_count || param->fp_check_hash_type) {
			param->fp_get_lmv = 1;
			ret = cb_get_dirstripe(path, dir, param);
			if (ret != 0)
				return ret;
		}

		param->fp_lmd->lmd_lmm.lmm_magic = 0;
		ret = get_lmd_info(path, parent, dir, param->fp_lmd,
				   param->fp_lum_size);
		if (ret == 0 && param->fp_lmd->lmd_lmm.lmm_magic == 0 &&
		    find_check_lmm_info(param)) {
			struct lov_user_md *lmm = &param->fp_lmd->lmd_lmm;

			/* We need to "fake" the "use the default" values
			 * since the lmm struct is zeroed out at this point. */
			lmm->lmm_magic = LOV_USER_MAGIC_V1;
			lmm->lmm_pattern = 0xFFFFFFFF;
			if (!param->fp_raw)
				ostid_set_seq(&lmm->lmm_oi,
					      FID_SEQ_LOV_DEFAULT);
			lmm->lmm_stripe_size = 0;
			lmm->lmm_stripe_count = 0;
			lmm->lmm_stripe_offset = -1;
		}
		if (ret == 0 && param->fp_mdt_uuid != NULL) {
			if (dir != NULL) {
				ret = llapi_file_fget_mdtidx(dirfd(dir),
						     &param->fp_file_mdt_index);
			} else if (S_ISREG(st->st_mode)) {
				/* FIXME: we could get the MDT index from the
				 * file's FID in lmd->lmd_lmm.lmm_oi without
				 * opening the file, once we are sure that
				 * LFSCK2 (2.6) has fixed up pre-2.0 LOV EAs.
				 * That would still be an ioctl() to map the
				 * FID to the MDT, but not an open RPC. */
				fd = open(path, O_RDONLY);
				if (fd > 0) {
					ret = llapi_file_fget_mdtidx(fd,
						     &param->fp_file_mdt_index);
				} else {
					ret = -errno;
				}
			} else {
				/* For a special file, we assume it resides on
				 * the same MDT as the parent directory. */
				ret = llapi_file_fget_mdtidx(dirfd(parent),
						     &param->fp_file_mdt_index);
			}
		}
		if (ret != 0) {
			if (ret == -ENOTTY)
				lustre_fs = 0;
			if (ret == -ENOENT)
				goto decided;

			goto out;
		} else {
			stripe_count = find_get_stripe_count(param);
		}
	}

	if (param->fp_type && !checked_type) {
		if ((st->st_mode & S_IFMT) == param->fp_type) {
			if (param->fp_exclude_type)
				goto decided;
		} else {
			if (!param->fp_exclude_type)
				goto decided;
		}
	}

        /* Prepare odb. */
	if (param->fp_obd_uuid || param->fp_mdt_uuid) {
		if (lustre_fs && param->fp_got_uuids &&
		    param->fp_dev != st->st_dev) {
			/* A lustre/lustre mount point is crossed. */
			param->fp_got_uuids = 0;
			param->fp_obds_printed = 0;
			param->fp_mdt_index = OBD_NOT_FOUND;
			param->fp_obd_index = OBD_NOT_FOUND;
		}

		if (lustre_fs && !param->fp_got_uuids) {
			ret = setup_target_indexes(dir ? dir : parent, path,
						   param);
			if (ret)
				goto out;

			param->fp_dev = st->st_dev;
		} else if (!lustre_fs && param->fp_got_uuids) {
			/* A lustre/non-lustre mount point is crossed. */
			param->fp_got_uuids = 0;
			param->fp_mdt_index = OBD_NOT_FOUND;
			param->fp_obd_index = OBD_NOT_FOUND;
                }
        }

	if (param->fp_check_stripe_size) {
		decision = find_check_stripe_size(param);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_stripe_count) {
		decision = find_value_cmp(stripe_count, param->fp_stripe_count,
					  param->fp_stripe_count_sign,
					  param->fp_exclude_stripe_count, 1, 0);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_mdt_count) {
		decision = find_value_cmp(
				param->fp_lmv_md->lum_stripe_count,
				param->fp_mdt_count,
				param->fp_mdt_count_sign,
				param->fp_exclude_mdt_count, 1, 0);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_layout) {
		decision = find_check_layout(param);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_hash_type) {
		__u32 found;

		found = param->fp_lmv_md->lum_hash_type & param->fp_hash_type;
		if ((found && param->fp_exclude_hash_type) ||
		    (!found && !param->fp_exclude_hash_type)) {
			decision = -1;
			goto decided;
		}
	}

	/* If an OBD UUID is specified but none matches, skip this file. */
	if ((param->fp_obd_uuid && param->fp_obd_index == OBD_NOT_FOUND) ||
	    (param->fp_mdt_uuid && param->fp_mdt_index == OBD_NOT_FOUND))
		goto decided;

	/* If an OST or MDT UUID is given, and some OST matches,
	 * check it here. */
	if (param->fp_obd_index != OBD_NOT_FOUND ||
	    param->fp_mdt_index != OBD_NOT_FOUND) {
		if (param->fp_obd_uuid) {
			if (check_obd_match(param)) {
				/* If no mdtuuid is given, we are done.
				 * Otherwise, fall through to the mdtuuid
				 * check below. */
				if (!param->fp_mdt_uuid)
					goto obd_matches;
			} else {
				goto decided;
			}
		}

		if (param->fp_mdt_uuid) {
			if (check_mdt_match(param))
				goto obd_matches;
			goto decided;
		}
	}

obd_matches:
	if (param->fp_check_uid) {
		if (st->st_uid == param->fp_uid) {
			if (param->fp_exclude_uid)
				goto decided;
		} else {
			if (!param->fp_exclude_uid)
				goto decided;
		}
	}

	if (param->fp_check_gid) {
		if (st->st_gid == param->fp_gid) {
			if (param->fp_exclude_gid)
				goto decided;
		} else {
			if (!param->fp_exclude_gid)
				goto decided;
		}
	}

	if (param->fp_check_projid) {
		int projid = 0;

		if (fd == -2)
			fd = open(path, O_RDONLY);

		if (fd > 0)
			ret = fget_projid(fd, &projid);
		else
			ret = -errno;
		if (ret)
			goto out;
		if (projid == param->fp_projid) {
			if (param->fp_exclude_uid)
				goto decided;
		} else {
			if (!param->fp_exclude_projid)
				goto decided;
		}
	}

	if (param->fp_check_pool) {
		decision = find_check_pool(param);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_comp_count || param->fp_check_comp_flags ||
	    param->fp_check_comp_start || param->fp_check_comp_end) {
		decision = find_check_comp_options(param);
		if (decision == -1)
			goto decided;
	}

	/* Check the time on mds. */
	decision = 1;
	if (param->fp_atime || param->fp_mtime || param->fp_ctime) {
                int for_mds;

		for_mds = lustre_fs ?
			(S_ISREG(st->st_mode) && stripe_count) : 0;
                decision = find_time_check(st, param, for_mds);
                if (decision == -1)
                        goto decided;
        }

        /* If file still fits the request, ask ost for updated info.
           The regular stat is almost of the same speed as some new
           'glimpse-size-ioctl'. */

	if (param->fp_check_size && S_ISREG(st->st_mode) && stripe_count)
		decision = 0;

	if (param->fp_check_size && S_ISDIR(st->st_mode))
		decision = 0;

	if (!decision) {
                /* For regular files with the stripe the decision may have not
                 * been taken yet if *time or size is to be checked. */
		if (param->fp_obd_index != OBD_NOT_FOUND)
                        print_failed_tgt(param, path, LL_STATFS_LOV);

		if (param->fp_mdt_index != OBD_NOT_FOUND)
                        print_failed_tgt(param, path, LL_STATFS_LMV);

		if (dir != NULL)
			ret = fstat_f(dirfd(dir), st);
		else if (de != NULL)
			ret = fstatat_f(dirfd(parent), de->d_name, st,
					AT_SYMLINK_NOFOLLOW);
		else
			ret = lstat_f(path, st);

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
				goto out;
			}
		}

		/* Check the time on osc. */
		decision = find_time_check(st, param, 0);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_size)
		decision = find_value_cmp(st->st_size, param->fp_size,
					  param->fp_size_sign,
					  param->fp_exclude_size,
					  param->fp_size_units, 0);

	if (decision != -1) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", path);
		if (param->fp_zero_end)
			llapi_printf(LLAPI_MSG_NORMAL, "%c", '\0');
		else
			llapi_printf(LLAPI_MSG_NORMAL, "\n");
	}

decided:
	ret = 0;
	/* Do not get down anymore? */
	if (param->fp_depth == param->fp_max_depth) {
		ret = 1;
		goto out;
	}
	param->fp_depth++;
out:
	if (fd > 0)
		close(fd);
	return ret;
}

static int cb_migrate_mdt_init(char *path, DIR *parent, DIR **dirp,
			       void *param_data, struct dirent64 *de)
{
	struct find_param	*param = (struct find_param *)param_data;
	DIR			*tmp_parent = parent;
	char			raw[OBD_MAX_IOCTL_BUFFER] = {'\0'};
	char			*rawbuf = raw;
	struct obd_ioctl_data	data = { 0 };
	int			fd;
	int			ret;
	char			*path_copy;
	char			*filename;
	bool			retry = false;

	if (parent == NULL && dirp == NULL)
		return -EINVAL;

	if (dirp != NULL)
		closedir(*dirp);

	if (parent == NULL) {
		tmp_parent = opendir_parent(path);
		if (tmp_parent == NULL) {
			*dirp = NULL;
			ret = -errno;
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "can not open %s", path);
			return ret;
		}
	}

	fd = dirfd(tmp_parent);

	path_copy = strdup(path);
	filename = basename(path_copy);
	data.ioc_inlbuf1 = (char *)filename;
	data.ioc_inllen1 = strlen(filename) + 1;
	data.ioc_inlbuf2 = (char *)&param->fp_mdt_index;
	data.ioc_inllen2 = sizeof(param->fp_mdt_index);
	ret = obd_ioctl_pack(&data, &rawbuf, sizeof(raw));
	if (ret != 0) {
		llapi_error(LLAPI_MSG_ERROR, ret,
			    "llapi_obd_statfs: error packing ioctl data");
		goto out;
	}

migrate:
	ret = ioctl(fd, LL_IOC_MIGRATE, rawbuf);
	if (ret != 0) {
		if (errno == EBUSY && !retry) {
			/* because migrate may not be able to lock all involved
			 * objects in order, for some of them it try lock, while
			 * there may be conflicting COS locks and cause migrate
			 * fail with EBUSY, hope a sync() could cause
			 * transaction commit and release these COS locks. */
			sync();
			retry = true;
			goto migrate;
		}
		ret = -errno;
		fprintf(stderr, "%s migrate failed: %s (%d)\n",
			path, strerror(-ret), ret);
		goto out;
	} else if (param->fp_verbose & VERBOSE_DETAIL) {
		fprintf(stdout, "migrate %s to MDT%d\n",
			path, param->fp_mdt_index);
	}

out:
	if (dirp != NULL) {
		/* If the directory is being migration, we need
		 * close the directory after migration,
		 * so the old directory cache will be cleanup
		 * on the client side, and re-open to get the
		 * new directory handle */
		*dirp = opendir(path);
		if (*dirp == NULL) {
			ret = -errno;
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "%s: Failed to open '%s'", __func__, path);
		}
	}

	if (parent == NULL)
		closedir(tmp_parent);

	free(path_copy);

	return ret;
}

int llapi_migrate_mdt(char *path, struct find_param *param)
{
	return param_callback(path, cb_migrate_mdt_init, cb_common_fini, param);
}

int llapi_mv(char *path, struct find_param *param)
{
#if LUSTRE_VERSION_CODE > OBD_OCD_VERSION(2, 9, 59, 0)
	static bool printed;

	if (!printed) {
		llapi_error(LLAPI_MSG_ERROR, -ESTALE,
			    "llapi_mv() is deprecated, use llapi_migrate_mdt()\n");
		printed = true;
	}
#endif
	return llapi_migrate_mdt(path, param);
}

int llapi_find(char *path, struct find_param *param)
{
        return param_callback(path, cb_find_init, cb_common_fini, param);
}

/*
 * Get MDT number that the file/directory inode referenced
 * by the open fd resides on.
 * Return 0 and mdtidx on success, or -ve errno.
 */
int llapi_file_fget_mdtidx(int fd, int *mdtidx)
{
        if (ioctl(fd, LL_IOC_GET_MDTIDX, mdtidx) < 0)
                return -errno;
        return 0;
}

static int cb_get_mdt_index(char *path, DIR *parent, DIR **dirp, void *data,
			    struct dirent64 *de)
{
	struct find_param *param = (struct find_param *)data;
	DIR *d = dirp == NULL ? NULL : *dirp;
	int ret;
	int mdtidx;

	if (parent == NULL && d == NULL)
		return -EINVAL;

	if (d != NULL) {
		ret = llapi_file_fget_mdtidx(dirfd(d), &mdtidx);
	} else /* if (parent) */ {
		int fd;

		fd = open(path, O_RDONLY | O_NOCTTY);
		if (fd > 0) {
			ret = llapi_file_fget_mdtidx(fd, &mdtidx);
			close(fd);
		} else {
			ret = -errno;
		}
	}

	if (ret != 0) {
		if (ret == -ENODATA) {
			if (!param->fp_obd_uuid)
				llapi_printf(LLAPI_MSG_NORMAL,
					     "'%s' has no stripe info\n", path);
			goto out;
		} else if (ret == -ENOENT) {
			llapi_error(LLAPI_MSG_WARN, ret,
				    "warning: %s: '%s' does not exist",
				    __func__, path);
			goto out;
		} else if (ret == -ENOTTY) {
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "%s: '%s' not on a Lustre fs",
				    __func__, path);
		} else {
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "error: %s: '%s' failed get_mdtidx",
				    __func__, path);
		}
		return ret;
	}

	if (param->fp_quiet || !(param->fp_verbose & VERBOSE_DETAIL))
		llapi_printf(LLAPI_MSG_NORMAL, "%d\n", mdtidx);
	else
		llapi_printf(LLAPI_MSG_NORMAL, "%s\nmdt_index:\t%d\n",
			     path, mdtidx);

out:
	/* Do not go down anymore? */
	if (param->fp_depth == param->fp_max_depth)
		return 1;

	param->fp_depth++;

	return 0;
}

static int cb_getstripe(char *path, DIR *parent, DIR **dirp, void *data,
			struct dirent64 *de)
{
        struct find_param *param = (struct find_param *)data;
	DIR *d = dirp == NULL ? NULL : *dirp;
        int ret = 0;

	if (parent == NULL && d == NULL)
		return -EINVAL;

	if (param->fp_obd_uuid) {
		param->fp_quiet = 1;
		ret = setup_obd_uuid(d ? dirfd(d) : dirfd(parent), path, param);
		if (ret)
			return ret;
	}

	if (d) {
		if (param->fp_get_lmv || param->fp_get_default_lmv) {
			ret = cb_get_dirstripe(path, d, param);
		} else {
			ret = ioctl(dirfd(d), LL_IOC_LOV_GETSTRIPE,
				     (void *)&param->fp_lmd->lmd_lmm);
		}

	} else if (parent && !param->fp_get_lmv && !param->fp_get_default_lmv) {
		char *fname = strrchr(path, '/');
		fname = (fname == NULL ? path : fname + 1);

		strlcpy((char *)&param->fp_lmd->lmd_lmm, fname,
			param->fp_lum_size);

		ret = ioctl(dirfd(parent), IOC_MDC_GETFILESTRIPE,
			    (void *)&param->fp_lmd->lmd_lmm);
	} else {
		return 0;
	}

        if (ret) {
                if (errno == ENODATA && d != NULL) {
			/* We need to "fake" the "use the default" values
			 * since the lmm struct is zeroed out at this point.
			 * The magic needs to be set in order to satisfy
			 * a check later on in the code path.
			 * The object_seq needs to be set for the "(Default)"
			 * prefix to be displayed. */
			if (param->fp_get_default_lmv) {
				struct lmv_user_md *lum = param->fp_lmv_md;

				lum->lum_magic = LMV_USER_MAGIC;
				lum->lum_stripe_count = 0;
				lum->lum_stripe_offset = -1;
				goto dump;
			} else if (param->fp_get_lmv) {
				struct lmv_user_md *lum = param->fp_lmv_md;
				int mdtidx;

				ret = llapi_file_fget_mdtidx(dirfd(d), &mdtidx);
				if (ret != 0)
					goto err_out;
				lum->lum_magic = LMV_MAGIC_V1;
				lum->lum_stripe_count = 0;
				lum->lum_stripe_offset = mdtidx;
				goto dump;
			} else {
				struct lov_user_md *lmm =
					&param->fp_lmd->lmd_lmm;

				lmm->lmm_magic = LOV_USER_MAGIC_V1;
				if (!param->fp_raw)
					ostid_set_seq(&lmm->lmm_oi,
						      FID_SEQ_LOV_DEFAULT);
				lmm->lmm_stripe_count = 0;
				lmm->lmm_stripe_size = 0;
				lmm->lmm_stripe_offset = -1;
				goto dump;
			}
                } else if (errno == ENODATA && parent != NULL) {
			if (!param->fp_obd_uuid && !param->fp_mdt_uuid)
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
err_out:
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "error: %s: %s failed for %s",
				     __func__, d ? "LL_IOC_LOV_GETSTRIPE" :
				    "IOC_MDC_GETFILESTRIPE", path);
		}

                return ret;
        }

dump:
	if (!(param->fp_verbose & VERBOSE_MDTINDEX))
		llapi_lov_dump_user_lmm(param, path, d ? LDF_IS_DIR : 0);

out:
	/* Do not get down anymore? */
	if (param->fp_depth == param->fp_max_depth)
		return 1;

	param->fp_depth++;

	return 0;
}

int llapi_getstripe(char *path, struct find_param *param)
{
	return param_callback(path, (param->fp_verbose & VERBOSE_MDTINDEX) ?
                              cb_get_mdt_index : cb_getstripe,
                              cb_common_fini, param);
}

int llapi_obd_fstatfs(int fd, __u32 type, __u32 index,
		      struct obd_statfs *stat_buf, struct obd_uuid *uuid_buf)
{
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

	rc = ioctl(fd, IOC_OBD_STATFS, (void *)rawbuf);

	return rc < 0 ? -errno : 0;
}

int llapi_obd_statfs(char *path, __u32 type, __u32 index,
		     struct obd_statfs *stat_buf, struct obd_uuid *uuid_buf)
{
	int fd;
	int rc;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: %s: opening '%s'",
			    __func__, path);
		/* If we can't even open a file on the filesystem (e.g. with
		 * -ESHUTDOWN), force caller to exit or it will loop forever. */
		return -ENODEV;
	}

	rc = llapi_obd_fstatfs(fd, type, index, stat_buf, uuid_buf);

	close(fd);

	return rc;
}

#define MAX_STRING_SIZE 128

int llapi_ping(char *obd_type, char *obd_name)
{
	glob_t path;
	char buf[1];
	int rc, fd;

	rc = cfs_get_param_paths(&path, "%s/%s/ping",
				obd_type, obd_name);
	if (rc != 0)
		return -errno;

	fd = open(path.gl_pathv[0], O_WRONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error opening %s",
			    path.gl_pathv[0]);
		goto failed;
	}

	/* The purpose is to send a byte as a ping, whatever this byte is. */
	/* coverity[uninit_use_in_call] */
	rc = write(fd, buf, 1);
	if (rc < 0)
		rc = -errno;
	close(fd);

	if (rc == 1)
		rc = 0;
failed:
	cfs_free_param_data(&path);
	return rc;
}

int llapi_target_iterate(int type_num, char **obd_type,
                         void *args, llapi_cb_t cb)
{
	char buf[MAX_STRING_SIZE];
	int i, rc = 0;
	glob_t param;
	FILE *fp;

	rc = cfs_get_param_paths(&param, "devices");
	if (rc != 0)
		return -ENOENT;

	fp = fopen(param.gl_pathv[0], "r");
	if (fp == NULL) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: opening '%s'",
			    param.gl_pathv[0]);
		goto free_path;
	}

        while (fgets(buf, sizeof(buf), fp) != NULL) {
                char *obd_type_name = NULL;
                char *obd_name = NULL;
                char *obd_uuid = NULL;
                char *bufp = buf;
                struct obd_statfs osfs_buffer;

                while(bufp[0] == ' ')
                        ++bufp;

                for(i = 0; i < 3; i++) {
                        obd_type_name = strsep(&bufp, " ");
                }
                obd_name = strsep(&bufp, " ");
                obd_uuid = strsep(&bufp, " ");

                memset(&osfs_buffer, 0, sizeof (osfs_buffer));

                for (i = 0; i < type_num; i++) {
                        if (strcmp(obd_type_name, obd_type[i]) != 0)
                                continue;

                        cb(obd_type_name, obd_name, obd_uuid, args);
                }
	}
	fclose(fp);
free_path:
	cfs_free_param_data(&param);
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

int llapi_quotactl(char *mnt, struct if_quotactl *qctl)
{
	char fsname[PATH_MAX + 1];
	int root;
	int rc;

	rc = llapi_search_fsname(mnt, fsname);
	if (rc) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "'%s' isn't on Lustre filesystem", mnt);
		return rc;
	}

	root = open(mnt, O_RDONLY | O_DIRECTORY);
	if (root < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "open %s failed", mnt);
		return rc;
	}

	rc = ioctl(root, OBD_IOC_QUOTACTL, qctl);
	if (rc < 0)
		rc = -errno;

	close(root);
	return rc;
}

/* Print mdtname 'name' into 'buf' using 'format'.  Add -MDT0000 if needed.
 * format must have %s%s, buf must be > 16
 * Eg: if name = "lustre-MDT0000", "lustre", or "lustre-MDT0000_UUID"
 *     then buf = "lustre-MDT0000"
 */
static int get_mdtname(char *name, char *format, char *buf)
{
        char suffix[]="-MDT0000";
        int len = strlen(name);

        if ((len > 5) && (strncmp(name + len - 5, "_UUID", 5) == 0)) {
                name[len - 5] = '\0';
                len -= 5;
        }

        if (len > 8) {
                if ((len <= 16) && strncmp(name + len - 8, "-MDT", 4) == 0) {
                        suffix[0] = '\0';
                } else {
                        /* Not enough room to add suffix */
                        llapi_err_noerrno(LLAPI_MSG_ERROR,
                                          "MDT name too long |%s|", name);
                        return -EINVAL;
                }
        }

        return sprintf(buf, format, name, suffix);
}

/** ioctl on filsystem root, with mdtindex sent as data
 * \param mdtname path, fsname, or mdtname (lutre-MDT0004)
 * \param mdtidxp pointer to integer within data to be filled in with the
 *    mdt index (0 if no mdt is specified).  NULL won't be filled.
 */
int root_ioctl(const char *mdtname, int opc, void *data, int *mdtidxp,
	       int want_error)
{
	char fsname[20];
	char *ptr;
	int fd, rc;
	long index;

	/* Take path, fsname, or MDTname.  Assume MDT0000 in the former cases.
	 Open root and parse mdt index. */
	if (mdtname[0] == '/') {
		index = 0;
		rc = get_root_path(WANT_FD | want_error, NULL, &fd,
				   (char *)mdtname, -1);
	} else {
		if (get_mdtname((char *)mdtname, "%s%s", fsname) < 0)
			return -EINVAL;
		ptr = fsname + strlen(fsname) - 8;
		*ptr = '\0';
		index = strtol(ptr + 4, NULL, 16);
		rc = get_root_path(WANT_FD | want_error, fsname, &fd, NULL, -1);
	}
	if (rc < 0) {
		if (want_error)
			llapi_err_noerrno(LLAPI_MSG_ERROR,
					  "Can't open %s: %d\n", mdtname, rc);
		return rc;
	}

	if (mdtidxp)
		*mdtidxp = index;

	rc = ioctl(fd, opc, data);
	if (rc == -1)
		rc = -errno;
	else
		rc = 0;
	close(fd);
	return rc;
}

int llapi_fid2path(const char *device, const char *fidstr, char *buf,
		   int buflen, long long *recno, int *linkno)
{
	const char *fidstr_orig = fidstr;
	struct lu_fid fid;
	struct getinfo_fid2path *gf;
	int rc;

	while (*fidstr == '[')
		fidstr++;

	sscanf(fidstr, SFID, RFID(&fid));
	if (!fid_is_sane(&fid)) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "bad FID format '%s', should be [seq:oid:ver]"
				  " (e.g. "DFID")\n", fidstr_orig,
				  (unsigned long long)FID_SEQ_NORMAL, 2, 0);
		return -EINVAL;
	}

	gf = malloc(sizeof(*gf) + buflen);
	if (gf == NULL)
		return -ENOMEM;

	gf->gf_fid = fid;
	gf->gf_recno = *recno;
	gf->gf_linkno = *linkno;
	gf->gf_pathlen = buflen;

	/* Take path or fsname */
	rc = root_ioctl(device, OBD_IOC_FID2PATH, gf, NULL, 0);
	if (rc)
		goto out_free;

	memcpy(buf, gf->gf_u.gf_path, gf->gf_pathlen);
	if (buf[0] == '\0') { /* ROOT path */
		buf[0] = '/';
		buf[1] = '\0';
	}
	*recno = gf->gf_recno;
	*linkno = gf->gf_linkno;

out_free:
	free(gf);
	return rc;
}

static int fid_from_lma(const char *path, const int fd, lustre_fid *fid)
{
	char			 buf[512];
	struct lustre_mdt_attrs	*lma;
	int			 rc;

	if (path == NULL)
		rc = fgetxattr(fd, XATTR_NAME_LMA, buf, sizeof(buf));
	else
		rc = lgetxattr(path, XATTR_NAME_LMA, buf, sizeof(buf));
	if (rc < 0)
		return -errno;
	lma = (struct lustre_mdt_attrs *)buf;
	fid_le_to_cpu(fid, &lma->lma_self_fid);
	return 0;
}

int llapi_get_mdt_index_by_fid(int fd, const lustre_fid *fid,
			       int *mdt_index)
{
	int	rc;

	rc = ioctl(fd, LL_IOC_FID2MDTIDX, fid);
	if (rc < 0)
		return -errno;

	*mdt_index = rc;

	return rc;
}

int llapi_fd2fid(const int fd, lustre_fid *fid)
{
	int rc;

	memset(fid, 0, sizeof(*fid));

	rc = ioctl(fd, LL_IOC_PATH2FID, fid) < 0 ? -errno : 0;
	if (rc == -EINVAL || rc == -ENOTTY)
		rc = fid_from_lma(NULL, fd, fid);

	return rc;
}

int llapi_path2fid(const char *path, lustre_fid *fid)
{
	int fd, rc;

	memset(fid, 0, sizeof(*fid));
	fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
	if (fd < 0) {
		if (errno == ELOOP || errno == ENXIO)
			return fid_from_lma(path, -1, fid);
		return -errno;
	}

	rc = llapi_fd2fid(fd, fid);
	if (rc == -EINVAL || rc == -ENOTTY)
		rc = fid_from_lma(path, -1, fid);

	close(fd);
	return rc;
}

int llapi_fd2parent(int fd, unsigned int linkno, lustre_fid *parent_fid,
		    char *name, size_t name_size)
{
	struct getparent	*gp;
	int			 rc;

	gp = malloc(sizeof(*gp) + name_size);
	if (gp == NULL)
		return -ENOMEM;

	gp->gp_linkno = linkno;
	gp->gp_name_size = name_size;

	rc = ioctl(fd, LL_IOC_GETPARENT, gp);
	if (rc < 0) {
		rc = -errno;
		goto err_free;
	}

	*parent_fid = gp->gp_fid;

	strncpy(name, gp->gp_name, name_size);
	name[name_size - 1] = '\0';

err_free:
	free(gp);
	return rc;
}

int llapi_path2parent(const char *path, unsigned int linkno,
		      lustre_fid *parent_fid, char *name, size_t name_size)
{
	int	fd;
	int	rc;

	fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
	if (fd < 0)
		return -errno;

	rc = llapi_fd2parent(fd, linkno, parent_fid, name, name_size);
	close(fd);
	return rc;
}

int llapi_get_connect_flags(const char *mnt, __u64 *flags)
{
	int root;
	int rc;

	root = open(mnt, O_RDONLY | O_DIRECTORY);
	if (root < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "open %s failed", mnt);
		return rc;
	}

	rc = ioctl(root, LL_IOC_GET_CONNECT_FLAGS, flags);
	if (rc < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			"ioctl on %s for getting connect flags failed", mnt);
	}
	close(root);
	return rc;
}

/**
 * Get a 64-bit value representing the version of file data pointed by fd.
 *
 * Each write or truncate, flushed on OST, will change this value. You can use
 * this value to verify if file data was modified. This only checks the file
 * data, not metadata.
 *
 * \param  flags  0: no flush pages, usually used it the process has already
 *		    taken locks;
 *                LL_DV_RD_FLUSH: OSTs will take LCK_PR to flush dirty pages
 *                  from clients;
 *                LL_DV_WR_FLUSH: OSTs will take LCK_PW to flush all caching
 *                  pages from clients.
 *
 * \retval 0 on success.
 * \retval -errno on error.
 */
int llapi_get_data_version(int fd, __u64 *data_version, __u64 flags)
{
        int rc;
        struct ioc_data_version idv;

        idv.idv_flags = flags;

        rc = ioctl(fd, LL_IOC_DATA_VERSION, &idv);
        if (rc)
                rc = -errno;
        else
                *data_version = idv.idv_version;

        return rc;
}

/*
 * Create a file without any name open it for read/write
 *
 * - file is created as if it were a standard file in the given \a directory
 * - file does not appear in \a directory and mtime does not change because
 *   the filename is handled specially by the Lustre MDS.
 * - file is removed at final close
 * - file modes are rw------- since it doesn't make sense to have a read-only
 *   or write-only file that cannot be opened again.
 * - if user wants another mode it must use fchmod() on the open file, no
 *   security problems arise because it cannot be opened by another process.
 *
 * \param[in]	directory	directory from which to inherit layout/MDT idx
 * \param[in]	idx		MDT index on which the file is created,
 *				\a idx == -1 means no specific MDT is requested
 * \param[in]	open_flags	standard open(2) flags
 *
 * \retval	0 on success.
 * \retval	-errno on error.
 */
int llapi_create_volatile_idx(char *directory, int idx, int open_flags)
{
	char	file_path[PATH_MAX];
	char	filename[PATH_MAX];
	int	saved_errno = errno;
	int	fd;
	int	rnumber;
	int	rc;

	do {
		rnumber = random();
		if (idx == -1)
			snprintf(filename, sizeof(filename),
				 LUSTRE_VOLATILE_HDR"::%.4X", rnumber);
		else
			snprintf(filename, sizeof(filename),
				 LUSTRE_VOLATILE_HDR":%.4X:%.4X", idx, rnumber);

		rc = snprintf(file_path, sizeof(file_path),
			      "%s/%s", directory, filename);
		if (rc >= sizeof(file_path))
			return -E2BIG;

		fd = open(file_path,
			  O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | open_flags,
			  S_IRUSR | S_IWUSR);
	} while (fd < 0 && errno == EEXIST);

	if (fd < 0) {
		llapi_error(LLAPI_MSG_ERROR, errno,
			    "Cannot create volatile file '%s' in '%s'",
			    filename + LUSTRE_VOLATILE_HDR_LEN,
			    directory);
		return -errno;
	}

	/* Unlink file in case this wasn't a Lustre filesystem and the
	 * magic volatile filename wasn't handled as intended. The
	 * effect is the same. If volatile open was supported then we
	 * expect unlink() to return -ENOENT. */
	(void)unlink(file_path);

	/* Since we are returning successfully we restore errno (and
	 * mask out possible EEXIST from open() and ENOENT from
	 * unlink(). */
	errno = saved_errno;

	return fd;
}

/**
 * Swap the layouts between 2 file descriptors
 * the 2 files must be open for writing
 * first fd received the ioctl, second fd is passed as arg
 * this is assymetric but avoid use of root path for ioctl
 */
int llapi_fswap_layouts_grouplock(int fd1, int fd2, __u64 dv1, __u64 dv2,
				  int gid, __u64 flags)
{
	struct lustre_swap_layouts	lsl;
	struct stat			st1;
	struct stat			st2;
	int				rc;

	if (flags & (SWAP_LAYOUTS_KEEP_ATIME | SWAP_LAYOUTS_KEEP_MTIME)) {
		rc = fstat(fd1, &st1);
		if (rc < 0)
			return -errno;

		rc = fstat(fd2, &st2);
		if (rc < 0)
			return -errno;
	}
	lsl.sl_fd = fd2;
	lsl.sl_flags = flags;
	lsl.sl_gid = gid;
	lsl.sl_dv1 = dv1;
	lsl.sl_dv2 = dv2;
	rc = ioctl(fd1, LL_IOC_LOV_SWAP_LAYOUTS, &lsl);
	if (rc < 0)
		return -errno;

	if (flags & (SWAP_LAYOUTS_KEEP_ATIME | SWAP_LAYOUTS_KEEP_MTIME)) {
		struct timeval	tv1[2];
		struct timeval	tv2[2];

		memset(tv1, 0, sizeof(tv1));
		memset(tv2, 0, sizeof(tv2));

		if (flags & SWAP_LAYOUTS_KEEP_ATIME) {
			tv1[0].tv_sec = st1.st_atime;
			tv2[0].tv_sec = st2.st_atime;
		} else {
			tv1[0].tv_sec = st2.st_atime;
			tv2[0].tv_sec = st1.st_atime;
		}

		if (flags & SWAP_LAYOUTS_KEEP_MTIME) {
			tv1[1].tv_sec = st1.st_mtime;
			tv2[1].tv_sec = st2.st_mtime;
		} else {
			tv1[1].tv_sec = st2.st_mtime;
			tv2[1].tv_sec = st1.st_mtime;
		}

		rc = futimes(fd1, tv1);
		if (rc < 0)
			return -errno;

		rc = futimes(fd2, tv2);
		if (rc < 0)
			return -errno;
	}

	return 0;
}

int llapi_fswap_layouts(int fd1, int fd2, __u64 dv1, __u64 dv2, __u64 flags)
{
	int	rc;
	int	grp_id;

	do
		grp_id = random();
	while (grp_id == 0);

	rc = llapi_fswap_layouts_grouplock(fd1, fd2, dv1, dv2, grp_id, flags);
	if (rc < 0)
		return rc;

	return 0;
}

/**
 * Swap the layouts between 2 files
 * the 2 files are open in write
 */
int llapi_swap_layouts(const char *path1, const char *path2,
		       __u64 dv1, __u64 dv2, __u64 flags)
{
	int	fd1, fd2, rc;

	fd1 = open(path1, O_WRONLY | O_LOV_DELAY_CREATE);
	if (fd1 < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: cannot open '%s' for write", path1);
		goto out;
	}

	fd2 = open(path2, O_WRONLY | O_LOV_DELAY_CREATE);
	if (fd2 < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: cannot open '%s' for write", path2);
		goto out_close;
	}

	rc = llapi_fswap_layouts(fd1, fd2, dv1, dv2, flags);
	if (rc < 0)
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: cannot swap layout between '%s' and '%s'",
			    path1, path2);

	close(fd2);
out_close:
	close(fd1);
out:
	return rc;
}

/**
 * Attempt to open a file with Lustre file identifier \a fid
 * and return an open file descriptor.
 *
 * \param[in] lustre_dir	path within Lustre filesystem containing \a fid
 * \param[in] fid		Lustre file identifier of file to open
 * \param[in] flags		open() flags
 *
 * \retval			non-negative file descriptor on successful open
 * \retval			-1 if an error occurred
 */
int llapi_open_by_fid(const char *lustre_dir, const lustre_fid *fid, int flags)
{
	char mntdir[PATH_MAX];
	char path[PATH_MAX];
	int rc;

	rc = llapi_search_mounts(lustre_dir, 0, mntdir, NULL);
	if (rc != 0)
		return -1;

	snprintf(path, sizeof(path), "%s/.lustre/fid/"DFID, mntdir, PFID(fid));
	return open(path, flags);
}

/**
 * Take group lock.
 *
 * \param fd   File to lock.
 * \param gid  Group Identifier.
 *
 * \retval 0 on success.
 * \retval -errno on failure.
 */
int llapi_group_lock(int fd, int gid)
{
	int rc;

	rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
	if (rc < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot get group lock");
	}
	return rc;
}

/**
 * Put group lock.
 *
 * \param fd   File to unlock.
 * \param gid  Group Identifier.
 *
 * \retval 0 on success.
 * \retval -errno on failure.
 */
int llapi_group_unlock(int fd, int gid)
{
	int rc;

	rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);
	if (rc < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot put group lock");
	}
	return rc;
}
