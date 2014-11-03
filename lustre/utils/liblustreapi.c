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
 * Copyright (c) 2011, 2013, Intel Corporation.
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
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <fnmatch.h>
#include <glob.h>
#include <libgen.h> /* for dirname() */
#ifdef HAVE_LINUX_UNISTD_H
#include <linux/unistd.h>
#else
#include <unistd.h>
#endif
#include <poll.h>

#include <libcfs/libcfs.h>
#include <lnet/lnetctl.h>
#include <lustre/lustreapi.h>
#include <lustre_ioctl.h>
#include "lustreapi_internal.h"

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

        if (strncmp(optarg, "-", 1) == 0)
                return -1;

        if (*size_units == 0)
                *size_units = 1;

        *size = strtoull(optarg, &end, 0);

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
        *size *= *size_units;
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
	if (!llapi_stripe_offset_is_valid(stripe_offset)) {
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

/**
  * return a parameter string for a specific device type or mountpoint
  *
  * \param param_path the path to the file containing parameter data
  * \param result buffer for parameter value string
  * \param result_size size of buffer for return value
  *
  * The \param param_path is appended to /proc/{fs,sys}/{lnet,lustre} to
  * complete the absolute path to the file containing the parameter data
  * the user is requesting. If that file exist then the data is read from
  * the file and placed into the \param result buffer that is passed by
  * the user. Data is only copied up to the \param result_size to prevent
  * overflow of the array.
  *
  * Return 0 for success, with a NUL-terminated string in \param result.
  * Return -ve value for error.
  */
int get_param(const char *param_path, char *result,
                     unsigned int result_size)
{
        char file[PATH_MAX + 1], pattern[PATH_MAX + 1], buf[result_size];
        FILE *fp = NULL;
        int rc = 0;

        snprintf(pattern, PATH_MAX, "/proc/{fs,sys}/{lnet,lustre}/%s",
                 param_path);
        rc = first_match(pattern, file);
	if (rc != 0 || result == NULL)
                return rc;

        fp = fopen(file, "r");
        if (fp != NULL) {
                while (fgets(buf, result_size, fp) != NULL)
                        strcpy(result, buf);
                fclose(fp);
        } else {
                rc = -errno;
        }
        return rc;
}

#define DEVICES_LIST "/proc/fs/lustre/devices"

/**
  * return a parameter string for a specific device type or mountpoint
  *
  * \param fsname Lustre filesystem name (optional)
  * \param file_path path to file in filesystem (optional, if fsname unset)
  * \param obd_type Lustre OBD device type
  * \param param_name parameter name to fetch
  * \param value return buffer for parameter value string
  * \param val_len size of buffer for return value
  *
  * If fsname is specified then the parameter will be from that filesystem
  * (if it exists). If file_path is given and it is in a mounted Lustre
  * filesystem, then the parameter will be otherwise the value may be
  * from any mounted filesystem (if there is more than one).
  *
  * If "obd_type" matches a Lustre device then the first matching device
  * (as with "lctl dl", constrained by \param fsname or \param mount_path)
  * will be used to provide the return value, otherwise the first such
  * device found will be used.
  *
  * Return 0 for success, with a NUL-terminated string in \param buffer.
  * Return -ve value for error.
  */
static int get_param_obdvar(const char *fsname, const char *file_path,
                            const char *obd_type, const char *param_name,
                            char *value, unsigned int val_len)
{
	char devices[PATH_MAX];
	char dev[PATH_MAX] = "*";
	char fs[PATH_MAX];
	FILE *fp = NULL;
	int rc = 0;

	fp = fopen(DEVICES_LIST, "r");
	if (fp == NULL) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: opening "DEVICES_LIST);
		goto out;
	}

	if (fsname == NULL && file_path != NULL) {
		rc = llapi_search_fsname(file_path, fs);
		if (rc) {
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "'%s' is not on a Lustre filesystem",
				    file_path);
			goto out;
		}
	} else if (fsname != NULL) {
		rc = strlcpy(fs, fsname, sizeof(fs));
		if (rc >= sizeof(fs)) {
			rc = -E2BIG;
			goto out;
		}
	}

	while (fgets(devices, sizeof(devices) - 1, fp) != NULL) {
		char *bufp = devices, *tmp;

		devices[sizeof(devices) - 1] = '\0';
		while (bufp[0] == ' ')
			++bufp;

		tmp = strstr(bufp, obd_type);
		if (tmp != NULL) {
			tmp += strlen(obd_type) + 1;
			if (strcmp(tmp, fs))
				continue;
			rc = strlcpy(dev, tmp, sizeof(dev));
			if (rc >= sizeof(dev)) {
				rc = -E2BIG;
				goto out;
			}

			tmp = strchr(dev, ' ');
			if (tmp != NULL)
				*tmp = '\0';
			break;
		}
	}

	if (dev[0] == '*' && strlen(fs)) {
		rc = snprintf(dev, sizeof(dev), "%s-*", fs);
		if (rc >= sizeof(dev)) {
			rc = -E2BIG;
			goto out;
		}
	}
	rc = snprintf(devices, sizeof(devices), "%s/%s/%s", obd_type, dev,
		      param_name);
	if (rc >= sizeof(devices)) {
		rc = -E2BIG;
		goto out;
	}

	fclose(fp);
	return get_param(devices, value, val_len);
out:
	if (fp != NULL)
		fclose(fp);
	return rc;
}

/*
 * TYPE one of llite, lmv, lov.
 * /proc/fs/lustre/TYPE/INST the directory of interest.
 */
static int get_param_cli(const char *type, const char *inst,
			 const char *param, char *buf, size_t buf_size)
{
	char param_path[PATH_MAX + 1];
	FILE *param_file = NULL;
	int rc;

	snprintf(param_path, sizeof(param_path),
		 "/proc/fs/lustre/%s/%s/%s", type, inst, param);

	param_file = fopen(param_path, "r");
	if (param_file == NULL) {
		rc = -errno;
		goto out;
	}

	if (fgets(buf, buf_size, param_file) == NULL) {
		rc = -errno;
		goto out;
	}

	rc = 0;
out:
	if (param_file != NULL)
		fclose(param_file);

	return rc;
}

static int get_param_llite(const char *path,
			   const char *param, char *buf, size_t buf_size)
{
	char inst[80];
	int rc;

	rc = llapi_getname(path, inst, sizeof(inst));
	if (rc != 0)
		return rc;

	return get_param_cli("llite", inst, param, buf, buf_size);
}

static int get_param_lov(const char *path,
			 const char *param, char *buf, size_t buf_size)
{
	struct obd_uuid uuid;
	int rc;

	rc = llapi_file_get_lov_uuid(path, &uuid);
	if (rc != 0)
		return rc;

	return get_param_cli("lov", uuid.uuid, param, buf, buf_size);
}

static int get_param_lmv(const char *path,
			 const char *param, char *buf, size_t buf_size)
{
	struct obd_uuid uuid;
	int rc;

	rc = llapi_file_get_lmv_uuid(path, &uuid);
	if (rc != 0)
		return rc;

	return get_param_cli("lmv", uuid.uuid, param, buf, buf_size);
}

static int get_mds_md_size(const char *path)
{
	int md_size = lov_user_md_size(LOV_MAX_STRIPE_COUNT, LOV_USER_MAGIC_V3);
	char buf[80];
	int rc;

	/* Get the max ea size from llite proc. */
	rc = get_param_llite(path, "max_easize", buf, sizeof(buf));
	if (rc != 0)
		goto out;

	rc = atoi(buf);
	if (rc > 0)
		md_size = rc;

out:
	return md_size;
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
        FILE *fd;
        char buffer[PATH_MAX + 1];
        int len = 0, rc;

        if (ostname != NULL)
                len = strlen(ostname);

	if (poolname == NULL) {
		if (len == 0)
			rc = -EINVAL;
		else
			rc = find_target_obdpath(fsname, buffer);
	} else {
                rc = find_poolpath(fsname, poolname, buffer);
	}
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
 * \param name the name of the file to be opened
 * \param flags access mode, see flags in open(2)
 * \param mode permisson of the file if it is created, see mode in open(2)
 * \param param stripe pattern of the newly created file
 *
 * \return file descriptor of opened file
 * \return -error failure
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
				  "error on ioctl "LPX64" for '%s' (%d): %s",
				  (__u64)LL_IOC_LOV_SETSTRIPE, name, fd,
				  errmsg);
	}

	if (rc) {
		close(fd);
		fd = rc;
	}
	if (lum != NULL)
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
				  "error on ioctl "LPX64" for '%s' (%d): %s",
				  (__u64)LL_IOC_LMV_SETSTRIPE, filename,
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
		/* thanks to the call to llapi_is_lustre_mnt() above,
		 * we are sure that mnt.mnt_fsname contains ":/",
		 * so ptr should never be NULL */
		if (ptr == NULL)
			continue;
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
	char fsname[PATH_MAX];
	char *pool, *tmp;
	char pathname[PATH_MAX];
	char path[PATH_MAX];
	char buf[1024];
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

        rc = poolpath(fsname, NULL, pathname);
        if (rc != 0) {
                llapi_error(LLAPI_MSG_ERROR, rc,
                            "Lustre filesystem '%s' not found",
                            fsname);
                return rc;
        }

        llapi_printf(LLAPI_MSG_NORMAL, "Pool: %s.%s\n", fsname, pool);
	rc = snprintf(path, sizeof(path), "%s/%s", pathname, pool);
	if (rc >= sizeof(path))
		return -EOVERFLOW;
        fd = fopen(path, "r");
        if (fd == NULL) {
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
		if (strlen(rname) > sizeof(fsname)-1)
			return -E2BIG;
		strncpy(fsname, rname, sizeof(fsname));
        } else {
                /* name is FSNAME */
		if (strlen(name) > sizeof(fsname)-1)
			return -E2BIG;
		strncpy(fsname, name, sizeof(fsname));
                rc = poolpath(fsname, NULL, pathname);
        }
        if (rc != 0) {
                llapi_error(LLAPI_MSG_ERROR, rc,
                            "Lustre filesystem '%s' not found", name);
                return rc;
        }

        llapi_printf(LLAPI_MSG_NORMAL, "Pools from %s:\n", fsname);
        dir = opendir(pathname);
        if (dir == NULL) {
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
			goto out;
                } else if ((rc == 0) && (cookie == NULL)) {
                        /* end of directory */
                        break;
                }

                /* ignore . and .. */
                if (!strcmp(pool.d_name, ".") || !strcmp(pool.d_name, ".."))
                        continue;

                /* check output bounds */
		if (nb_entries >= list_size) {
			rc = -EOVERFLOW;
			goto out;
		}

                /* +2 for '.' and final '\0' */
		if (used + strlen(pool.d_name) + strlen(fsname) + 2
		    > buffer_size) {
			rc = -EOVERFLOW;
			goto out;
		}

                sprintf(buffer + used, "%s.%s", fsname, pool.d_name);
                poollist[nb_entries] = buffer + used;
                used += strlen(pool.d_name) + strlen(fsname) + 2;
                nb_entries++;
        }

out:
        closedir(dir);
	return ((rc != 0) ? rc : nb_entries);
}

/* wrapper for lfs.c and obd.c */
int llapi_poollist(const char *name)
{
        /* list of pool names (assume that pool count is smaller
           than OST count) */
        char **list, *buffer = NULL, *path = NULL, *fsname = NULL;
        int obdcount, bufsize, rc, nb, i;
        char *poolname = NULL, *tmp = NULL, data[16];

	if (name == NULL)
		return -EINVAL;

	if (name[0] != '/') {
		fsname = strdup(name);
		if (fsname == NULL)
			return -ENOMEM;

                poolname = strchr(fsname, '.');
                if (poolname)
                        *poolname = '\0';
        } else {
                path = (char *) name;
        }

        rc = get_param_obdvar(fsname, path, "lov", "numobd",
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
        if (fsname)
                free(fsname);
        return rc;
}

typedef int (semantic_func_t)(char *path, DIR *parent, DIR **d,
			      void *data, struct dirent64 *de);

#define OBD_NOT_FOUND           (-1)

static int common_param_init(struct find_param *param, char *path)
{
	int lumlen = get_mds_md_size(path);

	if (lumlen < PATH_MAX + 1)
		lumlen = PATH_MAX + 1;

	param->lumlen = lumlen;
	param->lmd = malloc(sizeof(lstat_t) + param->lumlen);
	if (param->lmd == NULL) {
		llapi_error(LLAPI_MSG_ERROR, -ENOMEM,
			    "error: allocation of %zu bytes for ioctl",
			    sizeof(lstat_t) + param->lumlen);
		return -ENOMEM;
	}

	param->fp_lmv_count = 256;
	param->fp_lmv_md = malloc(lmv_user_md_size(256, LMV_MAGIC_V1));
	if (param->fp_lmv_md == NULL) {
		llapi_error(LLAPI_MSG_ERROR, -ENOMEM,
			    "error: allocation of %d bytes for ioctl",
			    lmv_user_md_size(256, LMV_MAGIC_V1));
		return -ENOMEM;
	}

	param->got_uuids = 0;
	param->obdindexes = NULL;
	param->obdindex = OBD_NOT_FOUND;
	if (!param->migrate)
		param->mdtindex = OBD_NOT_FOUND;
	return 0;
}

static void find_param_fini(struct find_param *param)
{
	if (param->obdindexes)
		free(param->obdindexes);

	if (param->lmd)
		free(param->lmd);

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

static int cb_get_dirstripe(char *path, DIR *d, struct find_param *param)
{
	struct lmv_user_md *lmv = (struct lmv_user_md *)param->fp_lmv_md;
	int ret = 0;

	lmv->lum_stripe_count = param->fp_lmv_count;
	if (param->get_default_lmv)
		lmv->lum_magic = LMV_USER_MAGIC;
	else
		lmv->lum_magic = LMV_MAGIC_V1;
	ret = ioctl(dirfd(d), LL_IOC_LMV_GETSTRIPE, lmv);

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

		param->have_fileinfo = 0;

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
			lstat_t *st = &param->lmd->lmd_st;

			rc = get_lmd_info(path, d, NULL, param->lmd,
					   param->lumlen);
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

int llapi_file_get_lmv_uuid(const char *path, struct obd_uuid *lov_uuid)
{
	int fd, rc;

	fd = open(path, O_RDONLY);
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
 * there are more OSTs then allocated to uuidp, then an error is returned with
 * the ost_count set to number of available obd uuids.
 */
static int llapi_get_target_uuids(int fd, struct obd_uuid *uuidp,
                                  int *ost_count, enum tgt_type type)
{
	struct obd_uuid name;
	char buf[1024];
	char format[32];
	FILE *fp;
	int rc = 0, index = 0;

        /* Get the lov name */
        if (type == LOV_TYPE) {
                rc = llapi_file_fget_lov_uuid(fd, &name);
                if (rc)
                        return rc;
        } else {
                rc = llapi_file_fget_lmv_uuid(fd, &name);
                if (rc)
                        return rc;
        }

        /* Now get the ost uuids from /proc */
        snprintf(buf, sizeof(buf), "/proc/fs/lustre/%s/%s/target_obd",
                 type == LOV_TYPE ? "lov" : "lmv", name.uuid);
        fp = fopen(buf, "r");
        if (fp == NULL) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "error: opening '%s'", buf);
                return rc;
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
        return rc;
}

int llapi_lov_get_uuids(int fd, struct obd_uuid *uuidp, int *ost_count)
{
        return llapi_get_target_uuids(fd, uuidp, ost_count, LOV_TYPE);
}

int llapi_get_obd_count(char *mnt, int *count, int is_mdt)
{
        DIR *root;
        int rc;

        root = opendir(mnt);
        if (!root) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "open %s failed", mnt);
                return rc;
        }

        *count = is_mdt;
        rc = ioctl(dirfd(root), LL_IOC_GETOBDCOUNT, count);
        if (rc < 0)
                rc = -errno;

        closedir(root);
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

/* Here, param->obduuid points to a single obduuid, the index of which is
 * returned in param->obdindex */
static int setup_obd_uuid(DIR *dir, char *dname, struct find_param *param)
{
	struct obd_uuid obd_uuid;
	char buf[1024];
	char format[32];
	FILE *fp;
	int rc = 0;

        if (param->got_uuids)
                return rc;

        /* Get the lov/lmv name */
        if (param->get_lmv)
                rc = llapi_file_fget_lmv_uuid(dirfd(dir), &obd_uuid);
        else
                rc = llapi_file_fget_lov_uuid(dirfd(dir), &obd_uuid);
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
        snprintf(buf, sizeof(buf), "/proc/fs/lustre/%s/%s/target_obd",
                 param->get_lmv ? "lmv" : "lov", obd_uuid.uuid);
        fp = fopen(buf, "r");
        if (fp == NULL) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "error: opening '%s'", buf);
                return rc;
        }

        if (!param->obduuid && !param->quiet && !param->obds_printed)
                llapi_printf(LLAPI_MSG_NORMAL, "%s:\n",
                             param->get_lmv ? "MDTS" : "OBDS:");

	snprintf(format, sizeof(format),
		 "%%d: %%%zus", sizeof(obd_uuid.uuid) - 1);
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		int index;

		if (sscanf(buf, format, &index, obd_uuid.uuid) < 2)
			break;

		if (param->obduuid) {
			if (llapi_uuid_match(obd_uuid.uuid,
					     param->obduuid->uuid)) {
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
                                  __func__, param->obduuid->uuid);
                rc = -EINVAL;
        }

        return (rc);
}

/* In this case, param->obduuid will be an array of obduuids and
 * obd index for all these obduuids will be returned in
 * param->obdindexes */
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
        uuids = (struct obd_uuid *)malloc(obdcount *
                                          sizeof(struct obd_uuid));
        if (uuids == NULL)
                return -ENOMEM;

retry_get_uuids:
        ret = llapi_get_target_uuids(dirfd(dir), uuids, &obdcount, type);
        if (ret) {
                struct obd_uuid *uuids_temp;

                if (ret == -EOVERFLOW) {
                        uuids_temp = realloc(uuids, obdcount *
                                             sizeof(struct obd_uuid));
			if (uuids_temp != NULL) {
				uuids = uuids_temp;
                                goto retry_get_uuids;
			}
                        else
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

        if (param->mdtuuid) {
                ret = setup_indexes(dir, path, param->mdtuuid, param->num_mdts,
                              &param->mdtindexes, &param->mdtindex, LMV_TYPE);
                if (ret)
                        return ret;
        }
        if (param->obduuid) {
                ret = setup_indexes(dir, path, param->obduuid, param->num_obds,
                              &param->obdindexes, &param->obdindex, LOV_TYPE);
                if (ret)
                        return ret;
        }
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
                rc = llapi_search_fsname(pathname, buffer);
                if (rc != 0)
                        return rc;
                fsname = buffer;
        }

        snprintf(pattern, sizeof(pattern), "/proc/fs/lustre/lov/%s-clilov-*",
                 fsname);

        rc = first_match(pattern, buffer);
        if (rc != 0)
                return rc;

	strlcpy(clilovpath, buffer, sizeof(buffer));

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

        f = fopen(fpath, "r");
        if (f == NULL) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc, "Cannot open '%s'", fpath);
                return rc;
        }

        if (fgets(line, sizeof(line), f) != NULL) {
                *attr = atoi(line);
        } else {
                llapi_error(LLAPI_MSG_ERROR, errno, "Cannot read from '%s'", fpath);
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

        rc = clilovpath(fsname, pathname, dpath);
        if (rc != 0)
                return rc;

        if (scount) {
                snprintf(fpath, PATH_MAX, "%s/stripecount", dpath);
                rc = sattr_read_attr(fpath, scount);
                if (rc != 0)
                        return rc;
        }

        if (ssize) {
                snprintf(fpath, PATH_MAX, "%s/stripesize", dpath);
                rc = sattr_read_attr(fpath, ssize);
                if (rc != 0)
                        return rc;
        }

        if (soffset) {
                snprintf(fpath, PATH_MAX, "%s/stripeoffset", dpath);
                rc = sattr_read_attr(fpath, soffset);
                if (rc != 0)
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
                rc = sattr_get_defaults(fsname_buf, NULL, &tmp[0], &tmp[1],
                                        &tmp[2]);
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

static void lov_dump_user_lmm_header(struct lov_user_md *lum, char *path,
                                     struct lov_user_ost_data_v1 *objects,
                                     int is_dir, int verbose, int depth,
                                     int raw, char *pool_name)
{
        char *prefix = is_dir ? "" : "lmm_";
	char *seperator = "";
        int rc;

	if (is_dir && lmm_oi_seq(&lum->lmm_oi) == FID_SEQ_LOV_DEFAULT) {
		lmm_oi_set_seq(&lum->lmm_oi, 0);
		if (verbose & VERBOSE_DETAIL)
			llapi_printf(LLAPI_MSG_NORMAL, "(Default) ");
	}

        if (depth && path && ((verbose != VERBOSE_OBJID) || !is_dir))
                llapi_printf(LLAPI_MSG_NORMAL, "%s\n", path);

	if ((verbose & VERBOSE_DETAIL) && !is_dir) {
		llapi_printf(LLAPI_MSG_NORMAL, "lmm_magic:          0x%08X\n",
			     lum->lmm_magic);
		llapi_printf(LLAPI_MSG_NORMAL, "lmm_seq:            "LPX64"\n",
			     lmm_oi_seq(&lum->lmm_oi));
		llapi_printf(LLAPI_MSG_NORMAL, "lmm_object_id:      "LPX64"\n",
			     lmm_oi_id(&lum->lmm_oi));
	}

        if (verbose & VERBOSE_COUNT) {
                if (verbose & ~VERBOSE_COUNT)
                        llapi_printf(LLAPI_MSG_NORMAL, "%sstripe_count:   ",
                                     prefix);
                if (is_dir) {
                        if (!raw && lum->lmm_stripe_count == 0) {
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
		seperator = is_dir ? " " : "\n";
        }

        if (verbose & VERBOSE_SIZE) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", seperator);
                if (verbose & ~VERBOSE_SIZE)
                        llapi_printf(LLAPI_MSG_NORMAL, "%sstripe_size:    ",
                                     prefix);
                if (is_dir && !raw && lum->lmm_stripe_size == 0) {
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
		seperator = is_dir ? " " : "\n";
        }

	if ((verbose & VERBOSE_LAYOUT) && !is_dir) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", seperator);
		if (verbose & ~VERBOSE_LAYOUT)
			llapi_printf(LLAPI_MSG_NORMAL, "%spattern:        ",
				     prefix);
		llapi_printf(LLAPI_MSG_NORMAL, "%.x", lum->lmm_pattern);
		seperator = "\n";
	}

        if ((verbose & VERBOSE_GENERATION) && !is_dir) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", seperator);
                if (verbose & ~VERBOSE_GENERATION)
                        llapi_printf(LLAPI_MSG_NORMAL, "%slayout_gen:     ",
                                     prefix);
		llapi_printf(LLAPI_MSG_NORMAL, "%u",
			     (int)lum->lmm_layout_gen);
		seperator = "\n";
        }

        if (verbose & VERBOSE_OFFSET) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", seperator);
                if (verbose & ~VERBOSE_OFFSET)
                        llapi_printf(LLAPI_MSG_NORMAL, "%sstripe_offset:  ",
                                     prefix);
                if (is_dir)
			llapi_printf(LLAPI_MSG_NORMAL, "%d",
                                     lum->lmm_stripe_offset ==
                                     (typeof(lum->lmm_stripe_offset))(-1) ? -1 :
				     lum->lmm_stripe_offset);
                else
			llapi_printf(LLAPI_MSG_NORMAL, "%u",
				     objects[0].l_ost_idx);
		seperator = is_dir ? " " : "\n";
        }

        if ((verbose & VERBOSE_POOL) && (pool_name != NULL)) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", seperator);
                if (verbose & ~VERBOSE_POOL)
                        llapi_printf(LLAPI_MSG_NORMAL, "%spool:           ",
                                     prefix);
		llapi_printf(LLAPI_MSG_NORMAL, "%s", pool_name);
        }

        if (!is_dir || (is_dir && (verbose != VERBOSE_OBJID)))
                llapi_printf(LLAPI_MSG_NORMAL, "\n");
}

void lov_dump_user_lmm_v1v3(struct lov_user_md *lum, char *pool_name,
                            struct lov_user_ost_data_v1 *objects,
                            char *path, int is_dir, int obdindex,
                            int depth, int header, int raw)
{
        int i, obdstripe = (obdindex != OBD_NOT_FOUND) ? 0 : 1;

        if (!obdstripe) {
                for (i = 0; !is_dir && i < lum->lmm_stripe_count; i++) {
                        if (obdindex == objects[i].l_ost_idx) {
                                obdstripe = 1;
                                break;
                        }
                }
        }

        if (obdstripe == 1)
                lov_dump_user_lmm_header(lum, path, objects, is_dir, header,
                                         depth, raw, pool_name);

        if (!is_dir && (header & VERBOSE_OBJID) &&
	    !(lum->lmm_pattern & LOV_PATTERN_F_RELEASED)) {
                if (obdstripe == 1)
                        llapi_printf(LLAPI_MSG_NORMAL,
				   "\tobdidx\t\t objid\t\t objid\t\t group\n");

                for (i = 0; i < lum->lmm_stripe_count; i++) {
                        int idx = objects[i].l_ost_idx;
                        long long oid = ostid_id(&objects[i].l_ost_oi);
                        long long gr = ostid_seq(&objects[i].l_ost_oi);
			if ((obdindex == OBD_NOT_FOUND) || (obdindex == idx)) {
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
		       char *path, int obdindex, int depth, int verbose)
{
	struct lmv_user_mds_data *objects = lum->lum_objects;
	char *prefix = lum->lum_magic == LMV_USER_MAGIC ? "(Default)" : "";
	int i, obdstripe = 0;
	char *separator = "";

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
			verbose = VERBOSE_POOL | VERBOSE_COUNT | VERBOSE_OFFSET;
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
		if (verbose & VERBOSE_OFFSET)
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

	if ((verbose & VERBOSE_POOL) && (pool_name[0] != '\0')) {
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

void llapi_lov_dump_user_lmm(struct find_param *param, char *path, int is_dir)
{
	__u32 magic;

	if (param->get_lmv || param->get_default_lmv)
		magic = (__u32)param->fp_lmv_md->lum_magic;
	else
		magic = *(__u32 *)&param->lmd->lmd_lmm; /* lum->lmm_magic */

	switch (magic) {
        case LOV_USER_MAGIC_V1:
                lov_dump_user_lmm_v1v3(&param->lmd->lmd_lmm, NULL,
                                       param->lmd->lmd_lmm.lmm_objects,
                                       path, is_dir,
				       param->obdindex, param->fp_max_depth,
                                       param->verbose, param->raw);
                break;
        case LOV_USER_MAGIC_V3: {
                char pool_name[LOV_MAXPOOLNAME + 1];
                struct lov_user_ost_data_v1 *objects;
                struct lov_user_md_v3 *lmmv3 = (void *)&param->lmd->lmd_lmm;

		strlcpy(pool_name, lmmv3->lmm_pool_name, sizeof(pool_name));
                objects = lmmv3->lmm_objects;
                lov_dump_user_lmm_v1v3(&param->lmd->lmd_lmm, pool_name,
                                       objects, path, is_dir,
				       param->obdindex, param->fp_max_depth,
                                       param->verbose, param->raw);
                break;
        }
	case LMV_MAGIC_V1:
	case LMV_USER_MAGIC: {
		char pool_name[LOV_MAXPOOLNAME + 1];
		struct lmv_user_md *lum;

		lum = (struct lmv_user_md *)param->fp_lmv_md;
		strlcpy(pool_name, lum->lum_pool_name, sizeof(pool_name));
		lmv_dump_user_lmm(lum, pool_name, path,
				  param->obdindex, param->fp_max_depth,
				  param->verbose);
		break;
	}
	default:
		llapi_printf(LLAPI_MSG_NORMAL, "unknown lmm_magic:  %#x "
			     "(expecting one of %#x %#x %#x %#x)\n",
			     *(__u32 *)&param->lmd->lmd_lmm,
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

        fd = open(dname, O_RDONLY);
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
        lstat_t *st = &param->lmd->lmd_st;
        struct lov_user_ost_data_v1 *lmm_objects;
        int i, j;

        if (param->obduuid && param->obdindex == OBD_NOT_FOUND)
                return 0;

        if (!S_ISREG(st->st_mode))
                return 0;

        /* Only those files should be accepted, which have a
         * stripe on the specified OST. */
        if (!param->lmd->lmd_lmm.lmm_stripe_count)
                return 0;

        if (param->lmd->lmd_lmm.lmm_magic ==
            LOV_USER_MAGIC_V3) {
                struct lov_user_md_v3 *lmmv3 = (void *)&param->lmd->lmd_lmm;

                lmm_objects = lmmv3->lmm_objects;
        } else if (param->lmd->lmd_lmm.lmm_magic ==  LOV_USER_MAGIC_V1) {
                lmm_objects = param->lmd->lmd_lmm.lmm_objects;
        } else {
                llapi_err_noerrno(LLAPI_MSG_ERROR, "%s:Unknown magic: 0x%08X\n",
                                  __func__, param->lmd->lmd_lmm.lmm_magic);
                return -EINVAL;
        }

        for (i = 0; i < param->lmd->lmd_lmm.lmm_stripe_count; i++) {
                for (j = 0; j < param->num_obds; j++) {
                        if (param->obdindexes[j] ==
                            lmm_objects[i].l_ost_idx) {
                                if (param->exclude_obd)
                                        return 0;
                                return 1;
                        }
                }
        }

        if (param->exclude_obd)
                return 1;
        return 0;
}

static int check_mdt_match(struct find_param *param)
{
        int i;

        if (param->mdtuuid && param->mdtindex == OBD_NOT_FOUND)
                return 0;

        /* FIXME: For striped dir, we should get stripe information and check */
	for (i = 0; i < param->num_mdts; i++) {
		if (param->mdtindexes[i] == param->file_mdtindex)
			return !param->exclude_mdt;
	}

        if (param->exclude_mdt)
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

        LASSERT(type == LL_STATFS_LOV || type == LL_STATFS_LMV);

        memset(&stat_buf, 0, sizeof(struct obd_statfs));
        memset(&uuid_buf, 0, sizeof(struct obd_uuid));
        ret = llapi_obd_statfs(path, type,
                               param->obdindex, &stat_buf,
                               &uuid_buf);
        if (ret) {
                llapi_printf(LLAPI_MSG_NORMAL,
                             "obd_uuid: %s failed %s ",
                             param->obduuid->uuid,
                             strerror(errno));
        }
        return ret;
}

static int cb_find_init(char *path, DIR *parent, DIR **dirp,
			void *data, struct dirent64 *de)
{
        struct find_param *param = (struct find_param *)data;
	DIR *dir = dirp == NULL ? NULL : *dirp;
        int decision = 1; /* 1 is accepted; -1 is rejected. */
        lstat_t *st = &param->lmd->lmd_st;
        int lustre_fs = 1;
        int checked_type = 0;
        int ret = 0;

        LASSERT(parent != NULL || dir != NULL);

        if (param->have_fileinfo == 0)
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
	if (param->obduuid || param->mdtuuid ||
	    param->fp_check_uid || param->fp_check_gid ||
	    param->fp_atime || param->fp_mtime || param->fp_ctime ||
	    param->check_pool || param->check_size ||
	    param->check_stripecount || param->check_stripesize ||
	    param->check_layout)
		decision = 0;

	if (param->fp_type != 0 && checked_type == 0)
                decision = 0;

        if (param->have_fileinfo == 0 && decision == 0) {
                ret = get_lmd_info(path, parent, dir, param->lmd,
                                   param->lumlen);
                if (ret == 0) {
                        if (dir) {
                                ret = llapi_file_fget_mdtidx(dirfd(dir),
                                                     &param->file_mdtindex);
                        } else {
                                int fd;
                                lstat_t tmp_st;

                                ret = lstat_f(path, &tmp_st);
                                if (ret) {
                                        ret = -errno;
                                        llapi_error(LLAPI_MSG_ERROR, ret,
                                                    "error: %s: lstat failed"
                                                    "for %s", __func__, path);
                                        return ret;
                                }
                                if (S_ISREG(tmp_st.st_mode)) {
                                        fd = open(path, O_RDONLY);
                                        if (fd > 0) {
                                                ret = llapi_file_fget_mdtidx(fd,
                                                         &param->file_mdtindex);
                                                close(fd);
                                        } else {
                                                ret = fd;
                                        }
                                } else {
                                        /* For special inode, it assumes to
                                         * reside on the same MDT with the
                                         * parent */
                                        fd = dirfd(parent);
                                        ret = llapi_file_fget_mdtidx(fd,
                                                        &param->file_mdtindex);
                                }
                        }
                }
                if (ret) {
                        if (ret == -ENOTTY)
                                lustre_fs = 0;
                        if (ret == -ENOENT)
                                goto decided;
                        return ret;
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
        if (param->obduuid || param->mdtuuid) {
                if (lustre_fs && param->got_uuids &&
		    param->fp_dev != st->st_dev) {
                        /* A lustre/lustre mount point is crossed. */
                        param->got_uuids = 0;
                        param->obds_printed = 0;
                        param->obdindex = param->mdtindex = OBD_NOT_FOUND;
                }

                if (lustre_fs && !param->got_uuids) {
                        ret = setup_target_indexes(dir ? dir : parent, path,
                                                   param);
                        if (ret)
                                return ret;

			param->fp_dev = st->st_dev;
                } else if (!lustre_fs && param->got_uuids) {
                        /* A lustre/non-lustre mount point is crossed. */
                        param->got_uuids = 0;
                        param->obdindex = param->mdtindex = OBD_NOT_FOUND;
                }
        }

        if (param->check_stripesize) {
                decision = find_value_cmp(param->lmd->lmd_lmm.lmm_stripe_size,
                                          param->stripesize,
                                          param->stripesize_sign,
                                          param->exclude_stripesize,
                                          param->stripesize_units, 0);
                if (decision == -1)
                        goto decided;
        }

        if (param->check_stripecount) {
                decision = find_value_cmp(param->lmd->lmd_lmm.lmm_stripe_count,
                                          param->stripecount,
                                          param->stripecount_sign,
                                          param->exclude_stripecount, 1, 0);
                if (decision == -1)
                        goto decided;
        }

	if (param->check_layout) {
		__u32 found;

		found = (param->lmd->lmd_lmm.lmm_pattern & param->layout);
		if ((param->lmd->lmd_lmm.lmm_pattern == 0xFFFFFFFF) ||
		    (found && param->exclude_layout) ||
		    (!found && !param->exclude_layout)) {
			decision = -1;
			goto decided;
		}
	}

        /* If an OBD UUID is specified but none matches, skip this file. */
        if ((param->obduuid && param->obdindex == OBD_NOT_FOUND) ||
            (param->mdtuuid && param->mdtindex == OBD_NOT_FOUND))
                goto decided;

        /* If a OST or MDT UUID is given, and some OST matches,
         * check it here. */
        if (param->obdindex != OBD_NOT_FOUND ||
            param->mdtindex != OBD_NOT_FOUND) {
                if (param->obduuid) {
                        if (check_obd_match(param)) {
                                /* If no mdtuuid is given, we are done.
                                 * Otherwise, fall through to the mdtuuid
                                 * check below. */
                                if (!param->mdtuuid)
                                        goto obd_matches;
                        } else {
                                goto decided;
                        }
                }
                if (param->mdtuuid) {
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

        if (param->check_pool) {
                struct lov_user_md_v3 *lmmv3 = (void *)&param->lmd->lmd_lmm;

                /* empty requested pool is taken as no pool search => V1 */
                if (((param->lmd->lmd_lmm.lmm_magic == LOV_USER_MAGIC_V1) &&
                     (param->poolname[0] == '\0')) ||
                    ((param->lmd->lmd_lmm.lmm_magic == LOV_USER_MAGIC_V3) &&
                     (strncmp(lmmv3->lmm_pool_name,
                              param->poolname, LOV_MAXPOOLNAME) == 0)) ||
                    ((param->lmd->lmd_lmm.lmm_magic == LOV_USER_MAGIC_V3) &&
                     (strcmp(param->poolname, "*") == 0))) {
                        if (param->exclude_pool)
                                goto decided;
                } else {
                        if (!param->exclude_pool)
                                goto decided;
                }
        }

	/* Check the time on mds. */
	decision = 1;
	if (param->fp_atime || param->fp_mtime || param->fp_ctime) {
                int for_mds;

                for_mds = lustre_fs ? (S_ISREG(st->st_mode) &&
                                       param->lmd->lmd_lmm.lmm_stripe_count)
                                    : 0;
                decision = find_time_check(st, param, for_mds);
                if (decision == -1)
                        goto decided;
        }

        /* If file still fits the request, ask ost for updated info.
           The regular stat is almost of the same speed as some new
           'glimpse-size-ioctl'. */

        if (param->check_size && S_ISREG(st->st_mode) &&
            param->lmd->lmd_lmm.lmm_stripe_count)
                decision = 0;

        while (!decision) {
                /* For regular files with the stripe the decision may have not
                 * been taken yet if *time or size is to be checked. */
                LASSERT((S_ISREG(st->st_mode) &&
                        param->lmd->lmd_lmm.lmm_stripe_count) ||
                        param->mdtindex != OBD_NOT_FOUND);

                if (param->obdindex != OBD_NOT_FOUND)
                        print_failed_tgt(param, path, LL_STATFS_LOV);

                if (param->mdtindex != OBD_NOT_FOUND)
                        print_failed_tgt(param, path, LL_STATFS_LMV);

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

                break;
        }

        if (param->check_size)
                decision = find_value_cmp(st->st_size, param->size,
                                          param->size_sign, param->exclude_size,
                                          param->size_units, 0);

        if (decision != -1) {
                llapi_printf(LLAPI_MSG_NORMAL, "%s", path);
                if (param->zeroend)
                        llapi_printf(LLAPI_MSG_NORMAL, "%c", '\0');
                else
                        llapi_printf(LLAPI_MSG_NORMAL, "\n");
        }

decided:
        /* Do not get down anymore? */
	if (param->fp_depth == param->fp_max_depth)
		return 1;

	param->fp_depth++;

	return 0;
}

static int cb_mv_init(char *path, DIR *parent, DIR **dirp,
		      void *param_data, struct dirent64 *de)
{
	struct find_param	*param = (struct find_param *)param_data;
	DIR			*dir = parent;
	char			raw[OBD_MAX_IOCTL_BUFFER] = {'\0'};
	char			*rawbuf = raw;
	struct obd_ioctl_data	data = { 0 };
	int			fd;
	int			ret;
	char			*filename;

	LASSERT(parent != NULL || dirp != NULL);
	if (dirp != NULL)
		closedir(*dirp);

	if (parent == NULL) {
		dir = opendir_parent(path);
		if (dir == NULL) {
			*dirp = NULL;
			ret = -errno;
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "can not open %s", path);
			return ret;
		}
	}

	fd = dirfd(dir);

	filename = basename(path);
	data.ioc_inlbuf1 = (char *)filename;
	data.ioc_inllen1 = strlen(filename) + 1;
	data.ioc_inlbuf2 = (char *)&param->mdtindex;
	data.ioc_inllen2 = sizeof(param->mdtindex);
	ret = obd_ioctl_pack(&data, &rawbuf, sizeof(raw));
	if (ret != 0) {
		llapi_error(LLAPI_MSG_ERROR, ret,
			    "llapi_obd_statfs: error packing ioctl data");
		goto out;
	}

	ret = ioctl(fd, LL_IOC_MIGRATE, rawbuf);
	if (ret != 0) {
		ret = -errno;
		fprintf(stderr, "%s migrate failed %d\n", path, ret);
		goto out;
	} else if (param->verbose & VERBOSE_DETAIL) {
		fprintf(stdout, "migrate %s to MDT%d\n", path, param->mdtindex);
	}

out:
	if (dirp != NULL) {
		/* If the directory is being migration, we need
		 * close the directory after migration,
		 * so the old directory cache will be cleanup
		 * on the client side, and re-open to get the
		 * new directory handle */
		*dirp = opendir(path);
		if (dirp == NULL) {
			ret = -errno;
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "%s: Failed to open '%s'", __func__, path);
			return ret;
		}
	}

	if (parent == NULL)
		closedir(dir);

	return ret;
}

int llapi_mv(char *path, struct find_param *param)
{
	return param_callback(path, cb_mv_init, cb_common_fini, param);
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
        int ret = 0;
        int mdtidx;

        LASSERT(parent != NULL || d != NULL);

        if (d) {
                ret = llapi_file_fget_mdtidx(dirfd(d), &mdtidx);
        } else if (parent) {
                int fd;

                fd = open(path, O_RDONLY);
                if (fd > 0) {
                        ret = llapi_file_fget_mdtidx(fd, &mdtidx);
                        close(fd);
                } else {
                        ret = -errno;
                }
        }

        if (ret) {
                if (ret == -ENODATA) {
                        if (!param->obduuid)
                                llapi_printf(LLAPI_MSG_NORMAL,
                                             "%s has no stripe info\n", path);
                        goto out;
                } else if (ret == -ENOENT) {
                        llapi_error(LLAPI_MSG_WARN, ret,
                                    "warning: %s: %s does not exist",
                                    __func__, path);
                        goto out;
                } else if (ret == -ENOTTY) {
                        llapi_error(LLAPI_MSG_ERROR, ret,
                                    "%s: '%s' not on a Lustre fs?",
                                    __func__, path);
                } else {
                        llapi_error(LLAPI_MSG_ERROR, ret,
                                    "error: %s: LL_IOC_GET_MDTIDX failed for %s",
                                    __func__, path);
                }
                return ret;
        }

	/* The 'LASSERT(parent != NULL || d != NULL);' guarantees
	 * that either 'd' or 'parent' is not null.
	 * So in all cases llapi_file_fget_mdtidx() is called,
	 * thus initializing 'mdtidx'. */
        if (param->quiet || !(param->verbose & VERBOSE_DETAIL))
		/* coverity[uninit_use_in_call] */
                llapi_printf(LLAPI_MSG_NORMAL, "%d\n", mdtidx);
        else
		/* coverity[uninit_use_in_call] */
                llapi_printf(LLAPI_MSG_NORMAL, "%s\nmdt_index:\t%d\n",
                             path, mdtidx);

out:
	/* Do not get down anymore? */
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

        LASSERT(parent != NULL || d != NULL);

        if (param->obduuid) {
                param->quiet = 1;
                ret = setup_obd_uuid(d ? d : parent, path, param);
                if (ret)
                        return ret;
        }

	if (d) {
		if (param->get_lmv || param->get_default_lmv) {
			ret = cb_get_dirstripe(path, d, param);
		} else {
			ret = ioctl(dirfd(d), LL_IOC_LOV_GETSTRIPE,
				     (void *)&param->lmd->lmd_lmm);
		}

	} else if (parent && !param->get_lmv && !param->get_default_lmv) {
		char *fname = strrchr(path, '/');
		fname = (fname == NULL ? path : fname + 1);

		strlcpy((char *)&param->lmd->lmd_lmm, fname, param->lumlen);

		ret = ioctl(dirfd(parent), IOC_MDC_GETFILESTRIPE,
			    (void *)&param->lmd->lmd_lmm);
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
			if (param->get_default_lmv) {
				struct lmv_user_md *lum = param->fp_lmv_md;

				lum->lum_magic = LMV_USER_MAGIC;
				lum->lum_stripe_count = 0;
				lum->lum_stripe_offset = -1;
				goto dump;
			} else if (param->get_lmv) {
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
				struct lov_user_md *lmm = &param->lmd->lmd_lmm;
				lmm->lmm_magic = LOV_USER_MAGIC_V1;
				if (!param->raw)
					ostid_set_seq(&lmm->lmm_oi,
						      FID_SEQ_LOV_DEFAULT);
				lmm->lmm_stripe_count = 0;
				lmm->lmm_stripe_size = 0;
				lmm->lmm_stripe_offset = -1;
				goto dump;
			}
                } else if (errno == ENODATA && parent != NULL) {
			if (!param->obduuid && !param->mdtuuid)
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
        if (!(param->verbose & VERBOSE_MDTINDEX))
                llapi_lov_dump_user_lmm(param, path, d ? 1 : 0);

out:
	/* Do not get down anymore? */
	if (param->fp_depth == param->fp_max_depth)
		return 1;

	param->fp_depth++;

	return 0;
}

int llapi_getstripe(char *path, struct find_param *param)
{
        return param_callback(path, (param->verbose & VERBOSE_MDTINDEX) ?
                              cb_get_mdt_index : cb_getstripe,
                              cb_common_fini, param);
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
		/* If we can't even open a file on the filesystem (e.g. with
		 * -ESHUTDOWN), force caller to exit or it will loop forever. */
		return -ENODEV;
	}
	rc = ioctl(fd, IOC_OBD_STATFS, (void *)rawbuf);
	if (rc)
		rc = errno ? -errno : -EINVAL;

	close(fd);
	return rc;
}

#define MAX_STRING_SIZE 128

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

	/* The purpose is to send a byte as a ping, whatever this byte is. */
	/* coverity[uninit_use_in_call] */
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

	rc = ioctl(dirfd(root), OBD_IOC_QUOTACHECK, check_type);
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
		rc = ioctl(dirfd(root), OBD_IOC_POLL_QUOTACHECK, qchk);
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

	rc = ioctl(dirfd(root), OBD_IOC_QUOTACTL, qctl);
        if (rc < 0)
                rc = -errno;

        closedir(root);
        return rc;
}

static int cb_quotachown(char *path, DIR *parent, DIR **dirp, void *data,
			 struct dirent64 *de)
{
        struct find_param *param = (struct find_param *)data;
	DIR *d = dirp == NULL ? NULL : *dirp;
        lstat_t *st;
        int rc;

        LASSERT(parent != NULL || d != NULL);

        rc = get_lmd_info(path, parent, d, param->lmd, param->lumlen);
        if (rc) {
                if (rc == -ENODATA) {
                        if (!param->obduuid && !param->quiet)
                                llapi_error(LLAPI_MSG_ERROR, -ENODATA,
                                          "%s has no stripe info", path);
                        rc = 0;
                } else if (rc == -ENOENT) {
                        rc = 0;
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

#include <pwd.h>
#include <grp.h>
#include <mntent.h>
#include <sys/wait.h>
#include <errno.h>
#include <ctype.h>

static int rmtacl_notify(int ops)
{
        FILE *fp;
        struct mntent *mnt;
	int found = 0, fd = 0, rc = 0;

        fp = setmntent(MOUNTED, "r");
        if (fp == NULL) {
                rc = -errno;
                llapi_error(LLAPI_MSG_ERROR, rc,
                            "error setmntent(%s)", MOUNTED);
                return rc;
        }

        while (1) {
                mnt = getmntent(fp);
                if (!mnt)
                        break;

		if (!llapi_is_lustre_mnt(mnt))
                        continue;

                fd = open(mnt->mnt_dir, O_RDONLY | O_DIRECTORY);
                if (fd < 0) {
                        rc = -errno;
                        llapi_error(LLAPI_MSG_ERROR, rc,
				    "Can't open '%s'", mnt->mnt_dir);
			goto out;
                }

                rc = ioctl(fd, LL_IOC_RMTACL, ops);
		close(fd);
                if (rc < 0) {
                        rc = -errno;
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "ioctl RMTACL on '%s' err %d",
				    mnt->mnt_dir, rc);
			goto out;
                }

                found++;
        }

out:
        endmntent(fp);
	return ((rc != 0) ? rc : found);
}

static char *next_token(char *p, int div)
{
        if (p == NULL)
                return NULL;

        if (div)
                while (*p && *p != ':' && !isspace(*p))
                        p++;
        else
                while (*p == ':' || isspace(*p))
                        p++;

        return *p ? p : NULL;
}

static int rmtacl_name2id(char *name, int is_user)
{
        if (is_user) {
                struct passwd *pw;

                pw = getpwnam(name);
                if (pw == NULL)
                        return INVALID_ID;
                else
                        return (int)(pw->pw_uid);
        } else {
                struct group *gr;

                gr = getgrnam(name);
                if (gr == NULL)
                        return INVALID_ID;
                else
                        return (int)(gr->gr_gid);
        }
}

static int isodigit(int c)
{
        return (c >= '0' && c <= '7') ? 1 : 0;
}

/*
 * Whether the name is just digits string (uid/gid) already or not.
 * Return value:
 * 1: str is id
 * 0: str is not id
 */
static int str_is_id(char *str)
{
        if (str == NULL)
                return 0;

        if (*str == '0') {
                str++;
                if (*str == 'x' || *str == 'X') { /* for Hex. */
                        if (!isxdigit(*(++str)))
                                return 0;

                        while (isxdigit(*(++str)));
                } else if (isodigit(*str)) { /* for Oct. */
                        while (isodigit(*(++str)));
                }
        } else if (isdigit(*str)) { /* for Dec. */
                while (isdigit(*(++str)));
        }

        return (*str == 0) ? 1 : 0;
}

typedef struct {
        char *name;
        int   length;
        int   is_user;
        int   next_token;
} rmtacl_name_t;

#define RMTACL_OPTNAME(name) name, sizeof(name) - 1

static rmtacl_name_t rmtacl_namelist[] = {
        { RMTACL_OPTNAME("user:"),            1,      0 },
        { RMTACL_OPTNAME("group:"),           0,      0 },
        { RMTACL_OPTNAME("default:user:"),    1,      0 },
        { RMTACL_OPTNAME("default:group:"),   0,      0 },
        /* for --tabular option */
        { RMTACL_OPTNAME("user"),             1,      1 },
        { RMTACL_OPTNAME("group"),            0,      1 },
        { 0 }
};

static int rgetfacl_output(char *str)
{
        char *start = NULL, *end = NULL;
        int is_user = 0, n, id;
        char c;
        rmtacl_name_t *rn;

        if (str == NULL)
                return -1;

        for (rn = rmtacl_namelist; rn->name; rn++) {
                if(strncmp(str, rn->name, rn->length) == 0) {
                        if (!rn->next_token)
                                start = str + rn->length;
                        else
                                start = next_token(str + rn->length, 0);
                        is_user = rn->is_user;
                        break;
                }
        }

        end = next_token(start, 1);
        if (end == NULL || start == end) {
                n = printf("%s", str);
                return n;
        }

        c = *end;
        *end = 0;
        id = rmtacl_name2id(start, is_user);
        if (id == INVALID_ID) {
                if (str_is_id(start)) {
                        *end = c;
                        n = printf("%s", str);
                } else
                        return -1;
        } else if ((id == NOBODY_UID && is_user) ||
                   (id == NOBODY_GID && !is_user)) {
                *end = c;
                n = printf("%s", str);
        } else {
                *end = c;
                *start = 0;
                n = printf("%s%d%s", str, id, end);
        }
        return n;
}

static int child_status(int status)
{
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int do_rmtacl(int argc, char *argv[], int ops, int (output_func)(char *))
{
        pid_t pid = 0;
        int fd[2], status, rc;
        FILE *fp;
        char buf[PIPE_BUF];

        if (output_func) {
                if (pipe(fd) < 0) {
                        rc = -errno;
			llapi_error(LLAPI_MSG_ERROR, rc, "Can't create pipe");
                        return rc;
                }

                pid = fork();
                if (pid < 0) {
                        rc = -errno;
			llapi_error(LLAPI_MSG_ERROR, rc, "Can't fork");
                        close(fd[0]);
                        close(fd[1]);
                        return rc;
                } else if (!pid) {
                        /* child process redirects its output. */
                        close(fd[0]);
                        close(1);
                        if (dup2(fd[1], 1) < 0) {
                                rc = -errno;
                                llapi_error(LLAPI_MSG_ERROR, rc,
					    "Can't dup2 %d", fd[1]);
                                close(fd[1]);
                                return rc;
                        }
                } else {
                        close(fd[1]);
                }
        }

        if (!pid) {
                status = rmtacl_notify(ops);
                if (status < 0)
                        return -errno;

                exit(execvp(argv[0], argv));
        }

        /* the following is parent process */
        fp = fdopen(fd[0], "r");
        if (fp == NULL) {
                rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "fdopen %d failed", fd[0]);
                kill(pid, SIGKILL);
                close(fd[0]);
                return rc;
        }

        while (fgets(buf, PIPE_BUF, fp) != NULL) {
                if (output_func(buf) < 0)
                        fprintf(stderr, "WARNING: unexpected error!\n[%s]\n",
                                buf);
        }
        fclose(fp);
        close(fd[0]);

        if (waitpid(pid, &status, 0) < 0) {
                rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "waitpid %d failed", pid);
                return rc;
        }

        return child_status(status);
}

int llapi_lsetfacl(int argc, char *argv[])
{
        return do_rmtacl(argc, argv, RMT_LSETFACL, NULL);
}

int llapi_lgetfacl(int argc, char *argv[])
{
        return do_rmtacl(argc, argv, RMT_LGETFACL, NULL);
}

int llapi_rsetfacl(int argc, char *argv[])
{
        return do_rmtacl(argc, argv, RMT_RSETFACL, NULL);
}

int llapi_rgetfacl(int argc, char *argv[])
{
        return do_rmtacl(argc, argv, RMT_RGETFACL, rgetfacl_output);
}

int llapi_cp(int argc, char *argv[])
{
        int rc;

        rc = rmtacl_notify(RMT_RSETFACL);
        if (rc < 0)
                return rc;

        exit(execvp(argv[0], argv));
}

int llapi_ls(int argc, char *argv[])
{
        int rc;

        rc = rmtacl_notify(RMT_LGETFACL);
        if (rc < 0)
                return rc;

        exit(execvp(argv[0], argv));
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
                index = strtol(ptr + 4, NULL, 10);
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
        if (rc && want_error)
                llapi_error(LLAPI_MSG_ERROR, rc, "ioctl %d err %d", opc, rc);

        close(fd);
        return rc;
}

/****** Changelog API ********/

static int changelog_ioctl(const char *mdtname, int opc, int id,
                           long long recno, int flags)
{
        struct ioc_changelog data;
        int *idx;

        data.icc_id = id;
        data.icc_recno = recno;
        data.icc_flags = flags;
        idx = (int *)(&data.icc_mdtindex);

        return root_ioctl(mdtname, opc, &data, idx, WANT_ERROR);
}

#define CHANGELOG_PRIV_MAGIC 0xCA8E1080
struct changelog_private {
	int				magic;
	enum changelog_send_flag	flags;
	lustre_kernelcomm		kuc;
};

/** Start reading from a changelog
 * @param priv Opaque private control structure
 * @param flags Start flags (e.g. CHANGELOG_FLAG_BLOCK)
 * @param device Report changes recorded on this MDT
 * @param startrec Report changes beginning with this record number
 * (just call llapi_changelog_fini when done; don't need an endrec)
 */
int llapi_changelog_start(void **priv, enum changelog_send_flag flags,
			  const char *device, long long startrec)
{
	struct changelog_private	*cp;
	static bool			 warned;
	int				 rc;

	/* Set up the receiver control struct */
	cp = calloc(1, sizeof(*cp));
	if (cp == NULL)
		return -ENOMEM;

	cp->magic = CHANGELOG_PRIV_MAGIC;
	cp->flags = flags;

	/* Set up the receiver */
	rc = libcfs_ukuc_start(&cp->kuc, 0 /* no group registration */, 0);
	if (rc < 0)
		goto out_free;

	*priv = cp;

	/* CHANGELOG_FLAG_JOBID will eventually become mandatory. Display a
	 * warning if it's missing. */
	if (!(flags & CHANGELOG_FLAG_JOBID) && !warned) {
		llapi_err_noerrno(LLAPI_MSG_WARN, "warning: %s() called "
				  "w/o CHANGELOG_FLAG_JOBID", __func__);
		warned = true;
	}

	/* Tell the kernel to start sending */
	rc = changelog_ioctl(device, OBD_IOC_CHANGELOG_SEND, cp->kuc.lk_wfd,
			     startrec, flags);
	/* Only the kernel reference keeps the write side open */
	close(cp->kuc.lk_wfd);
	cp->kuc.lk_wfd = LK_NOFD;
	if (rc < 0) {
		/* frees and clears priv */
		llapi_changelog_fini(priv);
		return rc;
	}

	return 0;

out_free:
	free(cp);
	return rc;
}

/** Finish reading from a changelog */
int llapi_changelog_fini(void **priv)
{
        struct changelog_private *cp = (struct changelog_private *)*priv;

        if (!cp || (cp->magic != CHANGELOG_PRIV_MAGIC))
                return -EINVAL;

        libcfs_ukuc_stop(&cp->kuc);
        free(cp);
        *priv = NULL;
        return 0;
}

/**
 * Convert all records to a same format according to the caller's wishes.
 * Default is CLF_VERSION | CLF_RENAME.
 * Add CLF_JOBID if explicitely requested.
 *
 * \param rec  The record to remap. It is expected to be big enough to
 *             properly handle the final format.
 * \return 1 if anything changed. 0 otherwise.
 */
/** Read the next changelog entry
 * @param priv Opaque private control structure
 * @param rech Changelog record handle; record will be allocated here
 * @return 0 valid message received; rec is set
 *         <0 error code
 *         1 EOF
 */
#define DEFAULT_RECORD_FMT	(CLF_VERSION | CLF_RENAME)
int llapi_changelog_recv(void *priv, struct changelog_rec **rech)
{
	struct changelog_private	*cp = (struct changelog_private *)priv;
	struct kuc_hdr			*kuch;
	enum changelog_rec_flags	 rec_fmt = DEFAULT_RECORD_FMT;
	int				 rc = 0;

	if (!cp || (cp->magic != CHANGELOG_PRIV_MAGIC))
		return -EINVAL;
	if (rech == NULL)
		return -EINVAL;
	kuch = malloc(KUC_CHANGELOG_MSG_MAXSIZE);
	if (kuch == NULL)
		return -ENOMEM;

	if (cp->flags & CHANGELOG_FLAG_JOBID)
		rec_fmt |= CLF_JOBID;

repeat:
	rc = libcfs_ukuc_msg_get(&cp->kuc, (char *)kuch,
				 KUC_CHANGELOG_MSG_MAXSIZE,
				 KUC_TRANSPORT_CHANGELOG);
	if (rc < 0)
		goto out_free;

        if ((kuch->kuc_transport != KUC_TRANSPORT_CHANGELOG) ||
            ((kuch->kuc_msgtype != CL_RECORD) &&
             (kuch->kuc_msgtype != CL_EOF))) {
                llapi_err_noerrno(LLAPI_MSG_ERROR,
                                  "Unknown changelog message type %d:%d\n",
                                  kuch->kuc_transport, kuch->kuc_msgtype);
                rc = -EPROTO;
                goto out_free;
        }

        if (kuch->kuc_msgtype == CL_EOF) {
                if (cp->flags & CHANGELOG_FLAG_FOLLOW) {
                        /* Ignore EOFs */
                        goto repeat;
                } else {
                        rc = 1;
                        goto out_free;
                }
        }

	/* Our message is a changelog_rec.  Use pointer math to skip
	 * kuch_hdr and point directly to the message payload. */
	*rech = (struct changelog_rec *)(kuch + 1);
	changelog_remap_rec(*rech, rec_fmt);

        return 0;

out_free:
        *rech = NULL;
        free(kuch);
        return rc;
}

/** Release the changelog record when done with it. */
int llapi_changelog_free(struct changelog_rec **rech)
{
        if (*rech) {
                /* We allocated memory starting at the kuc_hdr, but passed
                 * the consumer a pointer to the payload.
                 * Use pointer math to get back to the header.
                 */
                struct kuc_hdr *kuch = (struct kuc_hdr *)*rech - 1;
                free(kuch);
        }
        *rech = NULL;
        return 0;
}

int llapi_changelog_clear(const char *mdtname, const char *idstr,
                          long long endrec)
{
	long id;

        if (endrec < 0) {
                llapi_err_noerrno(LLAPI_MSG_ERROR,
                                  "can't purge negative records\n");
                return -EINVAL;
        }

        id = strtol(idstr + strlen(CHANGELOG_USER_PREFIX), NULL, 10);
        if ((id == 0) || (strncmp(idstr, CHANGELOG_USER_PREFIX,
                                  strlen(CHANGELOG_USER_PREFIX)) != 0)) {
                llapi_err_noerrno(LLAPI_MSG_ERROR,
                                  "expecting id of the form '"
                                  CHANGELOG_USER_PREFIX
                                  "<num>'; got '%s'\n", idstr);
                return -EINVAL;
        }

        return changelog_ioctl(mdtname, OBD_IOC_CHANGELOG_CLEAR, id, endrec, 0);
}

int llapi_fid2path(const char *device, const char *fidstr, char *buf,
                   int buflen, long long *recno, int *linkno)
{
        struct lu_fid fid;
        struct getinfo_fid2path *gf;
        int rc;

        while (*fidstr == '[')
                fidstr++;

        sscanf(fidstr, SFID, RFID(&fid));
        if (!fid_is_sane(&fid)) {
                llapi_err_noerrno(LLAPI_MSG_ERROR,
                                  "bad FID format [%s], should be "DFID"\n",
                                  fidstr, (__u64)1, 2, 0);
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
        if (rc) {
                if (rc != -ENOENT)
                        llapi_error(LLAPI_MSG_ERROR, rc, "ioctl err %d", rc);
        } else {
		memcpy(buf, gf->gf_path, gf->gf_pathlen);
		if (buf[0] == '\0') { /* ROOT path */
			buf[0] = '/';
			buf[1] = '\0';
		}
		*recno = gf->gf_recno;
		*linkno = gf->gf_linkno;
        }

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

	memset(gp, 0, sizeof(*gp) + name_size);
	gp->gp_linkno = linkno;
	gp->gp_name_size = name_size;

	rc = ioctl(fd, LL_IOC_GETPARENT, gp);
	if (rc < 0) {
		rc = -errno;
		goto err_free;
	}

	if (gp->gp_name_size > name_size) {
		rc = -EOVERFLOW;
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
        data->ioc_inllen1 = buffer_size - cfs_size_round(sizeof(*data));
        data->ioc_inlbuf1 = buffer + cfs_size_round(sizeof(*data));
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
	int	fd;
	int	random;
	int	rc;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		llapi_error(LLAPI_MSG_ERROR, errno,
			    "Cannot open /dev/urandom");
		return -errno;
	}
	rc = read(fd, &random, sizeof(random));
	close(fd);
	if (rc < sizeof(random)) {
		llapi_error(LLAPI_MSG_ERROR, errno,
			    "cannot read %zu bytes from /dev/urandom",
			    sizeof(random));
		return -errno;
	}
	if (idx == -1)
		snprintf(filename, sizeof(filename),
			 LUSTRE_VOLATILE_HDR"::%.4X", random);
	else
		snprintf(filename, sizeof(filename),
			 LUSTRE_VOLATILE_HDR":%.4X:%.4X", idx, random);

	rc = snprintf(file_path, sizeof(file_path),
		      "%s/%s", directory, filename);
	if (rc >= sizeof(file_path))
		return -E2BIG;

	fd = open(file_path, O_RDWR | O_CREAT | open_flags, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		llapi_error(LLAPI_MSG_ERROR, errno,
			    "Cannot create volatile file '%s' in '%s'",
			    filename + LUSTRE_VOLATILE_HDR_LEN,
			    directory);
		return -errno;
	}
	/* unlink file in case this wasn't a Lustre filesystem, and the
	 * magic volatile filename wasn't handled as intended.  The effect
	 * is the same. */
	unlink(file_path);

	return fd;
}

/**
 * Swap the layouts between 2 file descriptors
 * the 2 files must be open in write
 * first fd received the ioctl, second fd is passed as arg
 * this is assymetric but avoid use of root path for ioctl
 */
int llapi_fswap_layouts(int fd1, int fd2, __u64 dv1, __u64 dv2, __u64 flags)
{
	struct lustre_swap_layouts lsl;
	int rc;

	srandom(time(NULL));
	lsl.sl_fd = fd2;
	lsl.sl_flags = flags;
	lsl.sl_gid = random();
	lsl.sl_dv1 = dv1;
	lsl.sl_dv2 = dv2;
	rc = ioctl(fd1, LL_IOC_LOV_SWAP_LAYOUTS, &lsl);
	if (rc)
		rc = -errno;
	return rc;
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
