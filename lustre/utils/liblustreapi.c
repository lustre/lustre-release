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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
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
#include <sys/sysmacros.h>
#include <time.h>
#include <fnmatch.h>
#include <libgen.h> /* for dirname() */
#include <linux/limits.h>
#ifdef HAVE_LINUX_UNISTD_H
#include <linux/unistd.h>
#else
#include <unistd.h>
#endif
#include <poll.h>
#include <time.h>
#include <inttypes.h>

#include <libcfs/util/ioctl.h>
#include <libcfs/util/param.h>
#include <libcfs/util/string.h>
#include <linux/lnet/lnetctl.h>
#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_ostid.h>
#include <linux/lustre/lustre_ioctl.h>
#include "lustreapi_internal.h"
#include "lstddef.h"

static int llapi_msg_level = LLAPI_MSG_MAX;
const char *liblustreapi_cmd;

struct lustre_foreign_type lu_foreign_types[] = {
	{.lft_type = LU_FOREIGN_TYPE_NONE, .lft_name = "none"},
	{.lft_type = LU_FOREIGN_TYPE_SYMLINK, .lft_name = "symlink"},
	/* must be the last element */
	{.lft_type = LU_FOREIGN_TYPE_UNKNOWN, .lft_name = NULL}
	/* array max dimension must be <= UINT32_MAX */
};

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

void llapi_set_command_name(const char *cmd)
{
	liblustreapi_cmd = cmd;
}

void llapi_clear_command_name(void)
{
	liblustreapi_cmd = NULL;
}

static void error_callback_default(enum llapi_message_level level, int err,
				   const char *fmt, va_list ap)
{
	bool has_nl = strchr(fmt, '\n') != NULL;

	if (liblustreapi_cmd != NULL)
		fprintf(stderr, "%s %s: ", program_invocation_short_name,
			liblustreapi_cmd);
	else
		fprintf(stderr, "%s: ", program_invocation_short_name);


	if (level & LLAPI_MSG_NO_ERRNO) {
		vfprintf(stderr, fmt, ap);
		if (!has_nl)
			fprintf(stderr, "\n");
	} else {
		char *newfmt;

		/*
		 * Remove trailing linefeed so error string can be appended.
		 * @fmt is a const string, so we can't modify it directly.
		 */
		if (has_nl && (newfmt = strdup(fmt)))
			*strrchr(newfmt, '\n') = '\0';
		else
			newfmt = (char *)fmt;

		vfprintf(stderr, newfmt, ap);
		if (newfmt != fmt)
			free(newfmt);
		fprintf(stderr, ": %s (%d)\n", strerror(err), err);
	}
}

static void info_callback_default(enum llapi_message_level level, int err,
				  const char *fmt, va_list ap)
{
	if (err != 0) {
		if (liblustreapi_cmd != NULL) {
			fprintf(stdout, "%s %s: ",
				program_invocation_short_name,
				liblustreapi_cmd);
		} else {
			fprintf(stdout, "%s: ", program_invocation_short_name);
		}
	}
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

int llapi_ioctl_pack(struct obd_ioctl_data *data, char **pbuf, int max_len)
{
	struct obd_ioctl_data *overlay;
	char *ptr;

	data->ioc_len = obd_ioctl_packlen(data);
	data->ioc_version = OBD_IOCTL_VERSION;

	if (*pbuf != NULL && data->ioc_len > max_len) {
		llapi_error(LLAPI_MSG_ERROR, -EINVAL,
			    "pbuf = %p, ioc_len = %u, max_len = %d",
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
		ptr += __ALIGN_KERNEL(data->ioc_inllen1, 8);
	}

	if (data->ioc_inlbuf2) {
		memcpy(ptr, data->ioc_inlbuf2, data->ioc_inllen2);
		ptr += __ALIGN_KERNEL(data->ioc_inllen2, 8);
	}

	if (data->ioc_inlbuf3) {
		memcpy(ptr, data->ioc_inlbuf3, data->ioc_inllen3);
		ptr += __ALIGN_KERNEL(data->ioc_inllen3, 8);
	}

	if (data->ioc_inlbuf4) {
		memcpy(ptr, data->ioc_inlbuf4, data->ioc_inllen4);
		ptr += __ALIGN_KERNEL(data->ioc_inllen4, 8);
	}

	return 0;
}

int llapi_ioctl_unpack(struct obd_ioctl_data *data, char *pbuf, int max_len)
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
		ptr += __ALIGN_KERNEL(data->ioc_inllen1, 8);
	}

	if (data->ioc_inlbuf2) {
		memcpy(data->ioc_inlbuf2, ptr, data->ioc_inllen2);
		ptr += __ALIGN_KERNEL(data->ioc_inllen2, 8);
	}

	if (data->ioc_inlbuf3) {
		memcpy(data->ioc_inlbuf3, ptr, data->ioc_inllen3);
		ptr += __ALIGN_KERNEL(data->ioc_inllen3, 8);
	}

	if (data->ioc_inlbuf4) {
		memcpy(data->ioc_inlbuf4, ptr, data->ioc_inllen4);
		ptr += __ALIGN_KERNEL(data->ioc_inllen4, 8);
	}

	return 0;
}

/* XXX: llapi_xxx() functions return negative values upon failure */

int llapi_layout_search_ost(__u32 ost, char *pname, char *fsname)
{
	char ostname[MAX_OBD_NAME + 64];
	char *pool_name = pname;
	int rc = 0;

	/**
	 * The current policy is that the pool does not have to exist at the
	 * setstripe time, see sanity-pfl/-flr tests.
	 * If this logic will change, re-enable it.
	 *
	 * if (pname && strlen(pname) == 0)
	 */
		pool_name = NULL;

	snprintf(ostname, sizeof(ostname), "%s-OST%04x_UUID",
		 fsname, ost);
	rc = llapi_search_ost(fsname, pool_name, ostname);
	if (rc <= 0) {
		if (rc == 0)
			rc = -ENODEV;

		llapi_error(LLAPI_MSG_ERROR, rc,
			    "%s: cannot find OST %s in %s", __func__, ostname,
			    pool_name != NULL ? "pool" : "system");
		return rc;
	}

	return 0;
}

/**
 * Verify the setstripe parameters before using.
 * This is a pair method for comp_args_to_layout()/llapi_layout_sanity_cb()
 * when just 1 component or a non-PFL layout is given.
 *
 * \param[in] param		stripe parameters
 * \param[in] pool_name		pool name
 * \param[in] fsname		lustre FS name
 *
 * \retval			0, success
 *				< 0, error code on failre
 */
static int llapi_stripe_param_verify(const struct llapi_stripe_param *param,
				     char **pool_name,
				     char *fsname)
{
	int count;
	static int page_size;
	int rc = 0;

	if (page_size == 0) {
		/*
		 * 64 KB is the largest common page size (on ia64/PPC/ARM),
		 * but check the local page size just in case. The page_size
		 * will not change for the lifetime of this process at least.
		 */
		page_size = LOV_MIN_STRIPE_SIZE;
		if (getpagesize() > page_size) {
			page_size = getpagesize();
			llapi_err_noerrno(LLAPI_MSG_WARN,
					  "warning: page size (%u) larger than expected (%u)",
					  page_size, LOV_MIN_STRIPE_SIZE);
		}
	}
	if (!llapi_stripe_size_is_aligned(param->lsp_stripe_size)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: bad stripe_size %llu, must be an even multiple of %d bytes",
			    param->lsp_stripe_size, page_size);
		goto out;
	}
	if (!llapi_stripe_index_is_valid(param->lsp_stripe_offset)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: bad stripe offset %d",
			    param->lsp_stripe_offset);
		goto out;
	}
	if (llapi_stripe_size_is_too_big(param->lsp_stripe_size)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: stripe size '%llu' over 4GB limit",
			    param->lsp_stripe_size);
		goto out;
	}

	count = param->lsp_stripe_count;
	if (param->lsp_stripe_pattern == LOV_PATTERN_MDT) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Invalid pattern: %d, must be specified with -E\n",
			    param->lsp_stripe_pattern);
		goto out;
	} else {
		if (!llapi_stripe_count_is_valid(count)) {
			rc = -EINVAL;
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "Invalid stripe count %d\n", count);
			goto out;
		}
	}

	/* Make sure we have a good pool */
	if (*pool_name != NULL) {
		if (!llapi_pool_name_is_valid(pool_name, fsname)) {
			rc = -EINVAL;
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "Pool '%s' is not on filesystem '%s'",
				    *pool_name, fsname);
			goto out;
		}

		/* Make sure the pool exists and is non-empty */
		rc = llapi_search_ost(fsname, *pool_name, NULL);
		if (rc < 1) {
			char *err = rc == 0 ? "has no OSTs" : "does not exist";

			rc = -EINVAL;
			llapi_error(LLAPI_MSG_ERROR, rc, "pool '%s.%s' %s",
				    fsname, *pool_name, err);
			goto out;
		}
		rc = 0;
	}

	/* sanity check of target list */
	if (param->lsp_is_specific) {
		bool found = false;
		int i;

		for (i = 0; i < count; i++) {
			rc = llapi_layout_search_ost(param->lsp_osts[i],
						     *pool_name, fsname);
			if (rc)
				goto out;

			/* Make sure stripe offset is in OST list. */
			if (param->lsp_osts[i] == param->lsp_stripe_offset)
				found = true;
		}
		if (!found) {
			rc = -EINVAL;
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "%s: stripe offset '%d' is not in the target list",
				    __func__, param->lsp_stripe_offset);
			goto out;
		}
	} else if (param->lsp_stripe_offset != -1) {
		rc = llapi_layout_search_ost(param->lsp_stripe_offset,
					     *pool_name, fsname);
		if (rc)
			goto out;
	}
out:
	errno = -rc;
	return rc;
}

int llapi_dir_stripe_limit_check(int stripe_offset, int stripe_count,
				 int hash_type)
{
	int rc;

	if (!llapi_dir_stripe_index_is_valid(stripe_offset)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: bad stripe offset %d",
				stripe_offset);
		return rc;
	}
	if (!llapi_dir_stripe_count_is_valid(stripe_count)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: bad stripe count %d",
				stripe_count);
		return rc;
	}

	if (!llapi_dir_hash_type_is_valid(hash_type)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: bad hash type %d",
				hash_type);
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
	int md_size = lov_user_md_size(LOV_MAX_STRIPE_COUNT, LOV_USER_MAGIC_V3);

	/*
	 * Rather than open the file and do the ioctl to get the
	 * instance name and close the file and search for the param
	 * file and open the param file and read the param file and
	 * parse the value and close the param file, let's just return
	 * a large enough value. It's 2020, RAM is cheap and this is
	 * much faster.
	 */

	if (md_size < XATTR_SIZE_MAX)
		md_size = XATTR_SIZE_MAX;

	return md_size;
}

int llapi_get_agent_uuid(char *path, char *buf, size_t bufsize)
{
	return get_param_lmv(path, "uuid", buf, bufsize);
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
	struct lov_user_md *lum = NULL;
	char *pool_name = param->lsp_pool;
	size_t lum_size;
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
	rc = llapi_stripe_param_verify(param, &pool_name, fsname);
	if (rc != 0)
		return rc;

	if (param->lsp_is_specific)
		lum_size = lov_user_md_size(param->lsp_stripe_count,
					    LOV_USER_MAGIC_SPECIFIC);
	else if (pool_name)
		lum_size = sizeof(struct lov_user_md_v3);
	else
		lum_size = sizeof(*lum);

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
			/*
			 * LOV_USER_MAGIC_SPECIFIC uses v3 format plus specified
			 * OST list, therefore if pool is not specified we have
			 * to pack a null pool name for placeholder.
			 */
			memset(lumv3->lmm_pool_name, 0, LOV_MAXPOOLNAME);
		}

		for (i = 0; i < param->lsp_stripe_count; i++)
			lumv3->lmm_objects[i].l_ost_idx = param->lsp_osts[i];
	}

	if (ioctl(fd, LL_IOC_LOV_SETSTRIPE, lum) != 0) {
		char errmsg[512] = "stripe already set";

		rc = -errno;
		if (errno != EEXIST && errno != EALREADY)
			strncpy(errmsg, strerror(errno), sizeof(errmsg) - 1);
		if (rc == -EREMOTEIO)
			snprintf(errmsg, sizeof(errmsg),
				 "inactive OST among your specified %d OST(s)",
				 param->lsp_stripe_count);

		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "setstripe error for '%s': %s", name, errmsg);

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

int llapi_file_create_foreign(const char *name, mode_t mode, __u32 type,
			      __u32 flags, char *foreign_lov)
{
	size_t len;
	struct lov_foreign_md *lfm;
	int fd, rc;

	if (foreign_lov == NULL) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "foreign LOV EA content must be provided");
		goto out_err;
	}

	len = strlen(foreign_lov);
	if (len > XATTR_SIZE_MAX - offsetof(struct lov_foreign_md, lfm_value) ||
	    len <= 0) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "foreign LOV EA size %zu (must be 0 < len < %zu)",
			    len, XATTR_SIZE_MAX -
			    offsetof(struct lov_foreign_md, lfm_value));
		goto out_err;
	}

	lfm = malloc(len + offsetof(struct lov_foreign_md, lfm_value));
	if (lfm == NULL) {
		rc = -ENOMEM;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "failed to allocate lov_foreign_md");
		goto out_err;
	}

	fd = open(name, O_WRONLY|O_CREAT|O_LOV_DELAY_CREATE, mode);
	if (fd == -1) {
		fd = -errno;
		llapi_error(LLAPI_MSG_ERROR, fd, "open '%s' failed", name);
		goto out_free;
	}

	lfm->lfm_magic = LOV_USER_MAGIC_FOREIGN;
	lfm->lfm_length = len;
	lfm->lfm_type = type;
	lfm->lfm_flags = flags;
	memcpy(lfm->lfm_value, foreign_lov, len);

	if (ioctl(fd, LL_IOC_LOV_SETSTRIPE, lfm) != 0) {
		char *errmsg = "stripe already set";

		rc = -errno;
		if (errno == ENOTTY)
			errmsg = "not on a Lustre filesystem";
		else if (errno == EEXIST || errno == EALREADY)
			errmsg = "stripe already set";
		else
			errmsg = strerror(errno);

		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "setstripe error for '%s': %s", name, errmsg);

		close(fd);
		fd = rc;
	}

out_free:
	free(lfm);

	return fd;

out_err:
	errno = -rc;
	return rc;
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

static int verify_dir_param(const char *name,
			    const struct llapi_stripe_param *param)
{
	char fsname[MAX_OBD_NAME + 1] = { 0 };
	char *pool_name = param->lsp_pool;
	int rc;

	/* Make sure we are on a Lustre file system */
	rc = llapi_search_fsname(name, fsname);
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "'%s' is not on a Lustre filesystem",
			    name);
		return rc;
	}

	/* Check if the stripe pattern is sane. */
	rc = llapi_dir_stripe_limit_check(param->lsp_stripe_offset,
					  param->lsp_stripe_count,
					  param->lsp_stripe_pattern);
	if (rc != 0)
		return rc;

	/* Make sure we have a good pool */
	if (pool_name != NULL) {
		/*
		 * in case user gives the full pool name <fsname>.<poolname>,
		 * strip the fsname
		 */
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
		rc = llapi_search_tgt(fsname, pool_name, NULL, true);
		if (rc < 1) {
			char *err = rc == 0 ? "has no OSTs" : "does not exist";

			llapi_err_noerrno(LLAPI_MSG_ERROR, "pool '%s.%s' %s",
					  fsname, pool_name, err);
			return -EINVAL;
		}
	}

	/* sanity check of target list */
	if (param->lsp_is_specific) {
		char mdtname[MAX_OBD_NAME + 64];
		bool found = false;
		int i;

		for (i = 0; i < param->lsp_stripe_count; i++) {
			snprintf(mdtname, sizeof(mdtname), "%s-MDT%04x_UUID",
				 fsname, param->lsp_tgts[i]);
			rc = llapi_search_tgt(fsname, pool_name, mdtname, true);
			if (rc <= 0) {
				if (rc == 0)
					rc = -ENODEV;

				llapi_error(LLAPI_MSG_ERROR, rc,
					    "%s: cannot find MDT %s in %s",
					    __func__, mdtname,
					    pool_name != NULL ?
					    "pool" : "system");
				return rc;
			}

			/* Make sure stripe offset is in MDT list. */
			if (param->lsp_tgts[i] == param->lsp_stripe_offset)
				found = true;
		}
		if (!found) {
			llapi_error(LLAPI_MSG_ERROR, -EINVAL,
				    "%s: stripe offset '%d' is not in the target list",
				    __func__, param->lsp_stripe_offset);
			return -EINVAL;
		}
	}

	return 0;
}

static inline void param2lmu(struct lmv_user_md *lmu,
			     const struct llapi_stripe_param *param)
{
	lmu->lum_magic = param->lsp_is_specific ? LMV_USER_MAGIC_SPECIFIC :
						  LMV_USER_MAGIC;
	lmu->lum_stripe_count = param->lsp_stripe_count;
	lmu->lum_stripe_offset = param->lsp_stripe_offset;
	lmu->lum_hash_type = param->lsp_stripe_pattern;
	lmu->lum_max_inherit = param->lsp_max_inherit;
	lmu->lum_max_inherit_rr = param->lsp_max_inherit_rr;
	if (param->lsp_pool != NULL)
		strncpy(lmu->lum_pool_name, param->lsp_pool, LOV_MAXPOOLNAME);
	if (param->lsp_is_specific) {
		int i;

		for (i = 0; i < param->lsp_stripe_count; i++)
			lmu->lum_objects[i].lum_mds = param->lsp_tgts[i];
	}
}

int llapi_dir_set_default_lmv(const char *name,
			      const struct llapi_stripe_param *param)
{
	struct lmv_user_md lmu = { 0 };
	int fd;
	int rc = 0;

	rc = verify_dir_param(name, param);
	if (rc)
		return rc;

	/* TODO: default lmv doesn't support specific targets yet */
	if (param->lsp_is_specific)
		return -EINVAL;

	param2lmu(&lmu, param);

	fd = open(name, O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "unable to open '%s'", name);
		return rc;
	}

	rc = ioctl(fd, LL_IOC_LMV_SET_DEFAULT_STRIPE, &lmu);
	if (rc < 0) {
		char *errmsg = "stripe already set";

		rc = -errno;
		if (errno != EEXIST && errno != EALREADY)
			errmsg = strerror(errno);

		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "default dirstripe error on '%s': %s",
				  name, errmsg);
	}
	close(fd);
	return rc;
}

int llapi_dir_set_default_lmv_stripe(const char *name, int stripe_offset,
				     int stripe_count, int stripe_pattern,
				     const char *pool_name)
{
	const struct llapi_stripe_param param = {
		.lsp_stripe_count = stripe_count,
		.lsp_stripe_offset = stripe_offset,
		.lsp_stripe_pattern = stripe_pattern,
		.lsp_pool = (char *)pool_name
	};

	return llapi_dir_set_default_lmv(name, &param);
}

/**
 * Create a Lustre directory.
 *
 * \param name     the name of the directory to be created
 * \param mode     permission of the file if it is created, see mode in open(2)
 * \param param    stripe pattern of the newly created directory
 *
 * \retval         0 on success
 * \retval         negative errno on failure
 */
int llapi_dir_create(const char *name, mode_t mode,
		     const struct llapi_stripe_param *param)
{
	struct lmv_user_md *lmu = NULL;
	size_t lmu_size;
	struct obd_ioctl_data data = { 0 };
	char rawbuf[8192];
	char *buf = rawbuf;
	char *dirpath = NULL;
	char *namepath = NULL;
	char *dir;
	char *filename;
	int fd, rc;

	rc = verify_dir_param(name, param);
	if (rc)
		return rc;

	lmu_size = lmv_user_md_size(param->lsp_stripe_count,
				    param->lsp_is_specific ?
					 LMV_USER_MAGIC_SPECIFIC :
					 LMV_USER_MAGIC);

	lmu = calloc(1, lmu_size);
	if (lmu == NULL)
		return -ENOMEM;

	dirpath = strdup(name);
	if (!dirpath) {
		free(lmu);
		return -ENOMEM;
	}

	namepath = strdup(name);
	if (!namepath) {
		free(dirpath);
		free(lmu);
		return -ENOMEM;
	}

	param2lmu(lmu, param);

	filename = basename(namepath);
	dir = dirname(dirpath);

	data.ioc_inlbuf1 = (char *)filename;
	data.ioc_inllen1 = strlen(filename) + 1;
	data.ioc_inlbuf2 = (char *)lmu;
	data.ioc_inllen2 = lmu_size;
	data.ioc_type = mode;
	if (param->lsp_is_create)
		/* borrow obdo1.o_flags to store this flag */
		data.ioc_obdo1.o_flags = OBD_FL_OBDMDEXISTS;
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
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
				  "dirstripe error on '%s': %s", name, errmsg);
	}
	close(fd);
out:
	free(namepath);
	free(dirpath);
	free(lmu);
	return rc;
}

/**
 * Create a foreign directory.
 *
 * \param name     the name of the directory to be created
 * \param mode     permission of the file if it is created, see mode in open(2)
 * \param type     foreign type to be set in LMV EA
 * \param flags    foreign flags to be set in LMV EA
 * \param value    foreign pattern to be set in LMV EA
 *
 * \retval         0 on success
 * \retval         negative errno on failure
 */
int llapi_dir_create_foreign(const char *name, mode_t mode, __u32 type,
			     __u32 flags, const char *value)
{
	struct lmv_foreign_md *lfm = NULL;
	size_t lfm_size, len;
	struct obd_ioctl_data data = { 0 };
	char rawbuf[8192];
	char *buf = rawbuf;
	char *dirpath = NULL;
	char *namepath = NULL;
	char *dir;
	char *filename;
	int fd, rc;

	len = strlen(value);
	if (len > XATTR_SIZE_MAX - offsetof(struct lmv_foreign_md, lfm_value) ||
	    len <= 0) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "invalid LOV EA length %zu (must be 0 < len < %zu)",
			    len, XATTR_SIZE_MAX -
			    offsetof(struct lmv_foreign_md, lfm_value));
		return rc;
	}
	lfm_size = len + offsetof(struct lmv_foreign_md, lfm_value);
	lfm = calloc(1, lfm_size);
	if (lfm == NULL)
		return -ENOMEM;

	dirpath = strdup(name);
	if (!dirpath) {
		free(lfm);
		return -ENOMEM;
	}

	namepath = strdup(name);
	if (!namepath) {
		free(dirpath);
		free(lfm);
		return -ENOMEM;
	}

	lfm->lfm_magic = LMV_MAGIC_FOREIGN;
	lfm->lfm_length = len;
	lfm->lfm_type = type;
	lfm->lfm_flags = flags;
	memcpy(lfm->lfm_value, value, len);

	filename = basename(namepath);
	dir = dirname(dirpath);

	data.ioc_inlbuf1 = (char *)filename;
	data.ioc_inllen1 = strlen(filename) + 1;
	data.ioc_inlbuf2 = (char *)lfm;
	data.ioc_inllen2 = lfm_size;
	data.ioc_type = mode;
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
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
				  "dirstripe error on '%s': %s", name, errmsg);
	}
	close(fd);
out:
	free(namepath);
	free(dirpath);
	free(lfm);
	return rc;
}

int llapi_dir_create_pool(const char *name, int mode, int stripe_offset,
			  int stripe_count, int stripe_pattern,
			  const char *pool_name)
{
	const struct llapi_stripe_param param = {
		.lsp_stripe_count = stripe_count,
		.lsp_stripe_offset = stripe_offset,
		.lsp_stripe_pattern = stripe_pattern,
		.lsp_pool = (char *)pool_name
	};

	return llapi_dir_create(name, mode, &param);
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
	int idx = 0, mntlen = 0, fd;
	int rc = -ENODEV;
	int fsnamelen, mountlen;

	/* get the mount point */
	fp = setmntent(PROC_MOUNTS, "r");
	if (fp == NULL) {
		rc = -EIO;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot retrieve filesystem mount point");
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
		/*
		 * thanks to the call to llapi_is_lustre_mnt() above,
		 * we are sure that mnt.mnt_fsname contains ":/",
		 * so ptr should never be NULL
		 */
		if (ptr == NULL)
			continue;
		ptr_end = ptr;
		while (*ptr_end != '/' && *ptr_end != '\0')
			ptr_end++;

		/* Check the fsname for a match, if given */
		mountlen = ptr_end - ptr;
		if (!(want & WANT_FSNAME) && fsname != NULL &&
		    (fsnamelen = strlen(fsname)) > 0 &&
		    (fsnamelen != mountlen ||
		    (strncmp(ptr, fsname, mountlen) != 0)))
			continue;

		/* If the path isn't set return the first one we find */
		if (path == NULL || strlen(path) == 0) {
			strncpy(mntdir, mnt.mnt_dir, sizeof(mntdir) - 1);
			mntdir[sizeof(mntdir) - 1] = '\0';
			if ((want & WANT_FSNAME) && fsname != NULL) {
				strncpy(fsname, ptr, mountlen);
				fsname[mountlen] = '\0';
			}
			rc = 0;
			break;
		/* Otherwise find the longest matching path */
		} else if ((strlen(path) >= mntlen) &&
			   (strncmp(mnt.mnt_dir, path, mntlen) == 0)) {
			/* check the path format */
			if (strlen(path) > mntlen && path[mntlen] != '/')
				continue;
			strncpy(mntdir, mnt.mnt_dir, sizeof(mntdir) - 1);
			mntdir[sizeof(mntdir) - 1] = '\0';
			if ((want & WANT_FSNAME) && fsname != NULL) {
				strncpy(fsname, ptr, mountlen);
				fsname[mountlen] = '\0';
			}
			rc = 0;
			break;
		}
	}
	endmntent(fp);

	/* Found it */
	if (rc == 0) {
		if ((want & WANT_PATH) && path != NULL) {
			strncpy(path, mntdir, mntlen);
			path[mntlen] = '\0';
		}
		if (want & WANT_FD) {
			fd = open(mntdir, O_RDONLY | O_DIRECTORY | O_NONBLOCK);
			if (fd < 0) {
				rc = -errno;
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "cannot open '%s'", mntdir);

			} else {
				*outfd = fd;
			}
		}
	} else if (want & WANT_ERROR)
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "'%s' not on a mounted Lustre filesystem",
				  (want & WANT_PATH) ? fsname : path);
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
	} else {
		strcpy(mntdir, pathname);
	}

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
		char tmp[PATH_MAX - 1];
		char buf[PATH_MAX];
		char *ptr;

		tmp[0] = '\0';
		buf[0] = '\0';
		if (pathname[0] != '/') {
			/*
			 * Need an absolute path, but realpath() only works for
			 * pathnames that actually exist.  We go through the
			 * extra hurdle of dirname(getcwd() + pathname) in
			 * case the relative pathname contains ".." in it.
			 */
			char realpath[PATH_MAX - 1];

			if (getcwd(realpath, sizeof(realpath) - 2) == NULL) {
				rc = -errno;
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "cannot get current working directory");
				return rc;
			}

			rc = snprintf(tmp, sizeof(tmp), "%s/", realpath);
			if (rc >= sizeof(tmp)) {
				rc = -E2BIG;
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "invalid parent path '%s'",
					    tmp);
				return rc;
			}
		}

		rc = snprintf(buf, sizeof(buf), "%s%s", tmp, pathname);
		if (rc >= sizeof(buf)) {
			rc = -E2BIG;
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "invalid path '%s'", pathname);
			return rc;
		}
		path = realpath(buf, NULL);
		if (path == NULL) {
			ptr = strrchr(buf, '/');
			if (ptr == NULL) {
				llapi_error(LLAPI_MSG_ERROR |
					    LLAPI_MSG_NO_ERRNO, 0,
					    "cannot resolve path '%s'",
					    buf);
				return -ENOENT;
			}
			*ptr = '\0';
			path = realpath(buf, NULL);
			if (path == NULL) {
				rc = -errno;
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "cannot resolve path '%s'",
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
	/*
	 * pathname can be used as an argument by get_root_path(),
	 * clear it for safety
	 */
	pathname[0] = 0;
	return get_root_path(WANT_PATH, (char *)fsname, NULL, pathname, -1);
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

	snprintf(fsname, sizeof(fsname), "%s", poolname);
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
			*tmp = '\0';
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
		char fsname_buf[MAXNAMLEN];

		/* We will need fsname for printing later */
		rc = llapi_getname(name, fsname_buf, sizeof(fsname_buf));
		if (rc)
			return rc;

		ptr = strrchr(fsname_buf, '-');
		if (ptr)
			*ptr = '\0';

		fsname = strdup(fsname_buf);
		if (!fsname)
			return -ENOMEM;
	} else {
		/* name is FSNAME */
		fsname = strdup(name);
		if (!fsname)
			return -ENOMEM;
	}

	rc = poolpath(&pathname, fsname, NULL);
	if (rc != 0) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Lustre filesystem '%s' not found", name);
		goto free_path;
	}

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
			goto free_dir_no_msg;
		}

		/* +2 for '.' and final '\0' */
		if (used + strlen(pool->d_name) + strlen(fsname) + 2
		    > buffer_size) {
			rc = -EOVERFLOW;
			goto free_dir_no_msg;
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
	else
		llapi_printf(LLAPI_MSG_NORMAL, "Pools from %s:\n", fsname);

free_dir_no_msg:
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
	/*
	 * list of pool names (assume that pool count is smaller
	 * than OST count)
	 */
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

	/*
	 * Allocate space for each fsname-OST0000_UUID, 1 per OST,
	 * and also an array to store the pointers for all that
	 * allocated space.
	 */
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

typedef int (semantic_func_t)(char *path, int p, int *d,
			      void *data, struct dirent64 *de);

#define OBD_NOT_FOUND           (-1)

static void find_param_fini(struct find_param *param)
{
	if (param->fp_migrate)
		return;

	if (param->fp_obd_indexes) {
		free(param->fp_obd_indexes);
		param->fp_obd_indexes = NULL;
	}

	if (param->fp_lmd) {
		free(param->fp_lmd);
		param->fp_lmd = NULL;
	}

	if (param->fp_lmv_md) {
		free(param->fp_lmv_md);
		param->fp_lmv_md = NULL;
	}
}

static int common_param_init(struct find_param *param, char *path)
{
	int lum_size = get_mds_md_size(path);

	if (lum_size < 0)
		return lum_size;

	/* migrate has fp_lmv_md initialized outside */
	if (param->fp_migrate)
		return 0;

	if (lum_size < PATH_MAX + 1)
		lum_size = PATH_MAX + 1;

	param->fp_lum_size = lum_size;
	param->fp_lmd = calloc(1, offsetof(typeof(*param->fp_lmd), lmd_lmm) +
			       lum_size);
	if (param->fp_lmd == NULL) {
		llapi_error(LLAPI_MSG_ERROR, -ENOMEM,
			    "error: allocate %zu bytes for layout failed",
			    sizeof(lstat_t) + param->fp_lum_size);
		return -ENOMEM;
	}

	param->fp_lmv_stripe_count = 256;
	param->fp_lmv_md = calloc(1,
				  lmv_user_md_size(param->fp_lmv_stripe_count,
						   LMV_USER_MAGIC_SPECIFIC));
	if (param->fp_lmv_md == NULL) {
		llapi_error(LLAPI_MSG_ERROR, -ENOMEM,
			    "error: allocation of %d bytes for ioctl",
			    lmv_user_md_size(param->fp_lmv_stripe_count,
					     LMV_USER_MAGIC_SPECIFIC));
		find_param_fini(param);
		return -ENOMEM;
	}

	param->fp_got_uuids = 0;
	param->fp_obd_indexes = NULL;
	param->fp_obd_index = OBD_NOT_FOUND;
	param->fp_mdt_index = OBD_NOT_FOUND;
	return 0;
}

static int cb_common_fini(char *path, int p, int *dp, void *data,
			  struct dirent64 *de)
{
	struct find_param *param = data;

	param->fp_depth--;
	return 0;
}

/* set errno upon failure */
static int open_parent(const char *path)
{
	char *path_copy;
	char *parent_path;
	int parent;

	path_copy = strdup(path);
	if (path_copy == NULL)
		return -1;

	parent_path = dirname(path_copy);
	parent = open(parent_path, O_RDONLY|O_NDELAY|O_DIRECTORY);
	free(path_copy);

	return parent;
}

static int cb_get_dirstripe(char *path, int *d, struct find_param *param)
{
	int ret;
	bool did_nofollow = false;

again:
	param->fp_lmv_md->lum_stripe_count = param->fp_lmv_stripe_count;
	if (param->fp_get_default_lmv)
		param->fp_lmv_md->lum_magic = LMV_USER_MAGIC;
	else
		param->fp_lmv_md->lum_magic = LMV_MAGIC_V1;

	ret = ioctl(*d, LL_IOC_LMV_GETSTRIPE, param->fp_lmv_md);

	/* if ENOTTY likely to be a fake symlink, so try again after
	 * new open() with O_NOFOLLOW, but only once to prevent any
	 * loop like for the path of a file/dir not on Lustre !!
	 */
	if (ret < 0 && errno == ENOTTY && !did_nofollow) {
		int fd, ret2;

		did_nofollow = true;
		fd = open(path, O_RDONLY | O_NOFOLLOW);
		if (fd < 0) {
			/* restore original errno */
			errno = ENOTTY;
			return ret;
		}

		/* close original fd and set new */
		close(*d);
		*d = fd;
		ret2 = ioctl(fd, LL_IOC_LMV_GETSTRIPE, param->fp_lmv_md);
		if (ret2 < 0 && errno != E2BIG) {
			/* restore original errno */
			errno = ENOTTY;
			return ret;
		}
		/* LMV is ok or need to handle E2BIG case now */
		ret = ret2;
	}

	if (errno == E2BIG && ret != 0) {
		int stripe_count;
		int lmv_size;

		/* if foreign LMV case, fake stripes number */
		if (param->fp_lmv_md->lum_magic == LMV_MAGIC_FOREIGN) {
			struct lmv_foreign_md *lfm;

			lfm = (struct lmv_foreign_md *)param->fp_lmv_md;
			if (lfm->lfm_length < XATTR_SIZE_MAX -
			    offsetof(typeof(*lfm), lfm_value)) {
				uint32_t size = lfm->lfm_length +
					     offsetof(typeof(*lfm), lfm_value);

				stripe_count = lmv_foreign_to_md_stripes(size);
			} else {
				llapi_error(LLAPI_MSG_ERROR, -EINVAL,
					    "error: invalid %d foreign size returned from ioctl",
					    lfm->lfm_length);
				return -EINVAL;
			}
		} else {
			stripe_count = param->fp_lmv_md->lum_stripe_count;
		}
		if (stripe_count <= param->fp_lmv_stripe_count)
			return ret;

		free(param->fp_lmv_md);
		param->fp_lmv_stripe_count = stripe_count;
		lmv_size = lmv_user_md_size(stripe_count,
					    LMV_USER_MAGIC_SPECIFIC);
		param->fp_lmv_md = malloc(lmv_size);
		if (param->fp_lmv_md == NULL) {
			llapi_error(LLAPI_MSG_ERROR, -ENOMEM,
				    "error: allocation of %d bytes for ioctl",
				    lmv_user_md_size(param->fp_lmv_stripe_count,
						     LMV_USER_MAGIC_SPECIFIC));
			return -ENOMEM;
		}
		goto again;
	}
	return ret;
}

static void convert_lmd_statx(struct lov_user_mds_data *lmd_v2, lstat_t *st,
			      bool strict)
{
	memset(&lmd_v2->lmd_stx, 0, sizeof(lmd_v2->lmd_stx));
	lmd_v2->lmd_stx.stx_blksize = st->st_blksize;
	lmd_v2->lmd_stx.stx_nlink = st->st_nlink;
	lmd_v2->lmd_stx.stx_uid = st->st_uid;
	lmd_v2->lmd_stx.stx_gid = st->st_gid;
	lmd_v2->lmd_stx.stx_mode = st->st_mode;
	lmd_v2->lmd_stx.stx_ino = st->st_ino;
	lmd_v2->lmd_stx.stx_size = st->st_size;
	lmd_v2->lmd_stx.stx_blocks = st->st_blocks;
	lmd_v2->lmd_stx.stx_atime.tv_sec = st->st_atime;
	lmd_v2->lmd_stx.stx_ctime.tv_sec = st->st_ctime;
	lmd_v2->lmd_stx.stx_mtime.tv_sec = st->st_mtime;
	lmd_v2->lmd_stx.stx_rdev_major = major(st->st_rdev);
	lmd_v2->lmd_stx.stx_rdev_minor = minor(st->st_rdev);
	lmd_v2->lmd_stx.stx_dev_major = major(st->st_dev);
	lmd_v2->lmd_stx.stx_dev_minor = minor(st->st_dev);
	lmd_v2->lmd_stx.stx_mask |= STATX_BASIC_STATS;

	lmd_v2->lmd_flags = 0;
	if (strict) {
		lmd_v2->lmd_flags |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
	} else {
		lmd_v2->lmd_stx.stx_mask &= ~(STATX_SIZE | STATX_BLOCKS);
		if (lmd_v2->lmd_stx.stx_size)
			lmd_v2->lmd_flags |= OBD_MD_FLLAZYSIZE;
		if (lmd_v2->lmd_stx.stx_blocks)
			lmd_v2->lmd_flags |= OBD_MD_FLLAZYBLOCKS;
	}
	lmd_v2->lmd_flags |= OBD_MD_FLATIME | OBD_MD_FLMTIME | OBD_MD_FLCTIME |
			     OBD_MD_FLBLKSZ | OBD_MD_FLMODE | OBD_MD_FLTYPE |
			     OBD_MD_FLUID | OBD_MD_FLGID | OBD_MD_FLNLINK |
			     OBD_MD_FLRDEV;

}

static int convert_lmdbuf_v1v2(void *lmdbuf, int lmdlen)
{
	struct lov_user_mds_data_v1 *lmd_v1 = lmdbuf;
	struct lov_user_mds_data *lmd_v2 = lmdbuf;
	lstat_t st;
	int size;

	size = lov_comp_md_size((struct lov_comp_md_v1 *)&lmd_v1->lmd_lmm);
	if (size < 0)
		return size;

	if (lmdlen < sizeof(lmd_v1->lmd_st) + size)
		return -EOVERFLOW;

	st = lmd_v1->lmd_st;
	memmove(&lmd_v2->lmd_lmm, &lmd_v1->lmd_lmm,
		lmdlen - (&lmd_v2->lmd_lmm - &lmd_v1->lmd_lmm));
	convert_lmd_statx(lmd_v2, &st, false);
	lmd_v2->lmd_lmmsize = 0;
	lmd_v2->lmd_padding = 0;

	return 0;
}

int get_lmd_info_fd(const char *path, int parent_fd, int dir_fd,
		    void *lmdbuf, int lmdlen, enum get_lmd_info_type type)
{
	struct lov_user_mds_data *lmd = lmdbuf;
	static bool use_old_ioctl;
	unsigned long cmd;
	int ret = 0;

	if (parent_fd < 0 && dir_fd < 0)
		return -EINVAL;
	if (type != GET_LMD_INFO && type != GET_LMD_STRIPE)
		return -EINVAL;

	if (dir_fd >= 0) {
		/*
		 * LL_IOC_MDC_GETINFO operates on the current directory inode
		 * and returns struct lov_user_mds_data, while
		 * LL_IOC_LOV_GETSTRIPE returns only struct lov_user_md.
		 */
		if (type == GET_LMD_INFO)
			cmd = use_old_ioctl ? LL_IOC_MDC_GETINFO_V1 :
					      LL_IOC_MDC_GETINFO_V2;
		else
			cmd = LL_IOC_LOV_GETSTRIPE;

retry_getinfo:
		ret = ioctl(dir_fd, cmd, lmdbuf);
		if (ret < 0 && errno == ENOTTY &&
		    cmd == LL_IOC_MDC_GETINFO_V2) {
			cmd = LL_IOC_MDC_GETINFO_V1;
			use_old_ioctl = true;
			goto retry_getinfo;
		}

		if (cmd == LL_IOC_MDC_GETINFO_V1 && !ret)
			ret = convert_lmdbuf_v1v2(lmdbuf, lmdlen);

		if (ret < 0 && errno == ENOTTY && type == GET_LMD_STRIPE) {
			int dir_fd2;

			/* retry ioctl() after new open() with O_NOFOLLOW
			 * just in case it could be a fake symlink
			 * need using a new open() as dir_fd is being closed
			 * by caller
			 */

			dir_fd2 = open(path, O_RDONLY | O_NDELAY | O_NOFOLLOW);
			if (dir_fd2 < 0) {
				/* return original error */
				errno = ENOTTY;
			} else {
				ret = ioctl(dir_fd2, cmd, lmdbuf);
				/* pass new errno or success back to caller */

				close(dir_fd2);
			}
		}

	} else if (parent_fd >= 0) {
		const char *fname = strrchr(path, '/');

		/*
		 * IOC_MDC_GETFILEINFO takes as input the filename (relative to
		 * the parent directory) and returns struct lov_user_mds_data,
		 * while IOC_MDC_GETFILESTRIPE returns only struct lov_user_md.
		 *
		 * This avoids opening, locking, and closing each file on the
		 * client if that is not needed. Multiple of these ioctl() can
		 * be done on the parent dir with a single open for all
		 * files in that directory, and it also doesn't pollute the
		 * client dcache with millions of dentries when traversing
		 * a large filesystem.
		 */
		fname = (fname == NULL ? path : fname + 1);

		ret = snprintf(lmdbuf, lmdlen, "%s", fname);
		if (ret < 0)
			errno = -ret;
		else if (ret >= lmdlen || ret++ == 0)
			errno = EINVAL;
		else {
			if (type == GET_LMD_INFO)
				cmd = use_old_ioctl ? IOC_MDC_GETFILEINFO_V1 :
						      IOC_MDC_GETFILEINFO_V2;
			else
				cmd = IOC_MDC_GETFILESTRIPE;

retry_getfileinfo:
			ret = ioctl(parent_fd, cmd, lmdbuf);
			if (ret < 0 && errno == ENOTTY &&
			    cmd == IOC_MDC_GETFILEINFO_V2) {
				cmd = IOC_MDC_GETFILEINFO_V1;
				use_old_ioctl = true;
				goto retry_getfileinfo;
			}

			if (cmd == IOC_MDC_GETFILEINFO_V1 && !ret)
				ret = convert_lmdbuf_v1v2(lmdbuf, lmdlen);
		}
	}

	if (ret && type == GET_LMD_INFO) {
		if (errno == ENOTTY) {
			lstat_t st;

			/*
			 * ioctl is not supported, it is not a lustre fs.
			 * Do the regular lstat(2) instead.
			 */
			ret = lstat_f(path, &st);
			if (ret) {
				ret = -errno;
				llapi_error(LLAPI_MSG_ERROR, ret,
					    "error: %s: lstat failed for %s",
					    __func__, path);
			}

			convert_lmd_statx(lmd, &st, true);
			/*
			 * It may be wrong to set use_old_ioctl with true as
			 * the file is not a lustre fs. So reset it with false
			 * directly here.
			 */
			use_old_ioctl = false;
		} else if (errno == ENOENT) {
			ret = -errno;
			llapi_error(LLAPI_MSG_WARN, ret,
				    "warning: %s does not exist", path);
		} else if (errno != EISDIR && errno != ENODATA) {
			ret = -errno;
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "%s ioctl failed for %s.",
				    dir_fd >= 0 ? "LL_IOC_MDC_GETINFO" :
				    "IOC_MDC_GETFILEINFO", path);
		}
	}

	return ret;
}

static int llapi_semantic_traverse(char *path, int size, int parent,
				   semantic_func_t sem_init,
				   semantic_func_t sem_fini, void *data,
				   struct dirent64 *de)
{
	struct find_param *param = (struct find_param *)data;
	struct dirent64 *dent;
	int len, ret, d, p = -1;
	DIR *dir = NULL;

	ret = 0;
	len = strlen(path);

	d = open(path, O_RDONLY|O_NDELAY|O_DIRECTORY);
	/* if an invalid fake dir symlink, opendir() will return EINVAL
	 * instead of ENOTDIR. If a valid but dangling faked or real file/dir
	 * symlink ENOENT will be returned. For a valid/resolved fake or real
	 * file symlink ENOTDIR will be returned as for a regular file.
	 * opendir() will be successful for a  valid and resolved fake or real
	 * dir simlink or a regular dir.
	 */
	if (d == -1 && errno != ENOTDIR && errno != EINVAL && errno != ENOENT) {
		ret = -errno;
		llapi_error(LLAPI_MSG_ERROR, ret, "%s: Failed to open '%s'",
			    __func__, path);
		return ret;
	} else if (d == -1) {
		if (errno == ENOENT || errno == EINVAL) {
			int old_errno = errno;

			/* try to open with O_NOFOLLOW this will help
			 * differentiate fake vs real symlinks
			 * it is ok to not use O_DIRECTORY with O_RDONLY
			 * and it will prevent the need to deal with ENOTDIR
			 * error, instead of ELOOP, being returned by recent
			 * kernels for real symlinks
			 */
			d = open(path, O_RDONLY|O_NDELAY|O_NOFOLLOW);
			/* if a dangling real symlink should return ELOOP, or
			 * again ENOENT if really non-existing path, or E...??
			 * So return original error. If success or ENOTDIR, path
			 * is likely to be a fake dir/file symlink, so continue
			 */
			if (d == -1) {
				ret =  -old_errno;
				goto out;
			}

		}

		/* ENOTDIR */
		if (parent == -1 && d == -1) {
			/* Open the parent dir. */
			p = open_parent(path);
			if (p == -1) {
				ret = -errno;
				goto out;
			}
		}
	} else { /* d != -1 */
		int d2;

		/* try to reopen dir with O_NOFOLLOW just in case of a foreign
		 * symlink dir
		 */
		d2 = open(path, O_RDONLY|O_NDELAY|O_NOFOLLOW);
		if (d2 != -1) {
			close(d);
			d = d2;
		} else {
			/* continue with d */
			errno = 0;
		}
	}

	if (sem_init) {
		ret = sem_init(path, (parent != -1) ? parent : p, &d, data, de);
		if (ret)
			goto err;
	}

	if (d == -1)
		goto out;

	dir = fdopendir(d);
	if (dir == NULL) {
		/* ENOTDIR if fake symlink, do not consider it as an error */
		if (errno != ENOTDIR)
			llapi_error(LLAPI_MSG_ERROR, errno,
				    "fdopendir() failed");
		else
			errno = 0;

		goto out;
	}

	while ((dent = readdir64(dir)) != NULL) {
		int rc;

		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;

		path[len] = 0;
		if ((len + dent->d_reclen + 2) > size) {
			llapi_err_noerrno(LLAPI_MSG_ERROR,
					  "error: %s: string buffer too small for %s",
					  __func__, path);
			break;
		}
		strcat(path, "/");
		strcat(path, dent->d_name);

		if (dent->d_type == DT_UNKNOWN) {
			struct lov_user_mds_data *lmd = param->fp_lmd;

			rc = get_lmd_info_fd(path, d, -1, param->fp_lmd,
					     param->fp_lum_size, GET_LMD_INFO);
			if (rc == 0)
				dent->d_type = IFTODT(lmd->lmd_stx.stx_mode);
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
				if (rc < 0 && ret == 0) {
					ret = rc;
					break;
				}
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
	if (d != -1) {
		if (dir)
			closedir(dir);
		else
			close(d);
	}
	if (p != -1)
		close(p);
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

	buf = (char *)malloc(2 * PATH_MAX);
	if (!buf)
		return -ENOMEM;

	snprintf(buf, PATH_MAX + 1, "%s", path);
	ret = common_param_init(param, buf);
	if (ret)
		goto out;

	param->fp_depth = 0;

	ret = llapi_semantic_traverse(buf, 2 * PATH_MAX, -1, sem_init,
				      sem_fini, param, NULL);
out:
	find_param_fini(param);
	free(buf);
	return ret < 0 ? ret : 0;
}

int llapi_file_fget_lov_uuid(int fd, struct obd_uuid *lov_name)
{
	int rc;

	rc = ioctl(fd, OBD_IOC_GETDTNAME, lov_name);
	if (rc && errno == ENOTTY)
		rc = ioctl(fd, OBD_IOC_GETNAME_OLD, lov_name);
	if (rc) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot get lov name");
	}

	return rc;
}

int llapi_file_fget_lmv_uuid(int fd, struct obd_uuid *lov_name)
{
	int rc;

	rc = ioctl(fd, OBD_IOC_GETMDNAME, lov_name);
	if (rc) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: can't get lmv name.");
	}

	return rc;
}

int llapi_file_get_lov_uuid(const char *path, struct obd_uuid *lov_uuid)
{
	int fd, rc;

	/* do not follow faked symlinks */
	fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
	if (fd < 0) {
		/* real symlink should have failed with ELOOP so retry without
		 * O_NOFOLLOW just in case
		 */
		fd = open(path, O_RDONLY | O_NONBLOCK);
		if (fd < 0) {
			rc = -errno;
			llapi_error(LLAPI_MSG_ERROR, rc, "cannot open '%s'",
				    path);
			return rc;
		}
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

/*
 * Check if user specified value matches a real uuid.  Ignore _UUID,
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

	/*
	 * The UUIDs may legitimately be different lengths, if
	 * the system was upgraded from an older version.
	 */
	if (cmplen != searchlen)
		return 0;

	return (strncmp(search_uuid, real_uuid, cmplen) == 0);
}

/*
 * Here, param->fp_obd_uuid points to a single obduuid, the index of which is
 * returned in param->fp_obd_index
 */
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

/*
 * In this case, param->fp_obd_uuid will be an array of obduuids and
 * obd index for all these obduuids will be returned in
 * param->fp_obd_indexes
 */
static int setup_indexes(int d, char *path, struct obd_uuid *obduuids,
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
	ret = llapi_get_target_uuids(d, uuids, &obdcount, type);
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

		llapi_error(LLAPI_MSG_ERROR, ret, "cannot get ost uuid");
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
					  "invalid obduuid '%s'",
					  obduuids[obdnum].uuid);
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

static int setup_target_indexes(int d, char *path, struct find_param *param)
{
	int ret = 0;

	if (param->fp_mdt_uuid) {
		ret = setup_indexes(d, path, param->fp_mdt_uuid,
				    param->fp_num_mdts,
				    &param->fp_mdt_indexes,
				    &param->fp_mdt_index, LMV_TYPE);
		if (ret)
			return ret;
	}

	if (param->fp_obd_uuid) {
		ret = setup_indexes(d, path, param->fp_obd_uuid,
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
		snprintf(fsname_buf, sizeof(fsname_buf), "%s", fsname);
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
		snprintf(cache.fsname, sizeof(cache.fsname), "%s", fsname_buf);
	}

	if (scount)
		*scount = cache.stripecount;
	if (ssize)
		*ssize = cache.stripesize;
	if (soffset)
		*soffset = cache.stripeoffset;

	return 0;
}

static char *layout2name(__u32 layout_pattern)
{
	if (layout_pattern & LOV_PATTERN_F_RELEASED)
		return "released";
	else if (layout_pattern == LOV_PATTERN_MDT)
		return "mdt";
	else if (layout_pattern == LOV_PATTERN_RAID0)
		return "raid0";
	else if (layout_pattern ==
			(LOV_PATTERN_RAID0 | LOV_PATTERN_OVERSTRIPING))
		return "raid0,overstriped";
	else
		return "unknown";
}

enum lov_dump_flags {
	LDF_IS_DIR	= 0x0001,
	LDF_IS_RAW	= 0x0002,
	LDF_INDENT	= 0x0004,
	LDF_SKIP_OBJS	= 0x0008,
	LDF_YAML	= 0x0010,
	LDF_EXTENSION	= 0x0020,
};

static void lov_dump_user_lmm_header(struct lov_user_md *lum, char *path,
				     struct lov_user_ost_data_v1 *objects,
				     enum llapi_layout_verbose verbose,
				     int depth, char *pool_name,
				     enum lov_dump_flags flags)
{
	bool is_dir = flags & LDF_IS_DIR;
	bool is_raw = flags & LDF_IS_RAW;
	bool indent = flags & LDF_INDENT;
	bool yaml = flags & LDF_YAML;
	bool skip_objs = flags & LDF_SKIP_OBJS;
	bool extension = flags & LDF_EXTENSION;
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
		/*
		 * This needs a bit of hand-holding since old 1.x lmm_oi
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
		 * For newer layout types hopefully this will be a real FID.
		 */
		seq = lmm_oi_seq(&lum->lmm_oi) == 0 ?
			lmm_oi_id(&lum->lmm_oi) : lmm_oi_seq(&lum->lmm_oi);
		oid = lmm_oi_seq(&lum->lmm_oi) == 0 ?
			0 : (__u32)lmm_oi_id(&lum->lmm_oi);
		ver = (__u32)(lmm_oi_id(&lum->lmm_oi) >> 32);
		if (yaml)
			llapi_printf(LLAPI_MSG_NORMAL, DFID_NOBRACE"\n",
				     (unsigned long long)seq, oid, ver);
		else
			llapi_printf(LLAPI_MSG_NORMAL, DFID"\n",
				     (unsigned long long)seq, oid, ver);
	}

	if (verbose & VERBOSE_STRIPE_COUNT) {
		if (verbose & ~VERBOSE_STRIPE_COUNT)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%sstripe_count:  ",
				     space, prefix);
		if (is_dir) {
			if (!is_raw && lum->lmm_stripe_count == 0 &&
			    lov_pattern(lum->lmm_pattern) != LOV_PATTERN_MDT) {
				unsigned int scount;

				rc = sattr_cache_get_defaults(NULL, path,
							      &scount, NULL,
							      NULL);
				if (rc == 0)
					llapi_printf(LLAPI_MSG_NORMAL, "%d",
						     scount);
				else
					llapi_error(LLAPI_MSG_ERROR, rc,
						    "Cannot determine default stripe count.");
			} else {
				llapi_printf(LLAPI_MSG_NORMAL, "%d",
					     extension ? 0 :
					     (__s16)lum->lmm_stripe_count);
			}
		} else {
			llapi_printf(LLAPI_MSG_NORMAL, "%hd",
				     extension ? 0 :
				     (__s16)lum->lmm_stripe_count);
		}
		if (!yaml && is_dir)
			separator = " ";
		else
			separator = "\n";
	}

	if (((verbose & VERBOSE_STRIPE_SIZE) && !extension) ||
	    ((verbose & VERBOSE_EXT_SIZE) && extension)) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_EXT_SIZE && extension)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%sextension_size: ",
				     space, prefix);
		if (verbose & ~VERBOSE_STRIPE_SIZE && !extension)
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
					    "Cannot determine default stripe size.");
		} else {
			/* Extension size is in KiB */
			llapi_printf(LLAPI_MSG_NORMAL, "%llu",
				     extension ?
				     (unsigned long long)(lum->lmm_stripe_size * SEL_UNIT_SIZE) :
				     (unsigned long long)lum->lmm_stripe_size);
		}
		if (!yaml && is_dir)
			separator = " ";
		else
			separator = "\n";
	}

	if ((verbose & VERBOSE_PATTERN)) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_PATTERN)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%spattern:       ",
				     space, prefix);
		if (lov_pattern_supported(lum->lmm_pattern))
			llapi_printf(LLAPI_MSG_NORMAL, "%s",
				     layout2name(lum->lmm_pattern));
		else
			llapi_printf(LLAPI_MSG_NORMAL, "%x", lum->lmm_pattern);
		separator = (!yaml && is_dir) ? " " : "\n";
	}

	if ((verbose & VERBOSE_GENERATION) && !is_dir) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_GENERATION)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%slayout_gen:    ",
				     space, prefix);
		llapi_printf(LLAPI_MSG_NORMAL, "%u",
			     skip_objs ? 0 : (int)lum->lmm_layout_gen);
		separator = "\n";
	}

	if (verbose & VERBOSE_STRIPE_OFFSET) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_STRIPE_OFFSET)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%sstripe_offset: ",
				     space, prefix);
		if (is_dir || skip_objs)
			llapi_printf(LLAPI_MSG_NORMAL, "%d",
				     lum->lmm_stripe_offset ==
				     (typeof(lum->lmm_stripe_offset))(-1) ? -1 :
				     lum->lmm_stripe_offset);
		else if (lov_pattern(lum->lmm_pattern) == LOV_PATTERN_MDT)
			llapi_printf(LLAPI_MSG_NORMAL, "0");
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
			    enum llapi_layout_verbose verbose,
			    enum lov_dump_flags flags)
{
	bool is_dir = flags & LDF_IS_DIR;
	bool indent = flags & LDF_INDENT;
	bool skip_objs = flags & LDF_SKIP_OBJS;
	bool yaml = flags & LDF_YAML;
	bool obdstripe = obdindex == OBD_NOT_FOUND;
	int i;

	if (!obdstripe && !skip_objs) {
		for (i = 0; !is_dir && i < lum->lmm_stripe_count; i++) {
			if (obdindex == objects[i].l_ost_idx) {
				obdstripe = true;
				break;
			}
		}
	}

	if (!obdstripe)
		return;

	lov_dump_user_lmm_header(lum, path, objects, verbose, depth, pool_name,
				 flags);

	if (!is_dir && !skip_objs && (verbose & VERBOSE_OBJID) &&
	    !(lum->lmm_pattern & LOV_PATTERN_F_RELEASED ||
	      lov_pattern(lum->lmm_pattern) == LOV_PATTERN_MDT)) {
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
	}
	llapi_printf(LLAPI_MSG_NORMAL, "\n");
}

void lmv_dump_user_lmm(struct lmv_user_md *lum, char *pool_name,
		       char *path, int obdindex, int depth,
		       enum llapi_layout_verbose verbose,
		       enum lov_dump_flags flags)
{
	struct lmv_user_mds_data *objects = lum->lum_objects;
	char *prefix = lum->lum_magic == LMV_USER_MAGIC ? "(Default)" : "";
	char *separator = "";
	bool yaml = flags & LDF_YAML;
	bool obdstripe = false;
	int i;

	if (obdindex != OBD_NOT_FOUND) {
		if (lum->lum_stripe_count == 0) {
			if (obdindex == lum->lum_stripe_offset)
				obdstripe = true;
		} else {
			for (i = 0; i < lum->lum_stripe_count; i++) {
				if (obdindex == objects[i].lum_mds) {
					llapi_printf(LLAPI_MSG_NORMAL,
						     "%s%s\n", prefix,
						     path);
					obdstripe = true;
					break;
				}
			}
		}
	} else {
		obdstripe = true;
	}

	if (!obdstripe)
		return;

	/* show all information default */
	if (!verbose) {
		if (lum->lum_magic == LMV_USER_MAGIC)
			verbose = VERBOSE_POOL | VERBOSE_STRIPE_COUNT |
				  VERBOSE_STRIPE_OFFSET | VERBOSE_HASH_TYPE;
		else
			verbose = VERBOSE_OBJID;
	}

	if (depth && path && ((verbose != VERBOSE_OBJID)))
		llapi_printf(LLAPI_MSG_NORMAL, "%s%s\n", prefix, path);

	if (verbose & VERBOSE_STRIPE_COUNT) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_STRIPE_COUNT)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_stripe_count: ");
		llapi_printf(LLAPI_MSG_NORMAL, "%d",
			     (int)lum->lum_stripe_count);
		if ((verbose & VERBOSE_STRIPE_OFFSET) && !yaml)
			separator = " ";
		else
			separator = "\n";
	}

	if (verbose & VERBOSE_STRIPE_OFFSET) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_STRIPE_OFFSET)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_stripe_offset: ");
		llapi_printf(LLAPI_MSG_NORMAL, "%d",
			     (int)lum->lum_stripe_offset);
		if (verbose & VERBOSE_HASH_TYPE && !yaml)
			separator = " ";
		else
			separator = "\n";
	}

	if (verbose & VERBOSE_HASH_TYPE) {
		unsigned int type = lum->lum_hash_type & LMV_HASH_TYPE_MASK;
		unsigned int flags = lum->lum_hash_type & ~LMV_HASH_TYPE_MASK;

		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_HASH_TYPE)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_hash_type: ");
		if (type < LMV_HASH_TYPE_MAX)
			llapi_printf(LLAPI_MSG_NORMAL, "%s",
				     mdt_hash_name[type]);
		else
			llapi_printf(LLAPI_MSG_NORMAL, "%#x", type);

		if (flags & LMV_HASH_FLAG_MIGRATION)
			llapi_printf(LLAPI_MSG_NORMAL, ",migrating");
		if (flags & LMV_HASH_FLAG_BAD_TYPE)
			llapi_printf(LLAPI_MSG_NORMAL, ",bad_type");
		if (flags & LMV_HASH_FLAG_LOST_LMV)
			llapi_printf(LLAPI_MSG_NORMAL, ",lost_lmv");

		if (verbose & VERBOSE_HASH_TYPE && !yaml)
			separator = " ";
		else
			separator = "\n";
	}

	if ((verbose & VERBOSE_INHERIT) && lum->lum_magic == LMV_USER_MAGIC) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_INHERIT)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_max_inherit: ");
		if (lum->lum_max_inherit == LMV_INHERIT_UNLIMITED)
			llapi_printf(LLAPI_MSG_NORMAL, "-1");
		else if (lum->lum_max_inherit == LMV_INHERIT_NONE)
			llapi_printf(LLAPI_MSG_NORMAL, "0");
		else
			llapi_printf(LLAPI_MSG_NORMAL, "%hhu",
				     lum->lum_max_inherit);
		if (verbose & VERBOSE_INHERIT && !yaml)
			separator = " ";
		else
			separator = "\n";
	}

	if ((verbose & VERBOSE_INHERIT_RR) &&
	    lum->lum_magic == LMV_USER_MAGIC &&
	    lum->lum_stripe_offset == LMV_OFFSET_DEFAULT) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_INHERIT_RR)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_max_inherit_rr: ");
		if (lum->lum_max_inherit_rr == LMV_INHERIT_RR_UNLIMITED)
			llapi_printf(LLAPI_MSG_NORMAL, "-1");
		else if (lum->lum_max_inherit_rr == LMV_INHERIT_RR_NONE)
			llapi_printf(LLAPI_MSG_NORMAL, "0");
		else
			llapi_printf(LLAPI_MSG_NORMAL, "%hhu",
				     lum->lum_max_inherit_rr);
		if (verbose & VERBOSE_INHERIT_RR && !yaml)
			separator = " ";
		else
			separator = "\n";
	}

	separator = "\n";

	if (verbose & VERBOSE_OBJID && lum->lum_magic != LMV_USER_MAGIC) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (lum->lum_stripe_count > 0)
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
	enum llapi_layout_verbose verbose = param->fp_verbose;
	bool yaml = flags & LDF_YAML;

	if (depth && path && ((verbose != VERBOSE_OBJID) ||
			      !(flags & LDF_IS_DIR)) && !yaml)
		llapi_printf(LLAPI_MSG_NORMAL, "%s\n", path);

	if (verbose & VERBOSE_DETAIL) {
		llapi_printf(LLAPI_MSG_NORMAL, "composite_header:\n");
		llapi_printf(LLAPI_MSG_NORMAL, "%2slcm_magic:         0x%08X\n",
			     " ", comp_v1->lcm_magic);
		llapi_printf(LLAPI_MSG_NORMAL, "%2slcm_size:          %u\n",
			     " ", comp_v1->lcm_size);
		if (flags & LDF_IS_DIR)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%2slcm_flags:         %s\n", " ",
				     comp_v1->lcm_mirror_count > 0 ?
							"mirrored" : "");
		else
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%2slcm_flags:         %s\n", " ",
				llapi_layout_flags_string(comp_v1->lcm_flags));
	}

	if (verbose & VERBOSE_GENERATION) {
		if (verbose & ~VERBOSE_GENERATION)
			llapi_printf(LLAPI_MSG_NORMAL, "%2slcm_layout_gen:    ",
				     " ");
		llapi_printf(LLAPI_MSG_NORMAL, "%u\n", comp_v1->lcm_layout_gen);
	}

	if (verbose & VERBOSE_MIRROR_COUNT) {
		if (verbose & ~VERBOSE_MIRROR_COUNT)
			llapi_printf(LLAPI_MSG_NORMAL, "%2slcm_mirror_count:  ",
				     " ");
		llapi_printf(LLAPI_MSG_NORMAL, "%u\n",
			     comp_v1->lcm_magic == LOV_USER_MAGIC_COMP_V1 ?
			     comp_v1->lcm_mirror_count + 1 : 1);
	}

	if (verbose & VERBOSE_COMP_COUNT) {
		if (verbose & ~VERBOSE_COMP_COUNT)
			llapi_printf(LLAPI_MSG_NORMAL, "%2slcm_entry_count:   ",
				     " ");
		llapi_printf(LLAPI_MSG_NORMAL, "%u\n",
			     comp_v1->lcm_magic == LOV_USER_MAGIC_COMP_V1 ?
			     comp_v1->lcm_entry_count : 0);
	}

	if (verbose & VERBOSE_DETAIL && !yaml)
		llapi_printf(LLAPI_MSG_NORMAL, "components:\n");
}

static void lcme_flags2str(__u32 comp_flags)
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
	enum llapi_layout_verbose verbose = param->fp_verbose;
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

	if (verbose & VERBOSE_MIRROR_ID) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_MIRROR_ID)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%4slcme_mirror_id:      ", " ");
		if (entry->lcme_id != LCME_ID_INVAL)
			llapi_printf(LLAPI_MSG_NORMAL, "%u",
				     mirror_id_of(entry->lcme_id));
		else
			llapi_printf(LLAPI_MSG_NORMAL, "N/A");
		separator = "\n";
	}

	if (verbose & VERBOSE_COMP_FLAGS) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_COMP_FLAGS)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%4slcme_flags:          ", " ");
		lcme_flags2str(entry->lcme_flags);
		separator = "\n";
	}
	/* print snapshot timestamp if its a nosync comp */
	if ((verbose & VERBOSE_COMP_FLAGS) &&
	    (entry->lcme_flags & LCME_FL_NOSYNC)) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_COMP_FLAGS)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%4slcme_timestamp:      ", " ");
		if (yaml) {
			llapi_printf(LLAPI_MSG_NORMAL, "%llu",
				     (unsigned long long)entry->lcme_timestamp);
		} else {
			time_t stamp = entry->lcme_timestamp;
			char *date_str = asctime(localtime(&stamp));

			date_str[strlen(date_str) - 1] = '\0';
			llapi_printf(LLAPI_MSG_NORMAL, "'%s'", date_str);
		}

		separator = "\n";
	}

	if (verbose & VERBOSE_COMP_START) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_COMP_START)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%4slcme_extent.e_start: ", " ");
		llapi_printf(LLAPI_MSG_NORMAL, "%llu",
			     (unsigned long long)entry->lcme_extent.e_start);
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
				     (unsigned long long)entry->lcme_extent.e_end);
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

/*
 * Check if the value matches 1 of the given criteria (e.g. --atime +/-N).
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
 * (limit - margin, limit].
 */
static int find_value_cmp(unsigned long long file, unsigned long long limit,
			  int sign, int negopt, unsigned long long margin,
			  bool mds)
{
	int ret = -1;

	if (sign > 0) {
		/* Drop the fraction of margin (of days or size). */
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
		snprintf(pool_name, LOV_MAXPOOLNAME, "%s",
			 ((struct lov_user_md_v3 *)v1)->lmm_pool_name);
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
	    param->fp_check_comp_start || param->fp_check_comp_end ||
	    param->fp_check_mirror_id || param->fp_check_mirror_index)
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
 *     lmm_pattern:       raid0
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
 *     lmm_pattern:       raid0
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
	int i, j, match, ext;
	bool obdstripe = false;
	__u16 mirror_index = 0;
	__u16 mirror_id = 0;

	if (obdindex != OBD_NOT_FOUND) {
		for (i = 0; !(flags & LDF_IS_DIR) && !obdstripe &&
			    i < comp_v1->lcm_entry_count; i++) {
			if (!(comp_v1->lcm_entries[i].lcme_flags &
			      LCME_FL_INIT))
				continue;

			v1 = lov_comp_entry(comp_v1, i);
			objects = lov_v1v3_objects(v1);

			for (j = 0; j < v1->lmm_stripe_count; j++) {
				if (obdindex == objects[j].l_ost_idx) {
					obdstripe = true;
					break;
				}
			}
		}
	} else {
		obdstripe = true;
	}

	if (!obdstripe)
		return;

	lov_dump_comp_v1_header(param, path, flags);

	flags |= LDF_INDENT;

	for (i = 0; i < comp_v1->lcm_entry_count; i++) {
		entry = &comp_v1->lcm_entries[i];

		if (param->fp_check_comp_flags) {
			if (((param->fp_comp_flags & entry->lcme_flags) !=
			     param->fp_comp_flags) ||
			    (param->fp_comp_neg_flags & entry->lcme_flags))
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

		if (param->fp_check_mirror_index) {
			if (mirror_id != mirror_id_of(entry->lcme_id)) {
				mirror_index++;
				mirror_id = mirror_id_of(entry->lcme_id);
			}

			match = find_value_cmp(mirror_index,
					       param->fp_mirror_index,
					       param->fp_mirror_index_sign,
					       param->fp_exclude_mirror_index,
					       1, 0);
			if (match == -1)
				continue;
		} else if (param->fp_check_mirror_id) {
			if (mirror_id != mirror_id_of(entry->lcme_id))
				mirror_id = mirror_id_of(entry->lcme_id);

			match = find_value_cmp(mirror_id,
					       param->fp_mirror_id,
					       param->fp_mirror_id_sign,
					       param->fp_exclude_mirror_id,
					       1, 0);
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

			if (param->fp_verbose & VERBOSE_EXT_SIZE) {
				if (entry->lcme_flags & LCME_FL_EXTENSION)
					/* moved back below */
					i++;
				else
					continue;
			}
			break;
		}

		if (entry->lcme_flags & LCME_FL_INIT) {
			if (obdindex != OBD_NOT_FOUND) {
				flags |= LDF_SKIP_OBJS;
				v1 = lov_comp_entry(comp_v1, i);
				objects = lov_v1v3_objects(v1);

				for (j = 0; j < v1->lmm_stripe_count; j++) {
					if (obdindex == objects[j].l_ost_idx) {
						flags &= ~LDF_SKIP_OBJS;
						break;
					}
				}
			} else {
				flags &= ~LDF_SKIP_OBJS;
			}
		} else {
			flags |= LDF_SKIP_OBJS;
		}

		if (obdindex != OBD_NOT_FOUND && (flags & LDF_SKIP_OBJS))
			continue;
		lov_dump_comp_v1_entry(param, flags, i);

		v1 = lov_comp_entry(comp_v1, i);
		objects = lov_v1v3_objects(v1);
		lov_v1v3_pool_name(v1, pool_name);

		ext = entry->lcme_flags & LCME_FL_EXTENSION ? LDF_EXTENSION : 0;
		lov_dump_user_lmm_v1v3(v1, pool_name, objects, path, obdindex,
				       param->fp_max_depth, param->fp_verbose,
				       flags | ext);
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

		entry = &comp_v1->lcm_entries[i];
		ext = entry->lcme_flags & LCME_FL_EXTENSION ? LDF_EXTENSION : 0;
		lov_dump_user_lmm_v1v3(v1, pool_name, objects, path, obdindex,
				       param->fp_max_depth, param->fp_verbose,
				       flags | ext);
	}
}

#define VERBOSE_COMP_OPTS	(VERBOSE_COMP_COUNT | VERBOSE_COMP_ID | \
				 VERBOSE_COMP_START | VERBOSE_COMP_END | \
				 VERBOSE_COMP_FLAGS)

static inline bool has_any_comp_options(struct find_param *param)
{
	enum llapi_layout_verbose verbose = param->fp_verbose;

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

	new = malloc(offsetof(typeof(*new), lmd_lmm) + lum_off + lum_size);
	if (new == NULL) {
		llapi_printf(LLAPI_MSG_NORMAL, "out of memory\n");
		return new;
	}

	memcpy(new, orig, sizeof(new->lmd_stx) + sizeof(new->lmd_flags)
	       + sizeof(new->lmd_lmmsize));

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

		snprintf(pool_name, sizeof(pool_name), "%s",
			 lmmv3->lmm_pool_name);
		objects = lmmv3->lmm_objects;
		lov_dump_user_lmm_v1v3(&param->fp_lmd->lmd_lmm, pool_name,
				       objects, path, param->fp_obd_index,
				       param->fp_max_depth, param->fp_verbose,
				       flags);
	}
}

static uint32_t check_foreign_type(uint32_t foreign_type)
{
	uint32_t i;

	for (i = 0; i < LU_FOREIGN_TYPE_UNKNOWN; i++) {
		if (lu_foreign_types[i].lft_name == NULL)
			break;
		if (foreign_type == lu_foreign_types[i].lft_type)
			return i;
	}

	return LU_FOREIGN_TYPE_UNKNOWN;
}

static void lov_dump_foreign_lmm(struct find_param *param, char *path,
				 enum lov_dump_flags flags)
{
	struct lov_foreign_md *lfm = (void *)&param->fp_lmd->lmd_lmm;
	bool yaml = flags & LDF_YAML;

	if (!yaml && param->fp_depth && path)
		llapi_printf(LLAPI_MSG_NORMAL, "%s\n", path);

	if (param->fp_verbose & VERBOSE_DETAIL) {
		uint32_t type = check_foreign_type(lfm->lfm_type);

		llapi_printf(LLAPI_MSG_NORMAL, "lfm_magic:         0x%08X\n",
			     lfm->lfm_magic);
		llapi_printf(LLAPI_MSG_NORMAL, "lfm_length:          %u\n",
			     lfm->lfm_length);
		llapi_printf(LLAPI_MSG_NORMAL, "lfm_type:          0x%08X",
			     lfm->lfm_type);
		if (type < LU_FOREIGN_TYPE_UNKNOWN)
			llapi_printf(LLAPI_MSG_NORMAL, " (%s)\n",
				     lu_foreign_types[type].lft_name);
		else
			llapi_printf(LLAPI_MSG_NORMAL, " (unknown)\n");

		llapi_printf(LLAPI_MSG_NORMAL, "lfm_flags:          0x%08X\n",
			     lfm->lfm_flags);
	}
	llapi_printf(LLAPI_MSG_NORMAL, "lfm_value:     '%.*s'\n",
		     lfm->lfm_length, lfm->lfm_value);
	llapi_printf(LLAPI_MSG_NORMAL, "\n");
}

static void lmv_dump_foreign_lmm(struct find_param *param, char *path,
				    enum lov_dump_flags flags)
{
	struct lmv_foreign_md *lfm = (struct lmv_foreign_md *)param->fp_lmv_md;
	bool yaml = flags & LDF_YAML;

	if (!yaml && param->fp_depth && path)
		llapi_printf(LLAPI_MSG_NORMAL, "%s\n", path);

	if (param->fp_verbose & VERBOSE_DETAIL) {
		uint32_t type = check_foreign_type(lfm->lfm_type);

		llapi_printf(LLAPI_MSG_NORMAL, "lfm_magic:         0x%08X\n",
			     lfm->lfm_magic);
		llapi_printf(LLAPI_MSG_NORMAL, "lfm_length:          %u\n",
			     lfm->lfm_length);
		llapi_printf(LLAPI_MSG_NORMAL, "lfm_type:          0x%08X",
			     lfm->lfm_type);
		if (type < LU_FOREIGN_TYPE_UNKNOWN)
			llapi_printf(LLAPI_MSG_NORMAL, " (%s)\n",
				     lu_foreign_types[type].lft_name);
		else
			llapi_printf(LLAPI_MSG_NORMAL, " (unknown)\n");

		llapi_printf(LLAPI_MSG_NORMAL, "lfm_flags:          0x%08X\n",
			     lfm->lfm_flags);
	}
	llapi_printf(LLAPI_MSG_NORMAL, "lfm_value:     '%.*s'\n",
		     lfm->lfm_length, lfm->lfm_value);
	llapi_printf(LLAPI_MSG_NORMAL, "\n");
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
	case LOV_USER_MAGIC_SPECIFIC:
		lov_dump_plain_user_lmm(param, path, flags);
		break;
	case LOV_USER_MAGIC_FOREIGN:
		lov_dump_foreign_lmm(param, path, flags);
		break;
	case LMV_MAGIC_V1:
	case LMV_USER_MAGIC: {
		char pool_name[LOV_MAXPOOLNAME + 1];
		struct lmv_user_md *lum;

		lum = (struct lmv_user_md *)param->fp_lmv_md;
		snprintf(pool_name, sizeof(pool_name), "%s",
			 lum->lum_pool_name);
		lmv_dump_user_lmm(lum, pool_name, path, param->fp_obd_index,
				  param->fp_max_depth, param->fp_verbose,
				  flags);
		break;
	}
	case LOV_USER_MAGIC_COMP_V1:
		lov_dump_comp_v1(param, path, flags);
		break;
	case LMV_MAGIC_FOREIGN:
		lmv_dump_foreign_lmm(param, path, flags);
		break;
	default:
		llapi_printf(LLAPI_MSG_NORMAL,
			     "unknown lmm_magic:  %#x (expecting one of %#x %#x %#x %#x)\n",
			     *(__u32 *)&param->fp_lmd->lmd_lmm,
			     LOV_USER_MAGIC_V1, LOV_USER_MAGIC_V3,
			     LMV_USER_MAGIC, LMV_MAGIC_V1);
		return;
	}
}

static int llapi_file_get_stripe1(const char *path, struct lov_user_md *lum)
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
		goto out_free;
	}

	strcpy((char *)lum, fname);
	if (ioctl(fd, IOC_MDC_GETFILESTRIPE, (void *)lum) == -1)
		rc = -errno;

	if (close(fd) == -1 && rc == 0)
		rc = -errno;

out_free:
	free(dname);
	return rc;
}

int llapi_file_get_stripe(const char *path, struct lov_user_md *lum)
{
	char *canon_path = NULL;
	int rc, rc2;

	rc = llapi_file_get_stripe1(path, lum);
	if (!(rc == -ENOTTY || rc == -ENODATA))
		goto out;

	/* Handle failure due to symlinks by dereferencing path manually. */
	canon_path = canonicalize_file_name(path);
	if (canon_path == NULL)
		goto out; /* Keep original rc. */

	rc2 = llapi_file_get_stripe1(canon_path, lum);
	if (rc2 < 0)
		goto out; /* Keep original rc. */

	rc = 0;
out:
	free(canon_path);

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

	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
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

/*
 * Check if the file time matches all the given criteria (e.g. --atime +/-N).
 * Return -1 or 1 if file timestamp does not or does match the given criteria
 * correspondingly. Return 0 if the MDS time is being checked and there are
 * attributes on OSTs and it is not yet clear if the timespamp matches.
 *
 * If 0 is returned, we need to do another RPC to the OSTs to obtain the
 * updated timestamps.
 */
static int find_time_check(struct find_param *param, int mds)
{
	struct lov_user_mds_data *lmd = param->fp_lmd;
	int rc = 1;
	int rc2;

	/* Check if file is accepted. */
	if (param->fp_atime) {
		rc2 = find_value_cmp(lmd->lmd_stx.stx_atime.tv_sec,
				     param->fp_atime, param->fp_asign,
				     param->fp_exclude_atime,
				     param->fp_time_margin, mds);
		if (rc2 < 0)
			return rc2;
		rc = rc2;
	}

	if (param->fp_mtime) {
		rc2 = find_value_cmp(lmd->lmd_stx.stx_mtime.tv_sec,
				     param->fp_mtime, param->fp_msign,
				     param->fp_exclude_mtime,
				     param->fp_time_margin, mds);
		if (rc2 < 0)
			return rc2;

		/*
		 * If the previous check matches, but this one is not yet clear,
		 * we should return 0 to do an RPC on OSTs.
		 */
		if (rc == 1)
			rc = rc2;
	}

	if (param->fp_ctime) {
		rc2 = find_value_cmp(lmd->lmd_stx.stx_ctime.tv_sec,
				     param->fp_ctime, param->fp_csign,
				     param->fp_exclude_ctime,
				     param->fp_time_margin, mds);
		if (rc2 < 0)
			return rc2;

		/*
		 * If the previous check matches, but this one is not yet clear,
		 * we should return 0 to do an RPC on OSTs.
		 */
		if (rc == 1)
			rc = rc2;
	}

	return rc;
}

static int find_newerxy_check(struct find_param *param, int mds, bool from_mdt)
{
	struct lov_user_mds_data *lmd = param->fp_lmd;
	int i;
	int rc = 1;
	int rc2;

	for (i = 0; i < 2; i++) {
		/* Check if file is accepted. */
		if (param->fp_newery[NEWERXY_ATIME][i]) {
			rc2 = find_value_cmp(lmd->lmd_stx.stx_atime.tv_sec,
					     param->fp_newery[NEWERXY_ATIME][i],
					     -1, i, 0, mds);
			if (rc2 < 0)
				return rc2;
			rc = rc2;
		}

		if (param->fp_newery[NEWERXY_MTIME][i]) {
			rc2 = find_value_cmp(lmd->lmd_stx.stx_mtime.tv_sec,
					     param->fp_newery[NEWERXY_MTIME][i],
					     -1, i, 0, mds);
			if (rc2 < 0)
				return rc2;

			/*
			 * If the previous check matches, but this one is not
			 * yet clear, we should return 0 to do an RPC on OSTs.
			 */
			if (rc == 1)
				rc = rc2;
		}

		if (param->fp_newery[NEWERXY_CTIME][i]) {
			rc2 = find_value_cmp(lmd->lmd_stx.stx_ctime.tv_sec,
					     param->fp_newery[NEWERXY_CTIME][i],
					     -1, i, 0, mds);
			if (rc2 < 0)
				return rc2;

			/*
			 * If the previous check matches, but this one is not
			 * yet clear, we should return 0 to do an RPC on OSTs.
			 */
			if (rc == 1)
				rc = rc2;
		}

		/*
		 * File birth time (btime) can get from MDT directly.
		 * if @from_mdt is true, it means the input file attributs are
		 * obtained directly from MDT.
		 * Thus, if @from_mdt is false, we should skip the following
		 * btime check.
		 */
		if (!from_mdt)
			continue;

		if (param->fp_newery[NEWERXY_BTIME][i]) {
			if (!(lmd->lmd_stx.stx_mask & STATX_BTIME))
				return -EOPNOTSUPP;

			rc2 = find_value_cmp(lmd->lmd_stx.stx_btime.tv_sec,
					     param->fp_newery[NEWERXY_BTIME][i],
					     -1, i, 0, 0);
			if (rc2 < 0)
				return rc2;
		}
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
	struct lov_user_mds_data *lmd = param->fp_lmd;
	struct lov_user_md_v1 *v1 = &lmd->lmd_lmm;
	int i, j, k, count = 1;

	if (param->fp_obd_uuid && param->fp_obd_index == OBD_NOT_FOUND)
		return 0;

	if (!S_ISREG(lmd->lmd_stx.stx_mode))
		return 0;

	/* exclude foreign */
	if (v1->lmm_magic == LOV_USER_MAGIC_FOREIGN)
		return param->fp_exclude_obd;

	/*
	 * Only those files should be accepted, which have a
	 * stripe on the specified OST.
	 */
	if (v1->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
		count = comp_v1->lcm_entry_count;
	}

	for (i = 0; i < count; i++) {
		if (comp_v1)
			v1 = lov_comp_entry(comp_v1, i);

		objects = lov_v1v3_objects(v1);

		for (j = 0; j < v1->lmm_stripe_count; j++) {
			if (comp_v1 && !(comp_v1->lcm_entries[i].lcme_flags &
					 LCME_FL_INIT))
				continue;
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
static void print_failed_tgt(struct find_param *param, char *path, int type)
{
	struct obd_statfs stat_buf;
	struct obd_uuid uuid_buf;
	int tgt_nr, i, *indexes;
	int ret = 0;

	if (type != LL_STATFS_LOV && type != LL_STATFS_LMV) {
		llapi_error(LLAPI_MSG_NORMAL, ret, "%s: wrong statfs type(%d)",
			    __func__, type);
		return;
	}

	tgt_nr = (type == LL_STATFS_LOV) ? param->fp_obd_index :
		 param->fp_mdt_index;
	indexes = (type == LL_STATFS_LOV) ? param->fp_obd_indexes :
		  param->fp_mdt_indexes;

	for (i = 0; i < tgt_nr; i++) {
		memset(&stat_buf, 0, sizeof(struct obd_statfs));
		memset(&uuid_buf, 0, sizeof(struct obd_uuid));

		ret = llapi_obd_statfs(path, type, indexes[i], &stat_buf,
				       &uuid_buf);
		if (ret)
			llapi_error(LLAPI_MSG_NORMAL, ret,
				    "%s: obd_uuid: %s failed",
				    __func__, param->fp_obd_uuid->uuid);
	}
}

static int find_check_stripe_size(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_user_md_v1 *v1 = &param->fp_lmd->lmd_lmm;
	__u32 stripe_size = 0;
	int ret, i, count = 1;

	if (v1->lmm_magic == LOV_USER_MAGIC_FOREIGN)
		return param->fp_exclude_stripe_size ? 1 : -1;

	ret = param->fp_exclude_stripe_size ? 1 : -1;
	if (v1->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
		count = comp_v1->lcm_entry_count;
	}

	for (i = 0; i < count; i++) {
		struct lov_comp_md_entry_v1 *ent;

		if (comp_v1) {
			v1 = lov_comp_entry(comp_v1, i);

			ent = &comp_v1->lcm_entries[i];
			if (ent->lcme_flags & LCME_FL_EXTENSION)
				continue;
			if (!(ent->lcme_flags & LCME_FL_INIT))
				continue;
		}
		stripe_size = v1->lmm_stripe_size;
	}

	ret = find_value_cmp(stripe_size, param->fp_stripe_size,
			     param->fp_stripe_size_sign,
			     param->fp_exclude_stripe_size,
			     param->fp_stripe_size_units, 0);

	return ret;
}

static int find_check_ext_size(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1;
	struct lov_user_md_v1 *v1;
	int ret, i;

	ret = param->fp_exclude_ext_size ? 1 : -1;
	comp_v1 = (struct lov_comp_md_v1 *)&param->fp_lmd->lmd_lmm;
	if (comp_v1->lcm_magic != LOV_USER_MAGIC_COMP_V1)
		return ret;

	for (i = 0; i < comp_v1->lcm_entry_count; i++) {
		struct lov_comp_md_entry_v1 *ent;

		v1 = lov_comp_entry(comp_v1, i);

		ent = &comp_v1->lcm_entries[i];
		if (!(ent->lcme_flags & LCME_FL_EXTENSION))
			continue;

		ret = find_value_cmp(v1->lmm_stripe_size, param->fp_ext_size,
				     param->fp_ext_size_sign,
				     param->fp_exclude_ext_size,
				     param->fp_ext_size_units, 0);
		/* If any ext_size matches */
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

	if (v1->lmm_magic == LOV_USER_MAGIC_FOREIGN)
		return 0;

	if (v1->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
		count = comp_v1->lcm_entry_count;
	}

	for (i = 0; i < count; i++) {
		if (comp_v1) {
			struct lov_comp_md_entry_v1 *ent;

			v1 = lov_comp_entry(comp_v1, i);

			ent = &comp_v1->lcm_entries[i];
			if (!(ent->lcme_flags & LCME_FL_INIT))
				continue;

			if (ent->lcme_flags & LCME_FL_EXTENSION)
				continue;
		}
		stripe_count = v1->lmm_stripe_count;
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

		/* foreign file have a special magic but no pattern field */
		if (v1->lmm_magic == LOV_USER_MAGIC_FOREIGN)
			continue;

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

/*
 * if no type specified, check/exclude all foreign
 * if type specified, check all foreign&type and exclude !foreign + foreign&type
 */
static int find_check_foreign(struct find_param *param)
{
	if (S_ISREG(param->fp_lmd->lmd_stx.stx_mode)) {
		struct lov_foreign_md *lfm;

		lfm = (void *)&param->fp_lmd->lmd_lmm;
		if (lfm->lfm_magic != LOV_USER_MAGIC_FOREIGN) {
			if (param->fp_foreign_type == LU_FOREIGN_TYPE_UNKNOWN)
				return param->fp_exclude_foreign ? 1 : -1;
			return -1;
		}

		if (param->fp_foreign_type == LU_FOREIGN_TYPE_UNKNOWN ||
		    lfm->lfm_type == param->fp_foreign_type)
			return param->fp_exclude_foreign ? -1 : 1;
		return param->fp_exclude_foreign ? 1 : -1;
	}

	if (S_ISDIR(param->fp_lmd->lmd_stx.stx_mode)) {
		struct lmv_foreign_md *lfm;

		lfm = (void *)param->fp_lmv_md;
		if (lfm->lfm_magic != LMV_MAGIC_FOREIGN) {
			if (param->fp_foreign_type == LU_FOREIGN_TYPE_UNKNOWN)
				return param->fp_exclude_foreign ? 1 : -1;
			return -1;
		}

		if (param->fp_foreign_type == LU_FOREIGN_TYPE_UNKNOWN ||
		    lfm->lfm_type == param->fp_foreign_type)
			return param->fp_exclude_foreign ? -1 : 1;
		return param->fp_exclude_foreign ? 1 : -1;
	}
	return -1;
}

static int find_check_pool(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_user_md_v3 *v3 = (void *)&param->fp_lmd->lmd_lmm;
	int i, count = 1;
	bool found = false;

	if (v3->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v3;
		count = comp_v1->lcm_entry_count;
		/* empty requested pool is taken as no pool search */
		if (count == 0 && param->fp_poolname[0] == '\0') {
			found = true;
			goto found;
		}
	}

	for (i = 0; i < count; i++) {
		if (comp_v1 != NULL) {
			if (!(comp_v1->lcm_entries[i].lcme_flags &
			      LCME_FL_INIT))
				continue;

			v3 = (void *)lov_comp_entry(comp_v1, i);
		}

		if (v3->lmm_magic == LOV_USER_MAGIC_FOREIGN)
			continue;

		if (((v3->lmm_magic == LOV_USER_MAGIC_V1) &&
		     (param->fp_poolname[0] == '\0')) ||
		    ((v3->lmm_magic == LOV_USER_MAGIC_V3) &&
		     (strncmp(v3->lmm_pool_name,
			      param->fp_poolname, LOV_MAXPOOLNAME) == 0)) ||
		    ((v3->lmm_magic == LOV_USER_MAGIC_V3) &&
		     (strcmp(param->fp_poolname, "*") == 0))) {
			found = true;
			break;
		}
	}

found:
	if ((found && !param->fp_exclude_pool) ||
	    (!found && param->fp_exclude_pool))
		return 1;

	return -1;
}

static int find_check_comp_options(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1, *forged_v1 = NULL;
	struct lov_user_mds_data *lmd = param->fp_lmd;
	struct lov_user_md_v1 *v1 = &lmd->lmd_lmm;
	struct lov_comp_md_entry_v1 *entry;
	int i, ret = 0;

	if (v1->lmm_magic == LOV_USER_MAGIC_FOREIGN)
		return -1;

	if (v1->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
	} else {
		forged_v1 = malloc(sizeof(*forged_v1) + sizeof(*entry));
		if (forged_v1 == NULL)
			return -1;
		comp_v1 = forged_v1;
		comp_v1->lcm_entry_count = 1;
		entry = &comp_v1->lcm_entries[0];
		entry->lcme_flags = S_ISDIR(lmd->lmd_stx.stx_mode) ?
				    0 : LCME_FL_INIT;
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
			ret = 1;
			if (((param->fp_comp_flags & entry->lcme_flags) !=
			     param->fp_comp_flags) ||
			    (param->fp_comp_neg_flags & entry->lcme_flags)) {
				ret = -1;
				continue;
			}
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
	if (forged_v1)
		free(forged_v1);
	return ret;
}

static int find_check_mirror_options(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1;
	struct lov_user_md_v1 *v1 = &param->fp_lmd->lmd_lmm;
	int ret = 0;

	if (v1->lmm_magic != LOV_USER_MAGIC_COMP_V1)
		return -1;

	comp_v1 = (struct lov_comp_md_v1 *)v1;

	if (param->fp_check_mirror_count) {
		ret = find_value_cmp(comp_v1->lcm_mirror_count + 1,
				     param->fp_mirror_count,
				     param->fp_mirror_count_sign,
				     param->fp_exclude_mirror_count, 1, 0);
		if (ret == -1)
			return ret;
	}

	if (param->fp_check_mirror_state) {
		ret = 1;
		__u16 file_state = comp_v1->lcm_flags & LCM_FL_FLR_MASK;

		if ((param->fp_mirror_state != 0 &&
		    file_state != param->fp_mirror_state) ||
		    file_state == param->fp_mirror_neg_state)
			return -1;
	}

	return ret;
}

static bool find_check_lmm_info(struct find_param *param)
{
	return param->fp_check_pool || param->fp_check_stripe_count ||
	       param->fp_check_stripe_size || param->fp_check_layout ||
	       param->fp_check_comp_count || param->fp_check_comp_end ||
	       param->fp_check_comp_start || param->fp_check_comp_flags ||
	       param->fp_check_mirror_count || param->fp_check_foreign ||
	       param->fp_check_mirror_state || param->fp_check_ext_size ||
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

	rc = ioctl(fd, FS_IOC_FSGETXATTR, &fsx);
	if (rc)
		return -errno;

	*projid = fsx.fsx_projid;
	return 0;
}

static int cb_find_init(char *path, int p, int *dp,
			void *data, struct dirent64 *de)
{
	struct find_param *param = (struct find_param *)data;
	struct lov_user_mds_data *lmd = param->fp_lmd;
	int d = dp == NULL ? -1 : *dp;
	int decision = 1; /* 1 is accepted; -1 is rejected. */
	int lustre_fs = 1;
	int checked_type = 0;
	int ret = 0;
	__u32 stripe_count = 0;
	__u64 flags;
	int fd = -2;

	if (p == -1 && d == -1)
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

	/*
	 * Request MDS for the stat info if some of these parameters need
	 * to be compared.
	 */
	if (param->fp_obd_uuid || param->fp_mdt_uuid ||
	    param->fp_check_uid || param->fp_check_gid ||
	    param->fp_newerxy || param->fp_btime ||
	    param->fp_atime || param->fp_mtime || param->fp_ctime ||
	    param->fp_check_size || param->fp_check_blocks ||
	    find_check_lmm_info(param) ||
	    param->fp_check_mdt_count || param->fp_hash_type ||
	    param->fp_check_hash_flag)
		decision = 0;

	if (param->fp_type != 0 && checked_type == 0)
		decision = 0;

	if (decision == 0) {
		if (d != -1 && (param->fp_check_mdt_count ||
		    param->fp_hash_type || param->fp_check_foreign ||
		    param->fp_check_hash_flag)) {
			param->fp_get_lmv = 1;
			ret = cb_get_dirstripe(path, &d, param);
			if (ret != 0) {
				/*
				 * XXX this works to decide for foreign
				 * criterion only
				 */
				if (errno == ENODATA &&
				    param->fp_check_foreign) {
					if (param->fp_exclude_foreign)
						goto foreign;
					goto decided;
				}
				return ret;
			}
		}

		param->fp_lmd->lmd_lmm.lmm_magic = 0;
		ret = get_lmd_info_fd(path, p, d, param->fp_lmd,
				      param->fp_lum_size, GET_LMD_INFO);
		if (ret == 0 && param->fp_lmd->lmd_lmm.lmm_magic == 0 &&
		    find_check_lmm_info(param)) {
			struct lov_user_md *lmm = &param->fp_lmd->lmd_lmm;

			/*
			 * We need to "fake" the "use the default" values
			 * since the lmm struct is zeroed out at this point.
			 */
			lmm->lmm_magic = LOV_USER_MAGIC_V1;
			lmm->lmm_pattern = LOV_PATTERN_DEFAULT;
			if (!param->fp_raw)
				ostid_set_seq(&lmm->lmm_oi,
					      FID_SEQ_LOV_DEFAULT);
			lmm->lmm_stripe_size = 0;
			lmm->lmm_stripe_count = 0;
			lmm->lmm_stripe_offset = -1;
		}
		if (ret == 0 && param->fp_mdt_uuid != NULL) {
			if (d != -1) {
				ret = llapi_file_fget_mdtidx(d,
						     &param->fp_file_mdt_index);
			} else if (S_ISREG(lmd->lmd_stx.stx_mode)) {
				/*
				 * FIXME: we could get the MDT index from the
				 * file's FID in lmd->lmd_lmm.lmm_oi without
				 * opening the file, once we are sure that
				 * LFSCK2 (2.6) has fixed up pre-2.0 LOV EAs.
				 * That would still be an ioctl() to map the
				 * FID to the MDT, but not an open RPC.
				 */
				fd = open(path, O_RDONLY);
				if (fd > 0) {
					ret = llapi_file_fget_mdtidx(fd,
						     &param->fp_file_mdt_index);
				} else {
					ret = -errno;
				}
			} else {
				/*
				 * For a special file, we assume it resides on
				 * the same MDT as the parent directory.
				 */
				ret = llapi_file_fget_mdtidx(p,
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
		if ((lmd->lmd_stx.stx_mode & S_IFMT) == param->fp_type) {
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
		    param->fp_dev != makedev(lmd->lmd_stx.stx_dev_major,
					     lmd->lmd_stx.stx_dev_minor)) {
			/* A lustre/lustre mount point is crossed. */
			param->fp_got_uuids = 0;
			param->fp_obds_printed = 0;
			param->fp_mdt_index = OBD_NOT_FOUND;
			param->fp_obd_index = OBD_NOT_FOUND;
		}

		if (lustre_fs && !param->fp_got_uuids) {
			ret = setup_target_indexes((d != -1) ? d : p, path,
						   param);
			if (ret)
				goto out;

			param->fp_dev = makedev(lmd->lmd_stx.stx_dev_major,
						lmd->lmd_stx.stx_dev_minor);
		} else if (!lustre_fs && param->fp_got_uuids) {
			/* A lustre/non-lustre mount point is crossed. */
			param->fp_got_uuids = 0;
			param->fp_mdt_index = OBD_NOT_FOUND;
			param->fp_obd_index = OBD_NOT_FOUND;
		}
	}

	if (param->fp_check_foreign) {
		decision = find_check_foreign(param);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_stripe_size) {
		decision = find_check_stripe_size(param);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_ext_size) {
		decision = find_check_ext_size(param);
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
		if (param->fp_lmv_md->lum_magic == LMV_MAGIC_FOREIGN) {
			decision = -1;
			goto decided;
		}

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

	if (param->fp_hash_type) {
		__u32 found;
		__u32 type = param->fp_lmv_md->lum_hash_type &
			     LMV_HASH_TYPE_MASK;

		if (param->fp_lmv_md->lum_magic == LMV_MAGIC_FOREIGN) {
			decision = -1;
			goto decided;
		}

		found = (1 << type) & param->fp_hash_type;
		if ((found && param->fp_exclude_hash_type) ||
		    (!found && !param->fp_exclude_hash_type)) {
			decision = -1;
			goto decided;
		}
	}

	if (param->fp_check_hash_flag) {
		__u32 flags = param->fp_lmv_md->lum_hash_type &
			      ~LMV_HASH_TYPE_MASK;

		if (param->fp_lmv_md->lum_magic == LMV_MAGIC_FOREIGN) {
			decision = -1;
			goto decided;
		}

		if (!(flags & param->fp_hash_inflags) ||
		     (flags & param->fp_hash_exflags)) {
			decision = -1;
			goto decided;
		}
	}

	/* If an OBD UUID is specified but none matches, skip this file. */
	if ((param->fp_obd_uuid && param->fp_obd_index == OBD_NOT_FOUND) ||
	    (param->fp_mdt_uuid && param->fp_mdt_index == OBD_NOT_FOUND))
		goto decided;

	/*
	 * If an OST or MDT UUID is given, and some OST matches,
	 * check it here.
	 */
	if (param->fp_obd_index != OBD_NOT_FOUND ||
	    param->fp_mdt_index != OBD_NOT_FOUND) {
		if (param->fp_obd_uuid) {
			if (check_obd_match(param)) {
				/*
				 * If no mdtuuid is given, we are done.
				 * Otherwise, fall through to the mdtuuid
				 * check below.
				 */
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
		if (lmd->lmd_stx.stx_uid == param->fp_uid) {
			if (param->fp_exclude_uid)
				goto decided;
		} else {
			if (!param->fp_exclude_uid)
				goto decided;
		}
	}

	if (param->fp_check_gid) {
		if (lmd->lmd_stx.stx_gid == param->fp_gid) {
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
			if (param->fp_exclude_projid)
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

	if (param->fp_check_mirror_count || param->fp_check_mirror_state) {
		decision = find_check_mirror_options(param);
		if (decision == -1)
			goto decided;
	}

	/* Check the time on mds. */
	decision = 1;
	if (param->fp_atime || param->fp_mtime || param->fp_ctime) {
		int for_mds;

		for_mds = lustre_fs ?
			  (S_ISREG(lmd->lmd_stx.stx_mode) && stripe_count) : 0;
		decision = find_time_check(param, for_mds);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_btime) {
		if (!(lmd->lmd_stx.stx_mask & STATX_BTIME)) {
			ret = -EOPNOTSUPP;
			goto out;
		}

		decision = find_value_cmp(lmd->lmd_stx.stx_btime.tv_sec,
					  param->fp_btime, param->fp_bsign,
					  param->fp_exclude_btime,
					  param->fp_time_margin, 0);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_newerxy) {
		int for_mds;

		for_mds = lustre_fs ?
			  (S_ISREG(lmd->lmd_stx.stx_mode) && stripe_count) : 0;
		decision = find_newerxy_check(param, for_mds, true);
		if (decision == -1)
			goto decided;
		if (decision < 0) {
			ret = decision;
			goto out;
		}
	}

	flags = param->fp_lmd->lmd_flags;
	if (param->fp_check_size &&
	    ((S_ISREG(lmd->lmd_stx.stx_mode) && stripe_count) ||
	      S_ISDIR(lmd->lmd_stx.stx_mode)) &&
	    !(flags & OBD_MD_FLSIZE ||
	      (param->fp_lazy && flags & OBD_MD_FLLAZYSIZE)))
		decision = 0;

	if (param->fp_check_blocks &&
	    ((S_ISREG(lmd->lmd_stx.stx_mode) && stripe_count) ||
	      S_ISDIR(lmd->lmd_stx.stx_mode)) &&
	    !(flags & OBD_MD_FLBLOCKS ||
	      (param->fp_lazy && flags & OBD_MD_FLLAZYBLOCKS)))
		decision = 0;

	/*
	 * If file still fits the request, ask ost for updated info.
	 * The regular stat is almost of the same speed as some new
	 * 'glimpse-size-ioctl'.
	 */
	if (!decision) {
		lstat_t st;

		/*
		 * For regular files with the stripe the decision may have not
		 * been taken yet if *time or size is to be checked.
		 */
		if (param->fp_obd_index != OBD_NOT_FOUND)
			print_failed_tgt(param, path, LL_STATFS_LOV);

		if (param->fp_mdt_index != OBD_NOT_FOUND)
			print_failed_tgt(param, path, LL_STATFS_LMV);

		if (d != -1)
			ret = fstat_f(d, &st);
		else if (de != NULL)
			ret = fstatat_f(p, de->d_name, &st,
					AT_SYMLINK_NOFOLLOW);
		else
			ret = lstat_f(path, &st);

		if (ret) {
			if (errno == ENOENT) {
				llapi_error(LLAPI_MSG_ERROR, -ENOENT,
					    "warning: %s: %s does not exist",
					    __func__, path);
				goto decided;
			} else {
				ret = -errno;
				llapi_error(LLAPI_MSG_ERROR, ret,
					    "%s: stat on %s failed",
					    __func__, path);
				goto out;
			}
		}

		convert_lmd_statx(param->fp_lmd, &st, true);
		/* Check the time on osc. */
		decision = find_time_check(param, 0);
		if (decision == -1)
			goto decided;

		if (param->fp_newerxy) {
			decision = find_newerxy_check(param, 0, false);
			if (decision == -1)
				goto decided;
			if (decision < 0) {
				ret = decision;
				goto out;
			}
		}
	}

	if (param->fp_check_size) {
		decision = find_value_cmp(lmd->lmd_stx.stx_size,
					  param->fp_size,
					  param->fp_size_sign,
					  param->fp_exclude_size,
					  param->fp_size_units, 0);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_blocks) { /* convert st_blocks to bytes */
		decision = find_value_cmp(lmd->lmd_stx.stx_blocks * 512,
					  param->fp_blocks,
					  param->fp_blocks_sign,
					  param->fp_exclude_blocks,
					  param->fp_blocks_units, 0);
		if (decision == -1)
			goto decided;
	}

foreign:
	llapi_printf(LLAPI_MSG_NORMAL, "%s", path);
	if (param->fp_zero_end)
		llapi_printf(LLAPI_MSG_NORMAL, "%c", '\0');
	else
		llapi_printf(LLAPI_MSG_NORMAL, "\n");

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

static int cb_migrate_mdt_init(char *path, int p, int *dp,
			       void *param_data, struct dirent64 *de)
{
	struct find_param *param = (struct find_param *)param_data;
	struct lmv_user_md *lmu = param->fp_lmv_md;
	int tmp_p = p;
	char raw[MAX_IOC_BUFLEN] = {'\0'};
	char *rawbuf = raw;
	struct obd_ioctl_data data = { 0 };
	int ret;
	char *path_copy;
	char *filename;
	bool retry = false;

	if (p == -1 && dp == NULL)
		return -EINVAL;

	if (!lmu)
		return -EINVAL;

	if (dp != NULL && *dp != -1)
		close(*dp);

	if (p == -1) {
		tmp_p = open_parent(path);
		if (tmp_p == -1) {
			*dp = -1;
			ret = -errno;
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "can not open %s", path);
			return ret;
		}
	}

	path_copy = strdup(path);
	filename = basename(path_copy);

	data.ioc_inlbuf1 = (char *)filename;
	data.ioc_inllen1 = strlen(filename) + 1;
	data.ioc_inlbuf2 = (char *)lmu;
	data.ioc_inllen2 = lmv_user_md_size(lmu->lum_stripe_count,
					    lmu->lum_magic);
	ret = llapi_ioctl_pack(&data, &rawbuf, sizeof(raw));
	if (ret != 0) {
		llapi_error(LLAPI_MSG_ERROR, ret,
			    "%s: error packing ioctl data", __func__);
		goto out;
	}

migrate:
	ret = ioctl(tmp_p, LL_IOC_MIGRATE, rawbuf);
	if (ret != 0) {
		if (errno == EBUSY && !retry) {
			/*
			 * because migrate may not be able to lock all involved
			 * objects in order, for some of them it try lock, while
			 * there may be conflicting COS locks and cause migrate
			 * fail with EBUSY, hope a sync() could cause
			 * transaction commit and release these COS locks.
			 */
			sync();
			retry = true;
			goto migrate;
		} else if (errno == EALREADY) {
			if (param->fp_verbose & VERBOSE_DETAIL)
				llapi_printf(LLAPI_MSG_NORMAL,
					     "%s migrated to MDT%d already\n",
					     path, lmu->lum_stripe_offset);
			ret = 0;
		} else {
			ret = -errno;
			llapi_error(LLAPI_MSG_ERROR, ret, "%s migrate failed",
				    path);
			goto out;
		}
	} else if (param->fp_verbose & VERBOSE_DETAIL) {
		llapi_printf(LLAPI_MSG_NORMAL,
			     "migrate %s to MDT%d stripe count %d\n",
			     path, lmu->lum_stripe_offset,
			     lmu->lum_stripe_count);
	}

out:
	if (dp != NULL) {
		/*
		 * If the directory is being migration, we need
		 * close the directory after migration,
		 * so the old directory cache will be cleanup
		 * on the client side, and re-open to get the
		 * new directory handle
		 */
		*dp = open(path, O_RDONLY|O_NDELAY|O_DIRECTORY);
		if (*dp == -1) {
			ret = -errno;
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "%s: Failed to open '%s'", __func__, path);
		}
	}

	if (p == -1)
		close(tmp_p);

	free(path_copy);

	return ret;
}

/* dir migration finished, shrink its stripes */
static int cb_migrate_mdt_fini(char *path, int p, int *dp, void *data,
			       struct dirent64 *de)
{
	struct find_param *param = data;
	struct lmv_user_md *lmu = param->fp_lmv_md;
	int lmulen = lmv_user_md_size(lmu->lum_stripe_count, lmu->lum_magic);
	int ret = 0;

	if (de && de->d_type != DT_DIR)
		goto out;

	if (*dp != -1) {
		/*
		 * close it before setxattr because the latter may destroy the
		 * original object, and cause close fail.
		 */
		ret = close(*dp);
		*dp = -1;
		if (ret)
			goto out;
	}

	ret = setxattr(path, XATTR_NAME_LMV, lmu, lmulen, 0);
	if (ret == -EALREADY)
		ret = 0;
out:
	cb_common_fini(path, p, dp, data, de);
	return ret;
}

int llapi_migrate_mdt(char *path, struct find_param *param)
{
	return param_callback(path, cb_migrate_mdt_init, cb_migrate_mdt_fini,
			      param);
}

int llapi_mv(char *path, struct find_param *param)
{
#if LUSTRE_VERSION_CODE > OBD_OCD_VERSION(2, 9, 59, 0)
	static bool printed;

	if (!printed) {
		llapi_error(LLAPI_MSG_ERROR, -ESTALE,
			  "%s() is deprecated, use llapi_migrate_mdt() instead",
			  __func__);
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

static int cb_get_mdt_index(char *path, int p, int *dp, void *data,
			    struct dirent64 *de)
{
	struct find_param *param = (struct find_param *)data;
	int d = dp == NULL ? -1 : *dp;
	int ret;
	int mdtidx;

	if (p == -1 && d == -1)
		return -EINVAL;

	if (d != -1) {
		ret = llapi_file_fget_mdtidx(d, &mdtidx);
	} else /* if (p != -1) */ {
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

static int cb_getstripe(char *path, int p, int *dp, void *data,
			struct dirent64 *de)
{
	struct find_param *param = (struct find_param *)data;
	int d = dp == NULL ? -1 : *dp;
	int ret = 0;

	if (p == -1 && d == -1)
		return -EINVAL;

	if (param->fp_obd_uuid) {
		param->fp_quiet = 1;
		ret = setup_obd_uuid(d != -1 ? d : p, path, param);
		if (ret)
			return ret;
	}

	if (d != -1 && (param->fp_get_lmv || param->fp_get_default_lmv))
		ret = cb_get_dirstripe(path, &d, param);
	else if (d != -1 ||
		 (p != -1 && !param->fp_get_lmv && !param->fp_get_default_lmv))
		ret = get_lmd_info_fd(path, p, d, &param->fp_lmd->lmd_lmm,
				      param->fp_lum_size, GET_LMD_STRIPE);
	else if (d == -1 && (param->fp_get_lmv || param->fp_get_default_lmv)) {
		/* in case of a dangling or valid faked symlink dir, opendir()
		 * should have return either EINVAL or ENOENT, so let's try
		 * to get LMV just in case, and by opening it as a file but
		 * with O_NOFOLLOW ...
		 */
		int fd = open(path, O_RDONLY | O_NOFOLLOW);

		if (fd == -1)
			return 0;
		ret = cb_get_dirstripe(path, &fd, param);
		if (ret == 0)
			llapi_lov_dump_user_lmm(param, path, LDF_IS_DIR);
		close(fd);
		return 0;
	} else
		return 0;

	if (ret) {
		if (errno == ENODATA && d != -1) {
			/*
			 * We need to "fake" the "use the default" values
			 * since the lmm struct is zeroed out at this point.
			 * The magic needs to be set in order to satisfy
			 * a check later on in the code path.
			 * The object_seq needs to be set for the "(Default)"
			 * prefix to be displayed.
			 */
			if (param->fp_get_default_lmv) {
				struct lmv_user_md *lum = param->fp_lmv_md;

				lum->lum_magic = LMV_USER_MAGIC;
				lum->lum_stripe_count = 0;
				lum->lum_stripe_offset = LMV_OFFSET_DEFAULT;
				goto dump;
			} else if (param->fp_get_lmv) {
				struct lmv_user_md *lum = param->fp_lmv_md;
				int mdtidx;

				ret = llapi_file_fget_mdtidx(d, &mdtidx);
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
		} else if (errno == ENODATA && p != -1) {
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
				     __func__, d != -1 ?
					       "LL_IOC_LOV_GETSTRIPE" :
					       "IOC_MDC_GETFILESTRIPE", path);
		}

		return ret;
	}

dump:
	if (!(param->fp_verbose & VERBOSE_MDTINDEX))
		llapi_lov_dump_user_lmm(param, path, d != -1 ? LDF_IS_DIR : 0);

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
	char raw[MAX_IOC_BUFLEN] = {'\0'};
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

	rc = llapi_ioctl_pack(&data, &rawbuf, sizeof(raw));
	if (rc != 0) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "%s: error packing ioctl data", __func__);
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
		/*
		 * If we can't even open a file on the filesystem (e.g. with
		 * -ESHUTDOWN), force caller to exit or it will loop forever.
		 */
		return -ENODEV;
	}

	rc = llapi_obd_fstatfs(fd, type, index, stat_buf, uuid_buf);

	close(fd);

	return rc;
}

#define MAX_STRING_SIZE 128

int llapi_ping(char *obd_type, char *obd_name)
{
	int flags = O_RDONLY;
	char buf[1] = { 0 };
	glob_t path;
	int rc, fd;

	rc = cfs_get_param_paths(&path, "%s/%s/ping",
				obd_type, obd_name);
	if (rc != 0)
		return -errno;
retry_open:
	fd = open(path.gl_pathv[0], flags);
	if (fd < 0) {
		if (errno == EACCES && flags == O_RDONLY) {
			flags = O_WRONLY;
			goto retry_open;
		}
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error opening %s",
			    path.gl_pathv[0]);
		goto failed;
	}

	if (flags == O_RDONLY)
		rc = read(fd, buf, sizeof(buf));
	else
		rc = write(fd, buf, sizeof(buf));
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
	int i, rc = 0;
	glob_t param;
	FILE *fp;

	for (i = 0; i < type_num; i++) {
		int j;

		rc = cfs_get_param_paths(&param, "%s/*/uuid", obd_type[i]);
		if (rc != 0)
			continue;

		for (j = 0; j < param.gl_pathc; j++) {
			char obd_uuid[UUID_MAX + 1];
			char *obd_name;
			char *ptr;

			fp = fopen(param.gl_pathv[j], "r");
			if (fp == NULL) {
				rc = -errno;
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "error: opening '%s'",
					    param.gl_pathv[j]);
				goto free_path;
			}

			if (fgets(obd_uuid, sizeof(obd_uuid), fp) == NULL) {
				rc = -errno;
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "error: reading '%s'",
					    param.gl_pathv[j]);
				goto free_path;
			}

			/* Extract the obd_name from the sysfs path.
			 * 'topsysfs'/fs/lustre/'obd_type'/'obd_name'.
			 */
			obd_name = strstr(param.gl_pathv[j], "/fs/lustre/");
			if (!obd_name) {
				rc = -EINVAL;
				goto free_path;
			}

			/* skip /fs/lustre/'obd_type'/ */
			obd_name += strlen(obd_type[i]) + 12;
			/* chop off after obd_name */
			ptr = strrchr(obd_name, '/');
			if (ptr)
				*ptr = '\0';

			cb(obd_type[i], obd_name, obd_uuid, args);

			fclose(fp);
			fp = NULL;
		}
	}
free_path:
	if (fp)
		fclose(fp);
	cfs_free_param_data(&param);
	return rc;
}

static void do_target_check(char *obd_type_name, char *obd_name,
			    char *obd_uuid, void *args)
{
	int rc;

	rc = llapi_ping(obd_type_name, obd_name);
	if (rc == ENOTCONN)
		llapi_printf(LLAPI_MSG_NORMAL, "%s inactive.\n", obd_name);
	else if (rc)
		llapi_error(LLAPI_MSG_ERROR, rc, "error: check '%s'", obd_name);
	else
		llapi_printf(LLAPI_MSG_NORMAL, "%s active.\n", obd_name);
}

int llapi_target_check(int type_num, char **obd_type, char *dir)
{
	return llapi_target_iterate(type_num, obd_type, NULL, do_target_check);
}

#undef MAX_STRING_SIZE

/* Is this a lustre fs? */
int llapi_is_lustre_mnttype(const char *type)
{
	return strcmp(type, "lustre") == 0 || strcmp(type, "lustre_tgt") == 0;
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
	if (rc)
		return rc;

	root = open(mnt, O_RDONLY | O_DIRECTORY);
	if (root < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot open '%s'", mnt);
		return rc;
	}

	rc = ioctl(root, OBD_IOC_QUOTACTL, qctl);
	if (rc < 0)
		rc = -errno;
	if (rc == -ENOENT && LUSTRE_Q_CMD_IS_POOL(qctl->qc_cmd))
		llapi_error(LLAPI_MSG_ERROR | LLAPI_MSG_NO_ERRNO, rc,
			    "Cannot find pool '%s'", qctl->qc_poolname);

	close(root);
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
 * Flush cached pages from all clients.
 *
 * \param fd	File descriptor
 * \retval 0	success
 * \retval < 0	error
 */
int llapi_file_flush(int fd)
{
	__u64 dv;

	return llapi_get_data_version(fd, &dv, LL_DV_WR_FLUSH);
}

