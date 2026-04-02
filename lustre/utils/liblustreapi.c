// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <libgen.h> /* for dirname() */
#include <mntent.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/sysmacros.h>
#include <linux/limits.h>
#ifdef HAVE_LINUX_UNISTD_H
#include <linux/unistd.h>
#else
#include <unistd.h>
#endif

#include <libcfs/util/ioctl.h>
#include <libcfs/util/param.h>
#include <libcfs/util/string.h>
#include <linux/lnet/lnetctl.h>
#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_ioctl.h>
#include <linux/lustre/lustre_ostid.h>
#include "lstddef.h"
#include "lustreapi_internal.h"

static int llapi_msg_level = LLAPI_MSG_MAX;
const char *liblustreapi_cmd;

struct lustre_foreign_type lu_foreign_types[] = {
	{.lft_type = LU_FOREIGN_TYPE_NONE,	.lft_name = "none"},
	{.lft_type = LU_FOREIGN_TYPE_POSIX,	.lft_name = "posix"},
	{.lft_type = LU_FOREIGN_TYPE_PCCRW,	.lft_name = "pccrw"},
	{.lft_type = LU_FOREIGN_TYPE_PCCRO,	.lft_name = "pccro"},
	{.lft_type = LU_FOREIGN_TYPE_S3,	.lft_name = "S3"},
	{.lft_type = LU_FOREIGN_TYPE_SYMLINK,	.lft_name = "symlink"},
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

/*
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

/*
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
 * llapi_parse_size() - Convert a size string (with optional suffix) into binary
 *                      value.
 * @optarg: string containing numeric value with optional
 *          KMGTPE suffix to specify the unit size.
 *          The @string may be a decimal value.
 * @size: pointer to integer numeric value to be returned [out]
 * @size_units: units of @string if dimensionless.  Must be
 *              initialized by caller. If zero, units = bytes.
 * @bytes_spec: if suffix 'b' means bytes or 512-byte sectors.
 *
 * Return:
 * * %0 success
 * * %-EINVAL negative or too large size, or unknown suffix
 */
int llapi_parse_size(const char *optarg, unsigned long long *size,
		     unsigned long long *size_units, int bytes_spec)
{
	char *end;
	char *argbuf = (char *)optarg;
	unsigned long long frac = 0, frac_d = 1;

	if (strncmp(optarg, "-", 1) == 0)
		return -EINVAL;

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
		char next = tolower(*(end + 1));

		switch (tolower(*end)) {
		case 'b':
			if (bytes_spec) {
				*size_units = 1;
			} else {
				if (*size & (~0ULL << (64 - 9)))
					return -EINVAL;
				*size_units = 1 << 9;
			}
			break;
		case 'c':
			*size_units = 1;
			break;
		case 'k':
			if (*size & (~0ULL << (64 - 10)))
				return -EINVAL;
			*size_units = 1 << 10;
			break;
		case 'm':
			if (*size & (~0ULL << (64 - 20)))
				return -EINVAL;
			*size_units = 1 << 20;
			break;
		case 'g':
			if (*size & (~0ULL << (64 - 30)))
				return -EINVAL;
			*size_units = 1 << 30;
			break;
		case 't':
			if (*size & (~0ULL << (64 - 40)))
				return -EINVAL;
			*size_units = 1ULL << 40;
			break;
		case 'p':
			if (*size & (~0ULL << (64 - 50)))
				return -EINVAL;
			*size_units = 1ULL << 50;
			break;
		case 'e':
			if (*size & (~0ULL << (64 - 60)))
				return -EINVAL;
			*size_units = 1ULL << 60;
			break;
		default:
			return -EINVAL;
		}
		if (next != '\0' && next != 'i' && next != 'b')
			return -EINVAL;
	}
	*size = *size * *size_units + frac * *size_units / frac_d;

	return 0;
}

/**
 * llapi_stripe_param_verify() - Verify the setstripe parameters before using.
 * @param: stripe parameters
 * @pool_name: pool name
 * @fsname: lustre FS name
 *
 * This is a pair method for comp_args_to_layout()/llapi_layout_sanity_cb()
 * when just 1 component or a non-PFL layout is given.
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
static int llapi_stripe_param_verify(const struct llapi_stripe_param *param,
				     const char **pool_name, char *fsname)
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
	if (param->lsp_stripe_pattern & LOV_PATTERN_MDT) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Invalid pattern: '-L mdt', must be specified "
			    "with -E\n");
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
		if (!llapi_pool_name_is_valid(pool_name)) {
			rc = -EINVAL;
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "Invalid Poolname '%s'", *pool_name);
			goto out;
		}

		if (!lov_pool_is_ignored((const char *) *pool_name)) {
			/* Make sure the pool exists */
			rc = llapi_search_ost(fsname, *pool_name, NULL);
			if (rc < 0) {
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "pool '%s fsname %s' does not exist",
					    *pool_name, fsname);
				rc = -EINVAL;
				goto out;
			}
		}
	}

out:
	errno = -rc;
	return rc;
}

static int dir_stripe_limit_check(int stripe_offset, int stripe_count,
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

/**
 * llapi_file_open_param() - Open a Lustre file.
 * @name: the name of the file to be opened
 * @flags: access mode, see flags in open(2)
 * @mode: permission of the file if it is created, see mode in open(2)
 * @param: stripe pattern of the newly created file
 *
 * Return file descriptor of opened file or %negative errno on failure
 */
int llapi_file_open_param(const char *name, int flags, mode_t mode,
			  const struct llapi_stripe_param *param)
{
	char fsname[MAX_OBD_NAME + 1] = { 0 };
	struct lov_user_md *lum = NULL;
	const char *pool_name = param->lsp_pool;
	bool use_default_striping = false;
	size_t lum_size;
	int fd, rc = 0;

	/* Make sure we are on a Lustre file system */
	if (pool_name && !lov_pool_is_ignored(pool_name)) {
		rc = llapi_search_fsname(name, fsname);
		if (rc) {
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "'%s' is not on a Lustre filesystem", name);
			return rc;
		}
	}

	/* Check if the stripe pattern is sane. */
	rc = llapi_stripe_param_verify(param, &pool_name, fsname);
	if (rc < 0)
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
	if (!use_default_striping)
		fd = open(name, flags | O_LOV_DELAY_CREATE, mode);
	else
		fd = open(name, flags, mode);
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
		snprintf(lumv3->lmm_pool_name, sizeof(lumv3->lmm_pool_name),
			 "%s", pool_name);
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
			memset(lumv3->lmm_pool_name, 0,
			       sizeof(lumv3->lmm_pool_name));
		}

		for (i = 0; i < param->lsp_stripe_count; i++)
			lumv3->lmm_objects[i].l_ost_idx = param->lsp_osts[i];
	}

	if (!use_default_striping && ioctl(fd, LL_IOC_LOV_SETSTRIPE, lum) != 0) {
		char errbuf[512] = "stripe already set";
		char *errmsg = errbuf;

		rc = -errno;
		if (rc != -EEXIST && rc != -EALREADY)
			strncpy(errbuf, strerror(errno), sizeof(errbuf) - 1);
		if (rc == -EREMOTEIO)
			snprintf(errbuf, sizeof(errbuf),
				 "inactive OST among your specified %d OST(s)",
				 param->lsp_stripe_count);
		close(fd);
		/* the only reason we get EACESS on the ioctl is if setstripe
		 * has been explicitly restricted, normal permission errors
		 * happen earlier on open() and we never call ioctl()
		 */
		if (rc == -EACCES) {
			errmsg = "Setstripe is restricted by your administrator, default striping applied";
			llapi_err_noerrno(LLAPI_MSG_WARN,
					  "setstripe warning for '%s': %s",
					  name, errmsg);
			rc = remove(name);
			if (rc) {
				llapi_err_noerrno(LLAPI_MSG_ERROR,
						  "setstripe error for '%s': %s",
						  name, strerror(errno));
				goto out;
			}
			use_default_striping = true;
			goto retry_open;
		} else {
			llapi_err_noerrno(LLAPI_MSG_ERROR,
					  "setstripe error for '%s': %s", name,
					  errmsg);
		}
		fd = rc;
	}

out:
	free(lum);

	return fd;
}

int llapi_file_is_encrypted(int fd)
{
	unsigned long flags;
	int rc;

	rc = ioctl(fd, FS_IOC_GETFLAGS, &flags);
	if (rc == -1)
		return -errno;

	return !!(flags & LUSTRE_ENCRYPT_FL);
}

int llapi_file_open_pool(const char *name, int flags, int mode,
			 unsigned long long stripe_size, int stripe_offset,
			 int stripe_count, enum lov_pattern stripe_pattern,
			 char *pool_name)
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
		    int stripe_count, enum lov_pattern stripe_pattern)
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
	bool use_default_striping = false;
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

retry_open:
	if (!use_default_striping)
		fd = open(name, O_WRONLY|O_CREAT|O_LOV_DELAY_CREATE, mode);
	else
		fd = open(name, O_WRONLY|O_CREAT, mode);
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

	if (!use_default_striping && ioctl(fd, LL_IOC_LOV_SETSTRIPE, lfm) != 0) {
		char *errmsg;

		rc = -errno;
		if (errno == ENOTTY)
			errmsg = "not on a Lustre filesystem";
		else if (errno == EEXIST || errno == EALREADY)
			errmsg = "stripe already set";
		else if (errno == EACCES)
			errmsg = "Setstripe is restricted by your administrator, default striping applied";
		else
			errmsg = strerror(errno);

		close(fd);
		/* the only reason we get ENOPERM on the ioctl is if setstripe
		 * has been explicitly restricted, normal permission errors
		 * happen earlier on open() and we never call ioctl()
		 */
		if (rc == -EACCES) {
			llapi_err_noerrno(LLAPI_MSG_WARN,
					  "setstripe warning for '%s': %s",
					  name, errmsg);
			rc = remove(name);
			if (rc) {
				llapi_err_noerrno(LLAPI_MSG_ERROR,
						  "setstripe error for '%s': %s",
						  name, strerror(errno));
				goto out_free;
			}
			use_default_striping = true;
			goto retry_open;
		} else {
			llapi_err_noerrno(LLAPI_MSG_ERROR,
					  "setstripe error for '%s': %s", name,
					  errmsg);
		}

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
		      int stripe_offset, int stripe_count,
		      enum lov_pattern stripe_pattern)
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
			   enum lov_pattern stripe_pattern, char *pool_name)
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
	rc = dir_stripe_limit_check(param->lsp_stripe_offset,
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
	if (param->lsp_is_specific) {
		int i;

		for (i = 0; i < param->lsp_stripe_count; i++)
			lmu->lum_objects[i].lum_mds = param->lsp_tgts[i];
	}
	if (param->lsp_pool)
		snprintf(lmu->lum_pool_name, sizeof(lmu->lum_pool_name), "%s",
			 param->lsp_pool);
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
 * llapi_dir_create() - Create a Lustre directory.
 * @name: the name of the directory to be created
 * @mode: permission of the file if it is created, see mode in open(2)
 * @param: stripe pattern of the newly created directory
 *
 * Return:
 * * %0 on success
 * * %negative errno on failure
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
 * llapi_dir_create_foreign() - Create a foreign directory.
 * @name: the name of the directory to be created
 * @mode: permission of the file if it is created, see mode in open(2)
 * @type: foreign type to be set in LMV EA
 * @flags: foreign flags to be set in LMV EA
 * @value: foreign pattern to be set in LMV EA
 *
 * Return:
 * * %0 on success
 * * %negative errno on failure
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
			  int stripe_count, enum lov_pattern stripe_pattern,
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

/**
 * llapi_get_poolmembers() - Get the list of pool members.
 * @poolname: string of format \<fsname\>.\<poolname\>
 * @members: caller-allocated array of char*
 * @list_size: size of the members array
 * @buffer: caller-allocated buffer for storing OST names
 * @buffer_size: size of the buffer
 *
 * Return number of members retrieved for this pool or %-error on failure
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
 * llapi_get_poollist() - Get the list of pools in a filesystem.
 * @name: filesystem name or path
 * @poollist: caller-allocated array of char*
 * @list_size: size of the poollist array
 * @buffer: caller-allocated buffer for storing pool names
 * @buffer_size: size of the buffer
 *
 * Return number of pools retrieved for this filesystem or %-error on failure
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
	int poolcount, rc, i;
	char *buf, **pools;

	rc = llapi_get_poolbuf(name, &buf, &pools, &poolcount);
	if (rc)
		return rc;

	for (i = 0; i < poolcount; i++)
		llapi_printf(LLAPI_MSG_NORMAL, "%s\n", pools[i]);
	free(buf);

	return 0;
}

/**
 * llapi_get_poolbuf() - Get buffer that holds uuids plus list of pools in a FS.
 * @name: filesystem name or path
 * @buf: bufffer that has to be freed if function returns 0
 * @pools: pointer to the list of pools in buffer
 * @poolcount: number of pools
 *
 * Return:
 * * %0 when found at least 1 pool, i.e. poolcount  > 0
 * * %-error failure
 */
int llapi_get_poolbuf(const char *name, char **buf,
		      char ***pools, int *poolcount)
{
	/*
	 * list of pool names (assume that pool count is smaller
	 * than OST count)
	 */
	char **list, *buffer = NULL, *fsname = (char *)name;
	char *poolname = NULL, *tmp = NULL, data[16];
	enum param_filter type = FILTER_BY_PATH;
	int obdcount, bufsize, rc, nb;

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

	rc = (nb < 0 ? nb : 0);
	if (!rc) {
		*buf = buffer;
		*pools = list;
		*poolcount = nb;
	}
err:
	/* Don't free buffer, it will be used later */
	if (rc && buffer)
		free(buffer);
	if (fsname != NULL && type == FILTER_BY_FS_NAME)
		free(fsname);
	return rc;
}

/* set errno upon failure */
int open_parent(const char *path)
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

int llapi_file_fget_lov_uuid(int fd, struct obd_uuid *lov_name)
{
	int rc;

	rc = llapi_ioctl(fd, OBD_IOC_GETDTNAME, lov_name);
	if (rc) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot get lov name");
	}

	return rc;
}

int llapi_file_fget_lmv_uuid(int fd, struct obd_uuid *lov_name)
{
	int rc;

	rc = llapi_ioctl(fd, OBD_IOC_GETMDNAME, lov_name);
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

int llapi_file_fget_type_uuid(int fd, enum tgt_type type, struct obd_uuid *uuid)
{
	unsigned int cmd = 0;
	int rc;

	if (type == LOV_TYPE)
		cmd = OBD_IOC_GETDTNAME;
	else if (type == LMV_TYPE)
		cmd = OBD_IOC_GETMDNAME;
	else if (type == CLI_TYPE)
		cmd = OBD_IOC_GETUUID;

	rc = llapi_ioctl(fd, cmd, uuid);
	if (rc) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot get uuid");
	}

	return rc;
}

int llapi_file_get_type_uuid(const char *path, enum tgt_type type,
			struct obd_uuid *uuid)
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

	rc = llapi_file_fget_type_uuid(fd, type, uuid);

	close(fd);
	return rc;
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

enum lov_dump_flags {
	LDF_IS_DIR	= 0x0001,
	LDF_IS_RAW	= 0x0002,
	LDF_INDENT	= 0x0004,
	LDF_SKIP_OBJS	= 0x0008,
	LDF_YAML	= 0x0010,
	LDF_EXTENSION	= 0x0020,
	LDF_HEX_IDX	= 0x0040,
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
	char *fmt_idx = flags & LDF_HEX_IDX ? "%#x" : "%d";
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

	if (verbose & (VERBOSE_DETAIL | VERBOSE_DFID)) {
		__u64 seq;
		__u32 oid;
		__u32 ver;

		if (verbose & ~VERBOSE_DFID)
			llapi_printf(LLAPI_MSG_NORMAL, "%slmm_fid:           ",
				     space);

		if (is_dir) {
			struct lu_fid dir_fid;

			rc = llapi_path2fid(path, &dir_fid);
			if (rc)
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "Cannot determine directory fid.");

			seq = dir_fid.f_seq;
			oid = dir_fid.f_oid;
			ver = dir_fid.f_ver;
		} else {
			/*
			 * This needs a bit of hand-holding since old 1.x
			 * lmm_oi have { oi.oi_id = mds_inum, oi.oi_seq = 0 }
			 * and 2.x lmm_oi have { oi.oi_id = mds_oid,
			 * oi.oi_seq = mds_seq } instead of a real FID.
			 * Ideally the 2.x code would have stored this like a
			 * FID with { oi_id = mds_seq, oi_seq = mds_oid } so
			 * the ostid union lu_fid { f_seq = mds_seq,
			 * f_oid = mds_oid } worked properly (especially since
			 * IGIF FIDs use mds_inum as the FID SEQ), but
			 * unfortunately that didn't happen.
			 *
			 * Print it to look like an IGIF FID, even though the
			 * fields are reversed on disk, so that it makes sense
			 * to userspace.
			 *
			 * Don't use ostid_id() and ostid_seq(), since they
			 * assume the oi_fid fields are in the right order.
			 * This is why there are separate lmm_oi_seq() and
			 * lmm_oi_id() routines for this.
			 *
			 * For newer layout types hopefully this will be a
			 * real FID.
			 */
			seq = lmm_oi_seq(&lum->lmm_oi) == 0 ?
				lmm_oi_id(&lum->lmm_oi) :
				lmm_oi_seq(&lum->lmm_oi);
			oid = lmm_oi_seq(&lum->lmm_oi) == 0 ?
			    0 : (__u32)lmm_oi_id(&lum->lmm_oi);
			ver = (__u32)(lmm_oi_id(&lum->lmm_oi) >> 32);
		}

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
			    !(lov_pattern(lum->lmm_pattern) & LOV_PATTERN_MDT)){
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
			llapi_printf(LLAPI_MSG_NORMAL, "%i",
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
		char buf[128];

		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_PATTERN)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%spattern:       ",
				     space, prefix);
		if (lov_pattern_available(lum->lmm_pattern))
			llapi_printf(LLAPI_MSG_NORMAL, "%s",
				     llapi_lov_pattern_string(lum->lmm_pattern,
							buf, sizeof(buf)) ?:
							"overflow");
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
		bool is_dom = (lov_pattern(lum->lmm_pattern) & LOV_PATTERN_MDT);

		if (verbose & ~VERBOSE_STRIPE_OFFSET) {
			llapi_printf(LLAPI_MSG_NORMAL,
				     is_dom ?  "%s%smdt_index:     "
				     : "%s%sstripe_offset: ", space, prefix);
		}
		if (is_dir || skip_objs || is_dom)
			if (lum->lmm_stripe_offset ==
			    (typeof(lum->lmm_stripe_offset))(-1))
				llapi_printf(LLAPI_MSG_NORMAL, "-1");
			else
				llapi_printf(LLAPI_MSG_NORMAL, fmt_idx,
					     lum->lmm_stripe_offset);

		else
			llapi_printf(LLAPI_MSG_NORMAL, fmt_idx,
				     objects[0].l_ost_idx);
		if (!yaml && is_dir)
			separator = " ";
		else
			separator = "\n";
	}

	if ((verbose & VERBOSE_POOL) && pool_name && (pool_name[0] != '\0') &&
	    (!lov_pool_is_ignored(pool_name) || is_raw)) {
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

static void lov_dump_user_lmm_v1v3(struct lov_user_md *lum, char *pool_name,
				   struct lov_user_ost_data_v1 *objects,
				   char *path, int obdindex, int depth,
				   enum llapi_layout_verbose verbose,
				   enum lov_dump_flags flags)
{
	bool is_dir = flags & LDF_IS_DIR;
	bool indent = flags & LDF_INDENT;
	bool skip_objs = flags & LDF_SKIP_OBJS;
	bool yaml = flags & LDF_YAML;
	bool hex = flags & LDF_HEX_IDX;
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

	if (!skip_objs && (verbose & VERBOSE_OBJID) &&
	    ((!is_dir && !(lum->lmm_pattern & LOV_PATTERN_F_RELEASED ||
			   lov_pattern(lum->lmm_pattern) & LOV_PATTERN_MDT)) ||
	     (is_dir && (lum->lmm_magic == LOV_USER_MAGIC_SPECIFIC)))) {
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
					     hex ? "%sl_ost_idx: %#x\n"
						 : "%sl_ost_idx: %d\n",
					     space, idx);
				llapi_printf(LLAPI_MSG_NORMAL,
				    "%8sl_fid:     "DFID_NOBRACE"\n",
				    " ", PFID(&fid));
			} else if (indent) {
				struct lu_fid fid = { 0 };

				ostid_to_fid(&fid, &objects[i].l_ost_oi, idx);
				llapi_printf(LLAPI_MSG_NORMAL, hex ?
				    "%s%3d: { l_ost_idx: %#5x, l_fid: "DFID" }\n" :
				    "%s%3d: { l_ost_idx: %3d, l_fid: "DFID" }\n",
				    space, i, idx, PFID(&fid));
			} else if (is_dir) {
				llapi_printf(LLAPI_MSG_NORMAL,
					     "\t%6u\t%14s\t%13s\t%14s\n", idx, "N/A",
					     "N/A", "N/A");
			} else {
				char fmt[48] = { 0 };

				sprintf(fmt, "%s%s%s\n",
					hex ? "\t%#6x\t%14llu\t%#13llx\t"
					    : "\t%6u\t%14llu\t%#13llx\t",
					(fid_seq_is_rsvd(gr) ||
					 fid_seq_is_mdt0(gr)) ?
					 "%14llu" : "%#14llx", "%s");
				llapi_printf(LLAPI_MSG_NORMAL, fmt, idx, oid,
					     oid, gr,
					     obdindex == idx ? " *" : "");
			}
		}
	}
	if (!yaml)
		llapi_printf(LLAPI_MSG_NORMAL, "\n");
}

static void hsm_flags2str(__u32 hsm_flags)
{
	bool found = false;
	int i = 0;

	if (!hsm_flags) {
		llapi_printf(LLAPI_MSG_NORMAL, "0");
		return;
	}
	for (i = 0; i < ARRAY_SIZE(hsm_flags_table); i++) {
		if (hsm_flags & hsm_flags_table[i].hfn_flag) {
			if (found)
				llapi_printf(LLAPI_MSG_NORMAL, ",");
			llapi_printf(LLAPI_MSG_NORMAL, "%s",
				     hsm_flags_table[i].hfn_name);
			found = true;
		}
	}
	if (hsm_flags) {
		if (found)
			llapi_printf(LLAPI_MSG_NORMAL, ",");
		llapi_printf(LLAPI_MSG_NORMAL, "%#x", hsm_flags);
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

void lov_dump_hsm_lmm(void *lum, char *path, int depth,
		      enum llapi_layout_verbose verbose,
		      enum lov_dump_flags flags)
{
	struct lov_hsm_md *lhm = lum;
	bool indent = flags & LDF_INDENT;
	bool is_dir = flags & LDF_IS_DIR;
	char *space = indent ? "      " : "";

	if (!is_dir) {
		uint32_t type = check_foreign_type(lhm->lhm_type);

		llapi_printf(LLAPI_MSG_NORMAL, "%slhm_magic:         0x%08X\n",
			     space, lhm->lhm_magic);
		llapi_printf(LLAPI_MSG_NORMAL, "%slhm_pattern:       foreign\n",
			     space);
		llapi_printf(LLAPI_MSG_NORMAL, "%slhm_length:        %u\n",
			     space, lhm->lhm_length);
		llapi_printf(LLAPI_MSG_NORMAL, "%slhm_type:          0x%08X",
			     space, lhm->lhm_type);
		if (type < LU_FOREIGN_TYPE_UNKNOWN)
			llapi_printf(LLAPI_MSG_NORMAL, " (%s)\n",
				     lu_foreign_types[type].lft_name);
		else
			llapi_printf(LLAPI_MSG_NORMAL, " (unknown)\n");

		llapi_printf(LLAPI_MSG_NORMAL, "%slhm_flags:         ", space);
		hsm_flags2str(lhm->lhm_flags);
		llapi_printf(LLAPI_MSG_NORMAL, "\n");

		if (!lov_hsm_type_supported(lhm->lhm_type))
			return;

		llapi_printf(LLAPI_MSG_NORMAL, "%slhm_archive_id:    %llu\n",
			     space, (unsigned long long)lhm->lhm_archive_id);
		llapi_printf(LLAPI_MSG_NORMAL, "%slhm_archive_ver:   %llu\n",
			     space, (unsigned long long)lhm->lhm_archive_ver);
		llapi_printf(LLAPI_MSG_NORMAL, "%slhm_archive_uuid:  '%.*s'\n",
			     space, UUID_MAX, lhm->lhm_archive_uuid);
	}
}

static void lmv_dump_user_lmm(struct lmv_user_md *lum, char *pool_name,
			      char *path, int obdindex, int depth,
			      enum llapi_layout_verbose verbose,
			      enum lov_dump_flags flags)
{
	struct lmv_user_mds_data *objects = lum->lum_objects;
	char *prefix = lum->lum_magic == LMV_USER_MAGIC ? "(Default)" : "";
	char *separator = "";
	bool yaml = flags & LDF_YAML;
	bool hex = flags & LDF_HEX_IDX;
	bool obdstripe = false;
	struct lu_fid dir_fid;
	int rc;
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

	if (verbose & (VERBOSE_DETAIL | VERBOSE_DFID) ||
	    (verbose & VERBOSE_OBJID && lum->lum_stripe_count >= 0)) {
		rc = llapi_path2fid(path, &dir_fid);
		if (rc)
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "Cannot determine directory FID: %s", path);
	}

	if (depth && path && (verbose != VERBOSE_OBJID))
		llapi_printf(LLAPI_MSG_NORMAL, "%s%s\n", prefix, path);

	if (verbose & (VERBOSE_DETAIL | VERBOSE_DFID)) {
		if (verbose & ~VERBOSE_DFID)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "lmv_fid: %s", yaml ? "          " : "");
		llapi_printf(LLAPI_MSG_NORMAL, DFID_NOBRACE, PFID(&dir_fid));

		separator = yaml ? "\n" : " ";
	}

	if (verbose & VERBOSE_DETAIL) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		llapi_printf(LLAPI_MSG_NORMAL, "lmv_magic: %s%#x",
			     yaml ? "        " : "", (int)lum->lum_magic);
		separator = yaml ? "\n" : " ";
	}

	if (verbose & VERBOSE_STRIPE_COUNT) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_STRIPE_COUNT)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_stripe_count: %s",
				     yaml ? " " : "");
		llapi_printf(LLAPI_MSG_NORMAL, "%d",
			     (int)lum->lum_stripe_count);
		separator = yaml ? "\n" : " ";
	}

	if (verbose & VERBOSE_STRIPE_OFFSET) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_STRIPE_OFFSET)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_stripe_offset: ");
		llapi_printf(LLAPI_MSG_NORMAL, hex ? "%#x" : "%d",
			     (int)lum->lum_stripe_offset);
		separator = yaml ? "\n" : " ";
	}

	if (verbose & VERBOSE_HASH_TYPE) {
		unsigned int type = lum->lum_hash_type & LMV_HASH_TYPE_MASK;
		unsigned int flags = lum->lum_hash_type & ~LMV_HASH_TYPE_MASK;

		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_HASH_TYPE)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_hash_type: %s",
				     yaml ? "    " : "");
		if (type < LMV_HASH_TYPE_MAX)
			llapi_printf(LLAPI_MSG_NORMAL, "%s",
				     mdt_hash_name[type]);
		else
			llapi_printf(LLAPI_MSG_NORMAL, "%#x", type);

		if (flags & LMV_HASH_FLAG_OVERSTRIPED)
			llapi_printf(LLAPI_MSG_NORMAL, ",overstriped");
		if (flags & LMV_HASH_FLAG_MIGRATION)
			llapi_printf(LLAPI_MSG_NORMAL, ",migrating");
		if (flags & LMV_HASH_FLAG_BAD_TYPE)
			llapi_printf(LLAPI_MSG_NORMAL, ",bad_type");
		if (flags & LMV_HASH_FLAG_LOST_LMV)
			llapi_printf(LLAPI_MSG_NORMAL, ",lost_lmv");
		if (flags & LMV_HASH_FLAG_FIXED)
			llapi_printf(LLAPI_MSG_NORMAL, ",fixed");
		if (flags & ~LMV_HASH_FLAG_KNOWN)
			llapi_printf(LLAPI_MSG_NORMAL, ",unknown_%04x",
				     flags & ~LMV_HASH_FLAG_KNOWN);
		separator = yaml ? "\n" : " ";
	}

	if ((verbose & VERBOSE_INHERIT) && lum->lum_magic == LMV_USER_MAGIC) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_INHERIT)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_max_inherit: %s",
				     yaml ? "  " : "");
		if (lum->lum_max_inherit == LMV_INHERIT_UNLIMITED)
			llapi_printf(LLAPI_MSG_NORMAL, "-1");
		else if (lum->lum_max_inherit == LMV_INHERIT_NONE)
			llapi_printf(LLAPI_MSG_NORMAL, "0");
		else
			llapi_printf(LLAPI_MSG_NORMAL, "%hhu",
				     lum->lum_max_inherit);
		separator = yaml ? "\n" : " ";
	}

	if ((verbose & VERBOSE_INHERIT_RR) &&
	    lum->lum_magic == LMV_USER_MAGIC) {
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
		separator = yaml ? "\n" : " ";
	}

	if ((verbose & VERBOSE_POOL) && pool_name != NULL &&
	    pool_name[0] != '\0') {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_POOL)
			llapi_printf(LLAPI_MSG_NORMAL, "%slmv_pool: %s",
				     prefix, yaml ? "          " : "");
		llapi_printf(LLAPI_MSG_NORMAL, "%s%c ", pool_name, ' ');
	}

	separator = "\n";

	if ((verbose & VERBOSE_OBJID) && lum->lum_magic != LMV_USER_MAGIC) {
		char fmt[64];

		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (yaml)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "lmv_objects:\n");
		else if (lum->lum_stripe_count > 0)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "mdtidx\t\t FID[seq:oid:ver]\n");

		if (yaml)
			snprintf(fmt, sizeof(fmt),
				 "      - l_mdt_idx: %s\n%s\n",
				 hex ? "%#x" : "%d",
				 "        l_fid:     "DFID_NOBRACE);
		else
			snprintf(fmt, sizeof(fmt), "%s%s", hex ? "%#6x" : "%6u",
				"\t\t "DFID"\t\t%s\n");
		if (lum->lum_stripe_count == 0 && yaml) {
			llapi_printf(LLAPI_MSG_NORMAL, fmt,
				     lum->lum_stripe_offset,
				     PFID(&dir_fid), "");
		}
		for (i = 0; i < lum->lum_stripe_count; i++) {
			int idx = objects[i].lum_mds;
			struct lu_fid *fid = &objects[i].lum_fid;

			if ((obdindex == OBD_NOT_FOUND) || (obdindex == idx))
				llapi_printf(LLAPI_MSG_NORMAL, fmt, idx,
					     PFID(fid),
					     obdindex == idx ? " *":"");
		}
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
			llapi_printf(LLAPI_MSG_NORMAL, "%slcm_layout_gen:    ",
				     yaml ? "" : "  ");
		llapi_printf(LLAPI_MSG_NORMAL, "%u\n", comp_v1->lcm_layout_gen);
	}

	if (verbose & VERBOSE_MIRROR_COUNT) {
		if (verbose & ~VERBOSE_MIRROR_COUNT)
			llapi_printf(LLAPI_MSG_NORMAL, "%slcm_mirror_count:  ",
				     yaml ? "" : "  ");
		llapi_printf(LLAPI_MSG_NORMAL, "%u\n",
			     comp_v1->lcm_magic == LOV_USER_MAGIC_COMP_V1 ?
			     comp_v1->lcm_mirror_count + 1 : 1);
	}

	if (verbose & VERBOSE_COMP_COUNT) {
		if (verbose & ~VERBOSE_COMP_COUNT)
			llapi_printf(LLAPI_MSG_NORMAL, "%slcm_entry_count:   ",
				     yaml ? "" : "  ");
		llapi_printf(LLAPI_MSG_NORMAL, "%u\n",
			     comp_v1->lcm_magic == LOV_USER_MAGIC_COMP_V1 ?
			     comp_v1->lcm_entry_count : 0);
	}

	if (verbose & VERBOSE_DETAIL || yaml)
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
		const char *cfn_name = comp_flags_table[i].cfn_name;
		__u32 cfn_flag = comp_flags_table[i].cfn_flag;

		if ((comp_flags & cfn_flag) == cfn_flag) {
			if (found)
				llapi_printf(LLAPI_MSG_NORMAL, ",");
			llapi_printf(LLAPI_MSG_NORMAL, "%s", cfn_name);
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

	if (verbose & VERBOSE_COMP_ID || yaml) {
		if (verbose & VERBOSE_DETAIL || yaml)
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
	/* print mirror_link_id and snapshot timestamp */
	if (verbose & VERBOSE_COMP_FLAGS) {
		if (entry->lcme_mirror_link_id != 0) {
			llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
			if (verbose & ~VERBOSE_COMP_FLAGS)
				llapi_printf(LLAPI_MSG_NORMAL,
					     "%4slcme_mirror_link_id: ", " ");
			llapi_printf(LLAPI_MSG_NORMAL, "%#x",
				     entry->lcme_mirror_link_id);
			separator = "\n";
		}
		if ((entry->lcme_flags & LCME_FL_NOSYNC) ||
		    lcme_timestamp_time_unpack(entry->lcme_time_and_id)) {
			llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
			if (verbose & ~VERBOSE_COMP_FLAGS)
				llapi_printf(LLAPI_MSG_NORMAL,
					     "%4slcme_timestamp:      ", " ");
			if (yaml) {
				llapi_printf(LLAPI_MSG_NORMAL, "%llu",
					     (unsigned long long)
					     lcme_timestamp_time_unpack(entry->lcme_time_and_id));
			} else {
				time_t stamp = lcme_timestamp_time_unpack(entry->lcme_time_and_id);
				struct tm tm_buf;
				char date_str[64];

				/* Use localtime_r() and strftime() for thread safety
				 * with parallel find.
				 */
				if (localtime_r(&stamp, &tm_buf)) {
					strftime(date_str, sizeof(date_str), "%c",
						 &tm_buf);
					llapi_printf(LLAPI_MSG_NORMAL, "'%s'",
						     date_str);
				}
			}
			separator = "\n";
		}
	}

	/* Display EC-specific information for parity components */
	if (verbose & VERBOSE_EC_COUNT &&
	    (entry->lcme_flags & LCME_FL_PARITY)) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_EC_COUNT)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%4slcme_dstripe_count:  ", " ");
		llapi_printf(LLAPI_MSG_NORMAL, "%u%s",
				entry->lcme_dstripe_count, separator);
		if (verbose & ~VERBOSE_EC_COUNT)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%4slcme_cstripe_count:  ", " ");
		llapi_printf(LLAPI_MSG_NORMAL, "%u", entry->lcme_cstripe_count);
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

/*
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
			if (v1->lmm_magic == LOV_MAGIC_FOREIGN)
				continue;

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
				if (v1->lmm_magic == LOV_MAGIC_FOREIGN)
					continue;

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
		if (v1->lmm_magic == LOV_MAGIC_FOREIGN) {
			lov_dump_hsm_lmm(v1, path, param->fp_max_depth,
					 param->fp_verbose, flags);
		} else {
			objects = lov_v1v3_objects(v1);
			lov_v1v3_pool_name(v1, pool_name);

			ext = entry->lcme_flags & LCME_FL_EXTENSION ?
			      LDF_EXTENSION : 0;
			lov_dump_user_lmm_v1v3(v1, pool_name, objects, path,
					       obdindex, param->fp_max_depth,
					       param->fp_verbose, flags | ext);
		}
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
		if (v1->lmm_magic == LOV_MAGIC_FOREIGN) {
			lov_dump_hsm_lmm(v1, path, param->fp_max_depth,
					 param->fp_verbose, flags);
		} else {
			objects = lov_v1v3_objects(v1);
			lov_v1v3_pool_name(v1, pool_name);

			entry = &comp_v1->lcm_entries[i];
			ext = entry->lcme_flags & LCME_FL_EXTENSION ?
			      LDF_EXTENSION : 0;
			lov_dump_user_lmm_v1v3(v1, pool_name, objects, path,
					       obdindex, param->fp_max_depth,
					       param->fp_verbose, flags | ext);
		}
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

static struct lov_user_mds_data *
lov_forge_comp_v1(struct lov_user_mds_data *orig, bool is_dir)
{
	struct lov_user_md *lum = &orig->lmd_lmm;
	struct lov_user_mds_data *new;
	struct lov_comp_md_v1 *comp_v1;
	struct lov_comp_md_entry_v1 *ent;
	int lumd_hdr = offsetof(typeof(*new), lmd_lmm);
	int lum_off = sizeof(*comp_v1) + sizeof(*ent);
	int lum_size = lov_user_md_size(is_dir ? 0 : lum->lmm_stripe_count,
					lum->lmm_magic);

	new = malloc(sizeof(*new) + sizeof(*ent) + lum_size);
	if (new == NULL) {
		llapi_printf(LLAPI_MSG_NORMAL, "out of memory\n");
		return new;
	}
	/* struct lov_user_mds_data header */
	memcpy(new, orig, lumd_hdr);
	/* fill comp_v1 */
	comp_v1 = (struct lov_comp_md_v1 *)&new->lmd_lmm;
	comp_v1->lcm_magic = lum->lmm_magic;
	comp_v1->lcm_size = lum_off + lum_size;
	comp_v1->lcm_layout_gen = is_dir ? 0 : lum->lmm_layout_gen;
	comp_v1->lcm_flags = 0;
	comp_v1->lcm_entry_count = 1;
	/* fill entry */
	ent = &comp_v1->lcm_entries[0];
	ent->lcme_id = 0;
	ent->lcme_flags = is_dir ? 0 : LCME_FL_INIT;
	ent->lcme_extent.e_start = 0;
	ent->lcme_extent.e_end = LUSTRE_EOF;
	ent->lcme_offset = lum_off;
	ent->lcme_size = lum_size;
	/* fill blob at end of entry */
	memcpy((char *)&comp_v1->lcm_entries[1], lum, lum_size);

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
	if (param->fp_hex_idx)
		flags |= LDF_HEX_IDX;

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
	/* reach bottom? */
	if (param->fp_depth == param->fp_max_depth)
		data.ioc_type = MDS_MIGRATE_NSONLY;
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
	/* Do not get down anymore? */
	if (param->fp_depth == param->fp_max_depth)
		ret = 1;
	else
		param->fp_depth++;

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
	if (ret == -1) {
		if (errno == EALREADY) {
			ret = 0;
		} else {
			llapi_error(LLAPI_MSG_ERROR, errno,
				    "%s: error completing migration of %s",
				    __func__, path);
			ret = -errno;
		}
	}

out:
	cb_common_fini(path, p, dp, data, de);
	return ret;
}

int llapi_migrate_mdt(char *path, struct find_param *param)
{
	param->fp_stop_on_error = 1;
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

/*
 * Check string for escape sequences and print a message to stdout
 * if any invalid escapes are found.
 *
 * @param[in]	c	Pointer to character immediately following the
 *			'\' character indicating the start of an escape
 *			sequence.
 * @return		Number of characters examined in the escape sequence
 *			(regardless of whether the sequence is valid or not).
 */
static int validate_printf_esc(char *c)
{
	char *valid_esc = "nt\\";

	if (*c == '\0') {
		 /* backslash at end of string */
		llapi_err_noerrno(LLAPI_MSG_WARN,
			"warning: '\\' at end of -printf format string\n");
		return 0;
	}

	if (!strchr(valid_esc, *c))
		/* Invalid escape character */
		llapi_err_noerrno(LLAPI_MSG_WARN,
			"warning: unrecognized escape: '\\%c'\n", *c);

	return 1;
}

/*
 * Check string for format directives and print a message to stdout
 * if any invalid directives are found.
 *
 * @param[in]	c	Pointer to character immediately following the
 *			'%' character indicating the start of a format
 *			directive.
 * @return		Number of characters examined in the format directive
 *			(regardless of whether the directive is valid or not).
 */
static int validate_printf_fmt(char *c)
{
	char *valid_fmt_single = "abcigGkmMnpstuUwy%";
	char *valid_fmt_double = "ACTW";
	char *valid_fmt_lustre = "aAcFhioPpS";
	char curr = *c, next;

	if (curr == '\0') {
		llapi_err_noerrno(LLAPI_MSG_WARN,
			"warning: '%%' at end of -printf format string\n");
		return 0;
	}

	/* GNU find supports formats such as "%----10s" */
	while (curr == '-')
		curr = *(++c);

	if (isdigit(curr)) {
		/* skip width format specifier */
		while (isdigit(*c))
			c++;
	}

	curr = *c;
	next = *(c + 1);

	if ((next == '\0') || (next == '%') || (next == '\\'))
		/* Treat as single char format directive */
		goto check_single;

	/* Check format directives with multiple characters */
	if (strchr(valid_fmt_double, curr)) {
		/* For now, only valid formats are followed by '@' char */
		if (next != '@')
			llapi_err_noerrno(LLAPI_MSG_WARN,
				"warning: unrecognized format directive: '%%%c%c'\n",
				curr, next);
		return 2;
	}

	/* Lustre formats always start with 'L' */
	if (curr == 'L') {
		if (!strchr(valid_fmt_lustre, next))
			llapi_err_noerrno(LLAPI_MSG_WARN,
				"warning: unrecognized format directive: '%%%c%c'\n",
				curr, next);
		return 2;
	}

check_single:

	if (!strchr(valid_fmt_single, curr))
		llapi_err_noerrno(LLAPI_MSG_WARN,
			"warning: unrecognized format directive: '%%%c'\n", curr);
	return 1;
}

/*
 * Validate the user-supplied string for the -printf option and report
 * any invalid backslash escape sequences or format directives.
 *
 * @param[in]	param	Structure containing info about invocation of lfs find
 * @return		None
 */
void validate_printf_str(struct find_param *param)
{
	char *c = param->fp_format_printf_str;
	int ret = 0;

	while (*c) {
		switch (*c) {
		case '%':
			ret = validate_printf_fmt(++c);
			c += ret;
			break;
		case '\\':
			ret = validate_printf_esc(++c);
			c += ret;
			break;
		default:
			c++;
			break;
		}
	}
}

int llapi_find(char *path, struct find_param *param)
{
	if (param->fp_format_printf_str)
		validate_printf_str(param);
	if (param->fp_thread_count) {
		return parallel_find(path, param);
	} else {
		return param_callback(path, cb_find_init, cb_common_fini,
				      param);
	}
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
	bool hex = param->fp_hex_idx;

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
		llapi_printf(LLAPI_MSG_NORMAL, hex ? "%#x\n" : "%d\n", mdtidx);
	else
		llapi_printf(LLAPI_MSG_NORMAL, hex ? "%s\nmdt_index:\t%#x\n"
						   : "%s\nmdt_index:\t%d\n",
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
	int d = dp == NULL ? -1 : *dp, fd = -1;
	int ret = 0;
	struct stat st;

	if (p == -1 && d == -1)
		return -EINVAL;

	if (param->fp_obd_uuid) {
		param->fp_quiet = 1;
		ret = llapi_ostlist(path, param);
		if (ret)
			return ret;
	}

	if (!param->fp_no_follow && de && de->d_type == DT_LNK && d == -1)
		d = fd = open(path, O_RDONLY | O_DIRECTORY);

	if (d != -1 && (param->fp_get_lmv || param->fp_get_default_lmv))
		ret = cb_get_dirstripe(path, &d, param);
	else if (d != -1)
		ret = get_lmd_info_fd(path, p, d, &param->fp_lmd->lmd_lmm,
				      param->fp_lum_size, GET_LMD_STRIPE);
	else if (d == -1 && (param->fp_get_lmv || param->fp_get_default_lmv)) {
		/* in case of a dangling or valid faked symlink dir, opendir()
		 * should have return either EINVAL or ENOENT, so let's try
		 * to get LMV just in case, and by opening it as a file but
		 * with O_NOFOLLOW ...
		 */
		int flag = O_RDONLY | O_NONBLOCK;

		if (param->fp_no_follow)
			flag |= O_NOFOLLOW;

		fd = open(path, flag);
		if (fd == -1)
			return 0;
		if (fstat(fd, &st) != 0) {
			ret = -errno;
			close(fd);
			return ret;
		}
		/* clear O_NONBLOCK for non-PIPEs */
		if (!S_ISFIFO(st.st_mode))
			fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
		ret = cb_get_dirstripe(path, &fd, param);
		if (ret == 0)
			llapi_lov_dump_user_lmm(param, path, LDF_IS_DIR);
		close(fd);
		return 0;
	} else if (d == -1) {
		if (!param->fp_no_follow && de && de->d_type == DT_LNK) {
			/* open the target of symlink as a file */
			fd = open(path, O_RDONLY);
			if (fd == -1)
				return 0;
		}
		ret = get_lmd_info_fd(path, p, fd, &param->fp_lmd->lmd_lmm,
				      param->fp_lum_size, GET_LMD_STRIPE);
	} else
		return 0;

	if (fd >= 0)
		close(fd);

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

				if (param->fp_raw)
					goto out;
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
		cfs_free_param_data(&param);
	}
free_path:
	if (fp)
		fclose(fp);
	cfs_free_param_data(&param);
	return rc;
}

struct check_target_filter {
	char *nid;
	char *instance;
};

static void do_target_check(char *obd_type_name, char *obd_name,
			    char *obd_uuid, void *args)
{
	int rc;
	struct check_target_filter *filter = args;

	if (filter != NULL) {
		/* check NIDs if obd type is mgc */
		if (strcmp(obd_type_name, "mgc") == 0) {
			char *delimiter = filter->nid;
			char *nidstr = filter->nid;
			bool found = false;

			while (*nidstr && *delimiter) {
				delimiter = cfs_nidstr_find_delimiter(nidstr);
				if (!strncmp(obd_name + 3, nidstr,
					     delimiter - nidstr)) {
					found = true;
					break;
				}
				nidstr = delimiter + 1;
			}
			if (!found)
				return;
		}
		/* check instance for other types of device (osc/mdc) */
		else if (strstr(obd_name, filter->instance) == NULL)
			return;
	}

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
	char instance[MAX_INSTANCE_LEN];
	struct check_target_filter filter = {NULL, NULL};
	char *nid = NULL;
	int rc;

	if (dir == NULL || dir[0] == '\0')
		return llapi_target_iterate(type_num, obd_type, NULL,
					    do_target_check);

	rc = get_root_path(WANT_NID | WANT_ERROR, NULL, NULL, dir, -1, NULL,
			   &nid);
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot get nid of path '%s'", dir);
		return rc;
	}
	filter.nid = nid;

	rc = llapi_get_instance(dir, instance, ARRAY_SIZE(instance));
	if (rc)
		goto out;

	filter.instance = instance;

	rc = llapi_target_iterate(type_num, obd_type, &filter,
				    do_target_check);

out:
	free(nid);
	return rc;
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
 * llapi_file_flush() - Flush cached pages from all clients.
 * @fd: File descriptor
 *
 * Return:
 * * %0 on success
 * * %negative on error.
 */
int llapi_file_flush(int fd)
{
	__u64 dv;

	return llapi_get_data_version(fd, &dv, LL_DV_WR_FLUSH);
}

/**
 * llapi_fsync() - Flush dirty pages from all clients.
 * @fd: File descriptor
 *
 * OSTs will take LCK_PR to flush dirty pages from clients.
 *
 * Return
 * * %0 on success.
 * * %-errno on error.
 */
int llapi_fsync(int fd)
{
	__u64 dv;

	return llapi_get_data_version(fd, &dv, LL_DV_RD_FLUSH);
}
