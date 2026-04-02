// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (c) 2024 DataDirect Networks Storage, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * implement thread worker pool for parallel work queue operations.
 *
 * Author: Patrick Farrell <pfarrell@whamcloud.com>
 */

#include <fnmatch.h>
#include <grp.h>
#include <libgen.h> /* for dirname() */
#include <pthread.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include "lustreapi_internal.h"
#include "lstddef.h"

#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_ioctl.h>
#include <linux/lustre/lustre_ostid.h>

#define FORMATTED_BUF_LEN	1024

#ifndef DEFAULT_PROJID
#define DEFAULT_PROJID	0
#endif

void find_param_fini(struct find_param *param)
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

int common_param_init(struct find_param *param, char *path)
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

int cb_common_fini(char *path, int p, int *dp, void *data,
		   struct dirent64 *de)
{
	struct find_param *param = data;

	param->fp_depth--;
	return 0;
}

int cb_get_dirstripe(char *path, int *d, struct find_param *param)
{
	int ret;
	bool did_nofollow = false;

	if (!d || *d < 0)
		return -ENOTDIR;
again:
	param->fp_lmv_md->lum_stripe_count = param->fp_lmv_stripe_count;
	if (param->fp_get_default_lmv) {
#ifdef HAVE_STATX
		struct statx stx;

		/* open() may not fetch LOOKUP lock, statx() to ensure dir depth
		 * is set.
		 */
		statx(*d, "", AT_EMPTY_PATH, STATX_MODE, &stx);
#else
		struct stat st;

		fstat(*d, &st);
#endif
		param->fp_lmv_md->lum_magic = LMV_USER_MAGIC;
	} else {
		param->fp_lmv_md->lum_magic = LMV_MAGIC_V1;
	}
	if (param->fp_raw)
		param->fp_lmv_md->lum_type = LMV_TYPE_RAW;

	ret = ioctl(*d, LL_IOC_LMV_GETSTRIPE, param->fp_lmv_md);

	/* if ENOTTY likely to be a fake symlink, so try again after
	 * new open() with O_NOFOLLOW, but only once to prevent any
	 * loop like for the path of a file/dir not on Lustre !!
	 */
	if (ret < 0 && errno == ENOTTY && !did_nofollow) {
		int fd, ret2;
		struct stat st;

		did_nofollow = true;
		fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
		if (fd < 0) {
			/* restore original errno */
			errno = ENOTTY;
			return ret;
		}
		if (fstat(fd, &st) != 0) {
			errno = ENOTTY;
			close(fd);
			return ret;
		}
		if (!S_ISFIFO(st.st_mode))
			fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
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
		if (lmv_is_foreign(param->fp_lmv_md->lum_magic)) {
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

/**
 * llapi_get_lmm_from_path() - Get the mirror layout info from a file.
 * @path: a string containing the file path
 * @lmmbuf: pointer to an lov_user_md_v1 buffer
 *          that will be set with the mirror layout info
 *          from the file specified by @path.
 * Return:
 * * %0 success
 * * %-errno on error
 */
int llapi_get_lmm_from_path(const char *path, struct lov_user_md_v1 **lmmbuf)
{
	ssize_t lmmlen;
	int p = -1;
	int rc = 0;

	lmmlen = get_mds_md_size(path);
	if (lmmlen < 0)
		return -EINVAL;

	p = open_parent(path);
	if (p < 0)
		return -errno;

	*lmmbuf = calloc(1, lmmlen);
	if (*lmmbuf == NULL) {
		rc = -errno;
		goto out_close;
	}

	rc = get_lmd_info_fd(path, p, 0, *lmmbuf, lmmlen, GET_LMD_STRIPE);
	if (rc < 0) {
		free(*lmmbuf);
		*lmmbuf = NULL;
	}
out_close:
	close(p);

	return rc;
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
int find_value_cmp(unsigned long long file, unsigned long long limit, int sign,
		   int negopt, unsigned long long margin, bool mds)
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
 * check_obd_match() - Check if the stripes matches the indexes user provided
 * @param: pointer to struct find_param
 *
 * Return:
 * * %1 on matched
 * * %0 on Unmatched
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

/*
 * Check whether the obd is active or not, if it is not active, just print the
 * object affected by this failed target
 */
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
		if (lmv_is_foreign(lfm->lfm_magic)) {
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

int find_comp_end_cmp(unsigned long long end, struct find_param *param)
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

static int find_check_attr_options(struct find_param *param)
{
	bool found = true;
	__u64 attrs;

	attrs = param->fp_lmd->lmd_stx.stx_attributes_mask &
		param->fp_lmd->lmd_stx.stx_attributes;

	/* This is a AND between all (negated) specified attributes */
	if ((param->fp_attrs && (param->fp_attrs & attrs) != param->fp_attrs) ||
	    (param->fp_neg_attrs && (param->fp_neg_attrs & attrs)))
		found = false;

	if ((found && param->fp_exclude_attrs) ||
	    (!found && !param->fp_exclude_attrs))
		return -1;

	return 1;
}

/**
 * xattr_reg_match() - Match string with regular expression
 * @pattern: regular expression
 * @str: string from which @pattern to match
 * @len: length of @str
 *
 * This requires the regex to match the entire supplied string, not just a
 * substring.
 *
 * str must be null-terminated. len should be passed in anyways to avoid an
 * extra call to strlen(str) when the length is already known.
 *
 * Return %true if @str match @pattern else %false
 */
static bool xattr_reg_match(regex_t *pattern, const char *str, int len)
{
	regmatch_t pmatch;
	int ret;

	ret = regexec(pattern, str, 1, &pmatch, 0);
	if (ret == 0 && pmatch.rm_so == 0 && pmatch.rm_eo == len)
		return true;

	return false;
}

/**
 * xattr_done_matching() - return true if all supplied patterns have been
 *                         matched, allowing to skip checking any remaining
 *                         xattrs on a file.
 * @xmi: struct for xattr arguments to lfs find
 *
 * Note: This is only allowed if there are no "exclude" patterns.
 *
 * Returns %true if all supplied patters have been matched else %false
 */
static int xattr_done_matching(struct xattr_match_info *xmi)
{
	int i;

	for (i = 0; i < xmi->xattr_regex_count; i++) {
		/* if any pattern still undecided, need to keep going */
		if (!xmi->xattr_regex_matched[i])
			return false;
	}

	return true;
}

static int find_check_xattrs(char *path, struct xattr_match_info *xmi)
{
	ssize_t list_len = 0;
	ssize_t val_len = 0;
	bool fetched_val;
	char *p;
	int i;

	for (i = 0; i < xmi->xattr_regex_count; i++)
		xmi->xattr_regex_matched[i] = false;

	list_len = llistxattr(path, xmi->xattr_name_buf, XATTR_LIST_MAX);
	if (list_len < 0) {
		llapi_error(LLAPI_MSG_ERROR, errno,
			    "error: listxattr: %s", path);
		return -1;
	}

	/* loop over all xattr names on the file */
	for (p = xmi->xattr_name_buf;
	     p - xmi->xattr_name_buf < list_len;
	     p = strchr(p, '\0'), p++) {
		fetched_val = false;
		/* loop over all regex patterns specified and check them */
		for (i = 0; i < xmi->xattr_regex_count; i++) {
			if (xmi->xattr_regex_matched[i])
				continue;

			if (!xattr_reg_match(xmi->xattr_regex_name[i],
					     p, strlen(p)))
				continue;

			if (xmi->xattr_regex_value[i] == NULL)
				goto matched;

			/*
			 * even if multiple patterns match the same xattr name,
			 * don't call getxattr() more than once
			 */
			if (!fetched_val) {
				val_len = lgetxattr(path, p,
						    xmi->xattr_value_buf,
						    XATTR_SIZE_MAX);
				fetched_val = true;
				if (val_len < 0) {
					llapi_error(LLAPI_MSG_ERROR, errno,
						    "error: getxattr: %s",
						    path);
					continue;
				}

				/*
				 * the value returned by getxattr might or
				 * might not be null terminated.
				 * if it is, then decrement val_len so it
				 * matches what strlen() would return.
				 * if it is not, then add a null terminator
				 * since regexec() expects that.
				 */
				if (val_len > 0 &&
				    xmi->xattr_value_buf[val_len - 1] == '\0') {
					val_len--;
				} else {
					xmi->xattr_value_buf[val_len] = '\0';
				}
			}

			if (!xattr_reg_match(xmi->xattr_regex_value[i],
					     xmi->xattr_value_buf, val_len))
				continue;

matched:
			/*
			 * if exclude this xattr, we can exit early
			 * with NO match
			 */
			if (xmi->xattr_regex_exclude[i])
				return -1;

			xmi->xattr_regex_matched[i] = true;

			/*
			 * if all "include" patterns have matched, and there are
			 * no "exclude" patterns, we can exit early with match
			 */
			if (xattr_done_matching(xmi) == 1)
				return 1;
		}
	}

	/*
	 * finally, check that all supplied patterns either matched, or were
	 * "exclude" patterns if they did not match.
	 */
	for (i = 0; i < xmi->xattr_regex_count; i++) {
		if (!xmi->xattr_regex_matched[i] &&
		    !xmi->xattr_regex_exclude[i])
			return -1;
	}

	return 1;
}

static bool find_skip_file(struct find_param *param)
{
	if (param->fp_skip_count * 100 <
	    param->fp_skip_total++ * param->fp_skip_percent) {
		param->fp_skip_count++;
		return true;
	}
	return false;
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
 * Interpret backslash escape sequences and write output into buffer.
 * Anything written to the buffer will be null terminated.
 *
 * @param[in]	seq	String being parsed for escape sequence. The leading
 *			'\' character is not included in this string (only the
 *			characters after it)
 * @param[out]	buffer	Location where interpreted escape sequence is written
 * @param[in]	size	Size of the available buffer. (Needs to be large enough
 *			to handle escape sequence output plus null terminator.)
 * @param[out]	wrote	Number of bytes written to the buffer.
 * @return		Number of characters from input string processed
 *			as part of the escape sequence (0 for an unrecognized
 *			escape sequence)
 */
static int printf_format_escape(char *seq, char *buffer, size_t size,
				int *wrote)
{
	*wrote = 0;
	/* For now, only handle single char escape sequences: \n, \t, \\ */
	if (size < 2)
		return 0;

	switch (*seq) {
	case 'n':
		*buffer = '\n';
		break;
	case 't':
		*buffer = '\t';
		break;
	case '\\':
		*buffer = '\\';
		break;
	default:
		return 0;
	}

	*wrote = 1;
	return 1;
}

/*
 * Interpret formats for timestamps (%a, %A@, etc)
 *
 * @param[in]	seq	String being parsed for timestamp format.  The leading
 *			'%' character is not included in this string
 * @param[out]	buffer	Location where timestamp info is written
 * @param[in]	size	Size of the available buffer.
 * @param[out]	wrote	Number of bytes written to the buffer.
 * @return		Number of characters from input string processed
 *			as part of the format (0 for an unknown format)
 */
static int printf_format_timestamp(char *seq, char *buffer, size_t size,
				   int *wrote, struct find_param *param)
{
	struct statx_timestamp ts = { 0, 0 };
	struct tm tm_buf;
	struct tm *tm;
	time_t t;
	int rc = 0;
	char *fmt = "%c";  /* Print in ctime format by default */
	*wrote = 0;

	switch (*seq) {
	case 'a':
		ts = param->fp_lmd->lmd_stx.stx_atime;
		rc = 1;
		break;
	case 'A':
		if (*(seq + 1) == '@') {
			ts = param->fp_lmd->lmd_stx.stx_atime;
			fmt = "%s";
			rc = 2;
		}
		break;
	case 'c':
		ts = param->fp_lmd->lmd_stx.stx_ctime;
		rc = 1;
		break;
	case 'C':
		if (*(seq + 1) == '@') {
			ts = param->fp_lmd->lmd_stx.stx_ctime;
			fmt = "%s";
			rc = 2;
		}
		break;
	case 't':
		ts = param->fp_lmd->lmd_stx.stx_mtime;
		rc = 1;
		break;
	case 'T':
		if (*(seq + 1) == '@') {
			ts = param->fp_lmd->lmd_stx.stx_mtime;
			fmt = "%s";
			rc = 2;
		}
		break;
	case 'w':
		ts = param->fp_lmd->lmd_stx.stx_btime;
		rc = 1;
		break;
	case 'W':
		if (*(seq + 1) == '@') {
			ts = param->fp_lmd->lmd_stx.stx_btime;
			fmt = "%s";
			rc = 2;
		}
		break;
	default:
		rc = 0;
	}

	if (rc) {
		/* Found valid format, print to buffer */
		t = ts.tv_sec;
		/* Use localtime_r() for thread safety with parallel find */
		tm = localtime_r(&t, &tm_buf);
		if (tm)
			*wrote = strftime(buffer, size, fmt, tm);
	}

	return rc;
}

/*
 * Print all ost indices associated with a file layout using a commma separated
 * list.  For a file with mutliple components, the list of indices for each
 * component will be enclosed in brackets.
 *
 * @param[out]	buffer	Location where OST indices are written
 * @param[in]	size	Size of the available buffer.
 * @pararm[in]	layout	Pointer to layout structure for the file
 * @return		Number of bytes written to output buffer
 */
static int printf_format_ost_indices(char *buffer, size_t size,
				struct llapi_layout *layout)
{
	int err, bytes, wrote = 0;

	/* Make sure to start at the first component */
	err = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	if (err) {
		llapi_error(LLAPI_MSG_ERROR, err,
			    "error: layout component iteration failed\n");
		goto format_done;
	}
	while (1) {
		uint64_t idx, count, i;

		err = llapi_layout_stripe_count_get(layout, &count);
		if (err) {
			llapi_error(LLAPI_MSG_ERROR, err,
				    "error: cannot get stripe_count\n");
			goto format_done;
		}

		bytes = snprintf(buffer, (size - wrote), "%s", "[");
		wrote += bytes;
		if (wrote >= size)
			goto format_done;
		buffer += bytes;
		for (i = 0; i < count; i++) {
			err = llapi_layout_ost_index_get(layout, i, &idx);
			if (err) {
				llapi_error(LLAPI_MSG_ERROR, err,
					    "error: cannot get OST index\n");
				bytes = snprintf(buffer, (size - wrote),
						 "%c,", '?');
			} else {
				bytes = snprintf(buffer, size - wrote, "%llu,",
						 (unsigned long long)idx);
			}
			wrote += bytes;
			if (wrote >= size)
				goto format_done;
			buffer += bytes;
		}
		/* Overwrite last comma with closing bracket */
		*(buffer - 1) = ']';

		err = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
		if (err == 0)		/* next component is found */
			continue;
		if (err < 0)
			llapi_error(LLAPI_MSG_ERROR, err,
				    "error: layout component iteration failed\n");
		/* At this point, either got error or reached last component */
		break;
	}

format_done:
	if (wrote >= size)
		wrote = (size - 1);
	return wrote;
}

/*
 * Print file attributes as a comma-separated list of named attribute flags,
 * and hex value of any unknown attributes.
 *
 * @param[out]	buffer	Location where file attributes are written
 * @param[in]	size	Size of the available buffer.
 * @pararm[in]	lstx	Void pointer holding address of struct statx. Which is
 *                      containing attributes to be printed
 * @return		Number of bytes written to output buffer
 */
static int printf_format_file_attributes(char *buffer, size_t size,
					 void *lstx, bool longopt)
{
	lstatx_t *stx = (lstatx_t *)lstx;
	uint64_t attrs = stx->stx_attributes_mask & stx->stx_attributes;
	int bytes = 0, wrote = 0, first = 1;
	uint64_t known_attrs = 0;
	struct attrs_name *ap;

	/* before all, print '---' if no attributes, and exit */
	if (!attrs) {
		bytes = snprintf(buffer, size - wrote, "---");
		wrote += bytes;
		goto format_done;
	}

	/* first, browse list of known attributes */
	for (ap = (struct attrs_name *)attrs_array; ap->an_attr != 0; ap++) {
		known_attrs |= ap->an_attr;
		if (attrs & ap->an_attr) {
			if (longopt)
				bytes = snprintf(buffer, size - wrote, "%s%s",
						 first ? "" : ",", ap->an_name);
			else
				bytes = snprintf(buffer, size - wrote, "%c",
						 ap->an_shortname);
			wrote += bytes;
			first = 0;
			if (wrote >= size)
				goto format_done;
			buffer += bytes;
		}
	}

	/* second, print hex value for unknown attributes */
	attrs &= ~known_attrs;
	if (attrs) {
		bytes = snprintf(buffer, size - wrote, "%s0x%lx",
				 first ? "" : ",", attrs);
		wrote += bytes;
	}

format_done:
	if (wrote >= size)
		wrote = size - 1;
	return wrote;
}

/*
 * Parse Lustre-specific format sequences of the form %L{x}.
 *
 * @param[in]	seq	String being parsed for format sequence.  The leading
 *			'%' character is not included in this string
 * @param[out]	buffer	Location where interpreted format info is written
 * @param[in]	size	Size of the available buffer.
 * @param[out]	wrote	Number of bytes written to the buffer.
 * @param[in]	param	The find_param structure associated with the file/dir
 * @param[in]	path	Pathname of the current file/dir being handled
 * @param[in]	projid	Project ID associated with the current file/dir
 * @param[in]	d	File descriptor for the directory (or -1 for a
 *			non-directory file)
 * @return		Number of characters from input string processed
 *			as part of the format (0 for an unknown format)
 */
static int printf_format_lustre(char *seq, char *buffer, size_t size,
				int *wrote, struct find_param *param,
				char *path, __u32 projid, int d)
{
	struct lmv_user_md *lum;
	struct lmv_user_mds_data *objects;
	struct llapi_layout *layout = NULL;
	struct lu_fid fid;
	unsigned int hash_type;
	uint64_t str_cnt, str_size, idx;
	char pool_name[LOV_MAXPOOLNAME + 1] = { '\0' };
	int err, bytes, i;
	bool longopt = true;
	int rc = 2;	/* all current valid sequences are 2 chars */
	void *lstx;
	*wrote = 0;

	/* Sanity check.  Formats always look like %L{X} */
	if (*seq++ != 'L') {
		rc = 0;
		goto format_done;
	}

	/*
	 * Some formats like %LF or %LP are handled the same for both files
	 * and dirs, so handle all of those here.
	 */
	switch (*seq) {
	case 'a': /* file attributes */
		longopt = false;
		fallthrough;
	case 'A':
		lstx = &param->fp_lmd->lmd_stx;

		*wrote = printf_format_file_attributes(buffer, size, lstx,
						       longopt);
		goto format_done;
	case 'F':
		err = llapi_path2fid(path, &fid);
		if (err) {
			llapi_error(LLAPI_MSG_ERROR, err,
				    "error: cannot get fid\n");
			goto format_done;
		}
		*wrote = snprintf(buffer, size, DFID_NOBRACE, PFID(&fid));
		goto format_done;
	case 'P':
		*wrote = snprintf(buffer, size, "%u", projid);
		goto format_done;
	}

	/* Other formats for files/dirs need to be handled differently */
	if (d == -1) {		/* file */
		//layout = llapi_layout_get_by_xattr(&param->fp_lmd->lmd_lmm,
		//				   param->fp_lum_size, 0);
		layout = llapi_layout_get_by_path(path, 0);
		if (layout == NULL) {
			llapi_error(LLAPI_MSG_ERROR, errno,
				    "error: cannot get file layout\n");
			goto format_done;
		}

		/*
		 * Set the layout pointer to the last init component
		 * since that is the component used for most of these
		 * formats. (This also works for non-composite files)
		 */
		err = llapi_layout_get_last_init_comp(layout);
		if (err) {
			llapi_error(LLAPI_MSG_ERROR, err,
				    "error: cannot get last initialized compomnent\n");
			goto format_done;
		}

		switch (*seq) {
		case 'c':	/* stripe count */
			err = llapi_layout_stripe_count_get(layout, &str_cnt);
			if (err) {
				llapi_error(LLAPI_MSG_ERROR, err,
					    "error: cannot get stripe_count\n");
				goto format_done;
			}
			*wrote = snprintf(buffer, size, "%llu",
					  (unsigned long long)str_cnt);
			break;
		case 'h':	/* hash info */
			/* Not applicable to files.  Skip it. */
			break;
		case 'i':	/* starting index */
			err = llapi_layout_ost_index_get(layout, 0, &idx);
			if (err) {
				llapi_error(LLAPI_MSG_ERROR, err,
					    "error: cannot get OST index of last initialized component\n");
				goto format_done;
			}
			*wrote = snprintf(buffer, size, "%llu",
					  (unsigned long long)idx);
			break;
		case 'o':	/* list of object indices */
			*wrote = printf_format_ost_indices(buffer, size, layout);
			break;
		case 'p':	/* pool name */
			err = llapi_layout_pool_name_get(layout, pool_name,
							 sizeof(pool_name));
			if (err) {
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "error: cannot get pool name\n");
				goto format_done;
			}
			*wrote = snprintf(buffer, size, "%s", pool_name);
			break;
		case 'S':	/* stripe size */
			err = llapi_layout_stripe_size_get(layout, &str_size);
			if (err) {
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "error: cannot get stripe_size\n");
				goto format_done;
			}
			*wrote = snprintf(buffer, size, "%llu",
					  (unsigned long long)str_size);
			break;
		default:
			rc = 0;
			break;
		}
	} else {		/* directory */
		lum = (struct lmv_user_md *)param->fp_lmv_md;
		objects = lum->lum_objects;

		switch (*seq) {
		case 'c':	/* stripe count */
			*wrote = snprintf(buffer, size, "%d",
					  (int)lum->lum_stripe_count);
			break;
		case 'h':	/* hash info */
			hash_type = lum->lum_hash_type & LMV_HASH_TYPE_MASK;
			if (hash_type < LMV_HASH_TYPE_MAX)
				*wrote = snprintf(buffer, size, "%s",
						  mdt_hash_name[hash_type]);
			else
				*wrote = snprintf(buffer, size, "%#x",
						  hash_type);
			break;
		case 'i':	/* starting index */
			*wrote = snprintf(buffer, size, "%d",
					  lum->lum_stripe_offset);
			break;
		case 'o':	/* list of object indices */
			str_cnt = (int) lum->lum_stripe_count;
			*wrote = snprintf(buffer, size, "%s", "[");
			if (*wrote >= size)
				goto format_done;
			buffer += *wrote;
			for (i = 0; i < str_cnt; i++) {
				bytes = snprintf(buffer, (size - *wrote),
						 "%d,", objects[i].lum_mds);
				*wrote += bytes;
				if (*wrote >= size)
					goto format_done;
				buffer += bytes;
			}
			if (str_cnt == 0) {
				/* Use lum_offset as the only list entry */
				bytes = snprintf(buffer, (size - *wrote),
						"%d]", lum->lum_stripe_offset);
				*wrote += bytes;
			} else {
				/* Overwrite last comma with closing bracket */
				*(buffer - 1) = ']';
			}
			break;
		case 'p':	/* pool name */
			*wrote = snprintf(buffer, size, "%s",
					  lum->lum_pool_name);
			break;
		case 'S':	/* stripe size */
			/* This has no meaning for directories.  Skip it. */
			break;
		default:
			rc = 0;
			break;
		}
	}

format_done:
	if (layout != NULL)
		llapi_layout_free(layout);

	if (*wrote >= size)
		/* output of snprintf was truncated */
		*wrote = size - 1;

	return rc;
}

/*
 * Create a formated access mode string
 *
 * @param[in] param->fp_lmd->lmd_stx.stx_mode
 *
 */

static int snprintf_access_mode(char *buffer, size_t size, __u16 mode)
{
	char access_string[16];
	char *p = access_string;

	switch (mode & S_IFMT) {
	case S_IFREG:
		*p++ = '-';
		break;
	case S_IFDIR:
		*p++ = 'd';
		break;
	case S_IFLNK:
		*p++ = 'l';
		break;
	case S_IFIFO:
		*p++ = 'p';
		break;
	case S_IFSOCK:
		*p++ = 's';
		break;
	case S_IFBLK:
		*p++ = 'b';
		break;
	case S_IFCHR:
		*p++ = 'c';
		break;
	default:
		*p++ = '?';
		break;
	}

	*p++ = (mode & S_IRUSR) ? 'r' : '-';
	*p++ = (mode & S_IWUSR) ? 'w' : '-';
	*p++ = (mode & S_IXUSR) ? ((mode & S_ISUID) ? 's' : 'x') :
				  ((mode & S_ISUID) ? 'S' : '-');
	*p++ = (mode & S_IRGRP) ? 'r' : '-';
	*p++ = (mode & S_IWGRP) ? 'w' : '-';
	*p++ = (mode & S_IXGRP) ? ((mode & S_ISGID) ? 's' : 'x') :
				  ((mode & S_ISGID) ? 'S' : '-');
	*p++ = (mode & S_IROTH) ? 'r' : '-';
	*p++ = (mode & S_IWOTH) ? 'w' : '-';
	*p++ = (mode & S_IXOTH) ? ((mode & S_ISVTX) ? 't' : 'x') :
				  ((mode & S_ISVTX) ? 'T' : '-');
	*p = '\0';

	return snprintf(buffer, size, "%s", access_string);
}

static int parse_format_width(char **seq, size_t buf_size, int *width,
			      char *padding)
{
	bool negative_width = false;
	char *end = NULL;
	int parsed = 0;

	*padding = ' ';
	*width = 0;

	/* GNU find supports formats such as "%----10s" */
	while (**seq == '-') {
		(*seq)++;
		parsed++;
		negative_width = true;
	}

	/* GNU find and printf only do 0 padding on the left (width > 0)
	 * %-010m <=> %-10m.
	 */
	if (**seq == '0' && !negative_width)
		*padding = '0';

	errno = 0;
	*width = strtol(*seq, &end, 10);
	if (errno != 0)
		return -errno;
	if (*width >= buf_size)
		*width = buf_size - 1;

	/* increase the number of processed characters */
	parsed += end - *seq;
	*seq = end;
	if (negative_width)
		*width = -*width;

	/* GNU find only does 0 padding for %S, %d and %m. */
	switch (**seq) {
	case 'S':
	case 'd':
	case 'm':
		break;
	default:
		*padding = ' ';
		break;
	}

	return parsed;
}

/*
 * Interpret format specifiers beginning with '%'.
 *
 * @param[in]	seq	String being parsed for format specifier.  The leading
 *			'%' character is not included in this string
 * @param[out]	buffer	Location where formatted info is written
 * @param[in]	size	Size of the available buffer.
 * @param[out]	wrote	Number of bytes written to the buffer.
 * @param[in]	param	The find_param structure associated with the file/dir
 * @param[in]	path	Pathname of the current file/dir being handled
 * @param[in]	projid	Project ID associated with the current file/dir
 * @param[in]	d	File descriptor for the directory (or -1 for a
 *			non-directory file)
 * @return		Number of characters from input string processed
 *			as part of the format (0 for an unknown format)
 */
static int printf_format_directive(char *seq, char *buffer, size_t size,
				   int *wrote, struct find_param *param,
				   char *path, __u32 projid, int d)
{
	unsigned long long blocks = param->fp_lmd->lmd_stx.stx_blocks;
	__u16 mode = param->fp_lmd->lmd_stx.stx_mode;
	char padding;
	int width_rc;
	int rc = 1;  /* most specifiers are single character */
	int width;

	*wrote = 0;

	width_rc = parse_format_width(&seq, size, &width, &padding);
	if (width_rc < 0)
		return 0;

	switch (*seq) {
	case 'a': case 'A':
	case 'c': case 'C':
	case 't': case 'T':
	case 'w': case 'W':	/* timestamps */
		rc = printf_format_timestamp(seq, buffer, size, wrote, param);
		break;
	case 'b':	/* file size (in 512B blocks) */
		*wrote = snprintf(buffer, size, "%llu", blocks);
		break;
	case 'g': { /* groupname of owner*/
		/* __thread makes these variables thread-local to avoid
		 * races with parallel find worker threads.
		 */
		static __thread char save_gr_name[LOGIN_NAME_MAX + 1];
		static __thread gid_t save_gid = -1;

		if (save_gid != param->fp_lmd->lmd_stx.stx_gid) {
			struct group *gr;

			gr = getgrgid(param->fp_lmd->lmd_stx.stx_gid);
			if (gr) {
				save_gid = param->fp_lmd->lmd_stx.stx_gid;
				strncpy(save_gr_name, gr->gr_name,
					sizeof(save_gr_name) - 1);
			}
		}
		if (save_gr_name[0]) {
			*wrote = snprintf(buffer, size, "%s", save_gr_name);
			break;
		}
		fallthrough;
	}
	case 'G':	/* GID of owner */
		*wrote = snprintf(buffer, size, "%u",
				  param->fp_lmd->lmd_stx.stx_gid);
		break;
	case 'i':	/* inode number */
		*wrote = snprintf(buffer, size, "%llu",
				  param->fp_lmd->lmd_stx.stx_ino);
		break;
	case 'k':	/* file size (in 1K blocks) */
		*wrote = snprintf(buffer, size, "%llu", (blocks + 1) / 2);
		break;
	case 'L':	/* Lustre-specific formats */
		rc = printf_format_lustre(seq, buffer, size, wrote, param,
					  path, projid, d);
		break;
	case 'm':	/* file mode in octal */
		*wrote = snprintf(buffer, size, "%o", (mode & (~S_IFMT)));
		break;
	case 'M':	/* file access mode */
		*wrote = snprintf_access_mode(buffer, size, mode);
		break;
	case 'n':	/* number of hard links */
		*wrote = snprintf(buffer, size, "%u",
				  param->fp_lmd->lmd_stx.stx_nlink);
		break;
	case 'p':	/* Path name of file */
		*wrote = snprintf(buffer, size, "%s", path);
		break;
	case 's':	/* file size (in bytes) */
		*wrote = snprintf(buffer, size, "%llu",
				  param->fp_lmd->lmd_stx.stx_size);
		break;
	case 'u': {/* username of owner */
		/* __thread makes these variables thread-local to avoid
		 * races with parallel find worker threads.
		 */
		static __thread char save_username[LOGIN_NAME_MAX + 1];
		static __thread uid_t save_uid = -1;

		if (save_uid != param->fp_lmd->lmd_stx.stx_uid) {
			struct passwd *pw;

			pw = getpwuid(param->fp_lmd->lmd_stx.stx_uid);
			if (pw) {
				save_uid = param->fp_lmd->lmd_stx.stx_uid;
				strncpy(save_username, pw->pw_name,
					sizeof(save_username) - 1);
			}
		}
		if (save_username[0]) {
			*wrote = snprintf(buffer, size, "%s", save_username);
			break;
		}
		fallthrough;
	}
	case 'U':	/* UID of owner */
		*wrote = snprintf(buffer, size, "%u",
				   param->fp_lmd->lmd_stx.stx_uid);
		break;
	case 'y':	/* file type */
		if (S_ISREG(mode))
			*buffer = 'f';
		else if (S_ISDIR(mode))
			*buffer = 'd';
		else if (S_ISLNK(mode))
			*buffer = 'l';
		else if (S_ISBLK(mode))
			*buffer = 'b';
		else if (S_ISCHR(mode))
			*buffer = 'c';
		else if (S_ISFIFO(mode))
			*buffer = 'p';
		else if (S_ISSOCK(mode))
			*buffer = 's';
		else
			*buffer = '?';
		*wrote = 1;
		break;
	case '%':
		*buffer = '%';
		*wrote = 1;
		break;
	default:	/* invalid format specifier */
		rc = 0;
		break;
	}

	if (rc == 0)
		/* if parsing failed, return 0 to avoid skipping width_rc */
		return 0;

	if (width > 0 && width > *wrote) {
		/* left padding */
		int shift = width - *wrote;

		/* '\0' is added by caller if necessary */
		memmove(buffer + shift, buffer, *wrote);
		memset(buffer, padding, shift);
		*wrote += shift;
	} else if (width < 0 && -width > *wrote) {
		/* right padding */
		int shift = -width - *wrote;

		memset(buffer + *wrote, padding, shift);
		*wrote += shift;
	}

	if (*wrote >= size)
		/* output of snprintf was truncated */
		*wrote = size - 1;

	return width_rc + rc;
}

/*
 * Parse user-supplied string for the -printf option and interpret any
 * '%' format specifiers or '\' escape sequences.
 *
 * @param[in]	param	The find_param struct containing the -printf string
 *			as well as info about the current file/dir that mathced
 *			the lfs find search criteria
 * @param[in]	path	Path name for current file/dir
 * @param[in]	projid	Project ID associated with current file/dir
 * @param[in]	d	File descriptor for current directory (or -1 for a
 *			non-directory file)
 */
static void printf_format_string(struct find_param *param, char *path,
				 __u32 projid, int d)
{
	char output[FORMATTED_BUF_LEN];
	char *fmt_char = param->fp_format_printf_str;
	char *buff = output;
	size_t buff_size;
	int rc, written;

	buff = output;
	*buff = '\0';
	buff_size = FORMATTED_BUF_LEN;

	/* Always leave one free byte in buffer for trailing NUL */
	while (*fmt_char && (buff_size > 1)) {
		rc = 0;
		written = 0;
		if (*fmt_char == '%') {
			rc = printf_format_directive(fmt_char + 1, buff,
						  buff_size, &written, param,
						  path, projid, d);
		} else if (*fmt_char == '\\') {
			rc = printf_format_escape(fmt_char + 1, buff,
						  buff_size, &written);
		}

		if (rc > 0) {
			/* Either a '\' escape or '%' format was processed.
			 * Increment pointers accordingly.
			 */
			fmt_char += (rc + 1);
			buff += written;
			buff_size -= written;
		} else if (rc < 0) {
			return;
		} else {
			/* Regular char or invalid escape/format.
			 * Either way, copy current character.
			 */
			*buff++ = *fmt_char++;
			buff_size--;
		}
	}

	/* Terminate output buffer and print */
	*buff = '\0';
	llapi_printf(LLAPI_MSG_NORMAL, "%s", output);
}

/*
 * Gets the project id of a file, directory, or special file,
 * and stores it at the projid memory address passed in.
 * Returns 0 on success, or -errno for failure.
 *
 * @param[in]	path	The full path of the file or directory we're trying
 *			to retrieve the project id for.
 * @param[in]	fd	A reference to the file descriptor of either the file
 *			or directory we're inspecting. The file/dir may or may
 *			not have been already opened, but if not, we'll open
 *			it here (for regular files/directories).
 * @param[in]	mode	The mode type of the file. This will tell us if the file
 *			is a regular file/dir or if it's a special file type.
 * @param[out]	projid	A reference to where to store the projid of the file/dir
 */
static int get_projid(const char *path, int *fd, mode_t mode, __u32 *projid)
{
	struct fsxattr fsx = { 0 };
	struct lu_project lu_project = { 0 };
	int ret = 0;

	/* Check the mode of the file */
	if (S_ISREG(mode) || S_ISDIR(mode)) {
		/* This is a regular file type or directory */
		if (*fd < 0) {
			/* If we haven't yet opened the file,
			 * open it in read-only mode
			 */
			*fd = open(path, O_RDONLY | O_NOCTTY | O_NDELAY);
			if (*fd <= 0) {
				llapi_error(LLAPI_MSG_ERROR, -ENOENT,
					    "warning: %s: unable to open file \"%s\"to get project id",
					    __func__, path);
				return -ENOENT;
			}
		}
		ret = ioctl(*fd, FS_IOC_FSGETXATTR, &fsx);
		if (ret)
			return -errno;

		*projid = fsx.fsx_projid;
	} else {
		/* This is a special file type, like a symbolic link, block or
		 * character device file. We'll have to open its parent
		 * directory and get metadata about the file through that.
		 */
		char dir_path[PATH_MAX + 1] = { 0 };
		char base_path[PATH_MAX + 1] = { 0 };

		strncpy(dir_path, path, PATH_MAX);
		strncpy(base_path, path, PATH_MAX);
		char *dir_name = dirname(dir_path);
		char *base_name = basename(base_path);
		int dir_fd = open(dir_name, O_RDONLY | O_NOCTTY | O_NDELAY);

		if (dir_fd < 0) {
			llapi_error(LLAPI_MSG_ERROR, -ENOENT,
				    "warning: %s: unable to open dir \"%s\"to get project id",
				    __func__, path);
			return -errno;
		}
		lu_project.project_type = LU_PROJECT_GET;
		if (base_name)
			strncpy(lu_project.project_name, base_name, NAME_MAX);

		ret = ioctl(dir_fd, LL_IOC_PROJECT, &lu_project);
		close(dir_fd);
		if (ret) {
			llapi_error(LLAPI_MSG_ERROR, -ENOENT,
				    "warning: %s: failed to get xattr for '%s': %s",
				    __func__, path, strerror(errno));
			return -errno;
		}
		*projid = lu_project.project_id;
	}

	return 0;
}

/*
 * Check that the file's permissions in *st matches the one in find_param
 */
static int check_file_permissions(const struct find_param *param,
			mode_t mode)
{
	int decision = 0;

	mode &= 07777;

	switch (param->fp_perm_sign) {
	case LFS_FIND_PERM_EXACT:
		decision = (mode == param->fp_perm);
		break;
	case LFS_FIND_PERM_ALL:
		decision = ((mode & param->fp_perm) == param->fp_perm);
		break;
	case LFS_FIND_PERM_ANY:
		decision = ((mode & param->fp_perm) != 0);
		break;
	}

	if ((param->fp_exclude_perm && decision)
		|| (!param->fp_exclude_perm && !decision))
		return -1;
	else
		return 1;
}

/*
 * Wrapper to grab parameter settings for {lov,lmv}.*-clilov-*.* values
 */
static int get_param_tgt(const char *path, enum tgt_type type,
			 const char *param, char *buf, size_t buf_size)
{
	const char *typestr = type == LOV_TYPE ? "lov" : "lmv";
	struct obd_uuid uuid;
	int rc;

	rc = llapi_file_get_type_uuid(path, type, &uuid);
	if (rc != 0)
		return rc;

	rc = get_lustre_param_value(typestr, uuid.uuid, FILTER_BY_EXACT, param,
				    buf, buf_size);
	return rc;
}

int llapi_get_agent_uuid(char *path, char *buf, size_t bufsize)
{
	return get_param_tgt(path, LMV_TYPE, "uuid", buf, bufsize);
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
	int *indices = NULL;
	struct obd_uuid *uuids = NULL;
	int *indexes;
	char buf[16];
	long i;

	ret = get_param_tgt(path, type, "numobd", buf, sizeof(buf));
	if (ret != 0)
		return ret;

	obdcount = atoi(buf);
	uuids = malloc(obdcount * sizeof(struct obd_uuid));
	if (uuids == NULL)
		return -ENOMEM;
	indices = malloc(obdcount * sizeof(int));
	if (indices == NULL) {
		ret = -ENOMEM;
		goto out_uuids;
	}

retry_get_uuids:
	ret = llapi_get_target_uuids(d, uuids, indices, NULL, &obdcount, type);
	if (ret) {
		if (ret == -EOVERFLOW) {
			struct obd_uuid *uuids_temp;
			int *indices_temp = NULL;

			uuids_temp = realloc(uuids, obdcount *
					     sizeof(struct obd_uuid));
			if (uuids_temp)
				uuids = uuids_temp;
			indices_temp = realloc(indices, obdcount * sizeof(int));
			if (indices_temp)
				indices = indices_temp;
			if (uuids_temp && indices_temp)
				goto retry_get_uuids;
			ret = -ENOMEM;
		}

		llapi_error(LLAPI_MSG_ERROR, ret, "cannot fetch %u OST UUIDs",
			    obdcount);
		goto out_free;
	}

	indexes = malloc(num_obds * sizeof(*obdindex));
	if (indexes == NULL) {
		ret = -ENOMEM;
		goto out_free;
	}

	for (obdnum = 0; obdnum < num_obds; obdnum++) {
		int maxidx = LOV_V1_INSANE_STRIPE_COUNT;
		char *end = NULL;

		/* The user may have specified a simple index */
		i = strtol(obduuids[obdnum].uuid, &end, 0);
		if (end && *end == '\0' && i < LOV_V1_INSANE_STRIPE_COUNT) {
			indexes[obdnum] = i;
			obd_valid++;
		} else {
			maxidx = obdcount;
			for (i = 0; i < obdcount; i++) {
				if (llapi_uuid_match(uuids[i].uuid,
						     obduuids[obdnum].uuid)) {
					indexes[obdnum] = indices[i];
					obd_valid++;
					break;
				}
			}
		}

		if (i >= maxidx) {
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
	if (indices)
		free(indices);
out_uuids:
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

int cb_find_init(char *path, int p, int *dp,
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
	__u32 projid = DEFAULT_PROJID;
	bool gather_all = false;

	if (p == -1 && d == -1)
		return -EINVAL;
	/* if below minimum depth do not process further */
	if (param->fp_depth < param->fp_min_depth)
		goto decided;

	/* Reset this value between invocations */
	param->fp_get_lmv = 0;

	/* Gather all file/dir info, not just what's needed for search params */
	if (param->fp_format_printf_str)
		gather_all = true;

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
	if (de != NULL && de->d_type != DT_UNKNOWN) {
		if (param->fp_type != 0) {
			checked_type = 1;

			if (DTTOIF(de->d_type) == param->fp_type) {
				if (param->fp_exclude_type)
					goto decided;
			} else {
				if (!param->fp_exclude_type)
					goto decided;
			}
		}
		if ((param->fp_check_mdt_count || param->fp_hash_type ||
		     param->fp_check_hash_flag) && de->d_type != DT_DIR)
			goto decided;
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
	    param->fp_check_hash_flag || param->fp_perm_sign ||
	    param->fp_nlink || param->fp_attrs || param->fp_neg_attrs ||
	    gather_all)
		decision = 0;

	if (param->fp_type != 0 && checked_type == 0)
		decision = 0;

	if (decision == 0) {
		if (d != -1 &&
		    (param->fp_check_mdt_count || param->fp_hash_type ||
		     param->fp_check_hash_flag || param->fp_check_foreign ||
		     /*
		      * cb_get_dirstripe is needed when checking nlink because
		      * nlink is handled differently for multi-stripe directory
		      * vs. single-stripe directory
		      */
		     param->fp_nlink || gather_all)) {
			struct lmv_user_md *lmv;

			param->fp_get_lmv = 1;
			ret = cb_get_dirstripe(path, &d, param);
			lmv = param->fp_lmv_md;
			if (ret != 0) {
				if (errno == ENODATA) {
					/* Fill in struct for unstriped dir */
					ret = 0;
					lmv->lum_magic = LMV_MAGIC_V1;
					/* Use 0 until we find actual offset */
					lmv->lum_stripe_offset = 0;
					lmv->lum_stripe_count = 0;
					lmv->lum_hash_type = 0;

					if (param->fp_check_foreign) {
						if (param->fp_exclude_foreign)
							goto print;
						goto decided;
					}
				} else {
					return ret;
				}
			}

			if (param->fp_check_mdt_count) {
				if (lmv_is_foreign(lmv->lum_magic))
					goto decided;

				decision = find_value_cmp(lmv->lum_stripe_count,
						param->fp_mdt_count,
						param->fp_mdt_count_sign,
						param->fp_exclude_mdt_count,
						1, 0);
				if (decision == -1)
					goto decided;
			}

			if (param->fp_hash_type) {
				__u32 found;
				__u32 type = lmv->lum_hash_type &
					LMV_HASH_TYPE_MASK;

				if (lmv_is_foreign(lmv->lum_magic))
					goto decided;

				found = (1 << type) & param->fp_hash_type;
				if ((found && param->fp_exclude_hash_type) ||
				    (!found && !param->fp_exclude_hash_type))
					goto decided;
			}

			if (param->fp_check_hash_flag) {
				__u32 flags = lmv->lum_hash_type &
					~LMV_HASH_TYPE_MASK;

				if (lmv_is_foreign(lmv->lum_magic))
					goto decided;

				if (!(flags & param->fp_hash_inflags) ||
				    (flags & param->fp_hash_exflags))
					goto decided;
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
		if (ret == 0 && (param->fp_mdt_uuid != NULL || gather_all)) {
			if (d != -1) {
				ret = llapi_file_fget_mdtidx(d,
						     &param->fp_file_mdt_index);
				/*
				 *  Make sure lum_stripe_offset matches
				 *  mdt_index even for unstriped directories.
				 */
				if (ret == 0 && param->fp_get_lmv)
					param->fp_lmv_md->lum_stripe_offset =
						param->fp_file_mdt_index;
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

	/* Check the file permissions from the stat info */
	if (param->fp_perm_sign) {
		decision = check_file_permissions(param, lmd->lmd_stx.stx_mode);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_type && !checked_type) {
		if ((param->fp_check_mdt_count || param->fp_check_hash_flag ||
		     param->fp_hash_type) && !S_ISDIR(lmd->lmd_stx.stx_mode))
			goto decided;

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

	if (param->fp_check_layout) {
		decision = find_check_layout(param);
		if (decision == -1)
			goto decided;
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

	/* Retrieve project id from file/dir */
	if (param->fp_check_projid || gather_all) {
		ret = get_projid(path, &fd, lmd->lmd_stx.stx_mode, &projid);
		if (ret) {
			llapi_error(LLAPI_MSG_ERROR, -ENOENT,
				    "warning: %s: failed to get project id from file \"%s\"",
				    __func__, path);
			goto out;
		}
		if (param->fp_check_projid) {
			/* Conditionally filter this result based on --projid
			 * param, and whether or not we're including or
			 * excluding matching results.
			 * fp_exclude_projid = 0 means only include exact match.
			 * fp_exclude_projid = 1 means exclude exact match.
			 */
			bool matches = projid == param->fp_projid;

			if (matches == param->fp_exclude_projid)
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

	if (param->fp_attrs || param->fp_neg_attrs) {
		decision = find_check_attr_options(param);
		if (decision == -1)
			goto decided;
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

	if (param->fp_xattr_match_info) {
		decision = find_check_xattrs(path, param->fp_xattr_match_info);
		if (decision == -1)
			goto decided;
	}

	/*
	 * When checking nlink, stat(2) is needed for multi-striped directories
	 * because the nlink value retrieved from the MDS above comes from
	 * the number of stripes for the dir.
	 * The posix stat call below fills in the correct number of links.
	 * Single-stripe directories and regular files already have the
	 * correct nlink value.
	 */
	if (param->fp_nlink && S_ISDIR(lmd->lmd_stx.stx_mode) &&
	    (param->fp_lmv_md->lum_stripe_count != 0))
		decision = 0;

	/*
	 * If file still fits the request, ask ost for updated info.
	 * The regular stat is almost of the same speed as some new
	 * 'glimpse-size-ioctl'.
	 */
	if (!decision || gather_all) {
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

	if (param->fp_nlink) {
		decision = find_value_cmp(lmd->lmd_stx.stx_nlink,
					  param->fp_nlink, param->fp_nlink_sign,
					  param->fp_exclude_nlink, 1, 0);
		if (decision == -1)
			goto decided;
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

print:
	if (param->fp_skip_percent && find_skip_file(param))
		goto decided;

	if (param->fp_format_printf_str)
		printf_format_string(param, path, projid, d);
	else
		llapi_printf(LLAPI_MSG_NORMAL, "%s%c", path,
			     param->fp_zero_end ? '\0' : '\n');


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

int llapi_semantic_traverse(char *path, int size, int parent,
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
		struct find_work_queue *queue = param->fp_queue;
		int rc = 0;

		if (param->fp_thread_count && queue->fwq_shutdown)
			break;

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
			/* recursion down into a new subdirectory here */
			if (param->fp_thread_count) {
				rc = work_unit_create_and_add(path, param,
							      dent);
			} else {
				rc = llapi_semantic_traverse(path, size, d,
							     sem_init, sem_fini,
							     data, dent);
			}
			if (rc != 0 && ret == 0)
				ret = rc;
			if (rc < 0 && rc != -EALREADY &&
			    param->fp_stop_on_error)
				goto out;
			break;
		default:
			rc = 0;
			if (sem_init) {
				rc = sem_init(path, d, NULL, data, dent);
				if (rc < 0 && ret == 0) {
					ret = rc;
					if (rc && rc != -EALREADY &&
					    param->fp_stop_on_error)
						goto out;
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

int param_callback(char *path, semantic_func_t sem_init,
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

	ret = snprintf(buf, PATH_MAX + 1, "%s", path);
	if (ret < 0 || ret >= PATH_MAX + 1) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	ret = common_param_init(param, buf);
	if (ret)
		goto out;

	param->fp_depth = 0;

	ret = llapi_semantic_traverse(buf, 2 * PATH_MAX + 1, -1, sem_init,
				      sem_fini, param, NULL);
out:
	find_param_fini(param);
	free(buf);
	return ret < 0 ? ret : 0;
}

static void work_unit_free(struct find_work_unit *unit);

/* Placeholder worker function - just for testing thread creation */
static void *find_worker(void *arg)
{
	struct find_work_queue *queue = (struct find_work_queue *) arg;
	struct find_work_unit *unit = NULL;
	char *fail_loc = getenv("LLAPI_FAIL_LOC");
	int rc = 0;

	while (!queue->fwq_shutdown) {
		/* Get work unit from queue */
		pthread_mutex_lock(&queue->fwq_lock);
		while (queue->fwq_head == NULL && !queue->fwq_shutdown) {
			pthread_cond_wait(&queue->fwq_sleep_cond,
					  &queue->fwq_lock);
		}

		if (queue->fwq_shutdown) {
			pthread_mutex_unlock(&queue->fwq_lock);
			break;
		}

		/* Dequeue work unit */
		unit = queue->fwq_head;

		queue->fwq_head = unit->fwu_next;
		if (queue->fwq_head == NULL)
			queue->fwq_tail = NULL;
		pthread_mutex_unlock(&queue->fwq_lock);

		rc = llapi_semantic_traverse(unit->fwu_path, 2 * PATH_MAX, -1,
					     cb_find_init, cb_common_fini,
					     unit->fwu_param, NULL);
		if (rc && queue->fwq_error == 0)
			queue->fwq_error = rc;
		if ((rc < 0 && rc != -EALREADY &&
		     unit->fwu_param->fp_stop_on_error) ||
		    (fail_loc && !strcmp(fail_loc, "LLAPI_FAIL_PFIND_SEM"))) {
			if (fail_loc && !strcmp(fail_loc,
						"LLAPI_FAIL_PFIND_SEM"))
				rc = -EIO;
			queue->fwq_shutdown = 1;
			queue->fwq_error = rc;
		}

		work_unit_free(unit);
		ll_atomic_fetch_sub(&queue->fwq_active_units, 1);
	}

	return NULL;
}

/* Initialize the work queue */
static void find_work_queue_init(struct find_work_queue *queue)
{
	queue->fwq_head = NULL;
	queue->fwq_tail = NULL;
	queue->fwq_active_units = 0;
	pthread_mutex_init(&queue->fwq_lock, NULL);
	pthread_cond_init(&queue->fwq_sleep_cond, NULL);
	queue->fwq_shutdown = false;
	queue->fwq_error = 0;
}

static int find_threads_init(pthread_t *threads, struct find_work_queue *queue,
			     int numthreads)
{
	int ret;
	int i;

	for (i = 0; i < numthreads; i++) {
		ret = pthread_create(&threads[i], NULL, find_worker, queue);
		if (ret) {
			/* Set shutdown flag for any created threads */
			queue->fwq_shutdown = true;
			/* wake up queue... */
			pthread_cond_broadcast(&queue->fwq_sleep_cond);
			/* Wait for already-created threads to exit */
			while (--i >= 0)
				pthread_join(threads[i], NULL);
			return -ENOMEM;
		}
	}

	return 0;
}

void free_find_param(struct find_param *fp)
{
	if (!fp)
		return;

	free(fp->fp_pattern);
	free(fp->fp_obd_uuid);
	free(fp->fp_obd_indexes);
	free(fp->fp_mdt_uuid);
	free(fp->fp_mdt_indexes);
	free(fp->fp_lmd);
	free(fp->fp_lmv_md);

	/* Deep free xattr match info */
	if (fp->fp_xattr_match_info) {
		struct xattr_match_info *xmi = fp->fp_xattr_match_info;
		int i;

		free(xmi->xattr_regex_exclude);
		free(xmi->xattr_regex_matched);

		if (xmi->xattr_regex_name) {
			for (i = 0; i < xmi->xattr_regex_count; i++)
				free(xmi->xattr_regex_name[i]);
			free(xmi->xattr_regex_name);
		}

		if (xmi->xattr_regex_value) {
			for (i = 0; i < xmi->xattr_regex_count; i++)
				free(xmi->xattr_regex_value[i]);
			free(xmi->xattr_regex_value);
		}

		free(xmi->xattr_name_buf);
		free(xmi->xattr_value_buf);
		free(fp->fp_xattr_match_info);
	}

	free(fp->fp_format_printf_str);
	free(fp);
}

struct find_param *copy_find_param(const struct find_param *src)
{
	struct find_param *dst = calloc(1, sizeof(struct find_param));

	if (!dst)
		return NULL;

	/* Copy all scalar fields */
	memcpy(dst, src, sizeof(struct find_param));

	/* Clear all pointer fields to avoid double-free in error path */
	dst->fp_pattern = NULL;
	dst->fp_obd_uuid = NULL;
	dst->fp_obd_indexes = NULL;
	dst->fp_mdt_uuid = NULL;
	dst->fp_mdt_indexes = NULL;
	dst->fp_lmd = NULL;
	dst->fp_lmv_md = NULL;
	dst->fp_xattr_match_info = NULL;
	dst->fp_format_printf_str = NULL;

	/* Deep copy dynamically allocated fields */
	if (src->fp_pattern) {
		dst->fp_pattern = strdup(src->fp_pattern);
		if (!dst->fp_pattern)
			goto error;
	}

	/* OBD UUIDs */
	if (src->fp_obd_uuid && src->fp_num_alloc_obds > 0) {
		dst->fp_obd_uuid = calloc(src->fp_num_alloc_obds,
					  sizeof(struct obd_uuid));
		if (!dst->fp_obd_uuid)
			goto error;
		memcpy(dst->fp_obd_uuid, src->fp_obd_uuid,
			src->fp_num_alloc_obds * sizeof(struct obd_uuid));
	}

	if (src->fp_obd_indexes && src->fp_num_obds > 0) {
		dst->fp_obd_indexes = calloc(src->fp_num_obds,
					     sizeof(int));
		if (!dst->fp_obd_indexes)
			goto error;
		memcpy(dst->fp_obd_indexes, src->fp_obd_indexes,
			src->fp_num_obds * sizeof(int));
	}

	/* MDT UUIDs */
	if (src->fp_mdt_uuid && src->fp_num_alloc_mdts > 0) {
		dst->fp_mdt_uuid = calloc(src->fp_num_alloc_mdts,
					  sizeof(struct obd_uuid));
		if (!dst->fp_mdt_uuid)
			goto error;
		memcpy(dst->fp_mdt_uuid, src->fp_mdt_uuid,
		       src->fp_num_alloc_mdts * sizeof(struct obd_uuid));
	}

	if (src->fp_mdt_indexes && src->fp_num_mdts > 0) {
		dst->fp_mdt_indexes = calloc(src->fp_num_mdts,
					     sizeof(int));
		if (!dst->fp_mdt_indexes)
			goto error;
		memcpy(dst->fp_mdt_indexes, src->fp_mdt_indexes,
		       src->fp_num_mdts * sizeof(int));
	}

	/* LMD and LMV data */
	if (src->fp_lmd && src->fp_lum_size > 0) {
		size_t lmd_size = offsetof(typeof(*src->fp_lmd), lmd_lmm) +
				  src->fp_lum_size;

		dst->fp_lmd = malloc(lmd_size);
		if (!dst->fp_lmd)
			goto error;
		memcpy(dst->fp_lmd, src->fp_lmd, lmd_size);
	}

	if (src->fp_lmv_md) {
		size_t lmv_size = lmv_user_md_size(src->fp_lmv_stripe_count,
						   LMV_USER_MAGIC_SPECIFIC);
		dst->fp_lmv_md = malloc(lmv_size);
		if (!dst->fp_lmv_md)
			goto error;
		memcpy(dst->fp_lmv_md, src->fp_lmv_md, lmv_size);
	}

	/* xattr match info - deep copy all pointer fields */
	if (src->fp_xattr_match_info) {
		struct xattr_match_info *src_xmi = src->fp_xattr_match_info;
		struct xattr_match_info *dst_xmi;
		int i;

		dst->fp_xattr_match_info =
			calloc(1, sizeof(struct xattr_match_info));
		if (!dst->fp_xattr_match_info)
			goto error;

		dst_xmi = dst->fp_xattr_match_info;
		dst_xmi->xattr_regex_count = src_xmi->xattr_regex_count;

		/* Deep copy all pointer fields */
		if (src_xmi->xattr_regex_count > 0) {
			/* Copy exclude array */
			if (src_xmi->xattr_regex_exclude) {
				dst_xmi->xattr_regex_exclude =
					malloc(src_xmi->xattr_regex_count *
					       sizeof(bool));
				if (!dst_xmi->xattr_regex_exclude)
					goto error;
				memcpy(dst_xmi->xattr_regex_exclude,
				       src_xmi->xattr_regex_exclude,
				       src_xmi->xattr_regex_count *
				       sizeof(bool));
			}

			/* Copy matched array */
			if (src_xmi->xattr_regex_matched) {
				dst_xmi->xattr_regex_matched =
					malloc(src_xmi->xattr_regex_count *
					       sizeof(bool));
				if (!dst_xmi->xattr_regex_matched)
					goto error;
				memcpy(dst_xmi->xattr_regex_matched,
				       src_xmi->xattr_regex_matched,
				       src_xmi->xattr_regex_count *
				       sizeof(bool));
			}

			/* Copy regex name array */
			if (src_xmi->xattr_regex_name) {
				dst_xmi->xattr_regex_name =
					malloc(src_xmi->xattr_regex_count *
					       sizeof(regex_t *));
				if (!dst_xmi->xattr_regex_name)
					goto error;
				for (i = 0; i < src_xmi->xattr_regex_count;
				     i++) {
					if (!src_xmi->xattr_regex_name[i]) {
						dst_xmi->xattr_regex_name[i] =
							NULL;
						continue;
					}
					dst_xmi->xattr_regex_name[i] =
						malloc(sizeof(regex_t));
					if (!dst_xmi->xattr_regex_name[i])
						goto error;
					memcpy(dst_xmi->xattr_regex_name[i],
					       src_xmi->xattr_regex_name[i],
					       sizeof(regex_t));
				}
			}

			/* Copy regex value array */
			if (src_xmi->xattr_regex_value) {
				dst_xmi->xattr_regex_value =
					malloc(src_xmi->xattr_regex_count *
					       sizeof(regex_t *));
				if (!dst_xmi->xattr_regex_value)
					goto error;
				for (i = 0; i < src_xmi->xattr_regex_count;
				     i++) {
					if (!src_xmi->xattr_regex_value[i]) {
						dst_xmi->xattr_regex_value[i] =
							NULL;
						continue;
					}
					dst_xmi->xattr_regex_value[i] =
						malloc(sizeof(regex_t));
					if (!dst_xmi->xattr_regex_value[i])
						goto error;
					memcpy(dst_xmi->xattr_regex_value[i],
					       src_xmi->xattr_regex_value[i],
					       sizeof(regex_t));
				}
			}
		}

		/* Copy name buffer */
		if (src_xmi->xattr_name_buf) {
			dst_xmi->xattr_name_buf = malloc(XATTR_LIST_MAX);
			if (!dst_xmi->xattr_name_buf)
				goto error;
			memcpy(dst_xmi->xattr_name_buf,
			       src_xmi->xattr_name_buf, XATTR_LIST_MAX);
		}

		/* Copy value buffer */
		if (src_xmi->xattr_value_buf) {
			dst_xmi->xattr_value_buf = malloc(XATTR_SIZE_MAX);
			if (!dst_xmi->xattr_value_buf)
				goto error;
			memcpy(dst_xmi->xattr_value_buf,
			       src_xmi->xattr_value_buf, XATTR_SIZE_MAX);
		}
	}

	/* Format string */
	if (src->fp_format_printf_str) {
		dst->fp_format_printf_str = strdup(src->fp_format_printf_str);
		if (!dst->fp_format_printf_str)
			goto error;
	}

	return dst;

error:
	/* Cleanup on error */
	if (dst)
		free_find_param(dst);
	return NULL;
}

/* Free a work unit */
static void work_unit_free(struct find_work_unit *unit)
{
	if (!unit)
		return;

	free(unit->fwu_path);
	free(unit->fwu_de);
	free_find_param(unit->fwu_param);
	free(unit);
}

/* Create a new work unit */
static struct find_work_unit *work_unit_create(const char *path,
					       struct find_param *param,
					       struct dirent64 *de)
{
	struct find_work_unit *unit;

	unit = malloc(sizeof(*unit));
	if (!unit)
		return NULL;

	/* Initialize with zeros to ensure clean error handling */
	memset(unit, 0, sizeof(*unit));

	/* Copy the path */
	unit->fwu_path = (char *)malloc(PATH_MAX + 1);
	if (!unit->fwu_path)
		goto error;
	snprintf(unit->fwu_path, PATH_MAX + 1, "%s", path);

	/* Copy the directory entry if provided */
	if (de) {
		unit->fwu_de = malloc(sizeof(*de));
		if (!unit->fwu_de)
			goto error;
		memcpy(unit->fwu_de, de, sizeof(*de));
	}


	unit->fwu_param = copy_find_param(param);
	if (!unit->fwu_param)
		goto error;

	return unit;

error:
	work_unit_free(unit);
	return NULL;
}

int work_unit_create_and_add(const char *path, struct find_param *param,
			     struct dirent64 *dent)
{
	struct find_work_queue *queue = param->fp_queue;
	struct find_work_unit *unit;
	int rc = 0;

	unit = work_unit_create(path, param, dent);
	if (!unit) {
		rc = -ENOMEM;
		goto out;
	}

	ll_atomic_fetch_add(&queue->fwq_active_units, 1);

	pthread_mutex_lock(&queue->fwq_lock);

	/* add to queue, at tail if there's already something on the queue */
	if (queue->fwq_tail) {
		queue->fwq_tail->fwu_next = unit;
	} else {
		queue->fwq_head = unit;
	}
	queue->fwq_tail = unit;

	/* wake up any waiting workers */
	pthread_cond_signal(&queue->fwq_sleep_cond);
	pthread_mutex_unlock(&queue->fwq_lock);

out:
	return rc;
}

void cleanup_work_queue(struct find_work_queue *queue)
{
	struct find_work_unit *unit, *next;

	pthread_mutex_lock(&queue->fwq_lock);
	unit = queue->fwq_head;
	while (unit) {
		next = unit->fwu_next;
		work_unit_free(unit);
		ll_atomic_fetch_sub(&queue->fwq_active_units, 1);
		unit = next;
	}
	queue->fwq_head = queue->fwq_tail = NULL;
	pthread_mutex_unlock(&queue->fwq_lock);
}

static int pfind_param_callback(char *path, struct find_param *param,
				struct find_work_queue *queue)
{
	char *buf;
	int ret;

	if (strlen(path) > PATH_MAX) {
		ret = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, ret,
			    "Path name '%s' is too long", path);
		return ret;
	}

	buf = (char *)malloc(PATH_MAX + 1);
	if (!buf)
		return -ENOMEM;

	snprintf(buf, PATH_MAX + 1, "%s", path);
	ret = common_param_init(param, buf);
	if (ret)
		goto out;

	param->fp_queue = queue;
	ret = work_unit_create_and_add(buf, param, NULL);
	if (ret)
		goto out;

	/* Wait for all work to complete */
	while (ll_atomic_fetch_add(&queue->fwq_active_units, 0) > 0) {
		/* if a worker hit an error, it forces shutdown... */
		if (queue->fwq_shutdown)
			cleanup_work_queue(queue);
		else
			sched_yield();
	}
	/* collect error if one occurred... */
	ret = queue->fwq_error;

out:
	find_param_fini(param);
	free(buf);
	return ret < 0 ? ret : 0;
}

int parallel_find(char *path, struct find_param *param)
{
	struct find_work_queue queue = { 0 };
	pthread_t *threads = NULL;
	int numthreads = param->fp_thread_count;
	int rc;
	int i;

	if (param->fp_format_printf_str)
		validate_printf_str(param);

	/* require at least one thread */
	if (numthreads < 1)
		return -EINVAL;

	find_work_queue_init(&queue);

	threads = malloc(numthreads * sizeof(pthread_t));
	if (!threads)
		return -ENOMEM;

	rc = find_threads_init(threads, &queue, numthreads);
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Failed to initialize thread pool");
		goto cleanup;
	}
	/* Normal find - no parallelism yet */
	rc = pfind_param_callback(path, param, &queue);


	/* Signal shutdown and wait for threads before cleanup */
	pthread_mutex_lock(&queue.fwq_lock);
	queue.fwq_shutdown = true;
	pthread_cond_broadcast(&queue.fwq_sleep_cond);
	pthread_mutex_unlock(&queue.fwq_lock);
	for (i = 0; i < numthreads; i++)
		pthread_join(threads[i], NULL);

cleanup:
	free(threads);
	pthread_mutex_destroy(&queue.fwq_lock);
	pthread_cond_destroy(&queue.fwq_sleep_cond);

	return rc;
}
