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
#include <sys/resource.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include "lustreapi_internal.h"
#include "lustreapi_scan_backend.h"
#include "lstddef.h"

#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_ioctl.h>
#include <linux/lustre/lustre_ostid.h>

#define FORMATTED_BUF_LEN	1024
#define FORMATTED_BUF_MAX	(1024 * 1024)
#define FORMATTED_BUF_ROOM	128

/* Buf size used by llapi_semantic_traverse to build path of dir entries */
#define FIND_PATH_BUFLEN	(2 * PATH_MAX)

/* Maximum number of work units queued or being processed by parallel find */
#define FIND_QUEUE_MAX_UNITS	4096

/* file descriptors used per pfind thread */
#define FIND_FDS_PER_THREAD	4
/* file descriptors for pfind internal use */
#define FIND_FDS_RESERVED	16

/* levels of subdirectories the current thread is traversing itself */
static __thread int find_inline_depth;

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

int cb_common_fini(char *path, int p, int *dp, struct find_param *param,
		   struct dirent64 *de)
{
	param->fp_depth--;
	return 0;
}

/*
 * @d keeps its number but may not keep its open file description: the
 * ENOTTY retry below reopens the path without O_DIRECTORY and dup2()s the
 * result onto it.  A caller that wants a DIR stream on @d has to build it
 * after this returns, as llapi_semantic_traverse() does -- fdopendir()
 * first would leave the stream on a description this replaced.
 */
int cb_get_dirstripe(char *path, int d, struct find_param *param)
{
	int ret;
	bool did_nofollow = false;

	if (d < 0)
		return -ENOTDIR;
again:
	param->fp_lmv_md->lum_stripe_count = param->fp_lmv_stripe_count;
	if (param->fp_get_default_lmv) {
#ifdef HAVE_STATX
		struct statx stx;

		/* open() may not fetch LOOKUP lock, statx() to ensure dir depth
		 * is set.
		 */
		statx(d, "", AT_EMPTY_PATH, STATX_MODE, &stx);
#else
		struct stat st;

		fstat(d, &st);
#endif
		param->fp_lmv_md->lum_magic = LMV_USER_MAGIC;
	} else {
		param->fp_lmv_md->lum_magic = LMV_MAGIC_V1;
	}
	if (param->fp_raw)
		param->fp_lmv_md->lum_type = LMV_TYPE_RAW;

	ret = ioctl(d, LL_IOC_LMV_GETSTRIPE, param->fp_lmv_md);

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
		/*
		 * Move the reopen onto the number the caller already holds,
		 * rather than handing back a different one: every caller keeps
		 * a copy, and the old number must never be free for another
		 * thread to claim while those copies are still live.
		 */
		if (dup2(fd, d) < 0) {
			close(fd);
			/* restore original errno */
			errno = ENOTTY;
			return ret;
		}
		close(fd);
		ret2 = ioctl(d, LL_IOC_LMV_GETSTRIPE, param->fp_lmv_md);
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
	/*
	 * Everything up to lmd_lmm is still the V1 lmd_st: lmd_fid would read
	 * as an IGIF and stx_mask would keep st_nlink's bits, and
	 * convert_lmd_statx() writes only the fields lstat has.
	 */
	memset(lmd_v2, 0, offsetof(typeof(*lmd_v2), lmd_lmm));
	convert_lmd_statx(lmd_v2, &st, false);

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

			/*
			 * A stat answers for an object the ioctl could not,
			 * and the buffer holds the name written in for that
			 * ioctl or the previous object: lmd_fid would read as
			 * an IGIF, stx_mask would keep the name's bits, and
			 * llapi_get_lum_file_fd() copies by lmd_lmmsize.
			 * Cleared here rather than in convert_lmd_statx(),
			 * whose third caller -- find_decide() under
			 * gather_all -- runs after the V2 ioctl has put real
			 * values there.
			 */
			memset(lmd, 0, offsetof(typeof(*lmd), lmd_lmm));
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
			/* ! -newerbY: no birth time is not newer, a match */
			if (!(lmd->lmd_stx.stx_mask & STATX_BTIME) && i == 1)
				continue;
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

		/* a foreign layout or component has no pattern field */
		if (v1->lmm_magic == LOV_USER_MAGIC_FOREIGN) {
			valid = true;
			if (param->fp_layout & LOV_PATTERN_FOREIGN) {
				found = true;
				break;
			}
			continue;
		}

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
 * Find a foreign component, e.g. a PCC-RO mirror, of the type to check,
 * or else the first foreign component, so that a file with only foreign
 * components of other types is handled like a foreign layout of another
 * type.  Return NULL if the layout has no foreign component.
 */
static struct lov_foreign_md *find_foreign_comp(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1 = (void *)&param->fp_lmd->lmd_lmm;
	struct lov_foreign_md *first = NULL;
	struct lov_foreign_md *lfm;
	int i;

	for (i = 0; i < comp_v1->lcm_entry_count; i++) {
		lfm = (void *)lov_comp_entry(comp_v1, i);
		if (lfm->lfm_magic != LOV_USER_MAGIC_FOREIGN)
			continue;
		if (param->fp_foreign_type == LU_FOREIGN_TYPE_UNKNOWN ||
		    lfm->lfm_type == param->fp_foreign_type)
			return lfm;
		if (!first)
			first = lfm;
	}

	return first;
}

/*
 * if no type specified, check/exclude all foreign
 * if type specified, check all foreign&type and exclude !foreign + foreign&type
 * so "! --foreign=TYPE" matches only foreign objects of other types
 * a composite layout counts as foreign if it has a foreign component
 */
static int find_check_foreign(struct find_param *param)
{
	if (S_ISREG(param->fp_lmd->lmd_stx.stx_mode)) {
		struct lov_foreign_md *lfm;

		lfm = (void *)&param->fp_lmd->lmd_lmm;
		if (lfm->lfm_magic == LOV_USER_MAGIC_COMP_V1)
			lfm = find_foreign_comp(param);
		if (!lfm || lfm->lfm_magic != LOV_USER_MAGIC_FOREIGN) {
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
		if (!lmv_is_foreign(lfm->lfm_magic)) {
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

/* the options only a layout answers; not --projid, which an OST has */
static bool find_asks_layout(const struct find_param *param)
{
	return param->fp_check_pool || param->fp_check_stripe_count ||
	       param->fp_check_stripe_size || param->fp_check_layout ||
	       param->fp_check_comp_count || param->fp_check_comp_end ||
	       param->fp_check_comp_start || param->fp_check_comp_flags ||
	       param->fp_check_mirror_count || param->fp_check_foreign ||
	       param->fp_check_mirror_state || param->fp_check_ext_size;
}

static bool find_check_lmm_info(struct find_param *param)
{
	return find_asks_layout(param) || param->fp_check_projid;
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

/* An OST data object: one stripe of a file, which the file names */
static bool find_rec_is_ost_obj(const struct llapi_scan_rec *rec)
{
	return (rec->lfsr_valid & LLAPI_SCAN_CLASS) &&
	       rec->lfsr_class == LLAPI_SCAN_CLS_OST_OBJ;
}

/*
 * The FIDs of a file's OST objects, comma-separated, with one bracketed list
 * per component as %Lo prints the indices.  A stripe with no object yet is
 * left out, and a component with none prints nothing.
 */
static int printf_format_ost_fids(char *buffer, size_t size,
				  struct llapi_layout *layout)
{
	size_t wrote = 0;
	int rc;

	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	while (rc == 0) {
		uint64_t count, i;
		bool listed = false;

		if (llapi_layout_stripe_count_get(layout, &count) != 0 ||
		    count >= LLAPI_LAYOUT_INVALID)
			count = 0;
		for (i = 0; i < count && wrote < size; i++) {
			struct lu_fid fid;

			if (layout_ost_fid_get(layout, i, &fid) != 0)
				continue;
			wrote += snprintf(buffer + wrote, size - wrote,
					  "%c" DFID_NOBRACE, listed ? ',' : '[',
					  PFID(&fid));
			listed = true;
		}
		if (listed && wrote < size)
			wrote += snprintf(buffer + wrote, size - wrote, "]");
		rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	}

	return wrote < size ? wrote : size - 1;
}

/*
 * Print all ost indices associated with a file layout using a commma separated
 * list.  For a file with mutliple components, the list of indices for each
 * component will be enclosed in brackets.
 *
 * @param[out]	buffer	Location where OST indices are written
 * @param[in]	size	Size of the available buffer.
 * @pararm[in]	layout	Pointer to layout structure for the file
 * @param[in]	quiet	Say nothing about a layout that names no OSTs, which
 *			is an ordinary thing for one read off a target to be
 * @return		Number of bytes written to output buffer
 */
static int printf_format_ost_indices(char *buffer, size_t size,
				struct llapi_layout *layout, bool quiet)
{
	int err, bytes, wrote = 0;

	/* Make sure to start at the first component */
	err = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	if (err) {
		if (!quiet)
			llapi_error(LLAPI_MSG_ERROR, err,
				    "error: layout component iteration failed\n");
		goto format_done;
	}
	while (1) {
		uint64_t idx, count, i;
		uint64_t pattern = 0;
		uint32_t flags = 0;
		bool init;

		err = llapi_layout_stripe_count_get(layout, &count);
		if (err) {
			if (!quiet)
				llapi_error(LLAPI_MSG_ERROR, err,
					    "error: cannot get stripe_count\n");
			goto format_done;
		}
		/*
		 * No objects to list: a foreign component (count 0), or a
		 * default or -1 count on one with no objects yet.  The loop
		 * below is bounded by the count and needs at least one.
		 */
		if (count == 0 || count >= LLAPI_LAYOUT_INVALID)
			goto next_comp;

		/* no OST to name (DoM, or not instantiated yet): quiet '?' */
		init = (!llapi_layout_is_composite(layout) ||
			(llapi_layout_comp_flags_get(layout, &flags) == 0 &&
			 (flags & LCME_FL_INIT))) &&
		       !(llapi_layout_pattern_get(layout, &pattern) == 0 &&
			 pattern == LLAPI_LAYOUT_MDT);
		bytes = snprintf(buffer, (size - wrote), "%s", "[");
		wrote += bytes;
		if (wrote >= size)
			goto format_done;
		buffer += bytes;
		for (i = 0; i < count; i++) {
			err = llapi_layout_ost_index_get(layout, i, &idx);
			if (!err && idx == (__u32)-1)	/* lod placeholder */
				err = -ENOENT;
			else if (err)
				err = -errno;
			if (err) {
				if (!quiet && init)
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
next_comp:
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
 * @param[in]	rec	The record the object was delivered in
 * @param[in]	path	Pathname of the current file/dir being handled
 * @param[in]	projid	Project ID associated with the current file/dir
 * @param[in]	d	File descriptor for the directory (or -1 for a
 *			non-directory file)
 * @return		Number of characters from input string processed
 *			as part of the format (0 for an unknown format)
 */
static int printf_format_lustre(char *seq, char *buffer, size_t size,
				int *wrote, struct find_param *param,
				const struct llapi_scan_rec *rec,
				char *path, __u32 projid, int d)
{
	struct lmv_user_md *lum;
	struct lmv_user_mds_data *objects;
	struct llapi_layout *layout = NULL;
	struct lu_fid fid;
	unsigned int hash_type;
	uint64_t str_cnt, str_size, idx, pattern;
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
	 * An unknown letter, or a trailing %L, is printed as it stands.
	 * Keep this list in step with the switches below.
	 */
	if (*seq == '\0' || !strchr("aAFOPchiopS", *seq)) {
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
		if (!path) {
			/*
			 * A target scan walked no path to ask an MDT through.
			 * The FID is in the record, which is where the
			 * default output of such a scan reads it from too,
			 * and an object carrying no trusted.lma has none.
			 * An OST data object prints nothing: the FID a user
			 * knows is its file's, which is not read here.
			 */
			if (!rec || find_rec_is_ost_obj(rec) ||
			    !(rec->lfsr_valid & LLAPI_SCAN_FID))
				goto format_done;
			*wrote = snprintf(buffer, size, DFID_NOBRACE,
					  PFID(&rec->lfsr_fid));
			goto format_done;
		}
		err = llapi_path2fid(path, &fid);
		if (err) {
			/*
			 * A walk descends a directory that is not on Lustre
			 * -- cb_find_init() treats the stripe ioctl's ENOTTY
			 * as "no stripe" rather than an error -- so the
			 * objects under it reach here.  Having no FID is what
			 * such an object is, not a failure to report: the
			 * directive stays empty and nothing is said.
			 *
			 * Unlike the layout fetch below, llapi_path2fid()
			 * does not follow the ENOTTY convention: an object
			 * off Lustre answers ENODATA, or ENOTSUP where the
			 * library is built without server support.
			 */
			if (err != -ENOTTY && err != -ENODATA &&
			    err != -ENOTSUP)
				llapi_error(LLAPI_MSG_ERROR, err,
					    "error: cannot get fid\n");
			goto format_done;
		}
		*wrote = snprintf(buffer, size, DFID_NOBRACE, PFID(&fid));
		goto format_done;
	case 'O':
		/* an OST data object is one of its file's: only its own FID */
		if (rec && find_rec_is_ost_obj(rec)) {
			if (rec->lfsr_valid & LLAPI_SCAN_FID)
				*wrote = snprintf(buffer, size,
						  "[" DFID_NOBRACE "]",
						  PFID(&rec->lfsr_fid));
			goto format_done;
		}
		break;
	case 'P':
		*wrote = snprintf(buffer, size, "%u", projid);
		goto format_done;
	}

	/*
	 * Other formats for files/dirs need to be handled differently.  A
	 * target scan opens nothing, so d is -1 for a directory there as
	 * well and the mode is what tells the two apart.
	 */
	if (!path ? !S_ISDIR(param->fp_lmd->lmd_stx.stx_mode) :
			   d == -1) {		/* file */
		if (!path)
			/*
			 * The scan read trusted.lov already; there is no path
			 * to fetch it through a second time.  lmd_lmmsize is
			 * the bytes it read, or the forged default's.
			 */
			layout = llapi_layout_get_by_xattr(
					&param->fp_lmd->lmd_lmm,
					param->fp_lmd->lmd_lmmsize, 0);
		else
			layout = llapi_layout_get_by_path(path, 0);
		if (layout == NULL) {
			/* not on Lustre: see the note on %LF above.  This is
			 * the one fetch %Lc, %Li, %Lo, %Lp and %LS share.
			 * An object a scan could not read a layout for is
			 * left empty the same way, and says nothing: it is
			 * not an error for an object to have none.
			 */
			if (path && errno != ENOTTY)
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
			/*
			 * The guards in this branch are all the same one: a
			 * layout read off a target can be a default with no
			 * component instantiated, or one naming no objects,
			 * and having no answer for a directive is what such an
			 * object is -- not a failure worth a line per object.
			 */
			if (path)
				llapi_error(LLAPI_MSG_ERROR, err,
					    "error: cannot get last initialized component\n");
			goto format_done;
		}

		switch (*seq) {
		case 'c':	/* stripe count */
			err = llapi_layout_stripe_count_get(layout, &str_cnt);
			if (err) {
				if (path)
					llapi_error(LLAPI_MSG_ERROR, -errno,
						    "error: cannot get stripe_count\n");
				goto format_done;
			}
			/*
			 * A default layout has no count of its own, so print
			 * nothing.  Data-on-MDT has a real count of 0, but the
			 * default find_lmm_set_default() forges has the MDT
			 * bit set in its all-ones pattern too.
			 */
			if (str_cnt == LLAPI_LAYOUT_DEFAULT &&
			    !(param->fp_lmd->lmd_lmm.lmm_magic ==
			      LOV_USER_MAGIC_V1 &&
			      param->fp_lmd->lmd_lmm.lmm_pattern ==
			      LOV_PATTERN_DEFAULT) &&
			    llapi_layout_pattern_get(layout, &pattern) == 0 &&
			    pattern == LLAPI_LAYOUT_MDT)
				str_cnt = 0;
			if (str_cnt == LLAPI_LAYOUT_DEFAULT)
				goto format_done;
			*wrote = snprintf(buffer, size, "%llu",
					  (unsigned long long)str_cnt);
			break;
		case 'h':	/* hash info */
			/* Not applicable to files.  Skip it. */
			break;
		case 'i':	/* starting index */
			err = llapi_layout_ost_index_get(layout, 0, &idx);
			if (err) {
				if (path)
					llapi_error(LLAPI_MSG_ERROR, -errno,
						    "error: cannot get OST index of last initialized component\n");
				goto format_done;
			}
			*wrote = snprintf(buffer, size, "%llu",
					  (unsigned long long)idx);
			break;
		case 'o':	/* list of object indices */
			*wrote = printf_format_ost_indices(buffer, size, layout,
							   !path);
			break;
		case 'O':	/* list of object FIDs */
			*wrote = printf_format_ost_fids(buffer, size, layout);
			break;
		case 'p':	/* pool name */
			err = llapi_layout_pool_name_get(layout, pool_name,
							 sizeof(pool_name));
			if (err) {
				if (path)
					llapi_error(LLAPI_MSG_ERROR, -errno,
						    "error: cannot get pool name\n");
				goto format_done;
			}
			*wrote = snprintf(buffer, size, "%s", pool_name);
			break;
		case 'S':	/* stripe size */
			err = llapi_layout_stripe_size_get(layout, &str_size);
			if (err) {
				if (path)
					llapi_error(LLAPI_MSG_ERROR, -errno,
						    "error: cannot get stripe_size\n");
				goto format_done;
			}
			/* the default, as above, is not a size to print */
			if (str_size == LLAPI_LAYOUT_DEFAULT)
				goto format_done;
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

		/* off Lustre the LMV is a stub of zeroes: print nothing.
		 * A target scan has no path, and its LMV is the object's own.
		 */
		if (path != NULL && lum->lum_stripe_count == 0 &&
		    param->fp_file_mdt_index == OBD_NOT_FOUND)
			goto format_done;

		/*
		 * A foreign LMV is a different structure at the same address,
		 * so every field below is somebody else's bytes: lfm_length
		 * sits where lum_stripe_count does, lfm_flags where
		 * lum_hash_type does, and lfm_value under both lum_pool_name
		 * and lum_objects[].  Printing them would put the foreign
		 * value's length where a stripe count belongs and part of its
		 * payload where a pool name belongs.  'i' answers for one
		 * from the directory's own MDT index, below; the rest have no
		 * answer and print nothing.
		 */
		if (lmv_is_foreign(lum->lum_magic) && *seq != 'i')
			goto format_done;

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
			/*
			 * A target scan builds no stub for an unstriped
			 * directory and sets fp_file_mdt_index only under
			 * --mdt: the record's own index answers, or nothing.
			 */
			if (!path && rec &&
			    (lum->lum_magic == 0 ||
			     lmv_is_foreign(lum->lum_magic))) {
				if (!(rec->lfsr_valid & LLAPI_SCAN_MDT_INDEX))
					goto format_done;
				*wrote = snprintf(buffer, size, "%d",
						  (int)rec->lfsr_mdt_index);
				break;
			}
			/*
			 * A foreign LMV has no stripe offset: lfm_type is
			 * at that offset, so the directory's own MDT index
			 * is printed instead, from where the gather left
			 * it.
			 */
			if (lmv_is_foreign(lum->lum_magic)) {
				if (param->fp_file_mdt_index == OBD_NOT_FOUND)
					goto format_done;
				*wrote = snprintf(buffer, size, "%d",
						  param->fp_file_mdt_index);
				break;
			}
			*wrote = snprintf(buffer, size, "%d",
					  lum->lum_stripe_offset);
			break;
		case 'o':	/* list of object indices */
			/* unstriped, on a scan: a walk prints [its index] */
			if (!path && rec &&
			    lum->lum_magic == 0) {
				if (!(rec->lfsr_valid & LLAPI_SCAN_MDT_INDEX))
					goto format_done;
				*wrote = snprintf(buffer, size, "[%d]",
						  (int)rec->lfsr_mdt_index);
				break;
			}
			/*
			 * A target scan has no shard FIDs (that needs an FLD
			 * lookup), so lum_objects[] is empty.  Measure the
			 * array by lfsr_lmvsize, not lum_stripe_count: the
			 * product in lmv_user_md_size() can wrap.
			 */
			if (!path && rec &&
			    (rec->lfsr_lmvsize <
			     lmv_user_md_size(0, LMV_USER_MAGIC_SPECIFIC) ||
			     (rec->lfsr_lmvsize -
			      lmv_user_md_size(0, LMV_USER_MAGIC_SPECIFIC)) /
			     sizeof(struct lmv_user_mds_data) <
			     lum->lum_stripe_count))
				break;
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
		case 'O':	/* a directory has no OST objects */
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

/* A scan that had no size (or blocks) for the object prints nothing. */
static bool printf_scan_lacks(const struct find_param *param, const char *path,
			      __u32 stx_bit, __u64 lazy_flag)
{
	return !path &&
	       !(param->fp_lmd->lmd_stx.stx_mask & stx_bit) &&
	       !(param->fp_lmd->lmd_flags & lazy_flag);
}

/*
 * A striped directory on a scan: its link count and its times are the
 * master inode's, where a walk's stat gives the directory's own, counted
 * and merged over every shard.  Not printed rather than printed wrong.
 */
static bool printf_scan_striped_dir(const struct find_param *param,
				    const char *path)
{
	return !path && S_ISDIR(param->fp_lmd->lmd_stx.stx_mode) &&
	       !lmv_is_foreign(param->fp_lmv_md->lum_magic) &&
	       param->fp_lmv_md->lum_stripe_count != 0;
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
 * @param[in]	rec	The record the object was delivered in
 * @param[in]	path	Pathname of the current file/dir being handled
 * @param[in]	projid	Project ID associated with the current file/dir
 * @param[in]	d	File descriptor for the directory (or -1 for a
 *			non-directory file)
 * @return		Number of characters from input string processed
 *			as part of the format (0 for an unknown format)
 */
static int printf_format_directive(char *seq, char *buffer, size_t size,
				   int *wrote, struct find_param *param,
				   const struct llapi_scan_rec *rec,
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
		/* the birth time is the master's own, the others are not */
		if (*seq != 'w' && *seq != 'W' &&
		    printf_scan_striped_dir(param, path))
			*wrote = 0;
		break;
	case 'b':	/* file size (in 512B blocks) */
		if (printf_scan_lacks(param, path, STATX_BLOCKS,
				      OBD_MD_FLLAZYBLOCKS))
			break;
		*wrote = snprintf(buffer, size, "%llu", blocks);
		break;
	case 'g': { /* groupname of owner*/
		/* __thread makes these variables thread-local to avoid
		 * races with parallel find worker threads.
		 */
		static __thread char save_gr_name[LOGIN_NAME_MAX + 1];
		static __thread gid_t save_gid = -1;

		if (save_gid != param->fp_lmd->lmd_stx.stx_gid) {
			struct group grp;
			struct group *gr = NULL;
			char gbuf[4096];

			getgrgid_r(param->fp_lmd->lmd_stx.stx_gid, &grp,
				   gbuf, sizeof(gbuf), &gr);
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
		/*
		 * A target scan fills no stx_ino: the object's id on the
		 * target is a field of the record, which is where that scan's
		 * own default output reads it from as well.
		 */
		if (!path && rec &&
		    (rec->lfsr_valid & LLAPI_SCAN_INO))
			*wrote = snprintf(buffer, size, "%llu",
					  (unsigned long long)rec->lfsr_ino);
		else
			*wrote = snprintf(buffer, size, "%llu",
					  param->fp_lmd->lmd_stx.stx_ino);
		break;
	case 'k':	/* file size (in 1K blocks) */
		if (printf_scan_lacks(param, path, STATX_BLOCKS,
				      OBD_MD_FLLAZYBLOCKS))
			break;
		*wrote = snprintf(buffer, size, "%llu", (blocks + 1) / 2);
		break;
	case 'L':	/* Lustre-specific formats */
		rc = printf_format_lustre(seq, buffer, size, wrote, param,
					  rec, path, projid, d);
		break;
	case 'm':	/* file mode in octal */
		*wrote = snprintf(buffer, size, "%o", (mode & (~S_IFMT)));
		break;
	case 'M':	/* file access mode */
		*wrote = snprintf_access_mode(buffer, size, mode);
		break;
	case 'n':	/* number of hard links */
		if (printf_scan_striped_dir(param, path))
			break;
		*wrote = snprintf(buffer, size, "%u",
				  param->fp_lmd->lmd_stx.stx_nlink);
		break;
	case 'p':	/* Path name of file */
		/* the two format parsers can disagree: never print NULL */
		if (!path)
			break;
		*wrote = snprintf(buffer, size, "%s", path);
		break;
	case 's':	/* file size (in bytes) */
		if (printf_scan_lacks(param, path, STATX_SIZE,
				      OBD_MD_FLLAZYSIZE))
			break;
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
			struct passwd pwd;
			struct passwd *pw = NULL;
			char pbuf[4096];

			getpwuid_r(param->fp_lmd->lmd_stx.stx_uid, &pwd,
				   pbuf, sizeof(pbuf), &pw);
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
 * What a -printf format asks for, and whether it asks for the path.
 *
 * Every directive but %p is answered from the record a scan delivers, so a
 * target scan refuses only a format that names the path.  The mask collects
 * what those directives read beyond the fields every record carries; a walk
 * gathers all of it whatever the format says and has no use for the mask.
 */
static __u64 printf_format_want(const char *fmt, bool *needs_path)
{
	const char *c = fmt;
	__u64 want = 0;
	char *end;

	if (needs_path)
		*needs_path = false;

	while (*c != '\0') {
		if (*c++ != '%')
			continue;

		/* skip what parse_format_width() skips: '-'s, then strtol() */
		while (*c == '-')
			c++;
		(void)strtol(c, &end, 10);
		c = end;

		switch (*c) {
		case '\0':
			return want;
		case 'p':	/* the path as walked */
			if (needs_path)
				*needs_path = true;
			break;
		case 's':
			want |= LLAPI_SCAN_SIZE | LLAPI_SCAN_LAZY_SIZE;
			break;
		case 'b':
		case 'k':
			want |= LLAPI_SCAN_BLOCKS | LLAPI_SCAN_LAZY_BLOCKS;
			break;
		case 'n':
		case 'a': case 'A':
		case 'c': case 'C':
		case 't': case 'T':
			/* for printf_scan_striped_dir() */
			want |= LLAPI_SCAN_LMV;
			break;
		case 'L':
			/*
			 * Whether a %L directive is answered from the layout
			 * or from the directory stripe is the object's own
			 * mode, so a format carrying one asks for both.
			 */
			if (c[1] != '\0' && strchr("chiOopS", c[1]))
				want |= LLAPI_SCAN_LAYOUT | LLAPI_SCAN_LMV;
			break;
		}

		/*
		 * One character consumed whatever it was: %% leaves the
		 * second per cent a literal, and the second character of a
		 * two-character directive is not a directive itself.
		 */
		c++;
	}

	return want;
}

/*
 * Double the -printf buffer, keeping what it holds.  %LO and %Lo can need
 * more than FORMATTED_BUF_LEN for a wide or overstriped file.
 */
static bool printf_buf_grow(char **output, size_t *len, const char *stack,
			    char **buff, size_t *buff_size)
{
	size_t used = *buff - *output;
	char *grown;

	if (*len >= FORMATTED_BUF_MAX)
		return false;
	grown = malloc(*len * 2);
	if (!grown)
		return false;
	memcpy(grown, *output, used);
	if (*output != stack)
		free(*output);
	*output = grown;
	*len *= 2;
	*buff = grown + used;
	*buff_size = *len - used;

	return true;
}

/*
 * Parse user-supplied string for the -printf option and interpret any
 * '%' format specifiers or '\' escape sequences.
 *
 * @param[in]	param	The find_param struct containing the -printf string
 *			as well as info about the current file/dir that mathced
 *			the lfs find search criteria
 * @param[in]	rec	The record the object was delivered in
 * @param[in]	path	Path name for current file/dir, NULL for a target scan
 * @param[in]	projid	Project ID associated with current file/dir
 * @param[in]	d	File descriptor for current directory (or -1 for a
 *			non-directory file)
 */
static void printf_format_string(struct find_param *param,
				 const struct llapi_scan_rec *rec, char *path,
				 __u32 projid, int d)
{
	char stack_buf[FORMATTED_BUF_LEN];
	char *output = stack_buf;
	size_t output_len = sizeof(stack_buf);
	char *fmt_char = param->fp_format_printf_str;
	char *buff = output;
	size_t buff_size;
	int rc, written;

	buff = output;
	*buff = '\0';
	buff_size = FORMATTED_BUF_LEN;

	/* Always leave one free byte in buffer for trailing NUL */
	while (*fmt_char) {
		/* strftime() prints nothing rather than part of a time */
		if (buff_size < FORMATTED_BUF_ROOM)
			printf_buf_grow(&output, &output_len, stack_buf,
					&buff, &buff_size);
		if (buff_size <= 1)
			break;
		rc = 0;
		written = 0;
		if (*fmt_char == '%') {
			rc = printf_format_directive(fmt_char + 1, buff,
						  buff_size, &written, param,
						  rec, path, projid, d);
			/* the directive filled what was left: grow, redo */
			if (rc > 0 && (size_t)written + 1 >= buff_size &&
			    printf_buf_grow(&output, &output_len, stack_buf,
					    &buff, &buff_size))
				continue;
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
			goto out;
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
out:
	if (output != stack_buf)
		free(output);
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
int get_projid(const char *path, int *fd, mode_t mode, __u32 *projid)
{
	struct fsxattr fsx = { 0 };
	struct lu_project lu_project = { 0 };
	int ret = 0;
	int rc;

	/* Check the mode of the file */
	if (S_ISREG(mode) || S_ISDIR(mode)) {
		/* This is a regular file type or directory */
		if (*fd < 0) {
			/* If we haven't yet opened the file,
			 * open it in read-only mode
			 */
			*fd = open(path, O_RDONLY | O_NOCTTY | O_NDELAY);
			if (*fd <= 0) {
				/*
				 * LLAPI_MSG_DEBUG marks this diagnostic
				 * rather than an error: failing to open is
				 * an ordinary outcome for an object the
				 * caller cannot open, and scan_rec_gather()
				 * answers it by leaving LLAPI_SCAN_PROJID
				 * clear rather than by reporting.
				 *
				 * The level does not quiet it by itself.
				 * llapi_msg_level starts at LLAPI_MSG_MAX
				 * and neither lfs nor lfind lowers it, so
				 * the line still prints; what the level
				 * buys is a caller able to silence it with
				 * llapi_msg_set_level().
				 */
				llapi_error(LLAPI_MSG_DEBUG, -ENOENT,
					    "%s: unable to open file \"%s\" to get project id",
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
			llapi_error(LLAPI_MSG_DEBUG, -ENOENT,
				    "%s: unable to open dir \"%s\" to get project id",
				    __func__, path);
			return -errno;
		}
		lu_project.project_type = LU_PROJECT_GET;
		if (base_name)
			strncpy(lu_project.project_name, base_name, NAME_MAX);

		ret = ioctl(dir_fd, LL_IOC_PROJECT, &lu_project);
		/*
		 * Kept before the close(): a close() that fails -- EINTR, or
		 * EIO from a flush -- sets errno of its own, and this errno
		 * picks the branch below.
		 */
		rc = -errno;
		close(dir_fd);
		if (ret) {
			/*
			 * LL_IOC_PROJECT is Lustre's own number, so a parent
			 * that is not on Lustre answers ENOTTY.  Having no
			 * project id is what an object there is rather than a
			 * failure to report, as with its FID and its layout.
			 */
			if (rc != -ENOTTY)
				llapi_error(LLAPI_MSG_DEBUG, rc,
					    "%s: failed to get xattr for '%s'",
					    __func__, path);
			return rc;
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

/*
 * The pre-filters: what lfs find can decide from the directory entry alone,
 * before any I/O on the object.  --name against the entry name, -type
 * against d_type when the filesystem supplied one, and the directory-stripe
 * options against it too -- --mdt-count and --mdt-hash can only match a
 * directory, so anything else is rejected here rather than gathered for.
 *
 * *@checked_type says whether -type was settled here; if not, it is settled
 * against the MDT's mode later.
 *
 * Note the sense: true is a rejection, which is the opposite of the
 * `decision` find_decide() carries and of what find_check_layout() and
 * find_value_cmp() return.  Those answer "does this predicate accept the
 * object"; this answers "is the object settled already", and false is the
 * case that goes on to the MDT, so the two cannot share one convention.
 * bool rather than int for that reason: nothing here can fail, so there is
 * no errno to return, and a caller cannot mistake this answer for one.
 *
 * Return: true to reject the object here, false to go on and gather.
 */
static bool find_prefilter(const struct llapi_scan_rec *rec,
			   struct find_param *param, int *checked_type)
{
	/* a scanned object may have no name: find_device_prefilter() counts
	 * it undecided for -name
	 */
	if (param->fp_pattern && rec->lfsr_name) {
		int rc = fnmatch(param->fp_pattern, rec->lfsr_name, 0);

		if ((rc == FNM_NOMATCH && !param->fp_exclude_pattern) ||
		    (rc == 0 && param->fp_exclude_pattern))
			return true;
	}

	if (rec->lfsr_stx.stx_mask & STATX_TYPE) {
		mode_t type = rec->lfsr_stx.stx_mode & S_IFMT;

		if (param->fp_type != 0) {
			*checked_type = 1;
			if (type == param->fp_type) {
				if (param->fp_exclude_type)
					return true;
			} else {
				if (!param->fp_exclude_type)
					return true;
			}
		}
		if ((param->fp_check_mdt_count || param->fp_hash_type ||
		     param->fp_check_hash_flag) && type != S_IFDIR)
			return true;
	}

	return false;
}

/*
 * The demand mask: which of the record's fields lfs find will need for
 * this search, in the LLAPI_SCAN_* bits llapi_scan_namespace() takes --
 * but not with its convention for 0, which there means "the scanner's
 * default" and here means "nothing, so do not gather at all".  A caller
 * passing this to lfsp_want has to widen 0 itself, or turn the cheapest
 * search there is into the most expensive one.  This is the same test
 * cb_find_init() has always made before deciding whether to ask the MDT
 * at all; it now says what to ask for as well.
 */
static __u64 find_want(struct find_param *param, int checked_type,
		       bool gather_all)
{
	__u64 want = 0;

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
		want = LLAPI_SCAN_MDT_MASK;

	if (param->fp_type != 0 && checked_type == 0)
		want = LLAPI_SCAN_MDT_MASK;

	if (want == 0)
		return 0;

	/*
	 * cb_get_dirstripe is needed when checking nlink because nlink is
	 * handled differently for multi-stripe directory vs. single-stripe
	 * directory.
	 */
	if (!(param->fp_check_mdt_count || param->fp_hash_type ||
	      param->fp_check_hash_flag || param->fp_check_foreign ||
	      param->fp_nlink || gather_all))
		want &= ~(LLAPI_SCAN_LMV | LLAPI_SCAN_LMV_FOREIGN);
	if (!(param->fp_mdt_uuid != NULL || gather_all))
		want &= ~LLAPI_SCAN_MDT_INDEX;
	/* both cost an open: projid is fetched on demand, HSM is unused */
	want &= ~(LLAPI_SCAN_PROJID | LLAPI_SCAN_HSM);

	return want;
}

/*
 * The checks that need only the directory's LMV.  Run before the stat RPC,
 * so a directory they reject costs no more than the LMV fetch.
 *
 * Return: true if the object is rejected.
 */
static bool find_lmv_rejects(const struct find_param *param, bool have_lmv)
{
	struct lmv_user_md *lmv = param->fp_lmv_md;

	if (!param->fp_get_lmv)
		return false;

	/*
	 * No stripe of its own, so not foreign: rejected by --foreign, while
	 * with "! --foreign" the other checks still apply.
	 */
	if (!have_lmv && param->fp_check_foreign &&
	    !param->fp_exclude_foreign)
		return true;

	if (param->fp_check_mdt_count) {
		if (lmv_is_foreign(lmv->lum_magic))
			return true;

		if (find_value_cmp(lmv->lum_stripe_count,
				   param->fp_mdt_count,
				   param->fp_mdt_count_sign,
				   param->fp_exclude_mdt_count, 1, 0) == -1)
			return true;
	}

	if (param->fp_hash_type) {
		__u32 type = lmv->lum_hash_type & LMV_HASH_TYPE_MASK;
		__u32 found;

		if (lmv_is_foreign(lmv->lum_magic))
			return true;

		found = (1 << type) & param->fp_hash_type;
		if ((found && param->fp_exclude_hash_type) ||
		    (!found && !param->fp_exclude_hash_type))
			return true;
	}

	if (param->fp_check_hash_flag) {
		__u32 flags = lmv->lum_hash_type & ~LMV_HASH_TYPE_MASK;

		if (lmv_is_foreign(lmv->lum_magic))
			return true;

		if (!(flags & param->fp_hash_inflags) ||
		    (flags & param->fp_hash_exflags))
			return true;
	}

	return false;
}

/*
 * What find_decide() needs beyond struct find_param: where the object came
 * from, and what the gather settled.  A scan of a target fills it with
 * fc_path NULL and no descriptors.  Every caller sets fc_p and fc_d: 0 is
 * a descriptor, so zero-initialising them is not "none".
 */
struct find_ctx {
	const struct llapi_scan_rec *fc_rec;
	char			*fc_path;	/* NULL: no namespace walked */
	struct dirent64		*fc_de;
	int			 fc_p;		/* parent fd, or -1 */
	int			 fc_d;		/* directory fd, or -1 */
	int			*fc_fdp;	/* fd to reuse, or NULL */
	__u32			 fc_stripe_count;
	int			 fc_lustre_fs;
	int			 fc_checked_type;
	bool			 fc_gather_all;
	bool			 fc_undecided;	/* out: nothing settled it */
};

/*
 * The project id: an open and an ioctl for a walk, free for a scan.
 *
 * -ENOTSUP means there is no path to open, or no fd slot to keep the open
 * in, so no project id can be read.
 * An -ENOTSUP from the ioctl itself always comes with a path.  -ENOTTY
 * comes from get_projid() and means the object is not on Lustre.
 */
static int find_get_projid(struct find_ctx *fc, mode_t mode, __u32 *projid)
{
	if (fc->fc_rec->lfsr_valid & LLAPI_SCAN_PROJID) {
		*projid = fc->fc_rec->lfsr_projid;
		return 0;
	}
	if (fc->fc_path == NULL || fc->fc_fdp == NULL)
		return -ENOTSUP;

	return get_projid(fc->fc_path, fc->fc_fdp, mode, projid);
}

/*
 * Everything from the MDT's answer onwards: the checks that need it, the
 * glimpse for what only a stat can settle, and the printing.  Split out so
 * that a scan with no namespace behind it can reach it too.
 *
 * A target scan passes no path.  find_get_projid() tests fc_path itself,
 * and the other steps that take it are kept from NULL elsewhere: --xattr is
 * refused before the scan, setup_target_indexes() runs only where
 * lustre_fs is set, which a scan leaves 0, the stat arm counts the object
 * undecided when there is no path, descriptor or dirent, and the printing
 * tests the path where it needs one.
 *
 * Return: 0 once the object is decided, printed or rejected, or a negative
 * errno.  Which of the two it was is not reported: printing is the answer,
 * and no caller has ever read it.  No positive: cb_find_init() acts only
 * on a negative and then sets its own return, so a positive would be lost.
 */
static int find_decide(struct find_ctx *fc, struct find_param *param)
{
	struct lov_user_mds_data *lmd = param->fp_lmd;
	char *path = fc->fc_path;
	struct dirent64 *de = fc->fc_de;
	int p = fc->fc_p;
	int d = fc->fc_d;
	__u32 stripe_count = fc->fc_stripe_count;
	int lustre_fs = fc->fc_lustre_fs;
	int checked_type = fc->fc_checked_type;
	bool gather_all = fc->fc_gather_all;
	__u32 projid = DEFAULT_PROJID;
	bool no_projid = false;	/* the object has none, not one that is 0 */
	int decision = 1;	/* 1 is accepted; -1 is rejected. */
	bool size_elsewhere;
	int ret = 0;
	__u64 flags;

	/* a walk ran this before the stat; other callers did not */
	if (find_lmv_rejects(param, fc->fc_rec->lfsr_valid & LLAPI_SCAN_LMV))
		return 0;

	/* Check the file permissions from the stat info */
	if (param->fp_perm_sign) {
		decision = check_file_permissions(param, lmd->lmd_stx.stx_mode);
		if (decision == -1)
			return 0;
	}

	if (param->fp_type && !checked_type) {
		if ((param->fp_check_mdt_count || param->fp_check_hash_flag ||
		     param->fp_hash_type) && !S_ISDIR(lmd->lmd_stx.stx_mode))
			return 0;

		if ((lmd->lmd_stx.stx_mode & S_IFMT) == param->fp_type) {
			if (param->fp_exclude_type)
				return 0;
		} else {
			if (!param->fp_exclude_type)
				return 0;
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
				return ret;

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
			return 0;
	}

	if (param->fp_check_stripe_size) {
		decision = find_check_stripe_size(param);
		if (decision == -1)
			return 0;
	}

	if (param->fp_check_ext_size) {
		decision = find_check_ext_size(param);
		if (decision == -1)
			return 0;
	}

	if (param->fp_check_stripe_count) {
		decision = find_value_cmp(stripe_count, param->fp_stripe_count,
					  param->fp_stripe_count_sign,
					  param->fp_exclude_stripe_count, 1, 0);
		if (decision == -1)
			return 0;
	}

	if (param->fp_check_layout) {
		decision = find_check_layout(param);
		if (decision == -1)
			return 0;
	}

	/* If an OBD UUID is specified but none matches, skip this file. */
	if ((param->fp_obd_uuid && param->fp_obd_index == OBD_NOT_FOUND) ||
	    (param->fp_mdt_uuid && param->fp_mdt_index == OBD_NOT_FOUND))
		return 0;

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
				return 0;
			}
		}

		if (param->fp_mdt_uuid) {
			if (check_mdt_match(param))
				goto obd_matches;
			return 0;
		}
	}

obd_matches:
	if (param->fp_check_uid) {
		if (lmd->lmd_stx.stx_uid == param->fp_uid) {
			if (param->fp_exclude_uid)
				return 0;
		} else {
			if (!param->fp_exclude_uid)
				return 0;
		}
	}

	if (param->fp_check_gid) {
		if (lmd->lmd_stx.stx_gid == param->fp_gid) {
			if (param->fp_exclude_gid)
				return 0;
		} else {
			if (!param->fp_exclude_gid)
				return 0;
		}
	}

	/*
	 * Retrieve project id from file/dir.
	 *
	 * A target scan asks for it when the format prints it, which is free
	 * where the record carries one: find_get_projid() answers out of the
	 * record without an open.  Where it does not, the block is skipped
	 * and %LP prints DEFAULT_PROJID, as a walk off Lustre already does --
	 * an object with no project id is not a reason to drop it from a
	 * format whose other directives it can answer.  A walk never reaches
	 * this arm: -printf sets gather_all there.
	 */
	if (param->fp_check_projid || gather_all ||
	    (param->fp_format_printf_str &&
	     (fc->fc_rec->lfsr_valid & LLAPI_SCAN_PROJID))) {
		ret = find_get_projid(fc, lmd->lmd_stx.stx_mode, &projid);
		if (ret == -ENOTSUP && !path) {
			/*
			 * A scan with no path to open: the target answered no
			 * project id, which an inode whose i_extra_isize does
			 * not reach i_projid genuinely has none of.  Neither a
			 * match nor a miss, as an unglimpsable size is.  This
			 * holds for ! --projid N too, unlike ! -btime: a walk
			 * is told the kernel's default of 0 for such an inode,
			 * so ! --projid 0 would not match it there.
			 */
			fc->fc_undecided = true;
			return 0;
		}
		/*
		 * And a walk that crossed off Lustre, where the fetch cannot
		 * answer at all: the special-file arm asks LL_IOC_PROJECT of
		 * a parent that does not have it, and the regular arm asks
		 * FS_IOC_FSGETXATTR of a tmpfs, which only answers it from
		 * Linux v6.0.  Both are ENOTTY.  A search that asked for a
		 * project id cannot be answered for such an object, so
		 * --projid N does not match; ! --projid N does, and one that
		 * only prints it prints DEFAULT_PROJID.
		 *
		 * Reachable because -printf sets gather_all: left as an
		 * error, the walk would exit non-zero on the first symlink
		 * under the subtree, and on a pre-v6.0 client on the first
		 * regular file.
		 */
		if (ret == -ENOTTY) {
			/*
			 * --projid N cannot be answered for an object that
			 * has no project id at all, so it does not match.
			 * ! --projid N can be: whatever the object's is, it
			 * is not N.  Dropping it from the negated form too
			 * made this disagree with -printf, which already
			 * prints DEFAULT_PROJID for the same object.
			 */
			if (param->fp_check_projid &&
			    !param->fp_exclude_projid)
				return 0;
			projid = DEFAULT_PROJID;
			no_projid = true;
			ret = 0;
		}
		if (ret) {
			llapi_error(LLAPI_MSG_ERROR, -ENOENT,
				    "warning: %s: failed to get project id from file \"%s\"",
				    __func__, path ? path : "");
			return ret;
		}
		/*
		 * An object with no project id has nothing to compare, so
		 * only the negated form answers for it: its projid is not N
		 * because it has none.  DEFAULT_PROJID is -printf's stand-in
		 * and is never compared.
		 */
		if (param->fp_check_projid && !no_projid) {
			/* Conditionally filter this result based on --projid
			 * param, and whether or not we're including or
			 * excluding matching results.
			 * fp_exclude_projid = 0 means only include exact match.
			 * fp_exclude_projid = 1 means exclude exact match.
			 */
			bool matches = projid == param->fp_projid;

			if (matches == param->fp_exclude_projid)
				return 0;
		}
	}

	if (param->fp_check_pool) {
		decision = find_check_pool(param);
		if (decision == -1)
			return 0;
	}

	if (param->fp_check_comp_count || param->fp_check_comp_flags ||
	    param->fp_check_comp_start || param->fp_check_comp_end) {
		decision = find_check_comp_options(param);
		if (decision == -1)
			return 0;
	}

	if (param->fp_check_mirror_count || param->fp_check_mirror_state) {
		decision = find_check_mirror_options(param);
		if (decision == -1)
			return 0;
	}

	/* Check the time on mds. */
	decision = 1;
	if (param->fp_atime || param->fp_mtime || param->fp_ctime) {
		int for_mds;

		for_mds = lustre_fs ?
			  (S_ISREG(lmd->lmd_stx.stx_mode) && stripe_count) : 0;
		decision = find_time_check(param, for_mds);
		if (decision == -1)
			return 0;
	}

	if (param->fp_btime) {
		if (!(lmd->lmd_stx.stx_mask & STATX_BTIME)) {
			/*
			 * An object with no birth time -- an inode whose
			 * i_extra_isize does not reach i_crtime, or anything
			 * on a filesystem that is not Lustre -- cannot match
			 * a birth time.  It does not match, and the search
			 * carries on: ending it here, after matches have
			 * already been printed, is the wrong answer, and on a
			 * walk the error reaches llapi_semantic_traverse()
			 * and takes the whole subtree with it.
			 *
			 * ! -btime does match it, as for find(1) and as for
			 * --projid above: the negation of a false test.
			 *
			 * Not on a target scan.  Over a mount the MDS gives
			 * such an inode a birth time of 0, so a walk answers
			 * both forms from that.  The scan cannot say what the
			 * mount would, and counts both forms undecided.
			 */
			if (!path) {
				fc->fc_undecided = true;
				return 0;
			}
			if (param->fp_exclude_btime)
				goto btime_done;
			return 0;
		}

		decision = find_value_cmp(lmd->lmd_stx.stx_btime.tv_sec,
					  param->fp_btime, param->fp_bsign,
					  param->fp_exclude_btime,
					  param->fp_time_margin, 0);
		if (decision == -1)
			return 0;
	}
btime_done:

	if (param->fp_newerxy) {
		int for_mds;

		/* both forms undecided on a scan, as for -btime above */
		if (!path && !(lmd->lmd_stx.stx_mask & STATX_BTIME) &&
		    (param->fp_newery[NEWERXY_BTIME][0] ||
		     param->fp_newery[NEWERXY_BTIME][1])) {
			fc->fc_undecided = true;
			return 0;
		}
		for_mds = lustre_fs ?
			  (S_ISREG(lmd->lmd_stx.stx_mode) && stripe_count) : 0;
		decision = find_newerxy_check(param, for_mds, true);
		if (decision == -1)
			return 0;
		if (decision < 0) {
			/* -newerbY with no birth time, on a walk: no match */
			if (decision == -EOPNOTSUPP)
				return 0;
			ret = decision;
			return ret;
		}
	}

	if (param->fp_attrs || param->fp_neg_attrs) {
		decision = find_check_attr_options(param);
		if (decision == -1)
			return 0;
	}

	flags = param->fp_lmd->lmd_flags;
	/*
	 * A walk knows a size is elsewhere from the stripes it read.  A scan
	 * of a target has only what the scan reported, so a size it left out
	 * is undecided whatever the layout says: a file whose layout does not
	 * parse, or one the scanner has no answer for, has a stripe count of
	 * 0 too, and its stx_size is not a size.
	 */
	size_elsewhere = !path || S_ISDIR(lmd->lmd_stx.stx_mode) ||
			 (S_ISREG(lmd->lmd_stx.stx_mode) && stripe_count);
	if (param->fp_check_size && size_elsewhere &&
	    !(flags & OBD_MD_FLSIZE ||
	      (param->fp_lazy && flags & OBD_MD_FLLAZYSIZE)))
		decision = 0;

	if (param->fp_check_blocks && size_elsewhere &&
	    !(flags & OBD_MD_FLBLOCKS ||
	      (param->fp_lazy && flags & OBD_MD_FLLAZYBLOCKS)))
		decision = 0;

	if (param->fp_xattr_match_info) {
		decision = find_check_xattrs(path, param->fp_xattr_match_info);
		if (decision == -1)
			return 0;
	}

	/*
	 * When checking nlink, stat(2) is needed for multi-striped directories
	 * because the nlink value retrieved from the MDS above comes from
	 * the number of stripes for the dir.
	 * The posix stat call below fills in the correct number of links.
	 * Single-stripe directories and regular files already have the
	 * correct nlink value.
	 *
	 * A foreign LMV has no stripe count: lfm_length sits where
	 * lum_stripe_count does, so reading it here asks for a stat the
	 * object does not need.  A walk pays one and answers correctly; a
	 * scan has nothing to stat and drops the object instead.
	 */
	if (param->fp_nlink && S_ISDIR(lmd->lmd_stx.stx_mode) &&
	    !lmv_is_foreign(param->fp_lmv_md->lum_magic) &&
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
		 * What is left needs a stat and there is nothing to stat: no
		 * path, no descriptor.  Undecided, being neither a match nor
		 * a miss.
		 */
		if (!path && d == -1 && !de) {
			fc->fc_undecided = true;
			return 0;
		}

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
				return 0;
			} else {
				ret = -errno;
				llapi_error(LLAPI_MSG_ERROR, ret,
					    "%s: stat on %s failed",
					    __func__, path);
				return ret;
			}
		}

		convert_lmd_statx(param->fp_lmd, &st, true);
		/* Check the time on osc. */
		decision = find_time_check(param, 0);
		if (decision == -1)
			return 0;

		if (param->fp_newerxy) {
			decision = find_newerxy_check(param, 0, false);
			if (decision == -1)
				return 0;
			if (decision < 0) {
				ret = decision;
				return ret;
			}
		}
	}

	if (param->fp_nlink) {
		decision = find_value_cmp(lmd->lmd_stx.stx_nlink,
					  param->fp_nlink, param->fp_nlink_sign,
					  param->fp_exclude_nlink, 1, 0);
		if (decision == -1)
			return 0;
	}

	if (param->fp_check_size) {
		decision = find_value_cmp(lmd->lmd_stx.stx_size,
					  param->fp_size,
					  param->fp_size_sign,
					  param->fp_exclude_size,
					  param->fp_size_units, 0);
		if (decision == -1)
			return 0;
	}

	if (param->fp_check_blocks) { /* convert st_blocks to bytes */
		decision = find_value_cmp(lmd->lmd_stx.stx_blocks * 512,
					  param->fp_blocks,
					  param->fp_blocks_sign,
					  param->fp_exclude_blocks,
					  param->fp_blocks_units, 0);
		if (decision == -1)
			return 0;
	}

	if (param->fp_skip_percent && find_skip_file(param))
		return 0;

	if (param->fp_format_printf_str)
		printf_format_string(param, fc->fc_rec, path, projid, d);
	else if (path)
		llapi_printf(LLAPI_MSG_NORMAL, "%s%c", path,
			     param->fp_zero_end ? '\0' : '\n');
	else if (fc->fc_rec->lfsr_valid & LLAPI_SCAN_FID)
		/* no path was walked to it: its FID is the name it has */
		llapi_printf(LLAPI_MSG_NORMAL, DFID"%c",
			     PFID(&fc->fc_rec->lfsr_fid),
			     param->fp_zero_end ? '\0' : '\n');
	else if (fc->fc_rec->lfsr_valid & LLAPI_SCAN_INO)
		/*
		 * No trusted.lma, so no FID: printing DFID would name every
		 * such object [0x0:0x0:0x0].  Under --internal these are
		 * reachable, and the target's own id is the only name they
		 * have.
		 */
		llapi_printf(LLAPI_MSG_NORMAL, "obj:%llu%c",
			     (unsigned long long)fc->fc_rec->lfsr_ino,
			     param->fp_zero_end ? '\0' : '\n');

	return 0;
}

/* ------------------------------------------------------------------ */
/* The same predicates, over a scan of a target's own objects           */

struct find_device_state {
	struct find_param	*fds_param;
	__u64			 fds_undecided;
};

/*
 * What only the mounted filesystem can answer: the xattrs --xattr reads
 * through a path.  Refused before the scan, since afterwards "no matches" and
 * "cannot answer" look alike.  --ost and --mdt are decided against the
 * target's own label instead; see find_device_targets().
 */
static int find_device_supported(const struct find_param *param)
{
	const char *what = NULL;

	if (param->fp_xattr_match_info) {
		llapi_error(LLAPI_MSG_ERROR | LLAPI_MSG_NO_ERRNO, -ENOTSUP,
			    "--xattr needs a mounted filesystem");
		return -ENOTSUP;
	}

	if (param->fp_format_printf_str) {
		bool needs_path;

		/*
		 * Only %p needs the path.  Every other directive is answered
		 * from the record -- the FID, the ids, the timestamps and the
		 * layout among them -- and printing those per object is most
		 * of what -printf is for.
		 */
		printf_format_want(param->fp_format_printf_str, &needs_path);
		if (needs_path) {
			llapi_error(LLAPI_MSG_ERROR | LLAPI_MSG_NO_ERRNO,
				    -ENOTSUP,
				    "-printf %%p needs a path, which a target scan has not");
			return -ENOTSUP;
		}
	}

	/*
	 * A scan has no depth and pins its own thread count.  Refused, not
	 * ignored.  0 too: llapi_find_param_alloc() zeroes it.
	 */
	if ((param->fp_max_depth != (unsigned int)-1 &&
	     param->fp_max_depth != 0) || param->fp_min_depth != 0)
		what = "--maxdepth and --mindepth";
	else if (param->fp_thread_count != 0)
		what = "--threads";

	if (what) {
		llapi_error(LLAPI_MSG_ERROR | LLAPI_MSG_NO_ERRNO, -ENOTSUP,
			    "%s describes a walk, which a target scan is not",
			    what);
		return -ENOTSUP;
	}

	return 0;
}

/*
 * The searches that need a directory's stripe.  cb_find_init() tests the same
 * set before calling cb_get_dirstripe(), and gather_all with it; a target
 * scan asks for LLAPI_SCAN_LMV itself where -printf needs it.
 */
static bool find_needs_lmv(const struct find_param *param)
{
	return param->fp_check_mdt_count || param->fp_hash_type ||
	       param->fp_check_hash_flag || param->fp_check_foreign ||
	       param->fp_nlink;
}

/*
 * The index a name asks for, resolved against the one target being scanned.
 *
 * A mount resolves a UUID by asking the filesystem for its whole target list,
 * which is what setup_indexes() is for; a scan has one target and its label,
 * and whether that is the target the name means is all a search here needs to
 * know.  A decimal index needs no resolving and is taken as given.
 *
 * A name this target does not answer to resolves to OBD_NOT_FOUND, which no
 * record's index can equal, so the predicate comes out false for every object
 * and true for every object under its negation.  That is the difference from
 * a walk, where an unresolvable name is a user error: over a scan, a name for
 * some other target is not wrong, it is how a caller sweeps a list of devices
 * with one predicate and has each skip the ones that cannot hold a match.
 */
static int find_tgt_index(const struct llapi_scan_tgt *tgt, char *name)
{
	char label[sizeof(tgt->tt_label)];
	char *end = NULL;
	size_t len;
	long idx;

	idx = strtol(name, &end, 0);
	if (end && *end == '\0' && end != name && idx >= 0 &&
	    idx < LOV_V1_INSANE_STRIPE_COUNT)
		return (int)idx;

	/* compare as mounted: fsname=OST0001 is fsname-OST0001's target */
	snprintf(label, sizeof(label), "%s", tgt->tt_label);
	len = strlen(label);
	if (len >= 8)
		label[len - 8] = '-';
	if (llapi_uuid_match(label, name))
		return (int)tgt->tt_index;

	return OBD_NOT_FOUND;
}

/*
 * --ost and --mdt against the target being scanned, rather than against a
 * mount's target list.
 *
 * A scan reads one target, so these predicates are about that target and not
 * about each object: every object an MDT scan delivers is on that MDT, and
 * every object an OST scan delivers is on that OST.  Which of the two the
 * predicate can be asked of is the target's own kind -- an OST object's MDT
 * is an FLD lookup this has no client to make, and which OSTs a file is
 * striped over is in its layout, which is a different question from the one
 * answered here -- so the other way round is refused rather than answered
 * wrongly.
 *
 * --mdt is left to check_mdt_match(), which compares the resolved indices
 * against fp_file_mdt_index; the caller sets that from the target.  --ost is
 * answered here instead: check_obd_match() reads the layout, and an OST data
 * object has none, so it would reject every object of a target that is the
 * one asked for.
 *
 * Return: 1 for a search no object on this target can match, 0 to go on, or
 * a negative errno.
 */
static int find_device_targets(struct find_param *param,
			       const struct llapi_scan_tgt *tgt)
{
	bool is_mdt = !!(tgt->tt_flags & LLAPI_SCAN_TGT_MDT);
	bool matched = false;
	int *indexes;
	int i;

	/* not a target at all: the errno llapi_scan_device() gives it */
	if (!(tgt->tt_flags & (LLAPI_SCAN_TGT_MDT | LLAPI_SCAN_TGT_OST))) {
		llapi_error(LLAPI_MSG_ERROR | LLAPI_MSG_NO_ERRNO, -EINVAL,
			    "label '%s' names no MDT or OST", tgt->tt_label);
		return -EINVAL;
	}

	if (!(tgt->tt_flags & LLAPI_SCAN_TGT_INDEX)) {
		llapi_error(LLAPI_MSG_ERROR | LLAPI_MSG_NO_ERRNO, -ENOTSUP,
			    "%s: label '%s' carries no target index for --ost or --mdt",
			    is_mdt ? "MDT" : "OST", tgt->tt_label);
		return -ENOTSUP;
	}

	/* both refusals first, so every device of a sweep gives the same one */
	if (param->fp_mdt_uuid && !is_mdt) {
		llapi_error(LLAPI_MSG_ERROR | LLAPI_MSG_NO_ERRNO, -ENOTSUP,
			    "--mdt needs an MDT; '%s' is an OST, whose objects name their MDT only through an FLD lookup",
			    tgt->tt_label);
		return -ENOTSUP;
	}
	if (param->fp_obd_uuid && is_mdt) {
		llapi_error(LLAPI_MSG_ERROR | LLAPI_MSG_NO_ERRNO, -ENOTSUP,
			    "--ost needs an OST; over '%s' it would ask which OSTs a file is striped over, which this search does not answer",
			    tgt->tt_label);
		return -ENOTSUP;
	}

	if (param->fp_mdt_uuid) {
		indexes = calloc(param->fp_num_mdts, sizeof(*indexes));
		if (!indexes)
			return -ENOMEM;
		for (i = 0; i < param->fp_num_mdts; i++)
			indexes[i] = find_tgt_index(tgt,
						    param->fp_mdt_uuid[i].uuid);
		free(param->fp_mdt_indexes);
		param->fp_mdt_indexes = indexes;
		/*
		 * Every name is resolved, even to OBD_NOT_FOUND.  While
		 * fp_mdt_index is OBD_NOT_FOUND, find_decide() drops every
		 * object, even under the negation, which such a name matches.
		 */
		param->fp_mdt_index = param->fp_num_mdts;

		/* every object here has this MDT's index, as --ost below */
		for (i = 0; i < param->fp_num_mdts; i++) {
			if (indexes[i] == (int)tgt->tt_index) {
				matched = true;
				break;
			}
		}
		if (matched == !!param->fp_exclude_mdt)
			return 1;
		matched = false;
	}

	if (param->fp_obd_uuid) {
		for (i = 0; i < param->fp_num_obds; i++) {
			if (find_tgt_index(tgt, param->fp_obd_uuid[i].uuid) ==
			    (int)tgt->tt_index) {
				matched = true;
				break;
			}
		}

		if (matched == !!param->fp_exclude_obd)
			/* nothing on this target can match */
			return 1;
		/*
		 * Every object can, so the predicate is answered and the scan
		 * must not ask check_obd_match() for a second opinion off a
		 * layout an OST object does not have.  The caller puts it
		 * back.
		 */
		param->fp_obd_uuid = NULL;
	}

	return 0;
}

/*
 * The demand mask these predicates imply: what the object carries is free
 * and always asked for, an xattr only when a predicate reads it.
 */
static __u64 find_device_want(struct find_param *param)
{
	__u64 want = LLAPI_SCAN_FID | LLAPI_SCAN_INO | LLAPI_SCAN_CLASS |
		     LLAPI_SCAN_MODE | LLAPI_SCAN_TYPE | LLAPI_SCAN_NLINK |
		     LLAPI_SCAN_UID | LLAPI_SCAN_GID | LLAPI_SCAN_PROJID |
		     LLAPI_SCAN_ATIME | LLAPI_SCAN_MTIME | LLAPI_SCAN_CTIME |
		     LLAPI_SCAN_BTIME | LLAPI_SCAN_ATTRS;

	if (find_asks_layout(param) || param->fp_check_size ||
	    param->fp_check_blocks)
		want |= LLAPI_SCAN_LAYOUT;
	if (param->fp_check_size)
		want |= LLAPI_SCAN_SIZE | LLAPI_SCAN_LAZY_SIZE;
	if (param->fp_check_blocks)
		want |= LLAPI_SCAN_BLOCKS | LLAPI_SCAN_LAZY_BLOCKS;
	if (find_needs_lmv(param))
		want |= LLAPI_SCAN_LMV;
	if (param->fp_pattern)
		want |= LLAPI_SCAN_LINKEA;
	if (param->fp_format_printf_str)
		want |= printf_format_want(param->fp_format_printf_str, NULL);
	/* find_device_cb() skips a shard, so it has to know one */
	want |= LLAPI_SCAN_LMV_SHARD;

	return want;
}

/* No layout means the filesystem's default, which lfs find compares against. */
static void find_lmm_set_default(struct find_param *param)
{
	struct lov_user_md *lmm = &param->fp_lmd->lmd_lmm;

	lmm->lmm_magic = LOV_USER_MAGIC_V1;
	lmm->lmm_pattern = LOV_PATTERN_DEFAULT;
	if (!param->fp_raw)
		ostid_set_seq(&lmm->lmm_oi, FID_SEQ_LOV_DEFAULT);
	lmm->lmm_stripe_size = 0;
	lmm->lmm_stripe_count = 0;
	lmm->lmm_stripe_offset = -1;
	/*
	 * The bytes just written, so that a consumer sizing the layout by
	 * lmd_lmmsize -- llapi_layout_get_by_xattr() through %Lc and the
	 * rest -- is given the forgery's own length and not 0.
	 */
	param->fp_lmd->lmd_lmmsize = sizeof(struct lov_user_md_v1);
}

/*
 * The record's directory stripe, where the checks read it from.
 *
 * Both scanners hand over an lmv_user_md -- the namespace one from the
 * ioctl, the device one converted by scan_lmv_to_user() -- so this is a
 * bounded copy into the buffer find_check_* helpers read, and not a
 * conversion.
 *
 * A foreign directory arrives as a struct lmv_foreign_md instead, with
 * LLAPI_SCAN_LMV_FOREIGN set on the record, so every reader below tests
 * lmv_is_foreign() before it reads a field past the magic.
 */
static int find_rec_to_lmv(const struct llapi_scan_rec *rec,
			   struct find_param *param)
{
	__u32 hdr = lmv_user_md_size(0, LMV_USER_MAGIC_SPECIFIC);
	__u32 room = lmv_user_md_size(param->fp_lmv_stripe_count,
				      LMV_USER_MAGIC_SPECIFIC);

	/* the buffer is reused between objects, as the layout one is */
	memset(param->fp_lmv_md, 0, hdr);

	if (!(rec->lfsr_valid & LLAPI_SCAN_LMV) || !rec->lfsr_lmv ||
	    rec->lfsr_lmvsize == 0)
		return 0;

	/* a large foreign LMV: grow the buffer, as cb_get_dirstripe() does */
	if (rec->lfsr_lmvsize > room) {
		__u32 count = (rec->lfsr_lmvsize - hdr +
			       sizeof(struct lmv_user_mds_data) - 1) /
			      sizeof(struct lmv_user_mds_data);
		void *lmv = realloc(param->fp_lmv_md,
				    lmv_user_md_size(count,
						     LMV_USER_MAGIC_SPECIFIC));

		if (!lmv)
			return -ENOMEM;
		param->fp_lmv_md = lmv;
		param->fp_lmv_stripe_count = count;
	}

	memcpy(param->fp_lmv_md, rec->lfsr_lmv, rec->lfsr_lmvsize);
	return 0;
}

/*
 * Does the layout describe itself within the bytes it came in?
 *
 * These bytes are read off a target that may be in service, so an object can
 * be caught mid-update and the header can disagree with the buffer.  Every
 * consumer below walks the layout by that header -- find_check_comp_options()
 * over lcm_entry_count, find_get_stripe_count() through lcme_offset -- so a
 * torn composite EA claiming a large entry count would be read far past the
 * buffer it arrived in.  Nothing here trusts a field before the bytes holding
 * it have been accounted for.
 *
 * llapi_layout_lum_valid() is not this check: it weighs object counts against
 * a buffer the kernel produced, and reaches into lcm_entries[] to do it.
 */
static bool find_lmm_fits(const struct lov_user_md *lmm, __u32 size)
{
	const struct lov_comp_md_v1 *comp;
	__u32 magic, count, need;
	bool swap;
	__u32 i;

	/*
	 * Only lmm_magic is read before the switch; each arm checks the
	 * minimum size of its own magic.  A foreign layout's minimum,
	 * offsetof(lov_foreign_md, lfm_value), is smaller than
	 * lov_user_md_v1: `lfs setstripe --foreign=none --xattr=abc` stores
	 * a legal 19-byte trusted.lov.
	 */
	if (!lmm || size < sizeof(lmm->lmm_magic))
		return false;

	/*
	 * Run before the swab, so the byte order is whatever the target had.
	 * An unrecognised magic in either order is not a layout at all.
	 *
	 * The swapped set is layout_swab_lov_user_md()'s, deliberately: a
	 * top-level LOV_MAGIC_FOREIGN is not in it and comes back unswabbed,
	 * so accepting one here would leave a foreign EA -- an HSM-released
	 * or PCC file -- in the target's byte order with lmd_lmmsize set.
	 * find_check_foreign() would read the swapped lfm_magic and answer
	 * "not foreign", so --foreign would miss every such file on a
	 * big-endian host.  Refused instead: a layout predicate then counts
	 * the object undecided rather than answering it wrong.  A foreign
	 * magic in host order is still accepted below.
	 */
	magic = lmm->lmm_magic;
	swap = magic == __swab32(LOV_USER_MAGIC_V1) ||
	       magic == __swab32(LOV_USER_MAGIC_V3) ||
	       magic == __swab32(LOV_USER_MAGIC_COMP_V1);
	if (swap)
		magic = __swab32(magic);

#define FLF32(v) (swap ? __swab32(v) : (v))
#define FLF16(v) (swap ? __swab16(v) : (v))

	switch (magic) {
	case LOV_USER_MAGIC_V1:
	case LOV_USER_MAGIC_V3:
	/*
	 * `lfs setstripe -o 0,1 dir`, stored verbatim by
	 * lod_xattr_set_lov_on_dir() and not rewritten for a client
	 * either.  Its bytes are a lov_user_md_v3.
	 */
	case LOV_USER_MAGIC_SPECIFIC:
		/*
		 * The object array is measured by the buffer, as
		 * llapi_layout_objects_in_lum() does, not by lmm_stripe_count:
		 * a directory's default layout has the count and no
		 * lmm_objects[] (`lfs setstripe -c 4 dir` is 32 bytes).
		 */
		return size >= lov_user_md_size(0, magic);
	case LOV_USER_MAGIC_FOREIGN: {
		const struct lov_foreign_md *lfm = (const void *)lmm;

		if (size < offsetof(struct lov_foreign_md, lfm_value))
			return false;
		/*
		 * Subtracting rather than lov_foreign_md_size(), which adds
		 * the header in __u32: an lfm_length near the top of the
		 * range wraps to a small number and the test then succeeds
		 * for any buffer that got past the floor above.
		 */
		return lfm->lfm_length <=
		       size - offsetof(struct lov_foreign_md, lfm_value);
	}
	/*
	 * What lod writes for a layout with a self-extending component
	 * (lod_lov.c for a file, lod_object.c for a directory default).  A
	 * client never sees it -- lod_xattr_get() rewrites it to COMP_V1 --
	 * so reading trusted.lov off the device is the first consumer that
	 * has to know the magic.  The bytes are a lov_comp_md_v1.
	 */
	case LOV_MAGIC_SEL:
	case LOV_USER_MAGIC_COMP_V1:
		break;
	default:
		return false;
	}

	comp = (const struct lov_comp_md_v1 *)lmm;
	if (size < sizeof(*comp) || FLF32(comp->lcm_size) > size)
		return false;

	/* the entry array itself, before any lcme_offset is read */
	count = FLF16(comp->lcm_entry_count);
	need = count * (__u32)sizeof(comp->lcm_entries[0]);
	if (need > size - sizeof(*comp))
		return false;

	for (i = 0; i < count; i++) {
		__u32 off = FLF32(comp->lcm_entries[i].lcme_offset);
		__u32 len = FLF32(comp->lcm_entries[i].lcme_size);

		/*
		 * lov_comp_entry() is taken for every entry, instantiated or
		 * not, and its lmm_magic and lmm_stripe_count are read before
		 * LCME_FL_INIT is looked at -- so the offset has to admit a
		 * v1 header even where the entry itself is empty, which an
		 * uninstantiated component legitimately is.
		 */
		if (off > size - sizeof(struct lov_user_md_v1))
			return false;
		if (len > size - off)
			return false;
		/*
		 * llapi_layout_get_by_xattr() reads a pool name from any
		 * entry that is not v1 and a whole lov_hsm_md from a foreign
		 * one, so an unknown magic is refused and a foreign entry has
		 * to hold its own lfm_length.
		 */
		magic = FLF32(((const struct lov_user_md *)
			       ((const char *)lmm + off))->lmm_magic);
		switch (magic) {
		case LOV_USER_MAGIC_V1:
			break;
		case LOV_USER_MAGIC_V3:
		case LOV_USER_MAGIC_SPECIFIC:
			if (len < sizeof(struct lov_user_md_v3))
				return false;
			break;
		case LOV_MAGIC_FOREIGN: {
			const struct lov_foreign_md *lfm = (const void *)
				((const char *)lmm + off);
			__u32 hdr = offsetof(struct lov_foreign_md, lfm_value);

			if (len < hdr || FLF32(lfm->lfm_length) > len - hdr)
				return false;
			break;
		}
		default:
			return false;
		}
	}

#undef FLF32
#undef FLF16
	return true;
}

/*
 * The record as the deciding half expects it: the lov_user_mds_data every
 * find_check_* helper reads.  A field the scan could not answer for leaves
 * its bit out of stx_mask, as llite does when the MDT's answer is not
 * authoritative.
 *
 * Return: true where the object has a layout that could not be read, which
 * is not the same as having none.
 */
static bool find_rec_to_lmd(const struct llapi_scan_rec *rec,
			    struct find_param *param)
{
	struct lov_user_mds_data *lmd = param->fp_lmd;

	memset(lmd, 0, offsetof(typeof(*lmd), lmd_lmm));
	lmd->lmd_lmm.lmm_magic = 0;
	lmd->lmd_fid = rec->lfsr_fid;
	lmd->lmd_stx = rec->lfsr_stx;

	/*
	 * Authoritative, or lazy from trusted.som, or neither.  The lazy
	 * states are this API's and not statx's, so they arrive in lfsr_valid
	 * and leave as the lmd_flags the find_check_* helpers read; the
	 * number itself is in stx_size either way, with STATX_SIZE clear,
	 * which is how llite reports a size the MDT is not sure of.
	 */
	if (rec->lfsr_stx.stx_mask & STATX_SIZE)
		lmd->lmd_flags |= OBD_MD_FLSIZE;
	else if (rec->lfsr_valid & LLAPI_SCAN_LAZY_SIZE)
		lmd->lmd_flags |= OBD_MD_FLLAZYSIZE;
	if (rec->lfsr_stx.stx_mask & STATX_BLOCKS)
		lmd->lmd_flags |= OBD_MD_FLBLOCKS;
	else if (rec->lfsr_valid & LLAPI_SCAN_LAZY_BLOCKS)
		lmd->lmd_flags |= OBD_MD_FLLAZYBLOCKS;

	/*
	 * The layout is handed over as it is on disk.  lov_mds_md and
	 * lov_user_md are the same bytes, and the swab is a no-op wherever
	 * the host and the target agree on byte order.
	 *
	 * Copy, bound, swab, in that order -- the order
	 * llapi_layout_get_by_xattr() uses on the same bytes.  Why it is that
	 * way round is with the call itself.
	 */
	if ((rec->lfsr_valid & LLAPI_SCAN_LAYOUT) && rec->lfsr_lmm &&
	    rec->lfsr_lmmsize <= (__u32)param->fp_lum_size &&
	    rec->lfsr_lmmsize >= sizeof(lmd->lmd_lmm.lmm_magic)) {
		__u32 size = rec->lfsr_lmmsize;

		memcpy(&lmd->lmd_lmm, rec->lfsr_lmm, size);
		/*
		 * Bound the layout before swabbing it, not after.
		 * layout_swab_lov_user_md() walks lcm_entry_count and stores
		 * through lcme_offset, both taken from these bytes, and these
		 * bytes came off a target that may have been written while it
		 * was read.  find_lmm_fits() accepts either byte order for
		 * that reason.  llapi_layout_get_by_xattr() orders it the
		 * same way.
		 */
		if (find_lmm_fits(&lmd->lmd_lmm, size)) {
			layout_swab_lov_user_md(&lmd->lmd_lmm, size);
			/*
			 * Two magics are given a form the checks below read:
			 * lod_xattr_get() turns SEL into COMP_V1 for a client,
			 * and SPECIFIC becomes a V3 whose object list only
			 * --ost would read, which a target scan refuses.  A
			 * walk sees SPECIFIC as it is, so --pool matches such
			 * a directory on a scan and not on a walk.
			 */
			if (lmd->lmd_lmm.lmm_magic == LOV_MAGIC_SEL)
				lmd->lmd_lmm.lmm_magic = LOV_USER_MAGIC_COMP_V1;
			else if (lmd->lmd_lmm.lmm_magic ==
				 LOV_USER_MAGIC_SPECIFIC)
				lmd->lmd_lmm.lmm_magic = LOV_USER_MAGIC_V3;
			lmd->lmd_lmmsize = size;
			return false;
		}
	}

	/*
	 * One buffer serves the whole scan, so an object with no layout
	 * clears it rather than keep the previous object's stripe count.
	 */
	memset(&lmd->lmd_lmm, 0, sizeof(struct lov_user_md_v3));
	lmd->lmd_lmmsize = 0;

	return (rec->lfsr_valid & LLAPI_SCAN_LAYOUT) && rec->lfsr_lmm;
}

/*
 * The layout and what to do without one.  An object with no trusted.lov is
 * answered off the filesystem default, which is what a client would compare
 * against; one whose layout could not be read has no answer at all, and
 * forging a default there would answer --stripe-count, --pool and --foreign
 * off bytes nothing knows -- the outcome find_lmm_fits() accepts a short
 * foreign EA to avoid, reached the other way round.  A torn composite EA and
 * a byte-swapped LOV_MAGIC_SEL both land here.
 *
 * Return: 1 for an object the layout predicates cannot be answered for.
 */
static int find_rec_layout(const struct llapi_scan_rec *rec,
			   struct find_param *param)
{
	bool unread = find_rec_to_lmd(rec, param);

	/*
	 * Not find_check_lmm_info(): --projid is in the inode.  With no
	 * layout predicate only -printf reads the layout.  It prints what
	 * the object has, and leaves the directive empty for an unread one.
	 */
	if (!find_asks_layout(param))
		return 0;
	/* a predicate has no answer off bytes that did not parse */
	if (unread)
		return 1;
	/* the default an object with no trusted.lov would be given */
	if (param->fp_lmd->lmd_lmm.lmm_magic == 0)
		find_lmm_set_default(param);

	return 0;
}

/*
 * --name against every name the object has: a walk meets a hardlinked file
 * once per link, a scan meets it once with its names in the linkea.
 *
 * Three answers, so an int and not find_prefilter()'s bool -- and the two
 * senses agree where they overlap, 1 being a rejection in both.
 *
 * Return: 1 to reject the object, 0 to go on and gather, or 2 for an object
 * --name cannot be answered against at all.
 */
static int find_device_prefilter(const struct llapi_scan_rec *rec,
				 struct find_param *param, int *checked_type)
{
	struct llapi_scan_rec named = *rec;
	char name[NAME_MAX + 1] = "";
	unsigned int nr = 0;
	size_t off = 0;
	unsigned int i;

	/*
	 * An encrypted object's linkea holds its names as the client
	 * encrypted them, and only a client with the key can decode them.
	 * The top directory of an encrypted tree has a clear name of its
	 * own, but a record does not say which object that is.  So --name
	 * answers neither way, as for an object with no name.
	 */
	if (param->fp_pattern &&
	    (rec->lfsr_stx.stx_attributes_mask & STATX_ATTR_ENCRYPTED) &&
	    (rec->lfsr_stx.stx_attributes & STATX_ATTR_ENCRYPTED)) {
		named.lfsr_name = NULL;
		return find_prefilter(&named, param, checked_type) ? 1 : 2;
	}

	if (param->fp_pattern && (rec->lfsr_valid & LLAPI_SCAN_LINKEA))
		nr = scan_linkea_entry(rec->lfsr_linkea, rec->lfsr_linkeasize,
				       0, NULL, 0, NULL);

	/*
	 * No name anywhere: an OST data object has no linkea at all, and
	 * neither do the CLS_INTERNAL, CLS_NO_LMA and CLS_AGENT records
	 * LLAPI_SCAN_F_INTERNAL delivers.  Matching the empty string would
	 * drop every one of them for --name and keep every one for
	 * ! --name, and neither is an answer the target gave, so this is
	 * counted the way an absent birth time or project id is.
	 *
	 * A linkea claiming one entry whose name starts with NUL comes here
	 * too: scan_linkea() leaves lfsr_name NULL for it, and the entry is
	 * not spelled out again below.
	 *
	 * find_prefilter() skips -name for a nameless record, so it asks
	 * only -type and the directory checks.  An object that -uid or a
	 * time would reject is still counted undecided here.
	 */
	if (param->fp_pattern && nr <= 1 && !rec->lfsr_name) {
		/* ROOT and .lustre have no name to test, as on a walk */
		if (fid_is_root(&rec->lfsr_fid) ||
		    fid_seq_is_dot(rec->lfsr_fid.f_seq))
			return 1;
		return find_prefilter(rec, param, checked_type) ? 1 : 2;
	}

	/* one name or none, and the record carries it */
	if (nr <= 1) {
		if (!find_prefilter(rec, param, checked_type))
			return 0;
		goto no_match;
	}

	named.lfsr_name = name;

	for (i = 0; i < nr; i++) {
		if (scan_linkea_next(rec->lfsr_linkea, rec->lfsr_linkeasize,
				     &off, name, sizeof(name), NULL) == 0 ||
		    name[0] == '\0') {
			/*
			 * The linkea claims more names than it can spell:
			 * leh_reccount is capped by the smallest entry that
			 * could fit, so a torn trusted.link parses entry 0
			 * and runs out on a later one.  A name that starts
			 * with NUL is the same damage, and fnmatch() would
			 * answer it as "".  The names left are
			 * neither a match nor a miss, which is the no-name
			 * case above and not a rejection -- ask the other
			 * predicates the same way, since one of them may
			 * have decided the object already.
			 */
			named.lfsr_name = NULL;

			return find_prefilter(&named, param,
					      checked_type) ? 1 : 2;
		}
		if (!find_prefilter(&named, param, checked_type))
			return 0;
	}

no_match:
	/* a name the overflowed linkea did not store may still match */
	if (param->fp_pattern &&
	    (rec->lfsr_valid & LLAPI_SCAN_LINKEA) &&
	    scan_linkea_overflowed(rec->lfsr_linkea, rec->lfsr_linkeasize)) {
		named.lfsr_name = NULL;
		return find_prefilter(&named, param, checked_type) ? 1 : 2;
	}

	return 1;
}

static int find_device_cb(const struct llapi_scan_rec *rec, void *data)
{
	struct find_device_state *st = data;
	struct find_param *param = st->fds_param;
	struct find_ctx fc = { 0 };
	int checked_type = 0;
	int rc;

	/* a shard is part of its striped directory: the master answers */
	if (rec->lfsr_valid & LLAPI_SCAN_LMV_SHARD)
		return 0;

	rc = find_device_prefilter(rec, param, &checked_type);
	if (rc == 2)
		st->fds_undecided++;
	if (rc != 0)
		return 0;

	if (find_rec_layout(rec, param)) {
		st->fds_undecided++;
		return 0;
	}
	/*
	 * fp_get_lmv says the search asks for the directory stripe, as
	 * scan_rec_gather() sets it on a walk.  It is not whether an LMV was
	 * decoded: an unstriped directory must still reach the LMV checks, so
	 * --foreign, --mdt-count and --hash-type compare it.
	 */
	rc = find_rec_to_lmv(rec, param);
	if (rc < 0)
		return rc;
	param->fp_get_lmv = (rec->lfsr_stx.stx_mask & STATX_MODE) &&
			    S_ISDIR(rec->lfsr_stx.stx_mode) &&
			    find_needs_lmv(param);

	fc.fc_rec = rec;
	fc.fc_path = NULL;	/* stops the path-dependent steps */
	fc.fc_p = -1;
	fc.fc_d = -1;
	fc.fc_fdp = NULL;
	/*
	 * 0: there is no OST to refer a size or a time to.  The two do not
	 * come out the same, though.  A size is marked undecided and
	 * counted, the MDT's copy for a striped regular file being 0 rather
	 * than stale.  A time is answered from the MDT inode, which for such
	 * a file may lag the OSTs -- a glimpse is what a mount would settle
	 * it with, and a target scan has none.  Answering from the MDT is
	 * the closest a scan can come; llapi_find_device(3) says so.
	 */
	fc.fc_lustre_fs = 0;
	fc.fc_checked_type = checked_type;
	fc.fc_stripe_count = find_get_stripe_count(param);

	rc = find_decide(&fc, param);
	if (rc < 0)
		return rc;

	if (fc.fc_undecided)
		st->fds_undecided++;

	return 0;
}

/**
 * llapi_find_device() - lfs find's predicates, over a scan of a target
 * @target:	block device, image or snapshot holding an MDT or OST
 * @param:	the same search this library runs against a namespace
 * @sp:		scan parameters, or NULL for the defaults
 *
 * The objects come from llapi_scan_device() instead of a namespace walk,
 * so this reads a target directly and does not need it mounted, or its
 * server running, or a client anywhere.  A target holds names and parent
 * FIDs, not paths, so what it prints is a FID -- [0x200000401:0x1:0x0] --
 * or, for an object carrying no trusted.lma to hold one, obj: and the
 * target's own id for it.  The second form is reachable only under
 * LLAPI_SCAN_F_INTERNAL.  fp_zero_end chooses the separator, as for a walk.
 *
 * A predicate whose answer is only in the mounted filesystem is refused
 * before the scan starts rather than silently matching nothing.
 *
 * @sp is the same struct llapi_scan_device() takes, so a knob added there
 * costs this function nothing.  lfsp_flags takes LLAPI_SCAN_F_INTERNAL, to be
 * given the objects the target keeps for itself as well as the ones a
 * namespace can reach.
 *
 * Three fields are the search's to decide and are set in its own copy
 * whatever the caller set: lfsp_want (the predicates decide it),
 * lfsp_thread_count and lfsp_filter.  lfsp_got is ignored, and the caller's
 * is left untouched.  lfsp_filter goes because this
 * function has no void *data of its own to give it: the scan carries find's
 * state, and a caller's callback would be handed that and read it as its own
 * context.  lfsp_stats is filled as llapi_scan_device() fills it.
 *
 * Return: 0 on success, or a negative errno.
 */
int llapi_find_device(const char *target, struct find_param *param,
		      const struct llapi_scan_param *sp)
{
	struct llapi_scan_param spl = { .lfsp_size = sizeof(spl) };
	struct llapi_scan_stats stats = { .ss_size = sizeof(stats) };
	struct llapi_scan_stats *ustats = NULL;	/* the caller's, if any */
	struct find_device_state st = { 0 };
	struct obd_uuid *obd_uuid;
	struct llapi_scan_tgt tgt = { 0 };
	int lazy;
	int rc;

	if (!target || !param)
		return -EINVAL;

	if (sp) {
		rc = scan_param_copyin(&spl, sp, LLAPI_SCAN_F_KNOWN_DEV);
		if (rc != 0)
			return rc;
		/* filled after the scan, as llapi_scan_device() fills it */
		ustats = spl.lfsp_stats;
		if (ustats &&
		    ustats->ss_size < LLAPI_SCAN_STATS_MIN_SIZE)
			return -EINVAL;
	}

	rc = find_device_supported(param);
	if (rc < 0)
		return rc;

	rc = common_param_init(param, NULL);
	if (rc < 0)
		return rc;

	/*
	 * A scan cannot glimpse: there is no OST to ask and no mount to ask
	 * through, so trusted.som is the only answer a size can have.  The
	 * caller's value goes back before returning.
	 */
	lazy = param->fp_lazy;
	param->fp_lazy = 1;
	obd_uuid = param->fp_obd_uuid;

	/*
	 * --ost, --mdt and the layout options are about the target, so the
	 * label has to be read before the search can say whether they can be
	 * answered.  The probe is an open and a close, paid only when one of
	 * them was given.
	 */
	if (param->fp_obd_uuid || param->fp_mdt_uuid ||
	    find_asks_layout(param)) {
		rc = scan_device_target(target, &tgt);
		if (rc != 0)
			goto out;
	}

	/*
	 * An OST object has no layout, so these would be compared against a
	 * default that was never read.  Checked before find_device_targets()
	 * can skip this device, so every device of a sweep refuses it.
	 */
	if (find_asks_layout(param) && (tgt.tt_flags & LLAPI_SCAN_TGT_OST)) {
		llapi_error(LLAPI_MSG_ERROR | LLAPI_MSG_NO_ERRNO, -ENOTSUP,
			    "the layout options need an MDT; '%s' is an OST, whose objects carry no layout",
			    tgt.tt_label);
		rc = -ENOTSUP;
		goto out;
	}

	if (param->fp_obd_uuid || param->fp_mdt_uuid) {
		rc = find_device_targets(param, &tgt);
		if (rc != 0)
			goto out;
		/*
		 * Every object an MDT scan delivers is on that MDT, which is
		 * what check_mdt_match() compares the resolved indices
		 * against.  Constant for the whole scan, so it is set here
		 * rather than per record.
		 */
		if (param->fp_mdt_uuid)
			param->fp_file_mdt_index = (int)tgt.tt_index;
	}

	st.fds_param = param;
	spl.lfsp_want = find_device_want(param);
	/* find's own demand mask, not the caller's, so the caller's lfsp_got
	 * would answer for a question it did not ask
	 */
	spl.lfsp_got = NULL;
	spl.lfsp_stats = &stats;
	/* see the note above: there is no caller data to pair it with */
	spl.lfsp_filter = NULL;
	/*
	 * One thread: param->fp_lmd is one buffer for the whole search, and
	 * per-thread copies mean changing struct find_param.
	 */
	spl.lfsp_thread_count = 1;

	rc = llapi_scan_device(target, &spl, find_device_cb, &st);

	if (rc == 0 && st.fds_undecided != 0)
		llapi_error(LLAPI_MSG_WARN | LLAPI_MSG_NO_ERRNO, 0,
			    "%s: %llu objects could not be decided: the target has no answer for a field the search asked for",
			    target, (unsigned long long)st.fds_undecided);

	/*
	 * A scan that could not read part of the target has not searched it,
	 * and saying nothing would let a partial answer read as a whole one.
	 */
	if (rc == 0 && stats.ss_skipped != 0)
		llapi_error(LLAPI_MSG_WARN | LLAPI_MSG_NO_ERRNO, 0,
			    "%s: %llu of %llu objects were skipped: unreadable or inconsistent on the target",
			    target, (unsigned long long)stats.ss_skipped,
			    (unsigned long long)stats.ss_seen);

out:
	/*
	 * The scan's counters, so a program can see a partial answer and
	 * not only a message: ss_skipped is what could not be read.
	 * ss_emitted counts the records the search judged, not its matches.
	 * Here, so a target that was skipped answers zeros and not the
	 * counters of the caller's previous call.
	 */
	if (ustats) {
		__u32 size = ustats->ss_size;

		if (size > sizeof(stats))
			size = sizeof(stats);
		size = scan_stats_whole(size);
		stats.ss_size = size;
		memcpy(ustats, &stats, size);
	}
	param->fp_lazy = lazy;
	param->fp_obd_uuid = obd_uuid;
	find_param_fini(param);

	/*
	 * 1 says no object on the target could have matched, which is an
	 * empty answer and not a failure: a caller sweeping a list of devices
	 * with one --ost has to be able to skip the ones that cannot hold a
	 * match without the sweep failing.
	 */
	return rc > 0 ? 0 : rc;
}

int cb_find_init(char *path, int p, int *dp, struct find_param *param,
		 struct dirent64 *de)
{
	struct lov_user_mds_data *lmd = param->fp_lmd;
	struct llapi_scan_rec rec;
	struct find_ctx fc = { 0 };
	int d = dp == NULL ? -1 : *dp;
	int lustre_fs = 1;
	int checked_type = 0;
	int ret = 0;
	__u32 stripe_count = 0;
	__u64 want;
	int fd = -2;
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

	/* What the directory entry alone can settle. */
	scan_rec_dirent(&rec, path, p, d, de);
	if (find_prefilter(&rec, param, &checked_type))
		goto decided;

	/* Then only as much of the MDT's answer as this search needs. */
	want = find_want(param, checked_type, gather_all);
	if (want != 0) {
		bool have_lmv = false;

		/* the LMV first: its checks can reject before the stat RPC */
		ret = scan_rec_gather_begin(param, path, d, want, &have_lmv);
		if (ret == 0 && find_lmv_rejects(param, have_lmv))
			goto decided;
		if (ret == 0)
			ret = scan_rec_gather_finish(param, path, p, d, &fd,
						     want, have_lmv, &rec);
		if (ret == 0 && lmd->lmd_lmm.lmm_magic == 0 &&
		    find_check_lmm_info(param))
			find_lmm_set_default(param);
		if (ret != 0) {
			if (ret == -ENOTTY)
				lustre_fs = 0;
			if (ret == -ENOENT)
				goto decided;

			goto out;
		} else {
			stripe_count = find_get_stripe_count(param);
		}
		/* --mdt cannot be answered without the index: leave it out */
		if (param->fp_mdt_uuid != NULL &&
		    !(rec.lfsr_valid & LLAPI_SCAN_MDT_INDEX))
			goto decided;
	}

	fc.fc_rec = &rec;
	fc.fc_path = path;
	fc.fc_de = de;
	fc.fc_p = p;
	fc.fc_d = d;
	fc.fc_fdp = &fd;
	fc.fc_stripe_count = stripe_count;
	fc.fc_lustre_fs = lustre_fs;
	fc.fc_checked_type = checked_type;
	fc.fc_gather_all = gather_all;

	ret = find_decide(&fc, param);
	if (ret < 0)
		goto out;

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
			    llapi_find_cb_t sem_init,
			    llapi_find_cb_t sem_fini, void *data,
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

		if (param->fp_thread_count > 1 && queue->fwq_shutdown)
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
			else if (ret >= 0)
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
			if (param->fp_thread_count > 1 &&
			    (ll_atomic_fetch_add(&queue->fwq_active_units, 0) <
			     queue->fwq_max_units ||
			     find_inline_depth >=
			     queue->fwq_inline_depth_max)) {
				rc = work_unit_create_and_add(path, param,
							      dent);
			} else {
				find_inline_depth++;
				rc = llapi_semantic_traverse(path, size, d,
							     sem_init, sem_fini,
							     data, dent);
				find_inline_depth--;
			}
			if (rc != 0 && ret >= 0)
				ret = rc;
			if (rc < 0 && rc != -EALREADY &&
			    param->fp_stop_on_error)
				goto out;
			break;
		default:
			rc = 0;
			if (sem_init) {
				rc = sem_init(path, d, NULL, data, dent);
				if (rc < 0) {
					if (ret >= 0)
						ret = rc;
					if (rc != -EALREADY &&
					    param->fp_stop_on_error)
						goto out;
				}
			}
			if (sem_fini && rc == 0) {
				int rc2;

				rc2 = sem_fini(path, d, NULL, data, dent);
				/* record first error, keep scanning */
				if (rc2 < 0 && ret >= 0)
					ret = rc2;
			}
		}
	}

out:
	path[len] = 0;

	if (sem_fini) {
		int rc2;

		rc2 = sem_fini(path, parent, &d, data, de);
		if (rc2 < 0 && ret >= 0)
			ret = rc2;
	}
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

int param_callback(char *path, llapi_find_cb_t cb_init,
		   llapi_find_cb_t cb_fini, struct find_param *param)
{
	int ret, len = strlen(path);
	char *buf;

	if (len > PATH_MAX) {
		ret = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, ret,
			    "Path name '%s' is too long", path);
		return ret;
	}

	buf = (char *)malloc(FIND_PATH_BUFLEN);
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

	ret = llapi_semantic_traverse(buf, FIND_PATH_BUFLEN, -1, cb_init,
				      cb_fini, param, NULL);
out:
	find_param_fini(param);
	free(buf);
	return ret < 0 ? ret : 0;
}

static void work_unit_free(struct find_work_unit *unit);

/* Scratch buffers of a worker thread */
struct find_scratch {
	struct lov_user_mds_data	*fs_lmd;
	size_t				 fs_lum_size;
	struct lmv_user_md		*fs_lmv_md;
	__u32				 fs_lmv_stripe_count;
	char				*fs_xattr_name_buf;
	char				*fs_xattr_value_buf;
};

static int find_scratch_lend(struct find_scratch *fs, struct find_param *param)
{
	struct xattr_match_info *xmi = param->fp_xattr_match_info;

	if (!fs->fs_lmd) {
		fs->fs_lum_size = param->fp_lum_size;
		fs->fs_lmd = calloc(1, offsetof(typeof(*fs->fs_lmd), lmd_lmm) +
				    fs->fs_lum_size);
		if (!fs->fs_lmd)
			return -ENOMEM;
	}

	if (!fs->fs_lmv_md) {
		size_t lmv_size;

		fs->fs_lmv_stripe_count = param->fp_lmv_stripe_count;
		lmv_size = lmv_user_md_size(fs->fs_lmv_stripe_count,
					    LMV_USER_MAGIC_SPECIFIC);
		fs->fs_lmv_md = calloc(1, lmv_size);
		if (!fs->fs_lmv_md)
			return -ENOMEM;
	}

	if (xmi && !fs->fs_xattr_name_buf) {
		fs->fs_xattr_name_buf = malloc(XATTR_LIST_MAX);
		if (!fs->fs_xattr_name_buf)
			return -ENOMEM;
	}

	if (xmi && !fs->fs_xattr_value_buf) {
		/* room for a NUL after the value, as in lfs.c */
		fs->fs_xattr_value_buf = malloc(XATTR_SIZE_MAX + 1);
		if (!fs->fs_xattr_value_buf)
			return -ENOMEM;
	}

	param->fp_lmd = fs->fs_lmd;
	param->fp_lum_size = fs->fs_lum_size;
	param->fp_lmv_md = fs->fs_lmv_md;
	param->fp_lmv_stripe_count = fs->fs_lmv_stripe_count;
	if (xmi) {
		xmi->xattr_name_buf = fs->fs_xattr_name_buf;
		xmi->xattr_value_buf = fs->fs_xattr_value_buf;
	}

	return 0;
}

/*
 * Take the lent buffers back. The traversal may have reallocated fp_lmv_md,
 * or freed it and failed to allocate a new one: then fs_lmv_md is NULL, and
 * find_scratch_lend() allocates a new one for the next work unit.
 */
static void find_scratch_take_back(struct find_scratch *fs,
				   struct find_param *param)
{
	struct xattr_match_info *xmi = param->fp_xattr_match_info;

	fs->fs_lmd = param->fp_lmd;
	fs->fs_lum_size = param->fp_lum_size;
	param->fp_lmd = NULL;

	fs->fs_lmv_md = param->fp_lmv_md;
	fs->fs_lmv_stripe_count = param->fp_lmv_stripe_count;
	param->fp_lmv_md = NULL;

	if (xmi) {
		xmi->xattr_name_buf = NULL;
		xmi->xattr_value_buf = NULL;
	}
}

static void find_scratch_fini(struct find_scratch *fs)
{
	free(fs->fs_lmd);
	free(fs->fs_lmv_md);
	free(fs->fs_xattr_name_buf);
	free(fs->fs_xattr_value_buf);
}

/* Placeholder worker function - just for testing thread creation */
static void *find_worker(void *arg)
{
	struct find_work_queue *queue = (struct find_work_queue *) arg;
	struct find_work_unit *unit = NULL;
	struct find_scratch scratch = { NULL };
	char *fail_loc = getenv("LLAPI_FAIL_LOC");
	char *path;
	int rc = 0;

	path = malloc(FIND_PATH_BUFLEN);
	if (!path) {
		pthread_mutex_lock(&queue->fwq_lock);
		if (queue->fwq_error == 0)
			queue->fwq_error = -ENOMEM;
		queue->fwq_shutdown = true;
		pthread_cond_broadcast(&queue->fwq_sleep_cond);
		pthread_mutex_unlock(&queue->fwq_lock);
		return NULL;
	}

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

		rc = snprintf(path, FIND_PATH_BUFLEN, "%s", unit->fwu_path);
		if (rc < 0 || rc >= FIND_PATH_BUFLEN)
			rc = -ENAMETOOLONG;
		else
			rc = find_scratch_lend(&scratch, unit->fwu_param);
		if (rc == 0) {
			rc = llapi_semantic_traverse(path, FIND_PATH_BUFLEN, -1,
						     queue->fwq_cb_init,
						     queue->fwq_cb_fini,
						     unit->fwu_param, NULL);
			find_scratch_take_back(&scratch, unit->fwu_param);
		}
		/* skip the positive depth marker; keep the first error */
		if (rc < 0 && queue->fwq_error == 0)
			queue->fwq_error = rc;
		if ((rc < 0 && rc != -EALREADY &&
		     unit->fwu_param->fp_stop_on_error) ||
		    (fail_loc && !strcmp(fail_loc, "LLAPI_FAIL_PFIND_SEM"))) {
			/* fail_loc forces -EIO; otherwise the first error,
			 * already recorded above, is kept
			 */
			if (fail_loc && !strcmp(fail_loc,
						"LLAPI_FAIL_PFIND_SEM"))
				queue->fwq_error = -EIO;
			queue->fwq_shutdown = 1;
		}

		work_unit_free(unit);
		ll_atomic_fetch_sub(&queue->fwq_active_units, 1);
	}

	find_scratch_fini(&scratch);
	free(path);
	return NULL;
}

/* Initialize the work queue */
static void find_work_queue_init(struct find_work_queue *queue,
				 llapi_find_cb_t cb_init,
				 llapi_find_cb_t cb_fini)
{
	char *fail_loc;

	queue->fwq_head = NULL;
	queue->fwq_tail = NULL;
	queue->fwq_active_units = 0;
	pthread_mutex_init(&queue->fwq_lock, NULL);
	pthread_cond_init(&queue->fwq_sleep_cond, NULL);
	queue->fwq_shutdown = false;
	queue->fwq_error = 0;
	queue->fwq_cb_init = cb_init;
	queue->fwq_cb_fini = cb_fini;
	queue->fwq_max_units = FIND_QUEUE_MAX_UNITS;
	/* for tests, have the threads find the queue always full */
	fail_loc = getenv("LLAPI_FAIL_LOC");
	if (fail_loc && !strcmp(fail_loc, "LLAPI_FAIL_PFIND_QUEUE_FULL"))
		queue->fwq_max_units = 0;
}

/*
 * Number of levels of subdirectories that each of @numthreads threads may
 * traverse itself, for the walk to stay within the soft limit of open files.
 */
static int find_inline_depth_max(int numthreads)
{
	struct rlimit rlim;
	struct dirent *de;
	long nr_open = 0;
	long avail;
	DIR *dir;

	if (getrlimit(RLIMIT_NOFILE, &rlim) < 0 ||
	    rlim.rlim_cur == RLIM_INFINITY || rlim.rlim_cur > INT_MAX)
		return INT_MAX;

	/* the descriptors that are already open */
	dir = opendir("/proc/self/fd");
	if (dir) {
		while ((de = readdir(dir)) != NULL)
			if (de->d_name[0] != '.')
				nr_open++;
		closedir(dir);
	}

	avail = (long)rlim.rlim_cur - nr_open - FIND_FDS_RESERVED;
	avail = avail / numthreads - FIND_FDS_PER_THREAD;

	return avail > 0 ? avail : 0;
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
	unit->fwu_path = strdup(path);
	if (!unit->fwu_path)
		goto error;

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

int parallel_find(char *path, llapi_find_cb_t cb_init, llapi_find_cb_t cb_fini,
		  struct find_param *param)
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

	find_work_queue_init(&queue, cb_init, cb_fini);
	queue.fwq_inline_depth_max = find_inline_depth_max(numthreads);

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

/**
 * llapi_find_param_alloc() - Allocate a find_param struct.
 *
 * The returned structure should be freed with llapi_find_param_free().
 *
 * Return:
 * * on success, pointer to a zeroed struct find_param
 * * on failure, %NULL with errno set to %ENOMEM
 */
struct find_param *llapi_find_param_alloc(void)
{
	struct find_param *param;

	param = calloc(1, sizeof(*param));
	if (!param)
		errno = ENOMEM;

	return param;
}

/**
 * llapi_find_param_free() - Free a find_param struct.
 *
 * @param: Pointer to find_param structure
 */
void llapi_find_param_free(struct find_param *param)
{
	free(param);
}
