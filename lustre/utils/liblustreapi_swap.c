/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 or (at your discretion) any later version.
 * (LGPL) version 2.1 accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * LGPL HEADER END
 */
/*
 * Copyright (c) 2012 Commissariat a l'energie atomique et aux energies
 * alternatives
 * Copyright (c) 2017, 2021, DDN Storage Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/*
 * lustreapi library for file layout swapping.
 */

#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <lustre/lustreapi.h>

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

	idv.idv_flags = (__u32)flags;

	rc = ioctl(fd, LL_IOC_DATA_VERSION, &idv);
	if (rc)
		rc = -errno;
	else
		*data_version = idv.idv_version;

	return rc;
}

/*
 * Fetch layout version from OST objects. Layout version on OST objects are
 * only set when the file is a mirrored file AND after the file has been
 * written at least once.
 *
 * It actually fetches the least layout version from the objects.
 */
int llapi_get_ost_layout_version(int fd, __u32 *layout_version)
{
	int rc;
	struct ioc_data_version idv = { 0 };

	rc = ioctl(fd, LL_IOC_DATA_VERSION, &idv);
	if (rc)
		rc = -errno;
	else
		*layout_version = idv.idv_layout_version;

	return rc;
}

/*
 * Create a file without any name and open it for read/write
 *
 * - file is created as if it were a standard file in the given \a directory
 * - file does not appear in \a directory and mtime does not change because
 *   the filename is handled specially by the Lustre MDS.
 * - file is destroyed at final close
 *
 * \param[in]	directory	directory from which to inherit layout/MDT idx
 * \param[in]	mdt_idx		MDT index on which the file is created,
 *				\a idx == -1 means no specific MDT is requested
 * \param[in]	mode		standard open(2) mode
 * \param[in]	stripe_param	stripe parameters. May be NULL.
 *
 * \retval	a file descriptor on success.
 * \retval	-errno on error.
 */
int llapi_create_volatile_param(const char *directory, int mdt_idx,
				int open_flags, mode_t mode,
				const struct llapi_stripe_param *stripe_param)
{
	char file_path[PATH_MAX];
	int saved_errno = errno;
	int fd;
	unsigned int rnumber;
	int rc;

	do {
		rnumber = random();
		if (mdt_idx == -1)
			rc = snprintf(file_path, sizeof(file_path),
				      "%s/" LUSTRE_VOLATILE_HDR "::%.4X",
				      directory, rnumber);
		else
			rc = snprintf(file_path, sizeof(file_path),
				      "%s/" LUSTRE_VOLATILE_HDR ":%.4X:%.4X",
				      directory, mdt_idx, rnumber);

		if (rc < 0 || rc >= sizeof(file_path))
			return -ENAMETOOLONG;

		/*
		 * Either open O_WRONLY or O_RDWR, creating RDONLY
		 * is non-sensical here
		 */
		if ((open_flags & O_ACCMODE) == O_RDONLY)
			open_flags = O_RDWR | (open_flags & ~O_ACCMODE);

		open_flags |= O_CREAT | O_EXCL | O_NOFOLLOW;

		if (stripe_param != NULL) {
			fd = llapi_file_open_param(file_path, open_flags,
						   mode, stripe_param);
			if (fd < 0)
				rc = fd;
		} else {
			fd = open(file_path, open_flags, mode);
			if (fd < 0)
				rc = -errno;
		}
	} while (fd < 0 && rc == -EEXIST);

	if (fd < 0) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Cannot create volatile file '%s' in '%s'",
			    file_path + strlen(directory) + 1 +
			    LUSTRE_VOLATILE_HDR_LEN,
			    directory);
		return rc;
	}

	/*
	 * Unlink file in case this wasn't a Lustre filesystem and the magic
	 * volatile filename wasn't handled as intended. The effect is the
	 * same. If volatile open was supported then we expect unlink() to
	 * return -ENOENT.
	 */
	(void)unlink(file_path);

	/*
	 * Since we are returning successfully we restore errno (and
	 * mask out possible EEXIST from open() and ENOENT from unlink().
	 */
	errno = saved_errno;

	return fd;
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
 * \retval	a file descriptor on success.
 * \retval	-errno on error.
 */
int llapi_create_volatile_idx(const char *directory, int mdt_idx,
			      int open_flags)
{
	return llapi_create_volatile_param(directory, mdt_idx, open_flags,
					   S_IRUSR | S_IWUSR, NULL);
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

int llapi_group_lock64(int fd, __u64 gid)
{
	int rc;

	/* If this is ever compiled on a 32-bit system then a new
	 * LL_IOC_GROUP_LOCK64 will need to be defined that takes
	 * __u64 as an argument.  That may never happen again.
	 */
	BUILD_BUG_ON(sizeof(long) != sizeof(__u64));
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

int llapi_group_unlock64(int fd, __u64 gid)
{
	int rc;

	rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);
	if (rc < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot put group lock");
	}
	return rc;
}
