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
 * Copyright (c) 2017, DDN Storage Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/*
 *
 * lustreapi library for Persistent Client Cache.
 *
 * Author: Li Xi <lixi@ddn.com>
 * Author: Qian Yingjin <qian@ddn.com>
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_user.h>
#include <linux/lustre/lustre_fid.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include "lustreapi_internal.h"

/**
 * Fetch and attach a file to readwrite PCC.
 *
 */
static int llapi_readwrite_pcc_attach_fd(int fd, __u32 archive_id)
{
	int rc;
	struct ll_ioc_lease *data;

	rc = llapi_lease_acquire(fd, LL_LEASE_WRLCK);
	if (rc < 0) {
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot get lease");
		return rc;
	}

	data = malloc(offsetof(typeof(*data), lil_ids[1]));
	if (!data) {
		rc = -ENOMEM;
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "failed to allocate memory");
		return rc;
	}

	data->lil_mode = LL_LEASE_UNLCK;
	data->lil_flags = LL_LEASE_PCC_ATTACH;
	data->lil_count = 1;
	data->lil_ids[0] = archive_id;
	rc = llapi_lease_set(fd, data);
	if (rc <= 0) {
		if (rc == 0) /* lost lease lock */
			rc = -EBUSY;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot attach with ID: %u", archive_id);
	} else {
		rc = 0;
	}

	free(data);
	return rc;
}

static int llapi_readwrite_pcc_attach(const char *path, __u32 archive_id)
{
	int fd;
	int rc;

	fd = open(path, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot open '%s'",
			    path);
		return rc;
	}

	rc = llapi_readwrite_pcc_attach_fd(fd, archive_id);

	close(fd);
	return rc;
}

int llapi_pcc_attach(const char *path, __u32 id, enum lu_pcc_type type)
{
	int rc;

	switch (type) {
	case LU_PCC_READWRITE:
		rc = llapi_readwrite_pcc_attach(path, id);
		break;
	default:
		rc = -EINVAL;
		break;
	}
	return rc;
}

static int llapi_readwrite_pcc_attach_fid(const char *mntpath,
					  const struct lu_fid *fid,
					  __u32 id)
{
	int rc;
	int fd;

	fd = llapi_open_by_fid(mntpath, fid, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "llapi_open_by_fid for " DFID "failed",
			    PFID(fid));
		return rc;
	}

	rc = llapi_readwrite_pcc_attach_fd(fd, id);

	close(fd);
	return rc;
}

int llapi_pcc_attach_fid(const char *mntpath, const struct lu_fid *fid,
			 __u32 id, enum lu_pcc_type type)
{
	int rc;

	switch (type) {
	case LU_PCC_READWRITE:
		rc = llapi_readwrite_pcc_attach_fid(mntpath, fid, id);
		break;
	default:
		rc = -EINVAL;
		break;
	}
	return rc;
}


int llapi_pcc_attach_fid_str(const char *mntpath, const char *fidstr,
			     __u32 id, enum lu_pcc_type type)
{
	int rc;
	struct lu_fid fid;
	const char *fidstr_orig = fidstr;

	while (*fidstr == '[')
		fidstr++;
	rc = sscanf(fidstr, SFID, RFID(&fid));
	if (rc != 3) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "bad FID format '%s', should be [seq:oid:ver]"
				  " (e.g. "DFID")\n", fidstr_orig,
				  (unsigned long long)FID_SEQ_NORMAL, 2, 0);
		return -EINVAL;
	}

	rc = llapi_pcc_attach_fid(mntpath, &fid, id, type);

	return rc;
}

/**
 * detach PCC cache of a file by using fd.
 *
 * \param fd		File handle.
 * \param option	Detach option
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_pcc_detach_fd(int fd, __u32 option)
{
	struct lu_pcc_detach detach;
	int rc;

	detach.pccd_opt = option;
	rc = ioctl(fd, LL_IOC_PCC_DETACH, &detach);
	return rc;
}

/**
 * detach PCC cache of a file via FID.
 *
 * \param mntpath	Fullpath to the client mount point.
 * \param fid		FID of the file.
 * \param option	Detach option.
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_pcc_detach_fid(const char *mntpath, const struct lu_fid *fid,
			 __u32 option)
{
	int rc;
	int fd;
	struct lu_pcc_detach_fid detach;

	rc = get_root_path(WANT_FD, NULL, &fd, (char *)mntpath, -1, NULL);
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot get root path: %s",
			    mntpath);
		return rc;
	}

	/*
	 * PCC prefetching algorithm scans Lustre OPEN/CLOSE changelogs
	 * to determine the candidate files needing to prefetch into
	 * PCC. To avoid generattion of unnecessary open/close changelogs,
	 * we implement a new dir ioctl LL_IOC_PCC_DETACH_BY_FID to detach
	 * files.
	 */
	detach.pccd_fid = *fid;
	detach.pccd_opt = option;
	rc = ioctl(fd, LL_IOC_PCC_DETACH_BY_FID, &detach);
	close(fd);
	return rc;
}

/**
 * detach PCC cache of a file via FID.
 *
 * \param mntpath	Fullpath to the client mount point.
 * \param fidstr	FID string of the file.
 * \param option	Detach option.
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_pcc_detach_fid_str(const char *mntpath, const char *fidstr,
			     __u32 option)
{
	int rc;
	struct lu_fid fid;
	const char *fidstr_orig = fidstr;

	while (*fidstr == '[')
		fidstr++;
	rc = sscanf(fidstr, SFID, RFID(&fid));
	if (rc != 3 || !fid_is_sane(&fid)) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "bad FID format '%s', should be [seq:oid:ver]"
				  " (e.g. "DFID")\n", fidstr_orig,
				  (unsigned long long)FID_SEQ_NORMAL, 2, 0);
		return -EINVAL;
	}

	rc = llapi_pcc_detach_fid(mntpath, &fid, option);

	return rc;
}

/**
 * detach PCC cache of a file.
 *
 * \param path		Fullpath to the file to operate on.
 * \param option	Detach option.
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_pcc_detach_file(const char *path, __u32 option)
{
	int rc;
	int fd;

	fd = open(path, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot open '%s'",
			    path);
		return rc;
	}

	rc = llapi_pcc_detach_fd(fd, option);
	close(fd);
	return rc;
}

/**
 * Return the current PCC state related to a file.
 *
 * \param fd	File handle.
 * \param state	PCC state info.
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_pcc_state_get_fd(int fd, struct lu_pcc_state *state)
{
	int rc;

	rc = ioctl(fd, LL_IOC_PCC_STATE, state);
	/* If error, save errno value */
	rc = rc ? -errno : 0;

	return rc;
}

/**
 * Return the current PCC state related to file pointed by a path.
 *
 * see llapi_pcc_state_get_fd() for args use and return
 */
int llapi_pcc_state_get(const char *path, struct lu_pcc_state *state)
{
	int fd;
	int rc;

	fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return -errno;

	rc = llapi_pcc_state_get_fd(fd, state);

	close(fd);
	return rc;
}

/**
 * Add/delete a PCC backend on a client.
 */
int llapi_pccdev_set(const char *mntpath, const char *cmd)
{
	char buf[sizeof(struct obd_uuid)];
	glob_t path;
	ssize_t count;
	int fd;
	int rc;

	rc = llapi_getname(mntpath, buf, sizeof(buf));
	if (rc < 0) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot get name for '%s'", mntpath);
		return rc;
	}

	rc = cfs_get_param_paths(&path, "llite/%s/pcc", buf);
	if (rc != 0)
		return -errno;

	fd = open(path.gl_pathv[0], O_WRONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error opening %s",
			    path.gl_pathv[0]);
		goto out;
	}

	count = write(fd, cmd, strlen(cmd));
	if (count < 0) {
		rc = errno;
		if (errno != EIO)
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "error: setting llite.%s.pcc='%s'",
				    buf, cmd);
	} else if (count < strlen(cmd)) { /* Truncate case */
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "setting llite.%s.pcc='%s': wrote only %zd",
			    buf, cmd, count);
	}
	close(fd);
out:
	cfs_free_param_data(&path);
	return rc;
}

/**
 * List all PCC backend devices on a client.
 */
int llapi_pccdev_get(const char *mntpath)
{
	long page_size = sysconf(_SC_PAGESIZE);
	char pathbuf[sizeof(struct obd_uuid)];
	glob_t path;
	char *buf;
	int fd;
	int rc;

	rc = llapi_getname(mntpath, pathbuf, sizeof(pathbuf));
	if (rc < 0) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot get name for '%s'", mntpath);
		return rc;
	}

	rc = cfs_get_param_paths(&path, "llite/%s/pcc", pathbuf);
	if (rc != 0)
		return -errno;

	/* Read the contents of file to stdout */
	fd = open(path.gl_pathv[0], O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: pccdev_get: opening '%s'",
			    path.gl_pathv[0]);
		goto out_free_param;
	}

	buf = calloc(1, page_size);
	if (buf == NULL) {
		rc = -ENOMEM;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: pccdev_get: allocating '%s' buffer",
			    path.gl_pathv[0]);
		goto out_close;
	}

	while (1) {
		ssize_t count = read(fd, buf, page_size);

		if (count == 0)
			break;
		if (count < 0) {
			rc = -errno;
			if (errno != EIO) {
				llapi_error(LLAPI_MSG_ERROR, rc,
					   "error: pccdev_get: reading failed");
			}
			break;
		}

		if (fwrite(buf, 1, count, stdout) != count) {
			rc = -errno;
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "error: get_param: write to stdout");
			break;
		}
	}
out_close:
	close(fd);
	free(buf);
out_free_param:
	cfs_free_param_data(&path);
	return rc;
}
