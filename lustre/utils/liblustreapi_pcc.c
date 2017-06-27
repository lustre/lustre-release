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
static int llapi_readwrite_pcc_attach(const char *path, __u32 archive_id)
{
	int fd;
	int rc;
	struct ll_ioc_lease *data;

	fd = open(path, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot open '%s'",
			    path);
		return rc;
	}

	rc = llapi_lease_acquire(fd, LL_LEASE_WRLCK);
	if (rc < 0) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot get lease for '%s'", path);
		goto out_close;
	}

	data = malloc(offsetof(typeof(*data), lil_ids[1]));
	if (!data) {
		rc = -ENOMEM;
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "failed to allocate memory");
		goto out_close;
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
			    "cannot attach '%s' with ID: %u",
			     path, archive_id);
	} else {
		rc = 0;
	}

	free(data);
out_close:
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


/**
 * detach PCC cache of a file by an ioctl on the dir fd (usually a mount
 * point fd that the copytool already has open).
 *
 * If the file is being used, the detaching will return -EBUSY immediately.
 * Thus, if a PCC-attached file is kept open for a long time, the restore
 * request will always return failure.
 *
 * \param fd		Directory file descriptor.
 * \param fid		FID of the file.
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_pcc_detach_fid_fd(int fd, const struct lu_fid *fid)
{
	int rc;
	struct lu_pcc_detach detach;

	detach.pccd_fid = *fid;
	rc = ioctl(fd, LL_IOC_PCC_DETACH, &detach);
	if (rc == -EAGAIN)
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "FID "DFID" may be in the attaching state, "
			    "or you may need to re-run the pcc_attach "
			    "to finish the attach process.", PFID(fid));
	else if (rc)
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot detach FID "DFID" from PCC", PFID(fid));

	return rc;
}

/**
 * detach PCC cache of a file.
 *
 * \param mntpath	Fullpath to the client mount point.
 * \param fid		FID of the file.
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_pcc_detach_fid(const char *mntpath, const struct lu_fid *fid)
{
	int rc;
	int fd;

	rc = get_root_path(WANT_FD, NULL, &fd, (char *)mntpath, -1);
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot get root path: %s",
			    mntpath);
		return rc;
	}

	rc = llapi_pcc_detach_fid_fd(fd, fid);

	close(fd);
	return rc;
}

/**
 * detach PCC cache of a file.
 *
 * \param mntpath	Fullpath to the client mount point.
 * \param fid		FID string of the file.
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_pcc_detach_fid_str(const char *mntpath, const char *fidstr)
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

	rc = llapi_pcc_detach_fid(mntpath, &fid);

	return rc;
}

/**
 * detach PCC cache of a file.
 *
 * \param path	  Fullpath to the file to operate on.
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_pcc_detach_file(const char *path)
{
	int rc;
	lustre_fid fid;

	rc = llapi_path2fid(path, &fid);
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot get FID of '%s'",
			    path);
		return rc;
	}

	rc = llapi_pcc_detach_fid(path, &fid);
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
			    "cannot get name for '%s'\n", mntpath);
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
				    "error: setting llite.%s.pcc=\"%s\"\n",
				    buf, cmd);
	} else if (count < strlen(cmd)) { /* Truncate case */
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "setting llite.%s.pcc=\"%s\": wrote only %zd\n",
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
			    "cannot get name for '%s'\n", mntpath);
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
			    "error: pccdev_get: opening '%s'\n",
			    path.gl_pathv[0]);
		goto out_free_param;
	}

	buf = calloc(1, page_size);
	if (buf == NULL) {
		rc = -ENOMEM;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: pccdev_get: allocating '%s' buffer\n",
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
					    "error: pccdev_get: "
					    "reading failed\n");
			}
			break;
		}

		if (fwrite(buf, 1, count, stdout) != count) {
			rc = -errno;
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "error: get_param: write to stdout\n");
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
