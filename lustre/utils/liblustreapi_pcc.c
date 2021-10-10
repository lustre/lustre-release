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
#include <lnetconfig/cyaml.h>
#include "lustreapi_internal.h"
#include "libhsm_scanner.h"

/**
 * Fetch and attach a file to readwrite PCC.
 *
 */
static int llapi_pcc_attach_rw_fd(int fd, __u32 archive_id)
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

static int llapi_pcc_attach_rw(const char *path, __u32 archive_id)
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

	rc = llapi_pcc_attach_rw_fd(fd, archive_id);

	close(fd);
	return rc;
}

static int llapi_pcc_attach_ro_fd(int fd, __u32 roid)
{
	struct lu_pcc_attach attach;
	int rc;

	attach.pcca_id = roid;
	attach.pcca_type = LU_PCC_READONLY;
	rc = ioctl(fd, LL_IOC_PCC_ATTACH, &attach);
	if (rc) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot attach the file to PCC with ID %u failed",
			    roid);
	}

	return rc;
}

static int llapi_pcc_attach_ro(const char *path, __u32 roid)
{
	int fd;
	int rc;

	if (strlen(path) <= 0 || path[0] != '/') {
		rc = -EINVAL;
		llapi_err_noerrno(LLAPI_MSG_ERROR, "invalid file path: %s",
				  path);
		return rc;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "open file: %s failed",
			    path);
		return rc;
	}

	rc = llapi_pcc_attach_ro_fd(fd, roid);

	close(fd);
	return rc;
}

int llapi_pcc_attach(const char *path, __u32 id, enum lu_pcc_type type)
{
	int rc;

	switch (type & LU_PCC_TYPE_MASK) {
	case LU_PCC_READWRITE:
		rc = llapi_pcc_attach_rw(path, id);
		break;
	case LU_PCC_READONLY:
		rc = llapi_pcc_attach_ro(path, id);
		break;
	default:
		rc = -EINVAL;
		break;
	}
	return rc;
}

static int llapi_pcc_attach_rw_fid(const char *mntpath,
				   const struct lu_fid *fid,
				   __u32 rwid)
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

	rc = llapi_pcc_attach_rw_fd(fd, rwid);

	close(fd);
	return rc;
}

static int llapi_pcc_attach_ro_fid(const char *mntpath,
				   const struct lu_fid *fid,
				   __u32 roid)
{
	int rc;
	int fd;

	fd = llapi_open_by_fid(mntpath, fid, O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "llapi_open_by_fid for " DFID "failed",
			    PFID(fid));
		return rc;
	}

	rc = llapi_pcc_attach_ro_fd(fd, roid);

	close(fd);
	return rc;
}

int llapi_pcc_attach_fid(const char *mntpath, const struct lu_fid *fid,
			 __u32 id, enum lu_pcc_type type)
{
	int rc;

	switch (type & LU_PCC_TYPE_MASK) {
	case LU_PCC_READWRITE:
		rc = llapi_pcc_attach_rw_fid(mntpath, fid, id);
		break;
	case LU_PCC_READONLY:
		rc = llapi_pcc_attach_ro_fid(mntpath, fid, id);
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

	rc = llapi_fid_parse(fidstr, &fid, NULL);
	if (rc) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "PCC: '%s' is not a valid FID", fidstr);
		return -EINVAL;
	}

	rc = llapi_pcc_attach_fid(mntpath, &fid, id, type);

	return rc;
}

/**
 * detach PCC cache of a file by using fd.
 *
 * \param fd		File handle.
 * \param flags		Detach flags.
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_pcc_detach_fd(int fd, __u32 flags)
{
	struct lu_pcc_detach detach;
	int rc;

	detach.pccd_flags = flags;
	rc = ioctl(fd, LL_IOC_PCC_DETACH, &detach);
	/* If error, save errno value */
	rc = rc ? -errno : 0;

	return rc;
}

/**
 * detach PCC cache of a file via FID.
 *
 * \param dirfd		Dir file handle.
 * \param fid		FID of the file.
 * \param flags		Detach flags.
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_pcc_detach_at(int dirfd, const struct lu_fid *fid,
			enum lu_pcc_detach_flags flags)
{
	struct lu_pcc_detach_fid detach = {
		.pccd_fid = *fid,
		.pccd_flags = flags,
	};
	int rc;

	rc = ioctl(dirfd, LL_IOC_PCC_DETACH_BY_FID, &detach);
	return rc ? -errno : 0;
}

/**
 * detach PCC cache of a file via FID.
 *
 * \param mntpath	Fullpath to the client mount point.
 * \param fid		FID of the file.
 * \param flags		Detach flags.
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_pcc_detach_fid(const char *mntpath, const struct lu_fid *fid,
			 __u32 flags)
{
	int rc;
	int fd;
	struct lu_pcc_detach_fid detach;

	rc = llapi_root_path_open(mntpath, &fd);
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
	detach.pccd_flags = flags;
	rc = ioctl(fd, LL_IOC_PCC_DETACH_BY_FID, &detach);
	rc = rc ? -errno : 0;

	close(fd);
	return rc;
}

/**
 * detach PCC cache of a file via FID.
 *
 * \param mntpath	Fullpath to the client mount point.
 * \param fidstr	FID string of the file.
 * \param flags		Detach flags.
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_pcc_detach_fid_str(const char *mntpath, const char *fidstr,
			     __u32 flags)
{
	int rc;
	struct lu_fid fid;

	rc = llapi_fid_parse(fidstr, &fid, NULL);
	if (rc) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "PCC: '%s' is not a valid FID", fidstr);
		return -EINVAL;
	}

	rc = llapi_pcc_detach_fid(mntpath, &fid, flags);

	return rc;
}

/**
 * detach PCC cache of a file.
 *
 * \param path		Fullpath to the file to operate on.
 * \param flags		Detach flags.
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_pcc_detach_file(const char *path, __u32 flags)
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

	rc = llapi_pcc_detach_fd(fd, flags);
	close(fd);
	return rc;
}

/**
 * Return the current PCC state related to a file.
 *
 * \param fd	File handle for the parent directory.
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
	char *path_copy;
	char *filename;
	int fd;
	int rc;

	fd = open_parent(path);
	if (fd == -1) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "can not open %s", path);
		return rc;
	}

	path_copy = strdup(path);
	if (path_copy == NULL) {
		close(fd);
		return -ENOMEM;
	}

	filename = basename(path_copy);
	state->pccs_namelen = strlen(filename) + 1;
	strncpy(state->pccs_path, filename, sizeof(state->pccs_path) - 1);

	rc = llapi_pcc_state_get_fd(fd, state);
	if (rc != 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "Get PCC state on %s failed",
			    path);
	}

	close(fd);
	free(path_copy);

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
	char pathbuf[sizeof(struct obd_uuid)];
	char buf[65536]; /* large engough to hold PPC dev list */
	glob_t path;
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

	while (1) {
		ssize_t count = read(fd, buf, sizeof(buf));

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

	close(fd);
	cfs_free_param_data(&path);
	return rc;
out_free_param:
	cfs_free_param_data(&path);
	return rc;
}

static int llapi_pcc_scan_detach(const char *pname, const char *fname,
				 struct hsm_scan_control *hsc)
{
	struct lu_pcc_detach_fid detach;
	char fullname[PATH_MAX];
	char fidstr[FID_LEN];
	const char *fidname;
	bool lov_file;
	int rc;

	/* It is the saved lov file when archive on HSM backend. */
	detach.pccd_flags = PCC_DETACH_FL_UNCACHE;
	lov_file = endswith(fname, ".lov");
	if (lov_file) {
		size_t len;

		len = strlen(fname) - strlen(".lov");
		if (len > sizeof(fidstr)) {
			rc = -ENAMETOOLONG;
			errno = ENAMETOOLONG;
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "Too long PCC-RO fname %s/%s",
				    pname, fname);
			return rc;
		}
		strncpy(fidstr, fname, FID_LEN);
		fidstr[len] = '\0';
		detach.pccd_flags |= PCC_DETACH_FL_KNOWN_READWRITE;
		fidname = fidstr;
	} else {
		fidname = fname;
	}

	rc = llapi_fid_parse(fidname, &detach.pccd_fid, NULL);
	if (rc) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "PCC: '%s' is not a valid FID", fidname);
		return rc;
	}

	llapi_printf(LLAPI_MSG_DEBUG, "Handle the file: %s\n", fidname);

	rc = ioctl(hsc->hsc_mntfd, LL_IOC_PCC_DETACH_BY_FID, &detach);
	if (rc) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "failed to detach file '%s'\n", fidname);
		return rc;
	}

	if (detach.pccd_flags & PCC_DETACH_FL_CACHE_REMOVED) {
		llapi_printf(LLAPI_MSG_DEBUG,
			     "Detach and remove the PCC cached file: %s\n",
			     fidname);
	} else if (detach.pccd_flags & PCC_DETACH_FL_ATTACHING) {
		llapi_printf(LLAPI_MSG_DEBUG,
			     "'%s' is being attached, skip it", fidname);
	} else {
		snprintf(fullname, sizeof(fullname), "%s/%s", pname, fidname);
		llapi_printf(LLAPI_MSG_DEBUG,
			     "Remove non-cached file: %s flags: %X\n",
			     fullname, detach.pccd_flags);
		if (unlink(fullname) && errno != ENOENT) {
			rc = -errno;
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "Unlink %s failed", fullname);
		}

		if (detach.pccd_flags & PCC_DETACH_FL_KNOWN_READWRITE) {
			snprintf(fullname, sizeof(fullname), "%s/%s",
				 pname, fname);
			/* Remove *.lov file */
			unlink(fullname);
		}
	}

	return rc;
}

static int llapi_pcc_del_internal(const char *mntpath, const char *pccpath,
				  enum hsmtool_type type,
				  enum lu_pcc_cleanup_flags flags)
{
	struct hsm_scan_control hsc = {
		.hsc_type = type,
		.hsc_mntpath = mntpath,
		.hsc_hsmpath = pccpath,
		.hsc_mntfd = -1,
		.hsc_func = llapi_pcc_scan_detach,
		.hsc_errnum = 0,
	};
	char cmd[PATH_MAX];
	int rc;

	snprintf(cmd, sizeof(cmd), "del %s", pccpath);
	rc = llapi_pccdev_set(mntpath, cmd);
	if (rc < 0) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "failed to run '%s' on %s", cmd, mntpath);
		return rc;
	}

	if (flags & PCC_CLEANUP_FL_KEEP_DATA)
		return 0;

	hsc.hsc_mntfd = open(mntpath, O_RDONLY);
	if (hsc.hsc_mntfd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot open '%s'", mntpath);
		return rc;
	}

	rc = hsm_scan_process(&hsc);
	close(hsc.hsc_mntfd);

	return rc;
}

struct pcc_cmd_handler;

typedef int (*pcc_handler_t)(struct cYAML *node, struct pcc_cmd_handler *pch);

enum pcc_cmd_t {
	PCC_CMD_DEL,
	PCC_CMD_CLEAR,
};

struct pcc_cmd_handler {
	enum pcc_cmd_t			 pch_cmd;
	enum lu_pcc_type		 pch_type;
	bool				 pch_iter_cont;
	enum lu_pcc_cleanup_flags	 pch_flags;
	const char			*pch_mntpath;
	const char			*pch_pccpath;
	pcc_handler_t			 pch_cb;
	__u32				 pch_id;
};

static int llapi_pcc_yaml_cb_helper(struct pcc_cmd_handler *pch)
{
	struct cYAML *tree = NULL, *err_rc = NULL, *pcc_node = NULL,
		     *node = NULL;
	char pathbuf[sizeof(struct obd_uuid)];
	glob_t path;
	int rc;

	rc = llapi_getname(pch->pch_mntpath, pathbuf, sizeof(pathbuf));
	if (rc < 0) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot get name for '%s'\n", pch->pch_mntpath);
		return rc;
	}

	rc = cfs_get_param_paths(&path, "llite/%s/pcc", pathbuf);
	if (rc != 0)
		return -errno;

	tree = cYAML_build_tree(path.gl_pathv[0], NULL, 0, &err_rc, false);
	if (!tree) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot parse YAML file %s\n", path.gl_pathv[0]);
		cYAML_build_error(rc, -1, "yaml", "from PCC yaml",
				  "can't parse", &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		goto out_free;
	}

	pcc_node = cYAML_get_object_item(tree, "pcc");
	if (!pcc_node)
		goto out_free;

	if (!cYAML_is_sequence(pcc_node)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "bad PCC backend Array!");
		goto out_free;
	}

	while (cYAML_get_next_seq_item(pcc_node, &node) != NULL &&
	       pch->pch_iter_cont) {
		int ret;

		ret = pch->pch_cb(node, pch);
		if (ret && !rc)
			rc = ret;
	}

	/* Not found the given PCC backend on the client. */
	if (pch->pch_iter_cont && pch->pch_cmd == PCC_CMD_DEL)
		rc = -ENOENT;

out_free:
	if (tree)
		cYAML_free_tree(tree);
	cfs_free_param_data(&path);
	return rc;

}

static int llapi_handle_yaml_pcc_del(struct cYAML *node,
				     struct pcc_cmd_handler *pch)
{
	struct cYAML *pccpath, *hsmtool;
	enum hsmtool_type type;

	pccpath = cYAML_get_object_item(node, PCC_YAML_PCCPATH);
	hsmtool = cYAML_get_object_item(node, PCC_YAML_HSMTOOL);

	if (!pccpath || !pccpath->cy_valuestring ||
	    !hsmtool || !hsmtool->cy_valuestring)
		return 0;

	if (strcmp(pccpath->cy_valuestring, pch->pch_pccpath))
		return 0;

	pch->pch_iter_cont = false;
	type = hsmtool_string2type(hsmtool->cy_valuestring);
	return llapi_pcc_del_internal(pch->pch_mntpath, pch->pch_pccpath,
				      type, pch->pch_flags);
}

int llapi_pcc_del(const char *mntpath, const char *pccpath,
		  enum lu_pcc_cleanup_flags flags)
{
	struct pcc_cmd_handler pch;

	pch.pch_cmd = PCC_CMD_DEL;
	pch.pch_iter_cont = true;
	pch.pch_mntpath = mntpath;
	pch.pch_pccpath = pccpath;
	pch.pch_flags = flags;
	pch.pch_cb = llapi_handle_yaml_pcc_del;

	return llapi_pcc_yaml_cb_helper(&pch);
}


static int llapi_handle_yaml_pcc_clear(struct cYAML *node,
				       struct pcc_cmd_handler *pch)
{
	struct cYAML *pccpath, *hsmtool;
	enum hsmtool_type type;

	pccpath = cYAML_get_object_item(node, PCC_YAML_PCCPATH);
	hsmtool = cYAML_get_object_item(node, PCC_YAML_HSMTOOL);

	if (!pccpath || !pccpath->cy_valuestring ||
	    !hsmtool || !hsmtool->cy_valuestring)
		return 0;

	type = hsmtool_string2type(hsmtool->cy_valuestring);
	return llapi_pcc_del_internal(pch->pch_mntpath,
				      pccpath->cy_valuestring,
				      type, pch->pch_flags);
}

int llapi_pcc_clear(const char *mntpath, enum lu_pcc_cleanup_flags flags)
{
	struct pcc_cmd_handler pch;

	pch.pch_cmd = PCC_CMD_CLEAR;
	pch.pch_iter_cont = true;
	pch.pch_mntpath = mntpath;
	pch.pch_pccpath = NULL;
	pch.pch_flags = flags;
	pch.pch_cb = llapi_handle_yaml_pcc_clear;

	return llapi_pcc_yaml_cb_helper(&pch);
}
