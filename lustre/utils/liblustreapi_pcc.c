// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (c) 2017, DDN Storage Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustreapi library for Persistent Client Cache.
 *
 * Author: Li Xi <lixi@ddn.com>
 * Author: Qian Yingjin <qian@ddn.com>
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <linux/lustre/lustre_fid.h>
#include <linux/lustre/lustre_user.h>
#include <lnetconfig/cyaml.h>
#include <lustre/lustreapi.h>

#include "lustreapi_internal.h"
#include "libhsm_scanner.h"

/*
 * Fetch and attach a file to readwrite PCC.
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

/**
 * llapi_pcc_attach_fid_str() - Attach file to the PCC
 * @mntpath: Fullpath to the client mount point.
 * @fidstr: file to be attach (FID)
 * @id: unique id
 * @type: PCC type
 *
 * Return %0 on successful attachment or %negative on error
 */
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
 * llapi_pcc_detach_fd() - detach PCC cache of a file by using fd.
 * @fd: File handle.
 * @flags: Detach flags.
 *
 * Return %0 on success or %-errno on failure
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
 * llapi_pcc_detach_at() - detach PCC cache of a file via FID.
 * @dirfd: Dir file handle.
 * @fid: FID of the file.
 * @flags: Detach flags.
 *
 * Return %0 on success or %-errno on failure
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
 * llapi_pcc_detach_fid() - detach PCC cache of a file via FID.
 * @mntpath: Fullpath to the client mount point.
 * @fid: FID of the file.
 * @flags: Detach flags.
 *
 * Return %0 on success or %-errno on failure
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
 * llapi_pcc_detach_fid_str() - detach PCC cache of a file via FID.
 * @mntpath: Fullpath to the client mount point.
 * @fidstr: FID string of the file.
 * @flags: Detach flags.
 *
 * Return %0 on success or %-errno on failure
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
 * llapi_pcc_detach_file() - detach PCC cache of a file.
 * @path: Fullpath to the file to operate on.
 * @flags: Detach flags.
 *
 * Return %0 on success or %-errno on failure
 */
int llapi_pcc_detach_file(const char *path, __u32 flags)
{
	int rc;
	int fd;

	/* Specify O_CIPHERTEXT | O_DIRECT flags to allow pcc detach
	 * on encrypted file without the key.
	 */
	fd = open(path, O_RDWR | O_NONBLOCK | O_CIPHERTEXT | O_DIRECT);
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
 * llapi_pcc_state_get_fd() - Return the current PCC state related to a file.
 * @fd: File handle for the parent directory.
 * @state: PCC state info.
 *
 * Return %0 on success or %-errno on failure
 */
int llapi_pcc_state_get_fd(int fd, struct lu_pcc_state *state)
{
	int rc;

	rc = ioctl(fd, LL_IOC_PCC_STATE, state);
	/* If error, save errno value */
	rc = rc ? -errno : 0;

	return rc;
}

/*
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
 * llapi_pccdev_set() - Add/delete a PCC backend on a client.
 * @mntpath: Fullpath to the client mount point.
 * @cmd: command to be executed
 *
 * Return %0 on success or %-errno on failure
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
 * llapi_pccdev_get() - List all PCC backend devices on a client.
 * @mntpath: Fullpath to the client mount point.
 *
 * Return %0 on success or %-errno on failure
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
	char fidstr[FID_LEN + 1];
	const char *fidname;
	bool lov_file;
	int rc;

	/* It is the saved lov file when archive on HSM backend. */
	detach.pccd_flags = PCC_DETACH_FL_UNCACHE;
	lov_file = endswith(fname, ".lov");
	if (lov_file) {
		size_t len;

		len = strlen(fname) - strlen(".lov");
		if (len >= sizeof(fidstr)) {
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

	snprintf(cmd, sizeof(cmd), "%s %s", PCC_CMDNAME_DEL, pccpath);
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
	PCC_CMD_BACKEND_SELECT,
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

out_free:
	/* Not found the given PCC backend on the client. */
	if (pch->pch_iter_cont && (pch->pch_cmd == PCC_CMD_DEL ||
	    pch->pch_cmd == PCC_CMD_BACKEND_SELECT))
		rc = -ENOENT;

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

static int llapi_pcc_yaml_backend_get(struct cYAML *node,
				      struct pcc_cmd_handler *pch)
{
	struct cYAML *pccid;

	/* TODO: check the flags of PCC backends. */
	pccid = cYAML_get_object_item(node, pch->pch_type == LU_PCC_READWRITE ?
				      PCC_YAML_RWID : PCC_YAML_ROID);
	if (!pccid || pccid->cy_valueint == 0)
		return 0;

	pch->pch_iter_cont = false;
	pch->pch_id = pccid->cy_valueint;
	return 0;
}

int llapi_pcc_backend_id_get(const char *path, enum lu_pcc_type type, __u32 *id)
{
	struct pcc_cmd_handler pch;
	int rc;

	memset(&pch, 0, sizeof(pch));
	pch.pch_cmd = PCC_CMD_BACKEND_SELECT;
	pch.pch_iter_cont = true;
	pch.pch_mntpath = path;
	pch.pch_type = type;
	pch.pch_cb = llapi_pcc_yaml_backend_get;

	rc = llapi_pcc_yaml_cb_helper(&pch);
	if (rc == 0)
		*id = pch.pch_id;

	return rc;
}

#define PIN_YAML_HSM_STR	"hsm"

int verify_pin_xattr_object(struct cYAML *yaml)
{
	struct cYAML *node = NULL;

	if (yaml->cy_type != CYAML_TYPE_OBJECT)
		return -EINVAL;

	for (node = yaml->cy_child; node != NULL; node = node->cy_next) {
		/*
		 * Pin entries are stored as a flat mapping from key -> value,
		 * where existing PCC/HSM pins use numeric values
		 * (CYAML_TYPE_NUMBER) and pool pins use string values
		 * (CYAML_TYPE_STRING).
		 */
		if (node->cy_type != CYAML_TYPE_NUMBER &&
		    node->cy_type != CYAML_TYPE_STRING)
			return -EINVAL;
	}

	return 0;
}

/*
 * Parse a lustre.pin string that uses the extended pool syntax.
 *
 * Accepts a comma-separated "key: value" list, for example:
 *   [hsm: 1,pool: ["pool1","^pool2","^any"]]
 * where the "pool" value is itself a YAML flow sequence (or a bare
 * scalar) of pool names, each optionally prefixed with '^' to mark it as
 * denied, plus a literal "^any" token to mark the file as pinned
 * exclusively to the positive pool names listed alongside it.
 *
 * This is translated into a flat cYAML object with keys:
 *   - hsm: 1                (number, passed through unchanged)
 *   - pool: pool1           (string, one entry per positive pool token)
 *   - deny_pool: pool2      (string, one entry per ^poolX token)
 *   - only_pool: pool1      (string, added when ^any is present together
 *                             with at least one positive pool token)
 *
 * "only_pool" and "deny_pool" are internal keys produced by this parser;
 * they are rejected if they appear as keys in the textual pin string
 * itself, since callers must express those constraints via "^" markers
 * in the "pool" list instead.
 *
 * The outer "[...]" wrapper around the whole pin string is optional; when
 * omitted we still expect a comma-separated "key: value" list.
 *
 * @buff is parsed in place (tokens are NUL-terminated in the caller's
 * buffer) to avoid an extra XATTR_SIZE_MAX-sized copy on the stack; the
 * buffer's contents past this call should be considered clobbered.
 */
static struct cYAML *parse_pin_xattr_advanced(char *buff, int len)
{
	struct cYAML *root = NULL;
	int pos, end;

	if (len < 1 || len > XATTR_SIZE_MAX)
		goto invalid;

	root = cYAML_create_object(NULL, NULL);
	if (root == NULL)
		goto invalid;

	if (buff[0] == '[' && buff[len - 1] == ']') {
		/* Standard bracketed lustre.pin form. */
		pos = 1; /* after '[' */
		end = len - 1; /* index of ']' */
	} else {
		/* Also accept unbracketed comma-separated "key: value" list */
		pos = 0;
		end = len;
	}

	while (pos < end) {
		int key_start, key_end;
		int val_start, v_end, val_end;
		char *key, *val;

		/* Skip whitespace and stray commas. */
		while (pos < end && (isspace((unsigned char)buff[pos]) ||
				     buff[pos] == ','))
			pos++;
		if (pos >= end)
			break;

		key_start = pos;
		while (pos < end && !isspace((unsigned char)buff[pos]) &&
		       buff[pos] != ':')
			pos++;
		key_end = pos;
		while (pos < end && isspace((unsigned char)buff[pos]))
			pos++;
		if (pos >= end || buff[pos] != ':')
			goto invalid;
		buff[key_end] = '\0';
		key = &buff[key_start];

		pos++; /* skip ':' */
		while (pos < end && isspace((unsigned char)buff[pos]))
			pos++;
		val_start = pos;

		/*
		 * Find the end of this value. We keep everything up to the
		 * comma that clearly starts the next key (", <ident>:") or to
		 * the closing ']'.
		 */
		v_end = end;
		int i;

		for (i = pos; i < end; i++) {
			if (buff[i] != ',')
				continue;
			int j = i + 1;
			int k;

			while (j < end && isspace((unsigned char)buff[j]))
				j++;
			k = j;
			while (k < end && buff[k] != ':' && buff[k] != ',' &&
			       !isspace((unsigned char)buff[k]))
				k++;
			if (k < end && buff[k] == ':') {
				v_end = i;
				break;
			}
		}

		val_end = v_end;
		while (val_end > val_start &&
		       isspace((unsigned char)buff[val_end - 1]))
			val_end--;
		buff[val_end] = '\0';
		val = &buff[val_start];

		if (strcmp(key, "pool") == 0) {
			bool saw_any = false;
			char *first_pool = NULL;
			int tpos = 0;
			char *close;

			/*
			 * Support a YAML flow sequence for the pool list, e.g.:
			 *   ["pool1","^pool2","^any"]
			 * Strip a single surrounding '[...]' pair if present so
			 * that the inner comma-separated list can be tokenised.
			 */
			while (val[tpos] != '\0' &&
			       isspace((unsigned char)val[tpos]))
				tpos++;
			if (val[tpos] == '[') {
				close = &val[strlen(val) - 1];
				while (close > &val[tpos] &&
				       isspace((unsigned char)*close))
					close--;
				if (*close == ']') {
					*close = '\0';
					/* Skip the opening '['. */
					val = &val[tpos + 1];
				}
				tpos = 0;
			}
			while (val[tpos] != '\0') {
				int t_start, t_end;
				char *tok;
				char *tok_end;

				while (isspace((unsigned char)val[tpos]))
					tpos++;
				if (val[tpos] == '\0')
					break;
				t_start = tpos;
				while (val[tpos] != '\0' && val[tpos] != ',')
					tpos++;
				t_end = tpos;
				if (val[tpos] == ',')
					val[tpos++] = '\0';
				while (t_end > t_start &&
				       isspace((unsigned char)val[t_end - 1]))
					val[--t_end] = '\0';
				if (t_end <= t_start)
					continue;
				tok = &val[t_start];
				tok_end = &val[t_end - 1];

				/* Strip optional single/double quotes so we
				 * accept pool: ["pool","^pool2","^any"].
				 */
				if ((*tok == '"' || *tok == '\'') &&
				    tok_end > tok && *tok_end == *tok) {
					*tok_end = '\0';
					tok++;
				}

				if (tok[0] == '^') {
					if (strcmp(tok + 1, "any") == 0) {
						saw_any = true;
					} else if (cYAML_create_string(root,
								       "deny_pool",
								       tok + 1)
						   == NULL) {
						goto invalid;
					}
				} else {
					if (cYAML_create_string(root,
								"pool",
								tok) == NULL)
						goto invalid;
					if (first_pool == NULL)
						first_pool = tok;
				}
			}
			if (saw_any) {
				if (first_pool == NULL)
					goto invalid;
				if (cYAML_create_string(root,
							"only_pool",
							first_pool) == NULL)
					goto invalid;
			}
		} else {
			/* Generic key: parse as integer if possible, else as
			 * string. Explicit pool-constraint keys such as
			 * "only_pool" and "deny_pool" are not accepted in the
			 * textual pin string; callers must use the "pool" list
			 * with ^pool and ^any elements instead.
			 */
			if (strcmp(key, "only_pool") == 0 ||
			    strcmp(key, "deny_pool") == 0)
				goto invalid;
			char *v = val;
			bool is_num = false;

			if (*v == '-' || isdigit((unsigned char)*v)) {
				char *endp;
				long n;

				errno = 0;
				n = strtol(v, &endp, 10);
				if (errno == 0 && *endp == '\0')
					is_num = true;
				else
					errno = 0;
				if (is_num) {
					if (cYAML_create_number(root, key,
								(double)n) ==
					    NULL)
						goto invalid;
				}
			}
			if (!is_num) {
				if (cYAML_create_string(root, key, v) == NULL)
					goto invalid;
			}
		}

		pos = v_end + 1;
	}

	return root;

invalid:
	if (root)
		cYAML_free_tree(root);
	llapi_error(LLAPI_MSG_ERROR, EINVAL,
		    "invalid pin string '%.*s'.", len, buff);
	errno = EINVAL;
	return NULL;
}

/* Append a single character to *pp, bounds-checked against buff+buflen. */
static int pin_obj_putc(char **pp, char *buff, int buflen, char c)
{
	if (*pp - buff >= buflen - 1)
		return -EOVERFLOW;
	*(*pp)++ = c;
	return 0;
}

/*
 * Serialise a lustre.pin cYAML object into its string form.
 *
 * The on-disk representation is a single bracketed list of
 * comma-separated "key: value" pairs, for example:
 *   [hsm: 1,pool: [pool1,^pool2,^any]]
 *
 * Pool-related entries are flattened into a single YAML-compatible
 * list under the "pool" key:
 *   - each "pool: <name>" entry becomes a <name> element,
 *   - each "deny_pool: <name>" entry becomes a ^<name> element,
 *   - an "only_pool: <name>" constraint is encoded as a trailing
 *     ^any element, provided at least one positive pool entry exists.
 */
int dump_pin_object(struct cYAML *yaml, char *buff, int buflen)
{
	int rc = 0, remained;
	struct cYAML *node;
	char *p = buff;
	bool have_pool = false, have_deny = false, have_only = false;
	bool have_pool_tokens;
	bool first_entry = true;
	bool single_pool_scalar = false;
	int pool_count = 0, deny_count = 0;

	if (yaml->cy_child == NULL) {
		buff[0] = '\0';
		goto out;
	}

	/* Pre-scan for pool-related keys so that we can emit a single
	 * YAML-compatible pool list.
	 */
	for (node = yaml->cy_child; node != NULL; node = node->cy_next) {
		if (node->cy_type != CYAML_TYPE_STRING ||
		    node->cy_valuestring == NULL)
			continue;
		if (strcmp(node->cy_string, "pool") == 0) {
			have_pool = true;
			pool_count++;
		} else if (strcmp(node->cy_string, "deny_pool") == 0) {
			have_deny = true;
			deny_count++;
		}
		else if (strcmp(node->cy_string, "only_pool") == 0) {
			have_only = true;
		}
	}

	/* We only encode "only_pool" as "^any" when there is at least one
	 * positive pool entry; a lone only_pool key is preserved as-is.
	 */
	have_pool_tokens = have_pool || have_deny;
	if (have_pool_tokens &&
	    (pool_count + deny_count == 1) &&
	    !(have_only && have_pool))
		single_pool_scalar = true;

	rc = pin_obj_putc(&p, buff, buflen, '[');
	if (rc < 0)
		goto out;

	/* Emit non-pool-related keys first as "key: value" pairs. */
	for (node = yaml->cy_child; node != NULL; node = node->cy_next) {
		bool is_pool_key = false;

		if (node->cy_type == CYAML_TYPE_STRING &&
		    node->cy_valuestring != NULL) {
			if (strcmp(node->cy_string, "pool") == 0 ||
			    strcmp(node->cy_string, "deny_pool") == 0 ||
			    (strcmp(node->cy_string, "only_pool") == 0 &&
			     have_pool_tokens))
				is_pool_key = true;
		}

		if (is_pool_key)
			continue;

		if (!first_entry) {
			rc = pin_obj_putc(&p, buff, buflen, ',');
			if (rc < 0)
				goto out;
		}
		first_entry = false;

		remained = buff + buflen - p - 1;
		if (node->cy_type == CYAML_TYPE_NUMBER) {
			rc = snprintf(p, remained, "%s: %ld",
				      node->cy_string, node->cy_valueint);
		} else if (node->cy_type == CYAML_TYPE_STRING &&
			   node->cy_valuestring != NULL) {
			rc = snprintf(p, remained, "%s: %s",
				      node->cy_string, node->cy_valuestring);
		} else {
			rc = -EINVAL;
			goto out;
		}
		if (rc <= 0) {
			rc = -errno;
			goto out;
		} else if (rc > remained) {
			rc = -EOVERFLOW;
			goto out;
		}
		p += rc;
	}

	/* Now emit the combined pool representation, if any pool-related
	 * entries exist. For a single pool/deny entry with no exclusive
	 * marker we emit a simple scalar (pool: name or pool: ^name); when
	 * multiple entries or an exclusive constraint are present we use a
	 * YAML-compatible list.
	 */
	if (have_pool_tokens) {
		if (!first_entry) {
			rc = pin_obj_putc(&p, buff, buflen, ',');
			if (rc < 0)
				goto out;
		}
		first_entry = false;

		if (single_pool_scalar) {
			const char *name = NULL;
			bool is_deny = false;

			for (node = yaml->cy_child; node != NULL;
			     node = node->cy_next) {
				if (node->cy_type != CYAML_TYPE_STRING ||
				    node->cy_valuestring == NULL)
					continue;
				if (strcmp(node->cy_string, "pool") == 0) {
					name = node->cy_valuestring;
					is_deny = false;
					break;
				} else if (strcmp(node->cy_string, "deny_pool") == 0) {
					name = node->cy_valuestring;
					is_deny = true;
					break;
				}
			}

			if (name != NULL) {
				remained = buff + buflen - p - 1;
				if (is_deny)
					rc = snprintf(p, remained, "pool: ^%s",
						      name);
				else
					rc = snprintf(p, remained, "pool: %s",
						      name);
				if (rc <= 0) {
					rc = -errno;
					goto out;
				} else if (rc > remained) {
					rc = -EOVERFLOW;
					goto out;
				}
				p += rc;
			}
		} else {
			bool first_tok = true;

			remained = buff + buflen - p - 1;
			rc = snprintf(p, remained, "pool: [");
			if (rc <= 0) {
				rc = -errno;
				goto out;
			} else if (rc > remained) {
				rc = -EOVERFLOW;
				goto out;
			}
			p += rc;

			/* Positive pools. */
			for (node = yaml->cy_child; node != NULL;
			     node = node->cy_next) {
				if (node->cy_type != CYAML_TYPE_STRING ||
				    node->cy_valuestring == NULL ||
				    strcmp(node->cy_string, "pool") != 0)
					continue;

				if (!first_tok) {
					rc = pin_obj_putc(&p, buff, buflen, ',');
					if (rc < 0)
						goto out;
				}
				first_tok = false;

				remained = buff + buflen - p - 1;
				rc = snprintf(p, remained, "%s",
					      node->cy_valuestring);
				if (rc <= 0) {
					rc = -errno;
					goto out;
				} else if (rc > remained) {
					rc = -EOVERFLOW;
					goto out;
				}
				p += rc;
			}

			/* Deny pools. */
			for (node = yaml->cy_child; node != NULL;
			     node = node->cy_next) {
				if (node->cy_type != CYAML_TYPE_STRING ||
				    node->cy_valuestring == NULL ||
				    strcmp(node->cy_string, "deny_pool") != 0)
					continue;

				if (!first_tok) {
					rc = pin_obj_putc(&p, buff, buflen, ',');
					if (rc < 0)
						goto out;
				}
				first_tok = false;

				remained = buff + buflen - p - 1;
				rc = snprintf(p, remained, "^%s",
					      node->cy_valuestring);
				if (rc <= 0) {
					rc = -errno;
					goto out;
				} else if (rc > remained) {
					rc = -EOVERFLOW;
					goto out;
				}
				p += rc;
			}

			/* Exclusive marker. */
			if (have_only && have_pool) {
				if (!first_tok) {
					rc = pin_obj_putc(&p, buff, buflen, ',');
					if (rc < 0)
						goto out;
				}
				first_tok = false;

				remained = buff + buflen - p - 1;
				rc = snprintf(p, remained, "^any");
				if (rc <= 0) {
					rc = -errno;
					goto out;
				} else if (rc > remained) {
					rc = -EOVERFLOW;
					goto out;
				}
				p += rc;
			}

			rc = pin_obj_putc(&p, buff, buflen, ']');
			if (rc < 0)
				goto out;
		}
	}

	rc = pin_obj_putc(&p, buff, buflen, ']');
	if (rc < 0)
		goto out;
	*p = '\0';

	rc = 0;
out:
	return rc;
}

struct cYAML *read_pin_xattr_object(const char *path)
{
	int rc;
	struct cYAML *yaml = NULL;
	char buff[XATTR_SIZE_MAX];

	rc = getxattr(path, XATTR_LUSTRE_PIN, buff, sizeof(buff));
	if (rc < 0)
		goto out;

	yaml = parse_pin_xattr_advanced(buff, rc);
	if (yaml == NULL)
		goto out;

	rc = verify_pin_xattr_object(yaml);
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, -rc, "Invalid pin object.");
		cYAML_free_tree(yaml);
		yaml = NULL;
		errno = -rc;
		goto out;
	}

out:
	return yaml;
}

struct cYAML *read_pin_xattr_object_fd(int fd)
{
	int rc;
	struct cYAML *yaml = NULL;
	char buff[XATTR_SIZE_MAX];

	rc = fgetxattr(fd, XATTR_LUSTRE_PIN, buff, sizeof(buff));
	if (rc < 0)
		goto out;

	yaml = parse_pin_xattr_advanced(buff, rc);
	if (yaml == NULL)
		goto out;

	rc = verify_pin_xattr_object(yaml);
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, -rc, "Invalid pin object.");
		cYAML_free_tree(yaml);
		yaml = NULL;
		errno = -rc;
		goto out;
	}

out:
	return yaml;
}

int llapi_pcc_pin_file(const char *path, __u32 id)
{
	int rc = 0;
	struct cYAML *yaml, *node;
	char buff[XATTR_SIZE_MAX];

	yaml = read_pin_xattr_object(path);

	if (yaml == NULL && errno == ENODATA) {
		snprintf(buff, sizeof(buff), "[%s: %d]", PIN_YAML_HSM_STR, id);
		goto set;

	}
	if (yaml == NULL) {
		llapi_error(LLAPI_MSG_ERROR, errno,
			    "cannot read or parse pin xattr of file '%s'.",
			    path);
		rc = -errno;
		goto out;
	}

	/* Now we have an valid pin object, search for existing entry */
	for (node = yaml->cy_child; node != NULL; node = node->cy_next) {
		if (strcmp(node->cy_string, PIN_YAML_HSM_STR) == 0 &&
		    node->cy_valueint == id)
			break;
	}
	if (node != NULL) {
		rc = 0;
		goto out;
	}

	node = cYAML_create_number(yaml, PIN_YAML_HSM_STR, id);
	if (node == NULL) {
		rc = -errno;
		goto out;
	}

	rc = dump_pin_object(yaml, buff, sizeof(buff));
	if (rc)
		goto out;

set:
	rc = setxattr(path, XATTR_LUSTRE_PIN, buff, strlen(buff), 0);
	if (rc < 0)
		rc = -errno;
out:
	return rc;
}

int llapi_pcc_unpin_file(const char *path, __u32 id)
{
	int rc = 0;
	struct cYAML *yaml, *node;
	char buff[XATTR_SIZE_MAX];

	yaml = read_pin_xattr_object(path);

	if (yaml == NULL && errno == ENODATA) {
		rc = 0;
		goto out;
	}
	if (yaml == NULL) {
		llapi_error(LLAPI_MSG_ERROR, errno,
			    "cannot read or parse pin xattr of file '%s'.",
			    path);
		rc = -errno;
		goto out;
	}

	/* We have an valid pin object, search for the entry to be deleted */
	for (node = yaml->cy_child; node != NULL; node = node->cy_next) {
		if (strcmp(node->cy_string, PIN_YAML_HSM_STR) == 0 &&
		    node->cy_valueint == id)
			break;
	}
	if (node == NULL) {
		rc = 0;
		goto out;
	}

	/* Remove the node */
	if (node == yaml->cy_child) {
		/* the first child */
		if (node->cy_next)
			node->cy_next->cy_prev = NULL;
		yaml->cy_child = node->cy_next;
	} else {
		/* not the first child */
		node->cy_prev->cy_next = node->cy_next;
		if (node->cy_next)
			node->cy_next->cy_prev = node->cy_prev;
	}
	node->cy_prev = node->cy_next = NULL;
	cYAML_free_tree(node);

	rc = dump_pin_object(yaml, buff, sizeof(buff));
	if (rc)
		goto out;

	if (strlen(buff) == 0)
		rc = removexattr(path, XATTR_LUSTRE_PIN);
	else
		rc = setxattr(path, XATTR_LUSTRE_PIN, buff, strlen(buff), 0);

	if (rc < 0)
		rc = -errno;

out:
	return rc;
}
