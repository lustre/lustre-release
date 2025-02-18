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
 * lustre/utils/liblustreapi_root.c
 *
 * lustreapi library for managing the root fd cache for llapi internal use.
 *
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 *
 * Copyright (c) 2018, 2022, Data Direct Networks
 */

/* for O_DIRECTORY and struct file_handle */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <libgen.h> /* for dirname() */
#include <mntent.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h> /* for makedev() */
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include <libcfs/util/ioctl.h>
#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_fid.h>
#include "lustreapi_internal.h"

/* could have an array of these for a handful of different paths */
static struct root_cache {
	dev_t	dev;
	char	fsname[PATH_MAX];
	char	mnt_dir[PATH_MAX];
	char	nid[MAX_LINE_LEN];
	int	fd; /* cached fd on filesystem root for internal use only */
} root_cached = { 0 };

static pthread_rwlock_t root_cached_lock = PTHREAD_RWLOCK_INITIALIZER;

static int get_root_fd(const char *rootpath, int *outfd)
{
	int rc = 0;
	int fd;

	fd = open(rootpath, O_RDONLY | O_DIRECTORY | O_NONBLOCK);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot open '%s'", rootpath);
	} else {
		*outfd = fd;
	}

	return rc;
}

static int get_file_dev(const char *path, dev_t *dev)
{
#ifdef HAVE_STATX
	struct statx stx;

	if (!dev)
		return -EINVAL;
	if (statx(AT_FDCWD, path, 0, 0, &stx))
		return -errno;
	*dev = makedev(stx.stx_dev_major, stx.stx_dev_minor);
#else
	struct stat st;

	if (!dev)
		return -EINVAL;
	if (stat(path, &st) != 0)
		return -errno;

	*dev = st.st_dev;
#endif
	return 0;
}

static int get_root_path_fast(int want, char *fsname, int *outfd, char *path,
			      dev_t *dev, char *nid)
{
	int rc = -ENODEV;
	int fsnamelen;
	int mntlen;

	if (root_cached.dev == 0)
		return rc;

	/* hold a write lock on the cache if fd is going to be updated */
	if ((want & WANT_FD) && outfd && root_cached.fd <= 0)
		pthread_rwlock_wrlock(&root_cached_lock);
	else
		pthread_rwlock_rdlock(&root_cached_lock);

	if (root_cached.dev == 0)
		goto out_unlock;

	fsnamelen = strlen(root_cached.fsname);
	mntlen = strlen(root_cached.mnt_dir);

	/* Check the dev for a match, if given */
	if (!(want & WANT_DEV) && dev && *dev == root_cached.dev) {
		rc = 0;
	/* Check the fsname for a match, if given */
	} else if (!(want & WANT_FSNAME) && fsname &&
		   strlen(fsname) == fsnamelen &&
		   (strncmp(root_cached.fsname, fsname, fsnamelen) == 0)) {
		rc = 0;
	/* Otherwise find the longest matching path */
	} else if (path && strlen(path) >= mntlen &&
		   (strncmp(root_cached.mnt_dir, path, mntlen) == 0) &&
		   (strlen(path) == mntlen || path[mntlen] == '/')) {
		rc = 0;
	}

	if (rc)
		goto out_unlock;

	if ((want & WANT_FSNAME) && fsname)
		strcpy(fsname, root_cached.fsname);
	if ((want & WANT_PATH) && path)
		strcpy(path, root_cached.mnt_dir);
	if ((want & WANT_DEV) && dev)
		*dev = root_cached.dev;
	if ((want & WANT_FD) && outfd) {
		if (root_cached.fd > 0) {
			*outfd = root_cached.fd;
		} else {
			rc = get_root_fd(root_cached.mnt_dir, outfd);
			if (!rc)
				root_cached.fd = *outfd;
		}
	}
	if ((want & WANT_NID) && nid)
		strcpy(nid, root_cached.nid);
out_unlock:
	pthread_rwlock_unlock(&root_cached_lock);

	return rc;
}

static int get_root_path_slow(int want, char *fsname, int *outfd, char *path,
			      int index, dev_t *dev, char *nid)
{
	struct mntent mnt;
	char buf[PATH_MAX];
	char *ptr, *ptr_end;
	FILE *fp;
	int idx = -1, mntlen = 0;
	int rc = -ENODEV;
	int fsnamelen = 0;
	dev_t devmnt = 0;

	/* get the mount point */
	fp = setmntent(PROC_MOUNTS, "r");
	if (fp == NULL) {
		rc = -EIO;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot retrieve filesystem mount point");
		return rc;
	}
	while (getmntent_r(fp, &mnt, buf, sizeof(buf))) {

		if (!llapi_is_lustre_mnt(&mnt))
			continue;

		idx++;
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

		fsnamelen = ptr_end - ptr;

		/* avoid stat/statx call if path does not match mountpoint */
		if (path && (strlen(path) >= mntlen) &&
		    (strncmp(mnt.mnt_dir, path, mntlen) != 0))
			continue;

		/* ignore unaccessible filesystem */
		if (get_file_dev(mnt.mnt_dir, &devmnt))
			continue;

		if ((want & WANT_INDEX) && idx == index) {
			rc = 0;
			break;
		}

		/* Check the fsname for a match, if given */
		if (!(want & WANT_FSNAME) && fsname &&
		    strlen(fsname) == fsnamelen &&
		    (strncmp(ptr, fsname, fsnamelen) == 0)) {
			rc = 0;
			break;
		}

		/* Check the dev for a match, if given */
		if (!(want & WANT_DEV) && dev && *dev == devmnt) {
			rc = 0;
			break;
		}

		/*
		 * Otherwise find the longest matching path beginning of path
		 * and mnt_dir already verified to be the same.
		 */
		if (path && (strlen(path) == mntlen || path[mntlen] == '/')) {
			rc = 0;
			break;
		}
	}

	if (rc)
		goto out;

	/* Found it */
	if (!(want & WANT_INDEX)) {
		/* Cache the mount point information */
		pthread_rwlock_wrlock(&root_cached_lock);

		/* If the entry matches the saved one -> no update needed */
		if (strcmp(root_cached.mnt_dir, mnt.mnt_dir) == 0)
			goto unlock_root_cached;

		if (root_cached.fd > 0) {
			close(root_cached.fd);
			root_cached.fd = 0;
		}
		if ((want & WANT_FD) && outfd)
			rc = get_root_fd(mnt.mnt_dir, &root_cached.fd);
		strncpy(root_cached.fsname, ptr, fsnamelen);
		root_cached.fsname[fsnamelen] = '\0';
		strncpy(root_cached.mnt_dir, mnt.mnt_dir, mntlen);
		root_cached.mnt_dir[mntlen] = '\0';
		root_cached.dev = devmnt;
		ptr_end = strstr(mnt.mnt_fsname, ":/");
		strncpy(root_cached.nid, mnt.mnt_fsname,
			ptr_end - mnt.mnt_fsname);
		root_cached.nid[ptr_end - mnt.mnt_fsname] = '\0';

unlock_root_cached:
		pthread_rwlock_unlock(&root_cached_lock);
	}

	if ((want & WANT_FSNAME) && fsname) {
		strncpy(fsname, ptr, fsnamelen);
		fsname[fsnamelen] = '\0';
	}
	if ((want & WANT_PATH) && path) {
		strncpy(path, mnt.mnt_dir, mntlen);
		path[mntlen] = '\0';
	}
	if ((want & WANT_DEV) && dev)
		*dev = devmnt;
	if ((want & WANT_FD) && outfd) {
		if (root_cached.fd > 0)
			*outfd = root_cached.fd;
		else
			rc = get_root_fd(mnt.mnt_dir, outfd);
	}
	if ((want & WANT_NID) && nid) {
		ptr_end = strchr(mnt.mnt_fsname, ':');
		strncpy(nid, mnt.mnt_fsname, ptr_end - mnt.mnt_fsname);
		nid[ptr_end - mnt.mnt_fsname] = '\0';
	}

out:
	endmntent(fp);
	return rc;
}

/*
 * Find the fsname, the full path, and/or an open fd.
 * Either the fsname or path must not be NULL.
 *
 * @outfd is for llapi internal use only, do not return it to the application.
 */
int get_root_path(int want, char *fsname, int *outfd, char *path, int index,
		  dev_t *dev, char *nid)
{
	int rc = -ENODEV;

	assert(fsname || path);

	if (!(want & WANT_INDEX))
		rc = get_root_path_fast(want, fsname, outfd, path, dev, nid);
	if (rc)
		rc = get_root_path_slow(want, fsname, outfd, path, index, dev,
					nid);

	if (!rc || !(want & WANT_ERROR))
		goto out_errno;

	if (dev || !(want & WANT_DEV))
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "'%u/%u' dev not on a mounted Lustre filesystem",
				  major(*dev), minor(*dev));
	else
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "'%s' not on a mounted Lustre filesystem",
				  (want & WANT_PATH) ? fsname : path);
out_errno:
	errno = -rc;
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
	return get_root_path(want, fsname, NULL, mntdir, idx, NULL, NULL);
}

/* Given a path, find the corresponding Lustre fsname */
int llapi_search_fsname(const char *pathname, char *fsname)
{
	dev_t dev;
	int rc;

	rc = get_file_dev(pathname, &dev);
	if (rc) {
		char tmp[PATH_MAX];
		char *parent;
		int len;

		/* file does not exist try the parent */
		len = readlink(pathname, tmp, PATH_MAX);
		if (len != -1)
			tmp[len] = '\0';
		else
			strncpy(tmp, pathname, PATH_MAX - 1);

		parent = dirname(tmp);
		rc = get_file_dev(parent, &dev);
	}

	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot resolve path '%s'", pathname);
		return rc;
	}

	rc = get_root_path(WANT_FSNAME | WANT_ERROR, fsname, NULL, NULL, -1,
			   &dev, NULL);

	return rc;
}


int llapi_search_rootpath(char *pathname, const char *fsname)
{
	if (!pathname)
		return -EINVAL;

	/*
	 * pathname can be used as an argument by get_root_path(),
	 * clear it for safety
	 */
	pathname[0] = 0;
	return get_root_path(WANT_PATH, (char *)fsname, NULL, pathname, -1,
			     NULL, NULL);
}

int llapi_search_rootpath_by_dev(char *pathname, dev_t dev)
{
	if (!pathname)
		return -EINVAL;

	/*
	 * pathname can be used as an argument by get_root_path(),
	 * clear it for safety
	 */
	pathname[0] = 0;
	return get_root_path(WANT_PATH, NULL, NULL, pathname, -1, &dev, NULL);
}

