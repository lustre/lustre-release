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
#include <libcfs/util/string.h>
#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_fid.h>
#include "lustreapi_internal.h"

/* could have an array of these for a handful of different paths */
static struct root_cache {
	dev_t	dev;
	char	fsname[PATH_MAX];
	char	mnt_dir[PATH_MAX];
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

/**
 * get_root_path_fast() - get mountpoint info from internal root_cache
 *
 * @want: bitmask of WANT_* flags indicating what information to return
 * @fsname: if WANT_FSNAME is set, used as a buffer to return filesystem name
 * (size is assumed to be PATH_MAX). Otherwise used to match the mount point
 * @outfd: pointer to return open file descriptor (internal use only)
 * @path: if WANT_PATH is set, used as a buffer to return mount point path
 * (size is assumed to be PATH_MAX). Otherwise used to match the mount point
 * @dev: pointer to return device ID
 *
 * Return:
 * * %0 on success
 * * %-ENODEV if no matching Lustre mount is found
 * * %-ENAMETOOLONG if filesystem name, path, or NID is truncated
 * * %negative error code on other failures
 */
static int get_root_path_fast(int want, char *fsname, int *outfd, char *path,
			      dev_t *dev)
{
	int fsnamelen;
	int mntlen;
	int rc2;
	int rc = -ENODEV;

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

	if ((want & WANT_FSNAME) && fsname) {
		rc2 = scnprintf(fsname, PATH_MAX, "%s", root_cached.fsname);
		if (rc2 < 0 || rc2 >= PATH_MAX - 1) {
			rc = rc2 < 0 ? rc2 : -ENAMETOOLONG;
			goto out_unlock;
		}
	}
	if ((want & WANT_PATH) && path) {
		rc2 = scnprintf(path, PATH_MAX, "%s", root_cached.mnt_dir);
		if (rc2 < 0 || rc2 >= PATH_MAX - 1) {
			rc = rc2 < 0 ? rc2 : -ENAMETOOLONG;
			goto out_unlock;
		}
	}
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
out_unlock:
	pthread_rwlock_unlock(&root_cached_lock);

	return rc;
}

/**
 * get_root_path_slow() - get mountpoint info from /proc/mounts and add to cache
 *
 * @want: bitmask of WANT_* flags indicating what information to return
 * @fsname: if WANT_FSNAME is set, used as a buffer to return filesystem name
 * (size is assumed to be PATH_MAX). Otherwise used to match the mount point
 * @outfd: pointer to return open file descriptor (internal use only)
 * @path: if WANT_PATH is set, used as a buffer to return mount point path
 * (size is assumed to be PATH_MAX). Otherwise used to match the mount point
 * @index: if WANT_INDEX is set, specifies which Lustre mount to find
 * @dev: pointer to return device ID
 * @out_nid: buffer to return a nidlist (dynamically allocated if rc == 0)
 *
 * Return:
 * * %0 on success
 * * %-ENODEV if no matching Lustre mount is found
 * * %-ENAMETOOLONG if filesystem name, path, or NID is truncated
 * * %negative error code on other failures
 */
static int get_root_path_slow(int want, char *fsname, int *outfd, char *path,
			      int index, dev_t *dev, char **out_nid)
{
	struct mntent mnt;
	char buf[PATH_MAX];
	char *ptr, *ptr_end;
	FILE *fp;
	int idx = -1, mntlen = 0;
	int fsnamelen = 0;
	dev_t devmnt = 0;
	int rc2;
	int rc = -ENODEV;

	/* get the mount point */
	fp = setmntent(PROC_MOUNTS, "r");
	if (!fp) {
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
		if (!ptr)
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

		rc2 = scnprintf(root_cached.fsname, sizeof(root_cached.fsname),
				"%.*s", fsnamelen, ptr);
		if (rc2 < 0 || rc2 >= sizeof(root_cached.fsname) - 1) {
			rc = rc2 < 0 ? rc2 : -ENAMETOOLONG;
			goto unlock_root_cached;
		}

		rc2 = scnprintf(root_cached.mnt_dir,
				sizeof(root_cached.mnt_dir), "%.*s", mntlen,
				mnt.mnt_dir);
		if (rc2 < 0 || rc2 >= sizeof(root_cached.mnt_dir) - 1)
			rc = rc2 < 0 ? rc2 : -ENAMETOOLONG;

		root_cached.dev = devmnt;

		/* if rc, cache was only partially updated and must be reset */
		if (rc)
			memset(&root_cached, 0, sizeof(root_cached));

unlock_root_cached:
		pthread_rwlock_unlock(&root_cached_lock);

		if (rc)
			goto out;
	}

	if ((want & WANT_FSNAME) && fsname) {
		rc2 = scnprintf(fsname, PATH_MAX, "%.*s", fsnamelen, ptr);
		if (rc2 < 0 || rc2 >= PATH_MAX - 1) {
			rc = rc2 < 0 ? rc2 : -ENAMETOOLONG;
			goto out;
		}
	}
	if ((want & WANT_PATH) && path) {
		rc2 = scnprintf(path, PATH_MAX, "%.*s", mntlen, mnt.mnt_dir);
		if (rc2 < 0 || rc2 >= PATH_MAX - 1) {
			rc = rc2 < 0 ? rc2 : -ENAMETOOLONG;
			goto out;
		}
	}
	if ((want & WANT_DEV) && dev)
		*dev = devmnt;
	if ((want & WANT_FD) && outfd) {
		if (root_cached.fd > 0)
			*outfd = root_cached.fd;
		else
			rc = get_root_fd(mnt.mnt_dir, outfd);
	}

	if (!rc && (want & WANT_NID) && out_nid) {
		size_t nid_bufsz;

		ptr_end = strstr(mnt.mnt_fsname, ":/");
		nid_bufsz = ptr_end - mnt.mnt_fsname + 2;
		*out_nid = malloc(nid_bufsz);
		if (!*out_nid) {
			rc = -ENOMEM;
			goto out;
		}

		rc2 = scnprintf(*out_nid, nid_bufsz, "%.*s",
				(int)(ptr_end - mnt.mnt_fsname),
				mnt.mnt_fsname);
		if (rc2 < 0 || rc2 >= nid_bufsz - 1) {
			rc = rc2 < 0 ? rc2 : -ENAMETOOLONG;
			free(*out_nid);
			*out_nid = NULL;
			goto out;
		}
	}

out:
	endmntent(fp);
	return rc;
}

/**
 * get_root_path() - find filesystem info using cached or slow lookup
 *
 * @want: bitmask of WANT_* flags indicating what information to return
 * @fsname: if WANT_FSNAME is set, used as a buffer to return filesystem name
 * (size is assumed to be PATH_MAX). Otherwise used to match the mount point
 * @outfd: pointer to return open file descriptor (internal use only)
 * @path: if WANT_PATH is set, used as a buffer to return mount point path
 * (size is assumed to be PATH_MAX). Otherwise used to match the mount point
 * @index: if WANT_INDEX is set, specifies which Lustre mount to find
 * @dev: pointer to return device ID
 * @out_nid: buffer to return a nidlist (dynamically allocated if rc == 0)
 *
 * Find the fsname, the full path, and/or an open fd.
 * Either the fsname or path must not be NULL.
 *
 * outfd is for llapi internal use only, do not return it to the application.
 *
 * Return:
 * * %0 on success
 * * %-ENODEV if no matching Lustre mount is found
 * * %-ENAMETOOLONG if filesystem name, path, or NID is truncated
 * * %negative error code on other failures
 */
int get_root_path(int want, char *fsname, int *outfd, char *path, int index,
		  dev_t *dev, char **out_nid)
{
	int rc = -ENODEV;

	assert(fsname || path);

	if (!(want & WANT_INDEX) || !(want & WANT_NID))
		rc = get_root_path_fast(want, fsname, outfd, path, dev);
	if (rc || (want & WANT_NID))
		rc = get_root_path_slow(want, fsname, outfd, path, index, dev,
					out_nid);

	if (!rc || !(want & WANT_ERROR))
		goto out_errno;

	if (rc == -ENAMETOOLONG) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "filesystem name, path, or NID is too long");
		goto out_errno;
	}

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

