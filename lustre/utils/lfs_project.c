/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2017, DataDirect Networks Storage.
 * Copyright (c) 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/lfs_project.c
 *
 * Author: Wang Shilong <wshilong@ddn.com>
 * Author: Fan Yong <fan.yong@intel.com>
 */
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <stddef.h>
#include <libintl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <libcfs/util/list.h>
#include <libcfs/util/ioctl.h>
#include <sys/ioctl.h>

#include "lfs_project.h"
#include <lustre/lustreapi.h>

const char	*progname;

struct lfs_project_item {
	struct list_head lpi_list;
	char *lpi_pathname;
};

static int
lfs_project_item_alloc(struct list_head *head, const char *pathname)
{
	struct lfs_project_item *lpi;

	lpi = malloc(sizeof(struct lfs_project_item));
	if (lpi == NULL) {
		fprintf(stderr,
			"%s: cannot allocate project item for '%s': %s\n",
			progname, pathname, strerror(ENOMEM));
		return -ENOMEM;
	}

	lpi->lpi_pathname = strdup(pathname);
	if (!lpi->lpi_pathname) {
		free(lpi);
		return -ENOMEM;
	} else
		list_add_tail(&lpi->lpi_list, head);

	return 0;
}

static const char *mode_to_type(mode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFDIR:	return "dir";
	case S_IFREG:	return "regular";
	case S_IFLNK:	return "symlink";
	case S_IFCHR:	return "char device";
	case S_IFBLK:	return "block device";
	case S_IFIFO:	return "fifo";
	case S_IFSOCK:	return "sock";
	}

	return "unknown";
}

static int project_get_xattr(const char *pathname, struct fsxattr *fsx,
			     struct stat *st)
{
	int ret, fd;

	ret = lstat(pathname, st);
	if (ret) {
		fprintf(stderr, "%s: failed to stat '%s': %s\n",
			progname, pathname, strerror(errno));
		return -errno;
	}

	/* currently, only file and dir supported */
	if (!S_ISREG(st->st_mode) && !S_ISDIR(st->st_mode)) {
		errno = ENOTSUP;
		fprintf(stderr, "%s: unable to get xattr for %s '%s': %s\n",
				progname, mode_to_type(st->st_mode), pathname,
				strerror(errno));
		return -errno;
	}

	fd = open(pathname, O_RDONLY | O_NOCTTY | O_NDELAY);
	if (fd < 0) {
		fprintf(stderr, "%s: failed to open '%s': %s\n",
			progname, pathname, strerror(errno));
		return -errno;
	}

	ret = ioctl(fd, FS_IOC_FSGETXATTR, fsx);
	if (ret) {
		fprintf(stderr, "%s: failed to get xattr for '%s': %s\n",
			progname, pathname, strerror(errno));
		close(fd);
		return -errno;
	}
	return fd;
}

static int
project_check_one(const char *pathname, struct project_handle_control *phc)
{
	struct fsxattr fsx;
	int ret;
	struct stat st;

	ret = project_get_xattr(pathname, &fsx, &st);
	if (ret < 0)
		return ret;

	/* use top directory's project ID if not specified */
	if (!phc->assign_projid) {
		phc->assign_projid = true;
		phc->projid = fsx.fsx_projid;
	}

	if (!(fsx.fsx_xflags & FS_XFLAG_PROJINHERIT) &&
	    S_ISDIR(st.st_mode)) {
		if (!phc->newline) {
			printf("%s%c", pathname, '\0');
			goto out;
		}
		 printf("%s - project inheritance flag is not set\n",
			pathname);
	}

	if (fsx.fsx_projid != phc->projid) {
		if (!phc->newline) {
			printf("%s%c", pathname, '\0');
			goto out;
		}
		printf("%s - project identifier is not set (inode=%u, tree=%u)\n",
		       pathname, fsx.fsx_projid, phc->projid);
	}
out:
	close(ret);
	return 0;
}

static int
project_list_one(const char *pathname, struct project_handle_control *phc)
{
	struct fsxattr fsx;
	struct stat st;
	int ret;

	ret = project_get_xattr(pathname, &fsx, &st);
	if (ret < 0)
		return ret;

	printf("%5u %c %s\n", fsx.fsx_projid,
	       (fsx.fsx_xflags & FS_XFLAG_PROJINHERIT) ?
		'P' : '-', pathname);

	close(ret);
	return 0;
}

static int
project_set_one(const char *pathname, struct project_handle_control *phc)
{
	struct fsxattr fsx;
	struct stat st;
	int fd, ret = 0;

	fd = project_get_xattr(pathname, &fsx, &st);
	if (fd < 0)
		return fd;

	if ((!phc->set_projid || fsx.fsx_projid == phc->projid) &&
	    (!phc->set_inherit || (fsx.fsx_xflags & FS_XFLAG_PROJINHERIT)))
		goto out;

	if (phc->set_inherit)
		fsx.fsx_xflags |= FS_XFLAG_PROJINHERIT;
	if (phc->set_projid)
		fsx.fsx_projid = phc->projid;

	ret = ioctl(fd, FS_IOC_FSSETXATTR, &fsx);
	if (ret)
		fprintf(stderr, "%s: failed to set xattr for '%s': %s\n",
			progname, pathname, strerror(errno));
out:
	close(fd);
	return ret;
}

static int
project_clear_one(const char *pathname, struct project_handle_control *phc)
{
	struct fsxattr fsx;
	struct stat st;
	int ret = 0, fd;

	fd = project_get_xattr(pathname, &fsx, &st);
	if (fd < 0)
		return fd;

	if ((!(fsx.fsx_xflags & FS_XFLAG_PROJINHERIT)) &&
	     (fsx.fsx_projid == 0 || phc->keep_projid))
		goto out;

	fsx.fsx_xflags &= ~FS_XFLAG_PROJINHERIT;
	if (!phc->keep_projid)
		fsx.fsx_projid = 0;

	ret = ioctl(fd, FS_IOC_FSSETXATTR, &fsx);
	if (ret)
		fprintf(stderr, "%s: failed to set xattr for '%s': %s\n",
			progname, pathname, strerror(errno));
out:
	close(fd);
	return ret;
}

static int
lfs_project_handle_dir(struct list_head *head, const char *pathname,
		       struct project_handle_control *phc,
		       int (*func)(const char *,
				   struct project_handle_control *))
{
	char fullname[PATH_MAX];
	struct dirent *ent;
	DIR *dir;
	int ret = 0;
	int rc;

	dir = opendir(pathname);
	if (dir == NULL) {
		ret = -errno;
		fprintf(stderr, "%s: failed to opendir '%s': %s\n",
			progname, pathname, strerror(-ret));
		return ret;
	}

	while ((ent = readdir(dir)) != NULL) {
		/* skip "." and ".." */
		if (strcmp(ent->d_name, ".") == 0 ||
		    strcmp(ent->d_name, "..") == 0)
			continue;

		if (strlen(ent->d_name) + strlen(pathname) + 1 >=
		    sizeof(fullname)) {
			ret = -ENAMETOOLONG;
			errno = ENAMETOOLONG;
			fprintf(stderr, "%s: ignored too long path: %s/%s\n",
					progname, pathname, ent->d_name);
			continue;
		}
		snprintf(fullname, PATH_MAX, "%s/%s", pathname,
			 ent->d_name);

		rc = func(fullname, phc);
		if (rc && !ret)
			ret = rc;
		if (phc->recursive && ent->d_type == DT_DIR) {
			rc = lfs_project_item_alloc(head, fullname);
			if (rc && !ret)
				ret = rc;
		}
	}

	closedir(dir);
	return ret;
}

static int lfs_project_iterate(const char *pathname,
			       struct project_handle_control *phc,
			       int (*func)(const char *,
					   struct project_handle_control *))
{
	struct lfs_project_item *lpi;
	struct list_head head;
	struct stat st;
	int ret = 0;
	int rc = 0;

	ret = stat(pathname, &st);
	if (ret) {
		fprintf(stderr, "%s: failed to stat '%s': %s\n",
			progname, pathname, strerror(errno));
		return ret;
	}

	/* list opeation will skip top directory in default */
	if (!S_ISDIR(st.st_mode) || phc->dironly ||
	    project_list_one != func)
		ret = func(pathname, phc);

	/* dironly first, recursive will be ignored */
	if (!S_ISDIR(st.st_mode) || phc->dironly || ret)
		return ret;

	INIT_LIST_HEAD(&head);
	ret = lfs_project_item_alloc(&head, pathname);
	if (ret)
		return ret;

	while (!list_empty(&head)) {
		lpi = list_entry(head.next, struct lfs_project_item, lpi_list);
		list_del(&lpi->lpi_list);
		rc = lfs_project_handle_dir(&head, lpi->lpi_pathname,
					     phc, func);
		if (!ret && rc)
			ret = rc;
		free(lpi->lpi_pathname);
		free(lpi);
	}

	return ret;
}


int lfs_project_check(const char *pathname,
		      struct project_handle_control *phc)
{
	return lfs_project_iterate(pathname, phc, project_check_one);
}

int lfs_project_clear(const char *pathname,
		      struct project_handle_control *phc)
{
	return lfs_project_iterate(pathname, phc, project_clear_one);
}

int lfs_project_set(const char *pathname,
		    struct project_handle_control *phc)
{
	return lfs_project_iterate(pathname, phc, project_set_one);
}

int lfs_project_list(const char *pathname,
		     struct project_handle_control *phc)
{
	return lfs_project_iterate(pathname, phc, project_list_one);
}
