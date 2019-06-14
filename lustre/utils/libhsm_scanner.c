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
 * version 2 along with this program; if not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2019, DDN Storage Corporation.
 */
/*
 * lustre/utils/libhsm_scanner.c
 *
 * Library for scanning HSM backend fs.
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libcfs/util/list.h>
#include "libhsm_scanner.h"

struct hsm_scan_item {
	struct list_head	hsi_item;
	int			hsi_depth;
	char			hsi_pathname[PATH_MAX];
};

static int hsm_scan_item_alloc(struct list_head *head,
			       const char *pathname, int depth)
{
	struct hsm_scan_item *item;
	int rc;

	if (strlen(pathname) >= PATH_MAX) {
		rc = -ENAMETOOLONG;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "pathname is too long: %s\n", pathname);
		return rc;
	}

	item = malloc(sizeof(struct hsm_scan_item));
	if (item == NULL) {
		rc = -ENOMEM;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot allocate hsm item for '%s'", pathname);
		return rc;
	}

	item->hsi_depth = depth;
	strncpy(item->hsi_pathname, pathname, sizeof(item->hsi_pathname) - 1);
	list_add_tail(&item->hsi_item, head);

	return 0;
}

int hsm_scan_handle_dir(struct hsm_scan_control *hsc, struct list_head *head,
			struct hsm_scan_item *item)
{
	char fullname[PATH_MAX + NAME_MAX + 1];
	const char *pathname = item->hsi_pathname;
	int depth = item->hsi_depth;
	struct dirent *ent;
	DIR *dir;
	int ret;
	int rc = 0;

	dir = opendir(pathname);
	if (dir == NULL) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "failed to opendir '%s'",
			    pathname);
		return rc;
	}

	while ((ent = readdir(dir)) != NULL) {
		/* skip "." and ".." */
		if (strcmp(ent->d_name, ".") == 0 ||
		    strcmp(ent->d_name, "..") == 0)
			continue;

		llapi_printf(LLAPI_MSG_DEBUG,
			     "check file %d:'%s' under directory '%s'\n",
			     depth, ent->d_name, pathname);
		if (depth == 0 && ent->d_type == DT_DIR &&
		    strcmp(ent->d_name, "shadow") == 0) {
			llapi_printf(LLAPI_MSG_DEBUG,
				     "skipping check of 'shadow' directory.\n");
		} else {
			if (ent->d_type == DT_REG) {
				ret = hsc->hsc_func(pathname, ent->d_name, hsc);
				if (ret && !rc) {
					hsc->hsc_errnum++;
					rc = ret;
					/* ignore error, continue to check */
				}
			} else if (ent->d_type == DT_DIR) {
				if (strlen(ent->d_name) + strlen(pathname) + 1
				    >= sizeof(fullname)) {
					rc = -ENAMETOOLONG;
					errno = ENAMETOOLONG;
					llapi_err_noerrno(LLAPI_MSG_ERROR,
							  "ignore too long path: %s/%s\n",
							  pathname,
							  ent->d_name);
					hsc->hsc_errnum++;
					continue;
				}
				snprintf(fullname, sizeof(fullname), "%s/%s",
					 pathname, ent->d_name);
				rc = hsm_scan_item_alloc(head, fullname,
							 depth + 1);
			}
		}
	}

	if (rc)
		llapi_error(LLAPI_MSG_ERROR, rc, "failed to handle dir '%s'",
			    pathname);

	closedir(dir);
	return rc;
}

int hsm_scan_process(struct hsm_scan_control *hsc)
{
	struct hsm_scan_item *item;
	struct list_head head;
	struct stat st;
	int ret = 0;
	int rc;

	if (hsc->hsc_type != HSMTOOL_POSIX_V1 &&
	    hsc->hsc_type != HSMTOOL_POSIX_V2)
		return -EOPNOTSUPP;

	rc = stat(hsc->hsc_hsmpath, &st);
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc, "failed to stat '%s'",
			    hsc->hsc_hsmpath);
		return rc;
	}

	if (!S_ISDIR(st.st_mode)) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "HSM root path '%s' must be a directory.",
				  hsc->hsc_hsmpath);
		return -EINVAL;
	}

	INIT_LIST_HEAD(&head);
	rc = hsm_scan_item_alloc(&head, hsc->hsc_hsmpath, 0);
	if (rc)
		return rc;

	while (!list_empty(&head)) {
		item = list_entry(head.next, struct hsm_scan_item, hsi_item);
		list_del(&item->hsi_item);
		ret = hsm_scan_handle_dir(hsc, &head, item);
		if (!rc && ret)
			rc = ret;
		free(item);
	}

	return rc;
}
