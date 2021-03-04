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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/tests/ll_dirstripe_verify.c
 *
 * ll_dirstripe_verify <dir> <file>:
 * - to verify if the file has the same lov_user_md setting as the parent dir.
 * - if dir's offset is set -1, ll_dirstripe_verify <dir> <file1> <file2>
 *      is used to further verify if file1 and file2's obdidx is continuous.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

#include <libcfs/util/param.h>
#include <libcfs/util/string.h>
#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_idl.h>

#define MAX_LOV_UUID_COUNT      1000

/*
 * Returns bytes read on success and a negative value on failure.
 * If zero bytes are read it will be treated as failure as such
 * zero cannot be returned from this function.
 */
int read_proc_entry(char *proc_path, char *buf, int len)
{
	int rc, fd;

	memset(buf, 0, len);

	fd = open(proc_path, O_RDONLY);
	if (fd < 0) {
		llapi_error(LLAPI_MSG_ERROR, -errno, "cannot open '%s'",
			    proc_path);
		return -2;
	}

	rc = read(fd, buf, len - 1);
	if (rc < 0) {
		llapi_error(LLAPI_MSG_ERROR, -errno,
			    "error reading from '%s'", proc_path);
		rc = -3;
	} else if (rc == 0) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "read zero bytes from '%s'", proc_path);
		rc = -4;
	} else if (buf[rc - 1] == '\n') {
		buf[rc - 1] = '\0'; /* Remove trailing newline */
	}

	close(fd);

	return rc;
}

int compare(struct obd_uuid *puuid, struct lov_user_md *lum_dir,
	    struct lov_user_md *lum_file1, struct lov_user_md *lum_file2)
{
	int stripe_count = 0, min_stripe_count = 0, def_stripe_count = 1;
	int stripe_size = 0;
	int stripe_offset = -1;
	int ost_count;
	char buf[128];
	glob_t path;
	int i;

	if (cfs_get_param_paths(&path, "lov/%s/stripecount", puuid->uuid) != 0)
		return 2;
	if (read_proc_entry(path.gl_pathv[0], buf, sizeof(buf)) < 0) {
		cfs_free_param_data(&path);
		return 5;
	}
	cfs_free_param_data(&path);
	def_stripe_count = (short)atoi(buf);

	if (cfs_get_param_paths(&path, "lov/%s/numobd", puuid->uuid) != 0)
		return 2;
	if (read_proc_entry(path.gl_pathv[0], buf, sizeof(buf)) < 0) {
		cfs_free_param_data(&path);
		return 6;
	}
	cfs_free_param_data(&path);
	ost_count = atoi(buf);

	if (!lum_dir) {
		stripe_count = def_stripe_count;
		min_stripe_count = -1;
	} else {
		stripe_count = (signed short)lum_dir->lmm_stripe_count;
		printf("dir stripe %d, ", stripe_count);
		min_stripe_count = 1;
	}

	printf("default stripe %d, ost count %d\n",
	       def_stripe_count, ost_count);

	if (stripe_count == 0) {
		min_stripe_count = -1;
		stripe_count = 1;
	}

	stripe_count = (stripe_count > 0 && stripe_count <= ost_count) ?
						stripe_count : ost_count;
	min_stripe_count = min_stripe_count > 0 ? stripe_count :
						((stripe_count + 1) / 2);

	if (lum_file1->lmm_stripe_count != stripe_count ||
	    lum_file1->lmm_stripe_count < min_stripe_count) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "file1 stripe count %d != dir %d\n",
				  lum_file1->lmm_stripe_count, stripe_count);
		return 7;
	}

	if (lum_file1->lmm_stripe_count < stripe_count)
		llapi_err_noerrno(LLAPI_MSG_WARN,
				  "warning: file1 used fewer stripes %d < dir %d (likely due to bug 4900)\n",
				  lum_file1->lmm_stripe_count, stripe_count);

	if (lum_dir)
		stripe_size = (int)lum_dir->lmm_stripe_size;
	if (stripe_size == 0) {
		if (cfs_get_param_paths(&path, "lov/%s/stripesize",
					puuid->uuid) != 0)
			return 2;
		if (read_proc_entry(path.gl_pathv[0], buf, sizeof(buf)) < 0) {
			cfs_free_param_data(&path);
			return 5;
		}
		cfs_free_param_data(&path);

		stripe_size = atoi(buf);
	}

	if (lum_file1->lmm_stripe_size != stripe_size) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "file1 stripe size %d != dir %d\n",
				  lum_file1->lmm_stripe_size, stripe_size);
		return 8;
	}

	if (lum_dir)
		stripe_offset = (short int)lum_dir->lmm_stripe_offset;
	if (stripe_offset != -1) {
		for (i = 0; i < stripe_count; i++)
			if (lum_file1->lmm_objects[i].l_ost_idx !=
			    (stripe_offset + i) % ost_count) {
				llapi_err_noerrno(LLAPI_MSG_WARN,
						  "warning: file1 non-sequential stripe[%d] %d != %d\n",
						  i, lum_file1->lmm_objects[i].l_ost_idx,
						  (stripe_offset + i) %
						  ost_count);
			}
	} else if (lum_file2) {
		int next, idx, stripe = stripe_count - 1;

		next = (lum_file1->lmm_objects[stripe].l_ost_idx + 1) %
			ost_count;
		idx = lum_file2->lmm_objects[0].l_ost_idx;
		if (idx != next) {
			llapi_err_noerrno(LLAPI_MSG_WARN,
					  "warning: non-sequential file1 stripe[%d] %d != file2 stripe[0] %d\n",
					  stripe,
					  lum_file1->lmm_objects[stripe].l_ost_idx,
					  idx);
		}
	}

	return 0;
}

int compare_lum(struct obd_uuid *puuid, struct lov_user_md *lum_dir,
		struct lov_user_md *lum_file1, struct lov_user_md *lum_file2)
{
	struct lov_comp_md_v1 *comp_dir, *comp_file1;
	struct lov_user_md *sub_dir, *sub_file1;
	int i, rc = 0;

	if (!lum_dir || lum_dir->lmm_magic != LOV_MAGIC_COMP_V1)
		return compare(puuid, lum_dir, lum_file1, lum_file2);

	comp_dir = (struct lov_comp_md_v1 *)lum_dir;
	comp_file1 = (struct lov_comp_md_v1 *)lum_file1;

	if (lum_file1->lmm_magic != lum_dir->lmm_magic) {
		llapi_err_noerrno(LLAPI_MSG_ERROR, "file1 magic %#x != %#x\n",
				  lum_file1->lmm_magic, lum_dir->lmm_magic);
		return 10;
	}

	if (comp_file1->lcm_entry_count != comp_dir->lcm_entry_count) {
		llapi_err_noerrno(LLAPI_MSG_ERROR, "file1 comp cnt %d != %d\n",
				  comp_file1->lcm_entry_count,
				  comp_dir->lcm_entry_count);
		return 11;
	}

	for (i = 0; i < comp_dir->lcm_entry_count; i++) {
		sub_dir = (struct lov_user_md *)((char *)comp_dir +
				comp_dir->lcm_entries[i].lcme_offset);
		sub_file1 = (struct lov_user_md *)((char *)comp_file1 +
				comp_file1->lcm_entries[i].lcme_offset);

		rc = compare(puuid, sub_dir, sub_file1, NULL);
		if (rc)
			break;
	}

	return rc;
}

int main(int argc, char **argv)
{
	struct lov_user_md *lum_dir, *lum_file1 = NULL, *lum_file2 = NULL;
	struct obd_uuid uuid;
	int lum_size, rc;
	DIR *dir;

	if (argc < 3) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "Usage: %s <dirname> <filename1> [filename2]\n",
				  argv[0]);
		return 1;
	}

	dir = opendir(argv[1]);
	if (!dir) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: %s opendir failed", argv[1]);
		return rc;
	}

	lum_size = lov_user_md_size(MAX_LOV_UUID_COUNT, LOV_USER_MAGIC);
	lum_dir = (struct lov_user_md *)malloc(lum_size);
	if (!lum_dir) {
		rc = -ENOMEM;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: can't allocate %d bytes for dir EA",
			    lum_size);
		goto cleanup;
	}

	rc = llapi_file_get_stripe(argv[1], lum_dir);
	if (rc == -ENODATA) {
		char root[PATH_MAX], path[PATH_MAX + 2];

		rc = llapi_search_mounts(argv[1], 0, root, NULL);
		if (rc) {
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "error: can't get root path for %s\n",
				    argv[1]);
			goto cleanup;
		}

		snprintf(path, sizeof(path), "%s/.", root);
		rc = llapi_file_get_stripe(path, lum_dir);
		if (rc == -ENODATA) {
			free(lum_dir);
			lum_dir = NULL;
		} else if (rc) {
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "error: cant't get root's LOVEA for %s\n",
				    path);
			goto cleanup;
		}
	} else if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: can't get LOVEA for %s", argv[1]);
		goto cleanup;
	}

	/* XXX should be llapi_lov_getname() */
	rc = llapi_file_get_lov_uuid(argv[1], &uuid);
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: can't get lov name for %s",
			    argv[1]);
		return rc;
	}

	lum_file1 = malloc(lum_size);
	if (!lum_file1) {
		rc = -ENOMEM;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: can't allocate %d bytes for EA",
			    lum_size);
		goto cleanup;
	}

	rc = llapi_file_get_stripe(argv[2], lum_file1);
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: unable to get EA for %s", argv[2]);
		goto cleanup;
	}

	if (argc == 4) {
		lum_file2 = (struct lov_user_md *)malloc(lum_size);
		if (!lum_file2) {
			rc = -ENOMEM;
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "error: can't allocate %d bytes for file2 EA",
				    lum_size);
			goto cleanup;
		}

		rc = llapi_file_get_stripe(argv[3], lum_file2);
		if (rc) {
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "error: can't get EA for %s", argv[3]);
			goto cleanup;
		}
	}

	rc = compare_lum(&uuid, lum_dir, lum_file1, lum_file2);

cleanup:
	closedir(dir);
	if (lum_dir)
		free(lum_dir);
	if (lum_file1)
		free(lum_file1);
	if (lum_file2)
		free(lum_file2);

	return rc;
}
