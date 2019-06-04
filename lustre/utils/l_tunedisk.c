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
 * Copyright (c) 2018, Intel Corporation.
 */


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <stdio.h>

#include "mount_utils.h"
int	verbose;
char	*progname;


int main(int argc, char *const argv[])
{
	struct mount_opts mop = {
		.mo_max_sectors_kb = -1
	};
	struct lustre_disk_data *ldd = &mop.mo_ldd;

	char real_path[PATH_MAX] = {'\0'};
	unsigned int mount_type;
	int ret;

	verbose = 0;
	progname = strrchr(argv[0], '/');
	progname = progname ? progname + 1 : argv[0];

	ret = osd_init();
	if (ret != 0) {
		vprint("%s: osd_init() failed to initialize: %d\n",
		       progname, ret);
		return ret;
	}

	/* device is last arg */
	mop.mo_usource = argv[argc - 1];

	mop.mo_source = realpath(mop.mo_usource, real_path);
	if (mop.mo_source == NULL) {
		vprint("%s: No realpath for %s\n", progname, mop.mo_usource);
		goto out;
	}

	/* Check whether the disk has already been formatted by mkfs.lustre */
	ret = osd_is_lustre(mop.mo_source, &mount_type);
	if (ret == 0)
		goto out;

	ldd->ldd_mount_type = mount_type;

	ret = osd_read_ldd(mop.mo_source, ldd);
	if (ret != 0) {
		fprintf(stderr, "Failed to read previous Lustre data from %s "
			"(%d)\n", mop.mo_source, ret);
		goto out;
	}

	ret = osd_tune_lustre(mop.mo_source, &mop);

out:
	osd_fini();
	return ret;
}
