/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2009 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/utils/ll_decode_filter_fid.c
 *
 * Tool for printing the OST filter_fid structure on the objects
 * in human readable form.  This simplifies mapping of objid to
 * MDS inode numbers, which can be converted to pathnames via
 * debugfs -c -R "ncheck {list of inode numbers}"
 *
 * Author: Andreas Dilger <adilger@sun.com>
 */


#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <lustre/lustre_user.h>
#include <liblustre.h>

int main(int argc, char *argv[])
{
	char *prog;
	int rc = 0;
	int i;

	prog = basename(argv[0]);

	for (i = 1; i < argc; i++) {
		char buf[1024]; /* allow xattr that may be larger */
		struct filter_fid *ff = (void *)buf;
		int size;

		size = getxattr(argv[i], "trusted.fid", buf, sizeof(buf));
		if (size < 0) {
			fprintf(stderr, "%s: error reading fid: %s\n",
				argv[i], strerror(errno));
			if (rc == 0)
				rc = size;
		} else if (size > sizeof(*ff)) {
			fprintf(stderr, "%s: warning: fid larger than expected "
					"(%d bytes), recompile?\n",
					argv[i], size);
		} else {
			printf("%s: objid="LPU64" group="LPU64" inode="LPU64" generation=%u stripe=%u\n",
				argv[i], ff->ff_objid, ff->ff_group,
				ff->ff_fid.id, ff->ff_fid.generation,
				ff->ff_fid.f_type);
		}
	}

	return rc;
}
