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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/utils/ll_decode_filter_fid.c
 *
 * Tool for printing the OST filter_fid structure on the objects
 * in human readable form.
 *
 * Author: Andreas Dilger <adilger@sun.com>
 */


#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <libcfs/libcfs.h>
#include <lustre/lustre_user.h>

int main(int argc, char *argv[])
{
	int rc = 0;
	int i;

	for (i = 1; i < argc; i++) {
		char buf[1024]; /* allow xattr that may be larger */
		struct filter_fid *ff = (void *)buf;
		int size;

		size = getxattr(argv[i], "trusted.fid", buf,
				sizeof(struct filter_fid_old));
		if (size < 0) {
			fprintf(stderr, "%s: error reading fid: %s\n",
				argv[i], strerror(errno));
			if (rc == 0)
				rc = size;
			continue;
		}
		if (size > sizeof(struct filter_fid_old)) {
			fprintf(stderr, "%s: warning: fid larger than expected"
				" (%d bytes), recompile?\n", argv[i], size);
		} else if (size > sizeof(*ff)) {
			struct filter_fid_old *ffo = (void *)buf;

			/* old filter_fid */
			printf("%s: objid="LPU64" seq="LPU64" parent="DFID
			       " stripe=%u\n", argv[i],
			       le64_to_cpu(ffo->ff_objid),
			       le64_to_cpu(ffo->ff_seq),
			       le64_to_cpu(ffo->ff_parent.f_seq),
			       le32_to_cpu(ffo->ff_parent.f_oid), 0 /* ver */,
			       /* this is stripe_nr actually */
			       le32_to_cpu(ffo->ff_parent.f_stripe_idx));
		} else {
			printf("%s: parent="DFID" stripe=%u\n", argv[i],
			       le64_to_cpu(ff->ff_parent.f_seq),
			       le32_to_cpu(ff->ff_parent.f_oid), 0, /* ver */
			       /* this is stripe_nr actually */
			       le32_to_cpu(ff->ff_parent.f_stripe_idx));
		}
	}

	return rc;
}
