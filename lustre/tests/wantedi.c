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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <liblustre.h>
#include <obd.h>
#include <lustre_lib.h>

static int usage(char *prog, FILE *out)
{
        fprintf(out,
		"Usage: %s <dir> <desired child ino>\n", prog);
        exit(out == stderr);
}

#define LDISKFS_IOC_CREATE_INUM            _IOW('f', 5, long)

int main(int argc, char ** argv)
{
        int dirfd, wantedi, rc;

	if (argc < 2 || argc > 3)
		usage(argv[0], stderr);
	
	dirfd = open(argv[1], O_RDONLY);
	if (dirfd < 0) {
	       perror("open");
	       exit(1);
	}
        
	wantedi = atoi(argv[2]);
	printf("Creating %s/%d with ino %d\n", argv[1], wantedi, wantedi);

	rc = ioctl(dirfd, LDISKFS_IOC_CREATE_INUM, wantedi);
	if (rc < 0) {
	       perror("ioctl(LDISKFS_IOC_CREATE_INUM)");
	       exit(2);
	}

        return 0;
}
