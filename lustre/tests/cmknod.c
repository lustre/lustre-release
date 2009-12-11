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
 *
 * lustre/tests/cmknod.c
 *
 * Simple test to check that device nodes are correctly created and visible
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define TEST_MINOR 120
#define TEST_MAJOR 25

void usage(char *prog)
{
	fprintf(stderr, "usage: %s <filename>\n", prog);
	exit(1);
}

/* UMKA: This stuff inlined here instead of using appropriate header 
   to avoid linking to symbols which is not present in newer libc.
   
   Currently this is the case, as UML image contains RedHat 9 and 
   developers use something newer (Fedora, etc.). */
inline unsigned int
__gnu_dev_major (unsigned long long int __dev)
{
	return ((__dev >> 8) & 0xfff) | ((unsigned int) (__dev >> 32) & ~0xfff);
}

inline unsigned int
__gnu_dev_minor (unsigned long long int __dev)
{
	return (__dev & 0xff) | ((unsigned int) (__dev >> 12) & ~0xff);
}

inline unsigned long long int
__gnu_dev_makedev (unsigned int __major, unsigned int __minor)
{
	return ((__minor & 0xff) | ((__major & 0xfff) << 8)
		| (((unsigned long long int) (__minor & ~0xff)) << 12)
		| (((unsigned long long int) (__major & ~0xfff)) << 32));
}

#define __minor(dev) __gnu_dev_minor(dev)
#define __major(dev) __gnu_dev_major(dev)
#define __makedev(maj, min) __gnu_dev_makedev(maj, min)

int main( int argc, char **argv)
{
	char *prog = argv[0];
	char *filename = argv[1];
	int rc;
	struct stat st;
	dev_t device = __makedev(TEST_MAJOR, TEST_MINOR);

	if (argc != 2) 
		usage(prog);

	unlink(filename);
	
	/* First try block devices */
	rc = mknod(filename, 0700 | S_IFBLK, device);
	if ( rc < 0 ) {
		fprintf(stderr, "%s: mknod(%s) failed: rc %d: %s\n",
			prog, filename, errno, strerror(errno));
		return 2;
	}

	rc = stat(filename, &st);
	if ( rc < 0 ) {
		fprintf(stderr, "%s: stat(%s) failed: rc %d: %s\n",
			prog, filename, errno, strerror(errno));
		return 3;
	}
	
	if ( st.st_rdev != device) {
		fprintf(stderr, "%s: created device other than requested: (%u,%u) instead of (%u,%u)\n", 
			prog, __major(st.st_rdev),__minor(st.st_rdev),__major(device),__minor(device));
		return 4;
	}
	if (!S_ISBLK(st.st_mode)) {
		fprintf(stderr, "%s: created device of different type. Requested block device, got mode %o\n", prog, st.st_mode);
		return 5;
	}

	rc = unlink(filename);
	if ( rc < 0 ) {
		fprintf(stderr, "%s: Cannot unlink created device %s, rc %d: %s\n",
			prog, filename, errno, strerror(errno));
		return 6;
	}

	/* Second try char devices */
	rc = mknod(filename, 0700 | S_IFCHR, device);
	if ( rc < 0 ) {
		fprintf(stderr, "%s: mknod(%s) failed: rc %d: %s\n",
			prog, filename, errno, strerror(errno));
		return 7;
	}

	rc = stat(filename, &st);
	if ( rc < 0 ) {
		fprintf(stderr, "%s: stat(%s) failed: rc %d: %s\n",
			prog, filename, errno, strerror(errno));
		return 8;
	}
	if ( st.st_rdev != device) {
		fprintf(stderr, "%s: created device other than requested: (%u,%u) instead of (%u,%u)\n", 
			prog, __major(st.st_rdev),__minor(st.st_rdev),__major(device),__minor(device));
		return 9;
	}
	if (!S_ISCHR(st.st_mode)) {
		fprintf(stderr, "%s: created device of different type. Requested char device, got mode %o\n", prog, st.st_mode);
		return 10;
	}

	rc = unlink(filename);
	if ( rc < 0 ) {
		fprintf(stderr, "%s: Cannot unlink created device %s, rc %d: %s\n",
			prog, filename, errno, strerror(errno));
		return 11;
	}

	printf("%s: device nodes created correctly\n", prog);

	return 0;
}
