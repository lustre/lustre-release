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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/tests/utime.c
 *
 * Simple test for validating mtime on a file create and set via utime.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <utime.h>
#include <errno.h>

void usage(char *prog)
{
	fprintf(stderr, "usage: %s <filename> [-s <filename>]\n", prog);
	exit(1);
}

int main(int argc, char *argv[])
{
	long before_mknod, after_mknod;
	const char *prog = argv[0];
	const char *filename = argv[1];
	char *secname = NULL;
	struct utimbuf utb;
	struct stat st, st2;
	int rc;
	int c;

	while ((c = getopt(argc, argv, "s:")) != -1) {
		switch (c) {
		case 's':
			secname = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}
	if (optind + 1 > argc)
		usage(argv[0]);

	/*
	 * Adjust the before time back one second, because the kernel's
	 * CURRENT_TIME (lockless clock reading, used to set inode times)
	 * may drift against the do_gettimeofday() time (TSC-corrected and
	 * locked clock reading, used to return timestamps to user space).
	 * This means that the mknod time could be a second older than the
	 * before time, even for a local filesystem such as ext3.
	 */
	before_mknod = time(0) - 1;
	rc = mknod(filename, 0700, S_IFREG);
	after_mknod = time(0);
	if (rc && errno != EEXIST) {
		fprintf(stderr, "%s: mknod(%s) failed: rc %d: %s\n",
			prog, filename, errno, strerror(errno));
		return 2;
	} else if (!rc) {
		rc = stat(filename, &st);
		if (rc) {
			fprintf(stderr, "%s: stat(%s) failed: rc %d: %s\n",
				prog, filename, errno, strerror(errno));
			return 3;
		}

		if (st.st_mtime < before_mknod || st.st_mtime > after_mknod) {
			fprintf(stderr,
				"%s: bad mknod(%s) times %lu <= %lu <= %lu false\n",
				prog, filename, before_mknod, st.st_mtime,
				after_mknod);
			return 4;
		}

		printf("%s: good mknod times %lu%s <= %lu <= %lu for %s\n",
		       prog, before_mknod,
		       before_mknod == st.st_mtime ? "*" : "",
		       st.st_mtime, after_mknod, filename);

		if (secname) {
			sleep(1);
			rc = stat(secname, &st2);
			if (rc) {
				fprintf(stderr,
					"%s: stat(%s) failed: rc %d: %s\n",
					prog, secname, errno, strerror(errno));
				return 5;
			}

			if (st2.st_mtime < before_mknod ||
			    st2.st_mtime > after_mknod) {
				fprintf(stderr,
					"%s: bad mknod(%s) times %lu  <= %lu <= %lu false\n",
					prog, filename, before_mknod,
					st2.st_mtime, after_mknod);
				return 6;
			}

			printf("%s: good mknod times %lu%s <= %lu <= %lu for %s\n",
			       prog, before_mknod,
			       before_mknod == st.st_mtime ? "*" : "",
			       st2.st_mtime, after_mknod, secname);
		}
	}

	utb.actime = 200000;
	utb.modtime = 100000;
	rc = utime(filename, &utb);
	if (rc) {
		fprintf(stderr, "%s: utime(%s) failed: rc %d: %s\n",
			prog, filename, errno, strerror(errno));
		return 7;
	}

	rc = stat(filename, &st);
	if (rc) {
		fprintf(stderr, "%s: second stat(%s) failed: rc %d: %s\n",
			prog, filename, errno, strerror(errno));
		return 8;
	}

	if (st.st_mtime != utb.modtime) {
		fprintf(stderr, "%s: bad utime mtime(%s) %lu should be %lu\n",
			prog, filename, st.st_mtime, utb.modtime);
		return 9;
	}

	if (st.st_atime != utb.actime) {
		fprintf(stderr, "%s: bad utime atime(%s) %lu should be %lu\n",
			prog, filename, st.st_atime, utb.actime);
		return 10;
	}

	printf("%s: good utime mtimes %lu, atime %lu\n",
	       prog, utb.modtime, utb.actime);

	if (!secname)
		return 0;

	/* Checking that times in past get updated on another client. */
	rc = stat(secname, &st2);
	if (rc) {
		fprintf(stderr, "%s: second stat(%s) failed: rc %d: %s\n",
			prog, secname, errno, strerror(errno));
		return 12;
	}

	if (st2.st_mtime != st.st_mtime) {
		fprintf(stderr,
			"%s: not synced mtime(%s) between clients: %lu should be %lu\n",
			prog, secname, st2.st_mtime, st.st_mtime);
		return 13;
	}

	if (st2.st_ctime != st.st_ctime) {
		fprintf(stderr,
			"%s: not synced ctime(%s) between clients: %lu should be %lu\n",
			prog, secname, st2.st_ctime, st.st_ctime);
		return 14;
	}

	printf("%s: updated times for %s\n", prog, secname);

	return 0;
}
