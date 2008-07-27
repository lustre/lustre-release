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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

void
usage (char *argv0, int help)
{
	char *progname = strrchr(argv0, '/');

	if (progname == NULL)
		progname = argv0;
	
	fprintf (help ? stdout : stderr,
		 "Usage: %s [-e] file\n", progname);
	
	if (!help)
	{
		fprintf (stderr, "   or try '-h' for help\n");
		exit (1);
	}
	
	printf ("Create the given file with O_EXCL...\n");
	printf (" -e    expect EEXIST\n");
	printf (" -h    print help");
	printf (" Exit status is 0 on success, 1 on failure\n");
}

int main(int argc, char **argv)
{
        int rc;
	int want_eexist = 0;
	
	while ((rc = getopt (argc, argv, "eh")) != -1)
		switch (rc)
		{
		case 'e':
			want_eexist = 1;
			break;
		case 'h':
			usage (argv[1], 1);
			return (0);
		default:
			usage (argv[0], 0);
		}
	
        if (optind != argc - 1) { 
		usage (argv[0], 0);
                return 1;
        }

        rc = open(argv[optind], O_CREAT|O_EXCL, 0644);
        if (rc == -1)
	{
		if (want_eexist && errno == EEXIST)
		{
			printf("open failed: %s (expected)\n", strerror(errno));
			return (0);
		}
		printf("open failed: %s\n", strerror(errno));
		return (1);
	} else {
		if (want_eexist)
		{
			printf("open success (expecting EEXIST).\n");
			return (1);
		}
		printf("open success.\n");
		return (0);
	}
	
	return ((rc == 0) ? 0 : 1);
}
