/* GPL HEADER START
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
 * Copyright (c) 2020, Whamcloud.
 * Author: Mikhail Pershin <mpershin@whamcloud.com>
 */

/*
 * Test does lseek with SEEK_DATA/SEEK_HOLE options on a file and prints result.
 *
 * Two input options are '-d|--data' for SEEK_DATA and '-l|--hole' for hole
 */

#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>

char usage[] =
"Usage: %s [option] <start> <filename>\n"
"	where options are:\n"
"	--hole|-l seek first hole offset after given offset\n"
"	--data|-d seek first data offset after given offset\n";

int main(int argc, char **argv)
{
	int c;
	struct option long_opts[] = {
		{ .name = "hole", .has_arg = no_argument, .val = 'l' },
		{ .name = "data", .has_arg = no_argument, .val = 'd' },
		{ .name = NULL },
	};
	int opt = SEEK_HOLE;
	int fd;
	off_t cur_off;
	off_t ret_off;

	optind = 0;
	while ((c = getopt_long(argc, argv, "ld", long_opts, NULL)) != -1) {
		switch (c) {
		case 'l':
			opt = SEEK_HOLE;
			break;
		case 'd':
			opt = SEEK_DATA;
			break;
		default:
			fprintf(stderr, "error: %s: unknown option '%s'\n",
				argv[0], argv[optind - 1]);
		return -1;
		}
	}

	if (argc - optind < 2) {
		fprintf(stderr, usage, argv[0]);
		return -1;
	}

	cur_off = atoll(argv[optind]);

	fd = open(argv[optind + 1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "cannot open %s for reading, error %d",
			argv[optind + 1], errno);
		return -1;
	}

	ret_off = lseek(fd, cur_off, opt);
	close(fd);

	if (ret_off < 0) {
		fprintf(stderr, "lseek to %jd failed with %d\n",
			cur_off, errno);
		return ret_off;
	}
	printf("%jd\n", ret_off);
	return 0;
}
