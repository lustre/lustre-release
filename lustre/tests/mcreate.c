// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

static void usage(const char *prog, int status)
{
	fprintf(status == 0 ? stdout : stderr,
		"Usage: %s [OPTION]... FILE\n"
		"  -d, --device=DEV  use device number DEV\n"
		"  -h, --help        dispaly help\n"
		"  -m, --mode=MODE   use mode MODE\n"
		"  -M, --major=MAJOR use device major MAJOR\n"
		"  -N, --minor=MINOR use device minor MINOR\n",
		prog);

	exit(status);
}

int main(int argc, char **argv)
{
	struct option opts[] = {
		{ .name = "device", .has_arg = required_argument, .val = 'd' },
		{ .name = "help", .has_arg = no_argument, .val = 'h' },
		{ .name = "mode", .has_arg = required_argument, .val = 'm' },
		{ .name = "major", .has_arg = required_argument, .val = 'M' },
		{ .name = "minor", .has_arg = required_argument, .val = 'N' },
		{ .name = NULL }
	};
	const char *path;
	mode_t mode = S_IFREG | 0644;
	dev_t dev = 0;
	int rc;
	int c;

	while ((c = getopt_long(argc, argv, "d:hm:M:N:", opts, NULL)) != -1) {
		switch (c) {
		case 'd':
			dev = strtoul(optarg, NULL, 0);
			break;
		case 'h':
			usage(argv[0], 0);
		case 'm':
			mode = strtoul(optarg, NULL, 0);
			break;
		case 'M':
			dev = makedev(strtoul(optarg, NULL, 0), minor(dev));
			break;
		case 'N':
			dev = makedev(major(dev), strtoul(optarg, NULL, 0));
			break;
		case '?':
			usage(argv[0], 1);
		}
	}

	if (argc - optind != 1)
		usage(argv[0], 1);

	path = argv[optind];

	if ((mode & S_IFMT) == S_IFDIR)
		rc = mkdir(path, mode & ~S_IFMT);
	else if ((mode & S_IFMT) == S_IFLNK)
		rc = symlink("oldpath", path);
	else
		rc = mknod(path, mode, dev);

	if (rc) {
		rc = errno;
		fprintf(stderr, "%s: cannot create `%s' with mode %#o: %s\n",
			argv[0], path, mode, strerror(rc));
	}

	return rc;
}
