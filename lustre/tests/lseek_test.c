// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (c) 2020, Whamcloud.
 * Author: Mikhail Pershin <mpershin@whamcloud.com>
 */

/*
 * Test does lseek with SEEK_DATA/SEEK_HOLE options on a file and prints result.
 *
 * Two input options are '-d|--data' for SEEK_DATA and '-l|--hole' for hole.
 * Optional '-m|--mirror-id' selects a designated FLR mirror via liblustreapi.
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
#include <lustre/lustreapi.h>

char usage[] =
"Usage: %s [option] <start> <filename>\n"
"	where options are:\n"
"	--hole|-l seek first hole offset after given offset\n"
"	--data|-d seek first data offset after given offset\n"
"	--mirror-id|-m <id> seek on designated mirror (requires O_DIRECT)\n";

int main(int argc, char **argv)
{
	int c;
	struct option long_opts[] = {
		{ .name = "hole", .has_arg = no_argument, .val = 'l' },
		{ .name = "data", .has_arg = no_argument, .val = 'd' },
		{ .name = "mirror-id", .has_arg = required_argument,
		  .val = 'm' },
		{ .name = NULL },
	};
	int opt = SEEK_HOLE;
	unsigned int mirror_id = 0;
	int fd;
	int rc;
	off_t cur_off;
	off_t ret_off;
	char *fname;

	optind = 0;
	while ((c = getopt_long(argc, argv, "ldm:", long_opts, NULL)) != -1) {
		switch (c) {
		case 'l':
			opt = SEEK_HOLE;
			break;
		case 'd':
			opt = SEEK_DATA;
			break;
		case 'm':
			mirror_id = atoi(optarg);
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
	fname = argv[optind + 1];

	if (mirror_id > 0)
		fd = open(fname, O_RDONLY | O_DIRECT);
	else
		fd = open(fname, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "cannot open %s for reading: %s\n",
			fname, strerror(errno));
		return -1;
	}

	if (mirror_id > 0) {
		rc = llapi_mirror_set(fd, mirror_id);
		if (rc < 0) {
			fprintf(stderr, "failed to set mirror %u: %s\n",
				mirror_id, strerror(-rc));
			close(fd);
			return -1;
		}
	}

	ret_off = lseek(fd, cur_off, opt);

	if (mirror_id > 0)
		(void)llapi_mirror_clear(fd);

	close(fd);

	if (ret_off < 0) {
		fprintf(stderr, "lseek to %jd failed with %d\n",
			cur_off, errno);
		return ret_off;
	}
	printf("%jd\n", ret_off);
	return 0;
}
