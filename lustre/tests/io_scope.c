// SPDX-License-Identifier: GPL-2.0-only
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Exercise LL_IOC_SET_IO_SCOPE / llapi_io_scope_set().
 */

#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lustre/lustreapi.h>

#define IO_SCOPE_WRITE_SIZE	4096

static void usage(void)
{
	fprintf(stderr,
		"usage: io_scope [-s FILE|MIRROR|STRIPE|OBJECT] [-i mid] [-v layout_version] [-w] FILE\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	struct ll_ioc_io_scope ios;
	const char *name = "FILE";
	unsigned long mirror_id = 0;
	unsigned long layout_version = 0;
	bool do_write = false;
	void *buf;
	ssize_t written;
	int fd;
	int c;
	int rc;

	memset(&ios, 0, sizeof(ios));
	opterr = 0;
	while ((c = getopt(argc, argv, "s:i:v:w")) != -1) {
		switch (c) {
		case 's':
			name = optarg;
			break;
		case 'i':
			mirror_id = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			layout_version = strtoul(optarg, NULL, 0);
			break;
		case 'w':
			do_write = true;
			break;
		default:
			usage();
		}
	}

	if (argc == optind)
		usage();

	fd = open(argv[optind], O_RDWR | O_DIRECT);
	if (fd < 0)
		err(EXIT_FAILURE, "open %s", argv[optind]);

	if (!strcmp(name, "FILE"))
		ios.ios_scope = LL_IO_SCOPE_FILE;
	else if (!strcmp(name, "MIRROR"))
		ios.ios_scope = LL_IO_SCOPE_MIRROR;
	else if (!strcmp(name, "STRIPE"))
		ios.ios_scope = LL_IO_SCOPE_STRIPE;
	else if (!strcmp(name, "OBJECT"))
		ios.ios_scope = LL_IO_SCOPE_OBJECT;
	else
		errx(EXIT_FAILURE, "unknown scope '%s'", name);

	ios.ios_mirror_id = mirror_id;
	ios.ios_layout_version = layout_version;

	rc = llapi_io_scope_set(fd, &ios);
	if (rc < 0) {
		fprintf(stderr, "llapi_io_scope_set: %s\n", strerror(-rc));
		close(fd);
		exit(-rc);
	}

	if (do_write) {
		rc = posix_memalign(&buf, IO_SCOPE_WRITE_SIZE,
				    IO_SCOPE_WRITE_SIZE);
		if (rc)
			errx(EXIT_FAILURE, "posix_memalign: %s", strerror(rc));
		memset(buf, 0, IO_SCOPE_WRITE_SIZE);

		written = pwrite(fd, buf, IO_SCOPE_WRITE_SIZE, 0);
		if (written < 0) {
			rc = errno;
			fprintf(stderr, "pwrite: %s\n", strerror(rc));
			free(buf);
			close(fd);
			exit(rc);
		}
		free(buf);
		if (written != IO_SCOPE_WRITE_SIZE)
			errx(EXIT_FAILURE, "short write %zd", written);
	}

	close(fd);
	return 0;
}
