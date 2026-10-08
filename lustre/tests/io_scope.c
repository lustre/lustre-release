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
		"usage: io_scope [-s FILE|MIRROR|STRIPE|OBJECT] [-i mid] [-x stripe_idx] [-v layout_version] [-b] [-w|-r|-t size|-f|-l] FILE\n"
		"  -b clear O_DIRECT after setting the scope,\n"
		"  -w pwrite 4k at 0, -r pread 4k at 0, -t size ftruncate,\n"
		"  -f fallocate [0, 8k), -l lseek(SEEK_DATA, 0)\n");
	exit(EXIT_FAILURE);
}

/* exit status is the errno of the I/O under test */
static void __attribute__((noreturn)) die_errno(int fd, const char *op)
{
	int rc = errno;

	fprintf(stderr, "%s: %s\n", op, strerror(rc));
	close(fd);
	exit(rc);
}

int main(int argc, char *argv[])
{
	struct ll_ioc_io_scope ios;
	const char *name = "FILE";
	unsigned long mirror_id = 0;
	unsigned long layout_version = 0;
	unsigned long stripe_idx = 0;
	long trunc_size = -1;
	bool buffered = false;
	bool do_write = false;
	bool do_read = false;
	bool do_falloc = false;
	bool do_lseek = false;
	void *buf;
	ssize_t written;
	int fd;
	int c;
	int rc;

	memset(&ios, 0, sizeof(ios));
	opterr = 0;
	while ((c = getopt(argc, argv, "s:i:x:v:bwrt:fl")) != -1) {
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
		case 'x':
			stripe_idx = strtoul(optarg, NULL, 0);
			break;
		case 'b':
			buffered = true;
			break;
		case 'w':
			do_write = true;
			break;
		case 'r':
			do_read = true;
			break;
		case 't':
			trunc_size = strtol(optarg, NULL, 0);
			break;
		case 'f':
			do_falloc = true;
			break;
		case 'l':
			do_lseek = true;
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
	ios.ios_stripe_idx = stripe_idx;
	ios.ios_layout_version = layout_version;

	rc = llapi_io_scope_set(fd, &ios);
	if (rc < 0) {
		fprintf(stderr, "llapi_io_scope_set: %s\n", strerror(-rc));
		close(fd);
		exit(-rc);
	}

	if (buffered && fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_DIRECT) < 0)
		err(EXIT_FAILURE, "fcntl %s", argv[optind]);

	if (do_write) {
		rc = posix_memalign(&buf, IO_SCOPE_WRITE_SIZE,
				    IO_SCOPE_WRITE_SIZE);
		if (rc)
			errx(EXIT_FAILURE, "posix_memalign: %s", strerror(rc));
		memset(buf, 0, IO_SCOPE_WRITE_SIZE);

		written = pwrite(fd, buf, IO_SCOPE_WRITE_SIZE, 0);
		if (written < 0)
			die_errno(fd, "pwrite");
		free(buf);
		if (written != IO_SCOPE_WRITE_SIZE)
			errx(EXIT_FAILURE, "short write %zd", written);
	}

	if (do_read) {
		rc = posix_memalign(&buf, IO_SCOPE_WRITE_SIZE,
				    IO_SCOPE_WRITE_SIZE);
		if (rc)
			errx(EXIT_FAILURE, "posix_memalign: %s", strerror(rc));
		written = pread(fd, buf, IO_SCOPE_WRITE_SIZE, 0);
		if (written < 0)
			die_errno(fd, "pread");
		free(buf);
	}

	if (trunc_size >= 0 && ftruncate(fd, trunc_size) < 0)
		die_errno(fd, "ftruncate");

	if (do_falloc && fallocate(fd, 0, 0, 2 * IO_SCOPE_WRITE_SIZE) < 0)
		die_errno(fd, "fallocate");

	if (do_lseek && lseek(fd, 0, SEEK_DATA) < 0 && errno != ENXIO)
		die_errno(fd, "lseek");


	close(fd);
	return 0;
}
