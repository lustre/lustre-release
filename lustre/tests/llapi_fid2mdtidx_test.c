// SPDX-License-Identifier: GPL-2.0-only

/*
 * Verify LL_IOC_FID2MDTIDX on an arbitrary mount fd.
 *
 * This is intended for server-mount coverage, where the ioctl is handled by
 * tgt_mount.c::server_ioctl() instead of the client ioctl path.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lustre/lustreapi.h>

#define ERROR(fmt, ...)							\
	fprintf(stderr, "%s: %s:%d: %s: " fmt "\n",			\
		program_invocation_short_name, __FILE__, __LINE__,	\
		__func__, ## __VA_ARGS__)

#define DIE(fmt, ...)							\
	do {								\
		ERROR(fmt, ## __VA_ARGS__);				\
		exit(EXIT_FAILURE);					\
	} while (0)

#define ASSERTF(cond, fmt, ...)						\
	do {								\
		if (!(cond))						\
			DIE("assertion '%s' failed: " fmt,		\
			    #cond, ## __VA_ARGS__);			\
	} while (0)

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -d MOUNTPOINT -f FID -i EXPECTED_MDT_INDEX\n",
		prog);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	struct lu_fid fid;
	char *mountpoint = NULL;
	char *fidstr = NULL;
	char *endptr = NULL;
	long expected = -1;
	int fd = -1;
	int mdtidx;
	int rc;
	int opt;

	while ((opt = getopt(argc, argv, "d:f:i:")) != -1) {
		switch (opt) {
		case 'd':
			mountpoint = optarg;
			break;
		case 'f':
			fidstr = optarg;
			break;
		case 'i':
			errno = 0;
			expected = strtol(optarg, &endptr, 0);
			ASSERTF(errno == 0 && endptr != optarg &&
				*endptr == '\0',
				"invalid MDT index '%s'", optarg);
			break;
		default:
			usage(argv[0]);
		}
	}

	if (mountpoint == NULL || fidstr == NULL || expected < 0)
		usage(argv[0]);

	rc = llapi_fid_parse(fidstr, &fid, &endptr);
	ASSERTF(rc == 0 && endptr != fidstr && *endptr == '\0',
		"invalid FID '%s': rc=%d", fidstr, rc);

	fd = open(mountpoint, O_RDONLY);
	ASSERTF(fd >= 0, "open(%s) failed: %s",
		mountpoint, strerror(errno));

	rc = llapi_get_mdt_index_by_fid(fd, &fid, &mdtidx);
	close(fd);
	ASSERTF(rc >= 0, "llapi_get_mdt_index_by_fid(%s, %s) failed: %s",
		mountpoint, fidstr, strerror(-rc));
	ASSERTF(mdtidx == expected,
		"MDT index mismatch for %s on %s: got %d expected %ld",
		fidstr, mountpoint, mdtidx, expected);

	return EXIT_SUCCESS;
}
