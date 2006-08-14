/*
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
	fprintf(stderr, "usage: %s <filename>\n", prog);
	exit(1);
}

int main(int argc, char *argv[])
{
	long before_mknod, after_mknod;
	const char *prog = argv[0];
	const char *filename = argv[1];
        struct utimbuf utb;
	struct stat st;
	int rc;

	utb.actime = 0x47114711;
	utb.modtime = 0x11471147;

	if (argc != 2)
		usage(argv[0]);

	/* Adjust the before time back one second, because the kernel's
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
				"%s: bad mknod times %lu <= %lu <= %lu false\n",
				prog, before_mknod, st.st_mtime, after_mknod);
			return 4;
		}

		printf("%s: good mknod times %lu%s <= %lu <= %lu\n",
		       prog, before_mknod, before_mknod == st.st_mtime ? "*":"",
		       st.st_mtime, after_mknod);

	}

	/* See above */
	rc = utime(filename, &utb);
	if (rc) {
		fprintf(stderr, "%s: utime(%s) failed: rc %d: %s\n",
			prog, filename, errno, strerror(errno));
		return 5;
	}

	rc = stat(filename, &st);
	if (rc) {
		fprintf(stderr, "%s: second stat(%s) failed: rc %d: %s\n",
			prog, filename, errno, strerror(errno));
		return 6;
	}

	if (st.st_mtime != utb.modtime ) {
		fprintf(stderr, "%s: bad utime mtime %lu should be  %lu\n",
			prog, st.st_mtime, utb.modtime);
		return 7;
	}

	if (st.st_atime != utb.actime ) {
		fprintf(stderr, "%s: bad utime atime %lu should be  %lu\n",
			prog, st.st_atime, utb.actime);
		return 8;
	}

	printf("%s: good utime mtimes %lu, atime %lu\n",
	       prog, utb.modtime, utb.actime);

	return 0;
}
