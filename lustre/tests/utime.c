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
	long before_utime, after_utime;
	const char *prog = argv[0];
	const char *filename = argv[1];
	struct stat st;
	int rc;

	if (argc != 2)
		usage(argv[0]);

	before_mknod = time(0);
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

		printf("%s: good mknod times %lu <= %lu <= %lu\n",
		       prog, before_mknod, st.st_mtime, after_mknod);

		sleep(5);
	}

	before_utime = time(0);
	rc = utime(filename, NULL);
	after_utime = time(0);
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

	if (st.st_mtime < before_utime || st.st_mtime > after_utime) {
		fprintf(stderr, "%s: bad utime times %lu <= %lu <= %lu false\n",
			prog, before_utime, st.st_mtime, after_utime);
		return 7;
	}

	printf("%s: good utime times %lu <= %lu <= %lu\n",
	       prog, before_utime, st.st_mtime, after_utime);

	return 0;
}
