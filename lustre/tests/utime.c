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

void usage(char *prog)
{
	fprintf(stderr, "usage: %s <filename>\n", prog);
	exit(1);
}

int main(int argc, char *argv[])
{
	long before_mknod, after_mknod;
	long before_utime, after_utime;
	struct stat st;
	int rc;

	if (argc != 2)
		usage(argv[0]);

	before_mknod = time(0);
	rc = mknod(argv[1], 0700, S_IFREG);
	after_mknod = time(0);
	if (rc) {
		fprintf(stderr, "%s: mknod(%s) failed: rc %d: %s\n",
			argv[0], argv[1], rc, strerror(rc));
		return 2;
	}

	rc = stat(argv[1], &st);
	if (rc) {
		fprintf(stderr, "%s: stat(%s) failed: rc %d: %s\n",
			argv[0], argv[1], rc, strerror(rc));
		return 3;
	}

	if (st.st_mtime < before_mknod || st.st_mtime > after_mknod) {
		fprintf(stderr, "%s: bad mknod times %lu <= %lu <= %lu false\n",
			argv[0], before_mknod, st.st_mtime, after_mknod);
		return 4;
	}

	printf("%s: good mknod times %lu <= %lu <= %lu\n",
	       argv[0], before_mknod, st.st_mtime, after_mknod);

	sleep(5);

	before_utime = time(0);
	rc = utime(argv[0], NULL);
	after_utime = time(0);
	if (rc) {
		fprintf(stderr, "%s: stat(%s) failed: rc %d: %s\n",
			argv[0], argv[1], rc, strerror(rc));
		return 5;
	}

	rc = stat(argv[1], &st);
	if (rc) {
		fprintf(stderr, "%s: second stat(%s) failed: rc %d: %s\n",
			argv[0], argv[1], rc, strerror(rc));
		return 6;
	}

	if (st.st_mtime < before_utime || st.st_mtime > after_utime) {
		fprintf(stderr, "%s: bad utime times %lu <= %lu <= %lu false\n",
			argv[0], before_utime, st.st_mtime, after_utime);
		return 7;
	}

	printf("%s: good utime times %lu <= %lu <= %lu\n",
	       argv[0], before_mknod, st.st_mtime, after_mknod);

	return 0;
}
