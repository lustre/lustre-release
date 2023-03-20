#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	int fd;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "usage: %s file\n", argv[0]);
		return 1;
	}

	fd = open(argv[1], O_RDWR, 0);
	if (fd <= 0) {
		fprintf(stderr,
			"open failed on %s, error: %s\n",
			argv[1], strerror(errno));
		return errno;
	}

	rc = posix_fadvise(fd, 0, 1024 * 1024, POSIX_FADV_DONTNEED);
	if (rc) {
		fprintf(stderr,
			"fadvise FADV_DONTNEED failed on %s, error: %s\n",
			argv[1], strerror(errno));
		return errno;
	}
	return 0;
}
