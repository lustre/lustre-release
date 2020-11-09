#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/file.h>

int main(int argc, char **argv)
{
	char *fname = argv[1];
	char buf[5];
	int fd;
	off_t off;
	int rc;

	if (argc != 2) {
		fprintf(stdout, "usage: %s file\n", argv[0]);
		return 1;
	}

	fd = open(fname, O_RDWR | O_CREAT, 0666);
	if (fd < 0) {
		fprintf(stderr, "open %s failed:%d\n", fname, errno);
		return fd;
	}

	off = 1021 * 1024 * 1024;
	if (ftruncate(fd, off) < 0) {
		fprintf(stderr, "ftruncate %ld failed:%d\n", off, errno);
		rc = -1;
		goto close;
	}

	off -= 4;
	off = lseek(fd, off, SEEK_SET);
	if (off == (off_t)-1) {
		fprintf(stderr, "lseek %ld failed:%d\n", off, errno);
		rc = -1;
		goto close;
	}

	rc = read(fd, buf, 4);
	if (rc < 0) {
		fprintf(stderr, "read 4 bytes failed:%d\n", errno);
		goto close;
	} else if (rc != 4) {
		fprintf(stderr, "read returns %d, not 4 bytes\n", rc);
		rc = -1;
	} else {
		rc = 0;
	}

close:
	close(fd);

	return rc;
}
