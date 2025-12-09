#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <lustre/lustreapi.h>

int main(int argc, char *argv[])
{
	char *fname;
	int fd;
	int rc;
	unsigned int mirror_id;
	char *buf;
	ssize_t bytes_read;
	off_t offset;
	int i;
	int non_zero_count = 0;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <file> <mirror_id> <offset>\n",
			argv[0]);
		return 1;
	}

	fname = argv[1];
	mirror_id = atoi(argv[2]);
	offset = atoll(argv[3]);

	fd = open(fname, O_RDONLY | O_DIRECT);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n",
			fname, strerror(errno));
		return 1;
	}

	/* Allocate aligned buffer for O_DIRECT */
	rc = posix_memalign((void **)&buf, 4096, 4096);
	if (rc != 0) {
		fprintf(stderr, "Failed to allocate aligned buffer: %s\n",
			strerror(rc));
		close(fd);
		return 1;
	}

	printf("Reading from file %s, mirror %u at offset %lld\n",
	       fname, mirror_id, (long long)offset);

	/* Set designated mirror */
	rc = llapi_mirror_set(fd, mirror_id);
	if (rc < 0) {
		fprintf(stderr, "Failed to set mirror %u: %s\n",
			mirror_id, strerror(-rc));
		close(fd);
		return 1;
	}

	/* Read from the specified offset */
	memset(buf, 0xFF, 4096);  /* Fill with non-zero pattern */
	bytes_read = pread(fd, buf, 4096, offset);
	if (bytes_read < 0) {
		fprintf(stderr, "pread failed: %s\n", strerror(errno));
		llapi_mirror_clear(fd);
		close(fd);
		return 1;
	}

	printf("Read %zd bytes from offset %lld\n",
	       bytes_read, (long long)offset);

	/* Check if we got zeros or garbage */
	for (i = 0; i < bytes_read; i++)
		if (buf[i] != 0)
			non_zero_count++;

	printf("Non-zero bytes: %d out of %zd\n", non_zero_count, bytes_read);

	if (non_zero_count > 0) {
		printf("First 64 bytes (hex):\n");
		for (i = 0; i < 64 && i < bytes_read; i++) {
			printf("%02x ", (unsigned char)buf[i]);
			if ((i + 1) % 16 == 0)
				printf("\n");
		}
		if (i % 16 != 0)
			printf("\n");
	} else {
		printf("All bytes are zero (correct!)\n");
	}

	llapi_mirror_clear(fd);
	close(fd);
	free(buf);

	return (non_zero_count > 0) ? 1 : 0;
}

