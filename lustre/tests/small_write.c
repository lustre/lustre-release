#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int main (int argc, char **argv) {
	int fd, i, rc;
	unsigned long bytes, lbytes;
	struct stat st;
	char *str, *str2, *readbuf;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <filename> <bytes>\n", argv[0]);
		return 1;
	}

	bytes = strtoul(argv[2], NULL, 10);
	if (!bytes) {
		printf("No bytes!\n");
		return 1;
	}
	if (bytes % 2) {
		printf("Need an even number of bytes!\n");
		return 1;
	}
	lbytes = 3*bytes/2;

	str = malloc(bytes+1);
	if (!str) {
		printf("No enough memory for %lu bytes.\n", bytes);
		return 1;
	}
	str2 = malloc(lbytes+1);
	if (!str) {
		printf("No enough memory for %lu bytes.\n", lbytes);
		return 1;
	}
	readbuf = malloc(bytes*2);
	if (!str) {
		printf("No enough memory for %lu bytes.\n", bytes*2);
		return 1;
	}

	for(i=0; i < bytes; i++)
		str[i] = 'a' + (i % 26);
	str[i] = '\0';

	memcpy(str2, str, bytes);
	memcpy(str2+(bytes/2), str, bytes);
	str2[lbytes] = '\0';

	if (bytes < 320)
		printf("First  String: %s\nSecond String: %s\n", str, str2);

	fd = open(argv[1], O_CREAT|O_RDWR|O_TRUNC, 0700);
	if (fd == -1) {
		printf("Could not open file %s.\n", argv[1]);
		return 1;
	}

	rc = write(fd, str, bytes);
	if (rc != bytes) {
		printf("Write failed!\n");
		return 1;
	}

	sleep(1);
	rc = fstat(fd, &st);
	if (rc < 0 || st.st_size != bytes) {
		printf("bad file %lu size first write %lu != %lu: rc %d\n",
		       st.st_ino, st.st_size, bytes, rc);
		return 1;
	}

	rc = lseek(fd, bytes / 2, SEEK_SET);
	if (rc != bytes / 2) {
		printf("Seek failed!\n");
		return 1;
	}

	rc = write(fd, str, bytes);
	if (rc != bytes) {
		printf("Write failed!\n");
		return 1;
	}

	rc = fstat(fd, &st);
	if (rc < 0 || st.st_size != bytes + bytes / 2) {
		printf("bad file %lu size second write %lu != %lu: rc %d\n",
		       st.st_ino, st.st_size, bytes, rc);
		return 1;
	}

	rc = lseek(fd, 0, SEEK_SET);
	if (rc != 0) {
		printf("Seek failed!\n");
		return 1;
	}

	rc = read(fd, readbuf, bytes * 2);
	if (rc != lbytes) {
		printf("Read %d bytes instead of %lu.\n", rc, lbytes);
		if (rc == -1)
			perror("");
		else
			printf("%s\n%s\n", readbuf, str2);
		rc = fstat(fd, &st);
		if (rc < 0 || st.st_size != bytes + bytes / 2) {
			printf("bad file size after read %lu != %lu: rc %d\n",
			       st.st_size, bytes + bytes / 2, rc);
			return 1;
		}

		return 1;
	}

	fd = close(fd);
	if (fd == -1)
		return 1;

	if (bytes < 320)
		printf("%s\n%s\n", readbuf, str2);
	if (strcmp(readbuf, str2)) {
		printf("No match!\n");
		return 1;
	}

	printf("Pass!\n");
	return 0;
}
