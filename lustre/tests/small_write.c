#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define GOTO(label, rc)   do { rc; goto label; } while (0)

int main (int argc, char **argv) {
	int fd, i, rc = 0;
	unsigned long bytes, lbytes;
	struct stat st;
	char *str, *str2, *readbuf;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <filename> <bytes>\n", argv[0]);
		GOTO(out, rc = 1);
	}

	bytes = strtoul(argv[2], NULL, 10);
	if (!bytes) {
		printf("No bytes!\n");
		GOTO(out, rc = 2);
	}
	if (bytes % 2) {
		printf("Need an even number of bytes!\n");
		GOTO(out, rc = 3);
	}
	lbytes = 3*bytes/2;

	str = malloc(bytes+1);
	if (!str) {
		printf("No enough memory for %lu bytes.\n", bytes);
		GOTO(out, rc = 4);
	}
	str2 = malloc(lbytes+1);
	if (!str2) {
		printf("No enough memory for %lu bytes.\n", lbytes);
		GOTO(out_str, rc = 5);
	}
	readbuf = malloc(bytes*2);
	if (!readbuf) {
		printf("No enough memory for %lu bytes.\n", bytes*2);
		GOTO(out_str2, rc = 6);
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
		GOTO(out_readbuf, rc = 7);
	}

	rc = write(fd, str, bytes);
	if (rc != bytes) {
		printf("Write failed!\n");
		GOTO(out_fd, rc = 8);
	}

	sleep(1);
	rc = fstat(fd, &st);
	if (rc < 0 || st.st_size != bytes) {
		printf("bad file %lu size first write %lu != %lu: rc %d\n",
		       (unsigned long)st.st_ino, (unsigned long)st.st_size,
                       bytes, rc);
		GOTO(out_fd, rc = 9);
	}

	rc = lseek(fd, bytes / 2, SEEK_SET);
	if (rc != bytes / 2) {
		printf("Seek failed!\n");
		GOTO(out_fd, rc = 10);
	}

	rc = write(fd, str, bytes);
	if (rc != bytes) {
		printf("Write failed!\n");
		GOTO(out_fd, rc = 11);
	}

	rc = fstat(fd, &st);
	if (rc < 0 || st.st_size != bytes + bytes / 2) {
		printf("bad file %lu size second write %lu != %lu: rc %d\n",
		       (unsigned long)st.st_ino, (unsigned long)st.st_size,
                       bytes, rc);
		GOTO(out_fd, rc = 12);
	}

	rc = lseek(fd, 0, SEEK_SET);
	if (rc != 0) {
		printf("Seek failed!\n");
		GOTO(out_fd, rc = 13);
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
			       (unsigned long)st.st_size, bytes + bytes / 2,
                               rc);
			GOTO(out_fd, rc = 14);
		}

		GOTO(out_fd, rc = 15);
	}
	rc = 0;

	if (bytes < 320)
		printf("%s\n%s\n", readbuf, str2);
	if (strcmp(readbuf, str2)) {
		printf("No match!\n");
		GOTO(out_fd, rc = 16);
	}

	printf("Pass!\n");
out_fd:
	close(fd);
out_readbuf:
        free(readbuf);
out_str2:
        free(str2);
out_str:
        free(str);
out:
        return rc;
}
