/*
 * Check that flistxattr() calls on orphans do not return "trusted.link" EAs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/xattr.h>

int
main(int argc, char *argv[])
{
	char   *names;
	char   *name;
	ssize_t	size;
	int	fd;
	int	rc;

	fd = open(argv[1], O_RDWR | O_CREAT, 0666);
	if (fd == -1) {
		perror("open");
		return 1;
	}

	rc = unlink(argv[1]);
	if (rc == -1) {
		perror("unlink");
		close(fd);
		return 1;
	}

	size = flistxattr(fd, NULL, 0);
	if (size == -1) {
		perror("flistxattr size");
		close(fd);
		return 1;
	}

	names = malloc(size);
	if (names == NULL) {
		fprintf(stderr, "Cannot allocate names\n");
		close(fd);
		return 1;
	}

	size = flistxattr(fd, names, size);
	if (size == -1) {
		perror("flistxattr");
		free(names);
		close(fd);
		return 1;
	}

	for (name = names; name < names + size; name += strlen(name) + 1)
		if (strcmp(name, "trusted.link") == 0) {
			free(names);
			close(fd);
			return 1;
		}

	free(names);

	rc = close(fd);
	if (rc == -1) {
		perror("close");
		return 1;
	}

	return 0;
}
