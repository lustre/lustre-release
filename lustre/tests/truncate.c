#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	unsigned long long off;
	int err;

	if (argc != 3) {
		printf("usage %s file bytes\n", argv[0]);
		return 1;
	}

	off = strtoull(argv[2], NULL, 0);
	err = truncate64(argv[1], off);
	if (err)
		printf("Error truncating %s: %s\n", argv[1], strerror(errno));

	return err;
}
