#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	unsigned long off;
	int err;

	if (argc != 3) { 
		printf("usage %s file offset\n", argv[0]); 
		return 1;
	}

	off = strtoul(argv[2], NULL, 0);
	err = truncate(argv[1], off); 
	if ( err ) { 
		printf("Error truncating %s: %s\n", argv[1], strerror(errno));
	}
	return err;
}
