#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char ** argv)
{
        int rc, i;

        if (argc < 2) { 
                printf("Usage %s filename\n", argv[0]);
                return 1;
        }

	for (i = 1; i < argc; i++) {
        	rc = unlink(argv[i]);
        	if (rc)
                	printf("unlink(%s) error: %s\n", argv[i], strerror(errno));
        }
        return rc;
} 
