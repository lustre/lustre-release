#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char ** argv)
{
        int rc;

        if (argc < 3) { 
                printf("Usage: %s file link\n", argv[0]);
                return 1;
        }

        rc = link(argv[1], argv[2]);
        if (rc) { 
                printf("link(%s, %s) error: %s\n", argv[1], argv[2],
		       strerror(errno));
		return errno;
        }
	return 0;
} 
