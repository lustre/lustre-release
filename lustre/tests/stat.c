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
        struct stat buf;

        if (argc < 2) { 
                printf("Usage %s filename\n", argv[0]);
                return 1;
        }

        rc = stat(argv[1], &buf); 
        if (rc) { 
                printf("stat(%s) error: %s\n", argv[1], strerror(errno));
        }
        return rc;
} 
