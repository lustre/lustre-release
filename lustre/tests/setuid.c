#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/fsuid.h>

int main(int argc, char ** argv)
{
        int rc, fsuid;

        if (argc < 2) { 
                printf("Usage %s fsuid\n", argv[0]);
                return 1;
        }

        fsuid = strtoul(argv[2], NULL, 0);
        rc = setfsuid(fsuid);
        if (rc) { 
                printf("mknod(%s) error: %s\n", argv[1], strerror(errno));
        }
        return rc;
} 
