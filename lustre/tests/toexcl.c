#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

int main(int argc, char **argv)
{
        int rc;

        if (argc != 2) { 
                printf("usage: %s name\n", argv[0]);
                return 1;
        }

        rc = open(argv[1], O_CREAT|O_EXCL, 0644);
        if (rc == -1)
                printf("open failed: %s\n", strerror(errno));
        else
                printf("open success.\n");
        return 0;
}
