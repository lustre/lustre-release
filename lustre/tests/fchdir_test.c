#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>


int main(int argc, char **argv)
{
        int fd;
        int rc;

        fd = open(".", O_RDONLY);
        if (fd < 0) {
                perror("opening '.' :");
                exit(2);
        }

        rc = chdir("/mnt/lustre/subdir/subdir");
        if (rc) { 
                perror("cannot chdir subdir:");
                exit(3);
        }

        rc = fchdir(fd);
        if (rc) { 
                perror("cannot fchdir back\n");
                exit(4);
        }

        rc = close(fd);
        if (rc) { 
                perror("cannot close '.'\n");
                exit(5);
        }

        return(0);
}
