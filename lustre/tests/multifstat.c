#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

int main(int argc, char **argv)
{
        int fd1, fd2;
        struct stat st1, st2;

        if (argc != 3) {
                printf("Usage %s file1 file2\n", argv[0]);
                return 1;
        }


        fd1 = open(argv[1], O_CREAT| O_RDWR, 0666);
        if (fd1 == -1) {
                printf("Error opening %s: %s\n", argv[1], strerror(errno));
                return errno;
        }

        fd2 = open(argv[2], O_RDONLY);
        if (fd2 == -1) {
                printf("Error opening %s: %s\n", argv[2], strerror(errno));
                return errno;
        }

        sleep(1);

        if ( write(fd1, "hello", strlen("hello")) != strlen("hello")) {
                printf("Error writing: %s\n", strerror(errno));
                return errno;
        }

        if ( fstat(fd1, &st1) ) {
                printf("Error statting %s: %s\n", argv[1], strerror(errno));
                return errno;
        }

        if ( fstat(fd2, &st2) ) {
                printf("Error statting %s: %s\n", argv[2], strerror(errno));
                return errno;
        }

        if ( st1.st_size != st2.st_size ) {
                printf("Sizes don't match %ld, %ld\n",
                       st1.st_size, st2.st_size);
                return 1;
        }

        if ( st1.st_mtime != st2.st_mtime ) {
                printf("Mtimes don't match %ld, %ld\n",
                       st1.st_mtime, st2.st_mtime);
                return 1;
        }

        return 0;
}
