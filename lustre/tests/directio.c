#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>

// not correctly in the headers yet!!
#ifndef O_DIRECT
#define O_DIRECT	 040000	/* direct disk access hint */
#endif

#define BLOCKSIZE 4096

int main(int argc, char **argv)
{
        int fd;
        char *buf;
        int pages;
        int rc;

        if (argc != 3) {
                printf("Usage: %s file nr_pages\n", argv[0]);
                return 1;
        }

        pages = strtoul(argv[2], 0, 0);
        printf("directio on %s for %d pages \n", argv[1], pages);

        buf = mmap(0, pages * BLOCKSIZE, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANON, 0, 0);
        if (!buf) {
                printf("No memory %s\n", strerror(errno));
                return 1;
        }

        fd = open(argv[1], O_DIRECT | O_RDWR | O_CREAT);
        if (fd == -1) {
                printf("Cannot open %s:  %s\n", argv[1], strerror(errno));
                return 1;
        }

        rc = read(fd, buf, pages * BLOCKSIZE);
        if (rc != pages * BLOCKSIZE) {
                printf("Read error: %s, rc %d\n", strerror(errno), rc);
                return 1;
        }

        if ( lseek(fd, 0, SEEK_SET) != 0 ) {
                printf("Cannot seek %s\n", strerror(errno));
                return 1;
        }

        rc = write(fd, buf, pages * BLOCKSIZE);
        if (rc != pages * BLOCKSIZE) {
                printf("Write error %s\n", strerror(errno));
                return 1;
        }

        return 0;
}
