#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

// not correctly in the headers yet!!
#ifndef O_DIRECT
#define O_DIRECT         040000 /* direct disk access hint */
#endif

int main(int argc, char **argv)
{
        int fd;
        char *buf;
        int blocks;
        struct stat st;
        int rc;

        if (argc != 3) {
                printf("Usage: %s file nr_blocks\n", argv[0]);
                return 1;
        }

        blocks = strtoul(argv[2], 0, 0);
        fd = open(argv[1], O_DIRECT | O_RDWR | O_CREAT, 0644);
        if (fd == -1) {
                printf("Cannot open %s:  %s\n", argv[1], strerror(errno));
                return 1;
        }

        if (fstat(fd, &st) < 0) {
                printf("Cannot stat %s:  %s\n", argv[1], strerror(errno));
                return 1;
        }

        printf("directio on %s for %dx%lu blocks \n", argv[1], blocks,
               st.st_blksize);

        buf = mmap(0, blocks * st.st_blksize, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANON, 0, 0);
        if (!buf) {
                printf("No memory %s\n", strerror(errno));
                return 1;
        }

        rc = write(fd, buf, blocks * st.st_blksize);
        if (rc != blocks * st.st_blksize) {
                printf("Write error %s (rc = %d)\n", strerror(errno), rc);
                return 1;
        }

        if (lseek(fd, 0, SEEK_SET) != 0) {
                printf("Cannot seek %s\n", strerror(errno));
                return 1;
        }

        rc = read(fd, buf, blocks * st.st_blksize);
        if (rc != blocks * st.st_blksize) {
                printf("Read error: %s (rc = %d)\n", strerror(errno), rc);
                return 1;
        }

        return 0;
}
