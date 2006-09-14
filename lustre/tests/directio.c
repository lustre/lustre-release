/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#define  _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

int main(int argc, char **argv)
{
#ifdef O_DIRECT
        int fd;
        char *wbuf;
        int blocks, seek_blocks;
        long len;
        off64_t seek;
        struct stat64 st;
        int action;
        int rc;

        if (argc < 5 || argc > 6) {
                printf("Usage: %s <read/write/rdwr> file seek nr_blocks [blocksize]\n", argv[0]);
                return 1;
        }

        if (!strcmp(argv[1], "read"))
                action = O_RDONLY;
        else if (!strcmp(argv[1], "write"))
                action = O_WRONLY;
        else if (!strcmp(argv[1], "rdwr"))
                action = O_RDWR;
        else {
                printf("Usage: %s <read/write/rdwr> file seek nr_blocks [blocksize]\n", argv[0]);
                return 1;
        }

        seek_blocks = strtoul(argv[3], 0, 0);
        blocks = strtoul(argv[4], 0, 0);
        if (!blocks) {
                printf("Usage: %s <read/write/rdwr> file seek nr_blocks [blocksize]\n", argv[0]);
                return 1;
        }

        fd = open(argv[2], O_LARGEFILE | O_DIRECT | O_RDWR | O_CREAT, 0644);
        if (fd == -1) {
                printf("Cannot open %s:  %s\n", argv[1], strerror(errno));
                return 1;
        }

        if (argc >= 6)
                st.st_blksize = strtoul(argv[5], 0, 0);
        else if (fstat64(fd, &st) < 0) {
                printf("Cannot stat %s:  %s\n", argv[1], strerror(errno));
                return 1;
        }

        printf("directio on %s for %dx%lu bytes \n", argv[1], blocks,
               st.st_blksize);

        seek = (off64_t)seek_blocks * (off64_t)st.st_blksize;
        len = blocks * st.st_blksize;

        wbuf = mmap(0, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0);
        if (wbuf == MAP_FAILED) {
                printf("No memory %s\n", strerror(errno));
                return 1;
        }
        memset(wbuf, 0xba, len);

        if (action == O_WRONLY || action == O_RDWR) {
                if (lseek64(fd, seek, SEEK_SET) < 0) {
                        printf("lseek64 failed: %s\n", strerror(errno));
                        return 1;
                }

                rc = write(fd, wbuf, len);
                if (rc != len) {
                        printf("Write error %s (rc = %d, len = %ld)\n",
                               strerror(errno), rc, len);
                        return 1;
                }
        }

        if (action == O_RDONLY || action == O_RDWR) {
                char *rbuf;

                if (lseek64(fd, seek, SEEK_SET) < 0) {
                        printf("Cannot seek %s\n", strerror(errno));
                        return 1;
                }

                rbuf =mmap(0,len,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,0,0);
                if (rbuf == MAP_FAILED) {
                        printf("No memory %s\n", strerror(errno));
                        return 1;
                }

                rc = read(fd, rbuf, len);
                if (rc != len) {
                        printf("Read error: %s (rc = %d)\n",strerror(errno),rc);
                        return 1;
                }

                if (memcmp(wbuf, rbuf, len)) {
                        printf("Data mismatch\n");
                        return 1;
                }
        }

        printf("PASS\n");
        return 0;
#else /* !O_DIRECT */
#warning O_DIRECT not defined, directio test will fail
        printf("O_DIRECT not defined\n");
        return 1;
#endif /* !O_DIRECT */
}
