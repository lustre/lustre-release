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

int write_buffer(char *fname, char *buffer, int len)
{
        int fd, rc;

        fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd == -1) {
                printf("Cannot open %s:  %s\n", fname, strerror(errno));
                exit(1);
        }
        rc = write(fd, buffer, len);
        if (rc != len) {
                printf("write: %d\n", rc);
                exit(1);
        }
        close(fd);
        return 0;
}

void verify(char *buffer, char *compare, int length)
{
        int i;
        for (i = 0; i < length; i++) {
                if (buffer[i] != compare[i]) {
                        fprintf(stderr, "garbage read (i=%d): expected %c, found %c\n",
                               i, compare[i], buffer[i]);
                        write_buffer("/tmp/dio1", buffer, length);
                        write_buffer("/tmp/dio2", compare, length);
                        exit(1);
                }
        }
}


int main(int argc, char **argv)
{
        int fd;
        char *rbuf, *wbuf;
        int blocks, seek_blocks;
        long len;
        off64_t seek;
        struct stat64 st;
        int rc;

        if (argc < 4 || argc > 5) {
                printf("Usage: %s file seek nr_blocks [blocksize]\n", argv[0]);
                return 1;
        }

        seek_blocks = strtoul(argv[2], 0, 0);
        blocks = strtoul(argv[3], 0, 0);

        fd = open(argv[1], O_LARGEFILE | O_DIRECT | O_RDWR | O_CREAT, 0644);
        if (fd == -1) {
                printf("Cannot open %s:  %s\n", argv[1], strerror(errno));
                return 1;
        }

        if (argc == 5)
                st.st_blksize = strtoul(argv[4], 0, 0);
        else if (fstat64(fd, &st) < 0) {
                printf("Cannot stat %s:  %s\n", argv[1], strerror(errno));
                return 1;
        }

        fprintf(stderr, "directio on %s for %dx%lu bytes \n", argv[1], blocks,
                st.st_blksize);

        seek = (off64_t)seek_blocks * (off64_t)st.st_blksize;
#if 0
        if (lseek64(fd, seek, SEEK_SET) < 0) {
                printf("lseek64 failed: %s\n", strerror(errno));
                return 1;
        }
#endif
        len = blocks * st.st_blksize;
        wbuf = mmap(0, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0);
        if (wbuf == MAP_FAILED) {
                printf("No memory %s\n", strerror(errno));
                return 1;
        }

        rbuf = mmap(0, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0);
        if (rbuf == MAP_FAILED) {
                printf("No memory %s\n", strerror(errno));
                return 1;
        }

        memset(wbuf, 0xba, len);
        rc = write(fd, wbuf, len);
        if (rc != len) {
                printf("Write error %s (rc = %d)\n", strerror(errno), rc);
                return 1;
        }

        if (lseek64(fd, seek, SEEK_SET) < 0) {
                printf("Cannot seek %s\n", strerror(errno));
                return 1;
        }

        rc = read(fd, rbuf, len);
        if (rc != len) {
                printf("Read error: %s (rc = %d)\n", strerror(errno), rc);
                return 1;
        }

        verify(rbuf, wbuf, len);
        if (memcmp(wbuf, rbuf, len)) {
                printf("Data mismatch on line %d\n", __LINE__);
                return 1;
        }

        /* try 512-byte buffers, and make sure that the other parts of the
         * page aren't modified. */
        if (st.st_blksize < 4096) {
                printf("512-byte block size tests skipped (because blocksize "
                       "passed is < 4k)\n");
                printf("PASS\n");
                return 0;
        }



        /* write test */
        if (lseek64(fd, 512, SEEK_SET) < 0) {
                printf("Cannot seek %s\n", strerror(errno));
                return 1;
        }

        memset(wbuf, 0x44, len);
        memset(wbuf + 2048, 0x69, 512);
        rc = write(fd, wbuf + 2048, 512);
        if (rc != 512) {
                printf("Write error %s (rc = %d)\n", strerror(errno), rc);
                return 1;
        }

        memset(rbuf, 0x44, len);
        memset(rbuf + 2048, 0x69, 512);
        if (memcmp(wbuf, rbuf, len)) {
                printf("Data mismatch on line %d\n", __LINE__);
                return 1;
        }

        /* read test */
        if (lseek64(fd, 512, SEEK_SET) < 0) {
                printf("Cannot seek %s\n", strerror(errno));
                return 1;
        }
        memset(rbuf, 0xba, len);
        rc = read(fd, rbuf + 1024, 512);
        if (rc != 512) {
                printf("Read error: %s (rc = %d)\n", strerror(errno), rc);
                return 1;
        }

        memset(wbuf, 0xba, len);
        memset(wbuf + 1024, 0x69, 512);

        verify(rbuf, wbuf, len);
#if 0
        if (memcmp(wbuf, rbuf, len)) {
                printf("Data mismatch on line %d\n", __LINE__);
                return 1;
        }
#endif

        /* read back the whole block, to see that it's untouched. */
        if (lseek64(fd, seek, SEEK_SET) < 0) {
                printf("Cannot seek %s\n", strerror(errno));
                return 1;
        }

        memset(rbuf, 0x1, len);
        rc = read(fd, rbuf, len);
        if (rc != len) {
                printf("Read error: %s (rc = %d)\n", strerror(errno), rc);
                return 1;
        }

        memset(wbuf, 0xba, len);
        memset(wbuf + 512, 0x69, 512);
        if (memcmp(wbuf, rbuf, len)) {
                printf("Data mismatch on line %d\n", __LINE__);
                return 1;
        }

        printf("PASS\n");
        return 0;
}
