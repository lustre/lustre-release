#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#ifndef O_DIRECT
#define O_DIRECT         040000 /* direct disk access hint */
#endif

int main(int argc, char *argv[])
{
        char *filename;
        unsigned long count, i;
        int fd;

        if (argc != 3) {
                fprintf(stderr, "usage: %s <filename> <iterations>\n", argv[0]);
                exit(1);
        }

        filename = argv[1];
        count = strtoul(argv[2], NULL, 0);

        fd = open(filename, O_RDWR|O_CREAT, 0644);
        if (fd < 0) {
                fprintf(stderr, "open(%s, O_CREAT): %s\n", filename,
                        strerror(errno));
                exit(1);
        }
        if (close(fd) < 0) {
                fprintf(stderr, "close(): %s\n", strerror(errno));
                exit(1);
        }

        for (i = 0; i < count; i++) {
                fd = open(filename, O_RDONLY|O_LARGEFILE|O_DIRECT);
                if (fd < 0) {
                        fprintf(stderr, "open(%s, O_RDONLY): %s\n", filename,
                                strerror(errno));
                        exit(1);
                }
                if (close(fd) < 0) {
                        fprintf(stderr, "close(): %s\n", strerror(errno));
                        exit(1);
                }
        }
        if (unlink(filename) < 0) {
                fprintf(stderr, "unlink(%s): %s\n", filename, strerror(errno));
                exit(1);
        }
        printf("Done.\n");
        return 0;
}
