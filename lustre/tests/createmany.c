#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char ** argv)
{
        int i, rc = 0, do_open;
        char filename[4096];
        long int start, last, end, count;

        if (argc != 4) {
                printf("Usage %s <-o|-m> filenamebase <count|-time>\n",
                       argv[0]);
                return 1;
        }

        if (strcmp(argv[1], "-o") == 0) {
                do_open = 1;
        } else if (strcmp(argv[1], "-m") == 0) {
                do_open = 0;
        } else {
                printf("Usage %s {-o|-m} filenamebase <count|-time>\n",
                       argv[0]);
                return 1;
        }

        if (strlen(argv[2]) > 4080) {
                printf("name too long\n");
                return 1;
        }

        start = last = time(0);

        end = strtol(argv[3], NULL, 0);

        if (end > 0) {
                count = end;
                end = -1UL >> 1;
        } else {
                end = start - end;
                count = -1UL >> 1;
        }

        for (i = 0; i < count && time(0) < end; i++) {
                sprintf(filename, "%s%d", argv[2], i);
                if (do_open) {
                        int fd = open(filename, O_CREAT|O_RDWR, 0644);
                        if (fd < 0) {
                                printf("open(%s) error: %s\n", filename,
                                       strerror(errno));
                                rc = errno;
                                break;
                        }
                        close(fd);
                } else {
                        rc = mknod(filename, S_IFREG| 0444, 0);
                        if (rc) {
                                printf("mknod(%s) error: %s\n",
                                       filename, strerror(errno));
                                rc = errno;
                                break;
                        }
                }
                if ((i % 10000) == 0) {
                        printf(" - created %d (time %ld ; total %ld ; last %ld)\n",
                               i, time(0), time(0) - start, time(0) - last);
                        last = time(0);
                }
        }
        printf("total: %d creates in %ld seconds: %f creates/second\n", i,
               time(0) - start, ((float)i / (time(0) - start)));

        return rc;
}
