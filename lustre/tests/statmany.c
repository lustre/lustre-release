#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>

#if 0
#include <linux/extN_fs.h>
#endif
#include <linux/lustre_lib.h>
#include <linux/obd.h>

static int usage(char *name)
{
        printf("Usage: %s <-s|-e|-l> filenamebase file_count iterations\n"
               "-s : regular stat() calls\n"
               "-e : open then GET_EA ioctl\n"
               "-l : lookup ioctl only\n", name);
        exit(1);
}

int main(int argc, char ** argv)
{
        int i, count, iter, mode, offset;
        long int start, end, last, rc = 0;
        char parent[4096], *t;

        if (argc != 5)
                usage(argv[0]);

        if (strcmp(argv[1], "-s") == 0)
                mode = 's';
        else if (strcmp(argv[1], "-e") == 0)
                mode = 'e';
        else if (strcmp(argv[1], "-l") == 0)
                mode = 'l';
        else
                usage(argv[0]);

        if (strlen(argv[2]) > 4080) {
                printf("name too long\n");
                exit(1);
        }

        srand(time(0));

        count = strtoul(argv[3], NULL, 0);
        iter = strtoul(argv[4], NULL, 0);

        start = last = time(0);

        if (iter < 0) {
                end = start - iter;
                iter = -1UL >> 1;
        } else {
                end = -1UL >> 1;
        }

        t = strrchr(argv[2], '/');
        if (t == NULL) {
                strcpy(parent, ".");
                offset = -1;
        } else {
                strncpy(parent, argv[2], t - argv[2]);
                offset = t - argv[2] + 1;
        }

        for (i = 0; i < iter && last < end; i++) {
                char filename[4096];
                int tmp, fd;

                tmp = random() % count;
                sprintf(filename, "%s-%d", argv[2], tmp);

                switch(mode) {
                case 'e':
#if 0
                        fd = open(filename, O_RDWR|O_LARGEFILE);
                        if (fd < 0) {
                                printf("open(%s) error: %s\n", filename,
                                       strerror(errno));
                                break;
                        }
                        rc = ioctl(fd, EXTN_IOC_GETEA, NULL);
                        if (rc < 0) {
                                printf("ioctl(%s) error: %s\n", filename,
                                       strerror(errno));
                                break;
                        }
                        close(fd);
                        break;
#endif
                case 's': {
                        struct stat buf;

                        rc = stat(filename, &buf);
                        if (rc < 0) {
                                printf("stat(%s) error: %s\n", filename,
                                       strerror(errno));
                                break;
                        }
                        break;
                }
                case 'l': {
                        struct obd_ioctl_data data;
                        char rawbuf[8192];
                        char *buf = rawbuf;
                        int max = sizeof(rawbuf);

                        fd = open(parent, O_RDONLY);
                        if (fd < 0) {
                                printf("open(%s) error: %s\n", filename,
                                       strerror(errno));
                                break;
                        }

                        memset(&data, 0, sizeof(data));
                        data.ioc_version = OBD_IOCTL_VERSION;
                        data.ioc_len = sizeof(data);
                        if (offset >= 0)
                                data.ioc_inlbuf1 = filename + offset;
                        else
                                data.ioc_inlbuf1 = filename;
                        data.ioc_inllen1 = strlen(data.ioc_inlbuf1) + 1;

                        if (obd_ioctl_pack(&data, &buf, max)) {
                                printf("ioctl_pack failed.\n");
                                break;
                        }

                        rc = ioctl(fd, IOC_MDC_LOOKUP, buf);
                        if (rc < 0) {
                                printf("ioctl(%s) error: %s\n", filename,
                                       strerror(errno));
                                break;
                        }
                        close(fd);
                        break;
                }
                }
                if ((i % 10000) == 0) {
                        printf(" - stat %d (time %ld ; total %ld ; last %ld)\n",
                               i, time(0), time(0) - start, time(0) - last);
                        last = time(0);
                }
        }

        printf("total: %d stats in %ld seconds: %f stats/second\n", i,
               time(0) - start, ((float)i / (time(0) - start)));

        exit(rc);
}
