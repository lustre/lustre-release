#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

int main(int argc, char ** argv)
{
        int i, count, iter;
        long int start, last, rc = 0;

        if (argc != 4) {
                printf("Usage %s filenamebase file_count iterations\n",
                       argv[0]);
                exit(1);
        }

        if (strlen(argv[1]) > 4080) {
                printf("name too long\n");
                exit(1);
        }

        count = strtoul(argv[2], NULL, 0);
        iter = strtoul(argv[3], NULL, 0);

        start = last = time(0);

        for (i = 0; i < iter; i++) {
                struct stat buf;
                char filename[4096];
                int tmp;

                tmp = random() % count;
                sprintf(filename, "%s-%d", argv[1], tmp);

                rc = stat(filename, &buf);
                if (rc) {
                        printf("stat(%s) error: %s\n", filename,
                               strerror(errno));
                        break;
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
