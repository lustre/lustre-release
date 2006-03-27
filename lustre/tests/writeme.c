#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void usage(char *prog)
{
        printf("usage: %s [-s] filename\n", prog);
}

int main(int argc, char **argv)
{
        int fd, rc;
	int do_sync = 0;
        int i = 0;
	int file_arg = 1;
        char buf[4096];

        memset(buf, 0, 4096);

        if (argc < 2 || argc > 3) {
		usage(argv[0]);
                exit(1);
        }

        if (strcmp(argv[1], "-s") == 0) {
                do_sync = 1;
		file_arg++;
        }

        fd = open(argv[file_arg], O_RDWR | O_CREAT, 0600);
        if (fd == -1) {
                printf("Error opening %s\n", argv[1]);
                exit(1);
        }

        while (1) {
                sprintf(buf, "write %d\n", i);
                rc = write(fd, buf, sizeof(buf));
		if (do_sync)
			sync();
                sleep(1);
        }
        return 0;
}
