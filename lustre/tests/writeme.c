#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
        int fd, rc;
        int i = 0;
        char buf[4096];

        memset(buf, 0, 4096);

        if (argc != 2) {
                printf("Usage: %s <filename>\n", argv[0]);
                exit(1);
        }

        fd = open(argv[1], O_RDWR | O_CREAT, 0600);
        if (fd == -1) {
                printf("Error opening %s\n", argv[1]);
                exit(1);
        }

        while (1) {
                sprintf(buf, "write %d\n", i);
                rc = write(fd, buf, sizeof(buf));
                sleep(1);
        }
        return 0;
}
