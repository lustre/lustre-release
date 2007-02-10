/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/file.h>

void usage(void)
{
        fprintf(stderr, "usage: ./flocks_test on|off -c|-f|-l /path/to/file\n");
        exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
        int fd;
        int mount_with_flock = 0;
        int error = 0;

        if (argc != 4)
                usage();
        
        if (!strncmp(argv[1], "on", 3)) {
                mount_with_flock = 1;
        } else if (!strncmp(argv[1], "off", 4)) {
                mount_with_flock = 0;
        } else {
                usage();
        }

        if ((fd = open(argv[3], O_RDWR)) < 0) {
                fprintf(stderr, "Couldn't open file: %s\n", argv[2]);
                exit(EXIT_FAILURE);
        }

        if (!strncmp(argv[2], "-c", 3)) {
                struct flock fl;

                fl.l_type = F_RDLCK;
                fl.l_whence = SEEK_SET;
                fl.l_start = 0;
                fl.l_len = 1;

                error = fcntl(fd, F_SETLK, &fl);
        } else if (!strncmp(argv[2], "-l", 3)) {
                error = lockf(fd, F_LOCK, 1);
        } else if (!strncmp(argv[2], "-f", 3)) {
                error = flock(fd, LOCK_EX);
        } else {
                usage();
        }

        if (mount_with_flock)
                return((error == 0) ? EXIT_SUCCESS : EXIT_FAILURE);
        else
                return((error == 0) ? EXIT_FAILURE : EXIT_SUCCESS);
}
