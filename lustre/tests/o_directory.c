/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

/* for O_DIRECTORY */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
        int fd, rc;

        if (argc != 2) {
                printf("Usage: %s <filename>\n", argv[0]);
                exit(1);
        }

        fd = open(argv[1], O_RDONLY | O_CREAT, 0600);
        if (fd == -1) {
                printf("Error opening %s for create: %s\n", argv[1],
                       strerror(errno));
                exit(1);
        }
        rc = close(fd);
        if (rc < 0) {
                printf("Error closing %s: %s\n", argv[1], strerror(errno));
                exit(1);
        }

        fd = open(argv[1], O_DIRECTORY);
        if (fd >= 0) {
                printf("opening %s as directory should have returned an "
                       "error!\n", argv[1]);
                exit(1);
        }
        if (errno != ENOTDIR) {
                printf("opening %s as directory, expected -ENOTDIR and got "
                       "%s\n", argv[1], strerror(errno));
                exit(1);
        }

        return 0;
}
