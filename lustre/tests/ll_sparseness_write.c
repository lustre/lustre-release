/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#define BUFSIZE (1024*1024)   

/* Function: pwrite character '+' to <filename> at <offset> (man pwrite)
 * Return:   0 success
 *           1 failure */
int main(int argc, char**argv)
{
        int p_size;
        unsigned int offset;
        char *filename;
        int fd;
        char buf[] = "+++";
        char *end;

        if(argc != 3) {
                fprintf(stderr, "Usage: %s <filename> <offset>(KB)\n", argv[0]);
                exit(1);
        }

        filename = argv[1];
        offset = strtoul(argv[2], &end, 10);
        if (*end) {
                fprintf(stderr, "<offset> parameter should be integer\n");
                exit(1);
        }

        fd = open(filename, O_CREAT|O_RDWR, 0644);
        if (fd == -1) {
                fprintf(stderr, "Opening %s fails (%s)\n", 
                        filename, strerror(errno));
                return 1;
        }

        /* write the character '+' at offset */
        p_size = pwrite(fd, buf, 1, offset);
        if (p_size != 1) {
                fprintf(stderr, "pwrite %s fails (%s)\n", 
                        filename, strerror(errno));
                close(fd);
                return 1;
        }
                
        close(fd);
        return 0;
}
