/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
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
int compfunc(const void *x, const void *y)
{
        if (*(unsigned int *)x < *(unsigned int *)y) {
                return -1;
        } else if (*(unsigned int *)x == *(unsigned int *)y) {
                return 0;
        } else {
                return 1;
        }
}

/* sort offsets and delete redundant data in offsets 
 * no return 
 */
void collapse_redundant(unsigned *offsets, int offsetcount)
{
        int i, j;

        qsort(offsets, offsetcount, sizeof(unsigned int), compfunc);

        /* collapse the redundant offsets */
        for (i = 0; i < offsetcount - 1; i++) {
                if (offsets[i] == offsets[i + 1]) {
                        for (j = i; j < offsetcount; j++) {
                                offsets[j] = offsets[j + 1];
                        }
                        offsetcount--;
                }
        }
}

/* verify the sparse pwrite from page(0) to page(filesize / BUFSIZE)
 * if sucess return last verified page number else return (-1)
 */
int verify_content(int fd, int filesize, unsigned int *offsets, 
                   int O_number)
{
        int i , j;
        char *filebuf;
        int focus = 0;
        int p_number;

        filebuf = (char*) malloc(BUFSIZE);

        p_number = filesize / BUFSIZE;
        for (j = 0; j < p_number ; j++) {

                i = read(fd, filebuf, BUFSIZE);

                if (i != BUFSIZE) {
                        fprintf(stderr, 
                                "Reading file fails (%s), returning (%d)\n",
                                strerror(errno), i);
                        free(filebuf);
                        return -1;
                }

                /* check the position that should hold '+'
                 * If correct, change it to 0 in the buffer */
                for (; focus < O_number; focus++) {
                        if (offsets[focus] < (j + 1) * BUFSIZE - 1) {
                                if (filebuf[offsets[focus] % BUFSIZE] != '+') {
                                        fprintf(stderr, 
                                                "Bad content, should         \
                                                be '+' at %d.\n",
                                                offsets[focus]);
                                        free(filebuf);
                                        return -1;
                                } else {
                                        /* '+', change it to 0 for comparison */
                                        filebuf[offsets[focus] % BUFSIZE] = 0;
                                }
                        }
                }
                
                /* Hopefully '+' should have been changed to 0
                 * Thus, we should not encounter any strange character */
                for (i = 0; i < BUFSIZE; i++) {
                        if (filebuf[i] != 0) {
                                fprintf(stderr,
                                        "Bad content, should be 0 at %d.\n",
                                        i + j * BUFSIZE);
                                free(filebuf);
                                return -1;
                        }
                }
        }
       
        free(filebuf); 
        return focus;
}

/* verify the sparse pwrite with last page 
 * if sucess return 0 else return 1 
 */
int verify_tail(int fd, int filesize, unsigned int *offsets, 
                int O_number, int focus)
{
        int i;
        char *filebuf;
        int p_number;

        filebuf = (char*) malloc(BUFSIZE);

        /* The last page */
        p_number = filesize % BUFSIZE;
        i = read(fd, filebuf, p_number);
        if (i != p_number) {
                fprintf(stderr, "Reading file fails (%s), returning (%d)\n",
                        strerror(errno), i);
                free(filebuf);
                return 1;
        }
        for (; focus < O_number; focus++) {
                if (offsets[focus] < filesize) {
                        if (filebuf[offsets[focus] % BUFSIZE] != '+') {
                                fprintf(stderr, 
                                        "Bad content, should be '+' at %d.\n",
                                        offsets[focus]);
                                free(filebuf);
                                return 1;
                        } else {
                                /* '+', change it to 0 for later comparison */
                                filebuf[offsets[focus]%BUFSIZE] = 0;
                        }
                } else {
                        fprintf(stderr,
                                "Error: File size <= offset %d\n",
                                offsets[focus]);
                        free(filebuf);
                        return 1;
                }
        }

        for (i = 0; i < p_number; i++) {
                if (filebuf[i] != 0) {
                        fprintf(stderr, "Bad content, should be 0 at %d.\n",
                                filesize - (p_number - i) - 1);
                        free(filebuf);
                        return 1;
                }
        }
        
        free(filebuf);
        return 0;
}

/* Function: verify the sparse pwrite (bug 1222): the charaters at
 *          <offset> should be '+', and all other characters should be 0
 * Return: 0 success
 *         1 failure*/
int verify(char *filename, unsigned int *offsets, int O_number)
{
        int status; 
        unsigned int size;
        int fd;
        struct stat Fstat;
        int focus = 0;

        status = stat(filename, &Fstat);
        if (status == -1) {
                fprintf(stderr, "No such file named as %s.\n", filename);
                return 1;
        }
        size = Fstat.st_size;

        /* Because we always have '+' just before EOF,
         * qsorted offsets[] should have the (filesize-1) at the end */
        if (size != offsets[O_number - 1] + 1) {
                fprintf(stderr,
                        "Error: the final character not in the offset?\n");
                return 1;
        }

        /* now we check the integrity of the file */
        fd = open(filename, O_RDONLY);
        if (fd == -1) {
                fprintf(stderr, "Openning %s fails (%s)\n",
                        filename, strerror(errno));
                return 1;
        }

        if((status = verify_content(fd, size, offsets, O_number)) < 0) {
                close(fd);
                return status ;
        }

        return  verify_tail(fd, size, offsets, O_number, status);
}

/* verify the sparse pwrite file with the charaters at <offset> 
 * should be '+', and all other characters should be 0
 */
int main(int argc, char**argv)
{
        int i;
        char *filename;
        char *end;
        int O_number;
        unsigned int *offsets;

        if (argc < 3) {
                fprintf(stderr, 
                        "Usage: %s <filename> <offset> [ offset ... ]\n", 
                        argv[0]);
                exit(1);
        }

        filename = argv[1];
        O_number = argc - 2;
        offsets = (unsigned int *) malloc(sizeof(unsigned int) * O_number);
        for (i = 0; i < O_number; i++) {
                offsets[i] = strtoul(argv[i + 2], &end, 10);
                if (*end) {
                        fprintf(stderr, 
                                "<offset> parameter should be integer\n");
                        exit(1);
                }
        }

        collapse_redundant(offsets, O_number);

        return verify(filename,offsets,O_number);
}

