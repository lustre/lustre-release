/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Each loop does 3 things:
 *   - rank 0 truncates to 0
 *   - all ranks agree on a random chunk size
 *   - all ranks race to write their pattern to their chunk of the file
 *   - rank 0 makes sure that the resulting file size is ranks * chunk size
 *   - rank 0 makes sure that everyone's patterns went to the right place
 *
 * compile: mpicc -g -Wall -o write_disjoint write_disjoint.c
 * run:     mpirun -np N -machlist <hostlist file> write_disjoint
 *  or:     pdsh -w <N hosts> write_disjoint 
 *  or:     prun -n N [-N M] write_disjoint
 */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include "mpi.h"


#define FILENAME "/mnt/lustre/write_disjoint"
#define CHUNK_MAX_SIZE 123456

int rprintf(int rank, int loop, const char *fmt, ...)
{
        va_list       ap;
 
        printf("rank %d, loop %d: ", rank, loop);
 
        va_start(ap, fmt);
 
        vprintf(fmt, ap);
 
        MPI_Finalize();
        exit(1);
}

int main (int argc, char *argv[]) {
         int i, n, fd, chunk_size, file_size;
         int rank, noProcessors, done;
         off_t offset;
         char **chunk_buf;
         char *read_buf;
         struct stat stat_buf;
         ssize_t ret;

         MPI_Init(&argc, &argv);
         MPI_Comm_size(MPI_COMM_WORLD, &noProcessors);
         MPI_Comm_rank(MPI_COMM_WORLD, &rank);
                         
         chunk_buf = malloc(noProcessors * sizeof(chunk_buf[0]));
         for (i=0; i < noProcessors; i++) {
                chunk_buf[i] = malloc(CHUNK_MAX_SIZE);
                memset(chunk_buf[i], 'A'+ i, CHUNK_MAX_SIZE);
         }
         read_buf = malloc(noProcessors * CHUNK_MAX_SIZE);
         
         if (rank == 0) {
                fd = open(FILENAME, O_WRONLY|O_CREAT|O_TRUNC, 0666);
                if (fd < 0) 
                        rprintf(rank, -1, "open() returned %s\n", 
                                strerror(errno));
         }
         MPI_Barrier(MPI_COMM_WORLD);

         fd = open(FILENAME, O_RDWR);
         if (fd < 0)
                 rprintf(rank, -1, "open() returned %s\n", strerror(errno));
         
         for (n=0; n < 1000 ; n++) {
                 /* reset the environment */
                 if (rank == 0) {
                         ret = truncate(FILENAME, 0);
                         if (ret != 0)
                                 rprintf(rank, n, "truncate() returned %s\n", 
                                         strerror(errno) );
                 }
                 chunk_size = rand() % CHUNK_MAX_SIZE;

                 if (n % 1000 == 0 && rank == 0)
                         printf("loop %d: chunk_size %d\n", n, chunk_size);

                 MPI_Barrier(MPI_COMM_WORLD);
                 
                 /* Do the race */
                 offset = rank * chunk_size;
                 lseek(fd, offset, SEEK_SET);

                 done = 0;
                 do {
                        ret = write(fd, chunk_buf[rank]+done, chunk_size-done);
                        if (ret < 0) 
                                 rprintf(rank, n, "write() returned %s\n", 
                                         strerror(errno));
                        done += ret;
                 } while (done != chunk_size);

                 MPI_Barrier(MPI_COMM_WORLD);

                 /* Check the result */
                 if (rank == 0) {
                         lseek(fd, 0, SEEK_SET);
                         
                         /* quick check */
                         stat(FILENAME, &stat_buf);
                         file_size = stat_buf.st_size;
                         if (file_size != chunk_size * noProcessors)
                                  rprintf(rank, n, "invalid file size %d"
                                          " instead of %d\n", file_size, 
                                          chunk_size * noProcessors);

                        done = 0;
                        do {
                                ret = read(fd, read_buf + done, 
                                           (chunk_size * noProcessors) - done);
                                if (ret < 0) 
                                        rprintf(rank, n, "read returned %s\n",
                                                strerror(errno));

                                done += ret;
                        } while (done != chunk_size * noProcessors);

                        for (i = 0; i < noProcessors; i++) {
                                char command[4096]; 
                                int j;
                                if (!memcmp(read_buf + (i * chunk_size), 
                                           chunk_buf[i], chunk_size))
                                        continue;

                                printf("rank %d, loop %d: chunk %d corrupted "
                                       "with chunk_size %d\n", rank, n, i, 
                                       chunk_size);
                                printf("(ranks: page boundry, chunk boundry, "
                                       "page boundry)\n");
                                for (j = 1 ; j < noProcessors; j++) {
                                        int b = j * chunk_size;
                                        printf("\t%c -> %c: %d %d %d\n", 
                                               'A' + j - 1, 'A' + j, 
                                               b & ~(4096-1), b, 
                                               (b + 4096) & ~(4096-1));
                                }

                                sprintf(command, "od -Ad -a %s", FILENAME);
                                system(command);
                                MPI_Finalize();
                                exit(1);
                        }
                }
        }

        printf("Finished after %d loops\n", n);
        MPI_Finalize();
        return 0;
}
