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
#include <errno.h>
#include <unistd.h>
#include "mpi.h"


#define FILENAME "/mnt/lustre/write_disjoint"
#define CHUNK_MAX_SIZE 123456


int main( int argc,char *argv[] ) {
         int i, n, fd, chunk_size, file_size;
         int rank, noProcessors, ret, done;
         off_t offset;
         char **chunk_buf;
         char *read_buf;
         struct stat stat_buf;

         MPI_Init(&argc, &argv);
         MPI_Comm_size(MPI_COMM_WORLD, &noProcessors);
         MPI_Comm_rank(MPI_COMM_WORLD, &rank);
                         
         chunk_buf = (char**)malloc(noProcessors * sizeof(void*));
         for( i=0; i<noProcessors; i++) {
                  chunk_buf[i] = (char*)malloc(CHUNK_MAX_SIZE);
                 memset(chunk_buf[i], 'A'+ i, CHUNK_MAX_SIZE);
         }
         read_buf = (char*)malloc(noProcessors * CHUNK_MAX_SIZE);
         
         if(rank == 0) {
                  fd = open( FILENAME, O_WRONLY|O_CREAT|O_TRUNC, 0666);
                 if(fd==0) 
                         printf("open returned %s\n", strerror(errno) );
                 close(fd);
         }
         MPI_Barrier(MPI_COMM_WORLD);

         fd = open( FILENAME, O_RDWR);
         if( fd==0 )
                 printf("open returned %s\n", strerror(errno) );
         
         for(n=0; n<1000; n++) {
                 /* reset the environment */
                 if(rank == 0) {
                         ret = truncate( FILENAME, (off_t)0);
                         if( ret!=0 )
                                 printf("truncate returned %s\n", strerror(errno) );
                 }
                 chunk_size = rand() % CHUNK_MAX_SIZE;

                 MPI_Barrier(MPI_COMM_WORLD);
                 
                 /* Do the race */
                 offset = rank * chunk_size;
                 lseek(fd, offset, SEEK_SET);

                 done = 0;
                 do {
                          ret = write(fd, chunk_buf[rank]+done, chunk_size-done);
                         if( ret<0 ) {
                                 printf("write returned %s\n", strerror(errno) );
                                 break;
                         }
                         done += ret;
                 } while( done != chunk_size );

                 MPI_Barrier(MPI_COMM_WORLD);

                 /* Check the result */
                 if (rank == 0) {
                         lseek( fd, (off_t)0, SEEK_SET);
                         
                         /* quick check */
                         stat( FILENAME, &stat_buf);
                         file_size = stat_buf.st_size;
                         if(file_size != chunk_size*noProcessors) {
                                  printf("Error(%d): invalid file size %d insteed of %d\n", n, file_size, chunk_size*noProcessors);
                                 continue;
                         }

                         done = 0;
                         do {
                                 ret = read(fd, read_buf+done, chunk_size*noProcessors-done);
                                 if( ret<0 ) {
                                          printf("read returned %s\n", strerror(errno) );
                                          break;
                                 }
                                 done += ret;
                         } while( done!=chunk_size*noProcessors );
                           for(i=0; i<noProcessors; i++) {
                                 if( memcmp( read_buf+i*chunk_size, chunk_buf[i], chunk_size ) ) {
                                        printf("Error(%d): chunk %d corrupted\n", n, i);
                                 }
                         }
                 }
         }
         printf("Finished after %d loops\n", n);

         MPI_Finalize();
         return 0;
}
