#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "mpi.h"


#define FILENAME "/mnt/lustre/write_append_truncate"
//
// ext3 on one node is ok
//#define FILENAME "/mnt/local/blah"
//
// nfs over 2 nodes: fails
//#define FILENAME "/blah"

#define CHUNK_SIZE_MAX   12345
#define CHUNK_CHAR   'C'

#define APPEND_SIZE_MAX  54321
#define APPEND_CHAR  'A'

#define TRUNC_SIZE_MAX   (CHUNK_SIZE_MAX+APPEND_SIZE_MAX)
#define TRUNC_CHAR   '\0'

#define HOSTNAME_SIZE 50

int main( int argc,char *argv[] ) {
	 int n, failure, fd, file_size;
	 int rank, ret;
	 int chunk_size, append_size, trunc_offset;
	 char append_buf[APPEND_SIZE_MAX];
	 char chunk_buf[CHUNK_SIZE_MAX];
	 char read_buf[TRUNC_SIZE_MAX+APPEND_SIZE_MAX];
	 char trunc_buf[TRUNC_SIZE_MAX];
	 struct stat stat_buf;
	 int done;
	 int error=0;
	 char hostname[HOSTNAME_SIZE];
	 
	 memset(append_buf, APPEND_CHAR, APPEND_SIZE_MAX);
	 memset(chunk_buf, CHUNK_CHAR, CHUNK_SIZE_MAX);
	 memset(trunc_buf, TRUNC_CHAR, TRUNC_SIZE_MAX);
	 

	 MPI_Init(&argc,&argv);
	 MPI_Comm_rank(MPI_COMM_WORLD, &rank);

	 gethostname(hostname, HOSTNAME_SIZE);

	 if(rank == 0) {
	 	 fd = open( FILENAME, O_WRONLY|O_CREAT, 0666);
		 if(fd==0) 
			 printf("open returned %s\n", strerror(errno) );
		 close(fd);
	 }
	 MPI_Barrier(MPI_COMM_WORLD);

	 fd = open( FILENAME, O_RDWR | O_APPEND);
	 if( fd==0 )
		 printf("open returned %s\n", strerror(errno) );
	 
	 for(n=0; 106000*10 ; n++) {

		 /* reset the environment */
		 chunk_size = (rand()%(CHUNK_SIZE_MAX-1))+1;
		 append_size = (rand()%(APPEND_SIZE_MAX-1))+1;
		 trunc_offset = chunk_size + rand()%append_size;
		 if(rank == 0) {
			 ret = truncate( FILENAME, (off_t)0);
			 if( ret!=0 )
				 printf("truncate returned %s\n", strerror(errno) );
		

	 	 	 done = 0;
			 do {
				 ret = write(fd, chunk_buf+done, chunk_size-done);
				 if( ret<0 ) {
					 printf("write returned %s\n", strerror(errno) );
					 break;
				 }
			 	 done += ret;
			 } while( done != chunk_size );


			 //ret = write( fd, chunk_buf, chunk_size);
			 //if( ret!=chunk_size )
			//	 printf("write returned %s\n", strerror(errno) );
		 }

		 MPI_Barrier(MPI_COMM_WORLD);
		 
		 /* Do the race */
	 	 if( rank == n%2 ) {
			 //
	 	 	 done = 0;
			 do {
				 ret = write(fd, append_buf+done, append_size -done);
				 if( ret<0 ) {
					 printf("write returned %s\n", strerror(errno) );
					 break;
				 }
			 	 done += ret;
			 } while( done != append_size);
			 
			 //
		 	 //ret = write( fd, append_buf, append_size);
			 //if( ret!=append_size )
			//	 printf("write returned %s\n", strerror(errno) );
			 
		 } else if( rank == 1 - n%2 ) {

			 ret = truncate(FILENAME, (off_t)trunc_offset);
			 if( ret!=0 )
				 printf("truncate returned %s\n", strerror(errno) );
		 }
		 
		 MPI_Barrier(MPI_COMM_WORLD);

		 /* Check the result */
		 
		 if (rank == 0) {
			 lseek( fd, (off_t)0, SEEK_SET);
			 stat( FILENAME, &stat_buf);
			 file_size = stat_buf.st_size;
	 	 	 //
	 	 	 done = 0;
			 do {
				 ret = read(fd, read_buf+done, file_size-done);
				 if( ret<0 ) {
					 printf("read returned %s\n", strerror(errno) );
					 break;
				 }
			 	 done += ret;
			 } while( done != file_size);
			 //
			 //ret = read(fd, read_buf, file_size);
			 //if( ret!=file_size )
				 //printf("read returned %s\n", strerror(errno) );

			 if( memcmp( read_buf, chunk_buf, chunk_size ) ) {
				printf("Error(%d): chunk corrupted, chunk_size=%d\n", n, chunk_size);
				error=1;
			 }
			
			 failure = 0;
			
			 /* Check case 1: first append then truncate */
			 if( file_size == trunc_offset ) {
				failure = memcmp( read_buf+chunk_size, append_buf, trunc_offset-chunk_size);
				if( failure ) {
					printf("Error(%d): case 1 failed\n", n);
					error=1;
				}
			 } 
			 
			 /* Check case 2: first truncate then append */
			 else {
				failure = memcmp( read_buf+chunk_size, trunc_buf, trunc_offset-chunk_size);
				if( failure ) {
					printf("Error(%d): case 2 failed truncate\n", n);
					error=1;

				} 
				failure = memcmp( read_buf+trunc_offset, append_buf, append_size);
				if( failure ) {
					printf("Error(%d): case 2 failed append\n", n);
					error=1;
				}
			 }
		 }
		 MPI_Bcast(&error, 1, MPI_INT, 0, MPI_COMM_WORLD);
		 if (error==1) {
			 if (rank==0) {
				 system("od -A d -x " FILENAME);
		 	 }
			 printf("Debug(%d): Rank %d is on machine %s with pid %d\n", n, rank, hostname, (int)getpid() );
			 break;
		 }
		 
	 }
	 printf("Finished after %d loops\n", n);

	 MPI_Finalize();
	 return 0;
}
