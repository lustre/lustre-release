/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

/* for O_DIRECT */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include<stdio.h>
#include<errno.h>
#include<fcntl.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<unistd.h>
#include<signal.h>
#include<stdlib.h>
#include<string.h>

#define BUFFERSIZE 4096

/* This flag controls termination of the main loop. */
volatile sig_atomic_t keep_going = 1;

/* The signal handler just clears the flag and re-enables itself. */
void catch_alarm(int sig)
{
	keep_going = 0;
	signal(sig, catch_alarm);
}

int main(int argc, char **argv)
{
        char *file;
        unsigned char buf[BUFFERSIZE];
        int fd, i, rc;
	unsigned int test_time;
        mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;

        if (argc != 3) {
                printf("Invalid number of arguments.\n");
                printf("Usage %s <file> <test_time_in_seconds>\n", argv[0]);
                return -1;
        }

        file = argv[1];
        test_time = atoi(argv[2]);

	/* Establish a handler for SIGALRM signals. */
	signal(SIGALRM, catch_alarm);

       	/* Set an alarm to go off in a little while. */
       	alarm(test_time);

        fd = open(file, O_RDWR|O_TRUNC|O_CREAT|O_SYNC|O_LARGEFILE, mode);
        if (fd < 0) {
                fprintf(stderr, "Error: Cannot open file named ");
                perror(file);
                return -1;
        }

        memset(buf, 1, BUFFERSIZE);
	while (keep_going) {
                for (i = 0; i < 1024; i++) {
		        rc = write(fd, buf, BUFFERSIZE);
			if (rc < 0) {
                                fprintf(stderr, "Error: Write error ");
                                perror(file);
				exit(-1);
                        } else if (rc != BUFFERSIZE) {
                                fprintf(stderr, "Error: Ddidn't write all data \n");
			}
                }

                if (ftruncate(fd, 0) < 0) {
                        fprintf(stderr, "Error: Truncate error ");
                        perror(file);
			exit(-1);
                }
        }

        if (close(fd) < 0) {
                fprintf(stderr, "Error: Cannot close ");
                perror(file);
                return -1;
        }

        return 0;
}
