/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light user test program
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/queue.h>

#include <sysio.h>
#include <mount.h>

#include <mpi.h>

/******************************************************************************/
/*
 * MPI_CHECK will display a custom error message as well as an error string
 * from the MPI_STATUS and then exit the program
 */

#define MPI_CHECK(MPI_STATUS, MSG) do {                                  \
    char resultString[MPI_MAX_ERROR_STRING];                             \
    int resultLength;                                                    \
                                                                         \
    if (MPI_STATUS != MPI_SUCCESS) {                                     \
        fprintf(stdout, "** error **\n");                                \
        fprintf(stdout, "ERROR in %s (line %d): %s.\n",                  \
                __FILE__, __LINE__, MSG);                                \
        MPI_Error_string(MPI_STATUS, resultString, &resultLength);       \
        fprintf(stdout, "MPI %s\n", resultString);                       \
        fprintf(stdout, "** exiting **\n");                              \
        MPI_Abort(MPI_COMM_WORLD, 1);                                    \
    }                                                                    \
} while(0)

int		numTasks     = 0,	/* MPI variables */
		rank         = 0,
		tasksPerNode = 0;	/* tasks per node */




static char *test_file_name = "/mnt/lustre/test_lock_cancel";

extern int portal_debug;
extern int portal_subsystem_debug;
extern void __liblustre_setup_(void);
extern void __liblustre_cleanup_(void);

int main(int argc, char *argv[])
{
	int fd;
        long time1, time2;

        __liblustre_setup_();

	MPI_CHECK(MPI_Init(&argc, &argv), "MPI_Init()");
	MPI_CHECK(MPI_Comm_size(MPI_COMM_WORLD, &numTasks), "MPI_Comm_size");
	MPI_CHECK(MPI_Comm_rank(MPI_COMM_WORLD, &rank), "MPI_Comm_rank");

        if (numTasks < 2) {
                printf("this demo can't run on single node!\n");
                goto cleanup;
        }

#if 1
	portal_debug = 0;
	portal_subsystem_debug = 0;
#endif

        if (rank == 0) {
                unlink(test_file_name);
        }

        MPI_Barrier(MPI_COMM_WORLD);
        if (rank == 1) {
                printf("Node 1: creating file %s ...\n", test_file_name);
                fflush(stdout);
                fd = open(test_file_name, O_CREAT|O_RDWR, 0755);
                if (fd < 0) {
                        printf("Node %d: creat file err: %d", rank, fd);
                        fflush(stdout);
                        goto cleanup;
                }
                printf("Node %d: done create file\n", rank);
                fflush(stdout);
        } else {
                printf("Node %d: waiting node 1 create file\n", rank);
                fflush(stdout);
        }

        MPI_Barrier(MPI_COMM_WORLD);
        
        if (rank == 1) {
                printf("Node 1: file has been created, abort excution here!!!!!!!\n");
                fflush(stdout);
                exit(0);
        }
        
        sleep(1);
        printf("Node %d: synced with Node 1. sleep 5 seconds...\n", rank);
        fflush(stdout);
        sleep(5);
        printf("Node %d: wakeup from sleep. perform open()...\n", rank);
        fflush(stdout);

        time1 = time(NULL);
        fd = open(test_file_name, O_RDWR);
        if (fd < 0) {
                printf("Node %d: error open existed file: %d\n", rank, fd);
                fflush(stdout);
                goto cleanup;
        }
        time2 = time(NULL);
        printf("Node %d: successfully opened file, cost %ld seconds.\n",
                rank, time2 - time1);
        fflush(stdout);
        close(fd);

cleanup:
        __liblustre_cleanup_();
        printf("Node %d: end sucessfully.\n", rank);
	return 0;
}
