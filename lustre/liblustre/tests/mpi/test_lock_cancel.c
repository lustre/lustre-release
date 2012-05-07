/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/liblustre/tests/test_lock_cancel.c
 *
 * Lustre Light user test program
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

#include <../test_common.h>

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

extern void __liblustre_setup_(void);
extern void __liblustre_cleanup_(void);

void usage(char *cmd)
{
        printf("Usage: \t%s --target mdsnid:/mdsname/profile\n", cmd);
        printf("       \t%s --dumpfile dumpfile\n", cmd);
        exit(-1);
}

int main(int argc, char *argv[])
{
        int opt_index, c;
        static struct option long_opts[] = {
                {"target", 1, 0, 0},
                {"dumpfile", 1, 0, 0},
                {0, 0, 0, 0}
        };
	int fd;
        long time1, time2;
        struct stat statbuf;

        if (argc < 3)
                usage(argv[0]);

        while ((c = getopt_long(argc, argv, "", long_opts, &opt_index)) != -1) {
                switch (c) {
                case 0: {
                        if (!optarg[0])
                                usage(argv[0]);

                        if (!strcmp(long_opts[opt_index].name, "target")) {
                                setenv(ENV_LUSTRE_MNTTGT, optarg, 1);
                        } else if (!strcmp(long_opts[opt_index].name, "dumpfile")) {
                                setenv(ENV_LUSTRE_DUMPFILE, optarg, 1);
                        } else
                                usage(argv[0]);
                        break;
                }
                default:
                        usage(argv[0]);
                }
        }

        if (optind != argc)
                usage(argv[0]);

        __liblustre_setup_();

	MPI_CHECK(MPI_Init(&argc, &argv), "MPI_Init()");
	MPI_CHECK(MPI_Comm_size(MPI_COMM_WORLD, &numTasks), "MPI_Comm_size");
	MPI_CHECK(MPI_Comm_rank(MPI_COMM_WORLD, &rank), "MPI_Comm_rank");

        if (numTasks < 2) {
                printf("this demo can't run on single node!\n");
                goto cleanup;
        }

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
                close(fd);
                printf("Node 1: done creation. perform stat on file %s ...\n", test_file_name);
                fflush(stdout);

                if (stat(test_file_name, &statbuf)) {
                        printf("Node %d: stat file err: %d", rank, fd);
                        fflush(stdout);
                        goto cleanup;
                }

                printf("Node %d: done stat on file\n", rank);
                fflush(stdout);
        } else {
                printf("Node %d: waiting node 1 create & stat file\n", rank);
                fflush(stdout);
        }

        MPI_Barrier(MPI_COMM_WORLD);
        
        if (rank == 1) {
                printf("Node 1: file has been create+stat, abort excution here!!!!!!!\n");
                fflush(stdout);
                exit(0);
        }
        
        sleep(1);
        printf("Node %d: synced with Node 1. sleep 5 seconds...\n", rank);
        fflush(stdout);
        sleep(5);
        printf("Node %d: wakeup from sleep. perform unlink()...\n", rank);
        fflush(stdout);

        time1 = time(NULL);
        if (unlink(test_file_name)) {
                printf("Node %d: error unlink file: %s\n", rank, test_file_name);
                fflush(stdout);
                goto cleanup;
        }
        time2 = time(NULL);
        printf("Node %d: successfully unlink file, cost %ld seconds.\n",
                rank, time2 - time1);
        fflush(stdout);

cleanup:
        __liblustre_cleanup_();
        printf("Node %d: end sucessfully.\n", rank);
	return 0;
}
