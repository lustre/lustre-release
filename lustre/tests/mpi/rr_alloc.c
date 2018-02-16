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
 * version 2 along with this program; If not, see If not, see
 * http://www.gnu.org/licenses
 *
 * Please contact http://www.seagate.com/contacts/ or visit www.seagate.com
 * if you need additional information or have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2017, Seagate Technology LLC
 *
 * Author: Ashish Maurya <ashish.maurya@seagate.com>
 */
/*
 * lustre/tests/mpi/rr_alloc.c
 *
 * DESCRIPTION
 *
 * This code is creating <n> files using MPI processes which depend on the
 * mounted clients. Processes are running in parallel through all the client
 * nodes in RR fashion starting with rank 0 and so on, and creating files.
 *
 * USE CASE:- If there are 20 mounted clients on 4 client nodes, 5 clients on
 * each node, it will run 5 processes on each client node through each mount
 * point and each process will create <n> number of files given by the user.
 * Each process rank is mapped to its matching mount point on the client node
 * eg:- rank 0 <-> /tmp/mnt/lustre0 ; rank 1 <-> /tmp/mnt/lustre1 etc.
 *
 * NOTE:- For simplicity client on /mnt/lustre is not taken into account.
 *
 * IMPORTANT NOTE:- If argv[1] is /mnt/dir/ash, then the program assumes that.
 * /mnt0/dir/, /mnt1/dir/, etc exist.
 */

#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <libgen.h>

void usage(char *prog)
{
	printf("Usage: %s <filename with mount pt and test dir>", prog);
	printf(" <no. of files> <no. of cli nodes>\n");
	printf("Ex: mpirun -np <njobs> rr_alloc /tmp/mnt/lustre/ash 512 4\n");

	exit(EXIT_FAILURE);
}

void perr_exit(int rank, int error, const char *fmt, ...)
{
	va_list ap;

	printf("Process rank %d exited with error code %d\n", rank, error);
	va_start(ap, fmt);
	vprintf(fmt, ap);

	MPI_Abort(MPI_COMM_WORLD, error);
}

int main(int argc, char **argv)
{
	int proc_rank = 0;
	int serial_prank_per_cli = 0;
	int proc_per_cli_node = 0;
	int bytes = 0;
	int file_no = 0;
	int client_nodes = 0;
	int nproc = 0;
	int rc = 0;
	int fd = 0;
	int i = 0;
	char file_path[PATH_MAX] = {0};
	char mnt_path[PATH_MAX] = {0};
	char *path1;
	char *path2;
	char *path3;
	char *fname;
	char *dname;

	if (argc != 4)
		usage(argv[0]);

	if (!strchr(argv[1], '/')) {
		fprintf(stderr, "Please enter filename with mount point\n");
		usage(argv[0]);
	}

	/*
	 * Separating filename and mount point name. This is required for
	 * mapping processes to particular mount point.
	 */
	path1 = strdup(argv[1]);
	path2 = strdup(argv[1]);
	path3 = strdup(argv[1]);
	fname = basename(path1);
	dname = basename(dirname(path2));
	/* dirname looping depends on the depth of the file from mount path */
	strncpy(mnt_path, dirname(dirname(path3)), sizeof(mnt_path));

	file_no = atoi(argv[2]);
	if (!file_no) {
		fprintf(stderr, "Number of files must not be zero\n");
		usage(argv[0]);
	}
	client_nodes = atoi(argv[3]);
	if (!client_nodes) {
		fprintf(stderr, "Client nodes must not be zero\n");
		usage(argv[0]);
	}

	rc = MPI_Init(&argc, &argv);
	if (rc != MPI_SUCCESS) {
		fprintf(stderr, "MPI_Init failed: %d\n", rc);
		exit(EXIT_FAILURE);
	}

	rc = MPI_Comm_rank(MPI_COMM_WORLD, &proc_rank);
	if (rc != MPI_SUCCESS)
		perr_exit(proc_rank, rc, "MPI_Comm_rank failed: %d\n", rc);

	rc = MPI_Comm_size(MPI_COMM_WORLD, &nproc);
	if (rc != MPI_SUCCESS)
		perr_exit(proc_rank, rc, "MPI_Comm_size failed: %d\n", rc);

	/*
	 * Make sure that each rank is processed through its respective mnt pt
	 * eg: job 0,1 will be executed by /tmp/mnt/lustre0, /tmp/mnt/lustre1,
	 * etc. on each client node.
	 */
	/* Number of processes on each client nodes */
	proc_per_cli_node = nproc / client_nodes;

	/*
	 * By default rank of processes is allocated in RR fashion throughout
	 * all the client nodes so all the processes are not in serial order on
	 * a particular client node. In order to map each process to a mount pt
	 * by its rank we need process rank in serial order on a client node
	 */
	serial_prank_per_cli = proc_rank % proc_per_cli_node;

	rc = MPI_Barrier(MPI_COMM_WORLD);
	if (rc != MPI_SUCCESS)
		perr_exit(proc_rank, rc, "Prep MPI_Barrier failed: %d\n", rc);

	for (i = 0; i < file_no; i++) {
		bytes = snprintf(file_path, sizeof(file_path),
			"%s%d/%s/%s-%d-%d", mnt_path, serial_prank_per_cli,
			dname, fname, proc_rank, i);
		if (bytes >= sizeof(file_path))
			perr_exit(proc_rank, -ENAMETOOLONG, "Name too long\n");
		fd = open(file_path, O_CREAT|O_RDWR, 0644);
		if (fd < 0) {
			perr_exit(proc_rank, errno, "Cannot open \"%s\": %s\n",
				file_path, strerror(errno));
		}
		close(fd);
	}
	MPI_Finalize();
	return 0;
}
