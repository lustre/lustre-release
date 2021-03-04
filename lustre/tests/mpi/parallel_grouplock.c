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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/tests/parallel_grouplock.c
 *
 * Author: You Feng <youfeng@clusterfs.com>
 */

#include <limits.h>
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <asm/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include "lp_utils.h"

#define LPGL_BUF_LEN 8192
#define LPGL_TEST_ITEMS 12

#define MIN_GLHOST 5

#define MAX_WAIT_TRIES            10
#define WAIT_TIME                  1  /* secs */
#define ONE_MB               1048576  /*   1 MB */
#define MIN_LGBUF_SIZE     536870912  /* 512 MB */
#define MAX_LGBUF_SIZE     536870912  /* 512 MB */
// #define MAX_LGBUF_SIZE    1073741824  /*   1 GB */

#define READ    1
#define WRITE   2
#define IOCTL   3
#define CLOSE   4

int rank;
int size;

char *testdir;
int only_test;

char buf[LPGL_BUF_LEN];
char *lgbuf;
int lgbuf_size;
char filename[MAX_FILENAME_LEN];

static void
alloc_lgbuf()
{
	if (lgbuf)
		return;

	lgbuf_size = MAX_LGBUF_SIZE;
	for (; lgbuf_size >= MIN_LGBUF_SIZE; lgbuf_size -= ONE_MB)
		if ((lgbuf = (char *)malloc(lgbuf_size)) != NULL)
			return;

	FAIL("malloc of large buffer failed.\n");
}

static inline void
read_buf(int fd)
{
	int pos, rc;

	rc = read(fd, buf, sizeof(buf));
	if (rc == -1) {
		pos = lseek(fd, 0, SEEK_CUR);
		FAILF("read of file %s at pos %d for %zu bytes returned %d: (%d) %s.\n",
		      filename, pos, sizeof(buf), rc, errno, strerror(errno));
	} else if (rc != sizeof(buf)) {
		pos = lseek(fd, 0, SEEK_CUR);
		FAILF("read of file %s at pos %d for %zu bytes returned %d.\n",
		      filename, pos, sizeof(buf), rc);
	}
}

static inline void
write_buf(int fd, int index)
{
	int pos = index * sizeof(buf);
	int rc;

	memset(buf, index, sizeof(buf));
	lseek(fd, pos, SEEK_SET);
	rc = write(fd, buf, sizeof(buf));
	if (rc == -1)
		FAILF("write of file %s at pos %d for %zu bytes returned %d: (%d) %s.\n",
		      filename, pos, sizeof(buf), rc, errno, strerror(errno));
	else if (rc != sizeof(buf))
		FAILF("write of file %s at pos %d for %zu bytes returned %d.\n",
		      filename, pos, sizeof(buf), rc);
}

/*
 * task0 attempts GR(gid=1) -- granted immediately
 * task1 attempts PR|PW -- blocked, goes on waiting list
 * task2 attempts GR(gid=1) -> should be granted
 * task2 writes to file and releases GR(gid=1)
 * task0 waits for task2 to complete its processing
 * task0 writes to file and releases GR(gid=1)
 * task1 PR|PW should be granted and reads the file
 */
void grouplock_test1(char *filename, int fd, int blocking_op, int unlock_op)
{
	MPI_Request req1, req2;
	int iter, flag1, flag2, temp1, temp2;
	int i, rc, gid = 1;

	if (rank == 0) {
		rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
		if (rc == -1)
			FAILF("ioctl GROUP_LOCK of file %s: (%d) %s.\n",
			      filename, errno, strerror(errno));
	}

	MPI_Barrier(MPI_COMM_WORLD);

	switch (rank) {
	case 1:
		if (blocking_op == WRITE) {
			write_buf(fd, rank);
			lseek(fd, 0, SEEK_SET);
		}

		for (i = 0; i <= 2; i++)
			read_buf(fd);

		MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
		break;
	case 2:
		/* Wait for task1 to progress. This could be racey. */
		sleep(WAIT_TIME);

		rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
		if (rc == -1)
			FAILF("ioctl GROUP_LOCK of file %s: (%d) %s.\n",
			      filename, errno, strerror(errno));

		write_buf(fd, rank);

		if (unlock_op == CLOSE)
			rc = close(fd);
		else
			rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);

		if (rc == -1)
			FAILF("%s release GROUP_LOCK of file %s: (%d) %s.\n",
			      (unlock_op == CLOSE) ? "close" : "ioctl",
			      filename, errno, strerror(errno));

		MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
		break;
	case 0:
		/* PR|PW task will tell us when it completes */
		MPI_Irecv(&temp1, 1, MPI_INT, 1, 1, MPI_COMM_WORLD, &req1);
		/* 2nd locking task will tell us when it completes */
		MPI_Irecv(&temp2, 1, MPI_INT, 2, 1, MPI_COMM_WORLD, &req2);

		/* Wait for task2 to complete. */
		iter = MAX_WAIT_TRIES;
		do {
			iter--;
			if (!iter)
				FAIL("2nd locking task is not progressing\n");

			sleep(WAIT_TIME);

			MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
			if (flag1)
				FAIL("PR|PW task progressed even though GROUP lock is held\n");

			MPI_Test(&req2, &flag2, MPI_STATUS_IGNORE);
		} while (!flag2);

		/* Make sure task1 is still waiting. */
		iter = MAX_WAIT_TRIES;
		do {
			iter--;
			sleep(WAIT_TIME);
			MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
			if (flag1)
				FAIL("PR|PW task progressed even though GROUP lock is held\n");
		} while (iter);

		write_buf(fd, rank);

		/* Now we need to release the lock */
		rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);
		if (rc == -1)
			FAILF("ioctl GROUP_UNLOCK of file %s: (%d) %s.\n",
			      filename, errno, strerror(errno));

		/* Wait for task1 to complete. */
		iter = MAX_WAIT_TRIES;
		do {
			iter--;
			if (!iter) {
				FAIL("PR|PW task is not progressing even though GROUP lock was released\n");
				break;
			}
			sleep(WAIT_TIME);
			MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
		} while (!flag1);

		break;
	}
}

/*
 * task0 attempts GR(gid=1) -- granted immediately
 * task1 attempts GR(gid=2) -- blocked
 * task2 attempts PR|PW -- blocked
 * task3 attempts GR(gid=2) -- blocked
 * task4 attempts GR(gid=1) -- should be granted
 * task0,4 writes to file and releases GR(gid=1) --
 *       this allows task2 & 3's GR locks to be granted; task4 remains blocked.
 * task1 & 3 write to file and release GR(gid=2)
 * task2 PR|PW should be granted and reads the file.
 */
void grouplock_test2(char *filename, int fd, int blocking_op, int unlock_op)
{
	int i, iter, rc, gid = 1;
	int flag1, flag2, flag3, flag4;
	int temp1, temp2, temp3, temp4;
	MPI_Request req1, req2, req3, req4;

	if (rank == 0) {
		rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
		if (rc == -1)
			FAILF("ioctl GROUP_LOCK of file %s: (%d) %s.\n",
			      filename, errno, strerror(errno));
	}

	MPI_Barrier(MPI_COMM_WORLD);

	switch (rank) {
	case 3:
		/* Wait for task2 to issue its read request. */
		sleep(2 * WAIT_TIME);
	case 1:
		gid = 2;
		rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
		if (rc == -1)
			FAILF("ioctl GROUP_LOCK of file %s: (%d) %s.\n",
			      filename, errno, strerror(errno));

		write_buf(fd, rank);

		MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);

		/*
		 * Do not release the locks until task 0 is ready to watch
		 * for reading task only
		 */
		MPI_Recv(&temp1, 1, MPI_INT, 0, 1, MPI_COMM_WORLD,
			 MPI_STATUS_IGNORE);

		if (unlock_op == CLOSE)
			rc = close(fd);
		else
			rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);
		if (rc == -1)
			FAILF("%s release GROUP_LOCK of file %s: (%d) %s.\n",
			      (unlock_op == CLOSE) ? "close" : "ioctl",
			      filename, errno, strerror(errno));
		break;
	case 2:
		/* Give task1 a chance to request its GR lock. */
		sleep(WAIT_TIME);

		if (blocking_op == WRITE) {
			write_buf(fd, rank);
			lseek(fd, 0, SEEK_SET);
		}

		for (i = 0; i <= 3; i++)
			read_buf(fd);

		MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
		break;
	case 4:
		/* Give task1 & 3 a chance to queue their GR locks. */
		sleep(3 * WAIT_TIME);

		rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
		if (rc == -1)
			FAILF("ioctl GROUP_LOCK of file %s: (%d) %s.\n",
			      filename, errno, strerror(errno));

		write_buf(fd, rank);

		rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);
		if (rc == -1)
			FAILF("%s release GROUP_LOCK of file %s: (%d) %s.\n",
			      (unlock_op == CLOSE) ? "close" : "ioctl",
			      filename, errno, strerror(errno));

		MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
		break;
	case 0:
		/* locking tasks will tell us when they complete */
		MPI_Irecv(&temp1, 1, MPI_INT, 1, 1, MPI_COMM_WORLD, &req1);
		MPI_Irecv(&temp2, 1, MPI_INT, 2, 1, MPI_COMM_WORLD, &req2);
		MPI_Irecv(&temp3, 1, MPI_INT, 3, 1, MPI_COMM_WORLD, &req3);
		MPI_Irecv(&temp4, 1, MPI_INT, 4, 1, MPI_COMM_WORLD, &req4);

		/* Make sure all tasks that should be blocked are waiting. */
		iter = MAX_WAIT_TRIES;
		do {
			iter--;
			sleep(WAIT_TIME);
			MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
			MPI_Test(&req2, &flag2, MPI_STATUS_IGNORE);
			MPI_Test(&req3, &flag3, MPI_STATUS_IGNORE);
			if (flag1 || flag3)
				FAIL("GROUP (gid=2) task progressed even though GROUP (gid=1) lock is held.\n");
			if (flag2)
				FAIL("PR|PW task progressed even though GROUP (gid=1) lock is still held\n");
		} while (iter);

		/* Wait for task4 to signal it has completed. */
		iter = MAX_WAIT_TRIES;
		do {
			iter--;
			if (!iter)
				FAIL("2nd task GROUP(gid=1) not progressing\n");

			sleep(WAIT_TIME);
			MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
			MPI_Test(&req2, &flag2, MPI_STATUS_IGNORE);
			MPI_Test(&req3, &flag3, MPI_STATUS_IGNORE);
			MPI_Test(&req4, &flag4, MPI_STATUS_IGNORE);
			if (flag1 || flag3)
				FAIL("GROUP (gid=2) task progressed even though GROUP (gid=1) lock is held.\n");
			if (flag2)
				FAIL("PR|PW task progressed even though GROUP (gid=1) lock is still held\n");
		} while (!flag4);

		write_buf(fd, rank);

		/* Now let's release first lock */
		rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);
		if (rc == -1)
			FAILF("ioctl GROUP_UNLOCK of file %s returned %d",
			      filename, rc);

		/* Wait for task1 & 3 to signal they have their lock. */
		iter = MAX_WAIT_TRIES;
		do {
			iter--;
			if (!iter)
				FAIL("GROUP(gid=2) tasks not progressing\n");

			sleep(WAIT_TIME);
			MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
			MPI_Test(&req2, &flag2, MPI_STATUS_IGNORE);
			MPI_Test(&req3, &flag3, MPI_STATUS_IGNORE);
			if (flag2) {
				fprintf(stderr, "task2 %d\n", flag2);
				FAIL("PR task progressed even though GROUP lock was on the queue task\n");
			}
		} while (!(flag1 && flag3));

		/* Make sure task2 is still waiting. */
		iter = MAX_WAIT_TRIES;
		do {
			iter--;
			sleep(WAIT_TIME);
			MPI_Test(&req2, &flag2, MPI_STATUS_IGNORE);
			if (flag2)
				FAIL("PR task progressed even though GR(gid=2) lock was active.\n");
		} while (iter);

		/* Tell task1 & 3 to release their GR(gid=2) lock. */
		MPI_Send(&gid, 1, MPI_INT, 1, 1, MPI_COMM_WORLD);
		MPI_Send(&gid, 1, MPI_INT, 3, 1, MPI_COMM_WORLD);

		/* Wait for task2 (PR) to complete. */
		iter = MAX_WAIT_TRIES;
		do {
			iter--;
			if (!iter) {
				FAIL("reading task is not progressing even though GROUP locks are released\n");
				break;
			}
			sleep(WAIT_TIME);
			MPI_Test(&req2, &flag2, MPI_STATUS_IGNORE);
		} while (!flag3);
		break;
	}
}

/*
 * Tests a bug that once existed in the group lock code;
 * i.e. that a GR lock request on a O_NONBLOCK fd could fail even though
 * there is no blocking GROUP lock ahead of it on the waitq.
 *
 * task0 starts a large write (PW). this test could be racey if this
 *       write finishes too quickly.
 * task1 attempts GR(gid=1) -- blocked
 * task2 attempts GR(gid=2) with a O_NONBLOCK fs. should not fail.
 */
void grouplock_test3(char *filename, int fd)
{
	MPI_Request req1, req2;
	int iter, flag1, flag2, temp1, temp2;
	int rc, gid = 1;

	if (rank == 0) {
		alloc_lgbuf();
	} else if (rank == 2) {
		rc = fcntl(fd, F_SETFL, O_NONBLOCK);
		if (rc == -1)
			FAILF("fcntl(O_NONBLOCK) failed: (%d) %s.\n",
				errno, strerror(errno));
	}

	MPI_Barrier(MPI_COMM_WORLD);

	switch (rank) {
	case 2:
		gid = 2;
		usleep(10000);
		usleep(10000);
	case 1:
		/*
		 * Racey, we have to sleep just long enough for
		 * task0's write to start.
		 */
		usleep(10000);

		rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
		if (rc == -1)
			FAILF("ioctl GROUP_LOCK of file %s: (%d) %s.\n",
			      filename, errno, strerror(errno));

		/* tell task0 we have the lock. */
		MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);

		/* the close of fd will release the lock. */
		break;
	case 0:
		rc = write(fd, lgbuf, lgbuf_size);
		if (rc == -1)
			FAILF("write of file %s for %d bytes returned %d: (%d) %s.\n",
			      filename, lgbuf_size, rc, errno, strerror(errno));
		else if (rc != lgbuf_size)
			FAILF("write of file %s for %d bytes returned %d.\n",
			      filename, lgbuf_size, rc);

		/* GR tasks will tell us when they complete */
		MPI_Irecv(&temp1, 1, MPI_INT, 1, 1, MPI_COMM_WORLD, &req1);
		MPI_Irecv(&temp2, 1, MPI_INT, 2, 1, MPI_COMM_WORLD, &req2);

		/* Wait for task1 & 2 to complete. */
		iter = MAX_WAIT_TRIES;
		do {
			iter--;
			if (!iter) {
				FAIL("GR(gid=1) tasks are not progressing even no conflicting locks exist.\n");
				break;
			}
			sleep(WAIT_TIME);
			MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
			MPI_Test(&req2, &flag2, MPI_STATUS_IGNORE);
		} while (!(flag1 && flag2));
		break;
	}
}

/*
 * Tests a bug that once existed in the group lock code;
 * i.e. extent locks without O_NONBLOCK that go on the waitq before a group
 * lock request came in and was granted. The extent lock would timed out and
 * produce an error.
 *
 * task0 starts a large write (PW). this test could be racey if this
 *       write finishes too quickly.
 * task1 attempts PR -- blocked
 * task2 attempts GR(gid=1) -- blocked
 * task0 completes write
 * task1 should wakeup and complete its read
 * task2 should wakeup and after task1 complete.
 */
void grouplock_test4(char *filename, int fd)
{
	MPI_Request req1;
	int iter, flag1, temp1;
	int rc, gid = 1;

	if (rank == 0)
		alloc_lgbuf();

	MPI_Barrier(MPI_COMM_WORLD);

	switch (rank) {
	case 1:
		/*
		 * Racey, we have to sleep just long enough for
		 * task0's write to start.
		 */
		MPI_Recv(&temp1, 1, MPI_INT, 0, 1, MPI_COMM_WORLD,
			 MPI_STATUS_IGNORE);

		/* tell task2 to go. */
		MPI_Send(&gid, 1, MPI_INT, 2, 1, MPI_COMM_WORLD);
		sleep(WAIT_TIME);

		read_buf(fd);
		MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
		break;
	case 2:
		/* Give task0 & 1 a chance to start. */
		MPI_Recv(&temp1, 1, MPI_INT, 1, 1, MPI_COMM_WORLD,
			 MPI_STATUS_IGNORE);
		sleep(2 * WAIT_TIME);

		rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
		if (rc == -1)
			FAILF("ioctl GROUP_LOCK of file %s: (%d) %s.\n",
			      filename, errno, strerror(errno));

		/* tell task0 we have the lock. */
		MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);

		/*
		 * Do not release the locks until task 0 tells us too.
		 * for reading task only
		 */
		MPI_Recv(&temp1, 1, MPI_INT, 0, 1, MPI_COMM_WORLD,
			 MPI_STATUS_IGNORE);

		rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);
		if (rc == -1)
			FAILF("ioctl GROUP_UNLOCK of file %s: (%d) %s.\n",
			      filename, errno, strerror(errno));
		break;
	case 0:
		/* tell task1 to go to avoid race */
		MPI_Send(&gid, 1, MPI_INT, 1, 1, MPI_COMM_WORLD);
		rc = write(fd, lgbuf, lgbuf_size);
		if (rc == -1)
			FAILF("write of file %s for %d bytes returned %d: (%d) %s.\n",
			      filename, lgbuf_size,
			      rc, errno, strerror(errno));
		else if (rc != lgbuf_size)
			FAILF("write of file %s for %d bytes returned %d.\n",
			      filename, lgbuf_size, rc);

		/* wait for task2 to get its lock. */
		MPI_Recv(&temp1, 1, MPI_INT, 2, 1, MPI_COMM_WORLD,
			 MPI_STATUS_IGNORE);

		/* Tell task2 it's ok to release its GR(gid=1) lock. */
		MPI_Send(&gid, 1, MPI_INT, 2, 1, MPI_COMM_WORLD);

		/* wait a really long time. */
		sleep(180 * WAIT_TIME);

		/* PR task will tell us when it completes */
		MPI_Irecv(&temp1, 1, MPI_INT, 1, 1, MPI_COMM_WORLD, &req1);

		/*
		 * Make sure the PR task is successful and doesn't hang.
		 *
		 * XXX - To test properly we need to make sure the read
		 *       gets queued before task2's group lock request.
		 *       You may need to increase lgbuf_size.
		 */
		iter = MAX_WAIT_TRIES;
		do {
			iter--;
			if (!iter) {
				FAIL("PR task is hung !\n");
				break;
			}
			sleep(WAIT_TIME);
			MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
		} while (!flag1);

		break;
	}
}

/*
 * task0 attempts GR(gid=1) -- granted
 * task1 attempts PR on non-blocking fd -> should return -EAGAIN
 * task2 attempts PW on non-blocking fd -> should return -EAGAIN
 * task3 attempts GR(gid=2) on non-blocking fd -> should return -EAGAIN
 */
void grouplock_nonblock_test(char *filename, int fd)
{
	MPI_Request req1, req2, req3;
	int iter, flag1, flag2, flag3, temp1, temp2, temp3;
	int rc, gid = 1;

	if (rank == 0) {
		rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
		if (rc == -1)
			FAILF("ioctl GROUP_LOCK of file %s: (%d) %s.\n",
			      filename, errno, strerror(errno));
	}

	rc = fcntl(fd, F_SETFL, O_NONBLOCK);
	if (rc == -1)
		FAILF("fcntl(O_NONBLOCK) failed: (%d) %s.\n",
		      errno, strerror(errno));

	MPI_Barrier(MPI_COMM_WORLD);

	switch (rank) {
	case 1:
		rc = read(fd, buf, sizeof(buf));
		if ((rc != -1) || (errno != EAGAIN))
			FAIL("PR lock succeeded while incompatible GROUP LOCK (gid=1) is still held\n");

		MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
		break;
	case 2:
		rc = write(fd, buf, sizeof(buf));
		if ((rc != -1) || (errno != EAGAIN))
			FAIL("PW lock succeeded while incompatible GROUP LOCK (gid=1) is still held\n");

		MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
		break;
	case 3:
		gid = 2;
		rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
		if ((rc != -1) || (errno != EAGAIN))
			FAIL("GROUP_LOCK (gid=2) succeeded while incompatible GROUP LOCK (gid=1) is still held.\n");

		MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
		break;
	case 0:
		/* reading task will tell us when it completes */
		MPI_Irecv(&temp1, 1, MPI_INT, 1, 1, MPI_COMM_WORLD, &req1);
		/* writing task will tell us when it completes */
		MPI_Irecv(&temp2, 1, MPI_INT, 2, 1, MPI_COMM_WORLD, &req2);
		/* 2nd locking task will tell us when it completes */
		MPI_Irecv(&temp3, 1, MPI_INT, 3, 1, MPI_COMM_WORLD, &req3);

		iter = MAX_WAIT_TRIES;
		do {
			iter--;
			if (!iter)
				FAIL("non-blocking tasks are not progressing\n");

			sleep(WAIT_TIME);
			MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
			MPI_Test(&req2, &flag2, MPI_STATUS_IGNORE);
			MPI_Test(&req3, &flag3, MPI_STATUS_IGNORE);
		} while (!(flag1 && flag2 && flag3));

		rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);
		if (rc == -1)
			FAILF("ioctl GROUP_UNLOCK of file %s", filename);
		break;
	}
}

/* Just test some error paths with invalid requests */
void grouplock_errorstest(char *filename, int fd)
{
	int rc, gid = 1;

	MPI_Barrier(MPI_COMM_WORLD);

	switch (rank) {
	case 0:
		rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
		if (rc == -1)
			FAILF("ioctl GROUP_LOCK of file %s: (%d) %s.\n",
			      filename, errno, strerror(errno));

		/* second group lock on same fd, same gid */
		rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
		if (rc == -1) {
			if (errno != EINVAL)
				FAILF("Double GROUP lock failed with errno %d instead of EINVAL\n",
				      errno);
		} else {
			FAIL("Taking second GROUP lock on same fd succeed\n");
		}

		/* second group lock on same fd, different gid */
		rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid + 1);
		if (rc == -1) {
			if (errno != EINVAL)
				FAILF("Double GROUP lock with different gid failed with errno %d instead of EINVAL\n",
				      errno);
		} else {
			FAIL("Taking second GROUP lock on same fd, with different gid, succeeded.\n");
		}

		/* GROUP unlock with wrong gid */
		rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid + 1);
		if (rc == -1) {
			if (errno != EINVAL)
				FAILF("GROUP_UNLOCK with wrong gid failed with errno %d instead of EINVAL\n",
				      errno);
		} else {
			FAIL("GROUP unlock with wrong gid succeed\n");
		}

		rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);
		if (rc == -1)
			FAILF("ioctl GROUP_UNLOCK of file %s returned %d.",
			      filename, rc);
		break;

	case 1:
		/* unlock of never locked fd */
		rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);
		if (rc == -1) {
			if (errno != EINVAL)
				FAILF("GROUP_UNLOCK on never locked fd failed with errno %d instead of EINVAL.\n",
				      errno);
		} else {
			FAIL("GROUP unlock on never locked fd succeed\n");
		}
		break;
	}
}

void grouplock_file(char *name, int subtest)
{
	int fd;
	int flags = O_CREAT | O_RDWR | O_SYNC | O_TRUNC;
	int mode = 0666;

	sprintf(filename, "%s/%s", testdir, name);

	fd = open(filename, flags, mode);
	if (fd == -1)
		FAILF("open of file %s: (%d) %s.\n",
		      filename, errno, strerror(errno));

	MPI_Barrier(MPI_COMM_WORLD);

	switch (subtest) {
	case 1:
		grouplock_test1(filename, fd, READ, IOCTL);
		break;
	case 2:
		grouplock_test1(filename, fd, READ, CLOSE);
		break;
	case 3:
		grouplock_test1(filename, fd, WRITE, IOCTL);
		break;
	case 4:
		grouplock_test1(filename, fd, WRITE, CLOSE);
		break;
	case 5:
		grouplock_test2(filename, fd, READ, IOCTL);
		break;
	case 6:
		grouplock_test2(filename, fd, READ, CLOSE);
		break;
	case 7:
		grouplock_test2(filename, fd, WRITE, IOCTL);
		break;
	case 8:
		grouplock_test2(filename, fd, WRITE, CLOSE);
		break;
	case 9:
		grouplock_nonblock_test(filename, fd);
		break;
	case 10:
		grouplock_errorstest(filename, fd);
		break;
	case 11:
		grouplock_test3(filename, fd);
		break;
	case 12:
		grouplock_test4(filename, fd);
		break;
	default:
		FAILF("wrong subtest number %d (should be <= %d)",
		      subtest, LPGL_TEST_ITEMS);
	}

	close(fd);

	if (rank == 0)
		unlink(filename);

	MPI_Barrier(MPI_COMM_WORLD);
}

void parallel_grouplock(void)
{
	char teststr[16];
	int i;

	if (only_test) {
		sprintf(teststr, "subtest %d", only_test);
		begin(teststr);
		grouplock_file("parallel_grouplock", only_test);
		end(teststr);
	} else {
		for (i = 1; i <= LPGL_TEST_ITEMS; i++) {
			sprintf(teststr, "subtest %d", i);
			begin(teststr);
			grouplock_file("parallel_grouplock", i);
			end(teststr);
		}
	}
}

void usage(char *proc)
{
	int i;

	if (rank == 0) {
		printf("Usage: %s [-h] -d <testdir> [-n <num>]\n", proc);
		printf("           [-t <num>] [-v] [-V #] [-g]\n");
		printf("\t-h: prints this help message\n");
		printf("\t-d: the directory in which the tests will run\n");
		printf("\t-n: repeat test # times\n");
		printf("\t-t: run a particular test #\n");
		printf("\t-v: increase the verbositly level by 1\n");
		printf("\t-V: select a specific verbosity level\n");
		printf("\t-g: debug mode\n");
	}

	MPI_Initialized(&i);
	if (i)
		MPI_Finalize();
	exit(0);
}

int main(int argc, char *argv[])
{
	int i, iterations = 1, c;

	setbuf(stdout, 0);
	setbuf(stderr, 0);

	/*
	 * Check for -h parameter before MPI_Init so the binary can be
	 * called directly, without, for instance, mpirun
	 */
	for (i = 1; i < argc; ++i) {
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
			usage(argv[0]);
	}

	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &size);

	/* Parse command line options */
	while (1) {
		c = getopt(argc, argv, "d:ghn:t:vV:");
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			testdir = optarg;
			break;
		case 'g':
			debug = 1;
			break;
		case 'h':
			usage(argv[0]);
			break;
		case 'n':
			iterations = atoi(optarg);
			break;
		case 't':
			only_test = atoi(optarg);
			break;
		case 'v':
			verbose += 1;
			break;
		case 'V':
			verbose = atoi(optarg);
			break;
		}
	}

	if (rank == 0)
		printf("%s is running with %d task(es) %s\n",
		       argv[0], size, debug ? "in DEBUG mode" : "\b\b");

	if (size < MIN_GLHOST) {
		fprintf(stderr,
			"Error: %d tasks run, but should be at least %d tasks to run the test!\n",
			size, MIN_GLHOST);
		MPI_Abort(MPI_COMM_WORLD, 2);
	}

	if (!testdir && rank == 0) {
		fprintf(stderr,
			"Please specify a test directory! (\"%s -h\" for help)\n",
			argv[0]);
		MPI_Abort(MPI_COMM_WORLD, 2);
	}

	lp_gethostname();

	for (i = 0; i < iterations; ++i) {
		if (rank == 0)
			printf("%s: Running test #%s(iter %d)\n",
			       timestamp(), argv[0], i);

		parallel_grouplock();
		MPI_Barrier(MPI_COMM_WORLD);
	}

	if (rank == 0)
		printf("%s: All tests passed!\n", timestamp());

	MPI_Finalize();
	return 0;
}
