/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/tests/parallel_grouplock.c
 *
 * Author: You Feng <youfeng@clusterfs.com>
 */

#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <lustre/lustre_user.h>
#include "lp_utils.h"

#define LPGL_FILEN 700000
#define LPGL_TEST_ITEMS 7

#define MAX_GLHOST 4

/* waiting time in 0.1 s */
#define MAX_WAITING_TIME 20
int rank = 0;
int size = 0;

char *testdir = NULL;

/*
 * process1 attempts CW(gid=1) -- granted immediately
 * process2 attempts PR -- blocked, goes on waiting list
 * process3 attempts CW(gid=1) -> should be granted, but may go on
 *                                the waiting list
 */
void grouplock_test1(char *filename, int fd, char *errmsg)
{
        int rc, count, gid = 1;
        char buf[LPGL_FILEN];
        char zeros[LPGL_FILEN];
        MPI_Request req1, req2;
        int temp1, temp2;

        if (rank == 0) {
                if ((rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_LOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }
        }

        MPI_Barrier(MPI_COMM_WORLD);

        if (rank == 1) {
                memset(zeros, 0x0, sizeof(zeros));
                lseek(fd, 0, SEEK_SET);

                MPI_Send(&gid, 1, MPI_INT, 2, 1, MPI_COMM_WORLD);
                count = read(fd, buf, sizeof(buf));
                if (count != sizeof(buf)) {
                        if (count > 0)
                                dump_diff(zeros, buf, count, 0);
                        sprintf(errmsg, "read of file %s return %d",
                                filename, count);
                        FAIL(errmsg);
                }
                MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
        }

        if (rank == 2) {
                int temp;

                /* Wait for reading task to progress, this is probably somewhat
                   racey, though, may be adding usleep here would make things
                   better here. */
                usleep(100);
                MPI_Recv(&temp, 1, MPI_INT, 1, 1, MPI_COMM_WORLD,
                         MPI_STATUS_IGNORE);
                if ((rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_LOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }
                MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
        }

        if (rank == 0) {
                int iter = MAX_WAITING_TIME;
                int flag1, flag2;

                /* reading task will tell us when it completes */
                MPI_Irecv(&temp1, 1, MPI_INT, 1, 1, MPI_COMM_WORLD, &req1);
                /* 2nd locking task will tell us when it completes */
                MPI_Irecv(&temp2, 1, MPI_INT, 2, 1, MPI_COMM_WORLD, &req2);

                do {
                        iter--;
                        if (!iter) {
                                FAIL("2nd locking task is not progressing\n");
                        }
                        usleep(100);
                        MPI_Test(&req2, &flag2, MPI_STATUS_IGNORE);
                        MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
                        if (flag1) {
                                FAIL("PR task progressed even though GROUP lock"
                                     " is held\n");
                        }
                } while (!flag2);
        }

        /* Now we need to release the lock */

        if (rank == 0 || rank == 2) {
                if ((rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_UNLOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }
        }

        if (rank == 0) {
                int iter = MAX_WAITING_TIME;
                int flag1;

                do {
                        iter--;
                        if (!iter) {
                                FAIL("reading task is not progressing even "
                                     "though GROUP lock was released\n");
                                break;
                        }
                        usleep(100);
                        MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
                } while (!flag1);
        }

        MPI_Barrier(MPI_COMM_WORLD);

}

/*
 * process1 attempts CW(gid=1) -- granted immediately
 * process2 attempts CW(gid=2) -- blocked
 * process3 attempts PR -- blocked
 * process4 attempts CW(gid=2) -- blocked
 * process1 releases CW(gid=1) -- this allows process2's CW lock to be granted
                                  process3 remains blocked
 */
void grouplock_test2(char *filename, int fd, char *errmsg)
{
        int rc, count, gid = 1;
        char buf[LPGL_FILEN];
        char zeros[LPGL_FILEN];
        MPI_Request req1, req2, req3;
        int temp1, temp2, temp3;

        if (rank == 0) {
                if ((rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_LOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }
        }

        MPI_Barrier(MPI_COMM_WORLD);

        if (rank == 1 || rank == 3) {
                gid = 2;
                if (rank == 3) {
                        MPI_Recv(&temp1, 1, MPI_INT, 2, 1, MPI_COMM_WORLD,
                                 MPI_STATUS_IGNORE);
                        usleep(100);
                }
                if ((rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_LOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }
                MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
        }

        if (rank == 2) {
                memset(zeros, 0x0, sizeof(zeros));
                lseek(fd, 0, SEEK_SET);

                MPI_Send(&gid, 1, MPI_INT, 3, 1, MPI_COMM_WORLD);
                count = read(fd, buf, sizeof(buf));
                if (count != sizeof(buf)) {
                        if (count > 0)
                                dump_diff(zeros, buf, count, 0);
                        sprintf(errmsg, "read of file %s return %d",
                                filename, count);
                        FAIL(errmsg);
                }
                MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
        }

        if (rank == 0) {
                int iter = MAX_WAITING_TIME;
                int flag1, flag2, flag3;

                /* 2nd locking task will tell us when it completes */
                MPI_Irecv(&temp1, 1, MPI_INT, 1, 1, MPI_COMM_WORLD, &req1);
                /* 3nd locking task will tell us when it completes */
                MPI_Irecv(&temp2, 1, MPI_INT, 3, 1, MPI_COMM_WORLD, &req2);
                /* reading task will tell us when it completes */
                MPI_Irecv(&temp3, 1, MPI_INT, 2, 1, MPI_COMM_WORLD, &req3);

                do {
                        iter--;
                        usleep(100);
                        MPI_Test(&req2, &flag2, MPI_STATUS_IGNORE);
                        MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
                        MPI_Test(&req3, &flag3, MPI_STATUS_IGNORE);
                        if (flag3) {
                                FAIL("PR task progressed even though GROUP lock"
                                     " is held\n");
                        }
                        if (flag1 || flag2) {
                                FAIL("GROUP (gid=2) task progressed even though"
                                     " GROUP (gid=1) lock is held\n");
                        }

                } while (iter);

                /* Now let's release first lock */
                if ((rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_UNLOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }
                iter = MAX_WAITING_TIME;
                do {
                        iter--;
                        if (!iter) {
                                FAIL("GROUP(gid=2) tasks are not progressing\n");
                        }
                        usleep(100);
                        MPI_Test(&req2, &flag2, MPI_STATUS_IGNORE);
                        MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
                        MPI_Test(&req3, &flag3, MPI_STATUS_IGNORE);
                        if (flag3) {
                                fprintf(stderr, "task1 %d, task3 %d\n", flag1,
                                        flag2);
                                FAIL("PR task progressed even though GROUP lock"
                                     " was on the queue task\n");
                        }
                } while (!(flag1 && flag2));
                MPI_Send(&gid, 1, MPI_INT, 1, 1, MPI_COMM_WORLD);
                MPI_Send(&gid, 1, MPI_INT, 3, 1, MPI_COMM_WORLD);
        }

        if (rank == 1 || rank == 3) {
                /* Do not release the locks until task 0 is ready to watch
                   for reading task only */
                MPI_Recv(&temp1, 1, MPI_INT, 0, 1, MPI_COMM_WORLD,
                         MPI_STATUS_IGNORE);
                if ((rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_UNLOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }
        }

        if (rank == 0) {
                int iter = MAX_WAITING_TIME;
                int flag3;

                do {
                        iter--;
                        if (!iter) {
                                FAIL("reading task is not progressing even "
                                     "though GROUP locks are released\n");
                                break;
                        }
                        usleep(100);
                        MPI_Test(&req3, &flag3, MPI_STATUS_IGNORE);
                } while (!flag3);
        }

        MPI_Barrier(MPI_COMM_WORLD);

}

/*
 * process1 attempts CW(gid=1) -- granted
 * process2 attempts PR -- blocked
 * process3 attempts CW(gid=1) -> should be granted
 * process3 releases CW(gid=1)
 *   process2 should remain blocked
 * process1 releases CW(gid=1)
 *   process2's PR should be granted
 *
 * This is a lot like test1.
 */
void grouplock_test3(char *filename, int fd, char *errmsg)
{
        int rc, count, gid = 1;
        char buf[LPGL_FILEN];
        char zeros[LPGL_FILEN];
        MPI_Request req1, req2;
        int temp1, temp2;

        if (rank == 0) {
                if ((rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_LOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }
        }

        MPI_Barrier(MPI_COMM_WORLD);

        if (rank == 1) {
                memset(zeros, 0x0, sizeof(zeros));
                lseek(fd, 0, SEEK_SET);

                MPI_Send(&gid, 1, MPI_INT, 2, 1, MPI_COMM_WORLD);
                count = read(fd, buf, sizeof(buf));
                if (count != sizeof(buf)) {
                        if (count > 0)
                                dump_diff(zeros, buf, count, 0);
                        sprintf(errmsg, "read of file %s return %d",
                                filename, count);
                        FAIL(errmsg);
                }
                MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
        }

        if (rank == 2) {
                int temp;

                /* Wait for reading task to progress, this is probably somewhat
                   racey, though, may be adding usleep here would make things
                   better here. */
                usleep(100);
                MPI_Recv(&temp, 1, MPI_INT, 1, 1, MPI_COMM_WORLD,
                         MPI_STATUS_IGNORE);
                if ((rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_LOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }
                MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
        }

        if (rank == 0) {
                int iter = MAX_WAITING_TIME;
                int flag1, flag2;

                /* reading task will tell us when it completes */
                MPI_Irecv(&temp1, 1, MPI_INT, 1, 1, MPI_COMM_WORLD, &req1);
                /* 2nd locking task will tell us when it completes */
                MPI_Irecv(&temp2, 1, MPI_INT, 2, 1, MPI_COMM_WORLD, &req2);

                do {
                        iter--;
                        if (!iter) {
                                FAIL("2nd locking task is not progressing\n");
                        }
                        usleep(100);
                        MPI_Test(&req2, &flag2, MPI_STATUS_IGNORE);
                        MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
                        if (flag1) {
                                FAIL("PR task progressed even though GROUP lock"
                                     " is held\n");
                        }
                } while (!flag2);
        }

        /* Now we need to release the lock */

        if (rank == 2) {
                if ((rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_UNLOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }
        }

        if (rank == 0) {
                int iter = MAX_WAITING_TIME;
                int flag1;

                do {
                        iter--;
                        usleep(100);
                        MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
                } while (!flag1 && iter);
                if (iter) {
                        FAIL("reading task is progressing even "
                             "though GROUP lock was not fully released\n");
                }

                iter = MAX_WAITING_TIME;

                if ((rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_UNLOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }

                do {
                        iter--;
                        if (!iter) {
                                FAIL("reading task is not progressing even "
                                     "though GROUP lock was released\n");
                                break;
                        }
                        usleep(100);
                        MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
                } while (!flag1);
        }

        MPI_Barrier(MPI_COMM_WORLD);

}

/*
 * process1 attempts CW(gid=1) -- granted
 * process2 attempts PR on non-blocking fd -> should return -EWOULDBLOCK
 * process3 attempts CW(gid=2) on non-blocking fd -> should return -EWOULDBLOCK
 */
void grouplock_test4(char *filename, int fd, char *errmsg)
{
        int rc, count, gid = 1;
        char buf[LPGL_FILEN];
        char zeros[LPGL_FILEN];

        if (rank == 0) {
                if ((rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_LOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }
        }

        MPI_Barrier(MPI_COMM_WORLD);

        if (rank == 1) {
                memset(zeros, 0x0, sizeof(zeros));
                lseek(fd, 0, SEEK_SET);

                count = read(fd, buf, sizeof(buf));
                if (count != sizeof(buf)) {
                        if (count == -1 && errno == EWOULDBLOCK) {
                                MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
                                return;
                        }

                        if (count > 0)
                                dump_diff(zeros, buf, count, 0);
                        sprintf(errmsg, "read of file %s return %d",
                                filename, count);
                        FAIL(errmsg);
                } else {
                        FAIL("PR lock succeed while incompatible "
                             "GROUP LOCK (gid=1) is still held\n");
                }
        }

        if (rank == 2) {
                gid = 2;
                if ((rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid)) == -1) {
                        if (errno == EWOULDBLOCK) {
                                MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
                                return;
                        }

                        sprintf(errmsg, "ioctl GROUP_LOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                } else {
                        FAIL("GROUP_LOCK (gid=2) succeed while incompatible "
                             "GROUP LOCK (gid=1) is still held\n");
                }
        }


        if ( rank == 0) {
                int iter = MAX_WAITING_TIME;
                int flag1, flag2;
                MPI_Request req1, req2;
                int temp1, temp2;

                /* reading task will tell us when it completes */
                MPI_Irecv(&temp1, 1, MPI_INT, 1, 1, MPI_COMM_WORLD, &req1);
                /* 2nd locking task will tell us when it completes */
                MPI_Irecv(&temp2, 1, MPI_INT, 2, 1, MPI_COMM_WORLD, &req2);

                do {
                        iter--;
                        if (!iter) {
                                FAIL("non-blocking tasks are not progressing\n");
                        }
                        usleep(100);
                        MPI_Test(&req2, &flag2, MPI_STATUS_IGNORE);
                        MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
                } while (!(flag2 && flag1));

                if ((rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_UNLOCK of file %s", filename);
                        FAIL(errmsg);
                }
        }
}

/*
 * process1 attempts CW(gid=1) -- granted
 * process2 attempts CW(gid=2) -- blocked
 * process3 attempts CW(gid=2) -- blocked
 * process1 releases CW(gid=1)
 *   process2's CW(gid=2) should be granted
 *   process3's CW(gid=2) should be granted
 *
 * This is pretty much like test 3
 */
void grouplock_test5(char *filename, int fd, char *errmsg)
{
        int rc, gid = 1;
        MPI_Request req1, req2;
        int temp1, temp2;

        if (rank == 0) {
                if ((rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_LOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }
        }

        MPI_Barrier(MPI_COMM_WORLD);

        if (rank == 2 || rank == 1) {
                gid = 2;
                if ((rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_LOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }
                MPI_Send(&gid, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
        }

        if (rank == 0) {
                int iter = MAX_WAITING_TIME;
                int flag1, flag2;

                /* 3rd locking task will tell us when it completes */
                MPI_Irecv(&temp1, 1, MPI_INT, 1, 1, MPI_COMM_WORLD, &req1);
                /* 2nd locking task will tell us when it completes */
                MPI_Irecv(&temp2, 1, MPI_INT, 2, 1, MPI_COMM_WORLD, &req2);

                do {
                        iter--;
                        usleep(100);
                        MPI_Test(&req2, &flag2, MPI_STATUS_IGNORE);
                        MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
                } while (!flag2 && !flag1 && iter);
                if (iter) {
                        FAIL("incomptible locking tasks are progressing\n");
                }
        }

        /* Now we need to release the lock */

        if (rank == 0) {
                int iter = MAX_WAITING_TIME;
                int flag1, flag2;
                if ((rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_UNLOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }

                do {
                        iter--;
                        if (!iter) {
                                FAIL("locking tasks are not progressing even "
                                     "though incompatible lock released\n");
                        }
                        usleep(100);
                        MPI_Test(&req1, &flag1, MPI_STATUS_IGNORE);
                        MPI_Test(&req2, &flag2, MPI_STATUS_IGNORE);
                } while (!(flag1 && flag2));

        }

        if ( rank == 1 || rank == 2) {
                if ((rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_UNLOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }
        }

        MPI_Barrier(MPI_COMM_WORLD);


}

/*
 * process1 attempts CW(gid=1) -- granted
 * process2 attempts PW -- blocked
 * process2 attempts CW(gid=2) -- blocked
 * process3 attempts CW(gid=2) -- blocked
 * process1 releases CW(gid=1)
 *   process2's CW(gid=2) should be granted
 *   process3's CW(gid=2) should be granted
 *
 * after process1 release CW(gid=1), there are two pathes:
 *   path 1. process2 get PW
 *   path 2. process3 get CW(gid=2)
 *
 * green: Also about test6 - by definition if P* and CW lock are waiting,
 *        CW lock have bigger priority and should be granted first when it becomes
 *        possible. So after process1 releases its CW lock, process3 should always
 *        get CW lock, and when it will release it, process 2 will proceed with read
 *        and then with getting CW lock
 *
 * XXX This test does not make any sence at all the way it is described right
 * now, hence disabled.
 */
void grouplock_test6(char *filename, int fd, char *errmsg)
{
}

/* Just test some error paths with invalid requests */
void grouplock_errorstest(char *filename, int fd, char *errmsg)
{
        int gid = 1;
        int rc;

        /* To not do lots of separate tests with lots of fd opening/closing,
           different parts of this test are performed in different processes */

        if (rank == 0 || rank == 1 ) {
                if ((rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_LOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }
        }

        /* second group lock on same fd, same gid */
        if (rank == 0) {
                if ((rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid)) == -1) {
                        if (errno != EINVAL) {
                                sprintf(errmsg, "Double GROUP lock failed with errno %d instead of EINVAL\n", errno);
                                FAIL(errmsg);
                        }
                } else {
                        FAIL("Taking second GROUP lock on same fd succeed\n");
                }
        }

        /* second group lock on same fd, different gid */
        if (rank == 1) {
                if ((rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid + 1)) == -1) {
                        if (errno != EINVAL) {
                                sprintf(errmsg, "Double GROUP lock different gid failed with errno %d instead of EINVAL\n", errno);
                                FAIL(errmsg);
                        }
                } else {
                        FAIL("Taking second GROUP lock on same fd, different gid, succeed\n");
                }
        }

        /* GROUP unlock with wrong gid */
        if (rank == 0 || rank == 1) {
                if ((rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid + 1)) == -1) {
                        if (errno != EINVAL) {
                                sprintf(errmsg, "GROUP unlock with wrong gid failed with errno %d instead of EINVAL\n",
                                        errno);
                                FAIL(errmsg);
                        }
                } else {
                        FAIL("GROUP unlock with wrong gid succeed\n");
                }
        }

        if (rank == 0 || rank == 1) {
                if ((rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid)) == -1) {
                        sprintf(errmsg, "ioctl GROUP_UNLOCK of file %s return %d",
                                filename, rc);
                        FAIL(errmsg);
                }
        }

        /* unlock of never locked fd */
        if (rank == 2) {
                if ((rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid)) == -1) {
                        if (errno != EINVAL) {
                                sprintf(errmsg, "GROUP unlock on never locked fd failed with errno %d instead of EINVAL\n",
                                        errno);
                                FAIL(errmsg);
                        }
                } else {
                        FAIL("GROUP unlock on never locked fd succeed\n");
                }
        }
}

void grouplock_file(char *name, int items)
{
        int fd;
        char filename[MAX_FILENAME_LEN];
        char errmsg[MAX_FILENAME_LEN+20];

        sprintf(filename, "%s/%s", testdir, name);

        if (items == 4) {
                if ((fd = open(filename, O_RDWR | O_NONBLOCK)) == -1) {
                        sprintf(errmsg, "open of file %s", filename);
                        FAIL(errmsg);
                }
        } else if ((fd = open(filename, O_RDWR)) == -1) {
                sprintf(errmsg, "open of file %s", filename);
                FAIL(errmsg);
        }

        MPI_Barrier(MPI_COMM_WORLD);

        switch (items) {
        case 1:
                grouplock_test1(filename, fd, errmsg);
                break;
        case 2:
                grouplock_test2(filename, fd, errmsg);
                break;
        case 3:
                grouplock_test3(filename, fd, errmsg);
                break;
        case 4:
                grouplock_test4(filename, fd, errmsg);
                break;
        case 5:
                grouplock_test5(filename, fd, errmsg);
                break;
        case 6:
                grouplock_test6(filename, fd, errmsg);
                break;
        case 7:
                grouplock_errorstest(filename, fd, errmsg);
                break;
        default:
                sprintf(errmsg, "wrong test case number %d (should be <= %d)",
                        items, LPGL_TEST_ITEMS);
                FAIL(errmsg);
        }

        MPI_Barrier(MPI_COMM_WORLD);

        if (close(fd) == -1) {
                sprintf(errmsg, "close of file %s", filename);
                FAIL(errmsg);
        }

}

void parallel_grouplock(void)
{
        int i;

        for (i = 1;i <= LPGL_TEST_ITEMS;++i) {
                begin("setup");
                create_file("parallel_grouplock", LPGL_FILEN, 0);
                end("setup");

                begin("test");
                grouplock_file("parallel_grouplock", i);
                end("test");

                begin("cleanup");
                remove_file("parallel_grouplock");
                end("cleanup");
        }
}

void usage(char *proc)
{
        int i;

        if (rank == 0) {
                printf("Usage: %s [-h] -d <testdir>\n", proc);
                printf("           [-n \"13\"] [-v] [-V #] [-g]\n");
                printf("\t-h: prints this help message\n");
                printf("\t-d: the directory in which the tests will run\n");
                printf("\t-n: repeat test # times\n");
                printf("\t-v: increase the verbositly level by 1\n");
                printf("\t-V: select a specific verbosity level\n");
                printf("\t-g: debug mode\n");
        }

        MPI_Initialized(&i);
        if (i) MPI_Finalize();
        exit(0);
}

int main(int argc, char *argv[])
{
        char c;
        int i, iterations = 1;

        /* Check for -h parameter before MPI_Init so the binary can be
           called directly, without, for instance, mpirun */
        for (i = 1; i < argc; ++i) {
                if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
                        usage(argv[0]);
        }

        MPI_Init(&argc, &argv);
        MPI_Comm_rank(MPI_COMM_WORLD, &rank);
        MPI_Comm_size(MPI_COMM_WORLD, &size);

//        MPI_Comm_set_attr(MPI_COMM_WORLD, MPI_WTIME_IS_GLOBAL, &tr);

        /* Parse command line options */
        while (1) {
                c = getopt(argc, argv, "d:ghn:vV:");
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
                case 'v':
                        verbose += 1;
                        break;
                case 'V':
                        verbose = atoi(optarg);
                        break;
                }
        }

        if (rank == 0)
                printf("%s is running with %d process(es) %s\n",
                       argv[0], size, debug ? "in DEBUG mode" : "\b\b");

        if (size < MAX_GLHOST) {
                fprintf(stderr, "Error: "
                        "should be at least four processes to run the test!\n");
                MPI_Abort(MPI_COMM_WORLD, 2);
        }

        if (testdir == NULL && rank == 0) {
                fprintf(stderr, "Please specify a test directory! "
                        "(\"%s -h\" for help)\n", argv[0]);
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

        if (rank == 0) {
                printf("%s: All tests passed!\n", timestamp());
        }
        MPI_Finalize();
        return 0;
}
