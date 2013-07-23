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
 * version 2 along with this program; If not, see http://www.gnu.org/licenses
 *
 * Please  visit http://www.xyratex.com/contact if you need additional
 * information or have any questions.
 *
 * GPL HEADER END
*/

/*
 * Copyright 2012 Xyratex Technology Limited
*/

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/sem.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>

#define LOCK_LEN 100

struct flock flocks[4] = {
	/* 1st region */
	{
		.l_type         = F_WRLCK,
		.l_whence       = SEEK_SET,
		.l_start        = 0,
		.l_len          = LOCK_LEN,
		.l_pid          = 0,
	},
	/* 2nd region */
	{
		.l_type         = F_WRLCK,
		.l_whence       = SEEK_SET,
		.l_start        = LOCK_LEN,
		.l_len          = LOCK_LEN,
		.l_pid          = 0,
	},
	/* 3rd region */
	{
		.l_type         = F_WRLCK,
		.l_whence       = SEEK_SET,
		.l_start        = 2 * LOCK_LEN,
		.l_len          = LOCK_LEN,
		.l_pid          = 0,
	},
	/* 2nd & 3rd regions */
	{
		.l_type         = F_WRLCK,
		.l_whence       = SEEK_SET,
		.l_start        = LOCK_LEN,
		.l_len          = 2 * LOCK_LEN,
		.l_pid          = 0,
	},
};

enum {
	FLOCK_GET       = 0,
	FLOCK_PUT       = 1,
};

#define flock_call(fd, num, get, label)						\
	flocks[num].l_type = get == FLOCK_GET ? F_WRLCK : F_UNLCK;		\
	printf("%d: %s lock%d [%llu, %llu]\n", pid,				\
		get == FLOCK_GET ? "taking" : "putting",			\
		num, (unsigned long long)flocks[num].l_start,			\
		(unsigned long long)flocks[num].l_start + flocks[num].l_len);	\
	rc = fcntl(fd, F_SETLKW, &flocks[num]);                         	\
	if (rc < 0) {                                                   	\
		rc = errno;                                             	\
		fprintf(stderr, "%d: failed to %s lock%d, %s\n",        	\
			pid, get == FLOCK_GET ? "take" : "put",         	\
			num, strerror(errno));                          	\
		goto label;                                             	\
	} else {                                                        	\
		printf("%d: done\n", pid);                              	\
	}

void catch_alarm()
{
	fprintf(stderr, "lock timeout\n");
	exit(124);
}

int main(int argc, char* argv[])
{
	struct sigaction act;
	int status;
	pid_t wpid = 0;
	int fd, i, pid, num = 0, rc = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <file>\n", argv[0]);
		return EXIT_FAILURE;
	}
	fd = open(argv[1], O_RDWR|O_CREAT, (mode_t)0666);
	if (fd < 0) {
		fprintf(stderr, "error open file %s\n", argv[1]);
		return EXIT_FAILURE;
	}

	for (i = 0; i < 2; i++) {
		fflush(stdout);
		pid = fork();
		if (pid && i == 0)
			wpid = pid;
		if (pid == 0)
			wpid = 0;
		if (pid == 0 && i == 0) {
			pid = getpid();

			flock_call(fd, num, FLOCK_GET, err_lock0);

			printf("%d sleeping 1\n", pid);
			sleep(1);

			/* First of all, it should get blocked on flocks[1]
			 * 2nd child. Later, should deadlock with flocks[2]
			 * parent, after cancelling flocks[1] 2nd child. */
			printf("%d: taking lock3 [%llu, %llu]\n", pid,
				(unsigned long long)flocks[3].l_start,
				(unsigned long long)flocks[3].l_start +
				flocks[3].l_len);
			memset(&act, 0, sizeof(act));
			act.sa_handler = catch_alarm;
			sigemptyset(&act.sa_mask);
			sigaddset(&act.sa_mask, SIGALRM);
			if (sigaction(SIGALRM, &act, NULL) < 0) {
				fprintf(stderr, "SIGALRM signal setup failed"
						", errno: %d", errno);
				rc = 3;
				goto err_lock1;
			}
			alarm(5);
			rc = fcntl(fd, F_SETLKW, &flocks[3]);
			if (rc >= 0) {
				fprintf(stderr, "%d: should not succeed to "
						"take lock3\n", pid);

				flock_call(fd, 3, FLOCK_PUT, err_lock1);
				rc = EINVAL;
				goto err_lock1;
			}
			if (errno != EDEADLK) {
				rc = errno;
				fprintf(stderr, "%d: failed to take lock3: "
						"%s\n", pid, strerror(errno));
				goto err_lock1;
			}

			printf("%d: expected deadlock\n", pid);

			flock_call(fd, num, FLOCK_PUT, err_lock0);
			break;
		} else if (pid == 0 && i == 1) {
			pid = getpid();

			flock_call(fd, 1, FLOCK_GET, err_lock0);

			/* Let flocks[2] 2nd child get granted and
			 * flocks[3] 1st child, flocks[0] parent get blocked.*/
			printf("%d sleeping 2\n", pid);
			sleep(2);

			flock_call(fd, 1, FLOCK_PUT, err_lock0);
			break;
		} else if (pid && i == 1) {
			pid = getpid();
			num = 2;

			/* Let flocks[1] 2nd child get granted first */
			printf("%d: sleeping 1\n", pid);
			sleep(1);

			flock_call(fd, num, FLOCK_GET, err_lock0);

			/* Should get blocked on flocks[0], 1st shild
			 * and succeed later. */
			flock_call(fd, 0, FLOCK_GET, err_lock1);

			flock_call(fd, 0, FLOCK_PUT, err_lock1);
			flock_call(fd, num, FLOCK_PUT, err_lock0);
			break;
		}
	}

	if (pid == 0)
		sleep(2);
	if (wpid) {
		waitpid(wpid, &status, 0);
		rc = WEXITSTATUS(status);
	}
	printf("%d Exit\n", pid);
	close(fd);
	return rc;

err_lock1:
	flocks[num].l_type = F_UNLCK;
	fcntl(fd, F_SETLKW, &flocks[num]);
err_lock0:
	close(fd);
	return rc;
}
