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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <stdarg.h>

#define MAX_PATH_LENGTH 4096
/**
 * helper functions
 */
int t_fcntl(int fd, int cmd, ...)
{
	va_list ap;
	long arg;
	struct flock *lock;
	int rc = -1;

	va_start(ap, cmd);
	switch (cmd) {
	case F_GETFL:
		va_end(ap);
		rc = fcntl(fd, cmd);
		if (rc == -1) {
			rc = -errno;
			fprintf(stderr, "fcntl GETFL failed: %s\n",
				strerror(errno));
			return rc;
		}
		break;
	case F_SETFL:
		arg = va_arg(ap, long);
		va_end(ap);
		rc = fcntl(fd, cmd, arg);
		if (rc == -1) {
			rc = -errno;
			fprintf(stderr, "fcntl SETFL %ld failed: %s\n",
				arg, strerror(errno));
			return rc;
		}
		break;
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
		lock = va_arg(ap, struct flock *);
		va_end(ap);
		rc = fcntl(fd, cmd, lock);
		if (rc == -1) {
			rc = -errno;
			fprintf(stderr, "fcntl cmd %d failed: %s\n",
				cmd, strerror(errno));
			return rc;
		}
		break;
	case F_DUPFD:
		arg = va_arg(ap, long);
		va_end(ap);
		rc = fcntl(fd, cmd, arg);
		if (rc == -1) {
			rc = -errno;
			fprintf(stderr, "fcntl F_DUPFD %d failed: %s\n",
				(int)arg, strerror(errno));
			return rc;
		}
		break;
	default:
		va_end(ap);
		fprintf(stderr, "fcntl cmd %d not supported\n", cmd);
		return rc;
	}
	return rc;
}

int t_unlink(const char *path)
{
	int rc;

	rc = unlink(path);
	if (rc)
		fprintf(stderr,
			"unlink(%s) error: %s\n", path, strerror(errno));
	return rc;
}

/** =================================================================
 * test number 1
 *
 * normal flock test
 */
void t1_usage(void)
{
	fprintf(stderr,
		"usage: flocks_test 1 {on|off} {-c|-f|-l} /path/to/file\n");
}

int t1(int argc, char *argv[])
{
	int fd;
	int mount_with_flock = 0;
	int error = 0;
	int rc = 0;

	if (argc != 5) {
		t1_usage();
		return EXIT_FAILURE;
	}

	if (!strncmp(argv[2], "on", 3)) {
		mount_with_flock = 1;
	} else if (!strncmp(argv[2], "off", 4)) {
		mount_with_flock = 0;
	} else {
		t1_usage();
		return EXIT_FAILURE;
	}

	fd = open(argv[4], O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Couldn't open file '%s': %s\n", argv[4],
			strerror(errno));
		return EXIT_FAILURE;
	}

	if (!strncmp(argv[3], "-c", 3)) {
		struct flock fl;

		fl.l_type = F_RDLCK;
		fl.l_whence = SEEK_SET;
		fl.l_start = 0;
		fl.l_len = 1;

		error = fcntl(fd, F_SETLK, &fl);
	} else if (!strncmp(argv[3], "-l", 3)) {
		error = lockf(fd, F_LOCK, 1);
	} else if (!strncmp(argv[3], "-f", 3)) {
		error = flock(fd, LOCK_EX);
	} else {
		t1_usage();
		rc = EXIT_FAILURE;
		goto out;
	}

	if (mount_with_flock)
		rc = ((error == 0) ? EXIT_SUCCESS : EXIT_FAILURE);
	else
		rc = ((error == 0) ? EXIT_FAILURE : EXIT_SUCCESS);

out:
	if (fd >= 0)
		close(fd);
	return rc;
}

/** ===============================================================
 * test number 2
 *
 * 2 threads flock ops interweave
 */
struct thread_info {
	struct flock *lock;
	int fd;
	int rc;
} th_data;

void *t2_thread1(void *arg)
{
	struct thread_info *ti = arg;
	struct flock *lock = ti->lock;
	int fd = ti->fd;

	printf("thread 1: set write lock (blocking): rc = %d\n", ti->rc);
	lock->l_type = F_WRLCK;
	t_fcntl(fd, F_SETLKW, lock);
	printf("thread 1: set write lock done: rc = %d\n", ti->rc);
	(void)t_fcntl(fd, F_GETLK, lock); /* ignore this, operation will fail */
	printf("thread 1: unlock: rc = %d\n", ti->rc);
	lock->l_type = F_UNLCK;
	ti->rc += t_fcntl(fd, F_SETLK, lock);
	printf("thread 1: unlock done: rc = %d\n", ti->rc);

	if (ti->rc)
		fprintf(stdout, "thread1 exiting with rc = %d\n", ti->rc);
	return &ti->rc;
}

void *t2_thread2(void *arg)
{
	struct thread_info *ti = arg;
	struct flock *lock = ti->lock;
	int fd = ti->fd;

	sleep(2);
	printf("thread 2: unlock: rc = %d\n", ti->rc);
	lock->l_type = F_UNLCK;
	ti->rc += t_fcntl(fd, F_SETLK, lock);
	printf("thread 2: unlock done: rc = %d\n", ti->rc);
	printf("thread 2: set write lock (non-blocking): rc = %d\n", ti->rc);
	lock->l_type = F_WRLCK;
	ti->rc += t_fcntl(fd, F_SETLK, lock);
	printf("thread 2: set write lock done: rc = %d\n", ti->rc);
	(void)t_fcntl(fd, F_GETLK, lock); /* ignore this, operation will fail */

	if (ti->rc)
		fprintf(stdout, "thread2 exiting with rc = %d\n", ti->rc);
	return &ti->rc;
}

int t2(int argc, char *argv[])
{
	struct flock lock = {
		.l_type = F_RDLCK,
		.l_whence = SEEK_SET,
	};
	char file[MAX_PATH_LENGTH] = "";
	int  fd, rc;
	pthread_t th1, th2;
	struct thread_info ti;

	snprintf(file, MAX_PATH_LENGTH, "%s/test_t2_file", argv[2]);

	fd = open(file, O_RDWR|O_CREAT, (mode_t)0666);
	if (fd < 0) {
		fprintf(stderr, "error open file '%s': %s\n", file,
			strerror(errno));
		return EXIT_FAILURE;
	}

	t_fcntl(fd, F_SETFL, O_APPEND);
	rc = t_fcntl(fd, F_GETFL);
	if ((rc < 0) || (rc & O_APPEND) == 0) {
		fprintf(stderr, "error get flag: ret %x\n", rc);
		rc = EXIT_FAILURE;
		goto out;
	}

	ti.lock = &lock;
	ti.fd   = fd;
	ti.rc   = 0;
	rc = pthread_create(&th1, NULL, t2_thread1, &ti);
	if (rc) {
		fprintf(stderr, "error create thread 1\n");
		rc = EXIT_FAILURE;
		goto out;
	}
	rc = pthread_create(&th2, NULL, t2_thread2, &ti);
	if (rc) {
		fprintf(stderr, "error create thread 2\n");
		rc = EXIT_FAILURE;
		goto out;
	}
	pthread_join(th1, NULL);
	pthread_join(th2, NULL);
	if (ti.rc)
		rc = EXIT_FAILURE;
out:
	t_unlink(file);
	close(fd);

	return rc;
}

/** =================================================================
 * test number 3
 *
 * Bug 24040: Two conflicting flocks from same process different fds should fail
 *            two conflicting flocks from different processes but same fs
 *            should succeed.
 */
int t3(int argc, char *argv[])
{
	int fd, fd2;
	int pid;
	int rc = EXIT_SUCCESS;

	if (argc != 3) {
		fprintf(stderr, "usage: flocks_test 3 filename\n");
		return EXIT_FAILURE;
	}

	fd = open(argv[2], O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Couldn't open file '%s': %s\n", argv[2],
			strerror(errno));
		return EXIT_FAILURE;
	}
	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		perror("first flock failed");
		rc = EXIT_FAILURE;
		goto out;
	}
	fd2 = open(argv[2], O_RDWR);
	if (fd2 < 0) {
		fprintf(stderr, "Couldn't open file '%s': %s\n", argv[2],
			strerror(errno));
		rc = EXIT_FAILURE;
		goto out;
	}
	if (flock(fd2, LOCK_EX | LOCK_NB) >= 0) {
		fprintf(stderr, "Second flock succeeded - FAIL\n");
		rc = EXIT_FAILURE;
		close(fd2);
		goto out;
	}

	close(fd2);

	pid = fork();
	if (pid == -1) {
		perror("fork");
		rc = EXIT_FAILURE;
		goto out;
	}

	if (pid == 0) {
		fd2 = open(argv[2], O_RDWR);
		if (fd2 < 0) {
			fprintf(stderr, "Couldn't open file '%s': %s\n",
				argv[1], strerror(errno));
			rc = EXIT_FAILURE;
			goto out;
		}
		if (flock(fd2, LOCK_EX | LOCK_NB) >= 0) {
			fprintf(stderr, "Second flock succeeded - FAIL\n");
			rc = EXIT_FAILURE;
			goto out_child;
		}
		if (flock(fd, LOCK_UN) == -1) {
			fprintf(stderr, "Child unlock on parent fd failed\n");
			rc = EXIT_FAILURE;
			goto out_child;
		}
		if (flock(fd2, LOCK_EX | LOCK_NB) == -1) {
			fprintf(stderr, "Relock after parent unlock failed!\n");
			rc = EXIT_FAILURE;
			goto out_child;
		}
	out_child:
		close(fd2);
		exit(rc);
	}

	waitpid(pid, &rc, 0);
out:
	close(fd);
	return rc;
}

int t4(int argc, char *argv[])
{
	struct flock lock = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 10,
	};

	int fd, fd2;
	pid_t child_pid;
	int child_status;
	int rc = EXIT_SUCCESS;

	if (argc != 4) {
		fprintf(stderr, "usage: flocks_test 4 file1 file2\n");
		return EXIT_FAILURE;
	}

	fd = open(argv[2], O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Couldn't open file: %s\n", argv[2]);
		return EXIT_FAILURE;
	}
	fd2 = open(argv[3], O_RDWR);
	if (fd2 < 0) {
		fprintf(stderr, "Couldn't open file: %s\n", argv[3]);
		rc = EXIT_FAILURE;
		goto out;
	}

	child_pid = fork();
	if (child_pid < 0) {
		perror("fork");
		rc = EXIT_FAILURE;
		goto out;
	}

	if (child_pid == 0) {
		printf("%d: get lock1\n", getpid());
		fflush(stdout);
		if (t_fcntl(fd, F_SETLKW, &lock) < 0) {
			fprintf(stderr, "%d: cannot get lock1: %s\n",
				getpid(), strerror(errno));
			rc = EXIT_FAILURE;
			goto out_child;
		}
		printf("%d: done\n", getpid());
		sleep(3);
		printf("%d: get lock2\n", getpid());
		fflush(stdout);
		if (t_fcntl(fd2, F_SETLKW, &lock) < 0) {
			fprintf(stderr, "%d: cannot get lock2: %s\n",
				getpid(), strerror(errno));

			if (errno == EDEADLK)
				rc = EXIT_SUCCESS;
			else
				rc = EXIT_FAILURE;

			goto out_child;
		}
		printf("%d: done\n", getpid());
out_child:
		printf("%d: exit rc=%d\n", getpid(), rc);
		exit(rc);
	} else {
		printf("%d: get lock2\n", getpid());
		fflush(stdout);
		if (t_fcntl(fd2, F_SETLKW, &lock) < 0) {
			fprintf(stderr, "%d: cannot get lock2: %s\n",
				getpid(), strerror(errno));
			rc = EXIT_FAILURE;
			goto out;
		}
		printf("%d: done\n", getpid());
		sleep(3);
		printf("%d: get lock1\n", getpid());
		fflush(stdout);
		if (t_fcntl(fd, F_SETLKW, &lock) < 0) {
			fprintf(stderr, "%d: cannot get lock1: %s\n",
				getpid(), strerror(errno));

			if (errno != EDEADLK) {
				rc = EXIT_FAILURE;
				goto out;
			}
		}
		printf("%d: done\n", getpid());
	}

	sleep(1);

	if (close(fd) < 0) {
		fprintf(stderr, "%d: error closing file1: %s\n",
			getpid(), strerror(errno));
		rc = EXIT_FAILURE;
	}

	if (close(fd2) < 0) {
		fprintf(stderr, "%d: error closing file2: %s\n",
			getpid(), strerror(errno));
		rc = EXIT_FAILURE;
	}

	if (waitpid(child_pid, &child_status, 0) < 0) {
		fprintf(stderr, "%d: cannot get termination status of %d: %s\n",
			getpid(), child_pid, strerror(errno));
		rc = EXIT_FAILURE;
	} else if (!WIFEXITED(child_status)) {
		fprintf(stderr, "%d: child %d terminated with status %d\n",
			getpid(), child_pid, child_status);
		rc = EXIT_FAILURE;
	} else {
		rc = WEXITSTATUS(child_status);
	}

out:
	printf("%d: exit rc=%d\n", getpid(), rc);
	return rc;
}

#define T5_USAGE							      \
"usage: flocks_test 5 {set|get|unlock} [read|write] [sleep N] file1\n"	      \
"       set: F_SETLKW F_WRLCK\n"					      \
"       get: F_GETLK F_WRLCK  (conflict)\n"				      \
"       unlock: F_SETLKW F_UNLCK\n"					      \
"       read|write: lock mode, write by default\n"			      \
"       sleep N: sleep for N secs after fcntl\n"			      \
"       file1: fcntl is called for this file\n"

int t5(int argc, char *argv[])
{
	struct flock lock = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
	};

	int setlk = 0, getlk = 0, unlk = 0, secs = 0;
	int pos;
	int fd;
	int rc = 0;

	if (argc < 4 || argc > 7) {
		fprintf(stderr, T5_USAGE);
		return EXIT_FAILURE;
	}

	if (!strncmp(argv[2], "set", 4))
		setlk = 1;
	else if (!strncmp(argv[2], "get", 4))
		getlk = 1;
	else if (!strncmp(argv[2], "unlock", 7))
		unlk = 1;
	else {
		fprintf(stderr, "Wrong 2nd argument: %s\n", argv[2]);
		return EXIT_FAILURE;
	}

	pos = 3;

	if (!strncmp(argv[pos], "read", 5)) {
		lock.l_type = F_RDLCK;
		pos++;
	} else if (!strncmp(argv[pos], "write", 6)) {
		lock.l_type = F_WRLCK;
		pos++;
	}

	if (!strncmp(argv[pos], "sleep", 6)) {
		secs = atoi(argv[pos + 1]);
		if (secs < 0 || secs > 10) {
			fprintf(stderr, "Sleep argument is wrong: %s\n",
				argv[pos + 1]);
			return EXIT_FAILURE;
		}
		pos += 2;
	}

	fd = open(argv[pos], O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Couldn't open file: %s\n", argv[pos]);
		return EXIT_FAILURE;
	}

	fprintf(stderr, "\nFLOCKS_TEST 5: %s %s flock\n",
		setlk ? "SET" : getlk ? "GET" : "UNLOCK",
		lock.l_type == F_WRLCK ? "write" : "read");

	if (setlk) {
		rc = t_fcntl(fd, F_SETLKW, &lock);
	} else if (getlk) {
		rc = t_fcntl(fd, F_GETLK, &lock);
	} else if (unlk) {
		lock.l_type = F_UNLCK;
		rc = t_fcntl(fd, F_SETLKW, &lock);
	}

	if (secs)
		sleep(secs);

	close(fd);
	return rc < 0 ? -rc : 0;

}

/** ==============================================================
 * program entry
 */
void usage(void)
{
	fprintf(stderr,
		"usage: flocks_test test# [corresponding arguments]\n");
}

int main(int argc, char *argv[])
{
	int rc = EXIT_SUCCESS;

	if (argc < 2) {
		usage();
		exit(EXIT_FAILURE);
	}

	switch (atoi(argv[1])) {
	case 1:
		rc = t1(argc, argv);
		break;
	case 2:
		rc = t2(argc, argv);
		break;
	case 3:
		rc = t3(argc, argv);
		break;
	case 4:
		rc = t4(argc, argv);
		break;
	case 5:
		rc = t5(argc, argv);
		break;
	default:
		fprintf(stderr, "unknown test number '%s'\n", argv[1]);
		break;
	}

	if (rc)
		fprintf(stderr, "exiting with rc = %d\n", rc);
	return rc;
}
