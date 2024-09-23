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
#include <sys/time.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/resource.h>

#define MAX_PATH_LENGTH 4096


static double now(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}

/* helper functions */
static int t_fcntl(int fd, int cmd, ...)
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
	case F_OFD_GETLK:
	case F_OFD_SETLKW:
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

static int t_unlink(const char *path)
{
	int rc;

	rc = unlink(path);
	if (rc)
		fprintf(stderr,
			"unlink(%s) error: %s\n", path, strerror(errno));
	return rc;
}

/*
 * test number 1
 * normal flock test
 */
static void t1_usage(void)
{
	fprintf(stderr,
		"usage: flocks_test 1 {on|off} {-c|-f|-l} /path/to/file\n");
}

static int t1(int argc, char *argv[])
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

/*
 * test number 2
 * 2 threads flock ops interweave
 */
struct thread_info {
	struct flock *lock;
	int fd;
	int rc;
} th_data;

static void *t2_thread1(void *arg)
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

static void *t2_thread2(void *arg)
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

static int t2(int argc, char *argv[])
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

/*
 * test number 3
 *
 * Bug 24040: Two conflicting flocks from same process different fds should fail
 *            two conflicting flocks from different processes but same fs
 *            should succeed.
 */
static int t3(int argc, char *argv[])
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

static int t4(int argc, char *argv[])
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

static int t5(int argc, char *argv[])
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

#define	_OPS_FDS	-1

int _op_fds(int num, void *ptr)
{
	static int *fds;
	static int fdn;
	static int cfd;
	static char *name;
	struct rlimit rlb;
	int i;

	if (num == _OPS_FDS)
		return cfd;

	if (ptr) {
		name = ptr;
		cfd = open(name, O_RDWR);
		if (cfd < 0) {
			fprintf(stderr, "Couldn't open file: %s\n", name);
			return -1;
		}
		return 0;
	}

	if (num == 0 && ptr == NULL) {
		for (i = 0; i < fdn; i++)
			if (fds[i])
				close(i);
		free(fds);
		fdn = 0;
		return 0;
	}
	if (num <= 0) /* Invlid value, ignore */
		return 0;

	if (getrlimit(RLIMIT_NOFILE, &rlb)) {
		fprintf(stderr, "Getlimit error: %s|n", strerror(errno));
		return -1;
	}
	if (fdn < rlb.rlim_cur) {
		int count = rlb.rlim_cur;

		fds = realloc(fds, sizeof(int) * count);
		if (fds == NULL) {
			printf("error\n");
			return -1;
		}
		for (i = fdn; i < count; i++)
			fds[i] = 0;
		fdn = count;
	}
	for (i = 0; i < fdn; i++) {
		if (fds[i] == num) {
			cfd = i; /* Already open */
			return 0;
		}
	}
	cfd = open(name, O_RDWR);
	if (cfd < 0) {
		fprintf(stderr, "Couldn't open file: %s(%s)\n",
			name, strerror(errno));
		return -1;
	}
	if (cfd >= fdn) {
		fprintf(stderr, "Open too many files(cur:%d, lmt:%d)\n",
			cfd, fdn);
		return -1;
	}
	fds[cfd] = num;

	return 0;
}

int set_cfd(int fno)
{
	if (fno >= 0)
		return _op_fds(fno + 1, NULL);
	return -1;
}

#define	new_fds(name)	_op_fds(0, name)
#define	get_cfd()	_op_fds(_OPS_FDS, NULL)
#define	put_fds()	_op_fds(0, NULL)

#define	T6BUF_SIZE	200

int set_lock(struct flock *lock, char *buf)
{
	int i, v;
	struct tag_node {
		char    tag;
		int     mode;
	} tags[] = {
		{ 'W', F_WRLCK },
		{ 'R', F_RDLCK },
		{ 'U', F_UNLCK },
		{ 'S', 0 },	// setrlimit
		{ 'F', 0 },	// file select
		{ 'T', 0 },     // test lock
		{ 'P', 0 },     // pause
		{ 0, 0 }
	};

	for (i = 0; isspace(buf[i]) && i < T6BUF_SIZE;)
		i++;
	for (v = 0; tags[v].tag && i < T6BUF_SIZE; v++) {
		if (buf[i] == tags[v].tag) {
			char *head;

			head = buf + i + 1;
			for (; buf[i] != ','; i++)
				if (i >= T6BUF_SIZE)
					break;
			buf[i] = '\0';
			lock->l_start = atol(head);
			if (lock->l_start < 0)
				break;
			/* for special tag */
			if (tags[v].tag == 'S') {
				struct rlimit rlb;

				rlb.rlim_cur = lock->l_start;
				rlb.rlim_max = lock->l_start + 1;
				if (setrlimit(RLIMIT_NOFILE, &rlb)) {
					fprintf(stderr, "Setlimit error: %s\n",
						strerror(errno));
					return -1;
				}
				return 0;
			}
			if (tags[v].tag == 'F')
				return set_cfd(lock->l_start);

			if (tags[v].tag == 'T')
				return 2;

			if (tags[v].tag == 'P') {
				sleep(lock->l_start);
				return 0;
			}

			for (; !isdigit(buf[i]); i++)
				if (i >= T6BUF_SIZE)
					break;
			lock->l_len = atol(buf + i);
			if (lock->l_len <= 0)
				break;
			lock->l_type = tags[v].mode;
			return 1;
		}
	}
	fprintf(stderr, "Invalid line: %s\n", buf);
	return 0;
}

const char * fmode2str(int mode)
{
	static char buf[10];

	if (mode == F_WRLCK) return "W";
	if (mode == F_RDLCK) return "R";
	sprintf(buf, "%d", mode);
	return buf;
}

/*
 *	Read command from stdin then enqueue a lock
 *
 *	[W|R|U]sss,lll
 *	W: write R: read U: unlock
 *	sss: start of range
 *	lll: length of range
 *
 *	for example:
 *		F1		# open/select a fd as current one
 *		W1,100		# add a write lock from 1 to 100
 *		R100,100	# add a read lock from 100 to 199
 *		Gn		# dump lock info(output count n, 0 is all)
 */
static int t6(int argc, char *argv[])
{
	struct flock lock = {
		.l_whence = SEEK_SET,
	};

	int rc = 0;
	char buf[T6BUF_SIZE+1];
	double stime;

	if (argc < 3) {
		fprintf(stderr, "usage: flocks_test 6 file\n");
		return EXIT_FAILURE;
	}

	new_fds(argv[2]);
	if (get_cfd() < 0)
		return EXIT_FAILURE;

	memset(buf, '\0', T6BUF_SIZE + 1);
	stime = now();
	while (fgets(buf, T6BUF_SIZE, stdin)) {
		lock.l_whence = SEEK_SET,
		rc = set_lock(&lock, buf);
		if (rc == 0)
			continue;
		if (rc == -1)
			break;
		if (rc == 2) {
			int fd, i, cnt;

			fd = open(argv[2], O_RDWR);
			if (fd < 0) {
				fprintf(stderr, "Couldn't open file: %s\n",
					argv[2]);
				rc = EXIT_FAILURE;
				break;
			}
			cnt = lock.l_start;
			lock.l_start = 0;
			for (i = 0; cnt == 0 || i < cnt; i++) {
				lock.l_type = F_WRLCK;
				lock.l_len = 0;
				lock.l_pid = 0;
				rc = t_fcntl(fd, F_OFD_GETLK, &lock);
				if (rc != 0) {
					fprintf(stderr, "%d: get lock: %s\n",
						getpid(), strerror(errno));
					rc = EXIT_FAILURE;
					break;
				}
				if (lock.l_type == F_UNLCK)
					break;
				if (i > 0)
					printf(";");
				printf("%s%ld,%ld", fmode2str(lock.l_type),
				       lock.l_start, lock.l_len);
				lock.l_start += lock.l_len;
			}
			if (lock.l_start > 0)
				printf(".\n");
			close(fd);
			if (rc == EXIT_FAILURE)
				break;
			continue;
		}
		rc = t_fcntl(get_cfd(), F_OFD_SETLKW, &lock);
		if (rc != 0) {
			fprintf(stderr, "%d: cannot set lock: %s\n",
				getpid(), strerror(errno));
			rc = EXIT_FAILURE;
			break;
		}
	}
	put_fds();
	fprintf(stderr, "Time for processing %.03lfs\n", now() - stime);
	return rc;
}

static void usage(void)
{
	fprintf(stderr,
		"usage: flocks_test test# [corresponding arguments]\n");
}

/* program entry */
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
	case 6:
		rc = t6(argc, argv);
		break;
	default:
		fprintf(stderr, "unknown test number '%s'\n", argv[1]);
		break;
	}

	if (rc)
		fprintf(stderr, "exiting with rc = %d\n", rc);
	return rc;
}
