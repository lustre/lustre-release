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
 * Copyright 2014 Cray Inc, all rights reserved.
 * Author: Frank Zago.
 *
 * A few portions are extracted from llapi_layout_test.c
 *
 * The purpose of this test is to exert the group lock ioctls.
 *
 * The program will exit as soon as a non zero error code is returned.
 */

#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <poll.h>

#include <lustre/lustreapi.h>
#include <lustre/lustre_idl.h>

#define ERROR(fmt, ...)							\
	fprintf(stderr, "%s: %s:%d: %s: " fmt "\n",			\
		program_invocation_short_name, __FILE__, __LINE__,	\
		__func__, ## __VA_ARGS__);

#define DIE(fmt, ...)				\
	do {					\
		ERROR(fmt, ## __VA_ARGS__);	\
		exit(EXIT_FAILURE);		\
	} while (0)

#define ASSERTF(cond, fmt, ...)						\
	do {								\
		if (!(cond))						\
			DIE("assertion '%s' failed: "fmt,		\
			    #cond, ## __VA_ARGS__);			\
	} while (0)

#define PERFORM(testfn) \
	do {								\
		fprintf(stderr, "Starting test " #testfn " at %lld\n",	\
			(unsigned long long)time(NULL));		\
		testfn();						\
		fprintf(stderr, "Finishing test " #testfn " at %lld\n",	\
			(unsigned long long)time(NULL));		\
	} while (0)

/* Name of file/directory. Will be set once and will not change. */
static char mainpath[PATH_MAX];
static const char *maindir = "group_lock_test_name_9585766";

static char fsmountdir[PATH_MAX];	/* Lustre mountpoint */
static char *lustre_dir;		/* Test directory inside Lustre */

/* Cleanup our test file. */
static void cleanup(void)
{
	unlink(mainpath);
	rmdir(mainpath);
}

/* Test lock / unlock */
static void test10(void)
{
	int rc;
	int fd;
	int gid;
	int i;

	cleanup();

	/* Create the test file, and open it. */
	fd = creat(mainpath, 0);
	ASSERTF(fd >= 0, "creat failed for '%s': %s",
		mainpath, strerror(errno));

	/* Valid command first. */
	gid = 1234;
	rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
	ASSERTF(rc == 0, "cannot lock '%s': %s",
		mainpath, strerror(errno));
	rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);
	ASSERTF(rc == 0, "cannot unlock '%s': %s",
		mainpath, strerror(errno));

	/* Again */
	gid = 768;
	for (i = 0; i < 1000; i++) {
		rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
		ASSERTF(rc == 0,
			"cannot lock '%s': %s (loop %d)",
			mainpath, strerror(errno), i);
		rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);
		ASSERTF(rc == 0,
			"cannot unlock '%s': %s (loop %d)",
			mainpath, strerror(errno), i);
	}

	/* Lock twice. */
	gid = 97486;
	rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
	ASSERTF(rc == 0, "cannot lock '%s': %s", mainpath, strerror(errno));
	rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
	ASSERTF(rc == -1 && errno == EINVAL,
		"lock unexpectedly granted for '%s': %s",
		mainpath, strerror(errno));
	rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);
	ASSERTF(rc == 0, "cannot unlock '%s': %s", mainpath, strerror(errno));
	rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);
	ASSERTF(rc == -1 && errno == EINVAL, "unexpected unlock retval: %d %s",
		rc, strerror(errno));

	/* 0 is an invalid gid */
	gid = 0;
	rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
	ASSERTF(rc == -1 && errno == EINVAL, "unexpected lock retval: %s",
		strerror(errno));

	/* Lock/unlock with a different gid */
	gid = 3543;
	rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
	ASSERTF(rc == 0, "cannot lock '%s': %s", mainpath, strerror(errno));
	for (gid = -10; gid < 10; gid++) {
		rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);
		ASSERTF(rc == -1 && errno == EINVAL,
			"unexpected unlock retval: %d %s (gid %d)",
			rc, strerror(errno), gid);
	}
	gid = 3543;
	rc = ioctl(fd, LL_IOC_GROUP_UNLOCK, gid);
	ASSERTF(rc == 0, "cannot unlock '%s': %s", mainpath, strerror(errno));

	close(fd);
}

/* Test open/lock/close without unlocking */
static void test11(void)
{
	int rc;
	int fd;
	int gid;
	char buf[10000];

	cleanup();

	/* Create the test file. */
	fd = creat(mainpath, 0);
	ASSERTF(fd >= 0, "creat failed for '%s': %s",
		mainpath, strerror(errno));
	memset(buf, 0x5a, sizeof(buf));
	rc = write(fd, buf, sizeof(buf));
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));
	close(fd);

	/* Open/lock and close many times. Open with different
	 * flags. */
	for (gid = 1; gid < 10000; gid++) {
		int oflags = O_RDONLY;

		switch (gid % 10) {
		case 0:
			oflags = O_RDONLY;
			break;
		case 1:
			oflags = O_WRONLY;
			break;
		case 2:
			oflags = O_WRONLY | O_APPEND;
			break;
		case 3:
			oflags = O_WRONLY | O_CLOEXEC;
			break;
		case 4:
			oflags = O_WRONLY | O_DIRECT;
			break;
		case 5:
			oflags = O_WRONLY | O_NOATIME;
			break;
		case 6:
			oflags = O_WRONLY | O_SYNC;
			break;
		case 7:
			oflags = O_RDONLY | O_DIRECT;
			break;
		case 8:
			oflags = O_RDWR;
			break;
		case 9:
			oflags = O_RDONLY | O_LOV_DELAY_CREATE;
			break;
		}

		fd = open(mainpath, oflags);
		ASSERTF(fd >= 0, "open failed for '%s': %s (oflags=%d, gid=%d)",
			mainpath, strerror(errno), oflags, gid);

		rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
		ASSERTF(rc == 0, "cannot lock '%s': %s (oflags=%d, gid=%d)",
			mainpath, strerror(errno), oflags, gid);

		close(fd);
	}

	cleanup();
}

static void helper_test20(int fd)
{
	int gid;
	int rc;

	gid = 1234;
	rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
	ASSERTF(rc == -1 && errno == ENOTTY, "unexpected retval: %d %s",
		rc, strerror(errno));

	gid = 0;
	rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
	ASSERTF(rc == -1 && errno == ENOTTY, "unexpected retval: %d %s",
		rc, strerror(errno));

	gid = 1;
	rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
	ASSERTF(rc == -1 && errno == ENOTTY, "unexpected retval: %d %s",
		rc, strerror(errno));

	gid = -1;
	rc = ioctl(fd, LL_IOC_GROUP_LOCK, gid);
	ASSERTF(rc == -1 && errno == ENOTTY, "unexpected retval: %d %s",
		rc, strerror(errno));
}

/* Test lock / unlock on a directory */
static void test20(void)
{
	int fd;
	int rc;
	char dname[PATH_MAX];

	cleanup();

	/* Try the mountpoint. Should fail. */
	fd = open(fsmountdir, O_RDONLY | O_DIRECTORY);
	ASSERTF(fd >= 0, "open failed for '%s': %s", mainpath, strerror(errno));
	helper_test20(fd);
	close(fd);

	/* Try .lustre/ . Should fail. */
	rc = snprintf(dname, sizeof(dname), "%s/.lustre", fsmountdir);
	ASSERTF(rc < sizeof(dname), "Name too long");

	fd = open(fsmountdir, O_RDONLY | O_DIRECTORY);
	ASSERTF(fd >= 0, "open failed for '%s': %s", mainpath, strerror(errno));
	helper_test20(fd);
	close(fd);

	/* A regular directory. */
	rc = mkdir(mainpath, 0600);
	ASSERTF(fd >= 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd = open(mainpath, O_RDONLY | O_DIRECTORY);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));
	helper_test20(fd);
	close(fd);
}

/* Test locking between several fds. */
static void test30(void)
{
	int fd1;
	int fd2;
	int gid;
	int gid2;
	int rc;

	cleanup();

	/* Create the test file, and open it. */
	fd1 = creat(mainpath, 0);
	ASSERTF(fd1 >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	/* Open a second time in non blocking mode. */
	fd2 = open(mainpath, O_RDWR | O_NONBLOCK);
	ASSERTF(fd2 >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	/* Valid command first. */
	gid = 1234;
	rc = ioctl(fd1, LL_IOC_GROUP_LOCK, gid);
	ASSERTF(rc == 0, "cannot lock '%s': %s", mainpath, strerror(errno));
	rc = ioctl(fd1, LL_IOC_GROUP_UNLOCK, gid);
	ASSERTF(rc == 0, "cannot unlock '%s': %s", mainpath, strerror(errno));

	/* Lock on one fd, unlock on the other */
	gid = 6947556;
	rc = ioctl(fd1, LL_IOC_GROUP_LOCK, gid);
	ASSERTF(rc == 0, "cannot lock '%s': %s", mainpath, strerror(errno));
	rc = ioctl(fd2, LL_IOC_GROUP_UNLOCK, gid);
	ASSERTF(rc == -1 && errno == EINVAL,
		"unexpected unlock retval: %d %s", rc, strerror(errno));
	rc = ioctl(fd1, LL_IOC_GROUP_UNLOCK, gid);
	ASSERTF(rc == 0, "cannot unlock '%s': %s", mainpath, strerror(errno));

	/* Lock from both */
	gid = 89489665;
	rc = ioctl(fd1, LL_IOC_GROUP_LOCK, gid);
	ASSERTF(rc == 0, "cannot lock '%s': %s", mainpath, strerror(errno));
	rc = ioctl(fd2, LL_IOC_GROUP_LOCK, gid);
	ASSERTF(rc == 0, "cannot lock '%s': %s", mainpath, strerror(errno));
	rc = ioctl(fd2, LL_IOC_GROUP_UNLOCK, gid);
	ASSERTF(rc == 0, "cannot unlock '%s': %s", mainpath, strerror(errno));
	rc = ioctl(fd1, LL_IOC_GROUP_UNLOCK, gid);
	ASSERTF(rc == 0, "cannot unlock '%s': %s", mainpath, strerror(errno));

	/* Lock from both. Unlock in reverse order. */
	gid = 89489665;
	rc = ioctl(fd1, LL_IOC_GROUP_LOCK, gid);
	ASSERTF(rc == 0, "cannot lock '%s': %s", mainpath, strerror(errno));
	rc = ioctl(fd2, LL_IOC_GROUP_LOCK, gid);
	ASSERTF(rc == 0, "cannot lock '%s': %s", mainpath, strerror(errno));
	rc = ioctl(fd1, LL_IOC_GROUP_UNLOCK, gid);
	ASSERTF(rc == 0, "cannot unlock '%s': %s", mainpath, strerror(errno));
	rc = ioctl(fd2, LL_IOC_GROUP_UNLOCK, gid);
	ASSERTF(rc == 0, "cannot unlock '%s': %s", mainpath, strerror(errno));

	/* Try to lock with different gids */
	gid = 89489665;
	rc = ioctl(fd1, LL_IOC_GROUP_LOCK, gid);
	ASSERTF(rc == 0, "cannot lock '%s': %s", mainpath, strerror(errno));
	for (gid2 = -50; gid2 < 50; gid2++) {
		rc = ioctl(fd2, LL_IOC_GROUP_LOCK, gid2);
		if (gid2 == 0)
			ASSERTF(rc == -1 && errno == EINVAL,
				"unexpected lock retval for gid %d: %s",
				gid2, strerror(errno));
		else
			ASSERTF(rc == -1 && errno == EAGAIN,
				"unexpected lock retval for gid %d: %s",
				gid2, strerror(errno));
	}
	rc = ioctl(fd1, LL_IOC_GROUP_UNLOCK, gid);
	ASSERTF(rc == 0, "cannot unlock '%s': %s",
		mainpath, strerror(errno));

	close(fd1);
	close(fd2);
}

static void usage(char *prog)
{
	fprintf(stderr, "Usage: %s [-d lustre_dir]\n", prog);
	exit(EXIT_FAILURE);
}

static void process_args(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "d:")) != -1) {
		switch (c) {
		case 'd':
			lustre_dir = optarg;
			break;
		case '?':
		default:
			fprintf(stderr, "Unknown option '%c'\n", optopt);
			usage(argv[0]);
			break;
		}
	}
}

int main(int argc, char *argv[])
{
	char fsname[8];
	int rc;

	process_args(argc, argv);
	if (lustre_dir == NULL)
		lustre_dir = "/mnt/lustre";

	rc = llapi_search_mounts(lustre_dir, 0, fsmountdir, fsname);
	if (rc != 0) {
		fprintf(stderr, "Error: '%s': not a Lustre filesystem\n",
			lustre_dir);
		return EXIT_FAILURE;
	}

	/* Play nice with Lustre test scripts. Non-line buffered output
	 * stream under I/O redirection may appear incorrectly. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	/* Create a test filename and reuse it. Remove possibly old files. */
	rc = snprintf(mainpath, sizeof(mainpath), "%s/%s", lustre_dir, maindir);
	ASSERTF(rc > 0 && rc < sizeof(mainpath), "invalid name for mainpath");
	cleanup();

	atexit(cleanup);

	PERFORM(test10);
	PERFORM(test11);
	PERFORM(test20);
	PERFORM(test30);

	return EXIT_SUCCESS;
}
