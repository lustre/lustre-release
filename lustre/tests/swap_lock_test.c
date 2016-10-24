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
 * Copyright 2015 Cray Inc, all rights reserved.
 * Author: Frank Zago.
 *
 * A few portions are extracted from llapi_layout_test.c
 *
 * The purpose of this test is to exert the layout swap function, with
 * locking.
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
#include <time.h>

#include <lustre/lustreapi.h>

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
		cleanup();						\
		testfn();						\
		cleanup();						\
		fprintf(stderr, "Finishing test " #testfn " at %lld\n",	\
			(unsigned long long)time(NULL));		\
	} while (0)

/* Name of file/directory. Will be set once and will not change. */
static char mainpath[PATH_MAX];
static const char *maindir = "swap_lock_test_dir_4525654";

static char fsmountdir[PATH_MAX];	/* Lustre mountpoint */
static char *lustre_dir;		/* Test directory inside Lustre */

/* Cleanup our test directory. */
static void cleanup(void)
{
	char cmd[PATH_MAX];
	int rc;

	rc = snprintf(cmd, sizeof(cmd), "rm -rf -- '%s'", mainpath);
	ASSERTF(rc > 0 && rc < sizeof(cmd),
		"invalid delete command for path '%s'", mainpath);
	rc = system(cmd);
	ASSERTF(rc != -1, "Cannot execute rm command");
	ASSERTF(WEXITSTATUS(rc) == 0,
		"rm command returned %d", WEXITSTATUS(rc));
}

/* Create a filename inside the test directory. Will assert on
 * error. */
static char *create_file_name(const char *name)
{
	char *filename;
	int rc;

	rc = asprintf(&filename, "%s/%s/%s", lustre_dir, maindir, name);
	ASSERTF(rc > 0, "can't make filename for '%s'", name);

	return filename;
}

/* Create a file of a given size in the test directory, filed with
 * c. Will assert on error. */
int create_file(const char *name, size_t size, unsigned char c)
{
	int fd;
	char *filename;
	int rc;
	char buf[64*1024];

	filename = create_file_name(name);

	fd = open(filename, O_CREAT|O_TRUNC|O_RDWR, 0600);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		filename, strerror(errno));

	free(filename);

	/* Fill-up the new file. */
	memset(buf, c, sizeof(buf));

	while (size) {
		size_t to_write = size;

		if (to_write > sizeof(buf))
			to_write = sizeof(buf);

		rc = write(fd, buf, to_write);
		ASSERTF(rc > 0, "writing %zu bytes to '%s' failed: %s",
			to_write, name, strerror(errno));

		size -= to_write;
	}

	return fd;
}

/* Test basic swap */
static void test10(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;
	struct stat stbuf;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = create_file("foo2", foo2_size, 'y');

	rc = llapi_fswap_layouts(fd1, fd2, 0, 0, 0);
	ASSERTF(rc == 0, "llapi_fswap_layouts failed: %s",
		strerror(-rc));

	rc = fstat(fd1, &stbuf);
	ASSERTF(rc == 0, "stat failed on 'foo1': %s", strerror(errno));
	ASSERTF(stbuf.st_size == foo2_size,
		"invalid size found: %llu instead of %zu",
		(unsigned long long)stbuf.st_size, foo2_size);

	rc = fstat(fd2, &stbuf);
	ASSERTF(rc == 0, "stat failed on 'foo2': %s", strerror(errno));
	ASSERTF(stbuf.st_size == foo1_size,
		"invalid size found: %llu instead of %zu",
		(unsigned long long)stbuf.st_size, foo1_size);

	close(fd1);
	close(fd2);
}

/* Test self swap. It's a no-op and will always succeed. */
static void test11(void)
{
	int rc;
	int fd1;
	size_t foo1_size = 2000;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');

	rc = llapi_fswap_layouts(fd1, fd1, 0, 0, 0);
	ASSERTF(rc == 0, "llapi_fswap_layouts failed: %s",
		strerror(-rc));

	close(fd1);
}

/* Test self swap, on different handles. It's a no-op and will always
 * succeed. */
static void test12(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = dup(fd1);
	ASSERTF(fd2 != -1, "dup failed:  %s", strerror(errno));

	rc = llapi_fswap_layouts(fd1, fd2, 0, 0, 0);
	ASSERTF(rc == 0, "llapi_fswap_layouts failed: %s",
		strerror(-rc));

	close(fd1);
	close(fd2);
}

/* Swap with a non Lustre file */
static void test13(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');

	fd2 = open("/dev/null", O_RDWR);
	ASSERTF(fd2 != -1, "open '/dev/null/' failed:  %s", strerror(errno));

	/* Note that the returned error will be different for both
	 * operations. In the first swap, fd1 is on Lustre, so the
	 * ioctl will succeed, but its processing will eventually fail
	 * because fd2 is not on Lustre. In the second swap, the ioctl
	 * request is unknown, so ioctl() will directly fail. */
	rc = llapi_fswap_layouts(fd1, fd2, 0, 0, 0);
	ASSERTF(rc == -EINVAL, "llapi_fswap_layouts failed: %s",
		strerror(-rc));

	rc = llapi_fswap_layouts(fd2, fd1, 0, 0, 0);
	ASSERTF(rc == -ENOTTY, "llapi_fswap_layouts failed: %s",
		strerror(-rc));

	close(fd1);
	close(fd2);
}

/* Swap with bogus values */
static void test14(void)
{
	int rc;

	rc = llapi_fswap_layouts(-6, -2, 0, 0, 0);
	ASSERTF(rc == -EBADF, "llapi_fswap_layouts failed: %s",
		strerror(-rc));

	/* When run under a shell, rc is -EINVAL. When run under
	 * Lustre test suite, stdin is redirected, and rc is
	 * -ENOTTY. Catch both cases. */
	rc = llapi_fswap_layouts(0, 0, 0, 0, 0);
	ASSERTF(rc == -EINVAL || rc == -ENOTTY,
		"llapi_fswap_layouts failed: %s",
		strerror(-rc));

	rc = llapi_fswap_layouts(456789076, 234567895, 0, 0, 0);
	ASSERTF(rc == -EBADF, "llapi_fswap_layouts failed: %s",
		strerror(-rc));
}

/* Lease only test. */
static void test15(void)
{
	int rc;
	char *filename;
	int fd;
	int i;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	filename = create_file_name("foo1");

	fd = create_file("foo1", 1000, 'x');

	rc = llapi_lease_get(fd, LL_LEASE_RDLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", filename, strerror(-rc));

	close(fd);

	/* Read lease on read file */
	fd = open(filename, O_RDONLY);
	ASSERTF(fd >= 0, "open failed for '%s': %s", filename, strerror(errno));

	rc = llapi_lease_get(fd, LL_LEASE_RDLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_check(fd);
	ASSERTF(rc == LL_LEASE_RDLCK,
		"invalid lease type on '%s': %s", filename, strerror(-rc));

	close(fd);

	/* Write lease on write file */
	fd = open(filename, O_WRONLY);
	ASSERTF(fd >= 0, "open failed for '%s': %s", filename, strerror(errno));

	rc = llapi_lease_get(fd, LL_LEASE_WRLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_check(fd);
	ASSERTF(rc == LL_LEASE_WRLCK,
		"invalid lease type on '%s': %s", filename, strerror(-rc));

	close(fd);

	/* Read lease on read/write file */
	fd = open(filename, O_RDWR);
	ASSERTF(fd >= 0, "open failed for '%s': %s", filename, strerror(errno));

	rc = llapi_lease_get(fd, LL_LEASE_RDLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_check(fd);
	ASSERTF(rc == LL_LEASE_RDLCK,
		"invalid lease type on '%s': %s", filename, strerror(-rc));

	close(fd);

	/* Write lease on read/write file */
	fd = open(filename, O_RDWR);
	ASSERTF(fd >= 0, "open failed for '%s': %s", filename, strerror(errno));

	rc = llapi_lease_get(fd, LL_LEASE_WRLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_check(fd);
	ASSERTF(rc == LL_LEASE_WRLCK,
		"invalid lease type on '%s': %s", filename, strerror(-rc));

	close(fd);

	/* Read lease on write only file */
	fd = open(filename, O_WRONLY);
	ASSERTF(fd >= 0, "open failed for '%s': %s", filename, strerror(errno));

	rc = llapi_lease_get(fd, LL_LEASE_RDLCK);
	ASSERTF(rc == -EPERM, "cannot get lease '%s': %s",
		filename, strerror(-rc));

	rc = llapi_lease_check(fd);
	ASSERTF(rc == 0,
		"invalid lease type on '%s': %s", filename, strerror(-rc));

	close(fd);

	/* Write lease on read only file */
	fd = open(filename, O_RDONLY);
	ASSERTF(fd >= 0, "open failed for '%s': %s", filename, strerror(errno));

	rc = llapi_lease_get(fd, LL_LEASE_WRLCK);
	ASSERTF(rc == -EPERM, "cannot get lease '%s': %s",
		filename, strerror(-rc));

	rc = llapi_lease_check(fd);
	ASSERTF(rc == 0,
		"invalid lease type on '%s': %s", filename, strerror(-rc));

	close(fd);

	/* Get read lease again */
	fd = open(filename, O_RDWR);
	ASSERTF(fd >= 0, "open failed for '%s': %s", filename, strerror(errno));

	rc = llapi_lease_get(fd, LL_LEASE_RDLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_get(fd, LL_LEASE_RDLCK);
	ASSERTF(rc == -EBUSY, "can get lease '%s': %s",
		filename, strerror(-rc));

	rc = llapi_lease_check(fd);
	ASSERTF(rc == LL_LEASE_RDLCK,
		"invalid lease type on '%s': %s", filename, strerror(-rc));

	close(fd);

	/* Get write lease again */
	fd = open(filename, O_RDWR);
	ASSERTF(fd >= 0, "open failed for '%s': %s", filename, strerror(errno));

	rc = llapi_lease_get(fd, LL_LEASE_WRLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_get(fd, LL_LEASE_WRLCK);
	ASSERTF(rc == -EBUSY, "can get lease '%s': %s",
		filename, strerror(-rc));

	rc = llapi_lease_check(fd);
	ASSERTF(rc == LL_LEASE_WRLCK,
		"invalid lease type on '%s': %s", filename, strerror(-rc));

	close(fd);

	/* Get a lease, release and get again */
	fd = open(filename, O_RDWR);
	ASSERTF(fd >= 0, "open failed for '%s': %s", filename, strerror(errno));

	rc = llapi_lease_get(fd, LL_LEASE_RDLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_check(fd);
	ASSERTF(rc == LL_LEASE_RDLCK,
		"invalid lease type on '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_put(fd);
	ASSERTF(rc == LL_LEASE_RDLCK, "was not able to put back lease '%s': %s",
		filename, strerror(-rc));

	rc = llapi_lease_check(fd);
	ASSERTF(rc == 0,
		"invalid lease type on '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_get(fd, LL_LEASE_RDLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", filename, strerror(-rc));

	close(fd);

	/* Get a write lease, release and get again */
	fd = open(filename, O_RDWR);
	ASSERTF(fd >= 0, "open failed for '%s': %s", filename, strerror(errno));

	rc = llapi_lease_get(fd, LL_LEASE_WRLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_check(fd);
	ASSERTF(rc == LL_LEASE_WRLCK,
		"invalid lease type on '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_put(fd);
	ASSERTF(rc == LL_LEASE_WRLCK, "was not able to put back lease '%s': %s",
		filename, strerror(-rc));

	rc = llapi_lease_check(fd);
	ASSERTF(rc == 0,
		"invalid lease type on '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_get(fd, LL_LEASE_WRLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", filename, strerror(-rc));

	close(fd);

	/* Get and put lease in a loop */
	fd = open(filename, O_RDWR);
	ASSERTF(fd >= 0, "open failed for '%s': %s", filename, strerror(errno));

	for (i = 0; i < 1000; i++) {
		rc = llapi_lease_get(fd, LL_LEASE_WRLCK);
		ASSERTF(rc == 0, "cannot get lease '%s': %s",
			filename, strerror(-rc));

		rc = llapi_lease_put(fd);
		ASSERTF(rc == LL_LEASE_WRLCK,
			"was not able to put back lease '%s': %s",
			filename, strerror(-rc));

		rc = llapi_lease_get(fd, LL_LEASE_RDLCK);
		ASSERTF(rc == 0, "cannot get lease '%s': %s",
			filename, strerror(-rc));

		rc = llapi_lease_put(fd);
		ASSERTF(rc == LL_LEASE_RDLCK,
			"was not able to put back lease '%s': %s",
			filename, strerror(-rc));
	}

	close(fd);

	/* Get a write lease, release and take a read one */
	fd = open(filename, O_RDWR);
	ASSERTF(fd >= 0, "open failed for '%s': %s", filename, strerror(errno));

	rc = llapi_lease_get(fd, LL_LEASE_WRLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_check(fd);
	ASSERTF(rc == LL_LEASE_WRLCK,
		"invalid lease type on '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_put(fd);
	ASSERTF(rc == LL_LEASE_WRLCK, "was not able to put back lease '%s': %s",
		filename, strerror(-rc));

	rc = llapi_lease_check(fd);
	ASSERTF(rc == 0,
		"invalid lease type on '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_get(fd, LL_LEASE_RDLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", filename, strerror(-rc));

	close(fd);

	/* Get a read lease, release and take a write one */
	fd = open(filename, O_RDWR);
	ASSERTF(fd >= 0, "open failed for '%s': %s", filename, strerror(errno));

	rc = llapi_lease_get(fd, LL_LEASE_RDLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_check(fd);
	ASSERTF(rc == LL_LEASE_RDLCK,
		"invalid lease type on '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_put(fd);
	ASSERTF(rc == LL_LEASE_RDLCK, "was not able to put back lease '%s': %s",
		filename, strerror(-rc));

	rc = llapi_lease_check(fd);
	ASSERTF(rc == 0,
		"invalid lease type on '%s': %s", filename, strerror(-rc));

	rc = llapi_lease_get(fd, LL_LEASE_WRLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", filename, strerror(-rc));

	close(fd);

	free(filename);
}

/* Lease on file opened by FID */
static void test16(void)
{
	int rc;
	char *filename;
	int fd;
	lustre_fid fid;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	filename = create_file_name("foo1");

	fd = create_file("foo1", 1000, 'x');

	rc = llapi_path2fid(filename, &fid);
	ASSERTF(rc == 0, "llapi_path2fid failed for '%s': %s",
		filename, strerror(-rc));

	close(fd);

	fd = llapi_open_by_fid(fsmountdir, &fid,
			       O_RDWR | O_NOATIME | O_NONBLOCK | O_NOFOLLOW);
	ASSERTF(fd >= 0, "open failed for '%s': %s", filename, strerror(errno));

	rc = llapi_lease_get(fd, LL_LEASE_RDLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", filename, strerror(-rc));

	close(fd);

	free(filename);
}

/* Lease on directories */
static void test17(void)
{
	int rc;
	int fd;

	/* On a directory */
	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd = open(mainpath, O_DIRECTORY);
	ASSERTF(fd >= 0, "open failed for '%s': %s", mainpath, strerror(errno));

	rc = llapi_lease_get(fd, LL_LEASE_RDLCK);
	ASSERTF(rc == -ENOTTY, "can get lease on directory '%s': %s",
		mainpath, strerror(-rc));

	close(fd);

	/* On lustre mountpoint */
	fd = open(fsmountdir, O_DIRECTORY);
	ASSERTF(fd >= 0, "open failed for '%s': %s", mainpath, strerror(errno));

	rc = llapi_lease_get(fd, LL_LEASE_RDLCK);
	ASSERTF(rc == -ENOTTY, "can get lease on directory '%s': %s",
		mainpath, strerror(-rc));

	close(fd);
}

/* Read then swap */
static void test20(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;
	char buf[100];
	off_t offset;
	struct stat stbuf;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = create_file("foo2", foo2_size, 'y');

	/* foo2 is bigger than foo1. Read a byte in foo2, past foo1_size. */
	offset = lseek(fd2, foo1_size + 100, SEEK_SET);
	ASSERTF(offset == foo1_size + 100, "lseek to pos %zu failed: %s",
		foo1_size + 100, strerror(errno));

	rc = read(fd2, buf, 1);
	ASSERTF(rc == 1, "read 1 byte on foo2 failed: %s, rc=%d",
		strerror(errno), rc);
	ASSERTF(buf[0] == 'y', "invalid data found on foo2: %x", buf[0]);

	/* Now swap */
	rc = llapi_fswap_layouts(fd1, fd2, 0, 0, 0);
	ASSERTF(rc == 0, "llapi_fswap_layouts failed: %s",
		strerror(-rc));

	/* Read from fd1. Its file pointer is now positioned inside
	 * the new data. */
	rc = read(fd1, buf, 1);
	ASSERTF(rc == 1, "read 1 byte on foo1 failed: %s", strerror(errno));
	ASSERTF(buf[0] == 'y', "invalid data found on foo2: %x", buf[0]);

	rc = fstat(fd2, &stbuf);
	ASSERTF(rc == 0, "stat failed on 'foo2': %s", strerror(errno));
	ASSERTF(stbuf.st_size == foo1_size,
		"invalid size found: %llu instead of %zu",
		(unsigned long long)stbuf.st_size, foo1_size);

	/* Read from fd2. After the swap, the file pointer is past the
	 * data. */
	rc = read(fd2, buf, 1);
	ASSERTF(rc == 0, "unexpected read returned rc=%d (errno %s)",
		rc, strerror(errno));

	rc = close(fd1);
	ASSERTF(rc == 0, "close failed: %s", strerror(errno));

	rc = close(fd2);
	ASSERTF(rc == 0, "close failed: %s", strerror(errno));
}

/* Test multiple swaps between 2 files */
static void test30(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;
	int i;
	struct stat stbuf;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = create_file("foo2", foo2_size, 'y');

	for (i = 0; i < 1000; i++) {
		rc = llapi_fswap_layouts(fd1, fd2, 0, 0, 0);
		ASSERTF(rc == 0, "llapi_fswap_layouts failed: %s",
			strerror(-rc));

		rc = fstat(fd1, &stbuf);
		ASSERTF(rc == 0, "stat failed on 'foo1': %s", strerror(errno));
		ASSERTF(stbuf.st_size == i % 2 ? foo2_size : foo1_size,
			"invalid size found: %llu instead of %zu",
			(unsigned long long)stbuf.st_size,
			i % 2 ? foo2_size : foo1_size);

		rc = fstat(fd2, &stbuf);
		ASSERTF(rc == 0, "stat failed on 'foo2': %s", strerror(errno));
		ASSERTF(stbuf.st_size == i % 2 ? foo1_size : foo2_size,
			"invalid size found: %llu instead of %zu",
			(unsigned long long)stbuf.st_size,
			i % 2 ? foo1_size : foo2_size);
	}

	close(fd1);
	close(fd2);
}

/* Test multiple swaps between 3 files */
static void test31(void)
{
	int rc;
	int fd1;
	int fd2;
	int fd3;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;
	size_t foo3_size = 8000;
	int i;
	struct stat stbuf;


	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = create_file("foo2", foo2_size, 'y');
	fd3 = create_file("foo3", foo3_size, 'z');

	/* Note: swapping 3 fd this way will be back to original
	 * layouts every 2 loops. */
	for (i = 0; i < 999; i++) {
		rc = llapi_fswap_layouts(fd1, fd2, 0, 0, 0);
		ASSERTF(rc == 0, "llapi_fswap_layouts failed: %s",
			strerror(-rc));

		rc = llapi_fswap_layouts(fd2, fd3, 0, 0, 0);
		ASSERTF(rc == 0, "llapi_fswap_layouts failed: %s",
			strerror(-rc));

		rc = llapi_fswap_layouts(fd1, fd3, 0, 0, 0);
		ASSERTF(rc == 0, "llapi_fswap_layouts failed: %s",
			strerror(-rc));
	}

	rc = fstat(fd1, &stbuf);
	ASSERTF(rc == 0, "stat failed on 'foo2': %s", strerror(errno));
	ASSERTF(stbuf.st_size == foo1_size,
		"invalid size found: %llu instead of %zu",
		(unsigned long long)stbuf.st_size, foo1_size);

	rc = fstat(fd2, &stbuf);
	ASSERTF(rc == 0, "stat failed on 'foo2': %s", strerror(errno));
	ASSERTF(stbuf.st_size == foo3_size,
		"invalid size found: %llu instead of %zu",
		(unsigned long long)stbuf.st_size, foo3_size);

	rc = fstat(fd3, &stbuf);
	ASSERTF(rc == 0, "stat failed on 'foo2': %s", strerror(errno));
	ASSERTF(stbuf.st_size == foo2_size,
		"invalid size found: %llu instead of %zu",
		(unsigned long long)stbuf.st_size, foo2_size);

	close(fd1);
	close(fd2);
	close(fd3);
}

/* Swap with lease */
static void test40(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = create_file("foo2", foo2_size, 'y');

	rc = llapi_lease_get(fd1, LL_LEASE_RDLCK);
	ASSERTF(rc == 0, "cannot get lease '%s': %s", mainpath, strerror(-rc));

	rc = llapi_lease_check(fd1);
	ASSERTF(rc == LL_LEASE_RDLCK,
		"invalid lease type on '%s': %s", mainpath, strerror(-rc));

	rc = llapi_fswap_layouts(fd1, fd2, 0, 0, SWAP_LAYOUTS_CLOSE);
	ASSERTF(rc == 0, "llapi_fswap_layouts failed: %s",
		strerror(-rc));

	rc = llapi_lease_check(fd1);
	ASSERTF(rc == 0, "lease not lost on '%s': %s", mainpath, strerror(-rc));

	rc = llapi_lease_put(fd1);
	ASSERTF(rc == -ENOLCK,
		"was able to put back lease: %s", strerror(-rc));

	rc = llapi_lease_check(fd1);
	ASSERTF(rc == 0, "lease not lost on '%s': %s", mainpath, strerror(-rc));

	rc = close(fd1);
	ASSERTF(rc == 0, "close failed: %s", strerror(errno));

	rc = close(fd2);
	ASSERTF(rc == 0, "close failed: %s", strerror(errno));
}

/* Swap with close but no lease */
static void test41(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = create_file("foo2", foo2_size, 'y');

	rc = llapi_fswap_layouts(fd1, fd2, 0, 0, SWAP_LAYOUTS_CLOSE);
	ASSERTF(rc == -ENOLCK, "llapi_fswap_layouts failed: %s",
		strerror(-rc));

	/* swap failed, so fd1 has to be closed. */
	rc = close(fd1);
	ASSERTF(rc == 0, "close failed: %s", strerror(errno));

	rc = close(fd2);
	ASSERTF(rc == 0, "close failed: %s", strerror(errno));
}

/* swap with data versions */
static void test42(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;
	__u64 dv1 = 0;
	__u64 dv2 = 0;
	__u64 new_dv1 = 0;
	__u64 new_dv2 = 0;
	__u64 new_new_dv1 = 0;
	__u64 new_new_dv2 = 0;
	char *name_fd1;
	char *name_fd2;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	/* Get dataversion for two files.
	 * Make sure values are different so that the following checks make
	 * sense. */
	fd1 = create_file("foo1", foo1_size, 'x');

	rc = llapi_get_data_version(fd1, &dv1, LL_DV_RD_FLUSH);
	ASSERTF(rc == 0, "cannot get dataversion for fd1: %s", strerror(-rc));
	ASSERTF(dv1 != 0, "got dataversion 0 for fd1");

	for (;;) {
		fd2 = create_file("foo2", foo2_size, 'y');

		rc = llapi_get_data_version(fd2, &dv2, LL_DV_RD_FLUSH);
		ASSERTF(rc == 0, "cannot get dataversion for fd2: %s",
			strerror(-rc));
		ASSERTF(dv2 != 0, "got dataversion 0 for fd2");

		if (dv1 != dv2)
			break;

		close(fd2);
	}

	/* swaps that should fail */
	rc = llapi_fswap_layouts(fd1, fd2, 0, 0, SWAP_LAYOUTS_CHECK_DV1);
	ASSERTF(rc == -EAGAIN, "incorrect return from swap: %s", strerror(-rc));

	rc = llapi_fswap_layouts(fd1, fd2, dv1 + 456789, 0,
				 SWAP_LAYOUTS_CHECK_DV1);
	ASSERTF(rc == -EAGAIN, "incorrect return from swap: %s", strerror(-rc));

	rc = llapi_fswap_layouts(fd1, fd2, 0, 0, SWAP_LAYOUTS_CHECK_DV2);
	ASSERTF(rc == -EAGAIN, "incorrect return from swap: %s", strerror(-rc));

	rc = llapi_fswap_layouts(fd1, fd2, 0, dv2 + 987654,
				 SWAP_LAYOUTS_CHECK_DV2);
	ASSERTF(rc == -EAGAIN, "incorrect return from swap: %s", strerror(-rc));

	rc = llapi_fswap_layouts(fd1, fd2, 0, 0,
				 SWAP_LAYOUTS_CHECK_DV1 |
				 SWAP_LAYOUTS_CHECK_DV2);
	ASSERTF(rc == -EAGAIN, "incorrect return from swap: %s", strerror(-rc));

	rc = llapi_fswap_layouts(fd1, fd2, dv1 + 456789, 0,
				 SWAP_LAYOUTS_CHECK_DV1 |
				 SWAP_LAYOUTS_CHECK_DV2);
	ASSERTF(rc == -EAGAIN, "incorrect return from swap: %s", strerror(-rc));

	rc = llapi_fswap_layouts(fd1, fd2, dv1 + 456789, dv2 + 987654,
				 SWAP_LAYOUTS_CHECK_DV1 |
				 SWAP_LAYOUTS_CHECK_DV2);
	ASSERTF(rc == -EAGAIN, "incorrect return from swap: %s", strerror(-rc));

	rc = llapi_fswap_layouts(fd1, fd2, dv1, 0,
				 SWAP_LAYOUTS_CHECK_DV1 |
				 SWAP_LAYOUTS_CHECK_DV2);
	ASSERTF(rc == -EAGAIN, "incorrect return from swap: %s", strerror(-rc));

	rc = llapi_fswap_layouts(fd1, fd2, 0, dv2,
				 SWAP_LAYOUTS_CHECK_DV1 |
				 SWAP_LAYOUTS_CHECK_DV2);
	ASSERTF(rc == -EAGAIN, "incorrect return from swap: %s", strerror(-rc));

	rc = llapi_fswap_layouts(fd1, fd2, dv1, dv2 + 567,
				 SWAP_LAYOUTS_CHECK_DV1 |
				 SWAP_LAYOUTS_CHECK_DV2);
	ASSERTF(rc == -EAGAIN, "incorrect return from swap: %s", strerror(-rc));

	printf("DV = %llx and %llx\n", dv1, dv2);

	/* Finally, a good swap */
	rc = llapi_fswap_layouts(fd1, fd2, dv1, dv2,
				 SWAP_LAYOUTS_CHECK_DV1 |
				 SWAP_LAYOUTS_CHECK_DV2);
	ASSERTF(rc == 0, "incorrect return from swap: %s", strerror(-rc));

	/* Check dataversion. */
	rc = llapi_get_data_version(fd1, &new_dv1, LL_DV_RD_FLUSH);
	ASSERTF(rc == 0,
		"cannot get new dataversion for fd1: %s", strerror(-rc));
	ASSERTF(dv1 != 0, "got dataversion 0 for fd1");
	ASSERTF(dv1 != new_dv1, "got identical dataversion for fd1: %llx", dv1);

	rc = llapi_get_data_version(fd2, &new_dv2, LL_DV_RD_FLUSH);
	ASSERTF(rc == 0,
		"cannot get new dataversion for fd2: %s", strerror(-rc));
	ASSERTF(dv2 != 0, "got dataversion 0 for fd2");
	ASSERTF(dv2 != new_dv2, "got identical dataversion for fd2: %llx", dv1);

	printf("new DV = %llx and %llx\n", new_dv1, new_dv2);

	/* Try again with same parameters. */
	rc = llapi_fswap_layouts(fd1, fd2, dv1, dv2,
				 SWAP_LAYOUTS_CHECK_DV1 |
				 SWAP_LAYOUTS_CHECK_DV2);
	ASSERTF(rc == -EAGAIN, "incorrect return from swap: %s", strerror(-rc));

	close(fd1);
	close(fd2);

	/* Reopen the files and check again the dataversion */
	name_fd1 = create_file_name("foo1");
	fd1 = open(name_fd1, O_RDONLY);
	ASSERTF(fd1 >= 0,
		"open failed for '%s': %s", name_fd1, strerror(errno));

	rc = llapi_get_data_version(fd1, &new_new_dv1, LL_DV_RD_FLUSH);
	ASSERTF(rc == 0, "cannot get dataversion for fd1: %s", strerror(-rc));
	ASSERTF(new_new_dv1 != 0, "got dataversion 0 for fd1");
	ASSERTF(new_dv1 == new_new_dv1,
		"dataversion changed after re-opening: %llx and %llx",
		new_dv1, new_new_dv1);

	name_fd2 = create_file_name("foo2");
	fd2 = open(name_fd2, O_RDONLY);
	ASSERTF(fd2 >= 0,
		"open failed for '%s': %s", name_fd2, strerror(errno));

	rc = llapi_get_data_version(fd2, &new_new_dv2, LL_DV_RD_FLUSH);
	ASSERTF(rc == 0, "cannot get dataversion for fd2: %s", strerror(-rc));
	ASSERTF(new_new_dv2 != 0, "got dataversion 0 for fd2");
	ASSERTF(new_dv2 == new_new_dv2,
		"dataversion changed after re-opening: %llx and %llx",
		new_dv2, new_new_dv2);

	printf("DV= %llx and %llx\n", new_new_dv1, new_new_dv2);

	close(fd1);
	close(fd2);

	free(name_fd1);
	free(name_fd2);
}

/* swap group lock, no group */
static void test50(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = create_file("foo2", foo2_size, 'y');

	rc = llapi_fswap_layouts_grouplock(fd1, fd2, 0, 0, 0, 0);
	ASSERTF(rc == 0, "llapi_fswap_layouts_grouplock failed: %s",
		strerror(-rc));

	close(fd1);
	close(fd2);
}

/* swap group lock, with group */
static void test51(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = create_file("foo2", foo2_size, 'y');

	rc = llapi_fswap_layouts_grouplock(fd1, fd2, 0, 0, 456789, 0);
	ASSERTF(rc == 0, "llapi_fswap_layouts_grouplock failed: %s",
		strerror(-rc));

	close(fd1);
	close(fd2);
}

/* swap group lock, with existing group locks */
static void test52(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;
	int gid = 7356;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = create_file("foo2", foo2_size, 'y');

	/* lock a descriptor, but swap without */
	rc = llapi_group_lock(fd1, gid);
	ASSERTF(rc == 0, "cannot lock 'foo1': %s", strerror(-rc));

	rc = llapi_fswap_layouts_grouplock(fd1, fd2, 0, 0, 0, 0);
	ASSERTF(rc == 0, "llapi_fswap_layouts_grouplock failed: %s",
		strerror(-rc));

	rc = llapi_group_unlock(fd1, gid);
	ASSERTF(rc == 0, "cannot unlock 'foo1': %s", strerror(-rc));

	close(fd1);
	close(fd2);
}

/* Swap group lock, with existing group locks, on second descriptor */
static void test53(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;
	int gid = 7356;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = create_file("foo2", foo2_size, 'y');

	/* lock a descriptor, but swap without */
	rc = llapi_group_lock(fd2, gid);
	ASSERTF(rc == 0, "cannot lock 'foo1': %s", strerror(-rc));

	rc = llapi_fswap_layouts_grouplock(fd1, fd2, 0, 0, 0, 0);
	ASSERTF(rc == 0, "llapi_fswap_layouts_grouplock failed: %s",
		strerror(-rc));

	rc = llapi_group_unlock(fd2, gid);
	ASSERTF(rc == 0, "cannot unlock 'foo1': %s", strerror(-rc));

	close(fd1);
	close(fd2);
}

/* swap group lock, lock a descriptor, and try to swap with it. */
static void test54(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;
	int gid;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = create_file("foo2", foo2_size, 'y');

	gid = 7356;
	rc = llapi_group_lock(fd1, gid);
	ASSERTF(rc == 0, "cannot lock 'foo1': %s", strerror(-rc));

	rc = llapi_fswap_layouts_grouplock(fd1, fd2, 0, 0, gid, 0);
	ASSERTF(rc == -EINVAL, "llapi_fswap_layouts_grouplock failed: %s",
		strerror(-rc));

	rc = llapi_group_unlock(fd1, gid);
	ASSERTF(rc == 0, "cannot unlock 'foo1': %s", strerror(-rc));

	close(fd1);
	close(fd2);
}

/* Swap group lock, lock a descriptor, and try to swap with it, on
 * second descriptor. */
static void test55(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;
	int gid = 7356;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = create_file("foo2", foo2_size, 'y');

	rc = llapi_group_lock(fd2, gid);
	ASSERTF(rc == 0, "cannot lock 'foo1': %s", strerror(-rc));

	rc = llapi_fswap_layouts_grouplock(fd1, fd2, 0, 0, gid, 0);
	ASSERTF(rc == -EINVAL, "llapi_fswap_layouts_grouplock failed: %s",
		strerror(-rc));

	rc = llapi_group_unlock(fd2, gid);
	ASSERTF(rc == 0, "cannot unlock 'foo1': %s", strerror(-rc));

	close(fd1);
	close(fd2);
}

/* Swap group lock, lock a descriptor, and try to swap with another
 * one. */
static void test56(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;
	int gid1 = 78976;
	int gid2 = 3458;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = create_file("foo2", foo2_size, 'y');

	rc = llapi_group_lock(fd1, gid1);
	ASSERTF(rc == 0, "cannot lock 'foo1': %s", strerror(-rc));

	rc = llapi_group_lock(fd2, gid2);
	ASSERTF(rc == 0, "cannot lock 'foo1': %s", strerror(-rc));

	rc = llapi_fswap_layouts_grouplock(fd1, fd2, 0, 0, 0, 0);
	ASSERTF(rc == 0, "llapi_fswap_layouts_grouplock failed: %s",
		strerror(-rc));

	rc = llapi_group_unlock(fd1, gid1);
	ASSERTF(rc == 0, "cannot unlock 'foo1': %s", strerror(-rc));

	rc = llapi_group_unlock(fd2, gid2);
	ASSERTF(rc == 0, "cannot unlock 'foo2': %s", strerror(-rc));

	close(fd1);
	close(fd2);
}

/* Swap group lock, lock both descriptor, and try to swap with another
 * one. */
static void test57(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;
	int gid1 = 78976;
	int gid2 = 3458;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = create_file("foo2", foo2_size, 'y');

	rc = llapi_group_lock(fd1, gid1);
	ASSERTF(rc == 0, "cannot lock 'foo1': %s", strerror(-rc));

	rc = llapi_group_lock(fd2, gid2);
	ASSERTF(rc == 0, "cannot lock 'foo1': %s", strerror(-rc));

	rc = llapi_fswap_layouts_grouplock(fd1, fd2, 0, 0, gid1+gid2, 0);
	ASSERTF(rc == -EINVAL, "llapi_fswap_layouts_grouplock failed: %s",
		strerror(-rc));

	rc = llapi_group_unlock(fd1, gid1);
	ASSERTF(rc == 0, "cannot unlock 'foo1': %s", strerror(-rc));

	rc = llapi_group_unlock(fd2, gid2);
	ASSERTF(rc == 0, "cannot unlock 'foo2': %s", strerror(-rc));

	close(fd1);
	close(fd2);
}

/* Swap group lock, lock both descriptor with same gid, and try to
 * swap with it. */
static void test58(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;
	int gid = 6458907;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = create_file("foo2", foo2_size, 'y');

	rc = llapi_group_lock(fd1, gid);
	ASSERTF(rc == 0, "cannot lock 'foo1': %s", strerror(-rc));

	rc = llapi_group_lock(fd2, gid);
	ASSERTF(rc == 0, "cannot lock 'foo1': %s", strerror(-rc));

	rc = llapi_fswap_layouts_grouplock(fd1, fd2, 0, 0, gid, 0);
	ASSERTF(rc == -EINVAL, "llapi_fswap_layouts_grouplock failed: %s",
		strerror(-rc));

	rc = llapi_group_unlock(fd1, gid);
	ASSERTF(rc == 0, "cannot unlock 'foo1': %s", strerror(-rc));

	rc = llapi_group_unlock(fd2, gid);
	ASSERTF(rc == 0, "cannot unlock 'foo2': %s", strerror(-rc));

	close(fd1);
	close(fd2);
}

/* Swap group lock, lock both descriptor with same gid, and swap with
 * none. */
static void test59(void)
{
	int rc;
	int fd1;
	int fd2;
	size_t foo1_size = 2000;
	size_t foo2_size = 5000;
	int gid = 6458907;

	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	fd1 = create_file("foo1", foo1_size, 'x');
	fd2 = create_file("foo2", foo2_size, 'y');

	rc = llapi_group_lock(fd1, gid);
	ASSERTF(rc == 0, "cannot lock 'foo1': %s", strerror(-rc));

	rc = llapi_group_lock(fd2, gid);
	ASSERTF(rc == 0, "cannot lock 'foo1': %s", strerror(-rc));

	rc = llapi_fswap_layouts_grouplock(fd1, fd2, 0, 0, 0, 0);
	ASSERTF(rc == 0, "llapi_fswap_layouts_grouplock failed: %s",
		strerror(-rc));

	rc = llapi_group_unlock(fd1, gid);
	ASSERTF(rc == 0, "cannot unlock 'foo1': %s", strerror(-rc));

	rc = llapi_group_unlock(fd2, gid);
	ASSERTF(rc == 0, "cannot unlock 'foo2': %s", strerror(-rc));

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
	char fsname[8 + 1];
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

	atexit(cleanup);

	PERFORM(test10);
	PERFORM(test11);
	PERFORM(test12);
	PERFORM(test13);
	PERFORM(test14);
	PERFORM(test15);
	PERFORM(test16);
	PERFORM(test17);
	PERFORM(test20);
	PERFORM(test30);
	PERFORM(test31);
	PERFORM(test40);
	PERFORM(test41);
	PERFORM(test42);
	PERFORM(test50);
	PERFORM(test51);
	PERFORM(test52);
	PERFORM(test53);
	PERFORM(test54);
	PERFORM(test55);
	PERFORM(test56);
	PERFORM(test57);
	PERFORM(test58);
	PERFORM(test59);

	return EXIT_SUCCESS;
}
