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
 * Copyright 2016 Cray Inc. All rights reserved.
 * Authors: Patrick Farrell, Frank Zago
 *
 * A few portions are extracted from llapi_layout_test.c
 *
 * The purpose of this test is to exercise the lockahead advice of ladvise.
 *
 * The program will exit as soon as a test fails.
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
#include <linux/lustre/lustre_idl.h>

#define ERROR(fmt, ...)							\
	fprintf(stderr, "%s: %s:%d: %s: " fmt "\n",			\
		program_invocation_short_name, __FILE__, __LINE__,	\
		__func__, ## __VA_ARGS__);

#define DIE(fmt, ...)				\
	do {					\
		ERROR(fmt, ## __VA_ARGS__);	\
		exit(-1);		\
	} while (0)

#define ASSERTF(cond, fmt, ...)						\
	do {								\
		if (!(cond))						\
			DIE("assertion '%s' failed: "fmt,		\
			    #cond, ## __VA_ARGS__);			\
	} while (0)

#define PERFORM(testfn) \
	do {								\
		cleanup();						\
		fprintf(stderr, "Starting test " #testfn " at %lld\n",	\
			(unsigned long long)time(NULL));		\
		rc = testfn();						\
		fprintf(stderr, "Finishing test " #testfn " at %lld\n",	\
			(unsigned long long)time(NULL));		\
	} while (0)

/* Name of file/directory. Will be set once and will not change. */
static char mainpath[PATH_MAX];
/* Path to same file/directory on second mount */
static char mainpath2[PATH_MAX];
static char *mainfile;

static char fsmountdir[PATH_MAX];	/* Lustre mountpoint */
static char *lustre_dir;		/* Test directory inside Lustre */
static char *lustre_dir2;		/* Same dir but on second mountpoint */
static int single_test;			/* Number of a single test to execute*/

/* Cleanup our test file. */
static void cleanup(void)
{
	unlink(mainpath);
}

/* Trivial helper for one advice */
void setup_ladvise_lockahead(struct llapi_lu_ladvise *advice, int mode,
			     int flags, size_t start, size_t end, bool async)
{
	advice->lla_advice = LU_LADVISE_LOCKAHEAD;
	advice->lla_lockahead_mode = mode;
	if (async)
		advice->lla_peradvice_flags = flags | LF_ASYNC;
	else
		advice->lla_peradvice_flags = flags;
	advice->lla_start = start;
	advice->lla_end = end;
	advice->lla_value3 = 0;
	advice->lla_value4 = 0;
}

/* Test valid single lock ahead request */
static int test10(void)
{
	struct llapi_lu_ladvise advice;
	const int count = 1;
	int fd;
	size_t write_size = 1024 * 1024;
	int rc;
	char buf[write_size];

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	setup_ladvise_lockahead(&advice, MODE_WRITE_USER, 0, 0,
				  write_size - 1, true);

	/* Manually set the result so we can verify it's being modified */
	advice.lla_lockahead_result = 345678;

	rc = llapi_ladvise(fd, 0, count, &advice);
	ASSERTF(rc == 0,
		"cannot lockahead '%s': %s", mainpath, strerror(errno));
	ASSERTF(advice.lla_lockahead_result == 0,
		"unexpected extent result: %d",
		advice.lla_lockahead_result);

	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));


	close(fd);

	return 0;
}

/* Get lock, wait until lock is taken */
static int test11(void)
{
	struct llapi_lu_ladvise advice;
	const int count = 1;
	int fd;
	size_t write_size = 1024 * 1024;
	int rc;
	char buf[write_size];
	int i;
	int enqueue_requests = 0;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	setup_ladvise_lockahead(&advice, MODE_WRITE_USER, 0, 0,
				  write_size - 1, true);

	/* Manually set the result so we can verify it's being modified */
	advice.lla_lockahead_result = 345678;

	rc = llapi_ladvise(fd, 0, count, &advice);
	ASSERTF(rc == 0,
		"cannot lockahead '%s': %s", mainpath, strerror(errno));
	ASSERTF(advice.lla_lockahead_result == 0,
		"unexpected extent result: %d",
		advice.lla_lockahead_result);

	enqueue_requests++;

	/* Ask again until we get the lock (status 1). */
	for (i = 1; i < 100; i++) {
		usleep(100000); /* 0.1 second */
		advice.lla_lockahead_result = 456789;
		rc = llapi_ladvise(fd, 0, count, &advice);
		ASSERTF(rc == 0, "cannot lockahead '%s': %s",
			mainpath, strerror(errno));

		if (advice.lla_lockahead_result > 0)
			break;

		enqueue_requests++;
	}

	ASSERTF(advice.lla_lockahead_result == LLA_RESULT_SAME,
		"unexpected extent result: %d",
		advice.lla_lockahead_result);

	/* Again. This time it is always there. */
	for (i = 0; i < 100; i++) {
		advice.lla_lockahead_result = 456789;
		rc = llapi_ladvise(fd, 0, count, &advice);
		ASSERTF(rc == 0, "cannot lockahead '%s': %s",
			mainpath, strerror(errno));
		ASSERTF(advice.lla_lockahead_result > 0,
			"unexpected extent result: %d",
			advice.lla_lockahead_result);
	}

	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));

	close(fd);

	return enqueue_requests;
}

/* Test with several times the same extent */
static int test12(void)
{
	struct llapi_lu_ladvise *advice;
	const int count = 10;
	int fd;
	size_t write_size = 1024 * 1024;
	int rc;
	char buf[write_size];
	int i;
	int expected_lock_count = 0;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	advice = malloc(sizeof(struct llapi_lu_ladvise)*count);

	for (i = 0; i < count; i++) {
		setup_ladvise_lockahead(&(advice[i]), MODE_WRITE_USER, 0, 0,
					  write_size - 1, true);
		advice[i].lla_lockahead_result = 98674;
	}

	rc = llapi_ladvise(fd, 0, count, advice);
	ASSERTF(rc == 0,
		"cannot lockahead '%s': %s", mainpath, strerror(errno));
	for (i = 0; i < count; i++) {
		ASSERTF(advice[i].lla_lockahead_result >= 0,
			"unexpected extent result for extent %d: %d",
			i, advice[i].lla_lockahead_result);
	}
	/* Since all the requests are for the same extent, we should only have
	 * one lock at the end. */
	expected_lock_count = 1;

	/* Ask again until we get the locks. */
	for (i = 1; i < 100; i++) {
		usleep(100000); /* 0.1 second */
		advice[count-1].lla_lockahead_result = 456789;
		rc = llapi_ladvise(fd, 0, count, advice);
		ASSERTF(rc == 0, "cannot lockahead '%s': %s",
			mainpath, strerror(errno));

		if (advice[count-1].lla_lockahead_result > 0)
			break;
	}

	ASSERTF(advice[count-1].lla_lockahead_result == LLA_RESULT_SAME,
		"unexpected extent result: %d",
		advice[count-1].lla_lockahead_result);

	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));

	free(advice);
	close(fd);

	return expected_lock_count;
}

/* Grow a lock forward */
static int test13(void)
{
	struct llapi_lu_ladvise *advice = NULL;
	const int count = 1;
	int fd;
	size_t write_size = 1024 * 1024;
	int rc;
	char buf[write_size];
	int i;
	int expected_lock_count = 0;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	for (i = 0; i < 100; i++) {
		if (advice)
			free(advice);
		advice = malloc(sizeof(struct llapi_lu_ladvise)*count);
		setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0,
					i * write_size, (i+1)*write_size - 1,
					true);
		advice[0].lla_lockahead_result = 98674;

		rc = llapi_ladvise(fd, 0, count, advice);
		ASSERTF(rc == 0, "cannot lockahead '%s' at offset %llu: %s",
			mainpath,
			advice[0].lla_end,
			strerror(errno));

		ASSERTF(advice[0].lla_lockahead_result >= 0,
			"unexpected extent result for extent %d: %d",
			i, advice[0].lla_lockahead_result);

		expected_lock_count++;
	}

	/* Ask again until we get the lock. */
	for (i = 1; i < 100; i++) {
		usleep(100000); /* 0.1 second */
		advice[0].lla_lockahead_result = 456789;
		rc = llapi_ladvise(fd, 0, count, advice);
		ASSERTF(rc == 0, "cannot lockahead '%s': %s",
			mainpath, strerror(errno));

		if (advice[0].lla_lockahead_result > 0)
			break;
	}

	ASSERTF(advice[0].lla_lockahead_result == LLA_RESULT_SAME,
		"unexpected extent result: %d",
		advice[0].lla_lockahead_result);

	free(advice);

	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));

	close(fd);

	return expected_lock_count;
}

/* Grow a lock backward */
static int test14(void)
{
	struct llapi_lu_ladvise *advice = NULL;
	const int count = 1;
	int fd;
	size_t write_size = 1024 * 1024;
	int rc;
	char buf[write_size];
	int i;
	const int num_blocks = 100;
	int expected_lock_count = 0;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	for (i = 0; i < num_blocks; i++) {
		size_t start = (num_blocks - i - 1) * write_size;
		size_t end = (num_blocks - i) * write_size - 1;

		if (advice)
			free(advice);
		advice = malloc(sizeof(struct llapi_lu_ladvise)*count);
		setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0, start,
					end, true);
		advice[0].lla_lockahead_result = 98674;

		rc = llapi_ladvise(fd, 0, count, advice);
		ASSERTF(rc == 0, "cannot lockahead '%s' at offset %llu: %s",
			mainpath,
			advice[0].lla_end,
			strerror(errno));

		ASSERTF(advice[0].lla_lockahead_result >= 0,
			"unexpected extent result for extent %d: %d",
			i, advice[0].lla_lockahead_result);

		expected_lock_count++;
	}

	/* Ask again until we get the lock. */
	for (i = 1; i < 100; i++) {
		usleep(100000); /* 0.1 second */
		advice[0].lla_lockahead_result = 456789;
		rc = llapi_ladvise(fd, 0, count, advice);
		ASSERTF(rc == 0, "cannot lockahead '%s': %s",
			mainpath, strerror(errno));

		if (advice[0].lla_lockahead_result > 0)
			break;
	}

	ASSERTF(advice[0].lla_lockahead_result == LLA_RESULT_SAME,
		"unexpected extent result: %d",
		advice[0].lla_lockahead_result);

	free(advice);

	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));

	close(fd);

	return expected_lock_count;
}

/* Request many locks at 10MiB intervals */
static int test15(void)
{
	struct llapi_lu_ladvise *advice;
	const int count = 1;
	int fd;
	size_t write_size = 1024 * 1024;
	int rc;
	char buf[write_size];
	int i;
	int expected_lock_count = 0;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	advice = malloc(sizeof(struct llapi_lu_ladvise)*count);

	for (i = 0; i < 500; i++) {
		/* The 'UL' designators are required to avoid undefined
		 * behavior which GCC turns in to an infinite loop */
		__u64 start = i * 1024UL * 1024UL * 10UL;
		__u64 end = start + 1;

		setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0, start,
					end, true);

		advice[0].lla_lockahead_result = 345678;

		rc = llapi_ladvise(fd, 0, count, advice);

		ASSERTF(rc == 0, "cannot lockahead '%s' : %s",
			mainpath, strerror(errno));
		ASSERTF(advice[0].lla_lockahead_result >= 0,
			"unexpected extent result for extent %d: %d",
			i, advice[0].lla_lockahead_result);
		expected_lock_count++;
	}

	/* Ask again until we get the lock. */
	for (i = 1; i < 100; i++) {
		usleep(100000); /* 0.1 second */
		advice[0].lla_lockahead_result = 456789;
		rc = llapi_ladvise(fd, 0, count, advice);
		ASSERTF(rc == 0, "cannot lockahead '%s': %s",
			mainpath, strerror(errno));

		if (advice[0].lla_lockahead_result > 0)
			break;
	}

	ASSERTF(advice[0].lla_lockahead_result == LLA_RESULT_SAME,
		"unexpected extent result: %d",
		advice[0].lla_lockahead_result);

	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));
	/* The write should cancel the first lock (which was too small)
	 * and create one of its own, so the net effect on lock count is 0. */

	free(advice);

	close(fd);

	/* We have to map our expected return in to the range of valid return
	 * codes, 0-255. */
	expected_lock_count = expected_lock_count/100;

	return expected_lock_count;
}

/* Use lockahead to verify behavior of ladvise locknoexpand */
static int test16(void)
{
	struct llapi_lu_ladvise *advice;
	struct llapi_lu_ladvise *advice_noexpand;
	const int count = 1;
	int fd;
	size_t write_size = 1024 * 1024;
	__u64 start = 0;
	__u64 end = write_size - 1;
	int rc;
	char buf[write_size];
	int expected_lock_count = 0;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	advice = malloc(sizeof(struct llapi_lu_ladvise)*count);
	advice_noexpand = malloc(sizeof(struct llapi_lu_ladvise));

	/* First ask for a read lock, which will conflict with the write */
	setup_ladvise_lockahead(advice, MODE_READ_USER, 0, start, end, false);
	advice[0].lla_lockahead_result = 345678;
	rc = llapi_ladvise(fd, 0, count, advice);
	ASSERTF(rc == 0, "cannot lockahead '%s' : %s",
		mainpath, strerror(errno));
	ASSERTF(advice[0].lla_lockahead_result == 0,
		"unexpected extent result for extent: %d",
		advice[0].lla_lockahead_result);

	/* Use an async request to verify we got the read lock we asked for */
	setup_ladvise_lockahead(advice, MODE_READ_USER, 0, start, end, true);
	advice[0].lla_lockahead_result = 345678;
	rc = llapi_ladvise(fd, 0, count, advice);
	ASSERTF(rc == 0, "cannot lockahead '%s' : %s",
		mainpath, strerror(errno));
	ASSERTF(advice[0].lla_lockahead_result == LLA_RESULT_SAME,
		"unexpected extent result for extent: %d",
		advice[0].lla_lockahead_result);

	/* Set noexpand */
	advice_noexpand[0].lla_advice = LU_LADVISE_LOCKNOEXPAND;
	advice_noexpand[0].lla_peradvice_flags = 0;
	rc = llapi_ladvise(fd, 0, 1, advice_noexpand);

	ASSERTF(rc == 0, "cannot lockahead '%s' : %s",
		mainpath, strerror(errno));

	/* This write should generate a lock on exactly "write_size" bytes */
	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));
	/* Write should create one LDLM lock */
	expected_lock_count++;

	setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0, start, end, true);

	advice[0].lla_lockahead_result = 345678;

	rc = llapi_ladvise(fd, 0, count, advice);

	ASSERTF(rc == 0, "cannot lockahead '%s' : %s",
		mainpath, strerror(errno));
	ASSERTF(advice[0].lla_lockahead_result == LLA_RESULT_SAME,
		"unexpected extent result for extent: %d",
		advice[0].lla_lockahead_result);

	/* Now, disable locknoexpand and try writing again. */
	advice_noexpand[0].lla_peradvice_flags = LF_UNSET;
	rc = llapi_ladvise(fd, 0, 1, advice_noexpand);

	/* This write should get an expanded lock */
	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));
	/* Write should create one LDLM lock */
	expected_lock_count++;

	/* Verify it didn't get a lock on just the bytes it wrote.*/
	usleep(100000); /* 0.1 second, plenty of time to get the lock */

	start = start + write_size;
	end = end + write_size;
	setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0, start, end, true);

	advice[0].lla_lockahead_result = 345678;

	rc = llapi_ladvise(fd, 0, count, advice);

	ASSERTF(rc == 0, "cannot lockahead '%s' : %s",
		mainpath, strerror(errno));
	ASSERTF(advice[0].lla_lockahead_result == LLA_RESULT_DIFFERENT,
		"unexpected extent result for extent %d",
		advice[0].lla_lockahead_result);

	free(advice);

	close(fd);

	return expected_lock_count;
}

/* Use lockahead to verify behavior of ladvise locknoexpand, with O_NONBLOCK.
 * There should be no change in behavior. */
static int test17(void)
{
	struct llapi_lu_ladvise *advice;
	struct llapi_lu_ladvise *advice_noexpand;
	const int count = 1;
	int fd;
	size_t write_size = 1024 * 1024;
	__u64 start = 0;
	__u64 end = write_size - 1;
	int rc;
	char buf[write_size];
	int expected_lock_count = 0;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC | O_NONBLOCK,
		  S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	advice = malloc(sizeof(struct llapi_lu_ladvise)*count);
	advice_noexpand = malloc(sizeof(struct llapi_lu_ladvise));

	/* First ask for a read lock, which will conflict with the write */
	setup_ladvise_lockahead(advice, MODE_READ_USER, 0, start, end, false);
	advice[0].lla_lockahead_result = 345678;
	rc = llapi_ladvise(fd, 0, count, advice);
	ASSERTF(rc == 0, "cannot lockahead '%s' : %s",
		mainpath, strerror(errno));
	ASSERTF(advice[0].lla_lockahead_result == 0,
		"unexpected extent result for extent: %d",
		advice[0].lla_lockahead_result);

	/* Use an async request to verify we got the read lock we asked for */
	setup_ladvise_lockahead(advice, MODE_READ_USER, 0, start, end, true);
	advice[0].lla_lockahead_result = 345678;
	rc = llapi_ladvise(fd, 0, count, advice);
	ASSERTF(rc == 0, "cannot lockahead '%s' : %s",
		mainpath, strerror(errno));
	ASSERTF(advice[0].lla_lockahead_result == LLA_RESULT_SAME,
		"unexpected extent result for extent: %d",
		advice[0].lla_lockahead_result);

	/* Set noexpand */
	advice_noexpand[0].lla_advice = LU_LADVISE_LOCKNOEXPAND;
	advice_noexpand[0].lla_peradvice_flags = 0;
	rc = llapi_ladvise(fd, 0, 1, advice_noexpand);

	ASSERTF(rc == 0, "cannot lockahead '%s' : %s",
		mainpath, strerror(errno));

	/* This write should generate a lock on exactly "write_size" bytes */
	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));
	/* Write should create one LDLM lock */
	expected_lock_count++;

	setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0, start, end, true);

	advice[0].lla_lockahead_result = 345678;

	rc = llapi_ladvise(fd, 0, count, advice);

	ASSERTF(rc == 0, "cannot lockahead '%s' : %s",
		mainpath, strerror(errno));
	ASSERTF(advice[0].lla_lockahead_result == LLA_RESULT_SAME,
		"unexpected extent result for extent: %d",
		advice[0].lla_lockahead_result);

	/* Now, disable locknoexpand and try writing again. */
	advice_noexpand[0].lla_peradvice_flags = LF_UNSET;
	rc = llapi_ladvise(fd, 0, 1, advice_noexpand);

	/* This write should get an expanded lock */
	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));
	/* Write should create one LDLM lock */
	expected_lock_count++;

	/* Verify it didn't get a lock on just the bytes it wrote.*/
	usleep(100000); /* 0.1 second, plenty of time to get the lock */

	start = start + write_size;
	end = end + write_size;
	setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0, start, end, true);

	advice[0].lla_lockahead_result = 345678;

	rc = llapi_ladvise(fd, 0, count, advice);

	ASSERTF(rc == 0, "cannot lockahead '%s' : %s",
		mainpath, strerror(errno));
	ASSERTF(advice[0].lla_lockahead_result == LLA_RESULT_DIFFERENT,
		"unexpected extent result for extent %d",
		advice[0].lla_lockahead_result);

	free(advice);

	close(fd);

	return expected_lock_count;
}

/* Test overlapping requests */
static int test18(void)
{
	struct llapi_lu_ladvise *advice;
	const int count = 1;
	int fd;
	int rc;
	int i;
	int expected_lock_count = 0;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	advice = malloc(sizeof(struct llapi_lu_ladvise)*count);

	/* Overlapping locks - Should only end up with 1 */
	for (i = 0; i < 10; i++) {
		__u64 start = i;
		__u64 end = start + 4096;

		setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0, start,
					end, true);

		advice[0].lla_lockahead_result = 345678;

		rc = llapi_ladvise(fd, 0, count, advice);

		ASSERTF(rc == 0, "cannot lockahead '%s' : %s",
			mainpath, strerror(errno));
		ASSERTF(advice[0].lla_lockahead_result >= 0,
			"unexpected extent result for extent %d: %d",
			i, advice[0].lla_lockahead_result);
	}
	expected_lock_count = 1;

	/* Ask again until we get the lock. */
	for (i = 1; i < 100; i++) {
		usleep(100000); /* 0.1 second */
		advice[0].lla_lockahead_result = 456789;
		setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0, 0, 4096,
					true);
		rc = llapi_ladvise(fd, 0, count, advice);
		ASSERTF(rc == 0, "cannot lockahead '%s': %s",
			mainpath, strerror(errno));

		if (advice[0].lla_lockahead_result > 0)
			break;
	}

	ASSERTF(advice[0].lla_lockahead_result == LLA_RESULT_SAME,
		"unexpected extent result: %d",
		advice[0].lla_lockahead_result);

	free(advice);

	close(fd);

	return expected_lock_count;
}

/* Test that normal request blocks lock ahead requests */
static int test19(void)
{
	struct llapi_lu_ladvise *advice;
	const int count = 1;
	int fd;
	size_t write_size = 1024 * 1024;
	int rc;
	char buf[write_size];
	int i;
	int expected_lock_count = 0;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	advice = malloc(sizeof(struct llapi_lu_ladvise)*count);

	/* This should create a lock on the whole file, which will block lock
	 * ahead requests. */
	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));

	expected_lock_count = 1;

	/* These should all be blocked. */
	for (i = 0; i < 10; i++) {
		__u64 start = i * 4096;
		__u64 end = start + 4096;

		setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0, start,
					end, true);

		advice[0].lla_lockahead_result = 345678;

		rc = llapi_ladvise(fd, 0, count, advice);

		ASSERTF(rc == 0, "cannot lockahead '%s' : %s",
			mainpath, strerror(errno));
		ASSERTF(advice[0].lla_lockahead_result == LLA_RESULT_DIFFERENT,
			"unexpected extent result for extent %d: %d",
			i, advice[0].lla_lockahead_result);
	}

	free(advice);

	close(fd);

	return expected_lock_count;
}

/* Test sync requests, and matching with async requests */
static int test20(void)
{
	struct llapi_lu_ladvise advice;
	const int count = 1;
	int fd;
	size_t write_size = 1024 * 1024;
	int rc;
	char buf[write_size];
	int i;
	int expected_lock_count = 1;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	/* Async request */
	setup_ladvise_lockahead(&advice, MODE_WRITE_USER, 0, 0,
				write_size - 1, true);

	/* Manually set the result so we can verify it's being modified */
	advice.lla_lockahead_result = 345678;

	rc = llapi_ladvise(fd, 0, count, &advice);
	ASSERTF(rc == 0,
		"cannot lockahead '%s': %s", mainpath, strerror(errno));
	ASSERTF(advice.lla_lockahead_result == 0,
		"unexpected extent result: %d",
		advice.lla_lockahead_result);

	/* Ask again until we get the lock (status 1). */
	for (i = 1; i < 100; i++) {
		usleep(100000); /* 0.1 second */
		advice.lla_lockahead_result = 456789;
		rc = llapi_ladvise(fd, 0, count, &advice);
		ASSERTF(rc == 0, "cannot lockahead '%s': %s",
			mainpath, strerror(errno));

		if (advice.lla_lockahead_result > 0)
			break;
	}

	ASSERTF(advice.lla_lockahead_result == LLA_RESULT_SAME,
		"unexpected extent result: %d",
		advice.lla_lockahead_result);

	/* Convert to a sync request on smaller range, should match and not
	 * cancel */
	setup_ladvise_lockahead(&advice, MODE_WRITE_USER, 0, 0,
				write_size - 1 - write_size/2, false);

	advice.lla_lockahead_result = 456789;
	rc = llapi_ladvise(fd, 0, count, &advice);
	ASSERTF(rc == 0, "cannot lockahead '%s': %s",
		mainpath, strerror(errno));
	/* Sync requests cannot give detailed results */
	ASSERTF(advice.lla_lockahead_result == 0,
		"unexpected extent result: %d",
		advice.lla_lockahead_result);

	/* Use an async request to test original lock is still present */
	setup_ladvise_lockahead(&advice, MODE_WRITE_USER, 0, 0,
				write_size - 1, true);

	advice.lla_lockahead_result = 456789;
	rc = llapi_ladvise(fd, 0, count, &advice);
	ASSERTF(rc == 0, "cannot lockahead '%s': %s",
		mainpath, strerror(errno));
	ASSERTF(advice.lla_lockahead_result == LLA_RESULT_SAME,
		"unexpected extent result: %d",
		advice.lla_lockahead_result);

	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));

	close(fd);

	return expected_lock_count;
}

/* Test sync requests, and conflict with async requests */
static int test21(void)
{
	struct llapi_lu_ladvise advice;
	const int count = 1;
	int fd;
	size_t write_size = 1024 * 1024;
	int rc;
	char buf[write_size];
	int i;
	int expected_lock_count = 1;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	/* Async request */
	setup_ladvise_lockahead(&advice, MODE_WRITE_USER, 0, 0,
				write_size - 1, true);

	/* Manually set the result so we can verify it's being modified */
	advice.lla_lockahead_result = 345678;

	rc = llapi_ladvise(fd, 0, count, &advice);
	ASSERTF(rc == 0,
		"cannot lockahead '%s': %s", mainpath, strerror(errno));
	ASSERTF(advice.lla_lockahead_result == 0,
		"unexpected extent result: %d",
		advice.lla_lockahead_result);

	/* Ask again until we get the lock (status 1). */
	for (i = 1; i < 100; i++) {
		usleep(100000); /* 0.1 second */
		advice.lla_lockahead_result = 456789;
		rc = llapi_ladvise(fd, 0, count, &advice);
		ASSERTF(rc == 0, "cannot lockahead '%s': %s",
			mainpath, strerror(errno));

		if (advice.lla_lockahead_result > 0)
			break;
	}

	ASSERTF(advice.lla_lockahead_result == LLA_RESULT_SAME,
		"unexpected extent result: %d",
		advice.lla_lockahead_result);

	/* Convert to a sync request on larger range, should cancel existing
	 * lock */
	setup_ladvise_lockahead(&advice, MODE_WRITE_USER, 0, 0,
				write_size*2 - 1, false);

	advice.lla_lockahead_result = 456789;
	rc = llapi_ladvise(fd, 0, count, &advice);
	ASSERTF(rc == 0, "cannot lockahead '%s': %s",
		mainpath, strerror(errno));
	/* Sync requests cannot give detailed results */
	ASSERTF(advice.lla_lockahead_result == 0,
		"unexpected extent result: %d",
		advice.lla_lockahead_result);

	/* Use an async request to test new lock is there */
	setup_ladvise_lockahead(&advice, MODE_WRITE_USER, 0, 0,
				write_size*2 - 1, true);

	advice.lla_lockahead_result = 456789;
	rc = llapi_ladvise(fd, 0, count, &advice);
	ASSERTF(rc == 0, "cannot lockahead '%s': %s",
		mainpath, strerror(errno));
	ASSERTF(advice.lla_lockahead_result == LLA_RESULT_SAME,
		"unexpected extent result: %d",
		advice.lla_lockahead_result);

	memset(buf, 0xaa, write_size);
	rc = write(fd, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath, strerror(errno));

	close(fd);

	return expected_lock_count;
}

/* Test various valid and invalid inputs */
static int test22(void)
{
	struct llapi_lu_ladvise *advice;
	const int count = 1;
	int fd;
	int rc;
	size_t start = 0;
	size_t end = 0;

	fd = open(mainpath, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	/* A valid async request first */
	advice = malloc(sizeof(struct llapi_lu_ladvise)*count);
	start = 0;
	end = 1024*1024;
	setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0, start, end, true);
	rc = llapi_ladvise(fd, 0, count, advice);
	ASSERTF(rc == 0, "cannot lockahead '%s' : %s",
		mainpath, strerror(errno));
	free(advice);

	/* Valid request sync request */
	advice = malloc(sizeof(struct llapi_lu_ladvise)*count);
	start = 0;
	end = 1024*1024;
	setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0, start, end, false);
	rc = llapi_ladvise(fd, 0, count, advice);
	ASSERTF(rc == 0, "cannot lockahead '%s' : %s",
		mainpath, strerror(errno));
	free(advice);

	/* No actual block */
	advice = malloc(sizeof(struct llapi_lu_ladvise)*count);
	start = 0;
	end = 0;
	setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0, start, end, true);
	rc = llapi_ladvise(fd, 0, count, advice);
	ASSERTF(rc == -1 && errno == EINVAL,
		"unexpected return for no block lock: %d %s",
		rc, strerror(errno));
	free(advice);

	/* end before start */
	advice = malloc(sizeof(struct llapi_lu_ladvise)*count);
	start = 1024 * 1024;
	end = 0;
	setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0, start, end, true);
	rc = llapi_ladvise(fd, 0, count, advice);
	ASSERTF(rc == -1 && errno == EINVAL,
		"unexpected return for reversed block: %d %s",
		rc, strerror(errno));
	free(advice);

	/* bogus lock mode - 0x65464 */
	advice = malloc(sizeof(struct llapi_lu_ladvise)*count);
	start = 0;
	end = 1024 * 1024;
	setup_ladvise_lockahead(advice, 0x65464, 0, start, end, true);
	rc = llapi_ladvise(fd, 0, count, advice);
	ASSERTF(rc == -1 && errno == EINVAL,
		"unexpected return for bogus lock mode: %d %s",
		rc, strerror(errno));
	free(advice);

	/* bogus flags, 0x80 */
	advice = malloc(sizeof(struct llapi_lu_ladvise)*count);
	start = 0;
	end = 1024 * 1024;
	setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0x80, start, end,
				true);
	rc = llapi_ladvise(fd, 0, count, advice);
	ASSERTF(rc == -1 && errno == EINVAL,
		"unexpected return for bogus flags: %u %d %s",
		0x80, rc, strerror(errno));
	free(advice);

	/* bogus flags, 0xff - CEF_MASK */
	advice = malloc(sizeof(struct llapi_lu_ladvise)*count);
	end = 1024 * 1024;
	setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0xff, start, end,
				true);
	rc = llapi_ladvise(fd, 0, count, advice);
	ASSERTF(rc == -1 && errno == EINVAL,
		"unexpected return for bogus flags: %u %d %s",
		0xff, rc, strerror(errno));
	free(advice);

	/* bogus flags, 0xffffffff */
	advice = malloc(sizeof(struct llapi_lu_ladvise)*count);
	end = 1024 * 1024;
	setup_ladvise_lockahead(advice, MODE_WRITE_USER, 0xffffffff, start,
				end, true);
	rc = llapi_ladvise(fd, 0, count, advice);
	ASSERTF(rc == -1 && errno == EINVAL,
		"unexpected return for bogus flags: %u %d %s",
		0xffffffff, rc, strerror(errno));
	free(advice);

	close(fd);

	return 0;
}

/* Do lockahead requests from two mount points & sanity check size
 *
 * The key thing here is that client2 updates the size by writing, then asks
 * for another lock beyond that.  That next lock is never used.
 * The bug (LU-11670) is that the glimpse for client1 will only check the
 * highest lock and miss the size update made by the lower lock.
 */
static int test23(void)
{
	struct llapi_lu_ladvise advice;
	size_t write_size = 1024 * 1024;
	char buf[write_size];
	const int count = 1;
	struct stat sb;
	struct stat sb2;
	int fd;
	/* On second mount */
	int fd2;
	int rc;
	int i;

	fd = open(mainpath, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		mainpath, strerror(errno));

	/* mainpath2 is a different Lustre mount */
	fd2 = open(mainpath2, O_RDWR, S_IRUSR | S_IWUSR);
	ASSERTF(fd2 >= 0, "open failed for '%s': %s",
		mainpath2, strerror(errno));

	/* Lock + write MiB 1 from second client */
	setup_ladvise_lockahead(&advice, MODE_WRITE_USER, 0, 0,
				write_size - 1, true);

	/* Manually set the result so we can verify it's being modified */
	advice.lla_lockahead_result = 345678;

	rc = llapi_ladvise(fd2, 0, count, &advice);
	ASSERTF(rc == 0,
		"cannot lockahead '%s': %s", mainpath2, strerror(errno));
	ASSERTF(advice.lla_lockahead_result == 0,
		"unexpected extent result: %d",
		advice.lla_lockahead_result);

	/* Ask again until we get the lock (status 1). */
	for (i = 1; i < 100; i++) {
		usleep(100000); /* 0.1 second */
		advice.lla_lockahead_result = 456789;
		rc = llapi_ladvise(fd2, 0, count, &advice);
		ASSERTF(rc == 0, "cannot lockahead '%s': %s",
			mainpath2, strerror(errno));

		if (advice.lla_lockahead_result > 0)
			break;
	}

	ASSERTF(advice.lla_lockahead_result == LLA_RESULT_SAME,
		"unexpected extent result: %d",
		advice.lla_lockahead_result);

	rc = write(fd2, buf, write_size);
	ASSERTF(rc == sizeof(buf), "write failed for '%s': %s",
		mainpath2, strerror(errno));

	/* Lock (but don't write) MiB 2 from second client */
	setup_ladvise_lockahead(&advice, MODE_WRITE_USER, 0, write_size,
				2*write_size - 1, true);

	/* Manually set the result so we can verify it's being modified */
	advice.lla_lockahead_result = 345678;

	rc = llapi_ladvise(fd2, 0, count, &advice);
	ASSERTF(rc == 0,
		"cannot lockahead '%s': %s", mainpath2, strerror(errno));
	ASSERTF(advice.lla_lockahead_result == 0,
		"unexpected extent result: %d",
		advice.lla_lockahead_result);

	/* Ask again until we get the lock (status 1). */
	for (i = 1; i < 100; i++) {
		usleep(100000); /* 0.1 second */
		advice.lla_lockahead_result = 456789;
		rc = llapi_ladvise(fd2, 0, count, &advice);
		ASSERTF(rc == 0, "cannot lockahead '%s': %s",
			mainpath2, strerror(errno));

		if (advice.lla_lockahead_result > 0)
			break;
	}

	ASSERTF(advice.lla_lockahead_result == LLA_RESULT_SAME,
		"unexpected extent result: %d",
		advice.lla_lockahead_result);

	rc = fstat(fd, &sb);
	ASSERTF(!rc, "stat failed for '%s': %s",
		mainpath, strerror(errno));
	rc = fstat(fd2, &sb2);
	ASSERTF(!rc, "stat failed for '%s': %s",
		mainpath2, strerror(errno));

	ASSERTF(sb.st_size == sb2.st_size,
		"size on %s and %s differs: %lu vs %lu",
		mainpath, mainpath2, sb.st_size, sb2.st_size);

	ASSERTF(sb.st_size == write_size, "size %lu != bytes written (%lu)",
		sb.st_size, write_size);

	close(fd);
	close(fd2);

	return 0;
}

static void usage(char *prog)
{
	fprintf(stderr,
		"Usage: %s [-d lustre_dir], [-D lustre_dir2] [-t test]\n",
		prog);
	exit(-1);
}

static void process_args(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "d:D:f:t:")) != -1) {
		switch (c) {
		case 'f':
			mainfile = optarg;
			break;
		case 'd':
			lustre_dir = optarg;
			break;
		case 'D':
			lustre_dir2 = optarg;
			break;
		case 't':
			single_test = atoi(optarg);
			break;
		case '?':
		default:
			fprintf(stderr, "Invalid option '%c'\n", optopt);
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
	if (mainfile == NULL)
		mainfile = "lockahead_test_654";

	rc = llapi_search_mounts(lustre_dir, 0, fsmountdir, fsname);
	if (rc != 0) {
		fprintf(stderr, "Error: '%s': not a Lustre filesystem\n",
			lustre_dir);
		return -1;
	}

	if (lustre_dir2) {
		rc = llapi_search_mounts(lustre_dir2, 0, fsmountdir, fsname);
		if (rc != 0) {
			fprintf(stderr,
				"Error: '%s': not a Lustre filesystem\n",
				lustre_dir2);
			return -1;
		}
	}

	/* Play nice with Lustre test scripts. Non-line buffered output
	 * stream under I/O redirection may appear incorrectly. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	/* Create a test filename and reuse it. Remove possibly old files. */
	rc = snprintf(mainpath, sizeof(mainpath), "%s/%s", lustre_dir,
		      mainfile);
	ASSERTF(rc > 0 && rc < sizeof(mainpath), "invalid name for mainpath");

	if (lustre_dir2) {
		rc = snprintf(mainpath2, sizeof(mainpath2), "%s/%s",
			      lustre_dir2, mainfile);
		ASSERTF(rc > 0 && rc < sizeof(mainpath2),
			"invalid name for mainpath2");
	}

	cleanup();

	switch (single_test) {
	case 0:
		PERFORM(test10);
		PERFORM(test11);
		PERFORM(test12);
		PERFORM(test13);
		PERFORM(test14);
		PERFORM(test15);
		PERFORM(test16);
		PERFORM(test17);
		PERFORM(test18);
		PERFORM(test19);
		PERFORM(test20);
		PERFORM(test21);
		PERFORM(test22);
		/* Some tests require a second mount point */
		if (lustre_dir2)
			PERFORM(test23);
		/* When running all the test cases, we can't use the return
		 * from the last test case, as it might be non-zero to return
		 * info, rather than for an error.  Test cases assert and exit
		 * if an error occurs. */
		rc = 0;
		break;
	case 10:
		PERFORM(test10);
		break;
	case 11:
		PERFORM(test11);
		break;
	case 12:
		PERFORM(test12);
		break;
	case 13:
		PERFORM(test13);
		break;
	case 14:
		PERFORM(test14);
		break;
	case 15:
		PERFORM(test15);
		break;
	case 16:
		PERFORM(test16);
		break;
	case 17:
		PERFORM(test17);
		break;
	case 18:
		PERFORM(test18);
		break;
	case 19:
		PERFORM(test19);
		break;
	case 20:
		PERFORM(test20);
		break;
	case 21:
		PERFORM(test21);
		break;
	case 22:
		PERFORM(test22);
		break;
	case 23:
		ASSERTF(lustre_dir2,
			"must provide second mount point for test 23");
		PERFORM(test23);
		break;
	default:
		fprintf(stderr, "impossible value of single_test %d\n",
			single_test);
		rc = -1;
		break;
	}

	return rc;
}
