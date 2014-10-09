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

/* Copyright 2014 Cray Inc, all rights reserved. */
/* Some portions are extracted from llapi_layout_test.c */

/* The purpose of this test is to check some HSM functions. HSM must
 * be enabled before running it:
 *   echo enabled > /proc/fs/lustre/mdt/lustre-MDT0000/hsm_control
 */

/* All tests return 0 on success and non zero on error. The program will
 * exit as soon a non zero error is returned. */

#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>

#include <lustre/lustreapi.h>

static char fsmountdir[PATH_MAX];      /* Lustre mountpoint */
static char *lustre_dir;               /* Test directory inside Lustre */

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
	} while (0)							\

#define PERFORM(testfn) \
	do {								\
		fprintf(stderr, "Starting test " #testfn " at %llu\n",	\
			(unsigned long long)time(NULL));		\
		testfn();						\
		fprintf(stderr, "Finishing test " #testfn " at %llu\n",	\
		       (unsigned long long)time(NULL));			\
	} while (0)

/* Register and unregister 2000 times. Ensures there is no fd leak
 * since there is usually 1024 fd per process. */
int test1(void)
{
	int i;
	int rc;
	struct hsm_copytool_private *ctdata;

	for (i = 0; i < 2000; i++) {
		rc = llapi_hsm_copytool_register(&ctdata, fsmountdir,
						 0, NULL, 0);
		ASSERTF(rc == 0,
			"llapi_hsm_copytool_register failed: %s, loop=%d",
			strerror(-rc), i);

		rc = llapi_hsm_copytool_unregister(&ctdata);
		ASSERTF(rc == 0,
			"llapi_hsm_copytool_unregister failed: %s, loop=%d",
			strerror(-rc), i);
	}

	return 0;
}

/* Re-register */
int test2(void)
{
	int rc;
	struct hsm_copytool_private *ctdata1;
	struct hsm_copytool_private *ctdata2;

	rc = llapi_hsm_copytool_register(&ctdata1, fsmountdir, 0, NULL, 0);
	ASSERTF(rc == 0, "llapi_hsm_copytool_register failed: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_register(&ctdata2, fsmountdir, 0, NULL, 0);
	ASSERTF(rc == 0, "llapi_hsm_copytool_register failed: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_unregister(&ctdata2);
	ASSERTF(rc == 0, "llapi_hsm_copytool_unregister failed: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_unregister(&ctdata1);
	ASSERTF(rc == 0, "llapi_hsm_copytool_unregister failed: %s",
		strerror(-rc));

	return 0;
}

/* Bad parameters to llapi_hsm_copytool_register(). */
int test3(void)
{
	int rc;
	struct hsm_copytool_private *ctdata;
	int archives[33];

	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir, 1, NULL, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_register error: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir, 33, NULL, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_register error: %s",
		strerror(-rc));

	memset(archives, 1, sizeof(archives));
	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir, 34, archives, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_register error: %s",
		strerror(-rc));

#if 0
	/* BUG? Should that fail or not? */
	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir, -1, NULL, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_register error: %s",
		strerror(-rc));
#endif

	memset(archives, -1, sizeof(archives));
	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir, 1, archives, 0);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_register error: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_register(&ctdata, "/tmp", 0, NULL, 0);
	ASSERTF(rc == -ENOENT, "llapi_hsm_copytool_register error: %s",
		strerror(-rc));

	return 0;
}

/* Bad parameters to llapi_hsm_copytool_unregister(). */
int test4(void)
{
	int rc;

	rc = llapi_hsm_copytool_unregister(NULL);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_unregister error: %s",
		strerror(-rc));

	return 0;
}

/* Test llapi_hsm_copytool_recv in non blocking mode */
int test5(void)
{
	int rc;
	int i;
	struct hsm_copytool_private *ctdata;
	struct hsm_action_list	*hal;
	int msgsize;

	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir,
					 0, NULL, O_NONBLOCK);
	ASSERTF(rc == 0, "llapi_hsm_copytool_unregister failed: %s",
		strerror(-rc));

	/* Hopefully there is nothing lingering */
	for (i = 0; i < 1000; i++) {
		rc = llapi_hsm_copytool_recv(ctdata, &hal, &msgsize);
		ASSERTF(rc == -EWOULDBLOCK, "llapi_hsm_copytool_recv error: %s",
			strerror(-rc));
	}

	rc = llapi_hsm_copytool_unregister(&ctdata);
	ASSERTF(rc == 0, "llapi_hsm_copytool_unregister failed: %s",
		strerror(-rc));

	return 0;
}

/* Test llapi_hsm_copytool_recv with bogus parameters */
int test6(void)
{
	struct hsm_copytool_private *ctdata;
	struct hsm_action_list *hal;
	int rc;
	int msgsize;

	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir, 0, NULL, 0);
	ASSERTF(rc == 0, "llapi_hsm_copytool_unregister failed: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_recv(NULL, &hal, &msgsize);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_recv error: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_recv(ctdata, NULL, &msgsize);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_recv error: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_recv(ctdata, &hal, NULL);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_recv error: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_recv(ctdata, NULL, NULL);
	ASSERTF(rc == -EINVAL, "llapi_hsm_copytool_recv error: %s",
		strerror(-rc));

	rc = llapi_hsm_copytool_unregister(&ctdata);
	ASSERTF(rc == 0, "llapi_hsm_copytool_unregister failed: %s",
		strerror(-rc));

	return 0;
}

/* Test polling (without actual traffic) */
int test7(void)
{
	int rc;
	struct hsm_copytool_private *ctdata;
	struct hsm_action_list	*hal;
	int msgsize;
	int fd;
	struct pollfd fds[1];

	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir,
					 0, NULL, O_NONBLOCK);
	ASSERTF(rc == 0, "llapi_hsm_copytool_register failed: %s",
		strerror(-rc));

	fd = llapi_hsm_copytool_get_fd(ctdata);
	ASSERTF(fd >= 0, "llapi_hsm_copytool_get_fd failed: %s",
		strerror(-rc));

	/* Ensure it's read-only */
	rc = write(fd, &rc, 1);
	ASSERTF(rc == -1 && errno == EBADF, "write error: %d, %s",
		rc, strerror(errno));

	rc = llapi_hsm_copytool_recv(ctdata, &hal, &msgsize);
	ASSERTF(rc == -EWOULDBLOCK, "llapi_hsm_copytool_recv error: %s",
		strerror(-rc));

	fds[0].fd = fd;
	fds[0].events = POLLIN;
	rc = poll(fds, 1, 10);
	ASSERTF(rc == 0, "poll failed: %d, %s",
		rc, strerror(errno)); /* no event */

	rc = llapi_hsm_copytool_unregister(&ctdata);
	ASSERTF(rc == 0, "llapi_hsm_copytool_unregister failed: %s",
		strerror(-rc));

	return 0;
}

/* Create the testfile of a given length. It returns a valid file
 * descriptor. */
static char testfile[PATH_MAX];
static int create_testfile(size_t length)
{
	int rc;
	int fd;

	rc = snprintf(testfile, sizeof(testfile), "%s/hsm_check_test",
		      lustre_dir);
	ASSERTF((rc > 0 && rc < sizeof(testfile)), "invalid name for testfile");

	/* Remove old test file, if any. */
	unlink(testfile);

	/* Use truncate so we can create a file (almost) as big as we
	 * want, while taking 0 bytes of data. */
	fd = creat(testfile, S_IRWXU);
	ASSERTF(fd >= 0, "create failed for '%s': %s",
		testfile, strerror(errno));

	rc = ftruncate(fd, length);
	ASSERTF(rc == 0, "ftruncate failed for '%s': %s",
		testfile, strerror(errno));

	return fd;
}

/* Test llapi_hsm_state_get. */
void test50(void)
{
	struct hsm_user_state hus;
	int rc;
	int fd;

	fd = create_testfile(100);

	/* With fd variant */
	rc = llapi_hsm_state_get_fd(fd, &hus);
	ASSERTF(rc == 0, "llapi_hsm_state_get_fd failed: %s", strerror(-rc));
	ASSERTF(hus.hus_states == 0, "state=%u", hus.hus_states);

	rc = llapi_hsm_state_get_fd(fd, NULL);
	ASSERTF(rc == -EFAULT, "llapi_hsm_state_get_fd error: %s",
		strerror(-rc));

	rc = close(fd);
	ASSERTF(rc == 0, "close failed: %s", strerror(errno));

	/* Without fd */
	rc = llapi_hsm_state_get(testfile, &hus);
	ASSERTF(rc == 0, "llapi_hsm_state_get failed: %s", strerror(-rc));
	ASSERTF(hus.hus_states == 0, "state=%u", hus.hus_states);

	rc = llapi_hsm_state_get(testfile, NULL);
	ASSERTF(rc == -EFAULT, "llapi_hsm_state_get error: %s",
		strerror(-rc));

	memset(&hus, 0xaa, sizeof(hus));
	rc = llapi_hsm_state_get(testfile, &hus);
	ASSERTF(rc == 0, "llapi_hsm_state_get failed: %s", strerror(-rc));
	ASSERTF(hus.hus_states == 0, "state=%u", hus.hus_states);
	ASSERTF(hus.hus_archive_id == 0, "archive_id=%u", hus.hus_archive_id);
	ASSERTF(hus.hus_in_progress_state == 0, "hus_in_progress_state=%u",
		hus.hus_in_progress_state);
	ASSERTF(hus.hus_in_progress_action == 0, "hus_in_progress_action=%u",
		hus.hus_in_progress_action);
}

/* Test llapi_hsm_state_set. */
void test51(void)
{
	int rc;
	int fd;
	int i;
	struct hsm_user_state hus;

	fd = create_testfile(100);

	rc = llapi_hsm_state_set_fd(fd, 0, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	/* Set archive id */
	for (i = 0; i <= 32; i++) {
		rc = llapi_hsm_state_set_fd(fd, HS_EXISTS, 0, i);
		ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s",
			strerror(-rc));

		rc = llapi_hsm_state_get_fd(fd, &hus);
		ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s",
			strerror(-rc));
		ASSERTF(hus.hus_states == HS_EXISTS, "state=%u",
			hus.hus_states);
		ASSERTF(hus.hus_archive_id == i, "archive_id=%u, i=%d",
			hus.hus_archive_id, i);
	}

	/* Bugs following. This should not succeed. Builds the following file:
	 *
	 *   $ ../utils/lfs hsm_state /mnt/lustre/hsm_check_test
	 *
	 *   /mnt/lustre/hsm_check_test: (0x8008007d) released exists
	 *     archived never_release never_archive lost_from_hsm,
	 *     archive_id:-1789
	 */

	/* Invalid archive numbers */
	rc = llapi_hsm_state_set_fd(fd, HS_EXISTS, 0, 33);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_EXISTS, 0, 151);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_EXISTS, 0, -1789);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	/* Setable + Unsettable flags */
	rc = llapi_hsm_state_set_fd(fd, HS_DIRTY, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, 0, HS_DIRTY, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_ARCHIVED, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_RELEASED, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_NORELEASE, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_NOARCHIVE, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, HS_LOST, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	/* Bogus flags for good measure. */
	rc = llapi_hsm_state_set_fd(fd, 0x00080000, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	rc = llapi_hsm_state_set_fd(fd, 0x80000000, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_state_set_fd failed: %s", strerror(-rc));

	close(fd);
}

/* Test llapi_hsm_current_action */
void test52(void)
{
	int rc;
	int fd;
	struct hsm_current_action hca;

	/* No fd equivalent, so close it. */
	fd = create_testfile(100);
	close(fd);

	rc = llapi_hsm_current_action(testfile, &hca);
	ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s", strerror(-rc));
	ASSERTF(hca.hca_state, "hca_state=%u", hca.hca_state);
	ASSERTF(hca.hca_action, "hca_state=%u", hca.hca_action);

	rc = llapi_hsm_current_action(testfile, NULL);
	ASSERTF(rc == -EFAULT, "llapi_hsm_current_action failed: %s",
		strerror(-rc));
}

/* Helper to simulate archiving a file. No actual data movement
 * happens. */
void (*helper_progress)(struct hsm_copyaction_private *hcp);
void helper_archiving(const size_t length)
{
	int rc;
	int fd;
	struct hsm_copytool_private *ctdata;
	struct hsm_user_request	*hur;
	struct hsm_action_list	*hal;
	struct hsm_action_item	*hai;
	int			 msgsize;
	struct hsm_copyaction_private *hcp;
	struct hsm_user_state hus;

	fd = create_testfile(length);

	rc = llapi_hsm_copytool_register(&ctdata, fsmountdir,
					 0, NULL, 0);
	ASSERTF(rc == 0, "llapi_hsm_copytool_register failed: %s",
		strerror(-rc));

	/* Create and send the archive request. */
	hur = llapi_hsm_user_request_alloc(1, 0);
	ASSERTF(hur != NULL, "llapi_hsm_user_request_alloc returned NULL");

	hur->hur_request.hr_action = HUA_ARCHIVE;
	hur->hur_request.hr_archive_id = 1;
	hur->hur_request.hr_flags = 0;
	hur->hur_request.hr_itemcount = 1;
	hur->hur_request.hr_data_len = 0;
	hur->hur_user_item[0].hui_extent.length = -1;

	rc = llapi_fd2fid(fd, &hur->hur_user_item[0].hui_fid);
	ASSERTF(rc == 0, "llapi_fd2fid failed: %s", strerror(-rc));

	close(fd);

	rc = llapi_hsm_request(testfile, hur);
	ASSERTF(rc == 0, "llapi_hsm_request failed: %s", strerror(-rc));

	free(hur);

	/* Read the request */
	rc = llapi_hsm_copytool_recv(ctdata, &hal, &msgsize);
	ASSERTF(rc == 0, "llapi_hsm_copytool_recv failed: %s", strerror(-rc));
	ASSERTF(hal->hal_count == 1, "hal_count=%d", hal->hal_count);

	hai = hai_first(hal);
	ASSERTF(hai != NULL, "hai_first returned NULL");
	ASSERTF(hai->hai_action == HSMA_ARCHIVE,
		"hai_action=%d", hai->hai_action);

	/* "Begin" archiving */
	hcp = NULL;
	rc = llapi_hsm_action_begin(&hcp, ctdata, hai, -1, 0, false);
	ASSERTF(rc == 0, "llapi_hsm_action_begin failed: %s", strerror(-rc));
	ASSERTF(hcp != NULL, "hcp is NULL");

	if (helper_progress)
		helper_progress(hcp);

	/* Done archiving */
	rc = llapi_hsm_action_end(&hcp, &hai->hai_extent, 0, 0);
	ASSERTF(rc == 0, "llapi_hsm_action_end failed: %s", strerror(-rc));
	ASSERTF(hcp == NULL, "hcp is NULL");

	/* Close HSM client */
	rc = llapi_hsm_copytool_unregister(&ctdata);
	ASSERTF(rc == 0, "llapi_hsm_copytool_unregister failed: %s",
		strerror(-rc));

	/* Final check */
	rc = llapi_hsm_state_get(testfile, &hus);
	ASSERTF(rc == 0, "llapi_hsm_state_get failed: %s", strerror(-rc));
	ASSERTF(hus.hus_states == (HS_EXISTS | HS_ARCHIVED),
		"state=%u", hus.hus_states);
}

/* Simple archive. No progress. */
void test100(void)
{
	const size_t length = 100;
	helper_progress = NULL;
	helper_archiving(length);
}

/* Archive, with a report every byte. */
void test101(void)
{
	const size_t length = 1000;

	void test101_progress(struct hsm_copyaction_private *hcp)
	{
		int i;
		int rc;
		struct hsm_extent he;
		struct hsm_current_action hca;

		/* Report progress. 1 byte at a time :) */
		for (i = 0; i < length; i++) {
			he.offset = i;
			he.length = 1;
			rc = llapi_hsm_action_progress(hcp, &he, length, 0);
			ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
				strerror(-rc));
		}

		rc = llapi_hsm_current_action(testfile, &hca);
		ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
			strerror(-rc));
		ASSERTF(hca.hca_state == HPS_RUNNING,
			"hca_state=%u", hca.hca_state);
		ASSERTF(hca.hca_action == HUA_ARCHIVE,
			"hca_state=%u", hca.hca_action);
		ASSERTF(hca.hca_location.length == length,
			"length=%llu", hca.hca_location.length);
	}

	helper_progress = test101_progress;
	helper_archiving(length);
}

/* Archive, with a report every byte, backwards. */
void test102(void)
{
	const size_t length = 1000;

	void test102_progress(struct hsm_copyaction_private *hcp)
	{
		int i;
		int rc;
		struct hsm_extent he;
		struct hsm_current_action hca;

		/* Report progress. 1 byte at a time :) */
		for (i = length-1; i >= 0; i--) {
			he.offset = i;
			he.length = 1;
			rc = llapi_hsm_action_progress(hcp, &he, length, 0);
			ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
				strerror(-rc));
		}

		rc = llapi_hsm_current_action(testfile, &hca);
		ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
			strerror(-rc));
		ASSERTF(hca.hca_state == HPS_RUNNING,
			"hca_state=%u", hca.hca_state);
		ASSERTF(hca.hca_action == HUA_ARCHIVE,
			"hca_state=%u", hca.hca_action);
		ASSERTF(hca.hca_location.length == length,
			"length=%llu", hca.hca_location.length);
	}

	helper_progress = test102_progress;
	helper_archiving(length);
}

/* Archive, with a single report. */
void test103(void)
{
	const size_t length = 1000;

	void test103_progress(struct hsm_copyaction_private *hcp)
	{
		int rc;
		struct hsm_extent he;
		struct hsm_current_action hca;

		he.offset = 0;
		he.length = length;
		rc = llapi_hsm_action_progress(hcp, &he, length, 0);
		ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
			strerror(-rc));

		rc = llapi_hsm_current_action(testfile, &hca);
		ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
			strerror(-rc));
		ASSERTF(hca.hca_state == HPS_RUNNING,
			"hca_state=%u", hca.hca_state);
		ASSERTF(hca.hca_action == HUA_ARCHIVE,
			"hca_state=%u", hca.hca_action);
		ASSERTF(hca.hca_location.length == length,
			"length=%llu", hca.hca_location.length);
	}

	helper_progress = test103_progress;
	helper_archiving(length);
}

/* Archive, with 2 reports. */
void test104(void)
{
	const size_t length = 1000;

	void test104_progress(struct hsm_copyaction_private *hcp)
	{
		int rc;
		struct hsm_extent he;
		struct hsm_current_action hca;

		he.offset = 0;
		he.length = length/2;
		rc = llapi_hsm_action_progress(hcp, &he, length, 0);
		ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
			strerror(-rc));

		he.offset = length/2;
		he.length = length/2;
		rc = llapi_hsm_action_progress(hcp, &he, length, 0);
		ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
			strerror(-rc));

		rc = llapi_hsm_current_action(testfile, &hca);
		ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
			strerror(-rc));
		ASSERTF(hca.hca_state == HPS_RUNNING,
			"hca_state=%u", hca.hca_state);
		ASSERTF(hca.hca_action == HUA_ARCHIVE,
			"hca_state=%u", hca.hca_action);
		ASSERTF(hca.hca_location.length == length,
			"length=%llu", hca.hca_location.length);
	}

	helper_progress = test104_progress;
	helper_archiving(length);
}

/* Archive, with 1 bogus report. */
void test105(void)
{
	const size_t length = 1000;

	void test105_progress(struct hsm_copyaction_private *hcp)
	{
		int rc;
		struct hsm_extent he;
		struct hsm_current_action hca;

		he.offset = 2*length;
		he.length = 10*length;
		rc = llapi_hsm_action_progress(hcp, &he, length, 0);
		ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
			strerror(-rc));

		rc = llapi_hsm_current_action(testfile, &hca);
		ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
			strerror(-rc));
		ASSERTF(hca.hca_state == HPS_RUNNING,
			"hca_state=%u", hca.hca_state);
		ASSERTF(hca.hca_action == HUA_ARCHIVE,
			"hca_state=%u", hca.hca_action);

		/* BUG - offset should be 2*length, or length should
		 * be 8*length */
		ASSERTF(hca.hca_location.length == 10*length,
			"length=%llu", hca.hca_location.length);
	}

	helper_progress = test105_progress;
	helper_archiving(length);
}

/* Archive, with 1 empty report. */
void test106(void)
{
	const size_t length = 1000;

	void test106_progress(struct hsm_copyaction_private *hcp)
	{
		int rc;
		struct hsm_extent he;
		struct hsm_current_action hca;

		he.offset = 0;
		he.length = 0;
		rc = llapi_hsm_action_progress(hcp, &he, length, 0);
		ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
			strerror(-rc));

		rc = llapi_hsm_current_action(testfile, &hca);
		ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
			strerror(-rc));
		ASSERTF(hca.hca_state == HPS_RUNNING,
			"hca_state=%u", hca.hca_state);
		ASSERTF(hca.hca_action == HUA_ARCHIVE,
			"hca_state=%u", hca.hca_action);
		ASSERTF(hca.hca_location.length == 0,
			"length=%llu", hca.hca_location.length);
	}

	helper_progress = test106_progress;
	helper_archiving(length);
}

/* Archive, with 1 bogus report. */
void test107(void)
{
	const size_t length = 1000;

	void test107_progress(struct hsm_copyaction_private *hcp)
	{
		int rc;
		struct hsm_extent he;
		struct hsm_current_action hca;

		he.offset = -1;
		he.length = 10;
		rc = llapi_hsm_action_progress(hcp, &he, length, 0);
		ASSERTF(rc == -EINVAL, "llapi_hsm_action_progress error: %s",
			strerror(-rc));

		rc = llapi_hsm_current_action(testfile, &hca);
		ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
			strerror(-rc));
		ASSERTF(hca.hca_state == HPS_RUNNING,
			"hca_state=%u", hca.hca_state);
		ASSERTF(hca.hca_action == HUA_ARCHIVE,
			"hca_state=%u", hca.hca_action);
		ASSERTF(hca.hca_location.length == 0,
			"length=%llu", hca.hca_location.length);
	}

	helper_progress = test107_progress;
	helper_archiving(length);
}

/* Archive, with same report, many times. */
void test108(void)
{
	const size_t length = 1000;

	void test108_progress(struct hsm_copyaction_private *hcp)
	{
		int rc;
		struct hsm_extent he;
		int i;
		struct hsm_current_action hca;

		for (i = 0; i < 1000; i++) {
			he.offset = 0;
			he.length = length;
			rc = llapi_hsm_action_progress(hcp, &he, length, 0);
			ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
				strerror(-rc));
		}

		rc = llapi_hsm_current_action(testfile, &hca);
		ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
			strerror(-rc));
		ASSERTF(hca.hca_state == HPS_RUNNING,
			"hca_state=%u", hca.hca_state);
		ASSERTF(hca.hca_action == HUA_ARCHIVE,
			"hca_state=%u", hca.hca_action);
		ASSERTF(hca.hca_location.length == length,
			"length=%llu", hca.hca_location.length);
	}

	helper_progress = test108_progress;
	helper_archiving(length);
}

/* Archive, 1 report, with large number. */
void test109(void)
{
	const size_t length = 1000;

	void test109_progress(struct hsm_copyaction_private *hcp)
	{
		int rc;
		struct hsm_extent he;
		struct hsm_current_action hca;

		he.offset = 0;
		he.length = 0xffffffffffffffffULL;
		rc = llapi_hsm_action_progress(hcp, &he, length, 0);
		ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
			strerror(-rc));

		rc = llapi_hsm_current_action(testfile, &hca);
		ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
			strerror(-rc));
		ASSERTF(hca.hca_state == HPS_RUNNING,
			"hca_state=%u", hca.hca_state);
		ASSERTF(hca.hca_action == HUA_ARCHIVE,
			"hca_state=%u", hca.hca_action);
		ASSERTF(hca.hca_location.length == 0xffffffffffffffffULL,
			"length=%llu", hca.hca_location.length);
	}

	helper_progress = test109_progress;
	helper_archiving(length);
}

/* Archive, with 10 reports, checking progress. */
void test110(void)
{
	const size_t length = 1000;

	void test110_progress(struct hsm_copyaction_private *hcp)
	{
		int rc;
		int i;
		struct hsm_extent he;
		struct hsm_current_action hca;

		for (i = 0; i < 10; i++) {
			he.offset = i*length/10;
			he.length = length/10;
			rc = llapi_hsm_action_progress(hcp, &he, length, 0);
			ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
				strerror(-rc));

			rc = llapi_hsm_current_action(testfile, &hca);
			ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
				strerror(-rc));
			ASSERTF(hca.hca_state == HPS_RUNNING,
				"hca_state=%u", hca.hca_state);
			ASSERTF(hca.hca_action == HUA_ARCHIVE,
				"hca_state=%u", hca.hca_action);
			ASSERTF(hca.hca_location.length == (i+1)*length/10,
				"i=%d, length=%llu",
				i, hca.hca_location.length);
		}
	}

	helper_progress = test110_progress;
	helper_archiving(length);
}

/* Archive, with 10 reports in reverse order, checking progress. */
void test111(void)
{
	const size_t length = 1000;

	void test111_progress(struct hsm_copyaction_private *hcp)
	{
		int rc;
		int i;
		struct hsm_extent he;
		struct hsm_current_action hca;

		for (i = 0; i < 10; i++) {
			he.offset = (9-i)*length/10;
			he.length = length/10;
			rc = llapi_hsm_action_progress(hcp, &he, length, 0);
			ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
				strerror(-rc));

			rc = llapi_hsm_current_action(testfile, &hca);
			ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
				strerror(-rc));
			ASSERTF(hca.hca_state == HPS_RUNNING,
				"hca_state=%u", hca.hca_state);
			ASSERTF(hca.hca_action == HUA_ARCHIVE,
				"hca_state=%u", hca.hca_action);
			ASSERTF(hca.hca_location.length == (i+1)*length/10,
				"i=%d, length=%llu",
				i, hca.hca_location.length);
		}
	}

	helper_progress = test111_progress;
	helper_archiving(length);
}

/* Archive, with 10 reports, and duplicating them, checking
 * progress. */
void test112(void)
{
	const size_t length = 1000;

	void test112_progress(struct hsm_copyaction_private *hcp)
	{
		int rc;
		int i;
		struct hsm_extent he;
		struct hsm_current_action hca;

		for (i = 0; i < 10; i++) {
			he.offset = i*length/10;
			he.length = length/10;
			rc = llapi_hsm_action_progress(hcp, &he, length, 0);
			ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
				strerror(-rc));

			rc = llapi_hsm_current_action(testfile, &hca);
			ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
				strerror(-rc));
			ASSERTF(hca.hca_state == HPS_RUNNING,
				"hca_state=%u", hca.hca_state);
			ASSERTF(hca.hca_action == HUA_ARCHIVE,
				"hca_state=%u", hca.hca_action);
			ASSERTF(hca.hca_location.length == (i+1)*length/10,
				"i=%d, length=%llu",
				i, hca.hca_location.length);
		}

		for (i = 0; i < 10; i++) {
			he.offset = i*length/10;
			he.length = length/10;
			rc = llapi_hsm_action_progress(hcp, &he, length, 0);
			ASSERTF(rc == 0, "llapi_hsm_action_progress failed: %s",
				strerror(-rc));

			rc = llapi_hsm_current_action(testfile, &hca);
			ASSERTF(rc == 0, "llapi_hsm_current_action failed: %s",
				strerror(-rc));
			ASSERTF(hca.hca_state == HPS_RUNNING,
				"hca_state=%u", hca.hca_state);
			ASSERTF(hca.hca_action == HUA_ARCHIVE,
				"hca_state=%u", hca.hca_action);
			ASSERTF(hca.hca_location.length == length,
				"i=%d, length=%llu",
				i, hca.hca_location.length);
		}

	}

	helper_progress = test112_progress;
	helper_archiving(length);
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
		fprintf(stderr, "Error: %s: not a Lustre filesystem\n",
			lustre_dir);
		return EXIT_FAILURE;
	}

	/* Play nice with Lustre test scripts. Non-line buffered output
	 * stream under I/O redirection may appear incorrectly. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	PERFORM(test1);
	PERFORM(test2);
	PERFORM(test3);
	PERFORM(test4);
	PERFORM(test5);
	PERFORM(test6);
	PERFORM(test7);
	PERFORM(test50);
	PERFORM(test51);
	PERFORM(test52);
	PERFORM(test100);
	PERFORM(test101);
	PERFORM(test102);
	PERFORM(test103);
	PERFORM(test104);
	PERFORM(test105);
	PERFORM(test106);
	PERFORM(test107);
	PERFORM(test108);
	PERFORM(test109);
	PERFORM(test110);
	PERFORM(test111);
	PERFORM(test112);

	return EXIT_SUCCESS;
}
