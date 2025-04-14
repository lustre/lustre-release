// SPDX License Identifier: GPL-2.0
/* Basic framework for Lustre llapi tests.
 * All tests return 0 on success and non-zero on error.
 * The program will run all tests unless a list of tests to skip is provided.
 */
/*
 * Copyright 2014, 2015 Cray Inc, all rights reserved.
 * Copyright (c) 2015, Intel Corporation.
 * Copyright (c) 2025, DataDirect Networks, Inc. All rights reserved.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <lustre/lustreapi.h>
#include "llapi_test_utils.h"

static bool run_list_provided;
char fsmountdir[PATH_MAX];      /* Lustre mountpoint */

static void print_test_desc(int test_num, const char *test_desc,
			    const char *status)
{
	int i;

	i = printf(" test%u @%llu: %s ", test_num,
		   (unsigned long long)time(NULL), test_desc);
	for (; i < TEST_DESC_LEN; i++)
		printf(".");
	printf(" %s\n", status);
}

/* This function runs a single test by forking the process.  This way,
 * if there is a segfault during a test, the test program won't crash.
 */
static int test(void (*test_fn)(), const char *test_desc, bool test_skip,
		int test_num)
{
	int rc = 0;
	pid_t pid;
	char status_buf[128];

	if (test_skip) {
		if (!run_list_provided)
			print_test_desc(test_num, test_desc, "skip");
		return 0;
	}

	pid = fork();
	if (pid < 0) {
		ERROR("cannot fork: %s", strerror(errno));
	} else if (pid > 0) {
		int status = 0;

		/* Non-zero value indicates failure. */
		wait(&status);
		if (status == 0) {
			strncpy(status_buf, "pass", sizeof(status_buf));
		} else if WIFSIGNALED(status) {
			snprintf(status_buf, sizeof(status_buf),
				 "fail (exit status %d, killed by SIG%d)",
				 WEXITSTATUS(status), WTERMSIG(status));
			rc = -1;
		} else {
			snprintf(status_buf, sizeof(status_buf),
				 "fail (exit status %d)", WEXITSTATUS(status));
			rc = -1;
		}
		print_test_desc(test_num, test_desc, status_buf);
	} else if (pid == 0) {
		/* Run the test in the child process.
		 * Exit 0 here for success, non-zero from test_fn() on error.
		 */
		test_fn();
		exit(0);
	}

	return rc;
}

/* 'str_tests' are the tests to be skipped, such as "1,3,4,..." */
void set_tests_to_skip(const char *str_tests, struct test_tbl_entry *tst_tbl)
{
	const char *ptr = str_tests;

	if (tst_tbl == NULL || ptr == NULL || strlen(ptr) == 0)
		return;

	while (*ptr != '\0') {
		struct test_tbl_entry *tst;
		char *end;
		unsigned long tstno = strtoul(ptr, &end, 0);

		if (tstno > UINT_MAX || errno)
			DIE("Error: invalid test number '%s'", ptr);

		for (tst = tst_tbl; tst->tte_fn != NULL; tst++) {
			if (tst->tte_num == tstno) {
				tst->tte_skip = true;
				break;
			}
		}
		if (tst->tte_skip == false)
			DIE("Error: test %lu not found", tstno);

		if (*end == ',')
			ptr = end + 1;
		else
			break;
	}
}

/* 'str_tests' are the tests to be run, such as "5,6,7,..." */
void set_tests_to_run(const char *str_tests, struct test_tbl_entry *tst_tbl)
{
	struct test_tbl_entry *tst;
	const char *ptr = str_tests;

	if (tst_tbl == NULL || ptr == NULL || strlen(ptr) == 0)
		return;

	run_list_provided = true;
	for (tst = tst_tbl; tst->tte_fn != NULL; tst++)
		tst->tte_skip = true;

	while (*ptr != '\0') {
		struct test_tbl_entry *tst;
		char *end;
		unsigned long tstno = strtoul(ptr, &end, 0);

		if (tstno > UINT_MAX || errno)
			DIE("Error: invalid test number '%s'", ptr);

		for (tst = tst_tbl; tst->tte_fn != NULL; tst++) {
			if (tst->tte_num == tstno) {
				tst->tte_skip = false;
				break;
			}
		}
		if (tst->tte_skip == true)
			DIE("Error: test %lu not found", tstno);
		if (*end == ',')
			ptr = end + 1;
		else
			break;
	}
}

int run_tests(const char *lustre_dir, struct test_tbl_entry *tst_tbl)
{
	struct test_tbl_entry *tst;
	char fsname[8 + 1];
	struct stat st;
	int rc;

	if (lustre_dir == NULL)
		DIE("no test directory provided\n");

	if (tst_tbl == NULL)
		DIE("no test table provided\n");

	llapi_msg_set_level(LLAPI_MSG_OFF);

	if (stat(lustre_dir, &st) < 0)
		DIE("cannot stat %s: %s\n", lustre_dir, strerror(errno));
	else if (!S_ISDIR(st.st_mode))
		DIE("%s: not a directory\n", lustre_dir);

	rc = llapi_search_mounts(lustre_dir, 0, fsmountdir, fsname);
	if (rc != 0) {
		fprintf(stderr, "Error: %s: not a Lustre filesystem\n",
			lustre_dir);
		return EXIT_FAILURE;
	}

	/* Play nice with Lustre test scripts. Non-line buffered output
	 * stream under I/O redirection may appear incorrectly.
	 */
	setvbuf(stdout, NULL, _IOLBF, 0);

	for (tst = tst_tbl; tst->tte_fn != NULL; tst++) {
		if (test(tst->tte_fn, tst->tte_desc, tst->tte_skip,
			 tst->tte_num))
			rc++;
	}

	return rc;
}
