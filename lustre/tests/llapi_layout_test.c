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
 * Copyright (c) 2016, 2017, Intel Corporation.
 */
/*
 * These tests exercise the llapi_layout API which abstracts the layout
 * of a Lustre file behind an opaque data type.  They assume a Lustre
 * file system with at least 2 OSTs and a pool containing at least the
 * first 2 OSTs.  For example,
 *
 *  sudo lctl pool_new lustre.testpool
 *  sudo lctl pool_add lustre.testpool OST[0-1]
 *  gcc -Wall -g -Werror -o llapi_layout_test llapi_layout_test.c -llustreapi
 *  sudo ./llapi_layout_test
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <errno.h>
#include <lustre/lustreapi.h>
#include <pwd.h>
#include <limits.h>
#include <sys/stat.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/ioctl.h>

#define ERROR(fmt, ...)							\
	fprintf(stderr, "%s: %s:%d: %s: " fmt "\n",			\
		program_invocation_short_name, __FILE__, __LINE__,	\
		__func__, ## __VA_ARGS__);

#define DIE(fmt, ...)			\
do {					\
	ERROR(fmt, ## __VA_ARGS__);	\
	exit(EXIT_FAILURE);		\
} while (0)

#define ASSERTF(cond, fmt, ...)						\
do {									\
	if (!(cond))							\
		DIE("assertion '%s' failed: "fmt, #cond, ## __VA_ARGS__);\
} while (0)								\

static char *lustre_dir;
static char *poolname;
static bool run_list_provided;
static int num_osts = -1;

void usage(char *prog)
{
	printf("Usage: %s [-d lustre_dir] [-p pool_name] [-o num_osts] "
	       "[-s $n,$m,... (skip tests)] [-t $n,$m,... (run tests)]\n",
	       prog);
	exit(0);
}

#define T0FILE			"t0"
#define T0_STRIPE_COUNT		num_osts
#define T0_STRIPE_SIZE		1048576
#define T0_OST_OFFSET		(num_osts - 1)
#define T0_DESC		"Read/write layout attributes then create a file"
void test0(void)
{
	int rc;
	int fd;
	uint64_t count;
	uint64_t size;
	struct llapi_layout *layout = llapi_layout_alloc();
	char path[PATH_MAX];
	char mypool[LOV_MAXPOOLNAME + 1] = { '\0' };

	ASSERTF(layout != NULL, "errno %d", errno);

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T0FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	/* stripe count */
	rc = llapi_layout_stripe_count_set(layout, T0_STRIPE_COUNT);
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = llapi_layout_stripe_count_get(layout, &count);
	ASSERTF(rc == 0 && count == T0_STRIPE_COUNT, "%"PRIu64" != %d", count,
		T0_STRIPE_COUNT);

	/* stripe size */
	rc = llapi_layout_stripe_size_set(layout, T0_STRIPE_SIZE);
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = llapi_layout_stripe_size_get(layout, &size);
	ASSERTF(rc == 0 && size == T0_STRIPE_SIZE, "%"PRIu64" != %d", size,
		T0_STRIPE_SIZE);

	/* pool_name */
	rc = llapi_layout_pool_name_set(layout, poolname);
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = llapi_layout_pool_name_get(layout, mypool, sizeof(mypool));
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = strcmp(mypool, poolname);
	ASSERTF(rc == 0, "%s != %s", mypool, poolname);

	/* ost_index */
	rc = llapi_layout_ost_index_set(layout, 0, T0_OST_OFFSET);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* create */
	fd = llapi_layout_file_create(path, 0, 0660, layout);
	ASSERTF(fd >= 0, "path = %s, errno = %d", path, errno);
	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);
	llapi_layout_free(layout);
}

void __test1_helper(struct llapi_layout *layout)
{
	uint64_t ost0;
	uint64_t ost1;
	uint64_t size;
	uint64_t count;
	int rc;
	char mypool[LOV_MAXPOOLNAME + 1] = { '\0' };

	rc = llapi_layout_stripe_count_get(layout, &count);
	ASSERTF(count == T0_STRIPE_COUNT, "%"PRIu64" != %d", count,
		T0_STRIPE_COUNT);

	rc = llapi_layout_stripe_size_get(layout, &size);
	ASSERTF(size == T0_STRIPE_SIZE, "%"PRIu64" != %d", size,
		T0_STRIPE_SIZE);

	rc = llapi_layout_pool_name_get(layout, mypool, sizeof(mypool));
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = strcmp(mypool, poolname);
	ASSERTF(rc == 0, "%s != %s", mypool, poolname);

	rc = llapi_layout_ost_index_get(layout, 0, &ost0);
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = llapi_layout_ost_index_get(layout, 1, &ost1);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(ost0 == T0_OST_OFFSET, "%"PRIu64" != %d", ost0, T0_OST_OFFSET);
	ASSERTF(ost1 != ost0, "%"PRIu64" == %"PRIu64, ost0, ost1);
}

#define T1_DESC		"Read test0 file by path and verify attributes"
void test1(void)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T0FILE);
	struct llapi_layout *layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);
	__test1_helper(layout);
	llapi_layout_free(layout);
}

#define T2_DESC		"Read test0 file by FD and verify attributes"
void test2(void)
{
	int fd;
	int rc;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T0FILE);

	fd = open(path, O_RDONLY);
	ASSERTF(fd >= 0, "open(%s): errno = %d", path, errno);

	struct llapi_layout *layout = llapi_layout_get_by_fd(fd, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);

	rc = close(fd);
	ASSERTF(rc == 0, "close(%s): errno = %d", path, errno);

	__test1_helper(layout);
	llapi_layout_free(layout);
}

#define T3_DESC		"Read test0 file by FID and verify attributes"
void test3(void)
{
	int rc;
	struct llapi_layout *layout;
	struct lu_fid fid;
	char fidstr[4096];
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T0FILE);

	rc = llapi_path2fid(path, &fid);
	ASSERTF(rc == 0, "rc = %d, errno = %d", rc, errno);
	snprintf(fidstr, sizeof(fidstr), "0x%"PRIx64":0x%x:0x%x",
		 (uint64_t)fid.f_seq, fid.f_oid, fid.f_ver);
	errno = 0;
	layout = llapi_layout_get_by_fid(path, &fid, 0);
	ASSERTF(layout != NULL, "fidstr = %s, errno = %d", fidstr, errno);

	__test1_helper(layout);
	llapi_layout_free(layout);
}

#define T4FILE			"t4"
#define T4_STRIPE_COUNT		2
#define T4_STRIPE_SIZE		2097152
#define T4_DESC		"Verify compatibility with 'lfs setstripe'"
void test4(void)
{
	int rc;
	uint64_t ost0;
	uint64_t ost1;
	uint64_t count;
	uint64_t size;
	const char *lfs = getenv("LFS");
	char mypool[LOV_MAXPOOLNAME + 1] = { '\0' };
	char cmd[PATH_MAX + 128];
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T4FILE);

	if (lfs == NULL)
		lfs = "/usr/bin/lfs";

	rc = unlink(path);
	ASSERTF(rc == 0 || errno == ENOENT, "errno = %d", errno);

	snprintf(cmd, sizeof(cmd), "%s setstripe %s %s -c %d -S %d %s", lfs,
		 strlen(poolname) > 0 ? "-p" : "", poolname, T4_STRIPE_COUNT,
		 T4_STRIPE_SIZE, path);
	rc = system(cmd);
	ASSERTF(rc == 0, "system(%s): exit status %d", cmd, WEXITSTATUS(rc));

	errno = 0;
	struct llapi_layout *layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);

	rc = llapi_layout_stripe_count_get(layout, &count);
	ASSERTF(count == T4_STRIPE_COUNT, "%"PRIu64" != %d", count,
		T4_STRIPE_COUNT);

	rc = llapi_layout_stripe_size_get(layout, &size);
	ASSERTF(size == T4_STRIPE_SIZE, "%"PRIu64" != %d", size,
		T4_STRIPE_SIZE);

	rc = llapi_layout_pool_name_get(layout, mypool, sizeof(mypool));
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = strcmp(mypool, poolname);
	ASSERTF(rc == 0, "%s != %s", mypool, poolname);

	rc = llapi_layout_ost_index_get(layout, 0, &ost0);
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = llapi_layout_ost_index_get(layout, 1, &ost1);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(ost1 != ost0, "%"PRIu64" == %"PRIu64, ost0, ost1);

	llapi_layout_free(layout);
}

#define T5FILE		"t5"
#define T5_DESC		"llapi_layout_get_by_path ENOENT handling"
void test5(void)
{
	int rc;
	char path[PATH_MAX];
	struct llapi_layout *layout;

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T5FILE);

	rc = unlink(path);
	ASSERTF(rc == 0 || errno == ENOENT, "errno = %d", errno);

	errno = 0;
	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout == NULL && errno == ENOENT, "errno = %d", errno);
}

#define T6_DESC		"llapi_layout_get_by_fd EBADF handling"
void test6(void)
{
	errno = 0;
	struct llapi_layout *layout = llapi_layout_get_by_fd(9999, 0);
	ASSERTF(layout == NULL && errno == EBADF, "errno = %d", errno);
}

#define T7FILE		"t7"
#define T7_DESC		"llapi_layout_get_by_path EACCES handling"
void test7(void)
{
	int fd;
	int rc;
	uid_t myuid = getuid();
	char path[PATH_MAX];
	const char *runas = getenv("RUNAS_ID");
	struct passwd *pw;
	uid_t uid;

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T7FILE);
	ASSERTF(myuid == 0, "myuid = %d", myuid); /* Need root for this test. */

	/* Create file as root */
	rc = unlink(path);
	ASSERTF(rc == 0 || errno == ENOENT, "errno = %d", errno);

	fd = open(path, O_CREAT, 0400);
	ASSERTF(fd > 0, "errno = %d", errno);
	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Become unprivileged user */
	if (runas != NULL) {
		uid = atoi(runas);
		ASSERTF(uid != 0, "runas = %s", runas);
	} else {
		pw = getpwnam("nobody");
		ASSERTF(pw != NULL, "errno = %d", errno);
		uid = pw->pw_uid;
	}
	rc = seteuid(uid);
	ASSERTF(rc == 0, "errno = %d", errno);
	errno = 0;
	struct llapi_layout *layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout == NULL && errno == EACCES, "errno = %d", errno);
	rc = seteuid(myuid);
	ASSERTF(rc == 0, "errno = %d", errno);
}

/* llapi_layout_get_by_path() returns default layout for file with no
 * striping attributes. */
#define T8FILE		"t8"
#define T8_DESC		"llapi_layout_get_by_path ENODATA handling"
void test8(void)
{
	int fd;
	int rc;
	struct llapi_layout *layout;
	uint64_t count;
	uint64_t size;
	uint64_t pattern;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T8FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);
	fd = open(path, O_CREAT, 0640);
	ASSERTF(fd >= 0, "errno = %d", errno);
	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d\n", errno);

	rc = llapi_layout_stripe_count_get(layout, &count);
	ASSERTF(rc == 0, "errno = %d\n", errno);
	ASSERTF(count == LLAPI_LAYOUT_DEFAULT, "count = %"PRIu64"\n", count);

	rc = llapi_layout_stripe_size_get(layout, &size);
	ASSERTF(rc == 0, "errno = %d\n", errno);
	ASSERTF(size == LLAPI_LAYOUT_DEFAULT, "size = %"PRIu64"\n", size);

	rc = llapi_layout_pattern_get(layout, &pattern);
	ASSERTF(rc == 0, "errno = %d\n", errno);
	ASSERTF(pattern == LLAPI_LAYOUT_DEFAULT, "pattern = %"PRIu64"\n",
		pattern);

	llapi_layout_free(layout);
}

/* Verify llapi_layout_patter_set() return values for various inputs. */
#define T9_DESC		"verify llapi_layout_pattern_set() return values"
void test9(void)
{
	struct llapi_layout *layout;
	int rc;

	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d\n", errno);

	errno = 0;
	rc = llapi_layout_pattern_set(layout, LLAPI_LAYOUT_INVALID);
	ASSERTF(rc == -1 && errno == EOPNOTSUPP, "rc = %d, errno = %d", rc,
		errno);

	errno = 0;
	rc = llapi_layout_pattern_set(NULL, LLAPI_LAYOUT_DEFAULT);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc,
		errno);

	errno = 0;
	rc = llapi_layout_pattern_set(layout, LLAPI_LAYOUT_DEFAULT);
	ASSERTF(rc == 0, "rc = %d, errno = %d", rc, errno);

	errno = 0;
	rc = llapi_layout_pattern_set(layout, LLAPI_LAYOUT_RAID0);
	ASSERTF(rc == 0, "rc = %d, errno = %d", rc, errno);

	llapi_layout_free(layout);
}

/* Verify stripe_count interfaces return errors as expected */
#define T10_DESC	"stripe_count error handling"
void test10(void)
{
	int rc;
	uint64_t count;
	struct llapi_layout *layout;

	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* invalid stripe count */
	errno = 0;
	rc = llapi_layout_stripe_count_set(layout, LLAPI_LAYOUT_INVALID);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	errno = 0;
	rc = llapi_layout_stripe_count_set(layout, -1);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	/* NULL layout */
	errno = 0;
	rc = llapi_layout_stripe_count_set(NULL, 2);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	/* NULL layout */
	errno = 0;
	rc = llapi_layout_stripe_count_get(NULL, &count);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	/* NULL count */
	errno = 0;
	rc = llapi_layout_stripe_count_get(layout, NULL);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	/* stripe count too large */
	errno = 0;
	rc = llapi_layout_stripe_count_set(layout, LOV_MAX_STRIPE_COUNT + 1);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);
	llapi_layout_free(layout);
}

/* Verify stripe_size interfaces return errors as expected */
#define T11_DESC	"stripe_size error handling"
void test11(void)
{
	int rc;
	uint64_t size;
	struct llapi_layout *layout;

	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* negative stripe size */
	errno = 0;
	rc = llapi_layout_stripe_size_set(layout, -1);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	/* invalid stripe size */
	errno = 0;
	rc = llapi_layout_stripe_size_set(layout, LLAPI_LAYOUT_INVALID);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	/* stripe size too big */
	errno = 0;
	rc = llapi_layout_stripe_size_set(layout, (1ULL << 33));
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	/* NULL layout */
	errno = 0;
	rc = llapi_layout_stripe_size_set(NULL, 1048576);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	errno = 0;
	rc = llapi_layout_stripe_size_get(NULL, &size);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	/* NULL size */
	errno = 0;
	rc = llapi_layout_stripe_size_get(layout, NULL);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	llapi_layout_free(layout);
}

/* Verify pool_name interfaces return errors as expected */
#define T12_DESC	"pool_name error handling"
void test12(void)
{
	int rc;
	struct llapi_layout *layout;
	char mypool[LOV_MAXPOOLNAME + 1] = { '\0' };

	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* NULL layout */
	errno = 0;
	rc = llapi_layout_pool_name_set(NULL, "foo");
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	/* NULL pool name */
	errno = 0;
	rc = llapi_layout_pool_name_set(layout, NULL);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	/* NULL layout */
	errno = 0;
	rc = llapi_layout_pool_name_get(NULL, mypool, sizeof(mypool));
	ASSERTF(errno == EINVAL, "poolname = %s, errno = %d", poolname, errno);

	/* NULL buffer */
	errno = 0;
	rc = llapi_layout_pool_name_get(layout, NULL, sizeof(mypool));
	ASSERTF(errno == EINVAL, "poolname = %s, errno = %d", poolname, errno);

	/* Pool name too long*/
	errno = 0;
	rc = llapi_layout_pool_name_set(layout, "0123456789abcdef");
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	llapi_layout_free(layout);
}

/* Verify ost_index interface returns errors as expected */
#define T13FILE			"t13"
#define T13_STRIPE_COUNT	2
#define T13_DESC		"ost_index error handling"
void test13(void)
{
	int rc;
	int fd;
	uint64_t idx;
	struct llapi_layout *layout;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T13FILE);

	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* invalid OST index */
	errno = 0;
	rc = llapi_layout_ost_index_set(layout, 0, LLAPI_LAYOUT_INVALID);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	errno = 0;
	rc = llapi_layout_ost_index_set(layout, 0, -1);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	/* NULL layout */
	errno = 0;
	rc = llapi_layout_ost_index_set(NULL, 0, 1);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	errno = 0;
	rc = llapi_layout_ost_index_get(NULL, 0, &idx);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	/* NULL index */
	errno = 0;
	rc = llapi_layout_ost_index_get(layout, 0, NULL);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	/* Layout not read from file so has no OST data. */
	errno = 0;
	rc = llapi_layout_stripe_count_set(layout, T13_STRIPE_COUNT);
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = llapi_layout_ost_index_get(layout, 0, &idx);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	/* n greater than stripe count*/
	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);
	rc = llapi_layout_stripe_count_set(layout, T13_STRIPE_COUNT);
	ASSERTF(rc == 0, "errno = %d", errno);
	fd = llapi_layout_file_create(path, 0, 0644, layout);
	ASSERTF(fd >= 0, "errno = %d", errno);
	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);
	llapi_layout_free(layout);

	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);
	errno = 0;
	rc = llapi_layout_ost_index_get(layout, T13_STRIPE_COUNT + 1, &idx);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	llapi_layout_free(layout);
}

/* Verify llapi_layout_file_create() returns errors as expected */
#define T14_DESC	"llapi_layout_file_create error handling"
void test14(void)
{
	int rc;
	struct llapi_layout *layout = llapi_layout_alloc();

	/* NULL path */
	errno = 0;
	rc = llapi_layout_file_create(NULL, 0, 0, layout);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d", rc, errno);

	llapi_layout_free(layout);
}

/* Can't change striping attributes of existing file. */
#define T15FILE			"t15"
#define T15_STRIPE_COUNT	2
#define T15_DESC	"Can't change striping attributes of existing file"
void test15(void)
{
	int rc;
	int fd;
	uint64_t count;
	struct llapi_layout *layout;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T15FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);
	rc = llapi_layout_stripe_count_set(layout, T15_STRIPE_COUNT);
	ASSERTF(rc == 0, "errno = %d", errno);

	errno = 0;
	fd = llapi_layout_file_create(path, 0, 0640, layout);
	ASSERTF(fd >= 0, "fd = %d, errno = %d", fd, errno);
	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, T15_STRIPE_COUNT - 1);
	errno = 0;
	fd = llapi_layout_file_open(path, 0, 0640, layout);
	ASSERTF(fd >= 0, "fd = %d, errno = %d", fd, errno);
	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);
	llapi_layout_free(layout);

	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);
	rc = llapi_layout_stripe_count_get(layout, &count);
	ASSERTF(rc == 0 && count == T15_STRIPE_COUNT,
		"rc = %d, %"PRIu64" != %d", rc, count, T15_STRIPE_COUNT);
	llapi_layout_free(layout);
}

/* Default stripe attributes are applied as expected. */
#define T16FILE		"t16"
#define T16_DESC	"Default stripe attributes are applied as expected"
void test16(void)
{
	int		rc;
	int		fd;
	struct llapi_layout	*deflayout;
	struct llapi_layout	*filelayout;
	char		path[PATH_MAX];
	uint64_t	fsize;
	uint64_t	fcount;
	uint64_t	dsize;
	uint64_t	dcount;

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T16FILE);

	rc = unlink(path);
	ASSERTF(rc == 0 || errno == ENOENT, "errno = %d", errno);

	deflayout = llapi_layout_get_by_path(lustre_dir, LAYOUT_GET_EXPECTED);
	ASSERTF(deflayout != NULL, "errno = %d", errno);
	rc = llapi_layout_stripe_size_get(deflayout, &dsize);
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = llapi_layout_stripe_count_get(deflayout, &dcount);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* First, with a default struct llapi_layout */
	filelayout = llapi_layout_alloc();
	ASSERTF(filelayout != NULL, "errno = %d", errno);

	fd = llapi_layout_file_create(path, 0, 0640, filelayout);
	ASSERTF(fd >= 0, "errno = %d", errno);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	llapi_layout_free(filelayout);

	filelayout = llapi_layout_get_by_path(path, 0);
	ASSERTF(filelayout != NULL, "errno = %d", errno);

	rc = llapi_layout_stripe_count_get(filelayout, &fcount);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(fcount == dcount || dcount == LLAPI_LAYOUT_DEFAULT ||
		dcount == LLAPI_LAYOUT_WIDE,
		"%"PRIu64" != %"PRIu64, fcount, dcount);

	rc = llapi_layout_stripe_size_get(filelayout, &fsize);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(fsize == dsize, "%"PRIu64" != %"PRIu64, fsize, dsize);

	/* NULL layout also implies default layout */
	rc = unlink(path);
	ASSERTF(rc == 0 || errno == ENOENT, "errno = %d", errno);

	fd = llapi_layout_file_create(path, 0, 0640, filelayout);
	ASSERTF(fd >= 0, "errno = %d", errno);
	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);
	filelayout = llapi_layout_get_by_path(path, 0);
	ASSERTF(filelayout != NULL, "errno = %d", errno);

	rc = llapi_layout_stripe_count_get(filelayout, &fcount);
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = llapi_layout_stripe_size_get(filelayout, &fsize);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(fcount == dcount || dcount == LLAPI_LAYOUT_DEFAULT ||
		dcount == LLAPI_LAYOUT_WIDE,
		"%"PRIu64" != %"PRIu64, fcount, dcount);
	ASSERTF(fsize == dsize, "%"PRIu64" != %"PRIu64, fsize, dsize);

	llapi_layout_free(filelayout);
	llapi_layout_free(deflayout);
}

/* Setting stripe count to LLAPI_LAYOUT_WIDE uses all available OSTs. */
#define T17FILE		"t17"
#define T17_DESC	"LLAPI_LAYOUT_WIDE is honored"
void test17(void)
{
	int rc;
	int fd;
	int osts_all;
	uint64_t osts_layout;
	struct llapi_layout *layout;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T17FILE);

	rc = unlink(path);
	ASSERTF(rc == 0 || errno == ENOENT, "errno = %d", errno);
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);
	rc = llapi_layout_stripe_count_set(layout, LLAPI_LAYOUT_WIDE);
	ASSERTF(rc == 0, "errno = %d", errno);
	fd = llapi_layout_file_create(path, 0, 0640, layout);
	ASSERTF(fd >= 0, "errno = %d", errno);
	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);
	llapi_layout_free(layout);

	/* Get number of available OSTs */
	fd = open(path, O_RDONLY);
	ASSERTF(fd >= 0, "errno = %d", errno);
	rc = llapi_lov_get_uuids(fd, NULL, &osts_all);
	ASSERTF(rc == 0, "rc = %d, errno = %d", rc, errno);
	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);
	rc = llapi_layout_stripe_count_get(layout, &osts_layout);
	ASSERTF(osts_layout == osts_all, "%"PRIu64" != %d", osts_layout,
		osts_all);

	llapi_layout_free(layout);
}

/* Setting pool with "fsname.pool" notation. */
#define T18FILE		"t18"
#define T18_DESC	"Setting pool with fsname.pool notation"
void test18(void)
{
	int rc;
	int fd;
	struct llapi_layout *layout = llapi_layout_alloc();
	char path[PATH_MAX];
	char pool[LOV_MAXPOOLNAME*2 + 1];
	char mypool[LOV_MAXPOOLNAME + 1] = { '\0' };

	snprintf(pool, sizeof(pool), "lustre.%s", poolname);

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T18FILE);

	ASSERTF(layout != NULL, "errno = %d", errno);

	rc = unlink(path);
	ASSERTF(rc == 0 || errno == ENOENT, "errno = %d", errno);

	rc = llapi_layout_pool_name_set(layout, pool);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_pool_name_get(layout, mypool, sizeof(mypool));
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = strcmp(mypool, poolname);
	ASSERTF(rc == 0, "%s != %s", mypool, poolname);
	fd = llapi_layout_file_create(path, 0, 0640, layout);
	ASSERTF(fd >= 0, "errno = %d", errno);
	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	llapi_layout_free(layout);

	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);
	rc = llapi_layout_pool_name_get(layout, mypool, sizeof(mypool));
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = strcmp(mypool, poolname);
	ASSERTF(rc == 0, "%s != %s", mypool, poolname);
	llapi_layout_free(layout);
}

#define T19_DESC	"Maximum length pool name is NULL-terminated"
void test19(void)
{
	struct llapi_layout *layout;
	char *name = "0123456789abcde";
	char mypool[LOV_MAXPOOLNAME + 1] = { '\0' };
	int rc;

	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);
	rc = llapi_layout_pool_name_set(layout, name);
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = llapi_layout_pool_name_get(layout, mypool, sizeof(mypool));
	ASSERTF(strlen(name) == strlen(mypool), "name = %s, str = %s", name,
		mypool);
	llapi_layout_free(layout);
}

#define T20FILE		"t20"
#define T20_DESC	"LLAPI_LAYOUT_DEFAULT is honored"
void test20(void)
{
	int		rc;
	int		fd;
	struct llapi_layout	*deflayout;
	struct llapi_layout	*filelayout;
	char		path[PATH_MAX];
	uint64_t	fsize;
	uint64_t	fcount;
	uint64_t	dsize;
	uint64_t	dcount;

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T20FILE);

	rc = unlink(path);
	ASSERTF(rc == 0 || errno == ENOENT, "errno = %d", errno);

	filelayout = llapi_layout_alloc();
	ASSERTF(filelayout != NULL, "errno = %d", errno);

	rc = llapi_layout_stripe_size_set(filelayout, LLAPI_LAYOUT_DEFAULT);
	ASSERTF(rc == 0, "rc = %d, errno = %d", rc, errno);

	rc = llapi_layout_stripe_count_set(filelayout, LLAPI_LAYOUT_DEFAULT);
	ASSERTF(rc == 0, "rc = %d, errno = %d", rc, errno);

	fd = llapi_layout_file_create(path, 0, 0640, filelayout);
	ASSERTF(fd >= 0, "errno = %d", errno);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	llapi_layout_free(filelayout);

	deflayout = llapi_layout_get_by_path(lustre_dir, LAYOUT_GET_EXPECTED);
	ASSERTF(deflayout != NULL, "errno = %d", errno);

	filelayout = llapi_layout_get_by_path(path, 0);
	ASSERTF(filelayout != NULL, "errno = %d", errno);

	rc = llapi_layout_stripe_count_get(filelayout, &fcount);
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = llapi_layout_stripe_count_get(deflayout, &dcount);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(fcount == dcount || dcount == LLAPI_LAYOUT_DEFAULT ||
		dcount == LLAPI_LAYOUT_WIDE,
		"%"PRIu64" != %"PRIu64, fcount, dcount);

	rc = llapi_layout_stripe_size_get(filelayout, &fsize);
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = llapi_layout_stripe_size_get(deflayout, &dsize);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(fsize == dsize, "%"PRIu64" != %"PRIu64, fsize, dsize);

	llapi_layout_free(filelayout);
	llapi_layout_free(deflayout);
}

#define T21_DESC	"llapi_layout_file_create fails for non-Lustre file"
void test21(void)
{
	struct llapi_layout *layout;
	char template[PATH_MAX];
	int fd;
	int rc;

	snprintf(template, sizeof(template), "%s/XXXXXX", P_tmpdir);
	fd = mkstemp(template);
	ASSERTF(fd >= 0, "template = %s, errno = %d", template, errno);
	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", fd);
	rc = unlink(template);
	ASSERTF(rc == 0, "errno = %d", errno);

	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	fd = llapi_layout_file_create(template, 0, 0640, layout);
	ASSERTF(fd == -1 && errno == ENOENT,
		"fd = %d, errno = %d, template = %s", fd, errno, template);
	llapi_layout_free(layout);
}

#define T22FILE		"t22"
#define T22_DESC	"llapi_layout_file_create applied mode correctly"
void test22(void)
{
	int		rc;
	int		fd;
	char		path[PATH_MAX];
	struct stat	st;
	mode_t		mode_in = 0640;
	mode_t		mode_out;
	mode_t		umask_orig;

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T22FILE);

	rc = unlink(path);
	ASSERTF(rc == 0 || errno == ENOENT, "errno = %d", errno);

	umask_orig = umask(S_IWGRP | S_IWOTH);

	fd = llapi_layout_file_create(path, 0, mode_in, NULL);
	ASSERTF(fd >= 0, "errno = %d", errno);

	(void) umask(umask_orig);

	rc = fstat(fd, &st);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", fd);

	mode_out = st.st_mode & ~S_IFMT;
	ASSERTF(mode_in == mode_out, "%o != %o", mode_in, mode_out);
}

#define T23_DESC	"llapi_layout_get_by_path fails for non-Lustre file"
void test23(void)
{
	struct llapi_layout *layout;
	char template[PATH_MAX];
	int fd;
	int rc;

	snprintf(template, sizeof(template), "%s/XXXXXX", P_tmpdir);
	fd = mkstemp(template);
	ASSERTF(fd >= 0, "template = %s, errno = %d", template, errno);
	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", fd);

	layout = llapi_layout_get_by_path(template, 0);
	ASSERTF(layout == NULL && errno == ENOTTY,
		"errno = %d, template = %s", errno, template);

	rc = unlink(template);
	ASSERTF(rc == 0, "errno = %d", errno);
}

/* llapi_layout_get_by_path(path, LAYOUT_GET_EXPECTED) returns expected layout
 * for file with unspecified layout. */
#define T24FILE		"t24"
#define T24_DESC	"LAYOUT_GET_EXPECTED works with existing file"
void test24(void)
{
	int fd;
	int rc;
	struct llapi_layout *layout;
	uint64_t count;
	uint64_t size;
	uint64_t pattern;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T24FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);
	fd = open(path, O_CREAT, 0640);
	ASSERTF(fd >= 0, "errno = %d", errno);
	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	layout = llapi_layout_get_by_path(path, LAYOUT_GET_EXPECTED);
	ASSERTF(layout != NULL, "errno = %d\n", errno);

	rc = llapi_layout_stripe_count_get(layout, &count);
	ASSERTF(rc == 0, "errno = %d\n", errno);
	ASSERTF(count != LLAPI_LAYOUT_DEFAULT, "expected literal value");

	rc = llapi_layout_stripe_size_get(layout, &size);
	ASSERTF(rc == 0, "errno = %d\n", errno);
	ASSERTF(size != LLAPI_LAYOUT_DEFAULT, "expected literal value");

	rc = llapi_layout_pattern_get(layout, &pattern);
	ASSERTF(rc == 0, "errno = %d\n", errno);
	ASSERTF(pattern != LLAPI_LAYOUT_DEFAULT, "expected literal value");

	llapi_layout_free(layout);
}

/* llapi_layout_get_by_path(path, LAYOUT_GET_EXPECTED) returns expected layout
 * for directory with unspecified layout. */
#define T25DIR		"d25"
#define T25_DESC	"LAYOUT_GET_EXPECTED works with directory"
void test25(void)
{
	int rc;
	struct llapi_layout *layout;
	uint64_t count;
	uint64_t size;
	uint64_t pattern;
	char dir[PATH_MAX];

	snprintf(dir, sizeof(dir), "%s/%s", lustre_dir, T25DIR);

	rc = rmdir(dir);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);
	rc = mkdir(dir, 0750);
	ASSERTF(rc == 0, "errno = %d", errno);

	layout = llapi_layout_get_by_path(dir, LAYOUT_GET_EXPECTED);
	ASSERTF(layout != NULL, "errno = %d\n", errno);

	rc = llapi_layout_stripe_count_get(layout, &count);
	ASSERTF(rc == 0, "errno = %d\n", errno);
	ASSERTF(count != LLAPI_LAYOUT_DEFAULT, "expected literal value");

	rc = llapi_layout_stripe_size_get(layout, &size);
	ASSERTF(rc == 0, "errno = %d\n", errno);
	ASSERTF(size != LLAPI_LAYOUT_DEFAULT, "expected literal value");

	rc = llapi_layout_pattern_get(layout, &pattern);
	ASSERTF(rc == 0, "errno = %d\n", errno);
	ASSERTF(pattern != LLAPI_LAYOUT_DEFAULT, "expected literal value");

	llapi_layout_free(layout);
}

/* llapi_layout_get_by_path(path, LAYOUT_GET_EXPECTED) correctly combines
 * specified attributes of parent directory with attributes filesystem root. */
#define T26DIR		"d26"
#define T26_DESC	"LAYOUT_GET_EXPECTED partially specified parent"
#define T26_STRIPE_SIZE	(1048576 * 4)
void test26(void)
{
	int rc;
	struct llapi_layout *layout;
	const char *lfs = getenv("LFS");
	uint64_t count;
	uint64_t size;
	uint64_t pattern;
	char dir[PATH_MAX];
	char cmd[PATH_MAX + 64];

	snprintf(dir, sizeof(dir), "%s/%s", lustre_dir, T26DIR);
	rc = rmdir(dir);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);
	rc = mkdir(dir, 0750);
	ASSERTF(rc == 0, "errno = %d", errno);

	if (lfs == NULL)
		lfs = "/usr/bin/lfs";

	snprintf(cmd, sizeof(cmd), "%s setstripe -S %d %s", lfs,
		 T26_STRIPE_SIZE, dir);
	rc = system(cmd);
	ASSERTF(rc == 0, "system(%s): exit status %d", cmd, WEXITSTATUS(rc));

	layout = llapi_layout_get_by_path(dir, LAYOUT_GET_EXPECTED);
	ASSERTF(layout != NULL, "errno = %d\n", errno);

	rc = llapi_layout_stripe_count_get(layout, &count);
	ASSERTF(rc == 0, "errno = %d\n", errno);
	ASSERTF(count != LLAPI_LAYOUT_DEFAULT, "expected literal value");

	rc = llapi_layout_stripe_size_get(layout, &size);
	ASSERTF(rc == 0, "errno = %d\n", errno);
	ASSERTF(size == T26_STRIPE_SIZE, "size = %"PRIu64, size);

	rc = llapi_layout_pattern_get(layout, &pattern);
	ASSERTF(rc == 0, "errno = %d\n", errno);
	ASSERTF(pattern != LLAPI_LAYOUT_DEFAULT, "expected literal value");

	llapi_layout_free(layout);
}

/* llapi_layout_get_by_path(path, LAYOUT_GET_EXPECTED) work with
 * non existing file. */
#define T27DIR		"d27"
#define T27_DESC	"LAYOUT_GET_EXPECTED with non existing file"
#define T27_STRIPE_SIZE	(1048576 * 3)
void test27(void)
{
	int rc;
	struct llapi_layout *layout;
	const char *lfs = getenv("LFS");
	uint64_t count;
	uint64_t size;
	uint64_t pattern;
	char dirpath[PATH_MAX + 128];
	char filepath[PATH_MAX * 2];
	char cmd[PATH_MAX * 2];

	snprintf(dirpath, sizeof(dirpath) - 1, "%s/%s", lustre_dir, T27DIR);
	snprintf(filepath, sizeof(filepath), "%s/nonesuch", dirpath);

	rc = rmdir(dirpath);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);
	rc = mkdir(dirpath, 0750);
	ASSERTF(rc == 0, "errno = %d", errno);

	if (lfs == NULL)
		lfs = "/usr/bin/lfs";

	snprintf(cmd, sizeof(cmd), "%s setstripe -S %d %s", lfs,
		 T27_STRIPE_SIZE, dirpath);
	rc = system(cmd);
	ASSERTF(rc == 0, "system(%s): exit status %d", cmd, WEXITSTATUS(rc));

	layout = llapi_layout_get_by_path(filepath, LAYOUT_GET_EXPECTED);
	ASSERTF(layout != NULL, "errno = %d\n", errno);

	rc = llapi_layout_stripe_count_get(layout, &count);
	ASSERTF(rc == 0, "errno = %d\n", errno);
	ASSERTF(count != LLAPI_LAYOUT_DEFAULT, "expected literal value");

	rc = llapi_layout_stripe_size_get(layout, &size);
	ASSERTF(rc == 0, "errno = %d\n", errno);
	ASSERTF(size == T27_STRIPE_SIZE, "size = %"PRIu64, size);

	rc = llapi_layout_pattern_get(layout, &pattern);
	ASSERTF(rc == 0, "errno = %d\n", errno);
	ASSERTF(pattern != LLAPI_LAYOUT_DEFAULT, "expected literal value");

	llapi_layout_free(layout);
}

/* llapi_layout_stripe_count_get returns LLAPI_LAYOUT_WIDE for a directory
 * with a stripe_count of -1. */
#define T28DIR		"d28"
#define T28_DESC	"LLAPI_LAYOUT_WIDE returned as expected"
void test28(void)
{
	int rc;
	struct llapi_layout *layout;
	const char *lfs = getenv("LFS");
	uint64_t count;
	char dirpath[PATH_MAX];
	char cmd[PATH_MAX + 64];

	snprintf(dirpath, sizeof(dirpath), "%s/%s", lustre_dir, T28DIR);

	rc = rmdir(dirpath);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);
	rc = mkdir(dirpath, 0750);
	ASSERTF(rc == 0, "errno = %d", errno);

	if (lfs == NULL)
		lfs = "/usr/bin/lfs";

	snprintf(cmd, sizeof(cmd), "%s setstripe -c -1 %s", lfs, dirpath);
	rc = system(cmd);
	ASSERTF(rc == 0, "system(%s): exit status %d", cmd, WEXITSTATUS(rc));

	layout = llapi_layout_get_by_path(dirpath, 0);
	ASSERTF(layout != NULL, "errno = %d\n", errno);

	rc = llapi_layout_stripe_count_get(layout, &count);
	ASSERTF(rc == 0, "errno = %d\n", errno);
	ASSERTF(count == LLAPI_LAYOUT_WIDE, "count = %"PRIu64"\n", count);

	llapi_layout_free(layout);
}

#define T29FILE		"f29"
#define T29_DESC	"set ost index to non-zero stripe number"
void test29(void)
{
	int rc, fd, i;
	uint64_t ost0, ost1, nost;
	struct llapi_layout *layout;
	char path[PATH_MAX];

	if (num_osts < 2)
		return;

	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno %d", errno);

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T29FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	/* set ost index to LLAPI_LAYOUT_IDX_MAX should fail */
	rc = llapi_layout_ost_index_set(layout, 1, LLAPI_LAYOUT_IDX_MAX);
	ASSERTF(rc == -1 && errno == EINVAL, "rc = %d, errno = %d\n",
		rc, errno);

	/* specify ost index partially */
	rc = llapi_layout_ost_index_set(layout, 1, 0);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* create a partially specified layout will fail */
	fd = llapi_layout_file_create(path, 0, 0660, layout);
	ASSERTF(fd == -1 && errno == EINVAL, "path = %s, fd = %d, errno = %d",
		path, fd, errno);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	/* specify all stripes */
	rc = llapi_layout_ost_index_set(layout, 0, 1);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* create */
	fd = llapi_layout_file_create(path, 0, 0660, layout);
	ASSERTF(fd >= 0, "path = %s, fd = %d, errno = %d", path, fd, errno);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);
	llapi_layout_free(layout);

	/* get layout from file */
	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);

	rc = llapi_layout_ost_index_get(layout, 0, &ost0);
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = llapi_layout_ost_index_get(layout, 1, &ost1);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(ost0 == 1, "%"PRIu64" != %d", ost0, 1);
	ASSERTF(ost1 == 0, "%"PRIu64" != %d", ost1, 0);
	llapi_layout_free(layout);

	/* specify more ost indexes to test realloc */
	nost = 0;
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno %d", errno);
	for (i = 0; i < LOV_MAX_STRIPE_COUNT; i++) {
		rc = llapi_layout_ost_index_set(layout, i, nost);
		ASSERTF(rc == 0, "errno = %d", errno);
		rc = llapi_layout_ost_index_get(layout, i, &ost0);
		ASSERTF(rc == 0, "errno = %d", errno);
		nost++;
		if (nost == num_osts)
			nost = 0;
	}

	nost = 0;
	for (i = 0; i < LOV_MAX_STRIPE_COUNT; i++) {
		rc = llapi_layout_ost_index_get(layout, i, &ost0);
		ASSERTF(rc == 0, "errno = %d", errno);
		ASSERTF(ost0 == nost, "ost=%"PRIu64" nost=%"PRIu64"",
			ost0, nost);
		nost++;
		if (nost == num_osts)
			nost = 0;
	}
	llapi_layout_free(layout);

	nost = 0;
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno %d", errno);
	for (i = LOV_MAX_STRIPE_COUNT-1; i >= 0; i--) {
		rc = llapi_layout_ost_index_set(layout, i, nost);
		ASSERTF(rc == 0, "errno = %d", errno);
		rc = llapi_layout_ost_index_get(layout, i, &ost0);
		ASSERTF(rc == 0, "errno = %d", errno);
		nost++;
		if (nost == num_osts)
			nost = 0;
	}

	nost = 0;
	for (i = LOV_MAX_STRIPE_COUNT-1; i <= 0; i--) {
		rc = llapi_layout_ost_index_get(layout, i, &ost0);
		ASSERTF(rc == 0, "errno = %d", errno);
		ASSERTF(ost0 == nost, "ost=%"PRIu64", nost=%"PRIu64"",
			ost0, nost);
		nost++;
		if (nost == num_osts)
			nost = 0;
	}
	llapi_layout_free(layout);
}

#define T30FILE		"f30"
#define T30_DESC	"create composite file, traverse components"
void test30(void)
{
	int rc, fd;
	uint64_t start[3], end[3];
	uint64_t s, e;
	struct llapi_layout *layout;
	char path[PATH_MAX];

	start[0] = 0;
	end[0] = 64 * 1024 * 1024; /* 64m */
	start[1] = end[0];
	end[1] = 1 * 1024 * 1024 * 1024; /* 1G */
	start[2] = end[1];
	end[2] = LUSTRE_EOF;

	if (num_osts < 2)
		return;

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T30FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 1);
	ASSERTF(rc == 0, "errno %d", errno);

	/* add component without adjusting previous component's extent
	 * end will fail. */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == -1 && errno == EINVAL, "rc %d, errno %d", rc, errno);

	rc = llapi_layout_comp_extent_set(layout, start[0], end[0]);
	ASSERTF(rc == 0, "errno %d", errno);

	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno %d", errno);

	/* set non-contiguous extent will fail */
	rc = llapi_layout_comp_extent_set(layout, start[1] * 2, end[1]);
	ASSERTF(rc == 0, "errno %d", errno);
	rc = llapi_layout_sanity(layout, NULL, false, false);
	ASSERTF(rc == 12 /*LSE_NOT_ADJACENT_PREV*/, "rc %d", rc);

	rc = llapi_layout_comp_extent_set(layout, start[1], end[1]);
	ASSERTF(rc == 0, "errno %d", errno);

	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno %d", errno);

	rc = llapi_layout_comp_extent_set(layout, start[2], end[2]);
	ASSERTF(rc == 0, "errno %d", errno);

	/* create composite file */
	fd = llapi_layout_file_create(path, 0, 0660, layout);
	ASSERTF(fd >= 0, "path = %s, fd = %d, errno = %d", path, fd, errno);

	llapi_layout_free(layout);

	/* traverse & verify all components */
	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* current component should be the tail component */
	rc = llapi_layout_comp_extent_get(layout, &s, &e);
	ASSERTF(rc == 0, "errno %d", errno);
	ASSERTF(s == start[2] && e == end[2],
		"s: %"PRIu64", e: %"PRIu64"", s, e);

	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "rc %d, errno %d", rc, errno);

	/* delete non-tail component will fail */
	rc = llapi_layout_comp_del(layout);
	ASSERTF(rc == -1 && errno == EINVAL, "rc %d, errno %d", rc, errno);

	rc = llapi_layout_comp_extent_get(layout, &s, &e);
	ASSERTF(rc == 0, "errno %d", errno);
	ASSERTF(s == start[0] && e == end[0],
		"s: %"PRIu64", e: %"PRIu64"", s, e);

	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "rc %d, errno %d", rc,  errno);

	rc = llapi_layout_comp_extent_get(layout, &s, &e);
	ASSERTF(rc == 0, "errno %d", errno);
	ASSERTF(s == start[1] && e == end[1],
		"s: %"PRIu64", e: %"PRIu64"", s, e);

	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "rc %d, errno %d", rc,  errno);

	rc = llapi_layout_comp_del(layout);
	ASSERTF(rc == 0, "errno %d", errno);

	llapi_layout_free(layout);
}

#define T31FILE		"f31"
#define T31_DESC	"add/delete component to/from existing file"
void test31(void)
{
	int rc, fd, i;
	uint64_t start[2], end[2];
	uint64_t s, e;
	uint32_t id[2];
	struct llapi_layout *layout;
	char path[PATH_MAX];

	start[0] = 0;
	end[0] = 64 * 1024 * 1024; /* 64m */
	start[1] = end[0];
	end[1] = LUSTRE_EOF;

	if (num_osts < 2)
		return;

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T31FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 1);
	ASSERTF(rc == 0, "errno %d", errno);

	rc = llapi_layout_comp_extent_set(layout, start[0], end[0]);
	ASSERTF(rc == 0, "errno %d", errno);

	/* create composite file */
	fd = llapi_layout_file_create(path, 0, 0660, layout);
	ASSERTF(fd >= 0, "path = %s, fd = %d, errno = %d", path, fd, errno);
	llapi_layout_free(layout);

	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 2);
	ASSERTF(rc == 0, "errno %d", errno);

	rc = llapi_layout_comp_extent_set(layout, start[1], end[1]);
	ASSERTF(rc == 0, "errno %d", errno);

	/* add comopnent to existing file */
	rc = llapi_layout_file_comp_add(path, layout);
	ASSERTF(rc == 0, "errno %d", errno);
	llapi_layout_free(layout);

	/* verify the composite layout after adding */
	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);

	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "rc %d, errno %d", rc, errno);
	i = 0;
	do {
		rc = llapi_layout_comp_extent_get(layout, &s, &e);
		ASSERTF(rc == 0 && i < 2, "i %d, errno %d", i, errno);
		ASSERTF(s == start[i] && e == end[i],
			"i: %d s: %"PRIu64", e: %"PRIu64"", i, s, e);

		rc = llapi_layout_comp_id_get(layout, &id[i]);
		ASSERTF(rc == 0 && id[i] != 0, "i %d, errno %d, id %d",
			i, errno, id[i]);

		rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
		ASSERTF(rc == 0 || i == 1, "i=%d rc=%d errno=%d", i, rc, errno);
		i++;
	} while (rc == 0);

	/* Verify reverse iteration gives the same IDs as forward iteration */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_LAST);
	ASSERTF(rc == 0, "rc %d, errno %d", rc, errno);
	do {
		__u32 comp_id;

		--i;
		rc = llapi_layout_comp_id_get(layout, &comp_id);
		ASSERTF(rc == 0 && comp_id == id[i],
			"i %d, errno %d, id[] %u/%u", i, errno, id[i], comp_id);

		rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_PREV);
		ASSERTF(rc == 0 || i == 0, "i=%d rc=%d errno=%d", i, rc, errno);
	} while (rc == 0);

	llapi_layout_free(layout);

	/* delete non-tail component will fail */
	rc = llapi_layout_file_comp_del(path, id[0], 0);
	ASSERTF(rc < 0 && errno == EINVAL, "rc %d, errno %d", rc, errno);

	rc = llapi_layout_file_comp_del(path, id[1], 0);
	ASSERTF(rc == 0, "rc %d, errno %d", rc, errno);

	/* verify the composite layout after deleting */
	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);

	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "rc %d, errno %d", rc, errno);

	rc = llapi_layout_comp_extent_get(layout, &s, &e);
	ASSERTF(rc == 0, "errno %d", errno);
	ASSERTF(s == start[0] && e == end[0],
		"s: %"PRIu64", e: %"PRIu64"", s, e);
}

#define T32FILE			"t32"
#define T32_STRIPE_COUNT	(num_osts*2)
#define T32_DESC		"Test overstriping with layout_file_create"
void test32(void)
{
	int rc;
	int fd;
	uint64_t count;
	struct llapi_layout *layout = llapi_layout_alloc();
	void *lmdbuf = NULL;
	struct lov_user_md *lmd;
	char path[PATH_MAX];

	ASSERTF(layout != NULL, "errno %d", errno);

	/* Maximum possible, to be on the safe side - num_osts could be large */
	lmdbuf = malloc(XATTR_SIZE_MAX);
	ASSERTF(lmdbuf != NULL, "errno %d", errno);
	lmd = lmdbuf;

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T32FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	/* stripe count */
	rc = llapi_layout_stripe_count_set(layout, T32_STRIPE_COUNT);
	ASSERTF(rc == 0, "errno = %d", errno);
	rc = llapi_layout_stripe_count_get(layout, &count);
	ASSERTF(rc == 0 && count == T32_STRIPE_COUNT, "%"PRIu64" != %d", count,
		T32_STRIPE_COUNT);

	rc = llapi_layout_pattern_set(layout, LLAPI_LAYOUT_OVERSTRIPING);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* create */
	fd = llapi_layout_file_create(path, 0, 0660, layout);
	ASSERTF(fd >= 0, "path = %s, errno = %d", path, errno);

	rc = ioctl(fd, LL_IOC_LOV_GETSTRIPE_NEW, lmdbuf);
	ASSERTF(rc == 0, "errno = %d", errno);

	count = lmd->lmm_stripe_count;
	ASSERTF(count == T32_STRIPE_COUNT,
		"stripe count (%"PRIu64") not equal to expected (%d)",
		count, T32_STRIPE_COUNT);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);
	llapi_layout_free(layout);
	free(lmdbuf);
}

#define T33FILE			"t33"
#define T33_STRIPE_COUNT	(num_osts*2)
#define T33_DESC		"Test overstriping with llapi_file_open"
void test33(void)
{
	int rc;
	int fd;
	uint64_t count;
	void *lmdbuf = NULL;
	struct lov_user_md *lmd;
	char path[PATH_MAX];

	/* Maximum possible, to be on the safe side - num_osts could be large */
	lmdbuf = malloc(XATTR_SIZE_MAX);
	ASSERTF(lmdbuf != NULL, "errno %d", errno);
	lmd = lmdbuf;

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T33FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	fd = llapi_file_open(path, O_CREAT | O_RDWR, 0660, 0, -1, num_osts*2,
			     LOV_PATTERN_RAID0 | LOV_PATTERN_OVERSTRIPING);
	ASSERTF(fd >= 0, "path = %s, errno = %d", path, errno);

	rc = ioctl(fd, LL_IOC_LOV_GETSTRIPE_NEW, lmdbuf);
	ASSERTF(rc == 0, "errno = %d", errno);

	count = lmd->lmm_stripe_count;
	ASSERTF(count == T33_STRIPE_COUNT,
		"stripe count (%"PRIu64") not equal to expected (%d)",
		count, T33_STRIPE_COUNT);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);
	free(lmdbuf);
}

#define T34FILE		"f34"
#define T34_DESC	"create simple valid & invalid self extending layouts"
void test34(void)
{
	int rc, fd;
	uint64_t start[4], end[4];
	struct llapi_layout *layout;
	char path[PATH_MAX];

	start[0] = 0;
	end[0] = 10 * 1024 * 1024; /* 10m */
	start[1] = end[0];
	end[1] = 1024 * 1024 * 1024; /* 1G */
	start[2] = end[1];
	end[2] = 10ull * 1024 * 1024 * 1024; /* 10G */
	start[3] = end[2];
	end[3] = LUSTRE_EOF;

	if (num_osts < 2)
		return;

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T34FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 1);
	ASSERTF(rc == 0, "errno %d", errno);

	/* add component without adjusting previous component's extent
	 * end will fail.
	 */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == -1 && errno == EINVAL, "rc %d, errno %d", rc, errno);

	rc = llapi_layout_comp_extent_set(layout, start[0], end[0]);
	ASSERTF(rc == 0, "errno %d", errno);

	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno %d", errno);

	rc = llapi_layout_comp_extent_set(layout, start[1], end[1]);
	ASSERTF(rc == 0, "errno %d", errno);

	rc = llapi_layout_comp_flags_set(layout, LCME_FL_EXTENSION);
	ASSERTF(rc == 0, "errno %d", errno);

	/* Invalid size, too small - < 64 MiB */
	rc = llapi_layout_extension_size_set(layout, 32 << 20);
	ASSERTF(rc == -1, "errno %d", errno);

	/* too large - > 4 TiB */
	rc = llapi_layout_extension_size_set(layout, 5ull << 40);
	ASSERTF(rc == -1, "errno %d", errno);

	/* Valid size, 64 MiB */
	rc = llapi_layout_extension_size_set(layout, 64 << 20);
	ASSERTF(rc == 0, "errno %d", errno);

	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno %d", errno);

	rc = llapi_layout_comp_extent_set(layout, start[2], end[2]);
	ASSERTF(rc == 0, "errno %d", errno);

	/* Set extension space flag on adjacent components:
	 * This is invalid, but can't be checked until we try to create the
	 * file. */
	rc = llapi_layout_comp_flags_set(layout, LCME_FL_EXTENSION);
	ASSERTF(rc == 0, "errno %d", errno);

	fd = llapi_layout_file_create(path, 0, 0660, layout);
	ASSERTF(fd = -1, "path = %s, fd = %d, errno = %d", path, fd, errno);

	/* Delete incorrect component */
	rc = llapi_layout_comp_del(layout);
	ASSERTF(rc == 0, "errno %d", errno);

	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno %d", errno);

	/* Convert this comp to zero-length so it can be followed by extension
	 * space */
	rc = llapi_layout_comp_extent_set(layout, start[2], start[2]);
	ASSERTF(rc == 0, "errno %d", errno);

	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno %d", errno);

	rc = llapi_layout_comp_extent_set(layout, start[2], end[3]);
	ASSERTF(rc == 0, "errno %d", errno);

	rc = llapi_layout_comp_flags_set(layout, LCME_FL_EXTENSION);
	ASSERTF(rc == 0, "errno %d", errno);

	/* create composite file */
	fd = llapi_layout_file_create(path, 0, 0660, layout);
	ASSERTF(fd >= 0, "path = %s, fd = %d, errno = %d", path, fd, errno);

	llapi_layout_free(layout);

	/* traverse & verify all components */
	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);

	rc = llapi_layout_sanity(layout, NULL, false, false);
	ASSERTF(rc == 0, "errno %d", errno);
}

#define TEST_DESC_LEN	80
struct test_tbl_entry {
	void (*tte_fn)(void);
	char tte_desc[TEST_DESC_LEN];
	bool tte_skip;
};

static struct test_tbl_entry test_tbl[] = {
	{ .tte_fn = &test0, .tte_desc = T0_DESC, .tte_skip = false },
	{ .tte_fn = &test1, .tte_desc = T1_DESC, .tte_skip = false },
	{ .tte_fn = &test2, .tte_desc = T2_DESC, .tte_skip = false },
	{ .tte_fn = &test3, .tte_desc = T3_DESC, .tte_skip = false },
	{ .tte_fn = &test4, .tte_desc = T4_DESC, .tte_skip = false },
	{ .tte_fn = &test5, .tte_desc = T5_DESC, .tte_skip = false },
	{ .tte_fn = &test6, .tte_desc = T6_DESC, .tte_skip = false },
	{ .tte_fn = &test7, .tte_desc = T7_DESC, .tte_skip = false },
	{ .tte_fn = &test8, .tte_desc = T8_DESC, .tte_skip = false },
	{ .tte_fn = &test9, .tte_desc = T9_DESC, .tte_skip = false },
	{ .tte_fn = &test10, .tte_desc = T10_DESC, .tte_skip = false },
	{ .tte_fn = &test11, .tte_desc = T11_DESC, .tte_skip = false },
	{ .tte_fn = &test12, .tte_desc = T12_DESC, .tte_skip = false },
	{ .tte_fn = &test13, .tte_desc = T13_DESC, .tte_skip = false },
	{ .tte_fn = &test14, .tte_desc = T14_DESC, .tte_skip = false },
	{ .tte_fn = &test15, .tte_desc = T15_DESC, .tte_skip = false },
	{ .tte_fn = &test16, .tte_desc = T16_DESC, .tte_skip = false },
	{ .tte_fn = &test17, .tte_desc = T17_DESC, .tte_skip = false },
	{ .tte_fn = &test18, .tte_desc = T18_DESC, .tte_skip = false },
	{ .tte_fn = &test19, .tte_desc = T19_DESC, .tte_skip = false },
	{ .tte_fn = &test20, .tte_desc = T20_DESC, .tte_skip = false },
	{ .tte_fn = &test21, .tte_desc = T21_DESC, .tte_skip = false },
	{ .tte_fn = &test22, .tte_desc = T22_DESC, .tte_skip = false },
	{ .tte_fn = &test23, .tte_desc = T23_DESC, .tte_skip = false },
	{ .tte_fn = &test24, .tte_desc = T24_DESC, .tte_skip = false },
	{ .tte_fn = &test25, .tte_desc = T25_DESC, .tte_skip = false },
	{ .tte_fn = &test26, .tte_desc = T26_DESC, .tte_skip = false },
	{ .tte_fn = &test27, .tte_desc = T27_DESC, .tte_skip = false },
	{ .tte_fn = &test28, .tte_desc = T28_DESC, .tte_skip = false },
	{ .tte_fn = &test29, .tte_desc = T29_DESC, .tte_skip = false },
	{ .tte_fn = &test30, .tte_desc = T30_DESC, .tte_skip = false },
	{ .tte_fn = &test31, .tte_desc = T31_DESC, .tte_skip = false },
	{ .tte_fn = &test32, .tte_desc = T32_DESC, .tte_skip = false },
	{ .tte_fn = &test33, .tte_desc = T33_DESC, .tte_skip = false },
	{ .tte_fn = &test34, .tte_desc = T34_DESC, .tte_skip = false },
};

#define NUM_TESTS	(sizeof(test_tbl) / sizeof(struct test_tbl_entry))

void print_test_desc(int test_num, const char *test_desc, const char *status)
{
	int i;

	printf(" test %2d: %s ", test_num, test_desc);
	for (i = 0; i < TEST_DESC_LEN - strlen(test_desc); i++)
		printf(".");
	printf(" %s\n", status);
}

/* This function runs a single test by forking the process.  This way,
 * if there is a segfault during a test, the test program won't crash. */
int test(void (*test_fn)(), const char *test_desc, bool test_skip, int test_num)
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
		/* Run the test in the child process.  Exit with 0 for success,
		 * non-zero for failure */
		test_fn();
		exit(0);
	}

	return rc;
}

/* 'str_tests' are the tests to be skipped, such as "1,3,4,.." */
static void set_tests_skipped(char *str_tests)
{
	char *ptr = str_tests;
	int tstno;

	if (ptr == NULL || strlen(ptr) == 0)
		return;

	while (*ptr != '\0') {
		tstno = strtoul(ptr, &ptr, 0);
		if (tstno >= 0 && tstno < NUM_TESTS)
			test_tbl[tstno].tte_skip = true;
		if (*ptr == ',')
			ptr++;
		else
			break;
	}
}

static void set_tests_to_run(char *str_tests)
{
	char *ptr = str_tests;
	int tstno;
	int i = 0;

	if (ptr == NULL || strlen(ptr) == 0)
		return;

	for (i = 0; i < NUM_TESTS ; i++)
		test_tbl[i].tte_skip = true;

	while (*ptr != '\0') {
		tstno = strtoul(ptr, &ptr, 0);
		if (tstno >= 0 && tstno < NUM_TESTS)
			test_tbl[tstno].tte_skip = false;
		if (*ptr == ',')
			ptr++;
		else
			break;
	}
}

static void process_args(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "d:p:o:s:t:")) != -1) {
		switch (c) {
		case 'd':
			lustre_dir = optarg;
			break;
		case 'p':
			poolname = optarg;
			break;
		case 'o':
			num_osts = atoi(optarg);
			break;
		case 's':
			set_tests_skipped(optarg);
			break;
		case 't':
			run_list_provided = true;
			set_tests_to_run(optarg);
			break;
		case '?':
			fprintf(stderr, "Unknown option '%c'\n", optopt);
			usage(argv[0]);
		}
	}
}

int main(int argc, char *argv[])
{
	int rc = 0;
	int i;
	struct stat s;
	char fsname[8 + 1];

	llapi_msg_set_level(LLAPI_MSG_OFF);

	process_args(argc, argv);
	if (lustre_dir == NULL)
		lustre_dir = "/mnt/lustre";
	if (poolname == NULL)
		poolname = "testpool";
	if (num_osts == -1)
		num_osts = 2;

	if (num_osts < 2)
		DIE("Error: at least 2 OSTS are required\n");

	if (stat(lustre_dir, &s) < 0)
		DIE("cannot stat %s: %s\n", lustre_dir, strerror(errno));
	else if (!S_ISDIR(s.st_mode))
		DIE("%s: not a directory\n", lustre_dir);

	rc = llapi_search_fsname(lustre_dir, fsname);
	if (rc != 0) {
		fprintf(stderr, "Error: %s: not a Lustre filesystem\n",
			lustre_dir);
		exit(EXIT_FAILURE);
	}

	/* Play nice with Lustre test scripts. Non-line buffered output
	 * stream under I/O redirection may appear incorrectly. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	for (i = 0; i < NUM_TESTS; i++) {
		struct test_tbl_entry *tst = &test_tbl[i];
		if (test(tst->tte_fn, tst->tte_desc, tst->tte_skip, i) != 0)
			rc++;
	}

	return rc;
}
