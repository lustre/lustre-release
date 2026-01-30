// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2016, 2017, Intel Corporation.
 * Copyright (c) 2025, DataDirect Networks, Inc. All rights reserved.
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

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_user.h>
#include "llapi_test_utils.h"

static char *poolname = "testpool";
static int num_osts = 2;
static char lustre_dir[PATH_MAX - 5];	/* Lustre test directory */

#define IN_RANGE(value, low, high) ((value >= low) && (value <= high))

/* Layout sanity error codes - should match liblustreapi_layout.c */
#define LSE_NOT_ADJACENT_PREV 12

#define LAYOUT_ASSERTF(cond, rc, fmt, ...)				\
do {									\
	if (!(cond))							\
		llapi_layout_sanity_perror(rc);				\
	ASSERTF(cond, fmt, ## __VA_ARGS__);				\
} while (0)

static void usage(char *prog)
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
static void test0(void)
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

static void __test1_helper(struct llapi_layout *layout)
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
static void test1(void)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T0FILE);
	struct llapi_layout *layout = llapi_layout_get_by_path(path, 0);

	ASSERTF(layout != NULL, "errno = %d", errno);
	__test1_helper(layout);
	llapi_layout_free(layout);
}

#define T2_DESC		"Read test0 file by FD and verify attributes"
static void test2(void)
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
static void test3(void)
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
static void test4(void)
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
static void test5(void)
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
static void test6(void)
{
	errno = 0;
	struct llapi_layout *layout = llapi_layout_get_by_fd(9999, 0);

	ASSERTF(layout == NULL && errno == EBADF, "errno = %d", errno);
}

#define T7FILE		"t7"
#define T7_DESC		"llapi_layout_get_by_path EACCES handling"
static void test7(void)
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
 * striping attributes.
 */
#define T8FILE		"t8"
#define T8_DESC		"llapi_layout_get_by_path ENODATA handling"
static void test8(void)
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
static void test9(void)
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
static void test10(void)
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
static void test11(void)
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
static void test12(void)
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
static void test13(void)
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
static void test14(void)
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
static void test15(void)
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
static void test16(void)
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
		IN_RANGE(dcount, LLAPI_LAYOUT_WIDE_MIN, LLAPI_LAYOUT_WIDE_MAX),
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
		IN_RANGE(dcount, LLAPI_LAYOUT_WIDE_MIN, LLAPI_LAYOUT_WIDE_MAX),
		"%"PRIu64" != %"PRIu64, fcount, dcount);
	ASSERTF(fsize == dsize, "%"PRIu64" != %"PRIu64, fsize, dsize);

	llapi_layout_free(filelayout);
	llapi_layout_free(deflayout);
}

/* Setting stripe count to LLAPI_LAYOUT_WIDE uses all available OSTs. */
#define T17FILE		"t17"
#define T17_DESC	"LLAPI_LAYOUT_WIDE is honored"
static void test17(void)
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
static void test18(void)
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
static void test19(void)
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
static void test20(void)
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
static void test21(void)
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
	ASSERTF(fd == -1 && errno == ENOTTY,
		"fd = %d, errno = %d, template = %s", fd, errno, template);
	llapi_layout_free(layout);
}

#define T22FILE		"t22"
#define T22_DESC	"llapi_layout_file_create applied mode correctly"
static void test22(void)
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

	umask_orig = umask(0022);

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
static void test23(void)
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
 * for file with unspecified layout.
 */
#define T24FILE		"t24"
#define T24_DESC	"LAYOUT_GET_EXPECTED works with existing file"
static void test24(void)
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
 * for directory with unspecified layout.
 */
#define T25DIR		"d25"
#define T25_DESC	"LAYOUT_GET_EXPECTED works with directory"
static void test25(void)
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
 * specified attributes of parent directory with attributes filesystem root.
 */
#define T26DIR		"d26"
#define T26_DESC	"LAYOUT_GET_EXPECTED partially specified parent"
#define T26_STRIPE_SIZE	(1048576 * 4)
static void test26(void)
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
 * non existing file.
 */
#define T27DIR		"d27"
#define T27_DESC	"LAYOUT_GET_EXPECTED with non existing file"
#define T27_STRIPE_SIZE	(1048576 * 3)
static void test27(void)
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
 * with a stripe_count of -1.
 */
#define T28DIR		"d28"
#define T28_DESC	"LLAPI_LAYOUT_WIDE returned as expected"
static void test28(void)
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
static void test29(void)
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
static void test30(void)
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
	 * end will fail.
	 */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == -1 && errno == EINVAL, "rc %d, errno %d", rc, errno);

	rc = llapi_layout_comp_extent_set(layout, start[0], end[0]);
	ASSERTF(rc == 0, "errno %d", errno);

	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno %d", errno);

	/* set non-contiguous extent will fail */
	rc = llapi_layout_comp_extent_set(layout, start[1] * 2, end[1]);
	ASSERTF(rc == 0, "errno %d", errno);
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == LSE_NOT_ADJACENT_PREV, rc, "errno = %d", errno);

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
static void test31(void)
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
static void test32(void)
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
static void test33(void)
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
static void test34(void)
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
	 * This is invalid, but can't be checked until we create the file.
	 */
	rc = llapi_layout_comp_flags_set(layout, LCME_FL_EXTENSION);
	ASSERTF(rc == 0, "errno %d", errno);

	fd = llapi_layout_file_create(path, 0, 0660, layout);
	ASSERTF(fd = -1, "path = %s, fd = %d, errno = %d", path, fd, errno);

	/* Delete incorrect component */
	rc = llapi_layout_comp_del(layout);
	ASSERTF(rc == 0, "errno %d", errno);

	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno %d", errno);

	/* Convert this comp to 0-len that can be followed by extension space */
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

	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc, "errno %d", errno);
}

#define T35FILE		"f35"
#define T35_STRIPE_COUNT num_osts
#define T35_STRIPE_SIZE 1048576
#define T35_DESC	"create a file with layout different from default"
static void test35(void)
{
	char mypool[LOV_MAXPOOLNAME + 1] = { '\0'};
	struct llapi_layout *layout;
	char path[PATH_MAX];
	uint64_t count;
	uint64_t size;
	int fd;
	int rc;

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T35FILE);

	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "failed to allocate layout structure");
	llapi_layout_stripe_count_set(layout, T35_STRIPE_COUNT);
	llapi_layout_stripe_size_set(layout, T35_STRIPE_SIZE);
	llapi_layout_pool_name_set(layout, poolname);

	fd = llapi_layout_file_create(path, 0, 0640, layout);
	ASSERTF(fd >= 0, "failed to create " T35FILE);

	llapi_layout_free(layout);

	layout = llapi_layout_get_by_fd(fd, 0);
	ASSERTF(layout != NULL, "failed to get layout");

	rc = llapi_layout_stripe_count_get(layout, &count);
	ASSERTF(rc == 0 && count == T35_STRIPE_COUNT, "invalid stripe count");

	rc = llapi_layout_stripe_size_get(layout, &size);
	ASSERTF(rc == 0 && size == T35_STRIPE_SIZE, "invalid stripe size");

	rc = llapi_layout_pool_name_get(layout, mypool, sizeof(mypool));
	ASSERTF(rc == 0, "error reading pool name");
	ASSERTF(strcmp(mypool, poolname) == 0, "invalid pool name");

	llapi_layout_free(layout);
	close(fd);
}

#define T36_DESC	"verify mirror count is validated"
static void test36(void)
{
	int rc;
	struct llapi_layout *layout;

	/* Create a complete layout first */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1 */
	/* COMP1: [0, 1GiB] */
	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024 * 1024 * 1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* COMP2: [1GiB, EOF] */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024 * 1024 * 1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 2 */
	/* COMP1: [0, 1GiB] */
	rc = llapi_layout_add_first_comp(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024 * 1024 * 1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* COMP2: [1GiB, EOF] */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024 * 1024 * 1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Verify it fails with invalid mirror count since it is unset */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc != 0, rc,
		       "Layout should fail with invalid mirror count");

	/* Set the mirror count to 2 and verify it passes */
	rc = llapi_layout_mirror_count_set(layout, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc,
		       "Layout should pass with valid mirror count");

	/* Set the mirror count to 3 and verify it fails */
	rc = llapi_layout_mirror_count_set(layout, 3);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc != 0, rc,
		       "Layout should fail with invalid mirror count");

	/* Use llapi_layout_mirror_count_sync to sync the mirror count */
	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc,
		       "Layout should pass with valid mirror count");

	/* Set the mirror count to 0 and use llapi_layout_mirror_count_sync */
	rc = llapi_layout_mirror_count_set(layout, 0);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc,
		       "Layout should pass with valid mirror count");

	llapi_layout_free(layout);
}

#define T37FILE "f37"
#define T37_DESC "verify mirror count and mirror ids for existing files"
static void test37(void)
{
	struct llapi_layout *layout, *filelayout;
	char path[PATH_MAX];
	uint64_t s, e;
	uint16_t mirror_count;
	uint32_t id;
	int rc, fd;

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T37FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	/* Create a complete layout first */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1 */
	/* COMP1: [0, 1GiB] */
	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024 * 1024 * 1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* COMP2: [1GiB, EOF] */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024 * 1024 * 1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 2 */
	/* COMP1: [0, 1GiB] */
	rc = llapi_layout_add_first_comp(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024 * 1024 * 1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* COMP2: [1GiB, EOF] */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024 * 1024 * 1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* sync mirror count and create file*/
	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	fd = llapi_layout_file_create(path, 0, 0640, layout);
	ASSERTF(fd >= 0, "errno = %d", errno);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	llapi_layout_free(layout);

	/* Read the layout back from the file */
	filelayout = llapi_layout_get_by_path(path, 0);
	ASSERTF(filelayout != NULL, "errno = %d", errno);

	rc = llapi_layout_sanity(filelayout, false, false);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_use(filelayout, LLAPI_LAYOUT_COMP_USE_LAST);
	ASSERTF(rc == 0, "rc %d, errno %d", rc, errno);

	/* Verify the mirror ID is set on the last component after file read.
	 * Note, mirror count is not set on llapi_layout_get_by_path() and
	 * requires llapi_layout_mirror_count_sync() to be called.
	 */
	rc = llapi_layout_mirror_id_get(filelayout, &id);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(id != 0, "id = %d", id);

	/* Verify the extent of the last component */
	rc = llapi_layout_comp_extent_get(filelayout, &s, &e);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(s == 1024 * 1024 * 1024ULL && e == LUSTRE_EOF,
		"s: %" PRIu64 ", e: %" PRIu64 "", s, e);

	/* delete the last 2 components */
	rc = llapi_layout_comp_del(filelayout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* check the "new" last component */
	rc = llapi_layout_comp_extent_get(filelayout, &s, &e);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(s == 0 && e == 1024 * 1024 * 1024ULL,
		"s: %" PRIu64 ", e: %" PRIu64 "", s, e);

	rc = llapi_layout_comp_del(filelayout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_mirror_id_get(filelayout, &id);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(id != 0, "id = %d", id);

	/* sync mirror count (only mirror ids are set on get_by_path()) */
	rc = llapi_layout_mirror_count_sync(filelayout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Verify the mirror count is now 1 */
	rc = llapi_layout_mirror_count_get(filelayout, &mirror_count);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(mirror_count == 1, "mirror_count = %d", mirror_count);

	rc = llapi_layout_sanity(filelayout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc,
		       "Layout should pass with valid mirror count");

	/* re-add mirror 2 */
	/* COMP1: [0, 1GiB] */
	rc = llapi_layout_add_first_comp(filelayout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(filelayout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(filelayout, 0, 1024 * 1024 * 1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* COMP2: [1GiB, EOF] */
	rc = llapi_layout_comp_add(filelayout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(filelayout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(filelayout, 1024 * 1024 * 1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Verify last component has no mirror id set yet */
	rc = llapi_layout_comp_use(filelayout, LLAPI_LAYOUT_COMP_USE_LAST);
	ASSERTF(rc == 0, "rc %d, errno %d", rc, errno);

	rc = llapi_layout_mirror_id_get(filelayout, &id);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(id == 0, "id = %d", id);

	rc = llapi_layout_mirror_count_sync(filelayout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Verify last component has mirror id set yet now */
	rc = llapi_layout_mirror_id_get(filelayout, &id);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(id != 0, "id = %d", id);

	/* Verify the mirror count is 2 */
	rc = llapi_layout_mirror_count_get(filelayout, &mirror_count);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(mirror_count == 2, "mirror_count = %d", mirror_count);

	rc = llapi_layout_sanity(filelayout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc,
		       "Layout should pass with valid mirror count");

	llapi_layout_free(filelayout);
}

#define T40_DESC	"verify LCME_FL_PARITY cannot be set with flags_set function"
static void test40(void)
{
	int rc;
	struct llapi_layout *layout;

	/* Create a layout with one data component */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Add a regular component with explicit extent */
	rc = llapi_layout_comp_add_extent(layout, 0, LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Try to set LCME_FL_PARITY flag - this should fail */
	rc = llapi_layout_comp_flags_set(layout, LCME_FL_PARITY);
	ASSERTF(rc != 0,
		"Setting LCME_FL_PARITY with flags_set should fail but succeeded");

	llapi_layout_free(layout);
}

#define T41_DESC	"verify comp_add_opts parameter validation for EC components"
static void test41(void)
{
	int rc;
	struct llapi_layout *layout;

	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Try to add EC component with zero cstripe/dstripe */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, LUSTRE_EOF, 0, 0);
	ASSERTF(rc != 0,
		"Parity component with zero cstripe/dstripe should fail but succeeded");

	llapi_layout_free(layout);
}

#define T42_DESC	"verify parity component with non-matching extent is refused"
static void test42(void)
{
	int rc;
	struct llapi_layout *layout;

	/* Create layout with data mirror and EC mirror */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1: Regular data component [0, EOF] */
	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Add first component of Mirror 2 */
	rc = llapi_layout_add_first_comp(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Attempt to add EC component with different extent [0, 10MiB]
	 * This should fail because it doesn't match Mirror 1 extent [0, EOF]
	 */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, 10*1024*1024, 6, 2);
	ASSERTF(rc != 0, "errno = %d", errno);

	/* Layout is still valid as the extent was refused */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc,
		       "Layout sanity should succeed");

	llapi_layout_free(layout);
}

#define T43_DESC	"verify EC component cannot be added to incomplete layout"
static void test43(void)
{
	int rc;
	struct llapi_layout *layout;

	/* Create layout with incomplete data mirror: [0, 1GiB] (doesn't go
	 * to EOF)
	 */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1: Incomplete data component [0, 1GiB] */
	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Try to add EC parity component - creation should succeed but
	 * validation should fail
	 */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, 1024*1024*1024ULL, 4, 2);
	ASSERTF(rc == 0, "EC component creation should succeed: errno = %d",
		errno);

	/* Validation should catch the incomplete layout */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc != 0, rc,
		       "EC component on incomplete layout should fail validation");

	llapi_layout_free(layout);
}

#define T44_DESC	"verify EC components with zero stripe counts are rejected"
static void test44(void)
{
	int rc;
	struct llapi_layout *layout;

	/* Create a complete layout first */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* COMP1: [0, 1GiB] */
	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* COMP2: [1GiB, EOF] */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024*1024*1024ULL,
					   LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Test 1: cstripe_count = 0, dstripe_count > 0 (should fail) */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, 1024*1024*1024ULL, 4, 0);
	ASSERTF(rc != 0, "EC component with zero coding stripes should fail");

	/* Test 2: cstripe_count > 0, dstripe_count = 0 (should fail) */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, 1024*1024*1024ULL, 0, 2);
	ASSERTF(rc != 0, "EC component with zero data stripes should fail");

	/* Test 3: cstripe_count = 0, dstripe_count = 0 (should fail) */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, 1024*1024*1024ULL, 0, 0);
	ASSERTF(rc != 0, "EC component with zero stripe counts should fail");

	llapi_layout_free(layout);
}

#define T45_DESC	"verify overlapping EC extents are rejected"
static void test45(void)
{
	int rc;
	struct llapi_layout *layout;

	/* Create layout: COMP1[0-1GB], COMP2[1GB-2GB], COMP3[2GB-EOF] */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* COMP1: [0, 1GiB] */
	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* COMP2: [1GiB, 2GiB] */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024*1024*1024ULL,
					   2*1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* COMP3: [2GiB, EOF] */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 8);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 2*1024*1024*1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Add first EC component: [0, 1GiB] */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, 1024*1024*1024ULL, 4, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Try to add overlapping EC component: [512MiB, 1.5GiB], should fail */
	rc = llapi_layout_comp_add_ec(layout, 1, 512*1024*1024ULL,
				      1536*1024*1024ULL, 6, 2);
	ASSERTF(rc != 0, "errno = %d", errno);

	/* Validation should fail since the layout is incomplete due to missing
	 * EC components
	 */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc != 0, rc, "Layout should still be valid");

	llapi_layout_free(layout);
}

#define T46_DESC	"verify invalid EC extent ranges are rejected"
static void test46(void)
{
	int rc;
	struct llapi_layout *layout;

	/* Create a complete layout first */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* COMP1: [0, 1GiB] */
	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* COMP2: [1GiB, EOF] */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024*1024*1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Test 1: start > end (should fail) */
	rc = llapi_layout_comp_add_ec(layout, 1, 1024*1024*1024ULL,
				      512*1024*1024ULL, 4, 2);
	ASSERTF(rc != 0, "EC component with start > end should fail");

	/* Test 2: start == end (should fail) */
	rc = llapi_layout_comp_add_ec(layout, 1, 512*1024*1024ULL,
				      512*1024*1024ULL, 4, 2);
	ASSERTF(rc != 0, "EC component with start == end should fail");

	/* Test 3: start == LUSTRE_EOF (should fail) */
	rc = llapi_layout_comp_add_ec(layout, 1, LUSTRE_EOF, LUSTRE_EOF, 4, 2);
	ASSERTF(rc != 0, "EC component with start == LUSTRE_EOF should fail");

	llapi_layout_free(layout);
}

#define T47_DESC	"verify EC parameter constraints are enforced"
static void test47(void)
{
	int rc;
	struct llapi_layout *layout;

	/* Create a complete layout first */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* COMP1: [0, 1GiB] - use max data stripe count for validation test */
	rc = llapi_layout_stripe_count_set(layout, 255);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* COMP2: [1GiB, EOF] */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024*1024*1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Test 1: total ec count > data stripe count (should fail) */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, 1024*1024*1024ULL, 3, 4);
	ASSERTF(rc != 0,
		"EC component with total stripe count > data stripe count should fail");

	rc = llapi_layout_comp_add_ec(layout, 1, 0, 1024*1024*1024ULL, 4, 5);
	ASSERTF(rc != 0, "EC component with cstripe > dstripe should fail");

	/* Test 2: cstripe_count exceeds LOV_EC_MAX_CODING_STRIPES (should
	 * fail)
	 */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, 1024*1024*1024ULL, 255, 16);
	ASSERTF(rc != 0, "EC component with cstripe_count > 15 should fail");

	/* Test 3: Valid parameters at maximum coding stripe limit (should
	 * succeed)
	 */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, 1024*1024*1024ULL, 255, 15);
	ASSERTF(rc == 0, "EC component with cstripe_count = 15 should succeed");

	llapi_layout_free(layout);
}

#define T48_DESC	"verify duplicate EC components are rejected"
static void test48(void)
{
	int rc;
	struct llapi_layout *layout;

	/* Create layout with data mirror and EC mirror */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1: Regular data components */
	/* M1 COMP1: [0, 1GiB] */
	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M1 COMP2: [1GiB, EOF] */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024*1024*1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 2: EC components */
	/* Add first EC component: [0, 1GiB] */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, 1024*1024*1024ULL, 4, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Try to add duplicate EC component: [0, 1GiB] - should fail */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, 1024*1024*1024ULL, 4, 2);
	ASSERTF(rc != 0, "errno = %d", errno);

	/* Layout should be incomplete - the second EC component is missing */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc != 0, rc,
		       "Layout validation should fail due to being incomplete");

	/* Add non-overlapping EC component: [1GiB, EOF] */
	rc = llapi_layout_comp_add_ec(layout, 1, 1024 * 1024 * 1024ULL,
				      LUSTRE_EOF, 6, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc, "Layout validation should be complete now");

	llapi_layout_free(layout);
}

#define T49_DESC	"verify API parameter validation and error handling"
static void test49(void)
{
	int rc;
	struct llapi_layout *layout;

	/* Test 1: NULL layout pointer (should fail) */
	rc = llapi_layout_comp_add_ec(NULL, 1, 0, 1024*1024*1024ULL, 4, 2);
	ASSERTF(rc != 0, "NULL layout should fail but succeeded");

	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024*1024*1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Test 2: start == end (zero-length extent, should fail) */
	rc = llapi_layout_comp_add_ec(layout, 1, 1024*1024*1024ULL,
				      1024*1024*1024ULL, 4, 2);
	ASSERTF(rc != 0, "Zero-length extent should fail but succeeded");

	llapi_layout_free(layout);
}

/**
 * __verify_parity_comp() - verify a component's EC parameters and tight binding
 * @layout: layout to verify
 * @expected_dstripe: expected dstripe count
 * @expected_cstripe: expected cstripe count
 * @expected_mirror_link_id: expected mirror link ID this parity binds to
 * @comp_desc: description for error messages
 *
 * Verifies that the given layout component has the expected EC (Erasure Coding)
 * parameters and is properly bound to the expected data mirror. Only parity
 * components have EC parameters set and the LCME_FL_PARITY flag.
 *
 * Note, this should only be called for layouts retrieved from disk to retrieve
 * the permanent binding.
 *
 * Return:
 * * void - function asserts on verification failures
 */
static void __verify_parity_comp(struct llapi_layout *layout,
				 uint8_t expected_dstripe,
				 uint8_t expected_cstripe,
				 uint16_t expected_mirror_link_id,
				 const char *comp_desc)
{
	uint32_t flags;
	uint8_t cstripe, dstripe;
	uint64_t pattern;
	uint16_t mirror_link_id;
	uint32_t comp_id;
	int rc;

	rc = llapi_layout_comp_flags_get(layout, &flags);
	ASSERTF(rc == 0, "%s: failed to get flags, errno = %d", comp_desc,
		errno);

	/* Verify that the component has an ID - meaning it comes from disk */
	rc = llapi_layout_comp_id_get(layout, &comp_id);
	ASSERTF(rc == 0, "%s: failed to get id, errno = %d", comp_desc, errno);
	ASSERTF(comp_id != LCME_ID_INVAL, "%s: comp id is invalid", comp_desc);

	/* EC parameters are only set on parity components */
	ASSERTF(flags & LCME_FL_PARITY,
		"%s: PARITY flag not set on EC component", comp_desc);

	/* Link id should not be set on parity components */
	ASSERTF(!(flags & LCME_FL_IS_LINK_ID),
		"%s: IS_LINK_ID flag set on EC component", comp_desc);

	/* Verify pattern has LOV_PATTERN_PARITY bit set */
	rc = llapi_layout_pattern_get(layout, &pattern);
	ASSERTF(rc == 0, "%s: failed to get pattern, errno = %d", comp_desc,
		errno);
	ASSERTF(pattern & LOV_PATTERN_PARITY,
		"%s: LOV_PATTERN_PARITY not set in pattern 0x%lx", comp_desc,
		pattern);

	rc = llapi_layout_ec_dstripe_count_get(layout, &dstripe);
	ASSERTF(rc == 0, "%s: failed to get dstripe, errno = %d", comp_desc,
		errno);
	ASSERTF(dstripe == expected_dstripe, "%s: dstripe %u != expected %u",
		comp_desc, dstripe, expected_dstripe);

	rc = llapi_layout_ec_cstripe_count_get(layout, &cstripe);
	ASSERTF(rc == 0, "%s: failed to get cstripe, errno = %d", comp_desc,
		errno);
	ASSERTF(cstripe == expected_cstripe, "%s: cstripe %u != expected %u",
		comp_desc, cstripe, expected_cstripe);

	/* Verify tight binding to expected data mirror */
	rc = llapi_layout_comp_mirror_link_id_get(layout, &mirror_link_id);
	ASSERTF(rc == 0, "%s: failed to get mirror_link_id, errno = %d",
		comp_desc, errno);
	ASSERTF(mirror_link_id == expected_mirror_link_id,
		"%s: mirror_link_id %u != expected data mirror ID %u",
		comp_desc, mirror_link_id, expected_mirror_link_id);
}

/**
 * __verify_ec_data_comp() - verify a data component's EC binding
 * @layout: layout to verify
 * @expected_mirror_link_id: expected mirror link ID this data comp binds to
 * @comp_desc: description for error messages
 *
 * Verifies that the given layout component is properly bound to the expected
 * parity mirror.
 *
 * Note, this should only be called for layouts retrieved from disk to retrieve
 * the permanent binding.
 *
 * Return:
 * * void - function asserts on verification failures
 */
static void __verify_ec_data_comp(struct llapi_layout *layout,
				  uint16_t expected_mirror_link_id,
				  const char *comp_desc)
{
	uint32_t flags;
	uint64_t pattern;
	uint16_t mirror_link_id;
	uint32_t comp_id;
	int rc;

	rc = llapi_layout_comp_flags_get(layout, &flags);
	ASSERTF(rc == 0, "%s: failed to get flags, errno = %d", comp_desc,
		errno);

	/* Verify that the component has an ID - meaning it comes from disk */
	rc = llapi_layout_comp_id_get(layout, &comp_id);
	ASSERTF(rc == 0, "%s: failed to get id, errno = %d", comp_desc, errno);
	ASSERTF(comp_id != LCME_ID_INVAL, "%s: comp id is invalid", comp_desc);

	/* EC parameters should not be set on data components */
	ASSERTF(!(flags & LCME_FL_PARITY),
		"%s: PARITY flag set on data component", comp_desc);

	/* Verify pattern does not have LOV_PATTERN_PARITY bit set */
	rc = llapi_layout_pattern_get(layout, &pattern);
	ASSERTF(rc == 0, "%s: failed to get pattern, errno = %d", comp_desc,
		errno);
	ASSERTF(!(pattern & LOV_PATTERN_PARITY),
		"%s: LOV_PATTERN_PARITY set in pattern 0x%lx", comp_desc,
		pattern);

	/* Verify tight binding to expected parity mirror */
	rc = llapi_layout_comp_mirror_link_id_get(layout, &mirror_link_id);
	ASSERTF(rc == 0, "%s: failed to get mirror_link_id, errno = %d",
		comp_desc, errno);
	ASSERTF(mirror_link_id == expected_mirror_link_id,
		"%s: mirror_link_id %u != expected data mirror ID %u",
		comp_desc, mirror_link_id, expected_mirror_link_id);
}

/**
 * __verify_comp_extent() - verify a component's extent
 * @layout: layout to verify
 * @expected_start: expected extent start
 * @expected_end: expected extent end
 * @comp_desc: description for error messages
 *
 * Verifies that the given layout component has the expected extent range
 * by comparing the actual start and end values against the expected values.
 *
 * Return:
 * * void - function asserts on verification failures
 */
static void __verify_comp_extent(struct llapi_layout *layout,
				 uint64_t expected_start, uint64_t expected_end,
				 const char *comp_desc)
{
	uint64_t start, end;
	int rc;

	rc = llapi_layout_comp_extent_get(layout, &start, &end);
	ASSERTF(rc == 0, "%s: failed to get extent, errno = %d", comp_desc,
		errno);
	ASSERTF(start == expected_start,
		"%s: extent start %" PRIu64 " != expected %" PRIu64, comp_desc,
		start, expected_start);
	ASSERTF(end == expected_end,
		"%s: extent end %" PRIu64 " != expected %" PRIu64, comp_desc,
		end, expected_end);
}

#define T50FILE		"f50"
#define T50_DESC	"verify mixed parity mirror is rejected"
static void test50(void)
{
	int rc;
	struct llapi_layout *layout;

	/*
	 * Create layout with data mirror and partial EC mirror.
	 * This should now fail because Mirror 2 mixes non-PARITY
	 * and PARITY components.
	 */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1: Regular data components (3 components) */
	/* M1 COMP1: [0, 512MiB] */
	rc = llapi_layout_stripe_count_set(layout, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 512*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M1 COMP2: [512MiB, 1GiB] */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 512*1024*1024ULL,
					  1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M1 COMP3: [1GiB, EOF] */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024*1024*1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 2: Mixed mirror - data + EC (should fail validation) */
	/* M2 COMP1: [0, 512MiB] - regular data component */
	rc = llapi_layout_add_first_comp(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 512*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M2 EC1: [512MiB, 1GiB] with EC(2,4) */
	rc = llapi_layout_comp_add_ec(layout, 1, 512*1024*1024ULL,
				      1024*1024*1024ULL, 4, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M2 EC2: [1GiB, EOF] with EC(2,6) */
	rc = llapi_layout_comp_add_ec(layout, 1, 1024*1024*1024ULL, LUSTRE_EOF,
				      6, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Set mirror count for the layout (2 mirrors total) */
	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/*
	 * Validate the layout - should fail with LSE_EC_MIXED_MIRROR
	 * because Mirror 2 contains both non-PARITY and PARITY components
	 */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc != 0, rc,
		       "Mixed parity mirror should fail validation");

	llapi_layout_free(layout);
}

#define T51FILE		"f51"
#define T51_DESC	"verify parity-first mixed mirror is rejected"
static void test51(void)
{
	int rc;
	struct llapi_layout *layout;

	/*
	 * Test that a mirror starting with PARITY components but also
	 * containing non-PARITY components is rejected. This validates
	 * the parity-agnostic mirror boundary detection and mixed
	 * mirror rejection.
	 */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1: Regular data component [0, EOF] */
	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/*
	 * Mirror 2: Create a mixed mirror with both EC and non-EC components.
	 * Start by creating data component, then add EC for same extent,
	 * then add another data component. This creates a mirror where
	 * EC components come before non-EC components in the list.
	 * This should fail validation as a mixed mirror.
	 */
	/* M2 COMP1: [0, 1GiB] - data component */
	rc = llapi_layout_add_first_comp(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M3 EC1: [0, 1GiB] with EC(4,2) - EC component for same extent */
	rc = llapi_layout_comp_add_ec(layout, 2, 0, 1024*1024*1024ULL, 4, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M3 COMP2: [1GiB, EOF] - regular data component */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024*1024*1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Set mirror count for the layout (3 mirrors total) */
	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/*
	 * Validate the layout - should fail with LSE_EC_MIXED_MIRROR
	 * because Mirror 3 starts with PARITY but also has non-PARITY
	 */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc != 0, rc,
		       "Parity-first mixed mirror should fail validation");

	llapi_layout_free(layout);
}

#define T52FILE		"f52"
#define T52_DESC	"create simple EC layout with data and parity components"
static void test52(void)
{
	struct llapi_layout *layout;
	char path[PATH_MAX];
	int fd;
	int rc;

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T52FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	/* Create a layout with one data mirror and one EC mirror */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1: Regular data component [0, EOF] with 6 stripes */
	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 2: EC component [0, EOF] with EC(2,6) */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, LUSTRE_EOF, 6, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Set mirror count for the layout (2 mirrors total) */
	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Validate the layout */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc, "errno = %d", errno);

	fd = llapi_layout_file_create(path, 0, 0640, layout);
	ASSERTF(fd >= 0, "errno = %d", errno);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	llapi_layout_free(layout);

	/* Verify the created file has the correct layout */
	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Move to first component (Mirror 1, data component) */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);

	__verify_comp_extent(layout, 0, LUSTRE_EOF, "M1 data comp");
	/* Note: stripe count may be capped by number of OSTs */

	/* Move to second component (Mirror 2, EC parity component) */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);

	__verify_comp_extent(layout, 0, LUSTRE_EOF, "M2 EC parity");
	/* EC(6,2) - dstripe=6, cstripe=2, binds to M1 */
	__verify_parity_comp(layout, 6, 2, 1, "M2 EC parity");

	llapi_layout_free(layout);
}

#define T53FILE		"f53"
#define T53_DESC	"verify multiple data + multiple parity components layout"
static void test53(void)
{
	int fd;
	int rc;
	struct llapi_layout *layout;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T53FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	/* Create layout with data mirror and EC mirror, each with 2
	 * components
	 */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1: Regular data components */
	/* M1 COMP1: [0, 1GiB] with 4 stripes */
	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M1 COMP2: [1GiB, EOF] with 6 stripes */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024*1024*1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 2: EC components matching Mirror 1 extents */
	/* M2 EC1: [0, 1GiB] with EC(2,4) */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, 1024*1024*1024ULL, 4, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M2 EC2: [1GiB, EOF] with EC(2,6) */
	rc = llapi_layout_comp_add_ec(layout, 1, 1024*1024*1024ULL, LUSTRE_EOF,
				      6, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Set mirror count for the layout (2 mirrors total) */
	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Validate the layout */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc, "errno = %d", errno);

	fd = llapi_layout_file_create(path, 0, 0640, layout);
	ASSERTF(fd >= 0, "errno = %d", errno);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	llapi_layout_free(layout);

	/* Verify the created file has the correct layout */
	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* M1 COMP1: [0, 1GiB] - data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, 1024*1024*1024ULL, "M1 COMP1");

	/* M1 COMP2: [1GiB, EOF] - data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 1024*1024*1024ULL, LUSTRE_EOF, "M1 COMP2");

	/* M2 EC1: [0, 1GiB] with EC(4,2) - dstripe=4, cstripe=2,
	 * binds to M1 COMP1
	 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, 1024*1024*1024ULL, "M2 EC1");
	__verify_parity_comp(layout, 4, 2, 1, "M2 EC1");

	/* M2 EC2: [1GiB, EOF] with EC(6,2) - dstripe=6, cstripe=2,
	 * binds to M1 COMP2
	 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 1024*1024*1024ULL, LUSTRE_EOF, "M2 EC2");
	__verify_parity_comp(layout, 6, 2, 1, "M2 EC2");

	llapi_layout_free(layout);
}

#define T54FILE		"f54"
#define T54_DESC	"verify complex multi-component EC layout"
static void test54(void)
{
	int fd;
	int rc;
	struct llapi_layout *layout;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T54FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	/* Create layout with data mirror and EC mirror, each with 4
	 * components
	 */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1: Regular data components */
	/* M1 COMP1: [0, 256MiB] with 2 stripes */
	rc = llapi_layout_stripe_count_set(layout, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 256*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M1 COMP2: [256MiB, 512MiB] with 4 stripes */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 256*1024*1024ULL,
					  512*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M1 COMP3: [512MiB, 1GiB] with 6 stripes */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 512*1024*1024ULL,
					  1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M1 COMP4: [1GiB, EOF] with 8 stripes */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 8);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024*1024*1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 2: EC components matching Mirror 1 extents */
	/* M2 EC1: [0, 256MiB] with EC(1,2) */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, 256*1024*1024ULL, 2, 1);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M2 EC2: [256MiB, 512MiB] with EC(2,4) */
	rc = llapi_layout_comp_add_ec(layout, 1, 256*1024*1024ULL,
				      512*1024*1024ULL, 4, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M2 EC3: [512MiB, 1GiB] with EC(2,6) */
	rc = llapi_layout_comp_add_ec(layout, 1, 512*1024*1024ULL,
				      1024*1024*1024ULL, 6, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M2 EC4: [1GiB, EOF] with EC(3,8) */
	rc = llapi_layout_comp_add_ec(layout, 1, 1024*1024*1024ULL, LUSTRE_EOF,
				      8, 3);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Set mirror count for the layout (2 mirrors total) */
	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Validate the layout */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc, "errno = %d", errno);

	fd = llapi_layout_file_create(path, 0, 0640, layout);
	ASSERTF(fd >= 0, "errno = %d", errno);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	llapi_layout_free(layout);

	/* Verify the created file has the correct layout */
	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* M1 COMP1: [0, 256MiB] - data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, 256*1024*1024ULL, "M1 COMP1");

	/* M1 COMP2: [256MiB, 512MiB] - data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 256*1024*1024ULL, 512*1024*1024ULL,
			     "M1 COMP2");

	/* M1 COMP3: [512MiB, 1GiB] - data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 512*1024*1024ULL, 1024*1024*1024ULL,
			     "M1 COMP3");

	/* M1 COMP4: [1GiB, EOF] - data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 1024*1024*1024ULL, LUSTRE_EOF, "M1 COMP4");

	/* M2 EC1: [0, 256MiB] with EC(2,1) - dstripe=2, cstripe=1,
	 * binds to M1 COMP1
	 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, 256*1024*1024ULL, "M2 EC1");
	__verify_parity_comp(layout, 2, 1, 1, "M2 EC1");

	/* M2 EC2: [256MiB, 512MiB] with EC(4,2) - dstripe=4, cstripe=2,
	 * binds to M1 COMP2
	 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 256*1024*1024ULL, 512*1024*1024ULL,
			     "M2 EC2");
	__verify_parity_comp(layout, 4, 2, 1, "M2 EC2");

	/* M2 EC3: [512MiB, 1GiB] with EC(6,2) - dstripe=6, cstripe=2,
	 * binds to M1 COMP3
	 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 512*1024*1024ULL, 1024*1024*1024ULL,
			     "M2 EC3");
	__verify_parity_comp(layout, 6, 2, 1, "M2 EC3");

	/* M2 EC4: [1GiB, EOF] with EC(8,3) - dstripe=8, cstripe=3,
	 * binds to M1 COMP4
	 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 1024*1024*1024ULL, LUSTRE_EOF, "M2 EC4");
	__verify_parity_comp(layout, 8, 3, 1, "M2 EC4");

	llapi_layout_free(layout);
}

#define T55FILE		"f55"
#define T55_DESC	"verify additional EC component ordering scenarios"
static void test55(void)
{
	int fd;
	int rc;
	struct llapi_layout *layout;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T55FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	/* Create layout: COMP1 COMP2 COMP3 (complete to EOF) */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* COMP1: [0, 256MiB] */
	rc = llapi_layout_stripe_count_set(layout, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 256*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* COMP2: [256MiB, 512MiB] */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 256*1024*1024ULL,
					  512*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* COMP3: [512MiB, EOF] */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 512*1024*1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Add EC for all components in order - should work */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, 256*1024*1024ULL, 2, 1);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_add_ec(layout, 1, 256*1024*1024ULL,
				      512*1024*1024ULL, 4, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_add_ec(layout, 1, 512*1024*1024ULL, LUSTRE_EOF,
				      6, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Set mirror count for the layout (2 mirrors total) */
	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Validate the layout */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc, "errno = %d", errno);

	fd = llapi_layout_file_create(path, 0, 0640, layout);
	ASSERTF(fd >= 0, "errno = %d", errno);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	llapi_layout_free(layout);
}

#define T56FILE		"f56"
#define T56_DESC	"verify EC layout with two mirrors - EC only first mirror"
static void test56(void)
{
	int fd;
	int rc;
	struct llapi_layout *layout;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T56FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	/* Create layout with 3 mirrors: data, EC, data */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1: Regular data components */
	/* M1 COMP1: [0, 1GiB] with 4 stripes */
	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M1 COMP2: [1GiB, EOF] with 6 stripes */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024*1024*1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 2: EC components matching Mirror 1 extents */
	/* M2 EC1: [0, 1GiB] with EC(2,4) */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, 1024*1024*1024ULL, 4, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M2 EC2: [1GiB, EOF] with EC(2,6) */
	rc = llapi_layout_comp_add_ec(layout, 1, 1024*1024*1024ULL, LUSTRE_EOF,
				      6, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 3: Regular data components with different extents */
	rc = llapi_layout_add_first_comp(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M3 COMP1: [0, 2GiB] with 8 stripes */
	rc = llapi_layout_stripe_count_set(layout, 8);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 2*1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M3 COMP2: [2GiB, EOF] with 10 stripes */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 10);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 2*1024*1024*1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Set mirror count for the layout (3 mirrors total) */
	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Validate the layout */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc, "errno = %d", errno);

	fd = llapi_layout_file_create(path, 0, 0640, layout);
	ASSERTF(fd >= 0, "errno = %d", errno);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	llapi_layout_free(layout);

	/* Verify the created file has the correct layout */
	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* M1 COMP1: [0, 1GiB] - data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, 1024*1024*1024ULL, "M1 COMP1");

	/* M1 COMP2: [1GiB, EOF] - data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 1024*1024*1024ULL, LUSTRE_EOF, "M1 COMP2");

	/* M2 EC1: [0, 1GiB] with EC(4,2) - dstripe=4, cstripe=2,
	 * binds to M1 COMP1
	 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, 1024*1024*1024ULL, "M2 EC1");
	__verify_parity_comp(layout, 4, 2, 1, "M2 EC1");

	/* M2 EC2: [1GiB, EOF] with EC(6,2) - dstripe=6, cstripe=2,
	 * binds to M1 COMP2
	 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 1024*1024*1024ULL, LUSTRE_EOF, "M2 EC2");
	__verify_parity_comp(layout, 6, 2, 1, "M2 EC2");

	/* M3 COMP1: [0, 2GiB] - regular data component (no EC) */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, 2*1024*1024*1024ULL, "M3 COMP1");

	/* M3 COMP2: [2GiB, EOF] - regular data component (no EC) */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 2*1024*1024*1024ULL, LUSTRE_EOF,
			     "M3 COMP2");

	llapi_layout_free(layout);
}

#define T57FILE		"f57"
#define T57_DESC	"verify EC layout with two mirrors - EC both mirrors"
static void test57(void)
{
	int fd;
	int rc;
	struct llapi_layout *layout;
	char path[PATH_MAX];
	__u32 mirror_id;

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T57FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	/* Create layout with 4 mirrors: data, EC, data, EC */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1: Regular data components */
	/* M1 COMP1: [0, 1GiB] with 4 stripes */
	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M1 COMP2: [1GiB, EOF] with 6 stripes */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024*1024*1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_mirror_id_get(layout, &mirror_id);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 2: EC components matching Mirror 1 */
	/* M2 EC1: [0, 1GiB] with EC(2,4) */
	rc = llapi_layout_comp_add_ec(layout, mirror_id, 0,
				      1024 * 1024 * 1024ULL, 4, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M2 EC2: [1GiB, EOF] with EC(2,6) */
	rc = llapi_layout_comp_add_ec(layout, mirror_id, 1024 * 1024 * 1024ULL,
				      LUSTRE_EOF, 6, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 3: Regular data components (different extents from M1) */
	rc = llapi_layout_add_first_comp(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M3 COMP1: [0, 2GiB] with 8 stripes */
	rc = llapi_layout_stripe_count_set(layout, 8);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 2*1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M3 COMP2: [2GiB, EOF] with 10 stripes */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 10);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 2*1024*1024*1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 4: EC components matching Mirror 1 (not Mirror 3).
	 * This should fail since a data component can only be protected
	 * by one parity component.
	 *
	 * M4 EC1: [0, 1GiB] with EC(2,4) - matches M1 COMP1
	 */
	rc = llapi_layout_comp_add_ec(layout, mirror_id, 0, 1024*1024*1024ULL,
				      4, 2);
	ASSERTF(rc != 0, "errno = %d", errno);

	/* M4 EC2: [1GiB, EOF] with EC(2,6) - matches M1 COMP2 - should fail */
	rc = llapi_layout_comp_add_ec(layout, mirror_id, 1024*1024*1024ULL,
				      LUSTRE_EOF, 6, 2);
	ASSERTF(rc != 0, "errno = %d", errno);

	/* Set mirror count for the layout (3 mirrors total) */
	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Validate the layout */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc, "errno = %d", errno);

	fd = llapi_layout_file_create(path, 0, 0640, layout);
	ASSERTF(fd >= 0, "errno = %d", errno);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	llapi_layout_free(layout);

	/* Verify the created file has the correct layout */
	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* M1 COMP1: [0, 1GiB] - data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, 1024*1024*1024ULL, "M1 COMP1");

	/* M1 COMP2: [1GiB, EOF] - data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 1024*1024*1024ULL, LUSTRE_EOF, "M1 COMP2");

	/* M2 EC1: [0, 1GiB] with EC(4,2) - dstripe=4, cstripe=2,
	 * binds to M1 COMP1
	 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, 1024*1024*1024ULL, "M2 EC1");
	__verify_parity_comp(layout, 4, 2, 1, "M2 EC1");

	/* M2 EC2: [1GiB, EOF] with EC(6,2) - dstripe=6, cstripe=2,
	 * binds to M1 COMP2
	 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 1024*1024*1024ULL, LUSTRE_EOF, "M2 EC2");
	__verify_parity_comp(layout, 6, 2, 1, "M2 EC2");

	/* M3 COMP1: [0, 2GiB] - regular data component (no EC) */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, 2*1024*1024*1024ULL, "M3 COMP1");

	/* M3 COMP2: [2GiB, EOF] - regular data component (no EC) */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 2*1024*1024*1024ULL, LUSTRE_EOF,
			     "M3 COMP2");

	llapi_layout_free(layout);
}

#define T58FILE		"f58"
#define T58_DESC	"verify three mirrors with different extents - EC first only"
static void test58(void)
{
	int fd;
	int rc;
	struct llapi_layout *layout;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T58FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	/* Create layout with 4 mirrors with different extent structures */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1: Regular data components with 3 components */
	/* M1 COMP1: [0, 512MiB] with 2 stripes */
	rc = llapi_layout_stripe_count_set(layout, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 512*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M1 COMP2: [512MiB, 1GiB] with 4 stripes */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 512*1024*1024ULL,
					  1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M1 COMP3: [1GiB, EOF] with 6 stripes */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024*1024*1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 2: EC components matching Mirror 1 extents */
	/* M2 EC1: [0, 512MiB] with EC(1,2) */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, 512*1024*1024ULL, 2, 1);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M2 EC2: [512MiB, 1GiB] with EC(2,4) */
	rc = llapi_layout_comp_add_ec(layout, 1, 512*1024*1024ULL,
				      1024*1024*1024ULL, 4, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M2 EC3: [1GiB, EOF] with EC(2,6) */
	rc = llapi_layout_comp_add_ec(layout, 1, 1024*1024*1024ULL, LUSTRE_EOF,
				      6, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 3: Regular data with different extents (2 components) */
	rc = llapi_layout_add_first_comp(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M3 COMP1: [0, 2GiB] with 8 stripes */
	rc = llapi_layout_stripe_count_set(layout, 8);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 2*1024*1024*1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M3 COMP2: [2GiB, EOF] with 10 stripes */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 10);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 2*1024*1024*1024ULL,
					   LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 4: Regular data with single component */
	rc = llapi_layout_add_first_comp(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M4 COMP1: [0, EOF] with 12 stripes (single component) */
	rc = llapi_layout_stripe_count_set(layout, 12);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Set mirror count for the layout (4 mirrors total) */
	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Validate the layout */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc, "errno = %d", errno);

	fd = llapi_layout_file_create(path, 0, 0640, layout);
	ASSERTF(fd >= 0, "errno = %d", errno);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	llapi_layout_free(layout);

	/* Verify the created file has the correct layout */
	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* M1 COMP1: [0, 512MiB] - data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, 512*1024*1024ULL, "M1 COMP1");

	/* M1 COMP2: [512MiB, 1GiB] - data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 512*1024*1024ULL, 1024*1024*1024ULL,
			     "M1 COMP2");

	/* M1 COMP3: [1GiB, EOF] - data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 1024*1024*1024ULL, LUSTRE_EOF,
			     "M1 COMP3");

	/* M2 EC1: [0, 512MiB] with EC(2,1) - dstripe=2, cstripe=1,
	 * binds to M1 COMP1
	 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, 512*1024*1024ULL, "M2 EC1");
	__verify_parity_comp(layout, 2, 1, 1, "M2 EC1");

	/* M2 EC2: [512MiB, 1GiB] with EC(4,2) - dstripe=4, cstripe=2,
	 * binds to M1 COMP2
	 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 512*1024*1024ULL, 1024*1024*1024ULL,
			     "M2 EC2");
	__verify_parity_comp(layout, 4, 2, 1, "M2 EC2");

	/* M2 EC3: [1GiB, EOF] with EC(6,2) - dstripe=6, cstripe=2,
	 * binds to M1 COMP3
	 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 1024*1024*1024ULL, LUSTRE_EOF, "M2 EC3");
	__verify_parity_comp(layout, 6, 2, 1, "M2 EC3");

	/* M3 COMP1: [0, 2GiB] - regular data component (no EC) */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, 2*1024*1024*1024ULL, "M3 COMP1");

	/* M3 COMP2: [2GiB, EOF] - regular data component (no EC) */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 2*1024*1024*1024ULL, LUSTRE_EOF,
			     "M3 COMP2");

	/* M4 COMP1: [0, EOF] - regular data component (no EC) */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, LUSTRE_EOF, "M4 COMP1");

	llapi_layout_free(layout);
}

#define T59FILE		"f59"
#define T59_DESC	"EC verify mirror count and data-parity comp linkage"
static void test59(void)
{
	struct llapi_layout *layout;
	uint16_t link_id;
	uint32_t mirror_id;
	int rc;

	/*
	 * Create 2 data mirrors and 1 parity mirrors protecting the first
	 * data mirror. The linkage between the data and parity components will
	 * be verified by the test. In addition, this test verifies that
	 * removing EC components also removes the linkage and affects the
	 * mirror count correctly.
	 */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1: Regular data components */
	/* M1 COMP1: [0, 1GiB] with 4 stripes */
	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024 * 1024 * 1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M1 COMP2: [1GiB, EOF] with 8 stripes */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 8);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024 * 1024 * 1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 2: Regular data components */
	rc = llapi_layout_add_first_comp(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M2 COMP1: [0, 1GiB] with 4 stripes */
	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, 1024 * 1024 * 1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M2 COMP2: [1GiB, EOF] with 8 stripes */
	rc = llapi_layout_comp_add(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 8);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 1024 * 1024 * 1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Get mirror id from first component and first mirror */
	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_mirror_id_get(layout, &mirror_id);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 3: Parity components */
	/* M3 EC1: [0, 1GiB] with EC(2,1) */
	rc = llapi_layout_comp_add_ec(layout, mirror_id, 0,
				      1024 * 1024 * 1024ULL, 2, 1);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Check link id is set on first data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_mirror_link_id_get(layout, &link_id);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(link_id != LLAPI_MIRROR_LINK_NONE, "link_id = %d", link_id);

	/* M3 EC2: [1GiB, EOF] with EC(2,1) */
	rc = llapi_layout_comp_add_ec(layout, mirror_id, 1024 * 1024 * 1024ULL,
				      LUSTRE_EOF, 2, 1);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Check link id is set on second data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_mirror_link_id_get(layout, &link_id);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(link_id != LLAPI_MIRROR_LINK_NONE, "link_id = %d", link_id);

	/* Validate the layout */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc, "errno = %d", errno);

	/* Move current component to last */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_LAST);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Delete last EC component */
	rc = llapi_layout_comp_del(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* check link_id on M1 COMP2 was cleared */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_mirror_link_id_get(layout, &link_id);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(link_id == LLAPI_MIRROR_LINK_NONE, "link_id = %d", link_id);

	/* Verifying the layout fails due to being incomplete */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc != 0, rc, "Layout should be incomplete");

	/* Delete next last EC component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_LAST);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_del(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* check link_id on first component was cleared */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_mirror_link_id_get(layout, &link_id);
	ASSERTF(rc == 0, "errno = %d", errno);
	ASSERTF(link_id == LLAPI_MIRROR_LINK_NONE, "link_id = %d", link_id);

	/* Verifying the layout fails due to wrong mirror count */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc != 0, rc, "Layout should have wrong mirror count");

	/* Set correct mirror count */
	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc, "errno = %d", errno);

	llapi_layout_free(layout);
}

#define T60FILE		"f60"
#define T60_DESC	"verify EC component stripe size matches data component"
static void test60(void)
{
	int fd;
	int rc;
	struct llapi_layout *layout, *filelayout;
	uint64_t data_stripe_size, ec_stripe_size;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T60FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	/* Create a layout with one data component with specific stripe size */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Set stripe count and size for data component */
	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_size_set(layout, 4*1024*1024);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Add EC component with matching extent */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, LUSTRE_EOF, 6, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Navigate to first component and get its stripe size */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_size_get(layout, &data_stripe_size);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Navigate to second component (EC) and get its stripe size */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_size_get(layout, &ec_stripe_size);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Verify stripe sizes match */
	ASSERTF(data_stripe_size == ec_stripe_size,
		"EC stripe size %lu should match data stripe size %lu",
		ec_stripe_size, data_stripe_size);

	/* Try to set a different stripe size on EC component - should fail */
	rc = llapi_layout_stripe_size_set(layout, 1*1024*1024);
	ASSERTF(rc != 0 && errno == EINVAL,
		"Setting stripe size on EC component should fail with EINVAL");

	/* Set mirror count for the layout (2 mirrors total) */
	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Validate the layout */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc, "errno = %d", errno);

	/* Create the file with this layout */
	fd = llapi_layout_file_create(path, 0, 0640, layout);
	ASSERTF(fd >= 0, "errno = %d", errno);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	llapi_layout_free(layout);

	/* Read the layout back from the file and verify stripe sizes match */
	filelayout = llapi_layout_get_by_path(path, 0);
	ASSERTF(filelayout != NULL, "errno = %d", errno);

	/* Navigate to first component and get its stripe size */
	rc = llapi_layout_comp_use(filelayout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_size_get(filelayout, &data_stripe_size);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Navigate to second component (EC) and get its stripe size */
	rc = llapi_layout_comp_use(filelayout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_size_get(filelayout, &ec_stripe_size);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Verify stripe sizes match in the file layout */
	ASSERTF(data_stripe_size == ec_stripe_size,
		"File EC stripe size %lu should match data stripe size %lu",
		ec_stripe_size, data_stripe_size);

	ASSERTF(data_stripe_size == 4*1024*1024,
		"File data stripe size %lu should be 4MiB",
		data_stripe_size);

	llapi_layout_free(filelayout);
}

#define T61FILE		"f61"
#define T61_DESC	"verify a protected data component can't be deleted"
static void test61(void)
{
	struct llapi_layout *layout;
	int rc;

	/*
	 * Create a layout with a data component and an EC parity component
	 * protecting it. Then verify that attempting to delete the protected
	 * data component fails.
	 */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* M1: Create data component [0, EOF] with 6 stripes */
	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M2: Add EC parity component to protect the data component */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, LUSTRE_EOF, 6, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Attempt to delete the protected data component - should fail */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_del(layout);
	ASSERTF(rc != 0,
		"Deleting protected data component should fail but succeeded");
	ASSERTF(errno == EINVAL,
		"Expected EINVAL when deleting protected data component, got %d",
		errno);

	/* Delete parity component first - should succeed*/
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_LAST);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_del(layout);
	ASSERTF(rc == 0, "Deleting parity component should succeed, errno = %d",
		errno);

	/* Now deleting data component - should succeed */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);

	llapi_layout_free(layout);
}

#define T62FILE		"f62"
#define T62_DESC	"verify multiple parity mirrors for one data mirror is rejected"
static void test62(void)
{
	struct llapi_layout *layout;
	int rc;

	/* Attempt to create a layout with 5 mirrors:
	 * DATA1, PARITY1, DATA2, PARITY2, PARITY1.2
	 * Creating PARITY1.2 components should fail because a data component
	 * can only be protected by one parity component.
	 */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1 (DATA1): [0, EOF] with 4 stripes */
	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 2 (PARITY1): [0, EOF] with EC(4,2) - bind to M1 */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, LUSTRE_EOF, 4, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 3 (DATA2): [0, EOF] with 6 stripes */
	rc = llapi_layout_add_first_comp(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 4 (PARITY2): [0, EOF] with EC(6,2) - bind to M3 */
	rc = llapi_layout_comp_add_ec(layout, 3, 0, LUSTRE_EOF, 6, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 5 (PARITY1.2): [0, EOF] with EC(4,3) - bind to M1 */
	/* this should fail because M1 is already bound to M2 */
	rc = llapi_layout_comp_add_ec(layout, 3, 0, LUSTRE_EOF, 4, 3);
	ASSERTF(rc != 0, "errno = %d", errno);

	/* Validate the layout */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc, "errno = %d", errno);

	llapi_layout_free(layout);
}

#define T63FILE		"f63"
#define T63_DESC	"verify DATA1, PARITY1, DATA2, PARITY2 binding"
static void test63(void)
{
	struct llapi_layout *layout;
	char path[PATH_MAX];
	int fd;
	int rc;

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T63FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	/* Create layout with 4 mirrors: DATA1, PARITY1, DATA2, PARITY2 */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1 (DATA1): [0, EOF] with 4 stripes */
	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 2 (PARITY1): [0, EOF] with EC(4,2) - bind to M1 */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, LUSTRE_EOF, 4, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 3 (DATA2): [0, EOF] with 6 stripes */
	rc = llapi_layout_add_first_comp(layout);
	ASSERTF(rc == 0, "llapi_layout_add_first_comp failed: errno = %d",
		errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "llapi_layout_stripe_count_set failed: errno = %d",
		errno);

	rc = llapi_layout_comp_extent_set(layout, 0, LUSTRE_EOF);
	ASSERTF(rc == 0, "llapi_layout_comp_extent_set failed: errno = %d",
		errno);

	/* Mirror 4 (PARITY2): [0, EOF] with EC(6,2) - bind to M3 */
	rc = llapi_layout_comp_add_ec(layout, 3, 0, LUSTRE_EOF, 6, 2);
	ASSERTF(rc == 0, "llapi_layout_comp_add_ec failed: errno = %d", errno);

	/* Set mirror count for the layout (4 mirrors total) */
	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Validate the layout */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc, "errno = %d", errno);

	fd = llapi_layout_file_create(path, 0, 0640, layout);
	ASSERTF(fd >= 0, "errno = %d", errno);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	llapi_layout_free(layout);

	/* Verify the created file has the correct layout and bindings */
	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* M1 DATA1: [0, EOF] - regular data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, LUSTRE_EOF, "M1 DATA1");
	__verify_ec_data_comp(layout, 2, "M1 DATA1");

	/* M2 PARITY1: [0, EOF] with EC(4,2) - binds to M1 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, LUSTRE_EOF, "M2 PARITY1");
	__verify_parity_comp(layout, 4, 2, 1, "M2 PARITY1");

	/* M3 DATA2: [0, EOF] - regular data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, LUSTRE_EOF, "M3 DATA2");
	__verify_ec_data_comp(layout, 4, "M3 DATA2");

	/* M4 PARITY2: [0, EOF] with EC(6,2) - binds to M3 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, LUSTRE_EOF, "M4 PARITY2");
	__verify_parity_comp(layout, 6, 2, 3, "M4 PARITY2");

	llapi_layout_free(layout);
}

#define T64FILE		"f64"
#define T64_DESC	"verify DATA1, DATA2, PARITY1, PARITY2 binding"
static void test64(void)
{
	int fd;
	int rc;
	struct llapi_layout *layout;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T64FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	/* Create layout with 4 mirrors: DATA1, DATA2, PARITY1, PARITY2 */
	layout = llapi_layout_alloc();
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* Mirror 1 (DATA1): [0, EOF] with 4 stripes */
	rc = llapi_layout_stripe_count_set(layout, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 2 (DATA2): [0, EOF] with 6 stripes */
	rc = llapi_layout_add_first_comp(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout, 0, LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 3 (PARITY1): [0, EOF] with EC(4,2) - bind to M1 */
	rc = llapi_layout_comp_add_ec(layout, 1, 0, LUSTRE_EOF, 4, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Mirror 4 (PARITY2): [0, EOF] with EC(6,2) - bind to M2 */
	rc = llapi_layout_comp_add_ec(layout, 2, 0, LUSTRE_EOF, 6, 2);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Set mirror count for the layout (5 mirrors total) */
	rc = llapi_layout_mirror_count_sync(layout);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* Validate the layout */
	rc = llapi_layout_sanity(layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc, "errno = %d", errno);

	fd = llapi_layout_file_create(path, 0, 0640, layout);
	ASSERTF(fd >= 0, "errno = %d", errno);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	llapi_layout_free(layout);

	/* Verify the created file has the correct layout and bindings */
	layout = llapi_layout_get_by_path(path, 0);
	ASSERTF(layout != NULL, "errno = %d", errno);

	/* M1 DATA1: [0, EOF] - regular data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, LUSTRE_EOF, "M1 DATA1");
	__verify_ec_data_comp(layout, 3, "M1 DATA1");

	/* M2 DATA2: [0, EOF] - regular data component */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, LUSTRE_EOF, "M3 DATA2");
	__verify_ec_data_comp(layout, 4, "M2 DATA2");

	/* M3 PARITY1: [0, EOF] with EC(4,2) - binds to M1 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, LUSTRE_EOF, "M2 PARITY1");
	__verify_parity_comp(layout, 4, 2, 1, "M2 PARITY1");

	/* M4 PARITY2: [0, EOF] with EC(6,2) - binds to M3 */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(layout, 0, LUSTRE_EOF, "M4 PARITY2");
	__verify_parity_comp(layout, 6, 2, 2, "M4 PARITY2");

	llapi_layout_free(layout);
}

#define T65FILE		"f65"
#define T65_DESC	"verify layout merge preserves EC data-parity bindings"
static void test65(void)
{
	int fd;
	int rc;
	struct llapi_layout *layout1, *layout2, *merged_layout, *filelayout;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", lustre_dir, T65FILE);

	rc = unlink(path);
	ASSERTF(rc >= 0 || errno == ENOENT, "errno = %d", errno);

	/*
	 * Create layout1: DATA1 (2 comps) + PARITY1 (2 comps)
	 *   M1 (DATA1):   [0, 1GiB] + [1GiB, EOF]
	 *   M2 (PARITY1): [0, 1GiB] EC(4,2) + [1GiB, EOF] EC(4,2): binds to M1
	 */
	layout1 = llapi_layout_alloc();
	ASSERTF(layout1 != NULL, "errno = %d", errno);

	/* M1 DATA1 comp1: [0, 1GiB] with 4 stripes */
	rc = llapi_layout_stripe_count_set(layout1, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout1, 0, 1024 * 1024 * 1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M1 DATA1 comp2: [1GiB, EOF] with 4 stripes */
	rc = llapi_layout_comp_add(layout1);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout1, 4);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout1, 1024 * 1024 * 1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M2 PARITY1 comp1: [0, 1GiB] with EC(4,2) - bind to M1 */
	rc = llapi_layout_comp_add_ec(layout1, 1, 0, 1024 * 1024 * 1024ULL, 4,
				      2);
	ASSERTF(rc == 0, "llapi_layout_comp_add_ec failed: errno = %d", errno);

	/* M2 PARITY1 comp2: [1GiB, EOF] with EC(4,2) - bind to M1 */
	rc = llapi_layout_comp_add_ec(layout1, 1, 1024 * 1024 * 1024ULL,
				      LUSTRE_EOF, 4, 2);
	ASSERTF(rc == 0, "llapi_layout_comp_add_ec failed: errno = %d", errno);

	/*
	 * Create layout2: DATA1 (2 comps) + DATA2 (2 comps) + PARITY1 (2 comps)
	 *   M1 (DATA1):   [0, 1GiB] + [1GiB, EOF]
	 *   M2 (DATA2):   [0, 512MiB] + [512MiB, EOF]
	 *   M3 (PARITY1): [0, 1GiB] EC(6,2) + [1GiB, EOF] EC(6,2): binds to M1
	 */
	layout2 = llapi_layout_alloc();
	ASSERTF(layout2 != NULL, "errno = %d", errno);

	/* M1 DATA1 comp1: [0, 1GiB] with 6 stripes */
	rc = llapi_layout_stripe_count_set(layout2, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout2, 0, 1024 * 1024 * 1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M1 DATA1 comp2: [1GiB, EOF] with 6 stripes */
	rc = llapi_layout_comp_add(layout2);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout2, 6);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout2, 1024 * 1024 * 1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M2 DATA2 comp1: [0, 512MiB] with 8 stripes */
	rc = llapi_layout_add_first_comp(layout2);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout2, 8);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout2, 0, 512 * 1024 * 1024ULL);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M2 DATA2 comp2: [512MiB, EOF] with 8 stripes */
	rc = llapi_layout_comp_add(layout2);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_stripe_count_set(layout2, 8);
	ASSERTF(rc == 0, "errno = %d", errno);

	rc = llapi_layout_comp_extent_set(layout2, 512 * 1024 * 1024ULL,
					  LUSTRE_EOF);
	ASSERTF(rc == 0, "errno = %d", errno);

	/* M3 PARITY1 comp1: [0, 1GiB] with EC(6,2) - bind to M1 DATA1 */
	rc = llapi_layout_comp_add_ec(layout2, 1, 0, 1024 * 1024 * 1024ULL, 6,
				      2);
	ASSERTF(rc == 0, "llapi_layout_comp_add_ec failed: errno = %d", errno);

	/* M3 PARITY1 comp2: [1GiB, EOF] with EC(6,2) - bind to M1 DATA1 */
	rc = llapi_layout_comp_add_ec(layout2, 1, 1024 * 1024 * 1024ULL,
				      LUSTRE_EOF, 6, 2);
	ASSERTF(rc == 0, "llapi_layout_comp_add_ec failed: errno = %d", errno);

	/* Merge layout2 into layout1 */
	merged_layout = layout1;
	rc = llapi_layout_merge(&merged_layout, layout2);
	ASSERTF(rc == 0, "llapi_layout_merge failed: errno = %d", errno);

	/* Validate the merged layout */
	rc = llapi_layout_sanity(merged_layout, false, false);
	LAYOUT_ASSERTF(rc == 0, rc, "llapi_layout_sanity failed: errno = %d",
		       errno);

	/* Create file with merged layout */
	fd = llapi_layout_file_create(path, 0, 0640, merged_layout);
	ASSERTF(fd >= 0, "llapi_layout_file_create failed: errno = %d", errno);

	rc = close(fd);
	ASSERTF(rc == 0, "errno = %d", errno);

	llapi_layout_free(merged_layout);
	llapi_layout_free(layout2);

	/* Verify the created file has the correct layout and bindings */
	filelayout = llapi_layout_get_by_path(path, 0);
	ASSERTF(filelayout != NULL,
		"llapi_layout_get_by_path failed: errno = %d", errno);

	/*
	 * Expected layout after merge (10 components, 5 mirrors):
	 *   From layout1:
	 *     M1 (DATA1):   [0, 1GiB] + [1GiB, EOF] -> binds to M2
	 *     M2 (PARITY1): [0, 1GiB] + [1GiB, EOF] EC(4,2) -> binds to M1
	 *   From layout2 (mirror IDs offset by 2):
	 *     M3 (DATA1):   [0, 1GiB] + [1GiB, EOF] -> binds to M5
	 *     M4 (DATA2):   [0, 512MiB] + [512MiB, EOF] -> no EC binding
	 *     M5 (PARITY1): [0, 1GiB] + [1GiB, EOF] EC(6,2) -> binds to M3
	 */

	/* M1 DATA1 comp1: [0, 1GiB] */
	rc = llapi_layout_comp_use(filelayout, LLAPI_LAYOUT_COMP_USE_FIRST);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(filelayout, 0, 1024 * 1024 * 1024ULL,
			     "M1 DATA1 comp1");
	__verify_ec_data_comp(filelayout, 2, "M1 DATA1 comp1");

	/* M1 DATA1 comp2: [1GiB, EOF] */
	rc = llapi_layout_comp_use(filelayout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(filelayout, 1024 * 1024 * 1024ULL, LUSTRE_EOF,
			     "M1 DATA1 comp2");
	__verify_ec_data_comp(filelayout, 2, "M1 DATA1 comp2");

	/* M2 PARITY1 comp1: [0, 1GiB] with EC(4,2) - binds to M1 */
	rc = llapi_layout_comp_use(filelayout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(filelayout, 0, 1024 * 1024 * 1024ULL,
			     "M2 PARITY1 comp1");
	__verify_parity_comp(filelayout, 4, 2, 1, "M2 PARITY1 comp1");

	/* M2 PARITY1 comp2: [1GiB, EOF] with EC(4,2) - binds to M1 */
	rc = llapi_layout_comp_use(filelayout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(filelayout, 1024 * 1024 * 1024ULL, LUSTRE_EOF,
			     "M2 PARITY1 comp2");
	__verify_parity_comp(filelayout, 4, 2, 1, "M2 PARITY1 comp2");

	/* M3 DATA1 comp1: [0, 1GiB] - from layout2 */
	rc = llapi_layout_comp_use(filelayout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(filelayout, 0, 1024 * 1024 * 1024ULL,
			     "M3 DATA1 comp1");
	__verify_ec_data_comp(filelayout, 5, "M3 DATA1 comp1");

	/* M3 DATA1 comp2: [1GiB, EOF] - from layout2 */
	rc = llapi_layout_comp_use(filelayout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(filelayout, 1024 * 1024 * 1024ULL, LUSTRE_EOF,
			     "M3 DATA1 comp2");
	__verify_ec_data_comp(filelayout, 5, "M3 DATA1 comp2");

	/* M4 DATA2 comp1: [0, 512MiB] - from layout2, no EC binding */
	rc = llapi_layout_comp_use(filelayout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(filelayout, 0, 512 * 1024 * 1024ULL,
			     "M4 DATA2 comp1");
	__verify_ec_data_comp(filelayout, 0, "M4 DATA2 comp1");

	/* M4 DATA2 comp2: [512MiB, EOF] - from layout2, no EC binding */
	rc = llapi_layout_comp_use(filelayout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(filelayout, 512 * 1024 * 1024ULL, LUSTRE_EOF,
			     "M4 DATA2 comp2");
	__verify_ec_data_comp(filelayout, 0, "M4 DATA2 comp2");

	/* M5 PARITY1 comp1: [0, 1GiB] with EC(6,2) - binds to M3 */
	rc = llapi_layout_comp_use(filelayout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(filelayout, 0, 1024 * 1024 * 1024ULL,
			     "M5 PARITY1 comp1");
	__verify_parity_comp(filelayout, 6, 2, 3, "M5 PARITY1 comp1");

	/* M5 PARITY1 comp2: [1GiB, EOF] with EC(6,2) - binds to M3 */
	rc = llapi_layout_comp_use(filelayout, LLAPI_LAYOUT_COMP_USE_NEXT);
	ASSERTF(rc == 0, "errno = %d", errno);
	__verify_comp_extent(filelayout, 1024 * 1024 * 1024ULL, LUSTRE_EOF,
			     "M5 PARITY1 comp2");
	__verify_parity_comp(filelayout, 6, 2, 3, "M5 PARITY1 comp2");

	llapi_layout_free(filelayout);
}

static struct test_tbl_entry test_tbl[] = {
	TEST_REGISTER(0),
	TEST_REGISTER(1),
	TEST_REGISTER(2),
	TEST_REGISTER(3),
	TEST_REGISTER(4),
	TEST_REGISTER(5),
	TEST_REGISTER(6),
	TEST_REGISTER(7),
	TEST_REGISTER(8),
	TEST_REGISTER(9),
	TEST_REGISTER(10),
	TEST_REGISTER(11),
	TEST_REGISTER(12),
	TEST_REGISTER(13),
	TEST_REGISTER(14),
	TEST_REGISTER(15),
	TEST_REGISTER(16),
	TEST_REGISTER(17),
	TEST_REGISTER(18),
	TEST_REGISTER(19),
	TEST_REGISTER(20),
	TEST_REGISTER(21),
	TEST_REGISTER(22),
	TEST_REGISTER(23),
	TEST_REGISTER(24),
	TEST_REGISTER(25),
	TEST_REGISTER(26),
	TEST_REGISTER(27),
	TEST_REGISTER(28),
	TEST_REGISTER(29),
	TEST_REGISTER(30),
	TEST_REGISTER(31),
	TEST_REGISTER(32),
	TEST_REGISTER(33),
	TEST_REGISTER(34),
	TEST_REGISTER(35),
	TEST_REGISTER(36),
	TEST_REGISTER(37),
	TEST_REGISTER(40),
	TEST_REGISTER(41),
	TEST_REGISTER(42),
	TEST_REGISTER(43),
	TEST_REGISTER(44),
	TEST_REGISTER(45),
	TEST_REGISTER(46),
	TEST_REGISTER(47),
	TEST_REGISTER(48),
	TEST_REGISTER(49),
	TEST_REGISTER(50),
	TEST_REGISTER(51),
	TEST_REGISTER(52),
	TEST_REGISTER(53),
	TEST_REGISTER(54),
	TEST_REGISTER(55),
	TEST_REGISTER(56),
	TEST_REGISTER(57),
	TEST_REGISTER(58),
	TEST_REGISTER(59),
	TEST_REGISTER(60),
	TEST_REGISTER(61),
	TEST_REGISTER(62),
	TEST_REGISTER(63),
	TEST_REGISTER(64),
	TEST_REGISTER(65),
	TEST_REGISTER_END
};

static void process_args(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "d:p:o:s:t:")) != -1) {
		switch (c) {
		case 'd':
			if (snprintf(lustre_dir, sizeof(lustre_dir), "%s",
				     optarg) >= sizeof(lustre_dir))
				DIE("Error: test directory name too long\n");
			break;
		case 'p':
			poolname = optarg;
			break;
		case 'o':
			num_osts = atoi(optarg);
			if (num_osts < 2)
				DIE("Error: at least 2 OSTS are required\n");
			break;
		case 's':
			set_tests_to_skip(optarg, test_tbl);
			break;
		case 't':
			set_tests_to_run(optarg, test_tbl);
			break;
		case '?':
			fprintf(stderr, "Unknown option '%c'\n", optopt);
			usage(argv[0]);
		}
	}
}

int main(int argc, char *argv[])
{
	process_args(argc, argv);

	return run_tests(lustre_dir, test_tbl);
}
