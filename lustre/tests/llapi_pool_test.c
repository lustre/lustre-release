// SPDX-License-Identifier: GPL-2.0

/*
 * Tests for the liblustreapi pool pinning helpers.
 *
 * These tests exercise the llapi_pool_* APIs, which manipulate the
 * "lustre.pin" extended attribute to record per-pool pinning state,
 * and verify that they behave correctly and coexist with PCC pins.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <lustre/lustreapi.h>

#include "llapi_test_utils.h"

#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

static char lustre_dir[PATH_MAX - 5];

static void usage(char *prog)
{
	printf("Usage: %s -d LUSTRE_DIR [-s SKIP[,SKIP...]] [-t ONLY[,ONLY...]]\n",
	       prog);
	exit(0);
}

static void build_path(char *buf, size_t bufsize, const char *name)
{
	int rc;

	rc = snprintf(buf, bufsize, "%s/%s", lustre_dir, name);
	ASSERTF(rc > 0 && (size_t)rc < bufsize,
		"invalid path for '%s'", name);
}

static void create_empty_file(const char *name, char *path, size_t path_sz)
{
	int rc;
	int fd;

	build_path(path, path_sz, name);

	rc = unlink(path);
	ASSERTF(rc == 0 || errno == ENOENT,
		"unlink(%s) failed: %s", path, strerror(errno));

	fd = creat(path, 0600);
	ASSERTF(fd >= 0, "creat(%s) failed: %s", path, strerror(errno));
	close(fd);

	rc = lremovexattr(path, XATTR_LUSTRE_PIN);
	if (rc < 0 && errno != ENODATA && errno != ENOATTR)
		ASSERTF(0, "lremovexattr(%s) failed: %s", path,
			strerror(errno));
}

static ssize_t get_pin_xattr(const char *path, char *buf, size_t bufsize)
{
	ssize_t len;

	errno = 0;
	len = lgetxattr(path, XATTR_LUSTRE_PIN, buf, bufsize - 1);
	if (len < 0)
		return -1;

	buf[len] = '\0';
	return len;
}

#define T0_DESC "llapi_pool_pin_file/llapi_pool_unpin_file basic behavior"
static void test0(void)
{
	const char *pool_name = "testpool0";
	char path[PATH_MAX];
	char val[256];
	char expect[32];
	ssize_t len;
	int pinned;
	int rc;

	create_empty_file("pool_t0", path, sizeof(path));

	pinned = llapi_pool_is_pinned_file(path, pool_name);
	ASSERTF(pinned == 0,
		"llapi_pool_is_pinned_file expected 0, got %d (%s)",
		pinned, pinned < 0 ? strerror(-pinned) : "no error");

	rc = llapi_pool_pin_file(path, pool_name);
	ASSERTF(rc == 0, "llapi_pool_pin_file failed: %s", strerror(errno));

	pinned = llapi_pool_is_pinned_file(path, pool_name);
	ASSERTF(pinned == 1,
		"llapi_pool_is_pinned_file expected 1, got %d (%s)",
		pinned, pinned < 0 ? strerror(-pinned) : "no error");

	len = get_pin_xattr(path, val, sizeof(val));
	ASSERTF(len > 0, "lustre.pin xattr missing after pin: %s",
		strerror(errno));

	snprintf(expect, sizeof(expect), "%s: %s", "pool", pool_name);
	ASSERTF(strstr(val, expect) != NULL,
		"lustre.pin xattr '%s' does not contain '%s'", val, expect);

	rc = llapi_pool_unpin_file(path, pool_name);
	ASSERTF(rc == 0, "llapi_pool_unpin_file failed: %s", strerror(errno));

	pinned = llapi_pool_is_pinned_file(path, pool_name);
	ASSERTF(pinned == 0,
		"llapi_pool_is_pinned_file expected 0, got %d (%s)",
		pinned, pinned < 0 ? strerror(-pinned) : "no error");

	errno = 0;
	len = lgetxattr(path, XATTR_LUSTRE_PIN, val, sizeof(val));
	ASSERTF(len < 0 && (errno == ENODATA || errno == ENOATTR),
		"lustre.pin xattr should be removed, len=%zd, errno=%d",
		len, errno);
}

#define T1_DESC "llapi_pool_pin_file already pinned"
static void test1(void)
{
	const char *pool_name = "testpool1";
	char path[PATH_MAX];
	char v1[256];
	char v2[256];
	ssize_t len1;
	ssize_t len2;
	int rc;

	create_empty_file("pool_t1", path, sizeof(path));

	rc = llapi_pool_pin_file(path, pool_name);
	ASSERTF(rc == 0, "llapi_pool_pin_file failed: %s", strerror(errno));

	len1 = get_pin_xattr(path, v1, sizeof(v1));
	ASSERTF(len1 > 0, "lustre.pin xattr missing after first pin: %s",
		strerror(errno));

	rc = llapi_pool_pin_file(path, pool_name);
	ASSERTF(rc == 0, "second llapi_pool_pin_file failed: %s",
		strerror(errno));

	len2 = get_pin_xattr(path, v2, sizeof(v2));
	ASSERTF(len2 == len1 && memcmp(v1, v2, len1) == 0,
		"lustre.pin xattr changed on re-pin: '%s' vs '%s'", v1, v2);
}

#define T2_DESC "pool pins coexist with PCC hsm pins"
static void test2(void)
{
	const __u32 hsm_id = 2;
	const char *pool_name = "testpool2";
	char path[PATH_MAX];
	char val[256];
	char expect_hsm[64];
	char expect_pool[64];
	ssize_t len;
	int rc;

	create_empty_file("pool_t2", path, sizeof(path));

	rc = llapi_pcc_pin_file(path, hsm_id);
	ASSERTF(rc == 0, "llapi_pcc_pin_file failed: %s", strerror(-rc));

	rc = llapi_pool_pin_file(path, pool_name);
	ASSERTF(rc == 0, "llapi_pool_pin_file failed: %s", strerror(errno));

	len = get_pin_xattr(path, val, sizeof(val));
	ASSERTF(len > 0, "lustre.pin xattr missing after pin: %s",
		strerror(errno));

	snprintf(expect_hsm, sizeof(expect_hsm), "%s: %u", "hsm", hsm_id);
	snprintf(expect_pool, sizeof(expect_pool), "%s: %s", "pool", pool_name);
	ASSERTF(strstr(val, expect_hsm) != NULL,
		"lustre.pin xattr '%s' missing '%s'", val, expect_hsm);
	ASSERTF(strstr(val, expect_pool) != NULL,
		"lustre.pin xattr '%s' missing '%s'", val, expect_pool);

	rc = llapi_pool_unpin_file(path, pool_name);
	ASSERTF(rc == 0, "llapi_pool_unpin_file failed: %s", strerror(errno));

	len = get_pin_xattr(path, val, sizeof(val));
	ASSERTF(len > 0, "lustre.pin xattr lost hsm entry after pool unpin: %s",
		strerror(errno));
	ASSERTF(strstr(val, expect_hsm) != NULL,
		"hsm entry missing after pool unpin: '%s'", val);
	ASSERTF(strstr(val, expect_pool) == NULL,
		"pool entry still present after unpin: '%s'", val);

	rc = llapi_pcc_unpin_file(path, hsm_id);
	ASSERTF(rc == 0, "llapi_pcc_unpin_file failed: %s", strerror(-rc));

	errno = 0;
	len = lgetxattr(path, XATTR_LUSTRE_PIN, val, sizeof(val));
	ASSERTF(len < 0 && (errno == ENODATA || errno == ENOATTR),
		"lustre.pin xattr should be removed after final unpin, len=%zd, errno=%d",
		len, errno);
}

#define T3_DESC "llapi_pool_pin_fd, llapi_pool_unpin_fd and llapi_pool_is_pinned_fd"
static void test3(void)
{
	const char *pool_name = "testpool3";
	char path[PATH_MAX];
	int fd;
	int rc;
	int pinned;

	create_empty_file("pool_t3", path, sizeof(path));

	fd = open(path, O_RDONLY | O_NONBLOCK);
	ASSERTF(fd >= 0, "open(%s) failed: %s", path, strerror(errno));

	pinned = llapi_pool_is_pinned_fd(fd, pool_name);
	ASSERTF(pinned == 0,
		"llapi_pool_is_pinned_fd expected 0 before pin_fd, got %d (%s)",
		pinned, pinned < 0 ? strerror(-pinned) : "no error");

	rc = llapi_pool_pin_fd(fd, pool_name);
	ASSERTF(rc == 0, "llapi_pool_pin_fd failed: %s", strerror(errno));

	pinned = llapi_pool_is_pinned_fd(fd, pool_name);
	ASSERTF(pinned == 1,
		"llapi_pool_is_pinned_fd expected 1 after pin_fd, got %d (%s)",
		pinned, pinned < 0 ? strerror(-pinned) : "no error");

	pinned = llapi_pool_is_pinned_file(path, pool_name);
	ASSERTF(pinned == 1,
		"llapi_pool_is_pinned_file expected 1 after pin_fd, got %d (%s)",
		pinned, pinned < 0 ? strerror(-pinned) : "no error");

	rc = llapi_pool_unpin_fd(fd, pool_name);
	ASSERTF(rc == 0, "llapi_pool_unpin_fd failed: %s", strerror(errno));

	pinned = llapi_pool_is_pinned_fd(fd, pool_name);
	ASSERTF(pinned == 0,
		"llapi_pool_is_pinned_fd expected 0 after unpin_fd, got %d (%s)",
		pinned, pinned < 0 ? strerror(-pinned) : "no error");

	pinned = llapi_pool_is_pinned_file(path, pool_name);
	ASSERTF(pinned == 0,
		"llapi_pool_is_pinned_file expected 0 after unpin_fd, got %d (%s)",
		pinned, pinned < 0 ? strerror(-pinned) : "no error");

	close(fd);
}

#define T4_DESC "llapi_pool_pin_fid, llapi_pool_unpin_fid and llapi_pool_is_pinned_fid"
static void test4(void)
{
	const char *pool_name = "testpool4";
	char path[PATH_MAX];
	struct lu_fid fid;
	int pinned;
	int rc;

	create_empty_file("pool_t4", path, sizeof(path));

	rc = llapi_path2fid(path, &fid);
	ASSERTF(rc == 0, "llapi_path2fid(%s) failed: %s",
		path, strerror(-rc));

	pinned = llapi_pool_is_pinned_fid(lustre_dir, &fid, pool_name);
	ASSERTF(pinned == 0,
		"llapi_pool_is_pinned_fid expected 0 before pin_fid, got %d (%s)",
		pinned, pinned < 0 ? strerror(-pinned) : "no error");

	rc = llapi_pool_pin_fid(lustre_dir, &fid, pool_name);
	ASSERTF(rc == 0, "llapi_pool_pin_fid failed: %s", strerror(errno));

	pinned = llapi_pool_is_pinned_fid(lustre_dir, &fid, pool_name);
	ASSERTF(pinned == 1,
		"llapi_pool_is_pinned_fid expected 1 after pin_fid, got %d (%s)",
		pinned, pinned < 0 ? strerror(-pinned) : "no error");

	pinned = llapi_pool_is_pinned_file(path, pool_name);
	ASSERTF(pinned == 1,
		"llapi_pool_is_pinned_file expected 1 after pin_fid, got %d (%s)",
		pinned, pinned < 0 ? strerror(-pinned) : "no error");

	rc = llapi_pool_unpin_fid(lustre_dir, &fid, pool_name);
	ASSERTF(rc == 0, "llapi_pool_unpin_fid failed: %s", strerror(errno));

	pinned = llapi_pool_is_pinned_fid(lustre_dir, &fid, pool_name);
	ASSERTF(pinned == 0,
		"llapi_pool_is_pinned_fid expected 0 after unpin_fid, got %d (%s)",
		pinned, pinned < 0 ? strerror(-pinned) : "no error");

	pinned = llapi_pool_is_pinned_file(path, pool_name);
	ASSERTF(pinned == 0,
		"llapi_pool_is_pinned_file expected 0 after unpin_fid, got %d (%s)",
		pinned, pinned < 0 ? strerror(-pinned) : "no error");
}

static struct test_tbl_entry test_tbl[] = {
	TEST_REGISTER(0),
	TEST_REGISTER(1),
	TEST_REGISTER(2),
	TEST_REGISTER(3),
	TEST_REGISTER(4),
	TEST_REGISTER_END
};

static void process_args(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "d:s:t:")) != -1) {
		switch (c) {
		case 'd':
			if (snprintf(lustre_dir, sizeof(lustre_dir), "%s",
				     optarg) >= sizeof(lustre_dir))
				DIE("Error: test directory name too long\n");
			break;
		case 's':
			set_tests_to_skip(optarg, test_tbl);
			break;
		case 't':
			set_tests_to_run(optarg, test_tbl);
			break;
		case '?':
		default:
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
