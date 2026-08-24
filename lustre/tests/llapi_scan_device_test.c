// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, The Lustre Collective.
 */

/*
 * llapi_scan_device() against a real target, which need not be unmounted: a
 * scan in service skips what it cannot trust and counts it, so the counts
 * are part of what is checked.
 *
 * It does have to be quiescent, though, which is a weaker thing than
 * unmounted.  test1 scans four times and asserts one object count and one
 * FID digest across all of them, so anything creating or unlinking on the
 * target while it runs will fail it -- correctly, but for a reason that is
 * not the scanner's.  conf-sanity 300 runs this after stopall and so never
 * meets it.
 *
 * Author: Hiroshi Nishida <hnishida@thelustrecollective.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lustre/lustreapi.h>

#include "llapi_test_utils.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) ((sizeof(a)) / (sizeof((a)[0])))
#endif

static char *device;

/* Fields an object carries by itself, before an xattr has been read. */
#define SCAN_TIER0_MASK	(LLAPI_SCAN_INO | LLAPI_SCAN_MODE | LLAPI_SCAN_TYPE | \
			 LLAPI_SCAN_NLINK | LLAPI_SCAN_UID | LLAPI_SCAN_GID | \
			 LLAPI_SCAN_ATIME | LLAPI_SCAN_MTIME |		      \
			 LLAPI_SCAN_CTIME | LLAPI_SCAN_BTIME |		      \
			 LLAPI_SCAN_ATTRS | LLAPI_SCAN_PROJID |		      \
			 LLAPI_SCAN_MDT_INDEX)

struct scan_result {
	pthread_mutex_t	 res_lock;
	unsigned int	 res_count;
	unsigned int	 res_no_fid;
	unsigned int	 res_no_class;
	unsigned int	 res_bad_size;
	unsigned int	 res_mdt_index;	/* records with LLAPI_SCAN_MDT_INDEX */
	unsigned int	 res_stop_after;	/* 0: never stop */
	/* union of every lfsr_valid seen */
	__u64		 res_seen_valid;
	__u64		 res_fid_sum;	/* order-independent object digest */
};

static void result_init(struct scan_result *res)
{
	memset(res, 0, sizeof(*res));
	pthread_mutex_init(&res->res_lock, NULL);
}

/* Everything the record claims to have answered for, both masks at once. */
static __u64 scan_rec_valid(const struct llapi_scan_rec *rec)
{
	return rec->lfsr_valid | rec->lfsr_stx.stx_mask;
}

static int count_cb(const struct llapi_scan_rec *rec, void *data)
{
	struct scan_result *res = data;
	unsigned int n;

	pthread_mutex_lock(&res->res_lock);
	n = ++res->res_count;
	res->res_seen_valid |= scan_rec_valid(rec);
	res->res_fid_sum += rec->lfsr_fid.f_seq + rec->lfsr_fid.f_oid +
			    rec->lfsr_ino;
	if (rec->lfsr_size != sizeof(*rec))
		res->res_bad_size++;
	if (!(rec->lfsr_valid & LLAPI_SCAN_FID))
		res->res_no_fid++;
	if (!(rec->lfsr_valid & LLAPI_SCAN_CLASS))
		res->res_no_class++;
	if (rec->lfsr_valid & LLAPI_SCAN_MDT_INDEX)
		res->res_mdt_index++;
	pthread_mutex_unlock(&res->res_lock);

	if (res->res_stop_after != 0 && n >= res->res_stop_after)
		return 42;	/* must come back out of the scan */
	return 0;
}

#define T0_DESC "llapi_scan_device delivers records off the target"
static void test0(void)
{
	struct llapi_scan_stats stats = { .ss_size = sizeof(stats) };
	struct llapi_scan_param sp = { .lfsp_size = sizeof(sp) };
	__u64 classified = 0;
	struct scan_result res;
	unsigned int i;
	int rc;

	result_init(&res);
	sp.lfsp_stats = &stats;

	rc = llapi_scan_device(device, &sp, count_cb, &res);
	ASSERTF(rc == 0, "llapi_scan_device(%s) failed: %s",
		device, strerror(-rc));
	ASSERTF(res.res_count > 0, "%s delivered no objects at all", device);
	ASSERTF(res.res_bad_size == 0,
		"%u records did not carry sizeof(struct llapi_scan_rec)",
		res.res_bad_size);
	ASSERTF(res.res_no_class == 0, "%u records arrived unclassified",
		res.res_no_class);
	/* an object with no LMA is possible; every object having none is not */
	ASSERTF(res.res_no_fid < res.res_count,
		"not one of %u records carried a FID", res.res_count);
	ASSERTF(res.res_seen_valid & LLAPI_SCAN_INO,
		"no record reported the object id it came from");

	ASSERTF(stats.ss_emitted == res.res_count,
		"stats say %llu records, the consumer saw %u",
		(unsigned long long)stats.ss_emitted, res.res_count);
	ASSERTF(stats.ss_seen >= stats.ss_emitted,
		"%llu objects emitted out of %llu seen",
		(unsigned long long)stats.ss_emitted,
		(unsigned long long)stats.ss_seen);

	/*
	 * Every object is accounted for exactly once: an object the filter
	 * rejected, one that was skipped, and one that reached the classifier
	 * are the three ends of a scan, and their sum is what was seen.  A
	 * counter incremented on both sides of the pre-filter passes the
	 * inequality above and fails here.
	 */
	for (i = 0; i < LLAPI_SCAN_CLS_MAX; i++)
		classified += stats.ss_class[i];
	ASSERTF(stats.ss_seen ==
		stats.ss_filtered + stats.ss_skipped + classified,
		"%llu seen, but %llu filtered + %llu skipped + %llu classified",
		(unsigned long long)stats.ss_seen,
		(unsigned long long)stats.ss_filtered,
		(unsigned long long)stats.ss_skipped,
		(unsigned long long)classified);
}

#define T1_DESC "llapi_scan_device is the same answer at any thread count"
static void test1(void)
{
	const __u8 threads[] = { 1, 2, 4, 8 };
	unsigned int count = 0;
	__u64 sum = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(threads); i++) {
		struct llapi_scan_param sp = {
			.lfsp_size = sizeof(sp),
			.lfsp_thread_count = threads[i],
		};
		struct scan_result res;
		int rc;

		result_init(&res);
		rc = llapi_scan_device(device, &sp, count_cb, &res);
		ASSERTF(rc == 0, "scan with %u threads failed: %s",
			threads[i], strerror(-rc));

		if (i == 0) {
			count = res.res_count;
			sum = res.res_fid_sum;
			continue;
		}
		/*
		 * Workers must partition the objects, never share or drop
		 * one.  It only means something on a target big enough for
		 * more than one unit of work; any real MDT is past that.
		 */
		ASSERTF(res.res_count == count && res.res_fid_sum == sum,
			"%u threads: %u objects (%llu); 1 thread: %u (%llu)",
			threads[i], res.res_count,
			(unsigned long long)res.res_fid_sum, count,
			(unsigned long long)sum);
	}
}

#define T2_DESC "lfsp_want holds back what the consumer did not ask for"
static void test2(void)
{
	struct llapi_scan_param sp = {
		.lfsp_size = sizeof(sp),
		.lfsp_want = LLAPI_SCAN_FID | LLAPI_SCAN_MODE,
	};
	__u64 mdt_only = LLAPI_SCAN_MDT_INDEX | LLAPI_SCAN_LINKEA |
			 LLAPI_SCAN_PARENT;
	struct scan_result res;
	__u64 got = 0;
	int rc;

	result_init(&res);
	rc = llapi_scan_device(device, &sp, count_cb, &res);
	ASSERTF(rc == 0, "restricted scan failed: %s", strerror(-rc));

	/* the xattrs nothing asked for must not have been read */
	ASSERTF(!(res.res_seen_valid & (LLAPI_SCAN_LAYOUT | LLAPI_SCAN_LMV |
				       LLAPI_SCAN_LINKEA | LLAPI_SCAN_PARENT)),
		"a scan that asked for none of them reported 0x%llx",
		(unsigned long long)res.res_seen_valid);
	/*
	 * And no size: on an MDT, whether an object's own size is the file's
	 * rests on a layout this scan did not read.
	 */
	ASSERTF(!(res.res_seen_valid & (LLAPI_SCAN_SIZE | LLAPI_SCAN_BLOCKS |
				       LLAPI_SCAN_LAZY_SIZE |
				       LLAPI_SCAN_LAZY_BLOCKS)),
		"a scan that did not ask for a size reported one anyway");

	/*
	 * lfsp_got is what the scan will answer for.  A layout is an MDT's,
	 * and so are the MDT index, the linkea and the parent it names;
	 * where the target has an index every record carries it.
	 */
	result_init(&res);
	sp.lfsp_want = LLAPI_SCAN_FID | LLAPI_SCAN_LAYOUT | mdt_only;
	sp.lfsp_got = &got;
	rc = llapi_scan_device(device, &sp, count_cb, &res);
	ASSERTF(rc == 0, "lfsp_got scan failed: %s", strerror(-rc));
	if (!(got & LLAPI_SCAN_LAYOUT))
		ASSERTF(!(got & mdt_only),
			"an OST scan promised MDT fields 0x%llx",
			(unsigned long long)(got & mdt_only));
	if (got & LLAPI_SCAN_MDT_INDEX)
		ASSERTF(res.res_mdt_index == res.res_count,
			"lfsp_got has the MDT index, %u of %u records carry it",
			res.res_mdt_index, res.res_count);
}

/* the pre-filter runs before any xattr is read, so it must see no more
 * than what the object carries itself
 */
static int tier0_filter_cb(const struct llapi_scan_rec *rec, void *data)
{
	struct scan_result *res = data;

	if (scan_rec_valid(rec) & ~(__u64)SCAN_TIER0_MASK) {
		pthread_mutex_lock(&res->res_lock);
		res->res_no_class++;	/* reused: "saw more than it should" */
		pthread_mutex_unlock(&res->res_lock);
		return -EIO;
	}
	return 1;			/* reject everything */
}

#define T3_DESC "lfsp_filter rejects an object before its xattrs are read"
static void test3(void)
{
	struct llapi_scan_stats stats = { .ss_size = sizeof(stats) };
	struct llapi_scan_param sp = {
		.lfsp_size = sizeof(sp),
		.lfsp_filter = tier0_filter_cb,
	};
	struct scan_result res;
	int rc;

	result_init(&res);
	sp.lfsp_stats = &stats;

	rc = llapi_scan_device(device, &sp, count_cb, &res);
	ASSERTF(rc == 0, "filtered scan failed: %s", strerror(-rc));
	ASSERTF(res.res_no_class == 0,
		"the pre-filter saw fields no xattr had been read for");
	ASSERTF(res.res_count == 0,
		"a filter that rejected everything still delivered %u records",
		res.res_count);
	ASSERTF(stats.ss_filtered > 0,
		"nothing was counted as filtered, out of %llu seen",
		(unsigned long long)stats.ss_seen);
}

#define T4_DESC "a consumer can stop the scan and hear its own value back"
static void test4(void)
{
	const __u8 threads[] = { 1, 4 };
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(threads); i++) {
		struct llapi_scan_stats stats = { .ss_size = sizeof(stats) };
		struct llapi_scan_param sp = {
			.lfsp_size = sizeof(sp),
			.lfsp_thread_count = threads[i],
			.lfsp_stats = &stats,
		};
		struct scan_result res;
		int rc;

		result_init(&res);
		res.res_stop_after = 1;

		rc = llapi_scan_device(device, &sp, count_cb, &res);
		ASSERTF(rc == 42,
			"scan with %u threads returned %d, not its own 42",
			threads[i], rc);
		/* the record that stopped the scan was handed over too */
		ASSERTF(stats.ss_emitted == res.res_count,
			"%u threads: ss_emitted %llu, the callback saw %u",
			threads[i], (unsigned long long)stats.ss_emitted,
			res.res_count);
	}
}

#define T5_DESC "the objects a namespace never shows are held back by default"
static void test5(void)
{
	struct llapi_scan_param sp = { .lfsp_size = sizeof(sp) };
	struct scan_result all;
	struct scan_result visible;
	int rc;

	result_init(&visible);
	rc = llapi_scan_device(device, &sp, count_cb, &visible);
	ASSERTF(rc == 0, "default scan failed: %s", strerror(-rc));

	result_init(&all);
	sp.lfsp_flags = LLAPI_SCAN_F_INTERNAL;
	rc = llapi_scan_device(device, &sp, count_cb, &all);
	ASSERTF(rc == 0, "scan with LLAPI_SCAN_F_INTERNAL failed: %s",
		strerror(-rc));

	ASSERTF(all.res_count >= visible.res_count,
		"everything gave %u objects, fewer than the %u visible",
		all.res_count, visible.res_count);
	/* a Lustre target always has objects of its own */
	ASSERTF(all.res_count > visible.res_count,
		"a target with %u visible objects reported not one of its own",
		visible.res_count);
}

#define T6_DESC "bad arguments are refused, not crashed on"
static void test6(void)
{
	struct llapi_scan_param sp = { .lfsp_size = sizeof(sp) };
	/* what a caller built against a later definition of the struct
	 * passes: our fields, then bytes we know nothing about
	 */
	union {
		struct llapi_scan_param sp;
		unsigned char buf[sizeof(struct llapi_scan_param) + 8];
	} big;
	struct llapi_scan_stats stats = { 0 };
	struct scan_result res;
	unsigned int count;
	int rc;

	/* all of it: an initialiser need not zero buf's tail */
	memset(&big, 0, sizeof(big));
	big.sp.lfsp_size = sizeof(big);
	result_init(&res);

	rc = llapi_scan_device(NULL, &sp, count_cb, &res);
	ASSERTF(rc == -EINVAL, "NULL device returned %d, expected -EINVAL", rc);

	rc = llapi_scan_device(device, &sp, NULL, &res);
	ASSERTF(rc == -EINVAL, "NULL callback returned %d, expected -EINVAL",
		rc);

	/* what our own size delivers: a target may hold no objects at all */
	result_init(&res);
	rc = llapi_scan_device(device, &sp, count_cb, &res);
	ASSERTF(rc == 0, "llapi_scan_device(%s) failed: %s", device,
		strerror(-rc));
	count = res.res_count;

	/*
	 * A caller built against a longer struct than this library's: taken
	 * while the bytes past the end of our definition are zero, refused
	 * once one of them is set.  The buffer really is that long, because
	 * the library reads it.
	 */
	result_init(&res);
	rc = llapi_scan_device(device, &big.sp, count_cb, &res);
	ASSERTF(rc == 0, "a longer lfsp_size with a zero tail returned %d", rc);
	ASSERTF(res.res_count == count,
		"a longer lfsp_size delivered %u records, ours %u",
		res.res_count, count);

	big.buf[sizeof(struct llapi_scan_param) + 3] = 1;
	rc = llapi_scan_device(device, &big.sp, count_cb, &res);
	ASSERTF(rc == -EINVAL,
		"a longer lfsp_size with a field set returned %d, expected -EINVAL",
		rc);
	result_init(&res);

	/*
	 * A stats buffer too short to hold a counter is refused rather than
	 * filled with nothing, which a caller cannot tell from a scan that
	 * saw nothing.
	 */
	sp.lfsp_stats = &stats;
	rc = llapi_scan_device(device, &sp, count_cb, &res);
	ASSERTF(rc == -EINVAL, "ss_size 0 returned %d, expected -EINVAL", rc);
	sp.lfsp_stats = NULL;

	/* the library says so on its own; the test knows already */
	llapi_msg_set_level(LLAPI_MSG_OFF);
	rc = llapi_scan_device("/dev/does-not-exist", &sp, count_cb, &res);
	llapi_msg_set_level(LLAPI_MSG_ERROR);
	ASSERTF(rc < 0, "a missing device returned %d, expected an error", rc);
	ASSERTF(res.res_count == 0, "a missing device delivered %u records",
		res.res_count);
}

#define T7_DESC "llapi_find_device() refuses what a scan cannot answer"
static int find_device_quiet(struct find_param *param,
			     const struct llapi_scan_param *sp)
{
	int saved = dup(STDOUT_FILENO);
	int null = open("/dev/null", O_WRONLY);
	int rc;

	ASSERTF(saved >= 0 && null >= 0, "cannot redirect stdout: %s",
		strerror(errno));
	fflush(stdout);
	dup2(null, STDOUT_FILENO);
	rc = llapi_find_device(device, param, sp);
	fflush(stdout);
	dup2(saved, STDOUT_FILENO);
	close(saved);
	close(null);

	return rc;
}

static void test7(void)
{
	struct llapi_scan_stats stats = { .ss_size = sizeof(stats) };
	struct llapi_scan_param sp = { .lfsp_size = sizeof(sp) };
	struct find_param *param;
	__u64 got = 0x5a5a;
	int dummy;
	int rc;

	param = llapi_find_param_alloc();
	ASSERTF(param, "llapi_find_param_alloc() failed");

	/* the refusals lfs makes before calling: the library's own copy */
	llapi_msg_set_level(LLAPI_MSG_OFF);
	param->fp_xattr_match_info = (void *)&dummy;
	rc = find_device_quiet(param, &sp);
	param->fp_xattr_match_info = NULL;
	ASSERTF(rc == -ENOTSUP, "--xattr returned %d, expected -ENOTSUP", rc);

	param->fp_format_printf_str = "%p\n";
	rc = find_device_quiet(param, &sp);
	param->fp_format_printf_str = NULL;
	ASSERTF(rc == -ENOTSUP, "-printf %%p returned %d, expected -ENOTSUP",
		rc);

	param->fp_max_depth = 2;
	rc = find_device_quiet(param, &sp);
	param->fp_max_depth = 0;
	ASSERTF(rc == -ENOTSUP, "maxdepth 2 returned %d, expected -ENOTSUP",
		rc);

	param->fp_thread_count = 2;
	rc = find_device_quiet(param, &sp);
	param->fp_thread_count = 0;
	ASSERTF(rc == -ENOTSUP, "2 threads returned %d, expected -ENOTSUP",
		rc);

	stats.ss_size = 8;
	sp.lfsp_stats = &stats;
	rc = find_device_quiet(param, &sp);
	ASSERTF(rc == -EINVAL, "ss_size 8 returned %d, expected -EINVAL", rc);
	llapi_msg_set_level(LLAPI_MSG_ERROR);

	/* fp_max_depth 0, as allocated, means no limit; stats come back */
	stats.ss_size = sizeof(stats);
	sp.lfsp_got = &got;
	rc = find_device_quiet(param, &sp);
	ASSERTF(rc == 0, "llapi_find_device(%s) failed: %s", device,
		strerror(-rc));
	ASSERTF(stats.ss_seen > 0 && stats.ss_emitted > 0,
		"stats not filled: seen %llu, emitted %llu",
		(unsigned long long)stats.ss_seen,
		(unsigned long long)stats.ss_emitted);
	ASSERTF(got == 0x5a5a, "lfsp_got changed to %#llx",
		(unsigned long long)got);

	llapi_find_param_free(param);
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
	TEST_REGISTER_END
};

static void usage(char *prog)
{
	fprintf(stderr,
		"Usage: %s [-e <test>] [-o <test>] -d <device>\n"
		"       -d  the target to scan, read-only\n"
		"       -e  tests to skip\n"
		"       -o  tests to run\n",
		prog);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "d:e:o:")) != -1) {
		switch (c) {
		case 'd':
			device = optarg;
			break;
		case 'e':
			set_tests_to_skip(optarg, test_tbl);
			break;
		case 'o':
			set_tests_to_run(optarg, test_tbl);
			break;
		default:
			usage(argv[0]);
		}
	}

	if (!device)
		usage(argv[0]);

	/*
	 * As run_tests() does for the mountpoint suites.  This one calls
	 * run_test_tbl() directly -- its subject is a device, not a Lustre
	 * directory -- so without this the scans run at liblustreapi's
	 * default of LLAPI_MSG_MAX where its siblings run quiet, and test6,
	 * which turns messages off and puts them back, restores a level
	 * nothing had set.
	 */
	llapi_msg_set_level(LLAPI_MSG_ERROR);

	return run_test_tbl(test_tbl);
}
