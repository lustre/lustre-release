// SPDX-License-Identifier: GPL-2.0

/*
 * Tests for llapi_scan_namespace(), the client-side namespace scanner.
 *
 * These exercise the parts of its contract that only a real filesystem
 * can settle: that every object is delivered exactly once, that the
 * validity mask says what the scanner could answer for rather than
 * leaving a consumer to guess at zeroes, that the demand mask and the
 * pre-filter keep an object's attributes unfetched, that a consumer can
 * stop the scan and hear its own value back, and that none of it depends
 * on how many scan threads are running.
 */

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <fnmatch.h>
#include <getopt.h>
#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <lustre/lustreapi.h>

#include "llapi_test_utils.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) ((sizeof(a)) / (sizeof((a)[0])))
#endif

/* what lustreapi.h promises a consumer, checked from a consumer */
static_assert(offsetof(struct llapi_scan_rec, lfsr_stx) == 0,
	      "a record must cast to its statx");

static char lustre_dir[PATH_MAX - 5];
/* where the POSIX case builds its tree; -p, or P_tmpdir */
static char posix_dir[PATH_MAX / 2];

static void usage(char *prog)
{
	printf("Usage: %s -d LUSTRE_DIR [-p POSIX_DIR] [-s SKIP[,SKIP...]] [-t ONLY[,ONLY...]]\n",
	       prog);
	printf("  -p  a directory on a filesystem that is NOT Lustre, for the\n"
	       "      POSIX case; defaults to %s\n", P_tmpdir);
	exit(0);
}

/* The tree every test scans: 2 directories and 3 files below testdir. */
#define TREE_DIRS	3	/* testdir, testdir/sub, testdir/sub/deep */
#define TREE_FILES	3
#define TREE_OBJECTS	(TREE_DIRS + TREE_FILES)

/* bounded well below PATH_MAX so a subpath cannot truncate */
static char testdir[PATH_MAX / 2];

static void build_path(char *buf, size_t bufsize, const char *name)
{
	int rc;

	rc = snprintf(buf, bufsize, "%s/%s", lustre_dir, name);
	ASSERTF(rc > 0 && (size_t)rc < bufsize, "invalid path for '%s'", name);
}

static void create_file(const char *dir, const char *name)
{
	char path[PATH_MAX];
	int fd;
	int rc;

	rc = snprintf(path, sizeof(path), "%s/%s", dir, name);
	ASSERTF(rc > 0 && (size_t)rc < sizeof(path), "path too long: %s/%s",
		dir, name);
	fd = creat(path, 0600);
	ASSERTF(fd >= 0, "creat(%s) failed: %s", path, strerror(errno));
	close(fd);
}

static int unlink_cb(const char *path, const struct stat *sb, int type,
		     struct FTW *ftw)
{
	int rc = remove(path);

	ASSERTF(rc == 0 || errno == ENOENT, "cannot remove %s: %s", path,
		strerror(errno));
	return 0;
}

static void make_tree(void)
{
	char path[PATH_MAX];
	int rc;

	build_path(testdir, sizeof(testdir), "llapi_scan_test");

	rc = nftw(testdir, unlink_cb, 8, FTW_DEPTH | FTW_PHYS);
	ASSERTF(rc == 0 || errno == ENOENT, "cannot clean %s: %s", testdir,
		strerror(errno));

	rc = mkdir(testdir, 0700);
	ASSERTF(rc == 0, "mkdir(%s) failed: %s", testdir, strerror(errno));

	rc = snprintf(path, sizeof(path), "%s/sub", testdir);
	ASSERTF(rc > 0 && (size_t)rc < sizeof(path), "path too long");
	rc = mkdir(path, 0700);
	ASSERTF(rc == 0, "mkdir(%s) failed: %s", path, strerror(errno));

	create_file(testdir, "one.txt");
	create_file(testdir, "two.dat");
	create_file(path, "three.txt");

	rc = snprintf(path, sizeof(path), "%s/sub/deep", testdir);
	ASSERTF(rc > 0 && (size_t)rc < sizeof(path), "path too long");
	rc = mkdir(path, 0700);
	ASSERTF(rc == 0, "mkdir(%s) failed: %s", path, strerror(errno));
}

/* What a test collects from the records it is given. */
struct scan_result {
	pthread_mutex_t	 res_lock;
	unsigned int	 res_count;
	unsigned int	 res_dirs;
	unsigned int	 res_files;
	unsigned int	 res_no_fid;	/* records without LLAPI_SCAN_FID */
	unsigned int	 res_gathered;	/* records with anything but TYPE */
	unsigned int	 res_stop_after;	/* 0: never stop */
	/* union of every lfsr_valid seen */
	__u64		 res_seen_valid;
	int		 res_bad_size;	/* records whose lfsr_size was wrong */
	unsigned int	 res_layouts;	/* records carrying LLAPI_SCAN_LAYOUT */
	unsigned int	 res_striped;	/* of those, ones that decoded */
	/* lfsr_lmm that would not decode */
	int		 res_bad_layout;
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
	/*
	 * Both masks, in the one vocabulary lfsp_want is written in: the
	 * statx fields report through lfsr_stx.stx_mask and the rest through
	 * lfsr_valid, and the bits are the same bits.
	 */
	res->res_seen_valid |= scan_rec_valid(rec);
	if (rec->lfsr_size != sizeof(*rec))
		res->res_bad_size++;
	if (!(rec->lfsr_valid & LLAPI_SCAN_FID))
		res->res_no_fid++;
	if (scan_rec_valid(rec) & ~LLAPI_SCAN_TYPE)
		res->res_gathered++;
	if (rec->lfsr_stx.stx_mask & STATX_MODE) {
		if (S_ISDIR(rec->lfsr_stx.stx_mode))
			res->res_dirs++;
		else if (S_ISREG(rec->lfsr_stx.stx_mode))
			res->res_files++;
	}
	pthread_mutex_unlock(&res->res_lock);

	if (res->res_stop_after != 0 && n >= res->res_stop_after)
		return 42;	/* must come back out of the scan */
	return 0;
}

#define T0_DESC "llapi_scan_namespace delivers every object once"
static void test0(void)
{
	struct llapi_scan_param sp = { .lfsp_size = sizeof(sp) };
	struct scan_result res;
	int rc;

	make_tree();
	result_init(&res);

	rc = llapi_scan_namespace(testdir, &sp, count_cb, &res);
	ASSERTF(rc == 0, "llapi_scan_namespace failed: %s", strerror(-rc));
	ASSERTF(res.res_count == TREE_OBJECTS,
		"scanned %u objects, expected %d", res.res_count, TREE_OBJECTS);
	ASSERTF(res.res_dirs == TREE_DIRS && res.res_files == TREE_FILES,
		"saw %u dirs and %u files, expected %d and %d",
		res.res_dirs, res.res_files, TREE_DIRS, TREE_FILES);
	ASSERTF(res.res_bad_size == 0,
		"%u records did not carry sizeof(struct llapi_scan_rec)",
		res.res_bad_size);
	ASSERTF(res.res_no_fid == 0, "%u records arrived without a FID",
		res.res_no_fid);

	/* the mask has to be a real answer, not a constant */
	ASSERTF(res.res_seen_valid & LLAPI_SCAN_MODE,
		"no record reported a mode");
	ASSERTF(res.res_seen_valid & LLAPI_SCAN_UID,
		"no record reported a uid");
}

#define T1_DESC "llapi_scan_namespace is the same answer at any thread count"
static void test1(void)
{
	const __u8 threads[] = { 1, 2, 4, 8 };
	unsigned int first = 0;
	unsigned int i;

	make_tree();

	for (i = 0; i < ARRAY_SIZE(threads); i++) {
		struct llapi_scan_param sp = {
			.lfsp_size = sizeof(sp),
			.lfsp_thread_count = threads[i],
		};
		struct scan_result res;
		int rc;

		result_init(&res);
		rc = llapi_scan_namespace(testdir, &sp, count_cb, &res);
		ASSERTF(rc == 0, "scan with %u threads failed: %s",
			threads[i], strerror(-rc));
		if (i == 0)
			first = res.res_count;
		ASSERTF(res.res_count == first,
			"scan with %u threads saw %u objects, %u threads saw %u",
			threads[i], res.res_count, threads[0], first);
		ASSERTF(res.res_count == TREE_OBJECTS,
			"scan with %u threads saw %u objects, expected %d",
			threads[i], res.res_count, TREE_OBJECTS);
	}
}

#define T2_DESC "lfsp_max_depth limits the descent"
static void test2(void)
{
	struct llapi_scan_param sp = { .lfsp_size = sizeof(sp) };
	struct scan_result deep;
	struct scan_result shallow;
	int rc;

	make_tree();

	result_init(&shallow);
	sp.lfsp_max_depth = 1;
	rc = llapi_scan_namespace(testdir, &sp, count_cb, &shallow);
	ASSERTF(rc == 0, "depth-1 scan failed: %s", strerror(-rc));

	result_init(&deep);
	sp.lfsp_max_depth = 0;	/* unlimited */
	rc = llapi_scan_namespace(testdir, &sp, count_cb, &deep);
	ASSERTF(rc == 0, "unlimited scan failed: %s", strerror(-rc));

	ASSERTF(shallow.res_count < deep.res_count,
		"depth 1 saw %u objects, unlimited saw %u; expected fewer",
		shallow.res_count, deep.res_count);
	ASSERTF(deep.res_count == TREE_OBJECTS,
		"unlimited scan saw %u objects, expected %d",
		deep.res_count, TREE_OBJECTS);
}

#define T3_DESC "a consumer can stop the scan and hear its own value back"
static void test3(void)
{
	const __u8 threads[] = { 1, 4 };
	unsigned int i;

	make_tree();

	for (i = 0; i < ARRAY_SIZE(threads); i++) {
		struct llapi_scan_param sp = {
			.lfsp_size = sizeof(sp),
			.lfsp_thread_count = threads[i],
		};
		struct scan_result res;
		int rc;

		result_init(&res);
		res.res_stop_after = 1;

		rc = llapi_scan_namespace(testdir, &sp, count_cb, &res);
		ASSERTF(rc == 42,
			"scan with %u threads returned %d, not the callback's 42",
			threads[i], rc);
		/*
		 * The stop is enforced by the scanner, not by the traversal,
		 * which would otherwise note the value and walk on.  Allow
		 * one callback already in flight per thread.
		 */
		ASSERTF(res.res_count <= 1 + threads[i],
			"scan with %u threads delivered %u records after being stopped at 1",
			threads[i], res.res_count);
	}
}

#define T4_DESC "lfsp_want holds back what the consumer did not ask for"
static void test4(void)
{
	struct llapi_scan_param sp = {
		.lfsp_size = sizeof(sp),
		.lfsp_want = LLAPI_SCAN_TYPE,
	};
	struct scan_result res;
	char path[PATH_MAX];
	__u64 both = LLAPI_SCAN_LMV | LLAPI_SCAN_LMV_FOREIGN;
	__u64 got = 0;
	int rc;

	make_tree();
	result_init(&res);

	rc = llapi_scan_namespace(testdir, &sp, count_cb, &res);
	ASSERTF(rc == 0, "TYPE-only scan failed: %s", strerror(-rc));
	ASSERTF(res.res_count == TREE_OBJECTS,
		"TYPE-only scan saw %u objects, expected %d",
		res.res_count, TREE_OBJECTS);
	ASSERTF(res.res_no_fid == res.res_count,
		"%u of %u records carried a FID the consumer never asked for",
		res.res_count - res.res_no_fid, res.res_count);
	ASSERTF((res.res_seen_valid & ~LLAPI_SCAN_TYPE) == 0,
		"a TYPE-only scan reported fields 0x%llx",
		(unsigned long long)(res.res_seen_valid & ~LLAPI_SCAN_TYPE));

	/*
	 * LLAPI_SCAN_LMV_FOREIGN describes lfsr_lmv: asked for alone it has
	 * to fetch the stripe, or no foreign directory can ever carry it.
	 */
	rc = snprintf(path, sizeof(path), "%s/foreign", testdir);
	ASSERTF(rc > 0 && (size_t)rc < sizeof(path), "path too long");
	rc = llapi_dir_create_foreign(path, 0700, LU_FOREIGN_TYPE_POSIX, 0,
				      "llapi_scan_test@lfu");
	ASSERTF(rc == 0, "cannot create foreign %s: %s", path, strerror(-rc));

	result_init(&res);
	sp.lfsp_want = LLAPI_SCAN_TYPE | LLAPI_SCAN_LMV_FOREIGN;
	sp.lfsp_got = &got;
	rc = llapi_scan_namespace(testdir, &sp, count_cb, &res);
	ASSERTF(rmdir(path) == 0, "rmdir(%s) failed: %s", path,
		strerror(errno));
	ASSERTF(rc == 0, "LMV_FOREIGN scan failed: %s", strerror(-rc));
	ASSERTF((got & both) == both,
		"LMV_FOREIGN alone got 0x%llx, expected LMV with it",
		(unsigned long long)got);
	ASSERTF(res.res_seen_valid & LLAPI_SCAN_LMV_FOREIGN,
		"no record carried LLAPI_SCAN_LMV_FOREIGN for %s", path);
}

/* lfsp_filter: runs before any I/O, so it must see nothing but the dirent */
static int name_filter_cb(const struct llapi_scan_rec *rec, void *data)
{
	struct scan_result *res = data;

	if (scan_rec_valid(rec) & ~LLAPI_SCAN_TYPE) {
		pthread_mutex_lock(&res->res_lock);
		res->res_gathered++;
		pthread_mutex_unlock(&res->res_lock);
		return -EIO;
	}
	if (fnmatch("*.txt", rec->lfsr_name, 0) == 0)
		return 0;
	return 1;	/* skip, without gathering */
}

#define T5_DESC "lfsp_filter rejects an object before its attributes are read"
static void test5(void)
{
	struct llapi_scan_param sp = {
		.lfsp_size = sizeof(sp),
		.lfsp_filter = name_filter_cb,
	};
	struct scan_result res;
	int rc;

	make_tree();
	result_init(&res);

	rc = llapi_scan_namespace(testdir, &sp, count_cb, &res);
	ASSERTF(rc == 0, "filtered scan failed: %s", strerror(-rc));
	/* one.txt and sub/three.txt, and nothing else */
	ASSERTF(res.res_count == 2,
		"filtered scan delivered %u objects, expected 2",
		res.res_count);
	/* each delivered record passed the filter, and was gathered after */
	ASSERTF(res.res_gathered == res.res_count,
		"%u of %u delivered records were not gathered",
		res.res_count - res.res_gathered, res.res_count);
	ASSERTF(res.res_no_fid == 0,
		"%u delivered records arrived without a FID", res.res_no_fid);
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
	} big = { .sp = { .lfsp_size = sizeof(big) } };
	struct scan_result res;
	char path[PATH_MAX];
	void *map;
	long pg;
	int rc;

	make_tree();
	result_init(&res);

	rc = llapi_scan_namespace(NULL, &sp, count_cb, &res);
	ASSERTF(rc == -EINVAL, "NULL path returned %d, expected -EINVAL", rc);

	rc = llapi_scan_namespace(testdir, &sp, NULL, &res);
	ASSERTF(rc == -EINVAL, "NULL callback returned %d, expected -EINVAL",
		rc);

	/*
	 * A caller built against a longer struct than this library's: taken
	 * while the bytes past the end of our definition are zero, which is
	 * that caller saying it set no field we could not honour, and
	 * refused once one of them is set.  The buffer really is that long,
	 * because the library reads it.
	 */
	result_init(&res);
	rc = llapi_scan_namespace(testdir, &big.sp, count_cb, &res);
	ASSERTF(rc == 0, "a longer lfsp_size with a zero tail returned %d", rc);
	ASSERTF(res.res_count == TREE_OBJECTS,
		"a longer lfsp_size scanned %u objects, expected %d",
		res.res_count, TREE_OBJECTS);

	big.buf[sizeof(struct llapi_scan_param) + 3] = 1;
	rc = llapi_scan_namespace(testdir, &big.sp, count_cb, &res);
	ASSERTF(rc == -EINVAL,
		"a longer lfsp_size with a field set returned %d, expected -EINVAL",
		rc);

	/*
	 * A size no definition of the struct will reach is refused before a
	 * byte past ours is read: zeros up to a guard page, and a size that
	 * runs into it.
	 */
	pg = sysconf(_SC_PAGESIZE);
	map = mmap(NULL, 2 * pg, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ASSERTF(map != MAP_FAILED, "mmap failed: %s", strerror(errno));
	ASSERTF(mprotect((char *)map + pg, pg, PROT_NONE) == 0,
		"mprotect failed: %s", strerror(errno));
	((struct llapi_scan_param *)map)->lfsp_size = 2 * pg;
	rc = llapi_scan_namespace(testdir, map, count_cb, &res);
	ASSERTF(rc == -EINVAL,
		"an lfsp_size of %ld returned %d, expected -EINVAL",
		2 * pg, rc);
	munmap(map, 2 * pg);

	/* one built against a shorter one must still work, the fields it
	 * did not know about reading as zero
	 */
	result_init(&res);
	sp.lfsp_size = offsetof(struct llapi_scan_param, lfsp_want) +
		     sizeof(sp.lfsp_want);
	rc = llapi_scan_namespace(testdir, &sp, count_cb, &res);
	ASSERTF(rc == 0, "a short lfsp_size returned %d, expected success", rc);
	ASSERTF(res.res_count == TREE_OBJECTS,
		"a short lfsp_size scanned %u objects, expected %d",
		res.res_count, TREE_OBJECTS);
	sp.lfsp_size = sizeof(sp);

	/* the reserved bytes are must-be-zero, for the same reason a flag
	 * this library does not define is refused: neither changes lfsp_size
	 */
	sp.lfsp_padding[3] = 1;
	rc = llapi_scan_namespace(testdir, &sp, count_cb, &res);
	ASSERTF(rc == -EINVAL,
		"a set lfsp_padding returned %d, expected -EINVAL", rc);
	sp.lfsp_padding[3] = 0;

	/* and the third of the same family: a flag this library does not
	 * define, which the man page's ERRORS names beside the other two
	 */
	sp.lfsp_flags = LLAPI_SCAN_F_STOP_ON_ERROR << 1;
	rc = llapi_scan_namespace(testdir, &sp, count_cb, &res);
	ASSERTF(rc == -EINVAL,
		"an undefined lfsp_flags returned %d, expected -EINVAL", rc);
	sp.lfsp_flags = 0;

	/* the scan above delivered records: start the next check from zero */
	result_init(&res);
	rc = snprintf(path, sizeof(path), "%s/does-not-exist", testdir);
	ASSERTF(rc > 0 && (size_t)rc < sizeof(path), "path too long");
	rc = llapi_scan_namespace(path, &sp, count_cb, &res);
	ASSERTF(rc < 0, "a missing path returned %d, expected an error", rc);
	ASSERTF(res.res_count == 0, "a missing path delivered %u records",
		res.res_count);
}

#define T7_DESC "a project id is gathered only when it is asked for"
static void test7(void)
{
	struct llapi_scan_param sp = { .lfsp_size = sizeof(sp) };
	struct scan_result res;
	int rc;

	make_tree();

	/* an open and an ioctl per object, like the MDT index */
	result_init(&res);
	rc = llapi_scan_namespace(testdir, &sp, count_cb, &res);
	ASSERTF(rc == 0, "default scan failed: %s", strerror(-rc));
	ASSERTF(!(res.res_seen_valid & LLAPI_SCAN_PROJID),
		"a scan that asked for nothing in particular gathered a project id");

	result_init(&res);
	sp.lfsp_want = LLAPI_SCAN_MODE | LLAPI_SCAN_PROJID;
	rc = llapi_scan_namespace(testdir, &sp, count_cb, &res);
	ASSERTF(rc == 0, "projid scan failed: %s", strerror(-rc));
	ASSERTF(res.res_count == TREE_OBJECTS,
		"projid scan saw %u objects, expected %d",
		res.res_count, TREE_OBJECTS);
	ASSERTF(res.res_seen_valid & LLAPI_SCAN_PROJID,
		"no record reported a project id the consumer asked for");
}

#define T8_DESC "HSM state is gathered only when it is asked for"
static void test8(void)
{
	struct llapi_scan_param sp = { .lfsp_size = sizeof(sp) };
	struct scan_result res;
	int rc;

	make_tree();

	/* an ioctl per object, so not part of an unqualified scan */
	result_init(&res);
	rc = llapi_scan_namespace(testdir, &sp, count_cb, &res);
	ASSERTF(rc == 0, "default scan failed: %s", strerror(-rc));
	ASSERTF(!(res.res_seen_valid & LLAPI_SCAN_HSM),
		"a scan that asked for nothing in particular gathered HSM state");

	/*
	 * Asked for, it arrives for regular files.  A file with no archive
	 * has state 0, which is an answer: the bit says the scan looked.
	 */
	result_init(&res);
	sp.lfsp_want = LLAPI_SCAN_MODE | LLAPI_SCAN_HSM;
	rc = llapi_scan_namespace(testdir, &sp, count_cb, &res);
	ASSERTF(rc == 0, "HSM scan failed: %s", strerror(-rc));
	ASSERTF(res.res_count == TREE_OBJECTS,
		"HSM scan saw %u objects, expected %d",
		res.res_count, TREE_OBJECTS);
	ASSERTF(res.res_seen_valid & LLAPI_SCAN_HSM,
		"no record reported HSM state the consumer asked for");
}

/*
 * Decode lfsr_lmm the way a consumer is meant to.  The buffer is copied first:
 * the record contract says lfsr_lmm points into scanner-owned memory, and
 * llapi_layout_get_by_xattr() takes a non-const pointer because it may swab
 * in place -- which on the scanner's own buffer would corrupt the walk.
 */
static int layout_cb(const struct llapi_scan_rec *rec, void *data)
{
	struct scan_result *res = data;
	struct llapi_layout *layout;
	uint64_t stripes = 0;
	void *copy;
	int rc;

	pthread_mutex_lock(&res->res_lock);
	res->res_count++;
	res->res_seen_valid |= scan_rec_valid(rec);
	pthread_mutex_unlock(&res->res_lock);

	if (!(rec->lfsr_valid & LLAPI_SCAN_LAYOUT))
		return 0;
	if ((rec->lfsr_stx.stx_mask & STATX_MODE) &&
	    !S_ISREG(rec->lfsr_stx.stx_mode))
		return 0;

	pthread_mutex_lock(&res->res_lock);
	res->res_layouts++;
	pthread_mutex_unlock(&res->res_lock);

	if (rec->lfsr_lmm == NULL ||
	    rec->lfsr_lmmsize < sizeof(*rec->lfsr_lmm)) {
		pthread_mutex_lock(&res->res_lock);
		res->res_bad_layout++;
		pthread_mutex_unlock(&res->res_lock);
		return 0;
	}

	copy = malloc(rec->lfsr_lmmsize);
	if (copy == NULL)
		return -ENOMEM;
	memcpy(copy, rec->lfsr_lmm, rec->lfsr_lmmsize);

	layout = llapi_layout_get_by_xattr(copy, rec->lfsr_lmmsize, 0);
	if (layout == NULL) {
		free(copy);
		pthread_mutex_lock(&res->res_lock);
		res->res_bad_layout++;
		pthread_mutex_unlock(&res->res_lock);
		return 0;
	}

	/*
	 * Only that the count can be read, not what it is: these files are
	 * created empty, and whether that means OST objects, a DoM component
	 * or nothing yet is the filesystem's default layout's business.
	 */
	rc = llapi_layout_stripe_count_get(layout, &stripes);
	llapi_layout_free(layout);
	free(copy);

	pthread_mutex_lock(&res->res_lock);
	if (rc != 0)
		res->res_bad_layout++;
	else
		res->res_striped++;
	pthread_mutex_unlock(&res->res_lock);

	return 0;
}

#define T9_DESC "lfsr_lmm decodes to a layout a consumer can read"
static void test9(void)
{
	struct llapi_scan_param sp = { .lfsp_size = sizeof(sp) };
	struct scan_result res;
	int rc;

	make_tree();

	result_init(&res);
	sp.lfsp_want = LLAPI_SCAN_MODE | LLAPI_SCAN_LAYOUT;
	rc = llapi_scan_namespace(testdir, &sp, layout_cb, &res);
	ASSERTF(rc == 0, "layout scan failed: %s", strerror(-rc));
	ASSERTF(res.res_count == TREE_OBJECTS,
		"layout scan saw %u objects, expected %d",
		res.res_count, TREE_OBJECTS);
	ASSERTF(res.res_seen_valid & LLAPI_SCAN_LAYOUT,
		"no record reported a layout the consumer asked for");
	ASSERTF(res.res_layouts == TREE_FILES,
		"%u regular files carried a layout, expected %d",
		res.res_layouts, TREE_FILES);
	ASSERTF(res.res_bad_layout == 0,
		"%d records had an lfsr_lmm that would not decode",
		res.res_bad_layout);
	ASSERTF(res.res_striped == TREE_FILES,
		"%u layouts yielded a readable stripe count, expected %d",
		res.res_striped, TREE_FILES);
}

#define T10_DESC "a record off Lustre carries what a stat answers, and no FID"
static void test10(void)
{
	struct llapi_scan_param sp = { .lfsp_size = sizeof(sp) };
	char root[PATH_MAX / 2];
	char mnt[PATH_MAX];
	char fsname[PATH_MAX];
	char sub[PATH_MAX];
	struct scan_result res;
	int rc;

	/*
	 * The POSIX Input Scanner is this scanner with a different attribute
	 * source, so what it owes a consumer is not to invent the fields that
	 * source cannot answer.  A stat has no FID, and the buffer the ioctl
	 * would have filled holds the name the caller wrote there for it --
	 * which reads as a plausible IGIF, so nothing downstream catches it.
	 */
	rc = snprintf(root, sizeof(root), "%s/llapi_scan_posix.%u",
		      posix_dir[0] != '\0' ? posix_dir : P_tmpdir,
		      (unsigned int)getpid());
	ASSERTF(rc > 0 && (size_t)rc < sizeof(root), "path too long");

	/*
	 * On Lustre the FID and the layout would be present for a good
	 * reason, so the two assertions that matter would fail -- the other
	 * three bits are clear there too, MDT_INDEX, PROJID and HSM being
	 * outside the default demand mask and these mkdir()s unstriped.
	 * Skipped rather than failed: the tree is only a source of
	 * non-Lustre objects, and a site whose TMP sits on Lustre has not
	 * broken anything.
	 */
	if (llapi_search_mounts(posix_dir[0] != '\0' ? posix_dir : P_tmpdir,
				0, mnt, fsname) == 0) {
		printf("%s is Lustre: skipping, give -p DIR on a filesystem that is not\n",
		       posix_dir[0] != '\0' ? posix_dir : P_tmpdir);
		return;
	}

	rc = nftw(root, unlink_cb, 8, FTW_DEPTH | FTW_PHYS);
	ASSERTF(rc == 0 || errno == ENOENT, "cannot clean %s: %s", root,
		strerror(errno));
	rc = mkdir(root, 0700);
	ASSERTF(rc == 0, "mkdir(%s) failed: %s", root, strerror(errno));

	rc = snprintf(sub, sizeof(sub), "%s/sub", root);
	ASSERTF(rc > 0 && (size_t)rc < sizeof(sub), "path too long");
	rc = mkdir(sub, 0700);
	ASSERTF(rc == 0, "mkdir(%s) failed: %s", sub, strerror(errno));
	create_file(root, "one.txt");
	create_file(sub, "two.dat");

	result_init(&res);
	rc = llapi_scan_namespace(root, &sp, count_cb, &res);
	ASSERTF(rc == 0, "llapi_scan_namespace(%s) failed: %s", root,
		strerror(-rc));
	ASSERTF(res.res_count == 4, "scanned %u objects, expected 4",
		res.res_count);
	ASSERTF(res.res_dirs == 2 && res.res_files == 2,
		"saw %u dirs and %u files, expected 2 and 2",
		res.res_dirs, res.res_files);

	/* the whole point of the case */
	ASSERTF(!(res.res_seen_valid & LLAPI_SCAN_FID),
		"a record off Lustre carried a FID: valid=%#llx",
		(unsigned long long)res.res_seen_valid);
	ASSERTF(res.res_no_fid == res.res_count,
		"%u of %u records claimed a FID",
		res.res_count - res.res_no_fid, res.res_count);

	/* what a stat does answer, so the absence above is not silence */
	ASSERTF(res.res_seen_valid & LLAPI_SCAN_MODE, "no record had a mode");
	ASSERTF(res.res_seen_valid & LLAPI_SCAN_UID, "no record had a uid");
	ASSERTF(res.res_seen_valid & LLAPI_SCAN_SIZE, "no record had a size");
	ASSERTF(res.res_seen_valid & LLAPI_SCAN_MTIME,
		"no record had an mtime");

	/* and what only Lustre has */
	ASSERTF(!(res.res_seen_valid & (LLAPI_SCAN_LAYOUT | LLAPI_SCAN_LMV |
				       LLAPI_SCAN_MDT_INDEX | LLAPI_SCAN_HSM)),
		"a record off Lustre carried a Lustre-only field: valid=%#llx",
		(unsigned long long)res.res_seen_valid);

	rc = nftw(root, unlink_cb, 8, FTW_DEPTH | FTW_PHYS);
	ASSERTF(rc == 0, "cannot clean %s: %s", root, strerror(errno));
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
	TEST_REGISTER_END
};

static void process_args(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "d:p:s:t:")) != -1) {
		switch (c) {
		case 'd':
			if (snprintf(lustre_dir, sizeof(lustre_dir), "%s",
				     optarg) >= sizeof(lustre_dir))
				DIE("Error: test directory name too long\n");
			break;
		case 'p':
			if (snprintf(posix_dir, sizeof(posix_dir), "%s",
				     optarg) >= sizeof(posix_dir))
				DIE("Error: POSIX directory name too long\n");
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
