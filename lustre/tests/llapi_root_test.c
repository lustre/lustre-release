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
 * The purpose of this test is to check Lustre API root fd cache.
 *
 * The program will exit as soon as a non zero error code is returned.
 */

#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <time.h>
#include <pthread.h>


#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_idl.h>

#define ERROR(fmt, ...)							\
	fprintf(stderr, "%s: %s:%d: %s: " fmt "\n",                     \
		program_invocation_short_name, __FILE__, __LINE__,      \
		__func__, ## __VA_ARGS__)

#define DIE(fmt, ...)                  \
	do {			       \
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
		cleanup();						\
		fprintf(stderr, "Starting test " #testfn " at %lld\n",	\
			(unsigned long long)time(NULL));		\
		testfn();						\
		fprintf(stderr, "Finishing test " #testfn " at %lld\n",	\
		       (unsigned long long)time(NULL));			\
		cleanup();						\
	} while (0)

/* Name of file/directory. Will be set once and will not change. */
static char *mainpath;  /* path to file on mountpoint 1 */
static char *mainpath2; /* path to file on mountpoint 2 */

static char mnt_dir[PATH_MAX];	/* Lustre mountpoint 1 */
static char mnt_dir2[PATH_MAX];	/* Lustre mountpoint 2 */
static int mnt_fd = -1;
static int mnt_fd2 = -1;

/* Cleanup our test directory. */
static void cleanup(void)
{
	int rc;

	rc = remove(mainpath);
	ASSERTF(!rc || errno == ENOENT,
		"Failed to unlink %s: %s", mainpath, strerror(errno));
}

#define TEST1_THR_NBR 20
void *test1_thr(void *arg)
{
	char *fidstr = arg;
	char path[PATH_MAX];
	long long recno = -1;
	int linkno = 0;
	long long rc;

	rc = llapi_fid2path(mnt_dir2, fidstr, path,
			    sizeof(path), &recno, &linkno);

	return (void *) rc;
}

/* Race on root cache at startup */
static void test1(void)
{
	static pthread_t thread[TEST1_THR_NBR];
	int fd, i, iter;
	long long rc;
	struct lu_fid fid;
	char fidstr[FID_LEN + 1];

	fd = creat(mainpath, 00660);
	ASSERTF(fd >= 0, "creat failed for '%s': %s",
		mainpath, strerror(errno));

	rc = llapi_fd2fid(fd, &fid);
	ASSERTF(rc == 0, "llapi_fd2fid failed for '%s': %s",
		mainpath, strerror(-rc));
	close(fd);

	snprintf(fidstr, sizeof(fidstr), DFID_NOBRACE, PFID(&fid));
	for (iter = 0; iter < 100; iter++) {
		/* reset cache on first mountpoint */
		fd = llapi_open_by_fid(mnt_dir, &fid, O_RDONLY);
		ASSERTF(fd >= 0, "llapi_open_by_fid for " DFID_NOBRACE ": %d",
			PFID(&fid), fd);
		close(fd);

		/* start threads with llapi_open_by_fid() */
		for (i = 0; i < TEST1_THR_NBR; i++)
			pthread_create(&thread[i], NULL, &test1_thr, fidstr);

		for (i = 0; i < TEST1_THR_NBR; i++) {
			pthread_join(thread[i], (void **) &rc);
			ASSERTF(rc == 0,
				"llapi_fid2path for " DFID_NOBRACE " (iter: %d, thr:%d): %s",
				PFID(&fid), iter, i, strerror(-rc));
		}
	}
}

static void usage(char *prog)
{
	fprintf(stderr, "Usage: %s [-h]\n", basename(prog));
	fprintf(stderr, "or:    %s FILEPATH1 FILEPATH2\n", basename(prog));
	exit(EXIT_FAILURE);
}

static void process_args(int argc, char *argv[])
{
	/* default mountpoints used */
	if (argc == 1)
		return;

	if (argc > 1 && argv[1][0] == '-')
		usage(argv[0]);

	if (argc <= 2 || argv[1][0] == '\0' || argv[2][0] == '\0')
		usage(argv[0]);

	mainpath = argv[1];
	mainpath2 = argv[2];
}


static int fill_default_paths(void)
{
	static char tmp1[PATH_MAX] = "/mnt/lustre/llapi_root_test.XXXXXX";
	static char tmp2[PATH_MAX] = "/mnt/lustre2/";
	int fd;

	/* default paths needed?*/
	if (mainpath || mainpath2)
		return 0;

	fd = mkstemp(tmp1);
	if (fd < 0) {
		fprintf(stderr, "Failed to creat %s: %s\n",
			tmp1, strerror(errno));
		exit(EXIT_FAILURE);
	}

	close(fd);
	strcat(tmp2, basename(tmp1));

	mainpath = tmp1;
	mainpath2 = tmp2;

	return 0;
}

int main(int argc, char *argv[])
{
	char fsname[8 + 1];
	char fsname2[8 + 1];
	int rc;

	process_args(argc, argv);
	fill_default_paths();
	atexit(cleanup);

	if (strcmp(basename(mainpath), basename(mainpath2)) != 0 ||
		   strcmp(mainpath, mainpath2) == 0) {
		fprintf(stderr, "%s and %s should be the same file on 2 distinct mountpoints\n",
			mainpath, mainpath2);
		return EXIT_FAILURE;
	}

	rc = llapi_search_mounts(mainpath, 0, mnt_dir, fsname);
	if (rc != 0) {
		fprintf(stderr, "Error: %s: not a Lustre filesystem\n",
			mainpath);
		return EXIT_FAILURE;
	}

	rc = llapi_search_mounts(mainpath2, 0, mnt_dir2, fsname2);
	if (rc != 0) {
		fprintf(stderr, "Error: %s: not a Lustre filesystem\n",
			mainpath2);
		return EXIT_FAILURE;
	}

	if (strcmp(fsname, fsname2) != 0) {
		fprintf(stderr, "%s and %s are not on the same filesystem (%s, %s)\n",
			mnt_dir, mnt_dir2, fsname, fsname2);
		return EXIT_FAILURE;
	}

	mnt_fd = open(mnt_dir, O_RDONLY|O_DIRECTORY);
	ASSERTF(mnt_fd >= 0, "cannot open '%s': %s\n", mnt_dir, strerror(errno));

	mnt_fd2 = open(mnt_dir2, O_RDONLY|O_DIRECTORY);
	ASSERTF(mnt_fd2 >= 0, "cannot open '%s': %s\n", mnt_dir2, strerror(errno));

	fprintf(stderr, "Starting: %s %s %s\n\n",
		basename(argv[0]), mainpath, mainpath2);

	/* Play nice with Lustre test scripts. Non-line buffered output
	 * stream under I/O redirection may appear incorrectly.
	 */
	setvbuf(stdout, NULL, _IOLBF, 0);

	PERFORM(test1);

	return EXIT_SUCCESS;
}
