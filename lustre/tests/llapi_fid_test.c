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
 * Copyright 2014 Cray Inc, all rights reserved.
 *
 * Copyright (c) 2016, Intel Corporation.
 *
 * Author: Frank Zago.
 *
 * A few portions are extracted from llapi_layout_test.c
 *
 * The purpose of this test is to test the llapi fid related function
 * (fid2path, path2fid, ...)
 *
 * The program will exit as soon a non zero error code is returned.
 */

#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <time.h>

#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_idl.h>

#define ERROR(fmt, ...)							\
	fprintf(stderr, "%s: %s:%d: %s: " fmt "\n",                     \
		program_invocation_short_name, __FILE__, __LINE__,      \
		__func__, ## __VA_ARGS__);

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
static char mainpath[PATH_MAX];
static const char *maindir = "llapi_fid_test_name_9585766";

static char mnt_dir[PATH_MAX];	/* Lustre mountpoint */
static int mnt_fd = -1;
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

/* Helper - call path2fid, fd2fid and fid2path against an existing
 * file/directory */
static void helper_fid2path(const char *filename, int fd)
{
	struct lu_fid fid;
	struct lu_fid fid2;
	struct lu_fid fid3;
	char fidstr[FID_LEN + 1];
	char path1[PATH_MAX];
	char path2[PATH_MAX];
	char path3[PATH_MAX];
	long long recno1;
	long long recno2;
	int linkno1;
	int linkno2;
	int rc;

	rc = llapi_path2fid(filename, &fid);
	ASSERTF(rc == 0, "llapi_path2fid failed for '%s': %s",
		filename, strerror(-rc));

	/* Without braces */
	snprintf(fidstr, sizeof(fidstr), DFID_NOBRACE, PFID(&fid));
	recno1 = -1;
	linkno1 = 0;
	rc = llapi_fid2path(lustre_dir, fidstr, path1,
			    sizeof(path1), &recno1, &linkno1);
	ASSERTF(rc == 0, "llapi_fid2path failed for fid %s: %s",
		fidstr, strerror(-rc));

	/* Same with braces */
	snprintf(fidstr, sizeof(fidstr), DFID, PFID(&fid));
	recno2 = -1;
	linkno2 = 0;
	rc = llapi_fid2path(lustre_dir, fidstr, path2,
			    sizeof(path2), &recno2, &linkno2);
	ASSERTF(rc == 0, "llapi_fid2path failed for fid %s: %s",
		fidstr, strerror(-rc));

	/* Make sure both calls to llapi_fid2path returned the same
	 * data. */
	ASSERTF(strcmp(path1, path2) == 0, "paths are different: '%s' / '%s'",
		path1, path2);
	ASSERTF(recno1 == recno2, "recnos are different: %lld / %lld",
		recno1, recno2);
	ASSERTF(linkno1 == linkno2, "linknos are different: %d / %d",
		linkno1, linkno2);

	/* Use llapi_fid2path_at() */
	recno2 = -1;
	linkno2 = 0;
	rc = llapi_fid2path_at(mnt_fd, &fid, path2, sizeof(path2),
			       &recno2, &linkno2);
	ASSERTF(rc == 0, "llapi_fid2path failed for fid %s: %s",
		fidstr, strerror(-rc));

	/* Make sure both calls to llapi_fid2path returned the same
	 * data. */
	ASSERTF(strcmp(path1, path2) == 0, "paths are different: '%s' / '%s'",
		path1, path2);
	ASSERTF(recno1 == recno2, "recnos are different: %lld / %lld",
		recno1, recno2);
	ASSERTF(linkno1 == linkno2, "linknos are different: %d / %d",
		linkno1, linkno2);

	/* Try fd2fid and check that the result is still the same. */
	if (fd != -1) {
		rc = llapi_fd2fid(fd, &fid3);
		ASSERTF(rc == 0, "llapi_fd2fid failed for '%s': %s",
			mainpath, strerror(-rc));

		ASSERTF(memcmp(&fid, &fid3, sizeof(fid)) == 0,
			"fids are different");
	}

	/* Pass the result back to fid2path and ensure the fid stays
	 * the same. */
	rc = snprintf(path3, sizeof(path3), "%s/%s", mnt_dir, path1);
	ASSERTF((rc > 0 && rc < sizeof(path3)), "invalid name");
	rc = llapi_path2fid(path3, &fid2);
	ASSERTF(rc == 0, "llapi_path2fid failed for '%s': %s",
		path3, strerror(-rc));
	ASSERTF(memcmp(&fid, &fid2, sizeof(fid)) == 0, "fids are different");
}

/* Test helper_fid2path */
static void test10(void)
{
	int rc;
	int fd;
	struct stat statbuf;

	/* Against Lustre root */
	helper_fid2path(lustre_dir, -1);

	/* Against a regular file */
	fd = creat(mainpath, 0);
	ASSERTF(fd >= 0, "creat failed for '%s': %s",
		mainpath, strerror(errno));
	helper_fid2path(mainpath, fd);
	close(fd);
	rc = unlink(mainpath);
	ASSERTF(rc == 0, "unlink failed for '%s': %s",
		mainpath, strerror(errno));

	/* Against a pipe */
	rc = mkfifo(mainpath, 0);
	ASSERTF(rc == 0, "mkfifo failed for '%s': %s",
		mainpath, strerror(errno));
	helper_fid2path(mainpath, -1);
	rc = unlink(mainpath);
	ASSERTF(rc == 0, "unlink failed for '%s': %s",
		mainpath, strerror(errno));

	/* Against a directory */
	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));
	helper_fid2path(mainpath, -1);
	rc = rmdir(mainpath);
	ASSERTF(rc == 0, "rmdir failed for '%s': %s",
		mainpath, strerror(errno));

	/* Against a char device. Use same as /dev/null in case things
	 * go wrong. */
	rc = stat("/dev/null", &statbuf);
	ASSERTF(rc == 0, "stat failed for /dev/null: %s", strerror(errno));
	rc = mknod(mainpath, S_IFCHR, statbuf.st_rdev);
	ASSERTF(rc == 0, "mknod failed for '%s': %s",
		mainpath, strerror(errno));
	helper_fid2path(mainpath, -1);
	rc = unlink(mainpath);
	ASSERTF(rc == 0, "unlink failed for '%s': %s",
		mainpath, strerror(errno));

	/* Against a block device device. Reuse same dev. */
	rc = mknod(mainpath, S_IFBLK, statbuf.st_rdev);
	ASSERTF(rc == 0, "mknod failed for '%s': %s",
		mainpath, strerror(errno));
	helper_fid2path(mainpath, -1);
	rc = unlink(mainpath);
	ASSERTF(rc == 0, "unlink failed for '%s': %s",
		mainpath, strerror(errno));

	/* Against a socket. */
	rc = mknod(mainpath, S_IFSOCK, (dev_t)0);
	ASSERTF(rc == 0, "mknod failed for '%s': %s",
		mainpath, strerror(errno));
	helper_fid2path(mainpath, -1);
	rc = unlink(mainpath);
	ASSERTF(rc == 0, "unlink failed for '%s': %s",
		mainpath, strerror(errno));
}

/* Test against deleted files. */
static void test11(void)
{
	int rc;
	int fd;
	struct lu_fid fid;
	char fidstr[FID_LEN + 1];
	char path[PATH_MAX];
	long long recno;
	int linkno;

	/* Against a regular file */
	fd = creat(mainpath, 0);
	ASSERTF(fd >= 0, "creat failed for '%s': %s",
		mainpath, strerror(errno));
	close(fd);

	rc = llapi_path2fid(mainpath, &fid);
	ASSERTF(rc == 0, "llapi_path2fid failed for '%s': %s",
		mainpath, strerror(-rc));

	rc = unlink(mainpath);
	ASSERTF(rc == 0, "unlink failed for '%s': %s",
		mainpath, strerror(errno));

	snprintf(fidstr, sizeof(fidstr), DFID_NOBRACE, PFID(&fid));
	recno = -1;
	linkno = 0;
	rc = llapi_fid2path(lustre_dir, fidstr, path,
			    sizeof(path), &recno, &linkno);
	ASSERTF(rc == -ENOENT, "llapi_fid2path failed for fid %s: %s",
		fidstr, strerror(-rc));
}

/* Test volatile file. */
static void test12(void)
{
	int rc;
	int fd;
	int fd2;
	int fd3;
	struct lu_fid fid;

	/* Against a volatile file */
	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));
	fd = llapi_create_volatile_idx(mainpath, -1, 0);
	ASSERTF(fd >= 0, "creat failed for '%s': %s",
		mainpath, strerror(errno));

	rc = llapi_fd2fid(fd, &fid);
	ASSERTF(rc == 0, "llapi_path2fid failed for '%s': %s",
		mainpath, strerror(-rc));

	/* No many ways to test, except to open by fid. */
	fd2 = llapi_open_by_fid(mainpath, &fid, O_RDONLY);
	ASSERTF(fd2 >= 0, "llapi_open_by_fid for " DFID_NOBRACE ": %s",
		PFID(&fid), strerror(errno));

	close(fd);

	/* Check the file can still be opened, since fd2 is not
	 * closed. */
	fd3 = llapi_open_by_fid(mainpath, &fid, O_RDONLY);
	ASSERTF(fd3 >= 0, "llapi_open_by_fid for " DFID_NOBRACE ": %s",
		PFID(&fid), strerror(errno));

	close(fd2);
	close(fd3);

	/* The volatile file is gone now. */
	fd = llapi_open_by_fid(mainpath, &fid, O_RDONLY);
	ASSERTF(fd < 0, "llapi_open_by_fid for " DFID_NOBRACE ": %d",
		PFID(&fid), fd);
}

/* Test with sub directories */
static void test20(void)
{
	char testpath[PATH_MAX];
	size_t len;
	int dir_created = 0;
	int rc;

	rc = snprintf(testpath, sizeof(testpath), "%s", mainpath);
	ASSERTF((rc > 0 && rc < sizeof(testpath)),
		"invalid name for testpath '%s'", mainpath);

	rc = mkdir(testpath, S_IRWXU);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		testpath, strerror(errno));

	len = strlen(testpath);

	/* Create subdirectories as long as we can. Each new subdir is
	 * "/x", so we need at least 3 characters left in testpath. */
	while (len <= sizeof(testpath) - 3) {
		strncat(testpath, "/x", sizeof(testpath) - 1);

		len += 2;

		rc = mkdir(testpath, S_IRWXU);
		ASSERTF(rc == 0, "mkdir failed for '%s': %s",
			testpath, strerror(errno));

		dir_created++;

		helper_fid2path(testpath, -1);
	}

	/* And test the last one. */
	helper_fid2path(testpath, -1);

	/* Make sure we have created enough directories. Even with a
	 * reasonably long mountpath, we should have created at least
	 * 2000. */
	ASSERTF(dir_created >= 2000, "dir_created=%d -- '%s'",
		dir_created, testpath);
}

/* Test linkno from fid2path */
static void test30(void)
{
	/* Note that since the links are stored in the extended
	 * attributes, only a few of these will fit (about 150 in this
	 * test). Still, create more than that to ensure the system
	 * doesn't break. See LU-5746. */
	const int num_links = 1000;
	struct {
		char filename[PATH_MAX];
		bool seen;
	} links[num_links];
	char buf[PATH_MAX];
	char buf2[PATH_MAX * 2];
	struct lu_fid fid;
	char fidstr[FID_LEN + 1];
	int rc;
	int i;
	int j;
	int fd;
	int linkno;
	bool past_link_limit = false;

	/* Create the containing directory. */
	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));

	/* Initializes the link array. */
	for (i = 0; i < num_links; i++) {
		rc = snprintf(links[i].filename, sizeof(links[i].filename),
			      "%s/%s/link%04d", lustre_dir, maindir, i);

		ASSERTF((rc > 0 && rc < sizeof(links[i].filename)),
			"invalid name for link");

		links[i].seen = false;
	}

	/* Create the original file. */
	fd = creat(links[0].filename, 0);
	ASSERTF(fd >= 0, "create failed for '%s': %s",
		links[0].filename, strerror(errno));
	close(fd);

	rc = llapi_path2fid(links[0].filename, &fid);
	ASSERTF(rc == 0, "llapi_path2fid failed for '%s': %s",
		links[0].filename, strerror(-rc));
	snprintf(fidstr, sizeof(fidstr), DFID_NOBRACE, PFID(&fid));

	/* Create the links */
	for (i = 1; i < num_links; i++) {
		rc = link(links[0].filename, links[i].filename);
		ASSERTF(rc == 0, "link failed for '%s' / '%s': %s",
			links[0].filename, links[i].filename, strerror(errno));
	}

	/* Query the links, making sure we got all of them */
	for (i = 0; i < num_links + 10; i++) {
		long long recno;
		bool found;

		/* Without braces */
		recno = -1;
		linkno = i;
		rc = llapi_fid2path(links[0].filename, fidstr, buf,
				    sizeof(buf), &recno, &linkno);
		ASSERTF(rc == 0, "llapi_fid2path failed for fid %s: %s",
			fidstr, strerror(-rc));

		snprintf(buf2, sizeof(buf2), "%s/%s", mnt_dir, buf);

		if (past_link_limit == false) {
			/* Find the name in the links that were created */
			found = false;
			for (j = 0; j < num_links; j++) {
				if (strcmp(buf2, links[j].filename) == 0) {
					ASSERTF(links[j].seen == false,
						"link '%s' already seen",
						links[j].filename);
					links[j].seen = true;
					found = true;
					break;
				}
			}
			ASSERTF(found == true, "link '%s' not found", buf2);

			if (linkno == i) {
				/* The linkno hasn't changed. This
				 * means it is the last entry
				 * stored. */
				past_link_limit = true;

				fprintf(stderr,
					"Was able to store %d links in the EA\n",
					i);

				/* Also assume that some links were
				 * returned. It's hard to compute the
				 * exact value. */
				ASSERTF(i > 50,
					"not enough links were returned: %d",
					i);
			}
		} else {
			/* Past the number of links stored in the EA,
			 * Lustre will simply return the original
			 * file. */
			ASSERTF(strcmp(buf2, links[0].filename) == 0,
				       "unexpected link for record %d: '%s' / '%s'",
				       i, buf2, links[0].filename);
		}

	}
}

/* Test llapi_fd2parent/llapi_path2parent on mainpath (whatever its
 * type). mainpath must exist. */
static void help_test40(void)
{
	struct lu_fid parent_fid;
	struct lu_fid fid2;
	char buf[PATH_MAX];
	int rc;

	/* Successful call */
	memset(buf, 0x55, sizeof(buf));
	rc = llapi_path2parent(mainpath, 0, &parent_fid, buf, PATH_MAX);
	ASSERTF(rc == 0, "llapi_path2parent failed for '%s': %s",
		mainpath, strerror(errno));
	ASSERTF(strcmp(buf, maindir) == 0, "paths are different: '%s' / '%s'",
		buf, maindir);

	/* By construction, mainpath is just under lustre_dir, so we
	 * can check that the parent fid of mainpath is indeed the one
	 * of lustre_dir. */
	rc = llapi_path2fid(lustre_dir, &fid2);
	ASSERTF(rc == 0, "llapi_path2fid failed for '%s': %s",
		lustre_dir, strerror(-rc));
	ASSERTF(memcmp(&parent_fid, &fid2, sizeof(fid2)) == 0,
		"fids are different");

	/* Name too short */
	rc = llapi_path2parent(mainpath, 0, &parent_fid, buf, 0);
	ASSERTF(rc == -EOVERFLOW, "llapi_path2parent error: %s", strerror(-rc));

	rc = llapi_path2parent(mainpath, 0, &parent_fid, buf, 5);
	ASSERTF(rc == -EOVERFLOW, "llapi_path2parent error: %s", strerror(-rc));

	rc = llapi_path2parent(mainpath, 0, &parent_fid, buf, strlen(maindir));
	ASSERTF(rc == -EOVERFLOW, "llapi_path2parent error: %s", strerror(-rc));

	rc = llapi_path2parent(mainpath, 0, &parent_fid, buf,
			       strlen(maindir)+1);
	ASSERTF(rc == 0, "llapi_path2parent failed: %s", strerror(-rc));
}

static void test40(void)
{
	int fd;
	int rc;

	/* Against a directory. */
	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed for '%s': %s",
		mainpath, strerror(errno));
	help_test40();

	cleanup();

	/* Against a regular file */
	fd = creat(mainpath, 0);
	ASSERTF(fd >= 0, "creat failed for '%s': %s",
		mainpath, strerror(errno));
	close(fd);
}

/* Test LL_IOC_GETPARENT directly */
static void test41(void)
{
	int rc;
	int fd;
	int i;
	union {
		struct getparent gp;
		char buf[1024];
	} u;

	/* Against a regular file */
	fd = creat(mainpath, 0);
	ASSERTF(fd >= 0, "creat failed for '%s': %s",
		mainpath, strerror(errno));

	/* Ask a few times */
	for (i = 0; i < 256; i++) {
		memset(u.buf, i, sizeof(u.buf)); /* poison */
		u.gp.gp_linkno = 0;
		u.gp.gp_name_size = 100;

		rc = ioctl(fd, LL_IOC_GETPARENT, &u.gp);
		ASSERTF(rc == 0, "LL_IOC_GETPARENT failed: %s, rc=%d",
			strerror(errno), rc);
		ASSERTF(strcmp(u.gp.gp_name, maindir) == 0,
			"strings are different: %zd, %zd",
			strlen(u.gp.gp_name), strlen(maindir));
	}

	close(fd);
}

/* Test with linkno. Create sub directories, and put a link to the
 * original file in them. */
static void test42(void)
{

	const int num_links = 100;
	struct {
		char subdir[PATH_MAX];
		struct lu_fid subdir_fid;
		char filename[PATH_MAX];
		bool seen;
	} links[num_links];
	char link0[PATH_MAX];
	char buf[PATH_MAX];
	int rc;
	int i;
	int fd;
	int linkno;
	struct lu_fid parent_fid;

	/* Create the containing directory. */
	rc = mkdir(mainpath, 0);
	ASSERTF(rc == 0, "mkdir failed: for '%s': %s",
		mainpath, strerror(errno));

	/* Initializes the link array. */
	for (i = 0; i < num_links; i++) {
		rc = snprintf(links[i].subdir, sizeof(links[i].subdir),
			      "%s/sub%04d", mainpath, i);
		ASSERTF((rc > 0 && rc < sizeof(links[i].subdir)),
			"invalid name for subdir");

		rc = snprintf(links[i].filename, sizeof(links[i].filename),
			      "link%04d", i);
		ASSERTF((rc > 0 && rc < sizeof(links[i].filename)),
			"invalid name for link");

		links[i].seen = false;
	}

	/* Create the subdirectories. */
	for (i = 0; i < num_links; i++) {
		rc = mkdir(links[i].subdir, S_IRWXU);
		ASSERTF(rc == 0, "mkdir failed for '%s': %s",
			links[i].subdir, strerror(errno));

		rc = llapi_path2fid(links[i].subdir, &links[i].subdir_fid);
		ASSERTF(rc == 0, "llapi_path2fid failed for '%s': %s",
			links[i].subdir, strerror(-rc));
	}

	/* Create the original file. */
	rc = snprintf(link0, sizeof(link0), "%s/%s",
		      links[0].subdir, links[0].filename);
	ASSERTF((rc > 0 && rc < sizeof(link0)), "invalid name for file");

	fd = creat(link0, 0);
	ASSERTF(fd >= 0, "create failed for '%s': %s", link0, strerror(errno));
	close(fd);

	/* Create the links */
	for (i = 1; i < num_links; i++) {
		rc = snprintf(buf, sizeof(buf), "%s/%s",
			      links[i].subdir, links[i].filename);
		ASSERTF((rc > 0 && rc < sizeof(buf)),
			"invalid name for link %d", i);

		rc = link(link0, buf);
		ASSERTF(rc == 0, "link failed for '%s' / '%s': %s",
			link0, buf, strerror(errno));
	}

	/* Query the links, making sure we got all of them. Do it in
	 * reverse order, just because! */
	for (linkno = num_links-1; linkno >= 0; linkno--) {
		bool found;

		rc = llapi_path2parent(link0, linkno, &parent_fid, buf,
				       sizeof(buf));
		ASSERTF(rc == 0, "llapi_path2parent failed for '%s': %s",
			link0, strerror(-rc));

		/* Find the name in the links that were created */
		found = false;
		for (i = 0; i < num_links; i++) {
			if (memcmp(&parent_fid, &links[i].subdir_fid,
				   sizeof(parent_fid)) != 0)
				continue;

			ASSERTF(strcmp(links[i].filename, buf) == 0,
				"name differ: '%s' / '%s'",
				links[i].filename, buf);
			ASSERTF(links[i].seen == false,
				"link '%s' already seen", links[i].filename);
			links[i].seen = true;
			found = true;
			break;
		}
		ASSERTF(found == true, "link '%s' not found", buf);
	}

	/* check non existent n+1 link */
	rc = llapi_path2parent(link0, num_links, &parent_fid, buf, sizeof(buf));
	ASSERTF(rc == -ENODATA, "llapi_path2parent error for '%s': %s",
		link0, strerror(-rc));
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

	rc = llapi_search_mounts(lustre_dir, 0, mnt_dir, fsname);
	if (rc != 0) {
		fprintf(stderr, "Error: %s: not a Lustre filesystem\n",
			lustre_dir);
		return EXIT_FAILURE;
	}

	mnt_fd = open(mnt_dir, O_RDONLY|O_DIRECTORY);
	ASSERTF(!(mnt_fd < 0), "cannot open '%s': %s\n", mnt_dir, strerror(errno));

	/* Play nice with Lustre test scripts. Non-line buffered output
	 * stream under I/O redirection may appear incorrectly. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	/* Create a test filename and reuse it. Remove possibly old files. */
	rc = snprintf(mainpath, sizeof(mainpath), "%s/%s", lustre_dir, maindir);
	ASSERTF((rc > 0 && rc < sizeof(mainpath)), "invalid name for mainpath");
	cleanup();

	atexit(cleanup);

	PERFORM(test10);
	PERFORM(test11);
	PERFORM(test12);
	PERFORM(test20);
	PERFORM(test30);
	PERFORM(test40);
	PERFORM(test41);
	PERFORM(test42);

	return EXIT_SUCCESS;
}
