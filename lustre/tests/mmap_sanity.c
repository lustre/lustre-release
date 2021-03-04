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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>

#include <libcfs/util/param.h>

char *dir = NULL, *dir2 = NULL;
long page_size;
char mmap_sanity[256];

static void usage(void)
{
	printf("Usage: mmap_sanity -d dir [-m dir2] [-e <test cases>]\n");
	printf("       -d dir        lustre mount point\n");
	printf("       -m dir2       another mount point\n");
	printf("       -e testcases  skipped test cases, -e 1 -e 2 to exclude test cases 1 and 2.\n");
	exit(127);
}

static int remote_tst(int tc, char *mnt);
static int mmap_run(int tc)
{
	pid_t child;
	int rc = 0;

	child = fork();
	if (child < 0)
		return -errno;
	else if (child)
		return 0;

	if (dir2) {
		rc = remote_tst(tc, dir2);
	} else {
		rc = -EINVAL;
		fprintf(stderr, "invalid argument!\n");
	}
	_exit(rc);
}

static int mmap_initialize(char *myself)
{
	char buf[1024], *file;
	int fdr, fdw, count, rc = 0;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size == -1) {
		perror("sysconf(_SC_PAGESIZE)");
		return -errno;
	}

	/* copy myself to lustre for another client */
	fdr = open(myself, O_RDONLY);
	if (fdr < 0) {
		perror(myself);
		return -EINVAL;
	}
	file = strrchr(myself, '/');
	if (!file) {
		fprintf(stderr, "can't get test filename\n");
		close(fdr);
		return -EINVAL;
	}
	file++;
	sprintf(mmap_sanity, "%s/%s", dir, file);

	fdw = open(mmap_sanity, O_CREAT | O_WRONLY, 0777);
	if (fdw < 0) {
		perror(mmap_sanity);
		close(fdr);
		return -EINVAL;
	}
	while ((count = read(fdr, buf, sizeof(buf))) != 0) {
		int writes;

		if (count < 0) {
			perror("read()");
			rc = -errno;
			break;
		}
		writes = write(fdw, buf, count);
		if (writes != count) {
			perror("write()");
			rc = -errno;
			break;
		}
	}
	close(fdr);
	close(fdw);
	return rc;
}

static void mmap_finalize()
{
	unlink(mmap_sanity);
}

/* basic mmap operation on single node */
static int mmap_tst1(char *mnt)
{
	char *ptr, mmap_file[256];
	int region, fd, rc = 0;

	region = page_size * 10;
	sprintf(mmap_file, "%s/%s", mnt, "mmap_file1");

	if (unlink(mmap_file) && errno != ENOENT) {
		perror("unlink()");
		return -errno;
	}

	fd = open(mmap_file, O_CREAT | O_RDWR, 0600);
	if (fd < 0) {
		perror(mmap_file);
		return -errno;
	}
	if (ftruncate(fd, region) < 0) {
		perror("ftruncate()");
		rc = -errno;
		goto out_close;
	}

	ptr = mmap(NULL, region, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		perror("mmap()");
		rc = -errno;
		goto out_close;
	}
	memset(ptr, 'a', region);

	munmap(ptr, region);
out_close:
	close(fd);
	unlink(mmap_file);
	return rc;
}

/* MAP_PRIVATE create a copy-on-write mmap */
static int mmap_tst2(char *mnt)
{
	char *ptr, mmap_file[256], buf[256];
	int fd, rc = 0;

	sprintf(mmap_file, "%s/%s", mnt, "mmap_file2");

	if (unlink(mmap_file) && errno != ENOENT) {
		perror("unlink()");
		return -errno;
	}

	fd = open(mmap_file, O_CREAT | O_RDWR, 0600);
	if (fd < 0) {
		perror(mmap_file);
		return -errno;
	}
	if (ftruncate(fd, page_size) < 0) {
		perror("ftruncate()");
		rc = -errno;
		goto out_close;
	}

	ptr = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (ptr == MAP_FAILED) {
		perror("mmap()");
		rc = -errno;
		goto out_close;
	}
	memcpy(ptr, "blah", strlen("blah"));

	munmap(ptr, page_size);
out_close:
	close(fd);
	if (rc)
		return -rc;

	fd = open(mmap_file, O_RDONLY);
	if (fd < 0) {
		perror(mmap_file);
		return -errno;
	}
	rc = read(fd, buf, sizeof(buf));
	if (rc < 0) {
		perror("read()");
		rc = -errno;
		goto out_close;
	}
	rc = 0;

	if (strncmp("blah", buf, strlen("blah")) == 0) {
		fprintf(stderr, "mmap write back with MAP_PRIVATE!\n");
		rc = -EFAULT;
	}
	close(fd);
	unlink(mmap_file);
	return rc;
}

/* concurrent mmap operations on two nodes */
static int mmap_tst3(char *mnt)
{
	char *ptr, mmap_file[256];
	int region, fd, rc = 0;

	region = page_size * 100;
	sprintf(mmap_file, "%s/%s", mnt, "mmap_file3");

	if (unlink(mmap_file) && errno != ENOENT) {
		perror("unlink()");
		return -errno;
	}

	fd = open(mmap_file, O_CREAT | O_RDWR, 0600);
	if (fd < 0) {
		perror(mmap_file);
		return -errno;
	}
	if (ftruncate(fd, region) < 0) {
		perror("ftruncate()");
		rc = -errno;
		goto out_close;
	}

	ptr = mmap(NULL, region, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		perror("mmap()");
		rc = -errno;
		goto out_close;
	}

	rc = mmap_run(3);
	if (rc)
		goto out_unmap;

	memset(ptr, 'a', region);
	sleep(2);       /* wait for remote test finish */
out_unmap:
	munmap(ptr, region);
out_close:
	close(fd);
	unlink(mmap_file);
	return rc;
}

static int remote_tst3(char *mnt)
{
	char *ptr, mmap_file[256];
	int region, fd, rc = 0;

	region = page_size * 100;
	sprintf(mmap_file, "%s/%s", mnt, "mmap_file3");

	fd = open(mmap_file, O_RDWR, 0600);
	if (fd < 0) {
		perror(mmap_file);
		return -errno;
	}

	ptr = mmap(NULL, region, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		perror("mmap()");
		rc = -errno;
		goto out_close;
	}
	memset(ptr, 'b', region);
	memset(ptr, 'c', region);

	munmap(ptr, region);
out_close:
	close(fd);
	return rc;
}

/*
 * client1 write to file_4a from mmap()ed file_4b;
 * client2 write to file_4b from mmap()ed file_4a.
 */
static int mmap_tst4(char *mnt)
{
	char *ptr, filea[256], fileb[256];
	int region, fdr, fdw, rc = 0;

	region = page_size * 100;
	sprintf(filea, "%s/%s", mnt, "mmap_file_4a");
	sprintf(fileb, "%s/%s", mnt, "mmap_file_4b");

	if (unlink(filea) && errno != ENOENT) {
		perror("unlink()");
		return -errno;
	}
	if (unlink(fileb) && errno != ENOENT) {
		perror("unlink()");
		return -errno;
	}

	fdr = fdw = -1;
	fdr = open(fileb, O_CREAT | O_RDWR, 0600);
	if (fdr < 0) {
		perror(fileb);
		return -errno;
	}
	if (ftruncate(fdr, region) < 0) {
		perror("ftruncate()");
		rc = -errno;
		goto out_close;
	}
	fdw = open(filea, O_CREAT | O_RDWR, 0600);
	if (fdw < 0) {
		perror(filea);
		rc = -errno;
		goto out_close;
	}
	if (ftruncate(fdw, region) < 0) {
		perror("ftruncate()");
		rc = -errno;
		goto out_close;
	}

	ptr = mmap(NULL, region, PROT_READ | PROT_WRITE, MAP_SHARED, fdr, 0);
	if (ptr == MAP_FAILED) {
		perror("mmap()");
		rc = -errno;
		goto out_close;
	}

	rc = mmap_run(4);
	if (rc)
		goto out_unmap;

	memset(ptr, '1', region);

	rc = write(fdw, ptr, region);
	if (rc <= 0) {
		perror("write()");
		rc = -errno;
	} else {
		rc = 0;
	}

	sleep(2);       /* wait for remote test finish */
out_unmap:
	munmap(ptr, region);
out_close:
	if (fdr >= 0)
		close(fdr);
	if (fdw >= 0)
		close(fdw);
	unlink(filea);
	unlink(fileb);
	return rc;
}

static int remote_tst4(char *mnt)
{
	char *ptr, filea[256], fileb[256];
	int region, fdr, fdw, rc = 0;

	region = page_size * 100;
	sprintf(filea, "%s/%s", mnt, "mmap_file_4a");
	sprintf(fileb, "%s/%s", mnt, "mmap_file_4b");

	fdr = fdw = -1;
	fdr = open(filea, O_RDWR, 0600);
	if (fdr < 0) {
		perror(filea);
		return -errno;
	}
	fdw = open(fileb, O_RDWR, 0600);
	if (fdw < 0) {
		perror(fileb);
		rc = -errno;
		goto out_close;
	}

	ptr = mmap(NULL, region, PROT_READ | PROT_WRITE, MAP_SHARED, fdr, 0);
	if (ptr == MAP_FAILED) {
		perror("mmap()");
		rc = -errno;
		goto out_close;
	}

	memset(ptr, '2', region);

	rc = write(fdw, ptr, region);
	if (rc <= 0) {
		perror("write()");
		rc = -errno;
	} else {
		rc = 0;
	}

	munmap(ptr, region);
out_close:
	if (fdr >= 0)
		close(fdr);
	if (fdw >= 0)
		close(fdw);
	return rc;
}

static int cancel_lru_locks(char *filter)
{
	glob_t paths;
	pid_t child;
	int rc, i;

	child = fork();
	if (child < 0) {
		return -errno;
	} else if (child) {
		int status;

		rc = waitpid(child, &status, WNOHANG);
		if (rc == child)
			rc = 0;
		return rc;
	}

	if (filter)
		rc = cfs_get_param_paths(&paths,
					 "ldlm/namespaces/*-%s-*/lru_size",
					 filter);
	else
		rc = cfs_get_param_paths(&paths,
					 "ldlm/namespaces/*/lru_size");
	if (rc != 0)
		return -EINVAL;

	for (i = 0; i < paths.gl_pathc; i++) {
		FILE *f = fopen(paths.gl_pathv[i], "r");

		if (!f) {
			rc = -errno;
			fprintf(stderr, "cannot open '%s': %s\n",
				paths.gl_pathv[i], strerror(errno));
			break;
		}

		rc = fwrite("clear", strlen("clear") + 1, 1, f);
		if (rc < 1) {
			rc = -errno;
			fprintf(stderr, "fwrite failed for '%s': %s\n",
				paths.gl_pathv[i], strerror(errno));
			fclose(f);
			break;
		}
		fclose(f);
	}

	cfs_free_param_data(&paths);
	_exit(rc);
}

/*
 * don't dead lock while read/write file to/from the buffer which
 * mmaped to just this file
 */
static int mmap_tst5(char *mnt)
{
	char *ptr, mmap_file[256];
	int region, fd, off, rc = 0;

	region = page_size * 40;
	off = page_size * 10;
	sprintf(mmap_file, "%s/%s", mnt, "mmap_file5");

	if (unlink(mmap_file) && errno != ENOENT) {
		perror("unlink()");
		return -errno;
	}

	fd = open(mmap_file, O_CREAT | O_RDWR, 0600);
	if (fd < 0) {
		perror(mmap_file);
		return -errno;
	}
	if (ftruncate(fd, region) < 0) {
		perror("ftruncate()");
		rc = -errno;
		goto out_close;
	}

	ptr = mmap(NULL, region, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		perror("mmap()");
		rc = -errno;
		goto out_close;
	}
	memset(ptr, 'a', region);

	/* cancel unused locks */
	rc = cancel_lru_locks("osc");
	if (rc)
		goto out_unmap;

	/* read/write region of file and buffer should be overlap */
	rc = read(fd, ptr + off, off * 2);
	if (rc != off * 2) {
		perror("read()");
		rc = -errno;
		goto out_unmap;
	}
	rc = write(fd, ptr + off, off * 2);
	if (rc != off * 2) {
		perror("write()");
		rc = -errno;
	}
	rc = 0;
out_unmap:
	munmap(ptr, region);
out_close:
	close(fd);
	unlink(mmap_file);
	return rc;
}

/* mmap write to a file form client1 then mmap read from client2 */
static int mmap_tst6(char *mnt)
{
	char mmap_file[256], mmap_file2[256];
	char *ptr = NULL, *ptr2 = NULL;
	int fd = 0, fd2 = 0, rc = 0;

	sprintf(mmap_file, "%s/%s", mnt, "mmap_file6");
	sprintf(mmap_file2, "%s/%s", dir2, "mmap_file6");
	if (unlink(mmap_file) && errno != ENOENT) {
		perror("unlink()");
		return -errno;
	}

	fd = open(mmap_file, O_CREAT | O_RDWR, 0600);
	if (fd < 0) {
		perror(mmap_file);
		return -errno;
	}
	if (ftruncate(fd, page_size) < 0) {
		perror("ftruncate()");
		rc = -errno;
		goto out;
	}

	fd2 = open(mmap_file2, O_RDWR, 0600);
	if (fd2 < 0) {
		perror(mmap_file2);
		rc = -errno;
		goto out;
	}

	ptr = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		perror("mmap()");
		rc = -errno;
		goto out;
	}

	ptr2 = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		    fd2, 0);
	if (ptr2 == MAP_FAILED) {
		perror("mmap()");
		rc = -errno;
		goto out;
	}

	rc = cancel_lru_locks("osc");
	if (rc)
		goto out;

	memcpy(ptr, "blah", strlen("blah"));
	if (strncmp(ptr, ptr2, strlen("blah"))) {
		fprintf(stderr, "client2 mmap mismatch!\n");
		rc = -EFAULT;
		goto out;
	}
	memcpy(ptr2, "foo", strlen("foo"));
	if (strncmp(ptr, ptr2, strlen("foo"))) {
		fprintf(stderr, "client1 mmap mismatch!\n");
		rc = -EFAULT;
	}
out:
	if (ptr2)
		munmap(ptr2, page_size);
	if (ptr)
		munmap(ptr, page_size);
	if (fd2 > 0)
		close(fd2);
	if (fd > 0)
		close(fd);
	unlink(mmap_file);
	return rc;
}

static int mmap_tst7_func(char *mnt, int rw)
{
	char  fname[256];
	char *buf = MAP_FAILED;
	ssize_t bytes;
	int fd = -1;
	int rc = 0;

	if (snprintf(fname, 256, "%s/mmap_tst7.%s", mnt,
		     (rw == 0) ? "read" : "write") >= 256) {
		fprintf(stderr, "dir name too long\n");
		rc = -ENAMETOOLONG;
		goto out;
	}
	fd = open(fname, O_RDWR | O_DIRECT | O_CREAT, 0644);
	if (fd == -1) {
		perror("open");
		rc = -errno;
		goto out;
	}
	if (ftruncate(fd, 2 * page_size) == -1) {
		perror("truncate");
		rc = -errno;
		goto out;
	}
	buf = mmap(NULL, page_size * 2,
		   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		rc = -errno;
		goto out;
	}
	/* ensure the second page isn't mapped */
	munmap(buf + page_size, page_size);
	bytes = (rw == 0) ? read(fd, buf, 2 * page_size) :
		write(fd, buf, 2 * page_size);
	/* Expected behavior */
	if (bytes == page_size)
		goto out;

	fprintf(stderr, "%s returned %zd, errno = %d\n",
		(rw == 0) ? "read" : "write", bytes, errno);
	rc = -EIO;
out:
	if (buf != MAP_FAILED)
		munmap(buf, page_size);
	if (fd != -1)
		close(fd);
	return rc;
}

static int mmap_tst7(char *mnt)
{
	int rc;

	rc = mmap_tst7_func(mnt, 0);
	if (rc != 0)
		return rc;
	rc = mmap_tst7_func(mnt, 1);
	return rc;
}

static int mmap_tst8(char *mnt)
{
	char  fname[256];
	char *buf = MAP_FAILED;
	int fd = -1;
	int rc = 0;
	pid_t pid;
	char xyz[page_size * 2];

	if (snprintf(fname, 256, "%s/mmap_tst8", mnt) >= 256) {
		fprintf(stderr, "dir name too long\n");
		rc = -ENAMETOOLONG;
		goto out;
	}
	fd = open(fname, O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		perror("open");
		rc = -errno;
		goto out;
	}
	if (ftruncate(fd, page_size) == -1) {
		perror("truncate");
		rc = -errno;
		goto out;
	}
	buf = mmap(NULL, page_size * 2,
		   PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		rc = -errno;
		goto out;
	}

	pid = fork();
	if (pid == 0) { /* child */
		memcpy(xyz, buf, page_size * 2);
		/* shouldn't reach here. */
		exit(0);
	} else if (pid > 0) { /* parent */
		int status = 0;

		pid = waitpid(pid, &status, 0);
		if (pid < 0) {
			perror("wait");
			rc = -errno;
			goto out;
		}

		rc = -EFAULT;
		if (WIFSIGNALED(status) && SIGBUS == WTERMSIG(status))
			rc = 0;
	} else {
		perror("fork");
		rc = -errno;
	}

out:
	if (buf != MAP_FAILED)
		munmap(buf, page_size);
	if (fd != -1)
		close(fd);
	return rc;
}

static int mmap_tst9(char *mnt)
{
	char  fname[256];
	char *buf = MAP_FAILED;
	int fd = -1;
	int rc = 0;

	if (snprintf(fname, 256, "%s/mmap_tst9", mnt) >= 256) {
		fprintf(stderr, "dir name too long\n");
		rc = -ENAMETOOLONG;
		goto out;
	}
	if (unlink(fname) == -1 && errno != ENOENT) {
		perror("unlink");
		rc = -errno;
		goto out;
	}
	fd = open(fname, O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		perror("open");
		rc = -errno;
		goto out;
	}
	buf = mmap(NULL, page_size * 2,
		   PROT_READ, MAP_PRIVATE, fd, (loff_t)(-10 * page_size));
	if (buf == MAP_FAILED) {
		perror("mmap");
		rc = -errno;
		goto out;
	}
	rc = write(STDOUT_FILENO, buf, 2 * page_size);
	if (rc != -1) {
		fprintf(stderr, "write succeded with %d instead of failing\n",
			rc);
		rc = -EINVAL;
		goto out;
	} else if (errno != EFAULT) {
		fprintf(stderr, "write failed with %d instead of EFAULT(%d)\n",
			errno, EFAULT);
		rc = -errno;
		goto out;
	}
	rc = 0;
out:
	if (buf != MAP_FAILED)
		munmap(buf, page_size * 2);
	if (fd != -1)
		close(fd);
	return rc;
}

static int remote_tst(int tc, char *mnt)
{
	int rc = 0;

	switch (tc) {
	case 3:
		rc = remote_tst3(mnt);
		break;
	case 4:
		rc = remote_tst4(mnt);
		break;
	default:
		fprintf(stderr, "wrong test case number %d\n", tc);
		rc = -EINVAL;
		break;
	}
	return rc;
}

struct test_case {
	int tc;                     /* test case number */
	char *desc;                 /* test description */
	int (*test_fn)(char *mnt);  /* test function */
	int node_cnt;               /* node count */
	int skipped;                /* skipped by caller */
};

struct test_case tests[] = {
	{
		.tc		= 1,
		.desc		= "mmap test1: basic mmap operation",
		.test_fn	= mmap_tst1,
		.node_cnt	= 1
	},
	{
		.tc		= 2,
		.desc		= "mmap test2: MAP_PRIVATE not write back",
		.test_fn	= mmap_tst2,
		.node_cnt	= 1
	},
	{
		.tc		= 3,
		.desc		= "mmap test3: concurrent mmap ops on two nodes",
		.test_fn	= mmap_tst3,
		.node_cnt	= 2
	},
	{
		.tc		= 4,
		.desc		= "mmap test4: c1 write to f1 from mmapped f2, c2 write to f1 from mmapped f1",
		.test_fn	= mmap_tst4,
		.node_cnt	= 2
	},
	{
		.tc		= 5,
		.desc		= "mmap test5: read/write file to/from the buffer which mmapped to just this file",
		.test_fn	= mmap_tst5,
		.node_cnt	= 1
	},
	{
		.tc		= 6,
		.desc		= "mmap test6: check mmap write/read content on two nodes",
		.test_fn	= mmap_tst6,
		.node_cnt	= 2
	},
	{
		.tc		= 7,
		.desc		= "mmap test7: file i/o with an unmapped buffer",
		.test_fn	= mmap_tst7,
		.node_cnt	= 1
	},
	{
		.tc		= 8,
		.desc		= "mmap test8: SIGBUS for beyond file size",
		.test_fn	= mmap_tst8,
		.node_cnt	= 1
	},
	{
		.tc		= 9,
		.desc		= "mmap test9: SIGBUS for negative file offset",
		.test_fn	= mmap_tst9,
		.node_cnt	= 1
	},
	{
		.tc		= 0
	}
};

int main(int argc, char **argv)
{
	struct test_case *test;
	int nr_cases = sizeof(tests) / sizeof(*test);
	int c, rc = 0;

	while ((c = getopt(argc, argv, "d:m:e:")) != -1) {
		switch (c) {
		case 'd':
			dir = optarg;
			break;
		case 'm':
			dir2 = optarg;
			break;
		case 'e': {
			char *endptr = NULL;

			rc = strtol(optarg, &endptr, 10);
			if (endptr && *endptr != '\0')
				usage();
			if (rc > 0 && rc < nr_cases)
				tests[rc - 1].skipped = 1;
			break;
		}
		default:
			usage();
			break;
		}
	}

	if (!dir)
		usage();

	if (mmap_initialize(argv[0]) != 0) {
		fprintf(stderr, "mmap_initialize failed!\n");
		return -EINVAL;
	}

	rc = 0;
	for (test = tests; test->tc; test++) {
		double duration = 0.0;
		char *rs = "SKIPPED";

		if (!test->skipped && (test->node_cnt == 1 || dir2)) {
			struct timeval start, end;

			gettimeofday(&start, NULL);
			rc = test->test_fn(dir);
			gettimeofday(&end, NULL);

			duration = (double)(end.tv_sec - start.tv_sec) +
				(double)(end.tv_usec - start.tv_usec) / 1000000;
			rs = rc ? "FAIL" : "PASS";
		}

		fprintf(stderr, "%s (%s, %.5gs)\n", test->desc, rs, duration);
		if (rc)
			break;
	}

	mmap_finalize();
	return -rc;
}
