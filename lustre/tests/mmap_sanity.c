// SPDX-License-Identifier: GPL-2.0-only
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
#include <pthread.h>
#include <stdlib.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>

#include <libcfs/util/param.h>
#include "llapi_test_utils.h"

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

static void mmap_finalize(void)
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

	memset(ptr, '1', region / 2);
	sleep(2);
	memset(ptr + region / 2, '1', region / 2);

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

	memset(ptr, '2', region / 2);
	sleep(2);
	memset(ptr + region / 2, '2', region / 2);

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
		FILE *f = fopen(paths.gl_pathv[i], "r+");

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

#define NUM_THREADS	8
#define BUF_SIZE	4096
#define MAX_LEN		1048576
#define MAX_FILESIZE	(NUM_THREADS * MAX_LEN)

struct thread_data {
	int	 td_tid;
	char	*td_buf;
	size_t	 td_len;
	int	 td_fd;
};

static int mmap_create_file(char *fname, size_t size)
{
	char buf[BUF_SIZE];
	ssize_t written = 0;
	int rc = 0;
	int fd;

	fd = open(fname, O_WRONLY | O_CREAT, 0666);
	if (fd == -1) {
		perror("open");
		return -errno;
	}

	memset(buf, 'Q', sizeof(buf));
	while (written < size) {
		ssize_t ret;

		ret = write(fd, buf, BUF_SIZE);
		if (ret != BUF_SIZE) {
			fprintf(stderr, "failed to write %s: %s\n",
				fname, strerror(errno));
			rc = -errno;
			goto out;
		}

		written += ret;
	}

out:
	close(fd);
	return rc;
}

static void *tst10_thread(void *arg)
{
	struct thread_data *data = (struct thread_data *)arg;
	size_t size = data->td_len;
	int fd = data->td_fd;
	char buf[BUF_SIZE];
	loff_t offset = 0;
	char *ptr;
	int rc;

	ptr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (ptr == MAP_FAILED) {
		rc = errno;
		perror("mmap()");
		exit(rc);
	}

	do {
		memcpy(buf, ptr + offset, sizeof(buf));
		offset += sizeof(buf);
	} while (offset < size);

	rc = munmap(ptr, size);
	if (rc == -1) {
		rc = errno;
		perror("nunmap");
		exit(rc);
	}

	return NULL;
}

static int mmap_tst10(char *mnt)
{
	pthread_t thread[NUM_THREADS];
	struct thread_data data;
	char fname[PATH_MAX];
	int rc = 0;
	int fd;
	int i;

	if (snprintf(fname, PATH_MAX, "%s/mmap_tst10", mnt) >= PATH_MAX) {
		fprintf(stderr, "file name too long\n");
		return -ENAMETOOLONG;
	}

	rc = mmap_create_file(fname, MAX_FILESIZE);
	if (rc)
		return rc;

	fd = open(fname, O_RDONLY | O_DIRECT, 0644);
	if (fd == -1) {
		rc = -errno;
		perror("open");
		return rc;
	}

	data.td_fd = fd;
	data.td_len = MAX_FILESIZE;
	for (i = 0; i < NUM_THREADS; i++)
		pthread_create(&thread[i], NULL, tst10_thread, &data);

	for (i = 0; i < NUM_THREADS; i++)
		pthread_join(thread[i], NULL);

	close(fd);
	unlink(fname);
	return rc;
}

static void *tst11_thread(void *arg)
{
	struct thread_data *data = (struct thread_data *)arg;
	char *ptr = data->td_buf;
	char buf[BUF_SIZE];
	loff_t offset = 0;

	do {
		memcpy(buf, ptr + offset, sizeof(buf));
		offset += sizeof(buf);
	} while (offset < data->td_len);

	return NULL;
}

static int mmap_tst11(char *mnt)
{
	pthread_t thread[NUM_THREADS];
	struct thread_data data[NUM_THREADS];
	char fname[PATH_MAX];
	char *ptr;
	int rc = 0;
	int fd;
	int i;

	if (snprintf(fname, PATH_MAX, "%s/mmap_tst11", mnt) >= PATH_MAX) {
		fprintf(stderr, "file name too long\n");
		return -ENAMETOOLONG;
	}

	rc = mmap_create_file(fname, MAX_FILESIZE);
	if (rc)
		return rc;

	fd = open(fname, O_RDONLY | O_DIRECT, 0644);
	if (fd == -1) {
		rc = -errno;
		perror("open");
		return rc;
	}

	ptr = mmap(NULL, MAX_FILESIZE, PROT_READ, MAP_PRIVATE, fd, 0);
	if (ptr == MAP_FAILED) {
		rc = errno;
		perror("mmap()");
		exit(rc);
	}

	for (i = 0; i < NUM_THREADS; i++) {
		data[i].td_tid = i;
		data[i].td_len = MAX_LEN;
		data[i].td_buf = ptr + i * MAX_LEN;
		pthread_create(&thread[i], NULL, tst11_thread, &data[i]);
	}

	for (i = 0; i < NUM_THREADS; i++)
		pthread_join(thread[i], NULL);

	rc = munmap(ptr, MAX_FILESIZE);
	if (rc == -1) {
		rc = errno;
		perror("nunmap");
		exit(rc);
	}

	close(fd);
	unlink(fname);
	return rc;
}

static int mmap_tst12(char *mnt)
{
	char *buf = MAP_FAILED;
	char *buffer[256];
	struct stat st1, st2;
	long off;
	int fd = -1;
	int rc = 0;

	/* cancel unused locks */
	rc = cancel_lru_locks("osc");
	if (rc)
		goto out;

	fd = open(mmap_sanity, O_RDONLY);
	if (fd == -1) {
		perror("open");
		rc = -errno;
		goto out;
	}

	if (fstat(fd, &st1) != 0) {
		perror("fstat");
		rc = -errno;
		goto out;
	}

	sleep(1);

	buf = mmap(NULL, st1.st_size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_NORESERVE, fd, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		rc = -errno;
		goto out;
	}

	/* read some data */
	for (off = 0; off + 256 <= st1.st_size; off += 256)
		memcpy(buffer, off + buf, 256);

	if (fstat(fd, &st2) != 0) {
		perror("fstat");
		rc = -errno;
		goto out;
	}

	if (st1.st_mtime != st2.st_mtime) {
		fprintf(stderr, "before mmap read mtime(%ld) != after mtime=(%ld)\n",
			st1.st_mtime, st2.st_mtime);
		rc = -EINVAL;
		goto out;
	}
out:
	if (buf != MAP_FAILED)
		munmap(buf, st1.st_size);
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

#define MMAP_TEST_WRAPPER(n)			\
static void test##n(void)			\
{						\
	int rc = mmap_tst##n(dir);		\
						\
	if (rc)					\
		exit(EXIT_FAILURE);		\
}

MMAP_TEST_WRAPPER(1)
MMAP_TEST_WRAPPER(2)
MMAP_TEST_WRAPPER(3)
MMAP_TEST_WRAPPER(4)
MMAP_TEST_WRAPPER(5)
MMAP_TEST_WRAPPER(6)
MMAP_TEST_WRAPPER(7)
MMAP_TEST_WRAPPER(8)
MMAP_TEST_WRAPPER(9)
MMAP_TEST_WRAPPER(10)
MMAP_TEST_WRAPPER(11)
MMAP_TEST_WRAPPER(12)

static struct test_tbl_entry test_tbl[] = {
	{
		.tte_fn = test1,
		.tte_desc = "mmap test1: basic mmap operation",
		.tte_num = 1,
	},
	{
		.tte_fn = test2,
		.tte_desc = "mmap test2: MAP_PRIVATE not write back",
		.tte_num = 2,
	},
	{
		.tte_fn = test3,
		.tte_desc = "mmap test3: concurrent mmap ops on two nodes",
		.tte_num = 3,
	},
	{
		.tte_fn = test4,
		.tte_desc = "mmap test4: cross-mount concurrent mmap writes",
		.tte_num = 4,
	},
	{
		.tte_fn = test5,
		.tte_desc = "mmap test5: read/write file to/from mmapped buffer",
		.tte_num = 5,
	},
	{
		.tte_fn = test6,
		.tte_desc = "mmap test6: check mmap write/read content on two nodes",
		.tte_num = 6,
	},
	{
		.tte_fn = test7,
		.tte_desc = "mmap test7: file i/o with an unmapped buffer",
		.tte_num = 7,
	},
	{
		.tte_fn = test8,
		.tte_desc = "mmap test8: SIGBUS for beyond file size",
		.tte_num = 8,
	},
	{
		.tte_fn = test9,
		.tte_desc = "mmap test9: SIGBUS for negative file offset",
		.tte_num = 9,
	},
	{
		.tte_fn = test10,
		.tte_desc = "mmap test10: multi-thread mmap access",
		.tte_num = 10,
	},
	{
		.tte_fn = test11,
		.tte_desc = "mmap test11: multi-thread shared mmap",
		.tte_num = 11,
	},
	{
		.tte_fn = test12,
		.tte_desc = "mmap test12: mtime not change for readonly mmap access",
		.tte_num = 12,
	},
	TEST_REGISTER_END
};

int main(int argc, char **argv)
{
	int c, rc = 0;

	while ((c = getopt(argc, argv, "d:m:e:")) != -1) {
		switch (c) {
		case 'd':
			dir = optarg;
			break;
		case 'm':
			dir2 = optarg;
			break;
		case 'e':
			set_tests_to_skip(optarg, test_tbl);
			break;
		default:
			usage();
			break;
		}
	}

	if (!dir)
		usage();

	if (!dir2) {
		test_tbl[2].tte_skip = true;
		test_tbl[3].tte_skip = true;
		test_tbl[5].tte_skip = true;
	}

	if (mmap_initialize(argv[0]) != 0) {
		fprintf(stderr, "mmap_initialize failed!\n");
		return -EINVAL;
	}

	rc = run_tests(dir, test_tbl);
	mmap_finalize();

	return rc;
}
