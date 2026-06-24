// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2026, DataDirect Networks, Inc.
 *
 * Author: Xiyang Wang <xiwang@ddn.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#define OPEN_DIR_FLAGS (O_RDONLY | O_DIRECTORY)

static int exit_status;

static long long
extract_num(const char *s)
{
	const char *p = s + strlen(s);
	while (p > s && '0' <= p[-1] && p[-1] <= '9')
		p--;
	return strtoll(p, NULL, 10);
}

static int
cmp_name_numeric(const void *a, const void *b)
{
	long long x = extract_num(*(const char **)a);
	long long y = extract_num(*(const char **)b);

	/* numeric field wins; tie-break with strcmp to keep the order
	 * independent of LC_COLLATE
	 */
	if (x < y)
		return -1;
	if (x > y)
		return 1;
	return strcmp(*(const char **)a, *(const char **)b);
}

static void
walk_dir(const char *dirpath)
{
	struct stat root_st;
	struct stat st;
	struct dirent *d;
	DIR *dir;
	char **names;
	size_t n_alloc;
	size_t n_used;
	size_t i;
	int fd;
	int dfd;
	char subpath[PATH_MAX];

	if (fstatat(AT_FDCWD, dirpath, &root_st, AT_SYMLINK_NOFOLLOW) < 0) {
		fprintf(stderr, "sorted_readdir: cannot stat '%s': %s\n",
			dirpath, strerror(errno));
		exit_status = 1;
		return;
	}

	fd = open(dirpath, OPEN_DIR_FLAGS);
	if (fd < 0) {
		fprintf(stderr, "sorted_readdir: cannot open directory '%s': %s\n",
			dirpath, strerror(errno));
		exit_status = 1;
		return;
	}

	dir = fdopendir(fd);
	if (!dir) {
		fprintf(stderr, "sorted_readdir: fdopendir '%s': %s\n",
			dirpath, strerror(errno));
		close(fd);
		exit_status = 1;
		return;
	}
	/*
	 * Keep the dup'd fd (dfd) alive past closedir(): closedir() drops
	 * one reference, but dfd keeps the same struct file alive, so on
	 * llite ll_dir_release() -> ll_deauthorize_statahead() does not run
	 * until close(dfd) after the stat loop below. Without this, statahead
	 * would be torn down before the first fstatat() and test_123h would
	 * silently stop exercising it.
	 */
	dfd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
	if (dfd < 0) {
		fprintf(stderr, "sorted_readdir: fcntl '%s': %s\n",
			dirpath, strerror(errno));
		closedir(dir);
		exit_status = 1;
		return;
	}

	n_used = 0;

	n_alloc = (size_t)(root_st.st_size / 40);
	if (n_alloc < 64)
		n_alloc = 64;
	names = malloc(n_alloc * sizeof(names[0]));
	if (!names) {
		fprintf(stderr, "sorted_readdir: memory allocation failed\n");
		exit(1);
	}

	errno = 0;
	while ((d = readdir(dir))) {
		if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
			continue;

		if (n_used == n_alloc) {
			n_alloc = n_alloc * 2;
			names = realloc(names, n_alloc * sizeof(names[0]));
			if (!names) {
				fprintf(stderr, "sorted_readdir: memory allocation failed\n");
				exit(1);
			}
		}
		names[n_used] = malloc(strlen(d->d_name) + 1);
		if (!names[n_used]) {
			fprintf(stderr, "sorted_readdir: memory allocation failed\n");
			exit(1);
		}
		strcpy(names[n_used], d->d_name);
		n_used++;
	}
	if (errno) {
		fprintf(stderr, "sorted_readdir: readdir '%s': %s\n",
			dirpath, strerror(errno));
		exit_status = 1;
	}

	qsort(names, n_used, sizeof(names[0]), cmp_name_numeric);
	if (closedir(dir) < 0) {
		fprintf(stderr, "sorted_readdir: closedir '%s': %s\n",
			dirpath, strerror(errno));
		exit_status = 1;
	}

	for (i = 0; i < n_used; i++) {
		if (fstatat(dfd, names[i], &st, AT_SYMLINK_NOFOLLOW) < 0) {
			fprintf(stderr, "sorted_readdir: cannot stat '%s' in '%s': %s\n",
				names[i], dirpath, strerror(errno));
			exit_status = 1;
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			snprintf(subpath, sizeof(subpath), "%s/%s",
				 dirpath, names[i]);
			walk_dir(subpath);
			continue;
		}

		printf("%s/%s\n", dirpath, names[i]);
	}

	close(dfd);

	for (i = 0; i < n_used; i++)
		free(names[i]);
	free(names);

	printf("%s\n", dirpath);
}

int
main(int argc, char *argv[])
{
	int i;

	if (argc < 2)
		walk_dir(".");
	else
		for (i = 1; i < argc; i++)
			walk_dir(argv[i]);

	return exit_status;
}
