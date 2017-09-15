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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2017, Intel Corporation. All rights reserved.
 * Use is subject to license terms.
 *
 * lustre/tests/mirror_io.c
 *
 * Lustre mirror test tool.
 *
 * Author: Jinshan Xiong <jinshan.xiong@intel.com>
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <err.h>

#include <lustre/lustreapi.h>

#define syserr(exp, str, args...)			\
do {							\
	if (exp)					\
		err(EXIT_FAILURE, str, ##args);		\
} while (0)

#define syserrx(exp, str, args...)			\
do {							\
	if (exp)					\
		errx(EXIT_FAILURE, str, ##args);	\
} while (0)

#define ARRAY_SIZE(a) ((sizeof(a)) / (sizeof((a)[0])))

static const char *progname;

static void usage(void);

static int open_file(const char *fname)
{
	struct stat stbuf;
	int fd;

	if (stat(fname, &stbuf) < 0)
		err(1, "%s", fname);

	if (!S_ISREG(stbuf.st_mode))
		errx(1, "%s: '%s' is not a regular file", progname, fname);

	fd = open(fname, O_DIRECT | O_RDWR);
	syserr(fd < 0, "open %s", fname);

	return fd;
}

static size_t get_ids(int fd, unsigned int *ids)
{
	struct llapi_layout *layout;
	size_t count = 0;
	int rc;

	layout = llapi_layout_get_by_fd(fd, 0);
	syserrx(layout == NULL, "layout is NULL");

	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	syserrx(rc < 0, "first component");

	do {
		unsigned int id;

		rc = llapi_layout_mirror_id_get(layout, &id);
		syserrx(rc < 0, "id get");

		if (!count || ids[count - 1] != id)
			ids[count++] = id;

		rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
		syserrx(rc < 0, "move to next");
	} while (rc == 0);

	llapi_layout_free(layout);

	return count;
}

static void check_id(int fd, unsigned int id)
{
	unsigned int ids[LUSTRE_MIRROR_COUNT_MAX];
	size_t count;
	bool found = false;
	int i;

	count = get_ids(fd, ids);
	for (i = 0; i < count; i++) {
		if (id == ids[i]) {
			found = true;
			break;
		}
	}

	syserr(!found, "cannot find the mirror id: %d", id);
}

static void mirror_dump(int argc, char *argv[])
{
	const char *outfile = NULL;
	int id = -1;
	int fd;
	int outfd;
	int c;
	const size_t buflen = 4 * 1024 * 1024;
	void *buf;
	off_t pos;

	opterr = 0;
	while ((c = getopt(argc, argv, "i:o:")) != -1) {
		switch (c) {
		case 'i':
			id = atol(optarg);
			break;

		case 'o':
			outfile = optarg;
			break;

		default:
			errx(1, "unknown option: '%s'", argv[optind - 1]);
		}
	}

	if (argc > optind + 1)
		errx(1, "too many files");
	if (argc == optind)
		errx(1, "no file name given");

	syserrx(id < 0, "mirror id is not set");

	fd = open_file(argv[optind]);

	check_id(fd, id);

	if (outfile) {
		outfd = open(outfile, O_EXCL | O_WRONLY | O_CREAT, 0644);
		syserr(outfd < 0, "open %s", outfile);
	} else {
		outfd = STDOUT_FILENO;
	}

	c = posix_memalign(&buf, sysconf(_SC_PAGESIZE), buflen);
	syserr(c, "posix_memalign");

	pos = 0;
	while (1) {
		ssize_t bytes_read;
		ssize_t written;

		bytes_read = llapi_mirror_read(fd, id, buf, buflen, pos);
		if (!bytes_read)
			break;

		syserrx(bytes_read < 0, "mirror read");

		written = write(outfd, buf, bytes_read);
		syserrx(written < bytes_read, "short write");

		pos += bytes_read;
	}

	fsync(outfd);
	close(outfd);

	close(fd);

	free(buf);
}

static size_t add_tids(unsigned int *ids, size_t count, char *arg)
{
	while (*arg) {
		char *end;
		char *tmp;
		int id;
		int i;

		tmp = strchr(arg, ',');
		if (tmp)
			*tmp = 0;

		id = strtol(arg, &end, 10);
		syserrx(*end || id <= 0, "id string error: '%s'", arg);

		for (i = 0; i < count; i++)
			syserrx(id == ids[i], "duplicate id: %d", id);

		ids[count++] = (unsigned int)id;

		if (!tmp)
			break;

		arg = tmp + 1;
	}

	return count;
}

static void mirror_copy(int argc, char *argv[])
{
	int id = -1;
	int fd;
	int c;
	int i;

	unsigned int ids[4096] = { 0 };
	size_t count = 0;
	ssize_t result;

	opterr = 0;
	while ((c = getopt(argc, argv, "i:t:")) != -1) {
		switch (c) {
		case 'i':
			id = atol(optarg);
			break;

		case 't':
			count = add_tids(ids, count, optarg);
			break;

		default:
			errx(1, "unknown option: '%s'", argv[optind - 1]);
		}
	}

	if (argc > optind + 1)
		errx(1, "too many files");
	if (argc == optind)
		errx(1, "no file name given");

	syserrx(id < 0, "mirror id is not set");

	for (i = 0; i < count; i++)
		syserrx(id == ids[i], "src and dst have the same id");

	fd = open_file(argv[optind]);

	check_id(fd, id);

	result = llapi_mirror_copy_many(fd, id, ids, count);
	syserrx(result < 0, "copy error: %zd", result);

	fprintf(stdout, "mirror copied successfully: ");
	for (i = 0; i < result; i++)
		fprintf(stdout, "%d ", ids[i]);
	fprintf(stdout, "\n");

	close(fd);
}

/* XXX - does not work. Leave here as place holder */
static void mirror_ost_lv(int argc, char *argv[])
{
	int id = -1;
	int fd;
	int c;
	int rc;
	__u32 layout_version;

	opterr = 0;
	while ((c = getopt(argc, argv, "i:")) != -1) {
		switch (c) {
		case 'i':
			id = atol(optarg);
			break;

		default:
			errx(1, "unknown option: '%s'", argv[optind - 1]);
		}
	}

	if (argc > optind + 1)
		errx(1, "too many files");
	if (argc == optind)
		errx(1, "no file name given");

	syserrx(id < 0, "mirror id is not set");

	fd = open_file(argv[optind]);

	check_id(fd, id);

	rc = llapi_mirror_set(fd, id);
	syserr(rc < 0, "set mirror id error");

	rc = llapi_get_ost_layout_version(fd, &layout_version);
	syserr(rc < 0, "get ostlayoutversion error");

	llapi_mirror_clear(fd);
	close(fd);

	fprintf(stdout, "ostlayoutversion: %u\n", layout_version);
}

static void usage_wrapper(int argc, char *argv[])
{
	usage();
}

const struct subcommand {
	const char *name;
	void (*func)(int argc, char *argv[]);
	const char *helper;
} cmds[] = {
	{ "dump", mirror_dump, "dump mirror: <-i id> [-o file] FILE" },
	{ "copy", mirror_copy, "copy mirror: <-i id> <-t id1,id2> FILE" },
	{ "data_version", mirror_ost_lv, "ost layout version: <-i id> FILE" },
	{ "help", usage_wrapper, "print helper message" },
};

static void usage(void)
{
	int i;

	fprintf(stdout, "%s <command> [OPTIONS] [<FILE>]\n", progname);
	for (i = 0; i < ARRAY_SIZE(cmds); i++)
		fprintf(stdout, "\t%s - %s\n", cmds[i].name, cmds[i].helper);

	exit(0);
}

int main(int argc, char *argv[])
{
	bool found = false;
	int i;

	progname = basename(argv[0]);
	if (argc < 3)
		usage();

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		if (strcmp(cmds[i].name, argv[1]))
			continue;

		found = true;
		cmds[i].func(argc - 1, argv + 1);
		break;
	}

	if (!found) {
		syserrx(1, "unknown subcommand: '%s'", argv[1]);
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}
