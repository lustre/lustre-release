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
#include <sys/param.h>
#include <err.h>

#include <linux/lustre/lustre_idl.h>
#include <lustre/lustreapi.h>

#define syserr(exp, str, args...)					\
do {									\
	if (exp)							\
		errx(EXIT_FAILURE, "%d: "str, __LINE__, ##args);	\
} while (0)

#define syserrx(exp, str, args...)					\
do {									\
	if (exp)							\
		errx(EXIT_FAILURE, "%d: "str, __LINE__, ##args);	\
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

static size_t add_tids(__u16 *ids, size_t count, char *arg)
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

	__u16 ids[4096] = { 0 };
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

enum resync_errors {
	AFTER_RESYNC_START	= 1 << 0,
	INVALID_IDS		= 1 << 1,
	ZERO_RESYNC_IDS		= 1 << 2,
	DELAY_BEFORE_COPY	= 1 << 3,
	OPEN_TEST_FILE		= 1 << 4,
};

static enum resync_errors resync_parse_error(const char *err)
{
	struct {
		const char *loc;
		enum resync_errors error;
	} cmds[] = {
		{ "resync_start", AFTER_RESYNC_START },
		{ "invalid_ids", INVALID_IDS },
		{ "zero_resync_ids", ZERO_RESYNC_IDS },
		{ "delay_before_copy", DELAY_BEFORE_COPY },
		{ "open_test_file", OPEN_TEST_FILE },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(cmds); i++)
		if (strcmp(err, cmds[i].loc) == 0)
			return cmds[i].error;

	fprintf(stderr, "unknown error string: %s\n", err);
	return -1;
}

static void mirror_resync(int argc, char *argv[])
{
	const char *fname;
	int error_inject = 0;
	int fd;
	int c;
	int rc;
	int delay = 2;
	int idx;

	struct llapi_layout *layout;
	struct ll_ioc_lease *ioc;
	struct llapi_resync_comp comp_array[1024] = { { 0 } };
	size_t comp_size = 0;
	uint32_t flr_state;
	uint64_t start;
	uint64_t end;

	opterr = 0;
	while ((c = getopt(argc, argv, "e:d:")) != -1) {
		switch (c) {
		case 'e':
			error_inject |= resync_parse_error(optarg);
			break;
		case 'd':
			delay = atol(optarg);
			break;
		default:
			errx(1, "unknown option: '%s'", argv[optind - 1]);
		}
	}

	if (argc > optind + 1)
		errx(1, "too many files");
	if (argc == optind)
		errx(1, "no file name given");

	fname = argv[optind];
	fd = open_file(fname);

	/* set the lease on the file */
	ioc = calloc(sizeof(*ioc) + sizeof(__u32) * 4096, 1);
	syserr(ioc == NULL, "no memory");

	ioc->lil_mode = LL_LEASE_WRLCK;
	ioc->lil_flags = LL_LEASE_RESYNC;
	rc = llapi_lease_set(fd, ioc);
	if (rc < 0)
		free(ioc);
	syserr(rc < 0, "llapi_lease_set resync");

	if (error_inject & AFTER_RESYNC_START) {
		free(ioc);
		syserrx(1, "hit by error injection");
	}

	layout = llapi_layout_get_by_fd(fd, 0);
	if (layout == NULL)
		free(ioc);
	syserr(layout == NULL, "llapi_layout_get_by_fd");

	rc = llapi_layout_flags_get(layout, &flr_state);
	if (rc)
		free(ioc);
	syserr(rc, "llapi_layout_flags_get");

	flr_state &= LCM_FL_FLR_MASK;
	if (flr_state != LCM_FL_WRITE_PENDING &&
	    flr_state != LCM_FL_SYNC_PENDING) {
		free(ioc);
		syserrx(true, "file state error: %d", flr_state);
	}

	if (error_inject & DELAY_BEFORE_COPY)
		sleep(delay);

	comp_size = llapi_mirror_find_stale(layout, comp_array,
					    ARRAY_SIZE(comp_array), NULL, 0);

	printf("%s: found %zd stale components\n", fname, comp_size);

	/* get the read range [start, end) */
	start = comp_array[0].lrc_start;
	end = comp_array[0].lrc_end;
	for (idx = 1; idx < comp_size; idx++) {
		if (comp_array[idx].lrc_start < start)
			start = comp_array[idx].lrc_start;
		if (end < comp_array[idx].lrc_end)
			end = comp_array[idx].lrc_end;
	}

	rc = llapi_lease_check(fd);
	if (rc != LL_LEASE_WRLCK) {
		free(ioc);
		syserr(rc != LL_LEASE_WRLCK, "lost lease lock");
	}

	rc = llapi_mirror_resync_many(fd, layout, comp_array, comp_size, start,
				      end);
	if (rc < 0)
		free(ioc);
	syserrx(rc < 0, "llapi_mirror_resync_many");

	/* prepare ioc for lease put */
	ioc->lil_mode = LL_LEASE_UNLCK;
	ioc->lil_flags = LL_LEASE_RESYNC_DONE;
	ioc->lil_count = 0;
	for (idx = 0; idx < comp_size; idx++) {
		if (comp_array[idx].lrc_synced) {
			ioc->lil_ids[ioc->lil_count] = comp_array[idx].lrc_id;
			ioc->lil_count++;
		}
	}

	if (error_inject & ZERO_RESYNC_IDS)
		ioc->lil_count = 0;

	if (error_inject & INVALID_IDS && ioc->lil_count > 0)
		ioc->lil_ids[ioc->lil_count - 1] = 567; /* inject error */

	llapi_layout_free(layout);

	if (error_inject & OPEN_TEST_FILE) /* break lease */
		close(open(argv[optind], O_RDONLY));

	rc = llapi_lease_set(fd, ioc);
	syserr(rc <= 0, "llapi_lease_set resync failed");
	if (rc <= 0)
		llapi_lease_release(fd);

	free(ioc);
	close(fd);
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
	{ "resync", mirror_resync,
	  "resync mirrors: [-e error] [-d delay] FILE" },
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
