/*
 * GPL HEADDER START
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
 * Copyright 2015 Cray Inc, all rights reserved.
 * Author: Frank Zago.
 *
 * A few portions are extracted from llapi_layout_test.c
 */

/*
 * The CRC32 implementation is from RFC 1952, which bears the
 * following notice:
 *
 * Copyright (c) 1996 L. Peter Deutsch
 *
 * Permission is granted to copy and distribute this document for any
 * purpose and without charge, including translations into other
 * languages and incorporation into compilations, provided that the
 * copyright notice and this notice are preserved, and that any
 * substantive changes or deletions from the original are clearly
 * marked.
 */

/*
 * The purpose of this test is to exert the group lock ioctls in
 * conjunction with sendfile. Some bugs were found when both were used
 * at the same time. See LU-6368 and LU-6371.
 *
 * The program will exit as soon as a non zero error code is returned.
 *
 * It can be called like this:
 *
 * dd if=/dev/zero of=/mnt/lustre/foo1 bs=1M count=40
 * ./sendfile_grouplock /mnt/lustre/foo1
 */

#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <poll.h>
#include <sys/sendfile.h>

#include <lustre/lustreapi.h>
#include <lustre/lustre_idl.h>

#define ERROR(fmt, ...)							\
	fprintf(stderr, "%s: %s:%d: %s: " fmt "\n",			\
		program_invocation_short_name, __FILE__, __LINE__,	\
		__func__, ## __VA_ARGS__);

#define DIE(fmt, ...)				\
	do {					\
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
		fprintf(stderr, "Starting test " #testfn " at %lld\n",	\
			(unsigned long long)time(NULL));		\
		testfn();						\
		fprintf(stderr, "Finishing test " #testfn " at %lld\n",	\
			(unsigned long long)time(NULL));		\
	} while (0)

/* This test will copy from source_file to dest_file */
static const char *source_file;
static char *dest_file;
static unsigned long source_crc; /* CRC32 of original file */

/*
 * A small CRC32 implementation, from RFC 1952
 */

/* Table of CRCs of all 8-bit messages. */
static unsigned long crc_table[256];

/* Flag: has the table been computed? Initially false. */
static int crc_table_computed;

/* Make the table for a fast CRC. */
static void make_crc_table(void)
{
	unsigned long c;

	int n, k;
	for (n = 0; n < 256; n++) {
		c = (unsigned long) n;
		for (k = 0; k < 8; k++) {
			if (c & 1)
				c = 0xedb88320L ^ (c >> 1);
			else
				c = c >> 1;
		}
		crc_table[n] = c;
	}
	crc_table_computed = 1;
}

/*
 * Update a running crc with the bytes buf[0..len-1] and return the
 * updated crc. The crc should be initialized to zero. Pre- and
 * post-conditioning (one's complement) is performed within this
 * function so it shouldn't be done by the caller. Usage example:
 *
 *	unsigned long crc = 0L;
 *
 *	while (read_buffer(buffer, length) != EOF) {
 *		crc = update_crc(crc, buffer, length);
 *	}
 *	if (crc != original_crc) error();
 */
static unsigned long update_crc(unsigned long crc,
				unsigned char *buf, int len)
{
	unsigned long c = crc ^ 0xffffffffL;
	int n;

	if (!crc_table_computed)
		make_crc_table();
	for (n = 0; n < len; n++)
		c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);

	return c ^ 0xffffffffL;
}

/* Cleanup our test file. */
static void cleanup(void)
{
	unlink(dest_file);
}

/* Compute the CRC32 of a file */
static unsigned long compute_crc(const char *fname)
{
	unsigned char buf[1024*1024];
	unsigned long crc = 0L;
	struct stat stbuf;
	int fd;
	int rc;
	size_t filesize;

	fd = open(fname, O_RDONLY);
	ASSERTF(fd >= 0, "open failed for '%s': %s",
		fname, strerror(errno));

	rc = fstat(fd, &stbuf);
	ASSERTF(rc == 0, "fstat of '%s' failed: %s", fname, strerror(errno));
	filesize = stbuf.st_size;

	while (filesize != 0) {
		size_t to_read = sizeof(buf);
		ssize_t sret;

		if (to_read > filesize)
			to_read = filesize;

		sret = read(fd, buf, to_read);
		ASSERTF(sret >= 0, "read of %zu bytes from '%s' failed: %s",
			to_read, fname, strerror(errno));
		ASSERTF(sret > 0, "unexpected EOF for '%s'",
			fname);

		filesize -= sret;
		crc = update_crc(crc, buf, sret);
	}

	close(fd);

	return crc;
}

/* Helper. Copy a file with sendfile. The destination will be
 * created. If a group lock is 0, it means do not take one. */
static int sendfile_copy(const char *source, int source_gid,
			 const char *dest, int dest_gid)
{
	int rc;
	struct stat stbuf;
	size_t filesize;
	int fd_in;
	int fd_out;

	fd_in = open(source, O_RDONLY);
	ASSERTF(fd_in >= 0, "open failed for '%s': %s",
		source, strerror(errno));

	rc = fstat(fd_in, &stbuf);
	ASSERTF(rc == 0, "fstat of '%s' failed: %s", source, strerror(errno));
	filesize = stbuf.st_size;

	if (source_gid != 0) {
		rc = llapi_group_lock(fd_in, source_gid);
		ASSERTF(rc == 0, "cannot set group lock %d for '%s': %s",
			source_gid, source, strerror(-rc));
	}

	fd_out = open(dest, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	ASSERTF(fd_out >= 0, "creation failed for '%s': %s",
		dest, strerror(errno));

	if (dest_gid != 0) {
		rc = llapi_group_lock(fd_out, dest_gid);
		ASSERTF(rc == 0, "cannot set group lock %d for '%s': %s",
			dest_gid, dest, strerror(-rc));
	}

	/* Transfer by 10M blocks */
	while (filesize != 0) {
		size_t to_copy = 10*1024*1024;
		ssize_t sret;

		if (to_copy > filesize)
			to_copy = filesize;

		sret = sendfile(fd_out, fd_in, NULL, to_copy);
		rc = errno;

		/* Although senfile can return less than requested,
		 * that should not happen under present conditions. At
		 * the very least, make sure that a decent size was
		 * copied. See LU-6371. */

		ASSERTF(sret != 0, "sendfile read 0 bytes");
		ASSERTF(sret > 0, "sendfile failed: %s", strerror(rc));
		ASSERTF(sret > 100*1024,
			"sendfile read too little data: %zd bytes", sret);

		if (sret != to_copy)
			fprintf(stderr,
			       "Warning: sendfile returned %zd bytes instead of %zu requested\n",
			       sret, to_copy);

		filesize -= sret;

	}

	close(fd_out);
	close(fd_in);

	return 0;
}

/* Basic sendfile, without lock taken */
static void test10(void)
{
	unsigned long crc;

	cleanup();
	sendfile_copy(source_file, 0, dest_file, 0);
	sync();

	crc = compute_crc(dest_file);
	ASSERTF(source_crc == crc, "CRC differs: %lu and %lu", source_crc, crc);
}

/* sendfile, source locked */
static void test11(void)
{
	unsigned long crc;

	cleanup();
	sendfile_copy(source_file, 85543, dest_file, 0);
	sync();

	crc = compute_crc(dest_file);
	ASSERTF(source_crc == crc, "CRC differs: %lu and %lu", source_crc, crc);
}

/* sendfile, destination locked */
static void test12(void)
{
	unsigned long crc;

	cleanup();
	sendfile_copy(source_file, 0, dest_file, 98765);
	sync();

	crc = compute_crc(dest_file);
	ASSERTF(source_crc == crc, "CRC differs: %lu and %lu", source_crc, crc);
}

/* sendfile, source and destination locked, with same lock number */
static void test13(void)
{
	const int gid = 8765;
	unsigned long crc;

	cleanup();
	sendfile_copy(source_file, gid, dest_file, gid);
	sync();

	crc = compute_crc(dest_file);
	ASSERTF(source_crc == crc, "CRC differs: %lu and %lu", source_crc, crc);
}

/* sendfile, source and destination locked, with different lock number */
static void test14(void)
{
	unsigned long crc;

	cleanup();
	sendfile_copy(source_file, 98765, dest_file, 34543);
	sync();

	crc = compute_crc(dest_file);
	ASSERTF(source_crc == crc, "CRC differs: %lu and %lu", source_crc, crc);
}

/* Basic sendfile, without lock taken, to /dev/null */
static void test15(void)
{
	sendfile_copy(source_file, 0, "/dev/null", 0);
	sync();
}

/* sendfile, source locked, to /dev/null */
static void test16(void)
{
	sendfile_copy(source_file, 85543, "/dev/null", 0);
	sync();
}

int main(int argc, char *argv[])
{
	int rc;

	if (argc != 2 || argv[1][0] != '/') {
		fprintf(stderr,
			"Argument must be an absolute path to a Lustre file\n");
		return EXIT_FAILURE;
	}

	source_file = argv[1];
	rc = asprintf(&dest_file, "%s-dest", source_file);
	if (rc == -1) {
		fprintf(stderr, "Allocation failure\n");
		return EXIT_FAILURE;
	}

	/* Play nice with Lustre test scripts. Non-line buffered output
	 * stream under I/O redirection may appear incorrectly. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	cleanup();
	atexit(cleanup);

	/* Compute crc of original file */
	source_crc = compute_crc(source_file);

	PERFORM(test10);
	PERFORM(test11);
	PERFORM(test12);
	PERFORM(test13);
	PERFORM(test14);
	PERFORM(test15);
	PERFORM(test16);

	return EXIT_SUCCESS;
}
