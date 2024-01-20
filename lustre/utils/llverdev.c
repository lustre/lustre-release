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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 *
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/llverdev.c
 *
 * Large Block Device Verification Tool.
 * This program is used to test whether the block device is correctly
 * handling IO beyond 2TB boundary.
 * This tool have two working modes
 * 1. full mode
 * 2. partial mode
 *
 * In full mode, the program writes a test pattern on the entire disk.
 * The test pattern (device offset and timestamp) is written at the
 * beginning of each 4kB block. When the whole device is full the read
 * operation is performed to verify that the test pattern is correct.
 *
 * In partial mode, the program writes data at the critical locations
 * of the device such as start of the device, before and after multiple of 1GB
 * offset and at the end.
 *
 * A chunk buffer with default size of 1MB is used to write and read test
 * pattern in bulk.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef LUSTRE_UTILS
#define LUSTRE_UTILS
#endif
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include <features.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/time.h>
#include <gnu/stubs.h>

#define ONE_MB (1024 * 1024)
#define ONE_GB (1024 * 1024 * 1024)
#define HALF_MB (ONE_MB / 2)
#define ONE_KB 1024
#define HALF_KB (ONE_KB / 2)
#define BLOCKSIZE 4096
#define MAX_ALLOWED_IO_ERR 100

/* Structure for writting test pattern */
struct block_data {
	unsigned long long bd_offset;
	unsigned long long bd_time;
	unsigned long long bd_inode;
};

static char *progname;		 /* name by which this program was run. */
static unsigned int verbose = 1; /* prints offset in kB, operation rate */
static int readoption;		 /* run test in read-only (verify) mode */
static int writeoption;		 /* run test in write_only mode */
const char *devname;		 /* name of device to be tested. */
static unsigned int full = 1;	 /* flag to full check */
static int error_count;		 /* number of IO errors hit during run */
static ino_t ino_st;		 /* inode number of file under test */
static int isatty_flag;

static struct option const long_opts[] = {
	{ .val = 'c',	.name = "chunksize",	.has_arg = required_argument },
	{ .val = 'f',	.name = "force",	.has_arg = no_argument },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'l',	.name = "long",		.has_arg = no_argument },
	{ .val = 'l',	.name = "full",		.has_arg = no_argument },
	{ .val = 'o',	.name = "offset",	.has_arg = required_argument },
	{ .val = 'p',	.name = "partial",	.has_arg = required_argument },
	{ .val = 'q',	.name = "quiet",	.has_arg = required_argument },
	{ .val = 'r',	.name = "read",		.has_arg = no_argument },
	{ .val = 's',	.name = "size",		.has_arg = required_argument },
	{ .val = 't',	.name = "timestamp",	.has_arg = required_argument },
	{ .val = 'v',	.name = "verbose",	.has_arg = no_argument },
	{ .val = 'w',	.name = "write",	.has_arg = no_argument },
	{ .name = NULL } };

/*
 * Usage: displays help information, whenever user supply --help option in
 * command or enters incorrect command line.
 */
static void usage(int status)
{
	if (status != 0) {
		printf("\nUsage: %s [OPTION]... <device-name> ...\n",
		       progname);
		printf("Block device verification tool.\n"
		       "\t-c|--chunksize chunk_mb, IO size in MB, default=1\n"
		       "\t-f|--force, force test to run without confirmation\n"
		       "\t-h|--help, display this help and exit\n"
		       "\t-l|--long, --full check of device\n"
		       "\t-o|--offset, offset in kB from start of file\n"
		       "\t-p|--partial, for partial check (1GB steps)\n"
		       "\t-q|--quiet\n"
		       "\t-r|--read, run in verify mode\n"
		       "\t-s|--size, file/device size in MB to read/write\n"
		       "\t-t|--timestamp seconds, set verification timestamp\n"
		       "\t-v|--verbose\n"
		       "\t-w|--write, run in test-pattern mode, default=rw\n"
		       );
	}
	exit(status);
}

/*
 * Open_dev: Opens device in specified mode and returns fd.
 */
static int open_dev(const char *devname, int mode)
{
	int fd;

	fd = open(devname, mode | O_EXCL | O_LARGEFILE);
	if (fd < 0) {
		fprintf(stderr, "%s: Open failed: %s\n",
			progname, strerror(errno));
		exit(3);
	}
	return fd;
}

/*
 * sizeof_dev: Returns size of device in bytes
 */
static size_t sizeof_dev(int fd, unsigned long long dev_size)
{
	unsigned long long numbytes = 0;
	struct stat statbuf;

	if (fstat(fd, &statbuf) == 0) {
		ino_st = statbuf.st_ino;
		if (S_ISREG(statbuf.st_mode)) {
			if (dev_size)
				numbytes = dev_size;
			else if (statbuf.st_size > 1)
				numbytes = statbuf.st_size;
			else
				numbytes = (~0ULL >> 1);
			goto out;
		}
		if (!S_ISBLK(statbuf.st_mode)) {
			fprintf(stderr, "%s: '%s' not a block device or file\n",
				progname, devname);
			goto out;
		}
	} else {
		fprintf(stderr, "%s: error accessing '%s': %s\n",
			progname, devname, strerror(errno));
	}
#if defined BLKGETSIZE64	/* in sys/mount.h */
	if (ioctl(fd, BLKGETSIZE64, &numbytes) >= 0)
		goto out;
#endif
#if defined BLKGETSIZE		/* in sys/mount.h */
	{
		unsigned long sectors;

		if (ioctl(fd, BLKGETSIZE, &sectors) >= 0) {
			numbytes = (loff_t)sectors << 9;
			goto out;
		}
	}
#endif
	fprintf(stderr, "%s: unable to determine size of %s\n",
		progname, devname);

out:
	if (dev_size && dev_size < numbytes)
		numbytes = dev_size;
	return numbytes;
}

/*
 * Verify_chunk: Verifies test pattern in each 4kB (BLOCKSIZE) is correct.
 * Returns 0 if test offset and timestamp is correct otherwise 1.
 */
static int verify_chunk(char *chunk_buf, const size_t chunksize,
			unsigned long long chunk_off,
			const unsigned long long time_st,
			const unsigned long long inode_st,
			const char *file)
{
	struct block_data *bd;
	char *chunk_end;

	for (chunk_end = chunk_buf + chunksize - sizeof(*bd);
	     (char *)chunk_buf < chunk_end;
	     chunk_buf += BLOCKSIZE, chunk_off += BLOCKSIZE) {
		bd = (struct block_data *)chunk_buf;
		if ((bd->bd_offset == chunk_off) && (bd->bd_time == time_st) &&
		    (bd->bd_inode == inode_st))
			continue;

		fprintf(stderr,
			"\n%s: verify %s failed offset/timestamp/inode %llu/%llu/%llu: found %llu/%llu/%llu instead\n",
			progname, file, chunk_off, time_st, inode_st,
			bd->bd_offset, bd->bd_time, bd->bd_inode);
		error_count++;
		return 1;
	}
	return 0;
}

/*
 * fill_chunk: Fills the chunk with current or user specified timestamp
 * and offset. The test pattern is filled at the beginning of
 * each 4kB(BLOCKSIZE) blocks in chunk_buf.
 */
static void fill_chunk(char *chunk_buf, size_t chunksize, loff_t chunk_off,
		       const time_t time_st, const ino_t inode_st)
{
	struct block_data *bd;
	char *chunk_end;

	for (chunk_end = chunk_buf + chunksize - sizeof(*bd);
	     (char *)chunk_buf < chunk_end;
	     chunk_buf += BLOCKSIZE, chunk_off += BLOCKSIZE) {
		bd = (struct block_data *)chunk_buf;
		bd->bd_offset = chunk_off;
		bd->bd_time = time_st;
		bd->bd_inode = inode_st;
	}
}

static void show_rate(char *op, unsigned long long offset,
		      unsigned long long count)
{
	static unsigned long long subtot, total;
	static time_t start, last;
	time_t now;
	double diff;

	now = time(NULL);
	if (!start)
		start = now;
	if (count == 0) {
		subtot = total;
		last = start;
	} else {
		subtot += count;
		total += count;
	}
	diff = now - last;

	if ((verbose > 1 && diff >= (verbose > 3 ? 1 : 5)) || count == 0) {
		if (last != 0) {
			if (isatty_flag)
				printf("\r");
			printf("%s offset: %14llukB %5g MB/s            ", op,
			       offset / ONE_KB, (double)subtot / ONE_MB / diff);
			if (isatty_flag && count)
				fflush(stdout);
			else
				printf("\n");

			subtot = 0;
		}
		if (count == 0)
			subtot = total = start = last = 0;
		else
			last = now;
	}
}

/*
 * Write a chunk to disk, handling errors, interrupted writes, etc.
 *
 * If there is an IO error hit during the write, it is possible that
 * this will just show up as a short write, and a subsequent write
 * will return the actual error.  We want to continue in the face of
 * minor media errors so that we can validate the whole device if
 * possible, but if there are many errors we don't want to loop forever.
 *
 * The error count will be returned upon exit to ensure that the
 * media errors are detected even if nobody is looking at the output.
 *
 * Returns 0 on success, or -ve errno on failure.
 */
static size_t write_retry(int fd, const char *chunk_buf, size_t nrequested,
			  unsigned long long offset, const char *file)
{
	long nwritten;

retry:
	nwritten = pwrite(fd, chunk_buf, nrequested, offset);
	if (nwritten < 0) {
		if (errno != ENOSPC) {
			fprintf(stderr, "\n%s: write %s@%llu+%zi failed: %s\n",
				progname, file, offset, nrequested,
				strerror(errno));
			if (error_count++ < MAX_ALLOWED_IO_ERR)
				return 0;
		}
		return -errno;
	}
	if (nwritten < nrequested) {
		fprintf(stderr, "\n%s: write %s@%llu+%zi short: %ld/%ld\n",
			progname, file, offset, nrequested, nwritten,
			nrequested);
		offset += nwritten;
		chunk_buf += nwritten;
		nrequested -= nwritten;
		goto retry;
	}

	return 0;
}

/*
 * write_chunks: write the chunk_buf on the device. The number of write
 * operations are based on the parameters write_end, offset, and chunksize.
 *
 * Returns 0 on success, or -ve error number on failure.
 */
static int write_chunks(int fd, unsigned long long offset,
			unsigned long long *write_end, char *chunk_buf,
			size_t chunksize, const time_t time_st,
			const ino_t inode_st, const char *file)
{
	unsigned long long stride;

	stride = full ? chunksize : ONE_GB;
	for (offset = offset & ~(chunksize - 1); offset < *write_end;
	     offset += stride) {
		int ret;

		if (offset + chunksize > *write_end)
			chunksize = *write_end - offset;
		fill_chunk(chunk_buf, chunksize, offset, time_st, inode_st);
		ret = write_retry(fd, chunk_buf, chunksize, offset, file);
		if (ret < 0) {
			if (ret == -ENOSPC)
				*write_end = offset - stride;
			return ret;
		}

		show_rate("write", offset, chunksize);
	}

	if (fsync(fd) == -1) {
		fprintf(stderr, "%s: fsync failed: %s\n", progname,
			strerror(errno));
		return -errno;
	}
	return 0;
}

/*
 * read_chunk: reads the chunk_buf from the device. The number of read
 * operations are based on the parameters read_end, offset, and chunksize.
 */
static int read_chunks(int fd, unsigned long long offset,
		       unsigned long long read_end, char *chunk_buf,
		       size_t chunksize, const time_t time_st,
		       const ino_t inode_st, const char *file)
{
	unsigned long long stride;

	if (ioctl(fd, BLKFLSBUF, 0) < 0 && verbose > 1)
		fprintf(stderr, "%s: ioctl BLKFLSBUF failed: %s (ignoring)\n",
			progname, strerror(errno));

	stride = full ? chunksize : ONE_GB;
	for (offset = offset & ~(chunksize - 1); offset < read_end;
	     offset += stride) {
		ssize_t nread, rc;

		if (offset + chunksize > read_end)
			chunksize = read_end - offset;

		nread = 0;
		/* reset errno before calling pread */
		errno = 0;
read_more:
		rc = pread(fd, chunk_buf + nread, chunksize - nread,
			   offset + nread);
		if (rc == 0) {
			fprintf(stderr, "\n%s: read %s@%llu+%zi no data: %s\n",
				progname, file, offset + nread,
				chunksize - nread, strerror(errno));
			break;
		}
		if (rc < 0) {
			fprintf(stderr, "\n%s: read %s@%llu+%zi failed: %s\n",
				progname, file, offset + nread,
				chunksize - nread, strerror(errno));
			if (error_count++ < MAX_ALLOWED_IO_ERR)
				continue;
			return -errno;
		}
		nread += rc;
		if (nread < chunksize) {
			fprintf(stderr,
				"\n%s: read %s@%llu+%zi short: %zi/%zi\n",
				progname, file, offset + nread,
				chunksize - nread, rc, chunksize);
			goto read_more;
		}

		if (verify_chunk(chunk_buf, chunksize, offset, time_st,
				 inode_st, file) != 0)
			return 1;

		show_rate("read", offset, chunksize);
	}
	return 0;
}

static int parse_size(const char *optarg, unsigned long long *size,
		      unsigned long long size_units)
{
	char *end;

	*size = strtoull(optarg, &end, 0);
	if (*end != '\0') {
		size_units = 1;
		switch (*end) {
		case 'e': case 'E': size_units <<= 10; /* fallthrough */
		case 'p': case 'P': size_units <<= 10; /* fallthrough */
		case 't': case 'T': size_units <<= 10; /* fallthrough */
		case 'g': case 'G': size_units <<= 10; /* fallthrough */
		case 'm': case 'M': size_units <<= 10; /* fallthrough */
		case 'k': case 'K': size_units <<= 10; break;
		default:
			return -1;
		}
	}
	*size *= size_units;

	return 0;
}

int main(int argc, char **argv)
{
	unsigned long long chunksize = ONE_MB; /* IO chunk size */
	unsigned long long offset = 0; /* offset in kB */
	unsigned long long dev_size = 0;
	unsigned int force = 0; /* run test run without confirmation*/
	time_t time_st = 0; /* Default timestamp */
	char *chunk_buf = NULL;
	char yesno[4];
	int mode = O_RDWR; /* mode which device should be opened */
	int error = 0, c;
	int fd;

	progname = !strrchr(argv[0], '/') ? argv[0] : strrchr(argv[0], '/') + 1;
	while ((c = getopt_long(argc, argv, "c:fhlo:pqrs:t:vw", long_opts,
				NULL)) != -1) {
		switch (c) {
		case 'c':
			if (parse_size(optarg, &chunksize, ONE_MB)) {
				fprintf(stderr, "%s: bad chunksize '%s'\n",
					progname, optarg);
				return -1;
			}
			if (chunksize > ONE_GB || chunksize < 4096) {
				fprintf(stderr,
					"%s: valid chunksize 4KB-1GB, not '%s'\n",
					progname, optarg);
				return -1;
			}
			break;
		case 'f':
			force = 1;
			break;
		case 'l':
			full = 1;
			break;
		case 'o':
			if (parse_size(optarg, &offset, ONE_KB)) {
				fprintf(stderr, "%s: bad offset '%s'\n",
					progname, optarg);
				return -1;
			}
			break;
		case 'p':
			full = 0;
			break;
		case 'q':
			verbose = 0;
			break;
		case 'r':
			readoption = 1;
			mode = O_RDONLY;
			break;
		case 's':
			if (parse_size(optarg, &dev_size, ONE_MB)) {
				fprintf(stderr, "%s: bad size '%s'\n",
					progname, optarg);
				return -1;
			}
			break;
		case 't':
			time_st = (time_t)strtoul(optarg, NULL, 0);
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			writeoption = 1;
			mode = O_WRONLY;
			break;
		case 'h':
		default:
			usage(1);
			return 0;
		}
	}
	devname = argv[optind];
	if (!devname) {
		fprintf(stderr, "%s: device name not given\n", progname);
		usage(1);
		return -1;
	}

	if (readoption && writeoption)
		mode = O_RDWR;
	if (!readoption && !writeoption) {
		readoption = 1;
		writeoption = 1;
	}

	if (!force && writeoption) {
		printf("%s: permanently overwrite all data on %s (yes/no)? ",
		       progname, devname);
		if (scanf("%3s", yesno) == EOF && ferror(stdin)) {
			perror("reading from stdin");
			return -1;
		}
		if (!(strcasecmp("yes", yesno) || strcasecmp("y", yesno))) {
			printf("Not continuing due to '%s' response", yesno);
			return 0;
		}
	}

	if (!writeoption && time_st == 0) {
		fprintf(stderr, "%s: must give timestamp for read-only test\n",
			progname);
		usage(1);
	}

	fd = open_dev(devname, mode);
	dev_size = sizeof_dev(fd, dev_size);
	if (verbose)
		printf("%s: %s is %llu bytes (%g GB) in size\n",
		       progname, devname, dev_size, (double)dev_size / ONE_GB);

	if (!dev_size) {
		fprintf(stderr, "%s: cannot test on device size < 1MB\n",
			progname);
		error = 7;
		goto close_dev;
	}

	if (offset >= dev_size - chunksize) {
		fprintf(stderr, "%s: offset %llu >= device size %llu\n",
			progname, offset, dev_size);
		error = 6;
		goto close_dev;
	}
	if (!time_st)
		(void)time(&time_st);

	isatty_flag = isatty(STDOUT_FILENO);

	if (verbose)
		printf("timestamp: %lu chunksize: %llu size: %llu\n",
		       time_st, chunksize, dev_size);

	chunk_buf = (char *)calloc(chunksize, 1);
	if (!chunk_buf) {
		fprintf(stderr, "%s: memory allocation failed for chunk_buf\n",
			progname);
		error = 4;
		goto close_dev;
	}
	if (writeoption) {
		c = write_chunks(fd, offset, &dev_size, chunk_buf, chunksize,
				 time_st, ino_st, devname);
		if (c < 0 && c != -ENOSPC) {
			error = 3;
			goto chunk_buf;
		}
		if (!full && c != -ENOSPC) { /* end of device block-aligned */
			offset = ((dev_size - chunksize + BLOCKSIZE - 1) &
				  ~(BLOCKSIZE - 1));
			c = write_chunks(fd, offset, &dev_size, chunk_buf,
					 chunksize, time_st, ino_st, devname);
			if (c < 0 && c != -ENOSPC) {
				error = 3;
				goto chunk_buf;
			}
		}
		show_rate("write", dev_size, 0);
		if (verbose > 1)
			printf("write complete\n");
	}
	if (readoption) {
		if (read_chunks(fd, offset, dev_size, chunk_buf, chunksize,
				time_st, ino_st, devname)) {
			error = 2;
			goto chunk_buf;
		}
		if (!full && c != -ENOSPC) { /* end of device block-aligned */
			offset = ((dev_size - chunksize + BLOCKSIZE - 1) &
				  ~(BLOCKSIZE - 1));
			if (read_chunks(fd, offset, dev_size, chunk_buf,
					chunksize, time_st, ino_st, devname)) {
				error = 2;
				goto chunk_buf;
			}
		}
		show_rate("read", dev_size, 0);
		if (verbose > 1)
			printf("read complete\n");
		if (verbose)
			printf("%s: data verified successfully\n", progname);
	}
	error = error_count;
chunk_buf:
	free(chunk_buf);
close_dev:
	close(fd);
	return error;
}
