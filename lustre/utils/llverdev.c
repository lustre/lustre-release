/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/utils/llverdev.c
 *
 * Large Block Device Verification Tool.
 * This program is used to test whether the block device is correctly
 * handling IO beyond 2TB boundary.
 * This tool have two working modes
 * 1. full mode
 * 2. fast mode
 *	The full mode is basic mode in which program writes the test pattern
 * on entire disk. The test pattern (device offset and timestamp) is written
 * at the beginning of each 4kB block. When the whole device is full then
 * read operation is performed to verify that the test pattern is correct.
 *	In the fast mode the program writes data at the critical locations
 * of the device such as start of the device, before and after multiple of 1GB
 * offset and at the end.
 *	A chunk buffer with default size of 1MB is used to write and read test
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

#ifdef HAVE_EXT2FS_EXT2FS_H
#  include <ext2fs/ext2fs.h>
#endif

#define ONE_MB (1024 * 1024)
#define ONE_GB (1024 * 1024 * 1024)
#define HALF_MB (ONE_MB / 2)
#define ONE_KB 1024
#define HALF_KB (ONE_KB / 2)
#define BLOCKSIZE 4096

/* Structure for writting test pattern */
struct block_data {
	long long  bd_offset;
	time_t  bd_time;
};
static char *progname;		/* name by which this program was run. */
static unsigned verbose = 1;	/* prints offset in kB, operation rate */
static int readoption;		/* run test in read-only (verify) mode */
static int writeoption;		/* run test in write_only mode */
const char *devname;		/* name of device to be tested. */
static unsigned full = 1;	/* flag to full check */
static int fd;
static int isatty_flag;

static struct option const longopts[] =
{
	{ "chunksize", required_argument, 0, 'c' },
	{ "force", no_argument, 0, 'f' },
	{ "help", no_argument, 0, 'h' },
	{ "offset", required_argument, 0, 'o' },
	{ "partial", required_argument, 0, 'p' },
	{ "quiet", required_argument, 0, 'q' },
	{ "read", no_argument, 0, 'r' },
	{ "timestamp", required_argument, 0, 't' },
	{ "verbose", no_argument, 0, 'v' },
	{ "write", no_argument, 0, 'w' },
	{ "long", no_argument, 0, 'l' },
	{ 0, 0, 0, 0}
};

/*
 * Usage: displays help information, whenever user supply --help option in
 * command or enters incorrect command line.
 */
void usage(int status)
{
	if (status != 0) {
	      printf("\nUsage: %s [OPTION]... <device-name> ...\n",
		     progname);
	      printf("Block device verification tool.\n"
		     "\t-t {seconds}, --timestamp, "
		     "set test time  (default=current time())\n"
		     "\t-o {offset}, --offset, "
		     "offset in kB of start of test, default=0\n"
		     "\t-r, --read run test in verify mode\n"
		     "\t-w, --write run test in test-pattern mode, default=rw\n"
		     "\t-v, --verbose\n"
		     "\t-q, --quiet\n"
		     "\t-l, --long, full check of device\n"
		     "\t-p, --partial, for partial check (1GB steps)\n"
		     "\t-c, --chunksize, IO chunk size, default=1048576\n"
		     "\t-f, --force, force test to run without confirmation\n"
		     "\t-h, --help display this help and exit\n");
	}
	exit(status);
}

/*
 * Open_dev: Opens device in specified mode and returns fd.
 */
static int open_dev(const char *devname, int mode)
{
#ifdef HAVE_EXT2FS_EXT2FS_H
	int	mount_flags;
	char	mountpt[80] = "";

	if (ext2fs_check_mount_point(devname, &mount_flags, mountpt,
				     sizeof(mountpt))) {
		fprintf(stderr, "%s: ext2fs_check_mount_point failed:%s",
			progname, strerror(errno));
		exit(1);
	}
	if (mount_flags & EXT2_MF_MOUNTED){
		fprintf(stderr, "%s: %s is already mounted\n", progname,
			devname);
		exit(1);
	}
#endif
	fd = open(devname, mode | O_EXCL | O_LARGEFILE);
	if (fd < 0) {
		fprintf(stderr, "%s: Open failed: %s",progname,strerror(errno));
		exit(3);
	}
	return (fd);
}

#undef HAVE_BLKID_BLKID_H /* sigh, RHEL3 systems do not have libblkid.so.1 */
#ifdef HAVE_BLKID_BLKID_H
#include <blkid/blkid.h>
#endif
/*
 * sizeof_dev: Returns size of device in bytes
 */
static loff_t sizeof_dev(int fd)
{
	loff_t numbytes;

#ifdef HAVE_BLKID_BLKID_H
	numbytes = blkid_get_dev_size(fd);
	if (numbytes <= 0) {
		fprintf(stderr, "%s: blkid_get_dev_size(%s) failed",
			progname, devname);
		return 1;
	}
	goto out;
#else
# if defined BLKGETSIZE64	/* in sys/mount.h */
	if (ioctl(fd, BLKGETSIZE64, &numbytes) >= 0)
		goto out;
# endif
# if defined BLKGETSIZE		/* in sys/mount.h */
	{
		unsigned long sectors;

		if (ioctl(fd, BLKGETSIZE, &sectors) >= 0) {
			numbytes = (loff_t)sectors << 9;
			goto out;
		}
	}
# endif
	{
		struct stat statbuf;

		if (fstat(fd, &statbuf) == 0 && S_ISREG(statbuf.st_mode)) {
			numbytes = statbuf.st_size;
			goto out;
		}
	}
	fprintf(stderr, "%s: unable to determine size of %s\n",
			progname, devname);
	return 0;
#endif

out:
	if (verbose)
		printf("%s: %s is %llu bytes (%g GB) in size\n",
		       progname, devname,
		       (unsigned long long)numbytes, (double)numbytes / ONE_GB);

	return numbytes;
}

/*
 * Verify_chunk: Verifies test pattern in each 4kB (BLOCKSIZE) is correct.
 * Returns 0 if test offset and timestamp is correct otherwise 1.
 */
int verify_chunk(char *chunk_buf, size_t chunksize,
		 unsigned long long chunk_off, time_t time_st)
{
	struct block_data *bd;
	char *chunk_end;

	for (chunk_end = chunk_buf + chunksize - sizeof(*bd);
	     (char *)chunk_buf < chunk_end;
	     chunk_buf += BLOCKSIZE, chunk_off += BLOCKSIZE) {
		bd = (struct block_data *)chunk_buf;
		if ((bd->bd_offset == chunk_off) && (bd->bd_time == time_st))
			continue;

		fprintf(stderr, "\n%s: verify failed at offset/timestamp "
			"%llu/%lu: found %llu/%lu instead\n", progname,
			chunk_off, time_st, bd->bd_offset, bd->bd_time);
		return 1;
	}
	return 0;
}

/*
 * fill_chunk: Fills the chunk with current or user specified timestamp
 * and  offset. The test patters is filled at the beginning of
 * each 4kB(BLOCKSIZE) blocks in chunk_buf.
 */
void fill_chunk(char *chunk_buf, size_t chunksize, loff_t chunk_off,
		time_t time_st)
{
	struct block_data *bd;
	char *chunk_end;

	for (chunk_end = chunk_buf + chunksize - sizeof(*bd);
	     (char *)chunk_buf < chunk_end;
	     chunk_buf += BLOCKSIZE, chunk_off += BLOCKSIZE) {
		bd = (struct block_data *)chunk_buf;
		bd->bd_offset = chunk_off;
		bd->bd_time = time_st;
	}
}

void show_rate(char *op, unsigned long long offset, unsigned long long *count)
{
	static time_t last;
	time_t now;
	double diff;

	now = time(NULL);
	diff = now - last;

	if (diff > 4) {
		if (last != 0) {
			if (isatty_flag)
				printf("\r");
			printf("%s offset: %14llukB %5g MB/s            ", op,
			       offset / ONE_KB, (double)(*count) /ONE_MB /diff);
			if (isatty_flag)
				fflush(stdout);
			else
				printf("\n");

			*count = 0;
		}
		last = now;
	}
}

/*
 * write_chunk: write the chunk_buf on the device. The number of write
 * operations are based on the parameters write_end, offset, and chunksize.
 */
int write_chunks(unsigned long long offset, unsigned long long write_end,
		 char *chunk_buf, size_t chunksize, time_t time_st)
{
	unsigned long long stride, count = 0;

	stride = full ? chunksize : (ONE_GB - chunksize);

	for (offset = offset & ~(chunksize - 1); offset < write_end;
	     offset += stride) {
		if (lseek64(fd, offset, SEEK_SET) == -1) {
			fprintf(stderr, "\n%s: lseek64(%llu) failed: %s\n",
				progname, offset, strerror(errno));
			return 1;
		}
		if (offset + chunksize > write_end)
			chunksize = write_end - offset;

		if (!full && offset > chunksize) {
			fill_chunk(chunk_buf, chunksize, offset, time_st);
			if (write(fd, chunk_buf, chunksize) < 0) {
				fprintf(stderr, "\n%s: write %llu failed: %s\n",
					progname, offset, strerror(errno));
				return 1;
			}
			offset += chunksize;
			if (offset + chunksize > write_end)
				chunksize = write_end - offset;
		}

		fill_chunk(chunk_buf, chunksize, offset, time_st);
		if (write(fd, chunk_buf, chunksize) < 0) {
			fprintf(stderr, "\n%s: write %llu failed: %s\n",
				progname, offset, strerror(errno));
			return 1;
		}

		count += chunksize;
		if (verbose > 1)
			show_rate("write", offset, &count);
	}
	if (verbose > 1) {
		show_rate("write", offset, &count);
		printf("\nwrite complete\n");
	}
	if (fsync(fd) == -1) {
		fprintf(stderr, "%s: fsync faild: %s\n", progname,
			strerror(errno));
			return 1;
	}
	return 0;
}

/*
 * read_chunk: reads the chunk_buf from the device. The number of read
 * operations are based on the parameters read_end, offset, and chunksize.
 */
int read_chunks(unsigned long long offset, unsigned long long read_end,
		char *chunk_buf, size_t chunksize, time_t time_st)
{
	unsigned long long stride, count = 0;

	stride = full ? chunksize : (ONE_GB - chunksize);

	if (ioctl(fd, BLKFLSBUF, 0) < 0 && verbose)
		fprintf(stderr, "%s: ioctl BLKFLSBUF failed: %s (ignoring)\n",
			progname, strerror(errno));

	for (offset = offset & ~(chunksize - 1); offset < read_end;
	     offset += stride) {
		if (lseek64(fd, offset, SEEK_SET) == -1) {
			fprintf(stderr, "\n%s: lseek64(%llu) failed: %s\n",
				progname, offset, strerror(errno));
			return 1;
		}
		if (offset + chunksize > read_end)
			chunksize = read_end - offset;

		if (!full && offset > chunksize) {
			if (read (fd, chunk_buf, chunksize) < 0) {
				fprintf(stderr, "\n%s: read %llu failed: %s\n",
					progname, offset, strerror(errno));
				return 1;
			}
			if (verify_chunk(chunk_buf, chunksize, offset,
					 time_st) != 0)
				return 1;
			offset += chunksize;
			if (offset + chunksize >= read_end)
				chunksize = read_end - offset;
		}

		if (read(fd, chunk_buf, chunksize) < 0) {
			fprintf(stderr, "\n%s: read failed: %s\n", progname,
				strerror(errno));
			return 1;
		}

		if (verify_chunk(chunk_buf, chunksize, offset, time_st) != 0)
			return 1;

		count += chunksize;
		if (verbose > 1)
			show_rate("read", offset, &count);
	}
	if (verbose > 1) {
		show_rate("read", offset, &count);
		printf("\nread complete\n");
	}
	return 0;
}

int main(int argc, char **argv)
{
	time_t time_st = 0;		/* Default timestamp */
	long long offset = 0, offset_orig; /* offset in kB */
	size_t chunksize = ONE_MB;	/* IO chunk size */
	char *chunk_buf = NULL;
	unsigned int force = 0;		/* run test run without confirmation*/
	unsigned long long dev_size = 0;
	char yesno[4];
	int mode = O_RDWR;		/* mode which device should be opened */
	int error = 0, c;

	progname = strrchr(argv[0], '/') == NULL ?
		argv[0] : strrchr(argv[0], '/') + 1;
	while ((c = getopt_long(argc, argv, "c:fhlo:pqrt:vw", longopts,
				NULL)) != -1) {
		switch (c) {
		case 'c':
			chunksize = (strtoul(optarg, NULL, 0) * ONE_MB);
			if (!chunksize) {
				fprintf(stderr, "%s: chunk size value should be"
					"nonzero and multiple of 1MB\n",
					progname);
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
			offset = strtoull(optarg, NULL, 0) * ONE_KB;
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
			usage (1);
			return 0;
		}
	}
	offset_orig = offset;
	devname = argv[optind];
	if (!devname) {
		fprintf(stderr, "%s: device name not given\n", progname);
		usage (1);
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
		scanf("%3s", yesno);
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
	dev_size = sizeof_dev(fd);
	if (!dev_size) {
		fprintf(stderr, "%s: cannot test on device size < 1MB\n",
			progname);
		error = 7;
		goto close_dev;
	}

	if (dev_size < (offset * 2)) {
		fprintf(stderr, "%s: device size %llu < offset %llu\n",
			progname, dev_size, offset);
		error = 6;
		goto close_dev;
	}
	if (!time_st)
		(void)time(&time_st);

	isatty_flag = isatty(STDOUT_FILENO);

	if (verbose)
		printf("Timestamp: %lu\n", time_st);

	chunk_buf = (char *)calloc(chunksize, 1);
	if (chunk_buf == NULL) {
		fprintf(stderr, "%s: memory allocation failed for chunk_buf\n",
			progname);
		error = 4;
		goto close_dev;
	}
	if (writeoption) {
		if (write_chunks(offset, dev_size, chunk_buf, chunksize,
				 time_st)) {
			error = 3;
			goto chunk_buf;
		}
		if (!full) {  /* end of device aligned to a block */
			offset = ((dev_size - chunksize + BLOCKSIZE - 1) &
				  ~(BLOCKSIZE - 1));
			if (write_chunks(offset, dev_size, chunk_buf, chunksize,
					 time_st)) {
				error = 3;
				goto chunk_buf;
			}
		}
		offset = offset_orig;
	}
	if (readoption) {
		if (read_chunks(offset, dev_size, chunk_buf, chunksize,
				time_st)) {
			error = 2;
			goto chunk_buf;
		}
		if (!full) { /* end of device aligned to a block */
			offset = ((dev_size - chunksize + BLOCKSIZE - 1) &
				  ~(BLOCKSIZE - 1));
			if (read_chunks(offset, dev_size, chunk_buf, chunksize,
					time_st)) {
				error = 2;
				goto chunk_buf;
			}
		}
		if (verbose)
			printf("\n%s: data verified successfully\n", progname);
	}
	error = 0;
chunk_buf:
	free(chunk_buf);
close_dev:
	close(fd);
	return error;
}
