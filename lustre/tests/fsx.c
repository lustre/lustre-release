/*
 * Copyright (C) 1991, NeXT Computer, Inc.  All Rights Reserverd.
 * Copyright (c) 1998-2001 Apple Computer, Inc. All rights reserved.
 *
 * Copyright (c) 2012, Intel Corporation.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 *
 *	File:	fsx.c
 *	Author:	Avadis Tevanian, Jr.
 *
 *	File system exerciser.
 *
 *	Rewrite and enhancements 1998-2001 Conrad Minshall -- conrad@mac.com
 *
 *	Various features from Joe Sokol, Pat Dirks, and Clark Warner.
 *
 *	Small changes to work under Linux -- davej.
 *
 *	Sundry porting patches from Guy Harris 12/2001
 * $FreeBSD: src/tools/regression/fsx/fsx.c,v 1.1 2001/12/20 04:15:57 jkh Exp $
 *
 *	Checks for mmap last-page zero fill.
 *
 *	Add multi-file testing feature -- Zach Brown <zab@clusterfs.com>
 *
 *	Add random preallocation calls - Eric Sandeen <sandeen@redhat.com>
 *
 * $FreeBSD: src/tools/regression/fsx/fsx.c,v 1.2 2003/04/23 23:42:23 jkh Exp $
 * $DragonFly: src/test/stress/fsx/fsx.c,v 1.2 2005/05/02 19:31:56 dillon Exp $
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/stat.h>
#if defined(_UWIN) || defined(__linux__)
# include <sys/param.h>
# include <limits.h>
# include <time.h>
# include <strings.h>
#endif
#include <sys/time.h>
#include <fcntl.h>
#include <sys/mman.h>
#ifndef MAP_FILE
# define MAP_FILE 0
#endif
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <libcfs/util/string.h>
#include <setjmp.h>

/*
 * Each test run will work with one or more separate file descriptors for the
 * same file.  This allows testing cache coherency across multiple mountpoints
 * of the same network filesystem on a single client.
 */
struct test_file {
	char *path;
	int fd;
	int o_direct;
} *test_files = NULL, *tf;

int num_test_files;

enum fd_iteration_policy {
	FD_SINGLE,
	FD_ROTATE,
	FD_RANDOM,
};

int fd_policy = FD_RANDOM;
int fd_last;

/*
 *	A log entry is an operation and a bunch of arguments.
 */

struct log_entry {
	int operation;
	int args[3];
	struct timeval tv;
	const struct test_file *tf;
};

#define	LOGSIZE	100000

struct log_entry oplog[LOGSIZE]; /* the log */
int logptr; /* current position in log */
int logcount; /* total ops */
int jmpbuf_good;
jmp_buf jmpbuf;

/*
 * Define operations
 */

/* common operations */
#define OP_READ		0
#define OP_WRITE	1
#define OP_MAPREAD	2
#define OP_MAPWRITE	3
#define OP_MAX_LITE	4

/* !lite operations */
#define OP_TRUNCATE		4
#define OP_FALLOCATE		5
#define OP_PUNCH_HOLE		6
#define OP_ZERO_RANGE		7
#define OP_CLOSEOPEN		8
#define OP_MAX_FULL		9

#define OP_SKIPPED 101
/* _GNU_SOURCE defines O_DIRECT as 14th bit which is 0x4000(16384) */
#define OP_DIRECT  16384

#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE 0x02 /* de-allocates range */
#endif

#ifndef FALLOC_FL_KEEP_SIZE
#define FALLOC_FL_KEEP_SIZE 0x01 /* default is extend size */
#endif

#ifndef FALLOC_FL_ZERO_RANGE
#define FALLOC_FL_ZERO_RANGE 0x10 /* convert range to zeros */
#endif


char *original_buf; /* a pointer to the original data */
char *good_buf; /* a pointer to the correct data */
char *temp_buf; /* a pointer to the current data */
char *fname; /* name of our test file */
char logfile[PATH_MAX]; /* name of our log file */
char goodfile[PATH_MAX]; /* name of our test file */

struct timeval tv; /* time current operation started */
off_t file_size;
off_t biggest;
char state[256];
unsigned long testcalls; /* calls to function "test" */

long simulatedopcount;			/* -b flag */
int closeprob;				/* -c flag */
int debug ;				/* -d flag */
long debugstart;			/* -D flag */
int flush;				/* -f flag */
int do_fsync;				/* -y flag */
long maxfilelen = 256 * 1024;		/* -l flag */
int sizechecks = 1;			/* -n flag disables them */
int maxoplen = 64 * 1024;		/* -o flag */
int quiet;				/* -q flag */
long progressinterval;			/* -p flag */
int readbdy = 1;			/* -r flag */
int style;				/* -s flag */
int truncbdy = 1;			/* -t flag */
int writebdy = 1;			/* -w flag */
long monitorstart = -1;			/* -m flag */
long monitorend = -1;			/* -m flag */
int lite;				/* -L flag */
long numops = -1;			/* -N flag */
int randomoplen = 1;			/* -O flag disables it */
int seed = 1;				/* -S flag */
int mapped_writes = 1;			/* -W flag disables */
int fallocate_calls = 1;		/* -F flag disables */
int punch_hole_calls = 1;		/* -H flag disables */
int zero_range_calls = 1;		/* -z flag disables */
int mapped_reads = 1;			/* -R flag disables it */
int fsxgoodfd;
int o_direct;				/* -Z */
int fl_keep_size;

int page_size;
int page_mask;

FILE *fsxlogf;
int badoff = -1;

void
vwarnc(code, fmt, ap)
	int code;
	const char *fmt;
	va_list ap;
{
	fprintf(stderr, "fsx: ");
	if (fmt) {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, ": ");
	}
	fprintf(stderr, "%s\n", strerror(code));
}

void
__attribute__((format(__printf__, 1, 2)))
warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vwarnc(errno, fmt, ap);
	va_end(ap);
}

void
__attribute__((format(__printf__, 1, 2)))
prt(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);

	if (fsxlogf) {
		va_start(args, fmt);
		vfprintf(fsxlogf, fmt, args);
		va_end(args);
	}
}

/*
 * prterr() is now a macro. It internally calls ptrerr_func()
 * which transparently handles passing of function name.
 * This version also keeps checkpatch happy.
 */
void
ptrerr_func(const char *func, const char *prefix)
{
	prt("%s: %s%s%s\n", func, prefix, prefix ? ": " : "", strerror(errno));
}
#define prterr(prefix) ptrerr_func(__func__, prefix)

void
log4(int operation, int arg0, int arg1, int arg2)
{
	struct log_entry *le;

	le = &oplog[logptr];
	le->operation = operation;
	le->args[0] = arg0;
	le->args[1] = arg1;
	le->args[2] = arg2;
	gettimeofday(&tv, NULL);
	le->tv = tv;
	le->tf = tf;
	logptr++;
	logcount++;
	if (logptr >= LOGSIZE)
		logptr = 0;
}

const char *
fill_tf_buf(const struct test_file *tf)
{
	static int max_tf_len;
	static char tf_buf[32];

	if (fd_policy == FD_SINGLE)
		return "";

	if (max_tf_len == 0)
		max_tf_len = scnprintf(tf_buf, sizeof(tf_buf) - 1,
				      "%u", num_test_files - 1);

	snprintf(tf_buf, sizeof(tf_buf), "[%0*lu]", max_tf_len,
		(unsigned long)(tf - test_files));

	return tf_buf;
}

void
logdump(void)
{
	int i, count, down;
	struct log_entry *lp;
	char *falloc_type[3] = {"PAST_EOF", "EXTENDING", "INTERIOR"};

	prt("LOG DUMP (%d total operations):\n", logcount);
	if (logcount < LOGSIZE) {
		i = 0;
		count = logcount;
	} else {
		i = logptr;
		count = LOGSIZE;
	}
	for ( ; count > 0; count--) {
		int opnum;

		opnum = i + 1 + (logcount / LOGSIZE) * LOGSIZE;
		lp = &oplog[i];
		prt("%d%s: %lu.%06u ", opnum, fill_tf_buf(lp->tf),
		    lp->tv.tv_sec, (int)lp->tv.tv_usec);

		switch (lp->operation) {
		case OP_MAPREAD:
			prt("MAPREAD  0x%05x thru 0x%05x (0x%05x bytes)",
			    lp->args[0], lp->args[0] + lp->args[1] - 1,
			    lp->args[1]);
			if (badoff >= lp->args[0] && badoff <
						     lp->args[0] + lp->args[1])
				prt("\t***RRRR***");
			break;
		case OP_MAPWRITE:
			prt("MAPWRITE 0x%05x thru 0x%05x (0x%05x bytes)",
			    lp->args[0], lp->args[0] + lp->args[1] - 1,
			    lp->args[1]);
			if (badoff >= lp->args[0] && badoff <
						     lp->args[0] + lp->args[1])
				prt("\t******WWWW");
			break;
		case OP_READ:
		case OP_READ + OP_DIRECT:
			prt("READ%s  0x%05x thru 0x%05x (0x%05x bytes)",
			    lp->operation & OP_DIRECT ? "_OD" : "   ",
			    lp->args[0], lp->args[0] + lp->args[1] - 1,
			    lp->args[1]);
			if (badoff >= lp->args[0] &&
			    badoff < lp->args[0] + lp->args[1])
				prt("\t***RRRR***");
			break;
		case OP_WRITE:
		case OP_WRITE + OP_DIRECT:
			prt("WRITE%s 0x%05x thru 0x%05x (0x%05x bytes)",
			    lp->operation & OP_DIRECT ? "_OD" : "   ",
			    lp->args[0], lp->args[0] + lp->args[1] - 1,
			    lp->args[1]);
			if (lp->args[0] > lp->args[2])
				prt(" HOLE");
			else if (lp->args[0] + lp->args[1] > lp->args[2])
				prt(" EXTEND");
			if ((badoff >= lp->args[0] || badoff >= lp->args[2]) &&
			    badoff < lp->args[0] + lp->args[1])
				prt("\t***WWWW");
			break;
		case OP_TRUNCATE:
			down = lp->args[0] < lp->args[1];
			prt("TRUNCATE %s\tfrom 0x%05x to 0x%05x",
			    down ? "DOWN" : "UP", lp->args[1], lp->args[0]);
			if (badoff >= lp->args[!down] &&
			    badoff < lp->args[!!down])
				prt("\t******WWWW");
			break;
		case OP_FALLOCATE:
			/* 0: offset 1: length 2: where alloced */
			prt("FALLOC  \tfrom 0x%05x to 0x%05x\t(0x%05x bytes)%s",
			    lp->args[0], lp->args[0] + lp->args[1],
			    lp->args[1], falloc_type[lp->args[2]]);
			if (badoff >= lp->args[0] &&
			    badoff < lp->args[0] + lp->args[1])
				prt("\t******FFFF");
			break;
		case OP_PUNCH_HOLE:
			prt("PUNCH    0x%05x thru 0x%05x\t(0x%05x bytes)",
			    lp->args[0], lp->args[0] + lp->args[1] - 1,
			    lp->args[1]);
			if (badoff >= lp->args[0] && badoff <
						     lp->args[0] + lp->args[1])
				prt("\t******PPPP");
			break;
		case OP_ZERO_RANGE:
			prt("ZERO     0x%05x thru 0x%05x\t(0x%05x bytes)",
			    lp->args[0], lp->args[0] + lp->args[1] - 1,
			    lp->args[1]);
			if (badoff >= lp->args[0] && badoff <
						     lp->args[0] + lp->args[1])
				prt("\t******ZZZZ");
			break;
		case OP_CLOSEOPEN:
		case OP_CLOSEOPEN + OP_DIRECT:
			prt("CLOSE/OPEN%s",
			    lp->operation & OP_DIRECT ? "_OD" : "   ");
			break;
		case OP_SKIPPED:
			prt("SKIPPED (no operation)");
			break;
		default:
			prt("BOGUS LOG ENTRY (operation code = %d)!",
			    lp->operation);
		}
		prt("\n");
		i++;
		if (i == LOGSIZE)
			i = 0;
	}
}

void
save_buffer(char *buffer, off_t bufferlength, int fd)
{
	off_t ret;
	ssize_t byteswritten;

	if (fd <= 0 || bufferlength == 0)
		return;

	if (bufferlength > INT_MAX) {
		prt("fsx flaw: overflow in %s\n", __func__);
		exit(67);
	}
	if (lite) {
		off_t size_by_seek = lseek(fd, (off_t)0, SEEK_END);

		if (size_by_seek == (off_t)-1) {
			prterr("lseek eof");
		} else if (bufferlength > size_by_seek) {
			warn("%s: .fsxgood file too short... will save 0x%llx bytes instead of 0x%llx\n",
			     __func__, (unsigned long long)size_by_seek,
			     (unsigned long long)bufferlength);
			bufferlength = size_by_seek;
		}
	}

	ret = lseek(fd, (off_t)0, SEEK_SET);
	if (ret == (off_t)-1)
		prterr("lseek 0");

	byteswritten = write(fd, buffer, (size_t)bufferlength);
	if (byteswritten != bufferlength) {
		if (byteswritten == -1)
			prterr("write");
		else
			warn("%s: short write, 0x%x bytes instead of 0x%llx\n",
			     __func__, (unsigned int)byteswritten,
			     (unsigned long long)bufferlength);
	}
}

void
report_failure(int status)
{
	logdump();

	if (fsxgoodfd) {
		if (good_buf) {
			save_buffer(good_buf, file_size, fsxgoodfd);
			prt("Correct content saved for comparison\n");
			prt("(maybe hexdump \"%s\" vs \"%s\")\n",
			    fname, goodfile);
		}
		close(fsxgoodfd);
	}
	exit(status);
}

#define short_at(cp) ((unsigned short)((*((unsigned char *)(cp)) << 8) | \
		      *(((unsigned char *)(cp)) + 1)))

void
check_buffers(unsigned int offset, unsigned int size)
{
	unsigned char c, t;
	unsigned int i = 0;
	unsigned int n = 0;
	unsigned int op = 0;
	unsigned int bad = 0;

	if (memcmp(good_buf + offset, temp_buf, size) != 0) {
		prt("READ BAD DATA: offset = 0x%x, size = 0x%x\n",
		    offset, size);
		prt("OFFSET\tGOOD\tBAD\tRANGE\n");
		while (size > 0) {
			c = good_buf[offset];
			t = temp_buf[i];
			if (c != t) {
				if (n == 0) {
					bad = short_at(&temp_buf[i]);
					prt("%#07x\t%#06x\t%#06x", offset,
					    short_at(&good_buf[offset]), bad);
					op = temp_buf[offset & 1 ? i + 1 : i];
				}
				n++;
				badoff = offset;
			}
			offset++;
			i++;
			size--;
		}
		if (n) {
			prt("\t%#7x\n", n);
			if (bad)
				prt("operation# (mod 256) for the bad data may be %u\n",
				    ((unsigned int)op & 0xff));
			else
				prt("operation# (mod 256) for the bad data unknown, check HOLE and EXTEND ops\n");
		} else {
			prt("????????????????\n");
		}
		report_failure(110);
	}
}

struct test_file *
get_tf(void)
{
	unsigned int index = 0;

	switch (fd_policy) {
	case FD_ROTATE:
		index = fd_last++;
		break;
	case FD_RANDOM:
		index = random();
		break;
	case FD_SINGLE:
		index = 0;
		break;
	default:
		prt("unknown policy");
		exit(1);
		break;
	}
	return &test_files[index % num_test_files];
}

void
assign_fd_policy(char *policy)
{
	if (!strcmp(policy, "random")) {
		fd_policy = FD_RANDOM;
	} else if (!strcmp(policy, "rotate")) {
		fd_policy = FD_ROTATE;
	} else {
		prt("unknown -I policy: '%s'\n", policy);
		exit(1);
	}
}

int
get_fd(void)
{
	struct test_file *tf = get_tf();

	return tf->fd;
}

static const char *my_basename(const char *path)
{
	char *c = strrchr(path, '/');

	return c ? c++ : path;
}

void
open_test_files(char **argv, int argc)
{
	struct test_file *tf;
	int i;

	num_test_files = argc;
	if (num_test_files == 1)
		fd_policy = FD_SINGLE;

	test_files = calloc(num_test_files, sizeof(*test_files));
	if (!test_files) {
		prterr("reallocating space for test files");
		exit(1);
	}

	for (i = 0, tf = test_files; i < num_test_files; i++, tf++) {
		tf->path = argv[i];
#ifdef O_DIRECT
		tf->o_direct = (random() % (o_direct + 1)) ? OP_DIRECT : 0;
#endif
		tf->fd = open(tf->path,
			      O_RDWR | (lite ? 0 : O_CREAT | O_TRUNC) |
			      tf->o_direct, 0666);
		if (tf->fd < 0) {
			prterr(tf->path);
			exit(91);
		}
	}

	if (quiet || fd_policy == FD_SINGLE)
		return;

	for (i = 0, tf = test_files; i < num_test_files; i++, tf++)
		prt("fd %d: %s\n", i, tf->path);
}

void
close_test_files(void)
{
	int i;
	struct test_file *tf;

	for (i = 0, tf = test_files; i < num_test_files; i++, tf++) {
		if (close(tf->fd)) {
			prterr("close");
			report_failure(99);
		}
	}
}

void
check_size(void)
{
	struct stat statbuf;
	off_t size_by_seek;
	int fd = get_fd();

	if (fstat(fd, &statbuf)) {
		prterr("fstat");
		statbuf.st_size = -1;
	}
	size_by_seek = lseek(fd, (off_t)0, SEEK_END);
	if (file_size != statbuf.st_size || file_size != size_by_seek) {
		prt("Size error: expected 0x%llx stat 0x%llx seek 0x%llx\n",
		    (unsigned long long)file_size,
		    (unsigned long long)statbuf.st_size,
		    (unsigned long long)size_by_seek);
		report_failure(120);
	}
}

void
check_trunc_hack(void)
{
	struct stat statbuf;
	int fd = get_fd();

	/* should not ignore ftruncate(2)'s return value */
	if (ftruncate(fd, (off_t)0) < 0) {
		prterr("trunc_hack: ftruncate(0)");
		exit(1);
	}
	if (ftruncate(fd, (off_t)100000) < 0) {
		prterr("trunc_hack: ftruncate(100000)");
		exit(1);
	}
	if (fstat(fd, &statbuf)) {
		prterr("trunc_hack: fstat");
		statbuf.st_size = -1;
	}
	if (statbuf.st_size != (off_t)100000) {
		prt("no extend on truncate! not posix!\n");
		exit(130);
	}
	if (ftruncate(fd, 0) < 0) {
		prterr("trunc_hack: ftruncate(0) (2nd call)");
		exit(1);
	}
}

void
output_line(struct test_file *tf, int op, unsigned int offset,
	    unsigned int size)
{
	char *ops[] = {
		[OP_READ] = "read",
		[OP_WRITE] = "write",
		[OP_TRUNCATE] = "trunc from",
		[OP_MAPREAD] = "mapread",
		[OP_MAPWRITE] = "mapwrite",
		[OP_READ + OP_DIRECT] = "read_OD",
		[OP_WRITE + OP_DIRECT] = "write_OD",
		[OP_FALLOCATE] = "fallocate",
		[OP_PUNCH_HOLE] = "punch from",
	};

	/* W. */
	if (!(!quiet &&
	    ((progressinterval && testcalls % progressinterval == 0) ||
	    (debug && (monitorstart == -1 ||
	    (offset + size > monitorstart &&
	    (monitorend == -1 || offset <= monitorend)))))))
		return;

	prt("%06lu%s %lu.%06u %-10s %#08x %s %#08x\t(0x0%x bytes)\n",
	    testcalls, fill_tf_buf(tf), tv.tv_sec, (int)tv.tv_usec,
	    ops[op], offset, op == OP_TRUNCATE || op == OP_PUNCH_HOLE ?
	    " to " : "thru", offset + size - 1,
	     (int)size < 0 ? -(int)size : size);
}

void output_debug(unsigned int offset, unsigned int size, const char *what)
{
	struct timeval t;

	if (!quiet && (debug > 1 && (monitorstart == -1 ||
	    (offset + size >= monitorstart &&
	     (monitorend == -1 || offset <= monitorend))))) {
		gettimeofday(&t, NULL);
		prt("       %lu.%06u %s\n", t.tv_sec, (int)t.tv_usec, what);
	}
}

void
doflush(unsigned int offset, unsigned int size)
{
	unsigned int pg_offset;
	unsigned int map_size;
	char *p;
	struct test_file *tf = get_tf();
	int fd = tf->fd;

	if (tf->o_direct)
		return;

	pg_offset = offset & page_mask;
	map_size  = pg_offset + size;

	p = (char *)mmap(0, map_size, PROT_READ | PROT_WRITE,
			 MAP_FILE | MAP_SHARED, fd,
			 (off_t)(offset - pg_offset));
	if (p == (char *)-1) {
		prterr("mmap");
		report_failure(202);
	}
	if (msync(p, map_size, MS_INVALIDATE) != 0) {
		prterr("msync");
		report_failure(203);
	}
	if (munmap(p, map_size) != 0) {
		prterr("munmap");
		report_failure(204);
	}
	output_debug(offset, size, "flush done");
}

void
doread(unsigned int offset, unsigned int size)
{
	off_t ret;
	unsigned int iret;
	struct test_file *tf = get_tf();
	int fd = tf->fd;

	offset -= offset % readbdy;
	if (tf->o_direct)
		size -= size % readbdy;

	if (size == 0) {
		if (!quiet && testcalls > simulatedopcount && !tf->o_direct)
			prt("skipping zero size read\n");
		log4(OP_SKIPPED, OP_READ, offset, size);
		return;
	}
	if (size + offset > file_size) {
		if (!quiet && testcalls > simulatedopcount)
			prt("skipping seek/read past end of file\n");
		log4(OP_SKIPPED, OP_READ, offset, size);
		return;
	}

	log4(OP_READ + tf->o_direct, offset, size, 0);

	if (testcalls <= simulatedopcount)
		return;

	output_line(tf, OP_READ + tf->o_direct, offset, size);

	ret = lseek(fd, (off_t)offset, SEEK_SET);
	if (ret == (off_t)-1) {
		prterr("lseek");
		report_failure(140);
	}
	iret = read(fd, temp_buf, size);
	output_debug(offset, size, "read done");
	if (iret != size) {
		if (iret == -1)
			prterr("read");
		else
			prt("short read: 0x%x bytes instead of 0x%x\n",
			    iret, size);
		report_failure(141);
	}
	check_buffers(offset, size);
}

void
check_eofpage(char *s, unsigned int offset, char *p, int size)
{
	long last_page, should_be_zero;

	if (offset + size <= (file_size & ~page_mask))
		return;
	/*
	 * we landed in the last page of the file
	 * test to make sure the VM system provided 0's
	 * beyond the true end of the file mapping
	 * (as required by mmap def in 1996 posix 1003.1)
	 */
	last_page = ((long)p + (offset & page_mask) + size) & ~page_mask;

	for (should_be_zero = last_page + (file_size & page_mask);
	     should_be_zero < last_page + page_size;
	     should_be_zero++)
		if (*(char *)should_be_zero) {
			prt("Mapped %s: non-zero data past EOF (0x%llx) page offset 0x%lx is 0x%04x\n",
			    s, (long long)file_size - 1,
			    should_be_zero & page_mask,
			    short_at(should_be_zero));
			report_failure(205);
		}
}

void
domapread(unsigned int offset, unsigned int size)
{
	unsigned int pg_offset;
	unsigned int map_size;
	char *p;
	int fd;

	offset -= offset % readbdy;
	tf = get_tf();
	fd = tf->fd;
	if (size == 0) {
		if (!quiet && testcalls > simulatedopcount)
			prt("skipping zero size read\n");
		log4(OP_SKIPPED, OP_MAPREAD, offset, size);
		return;
	}
	if (size + offset > file_size) {
		if (!quiet && testcalls > simulatedopcount)
			prt("skipping seek/read past end of file\n");
		log4(OP_SKIPPED, OP_MAPREAD, offset, size);
		return;
	}

	log4(OP_MAPREAD, offset, size, 0);

	if (testcalls <= simulatedopcount)
		return;

	output_line(tf, OP_MAPREAD, offset, size);

	pg_offset = offset & page_mask;
	map_size  = pg_offset + size;

	p = mmap(0, map_size, PROT_READ, MAP_FILE | MAP_SHARED, fd,
		 (off_t)(offset - pg_offset));
	if (p == MAP_FAILED) {
		prterr("mmap");
		report_failure(190);
	}
	output_debug(offset, size, "mmap done");
	if (setjmp(jmpbuf) == 0) {
		jmpbuf_good = 1;
		memcpy(temp_buf, p + pg_offset, size);
		check_eofpage("Read", offset, p, size);
		jmpbuf_good = 0;
	} else {
		report_failure(1901);
	}
	output_debug(offset, size, "memcpy done");
	if (munmap(p, map_size) != 0) {
		prterr("munmap");
		report_failure(191);
	}
	output_debug(offset, size, "munmap done");

	check_buffers(offset, size);
}

void
gendata(char *original_buf, char *good_buf, unsigned int offset,
	unsigned int size)
{
	while (size--) {
		good_buf[offset] = testcalls % 256;
		if (offset % 2)
			good_buf[offset] += original_buf[offset];
		offset++;
	}
}

void
dowrite(unsigned int offset, unsigned int size)
{
	off_t ret;
	unsigned int iret;
	int fd;

	tf = get_tf();
	fd = tf->fd;
	offset -= offset % writebdy;
	if (tf->o_direct)
		size -= size % writebdy;
	if (size == 0) {
		if (!quiet && testcalls > simulatedopcount && !tf->o_direct)
			prt("skipping zero size write\n");
		log4(OP_SKIPPED, OP_WRITE, offset, size);
		return;
	}

	log4(OP_WRITE + tf->o_direct, offset, size, file_size);

	gendata(original_buf, good_buf, offset, size);
	if (file_size < offset + size) {
		if (file_size < offset)
			memset(good_buf + file_size, '\0', offset - file_size);
		file_size = offset + size;
		if (lite) {
			warn("Lite file size bug in fsx!");
			report_failure(149);
		}
	}

	if (testcalls <= simulatedopcount)
		return;

	output_line(tf, OP_WRITE + tf->o_direct, offset, size);

	ret = lseek(fd, (off_t)offset, SEEK_SET);
	if (ret == (off_t)-1) {
		prterr("lseek");
		report_failure(150);
	}
	iret = write(fd, good_buf + offset, size);
	output_debug(offset, size, "write done");
	if (iret != size) {
		if (iret == -1)
			prterr("write");
		else
			prt("short write: 0x%x bytes instead of 0x%x\n",
			    iret, size);
		report_failure(151);
	}
	if (do_fsync) {
		if (fsync(fd)) {
			prt("fsync() failed: %s\n", strerror(errno));
			report_failure(152);
		}
		output_debug(offset, size, "fsync done");
	}
	if (flush) {
		doflush(offset, size);
		output_debug(offset, size, "flush done");
	}
}

void
domapwrite(unsigned int offset, unsigned int size)
{
	unsigned int pg_offset;
	unsigned int map_size;
	off_t cur_filesize;
	char *p;
	int fd;

	tf = get_tf();
	fd = tf->fd;
	offset -= offset % writebdy;
	if (size == 0) {
		if (!quiet && testcalls > simulatedopcount)
			prt("skipping zero size write\n");
		log4(OP_SKIPPED, OP_MAPWRITE, offset, size);
		return;
	}
	cur_filesize = file_size;

	log4(OP_MAPWRITE, offset, size, 0);

	gendata(original_buf, good_buf, offset, size);
	if (file_size < offset + size) {
		if (file_size < offset)
			memset(good_buf + file_size, '\0', offset - file_size);
		file_size = offset + size;
		if (lite) {
			warn("Lite file size bug in fsx!");
			report_failure(200);
		}
	}

	if (testcalls <= simulatedopcount)
		return;

	output_line(tf, OP_MAPWRITE, offset, size);

	if (file_size > cur_filesize) {
		if (ftruncate(fd, file_size) == -1) {
			prterr("ftruncate");
			exit(201);
		}
		output_debug(offset, size, "truncate done");
	}
	pg_offset = offset & page_mask;
	map_size  = pg_offset + size;

	p = mmap(0, map_size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED,
		 fd, (off_t)(offset - pg_offset));
	if (p == MAP_FAILED) {
		prterr("mmap");
		report_failure(202);
	}
	output_debug(offset, map_size, "mmap done");
	if (setjmp(jmpbuf) == 0) {
		jmpbuf_good = 1;
		memcpy(p + pg_offset, good_buf + offset, size);
		if (msync(p, map_size, MS_SYNC) != 0) {
			prterr("msync");
			report_failure(203);
		}
		check_eofpage("Write", offset, p, size);
		jmpbuf_good = 0;
	} else {
		report_failure(2021);
	}
	output_debug(offset, map_size, "msync done");
	if (munmap(p, map_size) != 0) {
		prterr("munmap");
		report_failure(204);
	}
	output_debug(offset, map_size, "munmap done");
}

void
dotruncate(unsigned int size)
{
	int oldsize = file_size;
	int fd;

	tf = get_tf();
	fd = tf->fd;
	size -= size % truncbdy;
	if (size > biggest) {
		biggest = size;
		if (!quiet && testcalls > simulatedopcount)
			prt("truncating to largest ever: 0x%x\n", size);
	}

	log4(OP_TRUNCATE, size, (unsigned int)file_size, 0);

	if (size > file_size)
		memset(good_buf + file_size, '\0', size - file_size);
	file_size = size;

	if (testcalls <= simulatedopcount)
		return;

	output_line(tf, OP_TRUNCATE, oldsize, size - oldsize);

	if (ftruncate(fd, (off_t)size) == -1) {
		prt("ftruncate: 0x%x\n", size);
		prterr("ftruncate");
		report_failure(160);
	}
	output_debug(size, 0, "truncate done");
}

void
do_punch_hole(unsigned int offset, unsigned int length)
{
	int max_offset = 0;
	int max_len = 0;
	int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	int fd;

	tf = get_tf();
	fd = tf->fd;
	if (length == 0) {
		if (!quiet && testcalls > simulatedopcount) {
			prt("skipping zero length punch hole\n");
			log4(OP_SKIPPED, OP_PUNCH_HOLE, offset, length);
		}
		return;
	}

	if (file_size <= (loff_t)offset) {
		if (!quiet && testcalls > simulatedopcount) {
			prt("skipping hole punch off the end of the file\n");
			log4(OP_SKIPPED, OP_PUNCH_HOLE, offset, length);
		}
		return;
	}

	log4(OP_PUNCH_HOLE, offset, length, 0);

	if (testcalls <= simulatedopcount)
		return;

	output_line(tf, OP_PUNCH_HOLE, offset, length);
	if (fallocate(fd, mode, (loff_t)offset, (loff_t)length) == -1) {
		prt("punch hole: %x to %x\n", offset, length);
		prterr("fallocate");
		report_failure(161);
	}
	output_debug(offset, length, "zero_range done");

	max_offset = offset < file_size ? offset : file_size;
	max_len = max_offset + length <= file_size ? length :
			file_size - max_offset;
	memset(good_buf + max_offset, '\0', max_len);
}

void
do_zero_range(unsigned int offset, unsigned int length)
{
	unsigned int end_offset;
	int mode = FALLOC_FL_ZERO_RANGE;
	int keep_size;
	int fd;

	tf = get_tf();
	fd = tf->fd;
	if (length == 0) {
		if (!quiet && testcalls > simulatedopcount) {
			prt("skipping zero length zero range\n");
			log4(OP_SKIPPED, OP_ZERO_RANGE, offset, length);
		}
		return;
	}

	keep_size = random() % 2;

	end_offset = keep_size ? 0 : offset + length;

	if (end_offset > biggest) {
		biggest = end_offset;
		if (!quiet && testcalls > simulatedopcount)
			prt("zero_range to largest ever: 0x%x\n", end_offset);
	}

	/*
	 * last arg matches fallocate string array index in logdump:
	 * 0: allocate past EOF
	 * 1: extending prealloc
	 * 2: interior prealloc
	 */
	log4(OP_ZERO_RANGE, offset, length,
	     (end_offset > file_size) ? (keep_size ? 0 : 1) : 2);

	if (testcalls <= simulatedopcount)
		return;

	output_line(tf, OP_TRUNCATE, offset, length);

	if (fallocate(fd, mode, (loff_t)offset, (loff_t)length) == -1) {
		prt("pzero range: %x to %x\n", offset, length);
		prterr("fallocate");
		report_failure(161);
	}
	output_debug(offset, length, "zero_range done");

	memset(good_buf + offset, '\0', length);
}

/*
 * fallocate is basically a no-op unless extending,
 * then a lot like a truncate
 */
void
do_preallocate(unsigned int offset, unsigned int length)
{
	off_t end_offset;
	int keep_size;
	int fd;
	struct stat statbufs;

	tf = get_tf();
	fd = tf->fd;
	if (length == 0) {
		if (!quiet && testcalls > simulatedopcount)
			prt("skipping zero length fallocate\n");
		log4(OP_SKIPPED, OP_FALLOCATE, offset, length);
		return;
	}

	keep_size = fl_keep_size && (random() % 2);

	end_offset = offset + length;
	if (end_offset > biggest) {
		biggest = end_offset;
		if (!quiet && testcalls > simulatedopcount)
			prt("fallocating to largest ever: 0x%jx\n", end_offset);
	}

	/*
	 * last arg matches fallocate string array index in logdump:
	 * 0: allocate past EOF
	 * 1: extending prealloc
	 * 2: interior prealloc
	 */
	log4(OP_FALLOCATE, offset, length, (end_offset > file_size) ?
	     (keep_size ? 0 : 1) : 2);

	if (end_offset > file_size && !keep_size) {
		memset(good_buf + file_size, '\0', end_offset - file_size);
		file_size = end_offset;
	}

	if (testcalls <= simulatedopcount)
		return;

	fstat(fd, &statbufs);
	if (fallocate(fd, keep_size ? FALLOC_FL_KEEP_SIZE : 0, (loff_t)offset,
		      (loff_t)length) == -1) {
		prt("fallocate: %x to %x\n", offset, length);
		prterr("fallocate");
		report_failure(161);
	}
	output_line(tf, OP_FALLOCATE, offset, length);
	output_debug(offset, length, "fallocate done");
}

void
writefileimage()
{
	ssize_t iret;
	int fd = get_fd();

	if (lseek(fd, (off_t)0, SEEK_SET) == (off_t)-1) {
		prterr("lseek");
		report_failure(171);
	}
	iret = write(fd, good_buf, file_size);
	if ((off_t)iret != file_size) {
		if (iret == -1)
			prterr("write");
		else
			prt("short write: 0x%lx bytes instead of 0x%llx\n",
			    (unsigned long)iret, (unsigned long long)file_size);
		report_failure(172);
	}
	if (lite ? 0 : ftruncate(fd, file_size) == -1) {
		prt("ftruncate2: %llx\n", (unsigned long long)file_size);
		prterr("ftruncate");
		report_failure(173);
	}
}

void
docloseopen(void)
{
	int direct = 0;
	const char *tf_num = "";

	if (testcalls <= simulatedopcount)
		return;

	tf = get_tf();
#ifdef O_DIRECT
	direct = (random() % (o_direct + 1)) ? OP_DIRECT : 0;
#endif
	log4(OP_CLOSEOPEN + direct, file_size, (unsigned int)file_size, 0);

	if (fd_policy != FD_SINGLE)
		tf_num = fill_tf_buf(tf);

	if (debug)
		prt("%06lu %lu.%06u %sclose/open%s\n", testcalls, tv.tv_sec,
		    (int)tv.tv_usec, tf_num, direct ? "(O_DIRECT)" : "");
	if (close(tf->fd))
		report_failure(180);

	output_debug(monitorstart, 0, "close done");
	tf->o_direct = direct;
	tf->fd = open(tf->path, O_RDWR | tf->o_direct, 0);
	if (tf->fd < 0) {
		prterr(tf->o_direct ? "open(O_DIRECT)" : "open");
		report_failure(181);
	}
	output_debug(monitorstart, 0,
		     tf->o_direct ? "open(O_DIRECT) done" : "open done");
}

#define TRIM_OFF_LEN(off, len, size)	\
do {					\
	if (size)			\
		(off) %= (size);	\
	else				\
		(off) = 0;		\
	if ((off) + (len) > (size))	\
		(len) = (size) - (off);	\
} while (0)

void
test(void)
{
	unsigned long offset;
	unsigned long size = maxoplen;
	unsigned long rv = random();
	unsigned long op;
	int closeopen = 0;

	if (simulatedopcount > 0 && testcalls == simulatedopcount)
		writefileimage();

	testcalls++;

	if (closeprob)
		closeopen = (rv >> 3) < (1 << 28) / closeprob;

	if (debugstart > 0 && testcalls >= debugstart)
		debug = 1;

	if (!quiet && testcalls < simulatedopcount && testcalls % 100000 == 0)
		prt("%lu...\n", testcalls);

	offset = random();
	if (randomoplen)
		size = random() % (maxoplen + 1);

	/* calculate appropriate op to run */
	if (lite)
		op = rv % OP_MAX_LITE;
	else
		op = rv % OP_MAX_FULL;

	switch (op) {
	case OP_MAPREAD:
		if (!mapped_reads)
			op = OP_READ;
		break;
	case OP_MAPWRITE:
		if (!mapped_writes)
			op = OP_WRITE;
		break;
	case OP_FALLOCATE:
		if (!fallocate_calls) {
			log4(OP_SKIPPED, OP_FALLOCATE, offset, size);
			goto out;
		}
		break;
	case OP_PUNCH_HOLE:
		if (!punch_hole_calls) {
			log4(OP_SKIPPED, OP_PUNCH_HOLE, offset, size);
			goto out;
		}
		break;
	case OP_ZERO_RANGE:
		if (!zero_range_calls) {
			log4(OP_SKIPPED, OP_ZERO_RANGE, offset, size);
			goto out;
		}
		break;
	}

	switch (op) {
	case OP_READ:
		TRIM_OFF_LEN(offset, size, file_size);
		doread(offset, size);
		break;
	case OP_WRITE:
		TRIM_OFF_LEN(offset, size, maxfilelen);
		dowrite(offset, size);
		break;
	case OP_MAPREAD:
		TRIM_OFF_LEN(offset, size, file_size);
		domapread(offset, size);
		break;
	case OP_MAPWRITE:
		TRIM_OFF_LEN(offset, size, maxfilelen);
		domapwrite(offset, size);
		break;
	case OP_TRUNCATE:
		if (!style)
			size = random() % maxfilelen;
		dotruncate(size);
		break;
	case OP_FALLOCATE:
		TRIM_OFF_LEN(offset, size, maxfilelen);
		do_preallocate(offset, size);
		break;
	case OP_PUNCH_HOLE:
		TRIM_OFF_LEN(offset, size, file_size);
		do_punch_hole(offset, size);
		break;
	case OP_ZERO_RANGE:
		TRIM_OFF_LEN(offset, size, file_size);
		do_zero_range(offset, size);
		break;
	case OP_CLOSEOPEN:
		if (closeopen)
			docloseopen();
		break;
	default:
		prterr("unknown operation %d: Operation not supported");
		report_failure(42);
		break;
	}

out:
	if (sizechecks && testcalls > simulatedopcount)
		check_size();
}

void
segv(int sig)
{
	if (jmpbuf_good) {
		jmpbuf_good = 0;
		longjmp(jmpbuf, 1);
	}
	report_failure(9999);
}

void
cleanup(sig)
	int	sig;
{
	if (sig)
		prt("signal %d\n", sig);
	prt("testcalls = %lu\n", testcalls);
	exit(sig);
}

void
usage(void)
{
	fprintf(stdout,
		"usage: fsx [-dfnqFLOW] [-b opnum] [-c Prob] [-l flen] [-m start:end] [-o oplen] [-p progressinterval] [-r readbdy] [-s style] [-t truncbdy] [-w writebdy] [-D startingop] [ -I random|rotate ] [-N numops] [-P dirpath] [-S seed] [-Z [prob]] fname [additional paths to fname..]\n"
"	-b opnum: beginning operation number (default 1)\n"
"	-c P: 1 in P chance of file close+open at each op (default infinity)\n"
"	-d: debug output for all operations [-d -d = more debugging]\n"
"	-f flush and invalidate cache after I/O\n"
/* OSX: -d duration: number of hours for the tool to run\n\ */
/* OSX: -e: tests using an extended attribute rather than a file\n\ */
/* OSX: -f forkname: test the named fork of fname\n\ */
/* OSX: -g logpath: path for .fsxlog file\n\ */
/* OSX: -h: write 0s instead of creating holes (i.e. sparse file)\n\ */
/* OSX: -i: interactive mode, hit return before performing each operation\n\ */
"	-l flen: the upper bound on file size (default 262144)\n"
"	-m startop:endop: monitor (print debug output) specified byte range\n"
"	   (default 0:infinity)\n"
"	-n: no verifications of file size\n"
"	-o oplen: the upper bound on operation size (default 65536)\n"
"	-p progressinterval: debug output at specified operation interval\n"
"	-q: quieter operation\n"
"	-r readbdy: %1$u would make reads page aligned (default 1)\n"
"	-s style: 1 gives smaller truncates (default 0)\n"
"	-t truncbdy: %1$u would make truncates page aligned (default 1)\n"
"	-w writebdy: %1$u would make writes page aligned (default 1)\n"
/* XFS: -x: preallocate file space before starting, XFS only (default 0)\n\ */
"	-y synchronize changes to a file\n"
/* OSX: -v: debug output for all operations\n\ */
/* XFS: -A: Use the AIO system calls\n" */
/* OSX: -C mix cached and un-cached read/write ops\n\ */
"	-D startingop: debug output starting at specified operation\n"
"	-F: Do not use fallocate (preallocation) calls\n"
/* OSX: -G logsize: #entries in oplog (default 1024)\n\ */
#ifdef FALLOC_FL_PUNCH_HOLE
"	-H: Do not use punch hole calls\n"
#endif
#ifdef FALLOC_FL_ZERO_RANGE
"	-z: Do not use zero range calls\n"
#endif
/* XFS: -C: Do not use collapse range calls\n\ */
"	-I [rotate|random]: When multiple paths to the file are given,\n"
"	    each operation uses a different path.  Iterate through them in\n"
"	    order with 'rotate' or chose them at 'random'.  (default random)\n"
"	-L: fsxLite - no file creations & no file size changes\n"
/* OSX: -I: start interactive mode since operation opnum\n\ */
/* OSX: -M: slow motion mode, wait 1 second before each op\n\ */
"	-N numops: total # operations to do (default infinity)\n"
"	-O: use oplen (see -o flag) for every op (default random)\n"
"	-P: save .fsxlog and .fsxgood files in dirpath (default ./)\n"
"	-R: read() system calls only (mapped reads disabled)\n"
"	-S seed: for random # generator (default 1) 0 gets timestamp\n"
/* OSX: -T datasize: atomic data element write size [1,2,4] (default 4)\n\ */
"	-W: mapped write operations DISabled\n"
#ifdef O_DIRECT
"	-Z[P]: O_DIRECT file IO [1 in P chance for each open] (default off)\n"
#endif
"	fname: this filename is REQUIRED (no default)\n",
	page_size);
	exit(90);
}

int
getnum(char *s, char **e)
{
	int ret = -1;

	*e = (char *)0;
	ret = strtol(s, e, 0);
	if (*e)
		switch (**e) {
		case 'b':
		case 'B':
			ret *= 512;
			*e = *e + 1;
			break;
		case 'k':
		case 'K':
			ret *= 1024;
			*e = *e + 1;
			break;
		case 'm':
		case 'M':
			ret *= 1024 * 1024;
			*e = *e + 1;
			break;
		case 'w':
		case 'W':
			ret *= 4;
			*e = *e + 1;
			break;
		}
	return (ret);
}

int
test_fallocate(int mode)
{
	int ret = 0;
	int fd = get_fd();

	if (!lite) {
		/* Must go more than a page away so let's go 4M to be sure */
		if (fallocate(fd, mode, 0, 4096*1024) && errno == EOPNOTSUPP) {
			if (!quiet)
				warn("%s: filesystem does not support fallocate mode 0x%x, disabling!",
				     __func__, mode);
		} else {
			ret = 1;
		}

		/* Always call ftruncate since file size might be adjusted
		 * by fallocate even on error
		 */
		if (ftruncate(fd, 0) == -1)
			warn("ftruncate to 0 size failed");
	}
	return ret;
}

int
main(int argc, char **argv)
{
	int i, style, ch;
	char *endp;
	int dirpath = 0;

	goodfile[0] = 0;
	logfile[0] = 0;

	page_size = getpagesize();
	page_mask = page_size - 1;

	setvbuf(stdout, (char *)0, _IOLBF, 0); /* line buffered stdout */

	while ((ch = getopt(argc, argv,
			    "b:c:dfl:m:no:p:qr:s:t:w:xyzD:FHI:LN:OP:RS:WZ::"))
	       != EOF)
		switch (ch) {
		case 'b':
			simulatedopcount = getnum(optarg, &endp);
			if (!quiet)
				fprintf(stdout, "Will begin at operation %ld\n",
					simulatedopcount);
			if (simulatedopcount == 0)
				usage();
			simulatedopcount -= 1;
			break;
		case 'c':
			closeprob = getnum(optarg, &endp);
			if (!quiet)
				fprintf(stdout,
					"Chance of close/open is 1 in %d\n",
					closeprob);
			if (closeprob <= 0)
				usage();
			break;
		case 'd':
			debug++;
			break;
		case 'f':
			flush = 1;
			break;
		case 'l':
			maxfilelen = getnum(optarg, &endp);
			if (maxfilelen <= 0)
				usage();
			break;
		case 'm':
			monitorstart = getnum(optarg, &endp);
			if (monitorstart < 0)
				usage();
			if (!endp || *endp++ != ':')
				usage();
			monitorend = getnum(endp, &endp);
			if (monitorend < 0)
				usage();
			if (monitorend == 0)
				monitorend = -1; /* aka infinity */
			debug = 1;
		case 'n':
			sizechecks = 0;
			break;
		case 'o':
			maxoplen = getnum(optarg, &endp);
			if (maxoplen <= 0)
				usage();
			break;
		case 'p':
			progressinterval = getnum(optarg, &endp);
			if (progressinterval <= 0)
				usage();
			break;
		case 'q':
			quiet = 1;
			break;
		case 'r':
			readbdy = getnum(optarg, &endp);
			if (readbdy <= 0)
				usage();
			break;
		case 's':
			style = getnum(optarg, &endp);
			if (style < 0 || style > 1)
				usage();
			break;
		case 't':
			truncbdy = getnum(optarg, &endp);
			if (truncbdy <= 0)
				usage();
			break;
		case 'w':
			writebdy = getnum(optarg, &endp);
			if (writebdy <= 0)
				usage();
			break;
		case 'y':
			do_fsync = 1;
			break;
		case 'D':
			debugstart = getnum(optarg, &endp);
			if (debugstart < 1)
				usage();
			break;
		case 'F':
			fallocate_calls = 0;
			break;
		case 'H':
			punch_hole_calls = 0;
			break;
		case 'z':
			zero_range_calls = 0;
			break;
		case 'I':
			assign_fd_policy(optarg);
			break;
		case 'L':
			lite = 1;
			break;
		case 'N':
			numops = getnum(optarg, &endp);
			if (numops < 0)
				usage();
			break;
		case 'O':
			randomoplen = 0;
			break;
		case 'P':
			strncpy(goodfile, optarg, sizeof(goodfile) - 1);
			strncat(goodfile, "/", PATH_MAX - strlen(goodfile) - 1);
			strncpy(logfile, optarg, sizeof(logfile) - 1);
			strncat(logfile, "/", PATH_MAX - strlen(logfile) - 1);
			dirpath = 1;
			break;
		case 'R':
			mapped_reads = 0;
			break;
		case 'S':
			seed = getnum(optarg, &endp);
			if (seed == 0)
				seed = time(0) % 10000;
			if (!quiet)
				fprintf(stdout, "Seed set to %d\n", seed);
			if (seed < 0)
				usage();
			break;
		case 'W':
			mapped_writes = 0;
			if (!quiet)
				fprintf(stdout, "mapped writes DISABLED\n");
			break;
		case 'Z':
#ifdef O_DIRECT
			if (optarg)
				o_direct = getnum(optarg, &endp);
			if (!optarg || o_direct == 0)
				o_direct = 1;
#endif
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	argc -= optind;
	argv += optind;
	if (argc < 1)
		usage();
	fname = argv[0];

	signal(SIGHUP, cleanup);
	signal(SIGINT, cleanup);
	signal(SIGPIPE, cleanup);
	signal(SIGALRM, cleanup);
	signal(SIGTERM, cleanup);
	signal(SIGXCPU, cleanup);
	signal(SIGXFSZ, cleanup);
	signal(SIGVTALRM, cleanup);
	signal(SIGUSR1, cleanup);
	signal(SIGUSR2, cleanup);
	signal(SIGBUS, segv);
	signal(SIGSEGV, segv);

	initstate(seed, state, 256);
	setstate(state);

	open_test_files(argv, argc);

	strncat(goodfile, dirpath ? my_basename(fname) : fname, 256);
	strncat(goodfile, ".fsxgood", PATH_MAX - strlen(goodfile) - 1);
	fsxgoodfd = open(goodfile, O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (fsxgoodfd < 0) {
		prterr(goodfile);
		exit(92);
	}
	strncat(logfile, dirpath ? my_basename(fname) : fname, 256);
	strncat(logfile, ".fsxlog", PATH_MAX - strlen(logfile) - 1);
	fsxlogf = fopen(logfile, "w");
	if (!fsxlogf) {
		prterr(logfile);
		exit(93);
	}
	if (lite) {
		off_t ret;
		int fd = get_fd();

		maxfilelen = lseek(fd, (off_t)0, SEEK_END);
		file_size = maxfilelen;
		if (file_size == (off_t)-1) {
			prterr(fname);
			warn("%s: lseek eof", __func__);
			exit(94);
		}
		ret = lseek(fd, (off_t)0, SEEK_SET);
		if (ret == (off_t)-1) {
			prterr(fname);
			warn("%s: lseek 0", __func__);
			exit(95);
		}
	}
	original_buf = (char *)malloc(maxfilelen);
	if (!original_buf)
		exit(96);
	for (i = 0; i < maxfilelen; i++)
		original_buf[i] = random() % 256;
	if (o_direct) {
		int ret;

		ret = posix_memalign((void **)&good_buf, writebdy, maxfilelen);
		if (ret) {
			prt("%s: posix_memalign failed: %s\n", __func__,
			    strerror(ret));
			exit(96);
		}

		ret = posix_memalign((void **)&temp_buf, readbdy, maxoplen);
		if (ret) {
			prt("%s: posix_memalign failed: %s\n", __func__,
			    strerror(ret));
			exit(97);
		}
	} else {
		good_buf = malloc(maxfilelen);
		if (!good_buf) {
			prt("malloc failed.\n");
			exit(98);
		}

		temp_buf = malloc(maxoplen);
		if (!temp_buf) {
			prt("malloc failed.\n");
			exit(99);
		}
	}
	memset(good_buf, 0, maxfilelen);
	memset(temp_buf, 0, maxoplen);

	if (lite) {	/* zero entire existing file */
		ssize_t written;
		int fd = get_fd();

		written = write(fd, good_buf, (size_t)maxfilelen);
		if (written != maxfilelen) {
			if (written == -1) {
				prterr(fname);
				warn("%s: error on write", __func__);
			} else {
				warn("%s: short write, 0x%x bytes instead of 0x%lx\n",
				     __func__, (unsigned int)written,
				     maxfilelen);
			}
			exit(98);
		}
	} else {
		check_trunc_hack();
	}

	if (fallocate_calls)
		fallocate_calls = test_fallocate(0);

	if (punch_hole_calls)
		punch_hole_calls = test_fallocate(FALLOC_FL_PUNCH_HOLE |
						  FALLOC_FL_KEEP_SIZE);

	if (zero_range_calls)
		zero_range_calls = test_fallocate(FALLOC_FL_ZERO_RANGE);

	fl_keep_size = test_fallocate(FALLOC_FL_KEEP_SIZE);

	while (numops == -1 || numops--)
		test();

	close_test_files();
	prt("All operations completed A-OK!\n");

	free(original_buf);
	free(good_buf);
	free(temp_buf);

	return 0;
}
