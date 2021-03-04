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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/tests/lp_utils.h
 *
 * Author: You Feng <youfeng@clusterfs.com>
 */

#ifndef __LP_UTILS_H__
#define __LP_UTILS_H__

#include <linux/lustre/lustre_user.h>

#define FAILF(fmt, ...) \
do { \
	printf("%s: Process %d (%s)\n", timestamp(), rank, hostname); \
	if (debug) \
		printf("\tFAILED in %s:%d:%s()\n", \
		       __FILE__, __LINE__, __func__); \
	else \
		printf("\tFAILED in %s()\n", __func__); \
	printf(fmt, ##__VA_ARGS__); \
	fflush(stdout); \
	MPI_Abort(MPI_COMM_WORLD, 1); \
} while (0)

#define FAIL(msg)	FAILF("%s", (msg))

#ifndef MAX
#define MAX(a, b)	((a) > (b) ? (b) : (a))
#endif

#define FILEMODE S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH
#define MAX_FILENAME_LEN 512

extern int verbose;
extern int debug;

extern int rank;
extern int size;

extern char hostname[];
extern char *timestamp();
extern char *testdir;

extern void begin(char *str);
extern void end(char *str);

extern void dump_diff(char *orig_buf, char *buf, int len, long off);
extern void lp_gethostname(void);

extern void create_file(char *name, long filesize, int fill);
extern void fill_file(char *name, long filesize);

#define LP_STAT_FMT \
 \
"Stat error:\n \
\tfields\t\tvalue\told value\n \
\tst_dev\t\t%d\t%d\n \
\tst_ino\t\t%d\t%d\n \
\tst_mode\t\t%o\t%o\n \
\tst_nlink\t%d\t%d\n \
\tst_uid\t\t%d\t%d\n \
\tst_gid\t\t%d\t%d\n \
\tst_rdev\t\t%x.%x\t%x.%x\n \
\tst_size\t\t%lu\t%lu\n \
\tst_blksize\t%d\t%d\n \
\tst_blocks\t%u\t%u\n \
\tst_atime\t%d\t%d\n \
\tst_mtime\t%d\t%d\n \
\tst_ctime\t%d\t%d\n"
                                                                                
#define LP_STAT_ARGS \
 \
(int)state->st_dev, (int)old_state->st_dev, \
(int)state->st_ino, (int)old_state->st_ino, \
state->st_mode & 07777, old_state->st_mode & 07777, \
(int)state->st_nlink, (int)old_state->st_nlink, \
state->st_uid, old_state->st_uid, \
state->st_gid, old_state->st_gid, \
(int)((state->st_rdev >> 8) & 0xff), (int)(state->st_rdev & 0xff), \
(int)((old_state->st_rdev >> 8) & 0xff), (int)(old_state->st_rdev & 0xff), \
(unsigned long)state->st_size, (unsigned long)old_state->st_size, \
(int)state->st_blksize, (int)old_state->st_blksize, \
(unsigned int)state->st_blocks, (unsigned int)old_state->st_blocks, \
(int)state->st_atime, (int)old_state->st_atime, \
(int)state->st_mtime, (int)old_state->st_mtime, \
(int)state->st_ctime, (int)old_state->st_ctime

extern void check_stat(char *filename, struct stat *state, struct stat *old_state);
extern void remove_file(char *name);
extern void remove_file_or_dir(char *name);
extern void fill_stride(char *buf, int buf_size, long long rank, long long _off);

#endif /* __LP_UTILS_H__ */
