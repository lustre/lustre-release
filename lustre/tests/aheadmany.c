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
 * Copyright (c) 2023, Whamcloud DDN Storage Corporation.
 */
/*
 * Create|Open|Stat|Read ahead.
 * This program is mainly used to verify that ahead feature works as
 * expected for batch file accesses.
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/unistd.h>
#include <libgen.h>
#include <sys/ioctl.h>

#include <linux/lustre/lustre_user.h>

static char *progname;

static void usage(void)
{
	printf("Usage: %s {--iocall|-c [stat|open|create|read]}\n"
	       "[--start|-s start] [--end|-e end] [--basename NAME]\n"
	       "[--batch_max|-B] {--dir|-d DIR} dentry ...\n"
	       "\t--iocall|-c:	I/O syscall in a predictive batch access\n"
	       "\t--start|-s:	Start index of file names\n"
	       "\t--end|-e:	End index of file names\n"
	       "\t--basename|-b:Base name for file naming format\n"
	       "\t--noadvise|-N:No ahead advise hint IOCTL\n"
	       "\t--batch_max|-B: max batch count for ahead operations\n"
	       "\t--directory|-d: under this directory do ahead operations\n",
	       progname);
	exit(0);
}

static char *get_file_name(const char *dirpath, const char *basename, long n)
{
	static char filename[PATH_MAX];
	int bytes;

	bytes = snprintf(filename, PATH_MAX - 1, "%s/%s%ld",
			 dirpath, basename, n);
	if (bytes >= PATH_MAX - 1) {
		fprintf(stderr, "%s: file name too long\n", progname);
		exit(EXIT_FAILURE);
	}

	return filename;
}

static int ll_batch_io_by_name(const char *dirpath, const char *fname,
			       enum lu_access_flags flags, __u64 start,
			       __u64 end)
{
	int rc = 0;
	int i;

	for (i = start; i < end; i++) {
		char *filename;
		struct stat st;

		filename = get_file_name(dirpath, fname, i);
		if (flags & ACCESS_FL_STAT) {
			rc = stat(filename, &st);
			if (rc < 0) {
				rc = -errno;
				fprintf(stderr,
					"%s: stat(%s) failed: rc = %d\n",
					progname, filename, errno);
				break;
			}
		}
	}

	return rc;
}

static int ll_ahead_by_name_index(const char *dirpath, const char *fname,
				  enum lu_access_flags flags, __u64 start,
				  __u64 end, __u32 batch_max)
{
	struct llapi_lu_ladvise2 ladvise;
	int dir_fd;
	int rc;

	dir_fd = open(dirpath, O_DIRECTORY | O_RDONLY);
	if (dir_fd < 0) {
		rc = -errno;
		fprintf(stderr, "%s: failed to open dir '%s': rc = %d\n",
			progname, dirpath, rc);
		return rc;
	}

	ladvise.lla_advice = LU_LADVISE_AHEAD;
	ladvise.lla_ahead_mode = LU_AH_NAME_INDEX;
	ladvise.lla_access_flags = flags;
	ladvise.lla_start = start;
	ladvise.lla_end = end;
	ladvise.lla_batch_max = batch_max;
	strncpy(ladvise.lla_fname, fname, sizeof(ladvise.lla_fname) - 1);
	rc = ioctl(dir_fd, LL_IOC_LADVISE2, &ladvise);
	if (rc < 0) {
		fprintf(stderr, "%s: failed to ahead for '%s': rc = %d\n",
			progname, dirpath, rc);
		close(dir_fd);
		return rc;
	}

	rc = ll_batch_io_by_name(dirpath, fname, flags, start, end);
	close(dir_fd);
	return rc;
}

int main(int argc, char **argv)
{
	struct option long_opts[] = {
	{ .val = 'c',	.name = "iocall",	.has_arg = required_argument },
	{ .val = 's',	.name = "start",	.has_arg = required_argument },
	{ .val = 'e',	.name = "end",		.has_arg = required_argument },
	{ .val = 'b',	.name = "basename",	.has_arg = required_argument },
	{ .val = 'd',	.name = "directory",	.has_arg = required_argument },
	{ .val = 'B',	.name = "batch_max",	.has_arg = required_argument },
	{ .val = 'N',	.name = "noadvise",	.has_arg = no_argument },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .name = NULL } };
	enum lu_access_flags flags = ACCESS_FL_NONE;
	enum lu_ahead_mode mode = LU_AH_NAME_INDEX;
	__u32 batch_max = 0;
	const char *dirpath = NULL;
	char *fname = NULL;
	__u64 start_index = 0;
	__u64 end_index = 0;
	bool has_advise = true;
	char *end;
	int rc = 0;
	int c;

	progname = basename(argv[0]);
	while ((c = getopt_long(argc, argv, "c:s:e:b:d:B:Nh",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			if (strcmp(optarg, "stat") == 0) {
				flags |= ACCESS_FL_STAT;
			} else if (strcmp(optarg, "open") == 0) {
				flags |= ACCESS_FL_OPEN;
			} else if (strcmp(optarg, "creat") == 0 ||
				 strcmp(optarg, "create") == 0) {
				flags |= ACCESS_FL_CREAT;
			} else if (strcmp(optarg, "read") == 0) {
				flags |= ACCESS_FL_READ;
			} else if (strcmp(optarg, "write") == 0) {
				flags |= ACCESS_FL_WRITE;
			} else {
				fprintf(stderr, "%s %s: bad access type '%s'\n",
					progname, argv[0], optarg);
				return -EINVAL;
			}
			break;
		case 's':
			start_index = strtoull(optarg, &end, 0);
			if (*end) {
				fprintf(stderr, "%s %s: bad start index '%s'\n",
					progname, argv[0], optarg);
				return -EINVAL;
			}
			break;
		case 'e':
			end_index = strtoull(optarg, &end, 0);
			if (*end) {
				fprintf(stderr, "%s %s: bad start index '%s'\n",
					progname, argv[0], optarg);
				return -EINVAL;
			}
			break;
		case 'B':
			batch_max = strtoul(optarg, &end, 0);
			if (*end) {
				fprintf(stderr, "%s %s: bad batch count '%s'\n",
					progname, argv[0], optarg);
				return -EINVAL;
			}
			break;
		case 'N':
			has_advise = false;
			break;
		case 'b':
			fname = optarg;
			break;
		case 'd':
			dirpath = optarg;
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			return -EOPNOTSUPP;
		case 'h':
			usage();
		}
	}

	if (flags == ACCESS_FL_NONE) {
		fprintf(stderr, "%s: must specify access mode\n", progname);
		return -EINVAL;
	}

	if (!dirpath) {
		fprintf(stderr, "%s: must specify directory path\n", progname);
		return -EINVAL;
	}

	if (mode == LU_AH_NAME_INDEX) {
		if (!fname) {
			fprintf(stderr, "%s: must specify base file name\n",
				progname);
			return -EINVAL;
		}

		if (end_index == 0) {
			fprintf(stderr, "%s: must specify end index\n",
				progname);
			return -EINVAL;
		}

		if (flags != ACCESS_FL_STAT) {
			fprintf(stderr, "%s: only support stat-ahead\n",
				progname);
			return -EINVAL;
		}

		if (has_advise)
			rc = ll_ahead_by_name_index(dirpath, fname, flags,
						    start_index, end_index,
						    batch_max);
		else
			rc = ll_batch_io_by_name(dirpath, fname, flags,
						 start_index, end_index);
	} else {
		rc = -EOPNOTSUPP;
		fprintf(stderr, "%s: unsupported ahead type %d\n",
			progname, mode);
	}

	return rc;
}

