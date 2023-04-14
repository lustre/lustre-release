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
 * Copyright (c) 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/lr_reader.c
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */
 /* Safely read the last_rcvd file from a device */

#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <mntent.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include <string.h>
#include <getopt.h>

#include <asm/byteorder.h>
#include <linux/lustre/lustre_idl.h>
#include <linux/lustre/lustre_disk.h>
#include <linux/lustre/lustre_ver.h>

char *progname;
static struct option const long_opts[] = {
	{ .val = 'c',	.name = "client",	.has_arg = no_argument },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'r',	.name = "reply",	.has_arg = no_argument },
	{ .val = 'R',	.name = "reply_data",	.has_arg = required_argument },
	{ .val = 'C',	.name = "last_rcvd",	.has_arg = required_argument },
	{ .name = NULL } };

void dump_log(int fd)
{
	char buf[128];
	int n;

	do {
		n = read(fd, buf, sizeof(buf));
		n = write(2, buf, n);
	} while (n == sizeof(buf));

	fprintf(stderr, "\n");
}

FILE *open_debugfs_file(char *filename, char *tmpdir, char *dev)
{
	char log[] = "/tmp/run_command_logXXXXXX";
	char filepnm[128];
	char *cmd = NULL;
	FILE *fp = NULL;
	int flog = 0;
	int cmdsize;
	int n = 128;
	int rc = 0;

	flog = mkstemp(log);
	if (flog < 0)
		return NULL;

	do {
		cmdsize = n;
		cmd = realloc(cmd, cmdsize);
		if (!cmd) {
			fprintf(stderr, "%s: Unable to allocate cmd buffer\n",
				progname);
			goto out;
		}

		n = snprintf(cmd, cmdsize,
			 "%s -c -R 'dump /%s %s/%s' %s > %s 2>&1",
			 DEBUGFS, filename, tmpdir, filename, dev, log);
		n++;

	} while (n > cmdsize);

	rc = system(cmd);
	free(cmd);
	if (rc) {
		fprintf(stderr, "%s: Unable to dump %s file\n",
			progname, filename);
		goto out;
	}

	snprintf(filepnm, sizeof(filepnm), "%s/%s", tmpdir, filename);
	fp = fopen(filepnm, "r");
	if (!fp)
		rc = errno;

	unlink(filepnm);

out:
	if (rc)
		dump_log(flog);

	close(flog);
	unlink(log);

	errno = rc;
	return fp;
}

int print_last_rcvd(FILE *fp, int opt_client)
{
	struct lr_server_data lsd = {};
	int rc = 0;
	int n;

	/* read lr_server_data structure */
	printf("%s:\n", LAST_RCVD);
	n = fread(&lsd, 1, sizeof(lsd), fp);
	if (n < sizeof(lsd)) {
		fprintf(stderr, "%s: Short read (%d of %d)\n",
			progname, n, (int)sizeof(lsd));
		rc = ferror(fp) ? EIO : EINVAL;
	}

	/* swab structure fields of interest */
	lsd.lsd_feature_compat = __le32_to_cpu(lsd.lsd_feature_compat);
	lsd.lsd_feature_incompat = __le32_to_cpu(lsd.lsd_feature_incompat);
	lsd.lsd_feature_rocompat = __le32_to_cpu(lsd.lsd_feature_rocompat);
	lsd.lsd_last_transno = __le64_to_cpu(lsd.lsd_last_transno);
	lsd.lsd_osd_index = __le32_to_cpu(lsd.lsd_osd_index);
	lsd.lsd_mount_count = __le64_to_cpu(lsd.lsd_mount_count);

	/* display */
	printf("  uuid: %.40s\n", lsd.lsd_uuid);
	printf("  feature_compat: %#x\n", lsd.lsd_feature_compat);
	printf("  feature_incompat: %#x\n", lsd.lsd_feature_incompat);
	printf("  feature_rocompat: %#x\n", lsd.lsd_feature_rocompat);
	printf("  last_transaction: %llu\n",
	       (unsigned long long)lsd.lsd_last_transno);
	printf("  target_index: %u\n", lsd.lsd_osd_index);
	printf("  mount_count: %llu\n",
	       (unsigned long long)lsd.lsd_mount_count);

	if (!opt_client || rc)
		return rc;

	/* read client information */
	lsd.lsd_client_start = __le32_to_cpu(lsd.lsd_client_start);
	lsd.lsd_client_size = __le16_to_cpu(lsd.lsd_client_size);
	printf("  client_area_start: %u\n", lsd.lsd_client_start);
	printf("  client_area_size: %hu\n", lsd.lsd_client_size);

	/* seek to per-client data area */
	rc = fseek(fp, lsd.lsd_client_start, SEEK_SET);
	if (rc) {
		fprintf(stderr, "%s: seek failed. %s\n",
			progname, strerror(errno));
		return errno;
	}

	/* walk throuh the per-client data area */
	while (true) {
		struct lsd_client_data lcd;

		/* read a per-client data area */
		n = fread(&lcd, 1, sizeof(lcd), fp);
		if (n < sizeof(lcd)) {
			if (feof(fp))
				break;
			fprintf(stderr, "%s: Short read (%d of %d)\n",
				progname, n, (int)sizeof(lcd));
			return ferror(fp) ? EIO : EINVAL;
		}

		if (lcd.lcd_uuid[0] == '\0')
			continue;

		/* swab structure fields */
		lcd.lcd_last_transno =
			__le64_to_cpu(lcd.lcd_last_transno);
		lcd.lcd_last_xid = __le64_to_cpu(lcd.lcd_last_xid);
		lcd.lcd_last_result = __le32_to_cpu(lcd.lcd_last_result);
		lcd.lcd_last_data = __le32_to_cpu(lcd.lcd_last_data);
		lcd.lcd_generation = __le32_to_cpu(lcd.lcd_generation);

		/* display per-client data area */
		printf("\n  %.40s:\n", lcd.lcd_uuid);
		printf("    generation: %u\n", lcd.lcd_generation);
		printf("    last_transaction: %llu\n",
		       (unsigned long long)lcd.lcd_last_transno);
		printf("    last_xid: %llu\n",
		       (unsigned long long)lcd.lcd_last_xid);
		printf("    last_result: %u\n", lcd.lcd_last_result);
		printf("    last_data: %u\n", lcd.lcd_last_data);

		if (lcd.lcd_last_close_transno != 0 &&
		    lcd.lcd_last_close_xid != 0) {
			lcd.lcd_last_close_transno =
				__le64_to_cpu(lcd.lcd_last_close_transno);
			lcd.lcd_last_close_xid =
				__le64_to_cpu(lcd.lcd_last_close_xid);
			lcd.lcd_last_close_result =
				__le32_to_cpu(lcd.lcd_last_close_result);
			lcd.lcd_last_close_data =
				__le32_to_cpu(lcd.lcd_last_close_data);
			printf("    last_close_transation: %llu\n",
			       (unsigned long long)lcd.lcd_last_close_transno);
			printf("    last_close_xid: %llu\n",
			       (unsigned long long)lcd.lcd_last_close_xid);
			printf("    last_close_result: %u\n",
			       lcd.lcd_last_close_result);
			printf("    last_close_data: %u\n",
			       lcd.lcd_last_close_data);
		}
	}

	return 0;
}

int print_reply_data(FILE *fp)
{
	struct lsd_reply_header lrh = {};
	unsigned long long slot;
	__u32 recsz;
	int rc = 0;
	int n;

	/* read reply_data header */
	printf("\n%s:\n", REPLY_DATA);
	n = fread(&lrh, 1, sizeof(lrh), fp);
	if (n < sizeof(lrh)) {
		fprintf(stderr, "%s: Short read (%d of %d)\n",
			progname, n, (int)sizeof(lrh));
		rc = ferror(fp) ? EIO : EINVAL;
	}

	/* check header */
	lrh.lrh_magic = __le32_to_cpu(lrh.lrh_magic);
	lrh.lrh_header_size = __le32_to_cpu(lrh.lrh_header_size);
	lrh.lrh_reply_size = __le32_to_cpu(lrh.lrh_reply_size);
	if (lrh.lrh_header_size != sizeof(struct lsd_reply_header)) {
		fprintf(stderr,
			"%s: invalid %s header: lrh_header_size=0x%08x expected 0x%08x\n",
			progname, REPLY_DATA, lrh.lrh_header_size,
			(unsigned int)sizeof(struct lsd_reply_header));
		rc = EINVAL;
	}
	if (lrh.lrh_magic == LRH_MAGIC_V2) {
		if (lrh.lrh_reply_size != sizeof(struct lsd_reply_data)) {
			fprintf(stderr,
				"%s: invalid %s header: lrh_reply_size=0x%08x expected 0x%08x\n",
				progname, REPLY_DATA, lrh.lrh_reply_size,
				(unsigned int)sizeof(struct lsd_reply_data));
			rc = EINVAL;
		} else {
			recsz = sizeof(struct lsd_reply_data);
		}
	} else if (lrh.lrh_magic == LRH_MAGIC_V1) {
		if (lrh.lrh_reply_size != sizeof(struct lsd_reply_data_v1)) {
			fprintf(stderr,
				"%s: invalid %s header: lrh_reply_size=0x%08x expected 0x%08x\n",
				progname, REPLY_DATA, lrh.lrh_reply_size,
				(unsigned int)sizeof(struct lsd_reply_data));
			rc = EINVAL;
		} else {
			recsz = sizeof(struct lsd_reply_data_v1);
		}
	} else {
		fprintf(stderr,
			"%s: invalid %s header: lrh_magic=0x%08x expected 0x%08x or 0x%08x\n",
			progname, REPLY_DATA, lrh.lrh_magic, LRH_MAGIC_V1,
			LRH_MAGIC_V2);
		rc = EINVAL;
	}

	if (rc) {
		/* dump header */
		fprintf(stderr, "lsd_reply_header:\n");
		fprintf(stderr, "\tlrh_magic: 0x%08x\n", lrh.lrh_magic);
		fprintf(stderr, "\tlrh_header_size: %u\n", lrh.lrh_header_size);
		fprintf(stderr, "\tlrh_reply_size: %u\n", lrh.lrh_reply_size);
		return rc;
	}

	/* walk throuh the reply data */
	for (slot = 0; ; slot++) {
		struct lsd_reply_data lrd;

		/* read a reply data */
		n = fread(&lrd, 1, recsz, fp);
		if (n < recsz) {
			if (feof(fp))
				break;
			fprintf(stderr, "%s: Short read (%d of %d)\n",
				progname, n, (int)sizeof(lrd));
			return ferror(fp) ? EIO : EINVAL;
		}

		/* display reply data */
		lrd.lrd_transno = __le64_to_cpu(lrd.lrd_transno);
		lrd.lrd_xid = __le64_to_cpu(lrd.lrd_xid);
		lrd.lrd_data = __le64_to_cpu(lrd.lrd_data);
		lrd.lrd_result = __le32_to_cpu(lrd.lrd_result);
		lrd.lrd_client_gen = __le32_to_cpu(lrd.lrd_client_gen);

		if (lrh.lrh_magic > LRH_MAGIC_V1)
			lrd.lrd_batch_idx = __le32_to_cpu(lrd.lrd_batch_idx);

		printf("  %lld:\n", slot);
		printf("    client_generation: %u\n",
		       lrd.lrd_client_gen);
		printf("    last_transaction: %llu\n",
		       (unsigned long long)lrd.lrd_transno);
		printf("    last_xid: %llu\n",
		       (unsigned long long)lrd.lrd_xid);
		printf("    last_result: %u\n", lrd.lrd_result);
		printf("    last_data: %llu\n\n",
		       (unsigned long long)lrd.lrd_data);
		if (lrh.lrh_magic > LRH_MAGIC_V1)
			printf("    batch_idx: %u\n", lrd.lrd_batch_idx);
	}

	return 0;
}

void display_usage(void)
{
	printf("Usage: %s [OPTIONS] devicename\n", progname);
	printf("Usage: %s [OPTIONS] -C <last_rcvd_file> -R <reply_data_file>\n",
	       progname);
	printf("Read and print the last_rcvd/reply_data file from a device\n");
	printf("(safe for mounted devices) or from a file\n");
	printf("\t-c, --client, display client information\n");
	printf("\t-h, --help,   display this help and exit\n");
	printf("\t-r, --reply,  display reply data information\n");
	printf("\t-C FILE, --last_rcvd=FILE, specify FILE as input for client information\n");
	printf("\t-R FILE, --reply_data=FILE, specify FILE as input for reply information\n");
}


int main(int argc, char *const argv[])
{
	char tmpdir[] = "/tmp/dirXXXXXX";
	char *dev;
	FILE *filep = NULL;
	int ret = 0;
	int c;
	int opt_client = 0;
	int opt_reply = 0;
	char *file_client = NULL;
	char *file_reply = NULL;
	int need_dev = 1;

	progname = basename(argv[0]);
	while ((c = getopt_long(argc, argv, "hcrC:R:", long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			opt_client = 1;
			break;
		case 'r':
			opt_reply = 1;
			break;
		case 'C':
			file_client = optarg;
			break;
		case 'R':
			file_reply = optarg;
			break;
		case 'h':
		default:
			display_usage();
			return -1;
		}
	}

	if ((file_reply && file_client) ||
	    (!opt_reply && file_client) ||
	    (!opt_client && opt_reply && file_reply))
		need_dev = 0;

	dev = argv[optind];
	if (need_dev && !dev) {
		display_usage();
		return -1;
	}

	/* Make a temporary directory to hold Lustre data files. */
	if (need_dev && !mkdtemp(tmpdir)) {
		fprintf(stderr, "%s: Can't create temporary directory %s: %s\n",
			progname, tmpdir, strerror(errno));
		return errno;
	}

	if (file_client || dev) {
		if (file_client)
			filep = fopen(file_client, "r");
		else
			filep = open_debugfs_file(LAST_RCVD, tmpdir, dev);

		if (!filep) {
			ret = errno;
			fprintf(stderr, "%s: Can't open %s: %s\n",
				progname, LAST_RCVD, strerror(errno));
			goto out_rmdir;
		}

		ret = print_last_rcvd(filep, opt_client);
		fclose(filep);
		filep = NULL;
		if (ret)
			goto out_rmdir;
	}

	if (opt_reply) {
		if (file_reply)
			filep = fopen(file_reply, "r");
		else
			filep = open_debugfs_file(REPLY_DATA, tmpdir, dev);

		if (!filep) {
			ret = errno;
			fprintf(stderr, "%s: Can't open %s: %s\n",
				progname, LAST_RCVD, strerror(errno));
			goto out_rmdir;
		}

		ret = print_reply_data(filep);
		fclose(filep);
	}

out_rmdir:
	if (need_dev)
		rmdir(tmpdir);
	return ret;
}
