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
#include <linux/lustre/lustre_disk.h>
#include <linux/lustre/lustre_ver.h>

char *progname;
static struct option const long_opts[] = {
	{ .val = 'c',	.name = "client",	.has_arg = no_argument },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'r',	.name = "reply",	.has_arg = no_argument },
	{ .name = NULL } };

/* Executes the command \a cmd and returns command status.
 */
int run_command(char *cmd, size_t cmdsz)
{
	char log[] = "/tmp/run_command_logXXXXXX";
	int fd, rc;

	if (strlen(cmd) + strlen(log) + 8 > cmdsz) {
		fprintf(stderr, "Command buffer overflow: %.*s...\n",
			(int)cmdsz, cmd);
		return -ENOMEM;
	}

	fd = mkstemp(log);
	if (fd >= 0) {
		close(fd);
		strncat(cmd, " >", cmdsz);
		strncat(cmd, log, cmdsz);
	}
	strncat(cmd, " 2>&1", cmdsz - strlen(cmd));

	/* Can't use popen because we need the rv of the command */
	rc = system(cmd);
	if (rc && fd >= 0) {
		char buf[128];
		FILE *fp;
		fp = fopen(log, "r");
		if (fp) {
			while (fgets(buf, sizeof(buf), fp) != NULL) {
				if (rc)
					printf("   %s", buf);
			}
			fclose(fp);
		}
	}
	if (fd >= 0)
		remove(log);
	return rc;
}


void display_usage(void)
{
	printf("Usage: %s [OPTIONS] devicename\n", progname);
	printf("Read and print the last_rcvd file from a device\n");
	printf("(safe for mounted devices)\n");
	printf("\t-c, --client, display client information\n");
	printf("\t-h, --help,   display this help and exit\n");
	printf("\t-r, --reply,  display reply data information\n");
}


int main(int argc, char *const argv[])
{
	char tmpdir[] = "/tmp/dirXXXXXX";
	char cmd[128];
	char filepnm[128] = "";
	char *dev;
	struct lr_server_data lsd;
	FILE *filep = NULL;
	int ret;
	int c;
	int opt_client = 0;
	int opt_reply = 0;

	progname = argv[0];
	while ((c = getopt_long(argc, argv, "chr", long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			opt_client = 1;
			break;
		case 'r':
			opt_reply = 1;
			break;
		case 'h':
		default:
			display_usage();
			return -1;
		}
	}
	dev = argv[optind];
	if (!dev) {
		display_usage();
		return -1;
	}

	/* Make a temporary directory to hold Lustre data files. */
	if (!mkdtemp(tmpdir)) {
		fprintf(stderr, "%s: Can't create temporary directory %s: %s\n",
			progname, tmpdir, strerror(errno));
		return errno;
	}

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd),
		"%s -c -R 'dump /%s %s/%s' %s",
		DEBUGFS, LAST_RCVD, tmpdir, LAST_RCVD, dev);

	ret = run_command(cmd, sizeof(cmd));
	if (ret) {
		fprintf(stderr, "%s: Unable to dump %s file\n",
			progname, LAST_RCVD);
		goto out_rmdir;
	}

	snprintf(filepnm, 128, "%s/%s", tmpdir, LAST_RCVD);
	filep = fopen(filepnm, "r");
	if (!filep) {
		fprintf(stderr, "%s: Unable to read old data\n",
			progname);
		ret = -errno;
		goto out_rmdir;
	}
	unlink(filepnm);

	/* read lr_server_data structure */
	printf("%s:\n", LAST_RCVD);
	ret = fread(&lsd, 1, sizeof(lsd), filep);
	if (ret < sizeof(lsd)) {
		fprintf(stderr, "%s: Short read (%d of %d)\n",
			progname, ret, (int)sizeof(lsd));
		ret = -ferror(filep);
		if (ret)
			goto out_close;
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

	/* read client information */
	if (opt_client) {
		lsd.lsd_client_start = __le32_to_cpu(lsd.lsd_client_start);
		lsd.lsd_client_size = __le16_to_cpu(lsd.lsd_client_size);
		printf("  client_area_start: %u\n", lsd.lsd_client_start);
		printf("  client_area_size: %hu\n", lsd.lsd_client_size);

		/* seek to per-client data area */
		ret = fseek(filep, lsd.lsd_client_start, SEEK_SET);
		if (ret) {
			fprintf(stderr, "%s: seek failed. %s\n",
				progname, strerror(errno));
			ret = errno;
			goto out_close;
		}

		/* walk throuh the per-client data area */
		while (true) {
			struct lsd_client_data lcd;

			/* read a per-client data area */
			ret = fread(&lcd, 1, sizeof(lcd), filep);
			if (ret < sizeof(lcd)) {
				if (feof(filep))
					break;
				fprintf(stderr, "%s: Short read (%d of %d)\n",
					progname, ret, (int)sizeof(lcd));
				ret = -ferror(filep);
				goto out_close;
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
	}
	fclose(filep);
	filep = NULL;

	/* read reply data information */
	if (opt_reply) {
		struct lsd_reply_header lrh;
		struct lsd_reply_data lrd;
		unsigned long long slot;

		snprintf(cmd, sizeof(cmd),
			 "%s -c -R 'dump /%s %s/%s' %s",
			 DEBUGFS, REPLY_DATA, tmpdir, REPLY_DATA, dev);

		ret = run_command(cmd, sizeof(cmd));
		if (ret) {
			fprintf(stderr, "%s: Unable to dump %s file\n",
				progname, REPLY_DATA);
			goto out_rmdir;
		}

		snprintf(filepnm, sizeof(filepnm),
			 "%s/%s", tmpdir, REPLY_DATA);
		filep = fopen(filepnm, "r");
		if (!filep) {
			fprintf(stderr, "%s: Unable to read reply data\n",
				progname);
			ret = -errno;
			goto out_rmdir;
		}
		unlink(filepnm);

		/* read reply_data header */
		printf("\n%s:\n", REPLY_DATA);
		ret = fread(&lrh, 1, sizeof(lrh), filep);
		if (ret < sizeof(lrh)) {
			fprintf(stderr, "%s: Short read (%d of %d)\n",
				progname, ret, (int)sizeof(lrh));
			ret = -ferror(filep);
			if (ret)
				goto out_close;
		}

		/* check header */
		lrh.lrh_magic = __le32_to_cpu(lrh.lrh_magic);
		lrh.lrh_header_size = __le32_to_cpu(lrh.lrh_header_size);
		lrh.lrh_reply_size = __le32_to_cpu(lrh.lrh_reply_size);
		if (lrh.lrh_magic != LRH_MAGIC) {
			fprintf(stderr, "%s: invalid %s header: "
				"lrh_magic=%08x expected %08x\n",
				progname, REPLY_DATA, lrh.lrh_magic, LRH_MAGIC);
			goto out_close;
		}
		if (lrh.lrh_header_size != sizeof(struct lsd_reply_header)) {
			fprintf(stderr, "%s: invalid %s header: "
				"lrh_header_size=%08x expected %08x\n",
				progname, REPLY_DATA, lrh.lrh_header_size,
				(unsigned int)sizeof(struct lsd_reply_header));
			goto out_close;
		}
		if (lrh.lrh_reply_size != sizeof(struct lsd_reply_data)) {
			fprintf(stderr, "%s: invalid %s header: "
				"lrh_reply_size=%08x expected %08x\n",
				progname, REPLY_DATA, lrh.lrh_reply_size,
				(unsigned int)sizeof(struct lsd_reply_data));
			goto out_close;
		}

		/* walk throuh the reply data */
		for (slot = 0; ; slot++) {
			/* read a reply data */
			ret = fread(&lrd, 1, sizeof(lrd), filep);
			if (ret < sizeof(lrd)) {
				if (feof(filep))
					break;
				fprintf(stderr, "%s: Short read (%d of %d)\n",
					progname, ret, (int)sizeof(lrd));
				ret = -ferror(filep);
				goto out_close;
			}

			/* display reply data */
			lrd.lrd_transno = __le64_to_cpu(lrd.lrd_transno);
			lrd.lrd_xid = __le64_to_cpu(lrd.lrd_xid);
			lrd.lrd_data = __le64_to_cpu(lrd.lrd_data);
			lrd.lrd_result = __le32_to_cpu(lrd.lrd_result);
			lrd.lrd_client_gen = __le32_to_cpu(lrd.lrd_client_gen);

			printf("  %lld:\n", slot);
			printf("    client_generation: %u\n",
			       lrd.lrd_client_gen);
			printf("    last_transaction: %lluu\n",
			       (unsigned long long)lrd.lrd_transno);
			printf("    last_xid: %llu\n",
			       (unsigned long long)lrd.lrd_xid);
			printf("    last_result: %u\n", lrd.lrd_result);
			printf("    last_data: %llu\n\n",
			       (unsigned long long)lrd.lrd_data);
		}
	}

out_close:
	if (filep != NULL)
		fclose(filep);

out_rmdir:
	rmdir(tmpdir);
	return ret;
}
