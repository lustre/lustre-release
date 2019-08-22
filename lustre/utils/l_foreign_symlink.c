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
 * Copyright (c) 2020, Intel Corporation.
 */

/*
 * lustre/utils/l_foreign_symlink.c
 * Userland helper to provide detailed format items in order to allow for
 * a fast parsing of foreign symlink LOV/LMV EAs in llite.
 * Presently, the foreign symlink LOV/LMV EAs format and its translation
 * in format items is hard-coded, but in the future we may want to make it
 * smarter and automatize this process by some mean.
 */

#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <syslog.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stddef.h>
#include <ctype.h>
#include <dirent.h>
#include <getopt.h>

#include <libcfs/util/param.h>
#include <linux/lustre/lustre_user.h>
#include <linux/lustre/lustre_idl.h>

#define UUID_STRING_LENGTH 36
#define MAX_BUF_SIZE 1024

static char *progname;

static void errlog(const char *fmt, ...)
{
	va_list args;

	openlog(progname, LOG_PERROR | LOG_PID, LOG_KERN);

	va_start(args, fmt);
	vsyslog(LOG_ERR, fmt, args);
	va_end(args);

	closelog();
}

int main(int argc, char **argv)
{
	/* we want to request llite layer to parse each foreign symlink
	 * LOV/LMV EAs with lfm_value of format "<PUUID>:<CUUID>" and
	 * translate it as "<UUID>/<UUID>" relative path.
	 * To do so, will need to pass a serie of 4 items, one for
	 * <PUUID> position and length in lfm_value, one with constant
	 * string "/", one for <CUUID> position and length in lfm_value,
	 * a last one to indicate end of serie.
	 */
	struct ll_foreign_symlink_upcall_item *items;
	char *buf;
	glob_t path;
	int fd, rc;

	progname = basename(argv[0]);

	if (argc != 2) {
		errlog("usage: %s <sbi_sysfs_object_name>\n", argv[0]);
		return -1;
	}

	buf = malloc(MAX_BUF_SIZE);
	if (buf == NULL) {
		errlog("unable to allocate MAX_BUF_SIZE bytes\n");
		return -1;
	}

	/* the number of items is presently limited to MAX_NB_UPCALL_ITEMS */

	/* all items are expected to be on a __u32 boundary by llite */

	/* 1st item to locate <PUUID> */
	items = (struct ll_foreign_symlink_upcall_item *)buf;
	items->type = POSLEN_TYPE;
	items->pos = 0;
	items->len = UUID_STRING_LENGTH;

	/* 2nd item to store "/" string */
	items = (struct ll_foreign_symlink_upcall_item *)((char *)items +
			POSLEN_ITEM_SZ);
	items->type = STRING_TYPE;
	/* NUL byte is not necessary */
	items->size = strlen("/");
	memcpy(items->bytestring, "/", strlen("/"));
	/* space occupied by string will fit on __u32 boundary */

	/* 3rd item to locate <CUUID> */
	items = (struct ll_foreign_symlink_upcall_item *)((char *)items +
		STRING_ITEM_SZ(items->size));
	items->type = POSLEN_TYPE;
	items->pos = UUID_STRING_LENGTH + 1;
	items->len = UUID_STRING_LENGTH;

	/* 4th item is end of buf */
	items = (struct ll_foreign_symlink_upcall_item *)((char *)items +
			POSLEN_ITEM_SZ);
	items->type = EOB_TYPE;

	/* Send foreign symlink parsing items info to kernelspace */
	rc = cfs_get_param_paths(&path, "llite/%s/foreign_symlink_upcall_info",
				 argv[1]);
	if (rc != 0) {
		errlog("can't get param 'llite/%s/foreign_symlink_upcall_info': %s\n",
		       argv[1], strerror(errno));
		rc = -errno;
		goto out;
	}

	fd = open(path.gl_pathv[0], O_WRONLY);
	if (fd < 0) {
		errlog("can't open file '%s':%s\n", path.gl_pathv[0],
		       strerror(errno));
		rc = -errno;
		goto out_param;
	}

	rc = write(fd, buf, (char *)items + sizeof(items->type) - buf);
	close(fd);
	if (rc != (char *)items + sizeof(items->type) - buf) {
		errlog("partial write ret %d: %s\n", rc, strerror(errno));
		rc = -errno;
	} else {
		rc = 0;
	}

out_param:
	cfs_free_param_data(&path);
out:
	if (isatty(STDIN_FILENO))
		/* we are called from the command line */
		return rc < 0 ? -rc : rc;
	else
		return rc;
}
