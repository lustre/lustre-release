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
 * Copyright (c) 2021, DDN Storage Corporation.
 */
/*
 * lustre/tests/lov_getstripe_old.c
 *
 * ll_getstripe_old <file>:
 * - to verify if the striping information of composite layout files returned
 *   by llapi_file_get_stripe() is valid.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/vfs.h>
#include <lustre/lustreapi.h>
#define LOV_MAGIC_MAGIC 0x0BD0
#define LOV_MAGIC_MASK  0xFFFF
#define LOV_MAGIC_V1            (0x0BD10000 | LOV_MAGIC_MAGIC)
#define LOV_MAGIC_JOIN_V1       (0x0BD20000 | LOV_MAGIC_MAGIC)
#define LOV_MAGIC_V3            (0x0BD30000 | LOV_MAGIC_MAGIC)
static inline int maxint(int a, int b)
{
	return a > b ? a : b;
}

static void *alloc_lum()
{
	int v1, v3;

	v1 = sizeof(struct lov_user_md_v1) +
	     LOV_MAX_STRIPE_COUNT * sizeof(struct lov_user_ost_data_v1);
	v3 = sizeof(struct lov_user_md_v3) +
	     LOV_MAX_STRIPE_COUNT * sizeof(struct lov_user_ost_data_v1);

	return malloc(maxint(v1, v3));
}

int main(int argc, char **argv)
{
	struct lov_user_md *lum_file = NULL;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
		return 1;
	}
	lum_file = alloc_lum();
	if (lum_file == NULL) {
		rc = ENOMEM;
		goto cleanup;
	}

	rc = llapi_file_get_stripe(argv[1], lum_file);
	if (rc) {
		rc = errno;
		goto cleanup;
	}
	/* stripe_size stripe_count */
	if (lum_file->lmm_magic == LOV_MAGIC_V1)
		printf("lmm_magic: v1\n");
	else if (lum_file->lmm_magic == LOV_MAGIC_V3)
		printf("lmm_magic: v3\n");
	else if (lum_file->lmm_magic == (0x0BD60000 | LOV_MAGIC_MAGIC))
		printf("lmm_magic: LOV_MAGIC component\n");

	printf("stripe_count: %d\nstripe_size: %d\n",
		lum_file->lmm_stripe_count, lum_file->lmm_stripe_size);

cleanup:
	if (lum_file != NULL)
		free(lum_file);
	return rc;
}
