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
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
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
 * lustre/tests/ll_getstripe_info.c
 *
 * ll_getstripe_info <file>:
 * - get file's stripe info.
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <liblustre.h>
#include <obd.h>
#include <obd_lov.h>

#include <lustre/liblustreapi.h>

#define MAX_LOV_UUID_COUNT      1000

int main(int argc, char** argv)
{
        struct lov_user_md *lum_file = NULL;
        int rc;
        int lum_size;

        if (argc != 2) {
                fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
                return 1;
        }

        lum_size = lov_mds_md_size(MAX_LOV_UUID_COUNT, LOV_MAGIC);

        if ((lum_file = (struct lov_user_md *)malloc(lum_size)) == NULL) {
                fprintf(stderr, "unable to allocate memory for ioctl's");
                rc = errno;
                goto cleanup;
        }

        rc = llapi_file_get_stripe(argv[1], lum_file);
        if (rc) {
                rc = errno;
                goto cleanup;
        }

        /* stripe_size stripe_count stripe_offset */
        printf("%d %d %d\n", 
               lum_file->lmm_stripe_size,
               lum_file->lmm_stripe_count,
               lum_file->lmm_objects[0].l_ost_idx);

cleanup:
        if (lum_file != NULL)
                free(lum_file);

        return rc;
}
