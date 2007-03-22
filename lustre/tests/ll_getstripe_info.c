/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
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

        lum_size = lov_mds_md_size(MAX_LOV_UUID_COUNT);

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
