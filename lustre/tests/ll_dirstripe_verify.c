/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * ll_dirstripe_verify <dir> <file>:
 * - to verify if the file has the same lov_user_md setting as the parent dir.
 * - if dir's offset is set -1, ll_dirstripe_verify <dir> <file1> <file2>
 *      is used to further verify if file1 and file2's obdidx is continuous.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

#include <liblustre.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <lustre/lustre_user.h>
#include <linux/obd_lov.h>

#include <portals/ptlctl.h>


#define MAX_LOV_UUID_COUNT      1000

int compare(struct lov_user_md *lum_dir, struct lov_user_md *lum_file1,
            struct lov_user_md *lum_file2)
{
        int stripe_count;
        int stripe_size;
        int stripe_offset;
        int ost_count;
        int fd;
        char buf[32];
        int i;

        stripe_count = (int)lum_dir->lmm_stripe_count;
        if (stripe_count == 0) {
                fd = open("/proc/fs/lustre/lov/lov1/stripecount", O_RDONLY);
                if (fd == -1) {
                        fprintf(stderr, "open proc file error: %s\n", 
                                strerror(errno));
                        return -1; 
                }
                if (read(fd, buf, sizeof(buf)) == -1) {
                        fprintf(stderr, "read proc file error: %s\n", 
                                strerror(errno));
                        close(fd);
                        return -1;
                }
                
                stripe_count = atoi(buf);
                stripe_count = stripe_count ? stripe_count : 1;
                close(fd);
        }

        stripe_size = (int)lum_dir->lmm_stripe_size;
        if (stripe_size == 0) {
                fd = open("/proc/fs/lustre/lov/lov1/stripesize", O_RDONLY);
                if (fd == -1) {
                        fprintf(stderr, "open proc file error: %s\n", 
                                strerror(errno)); 
                        return -1; 
                }
                if (read(fd, buf, sizeof(buf)) == -1) {
                        fprintf(stderr, "read proc file error: %s\n", 
                                strerror(errno));
                        close(fd);
                        return -1;
                }

                stripe_size = atoi(buf);
                close(fd);
        }

        fd = open("/proc/fs/lustre/lov/lov1/numobd", O_RDONLY);
        if(fd  == -1) {
                fprintf(stderr, "open proc file error: %s\n", 
                        strerror(errno));
                return -1;
        }
        if (read(fd, buf, sizeof(buf)) == -1) {
                fprintf(stderr, "read proc file error: %s\n", 
                        strerror(errno));
                close(fd);
                return -1;
        }

        ost_count = atoi(buf);
        close(fd);

        if ((lum_file1->lmm_stripe_count != stripe_count) ||
            (lum_file1->lmm_stripe_size != stripe_size))
                return -1;
        
        stripe_offset = (short int)lum_dir->lmm_stripe_offset;
        if (stripe_offset != -1) {
                for (i = 0; i < stripe_count; i++)
                        if (lum_file1->lmm_objects[i].l_ost_idx != 
                            (stripe_offset + i) % ost_count) 
                                return -1;
        } else if (lum_file2 != NULL) {
                int next, idx;
                next = (lum_file1->lmm_objects[stripe_count-1].l_ost_idx + 1)
                       % ost_count;
                idx = lum_file2->lmm_objects[0].l_ost_idx;
                if (idx != next) 
                        return -1;
        }

        return 0;        
}

int main(int argc, char **argv)
{
        DIR * dir;
        struct lov_user_md *lum_dir, *lum_file1 = NULL, *lum_file2 = NULL;
        int rc;
        int lum_size;
        char *fname;

        if (argc < 3) {
                fprintf(stderr, "Usage: %s <dirname> <filename1> [filename2]\n",
                        argv[0]);
                exit(1);
        }

        dir = opendir(argv[1]);
        if (dir  == NULL) {
                fprintf(stderr, "%s opendir failed\n", argv[1]);
                return errno;
        }

        lum_size = lov_mds_md_size(MAX_LOV_UUID_COUNT);
        if ((lum_dir = (struct lov_user_md *)malloc(lum_size)) == NULL) {
                fprintf(stderr, "unable to allocate memory for ioctl's");
                return errno;
        }        

        rc = ioctl(dirfd(dir), LL_IOC_LOV_GETSTRIPE, lum_dir);
        if (rc) {
                if (errno == ENODATA) {
                        lum_dir->lmm_stripe_size = 0;
                        lum_dir->lmm_stripe_count = 0;
                        lum_dir->lmm_stripe_offset = -1;
                } else {
                        rc = errno;
                        goto cleanup;
                }       
        }

        if ((lum_file1 = (struct lov_user_md *)malloc(lum_size)) == NULL) {
                fprintf(stderr, "unable to allocate memory for ioctl's");
                rc = errno;
                goto cleanup;
        }

        fname = strrchr(argv[2], '/');
        fname++;
        strncpy((char *)lum_file1, fname, lum_size);
        rc = ioctl(dirfd(dir), IOC_MDC_GETSTRIPE, lum_file1);
        if (rc) {
                rc = errno;
                goto cleanup;
        }

        if (argc == 4) {
                if ((lum_file2 = (struct lov_user_md *)malloc(lum_size)) 
                    == NULL) {
                        fprintf(stderr, 
                                "unable to allocate memory for ioctl's");
                        rc = errno;
                        goto cleanup;
                }

                fname = strrchr(argv[3], '/');
                fname++;
                strncpy((char *)lum_file2, fname, lum_size);
                rc = ioctl(dirfd(dir), IOC_MDC_GETSTRIPE, lum_file2);
                if (rc) {
                        rc = errno;
                        goto cleanup;
                }
        }

        rc = compare(lum_dir, lum_file1, lum_file2);

cleanup:
        if (lum_dir != NULL)
                free(lum_dir);
        if (lum_file1 != NULL)
                free(lum_file1);
        if (lum_file2 != NULL)
                free(lum_file2);

        return rc;
}
