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
#include <ctype.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

#include <liblustre.h>
#include <obd.h>
#include <lustre_lib.h>
#include <lustre/lustre_user.h>
#include <obd_lov.h>

#include <lnet/lnetctl.h>


#define MAX_LOV_UUID_COUNT      1000

int read_proc_entry(char *proc_path, char *buf, int len)
{
        int rcnt = -2, fd;

        if ((fd = open(proc_path, O_RDONLY)) == -1) {
                fprintf(stderr, "open('%s') failed: %s\n",
                        proc_path, strerror(errno));
                rcnt = -3;
        } else if ((rcnt = read(fd, buf, len)) <= 0) {
                fprintf(stderr, "read('%s') failed: %s\n",
                        proc_path, strerror(errno));
        } else {
                buf[rcnt - 1] = '\0';
        }

        if (fd >= 0)
                close(fd);

        return (rcnt);
}

int compare(struct lov_user_md *lum_dir, struct lov_user_md *lum_file1,
            struct lov_user_md *lum_file2)
{
        int stripe_count = 0;
        int stripe_size = 0;
        int stripe_offset = -1;
        int ost_count;
        char buf[128];
        char lov_path[PATH_MAX];
        char tmp_path[PATH_MAX];
        int i, rc;

        rc = read_proc_entry("/proc/fs/lustre/llite/fs0/lov/common_name",
                             buf, sizeof(buf)) <= 0;
        if (rc < 0)
                return -rc;

        snprintf(lov_path, sizeof(lov_path) - 1, "/proc/fs/lustre/lov/%s", buf);

        if (lum_dir == NULL) {
                snprintf(tmp_path, sizeof(tmp_path) - 1, "%s/stripecount",
                         lov_path);
                if (read_proc_entry(tmp_path, buf, sizeof(buf)) <= 0)
                        return 5;

                stripe_count = atoi(buf);
        } else {
                stripe_count = (int)lum_dir->lmm_stripe_count;
        }
        if (stripe_count == 0)
                stripe_count = 1;

        snprintf(tmp_path, sizeof(tmp_path) - 1, "%s/numobd", lov_path);
        if (read_proc_entry(tmp_path, buf, sizeof(buf)) <= 0)
                return 6;

        ost_count = atoi(buf);
        stripe_count = stripe_count > 0 ? stripe_count : ost_count;

        if (lum_file1->lmm_stripe_count != stripe_count) {
                fprintf(stderr, "file1 stripe count %d != dir %d\n",
                        lum_file1->lmm_stripe_count, stripe_count);
                return 7;
        }

        if (lum_dir != NULL)
                stripe_size = (int)lum_dir->lmm_stripe_size;
        if (stripe_size == 0) {
                snprintf(tmp_path, sizeof(tmp_path) - 1, "%s/stripesize",
                         lov_path);
                if (read_proc_entry(tmp_path, buf, sizeof(buf)) <= 0)
                        return 5;

                stripe_size = atoi(buf);
        }

        if (lum_file1->lmm_stripe_size != stripe_size) {
                fprintf(stderr, "file1 stripe size %d != dir %d\n",
                        lum_file1->lmm_stripe_size, stripe_size);
                return 8;
        }

        if (lum_dir != NULL)
                stripe_offset = (short int)lum_dir->lmm_stripe_offset;
        if (stripe_offset != -1) {
                for (i = 0; i < stripe_count; i++)
                        if (lum_file1->lmm_objects[i].l_ost_idx !=
                            (stripe_offset + i) % ost_count) {
                                fprintf(stderr, "warning: file1 non-sequential "
                                        "stripe[%d] %d != %d\n", i,
                                        lum_file1->lmm_objects[i].l_ost_idx,
                                        (stripe_offset + i) % ost_count);
                        }
        } else if (lum_file2 != NULL) {
                int next, idx, stripe = stripe_count - 1;
                next = (lum_file1->lmm_objects[stripe].l_ost_idx + 1) %
                       ost_count;
                idx = lum_file2->lmm_objects[0].l_ost_idx;
                if (idx != next) {
                        fprintf(stderr, "warning: non-sequential "
                                "file1 stripe[%d] %d != file2 stripe[0] %d\n",
                                stripe,
                                lum_file1->lmm_objects[stripe].l_ost_idx, idx);
                }
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
        if (dir == NULL) {
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
                        free(lum_dir);
                        lum_dir = NULL;
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
                lum_file2 = (struct lov_user_md *)malloc(lum_size);
                if (lum_file2 == NULL) {
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
