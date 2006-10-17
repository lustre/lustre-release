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

/* Returns bytes read on success and a negative value on failure.
 * If zero bytes are read it will be treated as failure as such
 * zero cannot be returned from this function.
 */
int read_proc_entry(char *proc_path, char *buf, int len)
{
        int rc, fd;

        memset(buf, 0, len);

        fd = open(proc_path, O_RDONLY);
        if (fd == -1) {
                fprintf(stderr, "open('%s') failed: %s\n",
                        proc_path, strerror(errno));
                return -2;
        }

        rc = read(fd, buf, len - 1);
        if (rc < 0) {
                fprintf(stderr, "read('%s') failed: %s\n",
                        proc_path, strerror(errno));
                rc = -3;
        } else if (rc == 0) {
                fprintf(stderr, "read('%s') zero bytes\n", proc_path);
                rc = -4;
        } else if (/* rc > 0 && */ buf[rc - 1] == '\n') {
                buf[rc - 1] = '\0'; /* Remove trailing newline */
        }
        close(fd);

        return (rc);
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
        int i;
        FILE *fp;

        fp = popen("\\ls -d  /proc/fs/lustre/lov/*clilov*", "r");
        if (!fp) {
                fprintf(stderr, "open(lustre/lov/*clilov*) failed: %s\n", 
                        strerror(errno));
                return 2;
        }
        if (fscanf(fp, "%s", lov_path) < 1) { 
                fprintf(stderr, "read(lustre/lov/*clilov*) failed: %s\n",
                        strerror(errno));
                pclose(fp);
                return 3;
        }
        pclose(fp);

        if (lum_dir == NULL) {
                snprintf(tmp_path, sizeof(tmp_path) - 1, "%s/stripecount",
                         lov_path);
                if (read_proc_entry(tmp_path, buf, sizeof(buf)) < 0)
                        return 5;

                stripe_count = (int)strtoul(buf, NULL, 10);;
        } else {
                stripe_count = (signed short)lum_dir->lmm_stripe_count;
        }
        if (stripe_count == 0)
                stripe_count = 1;

        snprintf(tmp_path, sizeof(tmp_path) - 1, "%s/numobd", lov_path);
        if (read_proc_entry(tmp_path, buf, sizeof(buf)) < 0)
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
                if (read_proc_entry(tmp_path, buf, sizeof(buf)) < 0)
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
                return 1;
        }

        dir = opendir(argv[1]);
        if (dir == NULL) {
                fprintf(stderr, "%s opendir failed: %s\n", argv[1], 
                        strerror(errno));
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
        fname = (fname == NULL ? argv[2] : fname + 1);

        strncpy((char *)lum_file1, fname, lum_size);
        rc = ioctl(dirfd(dir), IOC_MDC_GETFILESTRIPE, lum_file1);
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
                fname = (fname == NULL ? argv[3] : fname + 1);
                strncpy((char *)lum_file2, fname, lum_size);
                rc = ioctl(dirfd(dir), IOC_MDC_GETFILESTRIPE, lum_file2);
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
