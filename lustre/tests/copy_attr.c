/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#include <stdio.h>
#include <liblustre.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <sys/types.h>
#include <attr/xattr.h>

#define XATTR_LUSTRE_MDS_OBJID          "trusted.lov"

int
main(int argc, char *argv[])
{
        struct lov_user_md *lmm1,*lmm2;
        int size;
        struct stat statbuf;

        if (argc != 3) {
                fprintf(stderr,"usage: copy_attr file1 file2 \n");
                exit(1);
        }

        size = getxattr(argv[1], XATTR_LUSTRE_MDS_OBJID, NULL, 0);
        if (size < 0) {
                perror("getting attr size");
                exit(1);
        }
        lmm1 = malloc(size);
        lmm2 = malloc(size);
        if (lmm1 == NULL || lmm2 == NULL) {
                fprintf(stderr,"Failure to get memory \n");
                exit(1);
        }

        if (getxattr(argv[1], XATTR_LUSTRE_MDS_OBJID, lmm1, size) < 0) {
                perror("getting xattr :");
                exit(1);
        }

        if (stat(argv[2], &statbuf)) {
                perror("stat");
                exit(1);
        }

        memcpy(lmm2, lmm1, size);
        lmm2->lmm_object_id = statbuf.st_ino;
        if (setxattr(argv[2], XATTR_LUSTRE_MDS_OBJID, lmm2, size, 0) < 0) {
                perror("setxattr");
                exit(1);
        }

        exit(0);
}
