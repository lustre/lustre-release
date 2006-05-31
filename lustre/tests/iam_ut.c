/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  iam_ut.c
 *  iam unit-tests
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>

#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif

#include <libcfs/libcfs.h>

enum {
        /*
         * Maximal format name length.
         */
        DX_FMT_NAME_LEN    = 16
};

struct iam_uapi_info {
        __u16 iui_keysize;
        __u16 iui_recsize;
        __u16 iui_ptrsize;
        __u16 iui_height;
        char  iui_fmt_name[DX_FMT_NAME_LEN];
};

struct iam_uapi_op {
        void *iul_key;
        void *iul_rec;
};

enum iam_ioctl_cmd {
        IAM_IOC_INIT     = _IOW('i', 1, struct iam_uapi_info),
        IAM_IOC_GETINFO  = _IOR('i', 2, struct iam_uapi_info),
        IAM_IOC_INSERT   = _IOWR('i', 3, struct iam_uapi_op),
        IAM_IOC_LOOKUP   = _IOWR('i', 4, struct iam_uapi_op)
};

static void usage(void)
{
        printf("usage: iam_ut [-v] [-h] file\n");
}

static int insert(int fd, const void *key, const void *rec)
{
        int result;

        struct iam_uapi_op op = {
                .iul_key = key,
                .iul_rec = rec
        };
        result = ioctl(fd, IAM_IOC_INSERT, &op);
        if (result != 0)
                fprintf(stderr, "ioctl(IAM_IOC_INSERT): %i (%m)\n", result);
        return result;
}

static int lookup(int fd, const void *key, void *rec)
{
        int result;

        struct iam_uapi_op op = {
                .iul_key = key,
                .iul_rec = rec
        };
        result = ioctl(fd, IAM_IOC_LOOKUP, &op);
        if (result != 0)
                fprintf(stderr, "ioctl(IAM_IOC_LOOKUP): %i (%m)\n", result);
        return result;
}

static void print_rec(const unsigned char *rec, int nr)
{
        int i;

        for (i = 0; i < nr; ++i)
                printf("%c", rec[i]);
        printf("|    |");
        for (i = 0; i < nr; ++i)
                printf("%x", rec[i]);
        printf("\n");
}

int main(int argc, char **argv)
{
        int rc;
        int fd;
        int opt;
        int blocksize = 4096;
        int keysize   = 8;
        int recsize   = 8;
        int ptrsize   = 4;
        int verbose   = 0;

        char *name;
        char rec[8];

        struct iam_uapi_info ua;

        do {
                opt = getopt(argc, argv, "v");
                switch (opt) {
                case 'v':
                        verbose++;
                case -1:
                        break;
                case 'b':
                        /* blocksize = atoi(optarg); */
                        break;
                case '?':
                default:
                        fprintf(stderr, "Unable to parse options.");
                case 'h':
                        usage();
                        return 0;
                }
        } while (opt != -1);

        if (optind >= argc) {
                fprintf(stderr, "filename missed\n");
                usage();
                return 1;
        }
        name = argv[optind];
        fd = open(name, O_RDWR);
        if (fd == -1) {
                fprintf(stderr, "open(%s): (%m)", name);
                return 1;
        }
        rc = ioctl(fd, IAM_IOC_INIT, &ua);
        if (rc != 0) {
                fprintf(stderr, "ioctl(IAM_IOC_INIT): %i (%m)", rc);
                return 1;
        }
        rc = ioctl(fd, IAM_IOC_GETINFO, &ua);
        if (rc != 0) {
                fprintf(stderr, "ioctl(IAM_IOC_GETATTR): %i (%m)", rc);
                return 1;
        }

        printf("keysize: %i, recsize: %i, ptrsize: %i, height: %i, name: %s\n",
               ua.iui_keysize, ua.iui_recsize, ua.iui_ptrsize,
               ua.iui_height, ua.iui_fmt_name);

        rc = insert(fd, "RIVERRUN", "PALEFIRE");
        if (rc != 0)
                return 1;

        rc = insert(fd, "DAEDALUS", "FINNEGAN");
        if (rc != 0)
                return 1;

        rc = insert(fd, "DAEDALUS", "FINNEGAN");
        if (errno != EEXIST) {
                if (rc == 0)
                        fprintf(stderr, "Duplicate key not detected!\n");
                return 1;
        }

        rc = lookup(fd, "RIVERRUN", rec);
        if (rc != 0)
                return 1;

        print_rec(rec, 8);

        return 0;
}
