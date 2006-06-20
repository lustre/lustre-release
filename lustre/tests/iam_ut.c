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
#include <assert.h>

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

struct iam_uapi_it {
        struct iam_uapi_op iui_op;
        __u16              iui_state;
};

enum iam_ioctl_cmd {
        IAM_IOC_INIT     = _IOW('i', 1, struct iam_uapi_info),
        IAM_IOC_GETINFO  = _IOR('i', 2, struct iam_uapi_info),
        IAM_IOC_INSERT   = _IOR('i', 3, struct iam_uapi_op),
        IAM_IOC_LOOKUP   = _IOWR('i', 4, struct iam_uapi_op),
        IAM_IOC_DELETE   = _IOR('i', 5, struct iam_uapi_op),
        IAM_IOC_IT_START = _IOR('i', 6, struct iam_uapi_it),
        IAM_IOC_IT_NEXT  = _IOW('i', 7, struct iam_uapi_it),
        IAM_IOC_IT_STOP  = _IOR('i', 8, struct iam_uapi_it)
};

static void usage(void)
{
        printf("usage: iam_ut [-v] [-h] file\n");
}

static int doop(int fd, const void *key, const void *rec,
                int cmd, const char *name)
{
        int result;

        struct iam_uapi_op op = {
                .iul_key = key,
                .iul_rec = rec
        };
        result = ioctl(fd, cmd, &op);
        if (result != 0)
                fprintf(stderr, "ioctl(%s): %i/%i (%m)\n", name, result, errno);
        return result;
}

static int doit(int fd, const void *key, const void *rec,
                int cmd, const char *name)
{
        int result;

        struct iam_uapi_it it = {
                .iui_op = {
                        .iul_key = key,
                        .iul_rec = rec
                },
                .iui_state = 0
        };

        assert((void *)&it == (void *)&it.iui_op);

        result = ioctl(fd, cmd, &it);
        if (result != 0)
                fprintf(stderr, "ioctl(%s): %i/%i (%m)\n", name, result, errno);
        else
                result = it.iui_state;
        return result;
}

static int insert(int fd, const void *key, const void *rec)
{
        return doop(fd, key, rec, IAM_IOC_INSERT, "IAM_IOC_INSERT");
}

static int lookup(int fd, const void *key, void *rec)
{
        return doop(fd, key, rec, IAM_IOC_LOOKUP, "IAM_IOC_LOOKUP");
}

static int delete(int fd, const void *key, void *rec)
{
        return doop(fd, key, rec, IAM_IOC_DELETE, "IAM_IOC_DELETE");
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

enum op {
        OP_TEST,
        OP_INSERT,
        OP_LOOKUP,
        OP_DELETE,
        OP_IT_START,
        OP_IT_NEXT,
        OP_IT_STOP
};

unsigned char hex2dec(unsigned char hex)
{
        if ('0' <= hex && hex <= '9')
                return hex - '0';
        else if ('a' <= hex && hex <= 'f')
                return hex - 'a';
        else {
                fprintf(stderr, "Wrong hex digit '%c'\n", hex);
                exit(1);
        }
}

unsigned char *packdigit(unsigned char *number)
{
        unsigned char *area;
        unsigned char *scan;

        area = calloc(strlen(number) / 2 + 2, sizeof area[0]);
        if (area != NULL) {
                for (scan = area; *number; number += 2, scan++)
                        *scan = (hex2dec(number[0]) << 4) | hex2dec(number[1]);
        }
        return area;
}

int main(int argc, char **argv)
{
        int i;
        int rc;
        int opt;
        int keysize;
        int recsize;
        int N = 0x10000;
        int verbose = 0;
        int doinit = 1;

        enum op op;

        char *key;
        char *rec;

        char *key_opt;
        char *rec_opt;

        struct iam_uapi_info ua;

        setbuf(stdout, NULL);
        setbuf(stderr, NULL);

        key_opt = NULL;
        rec_opt = NULL;

        op = OP_TEST;

        do {
                opt = getopt(argc, argv, "vilk:K:N:r:R:dsSn");
                switch (opt) {
                case 'v':
                        verbose++;
                case -1:
                        break;
                case 'K':
                        key_opt = packdigit(optarg);
                        break;
                case 'k':
                        key_opt = optarg;
                        break;
                case 'N':
                        N = atoi(optarg);
                        break;
                case 'R':
                        rec_opt = packdigit(optarg);
                        break;
                case 'r':
                        rec_opt = optarg;
                        break;
                case 'i':
                        op = OP_INSERT;
                        break;
                case 'l':
                        op = OP_LOOKUP;
                        break;
                case 'd':
                        op = OP_DELETE;
                        break;
                case 's':
                        op = OP_IT_START;
                        break;
                case 'S':
                        op = OP_IT_STOP;
                        doinit = 0;
                        break;
                case 'n':
                        op = OP_IT_NEXT;
                        doinit = 0;
                        break;
                case '?':
                default:
                        fprintf(stderr, "Unable to parse options.");
                case 'h':
                        usage();
                        return 0;
                }
        } while (opt != -1);

        if (doinit) {
                rc = ioctl(0, IAM_IOC_INIT, &ua);
                if (rc != 0) {
                        fprintf(stderr, "ioctl(IAM_IOC_INIT): %i (%m)\n", rc);
                        return 1;
                }
        }
        rc = ioctl(0, IAM_IOC_GETINFO, &ua);
        if (rc != 0) {
                fprintf(stderr, "ioctl(IAM_IOC_GETATTR): %i (%m)\n", rc);
                return 1;
        }

        keysize = ua.iui_keysize;
        recsize = ua.iui_recsize;
        if (verbose > 0)
                printf("keysize: %i, recsize: %i, ptrsize: %i, "
                       "height: %i, name: %s\n",
                       keysize, recsize, ua.iui_ptrsize,
                       ua.iui_height, ua.iui_fmt_name);

        key = calloc(keysize + 1, sizeof key[0]);
        rec = calloc(recsize + 1, sizeof rec[0]);

        if (key == NULL || rec == NULL) {
                fprintf(stderr, "cannot allocate memory\n");
                return 1;
        }

        memcpy(key, key_opt ? : "RIVERRUN", keysize + 1);
        memcpy(rec, rec_opt ? : "PALEFIRE", recsize + 1);

        if (op == OP_INSERT)
                return doop(0, key, rec, IAM_IOC_INSERT, "IAM_IOC_INSERT");
        else if (op == OP_DELETE)
                return doop(0, key, rec, IAM_IOC_DELETE, "IAM_IOC_DELETE");
        else if (op == OP_LOOKUP) {
                rc = doop(0, key, rec, IAM_IOC_LOOKUP, "IAM_IOC_LOOKUP");
                if (rc == 0)
                        print_rec(rec, recsize);
                return rc;
        } else if (op == OP_IT_START) {
                rc = doop(0, key, rec, IAM_IOC_IT_START, "IAM_IOC_IT_START");
                if (rc == 0) {
                        print_rec(key, keysize);
                        print_rec(rec, recsize);
                }
                return rc;
        } else if (op == OP_IT_STOP) {
                return doop(0, key, rec, IAM_IOC_IT_STOP, "IAM_IOC_IT_STOP");
        } else if (op == OP_IT_NEXT) {
                rc = doop(0, key, rec, IAM_IOC_IT_NEXT, "IAM_IOC_IT_NEXT");
                if (rc == 0) {
                        print_rec(key, keysize);
                        print_rec(rec, recsize);
                }
                return rc;
        }

        rc = insert(0, key, rec);
        if (rc != 0)
                return 1;

        rc = insert(0, "DAEDALUS", "FINNEGAN");
        if (rc != 0)
                return 1;

        rc = insert(0, "DAEDALUS", "FINNEGAN");
        if (errno != EEXIST) {
                if (rc == 0)
                        fprintf(stderr, "Duplicate key not detected!\n");
                return 1;
        }

        rc = lookup(0, "RIVERRUN", rec);
        if (rc != 0)
                return 1;

        print_rec(rec, recsize);

        for (i = 0; i < N; ++i) {
                memset(key, 0, keysize + 1);
                memset(rec, 0, recsize + 1);
                snprintf(key, keysize + 1, "y-%x-x", i);
                snprintf(rec, recsize + 1, "p-%x-q", 1000 - i);
                rc = insert(0, key, rec);
                if (rc != 0)
                        return 1;
                if (verbose > 1)
                        printf("key %#x inserted\n", i);
        }

        return 0;
}
