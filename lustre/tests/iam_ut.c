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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/tests/iam_ut.c
 *
 * iam_ut.c
 * iam unit-tests
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
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
        IAM_IOC_IT_STOP  = _IOR('i', 8, struct iam_uapi_it),

        IAM_IOC_POLYMORPH = _IOR('i', 9, unsigned long)
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

static int rec_is_nul_term(int recsize)
{
        return recsize == 255;
}

static void print_rec(const unsigned char *rec, int nr)
{
        int i;

        for (i = 0; i < nr; ++i) {
                printf("%c", rec[i]);
                if (rec_is_nul_term(nr) && rec[i] == 0)
                        break;
        }
        printf("|    |");
        for (i = 0; i < nr; ++i) {
                printf("%x", rec[i]);
                if (rec_is_nul_term(nr) && rec[i] == 0)
                        break;
        }
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
        if ('0' <= hex && hex <= '9') {
                return hex - '0';
        } else if ('a' <= hex && hex <= 'f') {
                return hex - 'a' + 10;
        } else if ('A' <= hex && hex <= 'F') {
                return hex - 'A' + 10;
        } else {
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
        int keynul = 1;
        int recnul = 1;

        void *(*copier)(void *, void *, size_t);

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
                opt = getopt(argc, argv, "vilk:K:N:r:R:dsSnP:");
                switch (opt) {
                case 'v':
                        verbose++;
                case -1:
                        break;
                case 'K':
                        key_opt = packdigit(optarg);
                        keynul = 0;
                        break;
                case 'k':
                        key_opt = optarg;
                        break;
                case 'N':
                        N = atoi(optarg);
                        break;
                case 'R':
                        rec_opt = packdigit(optarg);
                        recnul = 0;
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
                case 'P': {
                        unsigned long mode;

                        mode = strtoul(optarg, NULL, 0);
                        rc = ioctl(0, IAM_IOC_POLYMORPH, mode);
                        if (rc == -1)
                                perror("IAM_IOC_POLYMORPH");
                        return 0;
                }
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
                rc = 1;
                goto out;
        }

        copier = keynul ? &strncpy : &memcpy;
        copier(key, key_opt ? : "RIVERRUN", keysize + 1);
        if (keynul == 0) {
                free(key_opt);
                key_opt = NULL;
        }
        copier = recnul ? &strncpy : &memcpy;
        copier(rec, rec_opt ? : "PALEFIRE", recsize + 1);
        if (recnul == 0) {
                free(rec_opt);
                rec_opt = NULL;
        }

        if (op == OP_INSERT) {
                rc = doop(0, key, rec, IAM_IOC_INSERT, "IAM_IOC_INSERT");
                goto out;
        } else if (op == OP_DELETE) {
                rc = doop(0, key, rec, IAM_IOC_DELETE, "IAM_IOC_DELETE");
                goto out;
        } else if (op == OP_LOOKUP) {
                rc = doop(0, key, rec, IAM_IOC_LOOKUP, "IAM_IOC_LOOKUP");
                if (rc == 0)
                        print_rec(rec, recsize);
                goto out;
        } else if (op == OP_IT_START) {
                rc = doop(0, key, rec, IAM_IOC_IT_START, "IAM_IOC_IT_START");
                if (rc == 0) {
                        print_rec(key, keysize);
                        print_rec(rec, recsize);
                }
                goto out;
        } else if (op == OP_IT_STOP) {
                rc = doop(0, key, rec, IAM_IOC_IT_STOP, "IAM_IOC_IT_STOP");
                goto out;
        } else if (op == OP_IT_NEXT) {
                rc = doop(0, key, rec, IAM_IOC_IT_NEXT, "IAM_IOC_IT_NEXT");
                if (rc == 0) {
                        print_rec(key, keysize);
                        print_rec(rec, recsize);
                }
                goto out;
        }

        rc = insert(0, key, rec);
        if (rc != 0) {
                rc = 1;
                goto out;
        }

        rc = insert(0, "DAEDALUS", "FINNEGAN");
        if (rc != 0) {
                rc = 1;
                goto out;
        }

        rc = insert(0, "DAEDALUS", "FINNEGAN");
        if (errno != EEXIST) {
                if (rc == 0)
                        fprintf(stderr, "Duplicate key not detected!\n");
                if (rc != 0) {
                        rc = 1;
                        goto out;
                }
        }

        rc = lookup(0, "RIVERRUN", rec);
        if (rc != 0) {
                rc = 1;
                goto out;
        }

        print_rec(rec, recsize);

        for (i = 0; i < N; ++i) {
                memset(key, 0, keysize + 1);
                memset(rec, 0, recsize + 1);
                snprintf(key, keysize + 1, "y-%x-x", i);
                snprintf(rec, recsize + 1, "p-%x-q", 1000 - i);
                rc = insert(0, key, rec);
                if (rc != 0) {
                        rc = 1;
                        goto out;
                }
                if (verbose > 1)
                        printf("key %#x inserted\n", i);
        }

        rc = 0;

out:
        if (key) {
                free(key);
        }
        if (rec) {
                free(rec);
        }
        return rc;
}
