/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdio.h>
#include <signal.h>
#define printk printf

#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>

#include <unistd.h>
#include <sys/un.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>

#define __KERNEL__
#include <linux/list.h>
#undef __KERNEL__

#include "parser.h"
#include <stdio.h>

int fd = -1;
int connid = -1;
char rawbuf[8192];
char *buf = rawbuf;
int max = 8192;
int thread;

#define IOCINIT(data)                                                   \
do {                                                                    \
        memset(&data, 0, sizeof(data));                                 \
        data.ioc_version = OBD_IOCTL_VERSION;                           \
        data.ioc_conn1 = connid;                                        \
        data.ioc_len = sizeof(data);                                    \
        if (fd < 0) {                                                   \
                fprintf(stderr, "No device open, use device\n");        \
                return 1;                                               \
        }                                                               \
} while (0)

/*
    pack "LL LL LL LL LL LL LL L L L L L L L L L a60 a60 L L L",
    $obdo->{id}, 0,
    $obdo->{gr}, 0,
    $obdo->{atime}, 0,
    $obdo->{mtime}, 0 ,
    $obdo->{ctime}, 0,
    $obdo->{size}, 0,
    $obdo->{blocks}, 0,
    $obdo->{blksize},
    $obdo->{mode},
    $obdo->{uid},
    $obdo->{gid},
    $obdo->{flags},
    $obdo->{obdflags},
    $obdo->{nlink},
    $obdo->{generation},
    $obdo->{valid},
    $obdo->{inline},
    $obdo->{obdmd},
    0, 0, # struct list_head
    0;  #  struct obd_ops
}

*/

char * obdo_print(struct obdo *obd)
{
        char buf[1024];

        sprintf(buf, "id: %Ld\ngrp: %Ld\natime: %Ld\nmtime: %Ld\nctime: %Ld\n"
                "size: %Ld\nblocks: %Ld\nblksize: %d\nmode: %o\nuid: %d\n"
                "gid: %d\nflags: %x\nobdflags: %x\nnlink: %d,\nvalid %x\n",
                obd->o_id,
                obd->o_gr,
                obd->o_atime,
                obd->o_mtime,
                obd->o_ctime,
                obd->o_size,
                obd->o_blocks,
                obd->o_blksize,
                obd->o_mode,
                obd->o_uid,
                obd->o_gid,
                obd->o_flags,
                obd->o_obdflags,
                obd->o_nlink,
                obd->o_valid);
        return strdup(buf);
}

static char *cmdname(char *func)
{
        static char buf[512];

        if (thread) {
                sprintf(buf, "%s-%d", func, thread);
                return buf;
        }

        return func;
}

static int do_disconnect(char *func)
{
        struct obd_ioctl_data data;
        int rc;

        if (connid == -1)
                return 0;

        IOCINIT(data);

        rc = ioctl(fd, OBD_IOC_DISCONNECT , &data);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %x %s\n", cmdname(func),
                        OBD_IOC_DISCONNECT, strerror(errno));
        } else {
                printf("%s: disconnected connid %d\n", cmdname(func), connid);
                connid = -1;
        }

        return rc;
}

extern command_t cmdlist[];

static int jt_device(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        do_disconnect(argv[0]);

        memset(&data, 0, sizeof(data));
        if ( argc != 2 ) {
                fprintf(stderr, "usage: %s devno\n", cmdname(argv[0]));
                return -1;
        }

        data.ioc_dev = atoi(argv[1]);

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(argv[0]));
                return -2;
        }

        if (fd == -1)
                fd = open("/dev/obd", O_RDWR);
        if (fd == -1) {
                fprintf(stderr, "error: %s: opening /dev/obd: %s\n",
                        cmdname(argv[0]), strerror(errno));
                return errno;
        }

        rc = ioctl(fd, OBD_IOC_DEVICE , buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %x %s\n", cmdname(argv[0]),
                        OBD_IOC_DEVICE, strerror(rc = errno));

        return rc;
}

static int jt_connect(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);

        do_disconnect(argv[0]);

        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", cmdname(argv[0]));
                return -1;
        }

        rc = ioctl(fd, OBD_IOC_CONNECT , &data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %x %s\n", cmdname(argv[0]),
                        OBD_IOC_CONNECT, strerror(rc = errno));
        else
                connid = data.ioc_conn1;

        return rc;
}

static int jt_disconnect(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);

        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", cmdname(argv[0]));
                return -1;
        }

        rc = ioctl(fd, OBD_IOC_DISCONNECT , &data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %x %s\n", cmdname(argv[0]),
                        OBD_IOC_DISCONNECT, strerror(rc = errno));
        else
                connid = -1;

        return rc;
}

static int jt__device(int argc, char **argv)
{
        char *arg2[3];
        int rc;

        if (argc < 3) {
                fprintf(stderr, "usage: %s devno <command [args ...]>\n",
                        cmdname(argv[0]));
                return -1;
        }

        arg2[0] = "device";
        arg2[1] = argv[1];
        arg2[2] = NULL;
        rc = jt_device(2, arg2);

        if (!rc) {
                arg2[0] = "connect";
                arg2[1] = NULL;
                rc = jt_connect(1, arg2);
        }

        if (!rc)
                rc = Parser_execarg(argc - 2, argv + 2, cmdlist);

        if (!rc) {
                arg2[0] = "disconnect";
                arg2[1] = NULL;
                rc = jt_disconnect(1, arg2);
        }

        return rc;
}

static int jt__threads(int argc, char **argv)
{
        int threads;
        int i, j;
        int rc;

        if (argc < 4) {
                fprintf(stderr,
                        "usage: %s numthreads devno <command [args ...]>\n",
                        argv[0]);
                return -1;
        }

        threads = atoi(argv[1]);
        printf("%s: starting %d threads on device %s running %s\n",
               argv[0], threads, argv[2], argv[3]);

        for (i = 1; i <= threads; i++) {
                rc = fork();
                if (rc < 0) {
                        fprintf(stderr, "error: %s: #%d - %s\n", argv[0], i,
                                strerror(rc = errno));
                        break;
                } else if (rc == 0) {
                        thread = i;
                        argv[1] = "--device";
                        return jt__device(argc - 1, argv + 1);
                } else {
                        printf("%s: thread %d (PID %d) started\n",
                               argv[0], i, rc);
                        rc = 0;
                }
        }

        if (!thread) {
                printf("\n");
                for (j = 1; j < i; j++) {
                        int status;
                        int ret = wait(&status);

                        if (ret < 0) {
                                fprintf(stderr, "error: %s: wait - %s\n",
                                        argv[0], strerror(errno));
                                if (rc == 0)
                                        rc = errno;
                        } else if (WIFEXITED(status) == 0) {
                                fprintf(stderr, "%s: PID %d had rc=%d\n",
                                        argv[0], ret, WEXITSTATUS(status));
                                if (rc == 0)
                                        rc = WEXITSTATUS(status);
                        }
                }
        }

        return rc;
}

static int jt_detach(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);

        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", cmdname(argv[0]));
                return -1;
        }

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(argv[0]));
                return -2;
        }

        rc = ioctl(fd, OBD_IOC_DETACH , buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc=errno));

        return rc;
}

static int jt_cleanup(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);

        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", cmdname(argv[0]));
                return -1;
        }

        rc = ioctl(fd, OBD_IOC_CLEANUP , &data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc=errno));

        return rc;
}

static int jt_attach(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);

        if (argc != 2 && argc != 3) {
                fprintf(stderr, "usage: %s type [data]\n", cmdname(argv[0]));
                return -1;
        }

        data.ioc_inllen1 =  strlen(argv[1]) + 1;
        data.ioc_inlbuf1 = argv[1];
        if (argc == 3) {
                data.ioc_inllen2 = strlen(argv[2]) + 1;
                data.ioc_inlbuf2 = argv[2];
        }

        printf("%s: len %d addr %p type %s data %s\n",
               cmdname(argv[0]), data.ioc_len, buf,
               MKSTR(data.ioc_inlbuf1), MKSTR(data.ioc_inlbuf2));

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(argv[0]));
                return -2;
        }
        printf("%s: len %d addr %p raw %p type %s data %s and %s\n",
               cmdname(argv[0]), data.ioc_len, buf, rawbuf,
               MKSTR(data.ioc_inlbuf1), MKSTR(data.ioc_inlbuf2), &buf[516]);

        rc = ioctl(fd, OBD_IOC_ATTACH , buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %x %s\n", cmdname(argv[0]),
                        OBD_IOC_ATTACH, strerror(rc = errno));

        return rc;
}

static int jt_setup(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);

        if ( argc > 3) {
                fprintf(stderr, "usage: %s [device] [fstype]\n",
                        cmdname(argv[0]));
                return -1;
        }

        if (argc > 1) {
                data.ioc_inllen1 =  strlen(argv[1]) + 1;
                data.ioc_inlbuf1 = argv[1];
                data.ioc_dev = strtoul(argv[1], NULL, 0);
        } else {
                data.ioc_dev = -1;
        }
        if ( argc == 3 ) {
                data.ioc_inllen2 = strlen(argv[2]) + 1;
                data.ioc_inlbuf2 = argv[2];
        }

        printf("%s: len %d addr %p device %s type %s\n",
               cmdname(argv[0]), data.ioc_len, buf,
               MKSTR(data.ioc_inlbuf1), MKSTR(data.ioc_inlbuf2));

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(argv[0]));
                return -2;
        }
        printf("%s: len %d addr %p raw %p device %s type %s\n",
               cmdname(argv[0]), data.ioc_len, buf, rawbuf,
               MKSTR(data.ioc_inlbuf1), MKSTR(data.ioc_inlbuf2));

        rc = ioctl(fd, OBD_IOC_SETUP , buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}


static int jt_create(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int num = 1;
        int silent = 0;
        int i;
        int rc;

        IOCINIT(data);
        if (argc < 2 || argc > 4) {
                fprintf(stderr, "usage: %s num [mode] [silent]\n",
                        cmdname(argv[0]));
                return -1;
        }
        num = strtoul(argv[1], NULL, 0);

        if (argc > 2)
                data.ioc_obdo1.o_mode = strtoul(argv[2], NULL, 0);
        else
                data.ioc_obdo1.o_mode = 0100644;
        data.ioc_obdo1.o_valid = OBD_MD_FLMODE;

        if (argc > 3)
                silent = strtoul(argv[3], NULL, 0);

        printf("%s: %d obdos\n", cmdname(argv[0]), num);

        for (i = 0 ; i < num ; i++) {
                rc = ioctl(fd, OBD_IOC_CREATE , &data);
                if (rc < 0) {
                        fprintf(stderr, "error: %s: #%d - %s\n",
                                cmdname(argv[0]), i, strerror(rc = errno));
                        break;
                }
                if (!silent)
                        printf("%s: #%Ld succeeded\n", cmdname(argv[0]),
                               data.ioc_obdo1.o_id);
        }
        return rc;
}

static int jt_setattr(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);
        if (argc != 2) {
                fprintf(stderr, "usage: %s id mode\n", cmdname(argv[0]));
                return -1;
        }

        data.ioc_obdo1.o_id = strtoul(argv[1], NULL, 0);
        data.ioc_obdo1.o_mode = S_IFREG | strtoul(argv[2], NULL, 0);
        data.ioc_obdo1.o_valid = OBD_MD_FLMODE; 

        rc = ioctl(fd, OBD_IOC_SETATTR , &data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

static int jt_destroy(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);
        if (argc != 2) {
                fprintf(stderr, "usage: %s id\n", cmdname(argv[0]));
                return -1;
        }

        data.ioc_obdo1.o_id = strtoul(argv[1], NULL, 0);
        data.ioc_obdo1.o_mode = S_IFREG|0644;

        rc = ioctl(fd, OBD_IOC_DESTROY , &data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

static int jt_getattr(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        if (argc != 2) {
                fprintf(stderr, "usage: %s id\n", cmdname(argv[0]));
                return -1;
        }

        IOCINIT(data);
        data.ioc_obdo1.o_id = strtoul(argv[1], NULL, 0);
        /* to help obd filter */ 
        data.ioc_obdo1.o_mode = 0100644;
        data.ioc_obdo1.o_valid = 0xffffffff;
        printf("%s: object id %Ld\n", cmdname(argv[0]), data.ioc_obdo1.o_id);

        rc = ioctl(fd, OBD_IOC_GETATTR , &data);
        if (rc) {
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc=errno));
        } else {
                printf("%s: object id %Ld, mode %o\n", cmdname(argv[0]),
                       data.ioc_obdo1.o_id, data.ioc_obdo1.o_mode);
        }
        return rc;
}

static int jt_test_getattr(int argc, char **argv)
{
        struct obd_ioctl_data data;
        struct timeval start;
        int count, i;
        int silent = 0;
        int rc;

        if (argc != 2 && argc != 3) {
                fprintf(stderr, "usage: %s count [silent]\n", cmdname(argv[0]));
                return -1;
        }

        IOCINIT(data);
        count = strtoul(argv[1], NULL, 0);

        if (argc == 3) {
                if (argv[2][0] == 's' || argv[2][0] == 'q')
                        silent = 1;
                else
                        silent = strtoul(argv[2], NULL, 0);
        }
        data.ioc_obdo1.o_valid = 0xffffffff;
        data.ioc_obdo1.o_id = 2;
        gettimeofday(&start, NULL);
        printf("%s: %d attrs (testing only): %s", cmdname(argv[0]), count,
               ctime(&start.tv_sec));

        for (i = 0 ; i < count; i++) {
                rc = ioctl(fd, OBD_IOC_GETATTR , &data);
                if (rc) {
                        fprintf(stderr, "error: %s: #%d - %s\n",
                                cmdname(argv[0]), i, strerror(rc = errno));
                        break;
                } else if (!silent) {
                        printf("%s: got attr #%d\n", cmdname(argv[0]), i);
                }
        }
        if (!rc) {
                struct timeval end;
                double diff;

                gettimeofday(&end, NULL);

                diff = ((double)(end.tv_sec - start.tv_sec) +
                        (double)(end.tv_usec - start.tv_usec) / 1000000);

                printf("%s: %d attrs in %.4gs (%.4g attr/s): %s",
                       cmdname(argv[0]), i, diff, (double)i / diff,
                       ctime(&end.tv_sec));
        }
        return rc;
}

static int jt_test_brw(int argc, char **argv)
{
        struct obd_ioctl_data data;
        struct timeval start;
        char *bulk, *b;
        int pages = 1, obdos = 1, count;
        int silent = 0, write = 0, rw;
        int i, o, p;
        int len;
        int rc;

        if (argc < 2 || argc > 6) {
                fprintf(stderr,
                        "usage: %s count [write [silent [pages [obdos]]]]\n",
                        cmdname(argv[0]));
                return -1;
        }

        count = strtoul(argv[1], NULL, 0);

        if (argc >= 3) {
                if (argv[2][0] == 'w')
                        write = 1;
                else if (argv[2][0] == 'r')
                        write = 0;
                else
                        write = strtoul(argv[2], NULL, 0);
        }
        if (argc >= 4) {
                if (argv[3][0] == 's' || argv[3][0] == 'q')
                        silent = 1;
                else
                        silent = strtoul(argv[3], NULL, 0);
        }
        if (argc >= 5)
                pages = strtoul(argv[4], NULL, 0);
        if (argc >= 6)
                obdos = strtoul(argv[5], NULL, 0);

        if (obdos != 1 && obdos != 2) {
                fprintf(stderr, "error: %s: only 1 or 2 obdos supported\n",
                        cmdname(argv[0]));
                return -2;
        }

        len = pages * PAGE_SIZE;

        bulk = calloc(obdos, len);
        if (!bulk) {
                fprintf(stderr, "error: %s: no memory allocating %dx%d pages\n",
                        cmdname(argv[0]), obdos, pages);
                return -2;
        }
        IOCINIT(data);
        data.ioc_conn2 = connid;
        data.ioc_obdo1.o_id = 2;
        data.ioc_count = len;
        data.ioc_offset = 0;
        data.ioc_plen1 = len;
        data.ioc_pbuf1 = bulk;
        if (obdos > 1) {
                data.ioc_obdo2.o_id = 2;
                data.ioc_plen2 = len;
                data.ioc_pbuf2 = bulk + len;
        }

        gettimeofday(&start, NULL);
        printf("%s: %s %d (%dx%d pages) (testing only): %s",
               cmdname(argv[0]), write ? "writing" : "reading",
               count, obdos, pages, ctime(&start.tv_sec));

        /*
         * We will put in the start time (and loop count inside the loop)
         * at the beginning of each page so that we will be able to validate
         * (at some later time) whether the data actually made it or not.
         */
        for (o = 0, b = bulk; o < obdos; o++)
                for (p = 0; p < pages; p++, b += PAGE_SIZE)
                        memcpy(b, &start, sizeof(start));

        rw = write ? OBD_IOC_BRW_WRITE : OBD_IOC_BRW_READ;
        for (i = 0 ; i < count; i++) {
                if (write) {
                        b = bulk + sizeof(struct timeval);
                        for (o = 0; o < obdos; o++)
                                for (p = 0; p < pages; p++, b += PAGE_SIZE)
                                        memcpy(b, &count, sizeof(count));
                }

                rc = ioctl(fd, rw, &data);
                if (rc) {
                        fprintf(stderr, "error: %s: #%d - %s on %s\n",
                                cmdname(argv[0]), i, strerror(rc = errno),
                                write ? "write" : "read");
                        break;
                } else if (!silent)
                        printf("%s: %s number %d\n", cmdname(argv[0]),
                               write ? "write" : "read", i);
        }

        free(bulk);

        if (!rc) {
                struct timeval end;
                double diff;

                gettimeofday(&end, NULL);

                diff = ((double)(end.tv_sec - start.tv_sec) +
                        (double)(end.tv_usec - start.tv_usec) / 1000000);

                printf("%s: %s %dx%dx%d pages in %.4gs (%.4g pg/s): %s",
                       cmdname(argv[0]), write ? "wrote" : "read", obdos,
                       pages, i, diff, (double)obdos * i * pages / diff,
                       ctime(&end.tv_sec));
        }
        return rc;
}

static int jt_test_ldlm(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);
        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", cmdname(argv[0]));
                return 1;
        }

        rc = ioctl(fd, IOC_LDLM_TEST, &data);
        if (rc)
                fprintf(stderr, "error: %s: test failed: %s\n",
                        cmdname(argv[0]), strerror(rc = errno));
        return rc;
}

command_t cmdlist[] = {
        {"--device", jt__device, 0, "--device <devno> <command [args ...]>"},
        {"--threads", jt__threads, 0,
                "--threads <threads> <devno> <command [args ...]>"},
        {"device", jt_device, 0, "set current device (args device no)"},
        {"attach", jt_attach, 0, "name the type of device (args: type data"},
        {"setup", jt_setup, 0, "setup device (args: <blkdev> [data]"},
        {"detach", jt_detach, 0, "detach the current device (arg: )"},
        {"cleanup", jt_cleanup, 0, "cleanup the current device (arg: )"},
        {"create", jt_create, 0, "create [count [mode [silent]]]"},
        {"destroy", jt_destroy, 0, "destroy <id>"},
        {"getattr", jt_getattr, 0, "getattr <id>"},
        {"setattr", jt_setattr, 0, "setattr <id> <mode>"},
        {"connect", jt_connect, 0, "connect - get a connection to device"},
        {"disconnect", jt_disconnect, 0,
                "disconnect - break connection to device"},
        {"test_getattr", jt_test_getattr, 0, "test_getattr <count> [silent]"},
        {"test_brw", jt_test_brw, 0, "test_brw <count> [write [silent]]"},
        {"test_ldlm", jt_test_ldlm, 0, "test lock manager (no args)"},
        {"help", Parser_help, 0, "help"},
        {"exit", Parser_quit, 0, "quit"},
        {"quit", Parser_quit, 0, "quit"},
        { 0, 0, 0, NULL }
};


static void signal_server(int sig)
{
        if (sig == SIGINT) { 
                do_disconnect("sigint");
                exit(1);
        }
}

int main(int argc, char **argv)
{
        struct sigaction sigact;
        int rc = 0;

        sigact.sa_handler = signal_server;
        sigfillset(&sigact.sa_mask);
        sigact.sa_flags = SA_RESTART;
        sigaction(SIGINT, &sigact, NULL);


        if (argc > 1) {
                rc = Parser_execarg(argc - 1, argv + 1, cmdlist);
        } else {
                Parser_init("obdctl > ", cmdlist);
                Parser_commands();
        }

        do_disconnect(argv[0]);
        return rc;
}

