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
#include <sys/stat.h>
#include <stdio.h>
#include <signal.h>
#define printk printf
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <linux/module.h>

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

        sprintf(buf, "id: %Ld\ngrp: %Ld\natime: %Ld\nmtime: %Ld\nctime: %Ld\nsize: %Ld\nblocks: %Ld\nblksize: %d\nmode: %o\nuid: %d\ngid: %d\nflags: %x\nobdflags: %x\nnlink: %d,\nvalid %x\n",
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

static int do_disconnect()
{
        struct obd_ioctl_data data;
        int rc;

        if (connid == -1)
                return 0;

        IOCINIT(data);

        rc = ioctl(fd, OBD_IOC_DISCONNECT , &data);
        if (rc < 0) {
                printf("Device: %x %s\n", OBD_IOC_DISCONNECT, strerror(errno));
                return 0;
        } else {
                printf("Disconnected connid %d\n", connid);
        }
        connid = -1;

        return 0;
}

static int jt_device(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        do_disconnect();

        memset(&data, 0, sizeof(data));
        if ( argc != 2 ) {
                fprintf(stderr, "Usage: %s devno\n", argv[0]);
                return 1;
        }

        data.ioc_dev = atoi(argv[1]);

        if (obd_ioctl_pack(&data, &buf, max)) { 
                printf("invalid ioctl\n"); 
                return 1;
        }

        if (fd == -1) 
                fd = open("/dev/obd", O_RDWR);
        if (fd == -1) {
                printf("Opening /dev/obd: %s\n", strerror(errno));
                return 1;
        }

        rc = ioctl(fd, OBD_IOC_DEVICE , buf);
        if (rc < 0) {
                printf("Device: %x %s\n", OBD_IOC_DEVICE, strerror(errno));
                return 1;
        }

        return 0;
}

static int jt_connect(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);

        do_disconnect();

        if ( argc != 1 ) {
                fprintf(stderr, "Usage: %s\n", argv[0]);
                return 1;
        }

        rc = ioctl(fd, OBD_IOC_CONNECT , &data);
        if (rc < 0) {
                printf("Device: %x %s\n", OBD_IOC_CONNECT, strerror(errno));
                return 1;
        }
        connid = data.ioc_conn1;

        return 0;
}

static int jt_disconnect(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);

        if ( argc != 1 ) {
                fprintf(stderr, "Usage: %s\n", argv[0]);
                return 1;
        }

        rc = ioctl(fd, OBD_IOC_DISCONNECT , &data);
        if (rc < 0) {
                printf("Device: %x %s\n", OBD_IOC_DISCONNECT, strerror(errno));
                return 1;
        }
        connid = -1;

        return 0;
}


static int jt_detach(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);

        if ( argc != 1 ) {
                fprintf(stderr, "Usage: %s\n", argv[0]);
                return 1;
        }

        if (obd_ioctl_pack(&data, &buf, max)) { 
                printf("invalid ioctl\n"); 
                return 1;
        }

        rc = ioctl(fd, OBD_IOC_DETACH , buf);
        if (rc < 0) {
                printf("Detach: %s\n", strerror(errno));
                return 1;
        }
        return 0;
}

static int jt_cleanup(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);

        if ( argc != 1 ) {
                fprintf(stderr, "Usage: %s\n", argv[0]);
                return 1;
        }

        rc = ioctl(fd, OBD_IOC_CLEANUP , &data);
        if (rc < 0) {
                printf("Detach: %s\n", strerror(errno));
                return 1;
        }
        return 0;
}

static int jt_attach(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);

        if ( argc != 2 && argc != 3  ) {
                fprintf(stderr, "Usage: %s type [data]\n", argv[0]);
                return 1;
        }

        data.ioc_inllen1 =  strlen(argv[1]) + 1;
        data.ioc_inlbuf1 = argv[1];
        if ( argc == 3 ) { 
                data.ioc_inllen2 = strlen(argv[2]) + 1;
                data.ioc_inlbuf2 = argv[2];
        }

        printf("attach len %d addr %p type %s data %s\n", data.ioc_len, buf, 
               MKSTR(data.ioc_inlbuf1), MKSTR(data.ioc_inlbuf2));

        if (obd_ioctl_pack(&data, &buf, max)) { 
                printf("invalid ioctl\n"); 
                return 1;
        }
        printf("attach len %d addr %p raw %p type %s data %s and %s\n", data.ioc_len, buf, rawbuf,
               MKSTR(data.ioc_inlbuf1), MKSTR(data.ioc_inlbuf2), &buf[516]);

        rc = ioctl(fd, OBD_IOC_ATTACH , buf);
        if (rc < 0) {
                printf("Attach: %x %s\n", OBD_IOC_ATTACH, strerror(errno));
                return 1;
        }
        return 0;
}

static int jt_setup(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);

        if ( argc > 3  ) {
                fprintf(stderr, "Usage: %s [device] [fstype]\n", argv[0]);
                return 1;
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

        printf("setup len %d addr %p device %s type %s\n", data.ioc_len, buf, 
               MKSTR(data.ioc_inlbuf1), MKSTR(data.ioc_inlbuf2));

        if (obd_ioctl_pack(&data, &buf, max)) { 
                printf("invalid ioctl\n"); 
                return 1;
        }
        printf("setup len %d addr %p raw %p device %s type %s\n", 
               data.ioc_len, buf, rawbuf,
               MKSTR(data.ioc_inlbuf1), MKSTR(data.ioc_inlbuf2));

        rc = ioctl(fd, OBD_IOC_SETUP , buf);
        if (rc < 0) {
                printf("setup: %x %s\n", OBD_IOC_SETUP, strerror(errno));
                return 1;
        }
        return 0;
}


static int jt_create(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int num = 1;
        int silent = 0;
        int i;
        int rc;

        IOCINIT(data);
        if (argc > 1) { 
                num = strtoul(argv[1], NULL, 0);
        } else { 
                printf("usage %s num [mode] [silent]\n", argv[0]); 
        }

        if (argc > 2) { 
                data.ioc_obdo1.o_mode = strtoul(argv[2], NULL, 0);
        } else { 
                data.ioc_obdo1.o_mode = 0100644;
        }
        data.ioc_obdo1.o_valid = OBD_MD_FLMODE;

        if (argc > 3) { 
                silent = strtoul(argv[3], NULL, 0);
        }
                
        printf("Creating %d obdos\n", num);

        for (i = 0 ; i<num ; i++) { 
                rc = ioctl(fd, OBD_IOC_CREATE , &data);
                if (rc < 0) {
                        printf("Create: %x %s\n", OBD_IOC_CREATE, 
                               strerror(errno));
                        return 1;
                }
                printf("created obdo %Ld\n", data.ioc_obdo1.o_id);
        }
        return 0;
}

static int jt_setattr(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);
        if (argc < 2) { 
                printf("usage: %s id mode\n", argv[0]); 
                return -1;
        }

        data.ioc_obdo1.o_id = strtoul(argv[1], NULL, 0);
        data.ioc_obdo1.o_mode = strtoul(argv[2], NULL, 0);
        data.ioc_obdo1.o_valid = OBD_MD_FLMODE; 

        rc = ioctl(fd, OBD_IOC_SETATTR , &data);
        if (rc < 0) {
                printf("setattr: %x %s\n", OBD_IOC_SETATTR, strerror(errno));
        }
        return rc;
}

static int jt_destroy(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);
        if (argc < 1) { 
                printf("usage %s id\n", argv[0]); 
        }

        data.ioc_obdo1.o_id = strtoul(argv[1], NULL, 0);

        rc = ioctl(fd, OBD_IOC_DESTROY , &data);
        if (rc < 0) {
                printf("setattr: %x %s\n", OBD_IOC_DESTROY, strerror(errno));
        }
        return rc;
}

static int jt_multi_getattr(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int count, i;
        int rc;

        IOCINIT(data);
        if (argc == 2) { 
                count = strtoul(argv[1], NULL, 0);
                data.ioc_obdo1.o_valid = 0xffffffff;
                data.ioc_obdo1.o_id = 2;
                printf("getting %d attrs (testing only)\n", count);
        } else { 
                printf("usage %s id\n", argv[0]); 
                return 0;
        }

        for (i = 0 ; i < count; i++) {
                rc = ioctl(fd, OBD_IOC_GETATTR , &data);
                if (rc) { 
                        printf("Error: %s on i=%d\n", strerror(rc), i); 
                        break;
                } else { 
                        printf("attr number %d\n", i);
                }
        }
        return 0;
}

static int jt_getattr(int argc, char **argv)
{
        struct obd_ioctl_data data;
        int rc;

        IOCINIT(data);
        if (argc == 2) { 
                data.ioc_obdo1.o_id = strtoul(argv[1], NULL, 0);
                data.ioc_obdo1.o_valid = 0xffffffff;
                printf("getting attr for %Ld\n", data.ioc_obdo1.o_id);
        } else { 
                printf("usage %s id\n", argv[0]); 
                return 0;
        }

        rc = ioctl(fd, OBD_IOC_GETATTR , &data);
        if (rc) { 
                printf("Error: %s\n", strerror(rc)); 
        } else { 
                printf("attr obdo %Ld, mode %o\n", data.ioc_obdo1.o_id, 
                       data.ioc_obdo1.o_mode);
        }
        return 0;
}

command_t list[] = {
        {"device", jt_device, 0, "set current device (args device no)"},
        {"attach", jt_attach, 0, "name the typed of device (args: type data"},
        {"setup", jt_setup, 0, "setup device (args: blkdev, data"},
        {"detach", jt_detach, 0, "detach the current device (arg: )"},
        {"cleanup", jt_cleanup, 0, "cleanup the current device (arg: )"},
        {"create", jt_create, 0, "create [count [mode [silent]]]"},
        {"destroy", jt_destroy, 0, "destroy id"},
        {"test_getattr", jt_multi_getattr, 0, "test_getattr count [silent]"},
        {"getattr", jt_getattr, 0, "getattr id"},
        {"setattr", jt_setattr, 0, "setattr id mode"},
        {"connect", jt_connect, 0, "connect - get a connection to device"},
        {"disconnect", jt_disconnect, 0, "disconnect - break connection to device"},
        {"help", Parser_help, 0, "help"},
        {"exit", Parser_quit, 0, "quit"},
        {"quit", Parser_quit, 0, "quit"},
        { 0, 0, 0, NULL }
};


static void signal_server(int sig)
{
        if (sig == SIGINT) { 
                fprintf(stderr,"\nDisconnecting any existing connections...\n");
                do_disconnect();
                exit(1);
        }
}

int main(int argc, char **argv)
{
        struct sigaction sigact;
        sigact.sa_handler = signal_server;
        sigfillset(&sigact.sa_mask);
        sigact.sa_flags = SA_RESTART;
        sigaction(SIGINT, &sigact, NULL);

        if (argc > 1) { 
                return Parser_execarg(argc - 1, &argv[1], list);
        }

        Parser_init("obdctl > ", list);
        Parser_commands();
        do_disconnect();

        return 0;
}

