/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Eric Barton <eeb@clusterfs.com>
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
#include <stdarg.h>
#include <signal.h>

#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>
#include <linux/obd_lov.h>      /* for IOC_LOV_SET_OSC_ACTIVE */
#include <linux/obd.h>          /* for struct lov_stripe_md */
#include <linux/obd_class.h>
#include <linux/lustre_build_version.h>

#include <unistd.h>
#include <sys/un.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>

#include <asm/page.h>           /* needed for PAGE_SIZE - rread */

#define __KERNEL__
#include <linux/list.h>
#undef __KERNEL__

#include "obdctl.h"

struct obdio_conn {
        int	               oc_fd;
        uint64_t               oc_conn_addr;
        uint64_t               oc_conn_cookie;
        struct obd_ioctl_data  oc_data;
        char                   oc_buffer[8192];
};

char *
obdio_alloc_aligned_buffer (char **spacep, int size) 
{
        int   pagesize = getpagesize();
        char *space = malloc (size + pagesize - 1);
        
        *spacep = space;
        if (space == NULL)
                return (NULL);
        
        return ((char *)(((unsigned long)space + pagesize - 1) & ~(pagesize - 1)));
}

void
obdio_iocinit (struct obdio_conn *conn)
{
        memset (&conn->oc_data, 0, sizeof (conn->oc_data));
        conn->oc_data.ioc_version = OBD_IOCTL_VERSION;
        conn->oc_data.ioc_addr = conn->oc_conn_addr;
        conn->oc_data.ioc_cookie = conn->oc_conn_cookie;
        conn->oc_data.ioc_len = sizeof (conn->oc_data);
}

int
obdio_ioctl (struct obdio_conn *conn, int cmd) 
{
        char *buf = conn->oc_buffer;
        int   rc;
        int   rc2;
        
        rc = obd_ioctl_pack (&conn->oc_data, &buf, sizeof (conn->oc_buffer));
        if (rc != 0) {
                fprintf (stderr, "obd_ioctl_pack: %d (%s)\n", 
                         rc, strerror (errno));
                abort ();
        }
        
        rc = ioctl (conn->oc_fd, cmd, buf);
        if (rc != 0)
                return (rc);
        
        rc2 = obd_ioctl_unpack (&conn->oc_data, buf, sizeof (conn->oc_buffer));
        if (rc2 != 0) {
                fprintf (stderr, "obd_ioctl_unpack: %d (%s)\n",
                         rc2, strerror (errno));
                abort ();
        }
        
        return (rc);
}

struct obdio_conn *
obdio_connect (int device)
{
        struct obdio_conn  *conn;
        int                 rc;

        conn = malloc (sizeof (*conn));
        if (conn == NULL) {
                fprintf (stderr, "obdio_connect: no memory\n");
                return (NULL);
        }
        memset (conn, 0, sizeof (*conn));
        
	conn->oc_fd = open ("/dev/obd", O_RDWR);
	if (conn->oc_fd < 0) {
                fprintf (stderr, "Can't open /dev/obd: %s\n",
                         strerror (errno));
                goto failed;
        }

        obdio_iocinit (conn);
        conn->oc_data.ioc_dev = device;
        rc = obdio_ioctl (conn, OBD_IOC_DEVICE);
        if (rc != 0) {
                fprintf (stderr, "Can't set device %d: %s\n",
                         device, strerror (errno));
                goto failed;
        }
        
        obdio_iocinit (conn);
        rc = obdio_ioctl (conn, OBD_IOC_CONNECT);
        if (rc != 0) {
                fprintf (stderr, "Can't connect to device %d: %s\n",
                         device, strerror (errno));
                goto failed;
        }
        
        conn->oc_conn_addr = conn->oc_data.ioc_addr;
        conn->oc_conn_cookie = conn->oc_data.ioc_cookie;
        return (conn);
        
 failed:
        free (conn);
        return (NULL);
}

void
obdio_disconnect (struct obdio_conn *conn) 
{
        close (conn->oc_fd);
        /* obdclass will automatically close on last ref */
        free (conn);
}

int
obdio_open (struct obdio_conn *conn, uint64_t oid, struct lustre_handle *fh) 
{
        int    rc;
        
        obdio_iocinit (conn);
        
        conn->oc_data.ioc_obdo1.o_id = oid;
        conn->oc_data.ioc_obdo1.o_mode = S_IFREG;
        conn->oc_data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE;
        
        rc = obdio_ioctl (conn, OBD_IOC_OPEN);
        
        if (rc == 0)
                obd_oa2handle (fh, &conn->oc_data.ioc_obdo1);

        return (rc);
}

int
obdio_close (struct obdio_conn *conn, uint64_t oid, struct lustre_handle *fh) 
{
        obdio_iocinit (conn);
        

        conn->oc_data.ioc_obdo1.o_id = oid;
        conn->oc_data.ioc_obdo1.o_mode = S_IFREG;
        obd_handle2oa (&conn->oc_data.ioc_obdo1, fh);
        conn->oc_data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | 
                                          OBD_MD_FLMODE | OBD_MD_FLHANDLE;
        
        return (obdio_ioctl (conn, OBD_IOC_CLOSE));
}

int
obdio_pread (struct obdio_conn *conn, uint64_t oid, 
             char *buffer, uint32_t count, uint64_t offset) 
{
        obdio_iocinit (conn);
        
        conn->oc_data.ioc_obdo1.o_id = oid;
        conn->oc_data.ioc_obdo1.o_mode = S_IFREG;
        conn->oc_data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE;

        conn->oc_data.ioc_pbuf2 = buffer;
        conn->oc_data.ioc_plen2 = count;
        conn->oc_data.ioc_count = count;
        conn->oc_data.ioc_offset = offset;

        return (obdio_ioctl (conn, OBD_IOC_BRW_READ));
}

int
obdio_pwrite (struct obdio_conn *conn, uint64_t oid, 
              char *buffer, uint32_t count, uint64_t offset) 
{
        obdio_iocinit (conn);
        
        conn->oc_data.ioc_obdo1.o_id = oid;
        conn->oc_data.ioc_obdo1.o_mode = S_IFREG;
        conn->oc_data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE;

        conn->oc_data.ioc_pbuf2 = buffer;
        conn->oc_data.ioc_plen2 = count;
        conn->oc_data.ioc_count = count;
        conn->oc_data.ioc_offset = offset;

        return (obdio_ioctl (conn, OBD_IOC_BRW_WRITE));
}

void
obdio_test_extent (struct obdio_conn *conn, uint32_t myid, int reps,
                   uint64_t oid, uint64_t offset, uint32_t size)
{
        char     *space;
        char     *buffer = obdio_alloc_aligned_buffer (&space, size);
        uint32_t *ibuf;
        int       i;
        int       j;
        int       rc;
        
        if (buffer == NULL) {
                fprintf (stderr, "Can't allocate buffer size %d\n", size);
                abort ();
        }

        for (i = 0; i < reps; i++) {
                ibuf = (uint32_t *) buffer;
                for (j = 0; j < size / (4 * sizeof (*ibuf)); j++) {
                        ibuf[0] = myid;
                        ibuf[1] = i;
                        ibuf[2] = j;
                        ibuf[3] = myid;
                        ibuf += 4;
                }
                
                rc = obdio_pwrite (conn, oid, buffer, size, offset);
                if (rc != 0) {
                        fprintf (stderr, "Error writing "LPX64" @ "LPU64" for %u: %s\n",
                                 oid, offset, size, strerror (errno));
                        abort ();
                }
                
                memset (buffer, 0xbb, size);
                
                rc = obdio_pread (conn, oid, buffer, size, offset);
                if (rc != 0) {
                        fprintf (stderr, "Error reading "LPX64" @ "LPU64" for %u: %s\n",
                                 oid, offset, size, strerror (errno));
                        abort ();
                }
                
                ibuf = (uint32_t *) buffer;
                for (j = 0; j < size / (4 * sizeof (*ibuf)); j++) {
                        if (ibuf[0] != myid ||
                            ibuf[1] != i ||
                            ibuf[2] != j ||
                            ibuf[3] != myid) {
                                fprintf (stderr, "Error checking "LPX64" @ "LPU64" for %u, chunk %d: %s\n",
                                         oid, offset, size, j, strerror (errno));
                                fprintf (stderr, "Expected [%x,%x,%x,%x], got [%x,%x,%x,%x]\n",
                                         myid, i, j, myid, ibuf[0], ibuf[1], ibuf[2], ibuf[3]);
                                abort ();
                        }
                        ibuf += 4;
                }
        }
}

int
parse_kmg (uint64_t *valp, char *str)
{
        uint64_t        val;
        char            mod[32];

        switch (sscanf (str, LPU64"%1[gGmMkK]", &val, mod))
        {
        default:
                return (-1);

        case 1:
                *valp = val;
                return (0);

        case 2:
                switch (*mod)
                {
                case 'g':
                case 'G':
                        *valp = val << 30;
                        return (0);

                case 'm':
                case 'M':
                        *valp = val << 20;
                        return (0);

                case 'k':
                case 'K':
                        *valp = val << 10;
                        return (0);

                default:
                        *valp = val;
                        return (0);
                }
        }
}

void
usage (char *cmdname, int help) 
{
        char *name = strrchr (cmdname, '/');
        
        if (name == NULL)
                name = cmdname;
        
        fprintf (help ? stdout : stderr,
                 "usage: %s -d device -s size -o offset [-i id][-n reps] oid\n",
                 name);
}

int
main (int argc, char **argv) 
{
        struct lustre_handle fh;
        uint32_t           myid = getpid ();
        uint64_t           oid;
        uint64_t           base_offset = 0;
        int                set_base = 0;
        uint32_t           size = 0;
        int                set_size = 0;
        int                device = 0;
        int                set_device = 0;
        int                reps = 1;
        char              *end;
        struct obdio_conn *conn;
        uint64_t           val;
        int                rc;
        int                c;

        while ((c = getopt (argc, argv, "hi:s:b:d:n:")) != -1)
                switch (c) {
                case 'h':
                        usage (argv[0], 1);
                        return (0);
                        
                case 'i':
                        myid = strtol (optarg, &end, 0);
                        if (end == optarg || *end != 0) {
                                fprintf (stderr, "Can't parse id %s\n",
                                         optarg);
                                return (1);
                        }
                        myid = (uint32_t)val;
                        break;
                        
                case 's':
                        if (parse_kmg (&val, optarg) != 0) {
                                fprintf (stderr, "Can't parse size %s\n",
                                         optarg);
                                return (1);
                        }
                        size = (uint32_t)val;
                        set_size++;
                        break;
                        
                case 'b':
                        if (parse_kmg (&val, optarg) != 0) {
                                fprintf (stderr, "Can't parse base offset %s\n",
                                         optarg);
                                return (1);
                        }
                        base_offset = val;
                        set_base++;
                        break;

                case 'd':
                        device = strtol (optarg, &end, 0);
                        if (end == optarg || *end != 0) {
                                fprintf (stderr, "Can't parse device %s\n",
                                         optarg);
                                return (1);
                        }
                        set_device++;
                        break;
                case 'n':
                        if (parse_kmg (&val, optarg) != 0) {
                                fprintf (stderr, "Can't parse reps %s\n",
                                         optarg);
                                return (1);
                        }
                        reps = (int)val;
                        break;
                        
                default:
                        usage (argv[0], 0);
                        return (1);
        }

        if (!set_size ||
            !set_base ||
            !set_device ||
            optind == argc) {
                fprintf (stderr, "No %s specified\n",
                         !set_size ? "size" :
                         !set_base ? "base offset" :
                         !set_device ? "device" : "object id");
                return (1);
        }
        
        oid = strtoull (argv[optind], &end, 0);
        if (end == argv[optind] || *end != 0) {
                fprintf (stderr, "Can't parse object id %s\n",
                         argv[optind]);
                return (1);
        }
        
        conn = obdio_connect (device);
        if (conn == NULL)
                return (1);
        
        rc = obdio_open (conn, oid, &fh);
        if (rc != 0) {
                fprintf (stderr, "Failed to open object "LPX64": %s\n",
                         oid, strerror (errno));
                return (1);
        }
        
        obdio_test_extent (conn, myid, reps, oid, base_offset, size);
        
        rc = obdio_close (conn, oid, &fh);
        if (rc != 0) {
                fprintf (stderr, "Error closing object "LPX64": %s\n",
                         oid, strerror (errno));
                return (1);
        }

        obdio_disconnect (conn);
        return (0);
}


