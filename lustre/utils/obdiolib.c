/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2003 Cluster File Systems, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <liblustre.h>
#include "obdiolib.h"

void
obdio_iocinit (struct obdio_conn *conn)
{
        memset (&conn->oc_data, 0, sizeof (conn->oc_data));
        conn->oc_data.ioc_version = OBD_IOCTL_VERSION;
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
                fprintf (stderr, "obdio_ioctl: obd_ioctl_pack: %d (%s)\n",
                         rc, strerror (errno));
                abort ();
        }

        rc = ioctl (conn->oc_fd, cmd, buf);
        if (rc != 0)
                return (rc);

        rc2 = obd_ioctl_unpack (&conn->oc_data, buf, sizeof (conn->oc_buffer));
        if (rc2 != 0) {
                fprintf (stderr, "obdio_ioctl: obd_ioctl_unpack: %d (%s)\n",
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
                fprintf (stderr, "obdio_connect: Can't open /dev/obd: %s\n",
                         strerror (errno));
                goto failed;
        }

        obdio_iocinit (conn);
        conn->oc_data.ioc_dev = device;
        rc = obdio_ioctl (conn, OBD_IOC_DEVICE);
        if (rc != 0) {
                fprintf (stderr, "obdio_connect: Can't set device %d: %s\n",
                         device, strerror (errno));
                goto failed;
        }

        obdio_iocinit (conn);
        rc = obdio_ioctl (conn, OBD_IOC_CONNECT);
        if (rc != 0) {
                fprintf(stderr, "obdio_connect: Can't connect to device "
                        "%d: %s\n", device, strerror (errno));
                goto failed;
        }

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
                memcpy (fh, obdo_handle(&conn->oc_data.ioc_obdo1), sizeof (*fh));

        return (rc);
}

int
obdio_close (struct obdio_conn *conn, uint64_t oid, struct lustre_handle *fh)
{
        obdio_iocinit (conn);


        conn->oc_data.ioc_obdo1.o_id = oid;
        conn->oc_data.ioc_obdo1.o_mode = S_IFREG;
        memcpy (obdo_handle (&conn->oc_data.ioc_obdo1), fh, sizeof (*fh));
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

int
obdio_enqueue (struct obdio_conn *conn, uint64_t oid,
               int mode, uint64_t offset, uint32_t count,
               struct lustre_handle *lh)
{
        int   rc;

        obdio_iocinit (conn);

        conn->oc_data.ioc_obdo1.o_id = oid;
        conn->oc_data.ioc_obdo1.o_mode = S_IFREG;
        conn->oc_data.ioc_obdo1.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE;

        conn->oc_data.ioc_conn1 = mode;
        conn->oc_data.ioc_count = count;
        conn->oc_data.ioc_offset = offset;

        rc = obdio_ioctl (conn, ECHO_IOC_ENQUEUE);

        if (rc == 0)
                memcpy (lh, obdo_handle (&conn->oc_data.ioc_obdo1), sizeof (*lh));

        return (rc);
}

int
obdio_cancel (struct obdio_conn *conn, struct lustre_handle *lh)
{
        obdio_iocinit (conn);

        memcpy (obdo_handle (&conn->oc_data.ioc_obdo1), lh, sizeof (*lh));
        conn->oc_data.ioc_obdo1.o_valid = OBD_MD_FLHANDLE;

        return (obdio_ioctl (conn, ECHO_IOC_CANCEL));
}

void *
obdio_alloc_aligned_buffer (void **spacep, int size)
{
        int   pagesize = getpagesize();
        void *space = malloc (size + pagesize - 1);

        *spacep = space;
        if (space == NULL)
                return (NULL);

        return ((void *)(((unsigned long)space + pagesize - 1) & ~(pagesize - 1)));
}

struct obdio_barrier *
obdio_new_barrier (uint64_t oid, uint64_t id, int npeers)
{
        struct obdio_barrier *b;

        b = (struct obdio_barrier *)malloc (sizeof (*b));
        if (b == NULL) {
                fprintf (stderr, "obdio_new_barrier "LPX64": Can't allocate\n", oid);
                return (NULL);
        }

        b->ob_id = id;
        b->ob_oid = oid;
        b->ob_npeers = npeers;
        b->ob_ordinal = 0;
        b->ob_count = 0;
        return (b);
}

int
obdio_setup_barrier (struct obdio_conn *conn, struct obdio_barrier *b)
{
        struct lustre_handle    fh;
        struct lustre_handle    lh;
        int                     rc;
        int                     rc2;
        void                   *space;
        struct obdio_barrier   *fileb;

        if (b->ob_ordinal != 0 ||
            b->ob_count != 0) {
                fprintf (stderr, "obdio_setup_barrier: invalid parameter\n");
                abort ();
        }

        rc = obdio_open (conn, b->ob_oid, &fh);
        if (rc != 0) {
                fprintf (stderr, "obdio_setup_barrier "LPX64": Failed to open object: %s\n",
                         b->ob_oid, strerror (errno));
                return (rc);
        }

        fileb = (struct obdio_barrier *) obdio_alloc_aligned_buffer (&space, getpagesize ());
        if (fileb == NULL) {
                fprintf (stderr, "obdio_setup_barrier "LPX64": Can't allocate page buffer\n",
                         b->ob_oid);
                rc = -1;
                goto out_0;
        }

        memset (fileb, 0, getpagesize ());
        *fileb = *b;

        rc = obdio_enqueue (conn, b->ob_oid, LCK_PW, 0, getpagesize (), &lh);
        if (rc != 0) {
                fprintf (stderr, "obdio_setup_barrier "LPX64": Error on enqueue: %s\n",
                         b->ob_oid, strerror (errno));
                goto out_1;
        }

        rc = obdio_pwrite (conn, b->ob_oid, (void *)fileb, getpagesize (), 0);
        if (rc != 0)
                fprintf (stderr, "obdio_setup_barrier "LPX64": Error on write: %s\n",
                         b->ob_oid, strerror (errno));

        rc2 = obdio_cancel (conn, &lh);
        if (rc == 0 && rc2 != 0) {
                fprintf (stderr, "obdio_setup_barrier "LPX64": Error on cancel: %s\n",
                         b->ob_oid, strerror (errno));
                rc = rc2;
        }
 out_1:
        free (space);
 out_0:
        rc2 = obdio_close (conn, b->ob_oid, &fh);
        if (rc == 0 && rc2 != 0) {
                fprintf (stderr, "obdio_setup_barrier "LPX64": Error on close: %s\n",
                         b->ob_oid, strerror (errno));
                rc = rc2;
        }

        return (rc);
}

int
obdio_barrier (struct obdio_conn *conn, struct obdio_barrier *b)
{
        struct lustre_handle   fh;
        struct lustre_handle   lh;
        int                    rc;
        int                    rc2;
        void                  *space;
        struct obdio_barrier  *fileb;
        char                  *mode;

        rc = obdio_open (conn, b->ob_oid, &fh);
        if (rc != 0) {
                fprintf (stderr, "obdio_barrier "LPX64": Error on open: %s\n",
                         b->ob_oid, strerror (errno));
                return (rc);
        }

        fileb = (struct obdio_barrier *) obdio_alloc_aligned_buffer (&space, getpagesize ());
        if (fileb == NULL) {
                fprintf (stderr, "obdio_barrier "LPX64": Can't allocate page buffer\n",
                         b->ob_oid);
                rc = -1;
                goto out_0;
        }

        rc = obdio_enqueue (conn, b->ob_oid, LCK_PW, 0, getpagesize (), &lh);
        if (rc != 0) {
                fprintf (stderr, "obdio_barrier "LPX64": Error on PW enqueue: %s\n",
                         b->ob_oid, strerror (errno));
                goto out_1;
        }

        memset (fileb, 0xeb, getpagesize ());
        rc = obdio_pread (conn, b->ob_oid, (void *)fileb, getpagesize (), 0);
        if (rc != 0) {
                fprintf (stderr, "obdio_barrier "LPX64": Error on initial read: %s\n",
                         b->ob_oid, strerror (errno));
                goto out_2;
        }

        if (fileb->ob_id != b->ob_id ||
            fileb->ob_oid != b->ob_oid ||
            fileb->ob_npeers != b->ob_npeers ||
            fileb->ob_count >= b->ob_npeers ||
            fileb->ob_ordinal != b->ob_ordinal) {
                fprintf (stderr, "obdio_barrier "LPX64": corrupt on initial read\n", b->ob_id);
                fprintf (stderr, "  got ["LPX64","LPX64","LPX64","LPX64","LPX64"]\n",
                         fileb->ob_id, fileb->ob_oid, fileb->ob_npeers,
                         fileb->ob_ordinal, fileb->ob_count);
                fprintf (stderr, "  expected ["LPX64","LPX64","LPX64","LPX64","LPX64"]\n",
                         b->ob_id, b->ob_oid, b->ob_npeers,
                         b->ob_ordinal, b->ob_count);
                rc = -1;
                goto out_2;
        }

        fileb->ob_count++;
        if (fileb->ob_count == fileb->ob_npeers) { /* I'm the last joiner */
                fileb->ob_count = 0;       /* join count for next barrier */
                fileb->ob_ordinal++;                 /* signal all joined */
        }

        rc = obdio_pwrite (conn, b->ob_oid, (void *)fileb, getpagesize (), 0);
        if (rc != 0) {
                fprintf (stderr, "obdio_barrier "LPX64": Error on initial write: %s\n",
                         b->ob_oid, strerror (errno));
                goto out_2;
        }

        mode = "PW";
        b->ob_ordinal++;           /* now I wait... */
        while (fileb->ob_ordinal != b->ob_ordinal) {

                rc = obdio_cancel (conn, &lh);
                if (rc != 0) {
                        fprintf (stderr, "obdio_barrier "LPX64": Error on %s cancel: %s\n",
                                 b->ob_oid, mode, strerror (errno));
                        goto out_1;
                }

                mode = "PR";
                rc = obdio_enqueue (conn, b->ob_oid, LCK_PR, 0, getpagesize (), &lh);
                if (rc != 0) {
                        fprintf (stderr, "obdio_barrier "LPX64": Error on PR enqueue: %s\n",
                                 b->ob_oid, strerror (errno));
                        goto out_1;
                }

                memset (fileb, 0xeb, getpagesize ());
                rc = obdio_pread (conn, b->ob_oid, (void *)fileb, getpagesize (), 0);
                if (rc != 0) {
                        fprintf (stderr, "obdio_barrier "LPX64": Error on read: %s\n",
                                 b->ob_oid, strerror (errno));
                        goto out_2;
                }

                if (fileb->ob_id != b->ob_id ||
                    fileb->ob_oid != b->ob_oid ||
                    fileb->ob_npeers != b->ob_npeers ||
                    fileb->ob_count >= b->ob_npeers ||
                    (fileb->ob_ordinal != b->ob_ordinal - 1 &&
                     fileb->ob_ordinal != b->ob_ordinal)) {
                        fprintf (stderr, "obdio_barrier "LPX64": corrupt\n", b->ob_id);
                        fprintf (stderr, "  got ["LPX64","LPX64","LPX64","LPX64","LPX64"]\n",
                                 fileb->ob_id, fileb->ob_oid, fileb->ob_npeers,
                                 fileb->ob_ordinal, fileb->ob_count);
                        fprintf (stderr, "  expected ["LPX64","LPX64","LPX64","LPX64","LPX64"]\n",
                                 b->ob_id, b->ob_oid, b->ob_npeers,
                                 b->ob_ordinal, b->ob_count);
                        rc = -1;
                        goto out_2;
                }
        }

 out_2:
        rc2 = obdio_cancel (conn, &lh);
        if (rc == 0 && rc2 != 0) {
                fprintf (stderr, "obdio_barrier "LPX64": Error on cancel: %s\n",
                         b->ob_oid, strerror (errno));
                rc = rc2;
        }
 out_1:
        free (space);
 out_0:
        rc2 = obdio_close (conn, b->ob_oid, &fh);
        if (rc == 0 && rc2 != 0) {
                fprintf (stderr, "obdio_barrier "LPX64": Error on close: %s\n",
                         b->ob_oid, strerror (errno));
                rc = rc2;
        }

        return (rc);
}


