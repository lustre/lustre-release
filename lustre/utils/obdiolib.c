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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/utils/obdiolib.c
 *
 * Author: Eric Barton <eeb@clusterfs.com>
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
        conn->oc_data.ioc_dev = conn->oc_device;
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
                fprintf(stderr, "%s: obd_ioctl_pack: %d (%s)\n",
                        __FUNCTION__, rc, strerror(errno));
                abort();
        }

        rc = ioctl (conn->oc_fd, cmd, buf);
        if (rc != 0)
                return (rc);

        rc2 = obd_ioctl_unpack (&conn->oc_data, buf, sizeof (conn->oc_buffer));
        if (rc2 != 0) {
                fprintf(stderr, "%s: obd_ioctl_unpack: %d (%s)\n",
                        __FUNCTION__, rc2, strerror(errno));
                abort ();
        }

        return (rc);
}

struct obdio_conn *
obdio_connect (int device)
{
        struct obdio_conn  *conn;

        conn = malloc (sizeof (*conn));
        if (conn == NULL) {
                fprintf (stderr, "%s: no memory\n", __FUNCTION__);
                return (NULL);
        }
        memset (conn, 0, sizeof (*conn));

        conn->oc_fd = open ("/dev/obd", O_RDWR);
        if (conn->oc_fd < 0) {
                fprintf(stderr, "%s: Can't open /dev/obd: %s\n",
                        __FUNCTION__, strerror(errno));
                goto failed;
        }

        conn->oc_device = device;
        return (conn);

 failed:
        free (conn);
        return (NULL);
}

void
obdio_disconnect (struct obdio_conn *conn, int flags)
{
        close (conn->oc_fd);
        /* obdclass will automatically close on last ref */
        free (conn);
}

int
obdio_pread (struct obdio_conn *conn, __u64 oid,
             void *buffer, __u32 count, __u64 offset)
{
        obdio_iocinit (conn);

	ostid_set_id(&conn->oc_data.ioc_obdo1.o_oi, oid);
	conn->oc_data.ioc_obdo1.o_mode = S_IFREG;
	conn->oc_data.ioc_obdo1.o_valid =
		OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE;

        conn->oc_data.ioc_pbuf2 = buffer;
        conn->oc_data.ioc_plen2 = count;
        conn->oc_data.ioc_count = count;
        conn->oc_data.ioc_offset = offset;

        return (obdio_ioctl (conn, OBD_IOC_BRW_READ));
}

int
obdio_pwrite (struct obdio_conn *conn, __u64 oid,
              void *buffer, __u32 count, __u64 offset)
{
        obdio_iocinit (conn);

	ostid_set_id(&conn->oc_data.ioc_obdo1.o_oi, oid);
	conn->oc_data.ioc_obdo1.o_mode = S_IFREG;
	conn->oc_data.ioc_obdo1.o_valid =
		OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE;

        conn->oc_data.ioc_pbuf1 = (void*)1;
        conn->oc_data.ioc_plen1 = 1;
        conn->oc_data.ioc_pbuf2 = buffer;
        conn->oc_data.ioc_plen2 = count;
        conn->oc_data.ioc_count = count;
        conn->oc_data.ioc_offset = offset;

        return (obdio_ioctl (conn, OBD_IOC_BRW_WRITE));
}

int
obdio_enqueue (struct obdio_conn *conn, __u64 oid,
               int mode, __u64 offset, __u32 count,
               struct lustre_handle *lh)
{
        int   rc;

        obdio_iocinit (conn);

	ostid_set_id(&conn->oc_data.ioc_obdo1.o_oi, oid);
	conn->oc_data.ioc_obdo1.o_mode = S_IFREG;
	conn->oc_data.ioc_obdo1.o_valid =
		OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE;

        conn->oc_data.ioc_conn1 = mode;
        conn->oc_data.ioc_count = count;
        conn->oc_data.ioc_offset = offset;

        rc = obdio_ioctl (conn, ECHO_IOC_ENQUEUE);

        if (rc == 0)
                *lh = conn->oc_data.ioc_obdo1.o_handle;

        return (rc);
}

int
obdio_cancel (struct obdio_conn *conn, struct lustre_handle *lh)
{
        obdio_iocinit (conn);

        conn->oc_data.ioc_obdo1.o_handle = *lh;
        conn->oc_data.ioc_obdo1.o_valid = OBD_MD_FLHANDLE;

        return (obdio_ioctl (conn, ECHO_IOC_CANCEL));
}

void *
obdio_alloc_aligned_buffer (void **spacep, int size)
{
        int   pagemask = getpagesize() - 1;
        void *space = malloc(size + pagemask);

        if (space == NULL)
                return (NULL);

        *spacep = (void *)(((unsigned long)space + pagemask) & ~pagemask);
        return space;
}

struct obdio_barrier *
obdio_new_barrier (__u64 oid, __u64 id, int npeers)
{
        struct obdio_barrier *b;

        b = malloc(sizeof(*b));
        if (b == NULL) {
                fprintf(stderr, "%s "LPX64": Can't allocate\n",
                        __FUNCTION__, oid);
                return(NULL);
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
        struct lustre_handle    lh;
        int                     rc;
        int                     rc2;
        void                   *space, *fileptr;
        struct obdio_barrier   *fileb;

        if (b->ob_ordinal != 0 ||
            b->ob_count != 0) {
                fprintf(stderr, "%s: invalid parameter\n", __FUNCTION__);
                abort ();
        }

        space = obdio_alloc_aligned_buffer(&fileptr, getpagesize());
        if (space == NULL) {
                fprintf(stderr, "%s "LPX64": Can't allocate page buffer\n",
                        __FUNCTION__, b->ob_oid);
                return (-1);
        }

        fileb = fileptr;
        memset(fileb, 0, getpagesize());
        *fileb = *b;

        rc = obdio_enqueue(conn, b->ob_oid, LCK_PW, 0, getpagesize(), &lh);
        if (rc != 0) {
                fprintf(stderr, "%s "LPX64": Error on enqueue: %s\n",
                        __FUNCTION__, b->ob_oid, strerror(errno));
                goto out;
        }

        rc = obdio_pwrite(conn, b->ob_oid, fileb, getpagesize(), 0);
        if (rc != 0)
                fprintf(stderr, "%s "LPX64": Error on write: %s\n",
                        __FUNCTION__, b->ob_oid, strerror(errno));

        rc2 = obdio_cancel (conn, &lh);
        if (rc == 0 && rc2 != 0) {
                fprintf(stderr, "%s "LPX64": Error on cancel: %s\n",
                        __FUNCTION__, b->ob_oid, strerror(errno));
                rc = rc2;
        }
 out:
        free (space);
        return (rc);
}

int
obdio_barrier (struct obdio_conn *conn, struct obdio_barrier *b)
{
        struct lustre_handle   lh;
        int                    rc;
        int                    rc2;
        void                  *space, *fileptr;
        struct obdio_barrier  *fileb;
        char                  *mode;

        space = obdio_alloc_aligned_buffer(&fileptr, getpagesize());
        if (space == NULL) {
                fprintf(stderr, "%s "LPX64": Can't allocate page buffer\n",
                        __FUNCTION__, b->ob_oid);
                return (-1);
        }

        rc = obdio_enqueue(conn, b->ob_oid, LCK_PW, 0, getpagesize(), &lh);
        if (rc != 0) {
                fprintf(stderr, "%s "LPX64": Error on PW enqueue: %s\n",
                        __FUNCTION__, b->ob_oid, strerror(errno));
                goto out_1;
        }

        fileb = fileptr;
        memset(fileb, 0xeb, getpagesize());
        rc = obdio_pread(conn, b->ob_oid, fileb, getpagesize(), 0);
        if (rc != 0) {
                fprintf(stderr, "%s "LPX64": Error on initial read: %s\n",
                        __FUNCTION__, b->ob_oid, strerror(errno));
                goto out_2;
        }

        if (fileb->ob_id != b->ob_id ||
            fileb->ob_oid != b->ob_oid ||
            fileb->ob_npeers != b->ob_npeers ||
            fileb->ob_count >= b->ob_npeers ||
            fileb->ob_ordinal != b->ob_ordinal) {
                fprintf(stderr, "%s "LPX64": corrupt on initial read\n",
                        __FUNCTION__, b->ob_id);
                fprintf(stderr,
                        "  got ["LPX64","LPX64","LPX64","LPX64","LPX64"]\n",
                        fileb->ob_id, fileb->ob_oid, fileb->ob_npeers,
                        fileb->ob_ordinal, fileb->ob_count);
                fprintf(stderr,
                       "  expected ["LPX64","LPX64","LPX64","LPX64","LPX64"]\n",
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

        rc = obdio_pwrite(conn, b->ob_oid, fileb, getpagesize(), 0);
        if (rc != 0) {
                fprintf (stderr, "%s "LPX64": Error on initial write: %s\n",
                         __FUNCTION__, b->ob_oid, strerror(errno));
                goto out_2;
        }

        mode = "PW";
        b->ob_ordinal++;           /* now I wait... */
        while (fileb->ob_ordinal != b->ob_ordinal) {
                rc = obdio_cancel (conn, &lh);
                if (rc != 0) {
                        fprintf(stderr, "%s "LPX64": Error on %s cancel: %s\n",
                                __FUNCTION__, b->ob_oid, mode, strerror(errno));
                        goto out_1;
                }

                mode = "PR";
                rc = obdio_enqueue(conn, b->ob_oid, LCK_PR,0,getpagesize(),&lh);
                if (rc != 0) {
                        fprintf(stderr, "%s "LPX64": Error on PR enqueue: %s\n",
                                __FUNCTION__, b->ob_oid, strerror(errno));
                        goto out_1;
                }

                memset (fileb, 0xeb, getpagesize());
                rc = obdio_pread(conn, b->ob_oid, fileb, getpagesize(), 0);
                if (rc != 0) {
                        fprintf(stderr, "%s "LPX64": Error on read: %s\n",
                                __FUNCTION__, b->ob_oid, strerror(errno));
                        goto out_2;
                }

                if (fileb->ob_id != b->ob_id ||
                    fileb->ob_oid != b->ob_oid ||
                    fileb->ob_npeers != b->ob_npeers ||
                    fileb->ob_count >= b->ob_npeers ||
                    (fileb->ob_ordinal != b->ob_ordinal - 1 &&
                     fileb->ob_ordinal != b->ob_ordinal)) {
                        fprintf(stderr, "%s "LPX64": corrupt\n",
                                __FUNCTION__, b->ob_id);
                        fprintf(stderr, "  got ["LPX64","LPX64","LPX64","
                                LPX64","LPX64"]\n",
                                fileb->ob_id, fileb->ob_oid, fileb->ob_npeers,
                                fileb->ob_ordinal, fileb->ob_count);
                        fprintf(stderr, "  expected ["LPX64","LPX64","LPX64
                                ","LPX64","LPX64"]\n",
                                b->ob_id, b->ob_oid, b->ob_npeers,
                                b->ob_ordinal, b->ob_count);
                        rc = -1;
                        goto out_2;
                }
        }

 out_2:
        rc2 = obdio_cancel (conn, &lh);
        if (rc == 0 && rc2 != 0) {
                fprintf(stderr, "%s "LPX64": Error on cancel: %s\n",
                        __FUNCTION__, b->ob_oid, strerror(errno));
                rc = rc2;
        }
 out_1:
        free (space);
        return (rc);
}
