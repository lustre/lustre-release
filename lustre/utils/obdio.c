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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/utils/obdio.c
 *
 * Author: Eric Barton <eeb@clusterfs.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <liblustre.h>
#include "obdiolib.h"

int
obdio_test_fixed_extent (struct obdio_conn *conn,
                         __u32 myhid, __u32 mypid,
                         int reps, int locked, __u64 oid,
                         __u64 offset, __u32 size)
{
        struct lustre_handle lh;
        void                *space;
        void                *buffer;
        __u32               *ibuf;
        int                  i;
        int                  j;
        int                  rc = 0;

        space = obdio_alloc_aligned_buffer (&buffer, size);
        if (space == NULL) {
                fprintf (stderr, "Can't allocate buffer size %d\n", size);
                return (-1);
        }

        for (i = 0; i < reps; i++) {
                ibuf = (__u32 *) buffer;
                for (j = 0; j < size / (4 * sizeof (*ibuf)); j++) {
                        ibuf[0] = myhid;
                        ibuf[1] = mypid;
                        ibuf[2] = i;
                        ibuf[3] = j;
                        ibuf += 4;
                }

                if (locked) {
                        rc = obdio_enqueue(conn, oid, LCK_PW, offset, size,&lh);
                        if (rc != 0) {
                                fprintf(stderr, "Error on enqueue "LPX64" @ "
                                        LPU64" for %u: %s\n",
                                        oid, offset, size, strerror (errno));
                                goto out;
                        }
                }

                rc = obdio_pwrite (conn, oid, buffer, size, offset);
                if (rc != 0) {
                        fprintf(stderr, "Error writing "LPX64" @ "LPU64
                                " for %u: %s\n",
                                oid, offset, size, strerror (errno));
                        if (locked)
                                obdio_cancel (conn, &lh);
                        rc = -1;
                        goto out;
                }

                memset (buffer, 0xbb, size);

                rc = obdio_pread (conn, oid, buffer, size, offset);
                if (rc != 0) {
                        fprintf(stderr, "Error reading "LPX64" @ "LPU64
                                " for %u: %s\n",
                                oid, offset, size, strerror (errno));
                        if (locked)
                                obdio_cancel (conn, &lh);
                        rc = -1;
                        goto out;
                }

                if (locked) {
                        rc = obdio_cancel (conn, &lh);
                        if (rc != 0) {
                                fprintf(stderr, "Error on cancel "LPX64" @ "
                                        LPU64" for %u: %s\n",
                                        oid, offset, size, strerror (errno));
                                rc = -1;
                                goto out;
                        }
                }

                ibuf = (__u32 *) buffer;
                for (j = 0; j < size / (4 * sizeof (*ibuf)); j++) {
                        if (ibuf[0] != myhid ||
                            ibuf[1] != mypid ||
                            ibuf[2] != i ||
                            ibuf[3] != j) {
                                fprintf(stderr, "Error checking "LPX64" @ "
                                        LPU64" for %u, chunk %d\n",
                                        oid, offset, size, j);
                                fprintf(stderr, "Expected [%x,%x,%x,%x], "
                                        "got [%x,%x,%x,%x]\n",
                                        myhid, mypid, i, j,
                                        ibuf[0], ibuf[1], ibuf[2], ibuf[3]);
                                rc = -1;
                                goto out;
                        }
                        ibuf += 4;
                }
        }
 out:
        free (space);
        return (rc);
}

int
parse_kmg (__u64 *valp, char *str)
{
        __u64           val;
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
                 "usage: %s -d device -s size -o offset [-i id][-n reps][-l] oid\n",
                 name);
}

int
main (int argc, char **argv)
{
        __u32             mypid = getpid ();
        __u32             myhid = gethostid ();
        __u64             oid;
        __u64             base_offset = 0;
        __u32             size = 0;
        int                set_size = 0;
        int                device = -1;
        int                reps = 1;
        int                locked = 0;
        char              *end;
        struct obdio_conn *conn;
        __u64              val;
        int                v1;
        int                v2;
        int                rc;
        int                c;

        while ((c = getopt (argc, argv, "hi:s:o:d:n:l")) != -1)
                switch (c) {
                case 'h':
                        usage (argv[0], 1);
                        return (0);

                case 'i':
                        switch (sscanf (optarg, "%i.%i", &v1, &v2)) {
                        case 1:
                                mypid = v1;
                                break;
                        case 2:
                                myhid = v1;
                                mypid = v2;
                                break;
                        default:
                                fprintf (stderr, "Can't parse id %s\n",
                                         optarg);
                                return (1);
                        }
                        break;

                case 's':
                        if (parse_kmg (&val, optarg) != 0) {
                                fprintf (stderr, "Can't parse size %s\n",
                                         optarg);
                                return (1);
                        }
                        size = (__u32)val;
                        set_size++;
                        break;

                case 'o':
                        if (parse_kmg (&val, optarg) != 0) {
                                fprintf (stderr, "Can't parse offset %s\n",
                                         optarg);
                                return (1);
                        }
                        base_offset = val;
                        break;

                case 'd':
                        device = strtol (optarg, &end, 0);
                        if (end == optarg || *end != 0 || device < 0) {
                                fprintf (stderr, "Can't parse device %s\n",
                                         optarg);
                                return (1);
                        }
                        break;
                case 'n':
                        if (parse_kmg (&val, optarg) != 0) {
                                fprintf (stderr, "Can't parse reps %s\n",
                                         optarg);
                                return (1);
                        }
                        reps = (int)val;
                        break;
                case 'l':
                        locked = 1;
                        break;
                default:
                        usage (argv[0], 0);
                        return (1);
        }

        if (!set_size ||
            device < 0 ||
            optind == argc) {
                fprintf (stderr, "No %s specified\n",
                         !set_size ? "size" :
                         device < 0 ? "device" : "object id");
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

        rc = obdio_test_fixed_extent(conn, myhid, mypid, reps, locked,
                                     oid, base_offset, size);

        obdio_disconnect(conn, 0);

        return (rc == 0 ? 0 : 1);
}
