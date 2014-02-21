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
 * lustre/utils/obdbarrier.c
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
parse_kmg (__u64 *valp, char *str)
{
        __u64        val;
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
exponential_modulus (int i, int base)
{
        int   top = base;
        int   mod = 1;

        for (;;) {
                if (i < top)
                        return (i%mod == 0);

                mod = top;
                top *= base;
        }
}

int
main (int argc, char **argv)
{
        __u64                 bid = (((__u64)gethostid()) << 32) | getpid ();
        int                   set_bid = 0;
        __u64                 oid;
        int                   setup = 0;
        int                   device = -1;
        int                   npeers = 0;
        int                   reps = 1;
        char                  hostname[128];
        struct obdio_conn    *conn;
        struct obdio_barrier *b;
        char                 *end;
        __u64                 val;
        int                   rc;
        int                   c;

        setvbuf (stdout, NULL, _IOLBF, 0);
        memset (hostname, 0, sizeof (hostname));
        gethostname (hostname, sizeof (hostname));
        hostname[sizeof(hostname) - 1] = 0;

        while ((c = getopt (argc, argv, "hsi:d:n:p:")) != -1)
                switch (c) {
                case 'h':
                        usage (argv[0], 1);
                        return (0);

                case 'i':
                        bid = strtoll (optarg, &end, 0);
                        if (end == optarg || *end != 0) {
                                fprintf (stderr, "Can't parse id %s\n",
                                         optarg);
                                return (1);
                        }
                        set_bid = 1;
                        break;

                case 's':
                        setup = 1;
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

                case 'p':
                        npeers = strtol (optarg, &end, 0);
                        if (end == optarg || *end != 0 || npeers <= 0) {
                                fprintf (stderr, "Can't parse npeers %s\n",
                                         optarg);
                                return (1);
                        }
                        break;

                default:
                        usage (argv[0], 0);
                        return (1);
        }

        if ((!setup && !set_bid) ||
            npeers <= 0 ||
            device < 0 ||
            optind == argc) {
                fprintf (stderr, "%s not specified\n",
                         (!setup && !set_bid) ? "id" :
                         npeers <= 0 ? "npeers" :
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

        b = obdio_new_barrier (oid, bid, npeers);
	if (b == NULL) {
		rc = 1;
		goto out;
	}

        rc = 0;
        if (setup) {
                rc = obdio_setup_barrier (conn, b);
                if (rc == 0)
                        printf ("Setup barrier: -d %d -i "LPX64" -p %d -n1 "LPX64"\n",
                                device, bid, npeers, oid);
        } else {
                for (c = 0; c < reps; c++) {
                        rc = obdio_barrier (conn, b);
                        if (rc != 0)
                                break;
                        if (exponential_modulus (c, 10))
                                printf ("%s: Barrier %d\n", hostname, c);
                }
        }

        free(b);
out:
        obdio_disconnect(conn, 0);

        return (rc == 0 ? 0 : 1);
}
