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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (C) 2006 Myricom, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/mxlnd/mxlnd.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 * Author: Scott Atchley <atchley at myri.com>
 */

#include "mxlnd.h"

static int n_waitd = MXLND_N_SCHED;
CFS_MODULE_PARM(n_waitd, "i", int, 0444,
                "# of completion daemons");

/* this was used to allocate global rxs which are no londer used */
static int max_peers = MXLND_MAX_PEERS;
CFS_MODULE_PARM(max_peers, "i", int, 0444,
                "Unused - was maximum number of peers that may connect");

static int cksum = MXLND_CKSUM;
CFS_MODULE_PARM(cksum, "i", int, 0644,
                "set non-zero to enable message (not data payload) checksums");

static int ntx = MXLND_NTX;
CFS_MODULE_PARM(ntx, "i", int, 0444,
                "# of total tx message descriptors");

/* this duplicates ntx */
static int credits = MXLND_NTX;
CFS_MODULE_PARM(credits, "i", int, 0444,
                "Unused - was # concurrent sends to all peers");

static int peercredits = MXLND_MSG_QUEUE_DEPTH;
CFS_MODULE_PARM(peercredits, "i", int, 0444,
                "# concurrent sends to one peer");

static int board = MXLND_MX_BOARD;
CFS_MODULE_PARM(board, "i", int, 0444,
                "index value of the Myrinet board (NIC)");

static int ep_id = MXLND_MX_EP_ID;
CFS_MODULE_PARM(ep_id, "i", int, 0444, "MX endpoint ID");

static char *ipif_name = "myri0";
CFS_MODULE_PARM(ipif_name, "s", charp, 0444,
                "IPoMX interface name");

static int polling = MXLND_POLLING;
CFS_MODULE_PARM(polling, "i", int, 0444,
                "Use 0 to block (wait). A value > 0 will poll that many times before blocking");

static char *hosts = NULL;
CFS_MODULE_PARM(hosts, "s", charp, 0444,
                "Unused - was IP-to-hostname resolution file");

kmx_tunables_t kmxlnd_tunables = {
        .kmx_n_waitd            = &n_waitd,
        .kmx_max_peers          = &max_peers,
        .kmx_cksum              = &cksum,
        .kmx_ntx                = &ntx,
        .kmx_credits            = &credits,
        .kmx_peercredits        = &peercredits,
        .kmx_board              = &board,
        .kmx_ep_id              = &ep_id,
        .kmx_default_ipif       = &ipif_name,
        .kmx_polling            = &polling
};

#if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM

static char ipif_basename_space[32];

#ifndef HAVE_SYSCTL_UNNUMBERED

enum {
        MXLND_N_WAITD   = 1,
        MXLND_MAX_PEERS,
        MXLND_CKSUM,
        MXLND_NNTX,
        MXLND_CREDITS,
        MXLND_BOARD,
        MXLND_EP_ID,
        MXLND_IPIF_BASENAME,
        MXLND_POLLING
};
#else

#define MXLND_N_WAITD           CTL_UNNUMBERED
#define MXLND_MAX_PEERS         CTL_UNNUMBERED
#define MXLND_CKSUM             CTL_UNNUMBERED
#define MXLND_NNTX              CTL_UNNUMBERED
#define MXLND_CREDITS           CTL_UNNUMBERED
#define MXLND_BOARD             CTL_UNNUMBERED
#define MXLND_EP_ID             CTL_UNNUMBERED
#define MXLND_IPIF_BASENAME     CTL_UNNUMBERED
#define MXLND_POLLING           CTL_UNNUMBERED

#endif

static cfs_sysctl_table_t kmxlnd_ctl_table[] = {
        {
                .ctl_name = 1,
                .procname = "n_waitd",
                .data     = &n_waitd,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 2,
                .procname = "max_peers",
                .data     = &max_peers,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 3,
                .procname = "cksum",
                .data     = &cksum,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 4,
                .procname = "ntx",
                .data     = &ntx,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 5,
                .procname = "credits",
                .data     = &credits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 6,
                .procname = "peercredits",
                .data     = &peercredits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 7,
                .procname = "board",
                .data     = &board,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 8,
                .procname = "ep_id",
                .data     = &ep_id,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 9,
                .procname = "ipif_name",
                .data     = ipif_basename_space,
                .maxlen   = sizeof(ipif_basename_space),
                .mode     = 0444,
                .proc_handler = &proc_dostring
        },
        {
                .ctl_name = 10,
                .procname = "polling",
                .data     = &polling,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {0}
};

static cfs_sysctl_table_t kmxlnd_top_ctl_table[] = {
        {
                .ctl_name = 208,
                .procname = "mxlnd",
                .data     = NULL,
                .maxlen   = 0,
                .mode     = 0555,
                .child    = kmxlnd_ctl_table
        },
        {0}
};

void
kmxlnd_initstrtunable(char *space, char *str, int size)
{
        strncpy(space, str, size);
        space[size-1] = 0;
}

void
kmxlnd_sysctl_init (void)
{
        kmxlnd_initstrtunable(ipif_basename_space, ipif_name,
                              sizeof(ipif_basename_space));

        kmxlnd_tunables.kib_sysctl =
                cfs_register_sysctl_table(kmxlnd_top_ctl_table, 0);

        if (kmxlnd_tunables.kib_sysctl == NULL)
                CWARN("Can't setup /proc tunables\n");
}

void
kmxlnd_sysctl_fini (void)
{
        if (kmxlnd_tunables.kib_sysctl != NULL)
                cfs_unregister_sysctl_table(kmxlnd_tunables.kib_sysctl);
}

#else

void
kmxlnd_sysctl_init (void)
{
}

void
kmxlnd_sysctl_fini (void)
{
}

#endif

int
kmxlnd_tunables_init (void)
{
        kmxlnd_sysctl_init();
        return 0;
}

void
kmxlnd_tunables_fini (void)
{
        kmxlnd_sysctl_fini();
}
