/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/viblnd/viblnd_modparams.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 */

#include "viblnd.h"

static int service_number = 0x11b9a2;
CFS_MODULE_PARM(service_number, "i", int, 0444,
                "IB service number");

static int min_reconnect_interval = 1;
CFS_MODULE_PARM(min_reconnect_interval, "i", int, 0644,
                "minimum connection retry interval (seconds)");

static int max_reconnect_interval = 60;
CFS_MODULE_PARM(max_reconnect_interval, "i", int, 0644,
                "maximum connection retry interval (seconds)");

static int concurrent_peers = 1152;
CFS_MODULE_PARM(concurrent_peers, "i", int, 0444,
                "maximum number of peers that may connect");

static int cksum = 0;
CFS_MODULE_PARM(cksum, "i", int, 0644,
                "set non-zero to enable message (not RDMA) checksums");

static int timeout = 50;
CFS_MODULE_PARM(timeout, "i", int, 0644,
                "timeout (seconds)");

static int ntx = 256;
CFS_MODULE_PARM(ntx, "i", int, 0444,
                "# of message descriptors");

static int credits = 128;
CFS_MODULE_PARM(credits, "i", int, 0444,
                "# concurrent sends");

static int peer_credits = 8;
CFS_MODULE_PARM(peer_credits, "i", int, 0444,
                "# concurrent sends to 1 peer");

static int arp_retries = 3;
CFS_MODULE_PARM(arp_retries, "i", int, 0644,
                "# of times to retry ARP");

static char *hca_basename = "InfiniHost";
CFS_MODULE_PARM(hca_basename, "s", charp, 0444,
                "HCA base name");

static char *ipif_basename = "ipoib";
CFS_MODULE_PARM(ipif_basename, "s", charp, 0444,
                "IPoIB interface base name");

static int local_ack_timeout = 0x12;
CFS_MODULE_PARM(local_ack_timeout, "i", int, 0644,
                "ACK timeout for low-level 'sends'");

static int retry_cnt = 7;
CFS_MODULE_PARM(retry_cnt, "i", int, 0644,
                "Retransmissions when no ACK received");

static int rnr_cnt = 6;
CFS_MODULE_PARM(rnr_cnt, "i", int, 0644,
                "RNR retransmissions");

static int rnr_nak_timer = 0x10;
CFS_MODULE_PARM(rnr_nak_timer, "i", int, 0644,
                "RNR retransmission interval");

static int keepalive = 100;
CFS_MODULE_PARM(keepalive, "i", int, 0644,
                "Idle time in seconds before sending a keepalive");

static int concurrent_sends = IBNAL_RX_MSGS;
CFS_MODULE_PARM(concurrent_sends, "i", int, 0644,
                "send work-queue sizing");

#if IBNAL_USE_FMR
static int fmr_remaps = 1000;
CFS_MODULE_PARM(fmr_remaps, "i", int, 0444,
                "FMR mappings allowed before unmap");
#endif

kib_tunables_t kibnal_tunables = {
        .kib_service_number         = &service_number,
        .kib_min_reconnect_interval = &min_reconnect_interval,
        .kib_max_reconnect_interval = &max_reconnect_interval,
        .kib_concurrent_peers       = &concurrent_peers,
        .kib_cksum                  = &cksum,
        .kib_timeout                = &timeout,
        .kib_ntx                    = &ntx,
        .kib_credits                = &credits,
        .kib_peercredits            = &peer_credits,
        .kib_arp_retries            = &arp_retries,
        .kib_hca_basename           = &hca_basename,
        .kib_ipif_basename          = &ipif_basename,
        .kib_local_ack_timeout      = &local_ack_timeout,
        .kib_retry_cnt              = &retry_cnt,
        .kib_rnr_cnt                = &rnr_cnt,
        .kib_rnr_nak_timer          = &rnr_nak_timer,
        .kib_keepalive              = &keepalive,
        .kib_concurrent_sends       = &concurrent_sends,
#if IBNAL_USE_FMR
        .kib_fmr_remaps             = &fmr_remaps,
#endif
};

#if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM

static char hca_basename_space[32];
static char ipif_basename_space[32];

static cfs_sysctl_table_t kibnal_ctl_table[] = {
        {
                .ctl_name = 1,
                .procname = "service_number",
                .data     = &service_number,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 2,
                .procname = "min_reconnect_interval",
                .data     = &min_reconnect_interval,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 3,
                .procname = "max_reconnect_interval",
                .data     = &max_reconnect_interval,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 4,
                .procname = "concurrent_peers",
                .data     = &concurrent_peers,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 5,
                .procname = "cksum",
                .data     = &cksum,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 6,
                .procname = "timeout",
                .data     = &timeout,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 7,
                .procname = "ntx",
                .data     = &ntx,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 8,
                .procname = "credits",
                .data     = &credits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 9,
                .procname = "peer_credits",
                .data     = &peer_credits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 10,
                .procname = "arp_retries",
                .data     = &arp_retries,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 11,
                .procname = "hca_basename",
                .data     = hca_basename_space,
                .maxlen   = sizeof(hca_basename_space),
                .mode     = 0444,
                .proc_handler = &proc_dostring
        },
        {
                .ctl_name = 12,
                .procname = "ipif_basename",
                .data     = ipif_basename_space,
                .maxlen   = sizeof(ipif_basename_space),
                .mode     = 0444,
                .proc_handler = &proc_dostring
        },
        {
                .ctl_name = 13,
                .procname = "local_ack_timeout",
                .data     = &local_ack_timeout,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 14,
                .procname = "retry_cnt",
                .data     = &retry_cnt,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 15,
                .procname = "rnr_cnt",
                .data     = &rnr_cnt,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 16,
                .procname = "rnr_nak_timer",
                .data     = &rnr_nak_timer,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 17,
                .procname = "keepalive",
                .data     = &keepalive,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 18,
                .procname = "concurrent_sends",
                .data     = &concurrent_sends,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
#if IBNAL_USE_FMR
        {
                .ctl_name = 19,
                .procname = "fmr_remaps",
                .data     = &fmr_remaps,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
#endif
        {0}
};

static cfs_sysctl_table_t kibnal_top_ctl_table[] = {
        {
                .ctl_name = 203,
                .procname = "vibnal",
                .data     = NULL,
                .maxlen   = 0,
                .mode     = 0555,
                .child    = kibnal_ctl_table
        },
        {0}
};

void
kibnal_initstrtunable(char *space, char *str, int size)
{
        strncpy(space, str, size);
        space[size-1] = 0;
}

int
kibnal_tunables_init ()
{
        kibnal_initstrtunable(hca_basename_space, hca_basename,
                              sizeof(hca_basename_space));
        kibnal_initstrtunable(ipif_basename_space, ipif_basename,
                              sizeof(ipif_basename_space));

        kibnal_tunables.kib_sysctl =
                cfs_register_sysctl_table(kibnal_top_ctl_table, 0);

        if (kibnal_tunables.kib_sysctl == NULL)
                CWARN("Can't setup /proc tunables\n");

        if (*kibnal_tunables.kib_concurrent_sends > IBNAL_RX_MSGS)
                *kibnal_tunables.kib_concurrent_sends = IBNAL_RX_MSGS;
        if (*kibnal_tunables.kib_concurrent_sends < IBNAL_MSG_QUEUE_SIZE)
                *kibnal_tunables.kib_concurrent_sends = IBNAL_MSG_QUEUE_SIZE;

        return 0;
}

void
kibnal_tunables_fini ()
{
        if (kibnal_tunables.kib_sysctl != NULL)
                cfs_unregister_sysctl_table(kibnal_tunables.kib_sysctl);
}

#else

int
kibnal_tunables_init ()
{
        return 0;
}

void
kibnal_tunables_fini ()
{
}

#endif
