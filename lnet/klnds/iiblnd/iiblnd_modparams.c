/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *   Author: Eric Barton <eric@bartonsoftware.com>
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

#include "iiblnd.h"

static char *ipif_basename = "ib";
CFS_MODULE_PARM(ipif_basename, "s", charp, 0444,
                "IPoIB interface base name");

static char *service_name = "iiblnd";
CFS_MODULE_PARM(service_name, "s", charp, 0444,
                "IB service name");

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

static int sd_retries = 8;
CFS_MODULE_PARM(sd_retries, "i", int, 0444,
                "# times to retry SD queries");

static int keepalive = 100;
CFS_MODULE_PARM(keepalive, "i", int, 0644,
                "Idle time in seconds before sending a keepalive");

static int concurrent_sends = IBNAL_RX_MSGS;
CFS_MODULE_PARM(concurrent_sends, "i", int, 0644,
                "Send work queue sizing");

kib_tunables_t kibnal_tunables = {
        .kib_ipif_basename          = &ipif_basename,
        .kib_service_name           = &service_name,
        .kib_service_number         = &service_number,
        .kib_min_reconnect_interval = &min_reconnect_interval,
        .kib_max_reconnect_interval = &max_reconnect_interval,
        .kib_concurrent_peers       = &concurrent_peers,
        .kib_cksum                  = &cksum,
        .kib_timeout                = &timeout,
        .kib_keepalive              = &keepalive,
        .kib_ntx                    = &ntx,
        .kib_credits                = &credits,
        .kib_peercredits            = &peer_credits,
        .kib_sd_retries             = &sd_retries,
        .kib_concurrent_sends       = &concurrent_sends,
};

#if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM

/* NB max_size specified for proc_dostring entries only needs to be big enough
 * not to truncate the printout; it only needs to be the actual size of the
 * string buffer if we allow writes (and we don't) */

static cfs_sysctl_table_t kibnal_ctl_table[] = {
        {
                .ctl_name = 1,
                .procname = "ipif_basename",
                .data     = &ipif_basename,
                .maxlen   = 1024,
                .mode     = 0444,
                .proc_handler = &proc_dostring
        },
        {
                .ctl_name = 2,
                .procname = "service_name",
                .data     = &service_name,
                .maxlen   = 1024,
                .mode     = 0444,
                .proc_handler = &proc_dostring
        },
        {
                .ctl_name = 3,
                .procname = "service_number",
                .data     = &service_number,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 4,
                .procname = "min_reconnect_interval",
                .data     = &min_reconnect_interval,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 5,
                .procname = "max_reconnect_interval",
                .data     = &max_reconnect_interval,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 6,
                .procname = "concurrent_peers",
                .data     = &concurrent_peers,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 7,
                .procname = "cksum",
                .data     = &cksum,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 8,
                .procname = "timeout",
                .data     = &timeout,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 9,
                .procname = "ntx",
                .data     = &ntx,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 10,
                .procname = "credits",
                .data     = &credits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 11,
                .procname = "peer_credits",
                .data     = &peer_credits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 12,
                .procname = "sd_retries",
                .data     = &sd_retries,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 13,
                .procname = "keepalive",
                .data     = &keepalive,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 14,
                .procname = "concurrent_sends",
                .data     = &concurrent_sends,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {0}
};

static cfs_sysctl_table_t kibnal_top_ctl_table[] = {
        {
                .ctl_name = 203,
                .procname = "openibnal",
                .data     = NULL,
                .maxlen   = 0,
                .mode     = 0555,
                .child    = kibnal_ctl_table
        },
        {0}
};

int
kibnal_tunables_init ()
{
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
