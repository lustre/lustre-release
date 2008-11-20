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
 * lnet/klnds/iiblnd/iiblnd_modparams.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
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

#ifdef HAVE_SYSCTL_UNNUMBERED

enum {
        IIBLND_IPIF_BASENAME = 1,
        IIBLND_SERVICE_NAME,
        IIBLND_SERVICE_NUMBER,
        IIBLND_RECONNECT_MIN,
        IIBLND_RECONNECT_MAX,
        IIBLND_CONCURRENT_PEERS,
        IIBLND_CKSUM,
        IIBLND_TIMEOUT,
        IIBLND_NTX,
        IIBLND_CREDITS,
        IIBLND_PEER_CREDITS,
        IIBLND_SD_RETRIES,
        IIBLND_KEEPALIVE,
        IIBLND_CONCURRENT_SENDS
};

#else

#define IIBLND_IPIF_BASENAME    CTL_UNNUMBERED
#define IIBLND_SERVICE_NAME     CTL_UNNUMBERED
#define IIBLND_SERVICE_NUMBER   CTL_UNNUMBERED
#define IIBLND_RECONNECT_MIN    CTL_UNNUMBERED
#define IIBLND_RECONNECT_MAX    CTL_UNNUMBERED
#define IIBLND_CONCURRENT_PEERS CTL_UNNUMBERED
#define IIBLND_CKSUM            CTL_UNNUMBERED
#define IIBLND_TIMEOUT          CTL_UNNUMBERED
#define IIBLND_NTX              CTL_UNNUMBERED
#define IIBLND_CREDITS          CTL_UNNUMBERED
#define IIBLND_PEER_CREDITS     CTL_UNNUMBERED
#define IIBLND_SD_RETRIES       CTL_UNNUMBERED
#define IIBLND_KEEPALIVE        CTL_UNNUMBERED
#define IIBLND_CONCURRENT_SENDS CTL_UNNUMBERED

#endif

static cfs_sysctl_table_t kibnal_ctl_table[] = {
        {
                .ctl_name = IBBLND_IPIF_BASENAME,
                .procname = "ipif_basename",
                .data     = &ipif_basename,
                .maxlen   = 1024,
                .mode     = 0444,
                .proc_handler = &proc_dostring
        },
        {
                .ctl_name = IIBLND_SERVICE_NAME,
                .procname = "service_name",
                .data     = &service_name,
                .maxlen   = 1024,
                .mode     = 0444,
                .proc_handler = &proc_dostring
        },
        {
                .ctl_name = IIBLND_SERVICE_NUMBER,
                .procname = "service_number",
                .data     = &service_number,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = IIBLND_RECONNECT_MIN,
                .procname = "min_reconnect_interval",
                .data     = &min_reconnect_interval,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = IIBLND_RECONNECT_MAX,
                .procname = "max_reconnect_interval",
                .data     = &max_reconnect_interval,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = IIBLND_CONCURRENT_PEERS,
                .procname = "concurrent_peers",
                .data     = &concurrent_peers,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = IIBLND_CKSUM,
                .procname = "cksum",
                .data     = &cksum,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = IIBLND_TIMEOUT,
                .procname = "timeout",
                .data     = &timeout,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = IIBLND_NTX,
                .procname = "ntx",
                .data     = &ntx,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = IIBLND_CREDITS,
                .procname = "credits",
                .data     = &credits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = IIBLND_PEER_CREDITS,
                .procname = "peer_credits",
                .data     = &peer_credits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = IIBLND_SD_RETRIES,
                .procname = "sd_retries",
                .data     = &sd_retries,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = IIBLND_KEEPALIVE,
                .procname = "keepalive",
                .data     = &keepalive,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = IIBLND_CONCURRENT_SENDS,
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
                .ctl_name = CTL_IIBLND,
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
