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
 * lnet/klnds/o2iblnd/o2iblnd_modparams.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 */

#include "o2iblnd.h"

static int service = 987;
CFS_MODULE_PARM(service, "i", int, 0444,
                "service number (within RDMA_PS_TCP)");

static int cksum = 0;
CFS_MODULE_PARM(cksum, "i", int, 0644,
                "set non-zero to enable message (not RDMA) checksums");

static int timeout = 50;
CFS_MODULE_PARM(timeout, "i", int, 0644,
                "timeout (seconds)");

static int ntx = 256;
CFS_MODULE_PARM(ntx, "i", int, 0444,
                "# of message descriptors");

static int credits = 64;
CFS_MODULE_PARM(credits, "i", int, 0444,
                "# concurrent sends");

static int peer_credits = 8;
CFS_MODULE_PARM(peer_credits, "i", int, 0444,
                "# concurrent sends to 1 peer");

static char *ipif_name = "ib0";
CFS_MODULE_PARM(ipif_name, "s", charp, 0444,
                "IPoIB interface name");

static int retry_count = 5;
CFS_MODULE_PARM(retry_count, "i", int, 0644,
                "Retransmissions when no ACK received");

static int rnr_retry_count = 6;
CFS_MODULE_PARM(rnr_retry_count, "i", int, 0644,
                "RNR retransmissions");

static int keepalive = 100;
CFS_MODULE_PARM(keepalive, "i", int, 0644,
                "Idle time in seconds before sending a keepalive");

static int ib_mtu = 0;
CFS_MODULE_PARM(ib_mtu, "i", int, 0444,
                "IB MTU 256/512/1024/2048/4096");

#if IBLND_MAP_ON_DEMAND
static int concurrent_sends = IBLND_RX_MSGS;
#else
static int concurrent_sends = IBLND_MSG_QUEUE_SIZE;
#endif
CFS_MODULE_PARM(concurrent_sends, "i", int, 0444,
                "send work-queue sizing");

#if IBLND_MAP_ON_DEMAND
static int fmr_pool_size = 512;
CFS_MODULE_PARM(fmr_pool_size, "i", int, 0444,
                "size of the fmr pool (>= ntx)");

static int fmr_flush_trigger = 384;
CFS_MODULE_PARM(fmr_flush_trigger, "i", int, 0444,
                "# dirty FMRs that triggers pool flush");

static int fmr_cache = 1;
CFS_MODULE_PARM(fmr_cache, "i", int, 0444,
                "non-zero to enable FMR caching");
#endif

kib_tunables_t kiblnd_tunables = {
        .kib_service                = &service,
        .kib_cksum                  = &cksum,
        .kib_timeout                = &timeout,
        .kib_keepalive              = &keepalive,
        .kib_ntx                    = &ntx,
        .kib_credits                = &credits,
        .kib_peercredits            = &peer_credits,
        .kib_default_ipif           = &ipif_name,
        .kib_retry_count            = &retry_count,
        .kib_rnr_retry_count        = &rnr_retry_count,
        .kib_concurrent_sends       = &concurrent_sends,
        .kib_ib_mtu                 = &ib_mtu,
#if IBLND_MAP_ON_DEMAND
        .kib_fmr_pool_size          = &fmr_pool_size,
        .kib_fmr_flush_trigger      = &fmr_flush_trigger,
        .kib_fmr_cache              = &fmr_cache,
#endif
};

#if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM

static char ipif_basename_space[32];

#ifndef HAVE_SYSCTL_UNNUMBERED

enum {
        O2IBLND_SERVICE  = 1,
        O2IBLND_CKSUM,
        O2IBLND_TIMEOUT,
        O2IBLND_NTX,
        O2IBLND_CREDITS,
        O2IBLND_PEER_CREDITS,
        O2IBLND_IPIF_BASENAME,
        O2IBLND_RETRY_COUNT,
        O2IBLND_RNR_RETRY_COUNT,
        O2IBLND_KEEPALIVE,
        O2IBLND_CONCURRENT_SENDS,
        O2IBLND_IB_MTU,
        O2IBLND_FMR_POOL_SIZE,
        O2IBLND_FMR_FLUSH_TRIGGER,
        O2IBLND_FMR_CACHE
};
#else

#define O2IBLND_SERVICE          CTL_UNNUMBERED
#define O2IBLND_CKSUM            CTL_UNNUMBERED
#define O2IBLND_TIMEOUT          CTL_UNNUMBERED
#define O2IBLND_NTX              CTL_UNNUMBERED
#define O2IBLND_CREDITS          CTL_UNNUMBERED
#define O2IBLND_PEER_CREDITS     CTL_UNNUMBERED
#define O2IBLND_IPIF_BASENAME    CTL_UNNUMBERED
#define O2IBLND_RETRY_COUNT      CTL_UNNUMBERED
#define O2IBLND_RNR_RETRY_COUNT  CTL_UNNUMBERED
#define O2IBLND_KEEPALIVE        CTL_UNNUMBERED
#define O2IBLND_CONCURRENT_SENDS CTL_UNNUMBERED
#define O2IBLND_IB_MTU           CTL_UNNUMBERED
#define O2IBLND_FMR_POOL_SIZE    CTL_UNNUMBERED
#define O2IBLND_FMR_FLUSH_TRIGGER CTL_UNNUMBERED
#define O2IBLND_FMR_CACHE        CTL_UNNUMBERED

#endif

static cfs_sysctl_table_t kiblnd_ctl_table[] = {
        {
                .ctl_name = O2IBLND_SERVICE,
                .procname = "service",
                .data     = &service,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = O2IBLND_CKSUM,
                .procname = "cksum",
                .data     = &cksum,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = O2IBLND_TIMEOUT,
                .procname = "timeout",
                .data     = &timeout,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = O2IBLND_NTX,
                .procname = "ntx",
                .data     = &ntx,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = O2IBLND_CREDITS,
                .procname = "credits",
                .data     = &credits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = O2IBLND_PEER_CREDITS,
                .procname = "peer_credits",
                .data     = &peer_credits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = O2IBLND_IPIF_BASENAME,
                .procname = "ipif_name",
                .data     = ipif_basename_space,
                .maxlen   = sizeof(ipif_basename_space),
                .mode     = 0444,
                .proc_handler = &proc_dostring
        },
        {
                .ctl_name = O2IBLND_RETRY_COUNT,
                .procname = "retry_count",
                .data     = &retry_count,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = O2IBLND_RNR_RETRY_COUNT,
                .procname = "rnr_retry_count",
                .data     = &rnr_retry_count,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = O2IBLND_KEEPALIVE,
                .procname = "keepalive",
                .data     = &keepalive,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = O2IBLND_CONCURRENT_SENDS,
                .procname = "concurrent_sends",
                .data     = &concurrent_sends,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = O2IBLND_IB_MTU,
                .procname = "ib_mtu",
                .data     = &ib_mtu,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
#if IBLND_MAP_ON_DEMAND
        {
                .ctl_name = O2IBLND_FMR_POOL_SIZE,
                .procname = "fmr_pool_size",
                .data     = &fmr_pool_size,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = O2IBLND_FMR_FLUSH_TRIGGER,
                .procname = "fmr_flush_trigger",
                .data     = &fmr_flush_trigger,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = O2IBLND_FMR_CACHE,
                .procname = "fmr_cache",
                .data     = &fmr_cache,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
#endif
        {0}
};

static cfs_sysctl_table_t kiblnd_top_ctl_table[] = {
        {
                .ctl_name = CTL_O2IBLND,
                .procname = "o2iblnd",
                .data     = NULL,
                .maxlen   = 0,
                .mode     = 0555,
                .child    = kiblnd_ctl_table
        },
        {0}
};

void
kiblnd_initstrtunable(char *space, char *str, int size)
{
        strncpy(space, str, size);
        space[size-1] = 0;
}

void
kiblnd_sysctl_init (void)
{
        kiblnd_initstrtunable(ipif_basename_space, ipif_name,
                              sizeof(ipif_basename_space));

        kiblnd_tunables.kib_sysctl =
                cfs_register_sysctl_table(kiblnd_top_ctl_table, 0);

        if (kiblnd_tunables.kib_sysctl == NULL)
                CWARN("Can't setup /proc tunables\n");
}

void
kiblnd_sysctl_fini (void)
{
        if (kiblnd_tunables.kib_sysctl != NULL)
                cfs_unregister_sysctl_table(kiblnd_tunables.kib_sysctl);
}

#else

void
kiblnd_sysctl_init (void)
{
}

void
kiblnd_sysctl_fini (void)
{
}

#endif

int
kiblnd_tunables_init (void)
{
        kiblnd_sysctl_init();

        if (*kiblnd_tunables.kib_concurrent_sends > IBLND_RX_MSGS)
                *kiblnd_tunables.kib_concurrent_sends = IBLND_RX_MSGS;
        if (*kiblnd_tunables.kib_concurrent_sends < IBLND_MSG_QUEUE_SIZE)
                *kiblnd_tunables.kib_concurrent_sends = IBLND_MSG_QUEUE_SIZE;

        return 0;
}

void
kiblnd_tunables_fini (void)
{
        kiblnd_sysctl_fini();
}
