/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 *
 * This file is part of Portals, http://www.lustre.org
 *
 * Portals is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * Portals is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Portals; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include "qswlnd.h"

static int tx_maxcontig = (1<<10);
CFS_MODULE_PARM(tx_maxcontig, "i", int, 0444,
                "maximum payload to de-fragment");

static int ntxmsgs = 512;
CFS_MODULE_PARM(ntxmsgs, "i", int, 0444,
                "# tx msg buffers");

static int credits = 128;
CFS_MODULE_PARM(credits, "i", int, 0444,
                "# concurrent sends");

static int peer_credits = 8;
CFS_MODULE_PARM(peer_credits, "i", int, 0444,
                "# per-peer concurrent sends");

static int nrxmsgs_large = 64;
CFS_MODULE_PARM(nrxmsgs_large, "i", int, 0444,
                "# 'large' rx msg buffers");

static int ep_envelopes_large = 256;
CFS_MODULE_PARM(ep_envelopes_large, "i", int, 0444,
                "# 'large' rx msg envelope buffers");

static int nrxmsgs_small = 256;
CFS_MODULE_PARM(nrxmsgs_small, "i", int, 0444,
                "# 'small' rx msg buffers");

static int ep_envelopes_small = 2048;
CFS_MODULE_PARM(ep_envelopes_small, "i", int, 0444,
                "# 'small' rx msg envelope buffers");

static int optimized_puts = (32<<10);
CFS_MODULE_PARM(optimized_puts, "i", int, 0644,
                "zero-copy puts >= this size");

static int optimized_gets = 2048;
CFS_MODULE_PARM(optimized_gets, "i", int, 0644,
                "zero-copy gets >= this size");

#if KQSW_CKSUM
static int inject_csum_error = 0;
CFS_MODULE_PARM(inject_csum_error, "i", int, 0644,
                "test checksumming");
#endif

kqswnal_tunables_t kqswnal_tunables = {
        .kqn_tx_maxcontig       = &tx_maxcontig,
        .kqn_ntxmsgs            = &ntxmsgs,
        .kqn_credits            = &credits,
        .kqn_peercredits        = &peer_credits,
        .kqn_nrxmsgs_large      = &nrxmsgs_large,
        .kqn_ep_envelopes_large = &ep_envelopes_large,
        .kqn_nrxmsgs_small      = &nrxmsgs_small,
        .kqn_ep_envelopes_small = &ep_envelopes_small,
        .kqn_optimized_puts     = &optimized_puts,
        .kqn_optimized_gets     = &optimized_gets,
#if KQSW_CKSUM
        .kqn_inject_csum_error  = &inject_csum_error,
#endif
};

#if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM

#ifndef HAVE_SYSCTL_UNNUMBERED

enum
	KQSWNAL_TX_MAXCONTIG = 1,
	KQSWNAL_NTXMSG,
	KQSWNAL_CREDITS,
	KQSWNAL_PEERCREDITS,
	KQSWNAL_NRXMSGS_LARGE,
	KQSWNAL_EP_ENVELOPES_LARGE,
	KQSWNAL_NRXMSGS_SMALL,
	KQSWNAL_EP_ENVELOPES_SMALL,
	KQSWNAL_OPTIMIZED_PUTS,
	KQSWNAL_OPTIMIZED_GETS,
	KQSWNAL_INJECT_CSUM_ERROR
};
#else

#define KQSWNAL_TX_MAXCONTIG    CTL_UNNUMBERED
#define KQSWNAL_NTXMSG          CTL_UNNUMBERED
#define KQSWNAL_CREDITS         CTL_UNNUMBERED
#define KQSWNAL_PEERCREDITS     CTL_UNNUMBERED
#define KQSWNAL_NRXMSGS_LARGE   CTL_UNNUMBERED
#define KQSWNAL_EP_ENVELOPES_LARGE CTL_UNNUMBERED
#define KQSWNAL_NRXMSGS_SMALL   CTL_UNNUMBERED
#define KQSWNAL_EP_ENVELOPES_SMALL CTL_UNNUMBERED
#define KQSWNAL_OPTIMIZED_PUTS  CTL_UNNUMBERED
#define KQSWNAL_OPTIMIZED_GETS  CTL_UNNUMBERED
#define KQSWNAL_INJECT_CSUM_ERROR CTL_UNNUMBERED

#endif

static cfs_sysctl_table_t kqswnal_ctl_table[] = {
        {
                .ctl_name = KQSWNAL_TX_MAXCONTIG,
                .procname = "tx_maxcontig",
                .data     = &tx_maxcontig,
                .maxlen   = sizeof (int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KQSWNAL_NTXMSG,
                .procname = "ntxmsgs",
                .data     = &ntxmsgs,
                .maxlen   = sizeof (int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KQSWNAL_CREDITS,
                .procname = "credits",
                .data     = &credits,
                .maxlen   = sizeof (int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KQSWNAL_PEERCREDITS,
                .procname = "peer_credits",
                .data     = &peer_credits,
                .maxlen   = sizeof (int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KQSWNAL_NRXMSGS_LARGE,
                .procname = "nrxmsgs_large",
                .data     = &nrxmsgs_large,
                .maxlen   = sizeof (int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KQSWNAL_EP_ENVELOPES_LARGE,
                .procname = "ep_envelopes_large",
                .data     = &ep_envelopes_large,
                .maxlen   = sizeof (int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KQSWNAL_NRXMSGS_SMALL,
                .procname = "nrxmsgs_small",
                .data     = &nrxmsgs_small,
                .maxlen   = sizeof (int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KQSWNAL_EP_ENVELOPES_SMALL,
                .procname = "ep_envelopes_small",
                .data     = &ep_envelopes_small,
                .maxlen   = sizeof (int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KQSWNAL_OPTIMIZED_PUTS,
                .procname = "optimized_puts",
                .data     = &optimized_puts,
                .maxlen   = sizeof (int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KQSWNAL_OPTIMIZED_GETS,
                .procname = "optimized_gets",
                .data     = &optimized_gets,
                .maxlen   = sizeof (int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
#if KQSW_CKSUM
        {
                .ctl_name = KQSWNAL_INJECT_CSUM_ERROR,
                .procname = "inject_csum_error",
                .data     = &inject_csum_error,
                .maxlen   = sizeof (int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
#endif
        {0}
};

static cfs_sysctl_table_t kqswnal_top_ctl_table[] = {
        {
                .ctl_name = CTL_KQSWNAL,
                .procname = "qswnal",
                .data     = NULL,
                .maxlen   = 0,
                .mode     = 0555,
                .child    = kqswnal_ctl_table
        },
        {0}
};

int
kqswnal_tunables_init ()
{
        kqswnal_tunables.kqn_sysctl =
                cfs_register_sysctl_table(kqswnal_top_ctl_table, 0);

        if (kqswnal_tunables.kqn_sysctl == NULL)
                CWARN("Can't setup /proc tunables\n");

        return 0;
}

void
kqswnal_tunables_fini ()
{
        if (kqswnal_tunables.kqn_sysctl != NULL)
                cfs_unregister_sysctl_table(kqswnal_tunables.kqn_sysctl);
}
#else
int
kqswnal_tunables_init ()
{
        return 0;
}

void
kqswnal_tunables_fini ()
{
}
#endif
