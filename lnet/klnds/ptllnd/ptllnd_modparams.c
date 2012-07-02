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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/ptllnd/ptllnd_modparams.c
 *
 * Author: PJ Kirner <pjkirner@clusterfs.com>
 */


#include "ptllnd.h"

static int ntx = 256;
CFS_MODULE_PARM(ntx, "i", int, 0444,
                "# of TX descriptors");

static int max_nodes = 1152;
CFS_MODULE_PARM(max_nodes, "i", int, 0444,
                "maximum number of peer nodes");

static int max_procs_per_node = 2;
CFS_MODULE_PARM(max_procs_per_node, "i", int, 0444,
                "maximum number of processes per peer node to cache");

static int checksum = 0;
CFS_MODULE_PARM(checksum, "i", int, 0644,
                "set non-zero to enable message (not RDMA) checksums");

/* NB 250 is the Cray Portals wire timeout */
static int timeout = 250;
CFS_MODULE_PARM(timeout, "i", int, 0644,
                "timeout (seconds)");

static int portal = PTLLND_PORTAL;              /* <lnet/ptllnd_wire.h> */
CFS_MODULE_PARM(portal, "i", int, 0444,
                "portal id");

static int pid = PTLLND_PID;                    /* <lnet/ptllnd_wire.h> */
CFS_MODULE_PARM(pid, "i", int, 0444,
                "portals pid");

static int rxb_npages = 1;
CFS_MODULE_PARM(rxb_npages, "i", int, 0444,
                "# of pages per rx buffer");

static int rxb_nspare = 8;
CFS_MODULE_PARM(rxb_nspare, "i", int, 0444,
                "# of spare rx buffers");

static int credits = 128;
CFS_MODULE_PARM(credits, "i", int, 0444,
                "concurrent sends");

static int peercredits = PTLLND_PEERCREDITS;    /* <lnet/ptllnd_wire.h> */
CFS_MODULE_PARM(peercredits, "i", int, 0444,
                "concurrent sends to 1 peer");

static int peer_buffer_credits = 0;
CFS_MODULE_PARM(peer_buffer_credits, "i", int, 0444,
                "# per-peer router buffer credits");

static int max_msg_size = PTLLND_MAX_KLND_MSG_SIZE;  /* <lnet/ptllnd_wire.h> */
CFS_MODULE_PARM(max_msg_size, "i", int, 0444,
                "max size of immediate message");

static int peer_hash_table_size = 101;
CFS_MODULE_PARM(peer_hash_table_size, "i", int, 0444,
                "# of slots in the peer hash table");

static int reschedule_loops = 100;
CFS_MODULE_PARM(reschedule_loops, "i", int, 0644,
                "# of loops before scheduler does cond_resched()");

static int ack_puts = 0;
CFS_MODULE_PARM(ack_puts, "i", int, 0644,
                "get portals to ack all PUTs");

#ifdef PJK_DEBUGGING
static int simulation_bitmap = 0;
CFS_MODULE_PARM(simulation_bitmap, "i", int, 0444,
                "simulation bitmap");
#endif


kptl_tunables_t kptllnd_tunables = {
        .kptl_ntx                    = &ntx,
        .kptl_max_nodes              = &max_nodes,
        .kptl_max_procs_per_node     = &max_procs_per_node,
        .kptl_checksum               = &checksum,
        .kptl_portal                 = &portal,
        .kptl_pid                    = &pid,
        .kptl_timeout                = &timeout,
        .kptl_rxb_npages             = &rxb_npages,
        .kptl_rxb_nspare             = &rxb_nspare,
        .kptl_credits                = &credits,
        .kptl_peertxcredits          = &peercredits,
        .kptl_peerrtrcredits         = &peer_buffer_credits,
        .kptl_max_msg_size           = &max_msg_size,
        .kptl_peer_hash_table_size   = &peer_hash_table_size,
        .kptl_reschedule_loops       = &reschedule_loops,
        .kptl_ack_puts               = &ack_puts,
#ifdef PJK_DEBUGGING
        .kptl_simulation_bitmap      = &simulation_bitmap,
#endif
};


#if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM

#ifndef HAVE_SYSCTL_UNNUMBERED

enum {
        KPTLLND_NTX     = 1,
        KPTLLND_MAX_NODES,
        KPTLLND_MAX_PROC_PER_NODE,
        KPTLLND_CHECKSUM,
        KPTLLND_TIMEOUT,
        KPTLLND_PORTAL,
        KPTLLND_PID,
        KPTLLND_RXB_PAGES,
        KPTLLND_CREDITS,
        KPTLLND_PEERTXCREDITS,
        KPTLLND_PEERRTRCREDITS,
        KPTLLND_MAX_MSG_SIZE,
        KPTLLND_PEER_HASH_SIZE,
        KPTLLND_RESHEDULE_LOOPS,
        KPTLLND_ACK_PUTS,
        KPTLLND_TRACETIMEOUT,
        KPTLLND_TRACEFAIL,
        KPTLLND_TRACEBASENAME,
        KPTLLND_SIMULATION_BITMAP
};
#else

#define KPTLLND_NTX             CTL_UNNUMBERED
#define KPTLLND_MAX_NODES       CTL_UNNUMBERED
#define KPTLLND_MAX_PROC_PER_NODE CTL_UNNUMBERED
#define KPTLLND_CHECKSUM        CTL_UNNUMBERED
#define KPTLLND_TIMEOUT         CTL_UNNUMBERED
#define KPTLLND_PORTAL          CTL_UNNUMBERED
#define KPTLLND_PID             CTL_UNNUMBERED
#define KPTLLND_RXB_PAGES       CTL_UNNUMBERED
#define KPTLLND_CREDITS         CTL_UNNUMBERED
#define KPTLLND_PEERTXCREDITS   CTL_UNNUMBERED
#define KPTLLND_PEERRTRCREDITS  CTL_UNNUMBERED
#define KPTLLND_MAX_MSG_SIZE    CTL_UNNUMBERED
#define KPTLLND_PEER_HASH_SIZE  CTL_UNNUMBERED
#define KPTLLND_RESHEDULE_LOOPS CTL_UNNUMBERED
#define KPTLLND_ACK_PUTS        CTL_UNNUMBERED
#define KPTLLND_TRACETIMEOUT    CTL_UNNUMBERED
#define KPTLLND_TRACEFAIL       CTL_UNNUMBERED
#define KPTLLND_TRACEBASENAME   CTL_UNNUMBERED
#define KPTLLND_SIMULATION_BITMAP CTL_UNNUMBERED
#endif

static cfs_sysctl_table_t kptllnd_ctl_table[] = {
        {
                .ctl_name = KPTLLND_NTX,
                .procname = "ntx",
                .data     = &ntx,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KPTLLND_MAX_NODES,
                .procname = "max_nodes",
                .data     = &max_nodes,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KPTLLND_MAX_PROC_PER_NODE,
                .procname = "max_procs_per_node",
                .data     = &max_procs_per_node,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KPTLLND_CHECKSUM,
                .procname = "checksum",
                .data     = &checksum,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KPTLLND_TIMEOUT,
                .procname = "timeout",
                .data     = &timeout,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KPTLLND_PORTAL,
                .procname = "portal",
                .data     = &portal,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KPTLLND_PID,
                .procname = "pid",
                .data     = &pid,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KPTLLND_RXB_PAGES,
                .procname = "rxb_npages",
                .data     = &rxb_npages,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KPTLLND_CREDITS,
                .procname = "credits",
                .data     = &credits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KPTLLND_PEERTXCREDITS,
                .procname = "peercredits",
                .data     = &peercredits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KPTLLND_PEERRTRCREDITS,
                .procname = "peer_buffer_credits",
                .data     = &peer_buffer_credits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KPTLLND_MAX_MSG_SIZE,
                .procname = "max_msg_size",
                .data     = &max_msg_size,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KPTLLND_PEER_HASH_SIZE,
                .procname = "peer_hash_table_size",
                .data     = &peer_hash_table_size,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KPTLLND_RESHEDULE_LOOPS,
                .procname = "reschedule_loops",
                .data     = &reschedule_loops,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = KPTLLND_ACK_PUTS,
                .procname = "ack_puts",
                .data     = &ack_puts,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
#ifdef PJK_DEBUGGING
        {
                .ctl_name = KPTLLND_SIMULATION_BITMAP,
                .procname = "simulation_bitmap",
                .data     = &simulation_bitmap,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
#endif

        {0}
};

static cfs_sysctl_table_t kptllnd_top_ctl_table[] = {
        {
                .ctl_name = CTL_PTLLND,
                .procname = "ptllnd",
                .data     = NULL,
                .maxlen   = 0,
                .mode     = 0555,
                .child    = kptllnd_ctl_table
        },
        {0}
};

int
kptllnd_tunables_init ()
{
        kptllnd_tunables.kptl_sysctl =
                cfs_register_sysctl_table(kptllnd_top_ctl_table, 0);

        if (kptllnd_tunables.kptl_sysctl == NULL)
                CWARN("Can't setup /proc tunables\n");

        return 0;
}

void
kptllnd_tunables_fini ()
{
        if (kptllnd_tunables.kptl_sysctl != NULL)
                cfs_unregister_sysctl_table(kptllnd_tunables.kptl_sysctl);
}

#else

int
kptllnd_tunables_init ()
{
        return 0;
}

void
kptllnd_tunables_fini ()
{
}

#endif
