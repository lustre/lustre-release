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

static int timeout = 50;
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

#ifdef CRAY_XT3
static int ptltrace_on_timeout = 0;
CFS_MODULE_PARM(ptltrace_on_timeout, "i", int, 0644,
                "dump ptltrace on timeout");

static char *ptltrace_basename = "/tmp/lnet-ptltrace";
CFS_MODULE_PARM(ptltrace_basename, "s", charp, 0644,
                "ptltrace dump file basename");
#endif
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
        .kptl_peercredits            = &peercredits,
        .kptl_max_msg_size           = &max_msg_size,
        .kptl_peer_hash_table_size   = &peer_hash_table_size,
        .kptl_reschedule_loops       = &reschedule_loops,
        .kptl_ack_puts               = &ack_puts,
#ifdef CRAY_XT3
        .kptl_ptltrace_on_timeout    = &ptltrace_on_timeout,
        .kptl_ptltrace_basename      = &ptltrace_basename,
#endif
#ifdef PJK_DEBUGGING
        .kptl_simulation_bitmap      = &simulation_bitmap,
#endif
};


#if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM
#ifdef CRAY_XT3
static char ptltrace_basename_space[1024];

static void
kptllnd_init_strtunable(char **str_param, char *space, int size)
{
        strncpy(space, *str_param, size);
        space[size - 1] = 0;
        *str_param = space;
}
#endif

static cfs_sysctl_table_t kptllnd_ctl_table[] = {
        {
                .ctl_name = 1,
                .procname = "ntx",
                .data     = &ntx,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 2,
                .procname = "max_nodes",
                .data     = &max_nodes,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 3,
                .procname = "max_procs_per_node",
                .data     = &max_procs_per_node,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 4,
                .procname = "checksum",
                .data     = &checksum,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 5,
                .procname = "timeout",
                .data     = &timeout,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 6,
                .procname = "portal",
                .data     = &portal,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 7,
                .procname = "pid",
                .data     = &pid,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 8,
                .procname = "rxb_npages",
                .data     = &rxb_npages,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 9,
                .procname = "credits",
                .data     = &credits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 10,
                .procname = "peercredits",
                .data     = &peercredits,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 11,
                .procname = "max_msg_size",
                .data     = &max_msg_size,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 12,
                .procname = "peer_hash_table_size",
                .data     = &peer_hash_table_size,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 13,
                .procname = "reschedule_loops",
                .data     = &reschedule_loops,
                .maxlen   = sizeof(int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 14,
                .procname = "ack_puts",
                .data     = &ack_puts,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
#ifdef CRAY_XT3
        {
                .ctl_name = 15,
                .procname = "ptltrace_on_timeout",
                .data     = &ptltrace_on_timeout,
                .maxlen   = sizeof(int),
                .mode     = 0644,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = 16,
                .procname = "ptltrace_basename",
                .data     = ptltrace_basename_space,
                .maxlen   = sizeof(ptltrace_basename_space),
                .mode     = 0644,
                .proc_handler = &proc_dostring,
                .strategy = &sysctl_string
        },
#endif
#ifdef PJK_DEBUGGING
        {
                .ctl_name = 17,
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
                .ctl_name = 203,
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
#ifdef CRAY_XT3
        kptllnd_init_strtunable(&ptltrace_basename,
                                ptltrace_basename_space,
                                sizeof(ptltrace_basename_space));
#endif
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
