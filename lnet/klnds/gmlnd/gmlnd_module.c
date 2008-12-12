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
 *
 * Copyright (c) 2003 Los Alamos National Laboratory (LANL)
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include "gmlnd.h"


static int port = 4;
CFS_MODULE_PARM(port, "i", int, 0444,
                "GM port to use for communications");

static int ntx = 256;
CFS_MODULE_PARM(ntx, "i", int, 0444,
                "# tx descriptors");

static int credits = 128;
CFS_MODULE_PARM(credits, "i", int, 0444,
                "# concurrent sends");

static int peer_credits = 8;
CFS_MODULE_PARM(peer_credits, "i", int, 0444,
                "# concurrent sends per peer");

static int nlarge_tx_bufs = 32;
CFS_MODULE_PARM(nlarge_tx_bufs, "i", int, 0444,
                "# large tx message buffers");

static int nrx_small = 128;
CFS_MODULE_PARM(nrx_small, "i", int, 0444,
                "# small rx message buffers");

static int nrx_large = 64;
CFS_MODULE_PARM(nrx_large, "i", int, 0444,
                "# large rx message buffers");

gmnal_tunables_t gmnal_tunables = {
        .gm_port            = &port,
        .gm_ntx             = &ntx,
        .gm_credits         = &credits,
        .gm_peer_credits    = &peer_credits,
        .gm_nlarge_tx_bufs  = &nlarge_tx_bufs,
        .gm_nrx_small       = &nrx_small,
        .gm_nrx_large       = &nrx_large,
};

#if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM

#ifndef HAVE_SYSCTL_UNNUMBERED

enum {
        GMLND_PORT = 1,
        GMLND_NTX,
        GMLND_CREDITS,
        GMLND_PEERCREDITS,
        GMLND_NLARGE_TX_BUFS,
        GMLND_NRX_SMALL,
        GMLND_NRX_LARGE
};

#else

#define GMLND_PORT              CTL_UNNUMBERED
#define GMLND_NTX               CTL_UNNUMBERED
#define GMLND_CREDITS           CTL_UNNUMBERED
#define GMLND_PEERCREDITS       CTL_UNNUMBERED
#define GMLND_NLARGE_TX_BUFS    CTL_UNNUMBERED
#define GMLND_NRX_SMALL         CTL_UNNUMBERED
#define GMLND_NRX_LARGE         CTL_UNNUMBERED

#endif

static cfs_sysctl_table_t gmnal_ctl_table[] = {
        {
                .ctl_name = GMLND_PORT,
                .procname = "port",
                .data     = &port,
                .maxlen   = sizeof (int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = GMLND_NTX,
                .procname = "ntx",
                .data     = &ntx,
                .maxlen   = sizeof (int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = GMLND_CREDITS,
                .procname = "credits",
                .data     = &credits,
                .maxlen   = sizeof (int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = GMLND_PEERCREDITS,
                .procname = "peer_credits",
                .data     = &peer_credits,
                .maxlen   = sizeof (int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = GMLND_NLARGE_TX_BUFS,
                .procname = "nlarge_tx_bufs",
                .data     = &nlarge_tx_bufs,
                .maxlen   = sizeof (int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = GMLND_NRX_SMALL,
                .procname = "nrx_small",
                .data     = &nrx_small,
                .maxlen   = sizeof (int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {
                .ctl_name = GMLND_NRX_LARGE,
                .procname = "nrx_large",
                .data     = &nrx_large,
                .maxlen   = sizeof (int),
                .mode     = 0444,
                .proc_handler = &proc_dointvec
        },
        {0}
};

static cfs_sysctl_table_t gmnal_top_ctl_table[] = {
        {
                .ctl_name = CTL_GMLND,
                .procname = "gmnal",
                .data     = NULL,
                .maxlen   = 0,
                .mode     = 0555,
                .child    = gmnal_ctl_table
        },
        {0}
};
#endif

static int __init
gmnal_load(void)
{
        int     status;
        CDEBUG(D_TRACE, "This is the gmnal module initialisation routine\n");

#if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM
        gmnal_tunables.gm_sysctl =
                cfs_register_sysctl_table(gmnal_top_ctl_table, 0);

        if (gmnal_tunables.gm_sysctl == NULL)
                CWARN("Can't setup /proc tunables\n");
#endif
        CDEBUG(D_NET, "Calling gmnal_init\n");
        status = gmnal_init();
        if (status == 0) {
                CDEBUG(D_NET, "Portals GMNAL initialised ok\n");
        } else {
                CDEBUG(D_NET, "Portals GMNAL Failed to initialise\n");
                return(-ENODEV);
        }

        CDEBUG(D_NET, "This is the end of the gmnal init routine");

        return(0);
}

static void __exit
gmnal_unload(void)
{
        gmnal_fini();
#if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM
        if (gmnal_tunables.gm_sysctl != NULL)
                cfs_unregister_sysctl_table(gmnal_tunables.gm_sysctl);
#endif
}

module_init(gmnal_load);
module_exit(gmnal_unload);

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Kernel GM LND v1.01");
MODULE_LICENSE("GPL");
