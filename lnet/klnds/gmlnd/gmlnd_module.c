/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Los Alamos National Laboratory (LANL)
 *
 *   This file is part of Lustre, http://www.lustre.org/
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

#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM
static ctl_table gmnal_ctl_table[] = {
	{1, "port", &port,
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{2, "ntx", &ntx, 
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{3, "credits", &credits,
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{4, "peer_credits", &peer_credits,
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{5, "nlarge_tx_bufs", &nlarge_tx_bufs,
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{6, "nrx_small", &nrx_small,
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{7, "nrx_large", &nrx_large,
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{0}
};

static ctl_table gmnal_top_ctl_table[] = {
	{207, "gmnal", NULL, 0, 0555, gmnal_ctl_table},
	{0}
};
#endif

static int __init
gmnal_load(void)
{
	int	status;
	CDEBUG(D_TRACE, "This is the gmnal module initialisation routine\n");

#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM
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
#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM
        if (gmnal_tunables.gm_sysctl != NULL)
                cfs_unregister_sysctl_table(gmnal_tunables.gm_sysctl);
#endif
}

module_init(gmnal_load);
module_exit(gmnal_unload);

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Kernel GM LND v1.01");
MODULE_LICENSE("GPL");
