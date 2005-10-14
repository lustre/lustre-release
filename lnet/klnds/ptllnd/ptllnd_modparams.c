/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc. All rights reserved.
 *   Author: PJ Kirner <pjkirner@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   This file is confidential source code owned by Cluster File Systems.
 *   No viewing, modification, compilation, redistribution, or any other
 *   form of use is permitted except through a signed license agreement.
 *
 *   If you have not signed such an agreement, then you have no rights to
 *   this file.  Please destroy it immediately and contact CFS.
 *
 */


#include "ptllnd.h"

static int ntx = PTLLND_NTX;
CFS_MODULE_PARM(ntx, "i", int, 0444,
		"# of TX descriptors");

static int concurrent_peers = PTLLND_CONCURRENT_PEERS;
CFS_MODULE_PARM(concurrent_peers, "i", int, 0444,
		"maximum number of peers that may connect");

static int cksum = PTLLND_CKSUM;
CFS_MODULE_PARM(cksum, "i", int, 0644,
		"set non-zero to enable message (not RDMA) checksums");

static int timeout = PTLLND_TIMEOUT;
CFS_MODULE_PARM(timeout, "i", int, 0644,
		"timeout (seconds)");

static int portal = PTLLND_PORTAL;
CFS_MODULE_PARM(portal, "i", int, 0444,
		"portal id");

static int rxb_npages = PTLLND_RXB_NPAGES;
CFS_MODULE_PARM(rxb_npages, "i", int, 0444,
		"# of pages for rx buffers");

static int credits = PTLLND_CREDITS;
CFS_MODULE_PARM(credits, "i", int, 0444,
		"concurrent sends");

static int peercredits = PTLLND_PEERCREDITS;
CFS_MODULE_PARM(peercredits, "i", int, 0444,
		"concurrent sends to 1 peer");

static int max_msg_size = PTLLND_MAX_MSG_SIZE;
CFS_MODULE_PARM(max_msg_size, "i", int, 0444,
		"max size of immediate message");

static int peer_hash_table_size = PTLLND_PEER_HASH_SIZE;
CFS_MODULE_PARM(peer_hash_table_size, "i", int, 0444,
		"# of slots in the peer hash table");

#ifdef PJK_DEBUGGING
static int simulation_bitmap = 0;
CFS_MODULE_PARM(simulation_bitmap, "i", int, 0444,
		"simulation bitmap");
#endif


kptl_tunables_t kptllnd_tunables = {
        .kptl_ntx                    = &ntx,
        .kptl_concurrent_peers       = &concurrent_peers,
        .kptl_cksum                  = &cksum,
        .kptl_portal                 = &portal,
        .kptl_timeout                = &timeout,
        .kptl_rxb_npages             = &rxb_npages,
        .kptl_credits                = &credits,
        .kptl_peercredits            = &peercredits,
        .kptl_max_msg_size           = &max_msg_size,
        .kptl_peer_hash_table_size   = &peer_hash_table_size,
#ifdef PJK_DEBUGGING
        .kptl_simulation_bitmap      = &simulation_bitmap,
#endif
};


#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM

static ctl_table kptllnd_ctl_table[] = {
	{1, "ntx", &ntx,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{2, "concurrent_peers", &concurrent_peers,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{3, "cksum", &cksum,
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{4, "timeout", &timeout,
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{5, "portal", &portal,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{6, "rxb_npages", &rxb_npages,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{7, "credits", &credits,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{8, "peercredits", &peercredits,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{9, "max_msg_size", &max_msg_size,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{10, "peer_hash_table_size,", &peer_hash_table_size,
	 sizeof(int), 0444, NULL, &proc_dointvec},

#ifdef PJK_DEBUGGING
	{11, "simulation_bitmap,", &simulation_bitmap,
	 sizeof(int), 0444, NULL, &proc_dointvec},
#endif

	{0}
};

static ctl_table kptllnd_top_ctl_table[] = {
	{203, "ptllnd", NULL, 0, 0555, kptllnd_ctl_table},
	{0}
};

int
kptllnd_tunables_init ()
{
	kptllnd_tunables.kptl_sysctl =
		register_sysctl_table(kptllnd_top_ctl_table, 0);

	if (kptllnd_tunables.kptl_sysctl == NULL)
		CWARN("Can't setup /proc tunables\n");

	return 0;
}

void
kptllnd_tunables_fini ()
{
	if (kptllnd_tunables.kptl_sysctl != NULL)
		unregister_sysctl_table(kptllnd_tunables.kptl_sysctl);
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

