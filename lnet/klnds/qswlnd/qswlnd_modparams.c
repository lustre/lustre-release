/*
 * Copyright (C) 2002-2004 Cluster File Systems, Inc.
 *   Author: Eric Barton <eric@bartonsoftware.com>
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

#include "qswnal.h"

static int tx_maxcontig = KQSW_TX_MAXCONTIG;
CFS_MODULE_PARM(tx_maxcontig, "i", int, 0444,
		"maximum payload to de-fragment");

static int ntxmsgs = KQSW_NTXMSGS;
CFS_MODULE_PARM(ntxmsgs, "i", int, 0444,
		"# 'normal' tx msg buffers");

static int nnblk_txmsgs = KQSW_NNBLK_TXMSGS;
CFS_MODULE_PARM(nnblk_txmsgs, "i", int, 0444,
		"# 'reserved' tx msg buffers");

static int nrxmsgs_large = KQSW_NRXMSGS_LARGE;
CFS_MODULE_PARM(nrxmsgs_large, "i", int, 0444,
		"# 'large' rx msg buffers");

static int ep_envelopes_large = KQSW_EP_ENVELOPES_LARGE;
CFS_MODULE_PARM(ep_envelopes_large, "i", int, 0444,
		"# 'large' rx msg envelope buffers");

static int nrxmsgs_small = KQSW_NRXMSGS_SMALL;
CFS_MODULE_PARM(nrxmsgs_small, "i", int, 0444,
		"# 'small' rx msg buffers");

static int ep_envelopes_small = KQSW_EP_ENVELOPES_SMALL;
CFS_MODULE_PARM(ep_envelopes_small, "i", int, 0444,
		"# 'small' rx msg envelope buffers");

static int optimized_puts = KQSW_OPTIMIZED_PUTS;
CFS_MODULE_PARM(optimized_puts, "i", int, 0644,
		"zero-copy puts >= this size");

static int optimized_gets = KQSW_OPTIMIZED_GETS;
CFS_MODULE_PARM(optimized_gets, "i", int, 0644,
		"zero-copy gets >= this size");

kqswnal_tunables_t kqswnal_tunables = {
	.kqn_tx_maxcontig       = &tx_maxcontig,
	.kqn_ntxmsgs            = &ntxmsgs,
	.kqn_nnblk_txmsgs       = &nnblk_txmsgs,
	.kqn_nrxmsgs_large      = &nrxmsgs_large,
	.kqn_ep_envelopes_large = &ep_envelopes_large,
	.kqn_nrxmsgs_small      = &nrxmsgs_small,
	.kqn_ep_envelopes_small = &ep_envelopes_small,
	.kqn_optimized_puts     = &optimized_puts,
	.kqn_optimized_gets     = &optimized_gets,
};

#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM
static ctl_table kqswnal_ctl_table[] = {
	{1, "tx_maxcontig", &tx_maxcontig, 
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{2, "ntxmsgs", &ntxmsgs, 
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{3, "nnblk_txmsgs", &nnblk_txmsgs, 
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{4, "nrxmsgs_large", &nrxmsgs_large, 
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{5, "ep_envelopes_large", &ep_envelopes_large, 
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{6, "nrxmsgs_small", &nrxmsgs_small, 
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{7, "ep_envelopes_small", &ep_envelopes_small, 
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{8, "optimized_puts", &optimized_puts, 
	 sizeof (int), 0644, NULL, &proc_dointvec},
	{9, "optimized_gets", &optimized_gets, 
	 sizeof (int), 0644, NULL, &proc_dointvec},
	{0}
};

static ctl_table kqswnal_top_ctl_table[] = {
	{201, "qswnal", NULL, 0, 0555, kqswnal_ctl_table},
	{0}
};

int
kqswnal_tunables_init ()
{
	kqswnal_tunables.kqn_sysctl =
		register_sysctl_table(kqswnal_top_ctl_table, 0);
	
	if (kqswnal_tunables.kqn_sysctl == NULL)
		CWARN("Can't setup /proc tunables\n");

	return 0;
}

void
kqswnal_tunables_fini ()
{
	if (kqswnal_tunables.kqn_sysctl != NULL)
		unregister_sysctl_table(kqswnal_tunables.kqn_sysctl);
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
