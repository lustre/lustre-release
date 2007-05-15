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

#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM
static ctl_table kqswnal_ctl_table[] = {
	{1, "tx_maxcontig", &tx_maxcontig, 
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{2, "ntxmsgs", &ntxmsgs, 
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{3, "credits", &credits, 
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{4, "peer_credits", &peer_credits, 
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{5, "nrxmsgs_large", &nrxmsgs_large, 
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{6, "ep_envelopes_large", &ep_envelopes_large, 
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{7, "nrxmsgs_small", &nrxmsgs_small, 
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{8, "ep_envelopes_small", &ep_envelopes_small, 
	 sizeof (int), 0444, NULL, &proc_dointvec},
	{9, "optimized_puts", &optimized_puts, 
	 sizeof (int), 0644, NULL, &proc_dointvec},
	{10, "optimized_gets", &optimized_gets, 
	 sizeof (int), 0644, NULL, &proc_dointvec},
#if KQSW_CKSUM
	{11, "inject_csum_error", &inject_csum_error, 
	 sizeof (int), 0644, NULL, &proc_dointvec},
#endif
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
