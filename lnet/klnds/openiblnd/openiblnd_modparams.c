/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
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
 *
 */

#include "openiblnd.h"

static char *ipif_basename = "ib";
CFS_MODULE_PARM(ipif_basename, "s", charp, 0444,
                "IPoIB interface base name");

static int n_connd = 4;
CFS_MODULE_PARM(n_connd, "i", int, 0444,
                "# of connection daemons");

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

static int ntx = 384;
CFS_MODULE_PARM(ntx, "i", int, 0444,
		"# of message descriptors");

static int credits = 256;
CFS_MODULE_PARM(credits, "i", int, 0444,
		"# concurrent sends");

static int peer_credits = 16;
CFS_MODULE_PARM(peer_credits, "i", int, 0444,
		"# concurrent sends to 1 peer");

static int keepalive = 100;
CFS_MODULE_PARM(keepalive, "i", int, 0644,
                "Idle time in seconds before sending a keepalive");

kib_tunables_t kibnal_tunables = {
        .kib_ipif_basename          = &ipif_basename,
	.kib_n_connd                = &n_connd,
        .kib_min_reconnect_interval = &min_reconnect_interval,
        .kib_max_reconnect_interval = &max_reconnect_interval,
        .kib_concurrent_peers       = &concurrent_peers,
	.kib_cksum                  = &cksum,
        .kib_timeout                = &timeout,
        .kib_ntx                    = &ntx,
        .kib_credits                = &credits,
        .kib_peercredits            = &peer_credits,
        .kib_keepalive              = &keepalive,
};

#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM

static ctl_table kibnal_ctl_table[] = {
	{1, "ipif_basename", &ipif_basename, 
         1024, 0444, NULL, &proc_dostring},
	{2, "n_connd", &n_connd, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{3, "min_reconnect_interval", &min_reconnect_interval, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{4, "max_reconnect_interval", &max_reconnect_interval, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{5, "concurrent_peers", &concurrent_peers, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{6, "cksum", &cksum, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{7, "timeout", &timeout, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{8, "ntx", &ntx, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{9, "credits", &credits, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{10, "peer_credits", &peer_credits, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{11, "keepalive", &keepalive, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{0}
};

static ctl_table kibnal_top_ctl_table[] = {
	{203, "openibnal", NULL, 0, 0555, kibnal_ctl_table},
	{0}
};

int
kibnal_tunables_init ()
{
	kibnal_tunables.kib_sysctl =
		cfs_register_sysctl_table(kibnal_top_ctl_table, 0);
	
	if (kibnal_tunables.kib_sysctl == NULL)
		CWARN("Can't setup /proc tunables\n");

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
