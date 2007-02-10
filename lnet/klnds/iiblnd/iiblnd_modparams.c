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

#include "iiblnd.h"

static char *ipif_basename = "ib";
CFS_MODULE_PARM(ipif_basename, "s", charp, 0444,
                "IPoIB interface base name");

static char *service_name = "iiblnd";
CFS_MODULE_PARM(service_name, "s", charp, 0444,
                "IB service name");

static int service_number = 0x11b9a2;
CFS_MODULE_PARM(service_number, "i", int, 0444,
                "IB service number");

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

static int ntx = 256;
CFS_MODULE_PARM(ntx, "i", int, 0444,
		"# of message descriptors");

static int credits = 128;
CFS_MODULE_PARM(credits, "i", int, 0444,
		"# concurrent sends");

static int peer_credits = 8;
CFS_MODULE_PARM(peer_credits, "i", int, 0444,
		"# concurrent sends to 1 peer");

static int sd_retries = 8;
CFS_MODULE_PARM(sd_retries, "i", int, 0444,
		"# times to retry SD queries");

static int keepalive = 100;
CFS_MODULE_PARM(keepalive, "i", int, 0644,
                "Idle time in seconds before sending a keepalive");

static int concurrent_sends = IBNAL_RX_MSGS;
CFS_MODULE_PARM(concurrent_sends, "i", int, 0644,
                "Send work queue sizing");

kib_tunables_t kibnal_tunables = {
        .kib_ipif_basename          = &ipif_basename,
        .kib_service_name           = &service_name,
        .kib_service_number         = &service_number,
        .kib_min_reconnect_interval = &min_reconnect_interval,
        .kib_max_reconnect_interval = &max_reconnect_interval,
        .kib_concurrent_peers       = &concurrent_peers,
	.kib_cksum                  = &cksum,
        .kib_timeout                = &timeout,
        .kib_keepalive              = &keepalive,
        .kib_ntx                    = &ntx,
        .kib_credits                = &credits,
        .kib_peercredits            = &peer_credits,
        .kib_sd_retries             = &sd_retries,
        .kib_concurrent_sends       = &concurrent_sends,
};

#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM

/* NB max_size specified for proc_dostring entries only needs to be big enough
 * not to truncate the printout; it only needs to be the actual size of the
 * string buffer if we allow writes (and we don't) */

static ctl_table kibnal_ctl_table[] = {
	{1, "ipif_basename", &ipif_basename, 
         1024, 0444, NULL, &proc_dostring},
	{2, "service_name", &service_name, 
         1024, 0444, NULL, &proc_dostring},
	{3, "service_number", &service_number, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{4, "min_reconnect_interval", &min_reconnect_interval, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{5, "max_reconnect_interval", &max_reconnect_interval, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{6, "concurrent_peers", &concurrent_peers, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{7, "cksum", &cksum, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{8, "timeout", &timeout, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{9, "ntx", &ntx, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{10, "credits", &credits, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{11, "peer_credits", &peer_credits, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{12, "sd_retries", &sd_retries, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{13, "keepalive", &keepalive, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{14, "concurrent_sends", &concurrent_sends, 
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
		register_sysctl_table(kibnal_top_ctl_table, 0);
	
	if (kibnal_tunables.kib_sysctl == NULL)
		CWARN("Can't setup /proc tunables\n");

        if (*kibnal_tunables.kib_concurrent_sends > IBNAL_RX_MSGS)
                *kibnal_tunables.kib_concurrent_sends = IBNAL_RX_MSGS;
        if (*kibnal_tunables.kib_concurrent_sends < IBNAL_MSG_QUEUE_SIZE)
                *kibnal_tunables.kib_concurrent_sends = IBNAL_MSG_QUEUE_SIZE;

	return 0;
}

void
kibnal_tunables_fini ()
{
	if (kibnal_tunables.kib_sysctl != NULL)
		unregister_sysctl_table(kibnal_tunables.kib_sysctl);
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
