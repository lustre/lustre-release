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

#include "viblnd.h"

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

static int arp_retries = 3;
CFS_MODULE_PARM(arp_retries, "i", int, 0644,
		"# of times to retry ARP");

static char *hca_basename = "InfiniHost";
CFS_MODULE_PARM(hca_basename, "s", charp, 0444,
                "HCA base name");

static char *ipif_basename = "ipoib";
CFS_MODULE_PARM(ipif_basename, "s", charp, 0444,
                "IPoIB interface base name");

static int local_ack_timeout = 0x12;
CFS_MODULE_PARM(local_ack_timeout, "i", int, 0644,
                "ACK timeout for low-level 'sends'");

static int retry_cnt = 7;
CFS_MODULE_PARM(retry_cnt, "i", int, 0644,
                "Retransmissions when no ACK received");

static int rnr_cnt = 6;
CFS_MODULE_PARM(rnr_cnt, "i", int, 0644,
                "RNR retransmissions");

static int rnr_nak_timer = 0x10;
CFS_MODULE_PARM(rnr_nak_timer, "i", int, 0644,
                "RNR retransmission interval");

static int keepalive = 100;
CFS_MODULE_PARM(keepalive, "i", int, 0644,
                "Idle time in seconds before sending a keepalive");

static int concurrent_sends = IBNAL_RX_MSGS;
CFS_MODULE_PARM(concurrent_sends, "i", int, 0644,
                "send work-queue sizing");

#if IBNAL_USE_FMR
static int fmr_remaps = 1000;
CFS_MODULE_PARM(fmr_remaps, "i", int, 0444,
                "FMR mappings allowed before unmap");
#endif

kib_tunables_t kibnal_tunables = {
        .kib_service_number         = &service_number,
        .kib_min_reconnect_interval = &min_reconnect_interval,
        .kib_max_reconnect_interval = &max_reconnect_interval,
        .kib_concurrent_peers       = &concurrent_peers,
        .kib_cksum                  = &cksum,
        .kib_timeout                = &timeout,
        .kib_ntx                    = &ntx,
        .kib_credits                = &credits,
        .kib_peercredits            = &peer_credits,
        .kib_arp_retries            = &arp_retries,
        .kib_hca_basename           = &hca_basename,
        .kib_ipif_basename          = &ipif_basename,
        .kib_local_ack_timeout      = &local_ack_timeout,
        .kib_retry_cnt              = &retry_cnt,
        .kib_rnr_cnt                = &rnr_cnt,
        .kib_rnr_nak_timer          = &rnr_nak_timer,
        .kib_keepalive              = &keepalive,
        .kib_concurrent_sends       = &concurrent_sends,
#if IBNAL_USE_FMR
        .kib_fmr_remaps             = &fmr_remaps,
#endif
};

#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM

static char hca_basename_space[32];
static char ipif_basename_space[32];

static ctl_table kibnal_ctl_table[] = {
	{1, "service_number", &service_number, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{2, "min_reconnect_interval", &min_reconnect_interval, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{3, "max_reconnect_interval", &max_reconnect_interval, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{4, "concurrent_peers", &concurrent_peers, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{5, "cksum", &cksum, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{6, "timeout", &timeout, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{7, "ntx", &ntx, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{8, "credits", &credits, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{9, "peer_credits", &peer_credits, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{10, "arp_retries", &arp_retries, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{11, "hca_basename", hca_basename_space, 
	 sizeof(hca_basename_space), 0444, NULL, &proc_dostring},
	{12, "ipif_basename", ipif_basename_space, 
	 sizeof(ipif_basename_space), 0444, NULL, &proc_dostring},
	{13, "local_ack_timeout", &local_ack_timeout, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{14, "retry_cnt", &retry_cnt, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{15, "rnr_cnt", &rnr_cnt, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{16, "rnr_nak_timer", &rnr_nak_timer, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{17, "keepalive", &keepalive, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{18, "concurrent_sends", &concurrent_sends, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
#if IBNAL_USE_FMR
	{19, "fmr_remaps", &fmr_remaps, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
#endif        
	{0}
};

static ctl_table kibnal_top_ctl_table[] = {
	{203, "vibnal", NULL, 0, 0555, kibnal_ctl_table},
	{0}
};

void
kibnal_initstrtunable(char *space, char *str, int size)
{
        strncpy(space, str, size);
        space[size-1] = 0;
}

int
kibnal_tunables_init ()
{
        kibnal_initstrtunable(hca_basename_space, hca_basename,
                              sizeof(hca_basename_space));
        kibnal_initstrtunable(ipif_basename_space, ipif_basename,
                              sizeof(ipif_basename_space));

	kibnal_tunables.kib_sysctl =
		cfs_register_sysctl_table(kibnal_top_ctl_table, 0);

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
