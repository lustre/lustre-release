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

#include "vibnal.h"

static int service_number = IBNAL_SERVICE_NUMBER;
CFS_MODULE_PARM(service_number, "i", int, 0444,
                "IB service number");

static int min_reconnect_interval = IBNAL_MIN_RECONNECT_INTERVAL;
CFS_MODULE_PARM(min_reconnect_interval, "i", int, 0644,
		"minimum connection retry interval (seconds)");

static int max_reconnect_interval = IBNAL_MAX_RECONNECT_INTERVAL;
CFS_MODULE_PARM(max_reconnect_interval, "i", int, 0644,
		"maximum connection retry interval (seconds)");

static int concurrent_peers = IBNAL_CONCURRENT_PEERS;
CFS_MODULE_PARM(concurrent_peers, "i", int, 0444,
		"maximum number of peers that may connect");

static int cksum = IBNAL_CKSUM;
CFS_MODULE_PARM(cksum, "i", int, 0644,
		"set non-zero to enable message (not RDMA) checksums");

static int timeout = IBNAL_TIMEOUT;
CFS_MODULE_PARM(timeout, "i", int, 0644,
		"timeout (seconds)");

static int ntx = IBNAL_NTX;
CFS_MODULE_PARM(ntx, "i", int, 0444,
		"# of 'normal' message descriptors");

static int ntx_nblk = IBNAL_NTX_NBLK;
CFS_MODULE_PARM(ntx_nblk, "i", int, 0444,
		"# of 'reserved' message descriptors");

static int arp_retries = IBNAL_ARP_RETRIES;
CFS_MODULE_PARM(arp_retries, "i", int, 0644,
		"# of times to retry ARP");

static char *hca_basename = IBNAL_HCA_BASENAME;
CFS_MODULE_PARM(hca_basename, "s", charp, 0444,
                "HCA base name");

static char *ipif_basename = IBNAL_IPIF_BASENAME;
CFS_MODULE_PARM(ipif_basename, "s", charp, 0444,
                "IPoIB interface base name");

static int local_ack_timeout = IBNAL_LOCAL_ACK_TIMEOUT;
CFS_MODULE_PARM(local_ack_timeout, "i", int, 0644,
                "ACK timeout for low-level 'sends'");

static int retry_cnt = IBNAL_RETRY_CNT;
CFS_MODULE_PARM(retry_cnt, "i", int, 0644,
                "Retransmissions when no ACK received");

static int rnr_cnt = IBNAL_RNR_CNT;
CFS_MODULE_PARM(rnr_cnt, "i", int, 0644,
                "RNR retransmissions");

static int rnr_nak_timer = IBNAL_RNR_NAK_TIMER;
CFS_MODULE_PARM(rnr_nak_timer, "i", int, 0644,
                "RNR retransmission interval");

#if IBNAL_USE_FMR
static int fmr_remaps = IBNAL_FMR_REMAPS;
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
        .kib_ntx_nblk               = &ntx_nblk,
        .kib_arp_retries            = &arp_retries,
        .kib_hca_basename           = &hca_basename,
        .kib_ipif_basename          = &ipif_basename,
        .kib_local_ack_timeout      = &local_ack_timeout,
        .kib_retry_cnt              = &retry_cnt,
        .kib_rnr_cnt                = &rnr_cnt,
        .kib_rnr_nak_timer          = &rnr_nak_timer,
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
	{8, "ntx_nblk", &ntx_nblk, 
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{9, "arp_retries", &arp_retries, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{10, "hca_basename", hca_basename_space, 
	 sizeof(hca_basename_space), 0444, NULL, &proc_dostring},
	{11, "ipif_basename", ipif_basename_space, 
	 sizeof(ipif_basename_space), 0444, NULL, &proc_dostring},
	{12, "local_ack_timeout", &local_ack_timeout, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{13, "retry_cnt", &retry_cnt, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{14, "rnr_cnt", &rnr_cnt, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{15, "rnr_nak_timer", &rnr_nak_timer, 
	 sizeof(int), 0644, NULL, &proc_dointvec},
#if IBNAL_USE_FMR
	{16, "fmr_remaps", &fmr_remaps, 
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
		register_sysctl_table(kibnal_top_ctl_table, 0);
	
	if (kibnal_tunables.kib_sysctl == NULL)
		CWARN("Can't setup /proc tunables\n");

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
	
		
		

	
		
