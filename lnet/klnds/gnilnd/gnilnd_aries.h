/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2009-2012 Cray, Inc.
 *   Author: Nic Henke <nic@cray.com>, James Shimek <jshimek@cray.com>
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
#ifndef _GNILND_ARIES_H
#define _GNILND_ARIES_H

/* for libcfs_ipif_query */
#include <libcfs/libcfs.h>

#ifndef _GNILND_HSS_OPS_H
# error "must include gnilnd_hss_ops.h first"
#endif

/* Set HW related values */
#include <aries/aries_timeouts_gpl.h>

#define GNILND_BASE_TIMEOUT        TIMEOUT_SECS(TO_GNILND_timeout)
#define GNILND_CHECKSUM_DEFAULT    0            /* all off for Aries */

#if defined(CONFIG_CRAY_COMPUTE)
#define GNILND_REVERSE_RDMA        GNILND_REVERSE_PUT
#define GNILND_RDMA_DLVR_OPTION    GNI_DLVMODE_PERFORMANCE
#else
#define GNILND_REVERSE_RDMA        GNILND_REVERSE_GET
#define GNILND_RDMA_DLVR_OPTION    GNI_DLVMODE_PERFORMANCE
#endif

/* plug in our functions for use on the simulator */
#if !defined(GNILND_USE_RCA)

extern kgn_data_t kgnilnd_data;

#define kgnilnd_hw_hb()              do {} while(0)

/* Aries Sim doesn't have hardcoded tables, so we'll hijack the nic_pe
 * and decode our address and nic addr from that - the rest are just offsets */

static inline int
kgnilnd_nid_to_nicaddrs(__u32 nid, int numnic, __u32 *nicaddr)
{
	if (numnic > 1) {
		CERROR("manual nid2nic translation doesn't support"
		       "multiple nic addrs (you asked for %d)\n",
			numnic);
		return -EINVAL;
	}
	if (nid < kgnilnd_data.kgn_nid_trans_private) {
		CERROR("Request for invalid nid translation %u, minimum %Lu\n",
		       nid, kgnilnd_data.kgn_nid_trans_private);
		return -ESRCH;
	}

	*nicaddr = nid - kgnilnd_data.kgn_nid_trans_private;

	CDEBUG(D_NETTRACE, "Sim nid %d -> nic 0x%x\n", nid, *nicaddr);

	return 1;
}

static inline int
kgnilnd_nicaddr_to_nid(__u32 nicaddr, __u32 *nid)
{
	*nid = kgnilnd_data.kgn_nid_trans_private + nicaddr;
	return 1;
}

/* XXX Nic: This does not support multiple device!!!! */
static inline int
kgnilnd_setup_nic_translation(__u32 device_id)
{
	char              *if_name = "ipogif0";
	__u32              ipaddr, netmask, my_nid;
	int                up, rc;

	LCONSOLE_INFO("using Aries SIM IP info for RCA translation\n");

	rc = libcfs_ipif_query(if_name, &up, &ipaddr, &netmask);
	if (rc != 0) {
		CERROR ("can't get IP interface for %s: %d\n", if_name, rc);
		return rc;
	}
	if (!up) {
		CERROR ("IP interface %s is down\n", if_name);
		return -ENODEV;
	}

	my_nid = ((ipaddr >> 8) & 0xFF) + (ipaddr & 0xFF);

	kgnilnd_data.kgn_nid_trans_private = my_nid - device_id;

	return 0;
}

#endif /* GNILND_USE_RCA */

#endif /* _GNILND_ARIES_H */
