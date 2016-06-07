/*
 * Copyright (C) 2009-2012 Cray, Inc.
 *
 * Copyright (c) 2014, Intel Corporation.
 *
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

/* for lnet_ipif_query */
#include <lnet/lib-lnet.h>

#ifndef _GNILND_HSS_OPS_H
# error "must include gnilnd_hss_ops.h first"
#endif

/* Set HW related values */
#ifdef CONFIG_CRAY_XT
#include <aries/aries_timeouts_gpl.h>
#else
/* from aries_timeouts_gpl.h when building for generic kernel */
#define TIMEOUT_SECS(x)         ((uint64_t)(((x) / 1000.0) + 0.5))
#ifndef TO_GNILND_timeout
#define TO_GNILND_timeout               (60000.000000)
#endif /* TO_GNILND_timeout */
#endif /* CONFIG_CRAY_XT */

#define GNILND_BASE_TIMEOUT        TIMEOUT_SECS(TO_GNILND_timeout)
#define GNILND_CHECKSUM_DEFAULT    0            /* all off for Aries */

#if defined(CONFIG_CRAY_COMPUTE)
#define GNILND_REVERSE_RDMA        GNILND_REVERSE_PUT
#define GNILND_RDMA_DLVR_OPTION    GNI_DLVMODE_PERFORMANCE
#else
#define GNILND_REVERSE_RDMA        GNILND_REVERSE_GET
#define GNILND_RDMA_DLVR_OPTION    GNI_DLVMODE_PERFORMANCE
#define GNILND_SCHED_THREADS       7             /* scheduler threads */
#endif

/* Thread-safe kgni implemented in minor ver 45, code rev 0xb9 */
#define GNILND_KGNI_TS_MINOR_VER 0x45
#define GNILND_TS_ENABLE         1

/* register some memory to allocate a shared mdd */
static inline gni_return_t
kgnilnd_register_smdd_buf(kgn_device_t *dev)
{
	__u32        flags = GNI_MEM_READWRITE;

	if (*kgnilnd_tunables.kgn_bte_relaxed_ordering) {
		flags |= GNI_MEM_RELAXED_PI_ORDERING;
	}

	LIBCFS_ALLOC(dev->gnd_smdd_hold_buf, PAGE_SIZE);
	if (!dev->gnd_smdd_hold_buf) {
		CERROR("Can't allocate smdd hold buffer\n");
		return GNI_RC_ERROR_RESOURCE;
	}

	return kgnilnd_mem_register(dev->gnd_handle,
				    (__u64)dev->gnd_smdd_hold_buf,
				    PAGE_SIZE, NULL, flags,
				    &dev->gnd_smdd_hold_hndl);
}

static inline gni_return_t
kgnilnd_deregister_smdd_buf(kgn_device_t *dev)
{
	gni_return_t rc = kgnilnd_mem_deregister(dev->gnd_handle,
						 &dev->gnd_smdd_hold_hndl, 0);
	LIBCFS_FREE(dev->gnd_smdd_hold_buf, PAGE_SIZE);

	return rc;
}

/* plug in our functions for use on the simulator */
#if !defined(GNILND_USE_RCA)

extern kgn_data_t kgnilnd_data;

#define kgnilnd_hw_hb()              do {} while(0)

#ifdef CONFIG_CRAY_XT

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
		CERROR("Request for invalid nid translation %u,"
		       "minimum %llu\n",
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

	rc = lnet_ipif_query(if_name, &up, &ipaddr, &netmask);
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

#else /* CONFIG_CRAY_XT */
#include <net/inet_common.h>
#include <linux/if_arp.h>

static inline int
kgnilnd_nid_to_nicaddrs(__u32 nid, int numnic, __u32 *nicaddrs)
{
	int rc;

#define NID_MASK ((1ULL << 18) - 1)
	mm_segment_t fs;
	struct arpreq req = {
		.arp_dev = "ipogif0",
	};

	req.arp_pa.sa_family = AF_INET;
	((struct sockaddr_in *)&req.arp_pa)->sin_addr.s_addr = htonl(nid);

	fs = get_fs();
	set_fs(get_ds());

	rc = inet_ioctl(kgnilnd_data.kgn_sock, SIOCGARP, (unsigned long)&req);
	set_fs(fs);

	if (rc < 0) {
		CDEBUG(D_NETERROR, "inet_ioctl returned %d\n", rc);
		return 0;
	}

	/* use the lower 18 bits of the mac address to use as a nid value */
	*nicaddrs = *(__u32 *)&req.arp_ha.sa_data[2];
	*nicaddrs = ntohl(*nicaddrs) & NID_MASK;

	CDEBUG(D_NETTRACE, "nid %s -> nic 0x%x\n", libcfs_nid2str(nid),
		nicaddrs[0]);

	return 1;
}

static inline int
kgnilnd_nicaddr_to_nid(__u32 nicaddr, __u32 *nid)
{
	int rc;
	mm_segment_t fs;
	struct ifreq ifr = {
		.ifr_name = "ipogif0",
	};

	struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;

	fs = get_fs();
	set_fs(get_ds());
	rc = inet_ioctl(kgnilnd_data.kgn_sock, SIOCGIFADDR, (unsigned long)&ifr);
	set_fs(fs);

	if (rc < 0) {
		CDEBUG(D_NETERROR, "inet_ioctl returned %d\n", rc);
		return 1;
	}

	CDEBUG(D_NETTRACE, "ipaddr %08x\n", htonl(ipaddr->sin_addr.s_addr));

	*nid = htonl(ipaddr->sin_addr.s_addr);
	CDEBUG(D_NETTRACE, "nic 0x%x -> nid %s\n", nicaddr,
		libcfs_nid2str(*nid));
	return 0;
}

static inline int
kgnilnd_setup_nic_translation(__u32 device_id)
{
	return 0;
}

#endif /* CONFIG_CRAY_XT */

#endif /* GNILND_USE_RCA */

#endif /* _GNILND_ARIES_H */
