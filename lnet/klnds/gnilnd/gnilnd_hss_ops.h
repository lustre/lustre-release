/*
 * Copyright (C) 2010-2012 Cray, Inc.
 *   Author: Nic Henke <nic@cray.com>
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
#ifndef _GNILND_HSS_OPS_H
#define _GNILND_HSS_OPS_H

/* for krca nid & nic translation */
#include <krca_lib.h>
#include <linux/typecheck.h>

/* the SimNow nodes can't load rca.ko, so we need to detect this
 * and fake a table that'd work for lookups there */

typedef struct kgn_nid_entry {
	__u32   nid;
	__u32   nicaddr;
} kgn_nid_entry_t;

typedef struct kgn_hssops
{
	/* function pointers for nid and nic conversion */
	/* from krca_lib.h */
	int     (*nid_to_nicaddr)(__u32 nid, int numnic, __u32 *nicaddr);
	int     (*nicaddr_to_nid)(__u32 nicaddr, __u32 *nid);
	void    (*hb_to_l0)(void);
} kgn_hssops_t;

/* pull in static store in gnilnd.c */
extern kgn_hssops_t             kgnilnd_hssops;

#define GNILND_NO_RCA           0xdeadbeef
#define GNILND_NO_QUIESCE       0xdeadbeef

static inline int
kgnilnd_lookup_rca_funcs(void)
{
        void    *funcp;

	funcp = __symbol_get("send_hb_2_l0");
	if (funcp == 0) {
		CERROR("couldn't find send_hb_2_l0\n");
		/* not fatal for now */
	} else {
		kgnilnd_hssops.hb_to_l0 = funcp;
	}

	/* if we find one, we should get the other */

	funcp = __symbol_get("krca_nid_to_nicaddrs");
	if (funcp == 0) {
		kgnilnd_hssops.nid_to_nicaddr = (void *)GNILND_NO_RCA;
		kgnilnd_hssops.nicaddr_to_nid = (void *)GNILND_NO_RCA;
		LCONSOLE_INFO("using SimNow nid table for RCA translation\n");
		return 0;
	}
	kgnilnd_hssops.nid_to_nicaddr = funcp;

	funcp = __symbol_get("krca_nicaddr_to_nid");
	if (funcp == 0) {
		CERROR("found krca_nid_to_nicaddrs but not "
		       "krca_nicaddr_to_nid\n");
		return -ESRCH;
	}
	kgnilnd_hssops.nicaddr_to_nid = funcp;
	return 0;
}

#if defined(CONFIG_CRAY_GEMINI)
/* Gemini SimNow has a hard coded table to use - no RCA there */
#define GNILND_MAX_NID_TABLE    0xffffffff
/* this is all of the nodes defined in the Baker SimNow "sim_platforms" page */
static kgn_nid_entry_t kgn_nid_table[] = {
	{0x1, 0x100}, {0x2, 0x101}, {0x3, 0x104}, {0x4, 0x105},
	{0x5, 0x108}, {0x6, 0x109}, {0x7, 0x10c}, {0x8, 0x10d},
	{0x9, 0x110}, {0xa, 0x111}, {0xb, 0x114}, {0xc, 0x115},
	{0xd, 0x118}, {0xe, 0x119}, {0xf, 0x11c}, {0x10, 0x11d},
	{0x11, 0x120}, {0x12, 0x121}, {0x13, 0x124}, {0x14, 0x125},
	{0x15, 0x128}, {0x16, 0x129}, {0x17, 0x12c}, {0x18, 0x12d},
	{0x19, 0x130}, {0x1a, 0x131}, {0x1b, 0x134}, {0x1c, 0x135},
	{0x1d, 0x138}, {0x1e, 0x139}, {0x1f, 0x13c}, {0x20, 0x13d},
	{0x21, 0x140}, {0x22, 0x141}, {0x23, 0x144}, {0x24, 0x145},
	{0x25, 0x148}, {0x26, 0x149}, {0x27, 0x14c}, {0x28, 0x14d},
	{0x29, 0x150}, {0x2a, 0x151}, {0x2b, 0x154}, {0x2c, 0x155},
	{0x2d, 0x158}, {0x2e, 0x159}, {0x2f, 0x15c}, {0x30, 0x15d},
	{0x31, 0x160}, {0x32, 0x161}, {0x33, 0x164}, {0x3d, 0x178},
	{0x34, 0x165}, {0x3e, 0x179}, {0x35, 0x168}, {0x3f, 0x17c},
	{0x36, 0x169}, {0x40, 0x17d}, {0x37, 0x16c}, {0x41, 0x180},
	{0x38, 0x16d}, {0x42, 0x181}, {0x39, 0x170}, {0x3a, 0x171},
	{0x3b, 0x174}, {0x3c, 0x175}, {0x43, 0x184}, {0x44, 0x185},
	{0x45, 0x188}, {0x46, 0x189}, {0x47, 0x18c}, {0x48, 0x18d},
	/* entries after this are for 'dead' peer tests */
	{0x63, 0x1ff}, {0x111, 0x209},
	{GNILND_MAX_NID_TABLE, GNILND_MAX_NID_TABLE}
};
static int
gemini_nid_to_nicaddr(__u32 nid, int numnic, __u32 *nicaddr)
{
	int i;

	/* GNILND_NO_RCA, so use hardcoded table for Gemini SimNow */
	if (numnic > 1) {
		CERROR("manual nid2nic translation doesn't support"
		       "multiple nic addrs (you asked for %d)\n",
			numnic);
		return -EINVAL;
	}

	for (i = 0;;i++) {
		if (kgn_nid_table[i].nid == GNILND_MAX_NID_TABLE) {
			CERROR("could not translate %u to a NIC "
			       "address\n", nid);
			return -ESRCH;
		}
		if (kgn_nid_table[i].nid == nid) {
			*nicaddr = kgn_nid_table[i].nicaddr;
			return 1;
		}
	}
}

static int
gemini_nicaddr_to_nid(__u32 nicaddr, __u32 *nid)
{
	int i;

	/* GNILND_RCA_NOT_HOME, so use hardcoded table for SimNow */
	for (i = 0;;i++) {
		if (kgn_nid_table[i].nicaddr == GNILND_MAX_NID_TABLE) {
			CERROR("could not translate NIC address "
				"%u\n",
				nicaddr);
			return -ESRCH;
		}
		if (kgn_nid_table[i].nicaddr == nicaddr) {
			*nid = kgn_nid_table[i].nid;
			return 1;
		}
	}
}

static inline int
kgnilnd_setup_nic_translation(__u32 device_id)
{
        int rc;

	/* do lookup on first use */
	if (unlikely(kgnilnd_hssops.nid_to_nicaddr == NULL)) {
		rc = kgnilnd_lookup_rca_funcs();
		if (rc)
			return rc;
	}

	/* if we have a real function, return - we'll use those going forward */
	if (likely(kgnilnd_hssops.nid_to_nicaddr != (void *)GNILND_NO_RCA))
		return 0;

	kgnilnd_hssops.nid_to_nicaddr = gemini_nid_to_nicaddr;
	kgnilnd_hssops.nicaddr_to_nid = gemini_nicaddr_to_nid;
	return 0;
}

#elif defined(CONFIG_CRAY_ARIES)
/* for libcfs_ipif_query */
#include <libcfs/libcfs.h>

/* Aries Sim doesn't have hardcoded tables, so we'll hijack the nic_pe
 * and decode our address and nic addr from that - the rest are just offsets */
static __u32 aries_sim_base_nid;
static __u32 aries_sim_nic;

static int
aries_nid_to_nicaddr(__u32 nid, int numnic, __u32 *nicaddr)
{
	if (numnic > 1) {
		CERROR("manual nid2nic translation doesn't support"
		       "multiple nic addrs (you asked for %d)\n",
			numnic);
		return -EINVAL;
	}
	if (nid < aries_sim_base_nid) {
		CERROR("Request for invalid nid translation %u, minimum %u\n",
		       nid, aries_sim_base_nid);
		return -ESRCH;
	}

	*nicaddr = nid - aries_sim_base_nid;
	return 1;
}

static int
aries_nicaddr_to_nid(__u32 nicaddr, __u32 *nid)
{
	*nid = aries_sim_base_nid + nicaddr;
	return 1;
}

/* XXX Nic: This does not support multiple device!!!! */
static inline int
kgnilnd_setup_nic_translation(__u32 device_id)
{
	char              *if_name = "ipogif0";
	__u32              ipaddr, netmask, my_nid;
	int                up, rc;

	/* do lookup on first use */
	if (unlikely(kgnilnd_hssops.nid_to_nicaddr == NULL)) {
		rc = kgnilnd_lookup_rca_funcs();
		if (rc)
			return rc;
	}

	/* if we have a real function, return - we'll use those going forward */
	if (likely(kgnilnd_hssops.nid_to_nicaddr != (void *)GNILND_NO_RCA))
		return 0;

	rc = libcfs_ipif_query(if_name, &up, &ipaddr, &netmask);
	if (rc != 0) {
		CERROR("can't get IP interface for %s: %d\n", if_name, rc);
		return rc;
	}
	if (!up) {
		CERROR("IP interface %s is down\n", if_name);
		return -ENODEV;
	}

	my_nid = ((ipaddr >> 8) & 0xFF) + (ipaddr & 0xFF);
	aries_sim_nic = device_id;
	aries_sim_base_nid = my_nid - aries_sim_nic;

	kgnilnd_hssops.nid_to_nicaddr = aries_nid_to_nicaddr;
	kgnilnd_hssops.nicaddr_to_nid = aries_nicaddr_to_nid;

	return 0;
}
#else
#error "Undefined Network Type"
#endif

/* we use RCA types here to get the compiler to whine when we have
 * mismatched types */
static inline int
kgnilnd_nid_to_nicaddrs(rca_nid_t nid, int numnic, nic_addr_t *nicaddrs)
{
	/* compile time checks to ensure that the RCA types match
	 * the LNet idea of NID and NIC */
	typecheck(__u32, nid);
	typecheck(__u32, *nicaddrs);

	LASSERTF(kgnilnd_hssops.nid_to_nicaddr != NULL, "missing setup?\n");

	return kgnilnd_hssops.nid_to_nicaddr(nid, numnic, nicaddrs);
}

static inline int
kgnilnd_nicaddr_to_nid(nic_addr_t nicaddr, rca_nid_t *nid)
{
	/* compile time checks to ensure that the RCA types match
	 * the LNet idea of NID and NIC */
	typecheck(__u32, nicaddr);
	typecheck(__u32, nid[0]);

	LASSERTF(kgnilnd_hssops.nicaddr_to_nid != NULL, "missing setup ?\n");

	return kgnilnd_hssops.nicaddr_to_nid(nicaddr, nid);
}

#endif /* _GNILND_HSS_OPS_H */
