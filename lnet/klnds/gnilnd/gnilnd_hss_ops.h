/*
 * Copyright (C) 2009-2012 Cray, Inc.
 *
 *   Author: Nic Henke <nic@cray.com>
 *   Author: James Shimek <jshimek@cray.com>
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

#include <linux/typecheck.h>

#if defined(GNILND_USE_RCA)
/* for krca nid & nic translation */
#include <krca_lib.h>

/* it isn't exported, so just point directly to it */
extern void send_hb_2_l0(void);

static inline void
kgnilnd_hw_hb(void)
{
	send_hb_2_l0();
}

/* we use RCA types here to get the compiler to whine when we have
 * mismatched types */
static inline int
kgnilnd_nid_to_nicaddrs(rca_nid_t nid, int numnic, nic_addr_t *nicaddrs)
{
	int     rc;

	/* compile time checks to ensure that the RCA types match
	 * the LNet idea of NID and NIC */
	typecheck(__u32, nid);
	typecheck(__u32, *nicaddrs);

	rc = krca_nid_to_nicaddrs(nid, numnic, nicaddrs);

	CDEBUG(D_NETTRACE, "RCA nid %d -> nic 0x%x, rc: %d\n",
	       nid, nicaddrs[0], rc);

	RETURN(rc);
}

static inline int
kgnilnd_nicaddr_to_nid(nic_addr_t nicaddr, rca_nid_t *nid)
{
	/* compile time checks to ensure that the RCA types match
	 * the LNet idea of NID and NIC */
	typecheck(__u32, nicaddr);
	typecheck(__u32, nid[0]);

	return krca_nicaddr_to_nid(nicaddr, nid);
}

static inline int
kgnilnd_setup_nic_translation(__u32 device_id)
{
	return 0;
}

#endif /* GNILND_USE_RCA */

#endif /* _GNILND_HSS_OPS_H */
