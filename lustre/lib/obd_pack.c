/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
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
 * (Un)packing of OST requests
 *
 */

#define DEBUG_SUBSYSTEM S_OST

#include <linux/obd_ost.h>
#include <linux/lustre_net.h>

void ost_pack_ioo(void **tmp, struct obdo *oa, int bufcnt)
{
        struct obd_ioobj *ioo = *tmp;
        char *c = *tmp;

        ioo->ioo_id = HTON__u64(oa->o_id); 
        ioo->ioo_gr = HTON__u64(oa->o_gr); 
        ioo->ioo_type = HTON__u64(oa->o_mode); 
        ioo->ioo_bufcnt = HTON__u32(bufcnt); 
        *tmp = c + sizeof(*ioo); 
}

void ost_unpack_ioo(void **tmp, struct obd_ioobj **ioop)
{
        char *c = *tmp;
        struct obd_ioobj *ioo = *tmp;
        *ioop = *tmp;

        ioo->ioo_id = NTOH__u64(ioo->ioo_id); 
        ioo->ioo_gr = NTOH__u64(ioo->ioo_gr); 
        ioo->ioo_type = NTOH__u64(ioo->ioo_type); 
        ioo->ioo_bufcnt = NTOH__u32(ioo->ioo_bufcnt); 
        *tmp = c + sizeof(*ioo); 
}

void ost_pack_niobuf(void **tmp, void *addr, __u64 offset, __u32 len, 
                     __u32 flags, __u32 xid)
{
        struct niobuf *ioo = *tmp;
        char *c = *tmp;

        ioo->addr = HTON__u64((__u64)(unsigned long)addr); 
        ioo->offset = HTON__u64(offset); 
        ioo->len = HTON__u32(len); 
        ioo->flags = HTON__u32(flags); 
        ioo->xid = HTON__u32(xid);
        *tmp = c + sizeof(*ioo); 
}

void ost_unpack_niobuf(void **tmp, struct niobuf **nbp)
{
        char *c = *tmp;
        struct niobuf *nb = *tmp;

        *nbp = *tmp;

        nb->addr = NTOH__u64(nb->addr); 
        nb->offset = NTOH__u64(nb->offset); 
        nb->len = NTOH__u32(nb->len); 
        nb->flags = NTOH__u32(nb->flags); 

        *tmp = c + sizeof(*nb); 
}
