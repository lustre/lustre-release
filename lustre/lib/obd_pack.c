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

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/sched.h>
#include <linux/lp.h>
#include <linux/slab.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/list.h>
#include <asm/io.h>
#include <asm/segment.h>
#include <asm/system.h>
#include <asm/poll.h>
#include <asm/uaccess.h>

#define DEBUG_SUBSYSTEM S_OST

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obd_ost.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>

int ost_pack_req(char *buf1, int buflen1, char *buf2, int buflen2, 
		 struct ptlreq_hdr **hdr, union ptl_req *r,
		 int *len, char **buf)
{
        struct ost_req *req;
	char *ptr;

	*len = sizeof(**hdr) + size_round(buflen1) + size_round(buflen2) + 
		sizeof(*req); 

	OBD_ALLOC(*buf, *len);
	if (!*buf) {
		EXIT;
		return -ENOMEM;
	}

	memset(*buf, 0, *len); 
	*hdr = (struct ptlreq_hdr *)(*buf);
	req = (struct ost_req *)(*buf + sizeof(**hdr));
        r->ost = req;

	ptr = *buf + sizeof(**hdr) + sizeof(*req);

	(*hdr)->type =  OST_TYPE_REQ;

	req->buflen1 = NTOH__u32(buflen1);
	if (buf1) { 
		LOGL(buf1, buflen1, ptr); 
	} 

	req->buflen2 = NTOH__u32(buflen2);
	if (buf2) { 
		LOGL(buf2, buflen2, ptr);
	}
	return 0;
}

int ost_unpack_req(char *buf, int len, 
		   struct ptlreq_hdr **hdr,  union ptl_req *r)
{
        struct ost_req *req;

	if (len < sizeof(**hdr) + sizeof(*req)) { 
		EXIT;
		return -EINVAL;
	}

	*hdr = (struct ptlreq_hdr *) (buf);
	req = (struct ost_req *) (buf + sizeof(**hdr));
        r->ost = req;

	req->buflen1 = NTOH__u32(req->buflen1); 
	req->buflen2 = NTOH__u32(req->buflen2); 

	if (len < sizeof(**hdr) + sizeof(*req) + 
            size_round(req->buflen1) + size_round(req->buflen2) ) { 
		EXIT;
		return -EINVAL;
	}

	EXIT;
	return 0;
}


void *ost_req_buf1(struct ost_req *req)
{
        if (!req->buflen1) 
                return NULL;
        return (void *)((char *)req + sizeof(*req));
}

void *ost_req_buf2(struct ost_req *req)
{
        if (!req->buflen2) 
                return NULL;
        return (void *)((char *)req + sizeof(*req) + 
                        size_round(req->buflen1)); 
}

int ost_pack_rep(char *buf1, int buflen1, char *buf2, int buflen2,
		 struct ptlrep_hdr **hdr, union ptl_rep *r,
		 int *len, char **buf)
{
	char *ptr;
        struct ost_rep *rep;

	*len = sizeof(**hdr) + size_round(buflen1) + size_round(buflen2) + 
		sizeof(*rep); 

	OBD_ALLOC(*buf, *len);
	if (!*buf) {
		EXIT;
		return -ENOMEM;
	}

	memset(*buf, 0, *len); 
	*hdr = (struct ptlrep_hdr *)(*buf);
	rep = (struct ost_rep *)(*buf + sizeof(**hdr));
        r->ost = rep;

	ptr = *buf + sizeof(**hdr) + sizeof(*rep);

	rep->buflen1 = NTOH__u32(buflen1);
	if (buf1) { 
		LOGL(buf1, buflen1, ptr); 
	} 

	rep->buflen2 = NTOH__u32(buflen2);
	if (buf2) { 
		LOGL(buf2, buflen2, ptr);
	}
	return 0;
}


int ost_unpack_rep(char *buf, int len, 
		   struct ptlrep_hdr **hdr, union ptl_rep *r)
{
        struct ost_rep *rep;

	if (len < sizeof(**hdr) + sizeof(*rep)) { 
		EXIT;
		return -EINVAL;
	}

	*hdr = (struct ptlrep_hdr *) (buf);
	rep = (struct ost_rep *) (buf + sizeof(**hdr));
        r->ost = rep;

	rep->buflen1 = NTOH__u32(rep->buflen1); 
	rep->buflen2 = NTOH__u32(rep->buflen2); 

	if (len < sizeof(**hdr) + sizeof(*rep) + 
            size_round(rep->buflen1) + size_round(rep->buflen2) ) { 
		EXIT;
		return -EINVAL;
	}

	EXIT;
	return 0;
}

void *ost_rep_buf1(struct ost_rep *rep)
{
        if (!rep->buflen1) 
                return NULL;
        return (void *)((char *)rep + sizeof(*rep));
}

void *ost_rep_buf2(struct ost_rep *rep)
{
        if (!rep->buflen2) 
                return NULL;
        return (void *)((char *)rep + sizeof(*rep) + 
                        size_round(rep->buflen1)); 
}

void ost_pack_ioo(void **tmp, struct obdo *oa, int bufcnt)
{
        struct obd_ioobj *ioo = *tmp;
        char *c = *tmp;
        
        ioo->ioo_id = NTOH__u64(oa->o_id); 
        ioo->ioo_gr = NTOH__u64(oa->o_gr); 
        ioo->ioo_type = NTOH__u64(oa->o_mode); 
        ioo->ioo_bufcnt = NTOH__u32(bufcnt); 
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

        ioo->addr = NTOH__u64((__u64)(unsigned long)addr); 
        ioo->offset = NTOH__u64(offset); 
        ioo->len = NTOH__u32(len); 
        ioo->flags = NTOH__u32(flags); 
        ioo->xid = NTOH__u32(xid);
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
