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
 * (Un)packing of MDS and OST request records
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

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>

int mds_pack_req(char *name, int namelen, char *tgt, int tgtlen, 
		 struct ptlreq_hdr **hdr, union ptl_req *r,
		 int *len, char **buf)
{
        struct mds_req *req;
	char *ptr;

	*len = sizeof(**hdr) + size_round(namelen) + size_round(tgtlen) + 
		sizeof(*req); 

	OBD_ALLOC(*buf, *len);
	if (!*buf) {
		EXIT;
		return -ENOMEM;
	}

	memset(*buf, 0, *len); 
	*hdr = (struct ptlreq_hdr *)(*buf);
	req = (struct mds_req *)(*buf + sizeof(**hdr));
        r->mds = req;

	ptr = *buf + sizeof(**hdr) + sizeof(*req);

	(*hdr)->type =  MDS_TYPE_REQ;

	req->namelen = NTOH__u32(namelen);
	if (name) { 
		LOGL(name, namelen, ptr); 
	} 

	req->tgtlen = NTOH__u32(tgtlen);
	if (tgt) {
		LOGL(tgt, tgtlen, ptr);
	}
	return 0;
}


int mds_unpack_req(char *buf, int len, 
		   struct ptlreq_hdr **hdr, union ptl_req *r)
{
        struct mds_req *req;
        char *name, *tgt;

	if (len < sizeof(**hdr) + sizeof(*req)) { 
		EXIT;
		return -EINVAL;
	}

	*hdr = (struct ptlreq_hdr *) (buf);
        req = (struct mds_req *) (buf + sizeof(**hdr));
        r->mds = req;

	req->namelen = NTOH__u32(req->namelen); 
	req->tgtlen = NTOH__u32(req->tgtlen); 

	if (len < sizeof(**hdr) + sizeof(*req) +
            size_round(req->namelen) + size_round(req->tgtlen) ) { 
		EXIT;
		return -EINVAL;
	}

	if (req->namelen) { 
		name = buf + sizeof(**hdr) + sizeof(*req);
	} else { 
		name = NULL;
	}

	if (req->tgtlen) { 
		tgt = buf + sizeof(**hdr) + sizeof(*req) + 
                        size_round(req->namelen);
	} else { 
		tgt = NULL;
	}

	EXIT;
	return 0;
}

void *mds_req_tgt(struct mds_req *req)
{
        if (!req->tgtlen) 
                return NULL;
        return (void *)((char *)req + sizeof(*req) + 
                        size_round(req->namelen)); 
}

void *mds_req_name(struct mds_req *req)
{
        if (!req->namelen) 
                return NULL;
        return (void *)((char *)req + sizeof(*req));
}

int mds_pack_rep(char *name, int namelen, char *tgt, int tgtlen, 
		 struct ptlrep_hdr **hdr, union ptl_rep *r,
		 int *len, char **buf)
{
        struct mds_rep *rep;
	char *ptr;

	*len = sizeof(**hdr) + size_round(namelen) + size_round(tgtlen) + 
		sizeof(*rep); 

	OBD_ALLOC(*buf, *len);
	if (!*buf) {
		EXIT;
		return -ENOMEM;
	}

	memset(*buf, 0, *len); 
	*hdr = (struct ptlrep_hdr *)(*buf);
        rep = (struct mds_rep *)(*buf + sizeof(**hdr));
        r->mds = rep;

	ptr = *buf + sizeof(**hdr) + sizeof(*rep);

	(*hdr)->type =  MDS_TYPE_REP;

	rep->namelen = NTOH__u32(namelen);
	if (name) { 
		LOGL(name, namelen, ptr); 
	} 

        rep->tgtlen = NTOH__u32(tgtlen);
	if (tgt) { 
		LOGL(tgt, tgtlen, ptr);
	}
	return 0;
}

int mds_unpack_rep(char *buf, int len, 
		   struct ptlrep_hdr **hdr, union ptl_rep *r)
{
        struct mds_rep *rep;
	if (len < sizeof(**hdr)) { 
		EXIT;
		return -EINVAL;
	}
	*hdr = (struct ptlrep_hdr *) (buf);

	if (len < sizeof(**hdr) + sizeof(*rep)) { 
		EXIT;
		return -EINVAL;
	}

        rep = (struct mds_rep *) (buf + sizeof(**hdr));
        r->mds = rep;
	rep->namelen = NTOH__u32(rep->namelen); 
	rep->tgtlen = NTOH__u32(rep->namelen); 

	if (len < sizeof(**hdr) + sizeof(*rep) 
            + size_round(rep->namelen) + size_round(rep->tgtlen) ) { 
		EXIT;
		return -EINVAL;
	}

	EXIT;
	return 0;
}

void *mds_rep_name(struct mds_rep *rep)
{
        if (!rep->namelen) 
                return NULL;
        return (void *)((char *)rep + sizeof(*rep));
}

void *mds_rep_tgt(struct mds_rep *rep)
{
        if (!rep->tgtlen) 
                return NULL;
        return (void *)((char *)rep + sizeof(*rep) + size_round(rep->namelen)); 
}

