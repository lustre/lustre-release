/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
 *
 *   This file is part of InterMezzo, http://www.inter-mezzo.org.
 *
 *   InterMezzo is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   InterMezzo is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with InterMezzo; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Unpacking of KML records
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
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/list.h>
#include <asm/io.h>
#include <asm/segment.h>
#include <asm/system.h>
#include <asm/poll.h>
#include <asm/uaccess.h>

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>


int mds_pack_req(char *name, int namelen, char *tgt, int tgtlen, 
		 struct mds_req_hdr **hdr, struct mds_req **req, 
		 int *len, char **buf)
{
	char *ptr;

	*len = sizeof(**hdr) + size_round(namelen) + sizeround(tgtlen) + 
		sizeof(**req); 

	*buf = kmalloc(*len, GFP_KERNEL);
	if (!*buf) {
		EXIT;
		return -ENOMEM;
	}

	memset(*buf, 0, *len); 
	*hdr = (struct mds_req_hdr *)(*buf);
	*req = (struct mds_req *)(*buf + sizeof(**hdr));
	ptr = *buf + sizeof(**hdr) + sizeof(**req);

	(*hdr)->type =  MDS_TYPE_REQ;

	(*req)->namelen = NTOH_u32(namelen);
	if (name) { 
		LOGL(name, namelen, ptr); 
	} 

	(*req)->tgtlen = NTOH_u32(tgtlen);
	if (tgt) { 
		LOGL(tgt, tgtlen, ptr);
	}
	return 0;
}


int mds_unpack_req(char *buf, int len, 
		   struct mds_req_hdr **hdr, struct mds_req **req)
{
	if (len < sizeof(**hdr) + sizeof(**req)) { 
		EXIT;
		return -EINVAL;
	}

	*hdr = (struct mds_req_hdr *) (buf);
	*req = (struct mds_req *) (buf + sizeof(**hdr));
	(*req)->namelen = NTOH_u32((*req)->namelen); 
	(*req)->tgtlen = NTOH_u32((*req)->namelen); 

	if (len < sizeof(**hdr) + sizeof(**req) + (*req)->namelen + 
	    (*req)->tgtlen ) { 
		EXIT;
		return -EINVAL;
	}

	if ((*req)->namelen) { 
		(*req)->name = buf + sizeof(**hdr) + sizeof(**req);
	} else { 
		(*req)->name = NULL;
	}

	if ((*req)->tgtlen) { 
		(*req)->tgt = buf + sizeof(**hdr) + sizeof(**req) + 
			sizerount((*req)->namelen);
	} else { 
		(*req)->tgt = NULL;
	}

	EXIT;
	return 0;
}

int mds_pack_rep(char *name, int namelen, char *tgt, int tgtlen, 
		 struct mds_rep_hdr **hdr, struct mds_rep **rep, 
		 int *len, char **buf)
{
	char *ptr;

	*len = sizeof(**hdr) + size_round(namelen) + sizeround(tgtlen) + 
		sizeof(**rep); 

	*buf = kmalloc(*len, GFP_KERNEL);
	if (!*buf) {
		EXIT;
		return -ENOMEM;
	}

	memset(*buf, 0, *len); 
	*hdr = (struct mds_rep_hdr *)(*buf);
	*rep = (struct mds_rep *)(*buf + sizeof(**hdr));
	ptr = *buf + sizeof(**hdr) + sizeof(**rep);

	(*rep)->namelen = NTOH_u32(namelen);
	if (name) { 
		LOGL(name, namelen, ptr); 
	} 

	(*rep)->tgtlen = NTOH_u32(tgtlen);
	if (tgt) { 
		LOGL(tgt, tgtlen, ptr);
	}
	return 0;
}


int mds_unpack_rep(char *buf, int len, 
		   struct mds_rep_hdr **hdr, struct mds_rep **rep)
{
	if (len < sizeof(**hdr) + sizeof(**rep)) { 
		EXIT;
		return -EINVAL;
	}

	*hdr = (struct mds_rep_hdr *) (buf);
	*rep = (struct mds_rep *) (buf + sizeof(**hdr));
	(*rep)->namelen = NTOH_u32((*rep)->namelen); 
	(*rep)->tgtlen = NTOH_u32((*rep)->namelen); 

	if (len < sizeof(**hdr) + sizeof(**rep) + (*rep)->namelen + 
	    (*rep)->tgtlen ) { 
		EXIT;
		return -EINVAL;
	}

	if ((*rep)->namelen) { 
		(*rep)->name = buf + sizeof(**hdr) + sizeof(**rep);
	} else { 
		(*rep)->name = NULL;
	}

	if ((*rep)->tgtlen) { 
		(*rep)->tgt = buf + sizeof(**hdr) + sizeof(**rep) + 
			sizerount((*rep)->namelen);
	} else { 
		(*rep)->tgt = NULL;
	}

	EXIT;
	return 0;
}
