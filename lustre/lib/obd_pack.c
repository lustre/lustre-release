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
#include <linux/obd_class.h>
#include <linux/obd_ost.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>


int ost_pack_req(char *buf1, int buflen1, char *buf2, int buflen2, 
		 struct ost_req_hdr **hdr, struct ost_req **req, 
		 int *len, char **buf)
{
	char *ptr;
        struct ost_req_packed *preq;

	*len = sizeof(**hdr) + size_round(buflen1) + size_round(buflen2) + 
		sizeof(*preq); 

	*buf = kmalloc(*len, GFP_KERNEL);
	if (!*buf) {
		EXIT;
		return -ENOMEM;
	}

	memset(*buf, 0, *len); 
	*hdr = (struct ost_req_hdr *)(*buf);

	preq = (struct ost_req_packed *)(*buf + sizeof(**hdr));
	ptr = *buf + sizeof(**hdr) + sizeof(*preq);

	*req = (struct ost_req *)(*buf + sizeof(**hdr));

	(*hdr)->type =  OST_TYPE_REQ;

	(*req)->buflen1 = NTOH__u32(buflen1);
	if (buf1) { 
                preq->bufoffset1 = (__u32)(ptr - (char *)preq);
		LOGL(buf1, buflen1, ptr); 
	} 

	(*req)->buflen2 = NTOH__u32(buflen2);
	if (buf2) { 
                preq->bufoffset2 = (__u32)(ptr - (char *)preq);
		LOGL(buf2, buflen2, ptr);
	}
	return 0;
}

int ost_unpack_req(char *buf, int len, 
		   struct ost_req_hdr **hdr, struct ost_req **req)
{
        struct ost_req_packed *reqp;
        __u32 off1, off2;

	if (len < sizeof(**hdr) + sizeof(*reqp)) { 
		EXIT;
		return -EINVAL;
	}

	*hdr = (struct ost_req_hdr *) (buf);
	reqp = (struct ost_req_packed *) (buf + sizeof(**hdr));
	*req = (struct ost_req *) (buf + sizeof(**hdr));

	(*req)->buflen1 = NTOH__u32(reqp->buflen1); 
	(*req)->buflen2 = NTOH__u32(reqp->buflen2); 
        off1 = NTOH__u32(reqp->bufoffset1); 
        off2 = NTOH__u32(reqp->bufoffset2); 

	if (len < sizeof(**hdr) + sizeof(*reqp) + size_round(reqp->buflen1) + 
	    size_round(reqp->buflen2) ) { 
		EXIT;
		return -EINVAL;
	}

	if ((*req)->buflen1) { 
                (*req)->buf1 = (buf + sizeof(**hdr) + off1);
	} else { 
		(*req)->buf1 = 0;
	}
	if ((*req)->buflen2) { 
		(*req)->buf2 = (buf + sizeof(**hdr) + off2);
	} else { 
		(*req)->buf2 = 0;
	}

	EXIT;
	return 0;
}

int ost_pack_rep(void *buf1, __u32 buflen1, void *buf2, __u32 buflen2,
		 struct ost_rep_hdr **hdr, struct ost_rep **rep, 
		 int *len, char **buf)
{
	char *ptr;

	*len = sizeof(**hdr) + size_round(buflen1) + size_round(buflen2) + 
		sizeof(**rep); 

	*buf = kmalloc(*len, GFP_KERNEL);
	if (!*buf) {
		EXIT;
		return -ENOMEM;
	}

	memset(*buf, 0, *len); 
	*hdr = (struct ost_rep_hdr *)(*buf);
	*rep = (struct ost_rep *)(*buf + sizeof(**hdr));
	ptr = *buf + sizeof(**hdr) + sizeof(**rep);

	(*rep)->buflen1 = NTOH__u32(buflen1);
	if (buf1) { 
		LOGL(buf1, buflen1, ptr); 
	} 

	(*rep)->buflen2 = NTOH__u32(buflen2);
	if (buf2) { 
		LOGL(buf2, buflen2, ptr);
	}
	return 0;
}


int ost_unpack_rep(char *buf, int len, 
		   struct ost_rep_hdr **hdr, struct ost_rep **rep)
{
        struct ost_rep_packed *prep;
        __u32 off1, off2;

	if (len < sizeof(**hdr) + sizeof(**rep)) { 
		EXIT;
		return -EINVAL;
	}

	*hdr = (struct ost_rep_hdr *) (buf);
	*rep = (struct ost_rep *) (buf + sizeof(**hdr));
	prep = (struct ost_rep_packed *) (buf + sizeof(**hdr));
	(*rep)->buflen1 = NTOH__u32(prep->buflen1); 
	(*rep)->buflen2 = NTOH__u32(prep->buflen2); 
        off1 = prep->bufoffset1;
        off2 = prep->bufoffset2;

	if (len < sizeof(**hdr) + sizeof(*prep) + size_round((*rep)->buflen1) + 
	    size_round((*rep)->buflen2) ) { 
		EXIT;
		return -EINVAL;
	}

	if ((*rep)->buflen1) { 
                (*rep)->buf1 = (buf + sizeof(**hdr) + off1);
	} else { 
		(*rep)->buf1 = 0;
	}
	if ((*rep)->buflen2) { 
		(*rep)->buf2 = (buf + sizeof(**hdr) + off2);
	} else { 
		(*rep)->buf2 = 0;
	}

	EXIT;
	return 0;
}

