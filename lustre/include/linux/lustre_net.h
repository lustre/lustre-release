/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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

#ifndef _LUSTRE_NET_H
#define _LUSTRE_NET_H

#include <linux/kp30.h>
#include <portals/p30.h>
#include <linux/lustre_idl.h>

#define OSC_REQUEST_PORTAL 1
#define OSC_REPLY_PORTAL   2
#define MDS_REQUEST_PORTAL 3
#define MDS_REPLY_PORTAL   4
#define OST_REQUEST_PORTAL 5
#define OST_REPLY_PORTAL   6

struct ptlrpc_service {
        char *srv_buf;
        __u32 srv_buf_size;
        __u32 srv_ring_length;
        __u32 srv_portal;

        struct lustre_peer srv_self;

        /* FIXME: perhaps a list of EQs, if multiple NIs are used? */
        ptl_handle_eq_t srv_eq;

        ptl_handle_me_t srv_me;
        ptl_process_id_t srv_id;
        ptl_md_t srv_md;
        ptl_handle_md_t srv_md_h;
        wait_queue_head_t *srv_wait_queue;
};


struct ptlrpc_request { 
	struct list_head rq_list;
	struct mds_obd *rq_obd;
	struct ost_obd *rq_ost;
	int rq_status;

	char *rq_reqbuf;
	int rq_reqlen;
	struct ptlreq_hdr *rq_reqhdr;
	union ptl_req rq_req;
        __u32 rq_xid;

 	char *rq_repbuf;
	int rq_replen;
	struct ptlrep_hdr *rq_rephdr;
	union ptl_rep rq_rep;

        void * rq_reply_handle;
	wait_queue_head_t rq_wait_for_rep;

        ptl_md_t rq_reply_md;
        ptl_md_t rq_req_md;
        __u32 rq_reply_portal;
        __u32 rq_req_portal;

        struct lustre_peer rq_peer;
};

/* rpc/rpc.c */
int ptl_send_buf(struct ptlrpc_request *request, struct lustre_peer *peer,
                 int portal, int is_request);
int ptl_send_rpc(struct ptlrpc_request *request, struct lustre_peer *peer);
int rpc_register_service(struct ptlrpc_service *service, char *uuid);

/* FIXME */
#if 1
# define LUSTRE_NAL "ksocknal"
#else
# define LUSTRE_NAL "kqswnal"
#endif

#endif
