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

/* FOO_REQUEST_PORTAL receives requests for the FOO subsystem.
 * FOO_REPLY_PORTAL receives replies _from_ the FOO subsystem. */
#define OSC_REQUEST_PORTAL 1
#define OSC_REPLY_PORTAL   2
#define MDS_REQUEST_PORTAL 3
#define MDS_REPLY_PORTAL   4
#define OST_REQUEST_PORTAL 5
#define OST_REPLY_PORTAL   6
#define MDC_BULK_PORTAL    7
#define MDS_BULK_PORTAL    8
#define OSC_BULK_PORTAL    9
#define OST_BULK_PORTAL    10

/* default rpc ring length */
#define RPC_RING_LENGTH    2

/* generic wrappable next */
#define NEXT_INDEX(index, max)	(((index+1) >= max) ? 0 : (index+1))


struct ptlrpc_service {
        char *srv_buf[RPC_RING_LENGTH];
        __u32 srv_buf_size;
        __u32 srv_me_active;
	__u32 srv_me_tail;
	__u32 srv_md_active;
        __u32 srv_ring_length;
        __u32 srv_portal;
        __u32 srv_ref_count[RPC_RING_LENGTH];

        struct lustre_peer srv_self;

        /* FIXME: perhaps a list of EQs, if multiple NIs are used? */
        ptl_handle_eq_t srv_eq_h;

        ptl_handle_me_t srv_me_h[RPC_RING_LENGTH];
        ptl_process_id_t srv_id;
        ptl_md_t srv_md[RPC_RING_LENGTH];
        ptl_handle_md_t srv_md_h[RPC_RING_LENGTH];
        wait_queue_head_t *srv_wait_queue;
        int (*srv_req_unpack)(char *buf, int len, struct ptlreq_hdr **, 
                          union ptl_req *);
        int (*srv_rep_pack)(char *buf1, int len1, char *buf2, int len2,
                        struct ptlrep_hdr **, union ptl_rep*, 
                        int *replen, char **repbuf); 
};

struct ptlrpc_request { 
        int rq_type; /* one of PTLRPC_REQUEST, PTLRPC_REPLY, PTLRPC_BULK */
	struct list_head rq_list;
	struct mds_obd *rq_obd;
	struct ost_obd *rq_ost;
	int rq_status;
        __u32 rq_xid;

	char *rq_reqbuf;
	int rq_reqlen;
	struct ptlreq_hdr *rq_reqhdr;
	union ptl_req rq_req;

 	char *rq_repbuf;
	int rq_replen;
	struct ptlrep_hdr *rq_rephdr;
	union ptl_rep rq_rep;

        char *rq_bulkbuf;
        int rq_bulklen;
        int (*rq_bulk_cb)(struct ptlrpc_request *, void *);

        void *rq_reply_handle;
	wait_queue_head_t rq_wait_for_rep;
	wait_queue_head_t rq_wait_for_bulk;

        ptl_md_t rq_reply_md;
        ptl_handle_md_t rq_reply_md_h;
        ptl_handle_me_t rq_reply_me_h;

        ptl_md_t rq_req_md;
        ptl_md_t rq_bulk_md;
        ptl_handle_md_t rq_bulk_md_h;
        ptl_handle_me_t rq_bulk_me_h;
        __u32 rq_reply_portal;
        __u32 rq_req_portal;
        __u32 rq_bulk_portal;

        struct lustre_peer rq_peer;
};

struct ptlrpc_client {
        struct lustre_peer cli_server;
        __u32 cli_request_portal;
        __u32 cli_reply_portal;
        __u32 cli_xid;
        int (*cli_rep_unpack)(char *buf, int len, struct ptlrep_hdr **, 
                          union ptl_rep *);
        int (*cli_req_pack)(char *buf1, int len1, char *buf2, int len2,
                        struct ptlreq_hdr **, union ptl_req*, 
                        int *reqlen, char **reqbuf); 
        int (*cli_enqueue)(struct ptlrpc_request *req);
};

/* rpc/rpc.c */
#define PTLRPC_REQUEST 1
#define PTLRPC_REPLY   2
#define PTLRPC_BULK    3

int ptl_send_buf(struct ptlrpc_request *request, struct lustre_peer *peer,
                 int portal);
int ptl_send_rpc(struct ptlrpc_request *request, struct lustre_peer *peer);
int ptl_received_rpc(struct ptlrpc_service *service);
int rpc_register_service(struct ptlrpc_service *service, char *uuid);
int rpc_unregister_service(struct ptlrpc_service *service);
int ptlrpc_queue_wait(struct ptlrpc_request *req, 
                      struct ptlrpc_client *cl);
struct ptlrpc_request *ptlrpc_prep_req(struct ptlrpc_client *cl, 
                                       int opcode, int namelen, char *name,
                                       int tgtlen, char *tgt);
void ptlrpc_free_req(struct ptlrpc_request *request);


/* FIXME */
#if 1
# define LUSTRE_NAL "ksocknal"
#else
# define LUSTRE_NAL "kqswnal"
#endif

#endif
