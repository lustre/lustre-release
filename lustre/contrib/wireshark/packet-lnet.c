/* packet-lnet.c
 * Lnet packet dissection
 * Author: Laurent George <george@ocre.cea.fr>
 * based on packet-agentx.c and packet-afs.c
 * 20080903
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/to_str.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-infiniband.h>

#include "wireshark-compat.h"

/* This value inidcates whether we are processing an Infiniband packet, or
   TCP.  It gets set to the extra bytes the IB header requires if IB,
   or zero if TCP. */
static guint ib_lnd_extra_bytes;

/* How much data has at least to be available to be able to determine the
 * length of the lnet message.
 * Note: This is only used for TCP-based LNet packets.  Not used for Infiniband.
 */
#define LNET_HEADER_LEN 52
#define LNET_NID_DEST_OFFSET (24 + ib_lnd_extra_bytes)
#define LNET_NID_SRC_OFFSET (32 + ib_lnd_extra_bytes)
#define LNET_MSG_TYPE_OFFSET (48 + ib_lnd_extra_bytes)
#define LNET_PTL_INDEX_OFFSET_PUT (88 + ib_lnd_extra_bytes)

#define EXTRA_IB_HEADER_SIZE 24

/* TCP ports used for LNet. */
static guint global_lnet_tcp_port = 988;
static guint lnet_tcp_port = 988;

void proto_reg_handoff_lnet(void);

/* Define the lnet proto */
static int proto_lnet = -1;

static int hf_lnet_src_nid = -1 ;
static int hf_lnet_src_nid_addr = -1 ;
static int hf_lnet_src_nid_lnet_type = -1;
static int hf_lnet_src_nid_interface = -1  ;

static int hf_lnet_ksm_type = -1;
static int hf_lnet_ksm_csum = -1;
static int hf_lnet_ksm_zc_req_cookie = -1;
static int hf_lnet_ksm_zc_ack_cookie = -1;

static int hf_lnet_ib_magic = -1;
static int hf_lnet_ib_version = -1;
static int hf_lnet_ib_type = -1;
static int hf_lnet_ib_credits = -1;
static int hf_lnet_ib_nob = -1;
static int hf_lnet_ib_csum = -1;
static int hf_lnet_ib_srcstamp = -1;
static int hf_lnet_ib_dststamp = -1;

static int hf_lnet_dest_nid = -1 ;
static int hf_lnet_dest_nid_addr = -1 ;
static int hf_lnet_dest_nid_lnet_type = -1 ; 
static int hf_lnet_dest_nid_interface = -1 ;

static int hf_lnet_dest_pid = -1 ; 
static int hf_lnet_src_pid = -1 ;

static int hf_lnet_msg_type = -1 ;
static int hf_lnet_payload_length = -1;
static int hf_lnet_payload = -1 ;
static int hf_lnet_msg_header = -1 ; 
static int hf_lnet_msg_filler = -1 ;

static int hf_dst_wmd = -1 ;   
static int hf_dst_wmd_interface = -1 ;   
static int hf_dst_wmd_object = -1 ;   

static int hf_match_bits = -1 ; 
static int hf_mlength = -1 ; 

static int hf_hdr_data = -1 ;
static int hf_ptl_index = -1 ;
static int hf_offset = -1 ;
static gint ett_lnet = -1;

static int hf_src_offset = -1;
static int hf_sink_length = -1;

static int hf_hello_incarnation = -1 ;
static int hf_hello_type = -1 ; 

static gint ett_lnet_dest_nid= -1;
static gint ett_lnet_src_nid= -1;

tvbuff_t *next_tvb;

/* Breakdown of a NID. */
typedef struct t_nid {
	guint32 addr;
	guint16 interface;
	guint16 proto;
} t_nid ;

/*static heur_dissector_list_t heur_subdissector_list; */
static dissector_table_t subdissector_table;

static const value_string lndnames[] = {
	{ 1, "QSWLND   "},
	{ 2, "SOCKLND  "},
	{ 3, "GMLND    "},
	{ 4, "PTLLND   "},
	{ 5, "O2IBLND  "},
	{ 6, "CIBLND   "},
	{ 7, "OPENIBLND"}, 
	{ 8, "IIBLND   "},
	{ 9, "LOLND    "},
	{ 10,"RALND    "},
	{ 11,"VIBLND   "},
	{ 12,"MXLND    "} 
};

enum MSG_type{
	LNET_MSG_ACK = 0,
	LNET_MSG_PUT,
	LNET_MSG_GET,
	LNET_MSG_REPLY,
	LNET_MSG_HELLO,
} ;

static const value_string lnet_msg_type_t[] = {
	{ LNET_MSG_ACK  , "ACK"},  
	{ LNET_MSG_PUT  , "PUT"},  
	{ LNET_MSG_GET  , "GET"},  
	{ LNET_MSG_REPLY, "REPLY"},  
	{ LNET_MSG_HELLO, "HELLO"} 
};

/* Port Index numbers.  Defined in lustre/include/lustre/lustre_idl.h */
static const value_string portal_indices[] = {
	{ 0 , "LNET_RESERVED_PORTAL"},
	{ 1 , "CONNMGR_REQUEST_PORTAL"},
	{ 2 , "CONNMGR_REPLY_PORTAL"},
	{ 3 , "OSC_REQUEST_PORTAL(obsolete)"},
	{ 4 , "OSC_REPLY_PORTAL"},
	{ 5 , "OSC_BULK_PORTAL(obsolete)"},
	{ 6 , "OST_IO_PORTAL"},
	{ 7 , "OST_CREATE_PORTAL"},
	{ 8 , "OST_BULK_PORTAL"},
	{ 9 , "MDC_REQUEST_PORTAL(obsolete)"},
	{ 10 , "MDC_REPLY_PORTAL"},
	{ 11 , "MDC_BULK_PORTAL(obsolete)"},
	{ 12 , "MDS_REQUEST_PORTAL"},
	{ 13 , "MDS_REPLY_PORTAL(obsolete)"},
	{ 14 , "MDS_BULK_PORTAL"},
	{ 15 , "LDLM_CB_REQUEST_PORTAL"},
	{ 16 , "LDLM_CB_REPLY_PORTAL"},
	{ 17 , "LDLM_CANCEL_REQUEST_PORTAL"},
	{ 18 , "LDLM_CANCEL_REPLY_PORTAL"},
	{ 19 , "PTLBD_REQUEST_PORTAL(obsolete)"},
	{ 20 , "PTLBD_REPLY_PORTAL(obsolete)"},
	{ 21 , "PTLBD_BULK_PORTAL(obsolete)"},
	{ 22 , "MDS_SETATTR_PORTAL"},
	{ 23 , "MDS_READPAGE_PORTAL"},
	{ 24 , "MDS_MDS_PORTAL"},
	{ 25 , "MGC_REPLY_PORTAL"},
	{ 26 , "MGS_REQUEST_PORTAL"},
	{ 27 , "MGS_REPLY_PORTAL"},
	{ 28 , "OST_REQUEST_PORTAL"},
	{ 29 , "FLD_REQUEST_PORTAL"},
	{ 30 , "SEQ_METADATA_PORTAL"},
	{ 31 , "SEQ_DATA_PORTAL"},
	{ 32 , "SEQ_CONTROLLER_PORTAL"},
	{ 33 , "MGS_BULK_PORTAL"},
	{ 50 , "SRPC_REQUEST_PORTAL"},
	{ 51 , "SRPC_FRAMEWORK_REQUEST_PORTAL"},
	{ 52 , "SRPC_RDMA_PORTAL"}
};

/* SOCKLND constants. */
#define KSOCK_MSG_NOOP          0xc0            /* ksm_u empty */ 
#define KSOCK_MSG_LNET          0xc1            /* lnet msg */

static const value_string ksm_type_t[] = {
	{0xc0, "KSOCK_MSG_NOOP"},/* ksm_u empty */ 
	{0xc1, "KSOCK_MSG_LNET"} /* lnet msg */
};

/* O2IBLND constants. */
#define LNET_PROTO_IB_MAGIC	0x0be91b91

static const value_string ib_version_t[] = {
	{0x11, "1"},
	{0x12, "2"}
};

#define IBLND_MSG_CONNREQ	0xc0	/* connection request */
#define IBLND_MSG_CONNACK	0xc1	/* connection acknowledge */
#define IBLND_MSG_NOOP		0xd0	/* nothing (just credits) */
#define IBLND_MSG_IMMEDIATE	0xd1	/* immediate */
#define IBLND_MSG_PUT_REQ	0xd2	/* putreq (src->sink) */
#define IBLND_MSG_PUT_NAK	0xd3	/* completion (sink->src) */
#define IBLND_MSG_PUT_ACK	0xd4	/* putack (sink->src) */
#define IBLND_MSG_PUT_DONE	0xd5	/* completion (src->sink) */
#define IBLND_MSG_GET_REQ	0xd6	/* getreq (sink->src) */
#define IBLND_MSG_GET_DONE	0xd7	/* completion (src->sink: all OK) */

static const value_string ib_type_t[] = {
	{0xc0, "IBLND_MSG_CONNREQ"},
	{0xc1, "IBLND_MSG_CONNACK"},
	{0xd0, "IBLND_MSG_NOOP"},
	{0xd1, "IBLND_MSG_IMMEDIATE"},
	{0xd2, "IBLND_MSG_PUT_REQ"},
	{0xd3, "IBLND_MSG_PUT_NAK"},
	{0xd4, "IBLND_MSG_PUT_ACK"},
	{0xd5, "IBLND_MSG_PUT_DONE"},
	{0xd6, "IBLND_MSG_GET_REQ"},
	{0xd7, "IBLND_MSG_GET_DONE"}
};

static gboolean little_endian = TRUE;

#ifndef ENABLE_STATIC
const gchar version[] = VERSION;

/* Start the functions we need for the plugin stuff */

void
plugin_register(void)
{
	extern void proto_register_lnet(void);

	proto_register_lnet();
}

void
plugin_reg_handoff(void)
{
	extern void proto_reg_handoff_lnet(void);

	proto_reg_handoff_lnet();
}
#endif

static t_nid
get_nid(tvbuff_t *tvb, gint offset)
{
	t_nid nid ;

	nid.addr = g_htonl(tvb_get_ipv4(tvb, offset));
	nid.interface = tvb_get_letohs(tvb, offset + 4);
	nid.proto = tvb_get_letohs(tvb, offset + 6);
	return nid ;
}

static int dissect_csum(tvbuff_t * tvb, proto_tree *tree, int offset)
{
	guint32 csum;
	csum = tvb_get_letohl(tvb, offset);
	if (!csum)
		proto_tree_add_text(tree, tvb, offset, 4, "Checksum Disabled");
	else {
		if (ib_lnd_extra_bytes)
			proto_tree_add_item(tree, hf_lnet_ib_csum, tvb, offset,
					    4, little_endian);
		else
			proto_tree_add_item(tree, hf_lnet_ksm_csum, tvb, offset,
					    4, little_endian);
	}

	return offset + 4;
}


static int dissect_req_cookie(tvbuff_t * tvb, proto_tree *tree, int offset)
{
	guint32 req;
	req= tvb_get_letoh64(tvb, offset);
	if (!req)
		proto_tree_add_text(tree, tvb, offset, 8, "Ack not required");
	else
		proto_tree_add_item(tree, hf_lnet_ksm_zc_req_cookie, tvb, offset, 8, little_endian);
	return offset + 8;
}

static int dissect_ack_cookie(tvbuff_t * tvb, proto_tree *tree, int offset)
{
	guint32 ack;
	ack= tvb_get_letoh64(tvb, offset);
	if (!ack)
		proto_tree_add_text(tree, tvb, offset, 8, "Not ack");
	else
		proto_tree_add_item(tree, hf_lnet_ksm_zc_ack_cookie, tvb, offset, 8, little_endian);
	return offset + 8;
}

#ifdef WIRESHARK_COMPAT
static void
dissect_ksock_msg_noop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
#else
static int
dissect_ksock_msg_noop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		       void *ignored)
#endif
{
	guint32 offset;
	offset=0;
	proto_tree_add_item(tree, hf_lnet_ksm_type, tvb, offset, 4, TRUE);offset+=4;
	offset=dissect_csum(tvb,tree,offset);
	offset=dissect_req_cookie(tvb, tree, offset);
	offset=dissect_ack_cookie(tvb,tree,offset);
#ifndef WIRESHARK_COMPAT
	return offset;
#endif
}


static int dissect_ksock_msg(tvbuff_t * tvb, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, hf_lnet_ksm_type, tvb, offset, 4, TRUE);offset+=4;
	offset=dissect_csum(tvb,tree,offset);
	offset=dissect_req_cookie(tvb, tree, offset);
	offset=dissect_ack_cookie(tvb,tree,offset);
	return offset;
}

static int
dissect_ib_msg(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	/* typedef struct
	 * {
	 *	__u32             ibm_magic;            * I'm an ibnal message *
	 *	__u16             ibm_version;          * this is my version *

	 *	__u8              ibm_type;             * msg type *
	 *	__u8              ibm_credits;          * returned credits *
	 *	__u32             ibm_nob;              * # bytes in message *
	 *	__u32             ibm_cksum;            * checksum (0 == no
	 *                                                checksum) *
	 *	__u64             ibm_srcnid;           * sender's NID *
	 *	__u64             ibm_srcstamp;         * sender's incarnation *
	 *	__u64             ibm_dstnid;           * destination's NID *
	 *	__u64             ibm_dststamp;         * destination's
	 *                                                incarnation *

	 *	union {
	 *		kib_connparams_t      connparams;
	 *		kib_immediate_msg_t   immediate;
	 *		kib_putreq_msg_t      putreq;
	 *		kib_putack_msg_t      putack;
	 *		kib_get_msg_t         get;
	 *		kib_completion_msg_t  completion;
	 *	} WIRE_ATTR ibm_u;
	 *} WIRE_ATTR kib_msg_t;   */

	t_nid src_nid;
	t_nid dst_nid;
	guint8 msg_type;

	proto_tree_add_item(tree, hf_lnet_ib_magic, tvb, offset, 4,
			    little_endian);
	offset += 4;
	proto_tree_add_item(tree, hf_lnet_ib_version, tvb, offset, 2,
			    little_endian);
	offset += 2;
	msg_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_lnet_ib_type, tvb, offset, 1,
			    little_endian);
	offset += 1;
	proto_tree_add_item(tree, hf_lnet_ib_credits, tvb, offset, 1,
			    little_endian);
	offset += 1;
	proto_tree_add_item(tree, hf_lnet_ib_nob, tvb, offset, 4,
			    little_endian);
	offset += 4;
	offset = dissect_csum(tvb, tree, offset);

	src_nid = get_nid(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 8, "src_nid = %s@tcp%d",
			    ip_to_str((guint8 *) &src_nid.addr),
			    src_nid.interface);
	offset += 8;
	proto_tree_add_item(tree, hf_lnet_ib_srcstamp, tvb, offset, 8,
			    little_endian);
	offset += 8;

	dst_nid = get_nid(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 8, "dst_nid = %s@tcp%d",
			    ip_to_str((guint8 *) &dst_nid.addr),
			    dst_nid.interface);
	offset += 8;
	proto_tree_add_item(tree, hf_lnet_ib_dststamp, tvb,offset, 8,
			    little_endian);
	offset += 8;

	/* LNet payloads only exist when the LND msg type is IMMEDIATE.
	   Return a zero offset for all other types. */
	return (msg_type == IBLND_MSG_IMMEDIATE) ? offset : 0;
}

static int dissect_dest_nid(tvbuff_t * tvb, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, hf_lnet_dest_nid_addr, tvb, offset, 4, TRUE);offset+=4;
	proto_tree_add_item(tree, hf_lnet_dest_nid_interface, tvb, offset, 2, TRUE);offset+=2;
	proto_tree_add_item(tree, hf_lnet_dest_nid_lnet_type, tvb, offset, 2, TRUE);offset+=2;
	return offset;
}


static int dissect_src_nid(tvbuff_t * tvb, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, hf_lnet_src_nid_addr, tvb, offset, 4, TRUE);offset+=4;
	proto_tree_add_item(tree, hf_lnet_src_nid_interface, tvb, offset, 2, TRUE);offset+=2;
	proto_tree_add_item(tree, hf_lnet_src_nid_lnet_type, tvb, offset, 2, TRUE);offset+=2;
	return offset;
}

static int dissect_lnet_put(tvbuff_t * tvb, proto_tree *tree, int offset, packet_info *pinfo _U_)
{
	/* typedef struct lnet_put {
		 lnet_handle_wire_t  ack_wmd;
		 __u64               match_bits;
		 __u64               hdr_data;
		 __u32               ptl_index;
		 __u32               offset;
		 } WIRE_ATTR lnet_put_t; */

	proto_tree_add_item(tree,hf_dst_wmd_interface,tvb,offset,8,little_endian); offset+=8;
	proto_tree_add_item(tree,hf_dst_wmd_object,tvb,offset,8,little_endian);offset+=8;

	proto_tree_add_item(tree,hf_match_bits,tvb,offset,8,little_endian);offset+=8;
	proto_tree_add_item(tree,hf_hdr_data,tvb,offset,8,little_endian);offset+=8;
	col_append_sep_str(pinfo->cinfo, COL_INFO, ", ",
			   val_to_str(tvb_get_letohl(tvb, offset),
				      portal_indices,
				      "Unknown")); /* add some nice value  */
	proto_item_append_text(tree, ", %s" , val_to_str(tvb_get_letohl(tvb,
									offset),
							 portal_indices,
							 "Unknown"));
							 /* print ptl_index */
	proto_tree_add_item(tree,hf_ptl_index,tvb,offset,4,little_endian);offset+=4;
	proto_tree_add_item(tree,hf_offset,tvb,offset,4,little_endian);offset+=4;
	return offset ; 
}

static int dissect_lnet_get(tvbuff_t * tvb, proto_tree *tree, int offset, packet_info *pinfo _U_)
{
	/* typedef struct lnet_get {
	   lnet_handle_wire_t  return_wmd;
	   __u64               match_bits;
	   __u32               ptl_index;
	   __u32               src_offset;
	   __u32               sink_length;
	   } WIRE_ATTR lnet_get_t;
	*/

	proto_tree_add_item(tree, hf_dst_wmd_interface,
			    tvb, offset, 8, little_endian);
	offset += 8;
	proto_tree_add_item(tree, hf_dst_wmd_object, tvb, offset, 8,
			    little_endian);
	offset += 8;
	proto_tree_add_item(tree, hf_match_bits, tvb, offset, 8, little_endian);
	offset += 8;
	col_append_sep_str(pinfo->cinfo, COL_INFO, ", ",
			   val_to_str(tvb_get_letohl(tvb, offset),
				      portal_indices, "Unknown"));
	proto_item_append_text(tree, ", %s",
			       val_to_str(tvb_get_letohl(tvb, offset),
					  portal_indices, "Unknown"));
	proto_tree_add_item(tree, hf_ptl_index, tvb, offset, 4, little_endian);
	offset += 4;
	proto_tree_add_item(tree, hf_src_offset, tvb, offset, 4, little_endian);
	offset += 4;
	proto_tree_add_item(tree, hf_sink_length, tvb, offset, 4,
			    little_endian);
	offset += 4;
	return offset;
}

static int dissect_lnet_reply(tvbuff_t * tvb, proto_tree *tree, int offset)
{
	/* typedef struct lnet_reply {
		 lnet_handle_wire_t  dst_wmd;
		 } WIRE_ATTR lnet_reply_t; */

	proto_tree_add_item(tree,hf_dst_wmd_interface,tvb,offset,8,little_endian);offset+=8; 
	proto_tree_add_item(tree,hf_dst_wmd_object,tvb,offset,8,little_endian);offset+=8;

	return offset;
}


static int dissect_lnet_hello(tvbuff_t * tvb, proto_tree *tree, int offset)
{
	/* typedef struct lnet_hello {
		 __u64              incarnation;
		 __u32              type;
		 } WIRE_ATTR lnet_hello_t; */

	proto_tree_add_item(tree,hf_hello_incarnation,tvb,offset,8,little_endian); offset+=8;
	proto_tree_add_item(tree,hf_hello_type,tvb,offset,4,little_endian); offset+=4;
	return offset; 
}

static int dissect_lnet_ack(tvbuff_t * tvb, proto_tree *tree, int offset, packet_info *pinfo _U_)
{
	/* typedef struct lnet_ack {
		 lnet_handle_wire_t  dst_wmd;
		 __u64               match_bits;
		 __u32               mlength;
		 } WIRE_ATTR lnet_ack_t; */

	proto_tree_add_item(tree,hf_dst_wmd_interface,tvb,offset,8,TRUE); offset+=8;
	proto_tree_add_item(tree,hf_dst_wmd_object,tvb,offset,8,TRUE);offset+=8;
	proto_tree_add_item(tree,hf_match_bits,tvb,offset,8, little_endian);offset+=8;
	proto_tree_add_item(tree,hf_mlength, tvb,offset,4, little_endian); offset+=4;
	return offset ; 
} 

#ifdef WIRESHARK_COMPAT
static void dissect_lnet_message(tvbuff_t *, packet_info *, proto_tree *);
#else
static int dissect_lnet_message(tvbuff_t *, packet_info *, proto_tree *, void*);
#endif

/* The next two length getting routines are only used for KSOCK LNK messages. */
static guint 
get_lnet_message_len(packet_info  __attribute__((__unused__))*pinfo, tvbuff_t *tvb, int offset) 
{ 
	guint32 plen;

	/* Get the payload length */
	plen = tvb_get_letohl(tvb, offset + 28 + 24 + ib_lnd_extra_bytes);
						  /* 24 = ksm header,
						     28 = the rest of the
							  headers */

	/* That length doesn't include the header; add that in. */
	return plen + 72 + 24 + ib_lnd_extra_bytes; /*  +24 == ksock msg
							header.. :D */

}

static guint
get_noop_message_len(packet_info  __attribute__((__unused__))*pinfo, tvbuff_t *tvb, int offset)
{
	return 24;
}

static void 
dissect_lnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)  
{
	/* TODO : correct this, now we do a difference between packet with
	   NOOP and others ..  but I don't find how to use pdu_dissect with
	   a variable length<=LNET_HEADER_LEN */
	ib_lnd_extra_bytes = 0;
	switch (tvb_get_letohl(tvb, 0)) {
	case KSOCK_MSG_NOOP:
#ifdef WIRESHARK_COMPAT
		tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
				 get_noop_message_len,
				 dissect_ksock_msg_noop);
#else
		tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
				 get_noop_message_len,
				 dissect_ksock_msg_noop, NULL);
#endif
		break;
	case KSOCK_MSG_LNET:
#ifdef WIRESHARK_COMPAT
		tcp_dissect_pdus(tvb, pinfo, tree, TRUE, LNET_HEADER_LEN,
				 get_lnet_message_len,
				 dissect_lnet_message);
#else
		tcp_dissect_pdus(tvb, pinfo, tree, TRUE, LNET_HEADER_LEN,
				 get_lnet_message_len,
				 dissect_lnet_message, NULL);
#endif
		break;
	}
}

static int
#ifdef WIRESHARK_COMPAT
dissect_ib_lnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
#else
dissect_ib_lnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
#endif
{
	/* We can tell if this is an LNet payload by looking at the first
	 * 32-bit word for our magic number. */
	if (tvb_get_letohl(tvb, 0) != LNET_PROTO_IB_MAGIC) {
		/* Not an LNet payload. */
		return 0;
	}

	ib_lnd_extra_bytes = EXTRA_IB_HEADER_SIZE;
#ifdef WIRESHARK_COMPAT
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, LNET_HEADER_LEN,
			 get_lnet_message_len, dissect_lnet_message);
#else
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, LNET_HEADER_LEN,
			 get_lnet_message_len, dissect_lnet_message, NULL);
#endif
	return tvb_length(tvb);
}

/*----------------------------------------------------------- */
/* For the conversation */

typedef struct {
	guint64 match_bits;
} my_entry_t;


typedef struct lnet_request_key {
	guint64 match_bits ;
	guint32 conversation;
} lnet_request_key_t;

typedef struct lnet_request_val {
	guint64 match_bits;
	guint32 packet_num_parent;
} lnet_request_val_t;


static GHashTable *lnet_request_hash;

/*
 * Hash Functions
 */
static gint
lnet_equal(gconstpointer v, gconstpointer w)
{
	const struct lnet_request_key *v1 = (const struct lnet_request_key *)v;
	const struct lnet_request_key *v2 = (const struct lnet_request_key *)w;

	if (v1 -> conversation == v2 -> conversation &&
			v1 -> match_bits == v2 -> match_bits)
	{

		return 1;
	}

	return 0;
}

static guint
lnet_hash (gconstpointer v)
{
	const struct lnet_request_key *key = (const struct lnet_request_key *)v;
	return key -> conversation + key -> match_bits;
}


static void
lnet_init_protocol(void)
{
	if (lnet_request_hash)
		g_hash_table_destroy(lnet_request_hash);

	lnet_request_hash = g_hash_table_new(lnet_hash, lnet_equal);
}


static lnet_request_val_t*
get_lnet_conv(packet_info * pinfo , GHashTable * lnet_hash_table,  guint64 match_bits )
{
	conversation_t *  conversation ; 
	lnet_request_key_t request_key, *new_request_key;
	lnet_request_val_t *request_val=NULL ;

	conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);


	if (NULL == conversation)
		/* It's not part of any conversation - create a new one. */
		conversation = conversation_new(pinfo->fd->num,  &pinfo->src, &pinfo->dst, proto_lnet,
				pinfo->srcport, pinfo->destport, 0);

	request_key.conversation = conversation->index;
	request_key.match_bits = match_bits;

	request_val = (struct lnet_request_val * ) g_hash_table_lookup(lnet_hash_table, &request_key);
	if(!request_val){
		new_request_key = se_alloc(sizeof(struct lnet_request_key));
		*new_request_key = request_key;
		request_val = se_alloc(sizeof(struct lnet_request_val));
		request_val -> match_bits = match_bits;
		request_val -> packet_num_parent = pinfo->fd->num ;
		/*request_val -> filename = "test" ; */
		g_hash_table_insert(lnet_hash_table, new_request_key, request_val);

	}

	return request_val ;

}



/*----------------------------------------------------------- */
#ifdef WIRESHARK_COMPAT
static void
dissect_lnet_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
#else
static int
dissect_lnet_message(tvbuff_t *tvb, packet_info *pinfo,
		     proto_tree *tree, void *data)
#endif
{
	guint64 match;
	guint32 msg_type;
	gint offset = 0;
	t_nid dest_nid; /* nid value */
	t_nid src_nid;
	proto_item *ti = NULL; /* principal  node */
	proto_tree *lnet_tree = NULL; /* principal tree */
	proto_tree *lnet_nid_src_tree = NULL; /*subtree for the nids*/
	proto_tree *lnet_nid_dest_tree = NULL;
	proto_item *ti_src_nid; /* node for the nids */
	proto_item *ti_dest_nid;
	guint32 payload_length;
	guint32 msg_filler_length;

	/* lnet_request_val_t* conversation_val ; */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Lnet");

	msg_type = tvb_get_letohl(tvb, LNET_MSG_TYPE_OFFSET);
	/* We delete the entire line and add LNET  + msg_type */
	col_add_fstr(pinfo->cinfo, COL_INFO, "LNET_%s",
		     (msg_type < sizeof(lnet_msg_type_t)/sizeof(value_string))
		     ? lnet_msg_type_t[msg_type].strptr
		     : "Unknown");

	if (tree == NULL)
		goto out;

	/* principal node */
	ti = proto_tree_add_item(tree, proto_lnet, tvb, 0, -1, FALSE);

	lnet_tree = proto_item_add_subtree(ti, ett_lnet);

	if (ib_lnd_extra_bytes) {
		offset = dissect_ib_msg(tvb, lnet_tree, offset);
		if (offset == 0) {
			/*  There was no LNet payload, only ob2lnd. */
			goto out;
		}
	} else {
		/* dissect the first 24 bytes (ksock_msg_t in
		 * lnet/socklnd.h
		 */
		offset = dissect_ksock_msg(tvb, lnet_tree, offset);
	}

	/* Dest nid */
	dest_nid = get_nid(tvb, offset);
	ti_dest_nid = proto_tree_add_text(lnet_tree, tvb, offset, 8,
					  "dest_nid = %s@tcp%d",
					  ip_to_str((guint8 *) &dest_nid.addr),
					  dest_nid.interface);
	lnet_nid_dest_tree = proto_item_add_subtree(ti_dest_nid,
						    ett_lnet_dest_nid);
	offset = dissect_dest_nid(tvb, lnet_nid_dest_tree, offset);

	/* Same for src_nid */
	src_nid = get_nid(tvb, offset);
	ti_src_nid = proto_tree_add_text(lnet_tree, tvb, offset, 8,
					 "src_nid = %s@tcp%d",
					 ip_to_str((guint8 *) &src_nid.addr),
					 src_nid.interface);
	lnet_nid_src_tree = proto_item_add_subtree(ti_src_nid,
						   ett_lnet_src_nid);
	offset = dissect_src_nid(tvb, lnet_nid_src_tree, offset);

	/* pid */
	proto_tree_add_item(lnet_tree, hf_lnet_src_pid, tvb, offset, 4, TRUE);
	offset += 4;
	proto_tree_add_item(lnet_tree, hf_lnet_dest_pid, tvb, offset, 4, TRUE);
	offset += 4;

	/* message_type (32 bits) */
	msg_type = tvb_get_letohl(tvb, offset+0);
	/* put some nice info on lnet line */
	proto_item_append_text(ti, " %s",
			       (msg_type <
				sizeof(lnet_msg_type_t)/sizeof(value_string))
			       ? lnet_msg_type_t[msg_type].strptr
			       : "Unknow");
	proto_tree_add_item(lnet_tree, hf_lnet_msg_type, tvb,
			    offset, 4, TRUE);
	offset += 4;

	/* payload data (to follow) length :*/
	payload_length = tvb_get_letohl(tvb, offset+0);
	proto_tree_add_item(lnet_tree, hf_lnet_payload_length, tvb,
			    offset, 4, TRUE);
	offset += 4;

	/* here offset = 24+8+8+4+4+4+4 = 56 */
	match = 0;
	switch (msg_type) {
	case LNET_MSG_ACK:
		offset = dissect_lnet_ack(tvb, lnet_tree, offset, pinfo);
		match = tvb_get_letoh64(tvb, 72);
		break;
	case LNET_MSG_PUT:
		offset = dissect_lnet_put(tvb, lnet_tree, offset, pinfo);
		match = tvb_get_letoh64(tvb, 72);
		break;
	case LNET_MSG_GET:
		offset = dissect_lnet_get(tvb, lnet_tree, offset, pinfo);
		match = tvb_get_letoh64(tvb, 72);
		break;
	case LNET_MSG_REPLY:
		offset = dissect_lnet_reply(tvb, lnet_tree, offset);
		break;
	case LNET_MSG_HELLO:
		offset = dissect_lnet_hello(tvb, lnet_tree, offset);
		break;
	default:
		break;
	}

	/* conversation_val = */
	get_lnet_conv(pinfo, lnet_request_hash, match);
	/*	proto_tree_add_text(tree, tvb, 0 , 0, "match = %"
	 *	G_GINT64_MODIFIER "u parent = %d",
	 *	conversation_val -> match_bits ,
	 *	conversation_val -> packet_num_parent);
	 */

	/* padding */
	msg_filler_length = 72 - offset + 24 + ib_lnd_extra_bytes;
	if (msg_filler_length > 72)
		goto out;
	/*  +24 : ksosck_message take 24bytes, and allready in offset  */

	proto_tree_add_item(lnet_tree, hf_lnet_msg_filler, tvb, offset,
			    msg_filler_length, little_endian);
	offset += msg_filler_length;

	if (payload_length > 0) {
		/* display of payload */
		proto_tree_add_item(lnet_tree, hf_lnet_payload, tvb,
				    offset, payload_length,
				    little_endian);

		next_tvb = tvb_new_subset(tvb, offset,
					  payload_length, payload_length);
		if (msg_type == LNET_MSG_PUT)
			dissector_try_uint(subdissector_table,
				tvb_get_letohl(tvb, LNET_PTL_INDEX_OFFSET_PUT),
				next_tvb, pinfo, tree);

	}

	offset += payload_length;

out:
#ifdef WIRESHARK_COMPAT
	return;
#else
	return offset;
#endif
}

void
proto_register_lnet(void)
{
	static hf_register_info hf[] = {
		{ &hf_lnet_ksm_type           , 
			{ "Type of socklnd message"   , "lnet.ksm_type"                , FT_UINT32 , BASE_HEX     , VALS(ksm_type_t)      , 0x0 , ""         , HFILL }} , 
		{ &hf_lnet_ksm_csum           , 
			{ "Checksum"                  , "lnet.ksm_csum"                , FT_UINT32 , BASE_DEC     , NULL                  , 0x0 , ""         , HFILL }} , 
		{ &hf_lnet_ksm_zc_req_cookie  , 
			{ "Ack required"              , "lnet.ksm_zc_req_cookie"       , FT_UINT64 , BASE_HEX     , NULL                  , 0x0 , ""         , HFILL }} , 
		{ &hf_lnet_ksm_zc_ack_cookie  , 
			{ "Ack"                       , "lnet.ksm_zc_ack_cookie"       , FT_UINT64 , BASE_HEX     , NULL                  , 0x0 , ""         , HFILL }} , 
		{ &hf_lnet_ib_magic,
			{ "Magic of IB message", "lnet.ib.magic", FT_UINT32,
			  BASE_HEX, NULL, 0x0, "", HFILL} },
		{ &hf_lnet_ib_version,
			{ "Version", "lnet.ib.version", FT_UINT16, BASE_HEX,
			  VALS(ib_version_t), 0x0, "", HFILL} },
		{ &hf_lnet_ib_type,
			{ "Type of IB message", "lnet.ib.type", FT_UINT8,
			  BASE_HEX, VALS(ib_type_t), 0x0, "", HFILL} },
		{ &hf_lnet_ib_credits,
			{ "Returned Credits", "lnet.ib.credits", FT_UINT8,
			  BASE_DEC, NULL, 0x0, "", HFILL} },
		{ &hf_lnet_ib_nob,
			{ "Number of Bytes", "lnet.ib.nob", FT_UINT32,
			  BASE_DEC, NULL, 0x0, "", HFILL} },
		{ &hf_lnet_ib_csum,
			{ "Checksum", "lnet.ib_csum", FT_UINT32, BASE_DEC,
			  NULL, 0x0, "", HFILL} },
		{ &hf_lnet_ib_srcstamp,
			{ "Sender Timestamp", "lnet.ib.srcstamp",
			  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
			  "", HFILL} },
		{ &hf_lnet_ib_dststamp,
			{ "Destination Timestamp", "lnet.ib.dststamp",
			  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
			  "", HFILL} },

		{ &hf_lnet_src_nid            , 
			{ "Src nid"                   , "lnet.src_nid"                 , FT_UINT64 , BASE_HEX     , NULL                  , 0x0 , "src nid"  , HFILL }} , 
		{ &hf_lnet_src_nid_addr       , 
			{ "Src nid"                   , "lnet.src_nid_addr"            , FT_IPv4   , BASE_NONE    , NULL                  , 0x0 , ""         , HFILL }} , 
		{ &hf_lnet_src_nid_lnet_type  , 
			{ "lnd network type"          , "lnet.src_nid_type"            , FT_UINT16 , BASE_DEC     , VALS(lndnames)       , 0x0 , ""         , HFILL} },
		{ &hf_lnet_src_nid_interface  , 
			{ "lnd network interface"     , "lnet.src_nid_net_interface"   , FT_UINT16 , BASE_DEC     , NULL                  , 0x0 , NULL       , HFILL }} , 

		{ &hf_lnet_dest_nid           , 
			{ "Dest nid"                  , "lnet.dest_nid"                , FT_UINT64 , BASE_HEX     , NULL                  , 0x0 , ""         , HFILL }} , 

		{ &hf_lnet_dest_nid_addr      , 
			{ "Destination nid"           , "lnet.dest_nid_addr"           , FT_IPv4   , BASE_NONE    , NULL                  , 0x0 , ""         , HFILL }} , 
		{ &hf_lnet_dest_nid_lnet_type , 
			{ "lnd network type"          , "lnet.dest_nid_type"           , FT_UINT16 , BASE_DEC     , VALS(lndnames)       , 0x0 , ""         , HFILL} },
		{ &hf_lnet_dest_nid_interface , 
			{ "lnd network interface"     , "lnet.dest_nid_net_interface"  , FT_UINT16 , BASE_DEC     , NULL                  , 0x0 , NULL       , HFILL }} , 

		{ &hf_lnet_dest_pid           , 
			{ "Dest pid"                  , "lnet.dest_pid"                , FT_UINT32 , BASE_DEC_HEX , NULL                  , 0x0 , "dest pid" , HFILL }} , 
		{ &hf_lnet_src_pid            , 
			{ "Src pid"                   , "lnet.src_pid"                 , FT_UINT32 , BASE_DEC_HEX , NULL                  , 0x0 , "src nid"  , HFILL }} , 

		{ &hf_lnet_msg_type           , 
			{ "Message type"              , "lnet.msg_type"                , FT_UINT32 , BASE_DEC     , VALS(lnet_msg_type_t) , 0x0 , "msg type" , HFILL }} , 
		{ &hf_lnet_payload_length     , 
			{ "Payload length"            , "lnet.payload_length"          , FT_UINT32 , BASE_DEC     , NULL                  , 0x0 , ""         , HFILL }} , 
		{ &hf_lnet_payload            , 
			{ "Payload"                   , "lnet.payload"                 , FT_NONE   , BASE_NONE    , NULL                  , 0x0 , ""         , HFILL }} , 

		{&hf_dst_wmd                  , 
			{ "DST MD index "             , "lnet.msg_dst_cookie"          , FT_BYTES  , BASE_NONE    , NULL                  , 0x0 , ""         , HFILL }} , 
		{ &hf_dst_wmd_interface       , 
			{ "DST MD index interface"    , "lnet.msg_dst_inteface_cookie" , FT_UINT64 , BASE_HEX_DEC , NULL                  , 0x0 , ""         , HFILL }} , 
		{ &hf_dst_wmd_object          , 
			{ "DST MD index object"       , "lnet.msg_dst_object_cookie"   , FT_UINT64 , BASE_HEX_DEC , NULL                  , 0x0 , ""         , HFILL }} , 
		{ &hf_match_bits              , 
			{ "Match bits"                , "lnet.msg_dst_match_bits"      , FT_UINT64 , BASE_HEX_DEC , NULL                  , 0x0 , ""         , HFILL}}  , 
		{ &hf_mlength                 , 
			{ "Message length"            , "lnet.msg_length"              , FT_UINT32 , BASE_DEC     , NULL                  , 0x0 , ""         , HFILL}}  , 


		/* Put */
		{ &hf_hdr_data                , 
			{ "hdr data"                  , "lnet.msg_hdr_data"            , FT_UINT64 , BASE_HEX_DEC , NULL                  , 0x0 , ""         , HFILL}}  , 
		{ &hf_ptl_index               , 
			{ "ptl index"                 , "lnet.ptl_index"               , FT_UINT32 , BASE_DEC     , VALS(portal_indices)  , 0x0 , ""         , HFILL}}  , 
		{ &hf_offset                  , 
			{ "offset"                    , "lnet.offset"                  , FT_UINT32 , BASE_DEC     , NULL                  , 0x0 , ""         , HFILL}}  , 

		/* Get*/
		{ &hf_src_offset              , 
			{ "src offset"                , "lnet.src_offset"              , FT_UINT32 , BASE_DEC     , NULL                  , 0x0 , ""         , HFILL}}  , 
		{ &hf_sink_length             , 
			{ "sink length"               , "lnet.sink_length"             , FT_UINT32 , BASE_DEC     , NULL                  , 0x0 , ""         , HFILL}}  , 

		/* Hello*/
		{ &hf_hello_incarnation       , 
			{ "hello incarnation "        , "lnet.hello_incarnation"       , FT_UINT64 , BASE_HEX_DEC , NULL                  , 0x0 , ""         , HFILL}}  , 
		{ &hf_hello_type              , 
			{ "hello type"                , "lnet.hello_type"              , FT_UINT32 , BASE_DEC     , NULL                  , 0x0 , ""         , HFILL}}  , 

		{ &hf_lnet_msg_header         , 
			{ "ptl header"                , "lnet.ptl_header"              , FT_NONE   , BASE_NONE    , NULL                  , 0x0 , ""         , HFILL}}  , 

		{ &hf_lnet_msg_filler         , 
			{ "msg filler (padding)"      , "lnet.ptl_filler"              , FT_NONE   , BASE_NONE    , NULL                  , 0x0 , ""         , HFILL}}  , 

		/* Add more fields here */
	};

	static gint *ett[] = {
		&ett_lnet,
		&ett_lnet_dest_nid,
		&ett_lnet_src_nid
	};


	module_t *lnet_module;

	proto_lnet = proto_register_protocol("Lnet", /*name*/
			"Lnet",  /*short name*/
			"lnet"); /*abbrev*/

	proto_register_field_array(proto_lnet, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	lnet_module = prefs_register_protocol(proto_lnet, proto_reg_handoff_lnet);

	prefs_register_uint_preference(lnet_module, "tcp.lnet_port",
			"Lnet listener TCP Port",
			"Set the TCP port for Lnet"
			"(if other than the default of 988)",
			10, &global_lnet_tcp_port);

	subdissector_table = register_dissector_table("lnet.ptl_index", "lnet portal index", FT_UINT32 , BASE_DEC);

	register_init_routine(&lnet_init_protocol);

}


/* The registration hand-off routine */
void
proto_reg_handoff_lnet(void)
{
	static int lnet_prefs_initialized = FALSE;
	static dissector_handle_t lnet_handle;

	if(!lnet_prefs_initialized) {
		heur_dissector_add("infiniband.payload", dissect_ib_lnet,
				   proto_lnet);
		heur_dissector_add("infiniband.mad.cm.private",
				   dissect_ib_lnet, proto_lnet);
		lnet_handle = create_dissector_handle(dissect_lnet, proto_lnet);
		lnet_prefs_initialized = TRUE;
	}
	else
		dissector_delete_uint("tcp.port", global_lnet_tcp_port, lnet_handle);

	lnet_tcp_port = global_lnet_tcp_port;

	dissector_add_uint("tcp.port", lnet_tcp_port, lnet_handle);
}
