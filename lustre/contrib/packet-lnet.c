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

#include <epan/dissectors/packet-tcp.h>

/* how much data has at least to be available to be able to determine the
 * length of the lnet message */
#define LNET_HEADER_LEN 52
#define LNET_NID_DEST_OFFSET 24
#define LNET_NID_SRC_OFFSET 32
#define LNET_MSG_TYPE_OFFSET 48

static guint global_lnet_tcp_port = 988;
static guint lnet_tcp_port = 988;

void proto_reg_handoff_lnet(void);

#define LNET_PTL_INDEX_OFFSET_PUT 88

/* Define the lnet proto */
static int proto_lnet = -1;

static int hf_lnet_src_nid = -1 ;
static int hf_lnet_src_nid_addr = -1 ;
static int hf_lnet_src_nid_lnet_type = -1 ; 
static int hf_lnet_src_nid_interface = -1  ;

static int hf_lnet_ksm_type = -1 ;
static int hf_lnet_ksm_csum= -1;       
static int hf_lnet_ksm_zc_req_cookie=-1;
static int hf_lnet_ksm_zc_ack_cookie=-1; 

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

/*static heur_dissector_list_t heur_subdissector_list; */
static dissector_table_t subdissector_table;

static const value_string lnetnames[] = {
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

/* defined in lustre/include/lustre/lustre_idl.h */
static const value_string portal_indices[] = {
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
	{ 25 , "MGC_REPLY_PORTAL"},
	{ 26 , "MGS_REQUEST_PORTAL"},
	{ 27 , "MGS_REPLY_PORTAL"},
	{ 28 , "OST_REQUEST_PORTAL"}
};

#define KSOCK_MSG_NOOP          0xc0            /* ksm_u empty */ 
#define KSOCK_MSG_LNET          0xc1            /* lnet msg */

static const value_string ksm_type_t[] = {
	{0xc0, "KSOCK_MSG_NOOP"},/* ksm_u empty */ 
	{0xc1, "KSOCK_MSG_LNET"} /* lnet msg */
};


static int dissect_csum(tvbuff_t * tvb, proto_tree *tree, int offset)
{
	guint32 csum;
	csum = tvb_get_letohl(tvb, offset);
	if (!csum)
		proto_tree_add_text(tree, tvb, offset, 4, "checksum disabled");
	else
		proto_tree_add_item(tree, hf_lnet_ksm_csum, tvb, offset, 4, TRUE);

	offset+=4;
	return offset;
}


static int dissect_req_cookie(tvbuff_t * tvb, proto_tree *tree, int offset)
{
	guint32 req;
	req= tvb_get_letoh64(tvb, offset);
	if (!req)
		proto_tree_add_text(tree, tvb, offset, 8, "ack not required");
	else
		proto_tree_add_item(tree, hf_lnet_ksm_zc_req_cookie, tvb, offset, 8, TRUE);
	offset+=8;
	return offset;
}

static int dissect_ack_cookie(tvbuff_t * tvb, proto_tree *tree, int offset)
{
	guint32 ack;
	ack= tvb_get_letoh64(tvb, offset);
	if (!ack)
		proto_tree_add_text(tree, tvb, offset, 8, "not ack");
	else
		proto_tree_add_item(tree, hf_lnet_ksm_zc_ack_cookie, tvb, offset, 8, TRUE);
	offset+=8;
	return offset;
}

static void 
dissect_ksock_msg_noop( tvbuff_t * tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
	guint32 offset;
	offset=0;
	proto_tree_add_item(tree, hf_lnet_ksm_type, tvb, offset, 4, TRUE);offset+=4;
	offset=dissect_csum(tvb,tree,offset);
	offset=dissect_req_cookie(tvb, tree, offset);
	offset=dissect_ack_cookie(tvb,tree,offset);
}


static int dissect_ksock_msg(tvbuff_t * tvb, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, hf_lnet_ksm_type, tvb, offset, 4, TRUE);offset+=4;
	offset=dissect_csum(tvb,tree,offset);
	offset=dissect_req_cookie(tvb, tree, offset);
	offset=dissect_ack_cookie(tvb,tree,offset);
	return offset;
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

	gboolean little_endian=TRUE ;

	proto_tree_add_item(tree,hf_dst_wmd_interface,tvb,offset,8,little_endian); offset+=8;
	proto_tree_add_item(tree,hf_dst_wmd_object,tvb,offset,8,little_endian);offset+=8;

	proto_tree_add_item(tree,hf_match_bits,tvb,offset,8,little_endian);offset+=8;
	proto_tree_add_item(tree,hf_hdr_data,tvb,offset,8,little_endian);offset+=8;
	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(tvb_get_letohl(tvb,offset), portal_indices, "Unknow")); /* add some nice value  */
	proto_item_append_text(tree, ", %s" , val_to_str(tvb_get_letohl(tvb,offset), portal_indices, "Unknow")); /* print ptl_index */
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
		 } WIRE_ATTR lnet_get_t; */

	gboolean little_endian=TRUE ;
	proto_tree_add_item(tree,hf_dst_wmd_interface,tvb,offset,8,little_endian);offset+=8;
	proto_tree_add_item(tree,hf_dst_wmd_object,tvb,offset,8,little_endian);offset+=8;
	/*if (check_col(pinfo->cinfo, COL_INFO))*/
	/*        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, " %" G_GINT64_MODIFIER "u ", tvb_get_letoh64(tvb,offset) );*/

	proto_tree_add_item(tree,hf_match_bits,tvb,offset,8,little_endian);offset+=8;
	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(tvb_get_letohl(tvb,offset), portal_indices, "Unknow")); 
	proto_item_append_text(tree, ", %s" , val_to_str(tvb_get_letohl(tvb,offset), portal_indices, "Unknow")); /* print ptl_index */
	proto_tree_add_item(tree,hf_ptl_index,tvb,offset,4,little_endian);offset+=4;
	proto_tree_add_item(tree,hf_src_offset,tvb,offset,4,little_endian);offset+=4;
	proto_tree_add_item(tree,hf_sink_length,tvb,offset,4,little_endian);offset+=4;
	return offset; 
}

static int dissect_lnet_reply(tvbuff_t * tvb, proto_tree *tree, int offset)
{
	/* typedef struct lnet_reply {
		 lnet_handle_wire_t  dst_wmd;
		 } WIRE_ATTR lnet_reply_t; */

	gboolean little_endian=TRUE ;
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

	gboolean little_endian=TRUE ;
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
	proto_tree_add_item(tree,hf_match_bits,tvb,offset,8,TRUE);offset+=8;
	proto_tree_add_item(tree,hf_mlength, tvb,offset,4,TRUE); offset+=4;
	return offset ; 
} 

static void dissect_lnet_message(tvbuff_t * tvb, packet_info *pinfo, proto_tree *tree); 
/* return the pdu length */ 
static guint 
get_lnet_message_len(packet_info  __attribute__((__unused__))*pinfo, tvbuff_t *tvb, int offset) 
{ 
	/*
	 * Get the payload length
	 */
	guint32 plen;
	plen = tvb_get_letohl(tvb,offset+28+24); /*24 = ksm header, 28 = le reste des headers*/

	/*
	 * That length doesn't include the header; add that in.
	 */
	return plen + 72 +24 ; /*  +24 == ksock msg header.. :D */

}

static guint
get_noop_message_len(packet_info  __attribute__((__unused__))*pinfo, tvbuff_t *tvb _U_ , int offset _U_) 
{
	return 24;
}

static void 
dissect_lnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)  
{
	/* TODO : correct this, now we do a difference between packet with NOOP and others ..
		 but I don't find how to use pdu_dissect with a variable length<=LNET_HEADER_LEN */
	switch(tvb_get_letohl(tvb,0)){
		case KSOCK_MSG_NOOP:
			/*g_print("ksock noop %d \n", pinfo->fd->num);*/
			tcp_dissect_pdus(tvb,pinfo,tree,TRUE,0, get_noop_message_len,dissect_ksock_msg_noop);
			break;
		case KSOCK_MSG_LNET:
			tcp_dissect_pdus(tvb,pinfo,tree,TRUE,LNET_HEADER_LEN, get_lnet_message_len,dissect_lnet_message);
			break;
	}

}

typedef struct t_nid {
	guint32 addr;
	guint16 interface;
	guint16 proto;
} t_nid ;

static t_nid get_nid(tvbuff_t *tvb, gint offset)
{
	t_nid nid ;
	nid.addr = g_htonl(tvb_get_ipv4(tvb,offset));
	nid.interface = tvb_get_letohs(tvb,offset+4);
	nid.proto = tvb_get_letohs(tvb,offset+6);
	return nid ;
	/* example : 
	 * get_nid(tvb, LNET_NID_DEST_OFFSET);
	 * get_nid(tvb, LNET_NID_SRC_OFFSET); 
	 * */
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


static GHashTable *lnet_request_hash = NULL;

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
	guint val;

	val = key -> conversation + key -> match_bits ;

	return val;
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
static void
dissect_lnet_message(tvbuff_t * tvb, packet_info *pinfo, proto_tree *tree)
{

	guint64 match;
	guint32 msg_type;

	lnet_request_val_t* conversation_val ;


	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Lnet");
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
		/* t_nid dest_nid ; */
		/*t_nid src_nid ; */
		/*guint32 msg_type;*/
		/*[> col_clear(pinfo->cinfo, COL_INFO); <]*/
		/*dest_nid = get_nid(tvb, LNET_NID_DEST_OFFSET);*/
		/*src_nid = get_nid(tvb, LNET_NID_SRC_OFFSET);*/

		/*[> col_add_fstr(pinfo->cinfo, COL_INFO, "%s@tcp%d > %s@tcp%d",
			ip_to_str((guint8 *) &src_nid.addr), src_nid.interface,
			ip_to_str((guint8 *) & dest_nid.addr), dest_nid.interface); */

		msg_type = tvb_get_letohl(tvb, LNET_MSG_TYPE_OFFSET );
		/* We delete the entire line and add LNET  + msg_type */
		col_add_fstr(pinfo->cinfo, COL_INFO, "LNET_%s", (msg_type < sizeof(lnet_msg_type_t)/sizeof(value_string)) ? lnet_msg_type_t[msg_type].strptr : "Unknow") ; 
	}

	if (tree) {
		t_nid dest_nid ; /* nid value */
		t_nid src_nid ; 


		proto_item *ti = NULL; /* principal  node */
		proto_tree *lnet_tree = NULL ; /* principal tree */
		proto_tree *lnet_nid_src_tree= NULL ; /*subtree for the nids*/
		proto_tree *lnet_nid_dest_tree= NULL ; 
		proto_item *ti_src_nid ; /* node for the nids */
		proto_item *ti_dest_nid ; 

		gint offset = 0 ; 

		guint32 msg_type ;
		guint32 payload_length; 
		guint32 msg_filler_length;


		ti = proto_tree_add_item(tree,proto_lnet,tvb,0,-1,FALSE); /* principal node */ 
		/*	ti=proto_tree_add_protocol_format(tree, proto_lnet, tvb, 0, -1, "Lnet"); */

		lnet_tree = proto_item_add_subtree(ti,ett_lnet); /* add the subtree*/

		/* dissect the 24first bytes (ksock_msg_t in lnet/socklnd.h */
		offset=dissect_ksock_msg(tvb,lnet_tree,offset);

		/* dest nid */
		dest_nid = get_nid(tvb, LNET_NID_DEST_OFFSET);
		ti_dest_nid = proto_tree_add_text(lnet_tree, tvb, offset, 8, "dest_nid = %s@tcp%d", ip_to_str((guint8 *) &dest_nid.addr), dest_nid.interface);
		lnet_nid_dest_tree = proto_item_add_subtree(ti_dest_nid,ett_lnet_dest_nid) ; 
		offset=dissect_dest_nid(tvb,lnet_nid_dest_tree,offset); 

		/* same for src_nid */
		src_nid = get_nid(tvb, LNET_NID_SRC_OFFSET);
		ti_src_nid = proto_tree_add_text(lnet_tree, tvb, offset, 8, "src_nid = %s@tcp%d", ip_to_str((guint8 *) &src_nid.addr), src_nid.interface);
		lnet_nid_src_tree = proto_item_add_subtree(ti_src_nid,ett_lnet_src_nid) ; 
		offset=dissect_src_nid(tvb,lnet_nid_src_tree,offset);

		/* pid */
		proto_tree_add_item(lnet_tree, hf_lnet_src_pid, tvb, offset, 4, TRUE); offset+=4;
		proto_tree_add_item(lnet_tree, hf_lnet_dest_pid, tvb, offset, 4, TRUE); offset+=4;

		/* message_type (32 bits) */
		msg_type = tvb_get_letohl(tvb, offset+0);
		/* put some nice info on lnet line */ 
		proto_item_append_text(ti," %s", (msg_type < sizeof(lnet_msg_type_t)/sizeof(value_string)) ? lnet_msg_type_t[msg_type].strptr : "Unknow") ;  /* rajout de l'info dans l'arbre */
		proto_tree_add_item(lnet_tree, hf_lnet_msg_type, tvb, offset, 4, TRUE); offset+=4;

		/* payload data (to follow) length :*/
		payload_length = tvb_get_letohl(tvb,offset+0); 	
		proto_tree_add_item(lnet_tree, hf_lnet_payload_length, tvb, offset, 4, TRUE); offset+=4;

		/* here offset = 24+8+8+4+4+4+4 = 56 */
		match = 0 ;
		switch(msg_type) {
			case LNET_MSG_ACK:
				offset=dissect_lnet_ack(tvb,lnet_tree,offset,pinfo);
				match = tvb_get_letoh64(tvb,72 );
				break;
			case LNET_MSG_PUT:
				offset=dissect_lnet_put(tvb,lnet_tree,offset,pinfo);
				match = tvb_get_letoh64(tvb, 72);
				break;
			case LNET_MSG_GET:
				offset=dissect_lnet_get(tvb,lnet_tree,offset,pinfo);
				match = tvb_get_letoh64(tvb, 72);
				break;
			case LNET_MSG_REPLY:
				offset=dissect_lnet_reply(tvb,lnet_tree,offset);
				break;
			case LNET_MSG_HELLO:
				offset=dissect_lnet_hello(tvb,lnet_tree,offset);
				break;
			default:
				break;
		}


		conversation_val = get_lnet_conv(pinfo , lnet_request_hash, match );
		/*	proto_tree_add_text(tree, tvb, 0 , 0, "match = %" G_GINT64_MODIFIER "u parent = %d", conversation_val -> match_bits , conversation_val -> packet_num_parent); */


		/* padding */
		msg_filler_length = 72 - offset + 24 ; 
		if ( msg_filler_length > 72)
			return ;
		/*  +24 : ksosck_message take 24bytes, and allready in offset  */

		proto_tree_add_item(lnet_tree, hf_lnet_msg_filler, tvb, offset, msg_filler_length, TRUE);
		offset+=msg_filler_length;

		if (payload_length>0)
		{

			/* display of payload */ 
			proto_tree_add_item(lnet_tree,hf_lnet_payload, tvb, offset, payload_length, TRUE); 

			next_tvb = tvb_new_subset (tvb, offset, payload_length, payload_length);
			if(msg_type==LNET_MSG_PUT)
				dissector_try_port(subdissector_table, tvb_get_letohl(tvb,LNET_PTL_INDEX_OFFSET_PUT), next_tvb, pinfo, tree);

		}

		offset+=payload_length;
	} 
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

		{ &hf_lnet_src_nid            , 
			{ "Src nid"                   , "lnet.src_nid"                 , FT_UINT64 , BASE_HEX     , NULL                  , 0x0 , "src nid"  , HFILL }} , 
		{ &hf_lnet_src_nid_addr       , 
			{ "Src nid"                   , "lnet.src_nid_addr"            , FT_IPv4   , BASE_NONE    , NULL                  , 0x0 , ""         , HFILL }} , 
		{ &hf_lnet_src_nid_lnet_type  , 
			{ "lnd network type"          , "lnet.src_nid_type"            , FT_UINT16 , BASE_DEC     , VALS(lnetnames)       , 0x0 , ""         , HFILL }} , 
		{ &hf_lnet_src_nid_interface  , 
			{ "lnd network interface"     , "lnet.src_nid_net_interface"   , FT_UINT16 , BASE_DEC     , NULL                  , 0x0 , NULL       , HFILL }} , 

		{ &hf_lnet_dest_nid           , 
			{ "Dest nid"                  , "lnet.dest_nid"                , FT_UINT64 , BASE_HEX     , NULL                  , 0x0 , ""         , HFILL }} , 

		{ &hf_lnet_dest_nid_addr      , 
			{ "Destination nid"           , "lnet.dest_nid_addr"           , FT_IPv4   , BASE_NONE    , NULL                  , 0x0 , ""         , HFILL }} , 
		{ &hf_lnet_dest_nid_lnet_type , 
			{ "lnd network type"          , "lnet.dest_nid_type"           , FT_UINT16 , BASE_DEC     , VALS(lnetnames)       , 0x0 , ""         , HFILL }} , 
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
		lnet_handle = create_dissector_handle(dissect_lnet, proto_lnet);
		lnet_prefs_initialized = TRUE;
	}
	else {
		dissector_delete("tcp.port",global_lnet_tcp_port, lnet_handle);
	}

	lnet_tcp_port = global_lnet_tcp_port;

	dissector_add("tcp.port", lnet_tcp_port, lnet_handle);
}
