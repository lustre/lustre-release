/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2023-2025, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Yehuda Yitschak <yehuday@amazon.com>
 * Author: Yonatan Nachum <ynachum@amazon.com>
 */

#ifndef _EFALND_PROTO_H_
#define _EFALND_PROTO_H_

enum kefa_comp_status {
	/* Successful completion */
	KEFA_COMP_STATUS_OK				= 0,
	/* Unsupported operation */
	KEFA_COMP_STATUS_UNSUPPORTED_OP			= 1,
	/* No memory or pool empty on remote side */
	KEFA_COMP_STATUS_NO_MEMORY			= 2,
	/* Remote general error */
	KEFA_COMP_STATUS_GENERAL_ERROR			= 3,

	/* Failed to send message */
	KEFA_COMP_STATUS_COMM_FAILURE			= 20,
	/* No LNET message on remote side */
	KEFA_COMP_STATUS_NO_LNET_MSG			= 21,
	/* Failed translating BIO vector to SG list */
	KEFA_COMP_STATUS_BAD_ADDRESS			= 22,
	/* Failed mapping SG list (to device or MR) */
	KEFA_COMP_STATUS_DMA_FAILURE			= 23,
	/* Protocol not supported on remote side */
	KEFA_COMP_STATUS_UNSUPPORTED_PROTO		= 24,
};

struct kefa_nid_md_entry {
	lnet_nid_t nid;
	u8 gid[16];
	u16 qp_num;
	u32 qkey;
	u8 buffer[10];
} __packed;

struct kefa_qp_proto {
	u16 qp_num;
	u32 qkey;
} __packed;

struct kefa_rdma_desc {
	u32 key;			/* local/remote key */
	u64 addr;
	u32 nob;			/* # of bytes */
} __packed;

struct kefa_immediate_msg_v2 {
	struct lnet_hdr_nid16 hdr;	/* portals header */
	char payload[];			/* piggy-backed payload */
} __packed;

struct kefa_putr_req_msg_v2 {
	struct lnet_hdr_nid16 hdr;	/* portals header */
	u64 cookie;			/* opaque completion cookie */
	struct kefa_rdma_desc rdma_desc;/* src rdma desc */
} __packed;

struct kefa_getr_req_msg_v2 {
	struct lnet_hdr_nid16 hdr;	/* portals header */
	u64 sink_cookie;		/* opaque completion cookie */
} __packed;

struct kefa_getr_ack_msg {
	u64 sink_cookie;		/* opaque completion cookie */
	u64 src_cookie;			/* opaque completion cookie */
	struct kefa_rdma_desc rdma_desc;/* src rdma desc */
} __packed;

struct kefa_completion_msg {
	u64 cookie;			/* opaque completion cookie */
	s16 status;			/* enum kefa_comp_status */
} __packed;

struct kefa_conn_probe_msg {
	u16 lnd_ver;			/* LND version */
	u8 src_gid[16];			/* GID in raw format */
	u64 src_epoch;			/* Sender's epoch */
	struct kefa_qp_proto cm_qp;
	u64 caps;			/* Capabilities bit array */
} __packed;

struct kefa_conn_probe_resp_msg {
	u16 lnd_ver;			/* LND version */
	s16 status;			/* enum kefa_comp_status */
	u64 src_epoch;			/* Responder's epoch */
	u64 caps;			/* Capabilities bit array */
	u8 min_proto_ver;		/* Min supported protocol version */
	u8 max_proto_ver;		/* Max supported protocol version */
} __packed;

struct kefa_conn_req_msg {
	/* Optional for skipping conn probe */
	u16 lnd_ver;			/* LND version */
	u8 src_gid[16];			/* GID in raw format */
	u64 src_epoch;			/* Sender's epoch */
	struct kefa_qp_proto cm_qp;
	u64 caps;			/* Capabilities bit array */
	u64 reserved;
	u64 requests;			/* Requests bit array */
	u32 src_conn_id;		/* Sender's connection ID */
	u32 nqps;			/* Number of data QPs on the array */
	struct kefa_qp_proto data_qps[]; /* Data QPs array */
} __packed;

struct kefa_conn_req_ack {
	u16 lnd_ver;			/* LND version */
	u64 src_epoch;			/* Responder's epoch */
	u64 caps;			/* Capabilities bit array */
	u64 reserved;
	s16 status;			/* enum kefa_comp_status */
	u32 src_conn_id;		/* Responder's connection ID */
	u32 nqps;			/* Number of data QPs on the array */
	struct kefa_qp_proto data_qps[]; /* Data QPs array */
} __packed;

struct kefa_msg_v1 {
	lnet_nid_t srcnid;		/* sender's NID */
	lnet_nid_t dstnid;		/* destination's NID */
	u64 dst_epoch;			/* destination's epoch */
	u32 dst_conn_id;		/* ID for fast connection retrieval */
	u8 credits;			/* returned credits */

	union {
		struct kefa_conn_probe_msg conn_probe;
		struct kefa_conn_probe_resp_msg conn_probe_resp;
	} __packed u;
	/* No additional fields can be added after the union. */
} __packed;

struct kefa_msg_v2 {
	struct lnet_nid srcnid;		/* sender's NID */
	struct lnet_nid dstnid;		/* destination's NID */
	u64 dst_epoch;			/* destination's epoch */
	u32 dst_conn_id;		/* ID for fast connection retrieval */
	u8 credits;			/* returned credits */

	union {
		struct kefa_immediate_msg_v2 immediate;
		struct kefa_putr_req_msg_v2 putr_req;
		struct kefa_getr_req_msg_v2 getr_req;
		struct kefa_getr_ack_msg getr_ack;
		struct kefa_completion_msg completion;
		struct kefa_conn_probe_msg conn_probe;
		struct kefa_conn_probe_resp_msg conn_probe_resp;
		struct kefa_conn_req_msg conn_request;
		struct kefa_conn_req_ack conn_request_ack;
	} __packed u;
	/* No additional fields can be added after the union. */
} __packed;

struct kefa_hdr {
	/* First 3 fields fixed FOR ALL TIME */
	u32 magic;			/* I'm an efanal message */
	u8 proto_ver;			/* this is my protocol version number */
	u8 type;			/* efa msg type */
	u16 nob;			/* # bytes in whole message */
} __packed;

struct kefa_msg {
	struct kefa_hdr hdr;
	union {
		struct kefa_msg_v1 msg_v1;
		struct kefa_msg_v2 msg_v2;
	} __packed;
	/* No additional fields can be added after the union. */
} __packed;

#define EFALND_MSG_MAGIC LNET_PROTO_EFA_MAGIC	/* unique magic */

#define EFALND_PROTO_VER_1	0x81
#define EFALND_PROTO_VER_2	0x82
#define EFALND_MIN_PROTO_VER	EFALND_PROTO_VER_1
#define EFALND_MAX_PROTO_VER	EFALND_PROTO_VER_2

#define EFALND_MSG_RESERVED		0x00
#define EFALND_MSG_CONN_PROBE		0x01	/* connection probe */
#define EFALND_MSG_CONN_PROBE_RESP	0x02	/* connection probe response */
#define EFALND_MSG_CONN_REQ		0x03	/* connection request */
#define EFALND_MSG_CONN_REQ_ACK		0x04	/* connection request ack */
#define EFALND_MSG_IMMEDIATE		0x05	/* immediate */
#define EFALND_MSG_NACK			0x06	/* put/get request - nak */
#define EFALND_MSG_PUTR_REQ		0x07	/* put request - READ based */
#define EFALND_MSG_PUTR_DONE		0x08	/* put done - READ based */
#define EFALND_MSG_GETR_REQ		0x09	/* get request - READ based */
#define EFALND_MSG_GETR_ACK		0x0a	/* get request - READ based ack */
#define EFALND_MSG_GETR_DONE		0x0b	/* get request - completed */
#define EFALND_MSG_MAX			0x0c

#endif
