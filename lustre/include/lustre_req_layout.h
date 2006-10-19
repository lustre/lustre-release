/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/include/linux/lustre_req_layout.h
 *  Lustre Metadata Target (mdt) request handler
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef _LUSTRE_REQ_LAYOUT_H__
#define _LUSTRE_REQ_LAYOUT_H__

struct req_msg_field;
struct req_format;
struct req_capsule;

struct ptlrpc_request;

enum req_location {
        RCL_CLIENT,
        RCL_SERVER,
        RCL_NR
};

struct req_capsule {
        struct ptlrpc_request   *rc_req;
        const struct req_format *rc_fmt;
        __u32                    rc_swabbed;
        enum req_location        rc_loc;
        int                     *rc_area;
};

enum {
        /*
         * Maximal number of fields (buffers) in a request message.
         */
        REQ_MAX_FIELD_NR = 8
};

#if !defined(__REQ_LAYOUT_USER__)

/* struct ptlrpc_request, lustre_msg* */
#include <lustre_net.h>

void req_capsule_init(struct req_capsule *pill, struct ptlrpc_request *req,
                      enum req_location location, int *area);
void req_capsule_fini(struct req_capsule *pill);

void req_capsule_set(struct req_capsule *pill, const struct req_format *fmt);
int  req_capsule_pack(struct req_capsule *pill);

void *req_capsule_client_get(struct req_capsule *pill,
                             const struct req_msg_field *field);
void *req_capsule_server_get(struct req_capsule *pill,
                             const struct req_msg_field *field);
const void *req_capsule_other_get(struct req_capsule *pill,
                                  const struct req_msg_field *field);

void req_capsule_set_size(const struct req_capsule *pill,
                          const struct req_msg_field *field,
                          enum req_location loc, int size);
int req_capsule_get_size(const struct req_capsule *pill,
                          const struct req_msg_field *field,
                          enum req_location loc);
void req_capsule_extend(struct req_capsule *pill, const struct req_format *fmt);

int req_capsule_has_field(const struct req_capsule *pill,
                          const struct req_msg_field *field,
                          enum req_location loc);
int req_capsule_field_present(const struct req_capsule *pill,
                              const struct req_msg_field *field,
                              enum req_location loc);

int  req_layout_init(void);
void req_layout_fini(void);

/* __REQ_LAYOUT_USER__ */
#endif

extern const struct req_format RQF_SEQ_QUERY;
extern const struct req_format RQF_FLD_QUERY;
extern const struct req_format RQF_MDS_GETSTATUS;
extern const struct req_format RQF_MDS_STATFS;
extern const struct req_format RQF_MDS_SYNC;
extern const struct req_format RQF_MDS_GETXATTR;
extern const struct req_format RQF_MDS_SETXATTR;
extern const struct req_format RQF_MDS_GETATTR;
extern const struct req_format RQF_MDS_CLOSE;
extern const struct req_format RQF_MDS_PIN;
extern const struct req_format RQF_MDS_CONNECT;
extern const struct req_format RQF_MDS_DISCONNECT;
extern const struct req_format RQF_MDS_READPAGE;
extern const struct req_format RQF_MDS_WRITEPAGE;
extern const struct req_format RQF_MDS_IS_SUBDIR;
extern const struct req_format RQF_MDS_DONE_WRITING;

/*
 * This is format of direct (non-intent) MDS_GETATTR_NAME request.
 */
extern const struct req_format RQF_MDS_GETATTR_NAME;
extern const struct req_format RQF_MDS_REINT;
extern const struct req_format RQF_MDS_REINT_CREATE;
extern const struct req_format RQF_MDS_REINT_CREATE_RMT_ACL;
extern const struct req_format RQF_MDS_REINT_CREATE_SLAVE;
extern const struct req_format RQF_MDS_REINT_CREATE_SYM;
extern const struct req_format RQF_MDS_REINT_OPEN;
extern const struct req_format RQF_MDS_REINT_UNLINK;
extern const struct req_format RQF_MDS_REINT_LINK;
extern const struct req_format RQF_MDS_REINT_RENAME;
extern const struct req_format RQF_MDS_REINT_SETATTR;
extern const struct req_format RQF_LDLM_ENQUEUE;
extern const struct req_format RQF_LDLM_INTENT;
extern const struct req_format RQF_LDLM_INTENT_GETATTR;
extern const struct req_format RQF_LDLM_INTENT_OPEN;
extern const struct req_format RQF_LDLM_INTENT_CREATE;
extern const struct req_format RQF_LDLM_INTENT_UNLINK;

extern const struct req_msg_field RMF_PTLRPC_BODY;
extern const struct req_msg_field RMF_MDT_BODY;
extern const struct req_msg_field RMF_MDT_EPOCH;
extern const struct req_msg_field RMF_OBD_STATFS;
extern const struct req_msg_field RMF_NAME;
extern const struct req_msg_field RMF_SYMTGT;
extern const struct req_msg_field RMF_TGTUUID;
extern const struct req_msg_field RMF_CLUUID;
/*
 * connection handle received in MDS_CONNECT request.
 */
extern const struct req_msg_field RMF_CONN;
extern const struct req_msg_field RMF_CONNECT_DATA;
extern const struct req_msg_field RMF_DLM_REQ;
extern const struct req_msg_field RMF_DLM_REP;
extern const struct req_msg_field RMF_LDLM_INTENT;
extern const struct req_msg_field RMF_MDT_MD;
extern const struct req_msg_field RMF_REC_CREATE;
extern const struct req_msg_field RMF_REC_LINK;
extern const struct req_msg_field RMF_REC_UNLINK;
extern const struct req_msg_field RMF_REC_RENAME;
extern const struct req_msg_field RMF_REC_SETATTR;
extern const struct req_msg_field RMF_EADATA;
extern const struct req_msg_field RMF_ACL;
extern const struct req_msg_field RMF_LOGCOOKIES;
extern const struct req_msg_field RMF_REINT_OPC;
extern const struct req_msg_field RMF_CAPA1;
extern const struct req_msg_field RMF_CAPA2;

/* seq-mgr fields */
extern const struct req_msg_field RMF_SEQ_OPC;
extern const struct req_msg_field RMF_SEQ_RANGE;

/* FLD fields */
extern const struct req_msg_field RMF_FLD_OPC;
extern const struct req_msg_field RMF_FLD_MDFLD;

#endif /* _LUSTRE_REQ_LAYOUT_H__ */
