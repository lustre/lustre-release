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

#ifndef _LINUX_LUSTRE_REQ_LAYOUT_H__
#define _LINUX_LUSTRE_REQ_LAYOUT_H__

/* struct ptlrpc_request, lustre_msg* */
#include <linux/lustre_net.h>

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
        const struct req_format *rc_fmt[RCL_NR];
        __u32                    rc_swabbed;
        enum req_location        rc_loc;
};

void req_capsule_init(struct req_capsule *pill,
                      struct ptlrpc_request *req,
                      enum req_location location);
void req_capsule_fini(struct req_capsule *pill);

void req_capsule_client_init(struct req_capsule *pill,
                             const struct req_format *fmt);
void req_capsule_server_init(struct req_capsule *pill,
                             const struct req_format *fmt);
int req_capsule_start(struct req_capsule *pill,
                      const struct req_format *fmt, int *area);

const void *req_capsule_client_get(const struct req_capsule *pill,
                                   const struct req_msg_field *field);
void *req_capsule_server_get(const struct req_capsule *pill,
                             const struct req_msg_field *field);

int  req_layout_init(void);
void req_layout_fini(void);

extern const struct req_format RQF_MDS_GETSTATUS;
extern const struct req_format RQF_MDS_STATFS;
extern const struct req_format RQF_MDS_GETATTR;
extern const struct req_format RQF_MDS_GETATTR_NAME;
extern const struct req_format RQF_MDS_REINT_CREATE;

extern const struct req_msg_field RMF_MDT_BODY;
extern const struct req_msg_field RMF_OBD_STATFS;
extern const struct req_msg_field RMF_NAME;
extern const struct req_msg_field RMF_REC_CREATE;


#endif /* _LINUX_LUSTRE_REQ_LAYOUT_H__ */
