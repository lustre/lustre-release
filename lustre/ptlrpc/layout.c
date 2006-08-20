/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/ptlrpc/layout.c
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

#if !defined(__REQ_LAYOUT_USER__)

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_RPC

#ifdef __KERNEL__
#include <linux/module.h>
#else
# include <liblustre.h>
#endif

/* LUSTRE_VERSION_CODE */
#include <lustre_ver.h>

#include <obd_support.h>
/* lustre_swab_mdt_body */
#include <lustre/lustre_idl.h>
/* obd2cli_tgt() (required by DEBUG_REQ()) */
#include <obd.h>

/* __REQ_LAYOUT_USER__ */
#endif
/* struct ptlrpc_request, lustre_msg* */
#include <lustre_req_layout.h>
#include <linux/lustre_acl.h>

#if __KERNEL__
#define __POSIX_ACL_MAX_SIZE \
        (sizeof(xattr_acl_header) + 32 * sizeof(xattr_acl_entry))
#else
#define __POSIX_ACL_MAX_SIZE 0
#endif

static const struct req_msg_field *empty[] = {}; /* none */

static const struct req_msg_field *mdt_body_only[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_BODY
};

static const struct req_msg_field *mds_statfs_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_OBD_STATFS
};

static const struct req_msg_field *seq_query_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_SEQ_OPC
};

static const struct req_msg_field *seq_query_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_SEQ_RANGE
};

static const struct req_msg_field *fld_query_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_FLD_OPC,
        &RMF_FLD_MDFLD
};

static const struct req_msg_field *fld_query_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_FLD_MDFLD
};

static const struct req_msg_field *mds_getattr_name_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_BODY,
        &RMF_NAME
};

static const struct req_msg_field *mds_reint_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REINT_OPC
};

static const struct req_msg_field *mds_reint_create_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_CREATE,
        &RMF_NAME,
        &RMF_SYMTGT
};

static const struct req_msg_field *mds_reint_open_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_CREATE,
        &RMF_NAME,
        &RMF_EADATA
};

static const struct req_msg_field *mds_reint_open_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_BODY,
        &RMF_MDT_MD,
        &RMF_ACL
};

static const struct req_msg_field *mds_reint_unlink_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_UNLINK,
        &RMF_NAME
};

static const struct req_msg_field *mds_reint_link_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_LINK,
        &RMF_NAME
};

static const struct req_msg_field *mds_reint_rename_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_RENAME,
        &RMF_NAME,
        &RMF_SYMTGT
};

static const struct req_msg_field *mds_last_unlink_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_BODY,
        &RMF_MDT_MD,
        &RMF_LOGCOOKIES
};

static const struct req_msg_field *mds_reint_setattr_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_SETATTR,
        &RMF_EADATA,
        &RMF_LOGCOOKIES
};

static const struct req_msg_field *mds_connect_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_TGTUUID,
        &RMF_CLUUID,
        &RMF_CONN,
        &RMF_CONNECT_DATA
};

static const struct req_msg_field *mds_connect_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_CONNECT_DATA
};

static const struct req_msg_field *ldlm_enqueue_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REQ
};

static const struct req_msg_field *ldlm_enqueue_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REP
};

static const struct req_msg_field *ldlm_intent_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REQ,
        &RMF_LDLM_INTENT,
        &RMF_REINT_OPC
};

static const struct req_msg_field *ldlm_intent_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REP,
        &RMF_MDT_BODY,
        &RMF_MDT_MD,
        &RMF_ACL
};

static const struct req_msg_field *ldlm_intent_getattr_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REQ,
        &RMF_LDLM_INTENT,
        &RMF_MDT_BODY,     /* coincides with mds_getattr_name_client[] */
        &RMF_NAME
};

static const struct req_msg_field *ldlm_intent_create_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REQ,
        &RMF_LDLM_INTENT,
        &RMF_REC_CREATE,    /* coincides with mds_reint_create_client[] */
        &RMF_NAME,
        &RMF_EADATA
};

static const struct req_msg_field *ldlm_intent_open_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REQ,
        &RMF_LDLM_INTENT,
        &RMF_REC_CREATE,    /* coincides with mds_reint_open_client[] */
        &RMF_NAME,
        &RMF_EADATA
};

static const struct req_msg_field *ldlm_intent_unlink_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REQ,
        &RMF_LDLM_INTENT,
        &RMF_REC_UNLINK,    /* coincides with mds_reint_unlink_client[] */
        &RMF_NAME
};

static const struct req_msg_field *mds_getxattr_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_BODY,
        &RMF_NAME
};

static const struct req_msg_field *mds_getxattr_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_BODY,
        &RMF_EADATA
};

static const struct req_msg_field *mds_setxattr_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_BODY,
        &RMF_NAME,
        &RMF_EADATA
};

static const struct req_msg_field *mds_getattr_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_BODY,
        &RMF_MDT_MD,
        &RMF_ACL
};

static const struct req_format *req_formats[] = {
        &RQF_MDS_CONNECT,
        &RQF_MDS_DISCONNECT,
        &RQF_MDS_GETSTATUS,
        &RQF_MDS_STATFS,
        &RQF_MDS_GETATTR,
        &RQF_MDS_GETATTR_NAME,
        &RQF_MDS_REINT,
        &RQF_MDS_REINT_CREATE,
        &RQF_MDS_REINT_OPEN,
        &RQF_MDS_REINT_UNLINK,
        &RQF_MDS_REINT_LINK,
        &RQF_MDS_REINT_RENAME,
        &RQF_MDS_REINT_SETATTR,
        &RQF_LDLM_ENQUEUE,
        &RQF_LDLM_INTENT,
        &RQF_LDLM_INTENT_GETATTR,
        &RQF_LDLM_INTENT_OPEN,
        &RQF_LDLM_INTENT_CREATE,
        &RQF_LDLM_INTENT_UNLINK,
        &RQF_SEQ_QUERY,
        &RQF_FLD_QUERY,
        &RQF_MDS_GETXATTR,
        &RQF_MDS_SETXATTR,
        &RQF_MDS_SYNC,
        &RQF_MDS_CLOSE,
        &RQF_MDS_PIN,
        &RQF_MDS_READPAGE,
        &RQF_MDS_DONE_WRITING,
};

struct req_msg_field {
        __u32       rmf_flags;
        const char *rmf_name;
        /*
         * Field length. (-1) means "variable length".
         */
        int         rmf_size;
        void      (*rmf_swabber)(void *);
        int         rmf_offset[ARRAY_SIZE(req_formats)][RCL_NR];
};

enum rmf_flags {
        RMF_F_STRING = 1 << 0
};

struct req_capsule;

/*
 * Request fields.
 */
#define DEFINE_MSGF(name, flags, size, swabber) {       \
        .rmf_name    = (name),                          \
        .rmf_flags   = (flags),                         \
        .rmf_size    = (size),                          \
        .rmf_swabber = (void (*)(void*))(swabber)       \
}

const struct req_msg_field RMF_SEQ_OPC =
        DEFINE_MSGF("seq_query_opc", 0,
                    sizeof(__u32), lustre_swab_generic_32s);
EXPORT_SYMBOL(RMF_SEQ_OPC);

const struct req_msg_field RMF_SEQ_RANGE =
        DEFINE_MSGF("seq_query_range", 0,
                    sizeof(struct lu_range), lustre_swab_lu_range);
EXPORT_SYMBOL(RMF_SEQ_RANGE);

const struct req_msg_field RMF_FLD_OPC =
        DEFINE_MSGF("fld_query_opc", 0,
                    sizeof(__u32), lustre_swab_generic_32s);
EXPORT_SYMBOL(RMF_FLD_OPC);

const struct req_msg_field RMF_FLD_MDFLD =
        DEFINE_MSGF("fld_query_mdfld", 0,
                    sizeof(struct md_fld), lustre_swab_md_fld);
EXPORT_SYMBOL(RMF_FLD_MDFLD);

const struct req_msg_field RMF_MDT_BODY =
        DEFINE_MSGF("mdt_body", 0,
                    sizeof(struct mdt_body), lustre_swab_mdt_body);
EXPORT_SYMBOL(RMF_MDT_BODY);

const struct req_msg_field RMF_PTLRPC_BODY =
        DEFINE_MSGF("ptlrpc_body", 0,
                    sizeof(struct ptlrpc_body), lustre_swab_ptlrpc_body);
EXPORT_SYMBOL(RMF_PTLRPC_BODY);

const struct req_msg_field RMF_OBD_STATFS =
        DEFINE_MSGF("obd_statfs", 0,
                    sizeof(struct obd_statfs), lustre_swab_obd_statfs);
EXPORT_SYMBOL(RMF_OBD_STATFS);

const struct req_msg_field RMF_NAME =
        DEFINE_MSGF("name", RMF_F_STRING, -1, NULL);
EXPORT_SYMBOL(RMF_NAME);

const struct req_msg_field RMF_SYMTGT =
        DEFINE_MSGF("symtgt", RMF_F_STRING, -1, NULL);
EXPORT_SYMBOL(RMF_SYMTGT);

const struct req_msg_field RMF_TGTUUID =
        DEFINE_MSGF("tgtuuid", RMF_F_STRING, sizeof(struct obd_uuid) - 1, NULL);
EXPORT_SYMBOL(RMF_TGTUUID);

const struct req_msg_field RMF_CLUUID =
        DEFINE_MSGF("cluuid", RMF_F_STRING, sizeof(struct obd_uuid) - 1, NULL);
EXPORT_SYMBOL(RMF_CLUUID);

/*
 * connection handle received in MDS_CONNECT request.
 *
 * XXX no swabbing?
 */
const struct req_msg_field RMF_CONN =
        DEFINE_MSGF("conn", 0, sizeof(struct lustre_handle), NULL);
EXPORT_SYMBOL(RMF_CONN);

const struct req_msg_field RMF_CONNECT_DATA =
        DEFINE_MSGF("cdata", 0,
                    sizeof(struct obd_connect_data), lustre_swab_connect);
EXPORT_SYMBOL(RMF_CONNECT_DATA);

const struct req_msg_field RMF_DLM_REQ =
        DEFINE_MSGF("dlm_req", 0,
                    sizeof(struct ldlm_request), lustre_swab_ldlm_request);
EXPORT_SYMBOL(RMF_DLM_REQ);

const struct req_msg_field RMF_DLM_REP =
        DEFINE_MSGF("dlm_rep", 0,
                    sizeof(struct ldlm_reply), lustre_swab_ldlm_reply);
EXPORT_SYMBOL(RMF_DLM_REP);

const struct req_msg_field RMF_LDLM_INTENT =
        DEFINE_MSGF("ldlm_intent", 0,
                    sizeof(struct ldlm_intent), lustre_swab_ldlm_intent);
EXPORT_SYMBOL(RMF_LDLM_INTENT);


/* FIXME XXX by Huang Hua
 * to make sure about the size. Refer to MDS.
 */

const struct req_msg_field RMF_MDT_MD =
        DEFINE_MSGF("mdt_md", 0, MIN_MD_SIZE, lustre_swab_lov_mds_md);
EXPORT_SYMBOL(RMF_MDT_MD);

const struct req_msg_field RMF_REC_UNLINK =
        DEFINE_MSGF("rec_unlink", 0, sizeof(struct mdt_rec_unlink),
                    lustre_swab_mdt_rec_unlink);
EXPORT_SYMBOL(RMF_REC_UNLINK);

const struct req_msg_field RMF_REC_LINK =
        DEFINE_MSGF("rec_link", 0, sizeof(struct mdt_rec_link),
                    lustre_swab_mdt_rec_link);
EXPORT_SYMBOL(RMF_REC_LINK);

const struct req_msg_field RMF_REC_RENAME =
        DEFINE_MSGF("rec_rename", 0, sizeof(struct mdt_rec_rename),
                    lustre_swab_mdt_rec_rename);
EXPORT_SYMBOL(RMF_REC_RENAME);

const struct req_msg_field RMF_REC_CREATE =
        DEFINE_MSGF("rec_create", 0,
                    sizeof(struct mdt_rec_create), lustre_swab_mdt_rec_create);
EXPORT_SYMBOL(RMF_REC_CREATE);

const struct req_msg_field RMF_REC_SETATTR =
        DEFINE_MSGF("rec_setattr", 0, sizeof(struct mdt_rec_setattr),
                    lustre_swab_mdt_rec_setattr);
EXPORT_SYMBOL(RMF_REC_SETATTR);

/* FIXME: this length should be defined as a macro */
const struct req_msg_field RMF_EADATA = DEFINE_MSGF("eadata", 0, -1, NULL);
EXPORT_SYMBOL(RMF_EADATA);

const struct req_msg_field RMF_ACL = DEFINE_MSGF("acl", 0, 
                                     __POSIX_ACL_MAX_SIZE, NULL);
EXPORT_SYMBOL(RMF_ACL);

const struct req_msg_field RMF_LOGCOOKIES =
        DEFINE_MSGF("logcookies", 0, sizeof(struct llog_cookie), NULL);
EXPORT_SYMBOL(RMF_LOGCOOKIES);

const struct req_msg_field RMF_REINT_OPC =
        DEFINE_MSGF("reint_opc", 0, sizeof(__u32), lustre_swab_generic_32s);
EXPORT_SYMBOL(RMF_REINT_OPC);

/*
 * Request formats.
 */

struct req_format {
        const char *rf_name;
        int         rf_idx;
        struct {
                int                          nr;
                const struct req_msg_field **d;
        } rf_fields[RCL_NR];
};

#define DEFINE_REQ_FMT(name, client, client_nr, server, server_nr) {    \
        .rf_name   = name,                                              \
        .rf_fields = {                                                  \
                [RCL_CLIENT] = {                                        \
                        .nr = client_nr,                                \
                        .d  = client                                    \
                },                                                      \
                [RCL_SERVER] = {                                        \
                        .nr = server_nr,                                \
                        .d  = server                                    \
                }                                                       \
        }                                                               \
}

#define DEFINE_REQ_FMT0(name, client, server)                           \
DEFINE_REQ_FMT(name, client, ARRAY_SIZE(client), server, ARRAY_SIZE(server))

const struct req_format RQF_SEQ_QUERY =
        DEFINE_REQ_FMT0("SEQ_QUERY", seq_query_client, seq_query_server);
EXPORT_SYMBOL(RQF_SEQ_QUERY);

const struct req_format RQF_FLD_QUERY =
        DEFINE_REQ_FMT0("FLD_QUERY", fld_query_client, fld_query_server);
EXPORT_SYMBOL(RQF_FLD_QUERY);

const struct req_format RQF_MDS_GETSTATUS =
        DEFINE_REQ_FMT0("MDS_GETSTATUS", empty, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_GETSTATUS);

const struct req_format RQF_MDS_STATFS =
        DEFINE_REQ_FMT0("MDS_STATFS", empty, mds_statfs_server);
EXPORT_SYMBOL(RQF_MDS_STATFS);

const struct req_format RQF_MDS_SYNC =
        DEFINE_REQ_FMT0("MDS_SYNC", mdt_body_only, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_SYNC);

const struct req_format RQF_MDS_GETATTR =
        DEFINE_REQ_FMT0("MDS_GETATTR", mdt_body_only, mds_getattr_server);
EXPORT_SYMBOL(RQF_MDS_GETATTR);

const struct req_format RQF_MDS_GETXATTR =
        DEFINE_REQ_FMT0("MDS_GETXATTR",
                        mds_getxattr_client, mds_getxattr_server);
EXPORT_SYMBOL(RQF_MDS_GETXATTR);

const struct req_format RQF_MDS_SETXATTR =
        DEFINE_REQ_FMT0("MDS_SETXATTR", mds_setxattr_client, empty);
EXPORT_SYMBOL(RQF_MDS_SETXATTR);

const struct req_format RQF_MDS_GETATTR_NAME =
        DEFINE_REQ_FMT0("MDS_GETATTR_NAME",
                        mds_getattr_name_client, mds_getattr_server);
EXPORT_SYMBOL(RQF_MDS_GETATTR_NAME);

const struct req_format RQF_MDS_REINT =
        DEFINE_REQ_FMT0("MDS_REINT", mds_reint_client, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_REINT);

const struct req_format RQF_MDS_REINT_CREATE =
        DEFINE_REQ_FMT0("MDS_REINT_CREATE",
                        mds_reint_create_client, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_REINT_CREATE);

const struct req_format RQF_MDS_REINT_OPEN =
        DEFINE_REQ_FMT0("MDS_REINT_OPEN",
                        mds_reint_open_client, mds_reint_open_server);
EXPORT_SYMBOL(RQF_MDS_REINT_OPEN);

const struct req_format RQF_MDS_REINT_UNLINK =
        DEFINE_REQ_FMT0("MDS_REINT_UNLINK", mds_reint_unlink_client,
                        mds_last_unlink_server);
EXPORT_SYMBOL(RQF_MDS_REINT_UNLINK);

const struct req_format RQF_MDS_REINT_LINK =
        DEFINE_REQ_FMT0("MDS_REINT_LINK",
                        mds_reint_link_client, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_REINT_LINK);

const struct req_format RQF_MDS_REINT_RENAME =
        DEFINE_REQ_FMT0("MDS_REINT_RENAME", mds_reint_rename_client,
                        mds_last_unlink_server);
EXPORT_SYMBOL(RQF_MDS_REINT_RENAME);

const struct req_format RQF_MDS_REINT_SETATTR =
        DEFINE_REQ_FMT0("MDS_REINT_SETATTR",
                        mds_reint_setattr_client, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_REINT_SETATTR);

const struct req_format RQF_MDS_CONNECT =
        DEFINE_REQ_FMT0("MDS_CONNECT",
                        mds_connect_client, mds_connect_server);
EXPORT_SYMBOL(RQF_MDS_CONNECT);

const struct req_format RQF_MDS_DISCONNECT =
        DEFINE_REQ_FMT0("MDS_DISCONNECT", empty, empty);
EXPORT_SYMBOL(RQF_MDS_DISCONNECT);

const struct req_format RQF_LDLM_ENQUEUE =
        DEFINE_REQ_FMT0("LDLM_ENQUEUE",
                        ldlm_enqueue_client, ldlm_enqueue_server);
EXPORT_SYMBOL(RQF_LDLM_ENQUEUE);

const struct req_format RQF_LDLM_INTENT =
        DEFINE_REQ_FMT0("LDLM_INTENT",
                        ldlm_intent_client, ldlm_intent_server);
EXPORT_SYMBOL(RQF_LDLM_INTENT);

const struct req_format RQF_LDLM_INTENT_GETATTR =
        DEFINE_REQ_FMT0("LDLM_INTENT_GETATTR",
                        ldlm_intent_getattr_client, ldlm_intent_server);
EXPORT_SYMBOL(RQF_LDLM_INTENT_GETATTR);

const struct req_format RQF_LDLM_INTENT_OPEN =
        DEFINE_REQ_FMT0("LDLM_INTENT_OPEN",
                        ldlm_intent_open_client, ldlm_intent_server);
EXPORT_SYMBOL(RQF_LDLM_INTENT_OPEN);

const struct req_format RQF_LDLM_INTENT_CREATE =
        DEFINE_REQ_FMT0("LDLM_INTENT_CREATE",
                        ldlm_intent_create_client, ldlm_intent_server);
EXPORT_SYMBOL(RQF_LDLM_INTENT_CREATE);

const struct req_format RQF_LDLM_INTENT_UNLINK =
        DEFINE_REQ_FMT0("LDLM_INTENT_UNLINK",
                        ldlm_intent_unlink_client, ldlm_intent_server);
EXPORT_SYMBOL(RQF_LDLM_INTENT_UNLINK);

const struct req_format RQF_MDS_CLOSE =
        DEFINE_REQ_FMT0("MDS_CLOSE",
                        mdt_body_only, mds_last_unlink_server);
EXPORT_SYMBOL(RQF_MDS_CLOSE);

const struct req_format RQF_MDS_PIN =
        DEFINE_REQ_FMT0("MDS_PIN",
                        mdt_body_only, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_PIN);

const struct req_format RQF_MDS_DONE_WRITING =
        DEFINE_REQ_FMT0("MDS_DONE_WRITING",
                        mdt_body_only, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_DONE_WRITING);

const struct req_format RQF_MDS_READPAGE =
        DEFINE_REQ_FMT0("MDS_READPAGE",
                        mdt_body_only, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_READPAGE);

#if !defined(__REQ_LAYOUT_USER__)

int req_layout_init(void)
{
        int i;
        int j;
        int k;

        for (i = 0; i < ARRAY_SIZE(req_formats); ++i) {
                struct req_format *rf;

                rf = (struct req_format *)req_formats[i];
                rf->rf_idx = i;
                for (j = 0; j < RCL_NR; ++j) {
                        for (k = 0; k < rf->rf_fields[j].nr; ++k) {
                                struct req_msg_field *field;

                                field = (typeof(field))rf->rf_fields[j].d[k];
                                LASSERT(field->rmf_offset[i][j] == 0);
                                /*
                                 * k + 1 to detect unused format/field
                                 * combinations.
                                 */
                                field->rmf_offset[i][j] = k + 1;
                        }
                }
        }
        return 0;
}
EXPORT_SYMBOL(req_layout_init);

void req_layout_fini(void)
{
}
EXPORT_SYMBOL(req_layout_fini);

void req_capsule_init(struct req_capsule *pill,
                      struct ptlrpc_request *req, enum req_location location,
                      int *area)
{
        LASSERT(location == RCL_SERVER || location == RCL_CLIENT);

        memset(pill, 0, sizeof *pill);
        pill->rc_req = req;
        pill->rc_loc = location;
        pill->rc_area = area;
}
EXPORT_SYMBOL(req_capsule_init);

void req_capsule_fini(struct req_capsule *pill)
{
}
EXPORT_SYMBOL(req_capsule_fini);

static int __req_format_is_sane(const struct req_format *fmt)
{
        return
                0 <= fmt->rf_idx && fmt->rf_idx < ARRAY_SIZE(req_formats) &&
                req_formats[fmt->rf_idx] == fmt;
}

static struct lustre_msg *__req_msg(const struct req_capsule *pill,
                                    enum req_location loc)
{
        struct ptlrpc_request *req;

        req = pill->rc_req;
        return loc == RCL_CLIENT ? req->rq_reqmsg : req->rq_repmsg;
}

void req_capsule_set(struct req_capsule *pill, const struct req_format *fmt)
{
        LASSERT(pill->rc_fmt == NULL);
        LASSERT(__req_format_is_sane(fmt));

        pill->rc_fmt = fmt;
}
EXPORT_SYMBOL(req_capsule_set);

int req_capsule_pack(struct req_capsule *pill)
{
        int i;
        int nr;
        int result;
        int total;

        const struct req_format *fmt;

        LASSERT(pill->rc_loc == RCL_SERVER);
        fmt = pill->rc_fmt;
        LASSERT(fmt != NULL);

        nr = fmt->rf_fields[RCL_SERVER].nr;
        for (total = 0, i = 0; i < nr; ++i) {
                int *size;

                size = &pill->rc_area[i];
                if (*size == -1) {
                        *size = fmt->rf_fields[RCL_SERVER].d[i]->rmf_size;
                        LASSERT(*size != -1);
                }
                total += *size;
        }
        result = lustre_pack_reply(pill->rc_req, nr, pill->rc_area, NULL);
        if (result != 0) {
                DEBUG_REQ(D_ERROR, pill->rc_req,
                          "Cannot pack %d fields (%d bytes) in format `%s': ",
                          nr, total, fmt->rf_name);
        }
        return result;
}
EXPORT_SYMBOL(req_capsule_pack);

static int __req_capsule_offset(const struct req_capsule *pill,
                                const struct req_msg_field *field,
                                enum req_location loc)
{
        int offset;

        offset = field->rmf_offset[pill->rc_fmt->rf_idx][loc];
        LASSERT(offset > 0);
        offset --;
        LASSERT(0 <= offset && offset < (sizeof(pill->rc_swabbed) << 3));
        return offset;
}

static void *__req_capsule_get(struct req_capsule *pill,
                               const struct req_msg_field *field,
                               enum req_location loc)
{
        const struct req_format *fmt;
        struct lustre_msg       *msg;
        void                    *value;
        int                      len;
        int                      offset;

        void *(*getter)(struct lustre_msg *m, int n, int minlen);

        static const char *rcl_names[RCL_NR] = {
                [RCL_CLIENT] = "client",
                [RCL_SERVER] = "server"
        };

        fmt = pill->rc_fmt;
        LASSERT(fmt != NULL);
        LASSERT(__req_format_is_sane(fmt));

        offset = __req_capsule_offset(pill, field, loc);

        msg = __req_msg(pill, loc);

        getter = (field->rmf_flags & RMF_F_STRING) ?
                (typeof(getter))lustre_msg_string : lustre_msg_buf;

        len = max(field->rmf_size, 0);
        value = getter(msg, offset, len);

        if (!(pill->rc_swabbed & (1 << offset)) && loc != pill->rc_loc &&
            field->rmf_swabber != NULL && value != NULL &&
            lustre_msg_swabbed(msg)) {
                field->rmf_swabber(value);
                pill->rc_swabbed |= (1 << offset);
        }
        if (value == NULL)
                DEBUG_REQ(D_ERROR, pill->rc_req,
                          "Wrong buffer for field `%s' (%d of %d) "
                          "in format `%s': %d vs. %d (%s)\n",
                          field->rmf_name, offset, lustre_msg_bufcount(msg), fmt->rf_name,
                          lustre_msg_buflen(msg, offset), field->rmf_size,
                          rcl_names[loc]);
        return value;
}

void *req_capsule_client_get(struct req_capsule *pill,
                             const struct req_msg_field *field)
{
        return __req_capsule_get(pill, field, RCL_CLIENT);
}
EXPORT_SYMBOL(req_capsule_client_get);

void *req_capsule_server_get(struct req_capsule *pill,
                             const struct req_msg_field *field)
{
        return __req_capsule_get(pill, field, RCL_SERVER);
}
EXPORT_SYMBOL(req_capsule_server_get);

const void *req_capsule_other_get(struct req_capsule *pill,
                                  const struct req_msg_field *field)
{
        return __req_capsule_get(pill, field, pill->rc_loc ^ 1);
}
EXPORT_SYMBOL(req_capsule_other_get);

void req_capsule_set_size(const struct req_capsule *pill,
                          const struct req_msg_field *field,
                          enum req_location loc, int size)
{
        pill->rc_area[__req_capsule_offset(pill, field, loc)] = size;
}
EXPORT_SYMBOL(req_capsule_set_size);

int req_capsule_get_size(const struct req_capsule *pill,
                         const struct req_msg_field *field,
                         enum req_location loc)
{
        LASSERT(loc == RCL_SERVER || loc == RCL_CLIENT);

        return lustre_msg_buflen(__req_msg(pill, loc),
                                 __req_capsule_offset(pill, field, loc));
}
EXPORT_SYMBOL(req_capsule_get_size);

#define FMT_FIELD(fmt, i, j) (fmt)->rf_fields[(i)].d[(j)]

void req_capsule_extend(struct req_capsule *pill, const struct req_format *fmt)
{
        int i;
        int j;

        const struct req_format *old;

        LASSERT(pill->rc_fmt != NULL);
        LASSERT(__req_format_is_sane(fmt));

        old = pill->rc_fmt;
        /*
         * Sanity checking...
         */
        for (i = 0; i < RCL_NR; ++i) {
                LASSERT(fmt->rf_fields[i].nr >= old->rf_fields[i].nr);
                for (j = 0; j < old->rf_fields[i].nr - 1; ++j) {
                        LASSERT(FMT_FIELD(fmt, i, j) == FMT_FIELD(old, i, j));
                }
                /*
                 * Last field in old format can be shorter than in new.
                 */
                LASSERT(FMT_FIELD(fmt, i, j)->rmf_size >=
                        FMT_FIELD(old, i, j)->rmf_size);
        }
        /* last field should be returned to the unswabbed state */
        pill->rc_swabbed &= ~(__u32)(1 << j);
        pill->rc_fmt = fmt;
}
EXPORT_SYMBOL(req_capsule_extend);

int req_capsule_has_field(const struct req_capsule *pill,
                          const struct req_msg_field *field)
{
        return field->rmf_offset[pill->rc_fmt->rf_idx][pill->rc_loc ^ 1];
}
EXPORT_SYMBOL(req_capsule_has_field);

int req_capsule_field_present(const struct req_capsule *pill,
                              const struct req_msg_field *field)
{
        int loc;
        int offset;

        LASSERT(req_capsule_has_field(pill, field));

        loc = pill->rc_loc ^ 1;
        offset = __req_capsule_offset(pill, field, loc);
        return lustre_msg_bufcount(__req_msg(pill, loc)) > offset;
}
EXPORT_SYMBOL(req_capsule_field_present);

/* __REQ_LAYOUT_USER__ */
#endif
