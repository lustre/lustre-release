/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ptlrpc/layout.c
 *
 * Lustre Metadata Target (mdt) request handler
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
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

/*
 * empty set of fields... for suitable definition of emptiness.
 */
static const struct req_msg_field *empty[] = {
        &RMF_PTLRPC_BODY
};

static const struct req_msg_field *mgs_target_info_only[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MGS_TARGET_INFO
};

static const struct req_msg_field *mgs_set_info[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MGS_SEND_PARAM
};

static const struct req_msg_field *log_cancel_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_LOGCOOKIES
};

static const struct req_msg_field *mdt_body_only[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_BODY
};

static const struct req_msg_field *mdt_body_capa[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_BODY,
        &RMF_CAPA1
};

static const struct req_msg_field *quotactl_only[] = {
        &RMF_PTLRPC_BODY,
        &RMF_OBD_QUOTACTL
};

static const struct req_msg_field *qunit_data_only[] = {
        &RMF_PTLRPC_BODY,
        &RMF_QUNIT_DATA
};

static const struct req_msg_field *mdt_close_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_EPOCH,
        &RMF_REC_REINT,
        &RMF_CAPA1
};

static const struct req_msg_field *obd_statfs_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_OBD_STATFS
};

static const struct req_msg_field *seq_query_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_SEQ_OPC,
        &RMF_SEQ_RANGE
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
        &RMF_CAPA1,
        &RMF_NAME
};

static const struct req_msg_field *mds_reint_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_REINT
};

static const struct req_msg_field *mds_reint_create_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_REINT,
        &RMF_CAPA1,
        &RMF_NAME
};

static const struct req_msg_field *mds_reint_create_slave_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_REINT,
        &RMF_CAPA1,
        &RMF_NAME,
        &RMF_EADATA,
        &RMF_DLM_REQ
};

static const struct req_msg_field *mds_reint_create_rmt_acl_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_REINT,
        &RMF_CAPA1,
        &RMF_NAME,
        &RMF_EADATA,
        &RMF_DLM_REQ
};

static const struct req_msg_field *mds_reint_create_sym_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_REINT,
        &RMF_CAPA1,
        &RMF_NAME,
        &RMF_SYMTGT,
        &RMF_DLM_REQ
};

static const struct req_msg_field *mds_reint_open_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_REINT,
        &RMF_CAPA1,
        &RMF_CAPA2,
        &RMF_NAME,
        &RMF_EADATA
};

static const struct req_msg_field *mds_reint_open_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_BODY,
        &RMF_MDT_MD,
        &RMF_ACL,
        &RMF_CAPA1,
        &RMF_CAPA2
};

static const struct req_msg_field *mds_reint_unlink_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_REINT,
        &RMF_CAPA1,
        &RMF_NAME,
        &RMF_DLM_REQ
};

static const struct req_msg_field *mds_reint_link_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_REINT,
        &RMF_CAPA1,
        &RMF_CAPA2,
        &RMF_NAME,
        &RMF_DLM_REQ
};

static const struct req_msg_field *mds_reint_rename_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_REINT,
        &RMF_CAPA1,
        &RMF_CAPA2,
        &RMF_NAME,
        &RMF_SYMTGT,
        &RMF_DLM_REQ
};

static const struct req_msg_field *mds_last_unlink_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_BODY,
        &RMF_MDT_MD,
        &RMF_LOGCOOKIES
};

static const struct req_msg_field *mds_reint_setattr_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_REINT,
        &RMF_CAPA1,
        &RMF_MDT_EPOCH,
        &RMF_EADATA,
        &RMF_LOGCOOKIES,
        &RMF_DLM_REQ
};

static const struct req_msg_field *mds_reint_setxattr_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_REC_REINT,
        &RMF_CAPA1,
        &RMF_NAME,
        &RMF_EADATA
};

static const struct req_msg_field *obd_connect_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_TGTUUID,
        &RMF_CLUUID,
        &RMF_CONN,
        &RMF_CONNECT_DATA
};

static const struct req_msg_field *obd_connect_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_CONNECT_DATA
};

static const struct req_msg_field *mds_set_info_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_SETINFO_KEY,
        &RMF_SETINFO_VAL
};

static const struct req_msg_field *ldlm_enqueue_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REQ
};

static const struct req_msg_field *ldlm_enqueue_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REP
};

static const struct req_msg_field *ldlm_enqueue_lvb_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REP,
        &RMF_DLM_LVB
};

static const struct req_msg_field *ldlm_cp_callback_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REQ,
        &RMF_DLM_LVB
};

static const struct req_msg_field *ldlm_gl_callback_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_LVB
};

static const struct req_msg_field *ldlm_intent_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REQ,
        &RMF_LDLM_INTENT,
        &RMF_REC_REINT
};

static const struct req_msg_field *ldlm_intent_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REP,
        &RMF_MDT_BODY,
        &RMF_MDT_MD,
        &RMF_ACL
};

static const struct req_msg_field *ldlm_intent_open_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REP,
        &RMF_MDT_BODY,
        &RMF_MDT_MD,
        &RMF_ACL,
        &RMF_CAPA1,
        &RMF_CAPA2
};

static const struct req_msg_field *ldlm_intent_getattr_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REQ,
        &RMF_LDLM_INTENT,
        &RMF_MDT_BODY,     /* coincides with mds_getattr_name_client[] */
        &RMF_CAPA1,
        &RMF_NAME
};

static const struct req_msg_field *ldlm_intent_getattr_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REP,
        &RMF_MDT_BODY,
        &RMF_MDT_MD,
        &RMF_ACL,
        &RMF_CAPA1
};

static const struct req_msg_field *ldlm_intent_create_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REQ,
        &RMF_LDLM_INTENT,
        &RMF_REC_REINT,    /* coincides with mds_reint_create_client[] */
        &RMF_CAPA1,
        &RMF_NAME,
        &RMF_EADATA
};

static const struct req_msg_field *ldlm_intent_open_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REQ,
        &RMF_LDLM_INTENT,
        &RMF_REC_REINT,    /* coincides with mds_reint_open_client[] */
        &RMF_CAPA1,
        &RMF_CAPA2,
        &RMF_NAME,
        &RMF_EADATA,
        &RMF_REC_JOINFILE
};

static const struct req_msg_field *ldlm_intent_unlink_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_DLM_REQ,
        &RMF_LDLM_INTENT,
        &RMF_REC_REINT,    /* coincides with mds_reint_unlink_client[] */
        &RMF_CAPA1,
        &RMF_NAME
};

static const struct req_msg_field *mds_getxattr_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_BODY,
        &RMF_CAPA1,
        &RMF_NAME,
        &RMF_EADATA
};

static const struct req_msg_field *mds_getxattr_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_BODY,
        &RMF_EADATA
};

static const struct req_msg_field *mds_getattr_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_BODY,
        &RMF_MDT_MD,
        &RMF_ACL,
        &RMF_CAPA1,
        &RMF_CAPA2
};

static const struct req_msg_field *mds_setattr_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_MDT_BODY,
        &RMF_MDT_MD,
        &RMF_ACL,
        &RMF_CAPA1,
        &RMF_CAPA2
};

static const struct req_msg_field *llog_catinfo_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_NAME,
        &RMF_STRING
};

static const struct req_msg_field *llog_catinfo_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_STRING
};

static const struct req_msg_field *llog_origin_handle_create_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_LLOGD_BODY,
        &RMF_NAME
};

static const struct req_msg_field *llogd_body_only[] = {
        &RMF_PTLRPC_BODY,
        &RMF_LLOGD_BODY
};

static const struct req_msg_field *llog_log_hdr_only[] = {
        &RMF_PTLRPC_BODY,
        &RMF_LLOG_LOG_HDR
};

static const struct req_msg_field *llogd_conn_body_only[] = {
        &RMF_PTLRPC_BODY,
        &RMF_LLOGD_CONN_BODY
};

static const struct req_msg_field *llog_origin_handle_next_block_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_LLOGD_BODY,
        &RMF_EADATA
};

static const struct req_msg_field *ost_body_only[] = {
        &RMF_PTLRPC_BODY,
        &RMF_OST_BODY
};

static const struct req_msg_field *ost_body_capa[] = {
        &RMF_PTLRPC_BODY,
        &RMF_OST_BODY,
        &RMF_CAPA1
};

static const struct req_msg_field *ost_destroy_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_OST_BODY,
        &RMF_DLM_REQ
};


static const struct req_msg_field *ost_brw_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_OST_BODY,
        &RMF_OBD_IOOBJ,
        &RMF_NIOBUF_REMOTE,
        &RMF_CAPA1
};

static const struct req_msg_field *ost_brw_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_OST_BODY,
        &RMF_NIOBUF_REMOTE
};

static const struct req_msg_field *ost_set_info_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_SETINFO_KEY,
        &RMF_SETINFO_VAL
};

static const struct req_msg_field *ost_get_info_generic_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_GENERIC_DATA,
};

static const struct req_msg_field *ost_get_info_generic_client[] = {
        &RMF_PTLRPC_BODY,
        &RMF_SETINFO_KEY
};

static const struct req_msg_field *ost_get_last_id_server[] = {
        &RMF_PTLRPC_BODY,
        &RMF_OBD_ID
};

static const struct req_format *req_formats[] = {
        &RQF_OBD_PING,
        &RQF_SEC_CTX,
        &RQF_SEQ_QUERY,
        &RQF_FLD_QUERY,
        &RQF_MGS_TARGET_REG,
        &RQF_MGS_SET_INFO,
        &RQF_MDS_CONNECT,
        &RQF_MDS_DISCONNECT,
        &RQF_MDS_SET_INFO,
        &RQF_MDS_GETSTATUS,
        &RQF_MDS_STATFS,
        &RQF_MDS_GETATTR,
        &RQF_MDS_GETATTR_NAME,
        &RQF_MDS_GETXATTR,
        &RQF_MDS_SYNC,
        &RQF_MDS_CLOSE,
        &RQF_MDS_PIN,
        &RQF_MDS_UNPIN,
        &RQF_MDS_READPAGE,
        &RQF_MDS_WRITEPAGE,
        &RQF_MDS_IS_SUBDIR,
        &RQF_MDS_DONE_WRITING,
        &RQF_MDS_REINT,
        &RQF_MDS_REINT_CREATE,
        &RQF_MDS_REINT_CREATE_RMT_ACL,
        &RQF_MDS_REINT_CREATE_SLAVE,
        &RQF_MDS_REINT_CREATE_SYM,
        &RQF_MDS_REINT_OPEN,
        &RQF_MDS_REINT_UNLINK,
        &RQF_MDS_REINT_LINK,
        &RQF_MDS_REINT_RENAME,
        &RQF_MDS_REINT_SETATTR,
        &RQF_MDS_REINT_SETXATTR,
        &RQF_MDS_QUOTACHECK,
        &RQF_MDS_QUOTACTL,
        &RQF_MDS_QUOTA_DQACQ,
        &RQF_OST_CONNECT,
        &RQF_OST_DISCONNECT,
        &RQF_OST_QUOTACHECK,
        &RQF_OST_QUOTACTL,
        &RQF_OST_GETATTR,
        &RQF_OST_SETATTR,
        &RQF_OST_CREATE,
        &RQF_OST_PUNCH,
        &RQF_OST_SYNC,
        &RQF_OST_DESTROY,
        &RQF_OST_BRW,
        &RQF_OST_STATFS,
        &RQF_OST_SET_INFO,
        &RQF_OST_GET_INFO_GENERIC,
        &RQF_OST_GET_INFO_LAST_ID,
        &RQF_LDLM_ENQUEUE,
        &RQF_LDLM_ENQUEUE_LVB,
        &RQF_LDLM_CONVERT,
        &RQF_LDLM_CANCEL,
        &RQF_LDLM_CALLBACK,
        &RQF_LDLM_CP_CALLBACK,
        &RQF_LDLM_BL_CALLBACK,
        &RQF_LDLM_GL_CALLBACK,
        &RQF_LDLM_INTENT,
        &RQF_LDLM_INTENT_GETATTR,
        &RQF_LDLM_INTENT_OPEN,
        &RQF_LDLM_INTENT_CREATE,
        &RQF_LDLM_INTENT_UNLINK,
        &RQF_LOG_CANCEL,
        &RQF_LLOG_CATINFO,
        &RQF_LLOG_ORIGIN_HANDLE_CREATE,
        &RQF_LLOG_ORIGIN_HANDLE_DESTROY,
        &RQF_LLOG_ORIGIN_HANDLE_NEXT_BLOCK,
        &RQF_LLOG_ORIGIN_HANDLE_PREV_BLOCK,
        &RQF_LLOG_ORIGIN_HANDLE_READ_HEADER,
        &RQF_LLOG_ORIGIN_CONNECT
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

const struct req_msg_field RMF_GENERIC_DATA =
        DEFINE_MSGF("generic_data", 0,
                    -1, NULL);
EXPORT_SYMBOL(RMF_GENERIC_DATA);

const struct req_msg_field RMF_MGS_TARGET_INFO =
        DEFINE_MSGF("mgs_target_info", 0,
                    sizeof(struct mgs_target_info),
                    lustre_swab_mgs_target_info);
EXPORT_SYMBOL(RMF_MGS_TARGET_INFO);

const struct req_msg_field RMF_MGS_SEND_PARAM =
        DEFINE_MSGF("mgs_send_param", 0,
                    sizeof(struct mgs_send_param),
                    NULL);
EXPORT_SYMBOL(RMF_MGS_SEND_PARAM);

const struct req_msg_field RMF_SETINFO_VAL =
        DEFINE_MSGF("setinfo_val", 0,
                    sizeof(__u32), lustre_swab_generic_32s);
EXPORT_SYMBOL(RMF_SETINFO_VAL);

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

const struct req_msg_field RMF_OBD_QUOTACTL =
        DEFINE_MSGF("obd_quotactl", 0,
                    sizeof(struct obd_quotactl), lustre_swab_obd_quotactl);
EXPORT_SYMBOL(RMF_OBD_QUOTACTL);

const struct req_msg_field RMF_QUNIT_DATA =
        DEFINE_MSGF("qunit_data", 0,
                    sizeof(struct qunit_data), NULL);
EXPORT_SYMBOL(RMF_QUNIT_DATA);

const struct req_msg_field RMF_MDT_EPOCH =
        DEFINE_MSGF("mdt_epoch", 0,
                    sizeof(struct mdt_epoch), lustre_swab_mdt_epoch);
EXPORT_SYMBOL(RMF_MDT_EPOCH);

const struct req_msg_field RMF_PTLRPC_BODY =
        DEFINE_MSGF("ptlrpc_body", 0,
                    sizeof(struct ptlrpc_body), lustre_swab_ptlrpc_body);
EXPORT_SYMBOL(RMF_PTLRPC_BODY);

const struct req_msg_field RMF_OBD_STATFS =
        DEFINE_MSGF("obd_statfs", 0,
                    sizeof(struct obd_statfs), lustre_swab_obd_statfs);
EXPORT_SYMBOL(RMF_OBD_STATFS);

const struct req_msg_field RMF_SETINFO_KEY =
        DEFINE_MSGF("setinfo_key", 0, -1, NULL);
EXPORT_SYMBOL(RMF_SETINFO_KEY);

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

const struct req_msg_field RMF_STRING =
        DEFINE_MSGF("string", RMF_F_STRING, -1, NULL);
EXPORT_SYMBOL(RMF_STRING);

const struct req_msg_field RMF_LLOGD_BODY =
        DEFINE_MSGF("llogd_body", 0,
                    sizeof(struct llogd_body), lustre_swab_llogd_body);
EXPORT_SYMBOL(RMF_LLOGD_BODY);

const struct req_msg_field RMF_LLOG_LOG_HDR =
        DEFINE_MSGF("llog_log_hdr", 0,
                    sizeof(struct llog_log_hdr), lustre_swab_llog_hdr);
EXPORT_SYMBOL(RMF_LLOG_LOG_HDR);

const struct req_msg_field RMF_LLOGD_CONN_BODY =
        DEFINE_MSGF("llogd_conn_body", 0,
                    sizeof(struct llogd_conn_body),
                    lustre_swab_llogd_conn_body);
EXPORT_SYMBOL(RMF_LLOGD_CONN_BODY);

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

const struct req_msg_field RMF_DLM_LVB =
        DEFINE_MSGF("dlm_lvb", 0, sizeof(struct ost_lvb), NULL);
EXPORT_SYMBOL(RMF_DLM_LVB);

const struct req_msg_field RMF_MDT_MD =
        DEFINE_MSGF("mdt_md", 0, MIN_MD_SIZE, NULL);
EXPORT_SYMBOL(RMF_MDT_MD);

const struct req_msg_field RMF_REC_REINT =
        DEFINE_MSGF("rec_reint", 0, sizeof(struct mdt_rec_reint),
                    lustre_swab_mdt_rec_reint);
EXPORT_SYMBOL(RMF_REC_REINT);

const struct req_msg_field RMF_REC_JOINFILE =
        DEFINE_MSGF("rec_joinfile", 0, sizeof(struct mdt_rec_join),
                    lustre_swab_mdt_rec_join);
EXPORT_SYMBOL(RMF_REC_JOINFILE);

/* FIXME: this length should be defined as a macro */
const struct req_msg_field RMF_EADATA = DEFINE_MSGF("eadata", 0, -1, NULL);
EXPORT_SYMBOL(RMF_EADATA);

const struct req_msg_field RMF_ACL = 
        DEFINE_MSGF("acl", 0, LUSTRE_POSIX_ACL_MAX_SIZE, NULL);
EXPORT_SYMBOL(RMF_ACL);

const struct req_msg_field RMF_LOGCOOKIES =
        DEFINE_MSGF("logcookies", 0, sizeof(struct llog_cookie), NULL);
EXPORT_SYMBOL(RMF_LOGCOOKIES);

const struct req_msg_field RMF_CAPA1 =
        DEFINE_MSGF("capa", 0, sizeof(struct lustre_capa),
                    lustre_swab_lustre_capa);
EXPORT_SYMBOL(RMF_CAPA1);

const struct req_msg_field RMF_CAPA2 =
        DEFINE_MSGF("capa", 0, sizeof(struct lustre_capa),
                    lustre_swab_lustre_capa);
EXPORT_SYMBOL(RMF_CAPA2);

/* 
 * OST request field.
 */
const struct req_msg_field RMF_OST_BODY =
        DEFINE_MSGF("ost_body", 0,
                    sizeof(struct ost_body), lustre_swab_ost_body);
EXPORT_SYMBOL(RMF_OST_BODY);

const struct req_msg_field RMF_OBD_IOOBJ =
        DEFINE_MSGF("obd_ioobj", 0,
                    sizeof(struct obd_ioobj), lustre_swab_obd_ioobj);
EXPORT_SYMBOL(RMF_OBD_IOOBJ);

const struct req_msg_field RMF_NIOBUF_REMOTE =
        DEFINE_MSGF("niobuf_remote", 0, -1, lustre_swab_niobuf_remote);
EXPORT_SYMBOL(RMF_NIOBUF_REMOTE);

const struct req_msg_field RMF_OBD_ID =
        DEFINE_MSGF("obd_id", 0,
                    sizeof(obd_id), lustre_swab_ost_last_id);
EXPORT_SYMBOL(RMF_OBD_ID);


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

#define DEFINE_REQ_FMT0(name, client, server)                                  \
DEFINE_REQ_FMT(name, client, ARRAY_SIZE(client), server, ARRAY_SIZE(server))

const struct req_format RQF_OBD_PING =
        DEFINE_REQ_FMT0("OBD_PING", empty, empty);
EXPORT_SYMBOL(RQF_OBD_PING);
 
const struct req_format RQF_SEC_CTX =
        DEFINE_REQ_FMT0("SEC_CTX", empty, empty);
EXPORT_SYMBOL(RQF_SEC_CTX);
 
const struct req_format RQF_MGS_TARGET_REG =
        DEFINE_REQ_FMT0("MGS_TARGET_REG", mgs_target_info_only,
                         mgs_target_info_only);
EXPORT_SYMBOL(RQF_MGS_TARGET_REG);

const struct req_format RQF_MGS_SET_INFO =
        DEFINE_REQ_FMT0("MGS_SET_INTO", mgs_set_info,
                         mgs_set_info);
EXPORT_SYMBOL(RQF_MGS_SET_INFO);

const struct req_format RQF_LOG_CANCEL =
        DEFINE_REQ_FMT0("OBD_LOG_CANCEL", log_cancel_client, empty);
EXPORT_SYMBOL(RQF_LOG_CANCEL);

const struct req_format RQF_MDS_QUOTACHECK =
        DEFINE_REQ_FMT0("MDS_QUOTACHECK", quotactl_only, empty);
EXPORT_SYMBOL(RQF_MDS_QUOTACHECK);

const struct req_format RQF_OST_QUOTACHECK =
        DEFINE_REQ_FMT0("OST_QUOTACHECK", quotactl_only, empty);
EXPORT_SYMBOL(RQF_OST_QUOTACHECK);

const struct req_format RQF_MDS_QUOTACTL =
        DEFINE_REQ_FMT0("MDS_QUOTACTL", quotactl_only, quotactl_only);
EXPORT_SYMBOL(RQF_MDS_QUOTACTL);

const struct req_format RQF_OST_QUOTACTL =
        DEFINE_REQ_FMT0("OST_QUOTACTL", quotactl_only, quotactl_only);
EXPORT_SYMBOL(RQF_OST_QUOTACTL);

const struct req_format RQF_QC_CALLBACK =
        DEFINE_REQ_FMT0("QC_CALLBACK", quotactl_only, empty);
EXPORT_SYMBOL(RQF_QC_CALLBACK);

const struct req_format RQF_MDS_QUOTA_DQACQ =
        DEFINE_REQ_FMT0("MDS_QUOTA_DQACQ", qunit_data_only, qunit_data_only);
EXPORT_SYMBOL(RQF_MDS_QUOTA_DQACQ);

const struct req_format RQF_SEQ_QUERY =
        DEFINE_REQ_FMT0("SEQ_QUERY", seq_query_client, seq_query_server);
EXPORT_SYMBOL(RQF_SEQ_QUERY);

const struct req_format RQF_FLD_QUERY =
        DEFINE_REQ_FMT0("FLD_QUERY", fld_query_client, fld_query_server);
EXPORT_SYMBOL(RQF_FLD_QUERY);

const struct req_format RQF_MDS_GETSTATUS =
        DEFINE_REQ_FMT0("MDS_GETSTATUS", mdt_body_only, mdt_body_capa);
EXPORT_SYMBOL(RQF_MDS_GETSTATUS);

const struct req_format RQF_MDS_STATFS =
        DEFINE_REQ_FMT0("MDS_STATFS", empty, obd_statfs_server);
EXPORT_SYMBOL(RQF_MDS_STATFS);

const struct req_format RQF_MDS_SYNC =
        DEFINE_REQ_FMT0("MDS_SYNC", mdt_body_capa, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_SYNC);

const struct req_format RQF_MDS_GETATTR =
        DEFINE_REQ_FMT0("MDS_GETATTR", mdt_body_capa, mds_getattr_server);
EXPORT_SYMBOL(RQF_MDS_GETATTR);

const struct req_format RQF_MDS_GETXATTR =
        DEFINE_REQ_FMT0("MDS_GETXATTR",
                        mds_getxattr_client, mds_getxattr_server);
EXPORT_SYMBOL(RQF_MDS_GETXATTR);

const struct req_format RQF_MDS_GETATTR_NAME =
        DEFINE_REQ_FMT0("MDS_GETATTR_NAME",
                        mds_getattr_name_client, mds_getattr_server);
EXPORT_SYMBOL(RQF_MDS_GETATTR_NAME);

const struct req_format RQF_MDS_REINT =
        DEFINE_REQ_FMT0("MDS_REINT", mds_reint_client, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_REINT);

const struct req_format RQF_MDS_REINT_CREATE =
        DEFINE_REQ_FMT0("MDS_REINT_CREATE",
                        mds_reint_create_client, mdt_body_capa);
EXPORT_SYMBOL(RQF_MDS_REINT_CREATE);

const struct req_format RQF_MDS_REINT_CREATE_RMT_ACL =
        DEFINE_REQ_FMT0("MDS_REINT_CREATE_RMT_ACL",
                        mds_reint_create_rmt_acl_client, mdt_body_capa);
EXPORT_SYMBOL(RQF_MDS_REINT_CREATE_RMT_ACL);

const struct req_format RQF_MDS_REINT_CREATE_SLAVE =
        DEFINE_REQ_FMT0("MDS_REINT_CREATE_EA",
                        mds_reint_create_slave_client, mdt_body_capa);
EXPORT_SYMBOL(RQF_MDS_REINT_CREATE_SLAVE);

const struct req_format RQF_MDS_REINT_CREATE_SYM =
        DEFINE_REQ_FMT0("MDS_REINT_CREATE_SYM",
                        mds_reint_create_sym_client, mdt_body_capa);
EXPORT_SYMBOL(RQF_MDS_REINT_CREATE_SYM);

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
                        mds_reint_setattr_client, mds_setattr_server);
EXPORT_SYMBOL(RQF_MDS_REINT_SETATTR);

const struct req_format RQF_MDS_REINT_SETXATTR =
        DEFINE_REQ_FMT0("MDS_REINT_SETXATTR",
                        mds_reint_setxattr_client, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_REINT_SETXATTR);

const struct req_format RQF_MDS_CONNECT =
        DEFINE_REQ_FMT0("MDS_CONNECT",
                        obd_connect_client, obd_connect_server);
EXPORT_SYMBOL(RQF_MDS_CONNECT);

const struct req_format RQF_MDS_DISCONNECT =
        DEFINE_REQ_FMT0("MDS_DISCONNECT", empty, empty);
EXPORT_SYMBOL(RQF_MDS_DISCONNECT);
 
const struct req_format RQF_MDS_SET_INFO =
        DEFINE_REQ_FMT0("MDS_SET_INFO", mds_set_info_client, empty);
EXPORT_SYMBOL(RQF_MDS_SET_INFO);
 
const struct req_format RQF_LDLM_ENQUEUE =
        DEFINE_REQ_FMT0("LDLM_ENQUEUE",
                        ldlm_enqueue_client, ldlm_enqueue_lvb_server);
EXPORT_SYMBOL(RQF_LDLM_ENQUEUE);

const struct req_format RQF_LDLM_ENQUEUE_LVB =
        DEFINE_REQ_FMT0("LDLM_ENQUEUE_LVB",
                        ldlm_enqueue_client, ldlm_enqueue_lvb_server);
EXPORT_SYMBOL(RQF_LDLM_ENQUEUE_LVB);

const struct req_format RQF_LDLM_CONVERT =
        DEFINE_REQ_FMT0("LDLM_CONVERT",
                        ldlm_enqueue_client, ldlm_enqueue_server);
EXPORT_SYMBOL(RQF_LDLM_CONVERT);

const struct req_format RQF_LDLM_CANCEL =
        DEFINE_REQ_FMT0("LDLM_CANCEL", ldlm_enqueue_client, empty);
EXPORT_SYMBOL(RQF_LDLM_CANCEL);

const struct req_format RQF_LDLM_CALLBACK =
        DEFINE_REQ_FMT0("LDLM_CALLBACK", ldlm_enqueue_client, empty);
EXPORT_SYMBOL(RQF_LDLM_CALLBACK);

const struct req_format RQF_LDLM_CP_CALLBACK =
        DEFINE_REQ_FMT0("LDLM_CP_CALLBACK", ldlm_cp_callback_client, empty);
EXPORT_SYMBOL(RQF_LDLM_CP_CALLBACK);

const struct req_format RQF_LDLM_BL_CALLBACK =
        DEFINE_REQ_FMT0("LDLM_BL_CALLBACK", ldlm_enqueue_client, empty);
EXPORT_SYMBOL(RQF_LDLM_BL_CALLBACK);

const struct req_format RQF_LDLM_GL_CALLBACK =
        DEFINE_REQ_FMT0("LDLM_GL_CALLBACK", ldlm_enqueue_client,
                        ldlm_gl_callback_server);
EXPORT_SYMBOL(RQF_LDLM_GL_CALLBACK);

const struct req_format RQF_LDLM_INTENT =
        DEFINE_REQ_FMT0("LDLM_INTENT",
                        ldlm_intent_client, ldlm_intent_server);
EXPORT_SYMBOL(RQF_LDLM_INTENT);

const struct req_format RQF_LDLM_INTENT_GETATTR =
        DEFINE_REQ_FMT0("LDLM_INTENT_GETATTR",
                        ldlm_intent_getattr_client, ldlm_intent_getattr_server);
EXPORT_SYMBOL(RQF_LDLM_INTENT_GETATTR);

const struct req_format RQF_LDLM_INTENT_OPEN =
        DEFINE_REQ_FMT0("LDLM_INTENT_OPEN",
                        ldlm_intent_open_client, ldlm_intent_open_server);
EXPORT_SYMBOL(RQF_LDLM_INTENT_OPEN);

const struct req_format RQF_LDLM_INTENT_CREATE =
        DEFINE_REQ_FMT0("LDLM_INTENT_CREATE",
                        ldlm_intent_create_client, ldlm_intent_getattr_server);
EXPORT_SYMBOL(RQF_LDLM_INTENT_CREATE);

const struct req_format RQF_LDLM_INTENT_UNLINK =
        DEFINE_REQ_FMT0("LDLM_INTENT_UNLINK",
                        ldlm_intent_unlink_client, ldlm_intent_server);
EXPORT_SYMBOL(RQF_LDLM_INTENT_UNLINK);

const struct req_format RQF_MDS_CLOSE =
        DEFINE_REQ_FMT0("MDS_CLOSE",
                        mdt_close_client, mds_last_unlink_server);
EXPORT_SYMBOL(RQF_MDS_CLOSE);

const struct req_format RQF_MDS_PIN =
        DEFINE_REQ_FMT0("MDS_PIN",
                        mdt_body_capa, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_PIN);

const struct req_format RQF_MDS_UNPIN =
        DEFINE_REQ_FMT0("MDS_UNPIN", mdt_body_only, empty);
EXPORT_SYMBOL(RQF_MDS_UNPIN);

const struct req_format RQF_MDS_DONE_WRITING =
        DEFINE_REQ_FMT0("MDS_DONE_WRITING",
                        mdt_close_client, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_DONE_WRITING);

const struct req_format RQF_MDS_READPAGE =
        DEFINE_REQ_FMT0("MDS_READPAGE",
                        mdt_body_capa, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_READPAGE);

/* This is for split */
const struct req_format RQF_MDS_WRITEPAGE =
        DEFINE_REQ_FMT0("MDS_WRITEPAGE",
                        mdt_body_capa, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_WRITEPAGE);

const struct req_format RQF_MDS_IS_SUBDIR =
        DEFINE_REQ_FMT0("MDS_IS_SUBDIR",
                        mdt_body_only, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_IS_SUBDIR);

const struct req_format RQF_LLOG_CATINFO =
        DEFINE_REQ_FMT0("LLOG_CATINFO",
                        llog_catinfo_client, llog_catinfo_server);
EXPORT_SYMBOL(RQF_LLOG_CATINFO);

const struct req_format RQF_LLOG_ORIGIN_HANDLE_CREATE =
        DEFINE_REQ_FMT0("LLOG_ORIGIN_HANDLE_CREATE",
                        llog_origin_handle_create_client, llogd_body_only);
EXPORT_SYMBOL(RQF_LLOG_ORIGIN_HANDLE_CREATE);

const struct req_format RQF_LLOG_ORIGIN_HANDLE_DESTROY =
        DEFINE_REQ_FMT0("LLOG_ORIGIN_HANDLE_DESTROY",
                        llogd_body_only, llogd_body_only);
EXPORT_SYMBOL(RQF_LLOG_ORIGIN_HANDLE_DESTROY);

const struct req_format RQF_LLOG_ORIGIN_HANDLE_NEXT_BLOCK =
        DEFINE_REQ_FMT0("LLOG_ORIGIN_HANDLE_NEXT_BLOCK",
                        llogd_body_only, llog_origin_handle_next_block_server);
EXPORT_SYMBOL(RQF_LLOG_ORIGIN_HANDLE_NEXT_BLOCK);

const struct req_format RQF_LLOG_ORIGIN_HANDLE_PREV_BLOCK =
        DEFINE_REQ_FMT0("LLOG_ORIGIN_HANDLE_PREV_BLOCK",
                        llogd_body_only, llog_origin_handle_next_block_server);
EXPORT_SYMBOL(RQF_LLOG_ORIGIN_HANDLE_PREV_BLOCK);

const struct req_format RQF_LLOG_ORIGIN_HANDLE_READ_HEADER =
        DEFINE_REQ_FMT0("LLOG_ORIGIN_HANDLE_READ_HEADER",
                        llogd_body_only, llog_log_hdr_only);
EXPORT_SYMBOL(RQF_LLOG_ORIGIN_HANDLE_READ_HEADER);

const struct req_format RQF_LLOG_ORIGIN_CONNECT =
        DEFINE_REQ_FMT0("LLOG_ORIGIN_CONNECT", llogd_conn_body_only, empty);
EXPORT_SYMBOL(RQF_LLOG_ORIGIN_CONNECT);

const struct req_format RQF_OST_CONNECT =
        DEFINE_REQ_FMT0("OST_CONNECT",
                        obd_connect_client, obd_connect_server);
EXPORT_SYMBOL(RQF_OST_CONNECT);

const struct req_format RQF_OST_DISCONNECT =
        DEFINE_REQ_FMT0("OST_DISCONNECT", empty, empty);
EXPORT_SYMBOL(RQF_OST_DISCONNECT);

const struct req_format RQF_OST_GETATTR =
        DEFINE_REQ_FMT0("OST_GETATTR", ost_body_capa, ost_body_only);
EXPORT_SYMBOL(RQF_OST_GETATTR);

const struct req_format RQF_OST_SETATTR =
        DEFINE_REQ_FMT0("OST_SETATTR", ost_body_capa, ost_body_only);
EXPORT_SYMBOL(RQF_OST_SETATTR);

const struct req_format RQF_OST_CREATE =
        DEFINE_REQ_FMT0("OST_CREATE", ost_body_only, ost_body_only);
EXPORT_SYMBOL(RQF_OST_CREATE);

const struct req_format RQF_OST_PUNCH =
        DEFINE_REQ_FMT0("OST_PUNCH", ost_body_capa, ost_body_only);
EXPORT_SYMBOL(RQF_OST_PUNCH);

const struct req_format RQF_OST_SYNC =
        DEFINE_REQ_FMT0("OST_SYNC", ost_body_capa, ost_body_only);
EXPORT_SYMBOL(RQF_OST_SYNC);

const struct req_format RQF_OST_DESTROY =
        DEFINE_REQ_FMT0("OST_DESTROY", ost_destroy_client, ost_body_only);
EXPORT_SYMBOL(RQF_OST_DESTROY);

const struct req_format RQF_OST_BRW =
        DEFINE_REQ_FMT0("OST_BRW", ost_brw_client, ost_brw_server);
EXPORT_SYMBOL(RQF_OST_BRW);

const struct req_format RQF_OST_STATFS =
        DEFINE_REQ_FMT0("OST_STATFS", empty, obd_statfs_server);
EXPORT_SYMBOL(RQF_OST_STATFS);

const struct req_format RQF_OST_SET_INFO =
        DEFINE_REQ_FMT0("OST_SET_INFO", ost_set_info_client, empty);
EXPORT_SYMBOL(RQF_OST_SET_INFO);

const struct req_format RQF_OST_GET_INFO_GENERIC =
        DEFINE_REQ_FMT0("OST_GET_INFO", ost_get_info_generic_client,
                                        ost_get_info_generic_server);
EXPORT_SYMBOL(RQF_OST_GET_INFO_GENERIC);

const struct req_format RQF_OST_GET_INFO_LAST_ID =
        DEFINE_REQ_FMT0("OST_GET_INFO_LAST_ID", ost_get_info_generic_client,
                                                ost_get_last_id_server);
EXPORT_SYMBOL(RQF_OST_GET_INFO_LAST_ID);


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
                        LASSERT(rf->rf_fields[j].nr <= REQ_MAX_FIELD_NR);
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

void req_capsule_init_area(struct req_capsule *pill)
{
        int i;

        for (i = 0; i < ARRAY_SIZE(pill->rc_area[RCL_CLIENT]); i++) {
                pill->rc_area[RCL_CLIENT][i] = -1;
                pill->rc_area[RCL_SERVER][i] = -1;
        }
}
EXPORT_SYMBOL(req_capsule_init_area);

/*
 * Initialize capsule.
 *
 * @area is an array of REQ_MAX_FIELD_NR elements, used to store sizes of
 * variable-sized fields.
 */
void req_capsule_init(struct req_capsule *pill,
                      struct ptlrpc_request *req,
                      enum req_location location)
{
        LASSERT(location == RCL_SERVER || location == RCL_CLIENT);

        memset(pill, 0, sizeof *pill);
        pill->rc_req = req;
        pill->rc_loc = location;
        req_capsule_init_area(pill);
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

int req_capsule_filled_sizes(struct req_capsule *pill,
                           enum req_location loc)
{
        const struct req_format *fmt = pill->rc_fmt;
        int                      i;

        LASSERT(fmt != NULL);

        for (i = 0; i < fmt->rf_fields[loc].nr; ++i) {
                if (pill->rc_area[loc][i] == -1) {
                        pill->rc_area[loc][i] = 
                                            fmt->rf_fields[loc].d[i]->rmf_size;
                        if (pill->rc_area[loc][i] == -1) {
                                /* skip the following fields */
                                LASSERT(loc != RCL_SERVER);
                                break;
                        }
                }
        }
        return i;
}
EXPORT_SYMBOL(req_capsule_filled_sizes);

int req_capsule_server_pack(struct req_capsule *pill)
{
        const struct req_format *fmt;
        int                      count;
        int                      rc;

        LASSERT(pill->rc_loc == RCL_SERVER);
        fmt = pill->rc_fmt;
        LASSERT(fmt != NULL);

        count = req_capsule_filled_sizes(pill, RCL_SERVER);
        rc = lustre_pack_reply(pill->rc_req, count,
                               pill->rc_area[RCL_SERVER], NULL);
        if (rc != 0) {
                DEBUG_REQ(D_ERROR, pill->rc_req,
                          "Cannot pack %d fields in format `%s': ",
                          count, fmt->rf_name);
        }
        return rc;
}
EXPORT_SYMBOL(req_capsule_server_pack);

static int __req_capsule_offset(const struct req_capsule *pill,
                                const struct req_msg_field *field,
                                enum req_location loc)
{
        int offset;

        offset = field->rmf_offset[pill->rc_fmt->rf_idx][loc];
        LASSERTF(offset > 0, "%s:%s, off=%d, loc=%d\n",
                            pill->rc_fmt->rf_name,
                            field->rmf_name, offset, loc);
        offset --;
        LASSERT(0 <= offset && offset < (sizeof(pill->rc_swabbed) << 3));
        return offset;
}

static void *__req_capsule_get(struct req_capsule *pill,
                               const struct req_msg_field *field,
                               enum req_location loc,
                               void (*swabber)( void *))
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
        LASSERT(msg != NULL);

        getter = (field->rmf_flags & RMF_F_STRING) ?
                (typeof(getter))lustre_msg_string : lustre_msg_buf;

        if (pill->rc_area[loc][offset] != -1)
                len = pill->rc_area[loc][offset];
        else
                len = max(field->rmf_size, 0);
        value = getter(msg, offset, len);

        swabber = swabber ?: field->rmf_swabber;
        if (!(pill->rc_swabbed & (1 << offset)) && loc != pill->rc_loc &&
            swabber != NULL && value != NULL &&
            lustre_msg_swabbed(msg)) {
                swabber(value);
                pill->rc_swabbed |= (1 << offset);
        }
        if (value == NULL) {
                DEBUG_REQ(D_ERROR, pill->rc_req,
                          "Wrong buffer for field `%s' (%d of %d) "
                          "in format `%s': %d vs. %d (%s)\n",
                          field->rmf_name, offset, lustre_msg_bufcount(msg), fmt->rf_name,
                          lustre_msg_buflen(msg, offset), len,
                          rcl_names[loc]);
        }

        return value;
}

void *req_capsule_client_get(struct req_capsule *pill,
                             const struct req_msg_field *field)
{
        return __req_capsule_get(pill, field, RCL_CLIENT, NULL);
}
EXPORT_SYMBOL(req_capsule_client_get);

void *req_capsule_client_swab_get(struct req_capsule *pill,
                                  const struct req_msg_field *field,
                                  void (*swabber)(void* ))
{
        return __req_capsule_get(pill, field, RCL_CLIENT, swabber);
}
EXPORT_SYMBOL(req_capsule_client_swab_get);

void *req_capsule_client_sized_get(struct req_capsule *pill,
                                   const struct req_msg_field *field,
                                   int len)
{
        req_capsule_set_size(pill, field, RCL_CLIENT, len);
        return __req_capsule_get(pill, field, RCL_CLIENT, NULL);
}
EXPORT_SYMBOL(req_capsule_client_sized_get);

void *req_capsule_server_get(struct req_capsule *pill,
                             const struct req_msg_field *field)
{
        return __req_capsule_get(pill, field, RCL_SERVER, NULL);
}
EXPORT_SYMBOL(req_capsule_server_get);

void *req_capsule_server_swab_get(struct req_capsule *pill,
                                  const struct req_msg_field *field,
                                  void *swabber)
{
        return __req_capsule_get(pill, field, RCL_SERVER, swabber);
}
EXPORT_SYMBOL(req_capsule_server_swab_get);


void *req_capsule_server_sized_get(struct req_capsule *pill,
                                   const struct req_msg_field *field,
                                   int len)
{
        req_capsule_set_size(pill, field, RCL_SERVER, len);
        return __req_capsule_get(pill, field, RCL_SERVER, NULL);
}
EXPORT_SYMBOL(req_capsule_server_sized_get);

const void *req_capsule_other_get(struct req_capsule *pill,
                                  const struct req_msg_field *field)
{
        return __req_capsule_get(pill, field, pill->rc_loc ^ 1, NULL);
}
EXPORT_SYMBOL(req_capsule_other_get);

void req_capsule_set_size(struct req_capsule *pill,
                          const struct req_msg_field *field,
                          enum req_location loc, int size)
{
        LASSERT(loc == RCL_SERVER || loc == RCL_CLIENT);

        pill->rc_area[loc][__req_capsule_offset(pill, field, loc)] = size;
}
EXPORT_SYMBOL(req_capsule_set_size);

/* NB: this function doesn't correspond with req_capsule_set_size(), which
 * actually sets the size in pill.rc_area[loc][offset], but this function
 * returns the message buflen[offset], maybe we should use another name.
 */
int req_capsule_get_size(const struct req_capsule *pill,
                         const struct req_msg_field *field,
                         enum req_location loc)
{
        LASSERT(loc == RCL_SERVER || loc == RCL_CLIENT);

        return lustre_msg_buflen(__req_msg(pill, loc),
                                 __req_capsule_offset(pill, field, loc));
}
EXPORT_SYMBOL(req_capsule_get_size);

int req_capsule_msg_size(struct req_capsule *pill, enum req_location loc)
{
        return lustre_msg_size(pill->rc_req->rq_import->imp_msg_magic,
                               pill->rc_fmt->rf_fields[loc].nr,
                               pill->rc_area[loc]);
}

int req_capsule_fmt_size(__u32 magic, const struct req_format *fmt,
                         enum req_location loc)
{
        int size, i = 0;

        size = lustre_msg_hdr_size(magic, fmt->rf_fields[loc].nr);
        if (size < 0)
                return size;

        for (; i < fmt->rf_fields[loc].nr; ++i)
                if (fmt->rf_fields[loc].d[i]->rmf_size != -1)
                        size += size_round(fmt->rf_fields[loc].d[i]->rmf_size);
        return size;
}

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
                          const struct req_msg_field *field,
                          enum req_location loc)
{
        LASSERT(loc == RCL_SERVER || loc == RCL_CLIENT);

        return field->rmf_offset[pill->rc_fmt->rf_idx][loc];
}
EXPORT_SYMBOL(req_capsule_has_field);

int req_capsule_field_present(const struct req_capsule *pill,
                              const struct req_msg_field *field,
                              enum req_location loc)
{
        int offset;

        LASSERT(loc == RCL_SERVER || loc == RCL_CLIENT);
        LASSERT(req_capsule_has_field(pill, field, loc));

        offset = __req_capsule_offset(pill, field, loc);
        return lustre_msg_bufcount(__req_msg(pill, loc)) > offset;
}
EXPORT_SYMBOL(req_capsule_field_present);

void req_capsule_shrink(struct req_capsule *pill,
                        const struct req_msg_field *field,
                        unsigned int newlen,
                        enum req_location loc)
{
        const struct req_format *fmt;
        struct lustre_msg       *msg;
        int                      len;
        int                      offset;

        fmt = pill->rc_fmt;
        LASSERT(fmt != NULL);
        LASSERT(__req_format_is_sane(fmt));
        LASSERT(req_capsule_has_field(pill, field, loc));
        LASSERT(req_capsule_field_present(pill, field, loc));

        offset = __req_capsule_offset(pill, field, loc);

        msg = __req_msg(pill, loc);
        len = lustre_msg_buflen(msg, offset);
        LASSERTF(newlen <= len, "%s:%s, oldlen=%d, newlen=%d\n",
                                fmt->rf_name, field->rmf_name, len, newlen);

        if (loc == RCL_CLIENT)
                pill->rc_req->rq_reqlen = lustre_shrink_msg(msg, offset, newlen,
                                                            1);
        else
                pill->rc_req->rq_replen = lustre_shrink_msg(msg, offset, newlen,
                                                            1);
}
EXPORT_SYMBOL(req_capsule_shrink);

/* __REQ_LAYOUT_USER__ */
#endif
