/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/fid/fid_request.c
 *  Lustre Sequence Manager
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Yury Umanets <umka@clusterfs.com>
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_FID

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
# include <linux/module.h>
#else /* __KERNEL__ */
# include <liblustre.h>
#endif

#include <obd.h>
#include <obd_class.h>
#include <dt_object.h>
#include <md_object.h>
#include <obd_support.h>
#include <lustre_req_layout.h>
#include <lustre_fid.h>
#include "fid_internal.h"

static int seq_client_rpc(struct lu_client_seq *seq,
                          struct lu_range *range,
                          __u32 opc, const char *opcname)
{
        struct obd_export *exp = seq->lcs_exp;
        int repsize = sizeof(struct lu_range);
        int rc, reqsize = sizeof(__u32);
        struct ptlrpc_request *req;
        struct req_capsule pill;
        struct lu_range *ran;
        __u32 *op;
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp),
			      LUSTRE_MDS_VERSION,
                              SEQ_QUERY, 1, &reqsize,
                              NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        req_capsule_init(&pill, req, RCL_CLIENT, NULL);

        req_capsule_set(&pill, &RQF_SEQ_QUERY);

        op = req_capsule_client_get(&pill, &RMF_SEQ_OPC);
        *op = opc;

        req->rq_replen = lustre_msg_size(1, &repsize);

        if (seq->lcs_type == LUSTRE_SEQ_METADATA) {
                req->rq_request_portal = (opc == SEQ_ALLOC_SUPER) ?
                        SEQ_CONTROLLER_PORTAL : SEQ_METADATA_PORTAL;
        } else {
                req->rq_request_portal = (opc == SEQ_ALLOC_SUPER) ?
                        SEQ_CONTROLLER_PORTAL : SEQ_DATA_PORTAL;
        }

        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(out_req, rc);

        ran = req_capsule_server_get(&pill, &RMF_SEQ_RANGE);
        if (ran == NULL)
                GOTO(out_req, rc = -EPROTO);
        *range = *ran;

        if (!range_is_sane(range)) {
                CERROR("invalid seq range obtained from server: "
                       DRANGE"\n", PRANGE(range));
                GOTO(out_req, rc = -EINVAL);
        }

        if (range_is_exhausted(range)) {
                CERROR("seq range obtained from server is exhausted: "
                       DRANGE"]\n", PRANGE(range));
                GOTO(out_req, rc = -EINVAL);
        }

        if (rc == 0) {
                CDEBUG(D_INFO, "%s: allocated %s-sequence "
                       DRANGE"]\n", seq->lcs_name, opcname,
                       PRANGE(range));
        }
        
        EXIT;
out_req:
        req_capsule_fini(&pill);
        ptlrpc_req_finished(req);
        return rc;
}

/* request sequence-controller node to allocate new super-sequence. */
static int __seq_client_alloc_super(struct lu_client_seq *seq)
{
        return seq_client_rpc(seq, &seq->lcs_range,
                              SEQ_ALLOC_SUPER, "super");
}

int seq_client_alloc_super(struct lu_client_seq *seq)
{
        int rc;
        ENTRY;

        down(&seq->lcs_sem);
        rc = __seq_client_alloc_super(seq);
        up(&seq->lcs_sem);

        RETURN(rc);
}
EXPORT_SYMBOL(seq_client_alloc_super);

/* request sequence-controller node to allocate new meta-sequence. */
static int __seq_client_alloc_meta(struct lu_client_seq *seq)
{
        return seq_client_rpc(seq, &seq->lcs_range,
                              SEQ_ALLOC_META, "meta");
}

int seq_client_alloc_meta(struct lu_client_seq *seq)
{
        int rc;
        ENTRY;

        down(&seq->lcs_sem);
        rc = __seq_client_alloc_meta(seq);
        up(&seq->lcs_sem);

        RETURN(rc);
}
EXPORT_SYMBOL(seq_client_alloc_meta);

/* allocate new sequence for client (llite or MDC are expected to use this) */
static int __seq_client_alloc_seq(struct lu_client_seq *seq, seqno_t *seqnr)
{
        int rc = 0;
        ENTRY;

        LASSERT(range_is_sane(&seq->lcs_range));

        /* if we still have free sequences in meta-sequence we allocate new seq
         * from given range, if not - allocate new meta-sequence. */
        if (range_space(&seq->lcs_range) == 0) {
                rc = __seq_client_alloc_meta(seq);
                if (rc) {
                        CERROR("can't allocate new meta-sequence, "
                               "rc %d\n", rc);
                        RETURN(rc);
                }
        }

        LASSERT(range_space(&seq->lcs_range) > 0);
        *seqnr = seq->lcs_range.lr_start;
        seq->lcs_range.lr_start++;

        CDEBUG(D_INFO, "%s: allocated sequence ["LPX64"]\n",
               seq->lcs_name, *seqnr);
        RETURN(rc);
}

int seq_client_alloc_seq(struct lu_client_seq *seq, seqno_t *seqnr)
{
        int rc = 0;
        ENTRY;

        down(&seq->lcs_sem);
        rc = __seq_client_alloc_seq(seq, seqnr);
        up(&seq->lcs_sem);

        RETURN(rc);
}
EXPORT_SYMBOL(seq_client_alloc_seq);

int seq_client_alloc_fid(struct lu_client_seq *seq, struct lu_fid *fid)
{
        int rc;
        ENTRY;

        LASSERT(fid != NULL);

        down(&seq->lcs_sem);

        if (!fid_is_sane(&seq->lcs_fid) ||
            fid_oid(&seq->lcs_fid) >= seq->lcs_width)
        {
                seqno_t seqnr;
                
                /* allocate new sequence for case client has no sequence at all
                 * or sequence is exhausted and should be switched. */
                rc = __seq_client_alloc_seq(seq, &seqnr);
                if (rc) {
                        CERROR("can't allocate new sequence, "
                               "rc %d\n", rc);
                        GOTO(out, rc);
                }

                /* init new fid */
                seq->lcs_fid.f_oid = LUSTRE_FID_INIT_OID;
                seq->lcs_fid.f_seq = seqnr;
                seq->lcs_fid.f_ver = 0;

                /* inform caller that sequence switch is performed to allow it
                 * to setup FLD for it. */
                rc = 1;
        } else {
                seq->lcs_fid.f_oid++;
                rc = 0;
        }

        *fid = seq->lcs_fid;
        LASSERT(fid_is_sane(fid));

        CDEBUG(D_INFO, "%s: allocated FID "DFID"\n",
               seq->lcs_name, PFID(fid));

        EXIT;
out:
        up(&seq->lcs_sem);
        return rc;
}
EXPORT_SYMBOL(seq_client_alloc_fid);

static void seq_client_proc_fini(struct lu_client_seq *seq);

#ifdef LPROCFS
static int seq_client_proc_init(struct lu_client_seq *seq)
{
        int rc;
        ENTRY;

        seq->lcs_proc_dir = lprocfs_register(seq->lcs_name,
                                             proc_lustre_root,
                                             NULL, NULL);

        if (IS_ERR(seq->lcs_proc_dir)) {
                CERROR("LProcFS failed in seq-init\n");
                rc = PTR_ERR(seq->lcs_proc_dir);
                RETURN(rc);
        }

        rc = lprocfs_add_vars(seq->lcs_proc_dir,
                              seq_client_proc_list, seq);
        if (rc) {
                CERROR("can't init sequence manager "
                       "proc, rc %d\n", rc);
                GOTO(out_cleanup, rc);
        }

        RETURN(0);

out_cleanup:
        seq_client_proc_fini(seq);
        return rc;
}

static void seq_client_proc_fini(struct lu_client_seq *seq)
{
        ENTRY;
        if (seq->lcs_proc_dir) {
                if (!IS_ERR(seq->lcs_proc_dir))
                        lprocfs_remove(seq->lcs_proc_dir);
                seq->lcs_proc_dir = NULL;
        }
        EXIT;
}
#else
static int seq_client_proc_init(struct lu_client_seq *seq)
{
        return 0;
}

static void seq_client_proc_fini(struct lu_client_seq *seq)
{
        return;
}
#endif

int seq_client_init(struct lu_client_seq *seq,
                    const char *uuid,
                    struct obd_export *exp,
                    enum lu_cli_type type)
{
        int rc = 0;
        ENTRY;

        LASSERT(exp != NULL);

        seq->lcs_type = type;
        fid_zero(&seq->lcs_fid);
        range_zero(&seq->lcs_range);
        sema_init(&seq->lcs_sem, 1);
        seq->lcs_exp = class_export_get(exp);
        seq->lcs_width = LUSTRE_SEQ_MAX_WIDTH;

        snprintf(seq->lcs_name, sizeof(seq->lcs_name),
                 "%s-cli-%s", LUSTRE_SEQ_NAME, uuid);

        rc = seq_client_proc_init(seq);
        if (rc)
                seq_client_fini(seq);
        else
                CDEBUG(D_INFO|D_WARNING,
                       "Client Sequence Manager\n");
        RETURN(rc);
}
EXPORT_SYMBOL(seq_client_init);

void seq_client_fini(struct lu_client_seq *seq)
{
        ENTRY;

        seq_client_proc_fini(seq);

        if (seq->lcs_exp != NULL) {
                class_export_put(seq->lcs_exp);
                seq->lcs_exp = NULL;
        }

        CDEBUG(D_INFO|D_WARNING, "Client Sequence Manager\n");

        EXIT;
}
EXPORT_SYMBOL(seq_client_fini);
