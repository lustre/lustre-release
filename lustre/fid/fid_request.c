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
                          __u32 opc)
{
        struct obd_export *exp = seq->seq_exp;
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

        req_capsule_init(&pill, req, RCL_CLIENT,
                         &repsize);

        req_capsule_set(&pill, &RQF_SEQ_QUERY);

        op = req_capsule_client_get(&pill, &RMF_SEQ_OPC);
        *op = opc;

        req->rq_replen = lustre_msg_size(1, &repsize);
        
        req->rq_request_portal = (opc == SEQ_ALLOC_SUPER) ?
                SEQ_CTLR_PORTAL : SEQ_SRV_PORTAL;

        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(out_req, rc);

        ran = req_capsule_server_get(&pill, &RMF_SEQ_RANGE);
        if (ran == NULL) {
                CERROR("invalid range is returned\n");
                GOTO(out_req, rc = -EPROTO);
        }
        *range = *ran;
        
        LASSERT(range_is_sane(range));
        LASSERT(!range_is_exhausted(range));
        
        EXIT;
out_req:
        req_capsule_fini(&pill);
        ptlrpc_req_finished(req); 
        return rc;
}

static int __seq_client_alloc_opc(struct lu_client_seq *seq,
                                  int opc, const char *opcname)
{
        int rc;
        ENTRY;

        rc = seq_client_rpc(seq, &seq->seq_range, opc);
        if (rc == 0) {
                CDEBUG(D_INFO, "%s: allocated %s-sequence ["
                       LPX64"-"LPX64"]\n", seq->seq_name, opcname,
                       seq->seq_range.lr_start, seq->seq_range.lr_end);
        }
        RETURN(rc);
}

/* request sequence-controller node to allocate new super-sequence. */
static int __seq_client_alloc_super(struct lu_client_seq *seq)
{
        ENTRY;
        RETURN(__seq_client_alloc_opc(seq, SEQ_ALLOC_SUPER, "super"));
}

int seq_client_alloc_super(struct lu_client_seq *seq)
{
        int rc;
        ENTRY;
        
        down(&seq->seq_sem);
        rc = __seq_client_alloc_super(seq);
        up(&seq->seq_sem);

        RETURN(rc);
}
EXPORT_SYMBOL(seq_client_alloc_super);

/* request sequence-controller node to allocate new meta-sequence. */
static int __seq_client_alloc_meta(struct lu_client_seq *seq)
{
        ENTRY;
        RETURN(__seq_client_alloc_opc(seq, SEQ_ALLOC_META, "meta"));
}

int seq_client_alloc_meta(struct lu_client_seq *seq)
{
        int rc;
        ENTRY;

        down(&seq->seq_sem);
        rc = __seq_client_alloc_meta(seq);
        up(&seq->seq_sem);

        RETURN(rc);
}
EXPORT_SYMBOL(seq_client_alloc_meta);

/* allocate new sequence for client (llite or MDC are expected to use this) */
static int __seq_client_alloc_seq(struct lu_client_seq *seq, seqno_t *seqnr)
{
        int rc = 0;
        ENTRY;

        LASSERT(range_is_sane(&seq->seq_range));

        /* if we still have free sequences in meta-sequence we allocate new seq
         * from given range, if not - allocate new meta-sequence. */
        if (range_space(&seq->seq_range) == 0) {
                rc = __seq_client_alloc_meta(seq);
                if (rc) {
                        CERROR("can't allocate new meta-sequence, "
                               "rc %d\n", rc);
                        RETURN(rc);
                }
        }
        
        *seqnr = seq->seq_range.lr_start;
        seq->seq_range.lr_start++;
        
        CDEBUG(D_INFO, "%s: allocated sequence ["LPX64"]\n",
               seq->seq_name, *seqnr);
        RETURN(rc);
}

int seq_client_alloc_seq(struct lu_client_seq *seq, seqno_t *seqnr)
{
        int rc = 0;
        ENTRY;

        down(&seq->seq_sem);
        rc = __seq_client_alloc_seq(seq, seqnr);
        up(&seq->seq_sem);

        RETURN(rc);
}
EXPORT_SYMBOL(seq_client_alloc_seq);

int seq_client_alloc_fid(struct lu_client_seq *seq, struct lu_fid *fid)
{
        seqno_t seqnr = 0;
        int rc;
        ENTRY;

        LASSERT(fid != NULL);

        down(&seq->seq_sem);

        if (!fid_is_sane(&seq->seq_fid) ||
            fid_oid(&seq->seq_fid) >= seq->seq_width)
        {
                /* allocate new sequence for case client hass no sequence at all
                 * or sequnece is exhausted and should be switched. */
                rc = __seq_client_alloc_seq(seq, &seqnr);
                if (rc) {
                        CERROR("can't allocate new sequence, "
                               "rc %d\n", rc);
                        GOTO(out, rc);
                }

                /* init new fid */
                seq->seq_fid.f_oid = LUSTRE_FID_INIT_OID;
                seq->seq_fid.f_seq = seqnr;
                seq->seq_fid.f_ver = 0;

                /* inform caller that sequnece switch is performed to allow it
                 * to setup FLD for it. */
                rc = -ERESTART;
        } else {
                seq->seq_fid.f_oid++;
                rc = 0;
        }

        *fid = seq->seq_fid;
        LASSERT(fid_is_sane(fid));
        
        CDEBUG(D_INFO, "%s: allocated FID "DFID3"\n",
               seq->seq_name, PFID3(fid));

        EXIT;
out:
        up(&seq->seq_sem);
        return rc;
}
EXPORT_SYMBOL(seq_client_alloc_fid);

#ifdef LPROCFS
static int seq_client_proc_init(struct lu_client_seq *seq)
{
        int rc;
        ENTRY;

        seq->seq_proc_dir = lprocfs_register(seq->seq_name,
                                             proc_lustre_root,
                                             NULL, NULL);
        
        if (IS_ERR(seq->seq_proc_dir)) {
                CERROR("LProcFS failed in seq-init\n");
                rc = PTR_ERR(seq->seq_proc_dir);
                GOTO(err, rc);
        }

        rc = lprocfs_add_vars(seq->seq_proc_dir,
                              seq_client_proc_list, seq);
        if (rc) {
                CERROR("can't init sequence manager "
                       "proc, rc %d\n", rc);
                GOTO(err_dir, rc);
        }

        RETURN(0);

err_dir:
        lprocfs_remove(seq->seq_proc_dir);
err:
        seq->seq_proc_dir = NULL;
        return rc;
}

static void seq_client_proc_fini(struct lu_client_seq *seq)
{
        ENTRY;
        if (seq->seq_proc_dir) {
                lprocfs_remove(seq->seq_proc_dir);
                seq->seq_proc_dir = NULL;
        }
        EXIT;
}
#endif

int seq_client_init(struct lu_client_seq *seq,
                    const char *uuid,
                    struct obd_export *exp)
{
        int rc = 0;
        ENTRY;

        LASSERT(exp != NULL);
        
        fid_zero(&seq->seq_fid);
        range_zero(&seq->seq_range);
        sema_init(&seq->seq_sem, 1);
        seq->seq_exp = class_export_get(exp);
        seq->seq_width = LUSTRE_SEQ_MAX_WIDTH;

        snprintf(seq->seq_name, sizeof(seq->seq_name),
                 "%s-cli-%s", LUSTRE_SEQ_NAME, uuid);

#ifdef LPROCFS
        rc = seq_client_proc_init(seq);
#endif

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

#ifdef LPROCFS
        seq_client_proc_fini(seq);
#endif
        
        if (seq->seq_exp != NULL) {
                class_export_put(seq->seq_exp);
                seq->seq_exp = NULL;
        }
        
        CDEBUG(D_INFO|D_WARNING, "Client Sequence Manager\n");
        
        EXIT;
}
EXPORT_SYMBOL(seq_client_fini);
