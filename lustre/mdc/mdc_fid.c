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
 * lustre/mdc/mdc_fid.c
 *
 * MDC fid management
 *
 * Author: Yury Umanets <umka@clusterfs.com>
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
#include <obd_support.h>
#include "mdc_internal.h"

typedef __u64 mdsno_t;
struct md_fld {
        seqno_t mf_seq;
        mdsno_t mf_mds;
};

enum fld_op {
        FLD_CREATE = 0,
        FLD_DELETE = 1,
        FLD_LOOKUP = 2 
};


static int seq_client_rpc(struct lu_client_seq *seq, struct lu_range *input,
                          struct lu_range *output, __u32 opc,
                          const char *opcname)
{
        int rc, size[3] = { sizeof(struct ptlrpc_body),
                            sizeof(__u32),
                            sizeof(struct lu_range) };
        struct obd_export *exp = seq->lcs_exp;
        struct ptlrpc_request *req;
        struct lu_range *out, *in;
        __u32 *op;
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              SEQ_QUERY, 3, size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        req->rq_export = class_export_get(exp);
        op = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(__u32));
        *op = opc;

        /* Zero out input range, this is not recovery yet. */
        in = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF + 1,
                            sizeof(struct lu_range));
        if (input != NULL)
                *in = *input;
        else
                range_zero(in);

        size[1] = sizeof(struct lu_range);
        ptlrpc_req_set_repsize(req, 2, size);

        LASSERT(seq->lcs_type == LUSTRE_SEQ_METADATA);
        req->rq_request_portal = SEQ_METADATA_PORTAL;

        mdc_get_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        mdc_put_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);

        if (rc)
                GOTO(out_req, rc);

        out = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                            sizeof(struct lu_range));
        *output = *out;

        if (!range_is_sane(output)) {
                CERROR("%s: Invalid range received from server: "
                       DRANGE"\n", seq->lcs_name, PRANGE(output));
                GOTO(out_req, rc = -EINVAL);
        }

        if (range_is_exhausted(output)) {
                CERROR("%s: Range received from server is exhausted: "
                       DRANGE"]\n", seq->lcs_name, PRANGE(output));
                GOTO(out_req, rc = -EINVAL);
        }
        *in = *out;

        CDEBUG(D_INFO, "%s: Allocated %s-sequence "DRANGE"]\n",
               seq->lcs_name, opcname, PRANGE(output));

        EXIT;
out_req:
        ptlrpc_req_finished(req);
        return rc;
}


static int fld_client_rpc(struct lu_client_seq *seq,
                          struct md_fld *mf, __u32 fld_op)
{
        int size[3] = { sizeof(struct ptlrpc_body),
                        sizeof(__u32),
                        sizeof(struct md_fld) };
        struct obd_export *exp = seq->lcs_exp;
        struct ptlrpc_request *req;
        struct md_fld *pmf;
        __u32 *op;
        int rc;
        ENTRY;

        LASSERT(exp != NULL);

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MDS_VERSION,
                              FLD_QUERY, 3, size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        req->rq_export = class_export_get(exp);
        op = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(__u32));
        *op = fld_op;

        pmf = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF + 1,
                             sizeof(struct md_fld));
        *pmf = *mf;

        size[1] = sizeof(struct md_fld);
        ptlrpc_req_set_repsize(req, 2, size);
        req->rq_request_portal = FLD_REQUEST_PORTAL;

        mdc_get_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        mdc_put_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);
        if (rc)
                GOTO(out_req, rc);

        pmf = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                             sizeof(struct md_fld));
        if (pmf == NULL)
                GOTO(out_req, rc = -EFAULT);
        *mf = *pmf;
        EXIT;
out_req:
        ptlrpc_req_finished(req);
        return rc;
}


/* Request sequence-controller node to allocate new meta-sequence. */
static int seq_client_alloc_meta(struct lu_client_seq *seq)
{
        int rc;
        ENTRY;

        rc = seq_client_rpc(seq, NULL, &seq->lcs_space,
                            SEQ_ALLOC_META, "meta");
        RETURN(rc);
}

/* Allocate new sequence for client. */
static int seq_client_alloc_seq(struct lu_client_seq *seq, seqno_t *seqnr)
{
        int rc;
        ENTRY;

        LASSERT(range_is_sane(&seq->lcs_space));

        if (range_is_exhausted(&seq->lcs_space)) {
                rc = seq_client_alloc_meta(seq);
                if (rc) {
                        CERROR("%s: Can't allocate new meta-sequence, "
                               "rc %d\n", seq->lcs_name, rc);
                        RETURN(rc);
                } else {
                        CDEBUG(D_INFO, "%s: New range - "DRANGE"\n",
                               seq->lcs_name, PRANGE(&seq->lcs_space));
                }
        } else {
                rc = 0;
        }

        LASSERT(!range_is_exhausted(&seq->lcs_space));
        *seqnr = seq->lcs_space.lr_start;
        seq->lcs_space.lr_start += 1;

        CDEBUG(D_INFO, "%s: Allocated sequence ["LPX64"]\n", seq->lcs_name,
               *seqnr);

        RETURN(rc);
}

/* Allocate new fid on passed client @seq and save it to @fid. */
static int seq_client_alloc_fid(struct lu_client_seq *seq, struct lu_fid *fid)
{
        int rc;
        ENTRY;

        LASSERT(seq != NULL);
        LASSERT(fid != NULL);

        down(&seq->lcs_sem);

        if (fid_is_zero(&seq->lcs_fid) ||
            fid_oid(&seq->lcs_fid) >= seq->lcs_width)
        {
                seqno_t seqnr;

                rc = seq_client_alloc_seq(seq, &seqnr);
                if (rc) {
                        CERROR("%s: Can't allocate new sequence, "
                               "rc %d\n", seq->lcs_name, rc);
                        up(&seq->lcs_sem);
                        RETURN(rc);
                }

                CDEBUG(D_INFO, "%s: Switch to sequence "
                       "[0x%16.16"LPF64"x]\n", seq->lcs_name, seqnr);

                seq->lcs_fid.f_seq = seqnr;
                seq->lcs_fid.f_oid = LUSTRE_FID_INIT_OID;
                seq->lcs_fid.f_ver = 0;

                /*
                 * Inform caller that sequence switch is performed to allow it
                 * to setup FLD for it.
                 */
                rc = 1;
        } else {
                /* Just bump last allocated fid and return to caller. */
                seq->lcs_fid.f_oid += 1;
                rc = 0;
        }

        *fid = seq->lcs_fid;
        up(&seq->lcs_sem);

        CDEBUG(D_INFO, "%s: Allocated FID "DFID"\n", seq->lcs_name,  PFID(fid));
        RETURN(rc);
}

/*
 * Finish the current sequence due to disconnect.
 * See mdc_import_event()
 */
static void seq_client_flush(struct lu_client_seq *seq)
{
        LASSERT(seq != NULL);
        down(&seq->lcs_sem);
        fid_init(&seq->lcs_fid);
        range_zero(&seq->lcs_space);
        up(&seq->lcs_sem);
}

static int fld_client_create(struct lu_client_seq *lcs,
                             seqno_t seq, mdsno_t mds)
{
        struct md_fld md_fld = { .mf_seq = seq, .mf_mds = mds };
        int rc;
        ENTRY;

        CDEBUG(D_INFO, "%s: Create fld entry (seq: "LPX64"; mds: "
               LPU64") on target 0\n", lcs->lcs_name, seq, mds);

        rc = fld_client_rpc(lcs, &md_fld, FLD_CREATE);
        RETURN(rc);
}

static int seq_client_proc_init(struct lu_client_seq *seq)
{
        return 0;
}

static void seq_client_proc_fini(struct lu_client_seq *seq)
{
        return;
}

int seq_client_init(struct lu_client_seq *seq,
                    struct obd_export *exp,
                    enum lu_cli_type type,
                    __u64 width,
                    const char *prefix)
{
        int rc;
        ENTRY;

        LASSERT(seq != NULL);
        LASSERT(prefix != NULL);

        seq->lcs_exp = exp;
        seq->lcs_type = type;
        sema_init(&seq->lcs_sem, 1);
        seq->lcs_width = width;

        /* Make sure that things are clear before work is started. */
        seq_client_flush(seq);

        LASSERT(seq->lcs_exp != NULL);
        seq->lcs_exp = class_export_get(seq->lcs_exp);

        snprintf(seq->lcs_name, sizeof(seq->lcs_name),
                 "cli-%s", prefix);

        rc = seq_client_proc_init(seq);
        if (rc)
                seq_client_fini(seq);
        RETURN(rc);
}

void seq_client_fini(struct lu_client_seq *seq)
{
        ENTRY;

        seq_client_proc_fini(seq);
        LASSERT(seq->lcs_exp != NULL);

        if (seq->lcs_exp != NULL) {
                class_export_put(seq->lcs_exp);
                seq->lcs_exp = NULL;
        }

        EXIT;
}

/* Allocate new fid on passed client @seq and save it to @fid. */
int mdc_fid_alloc(struct lu_client_seq *seq, struct lu_fid *fid)
{
        int rc;
        ENTRY;
        
        rc = seq_client_alloc_fid(seq, fid);
        if (rc > 0) {
                /* Client switches to new sequence, setup FLD. */
                rc = fld_client_create(seq, fid_seq(fid), 0);
                if (rc) {
                        CERROR("Can't create fld entry, rc %d\n", rc);
                        /* Delete just allocated fid sequence */
                        seq_client_flush(seq);
                }
        }
        RETURN(rc);
}

void fid_cpu_to_le(struct lu_fid *dst, const struct lu_fid *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof fid_seq(src) +
                 sizeof fid_oid(src) + sizeof fid_ver(src));
        LASSERTF(fid_is_igif(src) || fid_ver(src) == 0, DFID"\n", PFID(src));
        dst->f_seq = cpu_to_le64(fid_seq(src));
        dst->f_oid = cpu_to_le32(fid_oid(src));
        dst->f_ver = cpu_to_le32(fid_ver(src));
}
EXPORT_SYMBOL(fid_cpu_to_le);

void fid_le_to_cpu(struct lu_fid *dst, const struct lu_fid *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof fid_seq(src) +
                 sizeof fid_oid(src) + sizeof fid_ver(src));
        dst->f_seq = le64_to_cpu(fid_seq(src));
        dst->f_oid = le32_to_cpu(fid_oid(src));
        dst->f_ver = le32_to_cpu(fid_ver(src));
        LASSERTF(fid_is_igif(dst) || fid_ver(dst) == 0, DFID"\n", PFID(dst));
}
EXPORT_SYMBOL(fid_le_to_cpu);

void range_cpu_to_le(struct lu_range *dst, const struct lu_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof src->lr_start +
                 sizeof src->lr_end);
        dst->lr_start = cpu_to_le64(src->lr_start);
        dst->lr_end = cpu_to_le64(src->lr_end);
}
EXPORT_SYMBOL(range_cpu_to_le);

void range_le_to_cpu(struct lu_range *dst, const struct lu_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof src->lr_start +
                 sizeof src->lr_end);
        dst->lr_start = le64_to_cpu(src->lr_start);
        dst->lr_end = le64_to_cpu(src->lr_end);
}
EXPORT_SYMBOL(range_le_to_cpu);

void range_cpu_to_be(struct lu_range *dst, const struct lu_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof src->lr_start +
                 sizeof src->lr_end);
        dst->lr_start = cpu_to_be64(src->lr_start);
        dst->lr_end = cpu_to_be64(src->lr_end);
}
EXPORT_SYMBOL(range_cpu_to_be);

void range_be_to_cpu(struct lu_range *dst, const struct lu_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof src->lr_start +
                 sizeof src->lr_end);
        dst->lr_start = be64_to_cpu(src->lr_start);
        dst->lr_end = be64_to_cpu(src->lr_end);
}
EXPORT_SYMBOL(range_be_to_cpu);

/**     
 * Build (DLM) resource name from fid.
 */
struct ldlm_res_id *
fid_build_reg_res_name(const struct lu_fid *f, struct ldlm_res_id *name)
{       
        memset(name, 0, sizeof *name);
        name->name[LUSTRE_RES_ID_SEQ_OFF] = fid_seq(f);
        name->name[LUSTRE_RES_ID_OID_OFF] = fid_oid(f);
        if (!fid_is_igif(f))
                name->name[LUSTRE_RES_ID_VER_OFF] = fid_ver(f);
        return name;
}
EXPORT_SYMBOL(fid_build_reg_res_name);

/**
 * Return true if resource is for object identified by fid.
 */
int fid_res_name_eq(const struct lu_fid *f, const struct ldlm_res_id *name)
{
        int ret;
        
        ret = name->name[LUSTRE_RES_ID_SEQ_OFF] == fid_seq(f) &&
              name->name[LUSTRE_RES_ID_OID_OFF] == fid_oid(f);
        if (!fid_is_igif(f))
                ret = ret && name->name[LUSTRE_RES_ID_VER_OFF] == fid_ver(f);
        return ret;
}
EXPORT_SYMBOL(fid_res_name_eq);
