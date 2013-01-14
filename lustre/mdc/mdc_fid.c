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
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
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

static int seq_client_rpc(struct lu_client_seq *seq, struct lu_seq_range *input,
                          struct lu_seq_range *output, __u32 opc,
                          const char *opcname)
{
        int rc;
        __u32 size[3] = { sizeof(struct ptlrpc_body),
                            sizeof(__u32),
                            sizeof(struct lu_seq_range) };
        struct obd_export *exp = seq->lcs_exp;
        struct ptlrpc_request *req;
        struct lu_seq_range *out, *in;
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
                            sizeof(struct lu_seq_range));
        if (input != NULL)
                *in = *input;
        else
                range_init(in);

        size[1] = sizeof(struct lu_seq_range);
        ptlrpc_req_set_repsize(req, 2, size);

        LASSERT(seq->lcs_type == LUSTRE_SEQ_METADATA);
        req->rq_request_portal = SEQ_METADATA_PORTAL;

        mdc_get_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);
        rc = ptlrpc_queue_wait(req);
        mdc_put_rpc_lock(exp->exp_obd->u.cli.cl_rpc_lock, NULL);

        if (rc)
                GOTO(out_req, rc);

        out = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                            sizeof(struct lu_seq_range));
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
        *seqnr = seq->lcs_space.lsr_start;
        seq->lcs_space.lsr_start += 1;

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
void seq_client_flush(struct lu_client_seq *seq)
{
        LASSERT(seq != NULL);
        down(&seq->lcs_sem);
        fid_init(&seq->lcs_fid);
        /**
         * this id shld not be used for seq range allocation.
         * set to -1 for dgb check.
         */
        seq->lcs_space.lsr_mdt = -1;
        range_init(&seq->lcs_space);
        up(&seq->lcs_sem);
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
        if (rc > 0)
                rc = 0;
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

void range_cpu_to_le(struct lu_seq_range *dst, const struct lu_seq_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof(*src) ==
                 sizeof(src->lsr_start) +
                 sizeof(src->lsr_end) +
                 sizeof(src->lsr_mdt) +
                 sizeof(src->lsr_padding));
        dst->lsr_start = cpu_to_le64(src->lsr_start);
        dst->lsr_end = cpu_to_le64(src->lsr_end);
}
EXPORT_SYMBOL(range_cpu_to_le);

void range_le_to_cpu(struct lu_seq_range *dst, const struct lu_seq_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof(*src) ==
                 sizeof(src->lsr_start) +
                 sizeof(src->lsr_end) +
                 sizeof(src->lsr_mdt) +
                 sizeof(src->lsr_padding));

        dst->lsr_start = le64_to_cpu(src->lsr_start);
        dst->lsr_end = le64_to_cpu(src->lsr_end);
}
EXPORT_SYMBOL(range_le_to_cpu);

void range_cpu_to_be(struct lu_seq_range *dst, const struct lu_seq_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof(*src) ==
                 sizeof(src->lsr_start) +
                 sizeof(src->lsr_end) +
                 sizeof(src->lsr_mdt) +
                 sizeof(src->lsr_padding));

        dst->lsr_start = cpu_to_be64(src->lsr_start);
        dst->lsr_end = cpu_to_be64(src->lsr_end);
}
EXPORT_SYMBOL(range_cpu_to_be);

void range_be_to_cpu(struct lu_seq_range *dst, const struct lu_seq_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof(*src) ==
                 sizeof(src->lsr_start) +
                 sizeof(src->lsr_end) +
                 sizeof(src->lsr_mdt) +
                 sizeof(src->lsr_padding));

        dst->lsr_start = be64_to_cpu(src->lsr_start);
        dst->lsr_end = be64_to_cpu(src->lsr_end);
}
EXPORT_SYMBOL(range_be_to_cpu);

/**
 * Build (DLM) resource name from fid.
 *
 * NOTE: until Lustre 1.8.7/2.1.1 the fid_ver() was packed into name[2],
 * but was moved into name[1] along with the OID to avoid consuming the
 * renaming name[2,3] fields that need to be used for the quota identifier.
 */
struct ldlm_res_id *
fid_build_reg_res_name(const struct lu_fid *f, struct ldlm_res_id *name)
{
        memset(name, 0, sizeof *name);
        name->name[LUSTRE_RES_ID_SEQ_OFF] = fid_seq(f);
        name->name[LUSTRE_RES_ID_VER_OID_OFF] = fid_oid(f);
        if (!fid_is_igif(f))
                name->name[LUSTRE_RES_ID_VER_OID_OFF] |= (__u64)fid_ver(f)<<32;
        return name;
}
EXPORT_SYMBOL(fid_build_reg_res_name);

/**
 * Return true if resource is for object identified by fid.
 */
int fid_res_name_eq(const struct lu_fid *f, const struct ldlm_res_id *name)
{
	return name->name[LUSTRE_RES_ID_SEQ_OFF] == fid_seq(f) &&
	       name->name[LUSTRE_RES_ID_VER_OID_OFF] ==
	       (fid_oid(f) | (fid_is_igif(f) ? 0 : (__u64)fid_ver(f)<<32));
}
EXPORT_SYMBOL(fid_res_name_eq);
