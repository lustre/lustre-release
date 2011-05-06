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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDC

#ifdef __KERNEL__
# include <linux/module.h>
# include <linux/pagemap.h>
# include <linux/miscdevice.h>
# include <linux/init.h>
#else
# include <liblustre.h>
#endif

#include <obd_class.h>
#include <lustre_dlm.h>
#include <lprocfs_status.h>
#include "mdc_internal.h"

int it_open_error(int phase, struct lookup_intent *it)
{
        if (it_disposition(it, DISP_OPEN_OPEN)) {
                if (phase >= DISP_OPEN_OPEN)
                        return it->d.lustre.it_status;
                else
                        return 0;
        }

        if (it_disposition(it, DISP_OPEN_CREATE)) {
                if (phase >= DISP_OPEN_CREATE)
                        return it->d.lustre.it_status;
                else
                        return 0;
        }

        if (it_disposition(it, DISP_LOOKUP_EXECD)) {
                if (phase >= DISP_LOOKUP_EXECD)
                        return it->d.lustre.it_status;
                else
                        return 0;
        }

        if (it_disposition(it, DISP_IT_EXECD)) {
                if (phase >= DISP_IT_EXECD)
                        return it->d.lustre.it_status;
                else
                        return 0;
        }
        CERROR("it disp: %X, status: %d\n", it->d.lustre.it_disposition,
               it->d.lustre.it_status);
        LBUG();
        return 0;
}
EXPORT_SYMBOL(it_open_error);

/* this must be called on a lockh that is known to have a referenced lock */
void mdc_set_lock_data(__u64 *l, void *data, __u32 *bits)
{
        struct ldlm_lock *lock;
        struct lustre_handle *lockh = (struct lustre_handle *)l;
        ENTRY;

        if(bits)
                *bits = 0;

        if (!*l) {
                EXIT;
                return;
        }

        lock = ldlm_handle2lock(lockh);

        LASSERT(lock != NULL);
        lock_res_and_lock(lock);
#ifdef __KERNEL__
        if (lock->l_ast_data && lock->l_ast_data != data) {
                struct inode *new_inode = data;
                struct inode *old_inode = lock->l_ast_data;
                LASSERTF(old_inode->i_state & I_FREEING,
                         "Found existing inode %p/%lu/%u state %lu in lock: "
                         "setting data to %p/%lu/%u\n", old_inode,
                         old_inode->i_ino, old_inode->i_generation,
                         old_inode->i_state,
                         new_inode, new_inode->i_ino, new_inode->i_generation);
        }
#endif
        lock->l_ast_data = data;
        if (bits)
                *bits = lock->l_policy_data.l_inodebits.bits;
        unlock_res_and_lock(lock);
        LDLM_LOCK_PUT(lock);

        EXIT;
}
EXPORT_SYMBOL(mdc_set_lock_data);

int mdc_change_cbdata(struct obd_export *exp, struct ll_fid *fid, 
                      ldlm_iterator_t it, void *data)
{
        struct ldlm_res_id res_id;
        ENTRY;

        fid_build_reg_res_name((struct lu_fid*)fid, &res_id);
        ldlm_resource_iterate(class_exp2obd(exp)->obd_namespace, &res_id,
                              it, data);

        EXIT;
        return 0;
}

/* find any ldlm lock of the inode in mdc
 * return 0    not find
 *        1    find one
 *      < 0    error */
int mdc_find_cbdata(struct obd_export *exp, struct ll_fid *fid,
                    ldlm_iterator_t it, void *data)
{
        struct ldlm_res_id res_id;
        int rc = 0;
        ENTRY;

        fid_build_reg_res_name((struct lu_fid*)fid, &res_id);
        rc = ldlm_resource_iterate(class_exp2obd(exp)->obd_namespace, &res_id,
                                   it, data);
        if (rc == LDLM_ITER_STOP)
                RETURN(1);
        else if (rc == LDLM_ITER_CONTINUE)
                RETURN(0);
        RETURN(rc);
}

static inline void mdc_clear_replay_flag(struct ptlrpc_request *req, int rc)
{
        /* Don't hold error requests for replay. */
        if (req->rq_replay) {
                spin_lock(&req->rq_lock);
                req->rq_replay = 0;
                spin_unlock(&req->rq_lock);
        }
        if (rc && req->rq_transno != 0) {
                DEBUG_REQ(D_ERROR, req, "transno returned on error rc %d", rc);
                LBUG();
        }
}

static int round_up(int val)
{
        int ret = 1;
        while (val) {
                val >>= 1;
                ret <<= 1;
        }
        return ret;
}

/* Save a large LOV EA into the request buffer so that it is available
 * for replay.  We don't do this in the initial request because the
 * original request doesn't need this buffer (at most it sends just the
 * lov_mds_md) and it is a waste of RAM/bandwidth to send the empty
 * buffer and may also be difficult to allocate and save a very large
 * request buffer for each open. (bug 5707)
 *
 * OOM here may cause recovery failure if lmm is needed (only for the
 * original open if the MDS crashed just when this client also OOM'd)
 * but this is incredibly unlikely, and questionable whether the client
 * could do MDS recovery under OOM anyways... */
static void mdc_realloc_openmsg(struct ptlrpc_request *req,
                                struct mds_body *body)
{
        int old_len, new_size, old_size;
        struct lustre_msg *old_msg = req->rq_reqmsg;
        struct lustre_msg *new_msg;
        int offset;

        if (mdc_req_is_2_0_server(req))
                offset = 4;
        else
                offset = 2;

        old_len = lustre_msg_buflen(old_msg, DLM_INTENT_REC_OFF + offset);
        old_size = lustre_packed_msg_size(old_msg);
        lustre_msg_set_buflen(old_msg, DLM_INTENT_REC_OFF + offset,
                              body->eadatasize);
        /* old buffer is more then need */
        if (old_len > body->eadatasize)
                return;

        new_size = lustre_packed_msg_size(old_msg);

        OBD_ALLOC(new_msg, new_size);
        if (new_msg != NULL) {
                DEBUG_REQ(D_INFO, req, "replace reqmsg for larger EA %u",
                          body->eadatasize);
                memcpy(new_msg, old_msg, old_size);

                spin_lock(&req->rq_lock);
                req->rq_reqmsg = new_msg;
                req->rq_reqlen = new_size;
                spin_unlock(&req->rq_lock);

                OBD_FREE(old_msg, old_size);
        } else {
                lustre_msg_set_buflen(old_msg,
                                      DLM_INTENT_REC_OFF + offset, old_len);
                body->valid &= ~OBD_MD_FLEASIZE;
                body->eadatasize = 0;
        }
}

static struct ptlrpc_request *mdc_intent_open_pack(struct obd_export *exp,
                                                   struct lookup_intent *it,
                                                   struct mdc_op_data *data,
                                                   void *lmm, __u32 lmmsize)
{
        struct ptlrpc_request *req;
        struct ldlm_intent *lit;
        struct obd_device *obddev = class_exp2obd(exp);
        __u32 size[9] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                        [DLM_LOCKREQ_OFF]     = sizeof(struct ldlm_request),
                        [DLM_INTENT_IT_OFF]   = sizeof(*lit),
                        [DLM_INTENT_REC_OFF]  = sizeof(struct mds_rec_create),
                        [DLM_INTENT_REC_OFF+1]= data->namelen + 1,
                        /* As an optimization, we allocate an RPC request buffer
                         * for at least a default-sized LOV EA even if we aren't
                         * sending one.  We grow the whole request to the next
                         * power-of-two size since we get that much from a slab
                         * allocation anyways. This avoids an allocation below
                         * in the common case where we need to save a
                         * default-sized LOV EA for open replay. */
                        [DLM_INTENT_REC_OFF+2]= max(lmmsize,
                                         obddev->u.cli.cl_default_mds_easize) };
        __u32 repsize[7] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                           [DLM_LOCKREPLY_OFF]   = sizeof(struct ldlm_reply),
                           [DLM_REPLY_REC_OFF]   = sizeof(struct mdt_body),
                           [DLM_REPLY_REC_OFF+1] = obddev->u.cli.
                                                        cl_max_mds_easize,
                           [DLM_REPLY_REC_OFF+2] = LUSTRE_POSIX_ACL_MAX_SIZE };
        CFS_LIST_HEAD(cancels);
        int do_join = (it->it_create_mode & M_JOIN_FILE) && data->data;
        int count = 0;
        int bufcount = 6;
        int repbufcount = 5;
        int mode;
        int rc;
        ENTRY;

        it->it_create_mode = (it->it_create_mode & ~S_IFMT) | S_IFREG;
        if (mdc_exp_is_2_0_server(exp)) {
                size[DLM_INTENT_REC_OFF] = sizeof(struct mdt_rec_create);
                size[DLM_INTENT_REC_OFF+4] = size[DLM_INTENT_REC_OFF+2];
                size[DLM_INTENT_REC_OFF+3] = size[DLM_INTENT_REC_OFF+1];
                size[DLM_INTENT_REC_OFF+2] = 0; /* capa */
                size[DLM_INTENT_REC_OFF+1] = 0; /* capa */
                bufcount = 8;
                repsize[DLM_REPLY_REC_OFF+3]=sizeof(struct lustre_capa);
                repsize[DLM_REPLY_REC_OFF+4]=sizeof(struct lustre_capa);
                repbufcount = 7;
        }
        rc = lustre_msg_size(class_exp2cliimp(exp)->imp_msg_magic,
                             bufcount, size);
        if (rc & (rc - 1))
                size[bufcount - 1] = min(size[bufcount - 1] + round_up(rc) - rc,
                                         (__u32)obddev->u.cli.cl_max_mds_easize);

        /* If inode is known, cancel conflicting OPEN locks. */
        if (data->fid2.id) {
                if (it->it_flags & (FMODE_WRITE|MDS_OPEN_TRUNC))
                        mode = LCK_CW;
#ifdef FMODE_EXEC
                else if (it->it_flags & FMODE_EXEC)
                        mode = LCK_PR;
#endif
                else
                        mode = LCK_CR;
                count = mdc_resource_get_unused(exp, &data->fid2, &cancels,
                                                mode, MDS_INODELOCK_OPEN);
        }

        /* If CREATE or JOIN_FILE, cancel parent's UPDATE lock. */
        if (it->it_op & IT_CREAT || do_join)
                mode = LCK_EX;
        else
                mode = LCK_CR;
        count += mdc_resource_get_unused(exp, &data->fid1, &cancels, mode,
                                         MDS_INODELOCK_UPDATE);
        if (do_join) {
                __u64 head_size = (*(__u64 *)data->data);
                /* join is like an unlink of the tail */
                if (mdc_exp_is_2_0_server(exp)) {
                        size[DLM_INTENT_REC_OFF+5]=sizeof(struct mdt_rec_join);
                } else {
                        size[DLM_INTENT_REC_OFF+3]=sizeof(struct mds_rec_join);
                }
                bufcount++;

                req = ldlm_prep_enqueue_req(exp, bufcount, size,&cancels,count);
                if (req)
                        mdc_join_pack(req, bufcount - 1, data, head_size);
        } else {
                req = ldlm_prep_enqueue_req(exp, bufcount, size,&cancels,count);
                it->it_create_mode &= ~M_JOIN_FILE;
        }

        if (req) {
                spin_lock(&req->rq_lock);
                req->rq_replay = req->rq_import->imp_replayable;
                spin_unlock(&req->rq_lock);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, DLM_INTENT_IT_OFF,
                                     sizeof(*lit));
                lit->opc = (__u64)it->it_op;

                /* pack the intended request */
                mdc_open_pack(req, DLM_INTENT_REC_OFF, data,
                              it->it_create_mode, 0, it->it_flags,
                              lmm, lmmsize);

                ptlrpc_req_set_repsize(req, repbufcount, repsize);
        }
        RETURN(req);
}

static struct ptlrpc_request *mdc_intent_unlink_pack(struct obd_export *exp,
                                                     struct lookup_intent *it,
                                                     struct mdc_op_data *data)
{
        struct ptlrpc_request *req;
        struct ldlm_intent *lit;
        struct obd_device *obddev = class_exp2obd(exp);
        __u32 size[5] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                        [DLM_LOCKREQ_OFF]     = sizeof(struct ldlm_request),
                        [DLM_INTENT_IT_OFF]   = sizeof(*lit),
                        [DLM_INTENT_REC_OFF]  = mdc_exp_is_2_0_server(exp) ?
                                                sizeof(struct mdt_rec_unlink) :
                                                sizeof(struct mds_rec_unlink),
                        [DLM_INTENT_REC_OFF+1]= data->namelen + 1 };
        __u32 repsize[5] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                           [DLM_LOCKREPLY_OFF]   = sizeof(struct ldlm_reply),
                           [DLM_REPLY_REC_OFF]   = sizeof(struct mdt_body),
                           [DLM_REPLY_REC_OFF+1] = obddev->u.cli.
                                                        cl_max_mds_easize,
                           [DLM_REPLY_REC_OFF+2] = obddev->u.cli.
                                                        cl_max_mds_cookiesize };
        ENTRY;

        req = ldlm_prep_enqueue_req(exp, 5, size, NULL, 0);
        if (req) {
                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, DLM_INTENT_IT_OFF,
                                     sizeof(*lit));
                lit->opc = (__u64)it->it_op;

                /* pack the intended request */
                mdc_unlink_pack(req, DLM_INTENT_REC_OFF, data);

                ptlrpc_req_set_repsize(req, 5, repsize);
        }
        RETURN(req);
}

static struct ptlrpc_request *mdc_intent_lookup_pack(struct obd_export *exp,
                                                     struct lookup_intent *it,
                                                     struct mdc_op_data *data)
{
        struct ptlrpc_request *req;
        struct ldlm_intent *lit;
        struct obd_device *obddev = class_exp2obd(exp);
        __u32 size[6] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                        [DLM_LOCKREQ_OFF]     = sizeof(struct ldlm_request),
                        [DLM_INTENT_IT_OFF]   = sizeof(*lit),
                        [DLM_INTENT_REC_OFF]  = sizeof(struct mdt_body),
                        [DLM_INTENT_REC_OFF+1]= data->namelen + 1,
                        [DLM_INTENT_REC_OFF+2]= 0 };
        __u32 repsize[6] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                           [DLM_LOCKREPLY_OFF]   = sizeof(struct ldlm_reply),
                           [DLM_REPLY_REC_OFF]   = sizeof(struct mdt_body),
                           [DLM_REPLY_REC_OFF+1] = obddev->u.cli.
                                                        cl_max_mds_easize,
                           [DLM_REPLY_REC_OFF+2] = LUSTRE_POSIX_ACL_MAX_SIZE,
                           [DLM_REPLY_REC_OFF+3] = 0 };
        obd_valid valid = OBD_MD_FLGETATTR | OBD_MD_FLEASIZE | OBD_MD_FLACL |
                          OBD_MD_FLMODEASIZE | OBD_MD_FLDIREA;
        int bufcount = 5;
        ENTRY;

        if (mdc_exp_is_2_0_server(exp)) {
                size[DLM_INTENT_REC_OFF+1] = 0; /* capa */
                size[DLM_INTENT_REC_OFF+2] = data->namelen + 1;
                bufcount = 6;
        }
        req = ldlm_prep_enqueue_req(exp, bufcount, size, NULL, 0);
        if (req) {
                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, DLM_INTENT_IT_OFF,
                                     sizeof(*lit));
                lit->opc = (__u64)it->it_op;

                /* pack the intended request */
                mdc_getattr_pack(req, DLM_INTENT_REC_OFF, valid, it->it_flags,
                                 data, obddev->u.cli.cl_max_mds_easize);
                ptlrpc_req_set_repsize(req, bufcount, repsize);
        }
        RETURN(req);
}

static struct ptlrpc_request *mdc_intent_readdir_pack(struct obd_export *exp)
{
        struct ptlrpc_request *req;
        __u32 size[2] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                        [DLM_LOCKREQ_OFF]     = sizeof(struct ldlm_request) };
        __u32 repsize[3] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                           [DLM_LOCKREPLY_OFF]   = sizeof(struct ldlm_reply),
                           [DLM_REPLY_REC_OFF] = sizeof(struct ost_lvb) };
        ENTRY;

        req = ldlm_prep_enqueue_req(exp, 2, size, NULL, 0);
        if (req)
                ptlrpc_req_set_repsize(req, 3, repsize);
        RETURN(req);
}

static int mdc_finish_enqueue(struct obd_export *exp,
                              struct ptlrpc_request *req,
                              struct ldlm_enqueue_info *einfo,
                              struct lookup_intent *it,
                              struct lustre_handle *lockh,
                              int rc)
{
        struct ldlm_request *lockreq;
        struct ldlm_reply *lockrep;
        ENTRY;

        LASSERT(rc >= 0);
        /* Similarly, if we're going to replay this request, we don't want to
         * actually get a lock, just perform the intent. */
        if (req->rq_transno || req->rq_replay) {
                lockreq = lustre_msg_buf(req->rq_reqmsg, DLM_LOCKREQ_OFF,
                                         sizeof(*lockreq));
                lockreq->lock_flags |= LDLM_FL_INTENT_ONLY;
        }

        if (rc == ELDLM_LOCK_ABORTED) {
                einfo->ei_mode = 0;
                memset(lockh, 0, sizeof(*lockh));
                rc = 0;
        } else { /* rc = 0 */
                struct ldlm_lock *lock = ldlm_handle2lock(lockh);
                LASSERT(lock);

                /* If the server gave us back a different lock mode, we should
                 * fix up our variables. */
                if (lock->l_req_mode != einfo->ei_mode) {
                        ldlm_lock_addref(lockh, lock->l_req_mode);
                        ldlm_lock_decref(lockh, einfo->ei_mode);
                        einfo->ei_mode = lock->l_req_mode;
                }
                LDLM_LOCK_PUT(lock);
        }

        lockrep = lustre_msg_buf(req->rq_repmsg, DLM_LOCKREPLY_OFF,
                                 sizeof(*lockrep));
        LASSERT(lockrep != NULL);  /* checked by ldlm_cli_enqueue() */
        /* swabbed by ldlm_cli_enqueue() */
        LASSERT(lustre_rep_swabbed(req, DLM_LOCKREPLY_OFF));

        it->d.lustre.it_disposition = (int)lockrep->lock_policy_res1;
        it->d.lustre.it_status = (int)lockrep->lock_policy_res2;
        it->d.lustre.it_lock_mode = einfo->ei_mode;
        it->d.lustre.it_lock_handle = lockh->cookie;
        it->d.lustre.it_data = req;

        if (it->d.lustre.it_status < 0 && req->rq_replay)
                mdc_clear_replay_flag(req, it->d.lustre.it_status);

        /* If we're doing an IT_OPEN which did not result in an actual
         * successful open, then we need to remove the bit which saves
         * this request for unconditional replay.
         *
         * It's important that we do this first!  Otherwise we might exit the
         * function without doing so, and try to replay a failed create
         * (bug 3440) */
        if ((it->it_op & IT_OPEN) &&
            req->rq_replay &&
            (!it_disposition(it, DISP_OPEN_OPEN) ||
             it->d.lustre.it_status != 0))
                mdc_clear_replay_flag(req, it->d.lustre.it_status);

        DEBUG_REQ(D_RPCTRACE, req, "op: %d disposition: %x, status: %d",
                  it->it_op,it->d.lustre.it_disposition,it->d.lustre.it_status);

        /* We know what to expect, so we do any byte flipping required here */
        if (it->it_op & (IT_OPEN | IT_UNLINK | IT_LOOKUP | IT_GETATTR)) {
                struct mds_body *body;

                body = lustre_swab_repbuf(req, DLM_REPLY_REC_OFF, sizeof(*body),
                                         lustre_swab_mds_body);
                if (body == NULL) {
                        CERROR ("Can't swab mds_body\n");
                        RETURN (-EPROTO);
                }

                /* If this is a successful OPEN request, we need to set
                   replay handler and data early, so that if replay happens
                   immediately after swabbing below, new reply is swabbed
                   by that handler correctly */
                if (it_disposition(it, DISP_OPEN_OPEN) &&
                    !it_open_error(DISP_OPEN_OPEN, it))
                        mdc_set_open_replay_data(NULL, req);

                if ((body->valid & OBD_MD_FLEASIZE) != 0) {
                        void *eadata;

                        mdc_update_max_ea_from_body(exp, body);

                        /* The eadata is opaque; just check that it is there.
                         * Eventually, obd_unpackmd() will check the contents */
                        eadata = lustre_swab_repbuf(req, DLM_REPLY_REC_OFF + 1,
                                                    body->eadatasize, NULL);
                        if (eadata == NULL) {
                                CERROR ("Missing/short eadata\n");
                                RETURN (-EPROTO);
                        }
                        /* We save the reply LOV EA in case we have to replay
                         * a create for recovery.  If we didn't allocate a
                         * large enough request buffer above we need to
                         * reallocate it here to hold the actual LOV EA. */
                        if (it->it_op & IT_OPEN) {
                                int offset = DLM_INTENT_REC_OFF;
                                void *lmm;

                                if (mdc_req_is_2_0_server(req))
                                        offset += 4;
                                else
                                        offset += 2;

                                if (lustre_msg_buflen(req->rq_reqmsg, offset) !=
                                    body->eadatasize)
                                        mdc_realloc_openmsg(req, body);

                                lmm = lustre_msg_buf(req->rq_reqmsg, offset,
                                                     body->eadatasize);
                                if (lmm)
                                        memcpy(lmm, eadata, body->eadatasize);
                        }
                }
        }

        RETURN(rc);
}

/* We always reserve enough space in the reply packet for a stripe MD, because
 * we don't know in advance the file type. */
int mdc_enqueue(struct obd_export *exp, struct ldlm_enqueue_info *einfo,
                struct lookup_intent *it, struct mdc_op_data *data,
                struct lustre_handle *lockh, void *lmm, int lmmsize,
                int extra_lock_flags)
{
        struct ptlrpc_request *req;
        struct obd_device *obddev = class_exp2obd(exp);
        struct ldlm_res_id res_id;
        ldlm_policy_data_t policy = { .l_inodebits = { MDS_INODELOCK_LOOKUP } };
        int flags = extra_lock_flags | LDLM_FL_HAS_INTENT;
        int rc;
        ENTRY;

        fid_build_reg_res_name((void *)&data->fid1, &res_id);
        LASSERTF(einfo->ei_type == LDLM_IBITS,"lock type %d\n", einfo->ei_type);
        if (it->it_op & (IT_UNLINK | IT_GETATTR | IT_READDIR))
                policy.l_inodebits.bits = MDS_INODELOCK_UPDATE;

        if (it->it_op & IT_OPEN) {
                if ((it->it_op & IT_CREAT) && mdc_exp_is_2_0_server(exp)) {
                        struct client_obd *cli = &obddev->u.cli;
                        data->fid3 = data->fid2;
                        rc = mdc_fid_alloc(cli->cl_seq, (void *)&data->fid2);
                        if (rc) {
                                CERROR("fid allocation result: %d\n", rc);
                                RETURN(rc);
                        }
                }
                req = mdc_intent_open_pack(exp, it, data, lmm, lmmsize);
                if (it->it_create_mode & M_JOIN_FILE) {
                        policy.l_inodebits.bits = MDS_INODELOCK_UPDATE;
                }
        } else if (it->it_op & IT_UNLINK) {
                req = mdc_intent_unlink_pack(exp, it, data);
        } else if (it->it_op & (IT_GETATTR | IT_LOOKUP)) {
                req = mdc_intent_lookup_pack(exp, it, data);
        } else if (it->it_op == IT_READDIR) {
                req = mdc_intent_readdir_pack(exp);
        } else {
                CERROR("bad it_op %x\n", it->it_op);
                RETURN(-EINVAL);
        }

        if (!req)
                RETURN(-ENOMEM);

         /* It is important to obtain rpc_lock first (if applicable), so that
          * threads that are serialised with rpc_lock are not polluting our
          * rpcs in flight counter */
        mdc_get_rpc_lock(obddev->u.cli.cl_rpc_lock, it);
        rc = mdc_enter_request(&obddev->u.cli);
        if (rc == 0) {
                rc = ldlm_cli_enqueue(exp, &req, einfo, res_id, &policy, &flags,
                                      NULL, 0, NULL, lockh, 0);
                mdc_exit_request(&obddev->u.cli);
                if (rc < 0)
                        CERROR("ldlm_cli_enqueue error: %d\n", rc);
        }
        mdc_put_rpc_lock(obddev->u.cli.cl_rpc_lock, it);
        if (rc < 0) {
                mdc_clear_replay_flag(req, rc);
                ptlrpc_req_finished(req);
                RETURN(rc);
        }
        rc = mdc_finish_enqueue(exp, req, einfo, it, lockh, rc);

        RETURN(rc);
}
EXPORT_SYMBOL(mdc_enqueue);

int mdc_revalidate_lock(struct obd_export *exp, struct lookup_intent *it,
                        struct ll_fid *fid)
{
                /* We could just return 1 immediately, but since we should only
                 * be called in revalidate_it if we already have a lock, let's
                 * verify that. */
        struct ldlm_res_id res_id;
        struct lustre_handle lockh;
        ldlm_policy_data_t policy;
        ldlm_mode_t mode;
        ENTRY;

        fid_build_reg_res_name((struct lu_fid*)fid, &res_id);
        /* As not all attributes are kept under update lock, e.g. 
           owner/group/acls are under lookup lock, we need both 
           ibits for GETATTR. */
        policy.l_inodebits.bits = (it->it_op == IT_GETATTR) ?
                MDS_INODELOCK_UPDATE | MDS_INODELOCK_LOOKUP :
                MDS_INODELOCK_LOOKUP;

        mode = ldlm_lock_match(exp->exp_obd->obd_namespace,
                               LDLM_FL_BLOCK_GRANTED, &res_id, LDLM_IBITS,
                               &policy, LCK_CR|LCK_CW|LCK_PR|LCK_PW, &lockh);
        if (mode) {
                memcpy(&it->d.lustre.it_lock_handle, &lockh, sizeof(lockh));
                it->d.lustre.it_lock_mode = mode;
        }

        RETURN(!!mode);
}
EXPORT_SYMBOL(mdc_revalidate_lock);

static int mdc_finish_intent_lock(struct obd_export *exp,
                                  struct ptlrpc_request *req,
                                  struct mdc_op_data *data,
                                  struct lookup_intent *it,
                                  struct lustre_handle *lockh)
{
        struct mds_body *mds_body;
        struct lustre_handle old_lock;
        struct ldlm_lock *lock;
        int rc;
        ENTRY;

        LASSERT(req != NULL);
        LASSERT(req != LP_POISON);
        LASSERT(req->rq_repmsg != LP_POISON);

        if (!it_disposition(it, DISP_IT_EXECD)) {
                /* The server failed before it even started executing the
                 * intent, i.e. because it couldn't unpack the request. */
                LASSERT(it->d.lustre.it_status != 0);
                RETURN(it->d.lustre.it_status);
        }
        rc = it_open_error(DISP_IT_EXECD, it);
        if (rc)
                RETURN(rc);

        mds_body = lustre_msg_buf(req->rq_repmsg, DLM_REPLY_REC_OFF,
                                  sizeof(*mds_body));
        /* mdc_enqueue checked */
        LASSERT(mds_body != NULL);
        /* mdc_enqueue swabbed */
        LASSERT(lustre_rep_swabbed(req, DLM_REPLY_REC_OFF));

        /* If we were revalidating a fid/name pair, mark the intent in
         * case we fail and get called again from lookup */

        if (data->fid2.id && (it->it_op != IT_GETATTR) &&
           ( !mdc_exp_is_2_0_server(exp) ||
             (mdc_exp_is_2_0_server(exp) && (it->it_create_mode & M_CHECK_STALE)))) {
                it_set_disposition(it, DISP_ENQ_COMPLETE);

                /* Also: did we find the same inode? */
                if (memcmp(&data->fid2, &mds_body->fid1, sizeof(data->fid2)) &&
                    memcmp(&data->fid3, &mds_body->fid1, sizeof(data->fid3)))
                        RETURN(-ESTALE);
        }

        rc = it_open_error(DISP_LOOKUP_EXECD, it);
        if (rc)
                RETURN(rc);

        /* keep requests around for the multiple phases of the call
         * this shows the DISP_XX must guarantee we make it into the call
         */
        if (!it_disposition(it, DISP_ENQ_CREATE_REF) &&
            it_disposition(it, DISP_OPEN_CREATE) &&
            !it_open_error(DISP_OPEN_CREATE, it)) {
                it_set_disposition(it, DISP_ENQ_CREATE_REF);
                ptlrpc_request_addref(req); /* balanced in ll_create_node */
        }
        if (!it_disposition(it, DISP_ENQ_OPEN_REF) &&
            it_disposition(it, DISP_OPEN_OPEN) &&
            !it_open_error(DISP_OPEN_OPEN, it)) {
                it_set_disposition(it, DISP_ENQ_OPEN_REF);
                ptlrpc_request_addref(req); /* balanced in ll_file_open */
                /* BUG 11546 - eviction in the middle of open rpc processing */
                OBD_FAIL_TIMEOUT(OBD_FAIL_MDC_ENQUEUE_PAUSE, obd_timeout);
        }

        if (it->it_op & IT_CREAT) {
                /* XXX this belongs in ll_create_it */
        } else if (it->it_op == IT_OPEN) {
                LASSERT(!it_disposition(it, DISP_OPEN_CREATE));
        } else {
                LASSERT(it->it_op & (IT_GETATTR | IT_LOOKUP));
        }

        /* If we already have a matching lock, then cancel the new
         * one.  We have to set the data here instead of in
         * mdc_enqueue, because we need to use the child's inode as
         * the l_ast_data to match, and that's not available until
         * intent_finish has performed the iget().) */
        lock = ldlm_handle2lock(lockh);
        if (lock) {
                ldlm_policy_data_t policy = lock->l_policy_data;

                LDLM_DEBUG(lock, "matching against this");
                LDLM_LOCK_PUT(lock);
                memcpy(&old_lock, lockh, sizeof(*lockh));
                if (ldlm_lock_match(NULL, LDLM_FL_BLOCK_GRANTED, NULL,
                                    LDLM_IBITS, &policy, LCK_NL, &old_lock)) {
                        ldlm_lock_decref_and_cancel(lockh,
                                                    it->d.lustre.it_lock_mode);
                        memcpy(lockh, &old_lock, sizeof(old_lock));
                        memcpy(&it->d.lustre.it_lock_handle, lockh,
                               sizeof(*lockh));
                }
        }

        CDEBUG(D_DENTRY,"D_IT dentry %.*s intent: %s status %d disp %x rc %d\n",
               data->namelen, data->name, ldlm_it2str(it->it_op),
               it->d.lustre.it_status, it->d.lustre.it_disposition, rc);
        RETURN(rc);
}

/* 
 * This long block is all about fixing up the lock and request state
 * so that it is correct as of the moment _before_ the operation was
 * applied; that way, the VFS will think that everything is normal and
 * call Lustre's regular VFS methods.
 *
 * If we're performing a creation, that means that unless the creation
 * failed with EEXIST, we should fake up a negative dentry.
 *
 * For everything else, we want to lookup to succeed.
 *
 * One additional note: if CREATE or OPEN succeeded, we add an extra
 * reference to the request because we need to keep it around until
 * ll_create/ll_open gets called.
 *
 * The server will return to us, in it_disposition, an indication of
 * exactly what d.lustre.it_status refers to.
 *
 * If DISP_OPEN_OPEN is set, then d.lustre.it_status refers to the open() call,
 * otherwise if DISP_OPEN_CREATE is set, then it status is the
 * creation failure mode.  In either case, one of DISP_LOOKUP_NEG or
 * DISP_LOOKUP_POS will be set, indicating whether the child lookup
 * was successful.
 *
 * Else, if DISP_LOOKUP_EXECD then d.lustre.it_status is the rc of the
 * child lookup.
 */
int mdc_intent_lock(struct obd_export *exp, struct mdc_op_data *op_data,
                    void *lmm, int lmmsize, struct lookup_intent *it,
                    int lookup_flags, struct ptlrpc_request **reqp,
                    ldlm_blocking_callback cb_blocking, int extra_lock_flags)
{
        struct lustre_handle lockh;
        int rc;
        ENTRY;

        LASSERT(it);

        CDEBUG(D_DLMTRACE,"name: %.*s("DFID") in inode ("DFID"), "
               "intent: %s flags %#o\n",
               op_data->namelen, op_data->name,
               PFID(((void *)&op_data->fid2)),
               PFID(((void *)&op_data->fid1)),
               ldlm_it2str(it->it_op), it->it_flags);

        lockh.cookie = 0;
        if (op_data->fid2.id &&
            (it->it_op == IT_LOOKUP || it->it_op == IT_GETATTR)) {
                rc = mdc_revalidate_lock(exp, it, &op_data->fid2);
                /* Only return failure if it was not GETATTR by cfid
                   (from inode_revalidate) */
                if (rc || op_data->namelen != 0)
                        RETURN(rc);
        }

        /* lookup_it may be called only after revalidate_it has run, because
         * revalidate_it cannot return errors, only zero.  Returning zero causes
         * this call to lookup, which *can* return an error.
         *
         * We only want to execute the request associated with the intent one
         * time, however, so don't send the request again.  Instead, skip past
         * this and use the request from revalidate.  In this case, revalidate
         * never dropped its reference, so the refcounts are all OK */
        if (!it_disposition(it, DISP_ENQ_COMPLETE)) {
                struct ldlm_enqueue_info einfo =
                        { LDLM_IBITS, it_to_lock_mode(it), cb_blocking,
                          ldlm_completion_ast, NULL, NULL };

                rc = mdc_enqueue(exp, &einfo, it, op_data, &lockh,
                                 lmm, lmmsize, extra_lock_flags);
                if (rc < 0)
                        RETURN(rc);
        } else if (!op_data->fid2.id) {
                /* DISP_ENQ_COMPLETE set means there is extra reference on
                 * request referenced from this intent, saved for subsequent
                 * lookup.  This path is executed when we proceed to this
                 * lookup, so we clear DISP_ENQ_COMPLETE */
                it_clear_disposition(it, DISP_ENQ_COMPLETE);
        }

        *reqp = it->d.lustre.it_data;
        rc = mdc_finish_intent_lock(exp, *reqp, op_data, it, &lockh);

        RETURN(rc);
}
EXPORT_SYMBOL(mdc_intent_lock);

static int mdc_intent_getattr_async_interpret(struct ptlrpc_request *req,
                                              void *unused, int rc)
{
        struct obd_export        *exp = req->rq_async_args.pointer_arg[0];
        struct md_enqueue_info   *minfo = req->rq_async_args.pointer_arg[1];
        struct ldlm_enqueue_info *einfo = req->rq_async_args.pointer_arg[2];
        struct lookup_intent     *it;
        struct lustre_handle     *lockh;
        struct obd_device        *obddev;
        int                       flags = LDLM_FL_HAS_INTENT;
        ENTRY;

        it    = &minfo->mi_it;
        lockh = &minfo->mi_lockh;

        obddev = class_exp2obd(exp);

        mdc_exit_request(&obddev->u.cli);
        if (OBD_FAIL_CHECK(OBD_FAIL_MDC_GETATTR_ENQUEUE))
                rc = -ETIMEDOUT;

        rc = ldlm_cli_enqueue_fini(exp, req, einfo->ei_type, 1, einfo->ei_mode,
                                   &flags, NULL, 0, NULL, lockh, rc);
        if (rc < 0) {
                CERROR("ldlm_cli_enqueue_fini: %d\n", rc);
                mdc_clear_replay_flag(req, rc);
                GOTO(out, rc);
        }

        rc = mdc_finish_enqueue(exp, req, einfo, it, lockh, rc);
        if (rc)
                GOTO(out, rc);

        rc = mdc_finish_intent_lock(exp, req, &minfo->mi_data, it, lockh);
        GOTO(out, rc);
out:
        OBD_FREE_PTR(einfo);
        minfo->mi_cb(exp, req, minfo, rc);

        return 0;
}

int mdc_intent_getattr_async(struct obd_export *exp,
                             struct md_enqueue_info *minfo,
                             struct ldlm_enqueue_info *einfo)
{
        struct mdc_op_data      *op_data = &minfo->mi_data;
        struct lookup_intent    *it = &minfo->mi_it;
        struct ptlrpc_request   *req;
        struct obd_device       *obddev = class_exp2obd(exp);
        struct ldlm_res_id res_id;
        ldlm_policy_data_t       policy = {
                                        .l_inodebits = { MDS_INODELOCK_LOOKUP }
                                 };
        int                      rc;
        int                      flags = LDLM_FL_HAS_INTENT;
        ENTRY;

        CDEBUG(D_DLMTRACE,"name: %.*s in inode "LPU64", intent: %s flags %#o\n",
               op_data->namelen, op_data->name, op_data->fid1.id,
               ldlm_it2str(it->it_op), it->it_flags);

        fid_build_reg_res_name((void *)&op_data->fid1, &res_id);
        req = mdc_intent_lookup_pack(exp, it, op_data);
        if (!req)
                RETURN(-ENOMEM);

        rc = mdc_enter_request(&obddev->u.cli);
        if (rc)
                RETURN(rc);
        rc = ldlm_cli_enqueue(exp, &req, einfo, res_id, &policy, &flags, NULL,
                              0, NULL, &minfo->mi_lockh, 1);
        if (rc < 0) {
                mdc_exit_request(&obddev->u.cli);
                RETURN(rc);
        }

        req->rq_async_args.pointer_arg[0] = exp;
        req->rq_async_args.pointer_arg[1] = minfo;
        req->rq_async_args.pointer_arg[2] = einfo;
        req->rq_interpret_reply = mdc_intent_getattr_async_interpret;
        ptlrpcd_add_req(req);

        RETURN(0);
}
EXPORT_SYMBOL(mdc_intent_getattr_async);
