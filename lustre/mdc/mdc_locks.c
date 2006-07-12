/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001-2003 Cluster File Systems, Inc.
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
#include <lustre_mds.h>
#include <lprocfs_status.h>
#include "mdc_internal.h"

int it_disposition(struct lookup_intent *it, int flag)
{
        return it->d.lustre.it_disposition & flag;
}
EXPORT_SYMBOL(it_disposition);

void it_set_disposition(struct lookup_intent *it, int flag)
{
        it->d.lustre.it_disposition |= flag;
}
EXPORT_SYMBOL(it_set_disposition);

void it_clear_disposition(struct lookup_intent *it, int flag)
{
        it->d.lustre.it_disposition &= ~flag;
}

static int it_to_lock_mode(struct lookup_intent *it)
{
        /* CREAT needs to be tested before open (both could be set) */
        if (it->it_op & IT_CREAT)
                return LCK_CW;
        else if (it->it_op & (IT_READDIR | IT_GETATTR | IT_OPEN | IT_LOOKUP))
                return LCK_CR;

        LBUG();
        RETURN(-EINVAL);
}

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
int mdc_set_lock_data(struct obd_export *exp, __u64 *lockh, void *data)
{
        struct ldlm_lock *lock;
        ENTRY;

        if (!*lockh) {
                EXIT;
                RETURN(0);
        }

        lock = ldlm_handle2lock((struct lustre_handle *)lockh);

        LASSERT(lock != NULL);
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
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
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        LDLM_LOCK_PUT(lock);

        RETURN(0);
}

int mdc_lock_match(struct obd_export *exp, int flags,
                   struct lu_fid *fid, ldlm_type_t type,
                   ldlm_policy_data_t *policy, ldlm_mode_t mode,
                   struct lustre_handle *lockh)
{
        struct ldlm_res_id res_id =
                { .name = {fid_seq(fid), 
                           fid_oid(fid),
                           fid_ver(fid)} };
        struct obd_device *obd = class_exp2obd(exp);
        int rc;
        ENTRY;

        rc = ldlm_lock_match(obd->obd_namespace, flags,
                             &res_id, type, policy, mode, lockh);

        RETURN(rc);
}

int mdc_cancel_unused(struct obd_export *exp,
                      struct lu_fid *fid,
                      int flags, void *opaque)
{
        struct ldlm_res_id res_id =
                { .name = {fid_seq(fid), 
                           fid_oid(fid), 
                           fid_ver(fid)} };
        struct obd_device *obd = class_exp2obd(exp);
        int rc;
        
        ENTRY;
        
        rc = ldlm_cli_cancel_unused(obd->obd_namespace, &res_id,
                                    flags, opaque);
        RETURN(rc);
}

int mdc_change_cbdata(struct obd_export *exp, struct lu_fid *fid, 
                      ldlm_iterator_t it, void *data)
{
        struct ldlm_res_id res_id = { .name = {0} };
        ENTRY;

        res_id.name[0] = fid_seq(fid);
        res_id.name[1] = fid_oid(fid);
        res_id.name[2] = fid_ver(fid);

        ldlm_change_cbdata(class_exp2obd(exp)->obd_namespace, 
                           &res_id, it, data);

        EXIT;
        return 0;
}

static inline void mdc_clear_replay_flag(struct ptlrpc_request *req, int rc)
{
        /* Don't hold error requests for replay. */
        if (req->rq_replay) {
                unsigned long irqflags;
                spin_lock_irqsave(&req->rq_lock, irqflags);
                req->rq_replay = 0;
                spin_unlock_irqrestore(&req->rq_lock, irqflags);
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
                                struct mdt_body *body, int size[5])
{
        int new_size, old_size;
        struct lustre_msg *new_msg;

        /* save old size */
        old_size = lustre_msg_size(5, size);

        size[4] = body->eadatasize;
        new_size = lustre_msg_size(5, size);
        OBD_ALLOC(new_msg, new_size);
        if (new_msg != NULL) {
                struct lustre_msg *old_msg = req->rq_reqmsg;
                unsigned long irqflags;

                DEBUG_REQ(D_INFO, req, "replace reqmsg for larger EA %u\n",
                          body->eadatasize);
                memcpy(new_msg, old_msg, old_size);
                new_msg->buflens[4] = body->eadatasize;

                spin_lock_irqsave(&req->rq_lock, irqflags);
                req->rq_reqmsg = new_msg;
                req->rq_reqlen = new_size;
                spin_unlock_irqrestore(&req->rq_lock, irqflags);

                OBD_FREE(old_msg, old_size);
        } else {
                body->valid &= ~OBD_MD_FLEASIZE;
                body->eadatasize = 0;
        }
}

/* We always reserve enough space in the reply packet for a stripe MD, because
 * we don't know in advance the file type. */
int mdc_enqueue(struct obd_export *exp,
                int lock_type,
                struct lookup_intent *it,
                int lock_mode,
                struct md_op_data *op_data,
                struct lustre_handle *lockh,
                void *lmm,
                int lmmsize,
                ldlm_completion_callback cb_completion,
                ldlm_blocking_callback cb_blocking,
                void *cb_data, int extra_lock_flags)
{
        struct ptlrpc_request *req;
        struct obd_device *obddev = class_exp2obd(exp);
        struct ldlm_res_id res_id =
                { .name = {fid_seq(&op_data->fid1), 
                           fid_oid(&op_data->fid1),
                           fid_ver(&op_data->fid1)} };
        ldlm_policy_data_t policy = { .l_inodebits = { MDS_INODELOCK_LOOKUP } };
        struct ldlm_request *lockreq;
        struct ldlm_intent *lit;
        int size[6] = {[MDS_REQ_INTENT_LOCKREQ_OFF] = sizeof(*lockreq),
                       [MDS_REQ_INTENT_IT_OFF] = sizeof(*lit) };
        struct ldlm_reply *dlm_rep;
        int repsize[4] = {sizeof(*dlm_rep),
                          sizeof(struct mdt_body),
                          obddev->u.cli.cl_max_mds_easize};
        void *eadata;
        unsigned long irqflags;
        int repbufcnt = 3, req_buffers = 2;
        int rc, flags = extra_lock_flags | LDLM_FL_HAS_INTENT;
        ENTRY;

        LASSERTF(lock_type == LDLM_IBITS, "lock type %d\n", lock_type);
//        LDLM_DEBUG_NOLOCK("mdsintent=%s,name=%s,dir=%lu",
//                          ldlm_it2str(it->it_op), it_name, it_inode->i_ino);

        if (it->it_op & IT_OPEN) {
                it->it_create_mode |= S_IFREG;

                size[req_buffers++] = sizeof(struct mdt_rec_create);
                size[req_buffers++] = op_data->namelen + 1;
                /* As an optimization, we allocate an RPC request buffer for
                 * at least a default-sized LOV EA even if we aren't sending
                 * one.  We grow the whole request to the next power-of-two
                 * size since we get that much from a slab allocation anyways.
                 * This avoids an allocation below in the common case where
                 * we need to save a default-sized LOV EA for open replay. */
                size[req_buffers++] = max(lmmsize,
                                          obddev->u.cli.cl_default_mds_easize);
                rc = lustre_msg_size(req_buffers, size);
                if (rc & (rc - 1))
                        size[req_buffers - 1] = min(size[req_buffers - 1] +
                                                    round_up(rc) - rc,
                                        obddev->u.cli.cl_max_mds_easize);

                if (it->it_flags & O_JOIN_FILE) {
                        __u64 head_size = *(__u32*)cb_data;
                        __u32 tsize = *(__u32*)lmm;

                        /* join is like an unlink of the tail */
                        policy.l_inodebits.bits = MDS_INODELOCK_UPDATE;
                        size[req_buffers++] = sizeof(struct mdt_rec_join);
                        req = ptlrpc_prep_req(class_exp2cliimp(exp),
                                              LUSTRE_DLM_VERSION, LDLM_ENQUEUE,
                                              req_buffers, size, NULL);
                        /* when joining file, cb_data and lmm args together
                         * indicate the head file size*/
                        mdc_join_pack(req, req_buffers - 1, op_data,
                                      (head_size << 32) | tsize);
                        cb_data = NULL;
                        lmm = NULL;
                } else
                        req = ptlrpc_prep_req(class_exp2cliimp(exp),
                                              LUSTRE_DLM_VERSION, LDLM_ENQUEUE,
                                              req_buffers, size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                spin_lock_irqsave (&req->rq_lock, irqflags);
                req->rq_replay = 1;
                spin_unlock_irqrestore (&req->rq_lock, irqflags);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, MDS_REQ_INTENT_IT_OFF,
                                     sizeof (*lit));
                lit->opc = (__u64)it->it_op;

                /* pack the intended request */
                mdc_open_pack(req, MDS_REQ_INTENT_REC_OFF, op_data,
                              it->it_create_mode, 0,
                              it->it_flags, lmm, lmmsize);

                repsize[repbufcnt++] = LUSTRE_POSIX_ACL_MAX_SIZE;
        } else if (it->it_op & IT_UNLINK) {
                size[req_buffers++] = sizeof(struct mdt_rec_unlink);
                size[req_buffers++] = op_data->namelen + 1;
                policy.l_inodebits.bits = MDS_INODELOCK_UPDATE;
                req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_DLM_VERSION,
                                      LDLM_ENQUEUE, req_buffers, size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, MDS_REQ_INTENT_IT_OFF,
                                     sizeof (*lit));
                lit->opc = (__u64)it->it_op;

                /* pack the intended request */
                mdc_unlink_pack(req, MDS_REQ_INTENT_REC_OFF, op_data);
                /* get ready for the reply */
                repsize[repbufcnt++] = obddev->u.cli.cl_max_mds_cookiesize;
        } else if (it->it_op & (IT_GETATTR | IT_LOOKUP)) {
                obd_valid valid = OBD_MD_FLGETATTR | OBD_MD_FLEASIZE |
                                  OBD_MD_FLACL | OBD_MD_FLMODEASIZE |
                                  OBD_MD_FLDIREA;
                size[req_buffers++] = sizeof(struct mdt_body);
                size[req_buffers++] = op_data->namelen + 1;

                if (it->it_op & IT_GETATTR)
                        policy.l_inodebits.bits = MDS_INODELOCK_UPDATE;

                req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_DLM_VERSION,
                                      LDLM_ENQUEUE, req_buffers, size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, MDS_REQ_INTENT_IT_OFF,
                                     sizeof (*lit));
                lit->opc = (__u64)it->it_op;

                /* pack the intended request */
                mdc_getattr_pack(req, MDS_REQ_INTENT_REC_OFF, valid,
                                 it->it_flags, op_data);
                /* get ready for the reply */
                repsize[repbufcnt++] = LUSTRE_POSIX_ACL_MAX_SIZE;
        } else if (it->it_op == IT_READDIR) {
                policy.l_inodebits.bits = MDS_INODELOCK_UPDATE;
                req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_DLM_VERSION,
                                      LDLM_ENQUEUE, 1, size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* get ready for the reply */
                repbufcnt = 1;
        } else {
                LBUG();
                RETURN(-EINVAL);
        }

        /* get ready for the reply */
        req->rq_replen = lustre_msg_size(repbufcnt, repsize);

        mdc_get_rpc_lock(obddev->u.cli.cl_rpc_lock, it);
        rc = ldlm_cli_enqueue(exp, req, obddev->obd_namespace, res_id,
                              lock_type, &policy,lock_mode, &flags, cb_blocking,
                              cb_completion, NULL, cb_data, NULL, 0, NULL,
                              lockh);
        mdc_put_rpc_lock(obddev->u.cli.cl_rpc_lock, it);

        /* Similarly, if we're going to replay this request, we don't want to
         * actually get a lock, just perform the intent. */
        if (req->rq_transno || req->rq_replay) {
                lockreq = lustre_msg_buf(req->rq_reqmsg,
                                         MDS_REQ_INTENT_LOCKREQ_OFF,
                                         sizeof(*lockreq));
                lockreq->lock_flags |= LDLM_FL_INTENT_ONLY;
        }

        /* This can go when we're sure that this can never happen */
        LASSERT(rc != -ENOENT);
        if (rc == ELDLM_LOCK_ABORTED) {
                lock_mode = 0;
                memset(lockh, 0, sizeof(*lockh));
                rc = 0;
        } else if (rc != 0) {
                CERROR("ldlm_cli_enqueue: %d\n", rc);
                LASSERTF(rc < 0, "rc %d\n", rc);
                mdc_clear_replay_flag(req, rc);
                ptlrpc_req_finished(req);
                RETURN(rc);
        } else { /* rc = 0 */
                struct ldlm_lock *lock = ldlm_handle2lock(lockh);
                LASSERT(lock);

                /* If the server gave us back a different lock mode, we should
                 * fix up our variables. */
                if (lock->l_req_mode != lock_mode) {
                        ldlm_lock_addref(lockh, lock->l_req_mode);
                        ldlm_lock_decref(lockh, lock_mode);
                        lock_mode = lock->l_req_mode;
                }

                ldlm_lock_allow_match(lock);
                LDLM_LOCK_PUT(lock);
        }

        dlm_rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*dlm_rep));
        LASSERT(dlm_rep != NULL);           /* checked by ldlm_cli_enqueue() */
        LASSERT_REPSWABBED(req, 0);         /* swabbed by ldlm_cli_enqueue() */

        it->d.lustre.it_disposition = (int) dlm_rep->lock_policy_res1;
        it->d.lustre.it_status = (int) dlm_rep->lock_policy_res2;
        it->d.lustre.it_lock_mode = lock_mode;
        it->d.lustre.it_data = req;

        if (it->d.lustre.it_status < 0 && req->rq_replay)
                mdc_clear_replay_flag(req, it->d.lustre.it_status);

        DEBUG_REQ(D_RPCTRACE, req, "op: %d disposition: %x, status: %d",
                  it->it_op,it->d.lustre.it_disposition,it->d.lustre.it_status);

        /* We know what to expect, so we do any byte flipping required here */
        LASSERT(repbufcnt == 4 || repbufcnt == 1);
        if (repbufcnt == 4) {
                struct mdt_body *body;

                body = lustre_swab_repbuf(req, 1, sizeof (*body),
                                          lustre_swab_mdt_body);
                if (body == NULL) {
                        CERROR ("Can't swab mdt_body\n");
                        RETURN (-EPROTO);
                }

                if ((body->valid & OBD_MD_FLEASIZE) != 0) {
                        /* The eadata is opaque; just check that it is there.
                         * Eventually, obd_unpackmd() will check the contents */
                        eadata = lustre_swab_repbuf(req, 2, body->eadatasize,
                                                    NULL);
                        if (eadata == NULL) {
                                CERROR ("Missing/short eadata\n");
                                RETURN (-EPROTO);
                        }
                        if (body->valid & OBD_MD_FLMODEASIZE) {
                                if (obddev->u.cli.cl_max_mds_easize < 
                                                        body->max_mdsize) {
                                        obddev->u.cli.cl_max_mds_easize = 
                                                body->max_mdsize;
                                        CDEBUG(D_INFO, "maxeasize become %d\n",
                                               body->max_mdsize);
                                }
                                if (obddev->u.cli.cl_max_mds_cookiesize <
                                                        body->max_cookiesize) {
                                        obddev->u.cli.cl_max_mds_cookiesize =
                                                body->max_cookiesize;
                                        CDEBUG(D_INFO, "cookiesize become %d\n",
                                               body->max_cookiesize);
                                }
                        }
                        /* We save the reply LOV EA in case we have to replay
                         * a create for recovery.  If we didn't allocate a
                         * large enough request buffer above we need to
                         * reallocate it here to hold the actual LOV EA. */
                        if (it->it_op & IT_OPEN) {
                                int pos = MDS_REQ_INTENT_REC_OFF + 2;

                                if (req->rq_reqmsg->buflens[pos] <
                                    body->eadatasize)
                                        mdc_realloc_openmsg(req, body, size);

                                lmm = lustre_msg_buf(req->rq_reqmsg, pos,
                                                     body->eadatasize);
                                if (lmm)
                                        memcpy(lmm, eadata, body->eadatasize);
                        }
                }
        }

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
int mdc_intent_lock(struct obd_export *exp, struct md_op_data *op_data,
                    void *lmm, int lmmsize, struct lookup_intent *it,
                    int lookup_flags, struct ptlrpc_request **reqp,
                    ldlm_blocking_callback cb_blocking,
                    int extra_lock_flags)
{
        struct ptlrpc_request *request;
        struct lustre_handle old_lock;
        struct lustre_handle lockh;
        struct mdt_body *mdt_body;
        struct ldlm_lock *lock;
        int rc = 0;
        ENTRY;
        LASSERT(it);

        CDEBUG(D_DLMTRACE,"name: %.*s in obj "DFID3", intent: %s flags %#o\n",
               op_data->namelen, op_data->name, PFID3(&op_data->fid1),
               ldlm_it2str(it->it_op), it->it_flags);

        if (fid_is_sane(&op_data->fid2) &&
            (it->it_op & (IT_LOOKUP | IT_GETATTR))) {
                /* We could just return 1 immediately, but since we should only
                 * be called in revalidate_it if we already have a lock, let's
                 * verify that. */
                struct ldlm_res_id res_id = { .name = { fid_seq(&op_data->fid2),
                                                        fid_oid(&op_data->fid2),
                                                        fid_ver(&op_data->fid2) } };
                struct lustre_handle lockh;
                ldlm_policy_data_t policy;
                int mode = LCK_CR;

                policy.l_inodebits.bits = (it->it_op == IT_GETATTR) ?
                                MDS_INODELOCK_UPDATE : MDS_INODELOCK_LOOKUP;
                rc = ldlm_lock_match(exp->exp_obd->obd_namespace,
                                     LDLM_FL_BLOCK_GRANTED, &res_id,
                                     LDLM_IBITS, &policy, LCK_CR, &lockh);
                if (!rc) {
                        mode = LCK_CW;
                        rc = ldlm_lock_match(exp->exp_obd->obd_namespace,
                                             LDLM_FL_BLOCK_GRANTED, &res_id,
                                             LDLM_IBITS, &policy, LCK_CW, &lockh);
                }
                if (!rc) {
                        mode = LCK_PR;
                        rc = ldlm_lock_match(exp->exp_obd->obd_namespace,
                                             LDLM_FL_BLOCK_GRANTED, &res_id,
                                             LDLM_IBITS, &policy, LCK_PR, &lockh);
                }
                if (rc) {
                        memcpy(&it->d.lustre.it_lock_handle, &lockh,
                               sizeof(lockh));
                        it->d.lustre.it_lock_mode = mode;
                }
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
                rc = mdc_enqueue(exp, LDLM_IBITS, it, it_to_lock_mode(it),
                                 op_data, &lockh, lmm, lmmsize,
                                 ldlm_completion_ast, cb_blocking, NULL,
                                 extra_lock_flags);
                if (rc < 0)
                        RETURN(rc);
                memcpy(&it->d.lustre.it_lock_handle, &lockh, sizeof(lockh));
        } else if (!fid_is_sane(&op_data->fid2)) {
                /* DISP_ENQ_COMPLETE set means there is extra reference on
                 * request referenced from this intent, saved for subsequent
                 * lookup.  This path is executed when we proceed to this
                 * lookup, so we clear DISP_ENQ_COMPLETE */
                it_clear_disposition(it, DISP_ENQ_COMPLETE);
        }
        request = *reqp = it->d.lustre.it_data;
        LASSERT(request != NULL);
        LASSERT(request != LP_POISON);
        LASSERT(request->rq_repmsg != LP_POISON);

        /* If we're doing an IT_OPEN which did not result in an actual
         * successful open, then we need to remove the bit which saves
         * this request for unconditional replay.
         *
         * It's important that we do this first!  Otherwise we might exit the
         * function without doing so, and try to replay a failed create
         * (bug 3440) */
        if (it->it_op & IT_OPEN && request->rq_replay &&
            (!it_disposition(it, DISP_OPEN_OPEN) ||it->d.lustre.it_status != 0))
                mdc_clear_replay_flag(request, it->d.lustre.it_status);

        if (!it_disposition(it, DISP_IT_EXECD)) {
                /* The server failed before it even started executing the
                 * intent, i.e. because it couldn't unpack the request. */
                LASSERT(it->d.lustre.it_status != 0);
                RETURN(it->d.lustre.it_status);
        }
        rc = it_open_error(DISP_IT_EXECD, it);
        if (rc)
                RETURN(rc);

        mdt_body = lustre_msg_buf(request->rq_repmsg, 1, sizeof(*mdt_body));
        LASSERT(mdt_body != NULL);           /* mdc_enqueue checked */
        LASSERT_REPSWABBED(request, 1); /* mdc_enqueue swabbed */

        /* If we were revalidating a fid/name pair, mark the intent in
         * case we fail and get called again from lookup */
        if (fid_is_sane(&op_data->fid2) && 
                        !it_disposition(it, DISP_OPEN_CREATE)) {
                it_set_disposition(it, DISP_ENQ_COMPLETE);
                /* Also: did we find the same inode? */
                if (memcmp(&op_data->fid2, &mdt_body->fid1, sizeof(op_data->fid2)))
                        RETURN(-ESTALE);
        }

        rc = it_open_error(DISP_LOOKUP_EXECD, it);
        if (rc)
                RETURN(rc);

        /* keep requests around for the multiple phases of the call
         * this shows the DISP_XX must guarantee we make it into the call
         */
        if (it_disposition(it, DISP_OPEN_CREATE) &&
            !it_open_error(DISP_OPEN_CREATE, it))
                ptlrpc_request_addref(request); /* balanced in ll_create_node */
        if (it_disposition(it, DISP_OPEN_OPEN) &&
            !it_open_error(DISP_OPEN_OPEN, it))
                ptlrpc_request_addref(request); /* balanced in ll_file_open */

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
        lock = ldlm_handle2lock(&lockh);
        if (lock) {
                ldlm_policy_data_t policy = lock->l_policy_data;
                LDLM_DEBUG(lock, "matching against this");
                LDLM_LOCK_PUT(lock);
                memcpy(&old_lock, &lockh, sizeof(lockh));
                if (ldlm_lock_match(NULL, LDLM_FL_BLOCK_GRANTED, NULL,
                                    LDLM_IBITS, &policy, LCK_NL, &old_lock)) {
                        ldlm_lock_decref_and_cancel(&lockh,
                                                    it->d.lustre.it_lock_mode);
                        memcpy(&lockh, &old_lock, sizeof(old_lock));
                        memcpy(&it->d.lustre.it_lock_handle, &lockh,
                               sizeof(lockh));
                }
        }
        CDEBUG(D_DENTRY,"D_IT dentry %.*s intent: %s status %d disp %x rc %d\n",
               op_data->namelen, op_data->name, ldlm_it2str(it->it_op),
               it->d.lustre.it_status, it->d.lustre.it_disposition, rc);

        RETURN(rc);
}
