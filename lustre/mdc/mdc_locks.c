/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.sf.net/projects/lustre/
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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

#include <linux/obd_class.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_dlm.h>
#include <linux/lprocfs_status.h>
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

static void mdc_fid2mdc_op_data(struct mdc_op_data *data, struct ll_uctxt *ctxt,
                                struct ll_fid *f1, struct ll_fid *f2,
                                const char *name, int namelen, int mode)
{
        LASSERT(data);
        LASSERT(ctxt);
        LASSERT(f1);

        data->ctxt = *ctxt;
        data->fid1 = *f1;
        if (f2)
                data->fid2 = *f2;
        else
                memset(&data->fid2, 0, sizeof(data->fid2));
        data->name = name;
        data->namelen = namelen;
        data->create_mode = mode;
        data->mod_time = LTIME_S(CURRENT_TIME);
}

static int it_to_lock_mode(struct lookup_intent *it)
{
        /* CREAT needs to be tested before open (both could be set) */
        if (it->it_op & IT_CREAT)
                return LCK_PW;
        else if (it->it_op & (IT_READDIR | IT_GETATTR | IT_OPEN | IT_LOOKUP))
                return LCK_PR;

        LBUG();
        RETURN(-EINVAL);
}

int it_open_error(int phase, struct lookup_intent *it)
{
        if (it_disposition(it, DISP_OPEN_OPEN)) {
                if (phase == DISP_OPEN_OPEN)
                        return it->d.lustre.it_status;
                else
                        return 0;
        }

        if (it_disposition(it, DISP_OPEN_CREATE)) {
                if (phase == DISP_OPEN_CREATE)
                        return it->d.lustre.it_status;
                else
                        return 0;
        }

        if (it_disposition(it, DISP_LOOKUP_EXECD)) {
                if (phase == DISP_LOOKUP_EXECD)
                        return it->d.lustre.it_status;
                else
                        return 0;
        }

        if (it_disposition(it, DISP_IT_EXECD)) {
                if (phase == DISP_IT_EXECD)
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
void mdc_set_lock_data(__u64 *l, void *data)
{
        struct ldlm_lock *lock;
        struct lustre_handle *lockh = (struct lustre_handle *)l;
        ENTRY;

        if (!*l) {
                EXIT;
                return;
        }

        lock = ldlm_handle2lock(lockh);

        LASSERT(lock != NULL);
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
#ifdef __KERNEL__
        if (lock->l_ast_data && lock->l_ast_data != data) {
                struct inode *new_inode = data;
                struct inode *old_inode = lock->l_ast_data;
                unsigned long state = old_inode->i_state & I_FREEING;
                CERROR("Found existing inode %p/%lu/%u state %lu in lock: "
                       "setting data to %p/%lu/%u\n", old_inode,
                       old_inode->i_ino, old_inode->i_generation, state,
                       new_inode, new_inode->i_ino, new_inode->i_generation);
                LASSERT(state);
        }
#endif
        lock->l_ast_data = data;
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        LDLM_LOCK_PUT(lock);

        EXIT;
}
EXPORT_SYMBOL(mdc_set_lock_data);

int mdc_change_cbdata(struct obd_export *exp, struct ll_fid *fid, 
                      ldlm_iterator_t it, void *data)
{
        struct ldlm_res_id res_id = { .name = {0} };
        ENTRY;

        res_id.name[0] = fid->id;
        res_id.name[1] = fid->generation;

        ldlm_change_cbdata(class_exp2obd(exp)->obd_namespace, &res_id, it, 
                           data);
        EXIT;
        return 0;
}



/* We always reserve enough space in the reply packet for a stripe MD, because
 * we don't know in advance the file type. */
int mdc_enqueue(struct obd_export *exp,
                int lock_type,
                struct lookup_intent *it,
                int lock_mode,
                struct mdc_op_data *data,
                struct lustre_handle *lockh,
                void *lmm,
                int lmmsize,
                ldlm_completion_callback cb_completion,
                ldlm_blocking_callback cb_blocking,
                void *cb_data)
{
        struct ptlrpc_request *req;
        struct obd_device *obddev = class_exp2obd(exp);
        struct ldlm_res_id res_id =
                { .name = {data->fid1.id, data->fid1.generation} };
        int size[6] = {sizeof(struct ldlm_request), sizeof(struct ldlm_intent)};
        int rc, flags = LDLM_FL_HAS_INTENT;
        int repsize[4] = {sizeof(struct ldlm_reply),
                          sizeof(struct mds_body),
                          obddev->u.cli.cl_max_mds_easize,
                          obddev->u.cli.cl_max_mds_cookiesize};
        struct ldlm_reply *dlm_rep;
        struct ldlm_intent *lit;
        struct ldlm_request *lockreq;
        void *eadata;
        unsigned long irqflags;
        int   reply_buffers = 0;
        ENTRY;

//        LDLM_DEBUG_NOLOCK("mdsintent=%s,name=%s,dir=%lu",
//                          ldlm_it2str(it->it_op), it_name, it_inode->i_ino);

        if (it->it_op & IT_OPEN) {
                it->it_create_mode |= S_IFREG;
                it->it_create_mode &= ~current->fs->umask;

                size[2] = sizeof(struct mds_rec_create);
                size[3] = data->namelen + 1;
                size[4] = obddev->u.cli.cl_max_mds_easize;
                req = ptlrpc_prep_req(class_exp2cliimp(exp), LDLM_ENQUEUE, 
                                      5, size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                spin_lock_irqsave (&req->rq_lock, irqflags);
                req->rq_replay = 1;
                spin_unlock_irqrestore (&req->rq_lock, irqflags);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, 1, sizeof (*lit));
                lit->opc = (__u64)it->it_op;

                /* pack the intended request */
                mdc_open_pack(req, 2, data, it->it_create_mode, 0,
                              it->it_flags, lmm, lmmsize);
                /* get ready for the reply */
                reply_buffers = 3;
                req->rq_replen = lustre_msg_size(3, repsize);
        } else if (it->it_op & IT_UNLINK) {
                size[2] = sizeof(struct mds_rec_unlink);
                size[3] = data->namelen + 1;
                req = ptlrpc_prep_req(class_exp2cliimp(exp), LDLM_ENQUEUE, 4,
                                      size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, 1, sizeof (*lit));
                lit->opc = (__u64)it->it_op;

                /* pack the intended request */
                mdc_unlink_pack(req, 2, data);
                /* get ready for the reply */
                reply_buffers = 4;
                req->rq_replen = lustre_msg_size(4, repsize);
        } else if (it->it_op & (IT_GETATTR | IT_LOOKUP)) {
                int valid = OBD_MD_FLNOTOBD | OBD_MD_FLEASIZE;
                size[2] = sizeof(struct mds_body);
                size[3] = data->namelen + 1;

                req = ptlrpc_prep_req(class_exp2cliimp(exp), LDLM_ENQUEUE, 4,
                                      size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, 1, sizeof (*lit));
                lit->opc = (__u64)it->it_op;

                /* pack the intended request */
                mdc_getattr_pack(req, valid, 2, it->it_flags, data);
                /* get ready for the reply */
                reply_buffers = 3;
                req->rq_replen = lustre_msg_size(3, repsize);
        } else if (it->it_op == IT_READDIR) {
                req = ptlrpc_prep_req(class_exp2cliimp(exp), LDLM_ENQUEUE, 1,
                                      size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* get ready for the reply */
                reply_buffers = 1;
                req->rq_replen = lustre_msg_size(1, repsize);
        }  else {
                LBUG();
                RETURN(-EINVAL);
        }

        mdc_get_rpc_lock(obddev->u.cli.cl_rpc_lock, it);
        rc = ldlm_cli_enqueue(exp, req, obddev->obd_namespace, NULL, res_id,
                              lock_type, NULL, 0, lock_mode, &flags,
                              cb_completion, cb_blocking, cb_data, 0, lockh);
        mdc_put_rpc_lock(obddev->u.cli.cl_rpc_lock, it);

        /* Similarly, if we're going to replay this request, we don't want to
         * actually get a lock, just perform the intent. */
        if (req->rq_transno || req->rq_replay) {
                lockreq = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*lockreq));
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
                LASSERT (rc < 0);
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

                LDLM_LOCK_PUT(lock);
        }

        dlm_rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*dlm_rep));
        LASSERT(dlm_rep != NULL);           /* checked by ldlm_cli_enqueue() */
        LASSERT_REPSWABBED(req, 0);         /* swabbed by ldlm_cli_enqueue() */

        it->d.lustre.it_disposition = (int) dlm_rep->lock_policy_res1;
        it->d.lustre.it_status = (int) dlm_rep->lock_policy_res2;
        it->d.lustre.it_lock_mode = lock_mode;
        it->d.lustre.it_data = req;

        /* We know what to expect, so we do any byte flipping required here */
        LASSERT(reply_buffers == 4 || reply_buffers == 3 || reply_buffers == 1);
        if (reply_buffers >= 3) {
                struct mds_body *body;

                body = lustre_swab_repbuf(req, 1, sizeof (*body),
                                           lustre_swab_mds_body);
                if (body == NULL) {
                        CERROR ("Can't swab mds_body\n");
                        RETURN (-EPROTO);
                }

                if ((body->valid & OBD_MD_FLEASIZE) != 0) {
                        void *replayea;
                        /* The eadata is opaque; just check that it is
                         * there.  Eventually, obd_unpackmd() will check
                         * the contents */
                        eadata = lustre_swab_repbuf(req, 2, body->eadatasize,
                                                    NULL);
                        if (eadata == NULL) {
                                CERROR ("Missing/short eadata\n");
                                RETURN (-EPROTO);
                        }
                        if (it->it_op & IT_OPEN) {
                                replayea = lustre_msg_buf(req->rq_reqmsg, 4, 
                                                          obddev->u.cli.cl_max_mds_easize);
                                LASSERT(replayea);
                                memcpy(replayea, eadata, body->eadatasize);
                        }
                }
        }

        RETURN(rc);
}
EXPORT_SYMBOL(mdc_enqueue);

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
int mdc_intent_lock(struct obd_export *exp, struct ll_uctxt *uctxt,
                    struct ll_fid *pfid, const char *name, int len,
                    void *lmm, int lmmsize,
                    struct ll_fid *cfid, struct lookup_intent *it, int flags,
                    struct ptlrpc_request **reqp,
                    ldlm_blocking_callback cb_blocking)
{
        struct lustre_handle lockh;
        struct ptlrpc_request *request;
        int rc = 0;
        struct mds_body *mds_body;
        struct lustre_handle old_lock;
        struct ldlm_lock *lock;
        ENTRY;
        LASSERT(it);

        CDEBUG(D_DLMTRACE, "name: %*s in %ld, intent: %s\n", len, name,
               (unsigned long) pfid->id, ldlm_it2str(it->it_op));

        if (cfid && (it->it_op == IT_LOOKUP || it->it_op == IT_GETATTR)) {
                /* We could just return 1 immediately, but since we should only
                 * be called in revalidate_it if we already have a lock, let's
                 * verify that. */
                struct ldlm_res_id res_id ={.name = {cfid->id, 
                                                     cfid->generation}};
                struct lustre_handle lockh;
                int mode, flags = LDLM_FL_BLOCK_GRANTED;

                mode = LCK_PR;
                rc = ldlm_lock_match(exp->exp_obd->obd_namespace, flags,
                                     &res_id, LDLM_PLAIN, NULL, 0, LCK_PR,
                                     &lockh);
                if (!rc) {
                        mode = LCK_PW;
                        rc = ldlm_lock_match(exp->exp_obd->obd_namespace, flags,
                                             &res_id, LDLM_PLAIN, NULL, 0,
                                             LCK_PW, &lockh);
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
                struct mdc_op_data op_data;
                mdc_fid2mdc_op_data(&op_data, uctxt, pfid, cfid, name, len, 0);

                rc = mdc_enqueue(exp, LDLM_PLAIN, it, it_to_lock_mode(it),
                                 &op_data, &lockh, lmm, lmmsize,
                                 ldlm_completion_ast, cb_blocking, NULL);
                if (rc < 0)
                        RETURN(rc);
                memcpy(&it->d.lustre.it_lock_handle, &lockh, sizeof(lockh));
        }
        request = *reqp = it->d.lustre.it_data;
        LASSERT(request != NULL);

        if (!it_disposition(it, DISP_IT_EXECD)) {
                /* The server failed before it even started executing the
                 * intent, i.e. because it couldn't unpack the request. */
                LASSERT(it->d.lustre.it_status != 0);
                RETURN(it->d.lustre.it_status);
        }
        rc = it_open_error(DISP_IT_EXECD, it);
        if (rc)
                RETURN(rc);

        mds_body = lustre_msg_buf(request->rq_repmsg, 1, sizeof(*mds_body));
        LASSERT(mds_body != NULL);           /* mdc_enqueue checked */
        LASSERT_REPSWABBED(request, 1); /* mdc_enqueue swabbed */

        /* If we were revalidating a fid/name pair, mark the intent in
         * case we fail and get called again from lookup */
        if (cfid != NULL) {
                it_set_disposition(it, DISP_ENQ_COMPLETE);
                /* Also: did we find the same inode? */
                if (memcmp(cfid, &mds_body->fid1, sizeof(*cfid)))
                        RETURN(-ESTALE);
        }

        /* If we're doing an IT_OPEN which did not result in an actual
         * successful open, then we need to remove the bit which saves
         * this request for unconditional replay. */
        if (it->it_op & IT_OPEN) {
                if (!it_disposition(it, DISP_OPEN_OPEN) ||
                    it->d.lustre.it_status != 0) {
                        unsigned long flags;

                        spin_lock_irqsave(&request->rq_lock, flags);
                        request->rq_replay = 0;
                        spin_unlock_irqrestore(&request->rq_lock, flags);
                }
        }

        rc = it_open_error(DISP_LOOKUP_EXECD, it);
        if (rc)
                RETURN(rc);

        /* keep requests around for the multiple phases of the call
         * this shows the DISP_XX must guarantee we make it into the call
         */
        if (it_disposition(it, DISP_OPEN_CREATE) &&
            !it_open_error(DISP_OPEN_CREATE, it))
                ptlrpc_request_addref(request);
        if (it_disposition(it, DISP_OPEN_OPEN) &&
            !it_open_error(DISP_OPEN_OPEN, it))
                ptlrpc_request_addref(request);

        if (it->it_op & IT_CREAT) {
                /* XXX this belongs in ll_create_iit */
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
                LDLM_DEBUG(lock, "matching against this");
                LDLM_LOCK_PUT(lock);
                memcpy(&old_lock, &lockh, sizeof(lockh));
                if (ldlm_lock_match(NULL, LDLM_FL_BLOCK_GRANTED, NULL,
                                    LDLM_PLAIN, NULL, 0, LCK_NL, &old_lock)) {
                        ldlm_lock_decref_and_cancel(&lockh,
                                                    it->d.lustre.it_lock_mode);
                        memcpy(&lockh, &old_lock, sizeof(old_lock));
                        memcpy(&it->d.lustre.it_lock_handle, &lockh,
                               sizeof(lockh));
                }
        }
        CDEBUG(D_DENTRY, "D_IT dentry %*s intent: %s status %d disp %x rc %d\n",
               len, name, ldlm_it2str(it->it_op), it->d.lustre.it_status,
               it->d.lustre.it_disposition, rc);

        RETURN(rc);
}
EXPORT_SYMBOL(mdc_intent_lock);
