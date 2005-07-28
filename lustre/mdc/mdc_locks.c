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
#include <linux/lustre_sec.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_acl.h>
#include <linux/lustre_lite.h>
#include "mdc_internal.h"

int it_disposition(struct lookup_intent *it, int flag)
{
        return LUSTRE_IT(it)->it_disposition & flag;
}
EXPORT_SYMBOL(it_disposition);

void it_set_disposition(struct lookup_intent *it, int flag)
{
        LUSTRE_IT(it)->it_disposition |= flag;
}
EXPORT_SYMBOL(it_set_disposition);

static void mdc_id2mdc_data(struct mdc_op_data *data,
                            struct lustre_id *f1, 
                            struct lustre_id *f2,
                            const char *name, 
                            int namelen, int mode)
{
        LASSERT(data);
        LASSERT(f1);

        data->id1 = *f1;
        if (f2)
                data->id2 = *f2;

        data->valid = 0;
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
        else if (it->it_op & (IT_READDIR | IT_GETATTR | IT_OPEN | IT_LOOKUP |
                              IT_CHDIR))
                return LCK_PR;

        LBUG();
        RETURN(-EINVAL);
}

int it_open_error(int phase, struct lookup_intent *it)
{
        if (it_disposition(it, DISP_OPEN_OPEN)) {
                if (phase == DISP_OPEN_OPEN)
                        return LUSTRE_IT(it)->it_status;
                else
                        return 0;
        }

        if (it_disposition(it, DISP_OPEN_CREATE)) {
                if (phase == DISP_OPEN_CREATE)
                        return LUSTRE_IT(it)->it_status;
                else
                        return 0;
        }

        if (it_disposition(it, DISP_LOOKUP_EXECD)) {
                if (phase == DISP_LOOKUP_EXECD)
                        return LUSTRE_IT(it)->it_status;
                else
                        return 0;
        }

        if (it_disposition(it, DISP_IT_EXECD)) {
                if (phase == DISP_IT_EXECD)
                        return LUSTRE_IT(it)->it_status;
                else
                        return 0;
        }
        CERROR("it disp: %X, status: %d\n", LUSTRE_IT(it)->it_disposition,
               LUSTRE_IT(it)->it_status);
        LBUG();
        return 0;
}
EXPORT_SYMBOL(it_open_error);

/* this must be called on a lockh that is known to have a referenced lock */
int mdc_set_lock_data(struct obd_export *exp, __u64 *l, void *data)
{
        struct ldlm_lock *lock;
        struct lustre_handle *lockh = (struct lustre_handle *)l;
        ENTRY;

        if (!*l) {
                EXIT;
                return 0;
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
                         old_inode->i_state, new_inode, new_inode->i_ino,
                         new_inode->i_generation);
        }
#endif
        lock->l_ast_data = data;
        unlock_res_and_lock(lock);
        LDLM_LOCK_PUT(lock);

        EXIT;
        return 0;
}
EXPORT_SYMBOL(mdc_set_lock_data);

int mdc_change_cbdata(struct obd_export *exp, struct lustre_id *id, 
                      ldlm_iterator_t it, void *data)
{
        struct ldlm_res_id res_id = { .name = {0} };
        ENTRY;

        res_id.name[0] = id_fid(id);
        res_id.name[1] = id_group(id);

        ldlm_change_cbdata(class_exp2obd(exp)->obd_namespace,
                           &res_id, it, data);

        EXIT;
        return 0;
}

static inline void
mdc_clear_replay_flag(struct ptlrpc_request *req, int rc)
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
        struct ldlm_res_id res_id = {
                .name = {id_fid(&data->id1), id_group(&data->id1)}
        };
        struct obd_device *obddev = class_exp2obd(exp);
        ldlm_policy_data_t policy = { .l_inodebits = { MDS_INODELOCK_LOOKUP } };
        struct ldlm_intent *lit;
        struct ldlm_request *lockreq;
        int reqsize[6] = {[MDS_REQ_SECDESC_OFF] = 0,
                          [MDS_REQ_INTENT_LOCKREQ_OFF] = sizeof(*lockreq),
                          [MDS_REQ_INTENT_IT_OFF] = sizeof(*lit)};
        int repsize[5] = {sizeof(struct ldlm_reply),
                          sizeof(struct mds_body),
                          obddev->u.cli.cl_max_mds_easize};
        int req_buffers = 3, reply_buffers = 0;
        int rc, flags = LDLM_FL_HAS_INTENT;
        struct ldlm_reply *dlm_rep = NULL;
        void *eadata;
        unsigned long irqflags;
        ENTRY;

//        LDLM_DEBUG_NOLOCK("mdsintent=%s,name=%s,dir=%lu",
//                          ldlm_it2str(it->it_op), it_name, it_inode->i_ino);

        reqsize[0] = lustre_secdesc_size();

        if (it->it_op & IT_OPEN) {
                it->it_create_mode |= S_IFREG;
                it->it_create_mode &= ~current->fs->umask;

                reqsize[req_buffers++] = sizeof(struct mds_rec_create);
                reqsize[req_buffers++] = data->namelen + 1;
                reqsize[req_buffers++] = obddev->u.cli.cl_max_mds_easize;

                req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_DLM_VERSION,
                                      LDLM_ENQUEUE, req_buffers, reqsize, NULL);
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
                mdc_open_pack(req->rq_reqmsg, MDS_REQ_INTENT_REC_OFF, data,
                              it->it_create_mode, 0, it->it_flags, lmm, lmmsize);
                /* get ready for the reply */
                repsize[3] = 4;
                repsize[4] = xattr_acl_size(LL_ACL_MAX_ENTRIES);
                reply_buffers = 5;
                req->rq_replen = lustre_msg_size(5, repsize);
        } else if (it->it_op & (IT_GETATTR | IT_LOOKUP | IT_CHDIR)) {
                __u64 valid = data->valid | OBD_MD_FLNOTOBD | OBD_MD_FLEASIZE |
                              OBD_MD_FLACL;

                /* we don't expect xattr retrieve could reach here */
                LASSERT(!(valid & (OBD_MD_FLXATTR | OBD_MD_FLXATTRLIST)));

                reqsize[req_buffers++] = sizeof(struct mds_body);
                reqsize[req_buffers++] = data->namelen + 1;

                if (it->it_op & IT_GETATTR)
                        policy.l_inodebits.bits = MDS_INODELOCK_UPDATE;

                req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_DLM_VERSION,
                                      LDLM_ENQUEUE, req_buffers, reqsize, NULL);

                if (!req)
                        RETURN(-ENOMEM);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, MDS_REQ_INTENT_IT_OFF,
                                     sizeof (*lit));
                lit->opc = (__u64)it->it_op;

                /* pack the intended request */
                mdc_getattr_pack(req->rq_reqmsg, MDS_REQ_INTENT_REC_OFF,
                                 valid, it->it_flags, data);
                
                /* get ready for the reply */
                repsize[3] = 4;
                repsize[4] = xattr_acl_size(LL_ACL_MAX_ENTRIES);
                reply_buffers = 5;
                req->rq_replen = lustre_msg_size(5, repsize);
        } else if (it->it_op == IT_READDIR) {
                policy.l_inodebits.bits = MDS_INODELOCK_UPDATE;
                req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_DLM_VERSION,
                                      LDLM_ENQUEUE, 2, reqsize, NULL);
                
                if (!req)
                        RETURN(-ENOMEM);
                /* get ready for the reply */
                reply_buffers = 1;
                req->rq_replen = lustre_msg_size(1, repsize);
        } else if (it->it_op == IT_UNLINK) {
                reqsize[req_buffers++] = sizeof(struct mds_body);
                policy.l_inodebits.bits = MDS_INODELOCK_UPDATE;
                req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_DLM_VERSION,
                                      LDLM_ENQUEUE, req_buffers, reqsize, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                /* pack the intended request */
                mdc_getattr_pack(req->rq_reqmsg, MDS_REQ_INTENT_REC_OFF,
                                 0, 0, data);

                /* pack the intent */
                lit = lustre_msg_buf(req->rq_reqmsg, MDS_REQ_INTENT_IT_OFF,
                                     sizeof (*lit));
                lit->opc = (__u64)it->it_op;

                /* get ready for the reply */
                reply_buffers = 3;
                req->rq_replen = lustre_msg_size(3, repsize);
        } else {
                LBUG();
                RETURN(-EINVAL);
        }

        lustre_pack_secdesc(req, reqsize[0]);

        mdc_get_rpc_lock(obddev->u.cli.cl_rpc_lock, it);
        rc = ldlm_cli_enqueue(exp, req, obddev->obd_namespace, res_id,
                              lock_type, &policy, lock_mode, &flags,cb_blocking,
                              cb_completion, NULL, cb_data, NULL, 0, NULL,
                              lockh);
        mdc_put_rpc_lock(obddev->u.cli.cl_rpc_lock, it);

        /* Similarly, if we're going to replay this request, we don't want to
         * actually get a lock, just perform the intent. */
        if (req->rq_transno || req->rq_replay) {
                lockreq = lustre_msg_buf(req->rq_reqmsg,
                                         MDS_REQ_INTENT_LOCKREQ_OFF,
                                         sizeof (*lockreq));
                lockreq->lock_flags |= LDLM_FL_INTENT_ONLY;
        }

        /* This can go when we're sure that this can never happen */
        LASSERT(rc != -ENOENT);
        /* We need dlm_rep to be assigned this early, to check lock mode of
           returned lock from request to avoid possible race with lock
           conversion */
        if (rc == ELDLM_LOCK_ABORTED || !rc) {
                dlm_rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*dlm_rep));
                LASSERT(dlm_rep != NULL);   /* checked by ldlm_cli_enqueue() */
        }
        if (rc == ELDLM_LOCK_ABORTED) {
                lock_mode = 0;
                memset(lockh, 0, sizeof(*lockh));
                rc = 0;
        } else if (rc != 0) {
                CERROR("ldlm_cli_enqueue: %d\n", rc);
                LASSERTF(rc < 0, "rc = %d\n", rc);
                mdc_clear_replay_flag(req, rc);
                ptlrpc_req_finished(req);
                RETURN(rc);
        } else { /* rc = 0 */
                struct ldlm_lock *lock = ldlm_handle2lock(lockh);
                LASSERT(lock);

                /* If the server gave us back a different lock mode, we should
                 * fix up our variables. */
                if (dlm_rep->lock_desc.l_req_mode != lock_mode) {
                        ldlm_lock_addref(lockh, dlm_rep->lock_desc.l_req_mode);
                        ldlm_lock_decref(lockh, lock_mode);
                        lock_mode = dlm_rep->lock_desc.l_req_mode;
                }

                ldlm_lock_allow_match(lock);
                LDLM_LOCK_PUT(lock);
        }

        LASSERT_REPSWABBED(req, 0);         /* swabbed by ldlm_cli_enqueue() */

        LUSTRE_IT(it)->it_disposition = (int) dlm_rep->lock_policy_res1;
        LUSTRE_IT(it)->it_status = (int) dlm_rep->lock_policy_res2;
        LUSTRE_IT(it)->it_lock_mode = lock_mode;
        LUSTRE_IT(it)->it_data = req;

        if (LUSTRE_IT(it)->it_status < 0 && req->rq_replay)
                mdc_clear_replay_flag(req, LUSTRE_IT(it)->it_status);

        DEBUG_REQ(D_DLMTRACE, req, "disposition: %x, status: %d",
                  LUSTRE_IT(it)->it_disposition, LUSTRE_IT(it)->it_status);

        /* We know what to expect, so we do any byte flipping required here */
        LASSERT(reply_buffers == 5 || reply_buffers == 4 || 
                reply_buffers == 3 || reply_buffers == 1);
        if (reply_buffers >= 3) {
                struct mds_body *body;

                body = lustre_swab_repbuf(req, 1, sizeof (*body),
                                          lustre_swab_mds_body);
                if (body == NULL) {
                        CERROR ("Can't swab mds_body\n");
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
                        if (it->it_op & IT_OPEN) {
                                void *replayea;

                                replayea = lustre_msg_buf(req->rq_reqmsg,
                                                          MDS_REQ_INTENT_REC_OFF + 2,
                                                          body->eadatasize);
                                LASSERT(replayea);
                                memcpy(replayea, eadata, body->eadatasize);

                                LASSERT(req->rq_reqmsg->bufcount == 6);
                                req->rq_reqmsg->buflens[5] = body->eadatasize;
                                /* If this isn't the last buffer, we might
                                 * have to shift other data around. */
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
 * exactly what d.lustre->it_status refers to.
 *
 * If DISP_OPEN_OPEN is set, then d.lustre->it_status refers to the open() call,
 * otherwise if DISP_OPEN_CREATE is set, then it status is the
 * creation failure mode.  In either case, one of DISP_LOOKUP_NEG or
 * DISP_LOOKUP_POS will be set, indicating whether the child lookup
 * was successful.
 *
 * Else, if DISP_LOOKUP_EXECD then d.lustre->it_status is the rc of the
 * child lookup.
 */
int mdc_intent_lock(struct obd_export *exp, struct lustre_id *pid, 
                    const char *name, int len, void *lmm, int lmmsize, 
                    struct lustre_id *cid, struct lookup_intent *it, 
                    int lookup_flags, struct ptlrpc_request **reqp,
                    ldlm_blocking_callback cb_blocking)
{
        struct lustre_handle lockh;
        struct ptlrpc_request *request;
        struct mds_body *mds_body;
        struct lustre_handle old_lock;
        struct ldlm_lock *lock;
        int rc = 0;
        ENTRY;
        LASSERT(it);

        CDEBUG(D_DLMTRACE, "name: %*s in obj "DLID4", intent: %s flags %#o\n",
               len, name, OLID4(pid), ldlm_it2str(it->it_op), it->it_flags);

        if (cid && (it->it_op == IT_LOOKUP || it->it_op == IT_GETATTR ||
                    it->it_op == IT_CHDIR)) {
                /* We could just return 1 immediately, but since we should only
                 * be called in revalidate_it if we already have a lock, let's
                 * verify that. */
                struct ldlm_res_id res_id = {.name = {id_fid(cid),
                                                      id_group(cid)}};
                struct lustre_handle lockh;
                ldlm_policy_data_t policy;
                int mode;

                /* For the GETATTR case, ll_revalidate_it issues two separate
                   queries - for LOOKUP and for UPDATE lock because it cannot
                   check them together - we might have those two bits to be
                   present in two separate granted locks */
                policy.l_inodebits.bits = (it->it_op == IT_GETATTR) ?
                        MDS_INODELOCK_UPDATE : MDS_INODELOCK_LOOKUP;
                
                mode = LCK_PR;
                rc = ldlm_lock_match(exp->exp_obd->obd_namespace,
                                     LDLM_FL_BLOCK_GRANTED, &res_id,
                                     LDLM_IBITS, &policy, mode,
                                     &lockh);

                if (!rc) {
                        mode = LCK_CR;
                        rc = ldlm_lock_match(exp->exp_obd->obd_namespace,
                                             LDLM_FL_BLOCK_GRANTED, &res_id,
                                             LDLM_IBITS, &policy, mode,
                                             &lockh);
                }
                if (!rc) {
                        mode = LCK_PW;
                        rc = ldlm_lock_match(exp->exp_obd->obd_namespace,
                                             LDLM_FL_BLOCK_GRANTED, &res_id,
                                             LDLM_IBITS, &policy, mode,
                                             &lockh);
                }
                if (!rc) {
                        mode = LCK_CW;
                        rc = ldlm_lock_match(exp->exp_obd->obd_namespace,
                                             LDLM_FL_BLOCK_GRANTED, &res_id,
                                             LDLM_IBITS, &policy, mode,
                                             &lockh);
                }
                if (rc) {
                        if (ptlrpcs_check_cred(exp->exp_obd->u.cli.cl_import)) {
                                /* return immediately if no credential held */
                                ldlm_lock_decref(&lockh, mode);
                                RETURN(-EACCES);
                        }
                        memcpy(&LUSTRE_IT(it)->it_lock_handle, &lockh,
                               sizeof(lockh));
                        LUSTRE_IT(it)->it_lock_mode = mode;
                }

                /* Only return failure if it was not GETATTR by cid (from
                   inode_revalidate) */
                if (rc || name)
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
                struct mdc_op_data *op_data;

                OBD_ALLOC(op_data, sizeof(*op_data));
                if (op_data == NULL)
                        RETURN(-ENOMEM);

                mdc_id2mdc_data(op_data, pid, cid, name, len, 0);

                if (name != NULL)
                        op_data->valid |= OBD_MD_FID;

                rc = mdc_enqueue(exp, LDLM_IBITS, it, it_to_lock_mode(it),
                                 op_data, &lockh, lmm, lmmsize,
                                 ldlm_completion_ast, cb_blocking, NULL);
                OBD_FREE(op_data, sizeof(*op_data));
                if (rc < 0)
                        RETURN(rc);
                
                memcpy(&LUSTRE_IT(it)->it_lock_handle, &lockh, sizeof(lockh));
        }
        request = *reqp = LUSTRE_IT(it)->it_data;
        LASSERT(request != NULL);
        
        /* If we're doing an IT_OPEN which did not result in an actual
         * successful open, then we need to remove the bit which saves this
         * request for unconditional replay.
         *
         * It's important that we do this first!  Otherwise we might exit the
         * function without doing so, and try to replay a failed create (bug
         * 3440) */
        if (it->it_op & IT_OPEN && request->rq_replay &&
            (!it_disposition(it, DISP_OPEN_OPEN) || LUSTRE_IT(it)->it_status != 0))
                mdc_clear_replay_flag(request, LUSTRE_IT(it)->it_status);
 
        if (!it_disposition(it, DISP_IT_EXECD)) {
                /* The server failed before it even started executing the
                 * intent, i.e. because it couldn't unpack the request. */
                LASSERT(LUSTRE_IT(it)->it_status != 0);
                RETURN(LUSTRE_IT(it)->it_status);
        }
        rc = it_open_error(DISP_IT_EXECD, it);
        if (rc)
                RETURN(rc);

        mds_body = lustre_msg_buf(request->rq_repmsg, 1, sizeof(*mds_body));
        LASSERT(mds_body != NULL);      /* mdc_enqueue checked */
        LASSERT_REPSWABBED(request, 1); /* mdc_enqueue swabbed */

        /* If we were revalidating a fid/name pair, mark the intent in case we
         * fail and get called again from lookup */
        if (cid != NULL) {
                it_set_disposition(it, DISP_ENQ_COMPLETE);
                /* Also: did we find the same inode? */
                
                /* we have to compare all the fields but type, because MDS can
                 * return fid/mds/ino/gen if inode lives on another MDS -bzzz */
                if (!(lookup_flags & LOOKUP_COBD) && !id_equal(cid, &mds_body->id1))
                        RETURN(-ESTALE);
        }

        rc = it_open_error(DISP_LOOKUP_EXECD, it);
        if (rc)
                RETURN(rc);

        /*
         * keep requests around for the multiple phases of the call this shows
         * the DISP_XX must guarantee we make it into the call.
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
                LASSERT(it->it_op & (IT_GETATTR | IT_LOOKUP | IT_CHDIR));
        }

        /*
         * if we already have a matching lock, then cancel the new one. We have
         * to set the data here instead of in mdc_enqueue, because we need to
         * use the child's inode as the l_ast_data to match, and that's not
         * available until intent_finish has performed the iget().)
         */
        lock = ldlm_handle2lock(&lockh);
        if (lock) {
                ldlm_policy_data_t policy = lock->l_policy_data;
                LDLM_DEBUG(lock, "matching against this");
                LDLM_LOCK_PUT(lock);
                
                LASSERTF(id_fid(&mds_body->id1) == lock->l_resource->lr_name.name[0] &&
                         id_group(&mds_body->id1) == lock->l_resource->lr_name.name[1],
                         "Invalid lock is returned to client. Lock res_is: %lu/%lu, "
                         "response res_id: %lu/%lu.\n",
                         (unsigned long)lock->l_resource->lr_name.name[0],
                         (unsigned long)lock->l_resource->lr_name.name[1],
                         (unsigned long)id_fid(&mds_body->id1),
                         (unsigned long)id_group(&mds_body->id1));
                
                memcpy(&old_lock, &lockh, sizeof(lockh));
                if (ldlm_lock_match(NULL, LDLM_FL_BLOCK_GRANTED, NULL,
                                    LDLM_IBITS, &policy, LCK_NL, &old_lock)) {
                        ldlm_lock_decref_and_cancel(&lockh,
                                                    LUSTRE_IT(it)->it_lock_mode);
                        memcpy(&lockh, &old_lock, sizeof(old_lock));
                        memcpy(&LUSTRE_IT(it)->it_lock_handle, &lockh,
                               sizeof(lockh));
                }
        }
        CDEBUG(D_DENTRY, "D_IT dentry %*s intent: %s status %d disp %x rc %d\n",
               len, name, ldlm_it2str(it->it_op), LUSTRE_IT(it)->it_status,
               LUSTRE_IT(it)->it_disposition, rc);

        RETURN(rc);
}
EXPORT_SYMBOL(mdc_intent_lock);
