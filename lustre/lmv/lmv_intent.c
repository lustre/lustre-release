/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
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
#define DEBUG_SUBSYSTEM S_LMV
#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <asm/div64.h>
#include <linux/seq_file.h>
#else
#include <liblustre.h>
#endif

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>
#include <linux/obd_ost.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_fsfilt.h>
#include <linux/obd_lmv.h>
#include "lmv_internal.h"


static inline void lmv_drop_intent_lock(struct lookup_intent *it)
{
        if (it->d.lustre.it_lock_mode != 0)
                ldlm_lock_decref((void *)&it->d.lustre.it_lock_handle,
                                 it->d.lustre.it_lock_mode);
}

int lmv_handle_remote_inode(struct obd_export *exp, struct ll_uctxt *uctxt,
                            void *lmm, int lmmsize, 
                            struct lookup_intent *it, int flags,
                            struct ptlrpc_request **reqp,
                            ldlm_blocking_callback cb_blocking)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mds_body *body = NULL;
        int rc = 0;
        ENTRY;

        body = lustre_msg_buf((*reqp)->rq_repmsg, 1, sizeof(*body));
        LASSERT(body != NULL);

        if (body->valid & OBD_MD_MDS) {
                /* oh, MDS reports that this is remote inode case
                 * i.e. we have to ask for real attrs on another MDS */
                struct ptlrpc_request *req;
                struct ll_fid nfid;
                struct lustre_handle plock;
                int pmode;

                if (it->it_op == IT_LOOKUP) {
                        /* unfortunately, we have to lie to MDC/MDS to
                         * retrieve attributes llite needs */
                        it->it_op = IT_GETATTR;
                }

                /* we got LOOKUP lock, but we really need attrs */
                pmode = it->d.lustre.it_lock_mode;
                if (pmode) {
                        memcpy(&plock, &it->d.lustre.it_lock_handle,
                                        sizeof(plock));
                        it->d.lustre.it_lock_mode = 0;
                }

                nfid = body->fid1;
                it->d.lustre.it_disposition &= ~DISP_ENQ_COMPLETE;
                rc = md_intent_lock(lmv->tgts[nfid.mds].ltd_exp, uctxt, &nfid,
                                    NULL, 0, lmm, lmmsize, NULL, it, flags,
                                    &req, cb_blocking);

                /* llite needs LOOKUP lock to track dentry revocation in 
                 * order to maintain dcache consistency. thus drop UPDATE
                 * lock here and put LOOKUP in request */
                if (rc == 0) {
                        lmv_drop_intent_lock(it);
                        memcpy(&it->d.lustre.it_lock_handle, &plock,
                                        sizeof(plock));
                        it->d.lustre.it_lock_mode = pmode;
                        
                } else if (pmode)
                        ldlm_lock_decref(&plock, pmode);

                ptlrpc_req_finished(*reqp);
                *reqp = req;
        }
        RETURN(rc);
}

int lmv_intent_open(struct obd_export *exp, struct ll_uctxt *uctxt,
                    struct ll_fid *pfid, const char *name, int len,
                    void *lmm, int lmmsize, struct ll_fid *cfid,
                    struct lookup_intent *it, int flags,
                    struct ptlrpc_request **reqp,
                    ldlm_blocking_callback cb_blocking)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mds_body *body = NULL;
        struct ll_fid rpfid = *pfid;
        struct lmv_obj *obj;
        struct mea *mea;
        int rc, mds;
        ENTRY;

        /* IT_OPEN is intended to open (and create, possible) an object. Parent
         * (pfid) may be splitted dir */

repeat:
        mds = rpfid.mds;
        obj = lmv_grab_obj(obd, &rpfid);
        if (obj) {
                /* directory is already splitted, so we have to forward
                 * request to the right MDS */
                mds = raw_name2idx(obj->objcount, (char *)name, len);
                CDEBUG(D_OTHER, "forward to MDS #%u\n", mds);
                rpfid = obj->objs[mds].fid;
                lmv_put_obj(obj);
        }

        rc = md_intent_lock(lmv->tgts[mds].ltd_exp, uctxt, &rpfid, name,
                            len, lmm, lmmsize, cfid, it, flags, reqp,
                            cb_blocking);
        if (rc == -ERESTART) {
                /* directory got splitted. time to update local object
                 * and repeat the request with proper MDS */
                LASSERT(fid_equal(pfid, &rpfid));
                rc = lmv_get_mea_and_update_object(exp, &rpfid);
                if (rc == 0) {
                        ptlrpc_req_finished(*reqp);
                        goto repeat;
                }
        }
        if (rc != 0)
                RETURN(rc);

        /* okay, MDS has returned success. Probably name has been resolved in
         * remote inode */
        rc = lmv_handle_remote_inode(exp, uctxt, lmm, lmmsize, it,
                                     flags, reqp, cb_blocking);
        if (rc != 0) {
                LASSERT(rc < 0);
                RETURN(rc);
        }

        /* caller may use attrs MDS returns on IT_OPEN lock request so, we have
         * to update them for splitted dir */
        body = lustre_msg_buf((*reqp)->rq_repmsg, 1, sizeof(*body));
        LASSERT(body != NULL);

        cfid = &body->fid1;
        obj = lmv_grab_obj(obd, cfid);
        if (!obj && (mea = body_of_splitted_dir(*reqp, 1))) {
                /* wow! this is splitted dir, we'd like to handle it */
                obj = lmv_create_obj(exp, &body->fid1, mea);
                if (IS_ERR(obj))
                        RETURN(PTR_ERR(obj));
        }

        if (obj) {
                /* this is splitted dir and we'd want to get attrs */
                CDEBUG(D_OTHER, "attrs from slaves for %lu/%lu/%lu\n",
                       (unsigned long)cfid->mds, (unsigned long)cfid->id,
                       (unsigned long)cfid->generation);
                rc = lmv_revalidate_slaves(exp, reqp, cfid,
                                           it, 1, cb_blocking);
        } else if (S_ISDIR(body->mode)) {
                /*CWARN("hmmm, %lu/%lu/%lu has not lmv obj?!\n",
                                (unsigned long) cfid->mds,
                                (unsigned long) cfid->id,
                                (unsigned long) cfid->generation);*/
        }
        
        if (obj)
                lmv_put_obj(obj);
        
        RETURN(rc);
}

int lmv_intent_getattr(struct obd_export *exp, struct ll_uctxt *uctxt,
                       struct ll_fid *pfid, const char *name, int len,
                       void *lmm, int lmmsize, struct ll_fid *cfid,
                       struct lookup_intent *it, int flags,
                       struct ptlrpc_request **reqp,
                       ldlm_blocking_callback cb_blocking)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mds_body *body = NULL;
        struct ll_fid rpfid = *pfid;
        struct lmv_obj *obj, *obj2;
        struct mea *mea;
        int rc = 0, mds;
        ENTRY;

        if (cfid) {
                /* caller wants to revalidate attrs of obj we have to revalidate
                 * slaves if requested object is splitted directory */
                CDEBUG(D_OTHER, "revalidate attrs for %lu/%lu/%lu\n",
                       (unsigned long)cfid->mds, (unsigned long)cfid->id,
                       (unsigned long)cfid->generation);
                mds = cfid->mds;
                obj = lmv_grab_obj(obd, cfid);
                if (obj) {
                        /* in fact, we need not this with current intent_lock(),
                         * but it may change some day */
                        rpfid = obj->objs[mds].fid;
                        lmv_put_obj(obj);
                }
                rc = md_intent_lock(lmv->tgts[mds].ltd_exp, uctxt, &rpfid, name,
                                    len, lmm, lmmsize, cfid, it, flags, reqp,
                                    cb_blocking);
                if (obj && rc >= 0) {
                        /* this is splitted dir. In order to optimize things a
                         * bit, we consider obj valid updating missing parts.

                         * FIXME: do we need to return any lock here? It would
                         * be fine if we don't. this means that nobody should
                         * use UPDATE lock to notify about object * removal */
                        CDEBUG(D_OTHER,
                               "revalidate slaves for %lu/%lu/%lu, rc %d\n",
                               (unsigned long)cfid->mds, (unsigned long)cfid->id,
                               (unsigned long)cfid->generation, rc);
                        
                        rc = lmv_revalidate_slaves(exp, reqp, cfid, it, rc,
                                                   cb_blocking);
                }

                RETURN(rc);                
        }

        CDEBUG(D_OTHER, "INTENT getattr for %*s on %lu/%lu/%lu\n",
               len, name, (unsigned long)pfid->mds, (unsigned long)pfid->id,
               (unsigned long)pfid->generation);

        mds = pfid->mds;
        obj = lmv_grab_obj(obd, pfid);
        if (obj && len) {
                /* directory is already splitted. calculate mds */
                mds = raw_name2idx(obj->objcount, (char *) name, len);
                rpfid = obj->objs[mds].fid;
                lmv_put_obj(obj);
                
                CDEBUG(D_OTHER, "forward to MDS #%u (slave %lu/%lu/%lu)\n",
                       mds, (unsigned long)rpfid.mds, (unsigned long)rpfid.id,
                       (unsigned long)rpfid.generation);
        }
        
        rc = md_intent_lock(lmv->tgts[mds].ltd_exp, uctxt, &rpfid, name,
                            len, lmm, lmmsize, NULL, it, flags, reqp,
                            cb_blocking);
        
        if (rc < 0)
                RETURN(rc);
        
        LASSERT(rc == 0);

        /* okay, MDS has returned success. probably name has been
         * resolved in remote inode */
        rc = lmv_handle_remote_inode(exp, uctxt, lmm, lmmsize, it,
                                     flags, reqp, cb_blocking);
        if (rc < 0)
                RETURN(rc);

        body = lustre_msg_buf((*reqp)->rq_repmsg, 1, sizeof(*body));
        LASSERT(body != NULL);
        
        cfid = &body->fid1;
        obj2 = lmv_grab_obj(obd, cfid);

        if (!obj2 && (mea = body_of_splitted_dir(*reqp, 1))) {
                /* wow! this is splitted dir, we'd like to handle it. */
                body = lustre_msg_buf((*reqp)->rq_repmsg, 1, sizeof(*body));
                LASSERT(body != NULL);

                obj2 = lmv_create_obj(exp, &body->fid1, mea);
                if (IS_ERR(obj2))
                        RETURN(PTR_ERR(obj2));
        }

        if (obj2) {
                /* this is splitted dir and we'd want to get attrs */
                CDEBUG(D_OTHER, "attrs from slaves for %lu/%lu/%lu, rc %d\n",
                       (unsigned long)cfid->mds, (unsigned long)cfid->id,
                       (unsigned long)cfid->generation, rc);
                
                rc = lmv_revalidate_slaves(exp, reqp, cfid, it, 1, cb_blocking);
                lmv_put_obj(obj2);
        }
        RETURN(rc);
}

void lmv_update_body_from_obj(struct mds_body *body, struct lmv_inode *obj)
{
        /* update size */
        body->size += obj->size;
/*        body->atime = obj->atime;
        body->ctime = obj->ctime;
        body->mtime = obj->mtime;
        body->nlink = obj->nlink;*/
}

int lmv_lookup_slaves(struct obd_export *exp, struct ptlrpc_request **reqp)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mds_body *body = NULL;
        struct lustre_handle *lockh;
        struct ldlm_lock *lock;
        struct mds_body *body2;
        struct ll_uctxt uctxt;
        struct lmv_obj *obj;
        int i, rc = 0;
        ENTRY;

        LASSERT(reqp);
        LASSERT(*reqp);

        /* master is locked. we'd like to take locks on slaves and update
         * attributes to be returned from the slaves it's important that lookup
         * is called in two cases:
         
         *  - for first time (dcache has no such a resolving yet).
         *  - ->d_revalidate() returned false.
         
         * last case possible only if all the objs (master and all slaves aren't
         * valid */

        body = lustre_msg_buf((*reqp)->rq_repmsg, 1, sizeof(*body));
        LASSERT(body != NULL);

        obj = lmv_grab_obj(obd, &body->fid1);
        LASSERT(obj != NULL);

        CDEBUG(D_OTHER, "lookup slaves for %lu/%lu/%lu\n",
               (unsigned long)body->fid1.mds,
               (unsigned long)body->fid1.id,
               (unsigned long)body->fid1.generation);

        uctxt.gid1 = 0;
        uctxt.gid2 = 0;

        lmv_lock_obj(obj);
        
        for (i = 0; i < obj->objcount; i++) {
                struct ll_fid fid = obj->objs[i].fid;
                struct ptlrpc_request *req = NULL;
                struct lookup_intent it;

                if (fid_equal(&fid, &obj->fid))
                        /* skip master obj */
                        continue;

                CDEBUG(D_OTHER, "lookup slave %lu/%lu/%lu\n",
                       (unsigned long)fid.mds, (unsigned long)fid.id,
                       (unsigned long)fid.generation);

                /* is obj valid? */
                memset(&it, 0, sizeof(it));
                it.it_op = IT_GETATTR;
                rc = md_intent_lock(lmv->tgts[fid.mds].ltd_exp, &uctxt, &fid,
                                    NULL, 0, NULL, 0, &fid, &it, 0, &req,
                                    lmv_dirobj_blocking_ast);
                
                lockh = (struct lustre_handle *)&it.d.lustre.it_lock_handle;
                if (rc > 0) {
                        /* nice, this slave is valid */
                        LASSERT(req == NULL);
                        CDEBUG(D_OTHER, "cached\n");
                        goto release_lock;
                }

                if (rc < 0)
                        /* error during revalidation */
                        GOTO(cleanup, rc);

                /* rc == 0, this means we have no such a lock and can't think
                 * obj is still valid. lookup it again */
                LASSERT(req == NULL);
                req = NULL;

                memset(&it, 0, sizeof(it));
                it.it_op = IT_GETATTR;
                rc = md_intent_lock(lmv->tgts[fid.mds].ltd_exp, &uctxt, &fid,
                                    NULL, 0, NULL, 0, NULL, &it, 0, &req,
                                    lmv_dirobj_blocking_ast);

                lockh = (struct lustre_handle *) &it.d.lustre.it_lock_handle;
                LASSERT(rc <= 0);

                if (rc < 0)
                        /* error during lookup */
                        GOTO(cleanup, rc);
                
                lock = ldlm_handle2lock(lockh);
                LASSERT(lock);

                lock->l_ast_data = lmv_get_obj(obj);

                body2 = lustre_msg_buf(req->rq_repmsg, 1, sizeof(*body2));
                LASSERT(body2);

                obj->objs[i].size = body2->size;
                
                CDEBUG(D_OTHER, "fresh: %lu\n",
                       (unsigned long)obj->objs[i].size);

                LDLM_LOCK_PUT(lock);

                if (req)
                        ptlrpc_req_finished(req);
release_lock:
                lmv_update_body_from_obj(body, obj->objs + i);

                if (it.d.lustre.it_lock_mode)
                        ldlm_lock_decref(lockh, it.d.lustre.it_lock_mode);
        }
cleanup:
        lmv_unlock_obj(obj);
        lmv_put_obj(obj);
        RETURN(rc);
}

int lmv_intent_lookup(struct obd_export *exp, struct ll_uctxt *uctxt,
                      struct ll_fid *pfid, const char *name, int len,
                      void *lmm, int lmmsize, struct ll_fid *cfid,
                      struct lookup_intent *it, int flags,
                      struct ptlrpc_request **reqp,
                      ldlm_blocking_callback cb_blocking)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mds_body *body = NULL;
        struct ll_fid rpfid = *pfid;
        struct lmv_obj *obj;
        struct mea *mea;
        int rc, mds;
        ENTRY;

        /* IT_LOOKUP is intended to produce name -> fid resolving (let's call
         * this lookup below) or to confirm requested resolving is still valid
         * (let's call this revalidation) cfid != NULL specifies revalidation */

        if (cfid) {
                /* this is revalidation: we have to check is LOOKUP lock still
                 * valid for given fid. very important part is that we have to
                 * choose right mds because namespace is per mds */
                rpfid = *pfid;
                obj = lmv_grab_obj(obd, pfid);
                if (obj) {
                        mds = raw_name2idx(obj->objcount, (char *) name, len);
                        rpfid = obj->objs[mds].fid;
                        lmv_put_obj(obj);
                }
                mds = rpfid.mds;
                
                CDEBUG(D_OTHER, "revalidate lookup for %lu/%lu/%lu to %d MDS\n",
                       (unsigned long)cfid->mds, (unsigned long)cfid->id,
                       (unsigned long)cfid->generation, mds);
                
                rc = md_intent_lock(lmv->tgts[mds].ltd_exp, uctxt, pfid, name,
                                    len, lmm, lmmsize, cfid, it, flags,
                                    reqp, cb_blocking);
                RETURN(rc);
        }

        mds = pfid->mds;
repeat:
        /* this is lookup. during lookup we have to update all the attributes,
         * because returned values will be put in struct inode */

        obj = lmv_grab_obj(obd, pfid);
        if (obj) {
                if (len) {
                        /* directory is already splitted. calculate mds */
                        mds = raw_name2idx(obj->objcount, (char *)name, len);
                        rpfid = obj->objs[mds].fid;
                }
                lmv_put_obj(obj);
        }

        rc = md_intent_lock(lmv->tgts[mds].ltd_exp, uctxt, &rpfid, name,
                            len, lmm, lmmsize, NULL, it, flags, reqp,
                            cb_blocking);
        if (rc > 0) {
                /* very interesting. it seems object is still valid but for some
                 * reason llite calls lookup, not revalidate */
                CWARN("lookup for %lu/%lu/%lu and data should be uptodate\n",
                      (unsigned long)rpfid.mds, (unsigned long)rpfid.id,
                      (unsigned long)rpfid.generation);
                LASSERT(*reqp == NULL);
                RETURN(rc);
        }

        if (rc == 0 && *reqp == NULL) {
                /* once again, we're asked for lookup, not revalidate */
                CWARN("lookup for %lu/%lu/%lu and data should be uptodate\n",
                       (unsigned long)rpfid.mds, (unsigned long)rpfid.id,
                       (unsigned long)rpfid.generation);
                RETURN(rc);
        }
       
        if (rc == -ERESTART) {
                /* directory got splitted since last update. this shouldn't be
                 * becasue splitting causes lock revocation, so revalidate had
                 * to fail and lookup on dir had to return mea */
                CWARN("we haven't knew about directory splitting!\n");
                LASSERT(obj == NULL);

                obj = lmv_create_obj(exp, &rpfid, NULL);
                if (IS_ERR(obj))
                        RETURN(PTR_ERR(obj));
                lmv_put_obj(obj);
                goto repeat;
        }

        if (rc < 0)
                RETURN(rc);

        /* okay, MDS has returned success. probably name has been resolved in
         * remote inode */
        rc = lmv_handle_remote_inode(exp, uctxt, lmm, lmmsize, it, flags,
                                     reqp, cb_blocking);

        if (rc == 0 && (mea = body_of_splitted_dir(*reqp, 1))) {
                /* wow! this is splitted dir, we'd like to handle it */
                body = lustre_msg_buf((*reqp)->rq_repmsg, 1, sizeof(*body));
                LASSERT(body != NULL);
                
                obj = lmv_grab_obj(obd, &body->fid1);
                if (!obj) {
                        obj = lmv_create_obj(exp, &body->fid1, mea);
                        if (IS_ERR(obj))
                                RETURN(PTR_ERR(obj));
                }
                lmv_put_obj(obj);
        }

        RETURN(rc);
}

int lmv_intent_lock(struct obd_export *exp, struct ll_uctxt *uctxt,
                    struct ll_fid *pfid, const char *name, int len,
                    void *lmm, int lmmsize, struct ll_fid *cfid,
                    struct lookup_intent *it, int flags,
                    struct ptlrpc_request **reqp,
                    ldlm_blocking_callback cb_blocking)
{
        struct obd_device *obd = exp->exp_obd;
        int rc = 0;
        ENTRY;

        LASSERT(it);
        LASSERT(pfid);

        CDEBUG(D_OTHER, "INTENT LOCK '%s' for '%*s' on %lu/%lu -> %u\n",
                        LL_IT2STR(it), len, name, (unsigned long) pfid->id,
                        (unsigned long) pfid->generation, pfid->mds);

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        if (it->it_op == IT_LOOKUP)
                rc = lmv_intent_lookup(exp, uctxt, pfid, name, len, lmm,
                                       lmmsize, cfid, it, flags, reqp,
                                       cb_blocking);
        else if (it->it_op & IT_OPEN)
                rc = lmv_intent_open(exp, uctxt, pfid, name, len, lmm,
                                     lmmsize, cfid, it, flags, reqp,
                                     cb_blocking);
        else if (it->it_op == IT_GETATTR || it->it_op == IT_CHDIR)
                rc = lmv_intent_getattr(exp, uctxt, pfid, name, len, lmm,
                                        lmmsize, cfid, it, flags, reqp,
                                        cb_blocking);
        else
                LBUG();
        RETURN(rc);
}

int lmv_revalidate_slaves(struct obd_export *exp, struct ptlrpc_request **reqp,
                          struct ll_fid *mfid, struct lookup_intent *oit,
                          int master_valid, ldlm_blocking_callback cb_blocking)
{
        struct obd_device *obd = exp->exp_obd;
        struct ptlrpc_request *mreq = *reqp;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lustre_handle master_lockh;
        struct ldlm_lock *lock;
        unsigned long size = 0;
        struct mds_body *body;
        struct ll_uctxt uctxt;
        struct lmv_obj *obj;
        int master_lock_mode;
        int i, rc = 0;
        ENTRY;

        /* we have to loop over the subobjects, check validity and update them
         * from MDSs if needed. it's very useful that we need not to update all
         * the fields. say, common fields (that are equal on all the subojects
         * need not to be update, another fields (i_size, for example) are
         * cached all the time */
        obj = lmv_grab_obj(obd, mfid);
        LASSERT(obj != NULL);

        uctxt.gid1 = 0;
        uctxt.gid2 = 0;
        master_lock_mode = 0;

        lmv_lock_obj(obj);
        
        for (i = 0; i < obj->objcount; i++) {
                struct ll_fid fid = obj->objs[i].fid;
                struct lustre_handle *lockh = NULL;
                struct ptlrpc_request *req = NULL;
                ldlm_blocking_callback cb;
                struct lookup_intent it;
                int master = 0;

                CDEBUG(D_OTHER, "revalidate subobj %lu/%lu/%lu\n",
                       (unsigned long)fid.mds, (unsigned long)fid.id,
                       (unsigned long) fid.generation);

                memset(&it, 0, sizeof(it));
                it.it_op = IT_GETATTR;
                cb = lmv_dirobj_blocking_ast;

                if (fid_equal(&fid, &obj->fid)) {
                        if (master_valid) {
                                /* lmv_intent_getattr() already checked
                                 * validness and took the lock */
                                if (mreq) {
                                        /* it even got the reply refresh attrs
                                         * from that reply */
                                        body = lustre_msg_buf(mreq->rq_repmsg,
                                                              1, sizeof(*body));
                                        LASSERT(body != NULL);
                                        goto update; 
                                }
                                /* take already cached attrs into account */
                                CDEBUG(D_OTHER,
                                       "master is locked and cached\n");
                                goto release_lock;
                        }
                        master = 1;
                        cb = cb_blocking;
                }

                /* is obj valid? */
                rc = md_intent_lock(lmv->tgts[fid.mds].ltd_exp, &uctxt, &fid,
                                    NULL, 0, NULL, 0, &fid, &it, 0, &req, cb);
                lockh = (struct lustre_handle *) &it.d.lustre.it_lock_handle;
                if (rc > 0) {
                        /* nice, this slave is valid */
                        LASSERT(req == NULL);
                        CDEBUG(D_OTHER, "cached\n");
                        goto release_lock;
                }

                if (rc < 0)
                        /* error during revalidation */
                        GOTO(cleanup, rc);

                /* rc == 0, this means we have no such a lock and can't think
                 * obj is still valid. lookup it again */
                LASSERT(req == NULL);
                req = NULL;
                
                memset(&it, 0, sizeof(it));
                it.it_op = IT_GETATTR;
                rc = md_intent_lock(lmv->tgts[fid.mds].ltd_exp, &uctxt, &fid,
                                    NULL, 0, NULL, 0, NULL, &it, 0, &req, cb);
                lockh = (struct lustre_handle *) &it.d.lustre.it_lock_handle;
                LASSERT(rc <= 0);

                if (rc < 0)
                        /* error during lookup */
                        GOTO(cleanup, rc);
              
                if (master) {
                        LASSERT(master_valid == 0);
                        /* save lock on master to be returned to the caller */
                        CDEBUG(D_OTHER, "no lock on master yet\n");
                        memcpy(&master_lockh, lockh, sizeof(master_lockh));
                        master_lock_mode = it.d.lustre.it_lock_mode;
                        it.d.lustre.it_lock_mode = 0;
                } else {
                        /* this is slave. we want to control it */
                        lock = ldlm_handle2lock(lockh);
                        LASSERT(lock);
                        lock->l_ast_data = lmv_get_obj(obj);
                        LDLM_LOCK_PUT(lock);
                }

                if (*reqp == NULL) {
                        /* this is first reply, we'll use it to return
                         * updated data back to the caller */
                        LASSERT(req);
                        ptlrpc_request_addref(req);
                        *reqp = req;

                }

                body = lustre_msg_buf(req->rq_repmsg, 1, sizeof(*body));
                LASSERT(body);
                
update:
                obj->objs[i].size = body->size;
                
                CDEBUG(D_OTHER, "fresh: %lu\n",
                       (unsigned long)obj->objs[i].size);

                if (req)
                        ptlrpc_req_finished(req);
release_lock:
                size += obj->objs[i].size;

                if (it.d.lustre.it_lock_mode)
                        ldlm_lock_decref(lockh, it.d.lustre.it_lock_mode);
        }

        if (*reqp) {
                /* some attrs got refreshed, we have reply and it's time to put
                 * fresh attrs to it */
                CDEBUG(D_OTHER, "return refreshed attrs: size = %lu\n",
                       (unsigned long)size);
                
                body = lustre_msg_buf((*reqp)->rq_repmsg, 1, sizeof(*body));
                LASSERT(body);

                /* FIXME: what about other attributes? */
                body->size = size;
                
                if (mreq == NULL) {
                        /* very important to maintain lli->mds the same because
                         * of revalidation. mreq == NULL means that caller has
                         * no reply and the only attr we can return is size */
                        body->valid = OBD_MD_FLSIZE;
                        body->mds = obj->fid.mds;
                }
                if (master_valid == 0) {
                        memcpy(&oit->d.lustre.it_lock_handle,
                               &master_lockh, sizeof(master_lockh));
                        oit->d.lustre.it_lock_mode = master_lock_mode;
                }
                rc = 0;
        } else {
                /* it seems all the attrs are fresh and we did no request */
                CDEBUG(D_OTHER, "all the attrs were fresh\n");
                if (master_valid == 0)
                        oit->d.lustre.it_lock_mode = master_lock_mode;
                rc = 1;
        }
cleanup:
        lmv_unlock_obj(obj);
        lmv_put_obj(obj);
        RETURN(rc);
}
