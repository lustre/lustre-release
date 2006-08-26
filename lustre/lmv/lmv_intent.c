/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003, 2004, 2005, 2006 Cluster File Systems, Inc.
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
#include <linux/namei.h>
#else
#include <liblustre.h>
#endif

#include <lustre/lustre_idl.h>
#include <obd_support.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <lustre_dlm.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include "lmv_internal.h"

static inline void lmv_drop_intent_lock(struct lookup_intent *it)
{
        if (it->d.lustre.it_lock_mode != 0)
                ldlm_lock_decref((void *)&it->d.lustre.it_lock_handle,
                                 it->d.lustre.it_lock_mode);
}

int lmv_intent_remote(struct obd_export *exp, void *lmm,
                      int lmmsize, struct lookup_intent *it,
                      int flags, struct ptlrpc_request **reqp,
                      ldlm_blocking_callback cb_blocking,
                      int extra_lock_flags)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct ptlrpc_request *req = NULL;
        struct mdt_body *body = NULL;
        struct lustre_handle plock;
        struct md_op_data *op_data;
        struct obd_export *tgt_exp;
        struct lu_fid nid;
        int pmode, rc = 0;
        ENTRY;

        body = lustre_msg_buf((*reqp)->rq_repmsg,
                              DLM_REPLY_REC_OFF, sizeof(*body));
        LASSERT(body != NULL);

        if (!(body->valid & OBD_MD_MDS))
                RETURN(0);

        /*
         * oh, MDS reports that this is remote inode case i.e. we have to ask
         * for real attrs on another MDS.
         */
        if (it->it_op & IT_LOOKUP) {
                /*
                 * unfortunately, we have to lie to MDC/MDS to retrieve
                 * attributes llite needs.
                 */
                it->it_op = IT_GETATTR;
        }

        /* we got LOOKUP lock, but we really need attrs */
        pmode = it->d.lustre.it_lock_mode;
        if (pmode) {
                memcpy(&plock, &it->d.lustre.it_lock_handle,
                       sizeof(plock));
                it->d.lustre.it_lock_mode = 0;
                it->d.lustre.it_data = 0;
        }

        LASSERT(fid_is_sane(&body->fid1));

        nid = body->fid1;
        it->d.lustre.it_disposition &= ~DISP_ENQ_COMPLETE;

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL)
                GOTO(out, rc = -ENOMEM);
        
        op_data->fid1 = nid;

        tgt_exp = lmv_get_export(lmv, &nid);
        if (IS_ERR(tgt_exp))
                RETURN(PTR_ERR(tgt_exp));

        rc = md_intent_lock(tgt_exp, op_data, lmm, lmmsize, it, flags,
                            &req, cb_blocking, extra_lock_flags);

        /*
         * llite needs LOOKUP lock to track dentry revocation in order to
         * maintain dcache consistency. Thus drop UPDATE lock here and put
         * LOOKUP in request.
         */
        if (rc == 0) {
                lmv_drop_intent_lock(it);
                memcpy(&it->d.lustre.it_lock_handle, &plock,
                       sizeof(plock));
                it->d.lustre.it_lock_mode = pmode;
        }

        OBD_FREE_PTR(op_data);
        EXIT;
out:
        if (rc && pmode)
                ldlm_lock_decref(&plock, pmode);

        ptlrpc_req_finished(*reqp);
        *reqp = req;
        return rc;
}

/*
 * IT_OPEN is intended to open (and create, possible) an object. Parent (pid)
 * may be split dir.
 */
int lmv_intent_open(struct obd_export *exp, const struct lu_fid *pid,
                    const char *name, int len, void *lmm, int lmmsize,
                    const struct lu_fid *cid, struct lookup_intent *it,
                    int flags, struct ptlrpc_request **reqp,
                    ldlm_blocking_callback cb_blocking,
                    int extra_lock_flags)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mdt_body *body = NULL;
        struct md_op_data *op_data;
        struct lmv_stripe_md *mea;
        struct lu_fid rpid = *pid;
        struct lmv_obj *obj;
        int rc, loop = 0;
        mdsno_t mds;
        ENTRY;

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL)
                RETURN(-ENOMEM);
        
repeat:
        LASSERT(++loop <= 2);
        rc = lmv_fld_lookup(lmv, &rpid, &mds);
        if (rc)
                GOTO(out_free_op_data, rc);
        obj = lmv_obj_grab(obd, &rpid);
        if (obj) {
                /* directory is already split, so we have to forward request to
                 * the right MDS. */
                mds = raw_name2idx(obj->lo_hashtype, obj->lo_objcount,
                                   (char *)name, len);

                CDEBUG(D_OTHER, "forward to MDS #"LPU64" ("DFID")\n",
                       mds, PFID(&rpid));
                rpid = obj->lo_inodes[mds].li_fid;
                lmv_obj_put(obj);
        }

        op_data->fid1 = rpid;

        if (cid)
                op_data->fid2 = *cid;
        op_data->name = name;
        op_data->namelen = len;

        rc = md_intent_lock(lmv->tgts[mds].ltd_exp, op_data,
                            lmm, lmmsize, it, flags, reqp,
                            cb_blocking, extra_lock_flags);
        if (rc == -ERESTART) {
                /* directory got split. time to update local object and
                 * repeat the request with proper MDS */
                LASSERT(lu_fid_eq(pid, &rpid));
                rc = lmv_handle_split(exp, &rpid);
                if (rc == 0) {
                        ptlrpc_req_finished(*reqp);
                        memset(op_data, 0, sizeof(*op_data));
                        goto repeat;
                }
        }
        if (rc != 0)
                GOTO(out_free_op_data, rc);

        /* okay, MDS has returned success. Probably name has been resolved in
         * remote inode */
        rc = lmv_intent_remote(exp, lmm, lmmsize, it, flags, reqp,
                               cb_blocking, extra_lock_flags);
        if (rc != 0) {
                LASSERT(rc < 0);

                /*
                 * This is possible, that some userspace application will try to
                 * open file as directory and we will have -ENOTDIR here. As
                 * this is "usual" situation, we should not print error here,
                 * only debug info.
                 */
                CDEBUG(D_OTHER, "can't handle remote %s: dir "DFID"("DFID"):"
                       "%*s: %d\n", LL_IT2STR(it), PFID(pid), PFID(&rpid),
                       len, name, rc);
                GOTO(out_free_op_data, rc);
        }

        /*
         * nothing is found, do not access body->fid1 as it is zero and thus
         * pointless.
         */
        if ((it->d.lustre.it_disposition & DISP_LOOKUP_NEG) &&
            !(it->d.lustre.it_disposition & DISP_OPEN_CREATE) &&
            !(it->d.lustre.it_disposition & DISP_OPEN_OPEN))
                GOTO(out_free_op_data, rc = 0);

        /* caller may use attrs MDS returns on IT_OPEN lock request so, we have
         * to update them for split dir */
        body = lustre_msg_buf((*reqp)->rq_repmsg, DLM_REPLY_REC_OFF, sizeof(*body));
        LASSERT(body != NULL);

        /* could not find object, FID is not present in response. */
        if (!(body->valid & OBD_MD_FLID))
                GOTO(out_free_op_data, rc = 0);

        cid = &body->fid1;
        obj = lmv_obj_grab(obd, cid);
        if (!obj && (mea = lmv_get_mea(*reqp, DLM_REPLY_REC_OFF))) {
                /* wow! this is split dir, we'd like to handle it */
                obj = lmv_obj_create(exp, &body->fid1, mea);
                if (IS_ERR(obj))
                        GOTO(out_free_op_data, rc = (int)PTR_ERR(obj));
        }

        if (obj) {
                /* this is split dir and we'd want to get attrs */
                CDEBUG(D_OTHER, "attrs from slaves for "DFID"\n",
                       PFID(cid));

                rc = lmv_revalidate_slaves(exp, reqp, cid, it, 1,
                                           cb_blocking, extra_lock_flags);
        } else if (S_ISDIR(body->mode)) {
                CDEBUG(D_OTHER, "object "DFID" has not lmv obj?\n",
                       PFID(cid));
        }

        if (obj)
                lmv_obj_put(obj);

        EXIT;
out_free_op_data:
        OBD_FREE_PTR(op_data);
        return rc;
}

int lmv_intent_getattr(struct obd_export *exp, const struct lu_fid *pid,
                       const char *name, int len, void *lmm, int lmmsize,
                       const struct lu_fid *cid, struct lookup_intent *it,
                       int flags, struct ptlrpc_request **reqp,
                       ldlm_blocking_callback cb_blocking,
                       int extra_lock_flags)
{
        struct lmv_obj *obj = NULL, *obj2 = NULL;
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mdt_body *body = NULL;
        struct md_op_data *op_data;
        struct lu_fid rpid = *pid;
        struct lmv_stripe_md *mea;
        mdsno_t mds;
        int rc = 0;
        ENTRY;

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL)
                RETURN(-ENOMEM);
        
        if (cid) {
                /* caller wants to revalidate attrs of obj we have to revalidate
                 * slaves if requested object is split directory */
                CDEBUG(D_OTHER, "revalidate attrs for "DFID"\n", PFID(cid));
                rc = lmv_fld_lookup(lmv, cid, &mds);
                if (rc)
                        GOTO(out_free_op_data, rc);
#if 0
                obj = lmv_obj_grab(obd, cid);
                if (obj) {
                        /* in fact, we do not need this with current
                         * intent_lock(), but it may change some day */
                        if (!lu_fid_eq(pid, cid)){
                                rpid = obj->lo_inodes[mds].li_fid;
                                rc = lmv_fld_lookup(lmv, &rpid, &mds);
                                if (rc) {
                                        lmv_obj_put(obj);
                                        GOTO(out_free_op_data, rc);
                                }
                        }
                        lmv_obj_put(obj);
                }
#endif
                op_data->fid2 = *cid;
        } else {
                CDEBUG(D_OTHER, "INTENT getattr for %*s on "DFID"\n",
                       len, name, PFID(pid));
                rc = lmv_fld_lookup(lmv, pid, &mds);
                if (rc)
                        GOTO(out_free_op_data, rc);
                obj = lmv_obj_grab(obd, pid);
                if (obj && len) {
                        /* directory is already split. calculate mds */
                        mds = raw_name2idx(obj->lo_hashtype, obj->lo_objcount,
                                           (char *)name, len);
                        rpid = obj->lo_inodes[mds].li_fid;
                        rc = lmv_fld_lookup(lmv, &rpid, &mds);
                        if (rc) {
                                lmv_obj_put(obj);
                                GOTO(out_free_op_data, rc);
                        }
                        lmv_obj_put(obj);

                        CDEBUG(D_OTHER, "forward to MDS #"LPU64" (slave "DFID")\n",
                               mds, PFID(&rpid));
                }
        }

        op_data->fid1 = rpid;
        op_data->name = name;
        op_data->namelen = len;

        /* the same about fid returning. */
        rc = md_intent_lock(lmv->tgts[mds].ltd_exp, op_data, lmm,
                            lmmsize, it, flags, reqp, cb_blocking,
                            extra_lock_flags);
        if (rc < 0)
                GOTO(out_free_op_data, rc);

        if (obj && rc > 0) {
                /*
                 * this is split dir. In order to optimize things a bit, we
                 * consider obj valid updating missing parts.

                 * FIXME: do we need to return any lock here? It would be fine
                 * if we don't. this means that nobody should use UPDATE lock to
                 * notify about object * removal.
                 */
                CDEBUG(D_OTHER,
                       "revalidate slaves for "DFID", rc %d\n",
                       PFID(cid), rc);

                LASSERT(cid != 0);
                rc = lmv_revalidate_slaves(exp, reqp, cid, it, rc,
                                           cb_blocking, extra_lock_flags);
                GOTO(out_free_op_data, rc);
        }

        if (*reqp == NULL)
                GOTO(out_free_op_data, rc);

        /*
         * okay, MDS has returned success. probably name has been resolved in
         * remote inode.
         */
        rc = lmv_intent_remote(exp, lmm, lmmsize, it, flags,
                               reqp, cb_blocking, extra_lock_flags);
        if (rc < 0)
                GOTO(out_free_op_data, rc);

        /*
         * nothing is found, do not access body->fid1 as it is zero and thus
         * pointless.
         */
        if (it->d.lustre.it_disposition & DISP_LOOKUP_NEG)
                GOTO(out_free_op_data, rc = 0);

        body = lustre_msg_buf((*reqp)->rq_repmsg, DLM_REPLY_REC_OFF, sizeof(*body));
        LASSERT(body != NULL);

        /* could not find object, FID is not present in response. */
        if (!(body->valid & OBD_MD_FLID))
                GOTO(out_free_op_data, rc = 0);

        cid = &body->fid1;
        obj2 = lmv_obj_grab(obd, cid);

        if (!obj2 && (mea = lmv_get_mea(*reqp, DLM_REPLY_REC_OFF))) {
                /* wow! this is split dir, we'd like to handle it. */
                body = lustre_msg_buf((*reqp)->rq_repmsg, DLM_REPLY_REC_OFF, sizeof(*body));
                LASSERT(body != NULL);

                obj2 = lmv_obj_create(exp, &body->fid1, mea);
                if (IS_ERR(obj2))
                        GOTO(out_free_op_data, rc = (int)PTR_ERR(obj2));
        }

        if (obj2) {
                /* this is split dir and we'd want to get attrs */
                CDEBUG(D_OTHER, "attrs from slaves for "DFID", rc %d\n",
                       PFID(cid), rc);

                rc = lmv_revalidate_slaves(exp, reqp, cid, it, 1,
                                           cb_blocking, extra_lock_flags);
                lmv_obj_put(obj2);
        }

        EXIT;
out_free_op_data:
        OBD_FREE_PTR(op_data);
        return rc;
}

void lmv_update_body(struct mdt_body *body, struct lmv_inode *lino)
{
        /* update size */
        body->size += lino->li_size;
}

/* this is not used currently */
int lmv_lookup_slaves(struct obd_export *exp, struct ptlrpc_request **reqp)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mdt_body *body = NULL;
        struct lustre_handle *lockh;
        struct md_op_data *op_data;
        struct ldlm_lock *lock;
        struct mdt_body *body2;
        struct lmv_obj *obj;
        int i, rc = 0;
        ENTRY;

        LASSERT(reqp);
        LASSERT(*reqp);

        /* master is locked. we'd like to take locks on slaves and update
         * attributes to be returned from the slaves it's important that lookup
         * is called in two cases:

         *  - for first time (dcache has no such a resolving yet).  -
         *  ->d_revalidate() returned false.

         * last case possible only if all the objs (master and all slaves aren't
         * valid */

        body = lustre_msg_buf((*reqp)->rq_repmsg,
                              DLM_REPLY_REC_OFF, sizeof(*body));
        LASSERT(body != NULL);
        LASSERT((body->valid & OBD_MD_FLID) != 0);

        obj = lmv_obj_grab(obd, &body->fid1);
        LASSERT(obj != NULL);

        CDEBUG(D_OTHER, "lookup slaves for "DFID"\n",
               PFID(&body->fid1));

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL)
                RETURN(-ENOMEM);
        
        lmv_obj_lock(obj);

        for (i = 0; i < obj->lo_objcount; i++) {
                struct lu_fid fid = obj->lo_inodes[i].li_fid;
                struct ptlrpc_request *req = NULL;
                struct obd_export *tgt_exp;
                struct lookup_intent it;

                if (lu_fid_eq(&fid, &obj->lo_fid))
                        /* skip master obj */
                        continue;

                CDEBUG(D_OTHER, "lookup slave "DFID"\n", PFID(&fid));

                /* is obj valid? */
                memset(&it, 0, sizeof(it));
                it.it_op = IT_GETATTR;

                memset(op_data, 0, sizeof(*op_data));
                op_data->fid1 = fid;
                op_data->fid2 = fid;

                tgt_exp = lmv_get_export(lmv, &fid);
                if (IS_ERR(tgt_exp))
                        GOTO(cleanup, rc = PTR_ERR(tgt_exp));

                rc = md_intent_lock(tgt_exp, op_data, NULL, 0, &it, 0, &req,
                                    lmv_blocking_ast, 0);

                lockh = (struct lustre_handle *)&it.d.lustre.it_lock_handle;
                if (rc > 0 && req == NULL) {
                        /* nice, this slave is valid */
                        LASSERT(req == NULL);
                        CDEBUG(D_OTHER, "cached\n");
                        goto release_lock;
                }

                if (rc < 0) {
                        /* error during lookup */
                        GOTO(cleanup, rc);
                }
                lock = ldlm_handle2lock(lockh);
                LASSERT(lock);

                lock->l_ast_data = lmv_obj_get(obj);

                body2 = lustre_msg_buf(req->rq_repmsg,
                                       DLM_REPLY_REC_OFF, sizeof(*body2));
                LASSERT(body2);

                obj->lo_inodes[i].li_size = body2->size;

                CDEBUG(D_OTHER, "fresh: %lu\n",
                       (unsigned long)obj->lo_inodes[i].li_size);

                LDLM_LOCK_PUT(lock);

                if (req)
                        ptlrpc_req_finished(req);
release_lock:
                lmv_update_body(body, obj->lo_inodes + i);

                if (it.d.lustre.it_lock_mode)
                        ldlm_lock_decref(lockh, it.d.lustre.it_lock_mode);
        }

        EXIT;
cleanup:
        OBD_FREE_PTR(op_data);
        lmv_obj_unlock(obj);
        lmv_obj_put(obj);
        return rc;
}

int lmv_intent_lookup(struct obd_export *exp, const struct lu_fid *pid,
                      const char *name, int len, void *lmm, int lmmsize,
                      const struct lu_fid *cid, struct lookup_intent *it,
                      int flags, struct ptlrpc_request **reqp,
                      ldlm_blocking_callback cb_blocking,
                      int extra_lock_flags)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mdt_body *body = NULL;
        struct lu_fid rpid = *pid;
        struct md_op_data *op_data;
        struct lmv_stripe_md *mea;
        struct lmv_obj *obj;
        int rc, loop = 0;
        mdsno_t mds;
        ENTRY;

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL)
                RETURN(-ENOMEM);
        
        /*
         * IT_LOOKUP is intended to produce name -> fid resolving (let's call
         * this lookup below) or to confirm requested resolving is still valid
         * (let's call this revalidation) cid != NULL specifies revalidation.
         */
        if (cid) {
                /*
                 * This is revalidate: we have to check is LOOKUP lock still
                 * valid for given fid. Very important part is that we have to
                 * choose right mds because namespace is per mds.
                 */
                rpid = *pid;
                obj = lmv_obj_grab(obd, pid);
                if (obj) {
                        mds = raw_name2idx(obj->lo_hashtype, obj->lo_objcount,
                                           (char *)name, len);
                        rpid = obj->lo_inodes[mds].li_fid;
                        lmv_obj_put(obj);
                }
                rc = lmv_fld_lookup(lmv, &rpid, &mds);
                if (rc)
                        GOTO(out_free_op_data, rc);

                CDEBUG(D_OTHER, "revalidate lookup for "DFID" to #"LPU64" MDS\n",
                       PFID(cid), mds);

                op_data->fid2 = *cid;
        } else {
                rc = lmv_fld_lookup(lmv, pid, &mds);
                if (rc)
                        GOTO(out_free_op_data, rc);
repeat:
                LASSERT(++loop <= 2);

                /*
                 * This is lookup. During lookup we have to update all the
                 * attributes, because returned values will be put in struct
                 * inode.
                 */
                obj = lmv_obj_grab(obd, pid);
                if (obj) {
                        if (len) {
                                /* directory is already split. calculate mds */
                                mds = raw_name2idx(obj->lo_hashtype, obj->lo_objcount,
                                                   (char *)name, len);
                                rpid = obj->lo_inodes[mds].li_fid;
                                rc = lmv_fld_lookup(lmv, &rpid, &mds);
                                if (rc) {
                                        lmv_obj_put(obj);
                                        GOTO(out_free_op_data, rc);
                                }
                        }
                        lmv_obj_put(obj);
                }
                fid_zero(&op_data->fid2);
        }

        op_data->fid1 = rpid;
        op_data->name = name;
        op_data->namelen = len;

        rc = md_intent_lock(lmv->tgts[mds].ltd_exp, op_data, lmm, lmmsize,
                            it, flags, reqp, cb_blocking, extra_lock_flags);
        if (rc > 0) {
                LASSERT(cid != 0);
                GOTO(out_free_op_data, rc);
        }
        if (rc > 0) {
                /*
                 * very interesting. it seems object is still valid but for some
                 * reason llite calls lookup, not revalidate.
                 */
                CDEBUG(D_OTHER, "lookup for "DFID" and data should be uptodate\n",
                      PFID(&rpid));
                LASSERT(*reqp == NULL);
                GOTO(out_free_op_data, rc);
        }

        if (rc == 0 && *reqp == NULL) {
                /* once again, we're asked for lookup, not revalidate */
                CDEBUG(D_OTHER, "lookup for "DFID" and data should be uptodate\n",
                      PFID(&rpid));
                GOTO(out_free_op_data, rc);
        }

        if (rc == -ERESTART) {
                /* directory got split since last update. this shouldn't be
                 * becasue splitting causes lock revocation, so revalidate had
                 * to fail and lookup on dir had to return mea */
                CWARN("we haven't knew about directory splitting!\n");
                LASSERT(obj == NULL);

                obj = lmv_obj_create(exp, &rpid, NULL);
                if (IS_ERR(obj))
                        GOTO(out_free_op_data, rc = (int)PTR_ERR(obj));
                lmv_obj_put(obj);
                memset(op_data, 0, sizeof(*op_data));
                goto repeat;
        }

        if (rc < 0)
                GOTO(out_free_op_data, rc);

        /* okay, MDS has returned success. Probably name has been resolved in
         * remote inode. */
        rc = lmv_intent_remote(exp, lmm, lmmsize, it, flags, reqp,
                               cb_blocking, extra_lock_flags);

        if (rc == 0 && (mea = lmv_get_mea(*reqp, DLM_REPLY_REC_OFF))) {
                /* wow! this is split dir, we'd like to handle it */
                body = lustre_msg_buf((*reqp)->rq_repmsg,
                                      DLM_REPLY_REC_OFF, sizeof(*body));
                LASSERT(body != NULL);
                LASSERT((body->valid & OBD_MD_FLID) != 0);

                obj = lmv_obj_grab(obd, &body->fid1);
                if (!obj) {
                        obj = lmv_obj_create(exp, &body->fid1, mea);
                        if (IS_ERR(obj))
                                GOTO(out_free_op_data, rc = (int)PTR_ERR(obj));
                }
                lmv_obj_put(obj);
        }

        EXIT;
out_free_op_data:
        OBD_FREE_PTR(op_data);
        return rc;
}

int lmv_intent_lock(struct obd_export *exp, struct md_op_data *op_data,
                    void *lmm, int lmmsize, struct lookup_intent *it,
                    int flags, struct ptlrpc_request **reqp,
                    ldlm_blocking_callback cb_blocking,
                    int extra_lock_flags)
{
        struct obd_device *obd = exp->exp_obd;
        const char *name = op_data->name;
        int len = op_data->namelen;
        struct lu_fid *pid, *cid;
        int rc;
        ENTRY;

        LASSERT(it != NULL);
        LASSERT(fid_is_sane(&op_data->fid1));
        
        pid = &op_data->fid1;
        
        cid = fid_is_sane(&op_data->fid2) ? &op_data->fid2 : NULL;

        CDEBUG(D_OTHER, "INTENT LOCK '%s' for '%*s' on "DFID"\n",
               LL_IT2STR(it), len, name, PFID(pid));

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        if (it->it_op & IT_LOOKUP)
                rc = lmv_intent_lookup(exp, pid, name, len, lmm,
                                       lmmsize, cid, it, flags, reqp,
                                       cb_blocking, extra_lock_flags);
        else if (it->it_op & IT_OPEN)
                rc = lmv_intent_open(exp, pid, name, len, lmm,
                                     lmmsize, cid, it, flags, reqp,
                                     cb_blocking, extra_lock_flags);
        else if (it->it_op & IT_GETATTR)
                rc = lmv_intent_getattr(exp, pid, name, len, lmm,
                                        lmmsize, cid, it, flags, reqp,
                                        cb_blocking, extra_lock_flags);
        else
                LBUG();
        RETURN(rc);
}

int lmv_revalidate_slaves(struct obd_export *exp, struct ptlrpc_request **reqp,
                          const struct lu_fid *mid, struct lookup_intent *oit,
                          int master_valid, ldlm_blocking_callback cb_blocking,
                          int extra_lock_flags)
{
        struct obd_device *obd = exp->exp_obd;
        struct ptlrpc_request *mreq = *reqp;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lustre_handle master_lockh;
        struct obd_export *tgt_exp;
        struct md_op_data *op_data;
        struct ldlm_lock *lock;
        unsigned long size = 0;
        struct mdt_body *body;
        struct lmv_obj *obj;
        int master_lock_mode;
        int i, rc = 0;
        ENTRY;

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL)
                RETURN(-ENOMEM);
        
        /* we have to loop over the subobjects, check validity and update them
         * from MDSs if needed. it's very useful that we need not to update all
         * the fields. say, common fields (that are equal on all the subojects
         * need not to be update, another fields (i_size, for example) are
         * cached all the time */
        obj = lmv_obj_grab(obd, mid);
        LASSERT(obj != NULL);

        master_lock_mode = 0;

        lmv_obj_lock(obj);

        for (i = 0; i < obj->lo_objcount; i++) {
                struct lu_fid fid = obj->lo_inodes[i].li_fid;
                struct lustre_handle *lockh = NULL;
                struct ptlrpc_request *req = NULL;
                ldlm_blocking_callback cb;
                struct lookup_intent it;
                int master = 0;

                CDEBUG(D_OTHER, "revalidate subobj "DFID"\n",
                       PFID(&fid));

                memset(op_data, 0, sizeof(*op_data));
                memset(&it, 0, sizeof(it));
                it.it_op = IT_GETATTR;

                cb = lmv_blocking_ast;

                if (lu_fid_eq(&fid, &obj->lo_fid)) {
                        if (master_valid) {
                                /* lmv_intent_getattr() already checked
                                 * validness and took the lock */
                                if (mreq) {
                                        /* it even got the reply refresh attrs
                                         * from that reply */
                                        body = lustre_msg_buf(mreq->rq_repmsg,
                                                              DLM_REPLY_REC_OFF, 
                                                              sizeof(*body));
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

                op_data->fid1 = fid;
                op_data->fid2 = fid;

                /* is obj valid? */
                tgt_exp = lmv_get_export(lmv, &fid);
                if (IS_ERR(tgt_exp))
                        GOTO(out_free_op_data, rc = PTR_ERR(tgt_exp));

                rc = md_intent_lock(tgt_exp, op_data, NULL, 0, &it, 0, &req, cb,
                                    extra_lock_flags);
                
                lockh = (struct lustre_handle *) &it.d.lustre.it_lock_handle;
                if (rc > 0 && req == NULL) {
                        /* nice, this slave is valid */
                        LASSERT(req == NULL);
                        CDEBUG(D_OTHER, "cached\n");
                        goto release_lock;
                }

                if (rc < 0) {
                        /* error during revalidation */
                        GOTO(cleanup, rc);
                }
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
                        lock->l_ast_data = lmv_obj_get(obj);
                        LDLM_LOCK_PUT(lock);
                }

                if (*reqp == NULL) {
                        /* this is first reply, we'll use it to return updated
                         * data back to the caller */
                        LASSERT(req);
                        ptlrpc_request_addref(req);
                        *reqp = req;

                }

                body = lustre_msg_buf(req->rq_repmsg,
                                      DLM_REPLY_REC_OFF, sizeof(*body));
                LASSERT(body);

update:
                obj->lo_inodes[i].li_size = body->size;

                CDEBUG(D_OTHER, "fresh: %lu\n",
                       (unsigned long)obj->lo_inodes[i].li_size);

                if (req)
                        ptlrpc_req_finished(req);
release_lock:
                size += obj->lo_inodes[i].li_size;

                if (it.d.lustre.it_lock_mode)
                        ldlm_lock_decref(lockh, it.d.lustre.it_lock_mode);
        }

        if (*reqp) {
                /* some attrs got refreshed, we have reply and it's time to put
                 * fresh attrs to it */
                CDEBUG(D_OTHER, "return refreshed attrs: size = %lu\n",
                       (unsigned long)size);

                body = lustre_msg_buf((*reqp)->rq_repmsg, 
                                      DLM_REPLY_REC_OFF, sizeof(*body));
                LASSERT(body);

                body->size = size;

                if (mreq == NULL) {
                        /*
                         * very important to maintain mds num the same because
                         * of revalidation. mreq == NULL means that caller has
                         * no reply and the only attr we can return is size.
                         */
                        body->valid = OBD_MD_FLSIZE;
                        
#if 0
                        rc = lmv_fld_lookup(lmv, &obj->lo_fid, &body->mds);
                        if (rc)
                                GOTO(cleanup, rc);
#endif
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

        EXIT;
cleanup:
        lmv_obj_unlock(obj);
        lmv_obj_put(obj);
out_free_op_data:
        OBD_FREE_PTR(op_data);
        return rc;
}
