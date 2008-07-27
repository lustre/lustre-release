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
# ifndef HAVE_VFS_INTENT_PATCHES
# include <linux/lustre_intent.h>
# endif
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
        if (it->d.lustre.it_lock_mode != 0) {
                ldlm_lock_decref((void *)&it->d.lustre.it_lock_handle,
                                 it->d.lustre.it_lock_mode);
                it->d.lustre.it_lock_mode = 0;
        }
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
        struct lustre_handle plock;
        struct md_op_data *op_data;
        struct obd_export *tgt_exp;
        struct mdt_body *body;
        int pmode, rc = 0;
        ENTRY;

        body = req_capsule_server_get(&(*reqp)->rq_pill, &RMF_DLM_REP);
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
                plock.cookie = it->d.lustre.it_lock_handle;
                it->d.lustre.it_lock_mode = 0;
                it->d.lustre.it_data = 0;
        }

        LASSERT(fid_is_sane(&body->fid1));

        it->d.lustre.it_disposition &= ~DISP_ENQ_COMPLETE;

        tgt_exp = lmv_find_export(lmv, &body->fid1);
        if (IS_ERR(tgt_exp))
                GOTO(out, rc = PTR_ERR(tgt_exp));

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL)
                GOTO(out, rc = -ENOMEM);

        op_data->op_fid1 = body->fid1;
        op_data->op_bias = MDS_CROSS_REF;

        rc = md_intent_lock(tgt_exp, op_data, lmm, lmmsize, it, flags,
                            &req, cb_blocking, extra_lock_flags);

        /*
         * llite needs LOOKUP lock to track dentry revocation in order to
         * maintain dcache consistency. Thus drop UPDATE lock here and put
         * LOOKUP in request.
         */
        if (rc == 0) {
                lmv_drop_intent_lock(it);
                it->d.lustre.it_lock_handle = plock.cookie;
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

int lmv_alloc_slave_fids(struct obd_device *obd, struct lu_fid *pid,
                         struct md_op_data *op, struct lu_fid *fid)
{
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lmv_obj *obj;
        mdsno_t mds;
        int mea_idx;
        int rc;
        ENTRY;

        obj = lmv_obj_grab(obd, pid);
        if (!obj) {
                CERROR("Object "DFID" should be split\n",
                       PFID(pid));
                RETURN(0);
        }

        mea_idx = raw_name2idx(obj->lo_hashtype, obj->lo_objcount,
                               (char *)op->op_name, op->op_namelen);
        mds = obj->lo_inodes[mea_idx].li_mds;
        lmv_obj_put(obj);

        rc = __lmv_fid_alloc(lmv, fid, mds);
        if (rc) {
                CERROR("Can't allocate new fid, rc %d\n",
                       rc);
                RETURN(rc);
        }

        CDEBUG(D_INFO, "Allocate new fid "DFID" for split "
               "obj\n", PFID(fid));

        RETURN(rc);
}

/*
 * IT_OPEN is intended to open (and create, possible) an object. Parent (pid)
 * may be split dir.
 */
int lmv_intent_open(struct obd_export *exp, struct md_op_data *op_data,
                    void *lmm, int lmmsize, struct lookup_intent *it,
                    int flags, struct ptlrpc_request **reqp,
                    ldlm_blocking_callback cb_blocking,
                    int extra_lock_flags)
{
        struct obd_device *obd = exp->exp_obd;
        struct lu_fid rpid = op_data->op_fid1;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct md_op_data *sop_data;
        struct obd_export *tgt_exp;
        struct lmv_stripe_md *mea;
        struct mdt_body *body;
        struct lmv_obj *obj;
        int rc, loop = 0;
        ENTRY;

        OBD_ALLOC_PTR(sop_data);
        if (sop_data == NULL)
                RETURN(-ENOMEM);

        /* save op_data fro repeat case */
        *sop_data = *op_data;

repeat:

        ++loop;
        LASSERT(loop <= 2);
        obj = lmv_obj_grab(obd, &rpid);
        if (obj) {
                int mea_idx;

                /*
                 * Directory is already split, so we have to forward request to
                 * the right MDS.
                 */
                mea_idx = raw_name2idx(obj->lo_hashtype, obj->lo_objcount,
                                       (char *)op_data->op_name,
                                       op_data->op_namelen);

                rpid = obj->lo_inodes[mea_idx].li_fid;

                sop_data->op_mds = obj->lo_inodes[mea_idx].li_mds;
                tgt_exp = lmv_get_export(lmv, sop_data->op_mds);
                sop_data->op_bias &= ~MDS_CHECK_SPLIT;
                lmv_obj_put(obj);
                CDEBUG(D_OTHER, "Choose slave dir ("DFID")\n", PFID(&rpid));
        } else {
                struct lmv_tgt_desc *tgt;

                sop_data->op_bias |= MDS_CHECK_SPLIT;
                tgt = lmv_find_target(lmv, &rpid);
                sop_data->op_mds = tgt->ltd_idx;
                tgt_exp = tgt->ltd_exp;
        }
        if (IS_ERR(tgt_exp))
                GOTO(out_free_sop_data, rc = PTR_ERR(tgt_exp));

        sop_data->op_fid1 = rpid;

        if (it->it_op & IT_CREAT) {
                /*
                 * For open with IT_CREATE and for IT_CREATE cases allocate new
                 * fid and setup FLD for it.
                 */
                /* save old child fid for correctly check stale data*/
                sop_data->op_fid3 = sop_data->op_fid2;
                rc = lmv_fid_alloc(exp, &sop_data->op_fid2, sop_data);
                if (rc)
                        GOTO(out_free_sop_data, rc);

                if (rc == -ERESTART)
                        goto repeat;
                else if (rc)
                        GOTO(out_free_sop_data, rc);
        }

        rc = md_intent_lock(tgt_exp, sop_data, lmm, lmmsize, it, flags,
                            reqp, cb_blocking, extra_lock_flags);

        if (rc == -ERESTART) {
                LASSERT(*reqp != NULL);
                DEBUG_REQ(D_WARNING|D_RPCTRACE, *reqp,
                          "Got -ERESTART during open!\n");
                ptlrpc_req_finished(*reqp);
                *reqp = NULL;
                it->d.lustre.it_data = 0;

                /*
                 * Directory got split. Time to update local object and repeat
                 * the request with proper MDS.
                 */
                LASSERT(lu_fid_eq(&op_data->op_fid1, &rpid));
                rc = lmv_handle_split(exp, &rpid);
                if (rc == 0) {
                        /* We should reallocate child FID. */
                        rc = lmv_alloc_slave_fids(obd, &rpid, op_data,
                                                  &sop_data->op_fid2);
                        if (rc == 0)
                                goto repeat;
                }
        }

        if (rc != 0)
                GOTO(out_free_sop_data, rc);

        /*
         * Okay, MDS has returned success. Probably name has been resolved in
         * remote inode.
         */
        rc = lmv_intent_remote(exp, lmm, lmmsize, it, flags, reqp,
                               cb_blocking, extra_lock_flags);
        if (rc != 0) {
                LASSERT(rc < 0);
                /*
                 * This is possible, that some userspace application will try to
                 * open file as directory and we will have -ENOTDIR here. As
                 * this is normal situation, we should not print error here,
                 * only debug info.
                 */
                CDEBUG(D_OTHER, "can't handle remote %s: dir "DFID"("DFID"):"
                       "%*s: %d\n", LL_IT2STR(it), PFID(&op_data->op_fid2),
                       PFID(&rpid), op_data->op_namelen, op_data->op_name, rc);
                GOTO(out_free_sop_data, rc);
        }

        /*
         * Nothing is found, do not access body->fid1 as it is zero and thus
         * pointless.
         */
        if ((it->d.lustre.it_disposition & DISP_LOOKUP_NEG) &&
            !(it->d.lustre.it_disposition & DISP_OPEN_CREATE) &&
            !(it->d.lustre.it_disposition & DISP_OPEN_OPEN))
                GOTO(out_free_sop_data, rc = 0);

        /* caller may use attrs MDS returns on IT_OPEN lock request so, we have
         * to update them for split dir */
        body = req_capsule_server_get(&(*reqp)->rq_pill, &RMF_DLM_REP);
        LASSERT(body != NULL);

        /* could not find object, FID is not present in response. */
        if (!(body->valid & OBD_MD_FLID))
                GOTO(out_free_sop_data, rc = 0);

        obj = lmv_obj_grab(obd, &body->fid1);
        if (!obj && (mea = lmv_get_mea(*reqp))) {
                /* FIXME: capability for remote! */
                /* wow! this is split dir, we'd like to handle it */
                obj = lmv_obj_create(exp, &body->fid1, mea);
                if (IS_ERR(obj))
                        GOTO(out_free_sop_data, rc = (int)PTR_ERR(obj));
        }

        if (obj) {
                /* This is split dir and we'd want to get attrs. */
                CDEBUG(D_OTHER, "attrs from slaves for "DFID"\n",
                       PFID(&body->fid1));

                rc = lmv_revalidate_slaves(exp, reqp, &body->fid1, it, 1,
                                           cb_blocking, extra_lock_flags);
        } else if (S_ISDIR(body->mode)) {
                CDEBUG(D_OTHER, "object "DFID" has not lmv obj?\n",
                       PFID(&body->fid1));
        }

        if (obj)
                lmv_obj_put(obj);

        EXIT;
out_free_sop_data:
        OBD_FREE_PTR(sop_data);
        return rc;
}

int lmv_intent_getattr(struct obd_export *exp, struct md_op_data *op_data,
                       void *lmm, int lmmsize, struct lookup_intent *it,
                       int flags, struct ptlrpc_request **reqp,
                       ldlm_blocking_callback cb_blocking,
                       int extra_lock_flags)
{
        struct lmv_obj *obj = NULL, *obj2 = NULL;
        struct obd_device *obd = exp->exp_obd;
        struct lu_fid rpid = op_data->op_fid1;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct md_op_data *sop_data;
        struct lmv_stripe_md *mea;
        struct mdt_body *body;
        mdsno_t mds;
        int rc = 0;
        ENTRY;

        OBD_ALLOC_PTR(sop_data);
        if (sop_data == NULL)
                RETURN(-ENOMEM);

        /* save op_data fro repeat case */
        *sop_data = *op_data;

        if (fid_is_sane(&op_data->op_fid2)) {
                /*
                 * Caller wants to revalidate attrs of obj we have to revalidate
                 * slaves if requested object is split directory.
                 */
                CDEBUG(D_OTHER, "revalidate attrs for "DFID"\n",
                       PFID(&op_data->op_fid2));

                rc = lmv_fld_lookup(lmv, &op_data->op_fid2, &mds);
                if (rc)
                        GOTO(out_free_sop_data, rc);
#if 0
                /*
                 * In fact, we do not need this with current intent_lock(), but
                 * it may change some day.
                 */
                obj = lmv_obj_grab(obd, &op_data->op_fid2);
                if (obj) {
                        if (!lu_fid_eq(&op_data->op_fid1, &op_data->op_fid2)){
                                rpid = obj->lo_inodes[mds].li_fid;
                                mds = obj->lo_inodes[mds].li_mds;
                        }
                        lmv_obj_put(obj);
                }
#endif
        } else {
                CDEBUG(D_OTHER, "INTENT getattr for %*s on "DFID"\n",
                       op_data->op_namelen, op_data->op_name,
                       PFID(&op_data->op_fid1));

                rc = lmv_fld_lookup(lmv, &op_data->op_fid1, &mds);
                if (rc)
                        GOTO(out_free_sop_data, rc);
                obj = lmv_obj_grab(obd, &op_data->op_fid1);
                if (obj && op_data->op_namelen) {
                        int mea_idx;

                        /* directory is already split. calculate mds */
                        mea_idx = raw_name2idx(obj->lo_hashtype, obj->lo_objcount,
                                               (char *)op_data->op_name,
                                               op_data->op_namelen);
                        rpid = obj->lo_inodes[mea_idx].li_fid;
                        mds = obj->lo_inodes[mea_idx].li_mds;
                        sop_data->op_bias &= ~MDS_CHECK_SPLIT;
                        lmv_obj_put(obj);

                        CDEBUG(D_OTHER, "forward to MDS #"LPU64" (slave "DFID")\n",
                               mds, PFID(&rpid));
                } else {
                        rc = lmv_fld_lookup(lmv, &op_data->op_fid1, &mds);
                        if (rc)
                                GOTO(out_free_sop_data, rc);
                        sop_data->op_bias |= MDS_CHECK_SPLIT;
                }
        }

        sop_data->op_fid1 = rpid;

        rc = md_intent_lock(lmv->tgts[mds].ltd_exp, sop_data, lmm,
                            lmmsize, it, flags, reqp, cb_blocking,
                            extra_lock_flags);

        LASSERTF(rc != -ERESTART, "GETATTR: Got unhandled -ERESTART!\n");
        if (rc < 0)
                GOTO(out_free_sop_data, rc);

        if (obj && rc > 0) {
                /*
                 * This is split dir. In order to optimize things a bit, we
                 * consider obj valid updating missing parts.

                 * FIXME: do we need to return any lock here? It would be fine
                 * if we don't. This means that nobody should use UPDATE lock to
                 * notify about object * removal.
                 */
                CDEBUG(D_OTHER,
                       "revalidate slaves for "DFID", rc %d\n",
                       PFID(&op_data->op_fid2), rc);

                LASSERT(fid_is_sane(&op_data->op_fid2));
                rc = lmv_revalidate_slaves(exp, reqp, &op_data->op_fid2, it, rc,
                                           cb_blocking, extra_lock_flags);
                GOTO(out_free_sop_data, rc);
        }

        if (*reqp == NULL)
                GOTO(out_free_sop_data, rc);

        /*
         * okay, MDS has returned success. Probably name has been resolved in
         * remote inode.
         */
        rc = lmv_intent_remote(exp, lmm, lmmsize, it, flags,
                               reqp, cb_blocking, extra_lock_flags);
        if (rc < 0)
                GOTO(out_free_sop_data, rc);

        /*
         * Nothing is found, do not access body->fid1 as it is zero and thus
         * pointless.
         */
        if (it->d.lustre.it_disposition & DISP_LOOKUP_NEG)
                GOTO(out_free_sop_data, rc = 0);

        LASSERT(*reqp);
        LASSERT((*reqp)->rq_repmsg);
        body = req_capsule_server_get(&(*reqp)->rq_pill, &RMF_MDT_BODY);
        LASSERT(body != NULL);

        /* could not find object, FID is not present in response. */
        if (!(body->valid & OBD_MD_FLID))
                GOTO(out_free_sop_data, rc = 0);

        obj2 = lmv_obj_grab(obd, &body->fid1);

        if (!obj2 && (mea = lmv_get_mea(*reqp))) {

                /* FIXME remote capability! */
                /* wow! this is split dir, we'd like to handle it. */
                obj2 = lmv_obj_create(exp, &body->fid1, mea);
                if (IS_ERR(obj2))
                        GOTO(out_free_sop_data, rc = (int)PTR_ERR(obj2));
        }

        if (obj2) {
                /* this is split dir and we'd want to get attrs */
                CDEBUG(D_OTHER, "attrs from slaves for "DFID", rc %d\n",
                       PFID(&body->fid1), rc);

                rc = lmv_revalidate_slaves(exp, reqp, &body->fid1, it, 1,
                                           cb_blocking, extra_lock_flags);
                lmv_obj_put(obj2);
        }

        EXIT;
out_free_sop_data:
        OBD_FREE_PTR(sop_data);
        return rc;
}

/* this is not used currently */
int lmv_lookup_slaves(struct obd_export *exp, struct ptlrpc_request **reqp)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lustre_handle *lockh;
        struct md_op_data *op_data;
        struct ldlm_lock *lock;
        struct mdt_body *body2;
        struct mdt_body *body;
        struct lmv_obj *obj;
        int i, rc = 0;
        ENTRY;

        LASSERT(reqp);
        LASSERT(*reqp);

        /*
         * Master is locked. we'd like to take locks on slaves and update
         * attributes to be returned from the slaves it's important that lookup
         * is called in two cases:

         *  - for first time (dcache has no such a resolving yet).  -
         *  ->d_revalidate() returned false.

         * Last case possible only if all the objs (master and all slaves aren't
         * valid.
         */

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL)
                RETURN(-ENOMEM);

        body = req_capsule_server_get(&(*reqp)->rq_pill, &RMF_MDT_BODY);
        LASSERT(body != NULL);

        LASSERT((body->valid & OBD_MD_FLID) != 0);
        obj = lmv_obj_grab(obd, &body->fid1);
        LASSERT(obj != NULL);

        CDEBUG(D_OTHER, "lookup slaves for "DFID"\n",
               PFID(&body->fid1));

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
                op_data->op_fid1 = fid;
                op_data->op_fid2 = fid;
                op_data->op_bias = MDS_CROSS_REF;

                tgt_exp = lmv_get_export(lmv, obj->lo_inodes[i].li_mds);
                if (IS_ERR(tgt_exp))
                        GOTO(cleanup, rc = PTR_ERR(tgt_exp));

                rc = md_intent_lock(tgt_exp, op_data, NULL, 0, &it, 0,
                                    &req, lmv_blocking_ast, 0);

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

                body2 = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
                LASSERT(body2 != NULL);

                obj->lo_inodes[i].li_size = body2->size;

                CDEBUG(D_OTHER, "fresh: %lu\n",
                       (unsigned long)obj->lo_inodes[i].li_size);

                LDLM_LOCK_PUT(lock);

                if (req)
                        ptlrpc_req_finished(req);
release_lock:
                lmv_update_body(body, obj->lo_inodes + i);

                if (it.d.lustre.it_lock_mode) {
                        ldlm_lock_decref(lockh, it.d.lustre.it_lock_mode);
                        it.d.lustre.it_lock_mode = 0;
                }
        }

        EXIT;
cleanup:
        lmv_obj_unlock(obj);
        lmv_obj_put(obj);
        OBD_FREE_PTR(op_data);
        return rc;
}

int lmv_intent_lookup(struct obd_export *exp, struct md_op_data *op_data,
                      void *lmm, int lmmsize, struct lookup_intent *it,
                      int flags, struct ptlrpc_request **reqp,
                      ldlm_blocking_callback cb_blocking,
                      int extra_lock_flags)
{
        struct obd_device *obd = exp->exp_obd;
        struct lu_fid rpid = op_data->op_fid1;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct md_op_data *sop_data;
        struct lmv_stripe_md *mea;
        struct mdt_body *body;
        struct lmv_obj *obj;
        int rc, loop = 0;
        int mea_idx;
        mdsno_t mds;
        ENTRY;

        OBD_ALLOC_PTR(sop_data);
        if (sop_data == NULL)
                RETURN(-ENOMEM);

        /* save op_data fro repeat case */
        *sop_data = *op_data;

        /*
         * IT_LOOKUP is intended to produce name -> fid resolving (let's call
         * this lookup below) or to confirm requested resolving is still valid
         * (let's call this revalidation) fid_is_sane(&sop_data->op_fid2) specifies
         * revalidation.
         */
        if (fid_is_sane(&op_data->op_fid2)) {
                /*
                 * This is revalidate: we have to check is LOOKUP lock still
                 * valid for given fid. Very important part is that we have to
                 * choose right mds because namespace is per mds.
                 */
                rpid = op_data->op_fid1;
                obj = lmv_obj_grab(obd, &rpid);
                if (obj) {
                        mea_idx = raw_name2idx(obj->lo_hashtype,
                                               obj->lo_objcount,
                                               (char *)op_data->op_name,
                                               op_data->op_namelen);
                        rpid = obj->lo_inodes[mea_idx].li_fid;
                        mds = obj->lo_inodes[mea_idx].li_mds;
                        sop_data->op_bias &= ~MDS_CHECK_SPLIT;
                        lmv_obj_put(obj);
                } else {
                        rc = lmv_fld_lookup(lmv, &rpid, &mds);
                        if (rc)
                                GOTO(out_free_sop_data, rc);
                        sop_data->op_bias |= MDS_CHECK_SPLIT;
                }

                CDEBUG(D_OTHER, "revalidate lookup for "DFID" to #"LPU64" MDS\n",
                       PFID(&op_data->op_fid2), mds);
        } else {
repeat:
                ++loop;
                LASSERT(loop <= 2);

                /*
                 * This is lookup. During lookup we have to update all the
                 * attributes, because returned values will be put in struct
                 * inode.
                 */
                obj = lmv_obj_grab(obd, &op_data->op_fid1);
                if (obj) {
                        if (op_data->op_namelen) {
                                /* directory is already split. calculate mds */
                                mea_idx = raw_name2idx(obj->lo_hashtype,
                                                       obj->lo_objcount,
                                                       (char *)op_data->op_name,
                                                       op_data->op_namelen);
                                rpid = obj->lo_inodes[mea_idx].li_fid;
                                mds = obj->lo_inodes[mea_idx].li_mds;
                        }
                        sop_data->op_bias &= ~MDS_CHECK_SPLIT;
                        lmv_obj_put(obj);
                } else {
                        rc = lmv_fld_lookup(lmv, &op_data->op_fid1, &mds);
                        if (rc)
                                GOTO(out_free_sop_data, rc);
                        sop_data->op_bias |= MDS_CHECK_SPLIT;
                }
                fid_zero(&sop_data->op_fid2);
        }

        sop_data->op_bias &= ~MDS_CROSS_REF;
        sop_data->op_fid1 = rpid;

        rc = md_intent_lock(lmv->tgts[mds].ltd_exp, sop_data, lmm, lmmsize,
                            it, flags, reqp, cb_blocking, extra_lock_flags);
        if (rc > 0) {
                LASSERT(fid_is_sane(&op_data->op_fid2));
                /*
                 * Very interesting. it seems object is still valid but for some
                 * reason llite calls lookup, not revalidate.
                 */
                CDEBUG(D_OTHER, "lookup for "DFID" and data should be uptodate\n",
                       PFID(&rpid));
                LASSERT(*reqp == NULL);
                GOTO(out_free_sop_data, rc);
        }

        if (rc == 0 && *reqp == NULL) {
                /* once again, we're asked for lookup, not revalidate */
                CDEBUG(D_OTHER, "lookup for "DFID" and data should be uptodate\n",
                       PFID(&rpid));
                GOTO(out_free_sop_data, rc);
        }

        if (rc == -ERESTART) {
                LASSERT(*reqp != NULL);
                DEBUG_REQ(D_WARNING|D_RPCTRACE, *reqp,
                          "Got -ERESTART during lookup!\n");
                ptlrpc_req_finished(*reqp);
                *reqp = NULL;
                it->d.lustre.it_data = 0;
                /*
                 * Directory got split since last update. This shouldn't be
                 * because splitting causes lock revocation, so revalidate had
                 * to fail and lookup on dir had to return mea.
                 */
                CWARN("we haven't knew about directory splitting!\n");
                LASSERT(obj == NULL);

                obj = lmv_obj_create(exp, &rpid, NULL);
                if (IS_ERR(obj))
                        GOTO(out_free_sop_data, rc = PTR_ERR(obj));
                lmv_obj_put(obj);
                goto repeat;
        }

        if (rc < 0)
                GOTO(out_free_sop_data, rc);

        /*
         * Okay, MDS has returned success. Probably name has been resolved in
         * remote inode.
         */
        rc = lmv_intent_remote(exp, lmm, lmmsize, it, flags, reqp,
                               cb_blocking, extra_lock_flags);

        if (rc == 0 && (mea = lmv_get_mea(*reqp))) {
                /* Wow! This is split dir, we'd like to handle it. */
                body = req_capsule_server_get(&(*reqp)->rq_pill, &RMF_MDT_BODY);
                LASSERT(body != NULL);
                LASSERT((body->valid & OBD_MD_FLID) != 0);

                obj = lmv_obj_grab(obd, &body->fid1);
                if (!obj) {
                        obj = lmv_obj_create(exp, &body->fid1, mea);
                        if (IS_ERR(obj))
                                GOTO(out_free_sop_data, rc = (int)PTR_ERR(obj));
                }
                lmv_obj_put(obj);
        }

        EXIT;
out_free_sop_data:
        OBD_FREE_PTR(sop_data);
        return rc;
}

int lmv_intent_lock(struct obd_export *exp, struct md_op_data *op_data,
                    void *lmm, int lmmsize, struct lookup_intent *it,
                    int flags, struct ptlrpc_request **reqp,
                    ldlm_blocking_callback cb_blocking,
                    int extra_lock_flags)
{
        struct obd_device *obd = exp->exp_obd;
        int rc;
        ENTRY;

        LASSERT(it != NULL);
        LASSERT(fid_is_sane(&op_data->op_fid1));

        CDEBUG(D_OTHER, "INTENT LOCK '%s' for '%*s' on "DFID"\n",
               LL_IT2STR(it), op_data->op_namelen, op_data->op_name,
               PFID(&op_data->op_fid1));

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        if (it->it_op & IT_LOOKUP)
                rc = lmv_intent_lookup(exp, op_data, lmm, lmmsize, it,
                                       flags, reqp, cb_blocking,
                                       extra_lock_flags);
        else if (it->it_op & IT_OPEN)
                rc = lmv_intent_open(exp, op_data, lmm, lmmsize, it,
                                     flags, reqp, cb_blocking,
                                     extra_lock_flags);
        else if (it->it_op & IT_GETATTR)
                rc = lmv_intent_getattr(exp, op_data,lmm, lmmsize, it,
                                        flags, reqp, cb_blocking,
                                        extra_lock_flags);
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

        /*
         * We have to loop over the subobjects, check validity and update them
         * from MDSs if needed. it's very useful that we need not to update all
         * the fields. say, common fields (that are equal on all the subojects
         * need not to be update, another fields (i_size, for example) are
         * cached all the time.
         */
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
                                /*
                                 * lmv_intent_getattr() already checked
                                 * validness and took the lock.
                                 */
                                if (mreq) {
                                        /*
                                         * It even got the reply refresh attrs
                                         * from that reply.
                                         */
                                        body = req_capsule_server_get(
                                                                &mreq->rq_pill,
                                                                &RMF_MDT_BODY);
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

                op_data->op_fid1 = fid;
                op_data->op_fid2 = fid;
                op_data->op_bias = MDS_CROSS_REF;

                /* Is obj valid? */
                tgt_exp = lmv_get_export(lmv, obj->lo_inodes[i].li_mds);
                if (IS_ERR(tgt_exp))
                        GOTO(cleanup, rc = PTR_ERR(tgt_exp));

                rc = md_intent_lock(tgt_exp, op_data, NULL, 0, &it, 0, &req, cb,
                                    extra_lock_flags);

                lockh = (struct lustre_handle *)&it.d.lustre.it_lock_handle;
                if (rc > 0 && req == NULL) {
                        /* Nice, this slave is valid */
                        LASSERT(req == NULL);
                        CDEBUG(D_OTHER, "cached\n");
                        goto release_lock;
                }

                if (rc < 0)
                        GOTO(cleanup, rc);

                if (master) {
                        LASSERT(master_valid == 0);
                        /* Save lock on master to be returned to the caller. */
                        CDEBUG(D_OTHER, "no lock on master yet\n");
                        memcpy(&master_lockh, lockh, sizeof(master_lockh));
                        master_lock_mode = it.d.lustre.it_lock_mode;
                        it.d.lustre.it_lock_mode = 0;
                } else {
                        /* This is slave. We want to control it. */
                        lock = ldlm_handle2lock(lockh);
                        LASSERT(lock != NULL);
                        lock->l_ast_data = lmv_obj_get(obj);
                        LDLM_LOCK_PUT(lock);
                }

                if (*reqp == NULL) {
                        /*
                         * This is first reply, we'll use it to return updated
                         * data back to the caller.
                         */
                        LASSERT(req);
                        ptlrpc_request_addref(req);
                        *reqp = req;
                }

                body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
                LASSERT(body != NULL);

update:
                obj->lo_inodes[i].li_size = body->size;

                CDEBUG(D_OTHER, "fresh: %lu\n",
                       (unsigned long)obj->lo_inodes[i].li_size);

                if (req)
                        ptlrpc_req_finished(req);
release_lock:
                size += obj->lo_inodes[i].li_size;

                if (it.d.lustre.it_lock_mode) {
                        ldlm_lock_decref(lockh, it.d.lustre.it_lock_mode);
                        it.d.lustre.it_lock_mode = 0;
                }
        }

        if (*reqp) {
                /*
                 * Some attrs got refreshed, we have reply and it's time to put
                 * fresh attrs to it.
                 */
                CDEBUG(D_OTHER, "return refreshed attrs: size = %lu\n",
                       (unsigned long)size);

                body = req_capsule_server_get(&(*reqp)->rq_pill, &RMF_MDT_BODY);
                LASSERT(body != NULL);

                body->size = size;

                if (mreq == NULL) {
                        /*
                         * Very important to maintain mds num the same because
                         * of revalidation. mreq == NULL means that caller has
                         * no reply and the only attr we can return is size.
                         */
                        body->valid = OBD_MD_FLSIZE;
                }
                if (master_valid == 0) {
                        oit->d.lustre.it_lock_handle = master_lockh.cookie;
                        oit->d.lustre.it_lock_mode = master_lock_mode;
                }
                rc = 0;
        } else {
                /* It seems all the attrs are fresh and we did no request */
                CDEBUG(D_OTHER, "all the attrs were fresh\n");
                if (master_valid == 0)
                        oit->d.lustre.it_lock_mode = master_lock_mode;
                rc = 1;
        }

        EXIT;
cleanup:
        OBD_FREE_PTR(op_data);
        lmv_obj_unlock(obj);
        lmv_obj_put(obj);
        return rc;
}
