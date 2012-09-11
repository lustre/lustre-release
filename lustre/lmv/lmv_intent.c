/*
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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

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
#include <linux/lustre_intent.h>
#else
#include <liblustre.h>
#endif

#include <obd_support.h>
#include <lustre/lustre_idl.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <lustre_dlm.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include "lmv_internal.h"

int lmv_intent_remote(struct obd_export *exp, void *lmm,
                      int lmmsize, struct lookup_intent *it,
                      int flags, struct ptlrpc_request **reqp,
                      ldlm_blocking_callback cb_blocking,
                      int extra_lock_flags)
{
        struct obd_device      *obd = exp->exp_obd;
        struct lmv_obd         *lmv = &obd->u.lmv;
        struct ptlrpc_request  *req = NULL;
        struct lustre_handle    plock;
        struct md_op_data      *op_data;
        struct lmv_tgt_desc    *tgt;
        struct mdt_body        *body;
        int                     pmode;
        int                     rc = 0;
        ENTRY;

        body = req_capsule_server_get(&(*reqp)->rq_pill, &RMF_MDT_BODY);
        if (body == NULL)
                RETURN(-EPROTO);

        /*
         * Not cross-ref case, just get out of here.
         */
        if (!(body->valid & OBD_MD_MDS))
                RETURN(0);

        /*
         * Unfortunately, we have to lie to MDC/MDS to retrieve
         * attributes llite needs and provideproper locking.
         */
        if (it->it_op & IT_LOOKUP)
                it->it_op = IT_GETATTR;

        /* 
         * We got LOOKUP lock, but we really need attrs. 
         */
        pmode = it->d.lustre.it_lock_mode;
        if (pmode) {
                plock.cookie = it->d.lustre.it_lock_handle;
                it->d.lustre.it_lock_mode = 0;
                it->d.lustre.it_data = NULL;
        }

        LASSERT(fid_is_sane(&body->fid1));

        tgt = lmv_find_target(lmv, &body->fid1);
        if (IS_ERR(tgt))
                GOTO(out, rc = PTR_ERR(tgt));

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL)
                GOTO(out, rc = -ENOMEM);

        op_data->op_fid1 = body->fid1;
        op_data->op_bias = MDS_CROSS_REF;
        
        CDEBUG(D_INODE, 
               "REMOTE_INTENT with fid="DFID" -> mds #%d\n", 
               PFID(&body->fid1), tgt->ltd_idx);

        it->d.lustre.it_disposition &= ~DISP_ENQ_COMPLETE;
        rc = md_intent_lock(tgt->ltd_exp, op_data, lmm, lmmsize, it,
                            flags, &req, cb_blocking, extra_lock_flags);
        if (rc)
                GOTO(out_free_op_data, rc);

        /*
         * LLite needs LOOKUP lock to track dentry revocation in order to
         * maintain dcache consistency. Thus drop UPDATE lock here and put
         * LOOKUP in request.
         */
        if (it->d.lustre.it_lock_mode != 0) {
                ldlm_lock_decref((void *)&it->d.lustre.it_lock_handle,
                                 it->d.lustre.it_lock_mode);
                it->d.lustre.it_lock_mode = 0;
        }
        it->d.lustre.it_lock_handle = plock.cookie;
        it->d.lustre.it_lock_mode = pmode;

        EXIT;
out_free_op_data:
        OBD_FREE_PTR(op_data);
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
int lmv_intent_open(struct obd_export *exp, struct md_op_data *op_data,
                    void *lmm, int lmmsize, struct lookup_intent *it,
                    int flags, struct ptlrpc_request **reqp,
                    ldlm_blocking_callback cb_blocking,
                    int extra_lock_flags)
{
        struct obd_device     *obd = exp->exp_obd;
        struct lu_fid          rpid = op_data->op_fid1;
        struct lmv_obd        *lmv = &obd->u.lmv;
        struct md_op_data     *sop_data;
        struct lmv_stripe_md  *mea;
        struct lmv_tgt_desc   *tgt;
        struct mdt_body       *body;
        struct lmv_object     *obj;
        int                    rc;
        int                    loop = 0;
        int                    sidx;
        ENTRY;

        OBD_ALLOC_PTR(sop_data);
        if (sop_data == NULL)
                RETURN(-ENOMEM);

        /* save op_data fro repeat case */
        *sop_data = *op_data;

repeat:

        ++loop;
        LASSERT(loop <= 2);
        obj = lmv_object_find(obd, &rpid);
        if (obj) {
                /*
                 * Directory is already split, so we have to forward request to
                 * the right MDS.
                 */
                sidx = raw_name2idx(obj->lo_hashtype, obj->lo_objcount,
                                       (char *)op_data->op_name,
                                       op_data->op_namelen);

                rpid = obj->lo_stripes[sidx].ls_fid;

                sop_data->op_mds = obj->lo_stripes[sidx].ls_mds;
                tgt = lmv_get_target(lmv, sop_data->op_mds);
                sop_data->op_bias &= ~MDS_CHECK_SPLIT;
                lmv_object_put(obj);

                CDEBUG(D_INODE,
                       "Choose slave dir ("DFID") -> mds #%d\n", 
                       PFID(&rpid), tgt->ltd_idx);
        } else {
                sop_data->op_bias |= MDS_CHECK_SPLIT;
                tgt = lmv_find_target(lmv, &rpid);
                sop_data->op_mds = tgt->ltd_idx;
        }
        if (IS_ERR(tgt))
                GOTO(out_free_sop_data, rc = PTR_ERR(tgt));

        sop_data->op_fid1 = rpid;

        if (it->it_op & IT_CREAT) {
                /*
                 * For open with IT_CREATE and for IT_CREATE cases allocate new
                 * fid and setup FLD for it.
                 */
                sop_data->op_fid3 = sop_data->op_fid2;
                rc = lmv_fid_alloc(exp, &sop_data->op_fid2, sop_data);
                if (rc)
                        GOTO(out_free_sop_data, rc);

                if (rc == -ERESTART)
                        goto repeat;
                else if (rc)
                        GOTO(out_free_sop_data, rc);
        }

        CDEBUG(D_INODE, 
               "OPEN_INTENT with fid1="DFID", fid2="DFID", name='%s' -> mds #%d\n", 
               PFID(&sop_data->op_fid1), PFID(&sop_data->op_fid2), 
               sop_data->op_name, tgt->ltd_idx);

        rc = md_intent_lock(tgt->ltd_exp, sop_data, lmm, lmmsize, it, flags,
                            reqp, cb_blocking, extra_lock_flags);

        if (rc == -ERESTART) {
                LASSERT(*reqp != NULL);
                DEBUG_REQ(D_WARNING|D_RPCTRACE, *reqp,
                          "Got -ERESTART during open!\n");
                ptlrpc_req_finished(*reqp);
                *reqp = NULL;
                it->d.lustre.it_data = NULL;

                /*
                 * Directory got split. Time to update local object and repeat
                 * the request with proper MDS.
                 */
                LASSERT(lu_fid_eq(&op_data->op_fid1, &rpid));
                rc = lmv_handle_split(exp, &rpid);
                if (rc == 0) {
                        /* We should reallocate child FID. */
                        rc = lmv_allocate_slaves(obd, &rpid, op_data,
                                                 &sop_data->op_fid2);
                        if (rc == 0)
                                goto repeat;
                }
        }

        if (rc != 0)
                GOTO(out_free_sop_data, rc);

        /*
         * Nothing is found, do not access body->fid1 as it is zero and thus
         * pointless.
         */
        if ((it->d.lustre.it_disposition & DISP_LOOKUP_NEG) &&
            !(it->d.lustre.it_disposition & DISP_OPEN_CREATE) &&
            !(it->d.lustre.it_disposition & DISP_OPEN_OPEN))
                GOTO(out_free_sop_data, rc = 0);

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
                CDEBUG(D_INODE, "Can't handle remote %s: dir "DFID"("DFID"):"
                       "%*s: %d\n", LL_IT2STR(it), PFID(&op_data->op_fid2),
                       PFID(&rpid), op_data->op_namelen, op_data->op_name, rc);
                GOTO(out_free_sop_data, rc);
        }

        /* 
         * Caller may use attrs MDS returns on IT_OPEN lock request so, we have
         * to update them for split dir. 
         */
        body = req_capsule_server_get(&(*reqp)->rq_pill, &RMF_MDT_BODY);
        LASSERT(body != NULL);
        
        /* 
         * Could not find object, FID is not present in response. 
         */
        if (!(body->valid & OBD_MD_FLID))
                GOTO(out_free_sop_data, rc = 0);

        obj = lmv_object_find(obd, &body->fid1);
        if (obj == NULL) {
                /* 
                 * XXX: Capability for remote call! 
                 */
                mea = lmv_get_mea(*reqp);
                if (mea != NULL) {
                        obj = lmv_object_create(exp, &body->fid1, mea);
                        if (IS_ERR(obj))
                                GOTO(out_free_sop_data, rc = (int)PTR_ERR(obj));
                }
        }

        if (obj) {
                /* 
                 * This is split dir and we'd want to get attrs. 
                 */
                CDEBUG(D_INODE, "Slave attributes for "DFID"\n",
                       PFID(&body->fid1));

                rc = lmv_revalidate_slaves(exp, reqp, &body->fid1, it, 1,
                                           cb_blocking, extra_lock_flags);
                lmv_object_put(obj);
        }
        EXIT;
out_free_sop_data:
        OBD_FREE_PTR(sop_data);
        return rc;
}

/*
 * Handler for: getattr, lookup and revalidate cases.
 */
int lmv_intent_lookup(struct obd_export *exp, struct md_op_data *op_data,
                      void *lmm, int lmmsize, struct lookup_intent *it,
                      int flags, struct ptlrpc_request **reqp,
                      ldlm_blocking_callback cb_blocking,
                      int extra_lock_flags)
{
        struct obd_device      *obd = exp->exp_obd;
        struct lu_fid           rpid = op_data->op_fid1;
        struct lmv_obd         *lmv = &obd->u.lmv;
        struct lmv_object      *obj = NULL;
        struct md_op_data      *sop_data;
        struct lmv_stripe_md   *mea;
        struct lmv_tgt_desc    *tgt = NULL;
        struct mdt_body        *body;
        int                     sidx;
        int                     loop = 0;
        int                     rc = 0;
        ENTRY;

        OBD_ALLOC_PTR(sop_data);
        if (sop_data == NULL)
                RETURN(-ENOMEM);

        *sop_data = *op_data;

repeat:
        ++loop;
        LASSERT(loop <= 2);

        obj = lmv_object_find(obd, &op_data->op_fid1);
        if (obj && op_data->op_namelen) {
                sidx = raw_name2idx(obj->lo_hashtype,
                                       obj->lo_objcount,
                                       (char *)op_data->op_name,
                                       op_data->op_namelen);
                rpid = obj->lo_stripes[sidx].ls_fid;
                tgt = lmv_get_target(lmv, 
                                     obj->lo_stripes[sidx].ls_mds);
                CDEBUG(D_INODE,
                       "Choose slave dir ("DFID") -> mds #%d\n", 
                       PFID(&rpid), tgt->ltd_idx);
                sop_data->op_bias &= ~MDS_CHECK_SPLIT;
        } else {
                tgt = lmv_find_target(lmv, &op_data->op_fid1);
                sop_data->op_bias |= MDS_CHECK_SPLIT;
        }
        if (obj)
                lmv_object_put(obj);
        
        if (IS_ERR(tgt))
                GOTO(out_free_sop_data, rc = PTR_ERR(tgt));
        
        if (!fid_is_sane(&sop_data->op_fid2))
                fid_zero(&sop_data->op_fid2);
        
        CDEBUG(D_INODE, 
               "LOOKUP_INTENT with fid1="DFID", fid2="DFID
               ", name='%s' -> mds #%d\n",
               PFID(&sop_data->op_fid1), PFID(&sop_data->op_fid2), 
               sop_data->op_name ? sop_data->op_name : "<NULL>", 
               tgt->ltd_idx);

        sop_data->op_bias &= ~MDS_CROSS_REF;
        sop_data->op_fid1 = rpid;

        rc = md_intent_lock(tgt->ltd_exp, sop_data, lmm, lmmsize, it, 
                            flags, reqp, cb_blocking, extra_lock_flags);

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
                LASSERT(obj == NULL);

                obj = lmv_object_create(exp, &rpid, NULL);
                if (IS_ERR(obj))
                        GOTO(out_free_sop_data, rc = PTR_ERR(obj));
                lmv_object_put(obj);
                goto repeat;
        }
        
        if (rc < 0)
                GOTO(out_free_sop_data, rc);

        if (obj && rc > 0) {
                /*
                 * This is split dir. In order to optimize things a bit, we
                 * consider obj valid updating missing parts.
                 */
                CDEBUG(D_INODE,
                       "Revalidate slaves for "DFID", rc %d\n",
                       PFID(&op_data->op_fid1), rc);

                LASSERT(fid_is_sane(&op_data->op_fid2));
                rc = lmv_revalidate_slaves(exp, reqp, &op_data->op_fid1, it, rc,
                                           cb_blocking, extra_lock_flags);
                GOTO(out_free_sop_data, rc);
        }

        if (*reqp == NULL)
                GOTO(out_free_sop_data, rc);

        /*
         * MDS has returned success. Probably name has been resolved in
         * remote inode. Let's check this.
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

        LASSERT(*reqp != NULL);
        LASSERT((*reqp)->rq_repmsg != NULL);
        body = req_capsule_server_get(&(*reqp)->rq_pill, &RMF_MDT_BODY);
        LASSERT(body != NULL);

        /* 
         * Could not find object, FID is not present in response. 
         */
        if (!(body->valid & OBD_MD_FLID))
                GOTO(out_free_sop_data, rc = 0);

        obj = lmv_object_find(obd, &body->fid1);
        if (obj == NULL) {
                /* 
                 * XXX: Remote capability is not handled.
                 */
                mea = lmv_get_mea(*reqp);
                if (mea != NULL) {
                        obj = lmv_object_create(exp, &body->fid1, mea);
                        if (IS_ERR(obj))
                                GOTO(out_free_sop_data, rc = (int)PTR_ERR(obj));
                }
        } else {
                CDEBUG(D_INODE, "Slave attributes for "DFID", rc %d\n",
                       PFID(&body->fid1), rc);

                rc = lmv_revalidate_slaves(exp, reqp, &body->fid1, it, 1,
                                           cb_blocking, extra_lock_flags);
                lmv_object_put(obj);
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
        int                rc;
        ENTRY;

        LASSERT(it != NULL);
        LASSERT(fid_is_sane(&op_data->op_fid1));

        CDEBUG(D_INODE, "INTENT LOCK '%s' for '%*s' on "DFID"\n",
               LL_IT2STR(it), op_data->op_namelen, op_data->op_name,
               PFID(&op_data->op_fid1));

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        if (it->it_op & (IT_LOOKUP | IT_GETATTR | IT_LAYOUT))
                rc = lmv_intent_lookup(exp, op_data, lmm, lmmsize, it,
                                       flags, reqp, cb_blocking,
                                       extra_lock_flags);
        else if (it->it_op & IT_OPEN)
                rc = lmv_intent_open(exp, op_data, lmm, lmmsize, it,
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
        struct obd_device      *obd = exp->exp_obd;
        struct lmv_obd         *lmv = &obd->u.lmv;
        int                     master_lockm = 0;
        struct lustre_handle   *lockh = NULL;
        struct ptlrpc_request  *mreq = *reqp;
        struct lustre_handle    master_lockh = { 0 };
        struct md_op_data      *op_data;
        struct ldlm_lock       *lock;
        unsigned long           size = 0;
        struct mdt_body        *body;
        struct lmv_object      *obj;
        int                     i;
        int                     rc = 0;
        struct lu_fid           fid;
        struct ptlrpc_request  *req;
        ldlm_blocking_callback  cb;
        struct lookup_intent    it;
        struct lmv_tgt_desc    *tgt;
        int                     master;
        ENTRY;

        CDEBUG(D_INODE, "Revalidate master obj "DFID"\n", PFID(mid));

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL)
                RETURN(-ENOMEM);

        /*
         * We have to loop over the subobjects, check validity and update them
         * from MDS if needed. It's very useful that we need not to update all
         * the fields. Say, common fields (that are equal on all the subojects
         * need not to be update, another fields (i_size, for example) are
         * cached all the time.
         */
        obj = lmv_object_find_lock(obd, mid);
	if (obj == NULL) {
		OBD_FREE_PTR(op_data);
		RETURN(-EALREADY);
	}

        for (i = 0; i < obj->lo_objcount; i++) {
                fid = obj->lo_stripes[i].ls_fid;
                master = lu_fid_eq(&fid, &obj->lo_fid);
                cb = master ? cb_blocking : lmv_blocking_ast;

                /*
                 * We need i_size and we would like to check possible cached locks, 
                 * so this is is IT_GETATTR intent.
                 */
                memset(&it, 0, sizeof(it));
                it.it_op = IT_GETATTR;

                if (master && master_valid) {
                        /*
                         * lmv_intent_lookup() already checked
                         * validness and took the lock.
                         */
                        if (mreq != NULL) {
                                body = req_capsule_server_get(&mreq->rq_pill,
                                                              &RMF_MDT_BODY);
                                LASSERT(body != NULL);
                                goto update;
                        }
                        /* 
                         * Take already cached attrs into account.
                         */
                        CDEBUG(D_INODE,
                               "Master "DFID"is locked and cached\n",
                               PFID(mid));
                        goto release_lock;
                }

                /*
                 * Prepare op_data for revalidating. Note that @fid2 shuld be
                 * defined otherwise it will go to server and take new lock
                 * which is what we reall not need here.
                 */
                memset(op_data, 0, sizeof(*op_data));
                op_data->op_bias = MDS_CROSS_REF;
                op_data->op_fid1 = fid;
                op_data->op_fid2 = fid;
                req = NULL;

                tgt = lmv_get_target(lmv, obj->lo_stripes[i].ls_mds);
                if (IS_ERR(tgt))
                        GOTO(cleanup, rc = PTR_ERR(tgt));

                CDEBUG(D_INODE, "Revalidate slave obj "DFID" -> mds #%d\n", 
                       PFID(&fid), tgt->ltd_idx);

                rc = md_intent_lock(tgt->ltd_exp, op_data, NULL, 0, &it, 0, 
                                    &req, cb, extra_lock_flags);

                lockh = (struct lustre_handle *)&it.d.lustre.it_lock_handle;
                if (rc > 0 && req == NULL) {
                        /* 
                         * Nice, this slave is valid.
                         */
                        CDEBUG(D_INODE, "Cached slave "DFID"\n", PFID(&fid));
                        goto release_lock;
                }

                if (rc < 0)
                        GOTO(cleanup, rc);

                if (master) {
                        /* 
                         * Save lock on master to be returned to the caller. 
                         */
                        CDEBUG(D_INODE, "No lock on master "DFID" yet\n", 
                               PFID(mid));
                        memcpy(&master_lockh, lockh, sizeof(master_lockh));
                        master_lockm = it.d.lustre.it_lock_mode;
                        it.d.lustre.it_lock_mode = 0;
                } else {
                        /* 
                         * This is slave. We want to control it. 
                         */
                        lock = ldlm_handle2lock(lockh);
                        LASSERT(lock != NULL);
                        lock->l_ast_data = lmv_object_get(obj);
                        LDLM_LOCK_PUT(lock);
                }

                if (*reqp == NULL) {
                        /*
                         * This is first reply, we'll use it to return updated
                         * data back to the caller.
                         */
                        LASSERT(req != NULL);
                        ptlrpc_request_addref(req);
                        *reqp = req;
                }

                body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
                LASSERT(body != NULL);

update:
                obj->lo_stripes[i].ls_size = body->size;

                CDEBUG(D_INODE, "Fresh size %lu from "DFID"\n",
                       (unsigned long)obj->lo_stripes[i].ls_size, PFID(&fid));

                if (req)
                        ptlrpc_req_finished(req);
release_lock:
                size += obj->lo_stripes[i].ls_size;

                if (it.d.lustre.it_lock_mode && lockh) {
                        ldlm_lock_decref(lockh, it.d.lustre.it_lock_mode);
                        it.d.lustre.it_lock_mode = 0;
                }
        }

        if (*reqp) {
                /*
                 * Some attrs got refreshed, we have reply and it's time to put
                 * fresh attrs to it.
                 */
                CDEBUG(D_INODE, "Return refreshed attrs: size = %lu for "DFID"\n",
                       (unsigned long)size, PFID(mid));

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
                        oit->d.lustre.it_lock_mode = master_lockm;
                }
                rc = 0;
        } else {
                /* 
                 * It seems all the attrs are fresh and we did no request. 
                 */
                CDEBUG(D_INODE, "All the attrs were fresh on "DFID"\n", 
                       PFID(mid));
                if (master_valid == 0)
                        oit->d.lustre.it_lock_mode = master_lockm;
                rc = 1;
        }

        EXIT;
cleanup:
        OBD_FREE_PTR(op_data);
        lmv_object_put_unlock(obj);
        return rc;
}

int lmv_allocate_slaves(struct obd_device *obd, struct lu_fid *pid,
                        struct md_op_data *op, struct lu_fid *fid)
{
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_object       *obj;
        mdsno_t                  mds;
        int                      sidx;
        int                      rc;
        ENTRY;

        obj = lmv_object_find(obd, pid);
        if (obj == NULL)
                RETURN(-EALREADY);

        sidx = raw_name2idx(obj->lo_hashtype, obj->lo_objcount,
                            (char *)op->op_name, op->op_namelen);
        mds = obj->lo_stripes[sidx].ls_mds;
        lmv_object_put(obj);

        rc = __lmv_fid_alloc(lmv, fid, mds);
        if (rc) {
                CERROR("Can't allocate fid, rc %d\n", rc);
                RETURN(rc);
        }

        CDEBUG(D_INODE, "Allocate new fid "DFID" for slave "
               "obj -> mds #%x\n", PFID(fid), mds);

        RETURN(rc);
}
