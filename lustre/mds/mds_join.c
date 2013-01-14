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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mds/mds_join.c
 *
 * Lustre Metadata join handler file
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
#include <obd_support.h>
#include <obd_class.h>
#include <obd.h>
#include <lustre_lib.h>
#include <lustre/lustre_idl.h>
#include <lustre_mds.h>
#include <lustre_dlm.h>
#include <lustre_log.h>
#include <lustre_fsfilt.h>
#include <lustre_lite.h>
#include <obd_lov.h>
#include "mds_internal.h"

struct mdsea_cb_data {
    struct llog_handle     *mc_llh;
    struct lov_mds_md      *mc_lmm;
    struct lov_mds_md_join *mc_lmm_join;
    __u64                   mc_offset;
    __u64                   mc_headfile_sz;
};

static int mdsea_iterate(struct llog_handle *llh_tail, llog_cb_t cb,
                         void *cbdata)
{
    return llog_process(llh_tail, cb, cbdata, NULL);
}

static int mds_insert_join_lmm(struct llog_handle *llh,
                               struct lov_mds_md *lmm,
                               __u64 start, __u64 len,
                               struct lov_mds_md_join *lmmj)
{
        struct llog_rec_hdr rec;
        struct mds_extent_desc *med;
        int sz_med, rc;
        ENTRY;


        sz_med = lov_mds_md_size(le32_to_cpu(lmm->lmm_stripe_count),
                                 LOV_MAGIC);
        sz_med += 2 * sizeof(__u64);
        sz_med = size_round(sz_med);

        rec.lrh_len  = cpu_to_le32(sz_med);
        rec.lrh_type = cpu_to_le32(LLOG_JOIN_REC);

        CDEBUG(D_INFO, "insert extent "LPU64":"LPU64" lmm \n", start, len);

        OBD_ALLOC(med, sz_med);
        if (med == NULL)
                RETURN(-ENOMEM);

        med->med_start = start;
        med->med_len = len;
        memcpy(&med->med_lmm, lmm,
                lov_mds_md_size(le32_to_cpu(lmm->lmm_stripe_count),
                                LOV_MAGIC));

        rc = llog_write_rec(llh, &rec, NULL, 0, med, -1);
        OBD_FREE(med, sz_med);

        if (lmmj) {
                /*modify lmmj for join stripe info*/
                lmmj->lmmj_md.lmm_stripe_count += lmm->lmm_stripe_count;
                lmmj->lmmj_extent_count ++;
        }

        RETURN(rc);
}

static int mdsea_append_extent(struct llog_handle *llh_tail,
                               struct llog_rec_hdr *rec_in_tail,
                               struct mdsea_cb_data *cbdata)
{
        struct mds_extent_desc *med =
                        &((struct llog_array_rec *)rec_in_tail)->lmr_med;
        int rc;
        ENTRY;

        CDEBUG(D_INODE, "insert lmm extent: "LPU64":"LPU64" \n",
               med->med_start, med->med_len);
        rc = mds_insert_join_lmm(cbdata->mc_llh, &med->med_lmm,
                                 med->med_start + cbdata->mc_headfile_sz,
                                 med->med_len, cbdata->mc_lmm_join);
        if (rc) {
                CERROR("error %d insert the lmm \n", rc);
                RETURN(rc);
        }
        RETURN(LLOG_DEL_RECORD);
}

static void mds_init_stripe_join(struct lov_mds_md_join *lmmj,
                                 struct lov_mds_md *lmm,
                                 struct llog_logid  *logid)
{
        lmmj->lmmj_md.lmm_magic = cpu_to_le32(LOV_MAGIC_JOIN);
        lmmj->lmmj_md.lmm_object_id = lmm->lmm_object_id;
        lmmj->lmmj_md.lmm_object_gr = lmm->lmm_object_gr;
        lmmj->lmmj_md.lmm_pattern = lmm->lmm_pattern;
        lmmj->lmmj_md.lmm_stripe_size = lmm->lmm_stripe_size;
        lmmj->lmmj_md.lmm_stripe_count = 0;
        lmmj->lmmj_extent_count = 0;
        lmmj->lmmj_array_id = *logid;
}

static int mdsea_cancel_last_extent(struct llog_handle *llh_tail,
                                    struct llog_rec_hdr *rec_in_tail,
                                    struct mdsea_cb_data *cbdata)
{
        struct mds_extent_desc *med =
                        &((struct llog_array_rec *)rec_in_tail)->lmr_med;

        CDEBUG(D_INODE, "extent: "LPU64":"LPU64" \n",  med->med_start,
               med->med_len);

        LASSERTF(cbdata->mc_offset == med->med_start,
                 "A hole in the extent "LPU64"--"LPU64"\n",
                 cbdata->mc_offset, med->med_start);

        if (med->med_len != -1)
                cbdata->mc_offset = med->med_start + med->med_len;

        if (med->med_start > cbdata->mc_headfile_sz || (med->med_len == -1)) {
                CDEBUG(D_INFO, "del rec offset"LPU64", head size "LPU64" \n",
                       med->med_start, cbdata->mc_headfile_sz);
                if (!cbdata->mc_lmm) {
                        int stripe = le32_to_cpu(med->med_lmm.lmm_stripe_count);
                        OBD_ALLOC(cbdata->mc_lmm,
                                  lov_mds_md_size(stripe, LOV_MAGIC));
                        if (!cbdata->mc_lmm)
                                RETURN(-ENOMEM);
                        memcpy(cbdata->mc_lmm, &med->med_lmm,
                               lov_mds_md_size(stripe, LOV_MAGIC));
                }
                RETURN(LLOG_DEL_RECORD);
        }
        RETURN(0);
}

static int  mds_adjust_last_extent(struct llog_handle *llh_head,
                                   __u64 head_size)
{
        struct mdsea_cb_data  *cbdata;
        int    rc;
        ENTRY;

        OBD_ALLOC_PTR(cbdata);

        if (!cbdata)
                RETURN(-ENOMEM);

        cbdata->mc_headfile_sz = head_size;
        /*Find the last extent and cancel the record in the lmm*/
        rc = mdsea_iterate(llh_head, (llog_cb_t)mdsea_cancel_last_extent,
                           cbdata);

        if (rc) {
                CERROR("can not find the last extent rc=%d\n", rc);
                GOTO(exit, rc);
        }

        LASSERT(cbdata->mc_lmm);

        CDEBUG(D_INODE, "insert lmm extent: "LPU64":"LPU64" \n",
               cbdata->mc_offset, (head_size - cbdata->mc_offset));

        rc = mds_insert_join_lmm(llh_head, cbdata->mc_lmm,
                                 cbdata->mc_offset,
                                 (head_size - cbdata->mc_offset),
                                 NULL);
        if (rc)
                CERROR("error insert the lmm rc %d \n", rc);
exit:
        if (cbdata && cbdata->mc_lmm)
                OBD_FREE(cbdata->mc_lmm,
                         lov_mds_md_size(cbdata->mc_lmm->lmm_stripe_count,
                                         LOV_MAGIC));
        if (cbdata)
                OBD_FREE_PTR(cbdata);

        RETURN(rc);
}

static void mds_finish_join(struct mds_obd *mds, struct ptlrpc_request *req,
                           struct inode *inode, struct lov_mds_md_join *lmmj)
{
        struct mds_body *body = lustre_msg_buf(req->rq_repmsg,DLM_REPLY_REC_OFF,
                                               sizeof(*body));
        int max_cookiesize = lmmj->lmmj_md.lmm_stripe_count *
                                sizeof(struct llog_cookie);
        int max_easize = sizeof(*lmmj);

        CDEBUG(D_INFO, "change the max md size from %d to %lu\n",
               mds->mds_max_mdsize, (unsigned long)sizeof(*lmmj));

        if (mds->mds_max_mdsize < max_easize ||
            mds->mds_max_cookiesize < max_cookiesize) {
                body->max_mdsize = mds->mds_max_mdsize > max_easize ?
                                   mds->mds_max_mdsize : max_easize;
                mds->mds_max_mdsize = body->max_mdsize;
                body->max_cookiesize = mds->mds_max_cookiesize > max_cookiesize?
                                   mds->mds_max_cookiesize : max_cookiesize;
                mds->mds_max_cookiesize = body->max_cookiesize;
                body->valid |= OBD_MD_FLMODEASIZE;
        }

        if (body->valid & OBD_MD_FLMODEASIZE)
                CDEBUG(D_INODE, "updating max_mdsize/max_cookiesize: %d/%d\n",
                       mds->mds_max_mdsize, mds->mds_max_cookiesize);

        mds_pack_inode2body(body, inode);
}

static int mds_join_unlink_tail_inode(struct mds_update_record *rec,
                                      struct ptlrpc_request *req,
                                      struct mds_rec_join *join_rec,
                                      struct lov_mds_md *tail_lmm,
                                      int lmm_size, struct dentry *dchild,
                                      void **handle,struct lustre_handle *lockh)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct inode *tail_inode, *head_inode;
        struct dentry *de_tailparent = NULL, *de_tail = NULL, *de_head = NULL;
        struct lustre_handle dlm_handles[4] = {{0}, {0}, {0}, {0}};
        struct ll_fid head_fid;
        int rc;
        ENTRY;

        if (lockh)
                ldlm_lock_decref(lockh, LCK_EX);

        head_inode = dchild->d_inode;
        ll_pack_fid(&head_fid, head_inode->i_ino, head_inode->i_generation,
                      head_inode->i_mode & S_IFMT);

        rc = mds_get_parents_children_locked(obd, mds, &join_rec->jr_fid,
                                             &de_tailparent, &head_fid,
                                             &de_head, LCK_EX, rec->ur_name,
                                             rec->ur_namelen, &de_tail,
                                             NULL, 0, NULL, dlm_handles,
                                             LCK_EX);
        if (rc)
                GOTO(cleanup, rc);

        *lockh = dlm_handles[1];
        LASSERT(de_tailparent);
        tail_inode = de_tail->d_inode;
        if (tail_inode == NULL) {
                CERROR("tail inode doesn't exist(dir %lu,name %s)!\n",
                       de_tailparent? de_tailparent->d_inode->i_ino : 0,
                       rec->ur_name);
                GOTO(cleanup, rc = -ENOENT);
        }

        if (!S_ISREG(tail_inode->i_mode)) {
                CERROR("tail file is not a regular file (dir %lu, name %s)!\n",
                       de_tailparent? de_tailparent->d_inode->i_ino : 0,
                       rec->ur_name);
                GOTO(cleanup, rc = -EINVAL);
        }

        *handle = fsfilt_start(obd, head_inode, FSFILT_OP_JOIN, NULL);
        if (IS_ERR(*handle)) {
                rc = PTR_ERR(*handle);
                GOTO(cleanup, rc);
        }

        rc = mds_get_md(obd, tail_inode, tail_lmm, &lmm_size, 1, 0,
                        req->rq_export->exp_connect_flags);
        if (rc < 0) /* get md fails */
                GOTO(cleanup, rc);

        LASSERT(le32_to_cpu(tail_lmm->lmm_magic) == LOV_MAGIC_JOIN ||
                le32_to_cpu(tail_lmm->lmm_magic) == LOV_MAGIC);

        LASSERT(de_tailparent);
        LOCK_INODE_MUTEX(de_tailparent->d_inode);
        rc = ll_vfs_unlink(de_tailparent->d_inode, de_tail, mds->mds_vfsmnt);
        UNLOCK_INODE_MUTEX(de_tailparent->d_inode);

        if (rc == 0) {
                CDEBUG(D_INODE, "delete the tail inode %lu/%u \n",
                       tail_inode->i_ino, tail_inode->i_generation);
        }
cleanup:
        if (dlm_handles[2].cookie != 0)
                ldlm_lock_decref(&dlm_handles[2], LCK_EX);

        if (dlm_handles[0].cookie != 0) {
                if (rc)
                        ldlm_lock_decref(&dlm_handles[0], LCK_EX);
                else
                        ptlrpc_save_lock(req, &dlm_handles[0], LCK_EX);
        }
        if (de_tail)
                l_dput(de_tail);

        if (de_tailparent)
                l_dput(de_tailparent);

        if (de_head)
                l_dput(de_head);

        RETURN(rc);
}

int mds_join_file(struct mds_update_record *rec, struct ptlrpc_request *req,
                  struct dentry *de_head, struct lustre_handle *lockh)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct inode *inodes[PTLRPC_NUM_VERSIONS] = { NULL };
        struct inode *head_inode = NULL;
        struct lvfs_run_ctxt saved;
        void *handle = NULL;
        struct lov_mds_md *head_lmm, *tail_lmm;
        struct lov_mds_md_join *head_lmmj = NULL, *tail_lmmj = NULL;
        int lmm_size, rc = 0, cleanup_phase = 0, size;
        struct llog_handle *llh_head = NULL, *llh_tail = NULL;
        struct llog_ctxt *ctxt = NULL;
        struct mds_rec_join *join_rec;
        ENTRY;

        join_rec = lustre_swab_reqbuf(req, DLM_INTENT_REC_OFF + 3,
                                      sizeof(*join_rec),
                                      lustre_swab_mds_rec_join);
        if (join_rec == NULL)
                RETURN (-EFAULT);

        DEBUG_REQ(D_INODE, req,"head "LPU64"/%u, ptail ino "LPU64"/%u, tail %s",
                  rec->ur_fid1->id, rec->ur_fid1->generation,
                  join_rec->jr_fid.id, join_rec->jr_fid.generation,
                  rec->ur_name);

        size = mds->mds_max_mdsize;
        lmm_size = mds->mds_max_mdsize;
        OBD_ALLOC(head_lmm, lmm_size);
        OBD_ALLOC(tail_lmm, lmm_size);
        if (!head_lmm || !tail_lmm)
                GOTO(cleanup, rc = -ENOMEM);

        /* acquire head's dentry */
        LASSERT(de_head);
        head_inode = de_head->d_inode;
        if (head_inode == NULL) {
                CERROR("head inode doesn't exist!\n");
                GOTO(cleanup, rc = -ENOENT);
        }

        /*Unlink tail inode and get the lmm back*/
        rc = mds_join_unlink_tail_inode(rec, req, join_rec, tail_lmm, lmm_size,
                                        de_head, &handle, lockh);
        if (rc) {
                CERROR("unlink tail_inode error %d\n", rc);
                GOTO(cleanup, rc);
        }

        LOCK_INODE_MUTEX(head_inode);
        cleanup_phase = 1;
        rc = mds_get_md(obd, head_inode, head_lmm, &size, 0, 0,
                        req->rq_export->exp_connect_flags);
        if (rc < 0)
                GOTO(cleanup, rc);

        LASSERT(le32_to_cpu(head_lmm->lmm_magic) == LOV_MAGIC_JOIN ||
                le32_to_cpu(head_lmm->lmm_magic) == LOV_MAGIC);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        ctxt = llog_get_context(obd, LLOG_LOVEA_ORIG_CTXT);
        LASSERT(ctxt != NULL);
        cleanup_phase = 2;
        if (le32_to_cpu(head_lmm->lmm_magic) == LOV_MAGIC) { /*simple file */
                struct llog_logid *llog_array;

                rc = llog_create(ctxt, &llh_head, NULL, NULL);
                if (rc) {
                        CERROR("cannot create new log, error = %d\n", rc);
                        GOTO(cleanup, rc);
                }
                cleanup_phase = 3;
                llog_array = &llh_head->lgh_id;
                CDEBUG(D_INFO,"create arrary for %lu with id "LPU64":"LPU64"\n",
                       head_inode->i_ino, llog_array->lgl_oid,
                       llog_array->lgl_ogr);
                rc = llog_init_handle(llh_head, LLOG_F_IS_PLAIN, NULL);
                if (rc)
                        GOTO(cleanup, rc);
                OBD_ALLOC_PTR(head_lmmj);
                if (head_lmmj == NULL)
                        GOTO(cleanup, rc = -ENOMEM);
                mds_init_stripe_join(head_lmmj, head_lmm, llog_array);
                mds_insert_join_lmm(llh_head, head_lmm, 0,join_rec->jr_headsize,
                                    head_lmmj);
        } else { /*head lmm is join file */
                head_lmmj = (struct lov_mds_md_join *)head_lmm;
                /* construct and fill extent llog object */
                rc = llog_create(ctxt, &llh_head,
                                 &head_lmmj->lmmj_array_id, NULL);
                if (rc) {
                        CERROR("cannot open existing log, error = %d\n", rc);
                        GOTO(cleanup, rc);
                }
                cleanup_phase = 3;
                rc = llog_init_handle(llh_head, LLOG_F_IS_PLAIN, NULL);
                if (rc)
                        GOTO(cleanup, rc);
                rc = mds_adjust_last_extent(llh_head, join_rec->jr_headsize);
                if (rc) {
                        CERROR("can't adjust last extent of obj rc=%d\n", rc);
                        GOTO(cleanup, rc);
                }
        }

        if (le32_to_cpu(tail_lmm->lmm_magic) != LOV_MAGIC_JOIN) {
                mds_insert_join_lmm(llh_head, tail_lmm, join_rec->jr_headsize,
                                    -1, head_lmmj);
        } else {
                struct mdsea_cb_data cbdata;
                tail_lmmj = (struct lov_mds_md_join *)tail_lmm;

                rc = llog_create(ctxt,&llh_tail,&tail_lmmj->lmmj_array_id,NULL);
                if (rc) {
                        CERROR("cannot open existing log, error = %d\n", rc);
                        GOTO(cleanup, rc);
                }
                rc = llog_init_handle(llh_tail, LLOG_F_IS_PLAIN, NULL);
                if (rc) {
                        llog_close(llh_tail);
                        GOTO(cleanup, rc);
                }
                cbdata.mc_llh = llh_head;
                cbdata.mc_headfile_sz = join_rec->jr_headsize;
                cbdata.mc_lmm_join = head_lmmj;
                rc = mdsea_iterate(llh_tail, (llog_cb_t)mdsea_append_extent,
                                   &cbdata);
                if (rc) {
                        llog_close(llh_tail);
                        CERROR("can not append extent log error %d \n", rc);
                        GOTO(cleanup, rc);
                }
                rc = llog_destroy(llh_tail);
                if (rc) {
                        llog_close(llh_tail);
                        CERROR("can not destroy log error %d \n", rc);
                        GOTO(cleanup, rc);
                }
                llog_free_handle(llh_tail);
        }
        LASSERT(head_inode);
        CDEBUG(D_INODE, "join finish, set lmm V2 to inode %lu \n",
               head_inode->i_ino);
        fsfilt_set_md(obd, head_inode, handle, head_lmmj,
                      sizeof(struct lov_mds_md_join), "lov");
        mds_finish_join(mds, req, head_inode, head_lmmj);
cleanup:
        inodes[0] = head_inode;
        rc = mds_finish_transno(mds, inodes, handle, req, rc, 0, 0);
        switch(cleanup_phase){
        case 3:
                llog_close(llh_head);
        case 2:
                llog_ctxt_put(ctxt);
                if (head_lmmj && ((void*)head_lmmj != (void*)head_lmm))
                        OBD_FREE_PTR(head_lmmj);

                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        case 1:
                UNLOCK_INODE_MUTEX(head_inode);
        case 0:
                if (tail_lmm != NULL)
                        OBD_FREE(tail_lmm, lmm_size);
                if (head_lmm != NULL)
                        OBD_FREE(head_lmm, lmm_size);
                break;
        default:
                CERROR("invalid cleanup_phase %d\n", cleanup_phase);
                LBUG();
        }
        req->rq_status = rc;
        RETURN(rc);
}
