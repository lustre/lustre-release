/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mdt/mdt_reint.c
 *  Lustre Metadata Target (mdt) reintegration routines
 *
 *  Copyright (C) 2002-2006 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Huang Hua <huanghua@clusterfs.com>
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
#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"


static int mdt_md_create(struct mdt_thread_info *info)
{
        struct mdt_device      *mdt = info->mti_mdt;
        struct mdt_object      *parent;
        struct mdt_object      *child;
        struct mdt_lock_handle *lh;
        struct mdt_body        *repbody;
        struct md_attr         *ma = &info->mti_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        int rc;
        ENTRY;

        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);

        lh = &info->mti_lh[MDT_LH_PARENT];
        lh->mlh_mode = LCK_EX;

        parent = mdt_object_find_lock(info, rr->rr_fid1,
                                      lh, MDS_INODELOCK_UPDATE);
        if (IS_ERR(parent))
                RETURN(PTR_ERR(parent));

        child = mdt_object_find(info->mti_ctxt, mdt, rr->rr_fid2);
        if (!IS_ERR(child)) {
                struct md_object *next = mdt_object_child(parent);

                ma->ma_need = MA_INODE;
                mdt_fail_write(info->mti_ctxt, info->mti_mdt->mdt_bottom,
                               OBD_FAIL_MDS_REINT_CREATE_WRITE);

                rc = mdo_create(info->mti_ctxt, next, rr->rr_name,
                                mdt_object_child(child), &info->mti_spec,
                                ma);
                if (rc == 0) {
                        /* return fid & attr to client. */
                        if (ma->ma_valid & MA_INODE)
                                mdt_pack_attr2body(repbody, &ma->ma_attr, 
                                                   mdt_object_fid(child));
                }
                mdt_object_put(info->mti_ctxt, child);
        } else
                rc = PTR_ERR(child);
        mdt_object_unlock_put(info, parent, lh, rc);
        RETURN(rc);
}

/* partial request to create object only */
static int mdt_md_mkobj(struct mdt_thread_info *info)
{
        struct mdt_device      *mdt = info->mti_mdt;
        struct mdt_object      *o;
        struct mdt_body        *repbody;
        struct md_attr         *ma = &info->mti_attr;
        int rc;
        ENTRY;

        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);

        o = mdt_object_find(info->mti_ctxt, mdt, info->mti_rr.rr_fid2);
        if (!IS_ERR(o)) {
                struct md_object *next = mdt_object_child(o);

                ma->ma_need = MA_INODE;
                rc = mo_object_create(info->mti_ctxt, next,
                                      &info->mti_spec, ma);
                if (rc == 0) {
                        /* return fid & attr to client. */
                        if (ma->ma_valid & MA_INODE)
                                mdt_pack_attr2body(repbody, &ma->ma_attr,
                                                   mdt_object_fid(o));
                }
                mdt_object_put(info->mti_ctxt, o);
        } else
                rc = PTR_ERR(o);

        RETURN(rc);
}

/* In the raw-setattr case, we lock the child inode.
 * In the write-back case or if being called from open,
 *               the client holds a lock already.
 * We use the ATTR_FROM_OPEN (translated into MRF_SETATTR_LOCKED by
 * mdt_setattr_unpack()) flag to tell these cases apart. */
int mdt_attr_set(struct mdt_thread_info *info, struct mdt_object *mo, int flags)
{
        struct md_attr          *ma = &info->mti_attr;
        struct mdt_lock_handle  *lh;
        int som_update = 0;
        int rc;
        ENTRY;

        if (info->mti_epoch)
                som_update = (info->mti_epoch->flags & MF_SOM_CHANGE);

        /* Try to avoid object_lock if another epoch has been started
         * already. */
        if (som_update && (info->mti_epoch->ioepoch != mo->mot_ioepoch))
                RETURN(0);
        
        lh = &info->mti_lh[MDT_LH_PARENT];
        lh->mlh_mode = LCK_EX;

        if (!(flags & MRF_SETATTR_LOCKED)) {
                __u64 lockpart = MDS_INODELOCK_UPDATE;
                if (ma->ma_attr.la_valid & (LA_MODE|LA_UID|LA_GID))
                        lockpart |= MDS_INODELOCK_LOOKUP;

                rc = mdt_object_lock(info, mo, lh, lockpart);
                if (rc != 0)
                        GOTO(out, rc);
        }

        /* Setattrs are syncronized through dlm lock taken above. If another
         * epoch started, its attributes may be already flushed on disk,
         * skip setattr. */
        if (som_update && (info->mti_epoch->ioepoch != mo->mot_ioepoch))
                GOTO(out, rc = 0);
                
        if (lu_object_assert_not_exists(&mo->mot_obj.mo_lu))
                GOTO(out, rc = -ENOENT);

        /* all attrs are packed into mti_attr in unpack_setattr */
        mdt_fail_write(info->mti_ctxt, info->mti_mdt->mdt_bottom,
                       OBD_FAIL_MDS_REINT_SETATTR_WRITE);

        /* all attrs are packed into mti_attr in unpack_setattr */
        rc = mo_attr_set(info->mti_ctxt, mdt_object_child(mo), ma);
        if (rc != 0)
                GOTO(out, rc);

        /* Re-enable SIZEONMDS. */
        if (som_update) {
                CDEBUG(D_INODE, "Closing epoch "LPU64" on "DFID". Count %d\n",
                       mo->mot_ioepoch, PFID(mdt_object_fid(mo)),
                       mo->mot_epochcount);
 
                mdt_sizeonmds_enable(info, mo);
        }
        
        EXIT;
out:
        mdt_object_unlock(info, mo, lh, rc);
        return(rc);
}

static int mdt_reint_setattr(struct mdt_thread_info *info)
{
        struct md_attr          *ma = &info->mti_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct mdt_export_data  *med = &req->rq_export->exp_mdt_data;
        struct mdt_file_data    *mfd;
        struct mdt_object       *mo;
        struct md_object        *next;
        struct mdt_body         *repbody;
        int                      rc;

        ENTRY;

        DEBUG_REQ(D_INODE, req, "setattr "DFID" %x", PFID(rr->rr_fid1),
                  (unsigned int)ma->ma_attr.la_valid);

        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        mo = mdt_object_find(info->mti_ctxt, info->mti_mdt, rr->rr_fid1);
        if (IS_ERR(mo))
                RETURN(rc = PTR_ERR(mo));

        if (info->mti_epoch && (info->mti_epoch->flags & MF_EPOCH_OPEN)) {
                /* Truncate case. */
                rc = mdt_write_get(info->mti_mdt, mo);
                if (rc)
                        GOTO(out, rc);

                mfd = mdt_mfd_new();
                if (mfd == NULL)
                        GOTO(out, rc = -ENOMEM);
                
                /* FIXME: in recovery, need to pass old epoch here */
                mdt_epoch_open(info, mo, 0);
                repbody->ioepoch = mo->mot_ioepoch;

                mdt_object_get(info->mti_ctxt, mo);
                mfd->mfd_mode = FMODE_EPOCHLCK;
                mfd->mfd_object = mo;
                mfd->mfd_xid = req->rq_xid;

                spin_lock(&med->med_open_lock);
                list_add(&mfd->mfd_list, &med->med_open_head);
                spin_unlock(&med->med_open_lock);
                repbody->handle.cookie = mfd->mfd_handle.h_cookie;
        }

        rc = mdt_attr_set(info, mo, rr->rr_flags);
        if (rc)
                GOTO(out, rc);

        if (info->mti_epoch && (info->mti_epoch->flags & MF_SOM_CHANGE)) {
                LASSERT(info->mti_epoch);

                /* Size-on-MDS Update. Find and free mfd. */
                spin_lock(&med->med_open_lock);
                mfd = mdt_handle2mfd(&(info->mti_epoch->handle));
                if (mfd == NULL) {
                        spin_unlock(&med->med_open_lock);
                        CDEBUG(D_INODE, "no handle for file close: "
                               "fid = "DFID": cookie = "LPX64"\n", 
                               PFID(info->mti_rr.rr_fid1),
                               info->mti_epoch->handle.cookie);
                        GOTO(out, rc = -ESTALE);
                }

                LASSERT(mfd->mfd_mode == FMODE_SOM);
                LASSERT(ma->ma_attr.la_valid & LA_SIZE);
                LASSERT(!(info->mti_epoch->flags & MF_EPOCH_CLOSE));

                class_handle_unhash(&mfd->mfd_handle);
                list_del_init(&mfd->mfd_list);
                spin_unlock(&med->med_open_lock);
                mdt_mfd_close(info, mfd);
        }

        ma->ma_need = MA_INODE;
        next = mdt_object_child(mo);
        rc = mo_attr_get(info->mti_ctxt, next, ma);
        if (rc != 0)
                GOTO(out, rc);

        mdt_pack_attr2body(repbody, &ma->ma_attr, mdt_object_fid(mo));
        EXIT;
out:
        mdt_object_put(info->mti_ctxt, mo);
        return rc;
}

static int mdt_reint_create(struct mdt_thread_info *info)
{
        int rc;
        ENTRY;

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_REINT_CREATE))
                RETURN(-ESTALE);

        switch (info->mti_attr.ma_attr.la_mode & S_IFMT) {
        case S_IFREG:
        case S_IFDIR:{
                if (strlen(info->mti_rr.rr_name) == 0) {
                        rc = mdt_md_mkobj(info);
                        break;
                }
        }
        case S_IFLNK:
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:{
                /* special file should stay on the same node as parent */
                LASSERT(strlen(info->mti_rr.rr_name) > 0);
                rc = mdt_md_create(info);
                break;
        }
        default:
                rc = -EOPNOTSUPP;
        }
        RETURN(rc);
}


static int mdt_reint_unlink(struct mdt_thread_info *info)
{
        struct mdt_reint_record *rr = &info->mti_rr;
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct md_attr          *ma = &info->mti_attr;
        struct lu_fid           *child_fid = &info->mti_tmp_fid1;
        struct mdt_object       *mp;
        struct mdt_object       *mc;
        struct mdt_lock_handle  *lhp;
        struct mdt_lock_handle  *lhc;
        int                      rc;
        ENTRY;

        DEBUG_REQ(D_INODE, req, "unlink "DFID"/%s\n", PFID(rr->rr_fid1),
                  rr->rr_name);

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNLINK))
                GOTO(out, rc = -ENOENT);

        /* step 1: lock the parent */
        lhp = &info->mti_lh[MDT_LH_PARENT];
        lhp->mlh_mode = LCK_EX;
        mp = mdt_object_find_lock(info, rr->rr_fid1, lhp,
                                  MDS_INODELOCK_UPDATE);
        if (IS_ERR(mp))
                GOTO(out, rc = PTR_ERR(mp));

        ma->ma_lmm = req_capsule_server_get(&info->mti_pill, &RMF_MDT_MD);
        ma->ma_lmm_size = req_capsule_get_size(&info->mti_pill,
                                               &RMF_MDT_MD, RCL_SERVER);

        ma->ma_cookie = req_capsule_server_get(&info->mti_pill,
                                               &RMF_LOGCOOKIES);
        ma->ma_cookie_size = req_capsule_get_size(&info->mti_pill,
                                                  &RMF_LOGCOOKIES,
                                                  RCL_SERVER);

        if (!ma->ma_lmm || !ma->ma_cookie)
                GOTO(out_unlock_parent, rc = -EINVAL);

        if (strlen(rr->rr_name) == 0) {
                /* remote partial operation */
                rc = mo_ref_del(info->mti_ctxt, mdt_object_child(mp), ma);
                GOTO(out_unlock_parent, rc);
        }

        /*step 2: find & lock the child */
        lhc = &info->mti_lh[MDT_LH_CHILD];
        lhc->mlh_mode = LCK_EX;
        rc = mdo_lookup(info->mti_ctxt, mdt_object_child(mp),
                        rr->rr_name, child_fid);
        if (rc != 0)
                 GOTO(out_unlock_parent, rc);

        /* we will lock the child regardless it is local or remote. No harm. */
        mc = mdt_object_find_lock(info, child_fid, lhc, MDS_INODELOCK_FULL);
        if (IS_ERR(mc))
                GOTO(out_unlock_parent, rc = PTR_ERR(mc));

        mdt_fail_write(info->mti_ctxt, info->mti_mdt->mdt_bottom,
                       OBD_FAIL_MDS_REINT_UNLINK_WRITE);

        /*Now we can only make sure we need MA_INODE, in mdd layer,
         *will check whether need MA_LOV and MA_COOKIE*/
        ma->ma_need = MA_INODE;
        rc = mdo_unlink(info->mti_ctxt, mdt_object_child(mp),
                        mdt_object_child(mc), rr->rr_name, ma);
        if (rc)
                GOTO(out_unlock_child, rc);

        mdt_handle_last_unlink(info, mc, ma);

        GOTO(out_unlock_child, rc);
out_unlock_child:
        mdt_object_unlock_put(info, mc, lhc, rc);
out_unlock_parent:
        mdt_object_unlock_put(info, mp, lhp, rc);
out:
        mdt_shrink_reply(info, REPLY_REC_OFF + 1);
        return rc;
}

static int mdt_reint_link(struct mdt_thread_info *info)
{
        struct mdt_reint_record *rr = &info->mti_rr;
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct md_attr          *ma = &info->mti_attr;
        struct mdt_object       *ms;
        struct mdt_object       *mp;
        struct mdt_lock_handle  *lhs;
        struct mdt_lock_handle  *lhp;
        int rc;

        ENTRY;

        DEBUG_REQ(D_INODE, req, "link original "DFID" to "DFID" %s",
                  PFID(rr->rr_fid1), PFID(rr->rr_fid2), rr->rr_name);

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_REINT_LINK))
                RETURN(-ENOENT);

        /* step 1: lock the source */
        lhs = &info->mti_lh[MDT_LH_PARENT];
        lhs->mlh_mode = LCK_EX;
        ms = mdt_object_find_lock(info, rr->rr_fid1, lhs, 
                                  MDS_INODELOCK_UPDATE);
        if (IS_ERR(ms))
                RETURN(PTR_ERR(ms));

        if (strlen(rr->rr_name) == 0) {
                /* remote partial operation */
                rc = mo_ref_add(info->mti_ctxt, mdt_object_child(ms));
                GOTO(out_unlock_source, rc);
        }
        /*step 2: find & lock the target parent dir*/
        lhp = &info->mti_lh[MDT_LH_CHILD];
        lhp->mlh_mode = LCK_EX;
        mp = mdt_object_find_lock(info, rr->rr_fid2, lhp, 
                                  MDS_INODELOCK_UPDATE);
        if (IS_ERR(mp))
                GOTO(out_unlock_source, rc = PTR_ERR(mp));

        /* step 4: link it */

        mdt_fail_write(info->mti_ctxt, info->mti_mdt->mdt_bottom,
                       OBD_FAIL_MDS_REINT_LINK_WRITE);

        rc = mdo_link(info->mti_ctxt, mdt_object_child(mp),
                      mdt_object_child(ms), rr->rr_name, ma);
        GOTO(out_unlock_target, rc);

out_unlock_target:
        mdt_object_unlock_put(info, mp, lhp, rc);
out_unlock_source:
        mdt_object_unlock_put(info, ms, lhs, rc);
        return rc;
}

/* partial operation for rename */
static int mdt_reint_rename_tgt(struct mdt_thread_info *info)
{
        struct mdt_reint_record *rr = &info->mti_rr;
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct md_attr          *ma = &info->mti_attr;
        struct mdt_object       *mtgtdir;
        struct mdt_object       *mtgt = NULL;
        struct mdt_lock_handle  *lh_tgtdir;
        struct mdt_lock_handle  *lh_tgt;
        struct lu_fid           *tgt_fid = &info->mti_tmp_fid1;
        int                      rc;

        ENTRY;

        DEBUG_REQ(D_INODE, req, "rename_tgt "DFID" to "DFID" %s",
                  PFID(rr->rr_fid2),
                  PFID(rr->rr_fid1), rr->rr_tgt);

        /* step 1: lookup & lock the tgt dir */
        lh_tgt = &info->mti_lh[MDT_LH_CHILD];
        lh_tgtdir = &info->mti_lh[MDT_LH_PARENT];
        lh_tgtdir->mlh_mode = LCK_EX;
        mtgtdir = mdt_object_find_lock(info, rr->rr_fid1, lh_tgtdir,
                                       MDS_INODELOCK_UPDATE);
        if (IS_ERR(mtgtdir))
                GOTO(out, rc = PTR_ERR(mtgtdir));

        /*step 2: find & lock the target object if exists*/
        rc = mdo_lookup(info->mti_ctxt, mdt_object_child(mtgtdir),
                        rr->rr_tgt, tgt_fid);
        if (rc != 0 && rc != -ENOENT) {
                GOTO(out_unlock_tgtdir, rc);
        } else if (rc == 0) {
                lh_tgt->mlh_mode = LCK_EX;

                mtgt = mdt_object_find_lock(info, tgt_fid, lh_tgt,
                                            MDS_INODELOCK_LOOKUP);
                if (IS_ERR(mtgt))
                        GOTO(out_unlock_tgtdir, rc = PTR_ERR(mtgt));

                rc = mdo_rename_tgt(info->mti_ctxt, mdt_object_child(mtgtdir),
                                    mdt_object_child(mtgt),
                                    rr->rr_fid2, rr->rr_tgt, ma);
        } else /* -ENOENT */ {
                rc = mdo_name_insert(info->mti_ctxt, mdt_object_child(mtgtdir),
                                     rr->rr_tgt, rr->rr_fid2,
                                     S_ISDIR(ma->ma_attr.la_mode));
        }

        /* handle last link of tgt object */
        if (rc == 0 && mtgt)
                mdt_handle_last_unlink(info, mtgt, ma);

        EXIT;
out_unlock_tgt:
        if (mtgt) {
                mdt_object_unlock_put(info, mtgt, lh_tgt, rc);
        }
out_unlock_tgtdir:
        mdt_object_unlock_put(info, mtgtdir, lh_tgtdir, rc);
out:
        return rc;
}

static int mdt_rename_lock(struct mdt_thread_info *info,
                           struct lustre_handle *lh)
{
        ldlm_policy_data_t policy = { .l_inodebits = { MDS_INODELOCK_UPDATE } }; 
        struct ldlm_namespace *ns = info->mti_mdt->mdt_namespace;
        int flags = LDLM_FL_ATOMIC_CB;
        struct ldlm_res_id res_id;
        struct lu_site *ls;
        int rc;
        ENTRY;

        ls = info->mti_mdt->mdt_md_dev.md_lu_dev.ld_site;
        fid_build_res_name(&LUSTRE_BFL_FID, &res_id);
        
        if (ls->ls_control_exp == NULL) {
                /* 
                 * Current node is controller, that is mdt0 where we should take
                 * BFL lock.
                 */
                rc = ldlm_cli_enqueue_local(ns, res_id, LDLM_IBITS, &policy,
                                            LCK_EX, &flags, ldlm_blocking_ast,
                                            ldlm_completion_ast, NULL, NULL, 0,
                                            NULL, lh);
        } else {
                /*
                 * This is the case mdt0 is remote node, issue DLM lock like
                 * other clients.
                 */
                rc = ldlm_cli_enqueue(ls->ls_control_exp, NULL, res_id,
                                      LDLM_IBITS, &policy, LCK_EX, &flags,
                                      ldlm_blocking_ast, ldlm_completion_ast,
                                      NULL, NULL, NULL, 0, NULL, lh, 0);
        }

        RETURN(rc);
}

static void mdt_rename_unlock(struct lustre_handle *lh)
{
        ENTRY;
        ldlm_lock_decref(lh, LCK_EX);
        EXIT;
}

/* 
 * This is is_subdir() variant, it is CMD is cmm forwards it to correct
 * target. Source should not be ancestor of target dir. May be other rename
 * checks can be moved here later.
 */
static int mdt_rename_check(struct mdt_thread_info *info, struct lu_fid *fid)
{
        struct mdt_reint_record *rr = &info->mti_rr;
        struct lu_fid dst_fid = *rr->rr_fid2;
        struct mdt_object *dst;
        int rc = 0;
        ENTRY;

        do {
                dst = mdt_object_find(info->mti_ctxt, info->mti_mdt, &dst_fid);
                if (!IS_ERR(dst)) {
                        rc = mdo_is_subdir(info->mti_ctxt, mdt_object_child(dst),
                                           fid, &dst_fid);
                        mdt_object_put(info->mti_ctxt, dst);
                        if (rc < 0) {
                                CERROR("Error while doing mdo_is_subdir(), rc %d\n",
                                       rc);
                        } else if (rc == 1) {
                                rc = -EINVAL;
                        }
                } else {
                        rc = PTR_ERR(dst);
                }
        } while (rc == EREMOTE);
        
        RETURN(rc);
}

static int mdt_reint_rename(struct mdt_thread_info *info)
{
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule      *pill = &info->mti_pill;
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct md_attr          *ma = &info->mti_attr;
        struct mdt_object       *msrcdir;
        struct mdt_object       *mtgtdir;
        struct mdt_object       *mold;
        struct mdt_object       *mnew = NULL;
        struct mdt_lock_handle  *lh_srcdirp;
        struct mdt_lock_handle  *lh_tgtdirp;
        struct mdt_lock_handle  *lh_oldp;
        struct mdt_lock_handle  *lh_newp;
        struct lu_fid           *old_fid = &info->mti_tmp_fid1;
        struct lu_fid           *new_fid = &info->mti_tmp_fid2;
        struct lustre_handle     rename_lh = { 0 };
        int                      rc;

        ENTRY;

        DEBUG_REQ(D_INODE, req, "rename "DFID"/%s to "DFID"/%s",
                  PFID(rr->rr_fid1), rr->rr_name,
                  PFID(rr->rr_fid2), rr->rr_tgt);

        rc = req_capsule_get_size(pill, &RMF_NAME, RCL_CLIENT);
        if (rc == 1) {
        /* if (rr->rr_name[0] == 0) {*/
                rc = mdt_reint_rename_tgt(info);
                GOTO(out, rc);
        }

        rc = mdt_rename_lock(info, &rename_lh);
        if (rc) {
                CERROR("can't lock FS for rename, rc %d\n", rc);
                RETURN(rc);
        }

        lh_newp = &info->mti_lh[MDT_LH_NEW];

        /* step 1: lock the source dir */
        lh_srcdirp = &info->mti_lh[MDT_LH_PARENT];
        lh_srcdirp->mlh_mode = LCK_EX;
        msrcdir = mdt_object_find_lock(info, rr->rr_fid1, lh_srcdirp,
                                       MDS_INODELOCK_UPDATE);
        if (IS_ERR(msrcdir))
                GOTO(out, rc = PTR_ERR(msrcdir));

        /*step 2: find & lock the target dir*/
        lh_tgtdirp = &info->mti_lh[MDT_LH_CHILD];
        lh_tgtdirp->mlh_mode = LCK_EX;
        if (lu_fid_eq(rr->rr_fid1, rr->rr_fid2)) {
                mdt_object_get(info->mti_ctxt, msrcdir);
                mtgtdir = msrcdir;
        } else {
                mtgtdir = mdt_object_find_lock(info, rr->rr_fid2, lh_tgtdirp,
                                               MDS_INODELOCK_UPDATE);
                if (IS_ERR(mtgtdir))
                        GOTO(out_unlock_source, rc = PTR_ERR(mtgtdir));
        }

        /*step 3: find & lock the old object*/
        rc = mdo_lookup(info->mti_ctxt, mdt_object_child(msrcdir),
                        rr->rr_name, old_fid);
        if (rc != 0)
                GOTO(out_unlock_target, rc);

        if (lu_fid_eq(old_fid, rr->rr_fid1) || lu_fid_eq(old_fid, rr->rr_fid2))
                GOTO(out_unlock_target, rc = -EINVAL);

        lh_oldp = &info->mti_lh[MDT_LH_OLD];
        lh_oldp->mlh_mode = LCK_EX;
        mold = mdt_object_find_lock(info, old_fid, lh_oldp,
                                    MDS_INODELOCK_LOOKUP);
        if (IS_ERR(mold))
                GOTO(out_unlock_target, rc = PTR_ERR(mold));

        /*step 4: find & lock the new object*/
        /* new target object may not exist now */
        rc = mdo_lookup(info->mti_ctxt, mdt_object_child(mtgtdir),
                        rr->rr_tgt, new_fid);
        if (rc == 0) {
                /* the new_fid should have been filled at this moment*/
                if (lu_fid_eq(old_fid, new_fid))
                       GOTO(out_unlock_old, rc);

                if (lu_fid_eq(new_fid, rr->rr_fid1) ||
                    lu_fid_eq(new_fid, rr->rr_fid2))
                        GOTO(out_unlock_old, rc = -EINVAL);

                lh_newp->mlh_mode = LCK_EX;
                mnew = mdt_object_find_lock(info, new_fid, lh_newp,
                                            MDS_INODELOCK_FULL);
                if (IS_ERR(mnew))
                        GOTO(out_unlock_old, rc = PTR_ERR(mnew));
        } else if (rc != -EREMOTE && rc != -ENOENT)
                GOTO(out_unlock_old, rc);

        /* step 5: dome some checking ...*/
        /* step 6: rename it */
        ma->ma_lmm = req_capsule_server_get(&info->mti_pill, &RMF_MDT_MD);
        ma->ma_lmm_size = req_capsule_get_size(&info->mti_pill,
                                               &RMF_MDT_MD, RCL_SERVER);

        ma->ma_cookie = req_capsule_server_get(&info->mti_pill,
                                                &RMF_LOGCOOKIES);
        ma->ma_cookie_size = req_capsule_get_size(&info->mti_pill,
                                               &RMF_LOGCOOKIES, RCL_SERVER);

        if (!ma->ma_lmm || !ma->ma_cookie)
                GOTO(out_unlock_new, rc = -EINVAL);

        ma->ma_need = MA_INODE | MA_LOV | MA_COOKIE;

        mdt_fail_write(info->mti_ctxt, info->mti_mdt->mdt_bottom,
                       OBD_FAIL_MDS_REINT_RENAME_WRITE);

        /* Check if @dst is subdir of @src. */
        rc = mdt_rename_check(info, old_fid);
        if (rc)
                GOTO(out_unlock_new, rc);

        rc = mdo_rename(info->mti_ctxt, mdt_object_child(msrcdir),
                        mdt_object_child(mtgtdir), old_fid, rr->rr_name,
                        (mnew ? mdt_object_child(mnew) : NULL), rr->rr_tgt, ma);
        
        /* handle last link of tgt object */
        if (rc == 0 && mnew)
                mdt_handle_last_unlink(info, mnew, ma);

out_unlock_new:
        if (mnew) {
                mdt_object_unlock_put(info, mnew, lh_newp, rc);
        }
out_unlock_old:
        mdt_object_unlock_put(info, mold, lh_oldp, rc);
out_unlock_target:
        mdt_object_unlock_put(info, mtgtdir, lh_tgtdirp, rc);
out_unlock_source:
        mdt_object_unlock_put(info, msrcdir, lh_srcdirp, rc);
out:
        mdt_rename_unlock(&rename_lh);
        mdt_shrink_reply(info, REPLY_REC_OFF + 1);
        return rc;
}


typedef int (*mdt_reinter)(struct mdt_thread_info *info);

static mdt_reinter reinters[REINT_MAX] = {
        [REINT_SETATTR]  = mdt_reint_setattr,
        [REINT_CREATE] = mdt_reint_create,
        [REINT_LINK] = mdt_reint_link,
        [REINT_UNLINK] = mdt_reint_unlink,
        [REINT_RENAME] = mdt_reint_rename,
        [REINT_OPEN] = mdt_open
};

int mdt_reint_rec(struct mdt_thread_info *info)
{
        int rc;
        ENTRY;

        rc = reinters[info->mti_rr.rr_opcode](info);

        RETURN(rc);
}
