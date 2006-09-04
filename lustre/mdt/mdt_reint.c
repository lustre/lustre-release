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
static int mdt_reint_setattr(struct mdt_thread_info *info)
{
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct mdt_object       *mo;
        struct md_object        *next;
        struct mdt_lock_handle  *lh;
        struct mdt_body         *repbody;
        int                      rc;

        ENTRY;

        DEBUG_REQ(D_INODE, req, "setattr "DFID" %x", PFID(rr->rr_fid1),
                  (unsigned int)attr->la_valid);

        lh = &info->mti_lh[MDT_LH_PARENT];
        lh->mlh_mode = LCK_EX;

        if (rr->rr_flags & MRF_SETATTR_LOCKED) {
                mo = mdt_object_find(info->mti_ctxt, info->mti_mdt,
                                     rr->rr_fid1);
        } else {
                __u64 lockpart = MDS_INODELOCK_UPDATE;
                if (attr->la_valid & (LA_MODE|LA_UID|LA_GID))
                        lockpart |= MDS_INODELOCK_LOOKUP;

                mo = mdt_object_find_lock(info, rr->rr_fid1, lh, lockpart);
        }
        if (IS_ERR(mo))
                RETURN(rc = PTR_ERR(mo));

        next = mdt_object_child(mo);
        if (lu_object_assert_not_exists(&mo->mot_obj.mo_lu))
                GOTO(out_unlock, rc = -ENOENT);

        /* all attrs are packed into mti_attr in unpack_setattr */
        mdt_fail_write(info->mti_ctxt, info->mti_mdt->mdt_bottom,
                       OBD_FAIL_MDS_REINT_SETATTR_WRITE);

        rc = mo_attr_set(info->mti_ctxt, next, &info->mti_attr);
        if (rc != 0)
                GOTO(out_unlock, rc);

        info->mti_attr.ma_need = MA_INODE;
        rc = mo_attr_get(info->mti_ctxt, next, &info->mti_attr);
        if (rc != 0)
                GOTO(out_unlock, rc);

        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        mdt_pack_attr2body(repbody, attr, mdt_object_fid(mo));

        /* don't return OST-specific attributes if we didn't just set them.
        if (valid & ATTR_SIZE)
                repbody->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
        if (valid & (ATTR_MTIME | ATTR_MTIME_SET))
                repbody->valid |= OBD_MD_FLMTIME;
        if (valid & (ATTR_ATIME | ATTR_ATIME_SET))
                repbody->valid |= OBD_MD_FLATIME;
        */
        GOTO(out_unlock, rc);
out_unlock:
        mdt_object_unlock_put(info, mo, lh, rc);
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
                RETURN(-ENOENT);

        /* step 1: lock the parent */
        lhp = &info->mti_lh[MDT_LH_PARENT];
        lhp->mlh_mode = LCK_EX;
        mp = mdt_object_find_lock(info, rr->rr_fid1, lhp,
                                  MDS_INODELOCK_UPDATE);
        if (IS_ERR(mp))
                RETURN(PTR_ERR(mp));

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

        /*step 3:  do some checking ...*/

        /* step 4: delete it */

        mdt_fail_write(info->mti_ctxt, info->mti_mdt->mdt_bottom,
                       OBD_FAIL_MDS_REINT_UNLINK_WRITE);

        ma->ma_lmm = req_capsule_server_get(&info->mti_pill, &RMF_MDT_MD);
        ma->ma_lmm_size = req_capsule_get_size(&info->mti_pill,
                                               &RMF_MDT_MD, RCL_SERVER);

        ma->ma_cookie = req_capsule_server_get(&info->mti_pill,
                                                &RMF_LOGCOOKIES);
        ma->ma_cookie_size = req_capsule_get_size(&info->mti_pill,
                                               &RMF_LOGCOOKIES, RCL_SERVER);

        if (!ma->ma_lmm || !ma->ma_cookie)
                GOTO(out_unlock_parent, rc = -EINVAL);

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
        if (rc != 0 && rc != -ENOENT)
                GOTO(out_unlock_tgtdir, rc);

        if (rc == 0) {
                lh_tgt->mlh_mode = LCK_EX;

                mtgt = mdt_object_find_lock(info, tgt_fid, lh_tgt,
                                            MDS_INODELOCK_LOOKUP);
                if (IS_ERR(mtgt))
                        GOTO(out_unlock_tgtdir, rc = PTR_ERR(mtgt));
        }

        /* step 3: rename_tgt or name_insert */
        if (mtgt)
                rc = mdo_rename_tgt(info->mti_ctxt, mdt_object_child(mtgtdir),
                                    mdt_object_child(mtgt),
                                    rr->rr_fid2, rr->rr_tgt, ma);
        else
                rc = mdo_name_insert(info->mti_ctxt, mdt_object_child(mtgtdir),
                                     rr->rr_tgt, rr->rr_fid2, 0 /* FIXME: isdir */);
        GOTO(out_unlock_tgt, rc);

out_unlock_tgt:
        if (mtgt) {
                mdt_object_unlock_put(info, mtgt, lh_tgt, rc);
        }
out_unlock_tgtdir:
        mdt_object_unlock_put(info, mtgtdir, lh_tgtdir, rc);
out:
        return rc;
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
        int                      rc;

        ENTRY;

        DEBUG_REQ(D_INODE, req, "rename "DFID"/%s to "DFID"/%s",
                  PFID(rr->rr_fid1), rr->rr_name,
                  PFID(rr->rr_fid2), rr->rr_tgt);

        rc = req_capsule_get_size(pill, &RMF_NAME, RCL_CLIENT);
        if (rc == 1) {
        /* if (rr->rr_name[0] == 0) {*/
                RETURN(mdt_reint_rename_tgt(info));
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
        if (rc != 0 && rc != -ENOENT)
                GOTO(out_unlock_old, rc);

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
        }

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

        rc = mdo_rename(info->mti_ctxt, mdt_object_child(msrcdir),
                        mdt_object_child(mtgtdir), old_fid,
                        rr->rr_name, mnew ? mdt_object_child(mnew): NULL,
                        rr->rr_tgt, ma);
        /* handle last link of tgt object */
        if (mnew)
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
