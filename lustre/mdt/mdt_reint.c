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
        struct lu_attr         *attr = &info->mti_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        int rc;
        ENTRY;

        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);

        lh = &info->mti_lh[MDT_LH_PARENT];
        lh->mlh_mode = LCK_PW;

        parent = mdt_object_find_lock(info->mti_ctxt, mdt, rr->rr_fid1,
                                      lh, MDS_INODELOCK_UPDATE);
        if (IS_ERR(parent))
                RETURN(PTR_ERR(parent));

        child = mdt_object_find(info->mti_ctxt, mdt, rr->rr_fid2);
        if (!IS_ERR(child)) {
                struct md_object *next = mdt_object_child(parent);

                rc = mdo_create(info->mti_ctxt, next, rr->rr_name,
                                mdt_object_child(child), attr);
                if (rc == 0) {
                        /* return fid to client. attr is over-written!!*/
                        rc = mo_attr_get(info->mti_ctxt, 
                                         mdt_object_child(child), 
                                         attr);
                        if (rc == 0) {
                                mdt_pack_attr2body(repbody, attr);
                                repbody->fid1 = *mdt_object_fid(child);
                                repbody->valid |= OBD_MD_FLID;
                        }
                }
                mdt_object_put(info->mti_ctxt, child);
        } else
                rc = PTR_ERR(child);
        mdt_object_unlock(mdt->mdt_namespace, parent, lh);
        mdt_object_put(info->mti_ctxt, parent);
        RETURN(rc);
}

/* partial request to create object only */
static int mdt_md_mkobj(struct mdt_thread_info *info)
{
        struct mdt_device      *mdt = info->mti_mdt;
        struct mdt_object      *o;
        struct mdt_body        *repbody;
        int rc;
        ENTRY;

        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);

        o = mdt_object_find(info->mti_ctxt, mdt, info->mti_rr.rr_fid1);
        if (!IS_ERR(o)) {
                struct md_object *next = mdt_object_child(o);

                rc = mo_object_create(info->mti_ctxt, next,
                                      &info->mti_attr);
                if (rc == 0) {
                        /* return fid to client. */
                        rc = mo_attr_get(info->mti_ctxt, 
                                         next, 
                                         &info->mti_attr);
                        if (rc == 0) {
                                mdt_pack_attr2body(repbody, &info->mti_attr);
                                repbody->fid1 = *mdt_object_fid(o);
                                repbody->valid |= OBD_MD_FLID;
                        }
                }
                mdt_object_put(info->mti_ctxt, o);
        } else
                rc = PTR_ERR(o);

        RETURN(rc);
}


static int mdt_reint_setattr(struct mdt_thread_info *info)
{
        struct lu_attr *attr = &info->mti_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct ptlrpc_request *req = mdt_info_req(info);
        struct mdt_object *mo;
        struct mdt_lock_handle *lh;
        struct lu_attr tmp_attr;
        struct mdt_body *repbody;
        int rc;
        int locked = 0;

        ENTRY;

        DEBUG_REQ(D_INODE, req, "setattr "DFID3" %x", PFID3(rr->rr_fid1),
                  (unsigned int)attr->la_valid);

        /* MDS_CHECK_RESENT */

        if (attr->la_valid & ATTR_FROM_OPEN) {
                mo = mdt_object_find(info->mti_ctxt, info->mti_mdt, 
                                     rr->rr_fid1);
                if (IS_ERR(mo))
                        RETURN(rc = PTR_ERR(mo));
        } else {
                __u64 lockpart = MDS_INODELOCK_UPDATE;
                if (attr->la_valid & (ATTR_MODE|ATTR_UID|ATTR_GID))
                        lockpart |= MDS_INODELOCK_LOOKUP;
        
                lh = &info->mti_lh[MDT_LH_PARENT];
                lh->mlh_mode = LCK_EX;
 
                mo = mdt_object_find_lock(info->mti_ctxt, info->mti_mdt, 
                                          rr->rr_fid1, lh, lockpart);
                
                if (IS_ERR(mo))
                        RETURN(rc = PTR_ERR(mo));
                locked = 1;
        }

        if (lu_object_assert_not_exists(info->mti_ctxt, &mo->mot_obj.mo_lu))
                GOTO(out_unlock, rc = -ENOENT);

        if (req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                GOTO(out_unlock, rc = -EROFS);

        rc = mo_attr_set(info->mti_ctxt, mdt_object_child(mo), attr);
        if (rc != 0)
                GOTO(out_unlock, rc);
        
        rc = mo_attr_get(info->mti_ctxt, mdt_object_child(mo), &tmp_attr);
        if (rc != 0)
                GOTO(out_unlock, rc);

        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        mdt_pack_attr2body(repbody, &tmp_attr);
        repbody->fid1 = *mdt_object_fid(mo);
        repbody->valid |= OBD_MD_FLID;
       
        /* don't return OST-specific attributes if we didn't just set them. 
        if (attr->la_valid & ATTR_SIZE)
                repbody->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
        if (attr->la_valid & (ATTR_MTIME | ATTR_MTIME_SET))
                repbody->valid |= OBD_MD_FLMTIME;
        if (attr->la_valid & (ATTR_ATIME | ATTR_ATIME_SET))
                repbody->valid |= OBD_MD_FLATIME;
        */
        /* FIXME: I have to combine the attr_set & xattr_set into one single
                  transaction. How can I?
        rc = mo_xattr_set(info->mti_ctxt, mdt_object_child(mo),
                          rr->rr_eadata, rr->rr_eadatalen, "lov");
        if (rc)
                GOTO(out_unlock, rc);
         */ 

        /* FIXME & TODO Please deal with logcookies here*/
        GOTO(out_unlock, rc);
out_unlock:
        if (locked) {
                mdt_object_unlock(info->mti_mdt->mdt_namespace, mo, lh);
        }
        mdt_object_put(info->mti_ctxt, mo);
        return (rc);
}


static int mdt_reint_create(struct mdt_thread_info *info)
{
        int rc;
        ENTRY;

        switch (info->mti_attr.la_mode & S_IFMT) {
        case S_IFDIR:{
                if (strlen(info->mti_rr.rr_name) > 0)
                        rc = mdt_md_create(info);
                else
                        rc = mdt_md_mkobj(info);
                break;
        }
        case S_IFREG:
        case S_IFLNK:
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:{
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
        struct ptlrpc_request *req = mdt_info_req(info);
        struct mdt_object *mp;
        struct mdt_object *mc;
        struct mdt_lock_handle *lhp;
        struct mdt_lock_handle *lhc;
        struct mdt_body *repbody;
        struct lu_fid child_fid;
        int rc;

        ENTRY;

        DEBUG_REQ(D_INODE, req, "unlink "DFID3"/"DFID3, PFID3(rr->rr_fid1),
                  PFID3(rr->rr_fid2));

        /* MDS_CHECK_RESENT here */

        /* step 1: lock the parent */
        lhp = &info->mti_lh[MDT_LH_PARENT];
        lhp->mlh_mode = LCK_EX;
        mp = mdt_object_find_lock(info->mti_ctxt, info->mti_mdt,
                                  rr->rr_fid1, lhp, MDS_INODELOCK_UPDATE);
        if (IS_ERR(mp))
                RETURN(PTR_ERR(mp));

        if (strlen(rr->rr_name) == 0) {
                if (req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                        GOTO(out_unlock_parent, rc = -EROFS);

                /* remote partial operation */
                rc = mo_ref_del(info->mti_ctxt, mdt_object_child(mp));
                GOTO(out_unlock_parent, rc);
        }

        /*step 2: find & lock the child */
        lhc = &info->mti_lh[MDT_LH_CHILD];
        lhc->mlh_mode = LCK_EX;
        rc = mdo_lookup(info->mti_ctxt, mdt_object_child(mp),
                        rr->rr_name, &child_fid);
        if (rc) {
                GOTO(out_unlock_parent, rc);
        }

        mc = mdt_object_find_lock(info->mti_ctxt, info->mti_mdt, &child_fid,
                                  lhc, MDS_INODELOCK_FULL);
        if (IS_ERR(mc))
                GOTO(out_unlock_parent, rc = PTR_ERR(mc));

        /* NB: Be aware of Bug 2029 */
        
        /*step 3: deal with orphan */

        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);

        if (req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                GOTO(out_unlock_child, rc = -EROFS);

        /* step 4: delete it */
        rc = mdo_unlink(info->mti_ctxt, mdt_object_child(mc),
                        mdt_object_child(mc), rr->rr_name);

        /*step 5: orphan handling & recovery issue */
        if (rc == 0) {
        /* If this is potentially the last reference to this inode, get the
         * OBD EA data first so the client can destroy OST objects.  We
         * only do the object removal later if no open files/links remain. */

                /* FIXME & TODO:
                 * 1. orphan handling here
                 * 2. Please deal with logcookies here */ 
        }
        GOTO(out_unlock_child, rc);
out_unlock_child:
        mdt_object_unlock(info->mti_mdt->mdt_namespace, mc, lhc);
        mdt_object_put(info->mti_ctxt, mc);
out_unlock_parent:
        mdt_object_unlock(info->mti_mdt->mdt_namespace, mp, lhp);
        mdt_object_put(info->mti_ctxt, mp);
        return rc;
}

static int mdt_reint_link(struct mdt_thread_info *info)
{
        struct mdt_reint_record *rr = &info->mti_rr;
        struct ptlrpc_request *req = mdt_info_req(info);
        struct mdt_object *ms;
        struct mdt_object *mt;
        struct mdt_lock_handle *lhs;
        struct mdt_lock_handle *lht;
        int rc;

        ENTRY;

        DEBUG_REQ(D_INODE, req, "link original "DFID3" to "DFID3" %s",
                  PFID3(rr->rr_fid1), PFID3(rr->rr_fid2), rr->rr_name);

        /* MDS_CHECK_RESENT here */

        /* step 1: lock the source */
        lhs = &info->mti_lh[MDT_LH_PARENT];
        lhs->mlh_mode = LCK_EX;
        ms = mdt_object_find_lock(info->mti_ctxt, info->mti_mdt,
                                  rr->rr_fid1, lhs, MDS_INODELOCK_UPDATE);
        if (IS_ERR(ms))
                RETURN(PTR_ERR(ms));

        if (strlen(rr->rr_name) == 0) {
                if (req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                        GOTO(out_unlock_source, rc = -EROFS);

                /* remote partial operation */
                rc = mo_ref_add(info->mti_ctxt, mdt_object_child(ms));
                GOTO(out_unlock_source, rc);
        }
        /*step 2: find & lock the target */
        lht = &info->mti_lh[MDT_LH_CHILD];
        lht->mlh_mode = LCK_EX;
        mt = mdt_object_find_lock(info->mti_ctxt, info->mti_mdt,
                                  rr->rr_fid2, lht, MDS_INODELOCK_UPDATE);
        if (IS_ERR(mt))
                GOTO(out_unlock_source, rc = PTR_ERR(mt));

        if (req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                GOTO(out_unlock_target, rc = -EROFS);

        /* step 4: link it */
        rc = mdo_link(info->mti_ctxt, mdt_object_child(mt),
                      mdt_object_child(ms), rr->rr_name);
        GOTO(out_unlock_target, rc);

out_unlock_target:
        mdt_object_unlock(info->mti_mdt->mdt_namespace, mt, lht);
        mdt_object_put(info->mti_ctxt, mt);
out_unlock_source:
        mdt_object_unlock(info->mti_mdt->mdt_namespace, ms, lhs);
        mdt_object_put(info->mti_ctxt, ms);
        return rc;
}

/* partial operation for rename */
static int mdt_reint_rename_tgt(struct mdt_thread_info *info)
{
        struct mdt_reint_record *rr = &info->mti_rr;
        struct ptlrpc_request *req = mdt_info_req(info);
        struct mdt_object *mtgtdir;
        struct mdt_object *mtgt = NULL;
        struct mdt_lock_handle *lh_tgtdir;
        struct mdt_lock_handle *lh_tgt;
        struct lu_fid tgt_fid;
        struct ldlm_namespace *ns = info->mti_mdt->mdt_namespace;
        int rc;

        ENTRY;

        DEBUG_REQ(D_INODE, req, "rename_tgt "DFID3" to "DFID3" %s",
                  PFID3(rr->rr_fid2),
                  PFID3(rr->rr_fid1), rr->rr_tgt);

        /* step 1: lookup & lock the tgt dir */
        lh_tgtdir = &info->mti_lh[MDT_LH_PARENT];
        lh_tgtdir->mlh_mode = LCK_PW;
        mtgtdir = mdt_object_find_lock(info->mti_ctxt, info->mti_mdt,
                                       rr->rr_fid1, lh_tgtdir, 
                                       MDS_INODELOCK_UPDATE);
        if (IS_ERR(mtgtdir))
                GOTO(out, rc = PTR_ERR(mtgtdir));

        /*step 2: find & lock the target object if exists*/
        rc = mdo_lookup(info->mti_ctxt, mdt_object_child(mtgtdir),
                        rr->rr_tgt, &tgt_fid);
        if (rc && rc != -ENOENT)
                GOTO(out_unlock_tgtdir, rc);

        if (req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                GOTO(out_unlock_tgt, rc = -EROFS);
        
        if (rc == 0) {
                lh_tgt = &info->mti_lh[MDT_LH_CHILD];
                lh_tgt->mlh_mode = LCK_EX;
 
                mtgt = mdt_object_find_lock(info->mti_ctxt, info->mti_mdt,
                                            &tgt_fid, lh_tgt, 
                                            MDS_INODELOCK_LOOKUP);
                if (IS_ERR(mtgt))
                        GOTO(out_unlock_tgtdir, rc = PTR_ERR(mtgt));
        }
        
        /* step 3: rename_tgt or name_insert */
        if (mtgt)
                rc = mdo_rename_tgt(info->mti_ctxt, mdt_object_child(mtgtdir),
                                    mdt_object_child(mtgt), 
                                    rr->rr_fid2, rr->rr_tgt);
        else
                rc = mdo_name_insert(info->mti_ctxt, mdt_object_child(mtgtdir),
                                     rr->rr_tgt, rr->rr_fid2);
        GOTO(out_unlock_tgt, rc);

out_unlock_tgt:
        if (mtgt) {
                mdt_object_unlock(ns, mtgt, lh_tgt);
                mdt_object_put(info->mti_ctxt, mtgt);
        }
out_unlock_tgtdir:
        mdt_object_unlock(ns, mtgtdir, lh_tgtdir);
        mdt_object_put(info->mti_ctxt, mtgtdir);
out:
        return rc;
}


static int mdt_reint_rename(struct mdt_thread_info *info)
{
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule *pill = &info->mti_pill;
        struct ptlrpc_request *req = mdt_info_req(info);
        struct mdt_object *msrcdir;
        struct mdt_object *mtgtdir;
        struct mdt_object *mold;
        struct mdt_object *mnew = NULL;
        struct mdt_lock_handle *lh_srcdirp;
        struct mdt_lock_handle *lh_tgtdirp;
        struct mdt_lock_handle lh_old;
        struct mdt_lock_handle lh_new;
        struct lu_fid old_fid = {0};
        struct lu_fid new_fid = {0};
        struct ldlm_namespace *ns = info->mti_mdt->mdt_namespace;
        int rc;

        ENTRY;

        DEBUG_REQ(D_INODE, req, "rename "DFID3"/%s to "DFID3"/%s",
                  PFID3(rr->rr_fid1), rr->rr_tgt,
                  PFID3(rr->rr_fid2), rr->rr_name);

        /* MDS_CHECK_RESENT here */

        rc = req_capsule_get_size(pill, &RMF_NAME, RCL_CLIENT);
        if (rc == 1) {
        /* if (strlen(rr->rr_name) == 0) {*/
                RETURN(mdt_reint_rename_tgt(info));
        }

        /* step 1: lock the source dir */
        lh_srcdirp = &info->mti_lh[MDT_LH_PARENT];
        lh_srcdirp->mlh_mode = LCK_EX;
        msrcdir = mdt_object_find_lock(info->mti_ctxt, info->mti_mdt,
                                       rr->rr_fid1, lh_srcdirp, 
                                       MDS_INODELOCK_UPDATE);
        if (IS_ERR(msrcdir))
                GOTO(out, rc = PTR_ERR(msrcdir));

        /*step 2: find & lock the target dir*/
        lh_tgtdirp = &info->mti_lh[MDT_LH_CHILD];
        lh_tgtdirp->mlh_mode = LCK_EX;
        mtgtdir = mdt_object_find_lock(info->mti_ctxt, info->mti_mdt,
                                       rr->rr_fid2, lh_tgtdirp, 
                                       MDS_INODELOCK_UPDATE);
        if (IS_ERR(mtgtdir))
                GOTO(out_unlock_source, rc = PTR_ERR(mtgtdir));
        
        /*step 3: find & lock the old object*/
        rc = mdo_lookup(info->mti_ctxt, mdt_object_child(msrcdir),
                        rr->rr_name, &old_fid);
        if (rc) 
                GOTO(out_unlock_target, rc);
 
        lh_old.mlh_mode = LCK_EX;
        mold = mdt_object_find_lock(info->mti_ctxt, info->mti_mdt,
                                    &old_fid, &lh_old, 
                                    MDS_INODELOCK_LOOKUP);
        if (IS_ERR(mold))
                GOTO(out_unlock_target, rc = PTR_ERR(mold));
        
        /*step 4: find & lock the new object*/
        /* new target object may not exist now */
        rc = mdo_lookup(info->mti_ctxt, mdt_object_child(mtgtdir),
                        rr->rr_tgt, &new_fid);
        if (rc && rc != -ENOENT)
                GOTO(out_unlock_old, rc);

        if (rc == 0) { 
                /* the new_fid should have been filled at this moment*/
                lh_new.mlh_mode = LCK_EX;
                mnew = mdt_object_find_lock(info->mti_ctxt, info->mti_mdt,
                                            &new_fid, &lh_new, 
                                            MDS_INODELOCK_FULL);
                if (IS_ERR(mnew))
                        GOTO(out_unlock_old, rc = PTR_ERR(mnew));
        }

        /* step 5: dome some checking*/
        if (req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                GOTO(out_unlock_new, rc = -EROFS);

        /* step 6: rename it */
        rc = mdo_rename(info->mti_ctxt, mdt_object_child(msrcdir),
                        mdt_object_child(mtgtdir), &old_fid,
                        rr->rr_name, mnew ? mdt_object_child(mnew): NULL,
                        rr->rr_tgt);
        if (rc)
                GOTO(out_unlock_new, rc);

        /* step 7: TODO:check old object */
        /* if (mold is orphan)
         */

out_unlock_new:
        if (mnew) {
                mdt_object_unlock(ns, mnew, &lh_new);
                mdt_object_put(info->mti_ctxt, mnew);
        }
out_unlock_old:
        mdt_object_unlock(ns, mold, &lh_old);
        mdt_object_put(info->mti_ctxt, mold);
out_unlock_target:
        mdt_object_unlock(ns, mtgtdir, lh_tgtdirp);
        mdt_object_put(info->mti_ctxt, mtgtdir);
out_unlock_source:
        mdt_object_unlock(ns, msrcdir, lh_srcdirp);
        mdt_object_put(info->mti_ctxt, msrcdir);
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
        [REINT_OPEN] = mdt_reint_open
};

int mdt_reint_rec(struct mdt_thread_info *info)
{
        int rc;
        ENTRY;

        rc = reinters[info->mti_rr.rr_opcode](info);

        RETURN(rc);
}
