/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mdt/mdt_open.c
 *  Lustre Metadata Target (mdt) open/close file handling
 *
 *  Copyright (C) 2002-2006 Cluster File Systems, Inc.
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

/* we do nothing because we do not have refcount now */
static void mdt_mfd_get(void *mfdp)
{
}

/* Create a new mdt_file_data struct, initialize it, 
 * and insert it to global hash table */ 
static struct mdt_file_data *mdt_mfd_new(void)
{
        struct mdt_file_data *mfd;
        ENTRY;

        OBD_ALLOC_PTR(mfd);
        if (mfd != NULL) {
                INIT_LIST_HEAD(&mfd->mfd_handle.h_link);
                INIT_LIST_HEAD(&mfd->mfd_list);
                class_handle_hash(&mfd->mfd_handle, mdt_mfd_get);
        } else
                CERROR("mdt: out of memory\n");

        RETURN(mfd);
}

/* Find the mfd pointed to by handle in global hash table. */
static struct mdt_file_data *mdt_handle2mfd(const struct lustre_handle *handle)
{
        ENTRY;
        LASSERT(handle != NULL);
        RETURN(class_handle2object(handle->cookie));
}

/* free mfd */
static void mdt_mfd_free(struct mdt_file_data *mfd)
{
        LASSERT(list_empty(&mfd->mfd_handle.h_link));
        OBD_FREE_PTR(mfd);
}

static int mdt_mfd_open(struct mdt_thread_info *info,
                        struct mdt_object *o, 
                        int flags, int created)
{
        struct mdt_export_data *med;
        struct mdt_file_data   *mfd;
        struct mdt_body        *repbody;
        struct md_attr         *ma = &info->mti_attr;
        struct lu_attr         *la = &ma->ma_attr;
        struct ptlrpc_request  *req = mdt_info_req(info);
        int                     rc = 0;
        ENTRY;

        med = &req->rq_export->exp_mdt_data;
        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);

        if (!created) {
                /* we have to get attr & lov ea for this object*/
                rc = mo_attr_get(info->mti_ctxt, mdt_object_child(o), la);
                if (rc == 0 && S_ISREG(la->la_mode)) {
                        ma->ma_valid |= MA_INODE;
                        rc = mo_xattr_get(info->mti_ctxt, 
                                          mdt_object_child(o),
                                          ma->ma_lmm, 
                                          ma->ma_lmm_size,
                                          XATTR_NAME_LOV);
                        if (rc >= 0) {
                                ma->ma_lmm_size = rc;
                                rc = 0;
                                ma->ma_valid |= MA_LOV;
                        }
                }
        }
        if (rc == 0){
                if (!S_ISREG(la->la_mode) &&
                    !S_ISDIR(la->la_mode) &&
                     (req->rq_export->exp_connect_flags & OBD_CONNECT_NODEVOH))
                        /* If client supports this, do not return open handle
                        *  for special device nodes */
                        RETURN(0);

                /* FIXME:maybe this can be done earlier? */
                if (S_ISDIR(la->la_mode)) {
                        if (flags & (MDS_OPEN_CREAT | FMODE_WRITE)) {
                                /* we are trying to create or 
                                 * write an existing dir. */
                                rc = -EISDIR;
                        }
                } else if (flags & MDS_OPEN_DIRECTORY) 
                        rc = -ENOTDIR;
        }
        if (rc != 0)
                RETURN(rc);
        if (ma->ma_valid & MA_INODE)
                mdt_pack_attr2body(repbody, la, mdt_object_fid(o));
        if (ma->ma_lmm_size && ma->ma_valid & MA_LOV) {
                repbody->eadatasize = ma->ma_lmm_size;
                if (S_ISDIR(la->la_mode))
                        repbody->valid |= OBD_MD_FLDIREA;
                else
                        repbody->valid |= OBD_MD_FLEASIZE;
        }

        if (flags & FMODE_WRITE) {
                /*mds_get_write_access*/
        } else if (flags & MDS_FMODE_EXEC) {
                /*mds_deny_write_access*/
        }

        mfd = mdt_mfd_new();
        if (mfd != NULL) {
                /* keep a reference on this object for this open,
                * and is released by mdt_mfd_close() */
                mdt_object_get(info->mti_ctxt, o);

                mfd->mfd_mode = flags;
                mfd->mfd_object = o;
                mfd->mfd_xid = mdt_info_req(info)->rq_xid;

                spin_lock(&med->med_open_lock);
                list_add(&mfd->mfd_list, &med->med_open_head);
                spin_unlock(&med->med_open_lock);

                repbody->handle.cookie = mfd->mfd_handle.h_cookie;
        } else 
                rc = -ENOMEM;

        RETURN(rc);
}

int mdt_open_by_fid(struct mdt_thread_info* info, const struct lu_fid *fid,
                    __u32 flags)
{
        struct mdt_object *o;
        struct lu_attr    *la = &info->mti_attr.ma_attr;
        int                rc;
        ENTRY;

        o = mdt_object_find(info->mti_ctxt, info->mti_mdt, fid);
        if (!IS_ERR(o)) {
                if (mdt_object_exists(info->mti_ctxt, &o->mot_obj.mo_lu)) {
                        if (la->la_flags & MDS_OPEN_EXCL &&
                            la->la_flags & MDS_OPEN_CREAT)
                                rc = -EEXIST;
                        else 
                                rc = mdt_mfd_open(info, o, flags, 0);
                } else {
                        rc = -ENOENT;
                        if (la->la_flags & MDS_OPEN_CREAT) {
                                rc = mo_object_create(info->mti_ctxt, 
                                                      mdt_object_child(o),
                                                      &info->mti_attr);
                                if (rc == 0)
                                        rc = mdt_mfd_open(info, o, flags, 1);
                        }
                }
                mdt_object_put(info->mti_ctxt, o);
        } else
                rc = PTR_ERR(o);

        RETURN(rc);
}

int mdt_pin(struct mdt_thread_info* info)
{
        struct mdt_body *body;
        int rc;
        ENTRY;
        
        rc = req_capsule_pack(&info->mti_pill);
        if (rc == 0) {
                body = req_capsule_client_get(&info->mti_pill, &RMF_MDT_BODY);
                rc = mdt_open_by_fid(info, &body->fid1, body->flags);
        }
        RETURN(rc);
}

/*  Get an internal lock on the inode number (but not generation) to sync
 *  new inode creation with inode unlink (bug 2029).  If child_lockh is NULL
 *  we just get the lock as a barrier to wait for other holders of this lock,
 *  and drop it right away again. */
int mdt_lock_new_child(struct mdt_thread_info *info, 
                       struct mdt_object *o,
                       struct mdt_lock_handle *child_lockh)
{
        struct mdt_lock_handle lockh;
        int rc;
        ENTRY;
        
        if (child_lockh == NULL)
                child_lockh = &lockh;

        mdt_lock_handle_init(&lockh);
        lockh.mlh_mode = LCK_EX;
        rc = mdt_object_lock(info, o, &lockh, MDS_INODELOCK_UPDATE);

        if (rc != ELDLM_OK)
                CERROR("can not mdt_object_lock: %d\n", rc);
        else if (child_lockh == &lockh)
                mdt_object_unlock(info, o, &lockh);

        RETURN(rc);
}

int mdt_reint_open(struct mdt_thread_info *info)
{
        struct mdt_device      *mdt = info->mti_mdt;
        struct mdt_object      *parent;
        struct mdt_object      *child;
        struct mdt_lock_handle *lh;
        struct ldlm_reply      *ldlm_rep;
        struct lu_fid          *child_fid = &info->mti_tmp_fid1;
        struct md_attr         *ma = &info->mti_attr;
        struct lu_attr         *la = &ma->ma_attr;
        int                     result;
        int                     created = 0;
        struct mdt_reint_record *rr = &info->mti_rr;
        ENTRY;
        
        ma->ma_lmm = req_capsule_server_get(&info->mti_pill,
                                            &RMF_MDT_MD);
        ma->ma_lmm_size = req_capsule_get_size(&info->mti_pill,
                                               &RMF_MDT_MD,
                                               RCL_SERVER);

        if (strlen(rr->rr_name) == 0) {
                /* reint partial remote open */
                RETURN(mdt_open_by_fid(info, rr->rr_fid1, la->la_flags));
        }

        /* we now have no resent message, so it must be an intent */
        /*TODO: remove this and add MDS_CHECK_RESENT if resent enabled*/
        LASSERT(info->mti_pill.rc_fmt == &RQF_LDLM_INTENT_OPEN);

        ldlm_rep = req_capsule_server_get(&info->mti_pill, &RMF_DLM_REP);

        intent_set_disposition(ldlm_rep, DISP_LOOKUP_EXECD);
        lh = &info->mti_lh[MDT_LH_PARENT];
        lh->mlh_mode = LCK_PW;
        parent = mdt_object_find_lock(info, rr->rr_fid1, lh, 
                                      MDS_INODELOCK_UPDATE);
        if (IS_ERR(parent)) {
                /* just simulate child not existing */
                intent_set_disposition(ldlm_rep, DISP_LOOKUP_NEG);
                GOTO(out, result = PTR_ERR(parent));
        }

        result = mdo_lookup(info->mti_ctxt, mdt_object_child(parent),
                            rr->rr_name, child_fid);
        if (result != 0 && result != -ENOENT) {
                GOTO(out_parent, result);
        }

        if (result == -ENOENT) {
                intent_set_disposition(ldlm_rep, DISP_LOOKUP_NEG);
                if (!(la->la_flags & MDS_OPEN_CREAT))
                        GOTO(out_parent, result);
                *child_fid = *info->mti_rr.rr_fid2;
        } else {
                intent_set_disposition(ldlm_rep, DISP_LOOKUP_POS);
                if (la->la_flags & MDS_OPEN_EXCL &&
                    la->la_flags & MDS_OPEN_CREAT)
                        GOTO(out_parent, result = -EEXIST);
        }

        child = mdt_object_find(info->mti_ctxt, mdt, child_fid);
        if (IS_ERR(child))
                GOTO(out_parent, result = PTR_ERR(child));

        if (result == -ENOENT) {
                /* not found and with MDS_OPEN_CREAT: let's create it */
                result = mdo_create(info->mti_ctxt,
                                    mdt_object_child(parent),
                                    rr->rr_name,
                                    mdt_object_child(child),
                                    rr->rr_tgt,
                                    &info->mti_attr);
                intent_set_disposition(ldlm_rep, DISP_OPEN_CREATE);
                if (result != 0)
                        GOTO(out_child, result);
                created = 1;
        }

        /* Open it now. */
        result = mdt_mfd_open(info, child, la->la_flags, created);
        intent_set_disposition(ldlm_rep, DISP_OPEN_OPEN);
        GOTO(finish_open, result);

finish_open:
        if (result != 0 && created) {
                mdo_unlink(info->mti_ctxt, mdt_object_child(parent),
                           mdt_object_child(child), rr->rr_name,
                           &info->mti_attr);
        } 
out_child:
        mdt_object_put(info->mti_ctxt, child);
out_parent:
        mdt_object_unlock_put(info, parent, lh);
out:
        return result;
}

int mdt_mfd_close(const struct lu_context *ctxt,
                  struct mdt_file_data *mfd)
{
        ENTRY;

        if (mfd->mfd_mode & FMODE_WRITE) {
                /*mdt_put_write_access*/
        } else if (mfd->mfd_mode & MDS_FMODE_EXEC) {
                /*mdt_allow_write_access*/
        }

        /* release reference on this object.
         * it will be destroyed by lower layer if necessary.
         */
        mdt_object_put(ctxt, mfd->mfd_object);

        mdt_mfd_free(mfd);
        RETURN(0);
}

int mdt_close(struct mdt_thread_info *info)
{
        struct mdt_export_data *med;
        struct mdt_file_data   *mfd;
        int rc;
        ENTRY;

        med = &mdt_info_req(info)->rq_export->exp_mdt_data;

        spin_lock(&med->med_open_lock);
        mfd = mdt_handle2mfd(&(info->mti_body->handle));
        if (mfd == NULL) {
                spin_unlock(&med->med_open_lock);
                CDEBUG(D_INODE, "no handle for file close: fid = "DFID3
                       ": cookie = "LPX64, PFID3(&info->mti_body->fid1),
                       info->mti_body->handle.cookie);
                rc = -ESTALE;
        } else {
                class_handle_unhash(&mfd->mfd_handle);
                list_del_init(&mfd->mfd_list);
                spin_unlock(&med->med_open_lock);
        
                rc = mdt_handle_last_unlink(info, mfd->mfd_object,
                                            &RQF_MDS_CLOSE_LAST);

                rc = mdt_mfd_close(info->mti_ctxt, mfd);
        }
        RETURN(rc);
}

int mdt_done_writing(struct mdt_thread_info *info)
{
        ENTRY;

        RETURN(0);
}
