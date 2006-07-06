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

/*
 * MDS file data handling: file data holds a handle for a file opened
 * by a client.
 */

static void mdt_mfd_get(void *mfdp)
{
        struct mdt_file_data *mfd = mfdp;

        atomic_inc(&mfd->mfd_refcount);
        CDEBUG(D_INFO, "GETting mfd %p : new refcount %d\n", mfd,
               atomic_read(&mfd->mfd_refcount));
}

/* Create a new mdt_file_data struct. 
 * reference is set to 1 */
static struct mdt_file_data *mdt_mfd_new(void)
{
        struct mdt_file_data *mfd;

        OBD_ALLOC_PTR(mfd);
        if (mfd == NULL) {
                CERROR("mds: out of memory\n");
                return NULL;
        }

        atomic_set(&mfd->mfd_refcount, 1);

        INIT_LIST_HEAD(&mfd->mfd_handle.h_link);
        INIT_LIST_HEAD(&mfd->mfd_list);
        class_handle_hash(&mfd->mfd_handle, mdt_mfd_get);

        return mfd;
}

/* Get a new reference on the mfd pointed to by handle, if handle is still
 * valid.  Caller must drop reference with mdt_mfd_put(). */
static struct mdt_file_data *mdt_handle2mfd(const struct lustre_handle *handle)
{
        ENTRY;
        LASSERT(handle != NULL);
        RETURN(class_handle2object(handle->cookie));
}

/* Drop mfd reference, freeing struct if this is the last one. */
static void mdt_mfd_put(struct mdt_file_data *mfd)
{
        CDEBUG(D_INFO, "PUTting mfd %p : new refcount %d\n", mfd,
               atomic_read(&mfd->mfd_refcount) - 1);
        LASSERT(atomic_read(&mfd->mfd_refcount) > 0 &&
                atomic_read(&mfd->mfd_refcount) < 0x5a5a);
        if (atomic_dec_and_test(&mfd->mfd_refcount)) {
                LASSERT(list_empty(&mfd->mfd_handle.h_link));
                OBD_FREE_PTR(mfd);
        }
}

static int mdt_object_open(struct mdt_thread_info *info,
                           struct mdt_object *o, 
                           int flags)
{
        struct mdt_export_data *med;
        struct mdt_file_data   *mfd;
        struct mdt_body        *repbody;
        struct lov_mds_md      *lmm;
        int                     rc = 0;
        ENTRY;

        med = &mdt_info_req(info)->rq_export->exp_mdt_data;
        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        lmm = req_capsule_server_get(&info->mti_pill, &RMF_MDT_MD);

        rc = mo_attr_get(info->mti_ctxt, mdt_object_child(o),
                         &info->mti_attr);
        if (rc != 0)
                GOTO(out, rc);

        mdt_pack_attr2body(repbody, &info->mti_attr);
        repbody->fid1 = *mdt_object_fid(o);
        repbody->valid |= OBD_MD_FLID;

        rc = mo_xattr_get(info->mti_ctxt, mdt_object_child(o),
                          lmm, info->mti_mdt->mdt_max_mdsize, "lov");
        if (rc < 0)
                GOTO(out, rc = -EINVAL);

        if (S_ISDIR(info->mti_attr.la_mode))
                repbody->valid |= OBD_MD_FLDIREA;
        else
                repbody->valid |= OBD_MD_FLEASIZE;
        repbody->eadatasize = rc;
        rc = 0;

        mfd = mdt_mfd_new();
        if (mfd == NULL) {
                CERROR("mds: out of memory\n");
                GOTO(out, rc = -ENOMEM);
        }

        if (flags & FMODE_WRITE) {
                /*mds_get_write_access*/
        } else if (flags & MDS_FMODE_EXEC) {
                /*mds_deny_write_access*/
        }

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

        RETURN(rc);
out:
        return rc;
}

int mdt_pin(struct mdt_thread_info* info)
{
        struct mdt_object *o;
        int rc;
        ENTRY;

        o = mdt_object_find(info->mti_ctxt, info->mti_mdt, &info->mti_body->fid1);
        if (!IS_ERR(o)) {
                if (mdt_object_exists(info->mti_ctxt, &o->mot_obj.mo_lu)) {
                        rc = mdt_object_open(info, o, info->mti_body->flags);
                        mdt_object_put(info->mti_ctxt, o);
                } else
                        rc = -ENOENT;
        } else
                rc = PTR_ERR(o);

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
        
        if (child_lockh == NULL)
                child_lockh = &lockh;

        lockh.mlh_mode = LCK_EX;
        rc = mdt_object_lock(info->mti_mdt->mdt_namespace, 
                             o, &lockh, MDS_INODELOCK_UPDATE);

        if (rc != ELDLM_OK)
                CERROR("can not mdt_object_lock: %d\n", rc);
        else if (child_lockh == &lockh)
                mdt_object_unlock(info->mti_mdt->mdt_namespace, 
                                  o, &lockh);

        RETURN(rc);
}

int mdt_reint_open(struct mdt_thread_info *info)
{
        struct mdt_device      *mdt = info->mti_mdt;
        struct mdt_object      *parent;
        struct mdt_object      *child;
        struct mdt_lock_handle *lh;
        struct ldlm_reply      *ldlm_rep;
        struct ptlrpc_request  *req = mdt_info_req(info);
        struct mdt_body        *body;
        struct lu_fid           child_fid;
        int                     result;
        int                     created = 0;
        struct mdt_reint_record *rr = &info->mti_rr;
        ENTRY;

        /* we now have no resent message, so it must be an intent */
        LASSERT(info->mti_pill.rc_fmt == &RQF_LDLM_INTENT_OPEN);

        /*TODO: MDS_CHECK_RESENT */;

        ldlm_rep = req_capsule_server_get(&info->mti_pill, &RMF_DLM_REP);
        body = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);

        lh = &info->mti_lh[MDT_LH_PARENT];
        lh->mlh_mode = LCK_PW;
        parent = mdt_object_find_lock(info->mti_ctxt, mdt, rr->rr_fid1,
                                      lh, MDS_INODELOCK_UPDATE);
        if (IS_ERR(parent))
                GOTO(out, result = PTR_ERR(parent));

        result = mdo_lookup(info->mti_ctxt, mdt_object_child(parent),
                            rr->rr_name, &child_fid);
        if (result && result != -ENOENT) {
                GOTO(out_parent, result);
        }

        intent_set_disposition(ldlm_rep, DISP_LOOKUP_EXECD);

        if (result == -ENOENT) {
                intent_set_disposition(ldlm_rep, DISP_LOOKUP_NEG);
                if (!(info->mti_attr.la_flags & MDS_OPEN_CREAT))
                        GOTO(out_parent, result);
                if (req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                        GOTO(out_parent, result = -EROFS);
                child_fid = *info->mti_rr.rr_fid2;
        } else {
                intent_set_disposition(ldlm_rep, DISP_LOOKUP_POS);
                if (info->mti_attr.la_flags & MDS_OPEN_EXCL &&
                    info->mti_attr.la_flags & MDS_OPEN_CREAT)
                        GOTO(out_parent, result = -EEXIST);

        }

        child = mdt_object_find(info->mti_ctxt, mdt, &child_fid);
        if (IS_ERR(child))
                GOTO(out_parent, result = PTR_ERR(child));

        if (result == -ENOENT) {
                /* not found and with MDS_OPEN_CREAT: let's create something */
                result = mdo_create(info->mti_ctxt,
                                    mdt_object_child(parent),
                                    rr->rr_name,
                                    mdt_object_child(child),
                                    &info->mti_attr);
                intent_set_disposition(ldlm_rep, DISP_OPEN_CREATE);
                if (result != 0)
                        GOTO(out_child, result);
                created = 1;
        } else
                intent_set_disposition(ldlm_rep, DISP_OPEN_OPEN);

        /* Open it now. */
        result = mdt_object_open(info, child, info->mti_attr.la_flags);
        GOTO(destroy_child, result);

destroy_child:
        if (result != 0 && created) {
                mdo_unlink(info->mti_ctxt, mdt_object_child(parent),
                           mdt_object_child(child), rr->rr_name);
        } else if (created) {
                mdt_lock_new_child(info, child, NULL);
        }
out_child:
        mdt_object_put(info->mti_ctxt, child);
out_parent:
        mdt_object_unlock(mdt->mdt_namespace, parent, lh);
        mdt_object_put(info->mti_ctxt, parent);
out:
        return result;
}

int mdt_mfd_close(const struct lu_context *ctxt,
                  struct mdt_file_data *mfd, 
                  int unlink_orphan)
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

        mdt_mfd_put(mfd);
        RETURN(0);
}

int mdt_close(struct mdt_thread_info *info)
{
        struct mdt_export_data *med;
        struct mdt_body        *repbody;
        struct mdt_file_data   *mfd;
        struct mdt_object      *o;
        struct lov_mds_md      *lmm;
        int rc;
        ENTRY;

        med = &mdt_info_req(info)->rq_export->exp_mdt_data;
        LASSERT(med);        

        spin_lock(&med->med_open_lock);
        mfd = mdt_handle2mfd(&(info->mti_body->handle));
        if (mfd == NULL) {
                spin_unlock(&med->med_open_lock);
                CDEBUG(D_INODE, "no handle for file close ino "DFID3
                       ": cookie "LPX64, PFID3(&info->mti_body->fid1), 
                       info->mti_body->handle.cookie);
                RETURN(-ESTALE);
        }
        class_handle_unhash(&mfd->mfd_handle);
        list_del_init(&mfd->mfd_list);
        spin_unlock(&med->med_open_lock);

        o = mfd->mfd_object;
        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        lmm = req_capsule_server_get(&info->mti_pill, &RMF_MDT_MD);

        rc = mo_attr_get(info->mti_ctxt, mdt_object_child(o),
                         &info->mti_attr);
        if (rc == 0) {
                mdt_pack_attr2body(repbody, &info->mti_attr);
                repbody->fid1 = *mdt_object_fid(o);
                repbody->valid |= OBD_MD_FLID;

                rc = mo_xattr_get(info->mti_ctxt, mdt_object_child(o),
                                  lmm, info->mti_mdt->mdt_max_mdsize, "lov");
                if (rc >= 0) {
                        if (S_ISDIR(info->mti_attr.la_mode))
                                repbody->valid |= OBD_MD_FLDIREA;
                        else
                                repbody->valid |= OBD_MD_FLEASIZE;
                        repbody->eadatasize = rc;
                        rc = 0;
                }
        }

        rc = mdt_mfd_close(info->mti_ctxt, mfd, 1);

        RETURN(rc);
}

int mdt_done_writing(struct mdt_thread_info *info)
{
        ENTRY;

        RETURN(0);
}
