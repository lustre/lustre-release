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

#include <linux/lustre_acl.h>
#include <lustre_mds.h>
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
        }
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
        LASSERT(list_empty(&mfd->mfd_list));
        OBD_FREE_PTR(mfd);
}

static int mdt_create_data(struct mdt_thread_info *info,
                           struct mdt_object *p, struct mdt_object *o)
{
        struct md_attr   *ma = &info->mti_attr;
        /* XXX: md_create_spec using should be made clear
         * struct mdt_reint_record *mrr = &info->mti_rr;
         */
        struct md_create_spec *spec = &info->mti_spec;

        ma->ma_need = MA_INODE | MA_LOV;
        return mdo_create_data(info->mti_ctxt, mdt_object_child(p),
                               mdt_object_child(o), spec, ma);
}


/*The following four functions are copied from MDS */

/* Write access to a file: executors cause a negative count,
 * writers a positive count.  The semaphore is needed to perform
 * a check for the sign and then increment or decrement atomically.
 *
 * This code is closely tied to the allocation of the d_fsdata and the
 * MDS epoch, so we use the same semaphore for the whole lot.
 *
 * FIXME and TODO : handle the epoch!
 * epoch argument is nonzero during recovery */
static int mdt_get_write_access(struct mdt_device *mdt, struct mdt_object *o,
                                __u64 epoch)
{
        int rc = 0;
        ENTRY;

        spin_lock(&mdt->mdt_epoch_lock);

        if (o->mot_writecount < 0) {
                rc = -ETXTBSY;
        } else {
                if (o->mot_io_epoch != 0) {
                        CDEBUG(D_INODE, "continue epoch "LPU64" for "DFID"\n",
                               o->mot_io_epoch, PFID(mdt_object_fid(o)));
                } else {
                        if (epoch > mdt->mdt_io_epoch)
                                mdt->mdt_io_epoch = epoch;
                        else
                                mdt->mdt_io_epoch++;
                        o->mot_io_epoch = mdt->mdt_io_epoch;
                        CDEBUG(D_INODE, "starting epoch "LPU64" for "DFID"\n",
                               mdt->mdt_io_epoch, PFID(mdt_object_fid(o)));
                }
                o->mot_writecount ++;
        }
        spin_unlock(&mdt->mdt_epoch_lock);
        RETURN(rc);
}

static void  mdt_put_write_access(struct mdt_device *mdt, struct mdt_object *o)
{
        ENTRY;

        spin_lock(&mdt->mdt_epoch_lock);
        o->mot_writecount --;
        if (o->mot_writecount == 0)
                o->mot_io_epoch = 0;
        spin_unlock(&mdt->mdt_epoch_lock);
        EXIT;
}

static int mdt_deny_write_access(struct mdt_device *mdt, struct mdt_object *o)
{
        int rc = 0;
        ENTRY;
        spin_lock(&mdt->mdt_epoch_lock);
        if (o->mot_writecount > 0) {
                rc = -ETXTBSY;
        } else
                o->mot_writecount --;
        spin_unlock(&mdt->mdt_epoch_lock);
        RETURN(rc);
}

static void mdt_allow_write_access(struct mdt_device *mdt, 
                                   struct mdt_object *o)
{
        ENTRY;
        spin_lock(&mdt->mdt_epoch_lock);
        o->mot_writecount ++;
        spin_unlock(&mdt->mdt_epoch_lock);
        EXIT;
}

int mdt_query_write_access(struct mdt_device *mdt, struct mdt_object *o)
{
        int wc;
        ENTRY;

        spin_lock(&mdt->mdt_epoch_lock);
        wc = o->mot_writecount;
        spin_unlock(&mdt->mdt_epoch_lock);

        RETURN(wc);
}

static int mdt_mfd_open(struct mdt_thread_info *info,
                        struct mdt_object *p,
                        struct mdt_object *o,
                        int flags, 
                        int created,
                        struct ldlm_reply *rep)
{
        struct mdt_export_data *med;
        struct mdt_file_data   *mfd;
        struct mdt_device      *mdt = info->mti_mdt;
        struct mdt_body        *repbody;
        struct md_attr         *ma = &info->mti_attr;
        struct lu_attr         *la = &ma->ma_attr;
        struct ptlrpc_request  *req = mdt_info_req(info);
        int                     rc = 0;
        int                     isreg, isdir, islnk;
        ENTRY;

        LASSERT(ma->ma_valid & MA_INODE);

        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        repbody->eadatasize = 0;
        repbody->aclsize = 0;

        isreg = S_ISREG(la->la_mode);
        isdir = S_ISDIR(la->la_mode);
        islnk = S_ISLNK(la->la_mode);
        mdt_pack_attr2body(repbody, la, mdt_object_fid(o));

        /* if we are following a symlink, don't open; and
         * do not return open handle for special nodes as client required
         */
        if (islnk || (!isreg && !isdir &&
            (req->rq_export->exp_connect_flags & OBD_CONNECT_NODEVOH))) {
                info->mti_trans_flags |= MDT_NONEED_TRANSNO;
                RETURN(0);
        }

        intent_set_disposition(rep, DISP_OPEN_OPEN);
        /* we need to return the existing object's fid back, so it is done
         * here, after preparing the reply */
        if (!created && (flags & MDS_OPEN_EXCL) && (flags & MDS_OPEN_CREAT))
                RETURN(-EEXIST);

        /* This can't be done earlier, we need to return reply body */
        if (isdir) {
                if (flags & (MDS_OPEN_CREAT | FMODE_WRITE)) {
                        /* we are trying to create or
                         * write an existing dir. */
                        RETURN(-EISDIR);
                }
        } else if (flags & MDS_OPEN_DIRECTORY)
                RETURN(-ENOTDIR);

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_OPEN_CREATE)) {
                obd_fail_loc = OBD_FAIL_LDLM_REPLY | OBD_FAIL_ONCE;
                RETURN(-EAGAIN);
        }

        if (isreg && !(ma->ma_valid & MA_LOV)) {
                /*No EA, check whether it is will set regEA and dirEA
                 *since in above attr get, these size might be zero,
                 *so reset it, to retrieve the MD after create obj*/
                ma->ma_lmm_size = req_capsule_get_size(&info->mti_pill,
                                                       &RMF_MDT_MD,
                                                       RCL_SERVER);
                /* TODO: handle REPLAY (p == NULL)*/
                rc = mdt_create_data(info, p, o);
                if (rc)
                        RETURN(rc);
        }

        CDEBUG(D_INODE, "after open, ma_valid bit = "LPX64" lmm_size = %d\n",
                        ma->ma_valid, ma->ma_lmm_size);

        if (ma->ma_valid & MA_LOV) {
                LASSERT(ma->ma_lmm_size);
                repbody->eadatasize = ma->ma_lmm_size;
                if (isdir)
                        repbody->valid |= OBD_MD_FLDIREA;
                else
                        repbody->valid |= OBD_MD_FLEASIZE;
        }
        /* FIXME: should determine the offset dynamicly,
         * did not get ACL before shrink. */
        mdt_shrink_reply(info, DLM_REPLY_REC_OFF + 1);


        if (flags & FMODE_WRITE) {
                /* FIXME: in recovery, need to pass old epoch here */
                rc = mdt_get_write_access(mdt, o, 0);
                if (rc == 0)
                        repbody->io_epoch = o->mot_io_epoch;
        } else if (flags & MDS_FMODE_EXEC) {
                rc = mdt_deny_write_access(mdt, o);
        }
        if (rc)
                RETURN(rc);

        rc = mo_open(info->mti_ctxt, mdt_object_child(o), flags);
        if (rc)
                RETURN(rc);
        
        mfd = mdt_mfd_new();
        if (mfd != NULL) {
                /* keep a reference on this object for this open,
                * and is released by mdt_mfd_close() */
                mdt_object_get(info->mti_ctxt, o);
                /* open hanling */

                mfd->mfd_mode = flags;
                mfd->mfd_object = o;
                mfd->mfd_xid = mdt_info_req(info)->rq_xid;

                med = &req->rq_export->exp_mdt_data;
                spin_lock(&med->med_open_lock);
                list_add(&mfd->mfd_list, &med->med_open_head);
                spin_unlock(&med->med_open_lock);

                repbody->handle.cookie = mfd->mfd_handle.h_cookie;
        } else
                rc = -ENOMEM;

        RETURN(rc);
}

static int mdt_open_by_fid(struct mdt_thread_info* info, 
                           const struct lu_fid *fid,
                           struct ldlm_reply *rep, 
                           __u32 flags)
{
        struct md_attr    *ma = &info->mti_attr;
        struct mdt_object *o;
        int                rc;
        ENTRY;

        o = mdt_object_find(info->mti_ctxt, info->mti_mdt, fid);
        if (IS_ERR(o)) 
                RETURN(rc = PTR_ERR(o));

        rc = lu_object_exists(&o->mot_obj.mo_lu);

        if (rc > 0) {
                /* successfully found the child object */
                if (flags & MDS_OPEN_EXCL && flags & MDS_OPEN_CREAT)
                                rc = -EEXIST;
                else {
                        struct txn_param txn;
                        struct thandle *th;
                        struct dt_device *dt = info->mti_mdt->mdt_bottom;
                        txn.tp_credits = 1;

                        LASSERT(dt);
                        th = dt->dd_ops->dt_trans_start(info->mti_ctxt, 
                                                        dt, &txn);
                        if (!IS_ERR(th)) {
                                dt->dd_ops->dt_trans_stop(info->mti_ctxt, th);
                                rc = mo_attr_get(info->mti_ctxt, 
                                                 mdt_object_child(o), ma);
                        }
                        else
                                rc = PTR_ERR(th);
                        if (rc == 0) {
                                intent_set_disposition(rep, DISP_LOOKUP_EXECD);
                                intent_set_disposition(rep, DISP_LOOKUP_POS);
                                intent_set_disposition(rep, DISP_OPEN_OPEN);
                                rc = mdt_mfd_open(info, NULL, o, flags, 0, rep);
                        }
                } 
        } else if (rc == 0) {
                rc = -ENOENT;
        } else  {
                /* the child object was created on remote server */
                struct mdt_body *repbody;
                repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
                repbody->fid1 = *fid;
                repbody->valid |= (OBD_MD_FLID | OBD_MD_MDS);
                rc = 0;
        }
        mdt_object_put(info->mti_ctxt, o);
        RETURN(rc);
}

/* cross-ref request. Currently it can only be a pure open (w/o create) */
int mdt_cross_open(struct mdt_thread_info* info, const struct lu_fid *fid,
                       struct ldlm_reply *rep, __u32 flags)
{
        struct md_attr    *ma = &info->mti_attr;
        struct mdt_object *o;
        int                rc;
        ENTRY;

        LASSERTF(!(flags & MDS_OPEN_CREAT), "Cross-ref open+create!\n");

        o = mdt_object_find(info->mti_ctxt, info->mti_mdt, fid);
        if (IS_ERR(o)) 
                RETURN(rc = PTR_ERR(o));

        rc = lu_object_exists(&o->mot_obj.mo_lu);
        if (rc > 0) {
                struct mdt_device *mdt = info->mti_mdt;
                spin_lock(&mdt->mdt_transno_lock);
                info->mti_transno = ++ mdt->mdt_last_transno;
                spin_unlock(&mdt->mdt_transno_lock);
                rc = mo_attr_get(info->mti_ctxt, mdt_object_child(o), ma);
                if (rc == 0)
                        rc = mdt_mfd_open(info, NULL, o, flags, 0, rep);
        } else if (rc == 0) {
                /* FIXME: something wrong here
                 * lookup was positive but there
                 * is no object! */
                CERROR("Cross-ref object doesn't exists!\n");
                rc = -EFAULT;
        } else  {
                /* FIXME: something wrong here
                 * the object is on another MDS! */
                CERROR("The object isn't on this server! FLD error?\n");
                rc = -EFAULT;
        }
        mdt_object_put(info->mti_ctxt, o);
        RETURN(rc);
}

int mdt_pin(struct mdt_thread_info* info)
{
        ENTRY;
        RETURN(-EOPNOTSUPP);
}

int mdt_open(struct mdt_thread_info *info)
{
        struct mdt_device      *mdt = info->mti_mdt;
        struct ptlrpc_request  *req = mdt_info_req(info);
        struct mdt_object      *parent;
        struct mdt_object      *child;
        struct mdt_lock_handle *lh;
        struct ldlm_reply      *ldlm_rep;
        struct lu_fid          *child_fid = &info->mti_tmp_fid1;
        struct md_attr         *ma = &info->mti_attr;
        struct lu_attr         *la = &ma->ma_attr;
        __u32                   create_flags = info->mti_spec.sp_cr_flags;
        struct mdt_reint_record *rr = &info->mti_rr;
        int                     result;
        int                     created = 0;
        ENTRY;

        OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_PAUSE_OPEN | OBD_FAIL_ONCE,
                         (obd_timeout + 1) / 4);

        req_capsule_set_size(&info->mti_pill, &RMF_MDT_MD, RCL_SERVER,
                             mdt->mdt_max_mdsize);

        result = req_capsule_pack(&info->mti_pill);
        if (result)
                RETURN(result);

        ma->ma_lmm = req_capsule_server_get(&info->mti_pill, &RMF_MDT_MD);
        ma->ma_lmm_size = mdt->mdt_max_mdsize;
        ma->ma_need = MA_INODE | MA_LOV;

        LASSERT(info->mti_pill.rc_fmt == &RQF_LDLM_INTENT_OPEN);
        ldlm_rep = req_capsule_server_get(&info->mti_pill, &RMF_DLM_REP);

        /* TODO: JOIN file */
        if (create_flags & MDS_OPEN_JOIN_FILE) {
                CERROR("JOIN file will be supported soon\n");
                RETURN(-EOPNOTSUPP);
        }

        CDEBUG(D_INODE, "I am going to create "DFID"/("DFID":%s) "
                        "cr_flag=%x mode=%06o replay=%d\n",
                        PFID(rr->rr_fid1), PFID(rr->rr_fid2),
                        rr->rr_name, create_flags, la->la_mode,
                        lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY);

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                /* this is a replay request. */
                result = mdt_open_by_fid(info,rr->rr_fid1, ldlm_rep, 
                                         create_flags);

                if (result != -ENOENT)
                        RETURN(result);

                /* We didn't find the correct object, so we
                 * need to re-create it via a regular replay. */
                if (!(create_flags & MDS_OPEN_CREAT)) {
                        DEBUG_REQ(D_ERROR, req,"OPEN_CREAT not in open replay");
                        RETURN(-EFAULT);
                }
        }

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_OPEN_PACK))
                RETURN(-ENOMEM);

        intent_set_disposition(ldlm_rep, DISP_LOOKUP_EXECD);
        if (rr->rr_name[0] == 0) {
                /* this is cross-ref open */
                intent_set_disposition(ldlm_rep, DISP_LOOKUP_POS);
                result = mdt_cross_open(info, rr->rr_fid1, ldlm_rep, create_flags);
                RETURN(result);
        }

        lh = &info->mti_lh[MDT_LH_PARENT];
        if (!(create_flags & MDS_OPEN_CREAT))
                lh->mlh_mode = LCK_CR;
        else
                lh->mlh_mode = LCK_EX;
        parent = mdt_object_find_lock(info, rr->rr_fid1, lh,
                                      MDS_INODELOCK_UPDATE);
        if (IS_ERR(parent))
                GOTO(out, result = PTR_ERR(parent));

        result = mdo_lookup(info->mti_ctxt, mdt_object_child(parent),
                            rr->rr_name, child_fid);
        if (result != 0 && result != -ENOENT && result != -ESTALE)
                GOTO(out_parent, result);

        if (result == -ENOENT || result == -ESTALE) {
                intent_set_disposition(ldlm_rep, DISP_LOOKUP_NEG);
                if (result == -ESTALE) {
                        /*ESTALE means the parent is a dead(unlinked) dir,
                         *so it should return -ENOENT to in accordance
                         *with the original mds implemantaion.*/
                        GOTO(out_parent, result = -ENOENT);
                }
                if (!(create_flags & MDS_OPEN_CREAT))
                        GOTO(out_parent, result);
                *child_fid = *info->mti_rr.rr_fid2;
                /* new object will be created. see the following */
        } else {
                intent_set_disposition(ldlm_rep, DISP_LOOKUP_POS);
                /* check for O_EXCL is moved to the mdt_mfd_open, we need to
                 * return FID back in that case */
        }

        child = mdt_object_find(info->mti_ctxt, mdt, child_fid);
        if (IS_ERR(child))
                GOTO(out_parent, result = PTR_ERR(child));

        if (result == -ENOENT) {
                /* not found and with MDS_OPEN_CREAT: let's create it */
                intent_set_disposition(ldlm_rep, DISP_OPEN_CREATE);
                result = mdo_create(info->mti_ctxt,
                                    mdt_object_child(parent),
                                    rr->rr_name,
                                    mdt_object_child(child),
                                    &info->mti_spec,
                                    &info->mti_attr);
                if (result != 0)
                        GOTO(out_child, result);
                created = 1;
        } else {
                /* we have to get attr & lov ea for this object*/
                result = mo_attr_get(info->mti_ctxt, 
                                     mdt_object_child(child), ma);
                if (result == -EREMOTE) {
                        struct mdt_body *repbody;

                        repbody = req_capsule_server_get(&info->mti_pill,
                                                         &RMF_MDT_BODY);

                        /* the object is on remote node
                         * return its FID for remote open */
                        repbody->fid1 = *mdt_object_fid(child);
                        repbody->valid |= (OBD_MD_FLID | OBD_MD_MDS);
                        GOTO(out_child, result = 0);
                }
                spin_lock(&mdt->mdt_transno_lock);
                info->mti_transno = ++ mdt->mdt_last_transno;
                spin_unlock(&mdt->mdt_transno_lock);
        }
        /* Try to open it now. */
        result = mdt_mfd_open(info, parent, child, create_flags, 
                              created, ldlm_rep);
        GOTO(finish_open, result);

finish_open:
        if (result != 0 && created) {
                int rc2;
                ma->ma_need = 0;
                rc2 = mdo_unlink(info->mti_ctxt, mdt_object_child(parent),
                                     mdt_object_child(child), rr->rr_name,
                                     &info->mti_attr);
                if (rc2 != 0)
                        CERROR("error in cleanup of open");
        }
out_child:
        mdt_object_put(info->mti_ctxt, child);
out_parent:
        mdt_object_unlock_put(info, parent, lh, result);
out:
        return result;
}

void mdt_mfd_close(const struct lu_context *ctxt,
                   struct mdt_device *mdt, struct mdt_file_data *mfd,
                   struct md_attr *ma)
{
        struct mdt_object *o = mfd->mfd_object;
        ENTRY;

        if (mfd->mfd_mode & FMODE_WRITE) {
                mdt_put_write_access(mdt, o);
        } else if (mfd->mfd_mode & MDS_FMODE_EXEC) {
                mdt_allow_write_access(mdt, o);
        }

        mdt_mfd_free(mfd);

        mo_close(ctxt, mdt_object_child(o), ma);
}

int mdt_close(struct mdt_thread_info *info)
{
        struct mdt_export_data *med;
        struct mdt_file_data   *mfd;
        struct mdt_object      *o;
        struct md_attr         *ma = &info->mti_attr;
        struct mdt_body        *repbody = NULL;
        int rc;
        ENTRY;

        req_capsule_set_size(&info->mti_pill, &RMF_MDT_MD, RCL_SERVER,
                             info->mti_mdt->mdt_max_mdsize);
        req_capsule_set_size(&info->mti_pill, &RMF_LOGCOOKIES, RCL_SERVER,
                             info->mti_mdt->mdt_max_cookiesize);
        rc = req_capsule_pack(&info->mti_pill);
        /* Continue to close handle even if we can not pack reply */
        if (rc == 0) {
                repbody = req_capsule_server_get(&info->mti_pill, 
                                                 &RMF_MDT_BODY);
                repbody->eadatasize = 0;
                repbody->aclsize = 0;
        }

        med = &mdt_info_req(info)->rq_export->exp_mdt_data;

        spin_lock(&med->med_open_lock);
        mfd = mdt_handle2mfd(&(info->mti_body->handle));
        if (mfd == NULL) {
                spin_unlock(&med->med_open_lock);
                CDEBUG(D_INODE, "no handle for file close: fid = "DFID
                       ": cookie = "LPX64"\n", PFID(&info->mti_body->fid1),
                       info->mti_body->handle.cookie);
                rc = -ESTALE;
        } else {
                class_handle_unhash(&mfd->mfd_handle);
                list_del_init(&mfd->mfd_list);
                spin_unlock(&med->med_open_lock);

                if (repbody != NULL) {
                        ma->ma_lmm = 
                                req_capsule_server_get(&info->mti_pill,
                                                       &RMF_MDT_MD);
                        ma->ma_lmm_size = 
                                req_capsule_get_size(&info->mti_pill,
                                                     &RMF_MDT_MD,
                                                     RCL_SERVER);
                        ma->ma_cookie = 
                                req_capsule_server_get(&info->mti_pill,
                                                       &RMF_LOGCOOKIES);
                        ma->ma_cookie_size = 
                                req_capsule_get_size(&info->mti_pill,
                                                     &RMF_LOGCOOKIES,
                                                     RCL_SERVER);
                        ma->ma_need = MA_INODE;
                }
                o = mfd->mfd_object;
                mdt_mfd_close(info->mti_ctxt, info->mti_mdt, mfd, ma);
                if (repbody != NULL)
                        rc = mdt_handle_last_unlink(info, o, ma);

                /* release reference on this object. */
                mdt_object_put(info->mti_ctxt, o);
        }
        if (repbody != NULL)
                mdt_shrink_reply(info, REPLY_REC_OFF + 1);

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_CLOSE_PACK))
                RETURN(-ENOMEM);
        
        RETURN(rc);
}

int mdt_done_writing(struct mdt_thread_info *info)
{
        int rc;
        ENTRY;

        req_capsule_set(&info->mti_pill, &RQF_MDS_DONE_WRITING);
        rc = req_capsule_pack(&info->mti_pill);

        RETURN(0);
}
