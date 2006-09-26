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
struct mdt_file_data *mdt_mfd_new(void)
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
struct mdt_file_data *mdt_handle2mfd(const struct lustre_handle *handle)
{
        ENTRY;
        LASSERT(handle != NULL);
        RETURN(class_handle2object(handle->cookie));
}

/* free mfd */
void mdt_mfd_free(struct mdt_file_data *mfd)
{
        LASSERT(list_empty(&mfd->mfd_handle.h_link));
        LASSERT(list_empty(&mfd->mfd_list));
        OBD_FREE_PTR(mfd);
}

static int mdt_create_data(struct mdt_thread_info *info,
                           struct mdt_object *p, struct mdt_object *o)
{
        struct md_create_spec *spec = &info->mti_spec;
        struct md_attr        *ma = &info->mti_attr;
        int rc;
        ENTRY;

        if (spec->sp_cr_flags & MDS_OPEN_DELAY_CREATE ||
                        !(spec->sp_cr_flags & FMODE_WRITE))
                RETURN(0);

        ma->ma_need = MA_INODE | MA_LOV;
        rc = mdo_create_data(info->mti_ctxt,
                             p ? mdt_object_child(p) : NULL,
                             mdt_object_child(o), spec, ma, &info->mti_uc);
        RETURN(rc);
}

static int mdt_epoch_opened(struct mdt_object *mo)
{
        return mo->mot_epochcount;
}

int mdt_sizeonmds_enabled(struct mdt_object *mo)
{
        return !mo->mot_ioepoch;
}

/* Re-enable Size-on-MDS. */
void mdt_sizeonmds_enable(struct mdt_thread_info *info,
                          struct mdt_object *mo)
{
       spin_lock(&info->mti_mdt->mdt_ioepoch_lock);
       if (info->mti_epoch->ioepoch == mo->mot_ioepoch) {
                mo->mot_ioepoch = 0;
                mo->mot_flags = 0;
       }
       spin_unlock(&info->mti_mdt->mdt_ioepoch_lock);
}

/* Open the epoch. Epoch open is allowed if @writecount is not negative.
 * The epoch and writecount handling is performed under the mdt_ioepoch_lock.
 *
 * @epoch is nonzero during recovery XXX not ready. */
int mdt_epoch_open(struct mdt_thread_info *info, struct mdt_object *o,
                    __u64 epoch)
{
        struct mdt_device *mdt = info->mti_mdt;
        int cancel = 0;
        int rc;
        ENTRY;

        if (!S_ISREG(lu_object_attr(&o->mot_obj.mo_lu)))
                RETURN(0);
        
        spin_lock(&mdt->mdt_ioepoch_lock);
        if (mdt_epoch_opened(o)) {
                /* Epoch continues even if there is no writers yet. */
                CDEBUG(D_INODE, "continue epoch "LPU64" for "DFID"\n",
                       o->mot_ioepoch, PFID(mdt_object_fid(o)));
        } else {
                if (epoch > mdt->mdt_ioepoch)
                        mdt->mdt_ioepoch = epoch;
                else
                        mdt->mdt_ioepoch++;
                o->mot_ioepoch = epoch ? epoch : mdt->mdt_ioepoch;
                CDEBUG(D_INODE, "starting epoch "LPU64" for "DFID"\n",
                       mdt->mdt_ioepoch, PFID(mdt_object_fid(o)));
                cancel = 1;
        }
        o->mot_epochcount++;
        spin_unlock(&mdt->mdt_ioepoch_lock);

        /* Cancel Size-on-MDS attributes on clients if not truncate.
         * In the later case, mdt_reint_setattr will do it. */
        if (cancel && (info->mti_rr.rr_fid1 != NULL)) {
                struct mdt_lock_handle  *lh = &info->mti_lh[MDT_LH_CHILD];
                lh->mlh_mode = LCK_EX;
                rc = mdt_object_lock(info, o, lh, MDS_INODELOCK_UPDATE);
                mdt_object_unlock(info, o, lh, 1);
                RETURN(rc);
        }
        RETURN(0);
}

/* Update the on-disk attributes if needed and re-enable Size-on-MDS caching. */
static int mdt_sizeonmds_update(struct mdt_thread_info *info,
                                struct mdt_object *o)
{
        ENTRY;

        CDEBUG(D_INODE, "Closing epoch "LPU64" on "DFID". Count %d\n",
               o->mot_ioepoch, PFID(mdt_object_fid(o)), o->mot_epochcount);
 
        if (info->mti_attr.ma_attr.la_valid & LA_SIZE)
                /* Do Size-on-MDS attribute update.
                 * Size-on-MDS is re-enabled inside. */
                RETURN(mdt_attr_set(info, o, 0));
        else
                mdt_sizeonmds_enable(info, o);
        RETURN(0);
}

/* Epoch closes.
 * Returns 1 if epoch does not close.
 * Returns 0 if epoch closes.
 * Returns -EAGAIN if epoch closes but an Size-on-MDS Update is still needed
 * from the client. */
static int mdt_epoch_close(struct mdt_thread_info *info, struct mdt_object *o)
{
        int eviction = (mdt_info_req(info) == NULL ? 1 : 0);
        struct lu_attr *la = &info->mti_attr.ma_attr;
        int achange = 0;
        int opened;
        int rc = 1;
        ENTRY;

        if (!S_ISREG(lu_object_attr(&o->mot_obj.mo_lu)))
                RETURN(0);

        spin_lock(&info->mti_mdt->mdt_ioepoch_lock);
        
        /* Epoch closes only if client tells about it or eviction occures. */
        if (eviction || (info->mti_epoch->flags & MF_EPOCH_CLOSE)) {
                LASSERT(o->mot_epochcount);
                o->mot_epochcount--;

                CDEBUG(D_INODE, "Closing epoch "LPU64" on "DFID". Count %d\n",
                       o->mot_ioepoch, PFID(mdt_object_fid(o)),
                       o->mot_epochcount);
                
                if (!eviction)
                        achange = (info->mti_epoch->flags & MF_SOM_CHANGE);
                
                rc = 0;
                if (!eviction && !mdt_epoch_opened(o)) {
                        /* Epoch ends. Is an Size-on-MDS update needed? */
                        if (o->mot_flags & MF_SOM_CHANGE) {
                                /* Some previous writer changed the attribute.
                                 * Do not believe to the current Size-on-MDS
                                 * update, re-ask client. */
                                rc = -EAGAIN;
                        } else if (!(la->la_valid & LA_SIZE) && achange) {
                                /* Attributes were changed by the last writer 
                                 * only but no Size-on-MDS update is received.*/
                                rc = -EAGAIN;
                        }
                }
                
                if (achange || eviction)
                        o->mot_flags |= MF_SOM_CHANGE;
        }
        
        opened = mdt_epoch_opened(o);
        spin_unlock(&info->mti_mdt->mdt_ioepoch_lock);

        /* XXX: if eviction occured, do nothing yet. */
        if ((rc == 0) && !opened && !eviction) {
                /* Epoch ends and wanted Size-on-MDS update is obtained. */
                rc = mdt_sizeonmds_update(info, o);
        }
        RETURN(rc);
}

int mdt_write_get(struct mdt_device *mdt, struct mdt_object *o)
{
        int rc = 0;
        ENTRY;
        spin_lock(&mdt->mdt_ioepoch_lock);
        if (o->mot_writecount < 0)
                rc = -ETXTBSY;
        else
                o->mot_writecount++;
        spin_unlock(&mdt->mdt_ioepoch_lock);
        RETURN(rc);
}

static void mdt_write_put(struct mdt_device *mdt, struct mdt_object *o)
{
        ENTRY;
        spin_lock(&mdt->mdt_ioepoch_lock);
        o->mot_writecount--;
        spin_unlock(&mdt->mdt_ioepoch_lock);
        EXIT;
}

static int mdt_write_deny(struct mdt_device *mdt, struct mdt_object *o)
{
        int rc = 0;
        ENTRY;
        spin_lock(&mdt->mdt_ioepoch_lock);
        if (o->mot_writecount > 0)
                rc = -ETXTBSY;
        else
                o->mot_writecount--;
        spin_unlock(&mdt->mdt_ioepoch_lock);
        RETURN(rc);
}

static void mdt_write_allow(struct mdt_device *mdt, struct mdt_object *o)
{
        ENTRY;
        spin_lock(&mdt->mdt_ioepoch_lock);
        o->mot_writecount++;
        spin_unlock(&mdt->mdt_ioepoch_lock);
        EXIT;
}

/* there can be no real transaction so prepare the fake one */
static void mdt_open_transno(struct mdt_thread_info* info)
{
        struct mdt_device *mdt = info->mti_mdt;
        struct ptlrpc_request *req = mdt_info_req(info);

        if (info->mti_transno != 0) {
                CDEBUG(D_INODE, "(open | create) | replay: transno = %llu,"
                                " last_committed = %llu\n",
                                info->mti_transno,
                                req->rq_export->exp_obd->obd_last_committed);
                return;
        }

        spin_lock(&mdt->mdt_transno_lock);
        info->mti_transno = ++ mdt->mdt_last_transno;
        spin_unlock(&mdt->mdt_transno_lock);

        CDEBUG(D_INODE, "open only: transno = %llu, last_committed = %llu\n",
                        info->mti_transno,
                        req->rq_export->exp_obd->obd_last_committed);

        req->rq_transno = info->mti_transno;
        lustre_msg_set_transno(req->rq_repmsg, info->mti_transno);
        target_committed_to_req(req);
        lustre_msg_set_last_xid(req->rq_repmsg, req->rq_xid);
}

static int mdt_mfd_open(struct mdt_thread_info *info,
                        struct mdt_object *p,
                        struct mdt_object *o,
                        int flags, 
                        int created,
                        struct ldlm_reply *rep)
{
        struct ptlrpc_request  *req = mdt_info_req(info);
        struct mdt_export_data *med = &req->rq_export->exp_mdt_data;
        struct md_attr         *ma  = &info->mti_attr;
        struct lu_attr         *la  = &ma->ma_attr;
        struct mdt_file_data   *mfd;
        struct mdt_body        *repbody;
        int                     rc = 0;
        int                     isreg, isdir, islnk;
        struct list_head        *t;
        ENTRY;

        LASSERT(ma->ma_valid & MA_INODE);

        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);

        isreg = S_ISREG(la->la_mode);
        isdir = S_ISDIR(la->la_mode);
        islnk = S_ISLNK(la->la_mode);
        mdt_pack_attr2body(repbody, la, mdt_object_fid(o));
        mdt_body_reverse_idmap(info, repbody);

        /* if we are following a symlink, don't open; and
         * do not return open handle for special nodes as client required
         */
        if (islnk || (!isreg && !isdir &&
            (req->rq_export->exp_connect_flags & OBD_CONNECT_NODEVOH))) {
                lustre_msg_set_transno(req->rq_repmsg, 0);
                GOTO(out, rc = 0);
        }

        mdt_set_disposition(info, rep, DISP_OPEN_OPEN);
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
                /* in replay case, p == NULL */
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

        mfd = NULL;
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT) {
                spin_lock(&med->med_open_lock);
                list_for_each(t, &med->med_open_head) {
                        mfd = list_entry(t, struct mdt_file_data, mfd_list);
                        if (mfd->mfd_xid == req->rq_xid) {
                                break;
                        }
                        mfd = NULL;
                }
                spin_unlock(&med->med_open_lock);
        
                if (mfd != NULL) {
                        repbody->handle.cookie = mfd->mfd_handle.h_cookie;
                        GOTO(out, rc = 0);
                }
        }

        if (flags & FMODE_WRITE) {
                rc = mdt_write_get(info->mti_mdt, o);
                if (rc == 0) {
                        /* FIXME: in recovery, need to pass old epoch here */
                        mdt_epoch_open(info, o, 0);
                        repbody->ioepoch = o->mot_ioepoch;
                }
        } else if (flags & MDS_FMODE_EXEC) {
                rc = mdt_write_deny(info->mti_mdt, o);
        }
        if (rc)
                RETURN(rc);

        rc = mo_open(info->mti_ctxt, mdt_object_child(o),
                     created ? flags | MDS_OPEN_CREATED : flags,
                     &info->mti_uc);
        if (rc)
                RETURN(rc);

        mfd = mdt_mfd_new();
        if (mfd != NULL) {
                
                /* keep a reference on this object for this open,
                * and is released by mdt_mfd_close() */
                mdt_object_get(info->mti_ctxt, o);
                /* open handling */

                mfd->mfd_mode = flags;
                mfd->mfd_object = o;
                mfd->mfd_xid = req->rq_xid;

                spin_lock(&med->med_open_lock);
                list_add(&mfd->mfd_list, &med->med_open_head);
                spin_unlock(&med->med_open_lock);

                repbody->handle.cookie = mfd->mfd_handle.h_cookie;
                mdt_open_transno(info);
        } else
                rc = -ENOMEM;

out:
        if (rc == 0) {
                if (med->med_rmtclient) {
                        void *buf = req_capsule_server_get(&info->mti_pill,
                                                           &RMF_ACL);

                        rc = mdt_pack_remote_perm(info, o, buf);
                        if (rc == 0) {
                                repbody->valid |= OBD_MD_FLRMTPERM;
                                repbody->aclsize =
                                                sizeof(struct mdt_remote_perm);
                        }
                }
        }

        RETURN(rc);
}

extern void mdt_req_from_mcd(struct ptlrpc_request *req,
                             struct mdt_client_data *mcd);

void mdt_reconstruct_open(struct mdt_thread_info *info,
                          struct mdt_lock_handle *lhc)
{
        const struct lu_context *ctxt = info->mti_ctxt;
        struct mdt_device       *mdt  = info->mti_mdt;
        struct req_capsule      *pill = &info->mti_pill;
        struct ptlrpc_request   *req  = mdt_info_req(info);
        struct mdt_export_data  *med  = &req->rq_export->exp_mdt_data;
        struct mdt_client_data  *mcd  = med->med_mcd;
        struct md_attr          *ma   = &info->mti_attr;
        struct mdt_reint_record *rr   = &info->mti_rr;
        __u32                   flags = info->mti_spec.sp_cr_flags;
        struct ldlm_reply       *ldlm_rep;
        struct mdt_object       *parent;
        struct mdt_object       *child;
        struct mdt_body         *repbody;
        int                      rc;
        ENTRY;

        LASSERT(pill->rc_fmt == &RQF_LDLM_INTENT_OPEN);
        ldlm_rep = req_capsule_server_get(&info->mti_pill, &RMF_DLM_REP);

        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        repbody->eadatasize = 0;
        repbody->aclsize = 0;

        ma->ma_lmm = req_capsule_server_get(&info->mti_pill, &RMF_MDT_MD);
        ma->ma_lmm_size = req_capsule_get_size(&info->mti_pill,
                                               &RMF_MDT_MD,
                                               RCL_SERVER);
        ma->ma_need = MA_INODE | MA_LOV;

        mdt_req_from_mcd(req, med->med_mcd);
        mdt_set_disposition(info, ldlm_rep, mcd->mcd_last_data);

        CERROR("This is reconstruct open: disp="LPX64", result=%d\n",
                ldlm_rep->lock_policy_res1, req->rq_status);

        if (mdt_get_disposition(ldlm_rep, DISP_OPEN_CREATE) && 
            req->rq_status != 0) {
                /* We did not create successfully, return error to client. */
                mdt_shrink_reply(info, DLM_REPLY_REC_OFF + 1);
                GOTO(out, rc = req->rq_status);
        }

        if (mdt_get_disposition(ldlm_rep, DISP_OPEN_CREATE)) {
                /* 
                 * We failed after creation, but we do not know in which step 
                 * we failed. So try to check the child object.
                 */
                parent = mdt_object_find(ctxt, mdt, rr->rr_fid1);
                LASSERT(!IS_ERR(parent));

                child = mdt_object_find(ctxt, mdt, rr->rr_fid2);
                LASSERT(!IS_ERR(child));

                rc = lu_object_exists(&child->mot_obj.mo_lu);
                if (rc > 0) {
                        struct md_object *next;
                        next = mdt_object_child(child);
                        rc = mo_attr_get(ctxt, next, ma, NULL);
                        if (rc == 0)
                              rc = mdt_mfd_open(info, parent, child, 
                                                flags, 1, ldlm_rep);
                } else if (rc < 0) {
                        /* the child object was created on remote server */
                        repbody->fid1 = *rr->rr_fid2;
                        repbody->valid |= (OBD_MD_FLID | OBD_MD_MDS);
                        rc = 0;
                } else if (rc == 0) {
                        /* the child does not exist, we should do regular open */
                        mdt_object_put(ctxt, parent);
                        mdt_object_put(ctxt, child);
                        GOTO(regular_open, 0);
                }
                mdt_object_put(ctxt, parent);
                mdt_object_put(ctxt, child);
                mdt_shrink_reply(info, DLM_REPLY_REC_OFF + 1);
                GOTO(out, rc);
        } else {
regular_open:
                /* We did not try to create, so we are a pure open */
                rc = mdt_reint_open(info, lhc);
        }

        EXIT;
out:
        req->rq_status = rc;
        lustre_msg_set_status(req->rq_repmsg, req->rq_status);
}

static int mdt_open_by_fid(struct mdt_thread_info* info, 
                           struct ldlm_reply *rep)
{
        __u32                    flags = info->mti_spec.sp_cr_flags;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct md_attr          *ma = &info->mti_attr;
        struct mdt_object       *o;
        int                     rc;
        ENTRY;

        o = mdt_object_find(info->mti_ctxt, info->mti_mdt, rr->rr_fid2);
        if (IS_ERR(o)) 
                RETURN(rc = PTR_ERR(o));

        rc = lu_object_exists(&o->mot_obj.mo_lu);

        if (rc > 0) {
                const struct lu_context *ctxt = info->mti_ctxt;

                mdt_set_disposition(info, rep, DISP_IT_EXECD);
                mdt_set_disposition(info, rep, DISP_LOOKUP_EXECD);
                mdt_set_disposition(info, rep, DISP_LOOKUP_POS);
                rc = mo_attr_get(ctxt, mdt_object_child(o), ma, NULL);
                if (rc == 0)
                        rc = mdt_mfd_open(info, NULL, o, flags, 0, rep);
        } else if (rc == 0) {
                rc = -ENOENT;
        } else  {
                /* the child object was created on remote server */
                struct mdt_body *repbody;
                repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
                repbody->fid1 = *rr->rr_fid2;
                repbody->valid |= (OBD_MD_FLID | OBD_MD_MDS);
                rc = 0;
        }
        mdt_object_put(info->mti_ctxt, o);
        RETURN(rc);
}

int mdt_pin(struct mdt_thread_info* info)
{
        ENTRY;
        RETURN(-EOPNOTSUPP);
}

/* Cross-ref request. Currently it can only be a pure open (w/o create) */
static int mdt_cross_open(struct mdt_thread_info* info,
                          const struct lu_fid *fid,
                          struct ldlm_reply *rep, __u32 flags)
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
                rc = mo_attr_get(info->mti_ctxt, mdt_object_child(o), ma, NULL);
                if (rc == 0)
                        rc = mdt_mfd_open(info, NULL, o, flags, 0, rep);
        } else if (rc == 0) {
                /*
                 * FIXME: something wrong here lookup was positive but there is
                 * no object!
                 */
                CERROR("Cross-ref object doesn't exists!\n");
                rc = -EFAULT;
        } else  {
                /* FIXME: something wrong here the object is on another MDS! */
                CERROR("The object isn't on this server! FLD error?\n");
                rc = -EFAULT;
        }
        mdt_object_put(info->mti_ctxt, o);
        RETURN(rc);
}

int mdt_reint_open(struct mdt_thread_info *info, struct mdt_lock_handle *lhc)
{
        struct mdt_device      *mdt = info->mti_mdt;
        struct ptlrpc_request  *req = mdt_info_req(info);
        struct mdt_object      *parent;
        struct mdt_object      *child;
        struct mdt_lock_handle *lh;
        struct ldlm_reply      *ldlm_rep;
        struct mdt_body        *repbody;
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

        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        repbody->eadatasize = 0;
        repbody->aclsize = 0;

        ma->ma_lmm = req_capsule_server_get(&info->mti_pill, &RMF_MDT_MD);
        ma->ma_lmm_size = req_capsule_get_size(&info->mti_pill,
                                               &RMF_MDT_MD,
                                               RCL_SERVER);
        ma->ma_need = MA_INODE | MA_LOV;

        LASSERT(info->mti_pill.rc_fmt == &RQF_LDLM_INTENT_OPEN);
        ldlm_rep = req_capsule_server_get(&info->mti_pill, &RMF_DLM_REP);

        /* TODO: JOIN file */
        if (create_flags & MDS_OPEN_JOIN_FILE) {
                CERROR("JOIN file will be supported soon\n");
                GOTO(out, result = -EOPNOTSUPP);
        }

        CDEBUG(D_INODE, "I am going to open "DFID"/("DFID":%s) "
                        "cr_flag=0%o mode=0%06o msg_flag=0x%x\n",
                        PFID(rr->rr_fid1), PFID(rr->rr_fid2),
                        rr->rr_name, create_flags, la->la_mode,
                        lustre_msg_get_flags(req->rq_reqmsg));

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                /* This is a replay request. */
                result = mdt_open_by_fid(info, ldlm_rep);

                if (result != -ENOENT)
                        GOTO(out, result);

                /*
                 * We didn't find the correct object, so we need to re-create it
                 * via a regular replay.
                 */
                if (!(create_flags & MDS_OPEN_CREAT)) {
                        DEBUG_REQ(D_ERROR, req,"OPEN_CREAT not in open replay");
                        GOTO(out, result = -EFAULT);
                }
                CDEBUG(D_INFO, "open replay failed to find object, "
                               "continue as regular open\n");
        }

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_OPEN_PACK))
                GOTO(out, result = -ENOMEM);

        mdt_set_disposition(info, ldlm_rep, DISP_IT_EXECD);
        mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_EXECD);
        if (rr->rr_name[0] == 0) {
                /* this is cross-ref open */
                mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);
                result = mdt_cross_open(info, rr->rr_fid1, ldlm_rep, create_flags);
                GOTO(out, result);
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
                            rr->rr_name, child_fid, &info->mti_uc);
        if (result != 0 && result != -ENOENT && result != -ESTALE)
                GOTO(out_parent, result);

        if (result == -ENOENT || result == -ESTALE) {
                mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_NEG);
                if (result == -ESTALE) {
                        /*
                         * ESTALE means the parent is a dead(unlinked) dir, so
                         * it should return -ENOENT to in accordance with the
                         * original mds implementaion.
                         */
                        GOTO(out_parent, result = -ENOENT);
                }
                if (!(create_flags & MDS_OPEN_CREAT))
                        GOTO(out_parent, result);
                *child_fid = *info->mti_rr.rr_fid2;
                /* new object will be created. see the following */
        } else {
                /*
                 * Check for O_EXCL is moved to the mdt_mfd_open, we need to
                 * return FID back in that case.
                 */
                mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);
        }

        child = mdt_object_find(info->mti_ctxt, mdt, child_fid);
        if (IS_ERR(child))
                GOTO(out_parent, result = PTR_ERR(child));

        if (result == -ENOENT) {
                /* Not found and with MDS_OPEN_CREAT: let's create it. */
                mdt_set_disposition(info, ldlm_rep, DISP_OPEN_CREATE);
                result = mdo_create(info->mti_ctxt,
                                    mdt_object_child(parent),
                                    rr->rr_name,
                                    mdt_object_child(child),
                                    &info->mti_spec,
                                    &info->mti_attr,
                                    &info->mti_uc);
                if (result == -ERESTART) {
                        mdt_clear_disposition(info, ldlm_rep, DISP_OPEN_CREATE);        
                        GOTO(out_child, result);
                }
                else {        
                        if (result != 0)
                                GOTO(out_child, result);
                }
                created = 1;
        } else {
                /* We have to get attr & lov ea for this object */
                result = mo_attr_get(info->mti_ctxt, mdt_object_child(child),
                                     ma, NULL);
                /*
                 * The object is on remote node, return its FID for remote open.
                 */
                if (result == -EREMOTE) {
                        int rc;
                        
                        /* 
                         * Check if this lock already was sent to client and
                         * this is resent case. For resent case do not take lock
                         * again, use what is already granted.
                         */
                        LASSERT(lhc != NULL);
                        
                        if (lustre_handle_is_used(&lhc->mlh_lh)) {
                                struct ldlm_lock *lock;
                                
                                LASSERT(lustre_msg_get_flags(req->rq_reqmsg) &
                                        MSG_RESENT);
                                
                                lock = ldlm_handle2lock(&lhc->mlh_lh);
                                if (!lock) {
                                        CERROR("Invalid lock handle "LPX64"\n",
                                               lhc->mlh_lh.cookie);
                                        LBUG();
                                }
                                LASSERT(fid_res_name_eq(mdt_object_fid(child),
                                                        &lock->l_resource->lr_name));
                                LDLM_LOCK_PUT(lock);
                                rc = 0;
                        } else {
                                mdt_lock_handle_init(lhc);
                                lhc->mlh_mode = LCK_CR;
                                
                                rc = mdt_object_lock(info, child, lhc,
                                                     MDS_INODELOCK_LOOKUP);
                        }
                        repbody->fid1 = *mdt_object_fid(child);
                        repbody->valid |= (OBD_MD_FLID | OBD_MD_MDS);
                        if (rc != 0)
                                result = rc;
                        GOTO(out_child, result);
                }
        }

        /* Try to open it now. */
        result = mdt_mfd_open(info, parent, child, create_flags, 
                              created, ldlm_rep);
        GOTO(finish_open, result);

finish_open:
        if (result != 0 && created) {
                int rc2;
                ma->ma_need = 0;
                ma->ma_cookie_size = 0;
                rc2 = mdo_unlink(info->mti_ctxt,
                                 mdt_object_child(parent),
                                 mdt_object_child(child),
                                 rr->rr_name,
                                 &info->mti_attr,
                                 &info->mti_uc);
                if (rc2 != 0)
                        CERROR("error in cleanup of open");
        }
out_child:
        mdt_object_put(info->mti_ctxt, child);
out_parent:
        mdt_object_unlock_put(info, parent, lh, result);
out:
        mdt_shrink_reply(info, DLM_REPLY_REC_OFF + 1);
        if (result)
                lustre_msg_set_transno(req->rq_repmsg, 0);
        return result;
}

#define MFD_CLOSED(mode) (((mode) & ~(FMODE_EPOCH | FMODE_SOM | \
                                      FMODE_EPOCHLCK)) == FMODE_CLOSED)

static int mdt_mfd_closed(struct mdt_file_data *mfd)
{
        return ((mfd == NULL) || MFD_CLOSED(mfd->mfd_mode));
}

int mdt_mfd_close(struct mdt_thread_info *info, struct mdt_file_data *mfd)
{
        struct mdt_object *o = mfd->mfd_object;
        struct md_object *next = mdt_object_child(o);
        struct md_attr *ma = &info->mti_attr;
        int rc = 0, ret = 0;
        int mode;
        ENTRY;

        mode = mfd->mfd_mode;
        mfd->mfd_mode = FMODE_CLOSED;

        if ((mode & FMODE_WRITE) || (mode & FMODE_EPOCHLCK)) {
                mdt_write_put(info->mti_mdt, o);
                ret = mdt_epoch_close(info, o);
        } else if (mode & MDS_FMODE_EXEC) {
                mdt_write_allow(info->mti_mdt, o);
        } else if (mode & FMODE_EPOCH) {
                ret = mdt_epoch_close(info, o);
        }

        ma->ma_need |= MA_INODE;
                
        if (!MFD_CLOSED(mode))
                rc = mo_close(info->mti_ctxt, next, ma, NULL);
        else if (ret == -EAGAIN)
                rc = mo_attr_get(info->mti_ctxt, next, ma, NULL);

        /* If the object is unlinked, do not try to re-enable SIZEONMDS */
        if ((ret == -EAGAIN) && (ma->ma_valid & MA_INODE) &&
            (ma->ma_attr.la_nlink == 0))
        {
                ret = 0;
        }

        if ((ret == -EAGAIN) || (ret == 1)) {
                struct mdt_export_data *med;
                /* The epoch has not closed or Size-on-MDS update is needed.
                 * Put mfd back into the list. */
                mfd->mfd_mode = (ret == 1 ? FMODE_EPOCH : FMODE_SOM);

                LASSERT(mdt_info_req(info));
                med = &mdt_info_req(info)->rq_export->exp_mdt_data;
                spin_lock(&med->med_open_lock);
                list_add(&mfd->mfd_list, &med->med_open_head);
                class_handle_hash_back(&mfd->mfd_handle);
                spin_unlock(&med->med_open_lock);
                if (ret == 1)
                        ret = 0;
                else {
                        CDEBUG(D_INODE, "Size-on-MDS attribute update is "
                               "needed on "DFID"\n", PFID(mdt_object_fid(o)));
                }
        } else {
                mdt_mfd_free(mfd);
                mdt_object_put(info->mti_ctxt, o);
        }

        RETURN(rc ? rc : ret);
}

int mdt_close(struct mdt_thread_info *info)
{
        struct mdt_export_data *med;
        struct mdt_file_data   *mfd;
        struct mdt_object      *o;
        struct md_attr         *ma = &info->mti_attr;
        struct mdt_body        *repbody = NULL;
        int rc, ret = 0;
        ENTRY;

        /* Close may come with the Size-on-MDS update. Unpack it. */
        rc = mdt_close_unpack(info);
        if (rc)
                RETURN(rc);

        LASSERT(info->mti_epoch);

        req_capsule_set_size(&info->mti_pill, &RMF_MDT_MD, RCL_SERVER,
                             info->mti_mdt->mdt_max_mdsize);
        req_capsule_set_size(&info->mti_pill, &RMF_LOGCOOKIES, RCL_SERVER,
                             info->mti_mdt->mdt_max_cookiesize);
        rc = req_capsule_pack(&info->mti_pill);
        /* Continue to close handle even if we can not pack reply */
        if (rc == 0) {
                repbody = req_capsule_server_get(&info->mti_pill, 
                                                 &RMF_MDT_BODY);
                ma->ma_lmm = req_capsule_server_get(&info->mti_pill, 
                                                    &RMF_MDT_MD);
                ma->ma_lmm_size = req_capsule_get_size(&info->mti_pill,
                                                       &RMF_MDT_MD,
                                                       RCL_SERVER);
                ma->ma_cookie = req_capsule_server_get(&info->mti_pill,
                                                       &RMF_LOGCOOKIES);
                ma->ma_cookie_size = req_capsule_get_size(&info->mti_pill,
                                                          &RMF_LOGCOOKIES,
                                                          RCL_SERVER);
                ma->ma_need = MA_INODE | MA_LOV | MA_COOKIE;
                repbody->eadatasize = 0;
                repbody->aclsize = 0;
        }

        med = &mdt_info_req(info)->rq_export->exp_mdt_data;

        spin_lock(&med->med_open_lock);
        mfd = mdt_handle2mfd(&(info->mti_epoch->handle));
        if (mdt_mfd_closed(mfd)) {
                spin_unlock(&med->med_open_lock);
                CDEBUG(D_INODE, "no handle for file close: fid = "DFID
                       ": cookie = "LPX64"\n", PFID(info->mti_rr.rr_fid1),
                       info->mti_epoch->handle.cookie);
                rc = -ESTALE;
        } else {
                class_handle_unhash(&mfd->mfd_handle);
                list_del_init(&mfd->mfd_list);
                spin_unlock(&med->med_open_lock);

                /* Do not lose object before last unlink. */
                o = mfd->mfd_object;
                mdt_object_get(info->mti_ctxt, o);
                ret = mdt_mfd_close(info, mfd);
                if (repbody != NULL)
                        rc = mdt_handle_last_unlink(info, o, ma);
                mdt_object_put(info->mti_ctxt, o);
        }
        if (repbody != NULL)
                mdt_shrink_reply(info, REPLY_REC_OFF + 1);

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_CLOSE_PACK))
                RETURN(-ENOMEM);
        
        RETURN(rc ? rc : ret);
}

int mdt_done_writing(struct mdt_thread_info *info)
{
        struct mdt_body        *repbody = NULL;
        struct mdt_export_data *med;
        struct mdt_file_data   *mfd;
        int rc;
        ENTRY;

        rc = req_capsule_pack(&info->mti_pill);
        if (rc)
                RETURN(rc);
        
        repbody = req_capsule_server_get(&info->mti_pill, 
                                         &RMF_MDT_BODY);
        repbody->eadatasize = 0;
        repbody->aclsize = 0;

        /* Done Writing may come with the Size-on-MDS update. Unpack it. */
        rc = mdt_close_unpack(info);
        if (rc)
                RETURN(rc);

        med = &mdt_info_req(info)->rq_export->exp_mdt_data;
        spin_lock(&med->med_open_lock);
        mfd = mdt_handle2mfd(&(info->mti_epoch->handle));
        if (mfd == NULL) {
                spin_unlock(&med->med_open_lock);
                CDEBUG(D_INODE, "no handle for file close: fid = "DFID
                       ": cookie = "LPX64"\n", PFID(info->mti_rr.rr_fid1),
                       info->mti_epoch->handle.cookie);
                rc = -ESTALE;
        } else {
                LASSERT((mfd->mfd_mode == FMODE_EPOCH) || 
                        (mfd->mfd_mode == FMODE_EPOCHLCK));
                class_handle_unhash(&mfd->mfd_handle);
                list_del_init(&mfd->mfd_list);
                spin_unlock(&med->med_open_lock);

                /* Set EPOCH CLOSE flag if not set by client. */
                info->mti_epoch->flags |= MF_EPOCH_CLOSE;
                rc = mdt_mfd_close(info, mfd);
        }
        RETURN(rc);
}
