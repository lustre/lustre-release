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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mds/mds_open.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Mike Shaver <shaver@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
# include <linux/buffer_head.h>
# include <linux/workqueue.h>
#else
# include <linux/locks.h>
#endif

#include <obd_class.h>
#include <obd_lov.h>
#include <lustre_fsfilt.h>
#include <lprocfs_status.h>

#include "mds_internal.h"

/* Exported function from this file are:
 *
 * mds_open - called by the intent handler
 * mds_close - an rpc handling function
 * mds_pin - an rpc handling function - which will go away
 * mds_mfd_close - for force closing files when a client dies
 */

/*
 * MDS file data handling: file data holds a handle for a file opened
 * by a client.
 */

static void mds_mfd_addref(void *mfdp)
{
        struct mds_file_data *mfd = mfdp;

        atomic_inc(&mfd->mfd_refcount);
        CDEBUG(D_INFO, "GETting mfd %p : new refcount %d\n", mfd,
               atomic_read(&mfd->mfd_refcount));
}

/* Create a new mds_file_data struct.
 * One reference for handle+med_open_head list and dropped by mds_mfd_unlink(),
 * one reference for the caller of this function. */
struct mds_file_data *mds_mfd_new(void)
{
        struct mds_file_data *mfd;

        OBD_ALLOC(mfd, sizeof *mfd);
        if (mfd == NULL) {
                CERROR("mds: out of memory\n");
                return NULL;
        }

        atomic_set(&mfd->mfd_refcount, 2);

        INIT_LIST_HEAD(&mfd->mfd_handle.h_link);
        INIT_LIST_HEAD(&mfd->mfd_list);
        class_handle_hash(&mfd->mfd_handle, mds_mfd_addref);

        return mfd;
}

/* Get a new reference on the mfd pointed to by handle, if handle is still
 * valid.  Caller must drop reference with mds_mfd_put(). */
static struct mds_file_data *mds_handle2mfd(struct lustre_handle *handle)
{
        ENTRY;
        LASSERT(handle != NULL);
        RETURN(class_handle2object(handle->cookie));
}

/* Drop mfd reference, freeing struct if this is the last one. */
static void mds_mfd_put(struct mds_file_data *mfd)
{
        CDEBUG(D_INFO, "PUTting mfd %p : new refcount %d\n", mfd,
               atomic_read(&mfd->mfd_refcount) - 1);
        LASSERT(atomic_read(&mfd->mfd_refcount) > 0 &&
                atomic_read(&mfd->mfd_refcount) < 0x5a5a);
        if (atomic_dec_and_test(&mfd->mfd_refcount)) {
                OBD_FREE_RCU(mfd, sizeof *mfd, &mfd->mfd_handle);
        }
}

/* Remove the mfd handle so that it cannot be found by open/close again.
 * Caller must hold med_open_lock for mfd_list manipulation. */
void mds_mfd_unlink(struct mds_file_data *mfd, int decref)
{
        class_handle_unhash(&mfd->mfd_handle);
        list_del_init(&mfd->mfd_list);
        if (decref)
                mds_mfd_put(mfd);
}

/* Caller must hold mds->mds_epoch_sem */
static int mds_alloc_filterdata(struct inode *inode)
{
        LASSERT(inode->i_filterdata == NULL);
        OBD_ALLOC(inode->i_filterdata, sizeof(struct mds_filter_data));
        if (inode->i_filterdata == NULL)
                return -ENOMEM;
        LASSERT(igrab(inode) == inode);
        return 0;
}

/* Caller must hold mds->mds_epoch_sem */
static void mds_free_filterdata(struct inode *inode)
{
        LASSERT(inode->i_filterdata != NULL);
        OBD_FREE(inode->i_filterdata, sizeof(struct mds_filter_data));
        inode->i_filterdata = NULL;
        iput(inode);
}

/* Write access to a file: executors cause a negative count,
 * writers a positive count.  The semaphore is needed to perform
 * a check for the sign and then increment or decrement atomically.
 *
 * This code is closely tied to the allocation of the d_fsdata and the
 * MDS epoch, so we use the same semaphore for the whole lot.
 *
 * We could use a different semaphore for each file, if it ever shows
 * up in a profile, which it won't.
 *
 * epoch argument is nonzero during recovery */
static int mds_get_write_access(struct mds_obd *mds, struct inode *inode,
                                __u64 epoch)
{
        int rc = 0;

        down(&mds->mds_epoch_sem);

        if (atomic_read(&inode->i_writecount) < 0) {
                up(&mds->mds_epoch_sem);
                RETURN(-ETXTBSY);
        }


        if (MDS_FILTERDATA(inode) && MDS_FILTERDATA(inode)->io_epoch != 0) {
                CDEBUG(D_INODE, "continuing MDS epoch "LPU64" for ino %lu/%u\n",
                       MDS_FILTERDATA(inode)->io_epoch, inode->i_ino,
                       inode->i_generation);
                goto out;
        }

        if (inode->i_filterdata == NULL)
                mds_alloc_filterdata(inode);
        if (inode->i_filterdata == NULL) {
                rc = -ENOMEM;
                goto out;
        }
        if (epoch > mds->mds_io_epoch)
                mds->mds_io_epoch = epoch;
        else
                mds->mds_io_epoch++;
        MDS_FILTERDATA(inode)->io_epoch = mds->mds_io_epoch;
        CDEBUG(D_INODE, "starting MDS epoch "LPU64" for ino %lu/%u\n",
               mds->mds_io_epoch, inode->i_ino, inode->i_generation);
 out:
        if (rc == 0)
                atomic_inc(&inode->i_writecount);
        up(&mds->mds_epoch_sem);
        return rc;
}

/* Returns EAGAIN if the client needs to get size and/or cookies and close
 * again -- which is never true if the file is about to be unlinked.  Otherwise
 * returns the number of remaining writers. */
static int mds_put_write_access(struct mds_obd *mds, struct inode *inode,
                                struct mds_body *body, int unlinking)
{
        int rc = 0;
        ENTRY;

        down(&mds->mds_epoch_sem);
        atomic_dec(&inode->i_writecount);
        rc = atomic_read(&inode->i_writecount);
        if (rc > 0)
                GOTO(out, rc);
#if 0
        if (!unlinking && !(body->valid & OBD_MD_FLSIZE))
                GOTO(out, rc = EAGAIN);
#endif
        mds_free_filterdata(inode);
 out:
        up(&mds->mds_epoch_sem);
        return rc;
}

static int mds_deny_write_access(struct mds_obd *mds, struct inode *inode)
{
        ENTRY;
        down(&mds->mds_epoch_sem);
        if (atomic_read(&inode->i_writecount) > 0) {
                up(&mds->mds_epoch_sem);
                RETURN(-ETXTBSY);
        }
        atomic_dec(&inode->i_writecount);
        up(&mds->mds_epoch_sem);
        RETURN(0);
}

static void mds_allow_write_access(struct inode *inode)
{
        ENTRY;
        atomic_inc(&inode->i_writecount);
}

int mds_query_write_access(struct inode *inode)
{
        ENTRY;
        RETURN(atomic_read(&inode->i_writecount));
}

/* This replaces the VFS dentry_open, it manages mfd and writecount */
static struct mds_file_data *mds_dentry_open(struct dentry *dentry,
                                             struct vfsmount *mnt, int flags,
                                             struct ptlrpc_request *req)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_file_data *mfd;
        struct mds_body *body;
        int error;
        ENTRY;

        mfd = mds_mfd_new();
        if (mfd == NULL) {
                CERROR("mds: out of memory\n");
                GOTO(cleanup_dentry, error = -ENOMEM);
        }

        body = lustre_msg_buf(req->rq_repmsg, DLM_REPLY_REC_OFF, sizeof(*body));

        if (flags & FMODE_WRITE) {
                /* FIXME: in recovery, need to pass old epoch here */
                error = mds_get_write_access(mds, dentry->d_inode, 0);
                if (error)
                        GOTO(cleanup_mfd, error);
                body->io_epoch = MDS_FILTERDATA(dentry->d_inode)->io_epoch;
        } else if (flags & MDS_FMODE_EXEC) {
                error = mds_deny_write_access(mds, dentry->d_inode);
                if (error)
                        GOTO(cleanup_mfd, error);
        }

        dget(dentry);

        /* Mark the file as open to handle open-unlink. */
        MDS_DOWN_WRITE_ORPHAN_SEM(dentry->d_inode);
        mds_orphan_open_inc(dentry->d_inode);
        MDS_UP_WRITE_ORPHAN_SEM(dentry->d_inode);

        mfd->mfd_mode = flags;
        mfd->mfd_dentry = dentry;
        mfd->mfd_xid = req->rq_xid;

        spin_lock(&med->med_open_lock);
        list_add(&mfd->mfd_list, &med->med_open_head);
        spin_unlock(&med->med_open_lock);

        body->handle.cookie = mfd->mfd_handle.h_cookie;

        RETURN(mfd);

cleanup_mfd:
        mds_mfd_put(mfd);
        mds_mfd_unlink(mfd, 1);
cleanup_dentry:
        return ERR_PTR(error);
}

/* Must be called with i_mutex held */
static int mds_create_objects(struct ptlrpc_request *req, int offset,
                              struct mds_update_record *rec,
                              struct mds_obd *mds, struct obd_device *obd,
                              struct dentry *dchild, void **handle,
                              struct lov_mds_md **objid)
{
        struct inode *inode = dchild->d_inode;
        struct obd_trans_info oti = { 0 };
        struct lov_mds_md *lmm = NULL;
        int rc, lmm_size;
        struct mds_body *body;
        struct obd_info oinfo = { { { 0 } } };
        void *lmm_buf;
        ENTRY;

        *objid = NULL;

        if (!S_ISREG(inode->i_mode))
                RETURN(0);
        if (rec->ur_flags & MDS_OPEN_DELAY_CREATE ||
            !(rec->ur_flags & FMODE_WRITE))
                RETURN(0);

        body = lustre_msg_buf(req->rq_repmsg, DLM_REPLY_REC_OFF, sizeof(*body));

        if (body->valid & OBD_MD_FLEASIZE)
                RETURN(0);

        oti_init(&oti, req);

        /* replay case */
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                if (rec->ur_fid2->id == 0) {
                        DEBUG_REQ(D_ERROR, req, "fid2 not set on open replay");
                        RETURN(-EFAULT);
                }

                body->valid |= OBD_MD_FLBLKSZ | OBD_MD_FLEASIZE;
                lmm_size = rec->ur_eadatalen;
                lmm = rec->ur_eadata;
                LASSERT(lmm);

                if (*handle == NULL)
                        *handle = fsfilt_start(obd,inode,FSFILT_OP_CREATE,NULL);
                if (IS_ERR(*handle)) {
                        rc = PTR_ERR(*handle);
                        *handle = NULL;
                        GOTO(out_ids, rc);
                }

                rc = fsfilt_set_md(obd, inode, *handle, lmm, lmm_size, "lov");
                if (rc)
                        CERROR("open replay failed to set md:%d\n", rc);

                /* for replay we not need send lmm to client, this not used now */
                lustre_shrink_reply(req, offset, 0, 1);
                *objid = lmm;

                RETURN(rc);
        }

        if (OBD_FAIL_CHECK_ONCE(OBD_FAIL_MDS_ALLOC_OBDO))
                GOTO(out_ids, rc = -ENOMEM);

        OBDO_ALLOC(oinfo.oi_oa);
        if (oinfo.oi_oa == NULL)
                GOTO(out_ids, rc = -ENOMEM);
        oinfo.oi_oa->o_uid = 0; /* must have 0 uid / gid on OST */
        oinfo.oi_oa->o_gid = 0;
        oinfo.oi_oa->o_mode = S_IFREG | 0600;
        oinfo.oi_oa->o_id = inode->i_ino;
        oinfo.oi_oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLFLAGS |
                OBD_MD_FLMODE | OBD_MD_FLUID | OBD_MD_FLGID;
        oinfo.oi_oa->o_size = 0;

        obdo_from_inode(oinfo.oi_oa, inode, OBD_MD_FLTYPE | OBD_MD_FLATIME |
                        OBD_MD_FLMTIME | OBD_MD_FLCTIME);
        if (!(rec->ur_flags & MDS_OPEN_HAS_OBJS)) {
                /* check if things like lfs setstripe are sending us the ea */
                if (rec->ur_flags & MDS_OPEN_HAS_EA) {
                        rc = obd_iocontrol(OBD_IOC_LOV_SETSTRIPE,
                                           mds->mds_osc_exp,
                                           0, &oinfo.oi_md, rec->ur_eadata);
                        if (rc)
                                GOTO(out_oa, rc);
                } else {
                        __u32 lmm_sz = mds->mds_max_mdsize;
                        OBD_ALLOC(lmm, lmm_sz);
                        if (lmm == NULL)
                                GOTO(out_oa, rc = -ENOMEM);

                        lmm_size = lmm_sz;
                        rc = mds_get_md(obd, dchild->d_parent->d_inode,
                                        lmm, &lmm_size, 1, 0);
                        if (rc > 0)
                                rc = obd_iocontrol(OBD_IOC_LOV_SETSTRIPE,
                                                   mds->mds_osc_exp,
                                                   0, &oinfo.oi_md, lmm);
                        OBD_FREE(lmm, lmm_sz);
                        if (rc)
                                GOTO(out_oa, rc);
                }
                rc = obd_create(mds->mds_osc_exp, oinfo.oi_oa, 
                                &oinfo.oi_md, &oti);
                if (rc) {
                        int level = D_ERROR;
                        if (rc == -ENOSPC)
                                level = D_INODE;
                        CDEBUG(level, "error creating objects for "
                                      "inode %lu: rc = %d\n",
                               inode->i_ino, rc);
                        if (rc > 0) {
                                CERROR("obd_create returned invalid "
                                       "rc %d\n", rc);
                                rc = -EIO;
                        }
                        GOTO(out_oa, rc);
                }
        } else {
                rc = obd_iocontrol(OBD_IOC_LOV_SETEA, mds->mds_osc_exp,
                                   0, &oinfo.oi_md, rec->ur_eadata);
                if (rc) {
                        GOTO(out_oa, rc);
                }
                oinfo.oi_md->lsm_object_id = oinfo.oi_oa->o_id;
        }
        if (i_size_read(inode)) {
                oinfo.oi_oa->o_size = i_size_read(inode);
                obdo_from_inode(oinfo.oi_oa, inode, OBD_MD_FLTYPE |
                                OBD_MD_FLATIME | OBD_MD_FLMTIME |
                                OBD_MD_FLCTIME | OBD_MD_FLSIZE);

                /* pack lustre id to OST */
                oinfo.oi_oa->o_fid = body->fid1.id;
                oinfo.oi_oa->o_generation = body->fid1.generation;
                oinfo.oi_oa->o_valid |= OBD_MD_FLFID | OBD_MD_FLGENER;
                oinfo.oi_policy.l_extent.start = i_size_read(inode);
                oinfo.oi_policy.l_extent.end = OBD_OBJECT_EOF;

                rc = obd_punch_rqset(mds->mds_osc_exp, &oinfo, &oti);
                if (rc) {
                        CERROR("error setting attrs for inode %lu: rc %d\n",
                               inode->i_ino, rc);
                        if (rc > 0) {
                                CERROR("obd_setattr_async returned bad rc %d\n",
                                       rc);
                                rc = -EIO;
                        }
                        GOTO(out_oa, rc);
                }
        }

        body->valid |= OBD_MD_FLBLKSZ | OBD_MD_FLEASIZE;
        obdo_refresh_inode(inode, oinfo.oi_oa, OBD_MD_FLBLKSZ);

        LASSERT(oinfo.oi_md && oinfo.oi_md->lsm_object_id);
        lmm = NULL;
        rc = obd_packmd(mds->mds_osc_exp, &lmm, oinfo.oi_md);
        if (rc < 0) {
                CERROR("cannot pack lsm, err = %d\n", rc);
                GOTO(out_oa, rc);
        }
        lmm_size = rc;
        body->eadatasize = rc;

        if (*handle == NULL)
                *handle = fsfilt_start(obd, inode, FSFILT_OP_CREATE, NULL);
        if (IS_ERR(*handle)) {
                rc = PTR_ERR(*handle);
                *handle = NULL;
                GOTO(free_diskmd, rc);
        }

        rc = fsfilt_set_md(obd, inode, *handle, lmm, lmm_size, "lov");
        lmm_buf = lustre_msg_buf(req->rq_repmsg, offset, lmm_size);
        LASSERT(lmm_buf);
        memcpy(lmm_buf, lmm, lmm_size);
        *objid = lmm_buf; /* save for mds_lov_update_objid */

 free_diskmd:
        obd_free_diskmd(mds->mds_osc_exp, &lmm);
 out_oa:
        oti_free_cookies(&oti);
        OBDO_FREE(oinfo.oi_oa);
 out_ids:
        if (oinfo.oi_md)
                obd_free_memmd(mds->mds_osc_exp, &oinfo.oi_md);
        RETURN(rc);
}

static void reconstruct_open(struct mds_update_record *rec, int offset,
                             struct ptlrpc_request *req,
                             struct lustre_handle *child_lockh)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct lsd_client_data *lcd = med->med_lcd;
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_file_data *mfd;
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
        struct dentry *parent, *dchild;
        struct ldlm_reply *rep;
        struct mds_body *body;
        int rc;
        struct list_head *t;
        int put_child = 1;
        ENTRY;

        LASSERT(offset == DLM_INTENT_REC_OFF); /* only called via intent */
        rep = lustre_msg_buf(req->rq_repmsg, DLM_LOCKREPLY_OFF, sizeof(*rep));
        body = lustre_msg_buf(req->rq_repmsg, DLM_REPLY_REC_OFF, sizeof(*body));

        /* copy rc, transno and disp; steal locks */
        mds_req_from_lcd(req, lcd);
        intent_set_disposition(rep, le32_to_cpu(lcd->lcd_last_data));

        /* Only replay if create or open actually happened. */
        if (!intent_disposition(rep, DISP_OPEN_CREATE | DISP_OPEN_OPEN) ) {
                EXIT;
                return; /* error looking up parent or child */
        }

        parent = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        if (IS_ERR(parent)) {
                rc = PTR_ERR(parent);
                LCONSOLE_WARN("Parent "LPU64"/%u lookup error %d." 
                              " Evicting client %s with export %s.\n",
                              rec->ur_fid1->id, rec->ur_fid1->generation, rc,
                              obd_uuid2str(&exp->exp_client_uuid),
                              obd_export_nid2str(exp));
                mds_export_evict(exp);
                EXIT;
                return;
        }

        dchild = ll_lookup_one_len(rec->ur_name, parent, rec->ur_namelen - 1);
        if (IS_ERR(dchild)) {
                rc = PTR_ERR(dchild);
                LCONSOLE_WARN("Child "LPU64"/%u lookup error %d." 
                              " Evicting client %s with export %s.\n",
                              rec->ur_fid1->id, rec->ur_fid1->generation, rc,
                              obd_uuid2str(&exp->exp_client_uuid),
                              obd_export_nid2str(exp));
                mds_export_evict(exp);
                EXIT;
                return;
        }

        if (!dchild->d_inode)
                GOTO(out_dput, 0); /* child not present to open */

        /* At this point, we know we have a child. We'll send
         * it back _unless_ it not created and open failed.
         */
        if (intent_disposition(rep, DISP_OPEN_OPEN) &&
            !intent_disposition(rep, DISP_OPEN_CREATE) &&
            req->rq_status) {
                GOTO(out_dput, 0);
        }

        mds_pack_inode2fid(&body->fid1, dchild->d_inode);
        mds_pack_inode2body(body, dchild->d_inode);
        if (S_ISREG(dchild->d_inode->i_mode)) {
                rc = mds_pack_md(obd, req->rq_repmsg, DLM_REPLY_REC_OFF + 1,
                                 body, dchild->d_inode, 1, 0);

                if (rc)
                        LASSERT(rc == req->rq_status);

                /* If we have LOV EA data, the OST holds size, mtime */
                if (!(body->valid & OBD_MD_FLEASIZE))
                        body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                        OBD_MD_FLATIME | OBD_MD_FLMTIME);
        }

        if (!(rec->ur_flags & MDS_OPEN_JOIN_FILE))
                lustre_shrink_reply(req, DLM_REPLY_REC_OFF + 1,
                                    body->eadatasize, 0);

        if (req->rq_export->exp_connect_flags & OBD_CONNECT_ACL &&
            !(rec->ur_flags & MDS_OPEN_JOIN_FILE)) {
                int acl_off = DLM_REPLY_REC_OFF + (body->eadatasize ? 2 : 1);

                rc = mds_pack_acl(med, dchild->d_inode, req->rq_repmsg,
                                  body, acl_off);
                lustre_shrink_reply(req, acl_off, body->aclsize, 0);
                if (!req->rq_status && rc)
                        req->rq_status = rc;
        }

        /* If we have -EEXIST as the status, and we were asked to create
         * exclusively, we can tell we failed because the file already existed.
         */
        if (req->rq_status == -EEXIST &&
            ((rec->ur_flags & (MDS_OPEN_CREAT | MDS_OPEN_EXCL)) ==
             (MDS_OPEN_CREAT | MDS_OPEN_EXCL))) {
                GOTO(out_dput, 0);
        }

        /* If we didn't get as far as trying to open, then some locking thing
         * probably went wrong, and we'll just bail here.
         */
        if (!intent_disposition(rep, DISP_OPEN_OPEN))
                GOTO(out_dput, 0);

        /* If we failed, then we must have failed opening, so don't look for
         * file descriptor or anything, just give the client the bad news.
         */
        if (req->rq_status)
                GOTO(out_dput, 0);

        mfd = NULL;
        spin_lock(&med->med_open_lock);
        list_for_each(t, &med->med_open_head) {
                mfd = list_entry(t, struct mds_file_data, mfd_list);
                if (mfd->mfd_xid == req->rq_xid) {
                        mds_mfd_addref(mfd);
                        break;
                }
                mfd = NULL;
        }
        spin_unlock(&med->med_open_lock);

        /* #warning "XXX fixme" bug 2991 */
        /* Here it used to LASSERT(mfd) if exp_outstanding_reply != NULL.
         * Now that exp_outstanding_reply is a list, it's just using mfd != NULL
         * to detect a re-open */
        if (mfd == NULL) {
                if (rec->ur_flags & MDS_OPEN_JOIN_FILE) {
                        rc = mds_join_file(rec, req, dchild, NULL);
                        if (rc)
                                GOTO(out_dput, rc);
                }
                mntget(mds->mds_vfsmnt);
                CERROR("Re-opened file \n");
                mfd = mds_dentry_open(dchild, mds->mds_vfsmnt,
                                      rec->ur_flags & ~MDS_OPEN_TRUNC, req);
                mntput(mds->mds_vfsmnt);
                if (IS_ERR(mfd)) {
                        req->rq_status = PTR_ERR(mfd);
                        mfd = NULL;
                        CERROR("%s: opening inode "LPU64" failed: rc %d\n",
                               req->rq_export->exp_obd->obd_name,
                               (__u64)dchild->d_inode->i_ino, req->rq_status);
                        GOTO(out_dput, req->rq_status);
                }
        } else {
                body->handle.cookie = mfd->mfd_handle.h_cookie;
                CDEBUG(D_INODE, "resend mfd %p, cookie "LPX64"\n", mfd,
                       mfd->mfd_handle.h_cookie);
        }

        mds_mfd_put(mfd);

 out_dput:
        if (put_child)
                l_dput(dchild);
        l_dput(parent);
        EXIT;
}

/* do NOT or the MAY_*'s, you'll get the weakest */
static int accmode(struct inode *inode, int flags)
{
        int res = 0;

        /* Sadly, NFSD reopens a file repeatedly during operation, so the
         * "acc_mode = 0" allowance for newly-created files isn't honoured.
         * NFSD uses the MDS_OPEN_OWNEROVERRIDE flag to say that a file
         * owner can write to a file even if it is marked readonly to hide
         * its brokenness. (bug 5781) */
        if (flags & MDS_OPEN_OWNEROVERRIDE && inode->i_uid == current->fsuid)
                return 0;

        if (flags & FMODE_READ)
                res = MAY_READ;
        if (flags & (FMODE_WRITE|MDS_OPEN_TRUNC))
                res |= MAY_WRITE;
        if (flags & MDS_FMODE_EXEC)
                res = MAY_EXEC;
        return res;
}

/* Handles object creation, actual opening, and I/O epoch */
static int mds_finish_open(struct ptlrpc_request *req, struct dentry *dchild,
                           struct mds_body *body, int flags, void **handle,
                           struct mds_update_record *rec,struct ldlm_reply *rep,
                           struct lustre_handle *lockh)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_file_data *mfd = NULL;
        struct lov_mds_md *lmm = NULL; /* object IDs created */
        int rc = 0;
        ENTRY;

        /* atomically create objects if necessary */
        LOCK_INODE_MUTEX(dchild->d_inode);

        if (S_ISREG(dchild->d_inode->i_mode) &&
            !(body->valid & OBD_MD_FLEASIZE)) {
                rc = mds_pack_md(obd, req->rq_repmsg, DLM_REPLY_REC_OFF + 1,
                                 body, dchild->d_inode, 0, 0);
                if (rc) {
                        UNLOCK_INODE_MUTEX(dchild->d_inode);
                        RETURN(rc);
                }
        }
        if (rec != NULL) {
                if ((body->valid & OBD_MD_FLEASIZE) &&
                    (rec->ur_flags & MDS_OPEN_HAS_EA)) {
                        UNLOCK_INODE_MUTEX(dchild->d_inode);
                        RETURN(-EEXIST);
                }
                if (rec->ur_flags & MDS_OPEN_JOIN_FILE) {
                        UNLOCK_INODE_MUTEX(dchild->d_inode);
                        rc = mds_join_file(rec, req, dchild, lockh);
                        if (rc)
                                RETURN(rc);
                        LOCK_INODE_MUTEX(dchild->d_inode);
                }
                if (!(body->valid & OBD_MD_FLEASIZE) &&
                    !(body->valid & OBD_MD_FLMODEASIZE)) {
                        /* no EA: create objects */
                        rc = mds_create_objects(req, DLM_REPLY_REC_OFF + 1, rec,
                                                mds, obd, dchild, handle, &lmm);
                        if (rc) {
                                CERROR("mds_create_objects: rc = %d\n", rc);
                                UNLOCK_INODE_MUTEX(dchild->d_inode);
                                RETURN(rc);
                        }
                }
        }
        /* If the inode has no EA data, then MDS holds size, mtime */
        if (S_ISREG(dchild->d_inode->i_mode) &&
            !(body->valid & OBD_MD_FLEASIZE)) {
                body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                OBD_MD_FLATIME | OBD_MD_FLMTIME);
        }
        UNLOCK_INODE_MUTEX(dchild->d_inode);

        if (rec && !(rec->ur_flags & MDS_OPEN_JOIN_FILE))
                lustre_shrink_reply(req, DLM_REPLY_REC_OFF + 1,
                                    body->eadatasize, 0);

        if (req->rq_export->exp_connect_flags & OBD_CONNECT_ACL &&
            rec && !(rec->ur_flags & MDS_OPEN_JOIN_FILE)) {
                int acl_off = DLM_REPLY_REC_OFF + (body->eadatasize ? 2 : 1);

                rc = mds_pack_acl(&req->rq_export->exp_mds_data,
                                  dchild->d_inode, req->rq_repmsg,
                                  body, acl_off);
                lustre_shrink_reply(req, acl_off, body->aclsize, 0);
                if (rc)
                        RETURN(rc);
        }

        if ((rc = mds_lov_prepare_objids(obd,lmm)) != 0)
                RETURN(rc);

        intent_set_disposition(rep, DISP_OPEN_OPEN);
        mfd = mds_dentry_open(dchild, mds->mds_vfsmnt, flags, req);
        if (IS_ERR(mfd))
                RETURN(PTR_ERR(mfd));

        CDEBUG(D_INODE, "mfd %p, cookie "LPX64"\n", mfd,
               mfd->mfd_handle.h_cookie);

        mds_lov_update_objids(obd, lmm);

        if (rc)
                mds_mfd_unlink(mfd, 1);

        mds_mfd_put(mfd);
        RETURN(rc);
}

static int mds_open_by_fid(struct ptlrpc_request *req, struct ll_fid *fid,
                           struct mds_body *body, int flags,
                           struct mds_update_record *rec,struct ldlm_reply *rep)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct dentry *dchild;
        char fidname[LL_FID_NAMELEN];
        int fidlen = 0, rc;
        void *handle = NULL;
        ENTRY;

        fidlen = ll_fid2str(fidname, fid->id, fid->generation);
        dchild = ll_lookup_one_len(fidname, mds->mds_pending_dir, fidlen);
        if (IS_ERR(dchild)) {
                rc = PTR_ERR(dchild);
                CERROR("error looking up %s in PENDING: rc = %d\n",fidname, rc);
                RETURN(rc);
        }

        if (dchild->d_inode != NULL) {
                mds_inode_set_orphan(dchild->d_inode);
                CWARN("Orphan %s found and opened in PENDING directory\n",
                       fidname);
        } else {
                l_dput(dchild);

                /* We didn't find it in PENDING so it isn't an orphan.  See
                 * if it was a regular inode that was previously created. */
                dchild = mds_fid2dentry(mds, fid, NULL);
                if (IS_ERR(dchild))
                        RETURN(PTR_ERR(dchild));
        }

        mds_pack_inode2fid(&body->fid1, dchild->d_inode);
        mds_pack_inode2body(body, dchild->d_inode);
        intent_set_disposition(rep, DISP_LOOKUP_EXECD);
        intent_set_disposition(rep, DISP_LOOKUP_POS);

        rc = mds_finish_open(req, dchild, body, flags, &handle, rec, rep, NULL);
        rc = mds_finish_transno(mds, dchild->d_inode, handle,
                                req, rc, rep ? rep->lock_policy_res1 : 0, 0);
        /* XXX what do we do here if mds_finish_transno itself failed? */

        l_dput(dchild);
        RETURN(rc);
}

int mds_pin(struct ptlrpc_request *req, int offset)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_body *reqbody, *repbody;
        struct lvfs_run_ctxt saved;
        int rc, size[2] = { sizeof(struct ptlrpc_body), sizeof(*repbody) };
        ENTRY;

        reqbody = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*reqbody));

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                 sizeof(*repbody));

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = mds_open_by_fid(req, &reqbody->fid1, repbody, reqbody->flags, NULL,
                             NULL);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        RETURN(rc);
}

/*  Get an internal lock on the inode number (but not generation) to sync
 *  new inode creation with inode unlink (bug 2029).  If child_lockh is NULL
 *  we just get the lock as a barrier to wait for other holders of this lock,
 *  and drop it right away again. */
int mds_lock_new_child(struct obd_device *obd, struct inode *inode,
                       struct lustre_handle *child_lockh)
{
        struct ldlm_res_id child_res_id = { .name = { inode->i_ino, 0, 1, 0 } };
        struct lustre_handle lockh;
        int lock_flags = LDLM_FL_ATOMIC_CB;
        int rc;

        if (child_lockh == NULL)
                child_lockh = &lockh;

        rc = ldlm_cli_enqueue_local(obd->obd_namespace, &child_res_id,
                                    LDLM_PLAIN, NULL, LCK_EX, &lock_flags,
                                    ldlm_blocking_ast, ldlm_completion_ast,
                                    NULL, NULL, 0, NULL, child_lockh);
        if (rc != ELDLM_OK)
                CERROR("ldlm_cli_enqueue_local: %d\n", rc);
        else if (child_lockh == &lockh)
                ldlm_lock_decref(child_lockh, LCK_EX);

        RETURN(rc);
}

int mds_open(struct mds_update_record *rec, int offset,
             struct ptlrpc_request *req, struct lustre_handle *child_lockh)
{
        /* XXX ALLOCATE _something_ - 464 bytes on stack here */
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_obd *mds = mds_req2mds(req);
        struct ldlm_reply *rep = NULL;
        struct mds_body *body = NULL;
        struct dentry *dchild = NULL, *dparent = NULL;
        struct mds_export_data *med;
        struct lustre_handle parent_lockh;
        int rc = 0, cleanup_phase = 0, acc_mode, created = 0;
        int parent_mode = LCK_CR;
        void *handle = NULL;
        struct lvfs_dentry_params dp = LVFS_DENTRY_PARAMS_INIT;
        unsigned int qcids[MAXQUOTAS] = { current->fsuid, current->fsgid };
        unsigned int qpids[MAXQUOTAS] = { 0, 0 };
        int child_mode = LCK_CR;
        /* Always returning LOOKUP lock if open succesful to guard
           dentry on client. */
        ldlm_policy_data_t policy = {.l_inodebits={MDS_INODELOCK_LOOKUP}};
        struct ldlm_res_id child_res_id = { .name = {0}};
        int lock_flags = 0;
        int rec_pending = 0;
        unsigned int gid = current->fsgid;
        ENTRY;

        mds_counter_incr(req->rq_export, LPROC_MDS_OPEN);

        OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_PAUSE_OPEN | OBD_FAIL_ONCE,
                         (obd_timeout + 1) / 4);

        CLASSERT(MAXQUOTAS < 4);
        if (offset == DLM_INTENT_REC_OFF) { /* intent */
                rep = lustre_msg_buf(req->rq_repmsg, DLM_LOCKREPLY_OFF,
                                     sizeof(*rep));
                body = lustre_msg_buf(req->rq_repmsg, DLM_REPLY_REC_OFF,
                                      sizeof(*body));
        } else if (offset == REQ_REC_OFF) { /* non-intent reint */
                body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                      sizeof(*body));
                LBUG(); /* XXX: not supported yet? */
        } else {
                body = NULL;
                LBUG();
        }

        MDS_CHECK_RESENT(req, reconstruct_open(rec, offset, req, child_lockh));

        /* Step 0: If we are passed a fid, then we assume the client already
         * opened this file and is only replaying the RPC, so we open the
         * inode by fid (at some large expense in security). */
        /*XXX liblustre use mds_open_by_fid to implement LL_IOC_LOV_SETSTRIPE */
        if (((lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) ||
             (req->rq_export->exp_libclient && rec->ur_flags&MDS_OPEN_HAS_EA))&&
            !(rec->ur_flags & MDS_OPEN_JOIN_FILE)) {
                if (rec->ur_fid2->id == 0) {
                        struct ldlm_lock *lock = ldlm_handle2lock(child_lockh);
                        if (lock) {
                                LDLM_ERROR(lock, "fid2 not set on open replay");
                                LDLM_LOCK_PUT(lock);
                        }
                        DEBUG_REQ(D_ERROR, req, "fid2 not set on open replay");
                        RETURN(-EFAULT);
                }

                rc = mds_open_by_fid(req, rec->ur_fid2, body, rec->ur_flags,
                                     rec, rep);
                if (rc != -ENOENT) {
                        if (req->rq_export->exp_libclient &&
                            rec->ur_flags & MDS_OPEN_HAS_EA)
                                RETURN(0);

                        RETURN(rc);
                }

                /* We didn't find the correct inode on disk either, so we
                 * need to re-create it via a regular replay. */
                if (!(rec->ur_flags & MDS_OPEN_CREAT)) {
                        DEBUG_REQ(D_ERROR, req,"OPEN_CREAT not in open replay");
                        RETURN(-EFAULT);
                }
        } else if (rec->ur_fid2->id) {
                DEBUG_REQ(D_ERROR, req, "fid2 "LPU64"/%u on open non-replay",
                          rec->ur_fid2->id, rec->ur_fid2->generation);
                RETURN(-EFAULT);
        }

        /* If we got here, we must be called via intent */
        LASSERT(offset == DLM_INTENT_REC_OFF);

        med = &req->rq_export->exp_mds_data;
        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OPEN_PACK)) {
                CERROR("test case OBD_FAIL_MDS_OPEN_PACK\n");
                RETURN(-ENOMEM);
        }

        /* Step 1: Find and lock the parent */
        if (rec->ur_flags & (MDS_OPEN_CREAT | MDS_OPEN_JOIN_FILE))
                parent_mode = LCK_EX;
        dparent = mds_fid2locked_dentry(obd, rec->ur_fid1, NULL, parent_mode,
                                        &parent_lockh, rec->ur_name,
                                        rec->ur_namelen - 1,
                                        MDS_INODELOCK_UPDATE);
        if (IS_ERR(dparent)) {
                rc = PTR_ERR(dparent);
                if (rc != -ENOENT) {
                        CERROR("parent "LPU64"/%u lookup error %d\n",
                               rec->ur_fid1->id, rec->ur_fid1->generation, rc);
                } else {
                        /* Just cannot find parent - make it look like
                         * usual negative lookup to avoid extra MDS RPC */
                        intent_set_disposition(rep, DISP_LOOKUP_EXECD);
                        intent_set_disposition(rep, DISP_LOOKUP_NEG);
                }
                GOTO(cleanup, rc);
        }
        LASSERT(dparent->d_inode != NULL);

        cleanup_phase = 1; /* parent dentry and lock */

        if (rec->ur_flags & MDS_OPEN_JOIN_FILE) {
                dchild = dget(dparent);
                cleanup_phase = 2; /* child dentry */
                acc_mode = accmode(dchild->d_inode, rec->ur_flags);
                GOTO(found_child, rc);
        }

        /* Step 2: Lookup the child */
      
        if (!(lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) &&
            (rec->ur_flags & MDS_OPEN_LOCK) && (rec->ur_namelen == 1)) {
                /* hack for nfsd with no_subtree_check, it will use anon
                 * dentry w/o filename to open the file. the anon dentry's
                 * parent was set to itself, so rec->ur_fid1 is the file.
                 * And in MDC it cannot derive the dentry's parent dentry,
                 * hence the file's name, so we hack here in MDS, 
                 * refer to bug 13030. */
                dchild = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        } else {
                dchild = ll_lookup_one_len(rec->ur_name, dparent,
                                           rec->ur_namelen - 1);
        }
        if (IS_ERR(dchild)) {
                rc = PTR_ERR(dchild);
                dchild = NULL; /* don't confuse mds_finish_transno() below */
                GOTO(cleanup, rc);
        }

        cleanup_phase = 2; /* child dentry */

        intent_set_disposition(rep, DISP_LOOKUP_EXECD);
        if (dchild->d_inode)
                intent_set_disposition(rep, DISP_LOOKUP_POS);
        else
                intent_set_disposition(rep, DISP_LOOKUP_NEG);

        /*Step 3: If the child was negative, and we're supposed to, create it.*/
        if (dchild->d_inode == NULL) {
                unsigned long ino = rec->ur_fid2->id;
                struct iattr iattr;
                struct inode *inode;

                if (!(rec->ur_flags & MDS_OPEN_CREAT)) {
                        /* It's negative and we weren't supposed to create it */
                        GOTO(cleanup, rc = -ENOENT);
                }

                if (req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                        GOTO(cleanup, rc = -EROFS);

                if (dparent->d_inode->i_mode & S_ISGID)
                        gid = dparent->d_inode->i_gid;
                else
                        gid = current->fsgid;

                /* we try to get enough quota to write here, and let ldiskfs
                 * decide if it is out of quota or not b=14783 */
                lquota_chkquota(mds_quota_interface_ref, obd,
                                current->fsuid, gid, 1, &rec_pending);

                intent_set_disposition(rep, DISP_OPEN_CREATE);
                handle = fsfilt_start(obd, dparent->d_inode, FSFILT_OP_CREATE,
                                      NULL);
                if (IS_ERR(handle)) {
                        rc = PTR_ERR(handle);
                        handle = NULL;
                        GOTO(cleanup, rc);
                }
                dchild->d_fsdata = (void *) &dp;
                dp.ldp_ptr = req;
                dp.ldp_inum = ino;

                LOCK_INODE_MUTEX(dparent->d_inode);
                rc = ll_vfs_create(dparent->d_inode, dchild, rec->ur_mode,NULL);
                UNLOCK_INODE_MUTEX(dparent->d_inode);
                if (dchild->d_fsdata == (void *)(unsigned long)ino)
                        dchild->d_fsdata = NULL;

                if (rc) {
                        CDEBUG(D_INODE, "error during create: %d\n", rc);
                        GOTO(cleanup, rc);
                }
                inode = dchild->d_inode;
                if (ino) {
                        LASSERT(ino == inode->i_ino);
                        /* Written as part of setattr */
                        inode->i_generation = rec->ur_fid2->generation;
                        CDEBUG(D_HA, "recreated ino %lu with gen %u\n",
                               inode->i_ino, inode->i_generation);
                }

                created = 1;
                LTIME_S(iattr.ia_atime) = rec->ur_time;
                LTIME_S(iattr.ia_ctime) = rec->ur_time;
                LTIME_S(iattr.ia_mtime) = rec->ur_time;

                iattr.ia_uid = current->fsuid;  /* set by push_ctxt already */
                iattr.ia_gid = gid;

                iattr.ia_valid = ATTR_UID | ATTR_GID | ATTR_ATIME |
                        ATTR_MTIME | ATTR_CTIME;

                rc = fsfilt_setattr(obd, dchild, handle, &iattr, 0);
                if (rc)
                        CERROR("error on child setattr: rc = %d\n", rc);

                iattr.ia_valid = ATTR_MTIME | ATTR_CTIME;

                rc = fsfilt_setattr(obd, dparent, handle, &iattr, 0);
                if (rc)
                        CERROR("error on parent setattr: rc = %d\n", rc);

                rc = fsfilt_commit(obd, dchild->d_inode, handle, 0);
                handle = NULL;
                acc_mode = 0;           /* Don't check for permissions */
        } else {
                acc_mode = accmode(dchild->d_inode, rec->ur_flags);
        }

        LASSERTF(!mds_inode_is_orphan(dchild->d_inode),
                 "dchild %.*s (%p) inode %p/%lu/%u\n", dchild->d_name.len,
                 dchild->d_name.name, dchild, dchild->d_inode,
                 dchild->d_inode->i_ino, dchild->d_inode->i_generation);

found_child:
        mds_pack_inode2fid(&body->fid1, dchild->d_inode);
        mds_pack_inode2body(body, dchild->d_inode);

        if (S_ISREG(dchild->d_inode->i_mode)) {
                /* Check permissions etc */
                rc = ll_permission(dchild->d_inode, acc_mode, NULL);
                if (rc != 0)
                        GOTO(cleanup, rc);

                if ((req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY) &&
                    (acc_mode & MAY_WRITE))
                        GOTO(cleanup, rc = -EROFS);

                /* An append-only file must be opened in append mode for
                 * writing */
                if (IS_APPEND(dchild->d_inode) && (acc_mode & MAY_WRITE) != 0 &&
                    ((rec->ur_flags & MDS_OPEN_APPEND) == 0 ||
                     (rec->ur_flags & MDS_OPEN_TRUNC) != 0))
                        GOTO(cleanup, rc = -EPERM);
        }

        if (!created && (rec->ur_flags & MDS_OPEN_CREAT) &&
            (rec->ur_flags & MDS_OPEN_EXCL)) {
                /* File already exists, we didn't just create it, and we
                 * were passed O_EXCL; err-or. */
                GOTO(cleanup, rc = -EEXIST); // returns a lock to the client
        }

        /* if we are following a symlink, don't open */
        if (S_ISLNK(dchild->d_inode->i_mode))
                GOTO(cleanup_no_trans, rc = 0);

        if (S_ISDIR(dchild->d_inode->i_mode)) {
                if (rec->ur_flags & MDS_OPEN_CREAT ||
                    rec->ur_flags & FMODE_WRITE) {
                        /* we are trying to create or write a exist dir */
                        GOTO(cleanup, rc = -EISDIR);
                }
                if (rec->ur_flags & MDS_FMODE_EXEC) {
                        /* we are trying to exec a directory */
                        GOTO(cleanup, rc = -EACCES);
                }
                if (ll_permission(dchild->d_inode, acc_mode, NULL)) {
                        intent_set_disposition(rep, DISP_OPEN_OPEN);
                        GOTO(cleanup, rc = -EACCES);
                }
        } else if (rec->ur_flags & MDS_OPEN_DIRECTORY) {
                GOTO(cleanup, rc = -ENOTDIR);
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OPEN_CREATE)) {
                obd_fail_loc = OBD_FAIL_LDLM_REPLY | OBD_FAIL_ONCE;
                GOTO(cleanup, rc = -EAGAIN);
        }

        /* Obtain OPEN lock as well */
        policy.l_inodebits.bits |= MDS_INODELOCK_OPEN;

        /* We cannot use acc_mode here, because it is zeroed in case of
           creating a file, so we get wrong lockmode */
        if (rec->ur_flags & FMODE_WRITE)
                child_mode = LCK_CW;
        else if (rec->ur_flags & MDS_FMODE_EXEC)
                child_mode = LCK_PR;
        else
                child_mode = LCK_CR;

        if (!(lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) && 
             (rec->ur_flags & MDS_OPEN_LOCK)) {
                /* In case of replay we do not get a lock assuming that the
                   caller has it already */
                child_res_id.name[0] = dchild->d_inode->i_ino;
                child_res_id.name[1] = dchild->d_inode->i_generation;

                rc = ldlm_cli_enqueue_local(obd->obd_namespace, &child_res_id,
                                            LDLM_IBITS, &policy, child_mode, 
                                            &lock_flags, ldlm_blocking_ast, 
                                            ldlm_completion_ast, NULL, NULL,
                                            0, NULL, child_lockh);
                if (rc != ELDLM_OK)
                        GOTO(cleanup, rc);

                /* Let mds_intent_policy know that we have a lock to return */
                intent_set_disposition(rep, DISP_OPEN_LOCK);
                cleanup_phase = 3;
        }

        if (!S_ISREG(dchild->d_inode->i_mode) &&
            !S_ISDIR(dchild->d_inode->i_mode) &&
            (req->rq_export->exp_connect_flags & OBD_CONNECT_NODEVOH)) {
                /* If client supports this, do not return open handle for
                 * special device nodes */
                GOTO(cleanup_no_trans, rc = 0);
        }

        /* Step 5: mds_open it */
        rc = mds_finish_open(req, dchild, body, rec->ur_flags, &handle, rec,
                             rep, &parent_lockh);
        GOTO(cleanup, rc);

 cleanup:
        rc = mds_finish_transno(mds, dchild ? dchild->d_inode : NULL, handle,
                                req, rc, rep ? rep->lock_policy_res1 : 0, 0);

 cleanup_no_trans:
        if (rec_pending)
                lquota_pending_commit(mds_quota_interface_ref, obd,
                                      current->fsuid, gid, 1);
        switch (cleanup_phase) {
        case 3:
                if (rc)
                        /* It is safe to leave IT_OPEN_LOCK set, if rc is not 0,
                         * mds_intent_policy won't try to return any locks */
                        ldlm_lock_decref(child_lockh, child_mode);
        case 2:
                if (rc && created) {
                        int err;
                        LOCK_INODE_MUTEX(dparent->d_inode);
                        err = ll_vfs_unlink(dparent->d_inode, dchild,
                                            mds->mds_vfsmnt);
                        UNLOCK_INODE_MUTEX(dparent->d_inode);
                        if (err) {
                                CERROR("unlink(%.*s) in error path: %d\n",
                                       dchild->d_name.len, dchild->d_name.name,
                                       err);
                        }
                } else if (created) {
                        mds_lock_new_child(obd, dchild->d_inode, NULL);
                        /* save uid/gid for quota acquire/release */
                        qpids[USRQUOTA] = dparent->d_inode->i_uid;
                        qpids[GRPQUOTA] = dparent->d_inode->i_gid;
                }
                l_dput(dchild);
        case 1:
                if (dparent == NULL)
                        break;

                l_dput(dparent);
                if (rc)
                        ldlm_lock_decref(&parent_lockh, parent_mode);
                else
                        ptlrpc_save_lock(req, &parent_lockh, parent_mode);
        }
        /* trigger dqacq on the owner of child and parent */
        lquota_adjust(mds_quota_interface_ref, obd, qcids, qpids, rc,
                      FSFILT_OP_CREATE);
        RETURN(rc);
}

/* Close a "file descriptor" and possibly unlink an orphan from the
 * PENDING directory.  Caller must hold child->i_mutex, this drops it.
 *
 * If we are being called from mds_disconnect() because the client has
 * disappeared, then req == NULL and we do not update last_rcvd because
 * there is nothing that could be recovered by the client at this stage
 * (it will not even _have_ an entry in last_rcvd anymore).
 *
 * Returns EAGAIN if the client needs to get more data and re-close. */
int mds_mfd_close(struct ptlrpc_request *req, int offset,
                  struct obd_device *obd, struct mds_file_data *mfd,
                  int unlink_orphan, struct lov_mds_md *lmm, int lmm_size,
                  struct llog_cookie *logcookies, int cookies_size,
                  __u64 *valid)
{
        struct inode *inode = mfd->mfd_dentry->d_inode;
        char fidname[LL_FID_NAMELEN];
        int last_orphan, fidlen, rc = 0, cleanup_phase = 0;
        struct dentry *pending_child = NULL;
        struct mds_obd *mds = &obd->u.mds;
        struct inode *pending_dir = mds->mds_pending_dir->d_inode;
        void *handle = NULL;
        struct mds_body *request_body = NULL, *reply_body = NULL;
        struct lvfs_dentry_params dp = LVFS_DENTRY_PARAMS_INIT;
        struct iattr iattr = { 0 };
        ENTRY;

        if (req && req->rq_reqmsg != NULL)
                request_body = lustre_msg_buf(req->rq_reqmsg, offset,
                                              sizeof(*request_body));
        if (req && req->rq_repmsg != NULL)
                reply_body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                            sizeof(*reply_body));

        fidlen = ll_fid2str(fidname, inode->i_ino, inode->i_generation);

        CDEBUG(D_INODE, "inode %p ino %s nlink %d orphan %d\n", inode, fidname,
               inode->i_nlink, mds_orphan_open_count(inode));

        last_orphan = mds_orphan_open_dec_test(inode) &&
                      mds_inode_is_orphan(inode);

        /* this is half of the actual "close" */
        if (mfd->mfd_mode & FMODE_WRITE) {
                rc = mds_put_write_access(mds, inode, request_body,
                                          last_orphan && unlink_orphan);
        } else if (mfd->mfd_mode & MDS_FMODE_EXEC) {
                mds_allow_write_access(inode);
        }
        /* here writecount change also needs protection from orphan write sem. 
         * so drop orphan write sem after mds_put_write_access, bz 12888. */
        MDS_UP_WRITE_ORPHAN_SEM(inode);

        if (last_orphan && unlink_orphan) {
                int stripe_count = 0;
                /* mds_put_write_access must have succeeded */
                LASSERTF(rc == 0, "inode %lu/%u: rc %d",
                         inode->i_ino, inode->i_generation, rc);

                CDEBUG(D_INODE, "destroying orphan object %s\n", fidname);

                if ((S_ISREG(inode->i_mode) && inode->i_nlink != 1) ||
                    (S_ISDIR(inode->i_mode) && inode->i_nlink != 2))
                        CERROR("found \"orphan\" %s %s with link count %d\n",
                               S_ISREG(inode->i_mode) ? "file" : "dir",
                               fidname, inode->i_nlink);

                /* Sadly, there is no easy way to save pending_child from
                 * mds_reint_unlink() into mfd, so we need to re-lookup,
                 * but normally it will still be in the dcache. */
                LOCK_INODE_MUTEX(pending_dir);
                cleanup_phase = 1; /* UNLOCK_INODE_MUTEX(pending_dir) when finished */
                pending_child = lookup_one_len(fidname, mds->mds_pending_dir,
                                               fidlen);
                if (IS_ERR(pending_child))
                        GOTO(cleanup, rc = PTR_ERR(pending_child));
                LASSERT(pending_child->d_inode != NULL);

                cleanup_phase = 2; /* dput(pending_child) when finished */
                if (S_ISDIR(pending_child->d_inode->i_mode)) {
                        rc = ll_vfs_rmdir(pending_dir, pending_child, 
                                          mds->mds_vfsmnt);
                        if (rc)
                                CERROR("error unlinking orphan dir %s: rc %d\n",
                                       fidname,rc);
                        goto out;
                }

                if (lmm != NULL) {
                        stripe_count = le32_to_cpu(lmm->lmm_stripe_count);
                }

                handle = fsfilt_start_log(obd, pending_dir, FSFILT_OP_UNLINK,
                                          NULL, stripe_count);
                if (IS_ERR(handle)) {
                        rc = PTR_ERR(handle);
                        handle = NULL;
                        GOTO(cleanup, rc);
                }
                if (lmm != NULL && (*valid & OBD_MD_FLEASIZE) &&
                    mds_log_op_unlink(obd, lmm, lmm_size,
                                      logcookies, cookies_size) > 0) {
                        *valid |= OBD_MD_FLCOOKIE;
                }

                dp.ldp_inum = 0;
                dp.ldp_ptr = req;
                pending_child->d_fsdata = (void *) &dp;
                rc = ll_vfs_unlink(pending_dir, pending_child, mds->mds_vfsmnt);
                if (rc)
                        CERROR("error unlinking orphan %s: rc %d\n",fidname,rc);

                goto out; /* Don't bother updating attrs on unlinked inode */
        }

        if (request_body != NULL) {
               if ((request_body->valid & OBD_MD_FLCTIME) &&
                   (request_body->ctime > LTIME_S(inode->i_ctime))) {
                       LTIME_S(iattr.ia_ctime) = request_body->ctime;
                       iattr.ia_valid |= ATTR_CTIME;
               }

               if ((request_body->valid & OBD_MD_FLMTIME) &&
                   (request_body->mtime > LTIME_S(inode->i_mtime)) &&
                   (iattr.ia_valid & ATTR_CTIME)) {
                       LTIME_S(iattr.ia_mtime) = request_body->mtime;
                       iattr.ia_valid |= ATTR_MTIME;
               }

               /* Only start a transaction to write out only the atime
                * if it is more out-of-date than the specified limit.
                * If we are already going to write out the inode then
                * update the atime anyway.
                */
               if ((request_body->valid & OBD_MD_FLATIME) &&
                   ((request_body->atime >
                     LTIME_S(inode->i_atime) + mds->mds_atime_diff) ||
                    (iattr.ia_valid != 0 &&
                     request_body->atime > LTIME_S(inode->i_atime)))) {
                       LTIME_S(iattr.ia_atime) = request_body->atime;
                       iattr.ia_valid |= ATTR_ATIME;
               }

               /* Store a rough estimate of the file size on the MDS for
                * tools like e2scan and HSM that are just using this for
                * rough decision making and will get the proper size later.
                * This is NOT guaranteed to be correct with multiple
                * writers, but is only needed until SOM is done. b=11063 */
               if ((request_body->valid & OBD_MD_FLSIZE) &&
                   (iattr.ia_valid != 0)) {
                       iattr.ia_size = request_body->size;
                       iattr.ia_valid |= ATTR_SIZE;
               }
        }

        if (iattr.ia_valid != 0) {
                handle = fsfilt_start(obd, inode, FSFILT_OP_SETATTR, NULL);
                if (IS_ERR(handle)) {
                        rc = PTR_ERR(handle);
                        handle = NULL;
                        GOTO(cleanup, rc);
                }
                rc = fsfilt_setattr(obd, mfd->mfd_dentry, handle, &iattr, 0);
                if (rc)
                        CERROR("error in setattr(%s): rc %d\n", fidname, rc);
        }
out:
        /* If other clients have this file open for write, rc will be > 0 */
        if (rc > 0)
                rc = 0;
        l_dput(mfd->mfd_dentry);
        mds_mfd_put(mfd);

 cleanup:
        if (req != NULL && reply_body != NULL) {
                rc = mds_finish_transno(mds, pending_dir, handle, req, rc, 0, 0);
        } else if (handle) {
                int err = fsfilt_commit(obd, pending_dir, handle, 0);
                if (err) {
                        CERROR("error committing close: %d\n", err);
                        if (!rc)
                                rc = err;
                }
        }

        switch (cleanup_phase) {
        case 2:
                dput(pending_child);
        case 1:
                UNLOCK_INODE_MUTEX(pending_dir);
        }
        RETURN(rc);
}

int mds_close(struct ptlrpc_request *req, int offset)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_body *body;
        struct mds_file_data *mfd;
        struct lvfs_run_ctxt saved;
        struct inode *inode;
        int rc, repsize[4] = { sizeof(struct ptlrpc_body),
                               sizeof(struct mds_body),
                               obd->u.mds.mds_max_mdsize,
                               obd->u.mds.mds_max_cookiesize };
        struct mds_body *reply_body;
        struct lov_mds_md *lmm;
        int lmm_size;
        struct llog_cookie *logcookies;
        int cookies_size;
        ENTRY;

        rc = lustre_pack_reply(req, 4, repsize, NULL);
        if (rc)
                req->rq_status = rc;
                /* continue on to drop local open even if we can't send reply */
        else
                MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));

        CDEBUG(D_INODE, "close req->rep_len %d mdsize %d cookiesize %d\n",
               req->rq_replen,
               obd->u.mds.mds_max_mdsize, obd->u.mds.mds_max_cookiesize);
        mds_counter_incr(req->rq_export, LPROC_MDS_CLOSE);

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL) {
                CERROR("Can't unpack body\n");
                req->rq_status = -EFAULT;
                RETURN(-EFAULT);
        }

        if (body->flags & MDS_BFLAG_UNCOMMITTED_WRITES)
                /* do some stuff */ ;

        spin_lock(&med->med_open_lock);
        mfd = mds_handle2mfd(&body->handle);
        if (mfd == NULL) {
                spin_unlock(&med->med_open_lock);
                DEBUG_REQ(D_ERROR, req, "no handle for file close ino "LPD64
                          ": cookie "LPX64, body->fid1.id, body->handle.cookie);
                req->rq_status = -ESTALE;
                RETURN(-ESTALE);
        }
        /* Remove mfd handle so it can't be found again.  We consume mfd_list
         * reference here, but still have mds_handle2mfd ref until mfd_close. */
        mds_mfd_unlink(mfd, 1);
        spin_unlock(&med->med_open_lock);

        inode = mfd->mfd_dentry->d_inode;
        /* child orphan sem protects orphan_dec_test && is_orphan race */
        MDS_DOWN_WRITE_ORPHAN_SEM(inode); /* mds_mfd_close drops this */
        if (mds_inode_is_orphan(inode) && mds_orphan_open_count(inode) == 1) {
                body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                      sizeof(*body));
                LASSERT(body != NULL);

                mds_pack_inode2fid(&body->fid1, inode);
                mds_pack_inode2body(body, inode);
                mds_pack_md(obd, req->rq_repmsg, REPLY_REC_OFF + 1, body, inode,
                            MDS_PACK_MD_LOCK, 0);
        }

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        reply_body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof(*reply_body));
        lmm = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF + 1, 0);
        lmm_size = lustre_msg_buflen(req->rq_repmsg, REPLY_REC_OFF + 1),
        logcookies = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF + 2, 0);
        cookies_size = lustre_msg_buflen(req->rq_repmsg, REPLY_REC_OFF + 2);
        req->rq_status = mds_mfd_close(req, offset, obd, mfd, 1,
                                       lmm, lmm_size, logcookies, cookies_size,
                                       &reply_body->valid);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        mds_shrink_reply(obd, req, body, REPLY_REC_OFF + 1);
        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_CLOSE_PACK)) {
                CERROR("test case OBD_FAIL_MDS_CLOSE_PACK\n");
                req->rq_status = -ENOMEM;
                RETURN(-ENOMEM);
        }

        RETURN(rc);
}

int mds_done_writing(struct ptlrpc_request *req, int offset)
{
        struct mds_body *body;
        int rc, size[2] = { sizeof(struct ptlrpc_body),
                            sizeof(struct mds_body) };
        ENTRY;

        MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL) {
                CERROR("Can't unpack body\n");
                req->rq_status = -EFAULT;
                RETURN(-EFAULT);
        }

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                req->rq_status = rc;

        RETURN(0);
}
