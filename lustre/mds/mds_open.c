/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Mike Shaver <shaver@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/init.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
# include <linux/buffer_head.h>
# include <linux/workqueue.h>
#else
# include <linux/locks.h>
#endif

#include <linux/obd_class.h>
#include <linux/lustre_mds.h>
#include <linux/obd_lov.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lprocfs_status.h>

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
        class_handle_hash(&mfd->mfd_handle, mds_mfd_addref);

        return mfd;
}

static struct mds_file_data *mds_handle2mfd(struct lustre_handle *handle)
{
        ENTRY;
        LASSERT(handle != NULL);
        RETURN(class_handle2object(handle->cookie));
}

static void mds_mfd_put(struct mds_file_data *mfd)
{
        CDEBUG(D_INFO, "PUTting mfd %p : new refcount %d\n", mfd,
               atomic_read(&mfd->mfd_refcount) - 1);
        LASSERT(atomic_read(&mfd->mfd_refcount) > 0 &&
                atomic_read(&mfd->mfd_refcount) < 0x5a5a);
        if (atomic_dec_and_test(&mfd->mfd_refcount)) {
                LASSERT(list_empty(&mfd->mfd_handle.h_link));
                OBD_FREE(mfd, sizeof *mfd);
        }
}

static void mds_mfd_destroy(struct mds_file_data *mfd)
{
        class_handle_unhash(&mfd->mfd_handle);
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

/* This replaces the VFS mds_dentry_open, it manages mfd and writecount */
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

        body = lustre_msg_buf(req->rq_repmsg, 1, sizeof (*body));

        if (flags & FMODE_WRITE) {
                /* FIXME: in recovery, need to pass old epoch here */
                error = mds_get_write_access(mds, dentry->d_inode, 0);
                if (error)
                        GOTO(cleanup_mfd, error);
                body->io_epoch = MDS_FILTERDATA(dentry->d_inode)->io_epoch;
        } else if (flags & FMODE_EXEC) {
                error = mds_deny_write_access(mds, dentry->d_inode);
                if (error)
                        GOTO(cleanup_mfd, error);
        }

        dget(dentry);

        /* Mark the file as open to handle open-unlink. */
        mds_open_orphan_inc(dentry->d_inode);

        mfd->mfd_mode = flags;
        mfd->mfd_dentry = dentry;
        mfd->mfd_xid = req->rq_xid;

        spin_lock(&med->med_open_lock);
        list_add(&mfd->mfd_list, &med->med_open_head);
        spin_unlock(&med->med_open_lock);
        mds_mfd_put(mfd);

        body->handle.cookie = mfd->mfd_handle.h_cookie;

        RETURN(mfd);

cleanup_mfd:
        mds_mfd_put(mfd);
        mds_mfd_destroy(mfd);
cleanup_dentry:
        return ERR_PTR(error);
}

static void mds_objids_from_lmm(obd_id *ids, struct lov_mds_md *lmm,
                                struct lov_desc *desc)
{
        int i;
        for (i = 0; i < le32_to_cpu(lmm->lmm_stripe_count); i++) {
                ids[le32_to_cpu(lmm->lmm_objects[i].l_ost_idx)] =
                        le64_to_cpu(lmm->lmm_objects[i].l_object_id);
        }
}

/* Must be called with i_sem held */
static int mds_create_objects(struct ptlrpc_request *req, int offset,
                              struct mds_update_record *rec,
                              struct mds_obd *mds, struct obd_device *obd,
                              struct inode *inode, void **handle, obd_id **ids)
{
        struct obdo *oa;
        struct obd_trans_info oti = { 0 };
        struct mds_body *body;
        struct lov_stripe_md *lsm = NULL;
        struct lov_mds_md *lmm = NULL;
        void *lmm_buf;
        int rc, lmm_bufsize, lmm_size;
        ENTRY;

        if (rec->ur_flags & MDS_OPEN_DELAY_CREATE ||
            !(rec->ur_flags & FMODE_WRITE))
                RETURN(0);

        body = lustre_msg_buf(req->rq_repmsg, 1, sizeof(*body));

        if (!S_ISREG(inode->i_mode))
                RETURN(0);
        if (body->valid & OBD_MD_FLEASIZE)
                RETURN(0);

        OBD_ALLOC(*ids, mds->mds_lov_desc.ld_tgt_count * sizeof(**ids));
        if (*ids == NULL)
                RETURN(-ENOMEM);
        oti.oti_objid = *ids;

        if (*handle == NULL)
                *handle = fsfilt_start(obd, inode, FSFILT_OP_CREATE, NULL);
        if (IS_ERR(*handle)) {
                rc = PTR_ERR(*handle);
                *handle = NULL;
                GOTO(out_ids, rc);
        }

        /* replay case */
        if (rec->ur_fid2->id) {
                body->valid |= OBD_MD_FLBLKSZ | OBD_MD_FLEASIZE;
                lmm_size = rec->ur_eadatalen;
                lmm = rec->ur_eadata;
                LASSERT(lmm);

                mds_objids_from_lmm(*ids, lmm, &mds->mds_lov_desc);

                lmm_buf = lustre_msg_buf(req->rq_repmsg, offset, 0);
                lmm_bufsize = req->rq_repmsg->buflens[offset];
                LASSERT(lmm_buf);
                LASSERT(lmm_bufsize >= lmm_size);
                memcpy(lmm_buf, lmm, lmm_size);
                rc = fsfilt_set_md(obd, inode, *handle, lmm, lmm_size);
                if (rc)
                        CERROR("open replay failed to set md:%d\n", rc);
                RETURN(0);
        }

        oa = obdo_alloc();
        if (oa == NULL)
                GOTO(out_ids, rc = -ENOMEM);
        oa->o_mode = S_IFREG | 0600;
        oa->o_id = inode->i_ino;
        oa->o_generation = inode->i_generation;
        oa->o_uid = 0; /* must have 0 uid / gid on OST */
        oa->o_gid = 0;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLGENER | OBD_MD_FLTYPE |
                OBD_MD_FLMODE | OBD_MD_FLUID | OBD_MD_FLGID;
        oa->o_size = 0;

        obdo_from_inode(oa, inode, OBD_MD_FLTYPE|OBD_MD_FLATIME|OBD_MD_FLMTIME|
                        OBD_MD_FLCTIME);

        /* check if things like lstripe/lfs stripe are sending us the ea */
        if (rec->ur_flags & MDS_OPEN_HAS_EA) {
                rc = obd_iocontrol(OBD_IOC_LOV_SETSTRIPE, mds->mds_osc_exp,
                                   0, &lsm, rec->ur_eadata);
                if (rc)
                        GOTO(out_oa, rc);
        }

        rc = obd_create(mds->mds_osc_exp, oa, &lsm, &oti);
        if (rc) {
                int level = D_ERROR;
                if (rc == -ENOSPC)
                        level = D_INODE;
                CDEBUG(level, "error creating objects for inode %lu: rc = %d\n",
                       inode->i_ino, rc);
                if (rc > 0) {
                        CERROR("obd_create returned invalid rc %d\n", rc);
                        rc = -EIO;
                }
                GOTO(out_oa, rc);
        }

        if (inode->i_size) {
                oa->o_size = inode->i_size;
                obdo_from_inode(oa, inode, OBD_MD_FLTYPE|OBD_MD_FLATIME|
                                OBD_MD_FLMTIME| OBD_MD_FLCTIME| OBD_MD_FLSIZE);
                rc = obd_setattr(mds->mds_osc_exp, oa, lsm, &oti);
                if (rc) {
                        CERROR("error setting attrs for inode %lu: rc %d\n",
                               inode->i_ino, rc);
                        if (rc > 0) {
                                CERROR("obd_setattr returned bad rc %d\n", rc);
                                rc = -EIO;
                        }
                        GOTO(out_oa, rc);
                }
        }

        body->valid |= OBD_MD_FLBLKSZ | OBD_MD_FLEASIZE;
        obdo_refresh_inode(inode, oa, OBD_MD_FLBLKSZ);

        LASSERT(lsm && lsm->lsm_object_id);
        lmm = NULL;
        rc = obd_packmd(mds->mds_osc_exp, &lmm, lsm);
        if (!rec->ur_fid2->id)
                obd_free_memmd(mds->mds_osc_exp, &lsm);
        LASSERT(rc >= 0);
        lmm_size = rc;
        body->eadatasize = rc;
        rc = fsfilt_set_md(obd, inode, *handle, lmm, lmm_size);
        lmm_buf = lustre_msg_buf(req->rq_repmsg, offset, 0);
        lmm_bufsize = req->rq_repmsg->buflens[offset];
        LASSERT(lmm_buf);
        LASSERT(lmm_bufsize >= lmm_size);

        memcpy(lmm_buf, lmm, lmm_size);
        obd_free_diskmd(mds->mds_osc_exp, &lmm);
 out_oa:
        oti_free_cookies(&oti);
        obdo_free(oa);
 out_ids:
        if (rc) {
                OBD_FREE(*ids, mds->mds_lov_desc.ld_tgt_count * sizeof(**ids));
                *ids = NULL;
        }
        RETURN(rc);
}

static void reconstruct_open(struct mds_update_record *rec, int offset,
                             struct ptlrpc_request *req,
                             struct lustre_handle *child_lockh)
{
        struct ptlrpc_request *oldreq = req->rq_export->exp_outstanding_reply;
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_client_data *mcd = med->med_mcd;
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_file_data *mfd;
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *parent, *child;
        struct ldlm_reply *rep;
        struct mds_body *body;
        int rc;
        struct list_head *t;
        int put_child = 1;
        ENTRY;

        LASSERT(offset == 2);                  /* only called via intent */
        rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*rep));
        body = lustre_msg_buf(req->rq_repmsg, 1, sizeof (*body));

        /* copy rc, transno and disp; steal locks */
        mds_req_from_mcd(req, mcd);
        intent_set_disposition(rep, mcd->mcd_last_data);

        /* Only replay if create or open actually happened. */
        if (!intent_disposition(rep, DISP_OPEN_CREATE | DISP_OPEN_OPEN) ) {
                EXIT;
                return; /* error looking up parent or child */
        }

        parent = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        LASSERT(!IS_ERR(parent));

        child = ll_lookup_one_len(rec->ur_name, parent, rec->ur_namelen - 1);
        LASSERT(!IS_ERR(child));

        if (!child->d_inode) {
                GOTO(out_dput, 0); /* child not present to open */
        }

        /* At this point, we know we have a child. We'll send
         * it back _unless_ it not created and open failed.
         */
        if (intent_disposition(rep, DISP_OPEN_OPEN) &&
            !intent_disposition(rep, DISP_OPEN_CREATE) &&
            req->rq_status) {
                GOTO(out_dput, 0);
        }

        /* get lock (write for O_CREAT, read otherwise) */

        mds_pack_inode2fid(&body->fid1, child->d_inode);
        mds_pack_inode2body(body, child->d_inode);
        if (S_ISREG(child->d_inode->i_mode)) {
                rc = mds_pack_md(obd, req->rq_repmsg, 2, body,
                                 child->d_inode, 1);

                if (rc)
                        LASSERT(rc == req->rq_status);

                /* If we have LOV EA data, the OST holds size, mtime */
                if (!(body->valid & OBD_MD_FLEASIZE))
                        body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                        OBD_MD_FLATIME | OBD_MD_FLMTIME);
        } else {
                /* XXX need to check this case */
        }

        /* If we're opening a file without an EA, change to a write
           lock (unless we already have one). */

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
        list_for_each(t, &med->med_open_head) {
                mfd = list_entry(t, struct mds_file_data, mfd_list);
                if (mfd->mfd_xid == req->rq_xid)
                        break;
                mfd = NULL;
        }

        if (oldreq != NULL) {
                /* if we're not recovering, it had better be found */
                LASSERT(mfd != NULL);
        } else if (mfd == NULL) {
                mntget(mds->mds_vfsmnt);
                CERROR("Re-opened file \n");
                mfd = mds_dentry_open(child, mds->mds_vfsmnt,
                                      rec->ur_flags & ~MDS_OPEN_TRUNC, req);
                if (!mfd) {
                        CERROR("mds: out of memory\n");
                        GOTO(out_dput, req->rq_status = -ENOMEM);
                }
                put_child = 0;
        }

 out_dput:
        if (put_child)
                l_dput(child);
        l_dput(parent);
        EXIT;
}

/* do NOT or the MAY_*'s, you'll get the weakest */
static int accmode(int flags)
{
        int res = 0;

        if (flags & FMODE_READ)
                res = MAY_READ;
        if (flags & (FMODE_WRITE|MDS_OPEN_TRUNC))
                res |= MAY_WRITE;
        if (flags & FMODE_EXEC)
                res = MAY_EXEC;
        return res;
}

/* Handles object creation, actual opening, and I/O epoch */
static int mds_finish_open(struct ptlrpc_request *req, struct dentry *dchild,
                           struct mds_body *body, int flags, void **handle,
                           struct mds_update_record *rec,struct ldlm_reply *rep)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_file_data *mfd = NULL;
        obd_id *ids = NULL; /* object IDs created */
        int rc;
        ENTRY;

        /* atomically create objects if necessary */
        down(&dchild->d_inode->i_sem);
        if (S_ISREG(dchild->d_inode->i_mode) &&
            !(body->valid & OBD_MD_FLEASIZE)) {
                rc = mds_pack_md(obd, req->rq_repmsg, 2, body,
                                 dchild->d_inode, 0);
                if (rc) {
                        up(&dchild->d_inode->i_sem);
                        RETURN(rc);
                }
        }
        if (rec != NULL) {
                /* no EA: create objects */
                rc = mds_create_objects(req, 2, rec, mds, obd,
                                        dchild->d_inode, handle, &ids);
                if (rc) {
                        CERROR("mds_create_objects: rc = %d\n", rc);
                        up(&dchild->d_inode->i_sem);
                        RETURN(rc);
                }
        }
        /* If the inode has EA data, then OSTs hold size, mtime */
        if (S_ISREG(dchild->d_inode->i_mode) &&
            !(body->valid & OBD_MD_FLEASIZE)) {
                body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                OBD_MD_FLATIME | OBD_MD_FLMTIME);
        }
        up(&dchild->d_inode->i_sem);

        intent_set_disposition(rep, DISP_OPEN_OPEN);
        mfd = mds_dentry_open(dchild, mds->mds_vfsmnt, flags, req);
        if (IS_ERR(mfd))
                RETURN(PTR_ERR(mfd));

        CDEBUG(D_INODE, "mfd %p, cookie "LPX64"\n", mfd,
               mfd->mfd_handle.h_cookie);
        if (ids != NULL) {
                mds_lov_update_objids(obd, ids);
                OBD_FREE(ids, sizeof(*ids) * mds->mds_lov_desc.ld_tgt_count);
        }
        if (rc)
                mds_mfd_destroy(mfd);
        RETURN(rc);
}

static int mds_open_by_fid(struct ptlrpc_request *req, struct ll_fid *fid,
                           struct mds_body *body, int flags,
                           struct mds_update_record *rec,struct ldlm_reply *rep)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct inode *pending_dir = mds->mds_pending_dir->d_inode;
        struct dentry *dchild;
        char fidname[LL_FID_NAMELEN];
        int fidlen = 0, rc;
        void *handle = NULL;
        ENTRY;

        down(&pending_dir->i_sem);
        fidlen = ll_fid2str(fidname, fid->id, fid->generation);
        dchild = lookup_one_len(fidname, mds->mds_pending_dir, fidlen);
        if (IS_ERR(dchild)) {
                up(&pending_dir->i_sem);
                rc = PTR_ERR(dchild);
                CERROR("error looking up %s in PENDING: rc = %d\n",fidname, rc);
                RETURN(rc);
        }

        if (dchild->d_inode != NULL) {
                up(&pending_dir->i_sem);
                mds_inode_set_orphan(dchild->d_inode);
                mds_pack_inode2fid(&body->fid1, dchild->d_inode);
                mds_pack_inode2body(body, dchild->d_inode);
                intent_set_disposition(rep, DISP_LOOKUP_EXECD);
                intent_set_disposition(rep, DISP_LOOKUP_POS);
                CWARN("Orphan %s found and opened in PENDING directory\n",
                       fidname);
                goto open;
        }
        dput(dchild);
        up(&pending_dir->i_sem);

        /* We didn't find it in PENDING so it isn't an orphan.  See
         * if it was a regular inode that was previously created. */
        dchild = mds_fid2dentry(mds, fid, NULL);
        if (IS_ERR(dchild))
                RETURN(PTR_ERR(dchild));

        mds_pack_inode2fid(&body->fid1, dchild->d_inode);
        mds_pack_inode2body(body, dchild->d_inode);
        intent_set_disposition(rep, DISP_LOOKUP_EXECD);
        intent_set_disposition(rep, DISP_LOOKUP_POS);

 open:
        rc = mds_finish_open(req, dchild, body, flags, &handle, rec, rep);
        rc = mds_finish_transno(mds, dchild ? dchild->d_inode : NULL, handle,
                                req, rc, rep ? rep->lock_policy_res1 : 0);
        /* XXX what do we do here if mds_finish_transno itself failed? */

        l_dput(dchild);
        RETURN(rc);
}

int mds_pin(struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_body *request_body, *reply_body;
        struct obd_run_ctxt saved;
        int rc, size = sizeof(*reply_body);
        ENTRY;

        request_body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof(*request_body));

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc)
                RETURN(rc);
        reply_body = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*reply_body));

        push_ctxt(&saved, &obd->obd_ctxt, NULL);
        rc = mds_open_by_fid(req, &request_body->fid1, reply_body,
                             request_body->flags, NULL, NULL);
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);

        RETURN(rc);
}

/*  Get a lock on the ino to sync with creation WRT inode reuse (bug 2029).
 *  If child_lockh is NULL we just get the lock as a barrier to wait for
 *  other holders of this lock, and drop it right away again. */
int mds_lock_new_child(struct obd_device *obd, struct inode *inode,
                       struct lustre_handle *child_lockh)
{
        struct ldlm_res_id child_res_id = { .name = { inode->i_ino } };
        struct lustre_handle lockh;
        int lock_flags = 0;
        int rc;

        if (child_lockh == NULL)
                child_lockh = &lockh;

        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                              child_res_id, LDLM_PLAIN, NULL, 0,
                              LCK_EX, &lock_flags, ldlm_completion_ast,
                              mds_blocking_ast, NULL, child_lockh);
        if (rc != ELDLM_OK)
                CERROR("ldlm_cli_enqueue: %d\n", rc);
        else if (child_lockh == &lockh)
                ldlm_lock_decref(child_lockh, LCK_EX);

        return rc;
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
        int parent_mode = LCK_PR;
        void *handle = NULL;
        struct dentry_params dp;
        ENTRY;

        if (offset == 2) { /* intent */
                rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*rep));
                body = lustre_msg_buf(req->rq_repmsg, 1, sizeof (*body));
        } else if (offset == 0) { /* non-intent reint */
                body = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*body));
        } else {
                body = NULL;
                LBUG();
        }

        MDS_CHECK_RESENT(req, reconstruct_open(rec, offset, req, child_lockh));

        /* Step 0: If we are passed a fid, then we assume the client already
         * opened this file and is only replaying the RPC, so we open the
         * inode by fid (at some large expense in security). */
        if (rec->ur_fid2->id) {
                rc = mds_open_by_fid(req, rec->ur_fid2, body, rec->ur_flags,
                                     rec, rep);
                if (rc != -ENOENT)
                        RETURN(rc);
                /* We didn't find the correct inode on disk either, so we
                 * need to re-create it via a regular replay. */
                LASSERT(rec->ur_flags & MDS_OPEN_CREAT);
        }
        LASSERT(offset == 2); /* If we got here, we must be called via intent */

        med = &req->rq_export->exp_mds_data;
        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OPEN_PACK)) {
                CERROR("test case OBD_FAIL_MDS_OPEN_PACK\n");
                RETURN(-ENOMEM);
        }

        acc_mode = accmode(rec->ur_flags);

        /* Step 1: Find and lock the parent */
        if (rec->ur_flags & O_CREAT)
                parent_mode = LCK_PW;
        dparent = mds_fid2locked_dentry(obd, rec->ur_fid1, NULL, parent_mode,
                                        &parent_lockh, rec->ur_name,
                                        rec->ur_namelen - 1);
        if (IS_ERR(dparent)) {
                rc = PTR_ERR(dparent);
                CERROR("parent lookup error %d\n", rc);
                GOTO(cleanup, rc);
        }
        LASSERT(dparent->d_inode != NULL);

        cleanup_phase = 1; /* parent dentry and lock */

        /* Step 2: Lookup the child */
        dchild = ll_lookup_one_len(rec->ur_name, dparent, rec->ur_namelen - 1);
        if (IS_ERR(dchild))
                GOTO(cleanup, rc = PTR_ERR(dchild));

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

                intent_set_disposition(rep, DISP_OPEN_CREATE);
                handle = fsfilt_start(obd, dparent->d_inode, FSFILT_OP_CREATE,
                                      NULL);
                if (IS_ERR(handle)) {
                        rc = PTR_ERR(handle);
                        handle = NULL;
                        GOTO(cleanup, rc);
                }
                dchild->d_fsdata = (void *) &dp;
                dp.p_ptr = req;
                dp.p_inum = ino;

                rc = ll_vfs_create(dparent->d_inode, dchild, rec->ur_mode,NULL);
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

                iattr.ia_uid = rec->ur_fsuid;
                if (dparent->d_inode->i_mode & S_ISGID)
                        iattr.ia_gid = dparent->d_inode->i_gid;
                else
                        iattr.ia_gid = rec->ur_fsgid;

                iattr.ia_valid = ATTR_UID | ATTR_GID | ATTR_ATIME |
                        ATTR_MTIME | ATTR_CTIME;

                rc = fsfilt_setattr(obd, dchild, handle, &iattr, 0);
                if (rc)
                        CERROR("error on child setattr: rc = %d\n", rc);

                iattr.ia_valid = ATTR_MTIME | ATTR_CTIME;

                rc = fsfilt_setattr(obd, dparent, handle, &iattr, 0);
                if (rc)
                        CERROR("error on parent setattr: rc = %d\n", rc);

                acc_mode = 0;                  /* Don't check for permissions */
        }

        LASSERT(!mds_inode_is_orphan(dchild->d_inode));

        mds_pack_inode2fid(&body->fid1, dchild->d_inode);
        mds_pack_inode2body(body, dchild->d_inode);

        if (S_ISREG(dchild->d_inode->i_mode)) {
                /* Check permissions etc */
                rc = ll_permission(dchild->d_inode, acc_mode, NULL);
                if (rc != 0)
                        GOTO(cleanup, rc);

                /* Can't write to a read-only file */
                if (IS_RDONLY(dchild->d_inode) && (acc_mode & MAY_WRITE) != 0)
                        GOTO(cleanup, rc = -EPERM);

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
                GOTO(cleanup, rc = 0);

        if ((rec->ur_flags & MDS_OPEN_DIRECTORY) &&
            !S_ISDIR(dchild->d_inode->i_mode))
                GOTO(cleanup, rc = -ENOTDIR);

        /* Step 5: mds_open it */
        rc = mds_finish_open(req, dchild, body, rec->ur_flags, &handle, rec,
                             rep);
        GOTO(cleanup, rc);

 cleanup:
        rc = mds_finish_transno(mds, dchild ? dchild->d_inode : NULL, handle,
                                req, rc, rep ? rep->lock_policy_res1 : 0);
        /* XXX what do we do here if mds_finish_transno itself failed? */
        if (created)
                mds_lock_new_child(obd, dchild->d_inode, NULL);

        switch (cleanup_phase) {
        case 2:
                if (rc && created) {
                        int err = vfs_unlink(dparent->d_inode, dchild);
                        if (err) {
                                CERROR("unlink(%*s) in error path: %d\n",
                                       dchild->d_name.len, dchild->d_name.name,
                                       err);
                        }
                }
                l_dput(dchild);
        case 1:
                if (dparent == NULL)
                        break;

                l_dput(dparent);
                if (rc)
                        ldlm_lock_decref(&parent_lockh, parent_mode);
                else
                        ldlm_put_lock_into_req(req, &parent_lockh, parent_mode);
        }
        if (rc == 0)
                atomic_inc(&mds->mds_open_count);
        RETURN(rc);
}

/* Close a "file descriptor" and possibly unlink an orphan from the
 * PENDING directory.
 *
 * If we are being called from mds_disconnect() because the client has
 * disappeared, then req == NULL and we do not update last_rcvd because
 * there is nothing that could be recovered by the client at this stage
 * (it will not even _have_ an entry in last_rcvd anymore).
 *
 * Returns EAGAIN if the client needs to get more data and re-close. */
int mds_mfd_close(struct ptlrpc_request *req, struct obd_device *obd,
                  struct mds_file_data *mfd, int unlink_orphan)
{
        struct inode *inode = mfd->mfd_dentry->d_inode;
        char fidname[LL_FID_NAMELEN];
        int last_orphan, fidlen, rc = 0, cleanup_phase = 0;
        struct dentry *pending_child = NULL;
        struct mds_obd *mds = &obd->u.mds;
        struct inode *pending_dir = mds->mds_pending_dir->d_inode;
        void *handle = NULL;
        struct mds_body *request_body, *reply_body;
        struct dentry_params dp;
        ENTRY;

        if (req != NULL) {
                request_body = lustre_msg_buf(req->rq_reqmsg, 0,
                                              sizeof(*request_body));
                reply_body = lustre_msg_buf(req->rq_repmsg, 0,
                                            sizeof(*reply_body));
        }

        fidlen = ll_fid2str(fidname, inode->i_ino, inode->i_generation);

        last_orphan = mds_open_orphan_dec_test(inode) &&
                mds_inode_is_orphan(inode);

        /* this is half of the actual "close" */
        if (mfd->mfd_mode & FMODE_WRITE) {
                rc = mds_put_write_access(mds, inode, request_body,
                                          last_orphan && unlink_orphan);
        } else if (mfd->mfd_mode & FMODE_EXEC) {
                mds_allow_write_access(inode);
        }

        if (last_orphan && unlink_orphan) {
                LASSERT(rc == 0); /* mds_put_write_access must have succeeded */

                CWARN("destroying orphan object %s\n", fidname);

                /* Sadly, there is no easy way to save pending_child from
                 * mds_reint_unlink() into mfd, so we need to re-lookup,
                 * but normally it will still be in the dcache. */
                pending_dir = mds->mds_pending_dir->d_inode;
                down(&pending_dir->i_sem);
                cleanup_phase = 1; /* up(i_sem) when finished */
                pending_child = lookup_one_len(fidname, mds->mds_pending_dir,
                                               fidlen);
                if (IS_ERR(pending_child))
                        GOTO(cleanup, rc = PTR_ERR(pending_child));
                LASSERT(pending_child->d_inode != NULL);

                cleanup_phase = 2; /* dput(pending_child) when finished */
                handle = fsfilt_start(obd, pending_dir, FSFILT_OP_UNLINK_LOG,
                                      NULL);
                if (IS_ERR(handle)) {
                        rc = PTR_ERR(handle);
                        handle = NULL;
                        GOTO(cleanup, rc);
                }

#ifdef ENABLE_ORPHANS
                if (req != NULL &&
                    (reply_body->valid & OBD_MD_FLEASIZE) &&
                    mds_log_op_unlink(obd, pending_child->d_inode,
                                      req->rq_repmsg, 1) > 0) {
                        reply_body->valid |= OBD_MD_FLCOOKIE;
                }
#endif
                pending_child->d_fsdata = (void *) &dp;
                dp.p_inum = 0;
                dp.p_ptr = req;
                if (S_ISDIR(pending_child->d_inode->i_mode))
                        rc = vfs_rmdir(pending_dir, pending_child);
                else
                        rc = vfs_unlink(pending_dir, pending_child);
                if (rc)
                        CERROR("error unlinking orphan %s: rc %d\n",fidname,rc);
        } else if (mfd->mfd_mode & FMODE_WRITE && rc == 0) {
                /* Update the on-disk attributes if this was the last write
                 * close, and all information was provided (i.e., rc == 0)
                 *
                 * XXX this should probably be abstracted with mds_reint_setattr
                 */
#if 0
                struct iattr iattr;

                /* XXX can't set block count with fsfilt_setattr (!) */
                iattr.ia_valid = ATTR_CTIME | ATTR_ATIME |
                        ATTR_MTIME | ATTR_SIZE;
                iattr.ia_atime = request_body->atime;
                iattr.ia_ctime = request_body->ctime;
                iattr.ia_mtime = request_body->mtime;
                iattr.ia_size = request_body->size;
                /* iattr.ia_blocks = request_body->blocks */

                handle = fsfilt_start(obd, inode, FSFILT_OP_SETATTR, NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                rc = fsfilt_setattr(obd, mfd->mfd_dentry, handle, &iattr, 0);
                if (rc)
                        CERROR("error in setattr(%s): rc %d\n", fidname, rc);
#endif
        }
        /* If other clients have this file open for write, rc will be > 0 */
        if (rc > 0)
                rc = 0;
        l_dput(mfd->mfd_dentry);
        mds_mfd_destroy(mfd);

 cleanup:
        atomic_dec(&mds->mds_open_count);
        if (req) {
                rc = mds_finish_transno(mds, pending_dir, handle, req, rc, 0);
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
                up(&pending_dir->i_sem);
        }
        RETURN(rc);
}

int mds_close(struct ptlrpc_request *req)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_body *body;
        struct mds_file_data *mfd;
        struct obd_run_ctxt saved;
        struct inode *inode;
        int rc, repsize[3] = {sizeof(struct mds_body),
                              obd->u.mds.mds_max_mdsize,
                              obd->u.mds.mds_max_cookiesize};
        ENTRY;

        rc = lustre_pack_reply(req, 3, repsize, NULL);
        if (rc) {
                CERROR("lustre_pack_reply: rc = %d\n", rc);
                req->rq_status = rc;
        } else {
                MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));
        }

        body = lustre_swab_reqbuf(req, 0, sizeof(*body), lustre_swab_mds_body);
        if (body == NULL) {
                CERROR("Can't unpack body\n");
                req->rq_status = -EFAULT;
                RETURN(-EFAULT);
        }

        if (body->flags & MDS_BFLAG_UNCOMMITTED_WRITES)
                /* do some stuff */ ;

        mfd = mds_handle2mfd(&body->handle);
        if (mfd == NULL) {
                DEBUG_REQ(D_ERROR, req, "no handle for file close ino "LPD64
                          ": cookie "LPX64, body->fid1.id, body->handle.cookie);
                req->rq_status = -ESTALE;
                RETURN(-ESTALE);
        }

        inode = mfd->mfd_dentry->d_inode;
        if (mds_inode_is_orphan(inode) && mds_open_orphan_count(inode) == 1) {
                body = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*body));
                LASSERT(body != NULL);

                mds_pack_inode2fid(&body->fid1, inode);
                mds_pack_inode2body(body, inode);
                mds_pack_md(obd, req->rq_repmsg, 1, body, inode, 1);
        }
        spin_lock(&med->med_open_lock);
        list_del(&mfd->mfd_list);
        spin_unlock(&med->med_open_lock);

        push_ctxt(&saved, &obd->obd_ctxt, NULL);
        req->rq_status = mds_mfd_close(rc ? NULL : req, obd, mfd, 1);
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_CLOSE_PACK)) {
                CERROR("test case OBD_FAIL_MDS_CLOSE_PACK\n");
                req->rq_status = -ENOMEM;
                mds_mfd_put(mfd);
                RETURN(-ENOMEM);
        }

        mds_mfd_put(mfd);
        RETURN(0);
}

int mds_done_writing(struct ptlrpc_request *req)
{
        struct mds_body *body;
        int rc, size = sizeof(struct mds_body);
        ENTRY;

        MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));

        body = lustre_swab_reqbuf(req, 0, sizeof(*body), lustre_swab_mds_body);
        if (body == NULL) {
                CERROR("Can't unpack body\n");
                req->rq_status = -EFAULT;
                RETURN(-EFAULT);
        }

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc) {
                CERROR("lustre_pack_reply: rc = %d\n", rc);
                req->rq_status = rc;
        }

        RETURN(0);
}
