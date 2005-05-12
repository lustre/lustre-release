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

#include <linux/obd_class.h>
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

#ifdef IFILTERDATA_ACTUALLY_USED
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
#endif /*IFILTERDATA_ACTUALLY_USED*/

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

#ifdef IFILTERDATA_ACTUALLY_USED
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
#endif /*IFILTERDATA_ACTUALLY_USED*/
        if (epoch > mds->mds_io_epoch)
                mds->mds_io_epoch = epoch;
        else
                mds->mds_io_epoch++;
#ifdef IFILTERDATA_ACTUALLY_USED
        MDS_FILTERDATA(inode)->io_epoch = mds->mds_io_epoch;
        CDEBUG(D_INODE, "starting MDS epoch "LPU64" for ino %lu/%u\n",
               mds->mds_io_epoch, inode->i_ino, inode->i_generation);
 out:
#endif /*IFILTERDATA_ACTUALLY_USED*/
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
#ifdef IFILTERDATA_ACTUALLY_USED
        mds_free_filterdata(inode);
#endif
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

        body = lustre_msg_buf(req->rq_repmsg, 1, sizeof (*body));

        if (flags & FMODE_WRITE) {
                /* FIXME: in recovery, need to pass old epoch here */
                error = mds_get_write_access(mds, dentry->d_inode, 0);
                if (error)
                        GOTO(cleanup_mfd, error);
#ifdef IFILTERDATA_ACTUALLY_USED
                body->io_epoch = MDS_FILTERDATA(dentry->d_inode)->io_epoch;
#endif /*IFILTERDATA_ACTUALLY_USED*/
        } else if (flags & FMODE_EXEC) {
                error = mds_deny_write_access(mds, dentry->d_inode);
                if (error)
                        GOTO(cleanup_mfd, error);
        }

        dget(dentry);

        /* Mark the file as open to handle open-unlink. */

        DOWN_WRITE_I_ALLOC_SEM(dentry->d_inode);
        mds_orphan_open_inc(dentry->d_inode);
        UP_WRITE_I_ALLOC_SEM(dentry->d_inode);

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
                              struct dentry *dchild, void **handle, 
                              obd_id **ids)
{
        struct obdo *oa = NULL;
        struct obd_trans_info oti = { 0 };
        struct mds_body *body;
        struct lov_stripe_md *lsm = NULL;
        struct lov_mds_md *lmm = NULL;
        struct inode *inode = dchild->d_inode;
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

        OBD_ALLOC(*ids, mds->mds_dt_desc.ld_tgt_count * sizeof(**ids));
        if (*ids == NULL)
                RETURN(-ENOMEM);
        oti.oti_objid = *ids;

        /* replay case */
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                LASSERT(id_ino(rec->ur_id2));
                body->valid |= OBD_MD_FLBLKSZ | OBD_MD_FLEASIZE;
                lmm_size = rec->ur_eadatalen;
                lmm = rec->ur_eadata;
                LASSERT(lmm);

                if (*handle == NULL)
                        *handle = fsfilt_start(obd,inode,FSFILT_OP_CREATE,NULL);
                if (IS_ERR(*handle)) {
                        rc = PTR_ERR(*handle);
                        *handle = NULL;
                        GOTO(out_oa, rc);
                }

                mds_objids_from_lmm(*ids, lmm, &mds->mds_dt_desc);

                lmm_buf = lustre_msg_buf(req->rq_repmsg, offset, 0);
                lmm_bufsize = req->rq_repmsg->buflens[offset];
                LASSERT(lmm_buf);
                LASSERT(lmm_bufsize >= lmm_size);
                memcpy(lmm_buf, lmm, lmm_size);
                rc = fsfilt_set_md(obd, inode, *handle, lmm,
                                   lmm_size, EA_LOV);
                if (rc)
                        CERROR("open replay failed to set md:%d\n", rc);
                RETURN(0);
        }

        if (OBD_FAIL_CHECK_ONCE(OBD_FAIL_MDS_ALLOC_OBDO))
                GOTO(out_ids, rc = -ENOMEM);

        oa = obdo_alloc();
        if (oa == NULL)
                GOTO(out_ids, rc = -ENOMEM);
        oa->o_mode = S_IFREG | 0600;
        oa->o_id = inode->i_ino;
        oa->o_gr = FILTER_GROUP_FIRST_MDS + mds->mds_num;
        oa->o_generation = inode->i_generation;
        oa->o_uid = 0; /* must have 0 uid / gid on OST */
        oa->o_gid = 0;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLGENER | OBD_MD_FLTYPE |
                OBD_MD_FLMODE | OBD_MD_FLUID | OBD_MD_FLGID | OBD_MD_FLGROUP;
        oa->o_size = 0;

        obdo_from_inode(oa, inode, OBD_MD_FLTYPE|OBD_MD_FLATIME|OBD_MD_FLMTIME|
                        OBD_MD_FLCTIME);

        if (!(rec->ur_flags & MDS_OPEN_HAS_OBJS)) {
                /* check if things like lfs setstripe are sending us the ea */
                if (rec->ur_flags & MDS_OPEN_HAS_EA) {
                        rc = obd_iocontrol(OBD_IOC_LOV_SETSTRIPE,
                                           mds->mds_dt_exp,
                                           0, &lsm, rec->ur_eadata);
                        if (rc)
                                GOTO(out_oa, rc);
                } else {
                        OBD_ALLOC(lmm, mds->mds_max_mdsize);
                        if (lmm == NULL)
                                GOTO(out_oa, rc = -ENOMEM);

                        lmm_size = mds->mds_max_mdsize;
                        rc = mds_get_md(obd, dchild->d_parent->d_inode,
                                        lmm, &lmm_size, 1, 0);
                        if (rc > 0)
                                rc = obd_iocontrol(OBD_IOC_LOV_SETSTRIPE,
                                                   mds->mds_dt_exp,
                                                   0, &lsm, lmm);
                        OBD_FREE(lmm, mds->mds_max_mdsize);
                        if (rc)
                                GOTO(out_oa, rc);
                } 
                LASSERT(oa->o_gr >= FILTER_GROUP_FIRST_MDS);
                rc = obd_create(mds->mds_dt_exp, oa, &lsm, &oti);
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
                rc = obd_iocontrol(OBD_IOC_LOV_SETEA, mds->mds_dt_exp,
                                   0, &lsm, rec->ur_eadata);
                if (rc) {
                        GOTO(out_oa, rc);
                }
                lsm->lsm_object_id = oa->o_id;
                lsm->lsm_object_gr = oa->o_gr;
        }
        if (inode->i_size) {
                oa->o_size = inode->i_size;
                obdo_from_inode(oa, inode, OBD_MD_FLTYPE|OBD_MD_FLATIME|
                                OBD_MD_FLMTIME| OBD_MD_FLCTIME| OBD_MD_FLSIZE);
                rc = obd_setattr(mds->mds_dt_exp, oa, lsm, &oti);
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
        rc = obd_packmd(mds->mds_dt_exp, &lmm, lsm);
        if (!id_ino(rec->ur_id2))
                obd_free_memmd(mds->mds_dt_exp, &lsm);
        LASSERT(rc >= 0);
        lmm_size = rc;
        body->eadatasize = rc;

        if (*handle == NULL)
                *handle = fsfilt_start(obd, inode, FSFILT_OP_CREATE, NULL);
        if (IS_ERR(*handle)) {
                rc = PTR_ERR(*handle);
                *handle = NULL;
                GOTO(out_ids, rc);
        }

        rc = fsfilt_set_md(obd, inode, *handle, lmm,
                           lmm_size, EA_LOV);
        
        lmm_buf = lustre_msg_buf(req->rq_repmsg, offset, 0);
        lmm_bufsize = req->rq_repmsg->buflens[offset];
        LASSERT(lmm_buf);
        LASSERT(lmm_bufsize >= lmm_size);

        memcpy(lmm_buf, lmm, lmm_size);
        obd_free_diskmd(mds->mds_dt_exp, &lmm);
 out_oa:
        oti_free_cookies(&oti);
        obdo_free(oa);
 out_ids:
        if (rc) {
                OBD_FREE(*ids, mds->mds_dt_desc.ld_tgt_count * sizeof(**ids));
                *ids = NULL;
        }
        if(lsm)
                obd_free_memmd(mds->mds_dt_exp, &lsm);
        RETURN(rc);
}

static void reconstruct_open(struct mds_update_record *rec, int offset,
                             struct ptlrpc_request *req,
                             struct lustre_handle *child_lockh)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_client_data *mcd = med->med_mcd;
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_file_data *mfd;
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *parent = NULL, *dchild;
        struct ldlm_reply *rep;
        struct mds_body *body;
        struct list_head *t;
        int put_child = 1;
        int rc;
        ENTRY;

        LASSERT(offset == 3); /* only called via intent */
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

        if (rec->ur_namelen == 1) {
                CDEBUG(D_HA, "OPEN by fid "DLID4" (RESENT)\n",
                       OLID4(rec->ur_id1));
                dchild = mds_id2dentry(obd, rec->ur_id1, NULL);
        } else {
                parent = mds_id2dentry(obd, rec->ur_id1, NULL);
                LASSERTF(!IS_ERR(parent), "lid "DLID4" rc %ld\n", 
                                OLID4(rec->ur_id1), PTR_ERR(parent));
                dchild = ll_lookup_one_len(rec->ur_name, parent, 
                                rec->ur_namelen - 1);
                LASSERTF(!IS_ERR(dchild), "parent "DLID4" child %s rc %ld\n",
                                OLID4(rec->ur_id1), rec->ur_name, PTR_ERR(dchild));
        }

        if (!dchild->d_inode)
                GOTO(out_dput, 0); /* child not present to open */

        /* At this point, we know we have a child. We'll send
         * it back _unless_ it not created and open failed.  */
        if (intent_disposition(rep, DISP_OPEN_OPEN) &&
            !intent_disposition(rep, DISP_OPEN_CREATE) &&
            req->rq_status)
                GOTO(out_dput, 0);

        /* get lock (write for O_CREAT, read otherwise) */
        mds_pack_inode2body(obd, body, dchild->d_inode, 1);
        if (S_ISREG(dchild->d_inode->i_mode)) {
                rc = mds_pack_md(obd, req->rq_repmsg, 2, body,
                                 dchild->d_inode, 1, 0);

                if (rc)
                        LASSERT(rc == req->rq_status);

                /* If we have LOV EA data, the OST holds size, mtime */
                if (!(body->valid & OBD_MD_FLEASIZE))
                        body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                        OBD_MD_FLATIME | OBD_MD_FLMTIME);
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
        list_for_each(t, &med->med_open_head) {
                mfd = list_entry(t, struct mds_file_data, mfd_list);
                if (mfd->mfd_xid == req->rq_xid)
                        break;
                mfd = NULL;
        }

        /* #warning "XXX fixme" bug 2991 */
        /* Here it used to LASSERT(mfd) if exp_outstanding_reply != NULL.
         * Now that exp_outstanding_reply is a list, it's just using mfd != NULL
         * to detect a re-open */
        if (mfd == NULL) {
                mntget(mds->mds_vfsmnt);
                CERROR("Re-opened file \n");
                mfd = mds_dentry_open(dchild, mds->mds_vfsmnt,
                                      rec->ur_flags & ~MDS_OPEN_TRUNC, req);
                if (!mfd) {
                        CERROR("mds: out of memory\n");
                        GOTO(out_dput, req->rq_status = -ENOMEM);
                }
                put_child = 0;
        } else {
                body->handle.cookie = mfd->mfd_handle.h_cookie;
                CDEBUG(D_INODE, "resend mfd %p, cookie "LPX64"\n", mfd,
                       mfd->mfd_handle.h_cookie);
        }

 out_dput:
        if (put_child)
                l_dput(dchild);
        if (parent)
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
                           struct mds_update_record *rec, struct ldlm_reply *rep)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_file_data *mfd = NULL;
        obd_id *ids = NULL; /* object IDs created */
        unsigned mode;
        int rc = 0;
        ENTRY;

        /* atomically create objects if necessary */
        down(&dchild->d_inode->i_sem);
        mode = dchild->d_inode->i_mode;
        if ((S_ISREG(mode) && !(body->valid & OBD_MD_FLEASIZE)) || 
            (S_ISDIR(mode) && !(body->valid & OBD_MD_FLDIREA))) {
                rc = mds_pack_md(obd, req->rq_repmsg, 2, body,
                                 dchild->d_inode, 0, 0);
                if (rc) {
                        up(&dchild->d_inode->i_sem);
                        RETURN(rc);
                }
        }
        if (rec != NULL) {
                /* no EA: create objects */
                if ((body->valid & OBD_MD_FLEASIZE) &&
                    (rec->ur_flags & MDS_OPEN_HAS_EA)) {
                        up(&dchild->d_inode->i_sem);
                        RETURN(-EEXIST);
                }
                if (!(body->valid & OBD_MD_FLEASIZE)) {
                        /* no EA: create objects */
                        rc = mds_create_objects(req, 2, rec, mds, obd,
                                                dchild, handle, &ids);
                        if (rc) {
                                CERROR("mds_create_objects: rc = %d\n", rc);
                                up(&dchild->d_inode->i_sem);
                                RETURN(rc);
                        }
                }
                if (S_ISREG(dchild->d_inode->i_mode) &&
                    (body->valid & OBD_MD_FLEASIZE)) {
                        rc = mds_revalidate_lov_ea(obd, dchild->d_inode,
                                                   req->rq_repmsg, 2);
                        if (!rc)
                                rc = mds_pack_md(obd, req->rq_repmsg, 2, body,
                                                 dchild->d_inode, 0, 0);
                        if (rc) {
                                up(&dchild->d_inode->i_sem);
                                RETURN(rc);
                        }
                }
        }
        rc = mds_pack_acl(obd, req->rq_repmsg, 3, body, dchild->d_inode);
        if (rc < 0) {
                CERROR("mds_pack_acl: rc = %d\n", rc);
                up(&dchild->d_inode->i_sem);
                RETURN(rc);
        }

        /* If the inode has no EA data, then MDSs hold size, mtime */
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
                mds_dt_update_objids(obd, ids);
                OBD_FREE(ids, sizeof(*ids) * mds->mds_dt_desc.ld_tgt_count);
        }
        //if (rc)
        //        mds_mfd_destroy(mfd);
        RETURN(rc);
}

static int mds_open_by_id(struct ptlrpc_request *req,
                          struct lustre_id *id,
                          struct mds_body *body, int flags,
                          struct mds_update_record *rec,
                          struct ldlm_reply *rep)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct inode *pending_dir = mds->mds_pending_dir->d_inode;
        struct dentry *dchild;
        char idname[LL_ID_NAMELEN];
        int idlen = 0, rc;
        void *handle = NULL;
        ENTRY;

        down(&pending_dir->i_sem);
        idlen = ll_id2str(idname, id_ino(id), id_gen(id));
        dchild = lookup_one_len(idname, mds->mds_pending_dir,
                                idlen);
        if (IS_ERR(dchild)) {
                up(&pending_dir->i_sem);
                rc = PTR_ERR(dchild);
                CERROR("error looking up %s in PENDING: rc = %d\n", 
                       idname, rc);
                RETURN(rc);
        }

        up(&pending_dir->i_sem);
        if (dchild->d_inode != NULL) {
                mds_inode_set_orphan(dchild->d_inode);
                mds_pack_inode2body(req2obd(req), body,
                                    dchild->d_inode, 1);
                
                intent_set_disposition(rep, DISP_LOOKUP_EXECD);
                intent_set_disposition(rep, DISP_LOOKUP_POS);
                CWARN("Orphan %s found and opened in PENDING directory\n",
                       idname);
                goto open;
        }
        l_dput(dchild);

        /*
         * we didn't find it in PENDING so it isn't an orphan.  See if it was a
         * regular inode that was previously created.
         */
        dchild = mds_id2dentry(req2obd(req), id, NULL);
        if (IS_ERR(dchild))
                RETURN(PTR_ERR(dchild));

        mds_pack_inode2body(req2obd(req), body,
                            dchild->d_inode, 1);
        
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

int mds_pin(struct ptlrpc_request *req, int offset)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_body *request_body, *reply_body;
        struct lvfs_run_ctxt saved;
        int rc, size = sizeof(*reply_body);
        ENTRY;

        request_body = lustre_msg_buf(req->rq_reqmsg, offset,
                                      sizeof(*request_body));

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc)
                RETURN(rc);
        reply_body = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*reply_body));

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = mds_open_by_id(req, &request_body->id1, reply_body,
                            request_body->flags, NULL, NULL);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        RETURN(rc);
}

/*
 * get a lock on the ino to sync with creation WRT inode reuse (bug 2029). If
 * child_lockh is NULL we just get the lock as a barrier to wait for other
 * holders of this lock, and drop it right away again.
 */
int mds_lock_new_child(struct obd_device *obd, struct inode *inode,
                       struct lustre_handle *child_lockh)
{
        struct ldlm_res_id child_res_id = { .name = { inode->i_ino, 0, 1, 0 } };
        struct lustre_handle lockh;
        int lock_flags = 0;
        int rc;
        ENTRY;

        if (child_lockh == NULL)
                child_lockh = &lockh;

        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, child_res_id,
                              LDLM_PLAIN, NULL, LCK_EX, &lock_flags,
                              mds_blocking_ast, ldlm_completion_ast, NULL,
                              NULL, NULL, 0, NULL, child_lockh);
        if (rc != ELDLM_OK)
                CERROR("ldlm_cli_enqueue: %d\n", rc);
        else if (child_lockh == &lockh)
                ldlm_lock_decref(child_lockh, LCK_EX);

        RETURN(rc);
}

int mds_open(struct mds_update_record *rec, int offset,
             struct ptlrpc_request *req, struct lustre_handle *child_lockh)
{
        /* XXX ALLOCATE _something_ - 464 bytes on stack here */
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_export_data *med = &req->rq_export->u.eu_mds_data;
        struct mds_obd *mds = mds_req2mds(req);
        struct ldlm_reply *rep = NULL;
        struct mds_body *body = NULL;
        struct dentry *dchild = NULL, *dparent = NULL;
        struct lustre_handle parent_lockh[2] = {{0}, {0}};
        int rc = 0, cleanup_phase = 0, acc_mode, created = 0;
        int parent_mode = LCK_PR;
        void *handle = NULL;
        struct dentry_params dp;
        struct mea *mea = NULL;
        int mea_size, update_mode;
        int child_mode = LCK_PR;
        /* Always returning LOOKUP lock if open succesful to guard
           dentry on client. */
        ldlm_policy_data_t policy = {.l_inodebits={MDS_INODELOCK_LOOKUP}};
        struct ldlm_res_id child_res_id = { .name = {0}};
        int lock_flags = 0;
        ENTRY;

        DEBUG_REQ(D_INODE, req, "parent "DLID4" name %*s mode %o",
                  OLID4(rec->ur_id1), rec->ur_namelen - 1, rec->ur_name,
                  rec->ur_mode);

        OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_PAUSE_OPEN | OBD_FAIL_ONCE,
                         (obd_timeout + 1) / 4);

        if (offset == 3) { /* intent */
                rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*rep));
                body = lustre_msg_buf(req->rq_repmsg, 1, sizeof (*body));
        } else if (offset == 1) { /* non-intent reint */
                body = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*body));
        } else {
                body = NULL;
                LBUG();
        }

        MDS_CHECK_RESENT(req, reconstruct_open(rec, offset, req, child_lockh));

        /*
         * Step 0: If we are passed a id, then we assume the client already
         * opened this file and is only replaying the RPC, so we open the inode
         * by fid (at some large expense in security).
         */
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                CDEBUG(D_HA, "open obj "DLID4" name %*s mode %o\n",
                       OLID4(rec->ur_id2), rec->ur_namelen - 1, 
                       rec->ur_name, rec->ur_mode);

                LASSERT(id_ino(rec->ur_id2));

                rc = mds_open_by_id(req, rec->ur_id2, body, rec->ur_flags,
                                    rec, rep);
                if (rc != -ENOENT) {
                        mds_body_do_reverse_map(med, body);
                        RETURN(rc);
                }

                /* We didn't find the correct inode on disk either, so we
                 * need to re-create it via a regular replay. */
                LASSERT(rec->ur_flags & MDS_OPEN_CREAT);
        } else {
                LASSERT(!id_ino(rec->ur_id2));
        }

        LASSERT(offset == 3); /* If we got here, we must be called via intent */

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OPEN_PACK)) {
                CERROR("test case OBD_FAIL_MDS_OPEN_PACK\n");
                RETURN(-ENOMEM);
        }

        acc_mode = accmode(rec->ur_flags);

        /* Step 1: Find and lock the parent */
        if (rec->ur_flags & MDS_OPEN_CREAT) {
                /* XXX Well, in fact we only need this lock mode change if
                   in addition to O_CREAT, the file does not exist.
                   But we do not know if it exists or not yet */
                parent_mode = LCK_PW;
        }
        
        if (rec->ur_namelen == 1) {
                /* client (LMV) wants to open the file by id */
                CDEBUG(D_OTHER, "OPEN by id "DLID4"\n", OLID4(rec->ur_id1));
                dchild = mds_id2dentry(obd, rec->ur_id1, NULL);
                if (IS_ERR(dchild)) {
                        rc = PTR_ERR(dparent);
                        CERROR("child lookup by an id error %d\n", rc);
                        GOTO(cleanup, rc);
                }
                goto got_child;
        }
       
restart:
        dparent = mds_id2locked_dentry(obd, rec->ur_id1, NULL, parent_mode,
                                       parent_lockh, &update_mode, rec->ur_name,
                                       rec->ur_namelen - 1, MDS_INODELOCK_UPDATE);
        if (IS_ERR(dparent)) {
                rc = PTR_ERR(dparent);
                if (rc != -ENOENT) {
                        CERROR("parent lookup for "DLID4" failed, error %d\n",
                               OLID4(rec->ur_id1), rc);
                } else {
                        /* Just cannot find parent - make it look like
                           usual negative lookup to avoid extra MDS RPC */
                        intent_set_disposition(rep, DISP_LOOKUP_EXECD);
                        intent_set_disposition(rep, DISP_LOOKUP_NEG);
                }
                GOTO(cleanup, rc);
        }
        LASSERT(dparent->d_inode != NULL);

        cleanup_phase = 1; /* parent dentry and lock */

        /* try to retrieve MEA data for this dir */
        rc = mds_md_get_attr(obd, dparent->d_inode, &mea, &mea_size);
        if (rc)
                GOTO(cleanup, rc);
       
        if (mea != NULL) {
                /*
                 * dir is already splitted, check is requested filename should *
                 * live at this MDS or at another one.
                 */
                int i;
                i = mea_name2idx(mea, rec->ur_name, rec->ur_namelen - 1);
                if (mea->mea_master != id_group(&mea->mea_ids[i])) {
                        CDEBUG(D_OTHER,
                               "%s: inapropriate MDS(%d) for %lu/%u:%s."
                               " should be %lu(%d)\n", obd->obd_name,
                               mea->mea_master, dparent->d_inode->i_ino,
                               dparent->d_inode->i_generation, rec->ur_name,
                               (unsigned long)id_group(&mea->mea_ids[i]), i);
                        GOTO(cleanup, rc = -ERESTART);
                }
        }

        /* Step 2: Lookup the child */
        dchild = ll_lookup_one_len(rec->ur_name, dparent, rec->ur_namelen - 1);
        if (IS_ERR(dchild)) {
                rc = PTR_ERR(dchild);
                dchild = NULL; /* don't confuse mds_finish_transno() below */
                GOTO(cleanup, rc);
        }

got_child:
        cleanup_phase = 2; /* child dentry */

        if (dchild->d_flags & DCACHE_CROSS_REF) {
                CDEBUG(D_OTHER, "cross reference: "DLID4"\n", OLID4(rec->ur_id1));
                
                /* we're gonna acquire LOOKUP lock on the child,
                 * but we have already locked parent and our order
                 * may conflict with enqueue_order_locks(). so,
                 * drop parent lock and acquire both the locks in
                 * common order. bug 6190 */
#ifdef S_PDIROPS
                if (parent_lockh[1].cookie != 0)
                        ldlm_lock_decref(parent_lockh + 1, update_mode);
#endif
                ldlm_lock_decref(parent_lockh, parent_mode);
                l_dput(dchild);
                l_dput(dparent);
                cleanup_phase = 0;

                rc = mds_get_parent_child_locked(obd, mds, rec->ur_id1,
                                                 parent_lockh, &dparent,
                                                 LCK_PR, MDS_INODELOCK_UPDATE,
                                                 &update_mode, rec->ur_name,
                                                 rec->ur_namelen, child_lockh,
                                                 &dchild, LCK_PR,
                                                 MDS_INODELOCK_LOOKUP);

                if (rc)
                        GOTO(cleanup, rc);

                if (dchild->d_inode || !(dchild->d_flags & DCACHE_CROSS_REF)) {
                        /* wow! someone unlink and create new one yet */
                        CDEBUG(D_OTHER, "nice race, repeat lookup\n");
                        ldlm_lock_decref(parent_lockh, parent_mode);
                        ldlm_lock_decref(child_lockh, LCK_PR);
                        l_dput(dchild);
                        l_dput(dparent);
                        LASSERT(rec->ur_namelen > 1);
                        GOTO(restart, rc);
                }

                mds_pack_dentry2body(obd, body, dchild, 1);
                intent_set_disposition(rep, DISP_LOOKUP_POS);
                intent_set_disposition(rep, DISP_LOOKUP_EXECD);
                
#ifdef S_PDIROPS
                if (parent_lockh[1].cookie != 0)
                        ldlm_lock_decref(parent_lockh + 1, update_mode);
#endif
                ldlm_lock_decref(parent_lockh, parent_mode);
                if (mea)
                        OBD_FREE(mea, mea_size);
                l_dput(dchild);
                l_dput(dparent);
                RETURN(rc);
        }
        
        intent_set_disposition(rep, DISP_LOOKUP_EXECD);

        if (dchild->d_inode)
                intent_set_disposition(rep, DISP_LOOKUP_POS);
        else
                intent_set_disposition(rep, DISP_LOOKUP_NEG);

        /* Step 3: If the child was negative, and we're supposed to, create it.*/
        if (dchild->d_inode == NULL) {
                unsigned long ino;
                struct iattr iattr;
                struct inode *inode;
                
                ino = (unsigned long)id_ino(rec->ur_id2);
                
                rc = mds_try_to_split_dir(obd, dparent, &mea, 0,
                                          update_mode);
                
                CDEBUG(D_OTHER, "%s: splitted %lu/%u - %d\n",
                       obd->obd_name, dparent->d_inode->i_ino,
                       dparent->d_inode->i_generation, rc);

                if (rc > 0) {
                        /* dir got splitted */
                        GOTO(cleanup, rc = -ERESTART);
                } else if (rc < 0) {
                        /* error happened during spitting */
                        GOTO(cleanup, rc);
                }

                if (!(rec->ur_flags & MDS_OPEN_CREAT)) {
                        /*
                         * dentry is negative and we weren't supposed to create
                         * object, get out of here.
                         */
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

                rc = ll_vfs_create(dparent->d_inode, dchild, rec->ur_mode, NULL);
                if (dchild->d_fsdata == (void *)(unsigned long)ino)
                        dchild->d_fsdata = NULL;

                if (rc) {
                        CDEBUG(D_INODE, "error during create: %d\n", rc);
                        GOTO(cleanup, rc);
                }
                inode = dchild->d_inode;
                if (ino) {
                        LASSERT(ino == inode->i_ino);
                        
                        /* written as part of setattr */
                        inode->i_generation = id_gen(rec->ur_id2);
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
                else {
                        MD_COUNTER_INCREMENT(obd, create);
                }

                down(&dchild->d_inode->i_sem);
                if (ino) {
                        rc = mds_update_inode_sid(obd, dchild->d_inode,
                                                  handle, rec->ur_id2);
                        if (rc) {
                                CERROR("mds_update_inode_sid() failed, "
                                       "rc = %d\n", rc);
                        }
                        id_assign_fid(&body->id1, rec->ur_id2);

                        /* 
                         * make sure, that fid is up-to-date.
                         */
                        mds_set_last_fid(obd, id_fid(rec->ur_id2));
                } else {
                        rc = mds_alloc_inode_sid(obd, dchild->d_inode,
                                                 handle, &body->id1);
                        if (rc) {
                                CERROR("mds_alloc_inode_sid() failed, "
                                       "rc = %d\n", rc);
                        }
                }
                up(&dchild->d_inode->i_sem);
                
                if (!(rec->ur_flags & O_EXCL)) { /* bug 3313 */
                        rc = fsfilt_commit(obd, dchild->d_inode->i_sb,
                                           dchild->d_inode, handle, 
                                           req->rq_export->exp_sync);
                        handle = NULL;
                }

                acc_mode = 0;           /* Don't check for permissions */
        }
        mds_pack_inode2body(obd, body, dchild->d_inode, 1);
	
        LASSERTF(!mds_inode_is_orphan(dchild->d_inode),
                 "dchild %.*s (%p) inode %p\n", dchild->d_name.len,
                 dchild->d_name.name, dchild, dchild->d_inode);

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

        if (S_ISDIR(dchild->d_inode->i_mode)) {
                if (rec->ur_flags & MDS_OPEN_CREAT ||
                    rec->ur_flags & FMODE_WRITE) {
                        /* we are trying to create or write a exist dir */
                        GOTO(cleanup, rc = -EISDIR);
                }
                if (ll_permission(dchild->d_inode, acc_mode, NULL))
                        GOTO(cleanup, rc = -EACCES);

                /* 
                 * here was checking for possible GNS mount points to skip their
                 * open. I removed it as its detection based only on SUID bit is
                 * not reliable. Opening such a dirs should not cause any
                 * problems, at least tests show that. --umka
                 */
        }

        /* if we are following a symlink, don't open */
        if (S_ISLNK(dchild->d_inode->i_mode))
                GOTO(cleanup_no_trans, rc = 0);

        if ((rec->ur_flags & MDS_OPEN_DIRECTORY) &&
            !S_ISDIR(dchild->d_inode->i_mode))
                GOTO(cleanup, rc = -ENOTDIR);
		
	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OPEN_CREATE)) {
		obd_fail_loc = OBD_FAIL_LDLM_REPLY | OBD_FAIL_ONCE;
		GOTO(cleanup, rc = -EAGAIN);
	}
 
        /* Obtain OPEN lock as well */
        policy.l_inodebits.bits |= MDS_INODELOCK_OPEN;

        /* We cannot use acc_mode here, because it is zeroed in case of
           creating a file, so we get wrong lockmode */
        if (accmode(rec->ur_flags) & MAY_WRITE)
    		child_mode = LCK_CW;
        else if (accmode(rec->ur_flags) & MAY_EXEC)
                child_mode = LCK_PR;
        else
                child_mode = LCK_CR;

        if (!(lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY)) {
                struct lustre_id sid;
		
		down(&dchild->d_inode->i_sem);
                rc = mds_read_inode_sid(obd, dchild->d_inode, &sid);
                up(&dchild->d_inode->i_sem);
                if (rc) {
                        CERROR("Can't read inode self id, "
                               "inode %lu, rc %d\n",
                               dchild->d_inode->i_ino, rc);
                        GOTO(cleanup, rc);
                }
                
		/* In case of replay we do not get a lock assuming that the
                   caller has it already */
                child_res_id.name[0] = id_fid(&sid);
                child_res_id.name[1] = id_group(&sid);

                rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace,
                                      child_res_id, LDLM_IBITS, &policy,
                                      child_mode, &lock_flags,
                                      mds_blocking_ast, ldlm_completion_ast,
                                      NULL, NULL, NULL, 0, NULL, child_lockh);
                if (rc != ELDLM_OK)
                        GOTO(cleanup, rc);

                cleanup_phase = 3;
        }

        /* Step 5: mds_open it */
        rc = mds_finish_open(req, dchild, body, rec->ur_flags, &handle,
                             rec, rep);

	EXIT;
cleanup:
        rc = mds_finish_transno(mds, dchild ? dchild->d_inode : NULL, handle,
                                req, rc, rep ? rep->lock_policy_res1 : 0);

cleanup_no_trans:
        switch (cleanup_phase) {
        case 3:
                if (rc) {
                        ldlm_lock_decref(child_lockh, child_mode);
                        child_lockh->cookie = 0;
                }
        case 2:
                if (rc && created) {
                        int err = vfs_unlink(dparent->d_inode, dchild);
                        if (err) {
                                CERROR("unlink(%.*s) in error path: %d\n",
                                       dchild->d_name.len, dchild->d_name.name,
                                       err);
                        }
                } else if (created) {
                        mds_lock_new_child(obd, dchild->d_inode, NULL);
                }
                l_dput(dchild);
        case 1:
                if (dparent == NULL)
                        break;

                l_dput(dparent);
#ifdef S_PDIROPS
                if (parent_lockh[1].cookie != 0)
                        ldlm_lock_decref(parent_lockh + 1, update_mode);
#endif
                if (rc)
                        ldlm_lock_decref(parent_lockh, parent_mode);
                else
                        ptlrpc_save_lock (req, parent_lockh, parent_mode);
        }
        if (mea)
                OBD_FREE(mea, mea_size);
        if (rc == 0)
                atomic_inc(&mds->mds_open_count);

        mds_body_do_reverse_map(med, body);

        /*
         * If we have not taken the "open" lock, we may not return 0 here,
         * because caller expects 0 to mean "lock is taken", and it needs
         * nonzero return here for caller to return EDLM_LOCK_ABORTED to
         * client. Later caller should rewrite the return value back to zero
         * if it to be used any further.
         */
        if ((cleanup_phase != 3) && !rc)
                rc = ENOLCK;

        RETURN(rc);
}

/* Close a "file descriptor" and possibly unlink an orphan from the
 * PENDING directory.  Caller must hold child->i_sem, this drops it. 
 *
 * If we are being called from mds_disconnect() because the client has
 * disappeared, then req == NULL and we do not update last_rcvd because
 * there is nothing that could be recovered by the client at this stage
 * (it will not even _have_ an entry in last_rcvd anymore).
 *
 * Returns EAGAIN if the client needs to get more data and re-close. */
int mds_mfd_close(struct ptlrpc_request *req, int offset,
                  struct obd_device *obd, struct mds_file_data *mfd,
                  int unlink_orphan)
{
        struct inode *inode = mfd->mfd_dentry->d_inode;
        char idname[LL_ID_NAMELEN];
        int last_orphan, idlen, rc = 0, cleanup_phase = 0;
        struct dentry *pending_child = NULL;
        struct mds_obd *mds = &obd->u.mds;
        struct inode *pending_dir = mds->mds_pending_dir->d_inode;
        void *handle = NULL;
        struct mds_body *request_body = NULL, *reply_body = NULL;
        struct dentry_params dp;
        struct iattr iattr = { 0 };
        struct llog_create_locks *lcl = NULL;
        ENTRY;

        if (req && req->rq_reqmsg != NULL)
                request_body = lustre_msg_buf(req->rq_reqmsg, offset,
                                              sizeof(*request_body));
        if (req && req->rq_repmsg != NULL)
                reply_body = lustre_msg_buf(req->rq_repmsg, 0,
                                            sizeof(*reply_body));

        idlen = ll_id2str(idname, inode->i_ino, inode->i_generation);
        CDEBUG(D_INODE, "inode %p ino %s nlink %d orphan %d\n", inode, 
               idname, inode->i_nlink, mds_orphan_open_count(inode));

        last_orphan = mds_orphan_open_dec_test(inode) &&
                mds_inode_is_orphan(inode);
        UP_WRITE_I_ALLOC_SEM(inode);

        /* this is half of the actual "close" */
        if (mfd->mfd_mode & FMODE_WRITE) {
                rc = mds_put_write_access(mds, inode, request_body,
                                          last_orphan && unlink_orphan);
        } else if (mfd->mfd_mode & FMODE_EXEC) {
                mds_allow_write_access(inode);
        }

        if (last_orphan && unlink_orphan) {
                struct lov_mds_md *lmm = NULL;
                int stripe_count = 0;
                LASSERT(rc == 0); /* mds_put_write_access must have succeeded */

                if (obd->obd_recovering) {
                        CDEBUG(D_HA, "not remove orphan %s until recovery"
                               " is over\n", idname);
                        GOTO(out, rc);
                }

                CDEBUG(D_HA, "destroying orphan object %s\n", idname);
                
                if ((S_ISREG(inode->i_mode) && inode->i_nlink != 1) ||
                    (S_ISDIR(inode->i_mode) && inode->i_nlink != 2))
                        CERROR("found \"orphan\" %s %s with link count %d\n",
                               S_ISREG(inode->i_mode) ? "file" : "dir",
                               idname, inode->i_nlink);
                /*
                 * sadly, there is no easy way to save pending_child from
                 * mds_reint_unlink() into mfd, so we need to re-lookup, but
                 * normally it will still be in the dcache.
                 */
                down(&pending_dir->i_sem);
                cleanup_phase = 1; /* up(i_sem) when finished */
                pending_child = lookup_one_len(idname, mds->mds_pending_dir,
                                               idlen);
                if (IS_ERR(pending_child))
                        GOTO(cleanup, rc = PTR_ERR(pending_child));
                LASSERT(pending_child->d_inode != NULL);

                cleanup_phase = 2; /* dput(pending_child) when finished */
                if (S_ISDIR(pending_child->d_inode->i_mode)) {
                        rc = vfs_rmdir(pending_dir, pending_child);
                        if (rc)
                                CERROR("error unlinking orphan dir %s: rc %d\n",
                                       idname, rc);
                        goto out;
                }

                if (req != NULL && req->rq_repmsg != NULL) {
                        lmm = lustre_msg_buf(req->rq_repmsg, 1, 0);
                        stripe_count = le32_to_cpu(lmm->lmm_stripe_count);
                }

                handle = fsfilt_start_log(obd, pending_dir, FSFILT_OP_UNLINK,
                                          NULL, stripe_count);
                if (IS_ERR(handle)) {
                        rc = PTR_ERR(handle);
                        handle = NULL;
                        GOTO(cleanup, rc);
                }

                pending_child->d_fsdata = (void *) &dp;
                dp.p_inum = 0;
                dp.p_ptr = req;
                rc = vfs_unlink(pending_dir, pending_child);
                if (rc)
                        CERROR("error unlinking orphan %s: rc %d\n",
                               idname, rc);

                if (req != NULL && req->rq_repmsg != NULL &&
                    (reply_body->valid & OBD_MD_FLEASIZE) &&
                    mds_log_op_unlink(obd, pending_child->d_inode,
                                      lmm, req->rq_repmsg->buflens[1],
                                      lustre_msg_buf(req->rq_repmsg, 2, 0),
                                      req->rq_repmsg->buflens[2], &lcl) > 0) {
                        reply_body->valid |= OBD_MD_FLCOOKIE;
                }

                goto out; /* Don't bother updating attrs on unlinked inode */
        }

#if 0
        if (request_body != NULL && mfd->mfd_mode & FMODE_WRITE && rc == 0) {
                /* Update the on-disk attributes if this was the last write
                 * close, and all information was provided (i.e., rc == 0)
                 *
                 * XXX this should probably be abstracted with mds_reint_setattr
                 */

                if (request_body->valid & OBD_MD_FLMTIME &&
                    LTIME_S(request_body->mtime) > LTIME_S(inode->i_mtime)) {
                        LTIME_S(iattr.ia_mtime) = LTIME_S(request_body->mtime);
                        iattr.ia_valid |= ATTR_MTIME;
                }
                if (request_body->valid & OBD_MD_FLCTIME &&
                    LTIME_S(request_body->ctime) > LTIME_S(inode->i_ctime)) {
                        LTIME_S(iattr.ia_ctime) = LTIME_S(request_body->ctime);
                        iattr.ia_valid |= ATTR_CTIME;
                }

                /* XXX can't set block count with fsfilt_setattr (!) */
                if (request_body->valid & OBD_MD_FLSIZE) {
                        iattr.ia_valid |= ATTR_SIZE;
                        iattr.ia_size = request_body->size;
                }
                /* if (request_body->valid & OBD_MD_FLBLOCKS) {
                        iattr.ia_valid |= ATTR_BLOCKS;
                        iattr.ia_blocks = request_body->blocks
                } */

        }
#endif
        if (request_body != NULL && request_body->valid & OBD_MD_FLATIME) {
                /* Only start a transaction to write out only the atime if
                 * it is more out-of-date than the specified limit.  If we
                 * are already going to write out the atime then do it anyway.
                 * */
                if ((request_body->atime >
                     LTIME_S(inode->i_atime) + MAX_ATIME_DIFF) ||
                    (iattr.ia_valid != 0 &&
                     request_body->atime > LTIME_S(inode->i_atime))) {
                        LTIME_S(iattr.ia_atime) = request_body->atime;
                        iattr.ia_valid |= ATTR_ATIME;
                }
        }

        if (iattr.ia_valid != 0) {
                handle = fsfilt_start(obd, inode, FSFILT_OP_SETATTR, NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                rc = fsfilt_setattr(obd, mfd->mfd_dentry, handle, &iattr, 0);
                if (rc)
                        CERROR("error in setattr(%s): rc %d\n", idname, rc);
        }
out:
        /* If other clients have this file open for write, rc will be > 0 */
        if (rc > 0)
                rc = 0;
        l_dput(mfd->mfd_dentry);
        mds_mfd_destroy(mfd);

 cleanup:
        atomic_dec(&mds->mds_open_count);
        if (req != NULL && reply_body != NULL) {
                rc = mds_finish_transno(mds, pending_dir, handle, req, rc, 0);
        } else if (handle) {
                int err, force_sync = 0;

                if (req && req->rq_export)
                        force_sync = req->rq_export->exp_sync;

                err = fsfilt_commit(obd, mds->mds_sb, pending_dir, handle, 
                                    force_sync);
                if (err) {
                        CERROR("error committing close: %d\n", err);
                        if (!rc)
                                rc = err;
                }
        }

        switch (cleanup_phase) {
        case 2:
                if (lcl != NULL)
                        ptlrpc_save_llog_lock(req, lcl);
                dput(pending_child);
        case 1:
                up(&pending_dir->i_sem);
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
        int rc, repsize[3] = {sizeof(struct mds_body),
                              obd->u.mds.mds_max_mdsize,
                              obd->u.mds.mds_max_cookiesize};
        ENTRY;
        MD_COUNTER_INCREMENT(obd, close);

        rc = lustre_pack_reply(req, 3, repsize, NULL);
        if (rc) {
                CERROR("lustre_pack_reply: rc = %d\n", rc);
                req->rq_status = rc;
        } else {
                MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));
        }

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                DEBUG_REQ(D_HA, req, "close replay\n");
                memcpy(lustre_msg_buf(req->rq_repmsg, 2, 0),
                       lustre_msg_buf(req->rq_reqmsg, offset + 1, 0),
                       req->rq_repmsg->buflens[2]);
        }

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
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
                          ": cookie "LPX64, id_ino(&body->id1), body->handle.cookie);
                req->rq_status = -ESTALE;
                RETURN(-ESTALE);
        }

        inode = mfd->mfd_dentry->d_inode;
        /* child i_alloc_sem protects orphan_dec_test && is_orphan race */
        DOWN_WRITE_I_ALLOC_SEM(inode); /* mds_mfd_close drops this */
        if (mds_inode_is_orphan(inode) && mds_orphan_open_count(inode) == 1) {
                struct mds_body *rep_body;

                rep_body = lustre_msg_buf(req->rq_repmsg, 0,
                                          sizeof (*rep_body));
                LASSERT(rep_body != NULL);

                mds_pack_inode2body(obd, rep_body, inode,
                                    (body->valid & OBD_MD_FID) ? 1 : 0);
                
                mds_pack_md(obd, req->rq_repmsg, 1, rep_body, 
			    inode, MDS_PACK_MD_LOCK, 0);
        }
        spin_lock(&med->med_open_lock);
        list_del(&mfd->mfd_list);
        spin_unlock(&med->med_open_lock);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        req->rq_status = mds_mfd_close(req, offset, obd, mfd, 1);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_CLOSE_PACK)) {
                CERROR("test case OBD_FAIL_MDS_CLOSE_PACK\n");
                req->rq_status = -ENOMEM;
                mds_mfd_put(mfd);
                RETURN(-ENOMEM);
        }

        mds_mfd_put(mfd);
        RETURN(0);
}

int mds_done_writing(struct ptlrpc_request *req, int offset)
{
        struct mds_body *body;
        int rc, size = sizeof(struct mds_body);
        ENTRY;

        MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
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
