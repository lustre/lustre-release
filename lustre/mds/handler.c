/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mds/handler.c
 *  Lustre Metadata Server (mds) request handler
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
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

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_dlm.h>
#include <linux/init.h>
#include <linux/obd_class.h>
#include <linux/random.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <linux/smp_lock.h>
#include <linux/buffer_head.h>
#include <linux/workqueue.h>
#include <linux/mount.h>
#else 
#include <linux/locks.h>
#endif
#include <linux/obd_lov.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lprocfs_status.h>

kmem_cache_t *mds_file_cache;

extern int mds_get_lovtgts(struct mds_obd *obd, int tgt_count,
                           struct obd_uuid *uuidarray);
extern int mds_get_lovdesc(struct mds_obd  *obd, struct lov_desc *desc);
int mds_finish_transno(struct mds_obd *mds, struct inode *i, void *handle,
                       struct ptlrpc_request *req, int rc, int disp);
static int mds_cleanup(struct obd_device * obddev);

inline struct mds_obd *mds_req2mds(struct ptlrpc_request *req)
{
        return &req->rq_export->exp_obd->u.mds;
}

static int mds_bulk_timeout(void *data)
{
        struct ptlrpc_bulk_desc *desc = data;

        ENTRY;
        recovd_conn_fail(desc->bd_connection);
        RETURN(1);
}

/* Assumes caller has already pushed into the kernel filesystem context */
static int mds_sendpage(struct ptlrpc_request *req, struct file *file,
                        __u64 offset, __u64 xid)
{
        struct ptlrpc_bulk_desc *desc;
        struct ptlrpc_bulk_page *bulk;
        struct l_wait_info lwi;
        char *buf;
        int rc = 0;
        ENTRY;

        desc = ptlrpc_prep_bulk(req->rq_connection);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);

        bulk = ptlrpc_prep_bulk_page(desc);
        if (bulk == NULL)
                GOTO(cleanup_bulk, rc = -ENOMEM);

        OBD_ALLOC(buf, PAGE_CACHE_SIZE);
        if (buf == NULL)
                GOTO(cleanup_bulk, rc = -ENOMEM);

        CDEBUG(D_EXT2, "reading %lu@"LPU64" from dir %lu (size %llu)\n",
               PAGE_CACHE_SIZE, offset, file->f_dentry->d_inode->i_ino,
               file->f_dentry->d_inode->i_size);
        rc = fsfilt_readpage(req->rq_export->exp_obd, file, buf,
                             PAGE_CACHE_SIZE, (loff_t *)&offset);

        if (rc != PAGE_CACHE_SIZE)
                GOTO(cleanup_buf, rc = -EIO);

        bulk->bp_xid = xid;
        bulk->bp_buf = buf;
        bulk->bp_buflen = PAGE_CACHE_SIZE;
        desc->bd_ptl_ev_hdlr = NULL;
        desc->bd_portal = MDS_BULK_PORTAL;

        rc = ptlrpc_bulk_put(desc);
        if (rc)
                GOTO(cleanup_buf, rc);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SENDPAGE)) {
                CERROR("obd_fail_loc=%x, fail operation rc=%d\n",
                       OBD_FAIL_MDS_SENDPAGE, rc);
                ptlrpc_abort_bulk(desc);
                GOTO(cleanup_buf, rc);
        }

        lwi = LWI_TIMEOUT(obd_timeout * HZ, mds_bulk_timeout, desc);
        rc = l_wait_event(desc->bd_waitq, desc->bd_flags & PTL_BULK_FL_SENT,
                          &lwi);
        if (rc) {
                if (rc != -ETIMEDOUT)
                        LBUG();
                GOTO(cleanup_buf, rc);
        }

        EXIT;
 cleanup_buf:
        OBD_FREE(buf, PAGE_SIZE);
 cleanup_bulk:
        ptlrpc_bulk_decref(desc);
 out:
        return rc;
}

/* only valid locked dentries or errors should be returned */
struct dentry *mds_fid2locked_dentry(struct obd_device *obd, struct ll_fid *fid,
                                     struct vfsmount **mnt, int lock_mode,
                                     struct lustre_handle *lockh)
{
        struct mds_obd *mds = &obd->u.mds;
        struct dentry *de = mds_fid2dentry(mds, fid, mnt), *retval = de;
        struct ldlm_res_id res_id = { .name = {0} };
        int flags = 0, rc;
        ENTRY;

        if (IS_ERR(de))
                RETURN(de);

        res_id.name[0] = de->d_inode->i_ino;
        res_id.name[1] = de->d_inode->i_generation;
        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                              res_id, LDLM_PLAIN, NULL, 0, lock_mode,
                              &flags, ldlm_completion_ast,
                              mds_blocking_ast, NULL, NULL, lockh);
        if (rc != ELDLM_OK) {
                l_dput(de);
                retval = ERR_PTR(-ENOLCK); /* XXX translate ldlm code */
        }

        RETURN(retval);
}

#ifndef DCACHE_DISCONNECTED
#define DCACHE_DISCONNECTED DCACHE_NFSD_DISCONNECTED
#endif



/* Look up an entry by inode number. */
/* this function ONLY returns valid dget'd dentries with an initialized inode
   or errors */
struct dentry *mds_fid2dentry(struct mds_obd *mds, struct ll_fid *fid,
                              struct vfsmount **mnt)
{
        /* stolen from NFS */
        struct super_block *sb = mds->mds_sb;
        unsigned long ino = fid->id;
        __u32 generation = fid->generation;
        struct inode *inode;
        struct list_head *lp;
        struct dentry *result;

        if (ino == 0)
                RETURN(ERR_PTR(-ESTALE));

        inode = iget(sb, ino);
        if (inode == NULL)
                RETURN(ERR_PTR(-ENOMEM));

        CDEBUG(D_DENTRY, "--> mds_fid2dentry: sb %p\n", inode->i_sb);

        if (is_bad_inode(inode) ||
            (generation && inode->i_generation != generation)) {
                /* we didn't find the right inode.. */
                CERROR("bad inode %lu, link: %d ct: %d or version  %u/%u\n",
                       inode->i_ino, inode->i_nlink,
                       atomic_read(&inode->i_count), inode->i_generation,
                       generation);
                iput(inode);
                RETURN(ERR_PTR(-ENOENT));
        }

        /* now to find a dentry. If possible, get a well-connected one */
        if (mnt)
                *mnt = mds->mds_vfsmnt;
        spin_lock(&dcache_lock);
        list_for_each(lp, &inode->i_dentry) {
                result = list_entry(lp, struct dentry, d_alias);
                if (!(result->d_flags & DCACHE_DISCONNECTED)) {
                        dget_locked(result);
                        result->d_vfs_flags |= DCACHE_REFERENCED;
                        spin_unlock(&dcache_lock);
                        iput(inode);
                        if (mnt)
                                mntget(*mnt);
                        return result;
                }
        }
        spin_unlock(&dcache_lock);
        result = d_alloc_root(inode);
        if (result == NULL) {
                iput(inode);
                return ERR_PTR(-ENOMEM);
        }
        if (mnt)
                mntget(*mnt);
        result->d_flags |= DCACHE_DISCONNECTED;
        return result;
}


/* Establish a connection to the MDS.
 *
 * This will set up an export structure for the client to hold state data
 * about that client, like open files, the last operation number it did
 * on the server, etc.
 */
static int mds_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct recovd_obd *recovd,
                       ptlrpc_recovery_cb_t recover)
{
        struct obd_export *exp;
        struct mds_export_data *med;
        struct mds_client_data *mcd;
        int rc;
        ENTRY;

        if (!conn || !obd || !cluuid)
                RETURN(-EINVAL);

        /* Check for aborted recovery. */
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_flags & OBD_ABORT_RECOVERY)
                target_abort_recovery(obd);
        spin_unlock_bh(&obd->obd_processing_task_lock);

        /* XXX There is a small race between checking the list and adding a
         * new connection for the same UUID, but the real threat (list
         * corruption when multiple different clients connect) is solved.
         *
         * There is a second race between adding the export to the list,
         * and filling in the client data below.  Hence skipping the case
         * of NULL mcd above.  We should already be controlling multiple
         * connects at the client, and we can't hold the spinlock over
         * memory allocations without risk of deadlocking.
         */
        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);
        exp = class_conn2export(conn);
        LASSERT(exp);
        med = &exp->exp_mds_data;

        OBD_ALLOC(mcd, sizeof(*mcd));
        if (!mcd) {
                CERROR("mds: out of memory for client data\n");
                GOTO(out_export, rc = -ENOMEM);
        }

        memcpy(mcd->mcd_uuid, cluuid, sizeof(mcd->mcd_uuid));
        med->med_mcd = mcd;

        INIT_LIST_HEAD(&med->med_open_head);
        spin_lock_init(&med->med_open_lock);

        rc = mds_client_add(&obd->u.mds, med, -1);
        if (rc)
                GOTO(out_mcd, rc);

        RETURN(0);

out_mcd:
        OBD_FREE(mcd, sizeof(*mcd));
out_export:
        class_disconnect(conn);

        return rc;
}

/* Call with med->med_open_lock held, please. */
inline int mds_close_mfd(struct mds_file_data *mfd, struct mds_export_data *med)
{
        struct file *file = mfd->mfd_file;
        int rc;
        struct dentry *de = NULL;
        LASSERT(file->private_data == mfd);

        LASSERT(mfd->mfd_servercookie != DEAD_HANDLE_MAGIC);

        list_del(&mfd->mfd_list);
        mfd->mfd_servercookie = DEAD_HANDLE_MAGIC;
        kmem_cache_free(mds_file_cache, mfd);

        if (file->f_dentry->d_parent) {
                LASSERT(atomic_read(&file->f_dentry->d_parent->d_count));
                de = dget(file->f_dentry->d_parent);
        }
        rc = filp_close(file, 0);
        if (de)
                l_dput(de);
        RETURN(rc);
}

static int mds_disconnect(struct lustre_handle *conn)
{
        struct obd_export *export = class_conn2export(conn);
        struct list_head *tmp, *n;
        struct mds_export_data *med = &export->exp_mds_data;
        int rc;
        ENTRY;

        /*
         * Close any open files.
         */
        spin_lock(&med->med_open_lock);
        list_for_each_safe(tmp, n, &med->med_open_head) {
                struct mds_file_data *mfd =
                        list_entry(tmp, struct mds_file_data, mfd_list);
                CERROR("force closing client file handle for %*s\n",
                       mfd->mfd_file->f_dentry->d_name.len,
                       mfd->mfd_file->f_dentry->d_name.name);
                rc = mds_close_mfd(mfd, med);
                if (rc)
                        CDEBUG(D_INODE, "Error closing file: %d\n", rc);
        }
        spin_unlock(&med->med_open_lock);

        ldlm_cancel_locks_for_export(export);
        if (med->med_outstanding_reply) {
                /* Fake the ack, so the locks get cancelled. */
                med->med_outstanding_reply->rq_flags &= ~PTL_RPC_FL_WANT_ACK;
                med->med_outstanding_reply->rq_flags |= PTL_RPC_FL_ERR;
                wake_up(&med->med_outstanding_reply->rq_wait_for_rep);
                med->med_outstanding_reply = NULL;
        }
        mds_client_free(export);

        rc = class_disconnect(conn);

        RETURN(rc);
}

/*
 * XXX This is NOT guaranteed to flush all transactions to disk (even though
 *     it is equivalent to calling sync()) because it only _starts_ the flush
 *     and does not wait for completion.  It's better than nothing though.
 *     What we really want is a mild form of fsync_dev_lockfs(), but it is
 *     non-standard, or enabling do_sync_supers in ext3, just for this call.
 */
static void mds_fsync_super(struct super_block *sb)
{
        lock_kernel();
        lock_super(sb);
        if (sb->s_dirt && sb->s_op && sb->s_op->write_super)
                sb->s_op->write_super(sb);
        unlock_super(sb);
        unlock_kernel();
}

static int mds_getstatus(struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_GETSTATUS_PACK)) {
                CERROR("mds: out of memory for message: size=%d\n", size);
                req->rq_status = -ENOMEM;
                RETURN(-ENOMEM);
        }

        /* Flush any outstanding transactions to disk so the client will
         * get the latest last_committed value and can drop their local
         * requests if they have any.  This would be fsync_super() if it
         * was exported.
         */
        mds_fsync_super(mds->mds_sb);

        body = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&body->fid1, &mds->mds_rootfid, sizeof(body->fid1));

        /* the last_committed and last_xid fields are filled in for all
         * replies already - no need to do so here also.
         */
        RETURN(0);
}

static int mds_getlovinfo(struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_status_req *streq;
        struct lov_desc *desc;
        int tgt_count;
        int rc, size[2] = {sizeof(*desc)};
        ENTRY;

        streq = lustre_msg_buf(req->rq_reqmsg, 0);
        streq->flags = NTOH__u32(streq->flags);
        streq->repbuf = NTOH__u32(streq->repbuf);
        size[1] = streq->repbuf;

        rc = lustre_pack_msg(2, size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc) {
                CERROR("mds: out of memory for message: size=%d\n", size[1]);
                req->rq_status = -ENOMEM;
                RETURN(-ENOMEM);
        }

        if (!mds->mds_has_lov_desc) {
                req->rq_status = -ENOENT;
                RETURN(0);
        }

        desc = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(desc, &mds->mds_lov_desc, sizeof *desc);
        lov_packdesc(desc);
        tgt_count = le32_to_cpu(desc->ld_tgt_count);
        if (tgt_count * sizeof(struct obd_uuid) > streq->repbuf) {
                CERROR("too many targets, enlarge client buffers\n");
                req->rq_status = -ENOSPC;
                RETURN(0);
        }

        rc = mds_get_lovtgts(mds, tgt_count,
                             lustre_msg_buf(req->rq_repmsg, 1));
        if (rc) {
                CERROR("get_lovtgts error %d\n", rc);
                req->rq_status = rc;
                RETURN(0);
        }
        RETURN(0);
}

int mds_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                     void *data, int flag)
{
        int do_ast;
        ENTRY;

        if (flag == LDLM_CB_CANCELING) {
                /* Don't need to do anything here. */
                RETURN(0);
        }

        /* XXX layering violation!  -phil */
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        /* Get this: if mds_blocking_ast is racing with ldlm_intent_policy,
         * such that mds_blocking_ast is called just before l_i_p takes the
         * ns_lock, then by the time we get the lock, we might not be the
         * correct blocking function anymore.  So check, and return early, if
         * so. */
        if (lock->l_blocking_ast != mds_blocking_ast) {
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                RETURN(0);
        }

        lock->l_flags |= LDLM_FL_CBPENDING;
        do_ast = (!lock->l_readers && !lock->l_writers);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        if (do_ast) {
                struct lustre_handle lockh;
                int rc;

                LDLM_DEBUG(lock, "already unused, calling ldlm_cli_cancel");
                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc < 0)
                        CERROR("ldlm_cli_cancel: %d\n", rc);
        } else {
                LDLM_DEBUG(lock, "Lock still has references, will be "
                           "cancelled later");
        }
        RETURN(0);
}

int mds_pack_md(struct obd_device *obd, struct lustre_msg *msg,
                int offset, struct mds_body *body, struct inode *inode)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lov_mds_md *lmm;
        int lmm_size = msg->buflens[offset];
        int rc;
        ENTRY;

        if (lmm_size == 0) {
                CDEBUG(D_INFO, "no space reserved for inode %lu MD\n",
                       inode->i_ino);
                RETURN(0);
        }

        lmm = lustre_msg_buf(msg, offset);

        /* I don't really like this, but it is a sanity check on the client
         * MD request.  However, if the client doesn't know how much space
         * to reserve for the MD, this shouldn't be fatal either...
         */
        if (lmm_size > mds->mds_max_mdsize) {
                CERROR("Reading MD for inode %lu of %d bytes > max %d\n",
                       inode->i_ino, lmm_size, mds->mds_max_mdsize);
                // RETURN(-EINVAL);
        }

        /* We don't need to store the reply size, because this buffer is
         * discarded right after unpacking, and the LOV can figure out the
         * size itself from the ost count.
         */
        if ((rc = fsfilt_get_md(obd, inode, lmm, lmm_size)) < 0) {
                CDEBUG(D_INFO, "No md for ino %lu: rc = %d\n",
                       inode->i_ino, rc);
        } else if (rc > 0) {
                body->valid |= OBD_MD_FLEASIZE;
                rc = 0;
        }

        RETURN(rc);
}

static int mds_getattr_internal(struct obd_device *obd, struct dentry *dentry,
                                struct ptlrpc_request *req,
                                struct mds_body *reqbody, int reply_off)
{
        struct mds_body *body;
        struct inode *inode = dentry->d_inode;
        int rc = 0;
        ENTRY;

        if (inode == NULL)
                RETURN(-ENOENT);

        body = lustre_msg_buf(req->rq_repmsg, reply_off);

        mds_pack_inode2fid(&body->fid1, inode);
        mds_pack_inode2body(body, inode);

        if (S_ISREG(inode->i_mode) && reqbody->valid & OBD_MD_FLEASIZE) {
                rc = mds_pack_md(obd, req->rq_repmsg, reply_off + 1,
                                 body, inode);
        } else if (S_ISLNK(inode->i_mode) && reqbody->valid & OBD_MD_LINKNAME) {
                char *symname = lustre_msg_buf(req->rq_repmsg, reply_off + 1);
                int len = req->rq_repmsg->buflens[reply_off + 1];

                rc = inode->i_op->readlink(dentry, symname, len);
                if (rc < 0) {
                        CERROR("readlink failed: %d\n", rc);
                } else {
                        CDEBUG(D_INODE, "read symlink dest %s\n", symname);
                        body->valid |= OBD_MD_LINKNAME;
                        rc = 0;
                }
        }
        RETURN(rc);
}

static int mds_getattr_pack_msg(struct ptlrpc_request *req, struct inode *inode,
                                int offset)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_body *body;
        int rc = 0, size[2] = {sizeof(*body)}, bufcount = 1;
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, offset);

        if (S_ISREG(inode->i_mode) && body->valid & OBD_MD_FLEASIZE) {
                int rc = fsfilt_get_md(req->rq_export->exp_obd, inode, NULL, 0);
                CDEBUG(D_INODE, "got %d bytes MD data for inode %lu\n",
                       rc, inode->i_ino);
                if (rc < 0) {
                        if (rc != -ENODATA)
                                CERROR("error getting inode %lu MD: rc = %d\n",
                                       inode->i_ino, rc);
                        size[bufcount] = 0;
                } else if (rc > mds->mds_max_mdsize) {
                        size[bufcount] = 0;
                        CERROR("MD size %d larger than maximum possible %u\n",
                               rc, mds->mds_max_mdsize);
                } else
                        size[bufcount] = rc;
                bufcount++;
        } else if (body->valid & OBD_MD_LINKNAME) {
                size[bufcount] = MIN(inode->i_size + 1, body->size);
                bufcount++;
                CDEBUG(D_INODE, "symlink size: %Lu, reply space: "LPU64"\n",
                       inode->i_size + 1, body->size);
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK)) {
                CERROR("failed MDS_GETATTR_PACK test\n");
                req->rq_status = -ENOMEM;
                GOTO(out, rc = -ENOMEM);
        }

        rc = lustre_pack_msg(bufcount, size, NULL, &req->rq_replen,
                             &req->rq_repmsg);
        if (rc) {
                CERROR("out of memoryK\n");
                req->rq_status = rc;
                GOTO(out, rc);
        }

        EXIT;
 out:
        return(rc);
}

/* This is more copy-and-paste from getattr_name than I'd like. */
static void reconstruct_getattr_name(int offset, struct ptlrpc_request *req,
                                     struct lustre_handle *client_lockh)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_client_data *mcd = med->med_mcd;
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_obd *mds = mds_req2mds(req);
        struct dentry *parent, *child;
        struct mds_body *body;
        struct inode *dir;
        struct obd_run_ctxt saved;
        struct obd_ucred uc;
        int namelen, rc = 0;
        char *name;

        req->rq_transno = mcd->mcd_last_transno;
        req->rq_status = mcd->mcd_last_result;

        if (med->med_outstanding_reply)
                mds_steal_ack_locks(med, req);

        if (req->rq_status)
                return;

        body = lustre_msg_buf(req->rq_reqmsg, offset);
        name = lustre_msg_buf(req->rq_reqmsg, offset + 1);
        namelen = req->rq_reqmsg->buflens[offset + 1];
        /* requests were at offset 2, replies go back at 1 */
        if (offset)
                offset = 1;

        uc.ouc_fsuid = body->fsuid;
        uc.ouc_fsgid = body->fsgid;
        uc.ouc_cap = body->capability;
        uc.ouc_suppgid1 = body->suppgid;
        uc.ouc_suppgid2 = -1;
        push_ctxt(&saved, &mds->mds_ctxt, &uc);
        parent = mds_fid2dentry(mds, &body->fid1, NULL);
        LASSERT(!IS_ERR(parent));
        dir = parent->d_inode;
        LASSERT(dir);
        child = lookup_one_len(name, parent, namelen - 1);
        LASSERT(!IS_ERR(child));

        if (!med->med_outstanding_reply) {
                /* XXX need to enqueue client lock */
                LBUG();
        }

        if (req->rq_repmsg == NULL)
                mds_getattr_pack_msg(req, child->d_inode, offset);
        
        rc = mds_getattr_internal(obd, child, req, body, offset);
        LASSERT(!rc);
        l_dput(child);
        l_dput(parent);
}

static int mds_getattr_name(int offset, struct ptlrpc_request *req,
                            struct lustre_handle *child_lockh)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct obd_run_ctxt saved;
        struct mds_body *body;
        struct dentry *de = NULL, *dchild = NULL;
        struct inode *dir;
        struct obd_ucred uc;
        struct ldlm_res_id child_res_id = { .name = {0} };
        struct lustre_handle parent_lockh;
        int namelen, flags = 0, rc = 0, cleanup_phase = 0;
        char *name;
        ENTRY;

        LASSERT(!strcmp(obd->obd_type->typ_name, "mds"));

        MDS_CHECK_RESENT(req, 
                         reconstruct_getattr_name(offset, req, child_lockh));

        if (req->rq_reqmsg->bufcount <= offset + 1) {
                LBUG();
                GOTO(cleanup, rc = -EINVAL);
        }

        body = lustre_msg_buf(req->rq_reqmsg, offset);
        name = lustre_msg_buf(req->rq_reqmsg, offset + 1);
        namelen = req->rq_reqmsg->buflens[offset + 1];
        /* requests were at offset 2, replies go back at 1 */
        if (offset)
                offset = 1;

        uc.ouc_fsuid = body->fsuid;
        uc.ouc_fsgid = body->fsgid;
        uc.ouc_cap = body->capability;
        uc.ouc_suppgid1 = body->suppgid;
        uc.ouc_suppgid2 = -1;
        push_ctxt(&saved, &mds->mds_ctxt, &uc);
        /* Step 1: Lookup/lock parent */
        de = mds_fid2locked_dentry(obd, &body->fid1, NULL, LCK_PR,
                                   &parent_lockh);
        if (IS_ERR(de))
                GOTO(cleanup, rc = PTR_ERR(de));
        dir = de->d_inode;
        LASSERT(dir);

        cleanup_phase = 1; /* parent dentry and lock */

        CDEBUG(D_INODE, "parent ino %lu, name %*s\n", dir->i_ino,namelen,name);

        /* Step 2: Lookup child */
        dchild = lookup_one_len(name, de, namelen - 1);
        if (IS_ERR(dchild)) {
                CDEBUG(D_INODE, "child lookup error %ld\n", PTR_ERR(dchild));
                GOTO(cleanup, rc = PTR_ERR(dchild));
        }

        cleanup_phase = 2; /* child dentry */

        if (dchild->d_inode == NULL) {
                GOTO(cleanup, rc = -ENOENT);
        }

        /* Step 3: Lock child */
        child_res_id.name[0] = dchild->d_inode->i_ino;
        child_res_id.name[1] = dchild->d_inode->i_generation;
        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                              child_res_id, LDLM_PLAIN, NULL, 0, LCK_PR,
                              &flags, ldlm_completion_ast, mds_blocking_ast,
                              NULL, NULL, child_lockh);
        if (rc != ELDLM_OK) {
                CERROR("ldlm_cli_enqueue: %d\n", rc);
                GOTO(cleanup, rc = -EIO);
        }

        cleanup_phase = 3; /* child lock */

        if (req->rq_repmsg == NULL)
                mds_getattr_pack_msg(req, dchild->d_inode, offset);

        rc = mds_getattr_internal(obd, dchild, req, body, offset);
        GOTO(cleanup, rc); /* returns the lock to the client */
        
 cleanup:
        rc = mds_finish_transno(mds, dchild ? dchild->d_inode : NULL, NULL,
                                req, rc, 0);
        switch (cleanup_phase) {
        case 3:
                if (rc)
                        ldlm_lock_decref(child_lockh, LCK_PR);
        case 2:
                l_dput(dchild);

        case 1:
                if (rc) {
                        ldlm_lock_decref(&parent_lockh, LCK_PR);
                } else {
                        memcpy(&req->rq_ack_locks[0].lock, &parent_lockh,
                               sizeof(parent_lockh));
                        req->rq_ack_locks[0].mode = LCK_PR;
                }
                l_dput(de);
        default: ;
        }
        req->rq_status = rc;
        pop_ctxt(&saved, &mds->mds_ctxt, &uc);
        return rc;
}

static int mds_getattr(int offset, struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct obd_run_ctxt saved;
        struct dentry *de;
        struct mds_body *body;
        struct obd_ucred uc;
        int rc = 0;
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, offset);
        uc.ouc_fsuid = body->fsuid;
        uc.ouc_fsgid = body->fsgid;
        uc.ouc_cap = body->capability;
        push_ctxt(&saved, &mds->mds_ctxt, &uc);
        de = mds_fid2dentry(mds, &body->fid1, NULL);
        if (IS_ERR(de)) {
                rc = req->rq_status = -ENOENT;
                GOTO(out_pop, PTR_ERR(de));
        }

        rc = mds_getattr_pack_msg(req, de->d_inode, offset);

        req->rq_status = mds_getattr_internal(obd, de, req, body, 0);

        l_dput(de);
        GOTO(out_pop, rc);
out_pop:
        pop_ctxt(&saved, &mds->mds_ctxt, &uc);
        return rc;
}

static int mds_statfs(struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct obd_statfs *osfs;
        int rc, size = sizeof(*osfs);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_STATFS_PACK)) {
                CERROR("mds: statfs lustre_pack_msg failed: rc = %d\n", rc);
                GOTO(out, rc);
        }

        osfs = lustre_msg_buf(req->rq_repmsg, 0);
        rc = fsfilt_statfs(obd, obd->u.mds.mds_sb, osfs);
        if (rc) {
                CERROR("mds: statfs failed: rc %d\n", rc);
                GOTO(out, rc);
        }
        obd_statfs_pack(osfs, osfs);

        EXIT;
out:
        req->rq_status = rc;
        return 0;
}

static struct mds_file_data *mds_handle2mfd(struct lustre_handle *handle)
{
        struct mds_file_data *mfd = NULL;
        ENTRY;

        if (!handle || !handle->addr)
                RETURN(NULL);

        mfd = (struct mds_file_data *)(unsigned long)(handle->addr);
        if (!kmem_cache_validate(mds_file_cache, mfd))
                RETURN(NULL);

        if (mfd->mfd_servercookie != handle->cookie)
                RETURN(NULL);

        RETURN(mfd);
}

#if 0

static int mds_store_md(struct mds_obd *mds, struct ptlrpc_request *req,
                        int offset, struct mds_body *body, struct inode *inode)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct lov_mds_md *lmm = lustre_msg_buf(req->rq_reqmsg, offset);
        int lmm_size = req->rq_reqmsg->buflens[offset];
        struct obd_run_ctxt saved;
        struct obd_ucred uc;
        void *handle;
        int rc, rc2;
        ENTRY;

        /* I don't really like this, but it is a sanity check on the client
         * MD request.
         */
        if (lmm_size > mds->mds_max_mdsize) {
                CERROR("Saving MD for inode %lu of %d bytes > max %d\n",
                       inode->i_ino, lmm_size, mds->mds_max_mdsize);
                //RETURN(-EINVAL);
        }

        CDEBUG(D_INODE, "storing %d bytes MD for inode %lu\n",
               lmm_size, inode->i_ino);
        uc.ouc_fsuid = body->fsuid;
        uc.ouc_fsgid = body->fsgid;
        uc.ouc_cap = body->capability;
        push_ctxt(&saved, &mds->mds_ctxt, &uc);
        handle = fsfilt_start(obd, inode, FSFILT_OP_SETATTR);
        if (IS_ERR(handle)) {
                rc = PTR_ERR(handle);
                GOTO(out_ea, rc);
        }

        rc = fsfilt_set_md(obd, inode,handle,lmm,lmm_size);
        rc = mds_finish_transno(mds, inode, handle, req, rc, 0);
out_ea:
        pop_ctxt(&saved, &mds->mds_ctxt, &uc);

        RETURN(rc);
}

#endif

static void reconstruct_close(struct ptlrpc_request *req)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_client_data *mcd = med->med_mcd;

        req->rq_transno = mcd->mcd_last_transno;
        req->rq_status = mcd->mcd_last_result;

        /* XXX When open-unlink is working, we'll need to steal ack locks as
         * XXX well, and make sure that we do the right unlinking after we
         * XXX get the ack back.
         */
}

static int mds_close(struct ptlrpc_request *req)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_body *body;
        struct mds_file_data *mfd;
        int rc;
        ENTRY;

        MDS_CHECK_RESENT(req, reconstruct_close(req));

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        mfd = mds_handle2mfd(&body->handle);
        if (mfd == NULL) {
                DEBUG_REQ(D_ERROR, req, "no handle for file close "LPD64
                          ": addr "LPX64", cookie "LPX64"\n",
                          body->fid1.id, body->handle.addr,
                          body->handle.cookie);
                RETURN(-ESTALE);
        }

        spin_lock(&med->med_open_lock);
        req->rq_status = mds_close_mfd(mfd, med);
        spin_unlock(&med->med_open_lock);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_CLOSE_PACK)) {
                CERROR("test case OBD_FAIL_MDS_CLOSE_PACK\n");
                req->rq_status = -ENOMEM;
                RETURN(-ENOMEM);
        }

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc) {
                CERROR("mds: lustre_pack_msg: rc = %d\n", rc);
                req->rq_status = rc;
        }

        RETURN(0);
}

static int mds_readpage(struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct vfsmount *mnt;
        struct dentry *de;
        struct file *file;
        struct mds_body *body, *repbody;
        struct obd_run_ctxt saved;
        int rc, size = sizeof(*body);
        struct obd_ucred uc;
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_READPAGE_PACK)) {
                CERROR("mds: out of memory\n");
                GOTO(out, rc = -ENOMEM);
        }

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        uc.ouc_fsuid = body->fsuid;
        uc.ouc_fsgid = body->fsgid;
        uc.ouc_cap = body->capability;
        push_ctxt(&saved, &mds->mds_ctxt, &uc);
        de = mds_fid2dentry(mds, &body->fid1, &mnt);
        if (IS_ERR(de))
                GOTO(out_pop, rc = PTR_ERR(de));

        CDEBUG(D_INODE, "ino %lu\n", de->d_inode->i_ino);

        file = dentry_open(de, mnt, O_RDONLY | O_LARGEFILE);
        /* note: in case of an error, dentry_open puts dentry */
        if (IS_ERR(file))
                GOTO(out_pop, rc = PTR_ERR(file));

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        repbody->size = file->f_dentry->d_inode->i_size;
        repbody->valid = OBD_MD_FLSIZE;

        /* to make this asynchronous make sure that the handling function
           doesn't send a reply when this function completes. Instead a
           callback function would send the reply */
        /* body->blocks is actually the xid -phil */
        rc = mds_sendpage(req, file, body->size, body->blocks);

        filp_close(file, 0);
out_pop:
        pop_ctxt(&saved, &mds->mds_ctxt, &uc);
out:
        req->rq_status = rc;
        RETURN(0);
}

int mds_reint(struct ptlrpc_request *req, int offset,
              struct lustre_handle *lockh)
{
        struct mds_update_record *rec; /* 116 bytes on the stack?  no sir! */
        int rc;

        OBD_ALLOC(rec, sizeof(*rec));
        if (rec == NULL)
                RETURN(-ENOMEM);

        rc = mds_update_unpack(req, offset, rec);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNPACK)) {
                CERROR("invalid record\n");
                GOTO(out, req->rq_status = -EINVAL);
        }
        /* rc will be used to interrupt a for loop over multiple records */
        rc = mds_reint_rec(rec, offset, req, lockh);
 out:
        OBD_FREE(rec, sizeof(*rec));
        return rc;
}

static int filter_recovery_request(struct ptlrpc_request *req,
                                   struct obd_device *obd, int *process)
{
        switch (req->rq_reqmsg->opc) {
        case MDS_CONNECT: /* This will never get here, but for completeness. */
        case MDS_DISCONNECT:
               *process = 1;
               RETURN(0);

        case MDS_CLOSE:
        case MDS_GETSTATUS: /* used in unmounting */
        case MDS_REINT:
        case LDLM_ENQUEUE:
                *process = target_queue_recovery_request(req, obd);
                RETURN(0);

        default:
                DEBUG_REQ(D_ERROR, req, "not permitted during recovery");
                *process = 0;
                /* XXX what should we set rq_status to here? */
                RETURN(ptlrpc_error(req->rq_svc, req));
        }
}

static char *reint_names[] = {
        [REINT_SETATTR] "setattr",
        [REINT_CREATE]  "create",
        [REINT_LINK]    "link",
        [REINT_UNLINK]  "unlink",
        [REINT_RENAME]  "rename",
        [REINT_OPEN]    "open",
};

void mds_steal_ack_locks(struct mds_export_data *med,
                         struct ptlrpc_request *req)
{
        struct ptlrpc_request *oldrep = med->med_outstanding_reply;
        memcpy(req->rq_ack_locks, oldrep->rq_ack_locks,
               sizeof req->rq_ack_locks);
        oldrep->rq_flags |= PTL_RPC_FL_RESENT;
        wake_up(&oldrep->rq_wait_for_rep);
        DEBUG_REQ(D_HA, oldrep, "stole locks from");
        DEBUG_REQ(D_HA, req, "stole locks for");
}

static void mds_send_reply(struct ptlrpc_request *req, int rc)
{
        int i;
        struct ptlrpc_req_ack_lock *ack_lock;
        struct l_wait_info lwi;
        struct mds_export_data *med =
                (req->rq_export && req->rq_ack_locks[0].mode) ?
                &req->rq_export->exp_mds_data : NULL;

        if (med) {
                med->med_outstanding_reply = req;
                req->rq_flags |= PTL_RPC_FL_WANT_ACK;
                init_waitqueue_head(&req->rq_wait_for_rep);
        }

        if (!OBD_FAIL_CHECK(OBD_FAIL_MDS_ALL_REPLY_NET | OBD_FAIL_ONCE)) {
                if (rc) {
                        DEBUG_REQ(D_ERROR, req, "processing error (%d)", rc);
                        ptlrpc_error(req->rq_svc, req);
                } else {
                        DEBUG_REQ(D_NET, req, "sending reply");
                        ptlrpc_reply(req->rq_svc, req);
                }
        } else {
                obd_fail_loc |= OBD_FAIL_ONCE | OBD_FAILED;
                DEBUG_REQ(D_ERROR, req, "dropping reply");
                if (!med && req->rq_repmsg)
                        OBD_FREE(req->rq_repmsg, req->rq_replen);
        }

        if (!med) {
                DEBUG_REQ(D_HA, req, "not waiting for ack");
                return;
        }

        lwi = LWI_TIMEOUT(obd_timeout / 2 * HZ, NULL, NULL);
        rc = l_wait_event(req->rq_wait_for_rep, 
                          (req->rq_flags & PTL_RPC_FL_WANT_ACK) == 0 ||
                          (req->rq_flags & PTL_RPC_FL_RESENT),
                          &lwi);

        if (req->rq_flags & PTL_RPC_FL_RESENT) {
                /* The client resent this request, so abort the
                 * waiting-ack portals stuff, and don't decref the
                 * locks.
                 */
                DEBUG_REQ(D_HA, req, "resent: not cancelling locks");
                ptlrpc_abort(req);
                return;
        }

        if (rc == -ETIMEDOUT) {
                ptlrpc_abort(req);
                recovd_conn_fail(req->rq_export->exp_connection);
                DEBUG_REQ(D_HA, req, "cancelling locks for timeout");
        } else {
                DEBUG_REQ(D_HA, req, "cancelling locks for ack");
        }
        
        med->med_outstanding_reply = NULL;
        
        for (ack_lock = req->rq_ack_locks, i = 0; i < 4; i++, ack_lock++) {
                if (!ack_lock->mode)
                        break;
                ldlm_lock_decref(&ack_lock->lock, ack_lock->mode);
        }
}

int mds_handle(struct ptlrpc_request *req)
{
        int should_process, rc;
        struct mds_obd *mds = NULL; /* quell gcc overwarning */
        struct obd_device *obd = NULL;
        ENTRY;

        rc = lustre_unpack_msg(req->rq_reqmsg, req->rq_reqlen);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_HANDLE_UNPACK)) {
                DEBUG_REQ(D_ERROR, req, "invalid request (%d)", rc);
                GOTO(out, rc);
        }

        OBD_FAIL_RETURN(OBD_FAIL_MDS_ALL_REQUEST_NET | OBD_FAIL_ONCE, 0);

        LASSERT(!strcmp(req->rq_obd->obd_type->typ_name, LUSTRE_MDT_NAME));

        if (req->rq_reqmsg->opc != MDS_CONNECT) {
                struct mds_export_data *med;
                if (req->rq_export == NULL) {
                        req->rq_status = -ENOTCONN;
                        GOTO(out, rc = -ENOTCONN);
                }

                med = &req->rq_export->exp_mds_data;
                obd = req->rq_export->exp_obd;
                mds = &obd->u.mds;
                spin_lock_bh(&obd->obd_processing_task_lock);
                if (obd->obd_flags & OBD_ABORT_RECOVERY)
                        target_abort_recovery(obd);
                spin_unlock_bh(&obd->obd_processing_task_lock);

                if (obd->obd_flags & OBD_RECOVERING) {
                        rc = filter_recovery_request(req, obd, &should_process);
                        if (rc || !should_process)
                                RETURN(rc);
                }
        }

        switch (req->rq_reqmsg->opc) {
        case MDS_CONNECT:
                DEBUG_REQ(D_INODE, req, "connect");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_CONNECT_NET, 0);
                rc = target_handle_connect(req, mds_handle);
                /* Make sure that last_rcvd is correct. */
                if (!rc) {
                        /* Now that we have an export, set mds. */
                        mds = mds_req2mds(req);
                        mds_fsync_super(mds->mds_sb);
                }
                break;

        case MDS_DISCONNECT:
                DEBUG_REQ(D_INODE, req, "disconnect");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_DISCONNECT_NET, 0);
                rc = target_handle_disconnect(req);
                /* Make sure that last_rcvd is correct. */
                if (!rc)
                        mds_fsync_super(mds->mds_sb);
                req->rq_status = rc;
                break;

        case MDS_GETSTATUS:
                DEBUG_REQ(D_INODE, req, "getstatus");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_GETSTATUS_NET, 0);
                rc = mds_getstatus(req);
                break;

        case MDS_GETLOVINFO:
                DEBUG_REQ(D_INODE, req, "getlovinfo");
                rc = mds_getlovinfo(req);
                break;

        case MDS_GETATTR:
                DEBUG_REQ(D_INODE, req, "getattr");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_GETATTR_NET, 0);
                rc = mds_getattr(0, req);
                break;

        case MDS_GETATTR_NAME: {
                struct lustre_handle lockh;
                DEBUG_REQ(D_INODE, req, "getattr_name");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_GETATTR_NAME_NET, 0);

                /* If this request gets a reconstructed reply, we won't be
                 * acquiring any new locks in mds_getattr_name, so we don't
                 * want to cancel.
                 */
                lockh.addr = 0;
                rc = mds_getattr_name(0, req, &lockh);
                if (rc == 0 && lockh.addr)
                        ldlm_lock_decref(&lockh, LCK_PR);
                break;
        }
        case MDS_STATFS:
                DEBUG_REQ(D_INODE, req, "statfs");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_STATFS_NET, 0);
                rc = mds_statfs(req);
                break;

        case MDS_READPAGE:
                DEBUG_REQ(D_INODE, req, "readpage");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_READPAGE_NET, 0);
                rc = mds_readpage(req);

                if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SENDPAGE))
                        return 0;
                break;

        case MDS_REINT: {
                int opc = *(u32 *)lustre_msg_buf(req->rq_reqmsg, 0);
                int size[2] = {sizeof(struct mds_body), mds->mds_max_mdsize};
                int bufcount;

                DEBUG_REQ(D_INODE, req, "reint (%s%s)",
                          reint_names[opc & REINT_OPCODE_MASK],
                          opc & REINT_REPLAYING ? "|REPLAYING" : "");

                OBD_FAIL_RETURN(OBD_FAIL_MDS_REINT_NET, 0);

                if (opc == REINT_UNLINK)
                        bufcount = 2;
                else
                        bufcount = 1;

                rc = lustre_pack_msg(bufcount, size, NULL,
                                     &req->rq_replen, &req->rq_repmsg);
                if (rc)
                        break;

                rc = mds_reint(req, 0, NULL);
                OBD_FAIL_RETURN(OBD_FAIL_MDS_REINT_NET_REP, 0);
                break;
        }

        case MDS_CLOSE:
                DEBUG_REQ(D_INODE, req, "close");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_CLOSE_NET, 0);
                rc = mds_close(req);
                break;

        case LDLM_ENQUEUE:
                DEBUG_REQ(D_INODE, req, "enqueue");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_ENQUEUE, 0);
                rc = ldlm_handle_enqueue(req, ldlm_server_completion_ast,
                                         ldlm_server_blocking_ast);
                break;
        case LDLM_CONVERT:
                DEBUG_REQ(D_INODE, req, "convert");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CONVERT, 0);
                rc = ldlm_handle_convert(req);
                break;
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                DEBUG_REQ(D_INODE, req, "callback");
                CERROR("callbacks should not happen on MDS\n");
                LBUG();
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_BL_CALLBACK, 0);
                break;
        default:
                rc = ptlrpc_error(req->rq_svc, req);
                RETURN(rc);
        }

        EXIT;

        /* If we're DISCONNECTing, the mds_export_data is already freed */
        if (!rc && req->rq_reqmsg->opc != MDS_DISCONNECT) {
                struct mds_export_data *med = &req->rq_export->exp_mds_data;
                struct obd_device *obd = list_entry(mds, struct obd_device,
                                                    u.mds);
                req->rq_repmsg->last_xid =
                        HTON__u64(le64_to_cpu(med->med_mcd->mcd_last_xid));
                if ((obd->obd_flags & OBD_NO_TRANSNO) == 0) {
                        req->rq_repmsg->last_committed =
                                HTON__u64(obd->obd_last_committed);
                } else {
                        DEBUG_REQ(D_IOCTL, req,
                                  "not sending last_committed update");
                }
                CDEBUG(D_INFO, "last_transno "LPU64", last_committed "LPU64
                       ", xid "LPU64"\n",
                       mds->mds_last_transno, obd->obd_last_committed,
                       NTOH__u64(req->rq_xid));
        }
 out:

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_LAST_REPLAY) {
                if (obd && (obd->obd_flags & OBD_RECOVERING)) {
                        DEBUG_REQ(D_HA, req, "LAST_REPLAY, queuing reply");
                        return target_queue_final_reply(req, rc);
                }
                /* Lost a race with recovery; let the error path DTRT. */
                rc = req->rq_status = -ENOTCONN;
        }

        mds_send_reply(req, rc);
        return 0;
}

/* Update the server data on disk.  This stores the new mount_count and
 * also the last_rcvd value to disk.  If we don't have a clean shutdown,
 * then the server last_rcvd value may be less than that of the clients.
 * This will alert us that we may need to do client recovery.
 *
 * Also assumes for mds_last_transno that we are not modifying it (no locking).
 */
int mds_update_server_data(struct mds_obd *mds)
{
        struct mds_server_data *msd = mds->mds_server_data;
        struct file *filp = mds->mds_rcvd_filp;
        struct obd_run_ctxt saved;
        loff_t off = 0;
        int rc;

        push_ctxt(&saved, &mds->mds_ctxt, NULL);
        msd->msd_last_transno = cpu_to_le64(mds->mds_last_transno);
        msd->msd_mount_count = cpu_to_le64(mds->mds_mount_count);

        CDEBUG(D_SUPER, "MDS mount_count is %Lu, last_transno is %Lu\n",
               (unsigned long long)mds->mds_mount_count,
               (unsigned long long)mds->mds_last_transno);
        rc = lustre_fwrite(filp, (char *)msd, sizeof(*msd), &off);
        if (rc != sizeof(*msd)) {
                CERROR("error writing MDS server data: rc = %d\n", rc);
                if (rc > 0)
                        rc = -EIO;
                GOTO(out, rc);
        }
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        rc = fsync_dev(filp->f_dentry->d_inode->i_rdev);
#else
        rc = file_fsync(filp, filp->f_dentry, 1);
#endif
        if (rc)
                CERROR("error flushing MDS server data: rc = %d\n", rc);

out:
        pop_ctxt(&saved, &mds->mds_ctxt, NULL);
        RETURN(rc);
}

/* mount the file system (secretly) */
static int mds_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct mds_obd *mds = &obddev->u.mds;
        struct vfsmount *mnt;
        int rc = 0;
        ENTRY;

#ifdef CONFIG_DEV_RDONLY
        dev_clear_rdonly(2);
#endif
        if (!data->ioc_inlbuf1 || !data->ioc_inlbuf2)
                RETURN(rc = -EINVAL);

        obddev->obd_fsops = fsfilt_get_ops(data->ioc_inlbuf2);
        if (IS_ERR(obddev->obd_fsops))
                RETURN(rc = PTR_ERR(obddev->obd_fsops));

        mnt = do_kern_mount(data->ioc_inlbuf2, 0, data->ioc_inlbuf1, NULL);
        if (IS_ERR(mnt)) {
                rc = PTR_ERR(mnt);
                CERROR("do_kern_mount failed: rc = %d\n", rc);
                GOTO(err_ops, rc);
        }

        CDEBUG(D_SUPER, "%s: mnt = %p\n", data->ioc_inlbuf1, mnt);
        mds->mds_sb = mnt->mnt_root->d_inode->i_sb;
        if (!mds->mds_sb)
                GOTO(err_put, rc = -ENODEV);

        spin_lock_init(&mds->mds_transno_lock);
        mds->mds_max_mdsize = sizeof(struct lov_mds_md);
        rc = mds_fs_setup(obddev, mnt);
        if (rc) {
                CERROR("MDS filesystem method init failed: rc = %d\n", rc);
                GOTO(err_put, rc);
        }

        obddev->obd_namespace =
                ldlm_namespace_new("mds_server", LDLM_NAMESPACE_SERVER);
        if (obddev->obd_namespace == NULL) {
                mds_cleanup(obddev);
                GOTO(err_fs, rc = -ENOMEM);
        }

        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "mds_ldlm_client", &obddev->obd_ldlm_client);

        mds->mds_has_lov_desc = 0;

        RETURN(0);

err_fs:
        mds_fs_cleanup(obddev);
err_put:
        unlock_kernel();
        mntput(mds->mds_vfsmnt);
        mds->mds_sb = 0;
        lock_kernel();
err_ops:
        fsfilt_put_ops(obddev->obd_fsops);
        return rc;
}

static int mds_cleanup(struct obd_device *obddev)
{
        struct super_block *sb;
        struct mds_obd *mds = &obddev->u.mds;
        ENTRY;

        sb = mds->mds_sb;
        if (!mds->mds_sb)
                RETURN(0);

        mds_update_server_data(mds);
        mds_fs_cleanup(obddev);

        unlock_kernel();
        mntput(mds->mds_vfsmnt);
        mds->mds_sb = 0;

        ldlm_namespace_free(obddev->obd_namespace);

        lock_kernel();
#ifdef CONFIG_DEV_RDONLY
        dev_clear_rdonly(2);
#endif
        fsfilt_put_ops(obddev->obd_fsops);

        RETURN(0);
}

inline void fixup_handle_for_resent_req(struct ptlrpc_request *req,
                                        struct lustre_handle *lockh)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_client_data *mcd = med->med_mcd;
        struct ptlrpc_request *oldrep = med->med_outstanding_reply;
        struct ldlm_reply *dlm_rep;

        if ((lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT) &&
            (mcd->mcd_last_xid == req->rq_xid) && (oldrep != NULL)) {
                DEBUG_REQ(D_HA, req, "restoring lock handle from %p", oldrep);
                dlm_rep = lustre_msg_buf(oldrep->rq_repmsg, 0);
                lockh->addr = dlm_rep->lock_handle.addr;
                lockh->cookie = dlm_rep->lock_handle.cookie;
        }
}

static int ldlm_intent_policy(struct ldlm_namespace *ns,
                              struct ldlm_lock **lockp, void *req_cookie,
                              ldlm_mode_t mode, int flags, void *data)
{
        struct ptlrpc_request *req = req_cookie;
        struct ldlm_lock *lock = *lockp;
        int rc = 0;
        ENTRY;

        if (!req_cookie)
                RETURN(0);

        if (req->rq_reqmsg->bufcount > 1) {
                /* an intent needs to be considered */
                struct ldlm_intent *it = lustre_msg_buf(req->rq_reqmsg, 1);
                struct mds_obd *mds = &req->rq_export->exp_obd->u.mds;
                struct mds_body *mds_body;
                struct ldlm_reply *rep;
                struct lustre_handle lockh;
                struct ldlm_lock *new_lock;
                int rc, offset = 2, repsize[3] = {sizeof(struct ldlm_reply),
                                                  sizeof(struct mds_body),
                                                  mds->mds_max_mdsize};

                it->opc = NTOH__u64(it->opc);

                LDLM_DEBUG(lock, "intent policy, opc: %s",
                           ldlm_it2str(it->opc));

                rc = lustre_pack_msg(3, repsize, NULL, &req->rq_replen,
                                     &req->rq_repmsg);
                if (rc) {
                        rc = req->rq_status = -ENOMEM;
                        RETURN(rc);
                }

                rep = lustre_msg_buf(req->rq_repmsg, 0);
                rep->lock_policy_res1 = IT_INTENT_EXEC;

                fixup_handle_for_resent_req(req, &lockh);

                /* execute policy */
                switch ((long)it->opc) {
                case IT_OPEN:
                case IT_CREAT|IT_OPEN:
                        rc = mds_reint(req, offset, &lockh);
                        /* We return a dentry to the client if IT_OPEN_POS is
                         * set, or if we make it to the OPEN portion of the
                         * programme (which implies that we created) */
                        if (!(rep->lock_policy_res1 & IT_OPEN_POS ||
                              rep->lock_policy_res1 & IT_OPEN_OPEN)) {
                                rep->lock_policy_res2 = rc;
                                RETURN(ELDLM_LOCK_ABORTED);
                        }
                        break;
                case IT_UNLINK:
                        rc = mds_reint(req, offset, &lockh);
                        /* Don't return a lock if the unlink failed, or if we're
                         * not sending back an EA */
                        if (rc) {
                                rep->lock_policy_res2 = rc;
                                RETURN(ELDLM_LOCK_ABORTED);
                        }
                        if (req->rq_status != 0) {
                                rep->lock_policy_res2 = req->rq_status;
                                RETURN(ELDLM_LOCK_ABORTED);
                        }
                        mds_body = lustre_msg_buf(req->rq_repmsg, 1);
                        if (!(mds_body->valid & OBD_MD_FLEASIZE)) {
                                rep->lock_policy_res2 = rc;
                                RETURN(ELDLM_LOCK_ABORTED);
                        }
                        break;
                case IT_GETATTR:
                case IT_LOOKUP:
                case IT_READDIR:
                        rc = mds_getattr_name(offset, req, &lockh);
                        /* FIXME: we need to sit down and decide on who should
                         * set req->rq_status, who should return negative and
                         * positive return values, and what they all mean. */
                        if (rc) {
                                rep->lock_policy_res2 = rc;
                                RETURN(ELDLM_LOCK_ABORTED);
                        }
                        if (req->rq_status != 0) {
                                rep->lock_policy_res2 = req->rq_status;
                                RETURN(ELDLM_LOCK_ABORTED);
                        }
                        break;
                default:
                        CERROR("Unhandled intent "LPD64"\n", it->opc);
                        LBUG();
                }

                if (flags & LDLM_FL_INTENT_ONLY) {
                        LDLM_DEBUG(lock, "INTENT_ONLY, aborting lock");
                        RETURN(ELDLM_LOCK_ABORTED);
                }

                /* By this point, whatever function we called above must have
                 * filled in 'lockh' or returned an error.  We want to give the
                 * new lock to the client instead of whatever lock it was about
                 * to get. */
                new_lock = ldlm_handle2lock(&lockh);
                LASSERT(new_lock != NULL);
                *lockp = new_lock;

                rep->lock_policy_res2 = req->rq_status;

                if (new_lock->l_export == req->rq_export) {
                        /* Already gave this to the client, which means that we
                         * reconstructed a reply. */
                        LASSERT(lustre_msg_get_flags(req->rq_reqmsg) & 
                                MSG_RESENT);
                        RETURN(ELDLM_LOCK_REPLACED);
                }

                /* Fixup the lock to be given to the client */
                l_lock(&new_lock->l_resource->lr_namespace->ns_lock);
                LASSERT(new_lock->l_readers + new_lock->l_writers == 1);
                new_lock->l_readers = 0;
                new_lock->l_writers = 0;

                new_lock->l_export = req->rq_export;
                list_add(&new_lock->l_export_chain,
                         &new_lock->l_export->exp_ldlm_data.led_held_locks);

                /* We don't need to worry about completion_ast (which isn't set
                 * in 'lock' yet anyways), because this lock is already
                 * granted. */
                new_lock->l_blocking_ast = lock->l_blocking_ast;

                memcpy(&new_lock->l_remote_handle, &lock->l_remote_handle,
                       sizeof(lock->l_remote_handle));

                new_lock->l_flags &= ~(LDLM_FL_LOCAL | LDLM_FL_AST_SENT |
                                       LDLM_FL_CBPENDING);

                LDLM_LOCK_PUT(new_lock);
                l_unlock(&new_lock->l_resource->lr_namespace->ns_lock);

                RETURN(ELDLM_LOCK_REPLACED);
        } else {
                int size = sizeof(struct ldlm_reply);
                rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen,
                                     &req->rq_repmsg);
                if (rc) {
                        LBUG();
                        RETURN(-ENOMEM);
                }
        }
        RETURN(rc);
}

int mds_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_multi_vars(0, &lvars);
        return lprocfs_obd_attach(dev, lvars.obd_vars);
}

int mds_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

int mdt_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_multi_vars(1, &lvars);
        return lprocfs_obd_attach(dev, lvars.obd_vars);
}

int mdt_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

static int mdt_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct mds_obd *mds = &obddev->u.mds;
        int i, rc = 0;
        ENTRY;

        mds->mds_service = ptlrpc_init_svc(MDS_NEVENTS, MDS_NBUFS,
                                           MDS_BUFSIZE, MDS_MAXREQSIZE,
                                           MDS_REQUEST_PORTAL, MDC_REPLY_PORTAL,
                                           mds_handle, "mds");
        if (!mds->mds_service) {
                CERROR("failed to start service\n");
                RETURN(rc = -ENOMEM);
        }

        for (i = 0; i < MDT_NUM_THREADS; i++) {
                char name[32];
                sprintf(name, "ll_mdt_%02d", i);
                rc = ptlrpc_start_thread(obddev, mds->mds_service, name);
                if (rc) {
                        CERROR("cannot start MDT thread #%d: rc %d\n", i, rc);
                        GOTO(err_thread, rc);
                }
        }

        mds->mds_setattr_service =
                ptlrpc_init_svc(MDS_NEVENTS, MDS_NBUFS,
                                MDS_BUFSIZE, MDS_MAXREQSIZE,
                                MDS_SETATTR_PORTAL, MDC_REPLY_PORTAL,
                                mds_handle, "mds");
        if (!mds->mds_setattr_service) {
                CERROR("failed to start getattr service\n");
                GOTO(err_thread, rc = -ENOMEM);
        }

        for (i = 0; i < MDT_NUM_THREADS; i++) {
                char name[32];
                sprintf(name, "ll_mdt_attr_%02d", i);
                rc = ptlrpc_start_thread(obddev, mds->mds_setattr_service,
                                         name);
                if (rc) {
                        CERROR("cannot start MDT setattr thread #%d: rc %d\n",
                               i, rc);
                        GOTO(err_thread2, rc);
                }
        }

        mds->mds_readpage_service =
                ptlrpc_init_svc(MDS_NEVENTS, MDS_NBUFS,
                                MDS_BUFSIZE, MDS_MAXREQSIZE,
                                MDS_READPAGE_PORTAL, MDC_REPLY_PORTAL,
                                mds_handle, "mds");
        if (!mds->mds_readpage_service) {
                CERROR("failed to start readpage service\n");
                GOTO(err_thread2, rc = -ENOMEM);
        }

        for (i = 0; i < MDT_NUM_THREADS; i++) {
                char name[32];
                sprintf(name, "ll_mdt_rdpg_%02d", i);
                rc = ptlrpc_start_thread(obddev, mds->mds_readpage_service,
                                         name);
                if (rc) {
                        CERROR("cannot start MDT readpage thread #%d: rc %d\n",
                               i, rc);
                        GOTO(err_thread3, rc);
                }
        }

        RETURN(0);

err_thread3:
        ptlrpc_stop_all_threads(mds->mds_readpage_service);
        ptlrpc_unregister_service(mds->mds_readpage_service);
err_thread2:
        ptlrpc_stop_all_threads(mds->mds_setattr_service);
        ptlrpc_unregister_service(mds->mds_setattr_service);
err_thread:
        ptlrpc_stop_all_threads(mds->mds_service);
        ptlrpc_unregister_service(mds->mds_service);
        return rc;
}


static int mdt_cleanup(struct obd_device *obddev)
{
        struct mds_obd *mds = &obddev->u.mds;
        ENTRY;

        ptlrpc_stop_all_threads(mds->mds_readpage_service);
        ptlrpc_unregister_service(mds->mds_readpage_service);

        ptlrpc_stop_all_threads(mds->mds_setattr_service);
        ptlrpc_unregister_service(mds->mds_setattr_service);

        ptlrpc_stop_all_threads(mds->mds_service);
        ptlrpc_unregister_service(mds->mds_service);

        RETURN(0);
}

extern int mds_iocontrol(unsigned int cmd, struct lustre_handle *conn,
                         int len, void *karg, void *uarg);

/* use obd ops to offer management infrastructure */
static struct obd_ops mds_obd_ops = {
        o_owner:       THIS_MODULE,
        o_attach:      mds_attach,
        o_detach:      mds_detach,
        o_connect:     mds_connect,
        o_disconnect:  mds_disconnect,
        o_setup:       mds_setup,
        o_cleanup:     mds_cleanup,
        o_iocontrol:   mds_iocontrol
};

static struct obd_ops mdt_obd_ops = {
        o_owner:       THIS_MODULE,
        o_attach:      mdt_attach,
        o_detach:      mdt_detach,
        o_setup:       mdt_setup,
        o_cleanup:     mdt_cleanup,
};


static int __init mds_init(void)
{
        struct lprocfs_static_vars lvars;
        mds_file_cache = kmem_cache_create("ll_mds_file_data",
                                           sizeof(struct mds_file_data),
                                           0, 0, NULL, NULL);
        if (mds_file_cache == NULL)
                return -ENOMEM;

        lprocfs_init_multi_vars(0, &lvars);
        class_register_type(&mds_obd_ops, lvars.module_vars, LUSTRE_MDS_NAME);
        lprocfs_init_multi_vars(1, &lvars);
        class_register_type(&mdt_obd_ops, lvars.module_vars, LUSTRE_MDT_NAME);
        ldlm_register_intent(ldlm_intent_policy);

        return 0;
}

static void __exit mds_exit(void)
{
        ldlm_unregister_intent();
        class_unregister_type(LUSTRE_MDS_NAME);
        class_unregister_type(LUSTRE_MDT_NAME);
        if (kmem_cache_destroy(mds_file_cache))
                CERROR("couldn't free MDS file cache\n");
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Metadata Server (MDS)");
MODULE_LICENSE("GPL");

module_init(mds_init);
module_exit(mds_exit);
