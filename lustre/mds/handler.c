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
#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
# include <linux/smp_lock.h>
# include <linux/buffer_head.h>
# include <linux/workqueue.h>
# include <linux/mount.h>
#else
# include <linux/locks.h>
#endif
#include <linux/obd_lov.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_commit_confd.h>

#include "mds_internal.h"

static int mds_cleanup(struct obd_device *obd, int flags);

static int mds_bulk_timeout(void *data)
{
        struct ptlrpc_bulk_desc *desc = data;
        struct obd_export *exp = desc->bd_export;

        CERROR("bulk send timed out: evicting %s@%s\n",
               exp->exp_client_uuid.uuid,
               exp->exp_connection->c_remote_uuid.uuid);
        ptlrpc_fail_export(exp);
        ptlrpc_abort_bulk (desc);
        RETURN(1);
}

/* Assumes caller has already pushed into the kernel filesystem context */
static int mds_sendpage(struct ptlrpc_request *req, struct file *file,
                        __u64 offset, __u64 xid)
{
        struct ptlrpc_bulk_desc *desc;
        struct l_wait_info lwi;
        struct page *page;
        int rc = 0;
        ENTRY;

        LASSERT ((offset & (PAGE_CACHE_SIZE - 1)) == 0);

        desc = ptlrpc_prep_bulk_exp (req, BULK_PUT_SOURCE, MDS_BULK_PORTAL);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);

        LASSERT (PAGE_SIZE == PAGE_CACHE_SIZE);
        page = alloc_pages (GFP_KERNEL, 0);
        if (page == NULL)
                GOTO(cleanup_bulk, rc = -ENOMEM);

        rc = ptlrpc_prep_bulk_page(desc, page, 0, PAGE_CACHE_SIZE);
        if (rc != 0)
                GOTO(cleanup_buf, rc);

        CDEBUG(D_EXT2, "reading %lu@"LPU64" from dir %lu (size %llu)\n",
               PAGE_CACHE_SIZE, offset, file->f_dentry->d_inode->i_ino,
               file->f_dentry->d_inode->i_size);
        rc = fsfilt_readpage(req->rq_export->exp_obd, file, page_address (page),
                             PAGE_CACHE_SIZE, (loff_t *)&offset);

        if (rc != PAGE_CACHE_SIZE)
                GOTO(cleanup_buf, rc = -EIO);

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
        rc = l_wait_event(desc->bd_waitq, ptlrpc_bulk_complete (desc), &lwi);
        if (rc) {
                LASSERT (rc == -ETIMEDOUT);
                GOTO(cleanup_buf, rc);
        }

        EXIT;
 cleanup_buf:
        __free_pages (page, 0);
 cleanup_bulk:
        ptlrpc_free_bulk (desc);
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
                              mds_blocking_ast, NULL, lockh);
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
        char fid_name[32];
        unsigned long ino = fid->id;
        __u32 generation = fid->generation;
        struct inode *inode;
        struct dentry *result;

        if (ino == 0)
                RETURN(ERR_PTR(-ESTALE));

        snprintf(fid_name, sizeof(fid_name), "0x%lx", ino);

        CDEBUG(D_DENTRY, "--> mds_fid2dentry: ino %lu, gen %u, sb %p\n",
               ino, generation, mds->mds_sb);

        /* under ext3 this is neither supposed to return bad inodes
           nor NULL inodes. */
        result = ll_lookup_one_len(fid_name, mds->mds_fid_de, strlen(fid_name));
        if (IS_ERR(result))
                RETURN(result);

        inode = result->d_inode;
        if (!inode)
                RETURN(ERR_PTR(-ENOENT));

        if (generation && inode->i_generation != generation) {
                /* we didn't find the right inode.. */
                CERROR("bad inode %lu, link: %d ct: %d or generation %u/%u\n",
                       inode->i_ino, inode->i_nlink,
                       atomic_read(&inode->i_count), inode->i_generation,
                       generation);
                dput(result);
                RETURN(ERR_PTR(-ENOENT));
        }

        if (mnt) {
                *mnt = mds->mds_vfsmnt;
                mntget(*mnt);
        }

        RETURN(result);
}


/* Establish a connection to the MDS.
 *
 * This will set up an export structure for the client to hold state data
 * about that client, like open files, the last operation number it did
 * on the server, etc.
 */
static int mds_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid)
{
        struct obd_export *exp;
        struct mds_export_data *med;
        struct mds_client_data *mcd;
        int rc, abort_recovery;
        ENTRY;

        if (!conn || !obd || !cluuid)
                RETURN(-EINVAL);

        /* Check for aborted recovery. */
        spin_lock_bh(&obd->obd_processing_task_lock);
        abort_recovery = obd->obd_abort_recovery;
        spin_unlock_bh(&obd->obd_processing_task_lock);
        if (abort_recovery)
                target_abort_recovery(obd);

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
        class_export_put(exp);

        OBD_ALLOC(mcd, sizeof(*mcd));
        if (!mcd) {
                CERROR("mds: out of memory for client data\n");
                GOTO(out_export, rc = -ENOMEM);
        }

        memcpy(mcd->mcd_uuid, cluuid, sizeof(mcd->mcd_uuid));
        med->med_mcd = mcd;

        INIT_LIST_HEAD(&med->med_open_head);
        spin_lock_init(&med->med_open_lock);

        rc = mds_client_add(obd, &obd->u.mds, med, -1);
        if (rc)
                GOTO(out_mcd, rc);

        RETURN(0);

out_mcd:
        OBD_FREE(mcd, sizeof(*mcd));
out_export:
        class_disconnect(conn, 0);

        return rc;
}

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

void mds_mfd_put(struct mds_file_data *mfd)
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

void mds_mfd_destroy(struct mds_file_data *mfd)
{
        class_handle_unhash(&mfd->mfd_handle);
        mds_mfd_put(mfd);
}

/* Close a "file descriptor" and possibly unlink an orphan from the
 * PENDING directory.
 *
 * If we are being called from mds_disconnect() because the client has
 * disappeared, then req == NULL and we do not update last_rcvd because
 * there is nothing that could be recovered by the client at this stage
 * (it will not even _have_ an entry in last_rcvd anymore).
 */
static int mds_mfd_close(struct ptlrpc_request *req, struct obd_device *obd,
                         struct mds_file_data *mfd)
{
        struct dentry *dparent = mfd->mfd_dentry->d_parent;
        struct inode *child_inode = mfd->mfd_dentry->d_inode;
        char fidname[LL_FID_NAMELEN];
        int last_orphan, fidlen, rc = 0;
        ENTRY;

        if (dparent) {
                LASSERT(atomic_read(&dparent->d_count) > 0);
                dparent = dget(dparent);
        }

        fidlen = ll_fid2str(fidname, child_inode->i_ino,
                            child_inode->i_generation);

        last_orphan = mds_open_orphan_dec_test(child_inode) &&
                mds_inode_is_orphan(child_inode);

        /* this is the actual "close" */
        l_dput(mfd->mfd_dentry);
        mds_mfd_destroy(mfd);

        if (dparent)
                l_dput(dparent);

        if (last_orphan) {
                struct mds_obd *mds = &obd->u.mds;
                struct inode *pending_dir = mds->mds_pending_dir->d_inode;
                struct dentry *pending_child = NULL;
                void *handle;

                CDEBUG(D_ERROR, "destroying orphan object %s\n", fidname);

                /* Sadly, there is no easy way to save pending_child from
                 * mds_reint_unlink() into mfd, so we need to re-lookup,
                 * but normally it will still be in the dcache.
                 */
                down(&pending_dir->i_sem);
                pending_child = lookup_one_len(fidname, mds->mds_pending_dir,
                                               fidlen);
                if (IS_ERR(pending_child))
                        GOTO(out_lock, rc = PTR_ERR(pending_child));
                LASSERT(pending_child->d_inode != NULL);

                handle = fsfilt_start(obd, pending_dir, FSFILT_OP_UNLINK, NULL);
                if (IS_ERR(handle))
                        GOTO(out_dput, rc = PTR_ERR(handle));
                rc = vfs_unlink(pending_dir, pending_child);
                if (rc)
                        CERROR("error unlinking orphan %s: rc %d\n",fidname,rc);

                if (req) {
                        rc = mds_finish_transno(mds, pending_dir, handle, req,
                                                rc, 0);
                } else {
                        int err = fsfilt_commit(obd, pending_dir, handle, 0);
                        if (err) {
                                CERROR("error committing orphan unlink: %d\n",
                                       err);
                                if (!rc)
                                        rc = err;
                        }
                }
        out_dput:
                dput(pending_child);
        out_lock:
                up(&pending_dir->i_sem);
        }

        RETURN(rc);
}

static int mds_disconnect(struct lustre_handle *conn, int flags)
{
        struct obd_export *export = class_conn2export(conn);
        struct mds_export_data *med = &export->exp_mds_data;
        struct obd_device *obd = export->exp_obd;
        struct obd_run_ctxt saved;
        int rc;
        ENTRY;

        push_ctxt(&saved, &obd->u.mds.mds_ctxt, NULL);
        /* Close any open files (which may also cause orphan unlinking). */
        spin_lock(&med->med_open_lock);
        while (!list_empty(&med->med_open_head)) {
                struct list_head *tmp = med->med_open_head.next;
                struct mds_file_data *mfd =
                        list_entry(tmp, struct mds_file_data, mfd_list);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                /* bug 1579: fix force-closing for 2.5 */
                struct dentry *dentry = mfd->mfd_dentry;

                list_del(&mfd->mfd_list);
                spin_unlock(&med->med_open_lock);

                CERROR("force closing client file handle for %*s (%s:%lu)\n",
                       dentry->d_name.len, dentry->d_name.name,
                       kdevname(dentry->d_inode->i_sb->s_dev),
                       dentry->d_inode->i_ino);
                rc = mds_mfd_close(NULL, obd, mfd);
#endif
                if (rc)
                        CDEBUG(D_INODE, "Error closing file: %d\n", rc);
                spin_lock(&med->med_open_lock);
        }
        spin_unlock(&med->med_open_lock);
        pop_ctxt(&saved, &obd->u.mds.mds_ctxt, NULL);

        ldlm_cancel_locks_for_export(export);
        if (export->exp_outstanding_reply) {
                struct ptlrpc_request *req = export->exp_outstanding_reply;
                unsigned long          flags;

                /* Fake the ack, so the locks get cancelled. */
                LBUG ();
                /* Actually we can't do this because it prevents us knowing
                 * if the ACK callback ran or not */
                spin_lock_irqsave (&req->rq_lock, flags);
                req->rq_want_ack = 0;
                req->rq_err = 1;
                wake_up(&req->rq_wait_for_rep);
                spin_unlock_irqrestore (&req->rq_lock, flags);

                export->exp_outstanding_reply = NULL;
        }

        if (!(flags & OBD_OPT_FAILOVER))
                mds_client_free(export);

        rc = class_disconnect(conn, flags);
        class_export_put(export);

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
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        if (sb->s_dirt && sb->s_op && sb->s_op->write_super)
                sb->s_op->write_super(sb);
#else
        if (sb->s_dirt && sb->s_op) {
                if (sb->s_op->sync_fs)
                        sb->s_op->sync_fs(sb, 1);
                else if (sb->s_op->write_super)
                        sb->s_op->write_super(sb);
        }
#endif
        unlock_super(sb);
        unlock_kernel();
}

static int mds_getstatus(struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_GETSTATUS_PACK)) {
                CERROR("mds: out of memory for message: size=%d\n", size);
                req->rq_status = -ENOMEM;       /* superfluous? */
                RETURN(-ENOMEM);
        }

        /* Flush any outstanding transactions to disk so the client will
         * get the latest last_committed value and can drop their local
         * requests if they have any.  This would be fsync_super() if it
         * was exported.
         */
        fsfilt_sync(obd, mds->mds_sb);

        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*body));
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
        struct obd_uuid *uuid0;
        int tgt_count;
        int rc, size[2] = {sizeof(*desc)};
        ENTRY;

        streq = lustre_swab_reqbuf (req, 0, sizeof (*streq),
                                    lustre_swab_mds_status_req);
        if (streq == NULL) {
                CERROR ("Can't unpack mds_status_req\n");
                RETURN (-EFAULT);
        }

        if (streq->repbuf > LOV_MAX_UUID_BUFFER_SIZE) {
                CERROR ("Illegal request for uuid array > %d\n",
                        streq->repbuf);
                RETURN (-EINVAL);
        }
        size[1] = streq->repbuf;

        rc = lustre_pack_msg(2, size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc) {
                CERROR("mds: out of memory for message: size=%d\n", size[1]);
                RETURN(-ENOMEM);
        }

        if (!mds->mds_has_lov_desc) {
                req->rq_status = -ENOENT;
                RETURN(0);
        }

        /* XXX We're sending the lov_desc in my byte order.
         * Receiver will swab... */
        desc = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*desc));
        memcpy(desc, &mds->mds_lov_desc, sizeof (*desc));

        tgt_count = mds->mds_lov_desc.ld_tgt_count;
        uuid0 = lustre_msg_buf(req->rq_repmsg, 1, tgt_count * sizeof (*uuid0));
        if (uuid0 == NULL) {
                CERROR("too many targets, enlarge client buffers\n");
                req->rq_status = -ENOSPC;
                RETURN(0);
        }

        rc = mds_get_lovtgts(mds, tgt_count, uuid0);
        if (rc) {
                CERROR("get_lovtgts error %d\n", rc);
                req->rq_status = rc;
                RETURN(0);
        }
        memcpy(&mds->mds_osc_uuid, &mds->mds_lov_desc.ld_uuid,
               sizeof(mds->mds_osc_uuid));
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
        int lmm_size;
        int rc;
        ENTRY;

        lmm = lustre_msg_buf(msg, offset, 0);
        if (lmm == NULL) {
                /* Some problem with getting eadata when I sized the reply
                 * buffer... */
                CDEBUG(D_INFO, "no space reserved for inode %lu MD\n",
                       inode->i_ino);
                RETURN(0);
        }
        lmm_size = msg->buflens[offset];

        /* I don't really like this, but it is a sanity check on the client
         * MD request.  However, if the client doesn't know how much space
         * to reserve for the MD, this shouldn't be fatal either...
         */
        if (lmm_size > mds->mds_max_mdsize) {
                CERROR("Reading MD for inode %lu of %d bytes > max %d\n",
                       inode->i_ino, lmm_size, mds->mds_max_mdsize);
                // RETURN(-EINVAL);
        }

        rc = fsfilt_get_md(obd, inode, lmm, lmm_size);
        if (rc < 0) {
                CERROR("Error %d reading eadata for ino %lu\n",
                       rc, inode->i_ino);
        } else if (rc > 0) {
                body->valid |= OBD_MD_FLEASIZE;
                body->eadatasize = rc;
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

        body = lustre_msg_buf(req->rq_repmsg, reply_off, sizeof(*body));
        LASSERT(body != NULL);                 /* caller prepped reply */

        mds_pack_inode2fid(&body->fid1, inode);
        mds_pack_inode2body(body, inode);

        if (S_ISREG(inode->i_mode) && (reqbody->valid & OBD_MD_FLEASIZE) != 0) {
                rc = mds_pack_md(obd, req->rq_repmsg, reply_off+1, body, inode);

                /* If we have LOV EA data, the OST holds size, atime, mtime */
                if (!(body->valid & OBD_MD_FLEASIZE))
                        body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                        OBD_MD_FLATIME | OBD_MD_FLMTIME);
        } else if (S_ISLNK(inode->i_mode) &&
                   (reqbody->valid & OBD_MD_LINKNAME) != 0) {
                char *symname = lustre_msg_buf(req->rq_repmsg, reply_off + 1,0);
                int len;

                LASSERT (symname != NULL);       /* caller prepped reply */
                len = req->rq_repmsg->buflens[reply_off + 1];

                rc = inode->i_op->readlink(dentry, symname, len);
                if (rc < 0) {
                        CERROR("readlink failed: %d\n", rc);
                } else if (rc != len - 1) {
                        CERROR ("Unexpected readlink rc %d: expecting %d\n",
                                rc, len - 1);
                        rc = -EINVAL;
                } else {
                        CDEBUG(D_INODE, "read symlink dest %s\n", symname);
                        body->valid |= OBD_MD_LINKNAME;
                        body->eadatasize = rc + 1;
                        symname[rc] = 0;        /* NULL terminate */
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

        body = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*body));
        LASSERT(body != NULL);                 /* checked by caller */
        LASSERT_REQSWABBED(req, offset);       /* swabbed by caller */

        if (S_ISREG(inode->i_mode) && (body->valid & OBD_MD_FLEASIZE)) {
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
                } else {
                        size[bufcount] = rc;
                }
                bufcount++;
        } else if (S_ISLNK(inode->i_mode) && (body->valid & OBD_MD_LINKNAME)) {
                if (inode->i_size + 1 != body->eadatasize)
                        CERROR("symlink size: %Lu, reply space: %d\n",
                               inode->i_size + 1, body->eadatasize);
                size[bufcount] = MIN(inode->i_size + 1, body->eadatasize);
                bufcount++;
                CDEBUG(D_INODE, "symlink size: %Lu, reply space: %d\n",
                       inode->i_size + 1, body->eadatasize);
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK)) {
                CERROR("failed MDS_GETATTR_PACK test\n");
                req->rq_status = -ENOMEM;
                GOTO(out, rc = -ENOMEM);
        }

        rc = lustre_pack_msg(bufcount, size, NULL, &req->rq_replen,
                             &req->rq_repmsg);
        if (rc) {
                CERROR("out of memory\n");
                GOTO(out, req->rq_status = rc);
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

        LASSERT (req->rq_export->exp_outstanding_reply);

        mds_steal_ack_locks(req->rq_export, req);

        if (req->rq_status)
                return;

        body = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*body));
        LASSERT (body != NULL);                 /* checked by caller */
        LASSERT_REQSWABBED (req, offset);       /* swabbed by caller */

        name = lustre_msg_string(req->rq_reqmsg, offset + 1, 0);
        LASSERT (name != NULL);                 /* checked by caller */
        LASSERT_REQSWABBED (req, offset + 1);   /* swabbed by caller */
        namelen = req->rq_reqmsg->buflens[offset + 1];

        LASSERT (offset == 2 || offset == 0);
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
        child = ll_lookup_one_len(name, parent, namelen - 1);
        LASSERT(!IS_ERR(child));

        if (req->rq_repmsg == NULL) {
                rc = mds_getattr_pack_msg(req, child->d_inode, offset);
                /* XXX need to handle error here */
                LASSERT (rc == 0);
        }

        rc = mds_getattr_internal(obd, child, req, body, offset);
        /* XXX need to handle error here */
        LASSERT(!rc);
        l_dput(child);
        l_dput(parent);
}

static int mds_getattr_name(int offset, struct ptlrpc_request *req,
                            struct lustre_handle *child_lockh)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct ldlm_reply *rep = NULL;
        struct obd_run_ctxt saved;
        struct mds_body *body;
        struct dentry *de = NULL, *dchild = NULL;
        struct inode *dir;
        struct obd_ucred uc;
        struct ldlm_res_id child_res_id = { .name = {0} };
        struct lustre_handle parent_lockh;
        int namesize;
        int flags = 0, rc = 0, cleanup_phase = 0;
        char *name;
        ENTRY;

        LASSERT(!strcmp(obd->obd_type->typ_name, "mds"));

        /* Swab now, before anyone looks inside the request */

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL) {
                CERROR("Can't swab mds_body\n");
                GOTO(cleanup, rc = -EFAULT);
        }

        LASSERT_REQSWAB(req, offset + 1);
        name = lustre_msg_string(req->rq_reqmsg, offset + 1, 0);
        if (name == NULL) {
                CERROR("Can't unpack name\n");
                GOTO(cleanup, rc = -EFAULT);
        }
        namesize = req->rq_reqmsg->buflens[offset + 1];

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT) {
                struct obd_export *exp = req->rq_export;
                if (exp->exp_outstanding_reply &&
                    exp->exp_outstanding_reply->rq_xid == req->rq_xid) {
                        reconstruct_getattr_name(offset, req, child_lockh);
                        RETURN(0);
                }
                DEBUG_REQ(D_HA, req, "no reply for RESENT req (have "LPD64")",
                          exp->exp_outstanding_reply ?
                          exp->exp_outstanding_reply->rq_xid : (u64)0);
        }

        LASSERT (offset == 0 || offset == 2);
        /* if requests were at offset 2, the getattr reply goes back at 1 */
        if (offset) { 
                rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*rep));
                offset = 1;
        }

        uc.ouc_fsuid = body->fsuid;
        uc.ouc_fsgid = body->fsgid;
        uc.ouc_cap = body->capability;
        uc.ouc_suppgid1 = body->suppgid;
        uc.ouc_suppgid2 = -1;
        push_ctxt(&saved, &mds->mds_ctxt, &uc);
        /* Step 1: Lookup/lock parent */
        intent_set_disposition(rep, DISP_LOOKUP_EXECD);
        de = mds_fid2locked_dentry(obd, &body->fid1, NULL, LCK_PR,
                                   &parent_lockh);
        if (IS_ERR(de))
                GOTO(cleanup, rc = PTR_ERR(de));
        dir = de->d_inode;
        LASSERT(dir);

        cleanup_phase = 1; /* parent dentry and lock */

        CDEBUG(D_INODE, "parent ino %lu, name %s\n", dir->i_ino, name);

        /* Step 2: Lookup child */
        dchild = ll_lookup_one_len(name, de, namesize - 1);
        if (IS_ERR(dchild)) {
                CDEBUG(D_INODE, "child lookup error %ld\n", PTR_ERR(dchild));
                GOTO(cleanup, rc = PTR_ERR(dchild));
        }

        cleanup_phase = 2; /* child dentry */

        if (dchild->d_inode == NULL) {
                intent_set_disposition(rep, DISP_LOOKUP_NEG);
                GOTO(cleanup, rc = -ENOENT);
        } else {
                intent_set_disposition(rep, DISP_LOOKUP_POS);
        }

        /* Step 3: Lock child */
        child_res_id.name[0] = dchild->d_inode->i_ino;
        child_res_id.name[1] = dchild->d_inode->i_generation;
        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                              child_res_id, LDLM_PLAIN, NULL, 0, LCK_PR,
                              &flags, ldlm_completion_ast, mds_blocking_ast,
                              NULL, child_lockh);
        if (rc != ELDLM_OK) {
                CERROR("ldlm_cli_enqueue: %d\n", rc);
                GOTO(cleanup, rc = -EIO);
        }

        cleanup_phase = 3; /* child lock */

        if (req->rq_repmsg == NULL) {
                rc = mds_getattr_pack_msg(req, dchild->d_inode, offset);
                if (rc != 0) {
                        CERROR ("mds_getattr_pack_msg: %d\n", rc);
                        GOTO (cleanup, rc);
                }
        }

        rc = mds_getattr_internal(obd, dchild, req, body, offset);
        GOTO(cleanup, rc); /* returns the lock to the client */

 cleanup:
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

        body = lustre_swab_reqbuf (req, offset, sizeof (*body),
                                   lustre_swab_mds_body);
        if (body == NULL) {
                CERROR ("Can't unpack body\n");
                RETURN (-EFAULT);
        }

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
        if (rc != 0) {
                CERROR ("mds_getattr_pack_msg: %d\n", rc);
                GOTO (out_pop, rc);
        }

        req->rq_status = mds_getattr_internal(obd, de, req, body, 0);

        l_dput(de);
        GOTO(out_pop, rc);
out_pop:
        pop_ctxt(&saved, &mds->mds_ctxt, &uc);
        return rc;
}


static int mds_obd_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                          unsigned long max_age)
{
        return fsfilt_statfs(obd, obd->u.mds.mds_sb, osfs);
}

static int mds_statfs(struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        int rc, size = sizeof(struct obd_statfs);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_STATFS_PACK)) {
                CERROR("mds: statfs lustre_pack_msg failed: rc = %d\n", rc);
                GOTO(out, rc);
        }

        /* We call this so that we can cache a bit - 1 jiffie worth */
        rc = obd_statfs(obd, lustre_msg_buf(req->rq_repmsg,0,size),jiffies-HZ);
        if (rc) {
                CERROR("mds_obd_statfs failed: rc %d\n", rc);
                GOTO(out, rc);
        }

        EXIT;
out:
        req->rq_status = rc;
        return 0;
}

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
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_body *body;
        struct mds_file_data *mfd;
        struct obd_run_ctxt saved;
        int rc;
        ENTRY;

        MDS_CHECK_RESENT(req, reconstruct_close(req));

        body = lustre_swab_reqbuf(req, 0, sizeof (*body),
                                  lustre_swab_mds_body);
        if (body == NULL) {
                CERROR ("Can't unpack body\n");
                RETURN (-EFAULT);
        }

        mfd = mds_handle2mfd(&body->handle);
        if (mfd == NULL) {
                DEBUG_REQ(D_ERROR, req, "no handle for file close "LPD64
                          ": cookie "LPX64"\n", body->fid1.id,
                          body->handle.cookie);
                RETURN(-ESTALE);
        }

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc) {
                CERROR("lustre_pack_msg: rc = %d\n", rc);
                req->rq_status = rc;
        }

        spin_lock(&med->med_open_lock);
        list_del(&mfd->mfd_list);
        spin_unlock(&med->med_open_lock);

        push_ctxt(&saved, &obd->u.mds.mds_ctxt, NULL);
        req->rq_status = mds_mfd_close(rc ? NULL : req, obd, mfd);
        pop_ctxt(&saved, &obd->u.mds.mds_ctxt, NULL);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_CLOSE_PACK)) {
                CERROR("test case OBD_FAIL_MDS_CLOSE_PACK\n");
                req->rq_status = -ENOMEM;
                mds_mfd_put(mfd);
                RETURN(-ENOMEM);
        }

        mds_mfd_put(mfd);
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
        int rc, size = sizeof(*repbody);
        struct obd_ucred uc;
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_READPAGE_PACK)) {
                CERROR("mds: out of memory\n");
                GOTO(out, rc = -ENOMEM);
        }

        body = lustre_swab_reqbuf (req, 0, sizeof (*body),
                                   lustre_swab_mds_body);
        if (body == NULL)
                GOTO (out, rc = -EFAULT);

        /* body->size is actually the offset -eeb */
        if ((body->size & ~PAGE_MASK) != 0) {
                CERROR ("offset "LPU64"not on a page boundary\n", body->size);
                GOTO (out, rc = -EFAULT);
        }

        /* body->nlink is actually the #bytes to read -eeb */
        if (body->nlink != PAGE_SIZE) {
                CERROR ("size %d is not PAGE_SIZE\n", body->nlink);
                GOTO (out, rc = -EFAULT);
        }

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

        repbody = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*repbody));
        repbody->size = file->f_dentry->d_inode->i_size;
        repbody->valid = OBD_MD_FLSIZE;

        /* to make this asynchronous make sure that the handling function
           doesn't send a reply when this function completes. Instead a
           callback function would send the reply */
        /* body->blocks is actually the xid -phil */
        /* body->size is actually the offset -eeb */
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
        case OST_CONNECT: /* This will never get here, but for completeness. */
        case MDS_DISCONNECT:
        case OST_DISCONNECT:
               *process = 1;
               RETURN(0);

        case MDS_CLOSE:
        case MDS_GETSTATUS: /* used in unmounting */
        case OBD_PING:
        case MDS_REINT:
        case LDLM_ENQUEUE:
                *process = target_queue_recovery_request(req, obd);
                RETURN(0);

        default:
                DEBUG_REQ(D_ERROR, req, "not permitted during recovery");
                *process = 0;
                /* XXX what should we set rq_status to here? */
                req->rq_status = -EAGAIN;
                RETURN(ptlrpc_error(req));
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

void mds_steal_ack_locks(struct obd_export *exp,
                         struct ptlrpc_request *req)
{
        unsigned long  flags;

        struct ptlrpc_request *oldrep = exp->exp_outstanding_reply;
        memcpy(req->rq_ack_locks, oldrep->rq_ack_locks,
               sizeof req->rq_ack_locks);
        spin_lock_irqsave (&req->rq_lock, flags);
        oldrep->rq_resent = 1;
        wake_up(&oldrep->rq_wait_for_rep);
        spin_unlock_irqrestore (&req->rq_lock, flags);
        DEBUG_REQ(D_HA, oldrep, "stole locks from");
        DEBUG_REQ(D_HA, req, "stole locks for");
}

int mds_handle(struct ptlrpc_request *req)
{
        int should_process;
        int rc = 0;
        struct mds_obd *mds = NULL; /* quell gcc overwarning */
        struct obd_device *obd = NULL;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_MDS_ALL_REQUEST_NET | OBD_FAIL_ONCE, 0);

        LASSERT(!strcmp(req->rq_obd->obd_type->typ_name, LUSTRE_MDT_NAME));

        /* XXX identical to OST */
        if (req->rq_reqmsg->opc != MDS_CONNECT) {
                struct mds_export_data *med;
                int recovering, abort_recovery;

                if (req->rq_export == NULL) {
                        CERROR("lustre_mds: operation %d on unconnected MDS\n",
                               req->rq_reqmsg->opc);
                        req->rq_status = -ENOTCONN;
                        GOTO(out, rc = -ENOTCONN);
                }

                med = &req->rq_export->exp_mds_data;
                obd = req->rq_export->exp_obd;
                mds = &obd->u.mds;

                /* Check for aborted recovery. */
                spin_lock_bh(&obd->obd_processing_task_lock);
                abort_recovery = obd->obd_abort_recovery;
                recovering = obd->obd_recovering;
                spin_unlock_bh(&obd->obd_processing_task_lock);
                if (abort_recovery) {
                        target_abort_recovery(obd);
                } else if (recovering) {
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
                req->rq_status = rc;            /* superfluous? */
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
                lockh.cookie = 0;
                rc = mds_getattr_name(0, req, &lockh);
                if (rc == 0 && lockh.cookie)
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
                __u32 *opcp = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*opcp));
                __u32  opc;
                int size[3] = {sizeof(struct mds_body), mds->mds_max_mdsize,
                               mds->mds_max_cookiesize};
                int bufcount;

                /* NB only peek inside req now; mds_reint() will swab it */
                if (opcp == NULL) {
                        CERROR ("Can't inspect opcode\n");
                        rc = -EINVAL;
                        break;
                }
                opc = *opcp;
                if (lustre_msg_swabbed (req->rq_reqmsg))
                        __swab32s(&opc);

                DEBUG_REQ(D_INODE, req, "reint %d (%s)", opc,
                          (opc < sizeof(reint_names) / sizeof(reint_names[0]) ||
                           reint_names[opc] == NULL) ? reint_names[opc] :
                                                       "unknown opcode");

                OBD_FAIL_RETURN(OBD_FAIL_MDS_REINT_NET, 0);

                if (opc == REINT_UNLINK)
                        bufcount = 3;
                else if (opc == REINT_OPEN)
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

        case MDS_PIN:
                DEBUG_REQ(D_INODE, req, "pin");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_PIN_NET, 0);
                rc = mds_pin(req);
                break;

        case OBD_PING:
                DEBUG_REQ(D_INODE, req, "ping");
                rc = target_handle_ping(req);
                break;

        case OBD_LOG_CANCEL:
                CDEBUG(D_INODE, "log cancel\n");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOG_CANCEL_NET, 0);
                rc = -ENOTSUPP; /* la la la */
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
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req);
                RETURN(rc);
        }

        EXIT;

        /* If we're DISCONNECTing, the mds_export_data is already freed */
        if (!rc && req->rq_reqmsg->opc != MDS_DISCONNECT) {
                struct mds_export_data *med = &req->rq_export->exp_mds_data;
                struct obd_device *obd = list_entry(mds, struct obd_device,
                                                    u.mds);
                req->rq_repmsg->last_xid =
                        le64_to_cpu(med->med_mcd->mcd_last_xid);

                if (!obd->obd_no_transno) {
                        req->rq_repmsg->last_committed =
                                obd->obd_last_committed;
                } else {
                        DEBUG_REQ(D_IOCTL, req,
                                  "not sending last_committed update");
                }
                CDEBUG(D_INFO, "last_transno "LPU64", last_committed "LPU64
                       ", xid "LPU64"\n",
                       mds->mds_last_transno, obd->obd_last_committed,
                       req->rq_xid);
        }
 out:

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_LAST_REPLAY) {
                if (obd && obd->obd_recovering) {
                        DEBUG_REQ(D_HA, req, "LAST_REPLAY, queuing reply");
                        return target_queue_final_reply(req, rc);
                }
                /* Lost a race with recovery; let the error path DTRT. */
                rc = req->rq_status = -ENOTCONN;
        }

        target_send_reply(req, rc, OBD_FAIL_MDS_ALL_REPLY_NET);
        return 0;
}

/* Update the server data on disk.  This stores the new mount_count and
 * also the last_rcvd value to disk.  If we don't have a clean shutdown,
 * then the server last_rcvd value may be less than that of the clients.
 * This will alert us that we may need to do client recovery.
 *
 * Also assumes for mds_last_transno that we are not modifying it (no locking).
 */
int mds_update_server_data(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct mds_server_data *msd = mds->mds_server_data;
        struct file *filp = mds->mds_rcvd_filp;
        struct obd_run_ctxt saved;
        loff_t off = 0;
        int rc;

        push_ctxt(&saved, &mds->mds_ctxt, NULL);
        msd->msd_last_transno = cpu_to_le64(mds->mds_last_transno);
        msd->msd_mount_count = cpu_to_le64(mds->mds_mount_count);

        CDEBUG(D_SUPER, "MDS mount_count is "LPU64", last_transno is "LPU64"\n",
               mds->mds_mount_count, mds->mds_last_transno);
        rc = fsfilt_write_record(obd, filp, (char *)msd, sizeof(*msd), &off);
        if (rc != sizeof(*msd)) {
                CERROR("error writing MDS server data: rc = %d\n", rc);
                if (rc > 0)
                        rc = -EIO;
                GOTO(out, rc);
        }
        rc = file_fsync(filp, filp->f_dentry, 1);
        if (rc)
                CERROR("error flushing MDS server data: rc = %d\n", rc);

out:
        pop_ctxt(&saved, &mds->mds_ctxt, NULL);
        RETURN(rc);
}

/* mount the file system (secretly) */
static int mds_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct mds_obd *mds = &obd->u.mds;
        struct vfsmount *mnt;
        int rc = 0;
        unsigned long page;
        ENTRY;


#ifdef CONFIG_DEV_RDONLY
        dev_clear_rdonly(2);
#endif
        if (!data->ioc_inlbuf1 || !data->ioc_inlbuf2)
                RETURN(rc = -EINVAL);

        if (data->ioc_inlbuf4)
                obd_str2uuid(&mds->mds_osc_uuid, data->ioc_inlbuf4);

        obd->obd_fsops = fsfilt_get_ops(data->ioc_inlbuf2);
        if (IS_ERR(obd->obd_fsops))
                RETURN(rc = PTR_ERR(obd->obd_fsops));


        if (data->ioc_inllen3 > 0 && data->ioc_inlbuf3) {
                if (*data->ioc_inlbuf3 == '/') {
                        CERROR("mds namespace mount: %s\n", 
                               data->ioc_inlbuf3);
//                        mds->mds_nspath = strdup(ioc->inlbuf4);
                } else {
                        CERROR("namespace mount must be absolute path: '%s'\n",
                               data->ioc_inlbuf3);
                }
        }

	if (!(page = __get_free_page(GFP_KERNEL)))
		return -ENOMEM;

        memset((void *)page, 0, PAGE_SIZE);
        sprintf((char *)page, "iopen_nopriv");

        mnt = do_kern_mount(data->ioc_inlbuf2, 0,
                            data->ioc_inlbuf1, (void *)page);
        free_page(page);
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
        mds->mds_max_cookiesize = sizeof(struct llog_cookie);
        rc = mds_fs_setup(obd, mnt);
        if (rc) {
                CERROR("MDS filesystem method init failed: rc = %d\n", rc);
                GOTO(err_put, rc);
        }

#ifdef ENABLE_ORPHANS
        rc = llog_start_commit_thread();
        if (rc < 0)
                GOTO(err_fs, rc);
#endif

#ifdef ENABLE_ORPHANS
        mds->mds_catalog = mds_get_catalog(obd);
        if (IS_ERR(mds->mds_catalog))
                GOTO(err_fs, rc = PTR_ERR(mds->mds_catalog));
#endif

        obd->obd_namespace = ldlm_namespace_new("mds_server",
                                                LDLM_NAMESPACE_SERVER);
        if (obd->obd_namespace == NULL) {
                mds_cleanup(obd, 0);
                GOTO(err_log, rc = -ENOMEM);
        }

        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "mds_ldlm_client", &obd->obd_ldlm_client);

        mds->mds_has_lov_desc = 0;
        obd->obd_replayable = 1;

        RETURN(0);

err_log:
#ifdef ENABLE_ORPHANS
        mds_put_catalog(mds->mds_catalog);
        /* No extra cleanup needed for llog_init_commit_thread() */
err_fs:
#endif
        mds_fs_cleanup(obd, 0);
err_put:
        unlock_kernel();
        mntput(mds->mds_vfsmnt);
        mds->mds_sb = 0;
        lock_kernel();
err_ops:
        fsfilt_put_ops(obd->obd_fsops);
        return rc;
}

static int mds_cleanup(struct obd_device *obd, int flags)
{
        struct mds_obd *mds = &obd->u.mds;
        ENTRY;

        if (mds->mds_sb == NULL)
                RETURN(0);

#ifdef ENABLE_ORPHANS
        mds_put_catalog(mds->mds_catalog);
#endif
        if (mds->mds_osc_obd)
                obd_disconnect(&mds->mds_osc_conn, flags);
        mds_update_server_data(obd);
        mds_fs_cleanup(obd, flags);

        unlock_kernel();

        /* 2 seems normal on mds, (may_umount() also expects 2
          fwiw), but we only see 1 at this point in obdfilter. */
        if (atomic_read(&obd->u.mds.mds_vfsmnt->mnt_count) > 2)
                CERROR("%s: mount point busy, mnt_count: %d\n", obd->obd_name,
                       atomic_read(&obd->u.mds.mds_vfsmnt->mnt_count));

        mntput(mds->mds_vfsmnt);
        mds->mds_sb = 0;

        ldlm_namespace_free(obd->obd_namespace);

        if (obd->obd_recovering)
                target_cancel_recovery_timer(obd);
        lock_kernel();
#ifdef CONFIG_DEV_RDONLY
        dev_clear_rdonly(2);
#endif
        fsfilt_put_ops(obd->obd_fsops);

        RETURN(0);
}

static void fixup_handle_for_resent_req(struct ptlrpc_request *req,
                                        struct ldlm_lock *new_lock,
                                        struct lustre_handle *lockh)
{
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
        struct ldlm_request *dlmreq =
                lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*dlmreq));
        struct lustre_handle remote_hdl = dlmreq->lock_handle1;
        struct list_head *iter;

        if (!(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT))
                return;

        l_lock(&obd->obd_namespace->ns_lock);
        list_for_each(iter, &exp->exp_ldlm_data.led_held_locks) {
                struct ldlm_lock *lock;
                lock = list_entry(iter, struct ldlm_lock, l_export_chain);
                if (lock == new_lock)
                        continue;
                if (lock->l_remote_handle.cookie == remote_hdl.cookie) {
                        lockh->cookie = lock->l_handle.h_cookie;
                        DEBUG_REQ(D_HA, req, "restoring lock cookie "LPX64,
                                  lockh->cookie);
                        l_unlock(&obd->obd_namespace->ns_lock);
                        return;
                }

        }
        l_unlock(&obd->obd_namespace->ns_lock);
        DEBUG_REQ(D_HA, req, "no existing lock with rhandle "LPX64,
                  remote_hdl.cookie);
}

int intent_disposition(struct ldlm_reply *rep, int flag)
{
        if (!rep)
                return 0;
        return (rep->lock_policy_res1 & flag);
}

void intent_set_disposition(struct ldlm_reply *rep, int flag)
{
        if (!rep)
                return;
        rep->lock_policy_res1 |= flag;
}

static int ldlm_intent_policy(struct ldlm_namespace *ns,
                              struct ldlm_lock **lockp, void *req_cookie,
                              ldlm_mode_t mode, int flags, void *data)
{
        struct ptlrpc_request *req = req_cookie;
        struct ldlm_lock *lock = *lockp;
        ENTRY;

        if (!req_cookie)
                RETURN(0);

        if (req->rq_reqmsg->bufcount > 1) {
                /* an intent needs to be considered */
                struct ldlm_intent *it;
                struct mds_obd *mds = &req->rq_export->exp_obd->u.mds;
                struct ldlm_reply *rep;
                struct lustre_handle lockh;
                struct ldlm_lock *new_lock;
                int offset = 2, repsize[4] = {sizeof(struct ldlm_reply),
                                              sizeof(struct mds_body),
                                              mds->mds_max_mdsize,
                                              mds->mds_max_cookiesize};

                it = lustre_swab_reqbuf(req, 1, sizeof (*it),
                                        lustre_swab_ldlm_intent);
                if (it == NULL) {
                        CERROR ("Intent missing\n");
                        req->rq_status = -EFAULT;
                        RETURN(req->rq_status);
                }

                LDLM_DEBUG(lock, "intent policy, opc: %s",
                           ldlm_it2str(it->opc));

                req->rq_status = lustre_pack_msg(it->opc == IT_UNLINK ? 4 : 3,
                                                 repsize, NULL, &req->rq_replen,
                                                 &req->rq_repmsg);
                if (req->rq_status)
                        RETURN(req->rq_status);

                rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*rep));
                intent_set_disposition(rep, DISP_IT_EXECD);

                fixup_handle_for_resent_req(req, lock, &lockh);

                /* execute policy */
                switch ((long)it->opc) {
                case IT_OPEN:
                case IT_CREAT|IT_OPEN:
                        /* XXX swab here to assert that an mds_open reint
                         * packet is following */
                        rep->lock_policy_res2 = mds_reint(req, offset, &lockh);
                        /* We abort the lock if the lookup was negative and
                         * we did not make it to the OPEN portion */
                        if (intent_disposition(rep, DISP_LOOKUP_NEG) &&
                            !intent_disposition(rep, DISP_OPEN_OPEN))
                                RETURN(ELDLM_LOCK_ABORTED);
                        break;
                case IT_GETATTR:
                case IT_LOOKUP:
                case IT_READDIR:
                        rep->lock_policy_res2 = mds_getattr_name(offset, req,
                                                                 &lockh);
                        /* FIXME: we need to sit down and decide on who should
                         * set req->rq_status, who should return negative and
                         * positive return values, and what they all mean. 
                         * - replay: returns 0 & req->status is old status
                         * - otherwise: returns req->status */
                        if (!intent_disposition(rep, DISP_LOOKUP_POS) || 
                            rep->lock_policy_res2)
                                RETURN(ELDLM_LOCK_ABORTED);
                        if (req->rq_status != 0) {
                                rep->lock_policy_res2 = req->rq_status;
                                RETURN(ELDLM_LOCK_ABORTED);
                        }
                        break;
                default:
                        CERROR("Unhandled intent "LPD64"\n", it->opc);
                        LBUG();
                }

                /* By this point, whatever function we called above must have
                 * either filled in 'lockh', been an intent replay, or returned
                 * an error.  We want to allow replayed RPCs to not get a lock,
                 * since we would just drop it below anyways because lock replay
                 * is done separately by the client afterwards.  For regular
                 * RPCs we want to give the new lock to the client instead of
                 * whatever lock it was about to get.
                 */
                new_lock = ldlm_handle2lock(&lockh);
                if (flags & LDLM_FL_INTENT_ONLY && !new_lock)
                        RETURN(ELDLM_LOCK_ABORTED);

                LASSERT(new_lock != NULL);

                /* If we've already given this lock to a client once, then we
                 * should have no readers or writers.  Otherwise, we should
                 * have one reader _or_ writer ref (which will be zeroed below
                 * before returning the lock to a client.
                 */
                if (new_lock->l_export == req->rq_export)
                        LASSERT(new_lock->l_readers + new_lock->l_writers == 0);
                else
                        LASSERT(new_lock->l_readers + new_lock->l_writers == 1);

                /* If we're running an intent only, we want to abort the new
                 * lock, and let the client abort the original lock. */
                if (flags & LDLM_FL_INTENT_ONLY) {
                        LDLM_DEBUG(lock, "INTENT_ONLY, aborting locks");
                        l_lock(&new_lock->l_resource->lr_namespace->ns_lock);
                        if (new_lock->l_readers)
                                ldlm_lock_decref(&lockh, LCK_PR);
                        else
                                ldlm_lock_decref(&lockh, LCK_PW);
                        l_unlock(&new_lock->l_resource->lr_namespace->ns_lock);
                        LDLM_LOCK_PUT(new_lock);
                        RETURN(ELDLM_LOCK_ABORTED);
                }

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
                if (lustre_pack_msg(1, &size, NULL, &req->rq_replen,
                                    &req->rq_repmsg)) {
                        LBUG();
                        RETURN(-ENOMEM);
                }
        }
        RETURN(0);
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
                                           mds_handle, "mds", obddev);

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
                                mds_handle, "mds_setattr", obddev);
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
                                mds_handle, "mds_readpage", obddev);
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


static int mdt_cleanup(struct obd_device *obddev, int flags)
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
        o_statfs:      mds_obd_statfs,
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

        lprocfs_init_multi_vars(0, &lvars);
        class_register_type(&mds_obd_ops, lvars.module_vars, LUSTRE_MDS_NAME);
        lprocfs_init_multi_vars(1, &lvars);
        class_register_type(&mdt_obd_ops, lvars.module_vars, LUSTRE_MDT_NAME);
        ldlm_register_intent(ldlm_intent_policy);

        return 0;
}

static void /*__exit*/ mds_exit(void)
{
        ldlm_unregister_intent();
        class_unregister_type(LUSTRE_MDS_NAME);
        class_unregister_type(LUSTRE_MDT_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Metadata Server (MDS)");
MODULE_LICENSE("GPL");

module_init(mds_init);
module_exit(mds_exit);
