/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mds/handler.c
 *  Lustre Metadata Server (mds) request handler
 *
 *  Copyright (c) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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
#include <linux/locks.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <linux/buffer_head.h>
#endif
#include <linux/obd_lov.h>
#include <linux/lprocfs_status.h>

static kmem_cache_t *mds_file_cache;

extern int mds_get_lovtgts(struct mds_obd *obd, int tgt_count,
                           obd_uuid_t *uuidarray);
extern int mds_get_lovdesc(struct mds_obd  *obd, struct lov_desc *desc);
extern int mds_update_last_rcvd(struct mds_obd *mds, void *handle,
                                struct ptlrpc_request *req);
static int mds_cleanup(struct obd_device * obddev);

extern struct lprocfs_vars status_var_nm_1[];
extern struct lprocfs_vars status_class_var[];

inline struct mds_obd *mds_req2mds(struct ptlrpc_request *req)
{
        return &req->rq_export->exp_obd->u.mds;
}

static int mds_bulk_timeout(void *data)
{
        struct ptlrpc_bulk_desc *desc = data;

        ENTRY;
        CERROR("(not yet) starting recovery of client %p\n", desc->bd_client);
        RETURN(1);
}

/* Assumes caller has already pushed into the kernel filesystem context */
static int mds_sendpage(struct ptlrpc_request *req, struct file *file,
                        __u64 offset)
{
        int rc = 0;
        struct mds_obd *mds = mds_req2mds(req);
        struct ptlrpc_bulk_desc *desc;
        struct ptlrpc_bulk_page *bulk;
        struct l_wait_info lwi;
        char *buf;
        ENTRY;

        desc = ptlrpc_prep_bulk(req->rq_connection);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);

        bulk = ptlrpc_prep_bulk_page(desc);
        if (bulk == NULL)
                GOTO(cleanup_bulk, rc = -ENOMEM);

        OBD_ALLOC(buf, PAGE_SIZE);
        if (buf == NULL)
                GOTO(cleanup_bulk, rc = -ENOMEM);

        rc = mds_fs_readpage(mds, file, buf, PAGE_SIZE, (loff_t *)&offset);

        if (rc != PAGE_SIZE)
                GOTO(cleanup_buf, rc = -EIO);

        bulk->bp_xid = req->rq_xid;
        bulk->bp_buf = buf;
        bulk->bp_buflen = PAGE_SIZE;
        desc->bd_portal = MDS_BULK_PORTAL;

        rc = ptlrpc_send_bulk(desc);
        if (rc)
                GOTO(cleanup_buf, rc);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SENDPAGE)) {
                CERROR("obd_fail_loc=%x, fail operation rc=%d\n",
                       OBD_FAIL_MDS_SENDPAGE, rc);
                ptlrpc_abort_bulk(desc);
                GOTO(cleanup_buf, rc);
        }

        lwi = LWI_TIMEOUT(obd_timeout * HZ, mds_bulk_timeout, desc);
        rc = l_wait_event(desc->bd_waitq, desc->bd_flags & PTL_BULK_FL_SENT, &lwi);
        if (rc) {
                if (rc != -ETIMEDOUT)
                        LBUG();
                GOTO(cleanup_buf, rc);
        }

        EXIT;
 cleanup_buf:
        OBD_FREE(buf, PAGE_SIZE);
 cleanup_bulk:
        ptlrpc_free_bulk(desc);
 out:
        return rc;
}

/*
 * Look up a named entry in a directory, and get an LDLM lock on it.
 * 'dir' is a inode for which an LDLM lock has already been taken.
 *
 * If we do not need an exclusive or write lock on this entry (e.g.
 * a read lock for attribute lookup only) then we do not hold the
 * directory on return.  It is up to the caller to know what type
 * of lock it is getting, and clean up appropriately.
 */
struct dentry *mds_name2locked_dentry(struct obd_device *obd,
                                      struct dentry *dir, struct vfsmount **mnt,
                                      char *name, int namelen, int lock_mode,
                                      struct lustre_handle *lockh,
                                      int dir_lock_mode)
{
        struct dentry *dchild;
        int flags = 0, rc;
        __u64 res_id[3] = {0};
        ENTRY;

        down(&dir->d_inode->i_sem);
        dchild = lookup_one_len(name, dir, namelen);
        if (IS_ERR(dchild)) {
                CERROR("child lookup error %ld\n", PTR_ERR(dchild));
                up(&dir->d_inode->i_sem);
                LBUG();
                RETURN(dchild);
        }
        if (dir_lock_mode != LCK_EX && dir_lock_mode != LCK_PW) {
                up(&dir->d_inode->i_sem);
                ldlm_lock_decref(lockh, dir_lock_mode);
        }

        if (lock_mode == 0 || !dchild->d_inode)
                RETURN(dchild);

        res_id[0] = dchild->d_inode->i_ino;
        res_id[1] = dchild->d_inode->i_generation;
        rc = ldlm_match_or_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                                   res_id, LDLM_PLAIN, NULL, 0, lock_mode,
                                   &flags, ldlm_completion_ast,
                                   mds_blocking_ast, NULL, 0, lockh);
        if (rc != ELDLM_OK) {
                l_dput(dchild);
                up(&dir->d_inode->i_sem);
                RETURN(ERR_PTR(-ENOLCK)); /* XXX translate ldlm code */
        }

        RETURN(dchild);
}

struct dentry *mds_fid2locked_dentry(struct obd_device *obd, struct ll_fid *fid,
                                     struct vfsmount **mnt, int lock_mode,
                                     struct lustre_handle *lockh)
{
        struct mds_obd *mds = &obd->u.mds;
        struct dentry *de = mds_fid2dentry(mds, fid, mnt), *retval = de;
        int flags = 0, rc;
        __u64 res_id[3] = {0};
        ENTRY;

        if (IS_ERR(de))
                RETURN(de);

        res_id[0] = de->d_inode->i_ino;
        res_id[1] = de->d_inode->i_generation;
        rc = ldlm_match_or_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                                   res_id, LDLM_PLAIN, NULL, 0, lock_mode,
                                   &flags, ldlm_completion_ast,
                                   mds_blocking_ast, NULL, 0, lockh);
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
                LBUG();
                iput(inode);
                RETURN(ERR_PTR(-ESTALE));
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
                       obd_uuid_t cluuid, struct recovd_obd *recovd,
                       ptlrpc_recovery_cb_t recover)
{
        struct obd_export *exp;
        struct mds_export_data *med;
        struct mds_client_data *mcd;
        struct list_head *p;
        int rc;
        ENTRY;

        if (!conn || !obd || !cluuid)
                RETURN(-EINVAL);

        MOD_INC_USE_COUNT;

        spin_lock(&obd->obd_dev_lock);
        list_for_each(p, &obd->obd_exports) {
                exp = list_entry(p, struct obd_export, exp_obd_chain);
                mcd = exp->exp_mds_data.med_mcd;
                if (!mcd) {
                        CERROR("FYI: NULL mcd - simultaneous connects\n");
                        continue;
                }
                if (!memcmp(cluuid, mcd->mcd_uuid, sizeof(mcd->mcd_uuid))) {
                        LASSERT(exp->exp_obd == obd);

                        if (!list_empty(&exp->exp_conn_chain)) {
                                CERROR("existing uuid/export, list not empty!\n");
                                spin_unlock(&obd->obd_dev_lock);
                                MOD_DEC_USE_COUNT;
                                RETURN(-EALREADY);
                        }
                        conn->addr = (__u64) (unsigned long)exp;
                        conn->cookie = exp->exp_cookie;
                        spin_unlock(&obd->obd_dev_lock);
                        CDEBUG(D_INFO, "existing export for UUID '%s' at %p\n",
                               cluuid, exp);
                        CDEBUG(D_IOCTL,"connect: addr %Lx cookie %Lx\n",
                               (long long)conn->addr, (long long)conn->cookie);
                        MOD_DEC_USE_COUNT;
                        RETURN(0);
                }
        }
        spin_unlock(&obd->obd_dev_lock);
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
                GOTO(out_dec, rc);
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

        rc = mds_client_add(med, -1);
        if (rc)
                GOTO(out_mcd, rc);

        RETURN(0);

out_mcd:
        OBD_FREE(mcd, sizeof(*mcd));
out_export:
        class_disconnect(conn);
out_dec:
        MOD_DEC_USE_COUNT;

        return rc;
}

/* Call with med->med_open_lock held, please. */
inline int mds_close_mfd(struct mds_file_data *mfd, struct mds_export_data *med)
{
        struct file *file = mfd->mfd_file;
        LASSERT(file->private_data == mfd);

        list_del(&mfd->mfd_list);
        mfd->mfd_servercookie = DEAD_HANDLE_MAGIC;
        kmem_cache_free(mds_file_cache, mfd);

        return filp_close(file, 0);
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
                rc = mds_close_mfd(mfd, med);
                if (rc) {
                        /* XXX better diagnostics, with file path and stuff */
                        CDEBUG(D_INODE, "Error %d closing mfd %p\n", rc, mfd);
                }
        }
        spin_unlock(&med->med_open_lock);

        ldlm_cancel_locks_for_export(export);
        mds_client_free(export);

        rc = class_disconnect(conn);
        if (!rc)
                MOD_DEC_USE_COUNT;

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
                RETURN(0);
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
                RETURN(0);
        }

        desc = lustre_msg_buf(req->rq_repmsg, 0);
        rc = mds_get_lovdesc(mds, desc);
        if (rc) {
                CERROR("mds_get_lovdesc error %d", rc);
                req->rq_status = rc;
                RETURN(0);
        }

        tgt_count = le32_to_cpu(desc->ld_tgt_count);
        if (tgt_count * sizeof(obd_uuid_t) > streq->repbuf) {
                CERROR("too many targets, enlarge client buffers\n");
                req->rq_status = -ENOSPC;
                RETURN(0);
        }

        /* XXX the MDS should not really know about this */
        mds->mds_max_mdsize = lov_mds_md_size(tgt_count);
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
                     void *data, __u32 data_len, int flag)
{
        int do_ast;
        ENTRY;

        if (flag == LDLM_CB_CANCELING) {
                /* Don't need to do anything here. */
                RETURN(0);
        }

        /* XXX layering violation!  -phil */
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
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
        } else
                LDLM_DEBUG(lock, "Lock still has references, will be"
                           "cancelled later");
        RETURN(0);
}

int mds_pack_md(struct mds_obd *mds, struct ptlrpc_request *req,
                int offset, struct mds_body *body, struct inode *inode)
{
        struct lov_mds_md *lmm;
        int lmm_size = req->rq_repmsg->buflens[offset];
        int rc;

        if (lmm_size == 0) {
                CERROR("no space reserved for inode %u MD\n", inode->i_ino);
                RETURN(0);
        }

        lmm = lustre_msg_buf(req->rq_repmsg, offset);

        /* I don't really like this, but it is a sanity check on the client
         * MD request.  However, if the client doesn't know how much space
         * to reserve for the MD, this shouldn't be fatal either...
         */
        if (lmm_size > mds->mds_max_mdsize) {
                CERROR("Reading MD for inode %u of %d bytes > max %d\n",
                       inode->i_ino, lmm_size, mds->mds_max_mdsize);
                // RETURN(-EINVAL);
        }

        /* We don't need to store the reply size, because this buffer is
         * discarded right after unpacking, and the LOV can figure out the
         * size itself from the ost count.
         */
        if ((rc = mds_fs_get_md(mds, inode, lmm, lmm_size)) < 0) {
                CDEBUG(D_INFO, "No md for ino %u: rc = %d\n", inode->i_ino, rc);
        } else {
                body->valid |= OBD_MD_FLEASIZE;
                rc = 0;
        }

        return rc;
}

static int mds_getattr_internal(struct mds_obd *mds, struct dentry *dentry,
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

        if (S_ISREG(inode->i_mode)) {
                rc = mds_pack_md(mds, req, reply_off + 1, body, inode);
        } else if (S_ISLNK(inode->i_mode) && reqbody->valid & OBD_MD_LINKNAME) {
                char *symname = lustre_msg_buf(req->rq_repmsg, reply_off + 1);
                int len = req->rq_repmsg->buflens[reply_off + 1];

                rc = inode->i_op->readlink(dentry, symname, len);
                if (rc < 0) {
                        CERROR("readlink failed: %d\n", rc);
                } else {
                        CDEBUG(D_INODE, "read symlink dest %s\n", symname);
                        body->valid |= OBD_MD_LINKNAME;
                }
        }
        RETURN(rc);
}

static int mds_getattr_name(int offset, struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct obd_run_ctxt saved;
        struct mds_body *body;
        struct dentry *de = NULL, *dchild = NULL;
        struct inode *dir;
        struct lustre_handle lockh;
        char *name;
        int namelen, flags = 0, lock_mode, rc = 0;
        struct obd_ucred uc;
        __u64 res_id[3] = {0, 0, 0};
        ENTRY;

        LASSERT(!strcmp(req->rq_export->exp_obd->obd_type->typ_name, "mds"));

        if (req->rq_reqmsg->bufcount <= offset + 1) {
                LBUG();
                GOTO(out_pre_de, rc = -EINVAL);
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
        push_ctxt(&saved, &mds->mds_ctxt, &uc);
        de = mds_fid2dentry(mds, &body->fid1, NULL);
        if (IS_ERR(de)) {
                LBUG();
                GOTO(out_pre_de, rc = -ESTALE);
        }

        dir = de->d_inode;
        CDEBUG(D_INODE, "parent ino %ld, name %*s\n", dir->i_ino,namelen,name);

        lock_mode = LCK_PR;
        res_id[0] = dir->i_ino;
        res_id[1] = dir->i_generation;

        rc = ldlm_lock_match(obd->obd_namespace, res_id, LDLM_PLAIN,
                             NULL, 0, lock_mode, &lockh);
        if (rc == 0) {
                LDLM_DEBUG_NOLOCK("enqueue res "LPU64, res_id[0]);
                rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                                      res_id, LDLM_PLAIN, NULL, 0, lock_mode,
                                      &flags, ldlm_completion_ast,
                                      mds_blocking_ast, NULL, 0, &lockh);
                if (rc != ELDLM_OK) {
                        CERROR("lock enqueue: err: %d\n", rc);
                        GOTO(out_create_de, rc = -EIO);
                }
        }
        ldlm_lock_dump((void *)(unsigned long)lockh.addr);

        down(&dir->i_sem);
        dchild = lookup_one_len(name, de, namelen - 1);
        if (IS_ERR(dchild)) {
                CDEBUG(D_INODE, "child lookup error %ld\n", PTR_ERR(dchild));
                up(&dir->i_sem);
                GOTO(out_create_dchild, rc = PTR_ERR(dchild));
        }

        rc = mds_getattr_internal(mds, dchild, req, body, offset);

        EXIT;
out_create_dchild:
        l_dput(dchild);
        up(&dir->i_sem);
        ldlm_lock_decref(&lockh, lock_mode);
out_create_de:
        l_dput(de);
out_pre_de:
        req->rq_status = rc;
        pop_ctxt(&saved);
        return 0;
}

static int mds_getattr(int offset, struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_run_ctxt saved;
        struct dentry *de;
        struct inode *inode;
        struct mds_body *body;
        struct obd_ucred uc;
        int rc = 0, size[2] = {sizeof(*body)}, bufcount = 1;
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

        inode = de->d_inode;
        if (S_ISREG(body->fid1.f_type)) {
                int rc = mds_fs_get_md(mds, inode, NULL, 0);
                CDEBUG(D_INODE, "got %d bytes MD data for inode %u\n",
                       rc, inode->i_ino);
                if (rc < 0) {
                        if (rc != -ENODATA)
                                CERROR("error getting inode %u MD: rc = %d\n",
                                       inode->i_ino, rc);
                        size[bufcount] = 0;
                } else if (rc < mds->mds_max_mdsize) {
                        size[bufcount] = 0;
                        CERROR("MD size %d larger than maximum possible %u\n",
                               rc, mds->mds_max_mdsize);
                } else
                        size[bufcount] = rc;
                bufcount++;
        } else if (body->valid & OBD_MD_LINKNAME) {
                size[bufcount] = MIN(inode->i_size + 1, body->size);
                bufcount++;
                CDEBUG(D_INODE, "symlink size: %d, reply space: %d\n",
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

        req->rq_status = mds_getattr_internal(mds, de, req, body, 0);

out:
        l_dput(de);
out_pop:
        pop_ctxt(&saved);
        RETURN(rc);
}

static int mds_statfs(struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_statfs *osfs;
        struct statfs sfs;
        int rc, size = sizeof(*osfs);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_STATFS_PACK)) {
                CERROR("mds: statfs lustre_pack_msg failed: rc = %d\n", rc);
                GOTO(out, rc);
        }

        rc = mds_fs_statfs(mds, &sfs);
        if (rc) {
                CERROR("mds: statfs failed: rc %d\n", rc);
                GOTO(out, rc);
        }
        osfs = lustre_msg_buf(req->rq_repmsg, 0);
        memset(osfs, 0, size);
        statfs_pack(osfs, &sfs);
        obd_statfs_pack(osfs, osfs);

out:
        req->rq_status = rc;
        RETURN(0);
}

static struct mds_file_data *mds_handle2mfd(struct lustre_handle *handle)
{
        struct mds_file_data *mfd = NULL;

        if (!handle || !handle->addr)
                RETURN(NULL);

        mfd = (struct mds_file_data *)(unsigned long)(handle->addr);
        if (!kmem_cache_validate(mds_file_cache, mfd))
                RETURN(NULL);

        if (mfd->mfd_servercookie != handle->cookie)
                RETURN(NULL);

        return mfd;
}

static int mds_store_md(struct mds_obd *mds, struct ptlrpc_request *req,
                        int offset, struct mds_body *body, struct inode *inode)
{
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
                CERROR("Saving MD for inode %u of %d bytes > max %d\n",
                       inode->i_ino, lmm_size, mds->mds_max_mdsize);
                //RETURN(-EINVAL);
        }

        CDEBUG(D_INODE, "storing %d bytes MD for inode %u\n",
               lmm_size, inode->i_ino);
        uc.ouc_fsuid = body->fsuid;
        uc.ouc_fsgid = body->fsgid;
        uc.ouc_cap = body->capability;
        push_ctxt(&saved, &mds->mds_ctxt, &uc);
        handle = mds_fs_start(mds, inode, MDS_FSOP_SETATTR);
        if (!handle)
                GOTO(out_ea, rc = -ENOMEM);

        rc = mds_fs_set_md(mds, inode, handle, lmm, lmm_size);
        if (!rc)
                rc = mds_update_last_rcvd(mds, handle, req);

        rc2 = mds_fs_commit(mds, inode, handle);
        if (rc2 && !rc)
                rc = rc2;
out_ea:
        pop_ctxt(&saved);

        RETURN(rc);
}

static int mds_open(struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_body *body;
        struct mds_export_data *med;
        struct mds_file_data *mfd;
        struct dentry *de;
        struct file *file;
        struct vfsmount *mnt;
        __u32 flags;
        struct list_head *tmp;
        int rc, size = sizeof(*body);
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OPEN_PACK)) {
                CERROR("test case OBD_FAIL_MDS_OPEN_PACK\n");
                req->rq_status = -ENOMEM;
                RETURN(-ENOMEM);
        }

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc) {
                CERROR("mds: pack error: rc = %d\n", rc);
                req->rq_status = rc;
                RETURN(rc);
        }

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        /* was this animal open already and the client lost the reply? */
        /* XXX need some way to detect a reopen, to avoid locked list walks */
        med = &req->rq_export->exp_mds_data;
        spin_lock(&med->med_open_lock);
        list_for_each(tmp, &med->med_open_head) {
                mfd = list_entry(tmp, typeof(*mfd), mfd_list);
                if (!memcmp(&mfd->mfd_clienthandle, &body->handle,
                            sizeof(mfd->mfd_clienthandle)) &&
                    body->fid1.id == mfd->mfd_file->f_dentry->d_inode->i_ino) {
                        de = mfd->mfd_file->f_dentry;
                        spin_unlock(&med->med_open_lock);
                        CERROR("Re opening "LPD64"\n", body->fid1.id);
                        GOTO(out_pack, rc = 0);
                }
        }
        spin_unlock(&med->med_open_lock);

        mfd = kmem_cache_alloc(mds_file_cache, GFP_KERNEL);
        if (!mfd) {
                CERROR("mds: out of memory\n");
                req->rq_status = -ENOMEM;
                RETURN(0);
        }

        de = mds_fid2dentry(mds, &body->fid1, &mnt);
        if (IS_ERR(de))
                GOTO(out_free, rc = PTR_ERR(de));

        /* check if this inode has seen a delayed object creation */
        if (lustre_msg_get_op_flags(req->rq_reqmsg) & MDS_OPEN_HAS_EA) {
                rc = mds_store_md(mds, req, 1, body, de->d_inode);
                if (rc) {
                        l_dput(de);
                        mntput(mnt);
                        GOTO(out_free, rc);
                }
        }

        flags = body->flags;
        /* dentry_open does a dput(de) and mntput(mnt) on error */
        file = dentry_open(de, mnt, flags & ~O_DIRECT);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                GOTO(out_free, 0);
        }

        file->private_data = mfd;
        mfd->mfd_file = file;
        memcpy(&mfd->mfd_clienthandle, &body->handle, sizeof(body->handle));
        get_random_bytes(&mfd->mfd_servercookie, sizeof(mfd->mfd_servercookie));
        spin_lock(&med->med_open_lock);
        list_add(&mfd->mfd_list, &med->med_open_head);
        spin_unlock(&med->med_open_lock);

out_pack:
        body = lustre_msg_buf(req->rq_repmsg, 0);
        mds_pack_inode2fid(&body->fid1, de->d_inode);
        mds_pack_inode2body(body, de->d_inode);
        body->handle.addr = (__u64)(unsigned long)mfd;
        body->handle.cookie = mfd->mfd_servercookie;
        CDEBUG(D_INODE, "llite file "LPX64": addr %p, cookie "LPX64"\n",
               mfd->mfd_clienthandle.addr, mfd, mfd->mfd_servercookie);
        RETURN(0);

out_free:
        mfd->mfd_servercookie = DEAD_HANDLE_MAGIC;
        kmem_cache_free(mds_file_cache, mfd);
        req->rq_status = rc;
        RETURN(0);
}

static int mds_close(struct ptlrpc_request *req)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_body *body;
        struct mds_file_data *mfd;
        int rc;
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        mfd = mds_handle2mfd(&body->handle);
        if (!mfd) {
                CERROR("no handle for file close "LPD64
                       ": addr "LPX64", cookie "LPX64"\n",
                       body->fid1.id, body->handle.addr, body->handle.cookie);
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

        CDEBUG(D_INODE, "ino %ld\n", de->d_inode->i_ino);

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
        /* note: in case of an error, dentry_open puts dentry */
        rc = mds_sendpage(req, file, body->size);

        filp_close(file, 0);
out_pop:
        pop_ctxt(&saved);
out:
        req->rq_status = rc;
        RETURN(0);
}

int mds_reint(struct ptlrpc_request *req, int offset)
{
        int rc;
        struct mds_update_record rec;

        rc = mds_update_unpack(req, offset, &rec);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNPACK)) {
                CERROR("invalid record\n");
                req->rq_status = -EINVAL;
                RETURN(0);
        }
        /* rc will be used to interrupt a for loop over multiple records */
        rc = mds_reint_rec(&rec, offset, req);
        return rc;
}

int mds_handle(struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        rc = lustre_unpack_msg(req->rq_reqmsg, req->rq_reqlen);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_HANDLE_UNPACK)) {
                CERROR("lustre_mds: Invalid request\n");
                GOTO(out, rc);
        }

        if (req->rq_reqmsg->opc != MDS_CONNECT && req->rq_export == NULL)
                GOTO(out, rc = -ENOTCONN);

        LASSERT(!strcmp(req->rq_obd->obd_type->typ_name, LUSTRE_MDT_NAME));

        switch (req->rq_reqmsg->opc) {
        case MDS_CONNECT:
                CDEBUG(D_INODE, "connect\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_CONNECT_NET, 0);
                rc = target_handle_connect(req);
                break;

        case MDS_DISCONNECT:
                CDEBUG(D_INODE, "disconnect\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_DISCONNECT_NET, 0);
                rc = target_handle_disconnect(req);
                goto out;

        case MDS_GETSTATUS:
                CDEBUG(D_INODE, "getstatus\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_GETSTATUS_NET, 0);
                rc = mds_getstatus(req);
                break;

        case MDS_GETLOVINFO:
                CDEBUG(D_INODE, "getlovinfo\n");
                rc = mds_getlovinfo(req);
                break;

        case MDS_GETATTR:
                CDEBUG(D_INODE, "getattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_GETATTR_NET, 0);
                rc = mds_getattr(0, req);
                break;

        case MDS_STATFS:
                CDEBUG(D_INODE, "statfs\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_STATFS_NET, 0);
                rc = mds_statfs(req);
                break;

        case MDS_READPAGE:
                CDEBUG(D_INODE, "readpage\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_READPAGE_NET, 0);
                rc = mds_readpage(req);

                if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SENDPAGE))
                        return 0;
                break;

        case MDS_REINT: {
                int size = sizeof(struct mds_body);
                CDEBUG(D_INODE, "reint\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_REINT_NET, 0);

                rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen,
                                     &req->rq_repmsg);
                if (rc) {
                        req->rq_status = rc;
                        break;
                }
                rc = mds_reint(req, 0);
                OBD_FAIL_RETURN(OBD_FAIL_MDS_REINT_NET_REP, 0);
                break;
                }

        case MDS_OPEN:
                CDEBUG(D_INODE, "open\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_OPEN_NET, 0);
                rc = mds_open(req);
                break;

        case MDS_CLOSE:
                CDEBUG(D_INODE, "close\n");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_CLOSE_NET, 0);
                rc = mds_close(req);
                break;

        case LDLM_ENQUEUE:
                CDEBUG(D_INODE, "enqueue\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_ENQUEUE, 0);
                rc = ldlm_handle_enqueue(req);
                break;
        case LDLM_CONVERT:
                CDEBUG(D_INODE, "convert\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CONVERT, 0);
                rc = ldlm_handle_convert(req);
                break;
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                CDEBUG(D_INODE, "callback\n");
                CERROR("callbacks should not happen on MDS\n");
                LBUG();
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_BL_CALLBACK, 0);
                break;
        default:
                rc = ptlrpc_error(req->rq_svc, req);
                RETURN(rc);
        }

        EXIT;

        if (!rc) {
                struct mds_export_data *med = &req->rq_export->exp_mds_data;
                struct mds_obd *mds = mds_req2mds(req);

                req->rq_repmsg->last_xid =
                        HTON__u64(le64_to_cpu(med->med_mcd->mcd_last_xid));
                req->rq_repmsg->last_committed =
                        HTON__u64(mds->mds_last_committed);
                CDEBUG(D_INFO, "last_rcvd ~%Lu, last_committed %Lu, xid %d\n",
                       (unsigned long long)mds->mds_last_rcvd,
                       (unsigned long long)mds->mds_last_committed,
                       cpu_to_le32(req->rq_xid));
        }
 out:
        if (rc) {
                CERROR("mds: processing error (opcode %d): %d\n",
                       req->rq_reqmsg->opc, rc);
                ptlrpc_error(req->rq_svc, req);
        } else {
                CDEBUG(D_NET, "sending reply\n");
                ptlrpc_reply(req->rq_svc, req);
        }
        return 0;
}

/* Update the server data on disk.  This stores the new mount_count and
 * also the last_rcvd value to disk.  If we don't have a clean shutdown,
 * then the server last_rcvd value may be less than that of the clients.
 * This will alert us that we may need to do client recovery.
 *
 * Assumes we are already in the server filesystem context.
 *
 * Also assumes for mds_last_rcvd that we are not modifying it (no locking).
 */
static
int mds_update_server_data(struct mds_obd *mds)
{
        struct mds_server_data *msd = mds->mds_server_data;
        struct file *filp = mds->mds_rcvd_filp;
        loff_t off = 0;
        int rc;

        msd->msd_last_rcvd = cpu_to_le64(mds->mds_last_rcvd);
        msd->msd_mount_count = cpu_to_le64(mds->mds_mount_count);

        CDEBUG(D_SUPER, "MDS mount_count is %Lu, last_rcvd is %Lu\n",
               (unsigned long long)mds->mds_mount_count,
               (unsigned long long)mds->mds_last_rcvd);
        rc = lustre_fwrite(filp, (char *)msd, sizeof(*msd), &off);
        if (rc != sizeof(*msd)) {
                CERROR("error writing MDS server data: rc = %d\n", rc);
                if (rc > 0)
                        RETURN(-EIO);
                RETURN(rc);
        }
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        rc = fsync_dev(filp->f_dentry->d_inode->i_rdev);
#else
        rc = file_fsync(filp,  filp->f_dentry, 1);
#endif
        if (rc)
                CERROR("error flushing MDS server data: rc = %d\n", rc);

        return 0;
}

/* Do recovery actions for the MDS */
static int mds_recover(struct obd_device *obddev)
{
        struct mds_obd *mds = &obddev->u.mds;
        struct obd_run_ctxt saved;
        int rc;

        /* This happens at the end when recovery is complete */
        ++mds->mds_mount_count;
        push_ctxt(&saved, &mds->mds_ctxt, NULL);
        rc = mds_update_server_data(mds);
        pop_ctxt(&saved);

        return rc;
}

/* mount the file system (secretly) */
static int mds_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct mds_obd *mds = &obddev->u.mds;
        struct vfsmount *mnt;
        int rc = 0;
        ENTRY;

        MOD_INC_USE_COUNT;
#ifdef CONFIG_DEV_RDONLY
        dev_clear_rdonly(2);
#endif
        if (!data->ioc_inlbuf1 || !data->ioc_inlbuf2)
                GOTO(err_dec, rc = -EINVAL);

        mds->mds_fstype = strdup(data->ioc_inlbuf2);

        mnt = do_kern_mount(mds->mds_fstype, 0, data->ioc_inlbuf1, NULL);
        if (IS_ERR(mnt)) {
                rc = PTR_ERR(mnt);
                CERROR("do_kern_mount failed: rc = %d\n", rc);
                GOTO(err_kfree, rc);
        }

        CERROR("%s: mnt is %p\n", data->ioc_inlbuf1, mnt);
        mds->mds_sb = mnt->mnt_root->d_inode->i_sb;
        if (!mds->mds_sb)
                GOTO(err_put, rc = -ENODEV);

        spin_lock_init(&mds->mds_last_lock);
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


        rc = mds_recover(obddev);
        if (rc)
                GOTO(err_fs, rc);

        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "mds_ldlm_client", &obddev->obd_ldlm_client);

        RETURN(0);

err_fs:
        mds_fs_cleanup(obddev);
err_put:
        unlock_kernel();
        mntput(mds->mds_vfsmnt);
        mds->mds_sb = 0;
        lock_kernel();
err_kfree:
        kfree(mds->mds_fstype);
err_dec:
        MOD_DEC_USE_COUNT;
        RETURN(rc);
}

static int mds_cleanup(struct obd_device *obddev)
{
        struct super_block *sb;
        struct mds_obd *mds = &obddev->u.mds;
        struct obd_run_ctxt saved;
        ENTRY;

        sb = mds->mds_sb;
        if (!mds->mds_sb)
                RETURN(0);

        push_ctxt(&saved, &mds->mds_ctxt, NULL);
        mds_update_server_data(mds);

        if (mds->mds_rcvd_filp) {
                int rc = filp_close(mds->mds_rcvd_filp, 0);
                mds->mds_rcvd_filp = NULL;

                if (rc)
                        CERROR("last_rcvd file won't close, rc=%d\n", rc);
        }
        pop_ctxt(&saved);

        unlock_kernel();
        mntput(mds->mds_vfsmnt);
        mds->mds_sb = 0;
        kfree(mds->mds_fstype);

        ldlm_namespace_free(obddev->obd_namespace);

        lock_kernel();
#ifdef CONFIG_DEV_RDONLY
        dev_clear_rdonly(2);
#endif
        mds_fs_cleanup(obddev);

        MOD_DEC_USE_COUNT;
        RETURN(0);
}

static int ldlm_intent_policy(struct ldlm_lock *lock, void *req_cookie,
                              ldlm_mode_t mode, int flags, void *data)
{
        struct ptlrpc_request *req = req_cookie;
        int rc = 0;
        ENTRY;

        if (!req_cookie)
                RETURN(0);

        if (req->rq_reqmsg->bufcount > 1) {
                /* an intent needs to be considered */
                struct ldlm_intent *it = lustre_msg_buf(req->rq_reqmsg, 1);
                struct mds_obd *mds= &req->rq_export->exp_obd->u.mds;
                struct mds_body *mds_rep;
                struct ldlm_reply *rep;
                __u64 new_resid[3] = {0, 0, 0}, old_res;
                int rc, size[3] = {sizeof(struct ldlm_reply),
                                                  sizeof(struct mds_body),
                                                  mds->mds_max_mdsize};

                it->opc = NTOH__u64(it->opc);

                LDLM_DEBUG(lock, "intent policy, opc: %s",
                           ldlm_it2str(it->opc));

                rc = lustre_pack_msg(3, size, NULL, &req->rq_replen,
                                     &req->rq_repmsg);
                if (rc) {
                        rc = req->rq_status = -ENOMEM;
                        RETURN(rc);
                }

                rep = lustre_msg_buf(req->rq_repmsg, 0);
                rep->lock_policy_res1 = 1;

                /* execute policy */
                switch ((long)it->opc) {
                case IT_CREAT|IT_OPEN:
                        rc = mds_reint(req, 2);
                        if (rc || (req->rq_status != 0 &&
                                   req->rq_status != -EEXIST)) {
                                rep->lock_policy_res2 = req->rq_status;
                                RETURN(ELDLM_LOCK_ABORTED);
                        }
                        break;
                case IT_CREAT:
                case IT_MKDIR:
                case IT_MKNOD:
                case IT_RENAME2:
                case IT_LINK2:
                case IT_RMDIR:
                case IT_SYMLINK:
                case IT_UNLINK:
                        rc = mds_reint(req, 2);
                        if (rc || (req->rq_status != 0 &&
                                   req->rq_status != -EISDIR &&
                                   req->rq_status != -ENOTDIR)) {
                                rep->lock_policy_res2 = req->rq_status;
                                RETURN(ELDLM_LOCK_ABORTED);
                        }
                        break;
                case IT_GETATTR:
                case IT_LOOKUP:
                case IT_OPEN:
                case IT_READDIR:
                case IT_READLINK:
                case IT_RENAME:
                case IT_LINK:
                case IT_SETATTR:
                        rc = mds_getattr_name(2, req);
                        /* FIXME: we need to sit down and decide on who should
                         * set req->rq_status, who should return negative and
                         * positive return values, and what they all mean. */
                        if (rc || req->rq_status != 0) {
                                rep->lock_policy_res2 = req->rq_status;
                                RETURN(ELDLM_LOCK_ABORTED);
                        }
                        break;
                case IT_READDIR|IT_OPEN:
                        LBUG();
                        break;
                default:
                        CERROR("Unhandled intent "LPD64"\n", it->opc);
                        LBUG();
                }

                /* We don't bother returning a lock to the client for a file
                 * or directory we are removing.
                 *
                 * As for link and rename, there is no reason for the client
                 * to get a lock on the target at this point.  If they are
                 * going to modify the file/directory later they will get a
                 * lock at that time.
                 */
                if (it->opc & (IT_UNLINK | IT_RMDIR | IT_LINK | IT_LINK2 |
                               IT_RENAME | IT_RENAME2))
                        RETURN(ELDLM_LOCK_ABORTED);

                rep->lock_policy_res2 = req->rq_status;
                mds_rep = lustre_msg_buf(req->rq_repmsg, 1);

                /* If the client is about to open a file that doesn't have an MD
                 * stripe record, it's going to need a write lock. */
                if (it->opc & IT_OPEN &&
                    !(lustre_msg_get_op_flags(req->rq_reqmsg)&MDS_OPEN_HAS_EA)){
                        LDLM_DEBUG(lock, "open with no EA; returning PW lock");
                        lock->l_req_mode = LCK_PW;
                }

                if (flags & LDLM_FL_INTENT_ONLY) {
                        LDLM_DEBUG(lock, "INTENT_ONLY, aborting lock");
                        RETURN(ELDLM_LOCK_ABORTED);
                }
                /* Give the client a lock on the child object, instead of the
                 * parent that it requested. */
                new_resid[0] = NTOH__u32(mds_rep->ino);
                new_resid[1] = NTOH__u32(mds_rep->generation);
                if (new_resid[0] == 0)
                        LBUG();
                old_res = lock->l_resource->lr_name[0];

                ldlm_lock_change_resource(lock, new_resid);
                if (lock->l_resource == NULL) {
                        LBUG();
                        RETURN(-ENOMEM);
                }
                LDLM_DEBUG(lock, "intent policy, old res %ld",
                           (long)old_res);
                RETURN(ELDLM_LOCK_CHANGED);
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
        return lprocfs_reg_obd(dev, status_var_nm_1, dev);
}

int mds_detach(struct obd_device *dev)
{
        return lprocfs_dereg_obd(dev);
}

static int mdt_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        int i;
        //        struct obd_ioctl_data* data = buf;
        struct mds_obd *mds = &obddev->u.mds;
        int rc = 0;
        ENTRY;

        MOD_INC_USE_COUNT;

        mds->mds_service = ptlrpc_init_svc(MDS_NEVENTS, MDS_NBUFS,
                                           MDS_BUFSIZE, MDS_MAXREQSIZE,
                                           MDS_REQUEST_PORTAL, MDC_REPLY_PORTAL,
                                           "self", mds_handle, "mds");
        if (!mds->mds_service) {
                CERROR("failed to start service\n");
                GOTO(err_dec, rc = -EINVAL);
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

        RETURN(0);

err_thread:
        ptlrpc_stop_all_threads(mds->mds_service);
        ptlrpc_unregister_service(mds->mds_service);
err_dec:
        MOD_DEC_USE_COUNT;
        RETURN(rc);
}


static int mdt_cleanup(struct obd_device *obddev)
{
        struct mds_obd *mds = &obddev->u.mds;
        ENTRY;

        ptlrpc_stop_all_threads(mds->mds_service);
        ptlrpc_unregister_service(mds->mds_service);

        MOD_DEC_USE_COUNT;
        RETURN(0);
}

extern int mds_iocontrol(long cmd, struct lustre_handle *conn,
                         int len, void *karg, void *uarg);

/* use obd ops to offer management infrastructure */
static struct obd_ops mds_obd_ops = {
        o_attach:      mds_attach,
        o_detach:      mds_detach,
        o_connect:     mds_connect,
        o_disconnect:  mds_disconnect,
        o_setup:       mds_setup,
        o_cleanup:     mds_cleanup,
        o_iocontrol:   mds_iocontrol
};

static struct obd_ops mdt_obd_ops = {
        o_setup:       mdt_setup,
        o_cleanup:     mdt_cleanup,
};


static int __init mds_init(void)
{

        mds_file_cache = kmem_cache_create("ll_mds_file_data",
                                           sizeof(struct mds_file_data),
                                           0, 0, NULL, NULL);
        if (mds_file_cache == NULL)
                return -ENOMEM;

        class_register_type(&mds_obd_ops, status_class_var, LUSTRE_MDS_NAME);
        class_register_type(&mdt_obd_ops, 0, LUSTRE_MDT_NAME);
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

MODULE_AUTHOR("Cluster File Systems <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Metadata Server (MDS) v0.01");
MODULE_LICENSE("GPL");

module_init(mds_init);
module_exit(mds_exit);
