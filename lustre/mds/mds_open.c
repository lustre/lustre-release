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
#include <linux/locks.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <linux/buffer_head.h>
#include <linux/workqueue.h>
#endif
#include <linux/obd_lov.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lprocfs_status.h>

extern kmem_cache_t *mds_file_cache;
extern inline struct mds_obd *mds_req2mds(struct ptlrpc_request *req);
extern void mds_start_transno(struct mds_obd *mds);
extern int mds_finish_transno(struct mds_obd *mds, void *handle,
                              struct ptlrpc_request *req, int rc);

int mds_open(struct mds_update_record *rec, int offset,
             struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct ldlm_reply *rep = lustre_msg_buf(req->rq_repmsg, 0);
        struct obd_ucred uc;
        struct obd_run_ctxt saved;
        struct lustre_handle lockh;
        int lock_mode;
        struct file *file;
        struct mds_body *body = lustre_msg_buf(req->rq_repmsg, 1);
        struct dentry *dchild, *parent;
        struct inode *dir;
        struct mds_export_data *med;
        struct mds_file_data *mfd = NULL;
        struct vfsmount *mnt = mds->mds_vfsmnt;
        __u32 flags;
        struct list_head *tmp;
        int rc = 0;
        ENTRY;

#warning replay of open needs to be redone
        /* was this animal open already and the client lost the reply? */
        /* XXX need some way to detect a reopen, to avoid locked list walks */
        med = &req->rq_export->exp_mds_data;
#if 0
        spin_lock(&med->med_open_lock);
        list_for_each(tmp, &med->med_open_head) {
                mfd = list_entry(tmp, typeof(*mfd), mfd_list);
                if (!memcmp(&mfd->mfd_clienthandle, &body->handle,
                            sizeof(mfd->mfd_clienthandle)) &&
                    body->fid1.id == mfd->mfd_file->f_dentry->d_inode->i_ino) {
                        dchild = mfd->mfd_file->f_dentry;
                        spin_unlock(&med->med_open_lock);
                        CERROR("Re opening "LPD64"\n", body->fid1.id);
                        GOTO(out_pack, rc = 0);
                }
        }
        spin_unlock(&med->med_open_lock);
#endif
        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OPEN_PACK)) {
                CERROR("test case OBD_FAIL_MDS_OPEN_PACK\n");
                req->rq_status = -ENOMEM;
                RETURN(-ENOMEM);
        }

        lock_mode = (rec->ur_flags & O_CREAT) ? LCK_PW : LCK_PR;
        parent = mds_fid2locked_dentry(obd, rec->ur_fid1, NULL, lock_mode,
                                       &lockh);
        if (IS_ERR(parent)) {
                rc = PTR_ERR(parent);
                CERROR("parent lookup error %d\n", rc);
                LBUG();
                RETURN(rc);
        }
        dir = parent->d_inode;
        rep->lock_policy_res1 |= IT_OPEN_LOOKUP;

        down(&dir->i_sem);
        dchild = lookup_one_len(lustre_msg_buf(req->rq_reqmsg, 3),
                                parent, req->rq_reqmsg->buflens[3] - 1);
        if (IS_ERR(dchild)) {
                up(&dir->i_sem);
                GOTO(out_unlock, rc = PTR_ERR(dchild));
        }

        if (dchild->d_inode)
                rep->lock_policy_res1 |= IT_OPEN_POS;
        else
                rep->lock_policy_res1 |= IT_OPEN_NEG;

        /* Negative dentry, just create the file */
        if ((rec->ur_flags & O_CREAT) && !dchild->d_inode) {
                int err;
                void *handle;
                mds_start_transno(mds);
                rep->lock_policy_res1 |= IT_OPEN_CREATE;
                handle = fsfilt_start(obd, dir, FSFILT_OP_CREATE);
                if (IS_ERR(handle)) {
                        rc = PTR_ERR(handle);
                        mds_finish_transno(mds, handle, req, rc);
                        GOTO(out_ldput, rc);
                }
                rc = vfs_create(dir, dchild, rec->ur_mode);
                up(&dir->i_sem);
                if (rc)
                        GOTO(out_unlock, rc);
                rc = mds_finish_transno(mds, handle, req, rc);
                err = fsfilt_commit(obd, dir, handle);
                if (err) {
                        CERROR("error on commit: err = %d\n", err);
                        if (!rc)
                                rc = err;
                        GOTO(out_ldput, rc);
                }
        } else if (!dchild->d_inode) {
                up(&dir->i_sem);
                GOTO(out_ldput, rc = -ENOENT);
        } else {
                up(&dir->i_sem);
        }

        /*
         * It already exists.
         */
        mds_pack_inode2fid(&body->fid1, dchild->d_inode);
        mds_pack_inode2body(body, dchild->d_inode);

        if (!S_ISREG(dchild->d_inode->i_mode))
                GOTO(out_ldput, rc = 0);

        rc = mds_pack_md(obd, req->rq_repmsg, 3, body, dchild->d_inode);
        if (rc) {
                CERROR("failure to get EA for %ld\n", dchild->d_inode->i_ino);
                GOTO(out_ldput, req->rq_status = rc);
        }

        rep->lock_policy_res1 |= IT_OPEN_OPEN;
        mfd = kmem_cache_alloc(mds_file_cache, GFP_KERNEL);
        if (!mfd) {
                CERROR("mds: out of memory\n");
                GOTO(out_ldput, req->rq_status = -ENOMEM);
        }

        flags = rec->ur_flags;
        /* dentry_open does a dput(de) and mntput(mnt) on error */
        mntget(mnt);
        file = dentry_open(dchild, mnt, flags & ~O_DIRECT & ~O_TRUNC);
        if (IS_ERR(file))
                GOTO(out_ldput, req->rq_status = PTR_ERR(file));

        file->private_data = mfd;
        mfd->mfd_file = file;
        get_random_bytes(&mfd->mfd_servercookie, sizeof(mfd->mfd_servercookie));
        spin_lock(&med->med_open_lock);
        list_add(&mfd->mfd_list, &med->med_open_head);
        spin_unlock(&med->med_open_lock);

 out_unlock:
        l_dput(parent);
        ldlm_lock_decref(&lockh, lock_mode);
        if (rc && rc != -EEXIST && mfd != NULL) {
                kmem_cache_free(mds_file_cache, mfd);
                mfd = NULL;
        }
        if (rc)
                RETURN(rc);

 out_pack:
        if (mfd) {
                body->handle.addr = (__u64)(unsigned long)mfd;
                body->handle.cookie = mfd->mfd_servercookie;
                CDEBUG(D_INODE, "file %p: mfd %p, cookie "LPX64"\n",
                       mfd->mfd_file, mfd, mfd->mfd_servercookie);
        }
        RETURN(0);

 out_ldput:
        l_dput(dchild);
        goto out_unlock;
}
