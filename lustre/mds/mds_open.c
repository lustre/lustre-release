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

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_dlm.h>
#include <linux/init.h>
#include <linux/obd_class.h>
#include <linux/random.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <linux/buffer_head.h>
#include <linux/workqueue.h>
#else
#include <linux/locks.h>
#endif
#include <linux/obd_lov.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lprocfs_status.h>

extern kmem_cache_t *mds_file_cache;
extern inline struct mds_obd *mds_req2mds(struct ptlrpc_request *req);
int mds_finish_transno(struct mds_obd *mds, struct inode *i, void *handle,
                       struct ptlrpc_request *req, int rc, __u32 op_data);
extern int enqueue_ordered_locks(int lock_mode, struct obd_device *obd,
                                 struct ldlm_res_id *p1_res_id,
                                 struct ldlm_res_id *p2_res_id,
                                 struct ldlm_res_id *c1_res_id,
                                 struct ldlm_res_id *c2_res_id,
                                 struct lustre_handle *p1_lockh,
                                 struct lustre_handle *p2_lockh,
                                 struct lustre_handle *c1_lockh,
                                 struct lustre_handle *c2_lockh);

int mds_open(struct mds_update_record *rec, int offset,
             struct ptlrpc_request *req, struct lustre_handle *child_lockh)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct ldlm_reply *rep = lustre_msg_buf(req->rq_repmsg, 0);
        struct file *file;
        struct mds_body *body = lustre_msg_buf(req->rq_repmsg, 1);
        struct dentry *dchild, *parent;
        struct mds_export_data *med;
        struct mds_file_data *mfd = NULL;
        struct ldlm_res_id child_res_id = { .name = {0} };
        struct lustre_handle parent_lockh;
        int rc = 0, parent_mode, child_mode = LCK_PR, lock_flags, created = 0;
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
        rep->lock_policy_res1 |= IT_OPEN_LOOKUP;
        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OPEN_PACK)) {
                CERROR("test case OBD_FAIL_MDS_OPEN_PACK\n");
                req->rq_status = -ENOMEM;
                RETURN(-ENOMEM);
        }

        /* Step 1: Find and lock the parent */
        parent_mode = (rec->ur_flags & O_CREAT) ? LCK_PW : LCK_PR;
        parent = mds_fid2locked_dentry(obd, rec->ur_fid1, NULL, parent_mode,
                                       &parent_lockh);
        if (IS_ERR(parent)) {
                rc = PTR_ERR(parent);
                CERROR("parent lookup error %d\n", rc);
                RETURN(rc);
        }
        LASSERT(parent->d_inode);

        /* Step 2: Lookup the child */
        dchild = lookup_one_len(lustre_msg_buf(req->rq_reqmsg, 3),
                                parent, req->rq_reqmsg->buflens[3] - 1);
        if (IS_ERR(dchild))
                GOTO(out_step_2, rc = PTR_ERR(dchild));

        if (dchild->d_inode)
                rep->lock_policy_res1 |= IT_OPEN_POS;
        else
                rep->lock_policy_res1 |= IT_OPEN_NEG;

        /* Step 3: If the child was negative, and we're supposed to,
         * create it. */
        if ((rec->ur_flags & O_CREAT) && !dchild->d_inode) {
                int err;
                void *handle;
                rep->lock_policy_res1 |= IT_OPEN_CREATE;
                handle = fsfilt_start(obd, parent->d_inode, FSFILT_OP_CREATE);
                if (IS_ERR(handle)) {
                        rc = PTR_ERR(handle);
                        mds_finish_transno(mds, parent->d_inode, handle, req,
                                           rc, rep->lock_policy_res1);
                        GOTO(out_step_3, rc);
                }
                rc = vfs_create(parent->d_inode, dchild, rec->ur_mode);
                err = mds_finish_transno(mds, parent->d_inode, handle, req, rc,
                                        rep->lock_policy_res1);
                if (err) {
                        CERROR("error on commit: err = %d\n", err);
                        if (!rc)
                                rc = err;
                        GOTO(out_step_3, rc);
                }
                created = 1;
                child_mode = LCK_PW;
        } else if (!dchild->d_inode) {
                /* It's negative and we weren't supposed to create it */
                GOTO(out_step_3, rc = -ENOENT);
        }

        /* Step 4: It's positive, so lock the child */
        child_res_id.name[0] = dchild->d_inode->i_ino;
        child_res_id.name[1] = dchild->d_inode->i_generation;
 reacquire:
        lock_flags = 0;
        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                              child_res_id, LDLM_PLAIN, NULL, 0, child_mode,
                              &lock_flags, ldlm_completion_ast,
                              mds_blocking_ast, NULL, NULL, child_lockh);
        if (rc != ELDLM_OK) {
                CERROR("ldlm_cli_enqueue: %d\n", rc);
                GOTO(out_step_3, rc = -EIO);
        }

        mds_pack_inode2fid(&body->fid1, dchild->d_inode);
        mds_pack_inode2body(body, dchild->d_inode);
        if (S_ISREG(dchild->d_inode->i_mode)) {
                rc = mds_pack_md(obd, req->rq_repmsg, 2, body, dchild->d_inode);
                if (rc)
                        GOTO(out_step_4, rc);
        } else {
                /* If this isn't a regular file, we can't open it. */
                GOTO(out_step_3, rc = 0); /* returns the lock to the client */
        }

        if (!created && (rec->ur_flags & O_CREAT) && (rec->ur_flags & O_EXCL)) {
                /* File already exists, we didn't just create it, and we
                 * were passed O_EXCL; err-or. */
                GOTO(out_step_3, rc = -EEXIST); // returns a lock to the client
        }

        /* If we're opening a file without an EA, the client needs a write
         * lock. */
        if (child_mode != LCK_PW && S_ISREG(dchild->d_inode->i_mode) &&
            !(body->valid & OBD_MD_FLEASIZE)) {
                ldlm_lock_decref(child_lockh, child_mode);
                child_mode = LCK_PW;
                goto reacquire;
        }

        /* Step 5: Open it */
        rep->lock_policy_res1 |= IT_OPEN_OPEN;
        mfd = kmem_cache_alloc(mds_file_cache, GFP_KERNEL);
        if (!mfd) {
                CERROR("mds: out of memory\n");
                GOTO(out_step_4, rc = -ENOMEM);
        }

        /* dentry_open does a dput(de) and mntput(mds->mds_vfsmnt) on error */
        mntget(mds->mds_vfsmnt);
        file = dentry_open(dchild, mds->mds_vfsmnt,
                           rec->ur_flags & ~(O_DIRECT | O_TRUNC));
        if (IS_ERR(file))
                GOTO(out_step_5, rc = PTR_ERR(file));

        file->private_data = mfd;
        mfd->mfd_file = file;
        get_random_bytes(&mfd->mfd_servercookie, sizeof(mfd->mfd_servercookie));
        spin_lock(&med->med_open_lock);
        list_add(&mfd->mfd_list, &med->med_open_head);
        spin_unlock(&med->med_open_lock);

        body->handle.addr = (__u64)(unsigned long)mfd;
        body->handle.cookie = mfd->mfd_servercookie;
        CDEBUG(D_INODE, "file %p: mfd %p, cookie "LPX64"\n",
               mfd->mfd_file, mfd, mfd->mfd_servercookie);
        GOTO(out_step_2, rc = 0); /* returns a lock to the client */

 out_step_5:
        if (mfd != NULL) {
                kmem_cache_free(mds_file_cache, mfd);
                mfd = NULL;
        }
 out_step_4:
        ldlm_lock_decref(child_lockh, child_mode);
 out_step_3:
        l_dput(dchild);
 out_step_2:
        l_dput(parent);
        if (rc) {
                ldlm_lock_decref(&parent_lockh, parent_mode);
        } else {
                memcpy(&req->rq_ack_locks[0].lock, &parent_lockh,
                       sizeof(parent_lockh));
                req->rq_ack_locks[0].mode = parent_mode;
        }
        RETURN(rc);
}
