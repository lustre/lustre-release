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

void reconstruct_open(struct mds_update_record *rec, struct ptlrpc_request *req,
                      struct lustre_handle *child_lockh)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_client_data *mcd = med->med_mcd;
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_file_data *mfd;
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *parent, *child;
        struct ldlm_reply *rep = lustre_msg_buf(req->rq_repmsg, 0);
        struct mds_body *body = lustre_msg_buf(req->rq_repmsg, 1);
        int disp, rc;
        ENTRY;

        ENTRY;

        /* copy rc, transno and disp; steal locks */
        req->rq_transno = mcd->mcd_last_transno;
        req->rq_status = mcd->mcd_last_result;
        disp = rep->lock_policy_res1 = mcd->mcd_last_data;
        
        if (med->med_outstanding_reply)
                mds_steal_ack_locks(med, req);
        
        /* We never care about these. */
        disp &= ~(IT_OPEN_LOOKUP | IT_OPEN_POS | IT_OPEN_NEG);
        if (!disp) {
                EXIT;
                return; /* error looking up parent or child */
        }

        parent = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        LASSERT(!IS_ERR(parent));

        child = lookup_one_len(lustre_msg_buf(req->rq_reqmsg, 3),
                               parent, req->rq_reqmsg->buflens[3] - 1);
        LASSERT(!IS_ERR(child));
        
        if (!child->d_inode) {
                GOTO(out_dput, 0); /* child not present to open */
        }

        /* At this point, we know we have a child, which means that we'll send
         * it back _unless_ it was open failed, _and_ we didn't create the file.
         * I love you guys.  No, really.
         */
        if (((disp & (IT_OPEN_OPEN | IT_OPEN_CREATE)) == IT_OPEN_OPEN) &&
            req->rq_status) {
                GOTO(out_dput, 0);
        }

        if (!med->med_outstanding_reply) {
                LBUG(); /* XXX need to get enqueue client lock */
        }

        /* get lock (write for O_CREAT, read otherwise) */
        
        mds_pack_inode2fid(&body->fid1, child->d_inode);
        mds_pack_inode2body(body, child->d_inode);
        if (S_ISREG(child->d_inode->i_mode)) {
                rc = mds_pack_md(obd, req->rq_repmsg, 2, body,
                                 child->d_inode);
                if (rc)
                        LASSERT(rc == req->rq_status);
        } else {
                /* XXX need to check this case */
        }

        /* If we're opening a file without an EA, change to a write
           lock (unless we already have one). */
                   
        /* If we have -EEXIST as the status, and we were asked to create
         * exclusively, we can tell we failed because the file already existed.
         */
        if (req->rq_status == -EEXIST &&
            ((rec->ur_flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL))) {
                GOTO(out_dput, 0);
        }

        /* If we didn't get as far as trying to open, then some locking thing
         * probably went wrong, and we'll just bail here.
         */
        if ((disp & IT_OPEN_OPEN) == 0) {
                GOTO(out_dput, 0);
        }

        /* If we failed, then we must have failed opening, so don't look for
         * file descriptor or anything, just give the client the bad news.
         */
        if (req->rq_status) {
                GOTO(out_dput, 0);
        }

        if (med->med_outstanding_reply) {
                struct list_head *t;
                mfd = NULL;
                /* XXX can we just look in the old reply to find the handle in
                 * XXX O(1) here? */
                list_for_each(t, &med->med_open_head) {
                        mfd = list_entry(t, struct mds_file_data, mfd_list);
                        if (mfd->mfd_xid == req->rq_xid)
                                break;
                        mfd = NULL;
                }
                /* if we're not recovering, it had better be found */
                LASSERT(mfd);
        } else {
                struct file *file;
                mfd = kmem_cache_alloc(mds_file_cache, GFP_KERNEL);
                if (!mfd) {
                        CERROR("mds: out of memory\n");
                        GOTO(out_dput, req->rq_status = -ENOMEM);
                }
                mntget(mds->mds_vfsmnt);
                file = dentry_open(child, mds->mds_vfsmnt,
                                   rec->ur_flags & ~(O_DIRECT | O_TRUNC));
                LASSERT(!IS_ERR(file)); /* XXX -ENOMEM? */
                file->private_data = mfd;
                mfd->mfd_file = file;
                mfd->mfd_xid = req->rq_xid;
                get_random_bytes(&mfd->mfd_servercookie,
                                 sizeof(mfd->mfd_servercookie));
                spin_lock(&med->med_open_lock);
                list_add(&mfd->mfd_list, &med->med_open_head);
                spin_unlock(&med->med_open_lock);
        }
                
        body->handle.addr = (__u64)(unsigned long)mfd;
        body->handle.cookie = mfd->mfd_servercookie;

 out_dput:
        l_dput(child);
        l_dput(parent);
        EXIT;
}

int mds_open(struct mds_update_record *rec, int offset,
             struct ptlrpc_request *req, struct lustre_handle *child_lockh)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct ldlm_reply *rep = lustre_msg_buf(req->rq_repmsg, 0);
        struct file *file;
        struct mds_body *body = lustre_msg_buf(req->rq_repmsg, 1);
        struct dentry *dchild = NULL, *parent;
        struct mds_export_data *med;
        struct mds_file_data *mfd = NULL;
        struct ldlm_res_id child_res_id = { .name = {0} };
        struct lustre_handle parent_lockh;
        int rc = 0, parent_mode, child_mode = LCK_PR, lock_flags, created = 0;
        int cleanup_phase = 0;
        void *handle = NULL;
        ENTRY;

        MDS_CHECK_RESENT(req, reconstruct_open(rec, req, child_lockh));

        med = &req->rq_export->exp_mds_data;
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
                GOTO(cleanup, rc);
        }
        LASSERT(parent->d_inode);

        cleanup_phase = 1; /* parent dentry and lock */

        /* Step 2: Lookup the child */
        dchild = lookup_one_len(lustre_msg_buf(req->rq_reqmsg, 3),
                                parent, req->rq_reqmsg->buflens[3] - 1);
        if (IS_ERR(dchild))
                GOTO(cleanup, rc = PTR_ERR(dchild));

        cleanup_phase = 2; /* child dentry */

        if (dchild->d_inode)
                rep->lock_policy_res1 |= IT_OPEN_POS;
        else
                rep->lock_policy_res1 |= IT_OPEN_NEG;

        /* Step 3: If the child was negative, and we're supposed to,
         * create it. */
        if (!dchild->d_inode) {
                if (!(rec->ur_flags & O_CREAT)) {
                        /* It's negative and we weren't supposed to create it */
                        GOTO(cleanup, rc = -ENOENT);
                }

                rep->lock_policy_res1 |= IT_OPEN_CREATE;
                handle = fsfilt_start(obd, parent->d_inode, FSFILT_OP_CREATE);
                if (IS_ERR(handle)) {
                        rc = PTR_ERR(handle);
                        handle = NULL;
                        GOTO(cleanup, rc);
                }
                rc = vfs_create(parent->d_inode, dchild, rec->ur_mode);
                if (rc)
                        GOTO(cleanup, rc);
                created = 1;
                child_mode = LCK_PW;
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
                GOTO(cleanup, rc = -EIO);
        }

        cleanup_phase = 3; /* child lock */

        mds_pack_inode2fid(&body->fid1, dchild->d_inode);
        mds_pack_inode2body(body, dchild->d_inode);
        if (S_ISREG(dchild->d_inode->i_mode)) {
                rc = mds_pack_md(obd, req->rq_repmsg, 2, body, dchild->d_inode);
                if (rc)
                        GOTO(cleanup, rc);
        } else {
                /* If this isn't a regular file, we can't open it. */

                /* We want to drop the child dentry, because we're not returning
                 * failure (which would do this for us in step 2), and we're not
                 * handing it off to the open file in dentry_open. */
                l_dput(dchild);
                GOTO(cleanup, rc = 0); /* returns the lock to the client */
        }

        if (!created && (rec->ur_flags & O_CREAT) && (rec->ur_flags & O_EXCL)) {
                /* File already exists, we didn't just create it, and we
                 * were passed O_EXCL; err-or. */
                GOTO(cleanup, rc = -EEXIST); // returns a lock to the client
        }

        /* If we're opening a file without an EA, the client needs a write
         * lock. */
        if (child_mode != LCK_PW && !(body->valid & OBD_MD_FLEASIZE)) {
                ldlm_lock_decref(child_lockh, child_mode);
                child_mode = LCK_PW;
                goto reacquire;
        }

        /* Step 5: Open it */
        rep->lock_policy_res1 |= IT_OPEN_OPEN;
        mfd = kmem_cache_alloc(mds_file_cache, GFP_KERNEL);
        if (!mfd) {
                CERROR("mds: out of memory\n");
                GOTO(cleanup, rc = -ENOMEM);
        }

        cleanup_phase = 4; /* mfd allocated */

        /* dentry_open does a dput(de) and mntput(mds->mds_vfsmnt) on error */
        mntget(mds->mds_vfsmnt);
        file = dentry_open(dchild, mds->mds_vfsmnt,
                           rec->ur_flags & ~(O_DIRECT | O_TRUNC));
        if (IS_ERR(file)) {
                dchild = NULL; /* prevent a double dput in step 2 */
                GOTO(cleanup, rc = PTR_ERR(file));
        }

        file->private_data = mfd;
        mfd->mfd_file = file;
        mfd->mfd_xid = req->rq_xid;
        get_random_bytes(&mfd->mfd_servercookie, sizeof(mfd->mfd_servercookie));
        spin_lock(&med->med_open_lock);
        list_add(&mfd->mfd_list, &med->med_open_head);
        spin_unlock(&med->med_open_lock);

        body->handle.addr = (__u64)(unsigned long)mfd;
        body->handle.cookie = mfd->mfd_servercookie;
        CDEBUG(D_INODE, "file %p: mfd %p, cookie "LPX64"\n",
               mfd->mfd_file, mfd, mfd->mfd_servercookie);
        GOTO(cleanup, rc = 0); /* returns a lock to the client */

 cleanup:
        rc = mds_finish_transno(mds, dchild ? dchild->d_inode : NULL, handle,
                                req, rc, rep->lock_policy_res1);
        switch (cleanup_phase) {
        case 4:
                if (rc)
                        kmem_cache_free(mds_file_cache, mfd);
        case 3:
                /* This is the same logic as in the IT_OPEN part of 
                 * ldlm_intent_policy: if we found the dentry, or we tried to
                 * open it (meaning that we created, if it wasn't found), then
                 * we return the lock to the caller and client. */
                if (!(rep->lock_policy_res1 & (IT_OPEN_OPEN | IT_OPEN_POS)))
                        ldlm_lock_decref(child_lockh, child_mode);
        case 2:
                if (rc) 
                    l_dput(dchild);
        case 1:
                l_dput(parent);
                if (rc) {
                        ldlm_lock_decref(&parent_lockh, parent_mode);
                } else {
                        memcpy(&req->rq_ack_locks[0].lock, &parent_lockh,
                               sizeof(parent_lockh));
                        req->rq_ack_locks[0].mode = parent_mode;
                }
        }
        RETURN(rc);
}
