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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
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

        DEBUG_REQ(D_ERROR, desc->bd_req,"bulk send timed out: evicting %s@%s\n",
                  exp->exp_client_uuid.uuid,
                  exp->exp_connection->c_remote_uuid.uuid);
        ptlrpc_fail_export(exp);
        ptlrpc_abort_bulk (desc);
        RETURN(1);
}

/* Assumes caller has already pushed into the kernel filesystem context */
static int mds_sendpage(struct ptlrpc_request *req, struct file *file,
                        loff_t offset, int count)
{
        struct ptlrpc_bulk_desc *desc;
        struct l_wait_info lwi;
        struct page **pages;
        int rc = 0, npages, i, tmpcount, tmpsize = 0;
        ENTRY;

        LASSERT((offset & (PAGE_SIZE - 1)) == 0); /* I'm dubious about this */

        npages = (count + PAGE_SIZE - 1) >> PAGE_SHIFT;
        OBD_ALLOC(pages, sizeof(*pages) * npages);
        if (!pages)
                GOTO(out, rc = -ENOMEM);

        desc = ptlrpc_prep_bulk_exp (req, BULK_PUT_SOURCE, MDS_BULK_PORTAL);
        if (desc == NULL)
                GOTO(out_free, rc = -ENOMEM);

        for (i = 0, tmpcount = count; i < npages; i++, tmpcount -= tmpsize) {
                tmpsize = tmpcount > PAGE_SIZE ? PAGE_SIZE : tmpcount;

                pages[i] = alloc_pages(GFP_KERNEL, 0);
                if (pages[i] == NULL)
                        GOTO(cleanup_buf, rc = -ENOMEM);

                rc = ptlrpc_prep_bulk_page(desc, pages[i], 0, tmpsize);
                if (rc != 0)
                        GOTO(cleanup_buf, rc);
        }

        for (i = 0, tmpcount = count; i < npages; i++, tmpcount -= tmpsize) {
                tmpsize = tmpcount > PAGE_SIZE ? PAGE_SIZE : tmpcount;
                CDEBUG(D_EXT2, "reading %u@%llu from dir %lu (size %llu)\n",
                       tmpsize, offset, file->f_dentry->d_inode->i_ino,
                       file->f_dentry->d_inode->i_size);

                rc = fsfilt_readpage(req->rq_export->exp_obd, file,
                                     page_address(pages[i]), tmpsize, &offset);

                if (rc != tmpsize)
                        GOTO(cleanup_buf, rc = -EIO);
        }

        rc = ptlrpc_bulk_put(desc);
        if (rc)
                GOTO(cleanup_buf, rc);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SENDPAGE)) {
                CERROR("obd_fail_loc=%x, fail operation rc=%d\n",
                       OBD_FAIL_MDS_SENDPAGE, rc);
                ptlrpc_abort_bulk(desc);
                GOTO(cleanup_buf, rc);
        }

        lwi = LWI_TIMEOUT(obd_timeout * HZ / 4, mds_bulk_timeout, desc);
        rc = l_wait_event(desc->bd_waitq, ptlrpc_bulk_complete (desc), &lwi);
        if (rc) {
                LASSERT (rc == -ETIMEDOUT);
                GOTO(cleanup_buf, rc);
        }

        EXIT;
 cleanup_buf:
        for (i = 0; i < npages; i++)
                if (pages[i])
                        __free_pages(pages[i], 0);

        ptlrpc_free_bulk(desc);
 out_free:
        OBD_FREE(pages, sizeof(*pages) * npages);
 out:
        return rc;
}

/* only valid locked dentries or errors should be returned */
struct dentry *mds_fid2locked_dentry(struct obd_device *obd, struct ll_fid *fid,
                                     struct vfsmount **mnt, int lock_mode,
                                     struct lustre_handle *lockh,
                                     char *name, int namelen)
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
                retval = ERR_PTR(-EIO); /* XXX translate ldlm code */
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

        CDEBUG(D_DENTRY, "--> mds_fid2dentry: ino/gen %lu/%u, sb %p\n",
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
                CERROR("bad inode %lu, link: %lu ct: %d or generation %u/%u\n",
                       inode->i_ino, (unsigned long)inode->i_nlink,
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
        struct mds_export_data *med; /*  */
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

        OBD_ALLOC(mcd, sizeof(*mcd));
        if (!mcd) {
                CERROR("mds: out of memory for client data\n");
                GOTO(out, rc = -ENOMEM);
        }

        memcpy(mcd->mcd_uuid, cluuid, sizeof(mcd->mcd_uuid));
        med->med_mcd = mcd;
        mcd->mcd_mount_count = cpu_to_le64(obd->u.mds.mds_mount_count);

        rc = mds_client_add(obd, &obd->u.mds, med, -1);
        if (rc == 0)
                EXIT;
out:
        if (rc) {
                OBD_FREE(mcd, sizeof(*mcd));
                class_disconnect(exp, 0);
        }
        class_export_put(exp);

        return rc;
}

static int mds_init_export(struct obd_export *exp) 
{
        struct mds_export_data *med = &exp->exp_mds_data;

        INIT_LIST_HEAD(&med->med_open_head);
        spin_lock_init(&med->med_open_lock);
        RETURN(0);
}

static int mds_destroy_export(struct obd_export *export)
{
        struct mds_export_data *med;
        struct obd_device *obd = export->exp_obd;
        struct obd_run_ctxt saved;
        int rc = 0;
        ENTRY;

        med = &export->exp_mds_data;
        target_destroy_export(export);

        push_ctxt(&saved, &obd->obd_ctxt, NULL);
        /* Close any open files (which may also cause orphan unlinking). */
        spin_lock(&med->med_open_lock);
        while (!list_empty(&med->med_open_head)) {
                struct list_head *tmp = med->med_open_head.next;
                struct mds_file_data *mfd =
                        list_entry(tmp, struct mds_file_data, mfd_list);
                BDEVNAME_DECLARE_STORAGE(btmp);

                /* bug 1579: fix force-closing for 2.5 */
                struct dentry *dentry = mfd->mfd_dentry;

                list_del(&mfd->mfd_list);
                spin_unlock(&med->med_open_lock);

                CERROR("force closing client file handle for %*s (%s:%lu)\n",
                       dentry->d_name.len, dentry->d_name.name,
                       ll_bdevname(dentry->d_inode->i_sb, btmp),
                       dentry->d_inode->i_ino);
                rc = mds_mfd_close(NULL, obd, mfd, 
                                   !(export->exp_flags & OBD_OPT_FAILOVER));

                if (rc)
                        CDEBUG(D_INODE, "Error closing file: %d\n", rc);
                spin_lock(&med->med_open_lock);
        }
        spin_unlock(&med->med_open_lock);
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);

        mds_client_free(export, !(export->exp_flags & OBD_OPT_FAILOVER));

        RETURN(rc);
}

static int mds_disconnect(struct obd_export *export, int flags)
{
        unsigned long irqflags;
        int rc;
        ENTRY;

        ldlm_cancel_locks_for_export(export);

        spin_lock_irqsave(&export->exp_lock, irqflags);
        export->exp_flags = flags;
        spin_unlock_irqrestore(&export->exp_lock, irqflags);

        rc = class_disconnect(export, flags);
        RETURN(rc);
}

static int mds_getstatus(struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_GETSTATUS_PACK)) {
                CERROR("mds: out of memory for message: size=%d\n", size);
                req->rq_status = -ENOMEM;       /* superfluous? */
                RETURN(-ENOMEM);
        }

        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*body));
        memcpy(&body->fid1, &mds->mds_rootfid, sizeof(body->fid1));

        /* the last_committed and last_xid fields are filled in for all
         * replies already - no need to do so here also.
         */
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

/* Call with lock=1 if you want mds_pack_md to take the i_sem.
 * Call with lock=0 if the caller has already taken the i_sem. */
int mds_pack_md(struct obd_device *obd, struct lustre_msg *msg, int offset,
                struct mds_body *body, struct inode *inode, int lock)
{
        struct mds_obd *mds = &obd->u.mds;
        void *lmm;
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
         * to reserve for the MD, it shouldn't be bad to have too much space.
         */
        if (lmm_size > mds->mds_max_mdsize) {
                CWARN("Reading MD for inode %lu of %d bytes > max %d\n",
                       inode->i_ino, lmm_size, mds->mds_max_mdsize);
                // RETURN(-EINVAL);
        }

        if (lock)
                down(&inode->i_sem);
        rc = fsfilt_get_md(obd, inode, lmm, lmm_size);
        if (lock)
                up(&inode->i_sem);
        if (rc < 0) {
                CERROR("Error %d reading eadata for ino %lu\n",
                       rc, inode->i_ino);
        } else if (rc > 0) {
                lmm_size = rc;
                rc = mds_convert_lov_ea(obd, inode, lmm, lmm_size);

                if (rc > 0)
                        lmm_size = rc;
                body->valid |= OBD_MD_FLEASIZE;
                body->eadatasize = lmm_size;
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
                rc = mds_pack_md(obd, req->rq_repmsg, reply_off + 1, body,
                                 inode, 1);

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
                int rc;
                down(&inode->i_sem);
                rc = fsfilt_get_md(req->rq_export->exp_obd, inode, NULL, 0);
                up(&inode->i_sem);
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

        rc = lustre_pack_reply(req, bufcount, size, NULL);
        if (rc) {
                CERROR("out of memory\n");
                GOTO(out, req->rq_status = rc);
        }

        EXIT;
 out:
        return(rc);
}

static int mds_getattr_name(int offset, struct ptlrpc_request *req,
                            struct lustre_handle *child_lockh)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct ldlm_reply *rep = NULL;
        struct obd_run_ctxt saved;
        struct mds_body *body;
        struct dentry *dparent = NULL, *dchild = NULL;
        struct obd_ucred uc;
        struct lustre_handle parent_lockh;
        int namesize;
        int rc = 0, cleanup_phase = 0, resent_req = 0;
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
        push_ctxt(&saved, &obd->obd_ctxt, &uc);
        cleanup_phase = 1; /* kernel context */
        intent_set_disposition(rep, DISP_LOOKUP_EXECD);

        /* FIXME: handle raw lookup */
#if 0
        if (body->valid == OBD_MD_FLID) {
                struct mds_body *mds_reply;
                int size = sizeof(*mds_reply);
                ino_t inum;
                // The user requested ONLY the inode number, so do a raw lookup
                rc = lustre_pack_reply(req, 1, &size, NULL);
                if (rc) {
                        CERROR("out of memory\n");
                        GOTO(cleanup, rc);
                }

                rc = dir->i_op->lookup_raw(dir, name, namesize - 1, &inum);

                mds_reply = lustre_msg_buf(req->rq_repmsg, offset,
                                           sizeof(*mds_reply));
                mds_reply->fid1.id = inum;
                mds_reply->valid = OBD_MD_FLID;
                GOTO(cleanup, rc);
        }
#endif

        if (child_lockh->cookie != 0) {
                LASSERT(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT);
                resent_req = 1;
        }

        if (resent_req == 0) {
                rc = mds_get_parent_child_locked(obd, &obd->u.mds, &body->fid1,
                                                 &parent_lockh, &dparent,
                                                 LCK_PR, name, namesize,
                                                 child_lockh, &dchild, LCK_PR);
                if (rc)
                        GOTO(cleanup, rc);
        } else {
                struct ldlm_lock *granted_lock;
                struct ll_fid child_fid;
                struct ldlm_resource *res;
                DEBUG_REQ(D_DLMTRACE, req, "resent, not enqueuing new locks");
                granted_lock = ldlm_handle2lock(child_lockh);
                LASSERT(granted_lock);

                res = granted_lock->l_resource;
                child_fid.id = res->lr_name.name[0];
                child_fid.generation = res->lr_name.name[1];
                dchild = mds_fid2dentry(&obd->u.mds, &child_fid, NULL);
                LASSERT(dchild);
                LDLM_LOCK_PUT(granted_lock);
        }

        cleanup_phase = 2; /* dchild, dparent, locks */

        if (dchild->d_inode == NULL) {
                intent_set_disposition(rep, DISP_LOOKUP_NEG);
                /* in the intent case, the policy clears this error:
                   the disposition is enough */
                GOTO(cleanup, rc = -ENOENT);
        } else {
                intent_set_disposition(rep, DISP_LOOKUP_POS);
        }

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
        case 2:
                if (resent_req == 0) {
                        if (rc && dchild->d_inode)
                                ldlm_lock_decref(child_lockh, LCK_PR);
                        ldlm_lock_decref(&parent_lockh, LCK_PR);
                        l_dput(dparent);
                }
                l_dput(dchild);
        case 1:
                pop_ctxt(&saved, &obd->obd_ctxt, &uc);
        default: ;
        }
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
        push_ctxt(&saved, &obd->obd_ctxt, &uc);
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
        pop_ctxt(&saved, &obd->obd_ctxt, &uc);
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

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_STATFS_PACK)) {
                CERROR("mds: statfs lustre_pack_reply failed: rc = %d\n", rc);
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

static int mds_sync(struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_obd *mds = &obd->u.mds;
        struct mds_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof(*body));
        if (body == NULL)
                GOTO(out, rc = -EPROTO);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_SYNC_PACK)) {
                CERROR("fsync lustre_pack_reply failed: rc = %d\n", rc);
                GOTO(out, rc);
        }

        if (body->fid1.id == 0) {
                /* a fid of zero is taken to mean "sync whole filesystem" */
                rc = fsfilt_sync(obd, mds->mds_sb);
                if (rc)
                        GOTO(out, rc);
        } else {
                /* just any file to grab fsync method - "file" arg unused */
                struct file *file = mds->mds_rcvd_filp;
                struct dentry *de;

                de = mds_fid2dentry(mds, &body->fid1, NULL);
                if (IS_ERR(de))
                        GOTO(out, rc = PTR_ERR(de));

                rc = file->f_op->fsync(NULL, de, 1);
                l_dput(de);
                if (rc)
                        GOTO(out, rc);

                body = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*body));
                mds_pack_inode2fid(&body->fid1, de->d_inode);
                mds_pack_inode2body(body, de->d_inode);
        }
out:
        req->rq_status = rc;
        return 0;
}

/* mds_readpage does not take a DLM lock on the inode, because the client must
 * already have a PR lock.
 *
 * If we were to take another one here, a deadlock will result, if another
 * thread is already waiting for a PW lock. */
static int mds_readpage(struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct vfsmount *mnt;
        struct dentry *de;
        struct file *file;
        struct mds_body *body, *repbody;
        struct obd_run_ctxt saved;
        int rc, size = sizeof(*repbody);
        struct obd_ucred uc;
        ENTRY;

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_READPAGE_PACK)) {
                CERROR("mds: out of memory\n");
                GOTO(out, rc = -ENOMEM);
        }

        body = lustre_swab_reqbuf(req, 0, sizeof(*body), lustre_swab_mds_body);
        if (body == NULL)
                GOTO (out, rc = -EFAULT);

        uc.ouc_fsuid = body->fsuid;
        uc.ouc_fsgid = body->fsgid;
        uc.ouc_cap = body->capability;
        push_ctxt(&saved, &obd->obd_ctxt, &uc);
        de = mds_fid2dentry(&obd->u.mds, &body->fid1, &mnt);
        if (IS_ERR(de))
                GOTO(out_pop, rc = PTR_ERR(de));

        CDEBUG(D_INODE, "ino %lu\n", de->d_inode->i_ino);

        file = dentry_open(de, mnt, O_RDONLY | O_LARGEFILE);
        /* note: in case of an error, dentry_open puts dentry */
        if (IS_ERR(file))
                GOTO(out_pop, rc = PTR_ERR(file));

        /* body->size is actually the offset -eeb */
        if ((body->size & (de->d_inode->i_blksize - 1)) != 0) {
                CERROR("offset "LPU64" not on a block boundary of %lu\n",
                       body->size, de->d_inode->i_blksize);
                GOTO(out_file, rc = -EFAULT);
        }

        /* body->nlink is actually the #bytes to read -eeb */
        if (body->nlink & (de->d_inode->i_blksize - 1)) {
                CERROR("size %u is not multiple of blocksize %lu\n",
                       body->nlink, de->d_inode->i_blksize);
                GOTO(out_file, rc = -EFAULT);
        }

        repbody = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*repbody));
        repbody->size = file->f_dentry->d_inode->i_size;
        repbody->valid = OBD_MD_FLSIZE;

        /* to make this asynchronous make sure that the handling function
           doesn't send a reply when this function completes. Instead a
           callback function would send the reply */
        /* body->size is actually the offset -eeb */
        rc = mds_sendpage(req, file, body->size, body->nlink);

out_file:
        filp_close(file, 0);
out_pop:
        pop_ctxt(&saved, &obd->obd_ctxt, &uc);
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

static int mds_filter_recovery_request(struct ptlrpc_request *req,
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
        case MDS_SYNC: /* used in unmounting */
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

int mds_handle(struct ptlrpc_request *req)
{
        int should_process;
        int rc = 0;
        struct mds_obd *mds = NULL; /* quell gcc overwarning */
        struct obd_device *obd = NULL;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_MDS_ALL_REQUEST_NET | OBD_FAIL_ONCE, 0);

        LASSERT(current->journal_info == NULL);
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
                        rc = mds_filter_recovery_request(req, obd,
                                                         &should_process);
                        if (rc || !should_process)
                                RETURN(rc);
                }
        }

        switch (req->rq_reqmsg->opc) {
        case MDS_CONNECT:
                DEBUG_REQ(D_INODE, req, "connect");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_CONNECT_NET, 0);
                rc = target_handle_connect(req, mds_handle);
                if (!rc)
                        /* Now that we have an export, set mds. */
                        mds = mds_req2mds(req);
                break;

        case MDS_DISCONNECT:
                DEBUG_REQ(D_INODE, req, "disconnect");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_DISCONNECT_NET, 0);
                rc = target_handle_disconnect(req);
                req->rq_status = rc;            /* superfluous? */
                break;

        case MDS_GETSTATUS:
                DEBUG_REQ(D_INODE, req, "getstatus");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_GETSTATUS_NET, 0);
                rc = mds_getstatus(req);
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
                /* this non-intent call (from an ioctl) is special */
                req->rq_status = rc;
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
                else if (opc == REINT_OPEN || opc == REINT_RENAME)
                        bufcount = 2;
                else
                        bufcount = 1;

                rc = lustre_pack_reply(req, bufcount, size, NULL);
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

        case MDS_DONE_WRITING:
                DEBUG_REQ(D_INODE, req, "done_writing");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_DONE_WRITING_NET, 0);
                rc = mds_done_writing(req);
                break;

        case MDS_PIN:
                DEBUG_REQ(D_INODE, req, "pin");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_PIN_NET, 0);
                rc = mds_pin(req);
                break;

        case MDS_SYNC:
                DEBUG_REQ(D_INODE, req, "sync");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_SYNC_NET, 0);
                rc = mds_sync(req);
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
        case LLOG_ORIGIN_HANDLE_CREATE:
                DEBUG_REQ(D_INODE, req, "llog_init");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_create(req);
                break;
        case LLOG_ORIGIN_HANDLE_NEXT_BLOCK:
                DEBUG_REQ(D_INODE, req, "llog next block");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_next_block(req);
                break;
        case LLOG_ORIGIN_HANDLE_READ_HEADER:
                DEBUG_REQ(D_INODE, req, "llog read header");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_read_header(req);
                break;
        case LLOG_ORIGIN_HANDLE_CLOSE:
                DEBUG_REQ(D_INODE, req, "llog close");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_close(req);
                break;
        case LLOG_CATINFO:
                DEBUG_REQ(D_INODE, req, "llog catinfo");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_catinfo(req);
                break;
        default:
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req);
                RETURN(rc);
        }

        LASSERT(current->journal_info == NULL);

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
int mds_update_server_data(struct obd_device *obd, int force_sync)
{
        struct mds_obd *mds = &obd->u.mds;
        struct mds_server_data *msd = mds->mds_server_data;
        struct file *filp = mds->mds_rcvd_filp;
        struct obd_run_ctxt saved;
        loff_t off = 0;
        int rc;
        ENTRY;

        push_ctxt(&saved, &obd->obd_ctxt, NULL);
        msd->msd_last_transno = cpu_to_le64(mds->mds_last_transno);

        CDEBUG(D_SUPER, "MDS mount_count is "LPU64", last_transno is "LPU64"\n",
               mds->mds_mount_count, mds->mds_last_transno);
        rc = fsfilt_write_record(obd, filp, msd, sizeof(*msd), &off,force_sync);
        if (rc)
                CERROR("error writing MDS server data: rc = %d\n", rc);
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);

        RETURN(rc);
}


/* mount the file system (secretly) */
static int mds_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg* lcfg = buf;
        struct mds_obd *mds = &obd->u.mds;
        struct vfsmount *mnt;
        int rc = 0;
        unsigned long page;
        ENTRY;

        dev_clear_rdonly(2);

        if (!lcfg->lcfg_inlbuf1 || !lcfg->lcfg_inlbuf2)
                RETURN(rc = -EINVAL);

        obd->obd_fsops = fsfilt_get_ops(lcfg->lcfg_inlbuf2);
        if (IS_ERR(obd->obd_fsops))
                RETURN(rc = PTR_ERR(obd->obd_fsops));

        if (!(page = __get_free_page(GFP_KERNEL)))
                RETURN(-ENOMEM);

        memset((void *)page, 0, PAGE_SIZE);
        sprintf((char *)page, "iopen_nopriv");

        mnt = do_kern_mount(lcfg->lcfg_inlbuf2, 0,
                            lcfg->lcfg_inlbuf1, (void *)page);
        free_page(page);
        if (IS_ERR(mnt)) {
                rc = PTR_ERR(mnt);
                CERROR("do_kern_mount failed: rc = %d\n", rc);
                GOTO(err_ops, rc);
        }

        CDEBUG(D_SUPER, "%s: mnt = %p\n", lcfg->lcfg_inlbuf1, mnt);

        sema_init(&mds->mds_orphan_recovery_sem, 1);
        sema_init(&mds->mds_epoch_sem, 1);
        spin_lock_init(&mds->mds_transno_lock);
        mds->mds_max_mdsize = sizeof(struct lov_mds_md);
        mds->mds_max_cookiesize = sizeof(struct llog_cookie);
        atomic_set(&mds->mds_open_count, 0);

        obd->obd_namespace = ldlm_namespace_new("mds_server",
                                                LDLM_NAMESPACE_SERVER);
        if (obd->obd_namespace == NULL) {
                mds_cleanup(obd, 0);
                GOTO(err_put, rc = -ENOMEM);
        }

        rc = mds_fs_setup(obd, mnt);
        if (rc) {
                CERROR("MDS filesystem method init failed: rc = %d\n", rc);
                GOTO(err_ns, rc);
        }

        rc = llog_start_commit_thread();
        if (rc < 0)
                GOTO(err_fs, rc);
        

        if (lcfg->lcfg_inllen3 > 0 && lcfg->lcfg_inlbuf3) {
                class_uuid_t uuid;

                generate_random_uuid(uuid);
                class_uuid_unparse(uuid, &mds->mds_lov_uuid);

                OBD_ALLOC(mds->mds_profile, lcfg->lcfg_inllen3);
                if (mds->mds_profile == NULL) 
                        GOTO(err_fs, rc = -ENOMEM);

                memcpy(mds->mds_profile, lcfg->lcfg_inlbuf3,
                       lcfg->lcfg_inllen3);

        } 

        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "mds_ldlm_client", &obd->obd_ldlm_client);
        obd->obd_replayable = 1;

        RETURN(0);

err_fs:
        /* No extra cleanup needed for llog_init_commit_thread() */
        mds_fs_cleanup(obd, 0);
err_ns:
        ldlm_namespace_free(obd->obd_namespace, 0);
        obd->obd_namespace = NULL;
err_put:
        unlock_kernel();
        mntput(mds->mds_vfsmnt);
        mds->mds_sb = 0;
        lock_kernel();
err_ops:
        fsfilt_put_ops(obd->obd_fsops);
        return rc;
}

static int mds_postsetup(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        int rc = 0;
        ENTRY;


        rc = llog_setup(obd, LLOG_CONFIG_ORIG_CTXT, obd, 0, NULL,
                        &llog_lvfs_ops);
        if (rc)
                RETURN(rc);

        if (mds->mds_profile) {
                struct obd_run_ctxt saved;
                struct lustre_profile *lprof;
                struct config_llog_instance cfg;

                cfg.cfg_instance = NULL;
                cfg.cfg_uuid = mds->mds_lov_uuid;
                push_ctxt(&saved, &obd->obd_ctxt, NULL);
                rc = class_config_parse_llog(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT), 
                                             mds->mds_profile, &cfg);
                pop_ctxt(&saved, &obd->obd_ctxt, NULL);
                if (rc)
                        GOTO(err_llog, rc);

                lprof = class_get_profile(mds->mds_profile);
                if (lprof == NULL) {
                        CERROR("No profile found: %s\n", mds->mds_profile);
                        GOTO(err_cleanup, rc = -ENOENT);
                }
                rc = mds_lov_connect(obd, lprof->lp_osc);
                if (rc)
                        GOTO(err_cleanup, rc);
        }

        RETURN(rc);

err_cleanup:
        mds_lov_clean(obd);
err_llog:
        llog_cleanup(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT));
        RETURN(rc);
}

static int mds_postrecov(struct obd_device *obd) 

{
        int rc, rc2;

        LASSERT(!obd->obd_recovering);

#ifdef ENABLE_ORPHANS
        rc = llog_connect(llog_get_context(obd, LLOG_UNLINK_ORIG_CTXT),
                          obd->u.mds.mds_lov_desc.ld_tgt_count, NULL, NULL);
        if (rc != 0) {
                CERROR("faild at llog_origin_connect: %d\n", rc);
        }
#endif
        rc = mds_cleanup_orphans(obd);

        rc2 = mds_lov_set_nextid(obd);
        if (rc2 == 0)
                rc2 = rc;
        RETURN(rc2);
}

int mds_lov_clean(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;

        if (mds->mds_profile) {
                char * cln_prof;
                struct config_llog_instance cfg;
                struct obd_run_ctxt saved;
                int len = strlen(mds->mds_profile) + sizeof("-clean") + 1;

                OBD_ALLOC(cln_prof, len);
                sprintf(cln_prof, "%s-clean", mds->mds_profile);

                cfg.cfg_instance = NULL;
                cfg.cfg_uuid = mds->mds_lov_uuid;

                push_ctxt(&saved, &obd->obd_ctxt, NULL);
                class_config_parse_llog(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT), 
                                        cln_prof, &cfg);
                pop_ctxt(&saved, &obd->obd_ctxt, NULL);

                OBD_FREE(cln_prof, len);
                OBD_FREE(mds->mds_profile, strlen(mds->mds_profile) + 1);
                mds->mds_profile = NULL;
        }
        RETURN(0);
}

static int mds_precleanup(struct obd_device *obd, int flags)
{
        int rc = 0;
        ENTRY;

        mds_lov_disconnect(obd, flags);
        mds_lov_clean(obd);
        llog_cleanup(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT));
        RETURN(rc);
}

static int mds_cleanup(struct obd_device *obd, int flags)
{
        struct mds_obd *mds = &obd->u.mds;
        ENTRY;

        if (mds->mds_sb == NULL)
                RETURN(0);

        mds_update_server_data(obd, 1);
        if (mds->mds_lov_objids != NULL) {
                OBD_FREE(mds->mds_lov_objids,
                         mds->mds_lov_desc.ld_tgt_count * sizeof(obd_id));
        }
        mds_fs_cleanup(obd, flags);

        unlock_kernel();

        /* 2 seems normal on mds, (may_umount() also expects 2
          fwiw), but we only see 1 at this point in obdfilter. */
        if (atomic_read(&obd->u.mds.mds_vfsmnt->mnt_count) > 2)
                CERROR("%s: mount busy, mnt_count %d != 2\n", obd->obd_name,
                       atomic_read(&obd->u.mds.mds_vfsmnt->mnt_count));

        mntput(mds->mds_vfsmnt);

        mds->mds_sb = 0;

        ldlm_namespace_free(obd->obd_namespace, flags & OBD_OPT_FORCE);

        if (obd->obd_recovering)
                target_cancel_recovery_timer(obd);
        lock_kernel();
        dev_clear_rdonly(2);
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

        /* This remote handle isn't enqueued, so we never received or
         * processed this request.  Clear MSG_RESENT, because it can
         * be handled like any normal request now. */

        lustre_msg_clear_flags(req->rq_reqmsg, MSG_RESENT);
        
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
        int rc;
        ENTRY;

        if (!req_cookie)
                RETURN(0);

        if (req->rq_reqmsg->bufcount > 1) {
                /* an intent needs to be considered */
                struct ldlm_intent *it;
                struct mds_obd *mds = &req->rq_export->exp_obd->u.mds;
                struct ldlm_reply *rep;
                struct lustre_handle lockh = { 0 };
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

                rc = lustre_pack_reply(req, it->opc == IT_UNLINK ? 4 : 3,
                                       repsize, NULL);
                if (rc)
                        RETURN(req->rq_status = rc);

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
#if 0
                        /* We abort the lock if the lookup was negative and
                         * we did not make it to the OPEN portion */
                        if (!intent_disposition(rep, DISP_LOOKUP_EXECD))
                                RETURN(ELDLM_LOCK_ABORTED);
                        if (intent_disposition(rep, DISP_LOOKUP_NEG) &&
                            !intent_disposition(rep, DISP_OPEN_OPEN))
#endif 
                                RETURN(ELDLM_LOCK_ABORTED);
                        break;
                case IT_GETATTR:
                case IT_LOOKUP:
                case IT_READDIR:
                        rep->lock_policy_res2 = mds_getattr_name(offset, req,
                                                                 &lockh);
                        /* FIXME: LDLM can set req->rq_status. MDS sets
                           policy_res{1,2} with disposition and status.
                           - replay: returns 0 & req->status is old status 
                           - otherwise: returns req->status */
                        if (intent_disposition(rep, DISP_LOOKUP_NEG))
                                rep->lock_policy_res2 = 0;
                        if (!intent_disposition(rep, DISP_LOOKUP_POS) || 
                            rep->lock_policy_res2)
                                RETURN(ELDLM_LOCK_ABORTED);
                        if (req->rq_status != 0) {
                                LBUG();
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
                if (new_lock == NULL && (flags & LDLM_FL_INTENT_ONLY))
                        RETURN(0);
                
                LASSERT(new_lock != NULL);

                /* If we've already given this lock to a client once, then we
                 * should have no readers or writers.  Otherwise, we should
                 * have one reader _or_ writer ref (which will be zeroed below)
                 * before returning the lock to a client.
                 */
                if (new_lock->l_export == req->rq_export) {
                        LASSERT(new_lock->l_readers + new_lock->l_writers == 0);
                } else {
                        LASSERT(new_lock->l_export == NULL);
                        LASSERT(new_lock->l_readers + new_lock->l_writers == 1);
                }

                *lockp = new_lock;

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

                new_lock->l_export = class_export_get(req->rq_export);
                list_add(&new_lock->l_export_chain,
                         &new_lock->l_export->exp_ldlm_data.led_held_locks);

                new_lock->l_blocking_ast = lock->l_blocking_ast;
                new_lock->l_completion_ast = lock->l_completion_ast;

                memcpy(&new_lock->l_remote_handle, &lock->l_remote_handle,
                       sizeof(lock->l_remote_handle));

                new_lock->l_flags &= ~LDLM_FL_LOCAL;

                LDLM_LOCK_PUT(new_lock);
                l_unlock(&new_lock->l_resource->lr_namespace->ns_lock);

                RETURN(ELDLM_LOCK_REPLACED);
        } else {
                int size = sizeof(struct ldlm_reply);
                rc = lustre_pack_reply(req, 1, &size, NULL);
                if (rc) {
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
        int rc = 0;
        ENTRY;

        mds->mds_service = ptlrpc_init_svc(MDS_NEVENTS, MDS_NBUFS,
                                           MDS_BUFSIZE, MDS_MAXREQSIZE,
                                           MDS_REQUEST_PORTAL, MDC_REPLY_PORTAL,
                                           mds_handle, "mds", 
                                           obddev->obd_proc_entry);

        if (!mds->mds_service) {
                CERROR("failed to start service\n");
                RETURN(rc = -ENOMEM);
        }

        rc = ptlrpc_start_n_threads(obddev, mds->mds_service, MDT_NUM_THREADS,
                                    "ll_mdt");
        if (rc)
                GOTO(err_thread, rc);

        mds->mds_setattr_service =
                ptlrpc_init_svc(MDS_NEVENTS, MDS_NBUFS,
                                MDS_BUFSIZE, MDS_MAXREQSIZE,
                                MDS_SETATTR_PORTAL, MDC_REPLY_PORTAL,
                                mds_handle, "mds_setattr", 
                                obddev->obd_proc_entry);
        if (!mds->mds_setattr_service) {
                CERROR("failed to start getattr service\n");
                GOTO(err_thread, rc = -ENOMEM);
        }

        rc = ptlrpc_start_n_threads(obddev, mds->mds_setattr_service,
                                 MDT_NUM_THREADS, "ll_mdt_attr");
        if (rc)
                GOTO(err_thread2, rc);
                        
        mds->mds_readpage_service =
                ptlrpc_init_svc(MDS_NEVENTS, MDS_NBUFS,
                                MDS_BUFSIZE, MDS_MAXREQSIZE,
                                MDS_READPAGE_PORTAL, MDC_REPLY_PORTAL,
                                mds_handle, "mds_readpage", 
                                obddev->obd_proc_entry);
        if (!mds->mds_readpage_service) {
                CERROR("failed to start readpage service\n");
                GOTO(err_thread2, rc = -ENOMEM);
        }

        rc = ptlrpc_start_n_threads(obddev, mds->mds_readpage_service,
                                    MDT_NUM_THREADS, "ll_mdt_rdpg");

        if (rc) 
                GOTO(err_thread3, rc);

        RETURN(0);

err_thread3:
        ptlrpc_unregister_service(mds->mds_readpage_service);
err_thread2:
        ptlrpc_unregister_service(mds->mds_setattr_service);
err_thread:
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

static struct dentry *mds_lvfs_fid2dentry(__u64 id, __u32 gen, __u64 gr, void *data)
{
        struct obd_device *obd = data;
        struct ll_fid fid;
        fid.id = id;
        fid.generation = gen;
        return mds_fid2dentry(&obd->u.mds, &fid, NULL);
}

struct lvfs_callback_ops mds_lvfs_ops = {
        l_fid2dentry:     mds_lvfs_fid2dentry,
};

/* use obd ops to offer management infrastructure */
static struct obd_ops mds_obd_ops = {
        o_owner:       THIS_MODULE,
        o_attach:      mds_attach,
        o_detach:      mds_detach,
        o_connect:     mds_connect,
        o_init_export:  mds_init_export,
        o_destroy_export:  mds_destroy_export,
        o_disconnect:  mds_disconnect,
        o_setup:       mds_setup,
        o_postsetup:   mds_postsetup,
        o_precleanup:  mds_precleanup,
        o_cleanup:     mds_cleanup,
        o_postrecov:   mds_postrecov,
        o_statfs:      mds_obd_statfs,
        o_iocontrol:   mds_iocontrol,
        o_create:      mds_obd_create,
        o_destroy:     mds_obd_destroy,
        o_llog_init:   mds_llog_init,
        o_llog_finish: mds_llog_finish,
        o_notify:      mds_notify,
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
