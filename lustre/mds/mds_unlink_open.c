/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mds/mds_orphan.c
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
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

/* code for handling open unlinked files */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>

#include <portals/list.h>
#include <linux/obd_class.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_commit_confd.h>
#include <linux/lvfs.h>

#include "mds_internal.h"


/* If we are unlinking an open file/dir (i.e. creating an orphan) then
 * we instead link the inode into the PENDING directory until it is
 * finally released.  We can't simply call mds_reint_rename() or some
 * part thereof, because we don't have the inode to check for link
 * count/open status until after it is locked.
 *
 * For lock ordering, we always get the PENDING, then pending_child lock
 * last to avoid deadlocks.
 */

int mds_open_unlink_rename(struct mds_update_record *rec,
                           struct obd_device *obd, struct dentry *dparent,
                           struct dentry *dchild, void **handle)
{
        struct mds_obd *mds = &obd->u.mds;
        struct inode *pending_dir = mds->mds_pending_dir->d_inode;
        struct dentry *pending_child;
        char fidname[LL_FID_NAMELEN];
        int fidlen = 0, rc;
        ENTRY;

        LASSERT(!mds_inode_is_orphan(dchild->d_inode));

        down(&pending_dir->i_sem);
        fidlen = ll_fid2str(fidname, dchild->d_inode->i_ino,
                            dchild->d_inode->i_generation);

        CWARN("pending destroy of %dx open file %s = %s\n",
              mds_open_orphan_count(dchild->d_inode),
              rec->ur_name, fidname);

        pending_child = lookup_one_len(fidname, mds->mds_pending_dir, fidlen);
        if (IS_ERR(pending_child))
                GOTO(out_lock, rc = PTR_ERR(pending_child));

        if (pending_child->d_inode != NULL) {
                CERROR("re-destroying orphan file %s?\n", rec->ur_name);
                LASSERT(pending_child->d_inode == dchild->d_inode);
                GOTO(out_dput, rc = 0);
        }

        *handle = fsfilt_start(obd, pending_dir, FSFILT_OP_RENAME, NULL);
        if (IS_ERR(*handle))
                GOTO(out_dput, rc = PTR_ERR(*handle));

        lock_kernel();
        rc = vfs_rename(dparent->d_inode, dchild, pending_dir, pending_child);
        unlock_kernel();
        if (rc)
                CERROR("error renaming orphan %lu/%s to PENDING: rc = %d\n",
                       dparent->d_inode->i_ino, rec->ur_name, rc);
        else
                mds_inode_set_orphan(dchild->d_inode);
out_dput:
        dput(pending_child);
out_lock:
        up(&pending_dir->i_sem);
        RETURN(rc);
}

static int mds_osc_destroy_orphan(struct mds_obd *mds, 
                                  struct ptlrpc_request *request)
{
        struct mds_body *body;
        struct lov_mds_md *lmm = NULL;
        struct lov_stripe_md *lsm = NULL;
        struct obd_trans_info oti = { 0 };
        struct obdo *oa;
        int rc;
        ENTRY;

        body = lustre_msg_buf(request->rq_repmsg, 0, sizeof(*body));
        if (!(body->valid & OBD_MD_FLEASIZE))
                RETURN(0);
        if (body->eadatasize == 0) {
                CERROR("OBD_MD_FLEASIZE set but eadatasize zero\n");
                RETURN(rc = -EPROTO); 
        }

        lmm = lustre_msg_buf(request->rq_repmsg, 1, body->eadatasize);
        LASSERT(lmm != NULL);

        rc = obd_unpackmd(mds->mds_osc_exp, &lsm, lmm, body->eadatasize);
        if (rc < 0) {
                CERROR("Error unpack md %p\n", lmm);
                RETURN(rc);
        } else {
                LASSERT(rc >= sizeof(*lsm));
                rc = 0;
        }

        oa = obdo_alloc();
        if (oa == NULL)
                GOTO(out_free_memmd, rc = -ENOMEM);
        oa->o_id = lsm->lsm_object_id;
        oa->o_mode = body->mode & S_IFMT;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE;

        if (body->valid & OBD_MD_FLCOOKIE) {
                oa->o_valid |= OBD_MD_FLCOOKIE;
                oti.oti_logcookies = 
                        lustre_msg_buf(request->rq_repmsg, 2,
                                       sizeof(struct llog_cookie) *
                                       lsm->lsm_stripe_count);
                if (oti.oti_logcookies == NULL)
                        oa->o_valid &= ~OBD_MD_FLCOOKIE;
                        body->valid &= ~OBD_MD_FLCOOKIE;
        }

        rc = obd_destroy(mds->mds_osc_exp, oa, lsm, &oti);
        obdo_free(oa);
        if (rc) 
                CERROR("destroy orphan objid 0x"LPX64" on ost error "
                       "%d\n", lsm->lsm_object_id, rc);
out_free_memmd:
        obd_free_memmd(mds->mds_osc_exp, &lsm);
        RETURN(rc);
}

static int mds_unlink_orphan(struct obd_device *obd, struct dentry *dchild,
                             struct inode *inode, struct inode *pending_dir)
{
        struct mds_obd *mds = &obd->u.mds;
        struct mds_body *body;
        void *handle = NULL;
        struct ptlrpc_request *req;
        int lengths[3] = {sizeof(struct mds_body),
                          mds->mds_max_mdsize,
                          mds->mds_max_cookiesize};
        int rc;
        ENTRY;

        LASSERT(mds->mds_osc_obd != NULL);
        OBD_ALLOC(req, sizeof(*req));
        if (!req) {
                CERROR("request allocation out of memory\n");
                GOTO(err_alloc_req, rc = -ENOMEM);
        }
        rc = lustre_pack_reply(req, 3, lengths, NULL);
        if (rc) {
                CERROR("cannot pack request %d\n", rc);
                GOTO(out_free_req, rc);
        }
        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*body));
        LASSERT(body != NULL);

        mds_pack_inode2body(body, inode);
        mds_pack_md(obd, req->rq_repmsg, 1, body, inode, 1);

        handle = fsfilt_start(obd, pending_dir, FSFILT_OP_UNLINK_LOG, NULL);
        if (IS_ERR(handle)) {
                rc = PTR_ERR(handle);
                CERROR("error fsfilt_start: %d\n", rc);
                handle = NULL;
                GOTO(out_free_msg, rc);
        }

        if (S_ISDIR(inode->i_mode)) {
                rc = vfs_rmdir(pending_dir, dchild);
        } else {
                rc = vfs_unlink(pending_dir, dchild);
        }
        if (rc) 
                CERROR("error %d unlinking orphan %*s from PENDING directory\n",
                       rc, dchild->d_name.len, dchild->d_name.name);

        if ((body->valid & OBD_MD_FLEASIZE)) {
                if (mds_log_op_unlink(obd, inode, req->rq_repmsg, 1) > 0)
                        body->valid |= OBD_MD_FLCOOKIE;
        }

        if (handle) {
                int err = fsfilt_commit(obd, pending_dir, handle, 0);
                if (err) {
                        CERROR("error committing orphan unlink: %d\n", err);
                        rc = err;
                        GOTO(out_free_msg, rc);
                }
        }
        rc = mds_osc_destroy_orphan(mds, req);
out_free_msg:
        OBD_FREE(req->rq_repmsg, req->rq_replen);
        req->rq_repmsg = NULL;
out_free_req:
        OBD_FREE(req, sizeof(*req));
err_alloc_req:
        RETURN(rc);
}

int mds_cleanup_orphans(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_run_ctxt saved;
        struct file *file;
        struct dentry *dchild;
        struct inode *child_inode, *pending_dir = mds->mds_pending_dir->d_inode;
        struct l_linux_dirent *dirent, *ptr;
        unsigned int count = pending_dir->i_size;
        int rc = 0, rc2 = 0, item = 0;
        ENTRY;

        push_ctxt(&saved, &obd->obd_ctxt, NULL);
        dget(mds->mds_pending_dir);
        mntget(mds->mds_vfsmnt);
        file = dentry_open(mds->mds_pending_dir, mds->mds_vfsmnt,
                           O_RDONLY | O_LARGEFILE);
        if (IS_ERR(file))
                GOTO(err_open, rc2 = PTR_ERR(file));

        OBD_ALLOC(dirent, count);
        if (dirent == NULL)
                GOTO(err_alloc_dirent, rc2 = -ENOMEM);

        rc = l_readdir(file, dirent, count);
        filp_close(file, 0);
        if (rc < 0)
                GOTO(err_out, rc2 = rc);

        for (ptr = dirent; (char *)ptr < (char *)dirent + rc;
                        (char *)ptr += ptr->d_reclen) {
                int namlen = strlen(ptr->d_name);

                if (((namlen == 1) && !strcmp(ptr->d_name, ".")) ||
                    ((namlen == 2) && !strcmp(ptr->d_name, "..")))
                        continue;

                down(&pending_dir->i_sem);
                dchild = lookup_one_len(ptr->d_name, mds->mds_pending_dir,
                                        namlen);
                if (IS_ERR(dchild)) {
                        up(&pending_dir->i_sem);
                        GOTO(err_out, rc2 = PTR_ERR(dchild));
                }
                if (!dchild->d_inode) {
                        CDEBUG(D_ERROR, "orphan %s has been removed\n",
                               ptr->d_name);
                        GOTO(next, rc2 = 0);
                }

                child_inode = dchild->d_inode;
                if (mds_inode_is_orphan(child_inode) &&
                    mds_open_orphan_count(child_inode)) {
                        CWARN("orphan %s was re-opened during recovery\n", 
                              ptr->d_name);
                        GOTO(next, rc2 = 0);
                }

                rc2 = mds_unlink_orphan(obd, dchild, child_inode, pending_dir);
                if (rc2 == 0) {
                        item ++;
                        CWARN("removed orphan %s from MDS and OST\n",
                               ptr->d_name);
                } else {
                        l_dput(dchild); 
                        up(&pending_dir->i_sem);
                        GOTO(err_out, rc2);
                }
next:
                l_dput(dchild);
                up(&pending_dir->i_sem);
        }
err_out:
        OBD_FREE(dirent, count);
err_pop:
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);
        if (rc2 == 0)
                rc2 = item;

        RETURN(rc2);

err_open:
        mntput(mds->mds_vfsmnt);
        l_dput(mds->mds_pending_dir);
        goto err_pop;
err_alloc_dirent:
        filp_close(file, 0);
        goto err_pop;
}
