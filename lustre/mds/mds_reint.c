/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/mds_reint.c
 *  Lustre Metadata Server (mds) reintegration routines
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/fs.h>
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_fsfilt.h>

#include "mds_internal.h"

void mds_commit_cb(struct obd_device *obd, __u64 transno, void *data,
                   int error)
{
        obd_transno_commit_cb(obd, transno, error);
}

struct mds_logcancel_data {
        struct lov_mds_md      *mlcd_lmm;
        int                     mlcd_size;
        int                     mlcd_cookielen;
        int                     mlcd_eadatalen;
        struct llog_cookie      mlcd_cookies[0];
};


static void mds_cancel_cookies_cb(struct obd_device *obd, __u64 transno,
                                  void *cb_data, int error)
{
        struct mds_logcancel_data *mlcd = cb_data;
        struct lov_stripe_md *lsm = NULL;
#ifdef ENABLE_ORPHANS
        struct llog_ctxt *ctxt;
#endif
        int rc;

        obd_transno_commit_cb(obd, transno, error);

        CDEBUG(D_HA, "cancelling %d cookies\n",
               (int)(mlcd->mlcd_cookielen / sizeof(*mlcd->mlcd_cookies)));

        rc = obd_unpackmd(obd->u.mds.mds_osc_exp, &lsm, mlcd->mlcd_lmm,
                          mlcd->mlcd_eadatalen);
        if (rc < 0) {
                CERROR("bad LSM cancelling %d log cookies: rc %d\n",
                       (int)(mlcd->mlcd_cookielen/sizeof(*mlcd->mlcd_cookies)),
                       rc);
        } else {
#ifdef ENABLE_ORPHANS
                ///* XXX 0 normally, SENDNOW for debug */);
                ctxt = llog_get_context(obd, mlcd->mlcd_cookies[0].lgc_subsys + 1);
                rc = llog_cancel(ctxt, lsm,
                                         mlcd->mlcd_cookielen /
                                         sizeof(*mlcd->mlcd_cookies),
                                         mlcd->mlcd_cookies, OBD_LLOG_FL_SENDNOW);
                if (rc)
                        CERROR("error cancelling %d log cookies: rc %d\n",
                               (int)(mlcd->mlcd_cookielen /
                                     sizeof(*mlcd->mlcd_cookies)), rc);
#endif
        }

        OBD_FREE(mlcd, mlcd->mlcd_size);
}

/* Assumes caller has already pushed us into the kernel context. */
int mds_finish_transno(struct mds_obd *mds, struct inode *inode, void *handle,
                       struct ptlrpc_request *req, int rc, __u32 op_data)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_client_data *mcd = med->med_mcd;
        struct obd_device *obd = req->rq_export->exp_obd;
        int err;
        __u64 transno;
        loff_t off;
        int log_pri = D_HA;
        ENTRY;

        /* if the export has already been failed, we have no last_rcvd slot */
        if (req->rq_export->exp_failed) {
                CERROR("committing transaction for disconnected client\n");
                if (handle)
                        GOTO(commit, rc);
                RETURN(rc);
        }

        if (IS_ERR(handle))
                RETURN(rc);

        if (handle == NULL) {
                /* if we're starting our own xaction, use our own inode */
                inode = mds->mds_rcvd_filp->f_dentry->d_inode;
                handle = fsfilt_start(obd, inode, FSFILT_OP_SETATTR, NULL);
                if (IS_ERR(handle)) {
                        CERROR("fsfilt_start: %ld\n", PTR_ERR(handle));
                        RETURN(PTR_ERR(handle));
                }
        }

        off = med->med_off;

        transno = req->rq_reqmsg->transno;
        if (transno == 0) {
                spin_lock(&mds->mds_transno_lock);
                transno = ++mds->mds_last_transno;
                spin_unlock(&mds->mds_transno_lock);
        } else {
                spin_lock(&mds->mds_transno_lock);
                if (transno > mds->mds_last_transno)
                        mds->mds_last_transno = transno;
                spin_unlock(&mds->mds_transno_lock);
        }
        req->rq_repmsg->transno = req->rq_transno = transno;
        mcd->mcd_last_transno = cpu_to_le64(transno);
        mcd->mcd_mount_count = cpu_to_le64(mds->mds_mount_count);
        mcd->mcd_last_xid = cpu_to_le64(req->rq_xid);
        mcd->mcd_last_result = cpu_to_le32(rc);
        mcd->mcd_last_data = cpu_to_le32(op_data);

        fsfilt_add_journal_cb(req->rq_export->exp_obd, transno, handle,
                              mds_commit_cb, NULL);
        err = fsfilt_write_record(obd, mds->mds_rcvd_filp, mcd, sizeof(*mcd),
                                  &off, 0);

        if (err) {
                log_pri = D_ERROR;
                if (rc == 0)
                        rc = err;
        }

        DEBUG_REQ(log_pri, req,
                  "wrote trans #"LPU64" client %s at idx %u: err = %d\n",
                  transno, mcd->mcd_uuid, med->med_idx, err);

        err = mds_lov_write_objids(obd);
        if (err) {
                log_pri = D_ERROR;
                if (rc == 0)
                        rc = err;
        }
        CDEBUG(log_pri, "wrote objids: err = %d\n", err);

commit:
        err = fsfilt_commit(obd, inode, handle, 0);
        if (err) {
                CERROR("error committing transaction: %d\n", err);
                if (!rc)
                        rc = err;
        }

        RETURN(rc);
}

/* this gives the same functionality as the code between
 * sys_chmod and inode_setattr
 * chown_common and inode_setattr
 * utimes and inode_setattr
 */
int mds_fix_attr(struct inode *inode, struct mds_update_record *rec)
{
        time_t now = LTIME_S(CURRENT_TIME);
        struct iattr *attr = &rec->ur_iattr;
        unsigned int ia_valid = attr->ia_valid;
        int error;
        ENTRY;

        /* only fix up attrs if the client VFS didn't already */
        if (!(ia_valid & ATTR_RAW))
                RETURN(0);

        if (!(ia_valid & ATTR_CTIME_SET))
                LTIME_S(attr->ia_ctime) = now;
        if (!(ia_valid & ATTR_ATIME_SET))
                LTIME_S(attr->ia_atime) = now;
        if (!(ia_valid & ATTR_MTIME_SET))
                LTIME_S(attr->ia_mtime) = now;

        if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
                RETURN(-EPERM);

        /* times */
        if ((ia_valid & (ATTR_MTIME|ATTR_ATIME)) == (ATTR_MTIME|ATTR_ATIME)) {
                if (rec->ur_fsuid != inode->i_uid &&
                    (error = ll_permission(inode, MAY_WRITE, NULL)) != 0)
                        RETURN(error);
        }

        if (ia_valid & ATTR_SIZE) {
                if ((error = ll_permission(inode, MAY_WRITE, NULL)) != 0)
                        RETURN(error);
        }

        if (ia_valid & ATTR_UID) {
                /* chown */
                error = -EPERM;
                if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
                        RETURN(-EPERM);
                if (attr->ia_uid == (uid_t) -1)
                        attr->ia_uid = inode->i_uid;
                if (attr->ia_gid == (gid_t) -1)
                        attr->ia_gid = inode->i_gid;
                attr->ia_mode = inode->i_mode;
                /*
                 * If the user or group of a non-directory has been
                 * changed by a non-root user, remove the setuid bit.
                 * 19981026 David C Niemi <niemi@tux.org>
                 *
                 * Changed this to apply to all users, including root,
                 * to avoid some races. This is the behavior we had in
                 * 2.0. The check for non-root was definitely wrong
                 * for 2.2 anyway, as it should have been using
                 * CAP_FSETID rather than fsuid -- 19990830 SD.
                 */
                if ((inode->i_mode & S_ISUID) == S_ISUID &&
                    !S_ISDIR(inode->i_mode)) {
                        attr->ia_mode &= ~S_ISUID;
                        attr->ia_valid |= ATTR_MODE;
                }
                /*
                 * Likewise, if the user or group of a non-directory
                 * has been changed by a non-root user, remove the
                 * setgid bit UNLESS there is no group execute bit
                 * (this would be a file marked for mandatory
                 * locking).  19981026 David C Niemi <niemi@tux.org>
                 *
                 * Removed the fsuid check (see the comment above) --
                 * 19990830 SD.
                 */
                if (((inode->i_mode & (S_ISGID | S_IXGRP)) ==
                     (S_ISGID | S_IXGRP)) && !S_ISDIR(inode->i_mode)) {
                        attr->ia_mode &= ~S_ISGID;
                        attr->ia_valid |= ATTR_MODE;
                }
        } else if (ia_valid & ATTR_MODE) {
                int mode = attr->ia_mode;
                /* chmod */
                if (attr->ia_mode == (mode_t) -1)
                        attr->ia_mode = inode->i_mode;
                attr->ia_mode =
                        (mode & S_IALLUGO) | (inode->i_mode & ~S_IALLUGO);
        }
        RETURN(0);
}

void mds_req_from_mcd(struct ptlrpc_request *req, struct mds_client_data *mcd)
{
        DEBUG_REQ(D_HA, req, "restoring transno "LPD64"/status %d",
                  mcd->mcd_last_transno, mcd->mcd_last_result);
        req->rq_repmsg->transno = req->rq_transno = mcd->mcd_last_transno;
        req->rq_repmsg->status = req->rq_status = mcd->mcd_last_result;

        if (req->rq_export->exp_outstanding_reply)
                mds_steal_ack_locks(req->rq_export, req);
}

static void reconstruct_reint_setattr(struct mds_update_record *rec,
                                      int offset, struct ptlrpc_request *req)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_obd *obd = &req->rq_export->exp_obd->u.mds;
        struct dentry *de;
        struct mds_body *body;

        mds_req_from_mcd(req, med->med_mcd);

        if (req->rq_export->exp_outstanding_reply)
                mds_steal_ack_locks(req->rq_export, req);

        de = mds_fid2dentry(obd, rec->ur_fid1, NULL);
        if (IS_ERR(de)) {
                LASSERT(PTR_ERR(de) == req->rq_status);
                return;
        }

        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*body));
        mds_pack_inode2fid(&body->fid1, de->d_inode);
        mds_pack_inode2body(body, de->d_inode);

        /* Don't return OST-specific attributes if we didn't just set them */
        if (rec->ur_iattr.ia_valid & ATTR_SIZE)
                body->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
        if (rec->ur_iattr.ia_valid & (ATTR_MTIME | ATTR_MTIME_SET))
                body->valid |= OBD_MD_FLMTIME;
        if (rec->ur_iattr.ia_valid & (ATTR_ATIME | ATTR_ATIME_SET))
                body->valid |= OBD_MD_FLATIME;

        l_dput(de);
}

/* In the raw-setattr case, we lock the child inode.
 * In the write-back case or if being called from open, the client holds a lock
 * already.
 *
 * We use the ATTR_FROM_OPEN flag to tell these cases apart. */
static int mds_reint_setattr(struct mds_update_record *rec, int offset,
                             struct ptlrpc_request *req,
                             struct lustre_handle *lh)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_body *body;
        struct dentry *de;
        struct inode *inode = NULL;
        struct lustre_handle lockh;
        void *handle = NULL;
        struct mds_logcancel_data *mlcd = NULL;
        int rc = 0, cleanup_phase = 0, err, locked = 0;
        ENTRY;

        LASSERT(offset == 0);

        MDS_CHECK_RESENT(req, reconstruct_reint_setattr(rec, offset, req));

        if (rec->ur_iattr.ia_valid & ATTR_FROM_OPEN) {
                de = mds_fid2dentry(mds, rec->ur_fid1, NULL);
                if (IS_ERR(de))
                        GOTO(cleanup, rc = PTR_ERR(de));
        } else {
                de = mds_fid2locked_dentry(obd, rec->ur_fid1, NULL, LCK_PW,
                                           &lockh, NULL, 0);
                if (IS_ERR(de))
                        GOTO(cleanup, rc = PTR_ERR(de));
                locked = 1;
        }

        cleanup_phase = 1;
        inode = de->d_inode;
        LASSERT(inode);
        if (S_ISREG(inode->i_mode) && rec->ur_eadata != NULL)
                down(&inode->i_sem);

        CDEBUG(D_INODE, "ino %lu\n", inode->i_ino);
        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_SETATTR_WRITE, inode->i_sb);

        handle = fsfilt_start(obd, inode, FSFILT_OP_SETATTR, NULL);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));

        if (rec->ur_iattr.ia_valid & (ATTR_MTIME | ATTR_CTIME))
                CDEBUG(D_INODE, "setting mtime %lu, ctime %lu\n",
                       LTIME_S(rec->ur_iattr.ia_mtime),
                       LTIME_S(rec->ur_iattr.ia_ctime));
        rc = mds_fix_attr(inode, rec);
        if (rc)
                GOTO(cleanup, rc);

        if (rec->ur_iattr.ia_valid & ATTR_ATTR_FLAG)    /* ioctl */
                rc = fsfilt_iocontrol(obd, inode, NULL, EXT3_IOC_SETFLAGS,
                                      (long)&rec->ur_iattr.ia_attr_flags);
        else                                            /* setattr */
                rc = fsfilt_setattr(obd, de, handle, &rec->ur_iattr, 0);

        if (rc == 0 && S_ISREG(inode->i_mode) && rec->ur_eadata != NULL) {
                rc = fsfilt_set_md(obd, inode, handle,
                                   rec->ur_eadata, rec->ur_eadatalen);
        }

        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*body));
        mds_pack_inode2fid(&body->fid1, inode);
        mds_pack_inode2body(body, inode);

        /* Don't return OST-specific attributes if we didn't just set them */
        if (rec->ur_iattr.ia_valid & ATTR_SIZE)
                body->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
        if (rec->ur_iattr.ia_valid & (ATTR_MTIME | ATTR_MTIME_SET))
                body->valid |= OBD_MD_FLMTIME;
        if (rec->ur_iattr.ia_valid & (ATTR_ATIME | ATTR_ATIME_SET))
                body->valid |= OBD_MD_FLATIME;

        if (rc == 0 && rec->ur_cookielen && !IS_ERR(mds->mds_osc_obd)) {
                OBD_ALLOC(mlcd, sizeof(*mlcd) + rec->ur_cookielen +
                          rec->ur_eadatalen);
                if (mlcd) {
                        mlcd->mlcd_size = sizeof(*mlcd) + rec->ur_cookielen +
                                rec->ur_eadatalen;
                        mlcd->mlcd_eadatalen = rec->ur_eadatalen;
                        mlcd->mlcd_cookielen = rec->ur_cookielen;
                        mlcd->mlcd_lmm = (void *)&mlcd->mlcd_cookies +
                                mlcd->mlcd_cookielen;
                        memcpy(&mlcd->mlcd_cookies, rec->ur_logcookies,
                               mlcd->mlcd_cookielen);
                        memcpy(mlcd->mlcd_lmm, rec->ur_eadata,
                               mlcd->mlcd_eadatalen);
                } else {
                        CERROR("unable to allocate log cancel data\n");
                }
        }
        EXIT;
 cleanup:
        if (mlcd != NULL)
                fsfilt_add_journal_cb(req->rq_export->exp_obd, 0, handle,
                                      mds_cancel_cookies_cb, mlcd);
        err = mds_finish_transno(mds, inode, handle, req, rc, 0);
        switch (cleanup_phase) {
        case 1:
                if (S_ISREG(inode->i_mode) && rec->ur_eadata != NULL)
                        down(&inode->i_sem);
                l_dput(de);
                if (locked) {
                        if (rc) {
                                ldlm_lock_decref(&lockh, LCK_PW);
                        } else {
                                ldlm_put_lock_into_req(req, &lockh, LCK_PW);
                        }
                }
        case 0:
                break;
        default:
                LBUG();
        }
        if (err && !rc)
                rc = err;

        req->rq_status = rc;
        return 0;
}

static void reconstruct_reint_create(struct mds_update_record *rec, int offset,
                                     struct ptlrpc_request *req)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_obd *obd = &req->rq_export->exp_obd->u.mds;
        struct dentry *parent, *child;
        struct mds_body *body;

        mds_req_from_mcd(req, med->med_mcd);

        if (req->rq_status)
                return;

        parent = mds_fid2dentry(obd, rec->ur_fid1, NULL);
        LASSERT(!IS_ERR(parent));
        child = ll_lookup_one_len(rec->ur_name, parent, rec->ur_namelen - 1);
        LASSERT(!IS_ERR(child));
        body = lustre_msg_buf(req->rq_repmsg, offset, sizeof (*body));
        mds_pack_inode2fid(&body->fid1, child->d_inode);
        mds_pack_inode2body(body, child->d_inode);
        l_dput(parent);
        l_dput(child);
}

static int mds_reint_create(struct mds_update_record *rec, int offset,
                            struct ptlrpc_request *req,
                            struct lustre_handle *lh)
{
        struct dentry *dparent = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *dchild = NULL;
        struct inode *dir = NULL;
        void *handle = NULL;
        struct lustre_handle lockh;
        int rc = 0, err, type = rec->ur_mode & S_IFMT, cleanup_phase = 0;
        int created = 0;
        struct dentry_params dp;
        ENTRY;

        LASSERT(offset == 0);
        LASSERT(!strcmp(req->rq_export->exp_obd->obd_type->typ_name, "mds"));

        MDS_CHECK_RESENT(req, reconstruct_reint_create(rec, offset, req));

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_CREATE))
                GOTO(cleanup, rc = -ESTALE);

        dparent = mds_fid2locked_dentry(obd, rec->ur_fid1, NULL, LCK_PW, &lockh,
                                        rec->ur_name, rec->ur_namelen - 1);
        if (IS_ERR(dparent)) {
                rc = PTR_ERR(dparent);
                CERROR("parent lookup error %d\n", rc);
                GOTO(cleanup, rc);
        }
        cleanup_phase = 1; /* locked parent dentry */
        dir = dparent->d_inode;
        LASSERT(dir);
        CDEBUG(D_INODE, "parent ino %lu creating name %s mode %o\n",
               dir->i_ino, rec->ur_name, rec->ur_mode);

        ldlm_lock_dump_handle(D_OTHER, &lockh);

        dchild = ll_lookup_one_len(rec->ur_name, dparent, rec->ur_namelen - 1);
        if (IS_ERR(dchild)) {
                rc = PTR_ERR(dchild);
                CERROR("child lookup error %d\n", rc);
                GOTO(cleanup, rc);
        }

        cleanup_phase = 2; /* child dentry */

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_CREATE_WRITE, dir->i_sb);

        if (dir->i_mode & S_ISGID) {
                if (S_ISDIR(rec->ur_mode))
                        rec->ur_mode |= S_ISGID;
        }

        dchild->d_fsdata = (void *)&dp;
        dp.p_inum = (unsigned long)rec->ur_fid2->id;
        dp.p_ptr = req;

        switch (type) {
        case S_IFREG:{
                handle = fsfilt_start(obd, dir, FSFILT_OP_CREATE, NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                rc = ll_vfs_create(dir, dchild, rec->ur_mode, NULL);
                EXIT;
                break;
        }
        case S_IFDIR:{
                handle = fsfilt_start(obd, dir, FSFILT_OP_MKDIR, NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                rc = vfs_mkdir(dir, dchild, rec->ur_mode);
                EXIT;
                break;
        }
        case S_IFLNK:{
                handle = fsfilt_start(obd, dir, FSFILT_OP_SYMLINK, NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                if (rec->ur_tgt == NULL)        /* no target supplied */
                        rc = -EINVAL;           /* -EPROTO? */
                else
                        rc = vfs_symlink(dir, dchild, rec->ur_tgt);
                EXIT;
                break;
        }
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:{
                int rdev = rec->ur_rdev;
                handle = fsfilt_start(obd, dir, FSFILT_OP_MKNOD, NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, (handle = NULL, rc = PTR_ERR(handle)));
                rc = vfs_mknod(dir, dchild, rec->ur_mode, rdev);
                EXIT;
                break;
        }
        default:
                CERROR("bad file type %o creating %s\n", type, rec->ur_name);
                dchild->d_fsdata = NULL;
                GOTO(cleanup, rc = -EINVAL);
        }

        /* In case we stored the desired inum in here, we want to clean up. */
        if (dchild->d_fsdata == (void *)(unsigned long)rec->ur_fid2->id)
                dchild->d_fsdata = NULL;

        if (rc) {
                CDEBUG(D_INODE, "error during create: %d\n", rc);
                GOTO(cleanup, rc);
        } else {
                struct iattr iattr;
                struct inode *inode = dchild->d_inode;
                struct mds_body *body;

                created = 1;
                LTIME_S(iattr.ia_atime) = rec->ur_time;
                LTIME_S(iattr.ia_ctime) = rec->ur_time;
                LTIME_S(iattr.ia_mtime) = rec->ur_time;
                iattr.ia_uid = rec->ur_fsuid;
                if (dir->i_mode & S_ISGID)
                        iattr.ia_gid = dir->i_gid;
                else
                        iattr.ia_gid = rec->ur_fsgid;
                iattr.ia_valid = ATTR_UID | ATTR_GID | ATTR_ATIME |
                        ATTR_MTIME | ATTR_CTIME;

                if (rec->ur_fid2->id) {
                        LASSERT(rec->ur_fid2->id == inode->i_ino);
                        inode->i_generation = rec->ur_fid2->generation;
                        /* Dirtied and committed by the upcoming setattr. */
                        CDEBUG(D_INODE, "recreated ino %lu with gen %u\n",
                               inode->i_ino, inode->i_generation);
                } else {
                        struct lustre_handle child_ino_lockh;
                        struct ldlm_res_id child_res_id =
                             { .name = { inode->i_ino, 0 } };
                        int lock_flags = 0;

                        CDEBUG(D_INODE, "created ino %lu with gen %x\n",
                               inode->i_ino, inode->i_generation);

                        /* The inode we were allocated may have just been freed
                         * by an unlink operation.  We take this lock to
                         * synchronize against the matching reply-ack-lock taken
                         * in unlink, to avoid replay problems if this reply
                         * makes it out to the client but the unlink's does not.
                         * See bug 2029 for more detail.*/
                        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace,
                                              NULL, child_res_id, LDLM_PLAIN,
                                              NULL, 0, LCK_EX, &lock_flags,
                                              ldlm_completion_ast,
                                              mds_blocking_ast, NULL,
                                              &child_ino_lockh);
                        if (rc != ELDLM_OK) {
                                CERROR("error locking for unlink/create sync: "
                                       "%d\n", rc);
                        } else {
                                ldlm_lock_decref(&child_ino_lockh, LCK_EX);
                        }
                }

                rc = fsfilt_setattr(obd, dchild, handle, &iattr, 0);
                if (rc)
                        CERROR("error on child setattr: rc = %d\n", rc);

                iattr.ia_valid = ATTR_MTIME | ATTR_CTIME;
                rc = fsfilt_setattr(obd, dparent, handle, &iattr, 0);
                if (rc)
                        CERROR("error on parent setattr: rc = %d\n", rc);

                body = lustre_msg_buf(req->rq_repmsg, offset, sizeof (*body));
                mds_pack_inode2fid(&body->fid1, inode);
                mds_pack_inode2body(body, inode);
        }
        EXIT;

cleanup:
        err = mds_finish_transno(mds, dir, handle, req, rc, 0);

        if (rc && created) {
                /* Destroy the file we just created.  This should not need
                 * extra journal credits, as we have already modified all of
                 * the blocks needed in order to create the file in the first
                 * place.
                 */
                switch (type) {
                case S_IFDIR:
                        err = vfs_rmdir(dir, dchild);
                        if (err)
                                CERROR("rmdir in error path: %d\n", err);
                        break;
                default:
                        err = vfs_unlink(dir, dchild);
                        if (err)
                                CERROR("unlink in error path: %d\n", err);
                        break;
                }
        } else {
                rc = err;
        }
        switch (cleanup_phase) {
        case 2: /* child dentry */
                l_dput(dchild);
        case 1: /* locked parent dentry */
                if (rc) {
                        ldlm_lock_decref(&lockh, LCK_PW);
                } else {
                        ldlm_put_lock_into_req(req, &lockh, LCK_PW);
                }
                l_dput(dparent);
        case 0:
                break;
        default:
                CERROR("invalid cleanup_phase %d\n", cleanup_phase);
                LBUG();
        }
        req->rq_status = rc;
        return 0;
}

/* This function doesn't use ldlm_match_or_enqueue because we're always called
 * with EX or PW locks, and the MDS is no longer allowed to match write locks,
 * because they take the place of local semaphores.
 *
 * Two locks are taken in numerical order */
int enqueue_ordered_locks(int lock_mode, struct obd_device *obd,
                          struct ldlm_res_id *p1_res_id,
                          struct ldlm_res_id *p2_res_id,
                          struct lustre_handle *p1_lockh,
                          struct lustre_handle *p2_lockh)
{
        struct ldlm_res_id res_id[2];
        struct lustre_handle *handles[2] = {p1_lockh, p2_lockh};
        int rc, flags;
        ENTRY;

        LASSERT(p1_res_id != NULL && p2_res_id != NULL);

        CDEBUG(D_INFO, "locks before: "LPU64"/"LPU64"\n",
               p1_res_id[0].name[0], p2_res_id[0].name[0]);

        if (p1_res_id->name[0] < p2_res_id->name[0]) {
                handles[0] = p1_lockh;
                handles[1] = p2_lockh;
                res_id[0] = *p1_res_id;
                res_id[1] = *p2_res_id;
        } else {
                handles[1] = p1_lockh;
                handles[0] = p2_lockh;
                res_id[1] = *p1_res_id;
                res_id[0] = *p2_res_id;
        }

        CDEBUG(D_INFO, "lock order: "LPU64"/"LPU64"\n",
               p1_res_id[0].name[0], p2_res_id[0].name[0]);

        flags = LDLM_FL_LOCAL_ONLY;
        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL, res_id[0],
                              LDLM_PLAIN, NULL, 0, lock_mode, &flags,
                              ldlm_completion_ast, mds_blocking_ast, NULL,
                              handles[0]);
        if (rc != ELDLM_OK)
                RETURN(-EIO);
        ldlm_lock_dump_handle(D_OTHER, handles[0]);

        if (memcmp(&res_id[0], &res_id[1], sizeof(res_id[0])) == 0) {
                memcpy(handles[1], handles[0], sizeof(*(handles[1])));
                ldlm_lock_addref(handles[1], lock_mode);
        } else {
                flags = LDLM_FL_LOCAL_ONLY;
                rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                                      res_id[1], LDLM_PLAIN, NULL, 0, lock_mode,
                                      &flags, ldlm_completion_ast,
                                      mds_blocking_ast, NULL, handles[1]);
                if (rc != ELDLM_OK) {
                        ldlm_lock_decref(handles[0], lock_mode);
                        RETURN(-EIO);
                }
        }
        ldlm_lock_dump_handle(D_OTHER, handles[1]);

        RETURN(0);
}

void mds_reconstruct_generic(struct ptlrpc_request *req)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;

        mds_req_from_mcd(req, med->med_mcd);
}

static int mds_reint_unlink(struct mds_update_record *rec, int offset,
                            struct ptlrpc_request *req,
                            struct lustre_handle *lh)
{
        struct dentry *dparent = NULL;
        struct dentry *dchild = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_body *body = NULL;
        struct inode *child_inode;
        struct lustre_handle parent_lockh, child_lockh, child_reuse_lockh;
        void *handle = NULL;
        struct ldlm_res_id child_res_id = { .name = {0} };
        int rc = 0, flags = 0, log_unlink = 0, cleanup_phase = 0;
        ENTRY;

        LASSERT(offset == 0 || offset == 2);

        MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNLINK))
                GOTO(cleanup, rc = -ENOENT);

        /* Step 1: Lookup the parent by FID */
        dparent = mds_fid2locked_dentry(obd, rec->ur_fid1, NULL, LCK_PW,
                                        &parent_lockh, rec->ur_name,
                                        rec->ur_namelen - 1);
        if (IS_ERR(dparent))
                GOTO(cleanup, rc = PTR_ERR(dparent));
        LASSERT(dparent->d_inode);

        cleanup_phase = 1; /* Have parent dentry lock */

        /* Step 2: Lookup the child */
        dchild = ll_lookup_one_len(rec->ur_name, dparent, rec->ur_namelen - 1);
        if (IS_ERR(dchild))
                GOTO(cleanup, rc = PTR_ERR(dchild));

        cleanup_phase = 2; /* child dentry */

        child_inode = dchild->d_inode;
        if (child_inode == NULL) {
                CDEBUG(D_INODE, "child doesn't exist (dir %lu, name %s)\n",
                       dparent->d_inode->i_ino, rec->ur_name);
                GOTO(cleanup, rc = -ENOENT);
        }

        DEBUG_REQ(D_INODE, req, "parent ino %lu, child ino %lu",
                  dparent->d_inode->i_ino, child_inode->i_ino);

        /* Step 3: Get a lock on the child */
        child_res_id.name[0] = child_inode->i_ino;
        child_res_id.name[1] = child_inode->i_generation;

        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                              child_res_id, LDLM_PLAIN, NULL, 0, LCK_EX,
                              &flags, ldlm_completion_ast, mds_blocking_ast,
                              NULL, &child_lockh);
        if (rc != ELDLM_OK)
                GOTO(cleanup, rc);

        cleanup_phase = 3; /* child lock */

        /* Step 4: Get a lock on the ino to sync with creation WRT inode
         * reuse (see bug 2029). */
        child_res_id.name[1] = 0;
        
        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                              child_res_id, LDLM_PLAIN, NULL, 0, LCK_EX,
                              &flags, ldlm_completion_ast, mds_blocking_ast,
                              NULL, &child_reuse_lockh);
        if (rc != ELDLM_OK)
                GOTO(cleanup, rc);

        cleanup_phase = 4; /* child lock */
        
        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_UNLINK_WRITE, dparent->d_inode->i_sb);

        /* ldlm_reply in buf[0] if called via intent */
        if (offset)
                offset = 1;

        body = lustre_msg_buf(req->rq_repmsg, offset, sizeof (*body));
        LASSERT(body != NULL);

        /* If this is the last reference to this inode, get the OBD EA
         * data first so the client can destroy OST objects. 
         * we only do the object removal if no open files remain.
         * Nobody can get at this name anymore because of the locks so 
         * we make decisions here as to whether to remove the inode */
        if (S_ISREG(child_inode->i_mode) && child_inode->i_nlink == 1 && 
            mds_open_orphan_count(child_inode) == 0) {
                mds_pack_inode2fid(&body->fid1, child_inode);
                mds_pack_inode2body(body, child_inode);
                mds_pack_md(obd, req->rq_repmsg, offset + 1, body,
                            child_inode, 1);
                if (!(body->valid & OBD_MD_FLEASIZE)) {
                        body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                        OBD_MD_FLATIME | OBD_MD_FLMTIME);
                } else {
                        log_unlink = 1;
                }
        }

        /* We have to do these checks ourselves, in case we are making an
         * orphan.  The client tells us whether rmdir() or unlink() was called,
         * so we need to return appropriate errors (bug 72).
         *
         * We don't have to check permissions, because vfs_rename (called from
         * mds_open_unlink_rename) also calls may_delete. */
        if ((rec->ur_mode & S_IFMT) == S_IFDIR) {
                if (!S_ISDIR(child_inode->i_mode))
                        GOTO(cleanup, rc = -ENOTDIR);
        } else {
                if (S_ISDIR(child_inode->i_mode))
                        GOTO(cleanup, rc = -EISDIR);
        }

        if (child_inode->i_nlink == (S_ISDIR(child_inode->i_mode) ? 2 : 1) &&
            mds_open_orphan_count(child_inode) > 0) {
                rc = mds_open_unlink_rename(rec, obd, dparent, dchild, &handle);
                cleanup_phase = 5; /* transaction */
                GOTO(cleanup, rc);
        }

        /* Step 4: Do the unlink: we already verified ur_mode above (bug 72) */
        switch (child_inode->i_mode & S_IFMT) {
        case S_IFDIR:
                /* Drop any lingering child directories before we start our
                 * transaction, to avoid doing multiple inode dirty/delete
                 * in our compound transaction (bug 1321). */
                shrink_dcache_parent(dchild);
                handle = fsfilt_start(obd, dparent->d_inode, FSFILT_OP_RMDIR,
                                      NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                cleanup_phase = 5; /* transaction */
                rc = vfs_rmdir(dparent->d_inode, dchild);
                break;
        case S_IFREG: {
                handle = fsfilt_start(obd, dparent->d_inode,
                                      FSFILT_OP_UNLINK_LOG, NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));

                cleanup_phase = 5; /* transaction */
                rc = vfs_unlink(dparent->d_inode, dchild);

#ifdef ENABLE_ORPHANS

                if (!rc && log_unlink)
                        if (mds_log_op_unlink(obd, child_inode, req->rq_repmsg,
                                              offset + 1) > 0)
                                body->valid |= OBD_MD_FLCOOKIE;
#endif
                break;
        }
        case S_IFLNK:
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:
                handle = fsfilt_start(obd, dparent->d_inode, FSFILT_OP_UNLINK,
                                      NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                cleanup_phase = 5;
                rc = vfs_unlink(dparent->d_inode, dchild);
                break;
        default:
                CERROR("bad file type %o unlinking %s\n", rec->ur_mode,
                       rec->ur_name);
                LBUG();
                GOTO(cleanup, rc = -EINVAL);
        }

 cleanup:
        if (rc == 0) {
                struct iattr iattr;
                int err;

                iattr.ia_valid = ATTR_MTIME | ATTR_CTIME;
                LTIME_S(iattr.ia_mtime) = rec->ur_time;
                LTIME_S(iattr.ia_ctime) = rec->ur_time;

                err = fsfilt_setattr(obd, dparent, handle, &iattr, 0);
                if (err)
                        CERROR("error on parent setattr: rc = %d\n", err);
        }

        switch(cleanup_phase) {
        case 5:
                rc = mds_finish_transno(mds, dparent->d_inode, handle, req,
                                        rc, 0);
                if (!rc)
                        (void)obd_set_info(mds->mds_osc_exp, strlen("unlinked"),
                                           "unlinked", 0, NULL);
        case 4: /* child ino-reuse lock */
                if (rc && body != NULL) {
                        // Don't unlink the OST objects if the MDS unlink failed
                        body->valid = 0;
                }
                if (rc)
                        ldlm_lock_decref(&child_reuse_lockh, LCK_EX);
                else
                        ldlm_put_lock_into_req(req, &child_reuse_lockh, LCK_EX);
        case 3: /* child lock */
                ldlm_lock_decref(&child_lockh, LCK_EX);
        case 2: /* child dentry */
                l_dput(dchild);
        case 1: /* parent dentry and lock */
                if (rc) {
                        ldlm_lock_decref(&parent_lockh, LCK_PW);
                } else {
                        ldlm_put_lock_into_req(req, &parent_lockh, LCK_PW);
                }
                l_dput(dparent);
        case 0:
                break;
        default:
                CERROR("invalid cleanup_phase %d\n", cleanup_phase);
                LBUG();
        }
        req->rq_status = rc;
        return 0;
}

static int mds_reint_link(struct mds_update_record *rec, int offset,
                          struct ptlrpc_request *req,
                          struct lustre_handle *lh)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *de_src = NULL;
        struct dentry *de_tgt_dir = NULL;
        struct dentry *dchild = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        struct lustre_handle *handle = NULL, tgt_dir_lockh, src_lockh;
        struct ldlm_res_id src_res_id = { .name = {0} };
        struct ldlm_res_id tgt_dir_res_id = { .name = {0} };
        int lock_mode = 0, rc = 0, cleanup_phase = 0;
        ENTRY;

        LASSERT(offset == 0);

        MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_LINK))
                GOTO(cleanup, rc = -ENOENT);

        /* Step 1: Lookup the source inode and target directory by FID */
        de_src = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        if (IS_ERR(de_src))
                GOTO(cleanup, rc = PTR_ERR(de_src));

        cleanup_phase = 1; /* source dentry */

        de_tgt_dir = mds_fid2dentry(mds, rec->ur_fid2, NULL);
        if (IS_ERR(de_tgt_dir))
                GOTO(cleanup, rc = PTR_ERR(de_tgt_dir));

        cleanup_phase = 2; /* target directory dentry */

        CDEBUG(D_INODE, "linking %*s/%s to inode %lu\n",
               de_tgt_dir->d_name.len, de_tgt_dir->d_name.name, rec->ur_name,
               de_src->d_inode->i_ino);

        /* Step 2: Take the two locks */
        lock_mode = LCK_EX;
        src_res_id.name[0] = de_src->d_inode->i_ino;
        src_res_id.name[1] = de_src->d_inode->i_generation;
        tgt_dir_res_id.name[0] = de_tgt_dir->d_inode->i_ino;
        tgt_dir_res_id.name[1] = de_tgt_dir->d_inode->i_generation;

        rc = enqueue_ordered_locks(LCK_EX, obd, &src_res_id, &tgt_dir_res_id,
                                   &src_lockh, &tgt_dir_lockh);
        if (rc != ELDLM_OK)
                GOTO(cleanup, rc = -EIO);

        cleanup_phase = 3; /* locks */

        /* Step 3: Lookup the child */
        dchild = ll_lookup_one_len(rec->ur_name, de_tgt_dir, rec->ur_namelen-1);
        if (IS_ERR(dchild)) {
                rc = PTR_ERR(dchild);
                if (rc != -EPERM && rc != -EACCES)
                        CERROR("child lookup error %d\n", rc);
                GOTO(cleanup, rc);
        }

        cleanup_phase = 4; /* child dentry */

        if (dchild->d_inode) {
                CDEBUG(D_INODE, "child exists (dir %lu, name %s)\n",
                       de_tgt_dir->d_inode->i_ino, rec->ur_name);
                rc = -EEXIST;
                GOTO(cleanup, rc);
        }

        /* Step 4: Do it. */
        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_LINK_WRITE, de_src->d_inode->i_sb);

        handle = fsfilt_start(obd, de_tgt_dir->d_inode, FSFILT_OP_LINK, NULL);
        if (IS_ERR(handle)) {
                rc = PTR_ERR(handle);
                GOTO(cleanup, rc);
        }

        rc = vfs_link(de_src, de_tgt_dir->d_inode, dchild);
        if (rc && rc != -EPERM && rc != -EACCES)
                CERROR("vfs_link error %d\n", rc);
cleanup:
        rc = mds_finish_transno(mds, de_tgt_dir ? de_tgt_dir->d_inode : NULL,
                                handle, req, rc, 0);
        EXIT;

        switch (cleanup_phase) {
        case 4: /* child dentry */
                l_dput(dchild);
        case 3: /* locks */
                if (rc) {
                        ldlm_lock_decref(&src_lockh, lock_mode);
                        ldlm_lock_decref(&tgt_dir_lockh, lock_mode);
                } else {
                        ldlm_put_lock_into_req(req, &src_lockh, lock_mode);
                        ldlm_put_lock_into_req(req, &tgt_dir_lockh, lock_mode);
                }
        case 2: /* target dentry */
                l_dput(de_tgt_dir);
        case 1: /* source dentry */
                l_dput(de_src);
        case 0:
                break;
        default:
                CERROR("invalid cleanup_phase %d\n", cleanup_phase);
                LBUG();
        }
        req->rq_status = rc;
        return 0;
}

/*
 * add a hard link in the PENDING directory, only used by rename()
 */
static int mds_add_link_orphan(struct mds_update_record *rec,
                               struct obd_device *obd,
                               struct dentry *dentry)
{
        struct mds_obd *mds = &obd->u.mds;
        struct inode *pending_dir = mds->mds_pending_dir->d_inode;
        struct dentry *pending_child;
        char fidname[LL_FID_NAMELEN];
        int fidlen = 0, rc;
        ENTRY;

        LASSERT(dentry->d_inode);
        LASSERT(!mds_inode_is_orphan(dentry->d_inode));

        down(&pending_dir->i_sem);
        fidlen = ll_fid2str(fidname, dentry->d_inode->i_ino,
                            dentry->d_inode->i_generation);

        CDEBUG(D_ERROR, "pending destroy of %dx open file %s = %s\n",
               mds_open_orphan_count(dentry->d_inode),
               rec->ur_name, fidname);

        pending_child = lookup_one_len(fidname, mds->mds_pending_dir, fidlen);
        if (IS_ERR(pending_child))
                GOTO(out_lock, rc = PTR_ERR(pending_child));

        if (pending_child->d_inode != NULL) {
                CERROR("re-destroying orphan file %s?\n", rec->ur_name);
                LASSERT(pending_child->d_inode == dentry->d_inode);
                GOTO(out_dput, rc = 0);
        }

        lock_kernel();
        rc = vfs_link(dentry, pending_dir, pending_child);
        unlock_kernel();
        if (rc)
                CERROR("error addlink orphan %s to PENDING: rc = %d\n",
                       rec->ur_name, rc);
        else
                mds_inode_set_orphan(dentry->d_inode);
out_dput:
        l_dput(pending_child);
out_lock:
        up(&pending_dir->i_sem);
        RETURN(rc);
}

static int mds_reint_rename(struct mds_update_record *rec, int offset,
                            struct ptlrpc_request *req,
                            struct lustre_handle *lockh)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *de_srcdir = NULL;
        struct dentry *de_tgtdir = NULL;
        struct dentry *de_old = NULL;
        struct dentry *de_new = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        struct lustre_handle dlm_handles[4];
        struct ldlm_res_id p1_res_id = { .name = {0} };
        struct ldlm_res_id p2_res_id = { .name = {0} };
        struct ldlm_res_id c1_res_id = { .name = {0} };
        struct ldlm_res_id c2_res_id = { .name = {0} };
        struct mds_body *body = NULL;
        int rc = 0, lock_count = 3, flags = LDLM_FL_LOCAL_ONLY;
        int cleanup_phase = 0;
        void *handle = NULL;
        ENTRY;

        LASSERT(offset == 0);

        MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));

        de_srcdir = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        if (IS_ERR(de_srcdir))
                GOTO(cleanup, rc = PTR_ERR(de_srcdir));

        cleanup_phase = 1; /* source directory dentry */

        de_tgtdir = mds_fid2dentry(mds, rec->ur_fid2, NULL);
        if (IS_ERR(de_tgtdir))
                GOTO(cleanup, rc = PTR_ERR(de_tgtdir));

        cleanup_phase = 2; /* target directory dentry */

        /* The idea here is that we need to get four locks in the end:
         * one on each parent directory, one on each child.  We need to take
         * these locks in some kind of order (to avoid deadlocks), and the order
         * I selected is "increasing resource number" order.  We need to take
         * the locks on the parent directories, however, before we can lookup
         * the children.  Thus the following plan:
         *
         * 1. Take locks on the parent(s), in order
         * 2. Lookup the children
         * 3. Take locks on the children, in order
         * 4. Execute the rename
         */

        /* Step 1: Take locks on the parent(s), in order */
        p1_res_id.name[0] = de_srcdir->d_inode->i_ino;
        p1_res_id.name[1] = de_srcdir->d_inode->i_generation;

        p2_res_id.name[0] = de_tgtdir->d_inode->i_ino;
        p2_res_id.name[1] = de_tgtdir->d_inode->i_generation;

        rc = enqueue_ordered_locks(LCK_EX, obd, &p1_res_id, &p2_res_id,
                                   &(dlm_handles[0]), &(dlm_handles[1]));
        if (rc != ELDLM_OK)
                GOTO(cleanup, rc);

        cleanup_phase = 3; /* parent locks */

        /* Step 2: Lookup the children */
        de_old = ll_lookup_one_len(rec->ur_name, de_srcdir, rec->ur_namelen-1);
        if (IS_ERR(de_old)) {
                CERROR("old child lookup error (%*s): %ld\n",
                       rec->ur_namelen - 1, rec->ur_name, PTR_ERR(de_old));
                GOTO(cleanup, rc = PTR_ERR(de_old));
        }

        cleanup_phase = 4; /* original name dentry */

        if (de_old->d_inode == NULL)
                GOTO(cleanup, rc = -ENOENT);

        /* sanity check for src inode */
        if (de_old->d_inode->i_ino == de_srcdir->d_inode->i_ino ||
            de_old->d_inode->i_ino == de_tgtdir->d_inode->i_ino)
                GOTO(cleanup, rc = -EINVAL);

        de_new = ll_lookup_one_len(rec->ur_tgt, de_tgtdir, rec->ur_tgtlen - 1);
        if (IS_ERR(de_new)) {
                CERROR("new child lookup error (%*s): %ld\n",
                       rec->ur_tgtlen - 1, rec->ur_tgt, PTR_ERR(de_new));
                GOTO(cleanup, rc = PTR_ERR(de_new));
        }

        cleanup_phase = 5; /* target dentry */

        /* sanity check for dest inode */
        if (de_new->d_inode &&
            (de_new->d_inode->i_ino == de_srcdir->d_inode->i_ino ||
            de_new->d_inode->i_ino == de_tgtdir->d_inode->i_ino))
                GOTO(cleanup, rc = -EINVAL);

        /* Step 3: Take locks on the children */
        c1_res_id.name[0] = de_old->d_inode->i_ino;
        c1_res_id.name[1] = de_old->d_inode->i_generation;
        if (de_new->d_inode == NULL) {
                flags = LDLM_FL_LOCAL_ONLY;
                rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                                      c1_res_id, LDLM_PLAIN, NULL, 0, LCK_EX,
                                      &flags, ldlm_completion_ast,
                                      mds_blocking_ast, NULL,
                                      &(dlm_handles[2]));
                lock_count = 3;
        } else {
                c2_res_id.name[0] = de_new->d_inode->i_ino;
                c2_res_id.name[1] = de_new->d_inode->i_generation;
                rc = enqueue_ordered_locks(LCK_EX, obd, &c1_res_id, &c2_res_id,
                                           &(dlm_handles[2]),
                                           &(dlm_handles[3]));
                lock_count = 4;
        }
        if (rc != ELDLM_OK)
                GOTO(cleanup, rc);

        cleanup_phase = 6; /* child locks */

        /* if we are about to remove the target at first, pass the EA of
         * that inode to client to perform and cleanup on OST */
        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*body));
        LASSERT(body != NULL);

        if (de_new->d_inode &&
            S_ISREG(de_new->d_inode->i_mode) &&
            de_new->d_inode->i_nlink == 1 &&
            mds_open_orphan_count(de_new->d_inode) == 0) {
                mds_pack_inode2fid(&body->fid1, de_new->d_inode);
                mds_pack_inode2body(body, de_new->d_inode);
                mds_pack_md(obd, req->rq_repmsg, 1, body, de_new->d_inode, 1);
                if (!(body->valid & OBD_MD_FLEASIZE)) {
                        body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                        OBD_MD_FLATIME | OBD_MD_FLMTIME);
                } else {
                        /* XXX need log unlink? */
                }
        }

        /* Step 4: Execute the rename */
        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_RENAME_WRITE,de_srcdir->d_inode->i_sb);

        handle = fsfilt_start(obd, de_tgtdir->d_inode, FSFILT_OP_RENAME, NULL);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));

        /* FIXME need adjust the journal block count? */
        /* if the target should be moved to PENDING, we at first increase the
         * link and later vfs_rename() will decrease the link count again */
        if (de_new->d_inode &&
            S_ISREG(de_new->d_inode->i_mode) &&
            de_new->d_inode->i_nlink == 1 &&
            mds_open_orphan_count(de_new->d_inode) > 0) {
                rc = mds_add_link_orphan(rec, obd, de_new);
                if (rc)
                        GOTO(cleanup, rc);
        }

        lock_kernel();
        de_old->d_fsdata = req;
        de_new->d_fsdata = req;
        rc = vfs_rename(de_srcdir->d_inode, de_old, de_tgtdir->d_inode, de_new);
        unlock_kernel();

        EXIT;
cleanup:
        rc = mds_finish_transno(mds, de_tgtdir ? de_tgtdir->d_inode : NULL,
                                handle, req, rc, 0);
        switch (cleanup_phase) {
        case 6: /* child locks */
                if (rc) {
                        ldlm_lock_decref(&(dlm_handles[2]), LCK_EX);
                        if (lock_count == 4)
                                ldlm_lock_decref(&(dlm_handles[3]), LCK_EX);
                } else {
                        ldlm_put_lock_into_req(req, &(dlm_handles[2]), LCK_EX);
                        if (lock_count == 4)
                                ldlm_put_lock_into_req(req,
                                                &(dlm_handles[3]), LCK_EX);
                }
        case 5: /* target dentry */
                l_dput(de_new);
        case 4: /* source dentry */
                l_dput(de_old);
        case 3: /* parent locks */
                if (rc) {
                        ldlm_lock_decref(&(dlm_handles[0]), LCK_EX);
                        ldlm_lock_decref(&(dlm_handles[1]), LCK_EX);
                } else {
                        ldlm_put_lock_into_req(req, &(dlm_handles[0]), LCK_EX);
                        ldlm_put_lock_into_req(req, &(dlm_handles[1]), LCK_EX);
                }
        case 2: /* target directory dentry */
                l_dput(de_tgtdir);
        case 1: /* source directry dentry */
                l_dput(de_srcdir);
        case 0:
                break;
        default:
                CERROR("invalid cleanup_phase %d\n", cleanup_phase);
                LBUG();
        }
        req->rq_status = rc;
        return 0;
}

typedef int (*mds_reinter)(struct mds_update_record *, int offset,
                           struct ptlrpc_request *, struct lustre_handle *);

static mds_reinter reinters[REINT_MAX + 1] = {
        [REINT_SETATTR] mds_reint_setattr,
        [REINT_CREATE] mds_reint_create,
        [REINT_UNLINK] mds_reint_unlink,
        [REINT_LINK] mds_reint_link,
        [REINT_RENAME] mds_reint_rename,
        [REINT_OPEN] mds_open
};

int mds_reint_rec(struct mds_update_record *rec, int offset,
                  struct ptlrpc_request *req, struct lustre_handle *lockh)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct obd_run_ctxt saved;
        int rc;
        ENTRY;

        /* checked by unpacker */
        LASSERT(rec->ur_opcode <= REINT_MAX &&
                reinters[rec->ur_opcode] != NULL);

        push_ctxt(&saved, &obd->obd_ctxt, &rec->ur_uc);
        rc = reinters[rec->ur_opcode] (rec, offset, req, lockh);
        pop_ctxt(&saved, &obd->obd_ctxt, &rec->ur_uc);

        RETURN(rc);
}
