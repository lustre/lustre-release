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
        struct llog_ctxt *ctxt;
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
        if (rc != 0) {
                LASSERT(transno == 0);
        } else if (transno == 0) {
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
                  "wrote trans #"LPU64" client %s at idx %u: err = %d",
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

void mds_steal_ack_locks(struct ptlrpc_request *req)
{
        struct obd_export         *exp = req->rq_export;
        struct list_head          *tmp;
        struct ptlrpc_reply_state *oldrep;
        struct ptlrpc_service     *svc;
        unsigned long              flags;
        int                        i;

        /* CAVEAT EMPTOR: spinlock order */
        spin_lock_irqsave (&exp->exp_lock, flags);
        list_for_each (tmp, &exp->exp_outstanding_replies) {
                oldrep = list_entry(tmp, struct ptlrpc_reply_state,rs_exp_list);

                if (oldrep->rs_xid != req->rq_xid)
                        continue;

                if (oldrep->rs_msg.opc != req->rq_reqmsg->opc)
                        CERROR ("Resent req xid "LPX64" has mismatched opc: "
                                "new %d old %d\n", req->rq_xid,
                                req->rq_reqmsg->opc, oldrep->rs_msg.opc);

                svc = oldrep->rs_srv_ni->sni_service;
                spin_lock (&svc->srv_lock);

                list_del_init (&oldrep->rs_exp_list);

                CWARN("Stealing %d locks from rs %p x"LPD64".t"LPD64
                      " o%d NID"LPX64"\n",
                      oldrep->rs_nlocks, oldrep, 
                      oldrep->rs_xid, oldrep->rs_transno, oldrep->rs_msg.opc,
                      exp->exp_connection->c_peer.peer_nid);

                for (i = 0; i < oldrep->rs_nlocks; i++)
                        ptlrpc_save_lock(req, 
                                         &oldrep->rs_locks[i],
                                         oldrep->rs_modes[i]);
                oldrep->rs_nlocks = 0;

                DEBUG_REQ(D_HA, req, "stole locks for");
                ptlrpc_schedule_difficult_reply (oldrep);

                spin_unlock (&svc->srv_lock);
                spin_unlock_irqrestore (&exp->exp_lock, flags);
                return;
        }
        spin_unlock_irqrestore (&exp->exp_lock, flags);
}

void mds_req_from_mcd(struct ptlrpc_request *req, struct mds_client_data *mcd)
{
        DEBUG_REQ(D_HA, req, "restoring transno "LPD64"/status %d",
                  mcd->mcd_last_transno, mcd->mcd_last_result);
        req->rq_repmsg->transno = req->rq_transno = mcd->mcd_last_transno;
        req->rq_repmsg->status = req->rq_status = mcd->mcd_last_result;

        mds_steal_ack_locks(req);
}

static void reconstruct_reint_setattr(struct mds_update_record *rec,
                                      int offset, struct ptlrpc_request *req)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_obd *obd = &req->rq_export->exp_obd->u.mds;
        struct dentry *de;
        struct mds_body *body;

        mds_req_from_mcd(req, med->med_mcd);

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

        DEBUG_REQ(D_INODE, req, "setattr "LPU64"/%u %x", rec->ur_fid1->id,
                  rec->ur_fid1->generation, rec->ur_iattr.ia_valid);

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
        if ((S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)) && 
            rec->ur_eadata != NULL)
                down(&inode->i_sem);

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

        if (rc == 0 && (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode))
            && rec->ur_eadata != NULL) {
                struct lov_stripe_md *lsm = NULL;

                rc = obd_iocontrol(OBD_IOC_LOV_SETSTRIPE,
                                   mds->mds_osc_exp, 0, &lsm, rec->ur_eadata);
                if (rc)
                        GOTO(cleanup, rc);
                
                obd_free_memmd(mds->mds_osc_exp, &lsm);

                rc = fsfilt_set_md(obd, inode, handle, rec->ur_eadata,
                                   rec->ur_eadatalen);
                if (rc) 
                        GOTO(cleanup, rc);
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
                if ((S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)) && 
                    rec->ur_eadata != NULL)
                        up(&inode->i_sem);
                l_dput(de);
                if (locked) {
                        if (rc) {
                                ldlm_lock_decref(&lockh, LCK_PW);
                        } else {
                                ptlrpc_save_lock (req, &lockh, LCK_PW);
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

        DEBUG_REQ(D_INODE, req, "parent "LPU64"/%u name %s mode %o",
                  rec->ur_fid1->id, rec->ur_fid1->generation,
                  rec->ur_name, rec->ur_mode);

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

                        CDEBUG(D_INODE, "created ino %lu with gen %x\n",
                               inode->i_ino, inode->i_generation);

                        /* The inode we were allocated may have just been freed
                         * by an unlink operation.  We take this lock to
                         * synchronize against the matching reply-ack-lock taken
                         * in unlink, to avoid replay problems if this reply
                         * makes it out to the client but the unlink's does not.
                         * See bug 2029 for more detail.*/
                        rc = mds_lock_new_child(obd, inode, &child_ino_lockh);
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
                        ptlrpc_save_lock (req, &lockh, LCK_PW);
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

int res_gt(struct ldlm_res_id *res1, struct ldlm_res_id *res2)
{
        int i;

        for (i = 0; i < RES_NAME_SIZE; i++) {
                /* return 1 here, because enqueue_ordered will skip resources
                 * of all zeroes if they're sorted to the end of the list. */
                if (res1->name[i] == 0 && res2->name[i] != 0)
                        return 1;
                if (res2->name[i] == 0 && res1->name[i] != 0)
                        return 0;

                if (res1->name[i] > res2->name[i])
                        return 1;
                if (res1->name[i] < res2->name[i])
                        return 0;
        }
        return 0;
}

/* This function doesn't use ldlm_match_or_enqueue because we're always called
 * with EX or PW locks, and the MDS is no longer allowed to match write locks,
 * because they take the place of local semaphores.
 *
 * One or two locks are taken in numerical order.  A res_id->name[0] of 0 means
 * no lock is taken for that res_id.  Must be at least one non-zero res_id. */
int enqueue_ordered_locks(struct obd_device *obd, struct ldlm_res_id *p1_res_id,
                          struct lustre_handle *p1_lockh, int p1_lock_mode,
                          struct ldlm_res_id *p2_res_id,
                          struct lustre_handle *p2_lockh, int p2_lock_mode)
{
        struct ldlm_res_id *res_id[2] = { p1_res_id, p2_res_id };
        struct lustre_handle *handles[2] = { p1_lockh, p2_lockh };
        int lock_modes[2] = { p1_lock_mode, p2_lock_mode };
        int rc, flags;
        ENTRY;

        LASSERT(p1_res_id != NULL && p2_res_id != NULL);

        CDEBUG(D_INFO, "locks before: "LPU64"/"LPU64"\n",
               res_id[0]->name[0], res_id[1]->name[0]);

        if (res_gt(p1_res_id, p2_res_id)) {
                handles[1] = p1_lockh;
                handles[0] = p2_lockh;
                res_id[1] = p1_res_id;
                res_id[0] = p2_res_id;
                lock_modes[1] = p1_lock_mode;
                lock_modes[0] = p2_lock_mode;
        }

        CDEBUG(D_DLMTRACE, "lock order: "LPU64"/"LPU64"\n",
               res_id[0]->name[0], res_id[1]->name[0]);

        flags = LDLM_FL_LOCAL_ONLY;
        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, *res_id[0],
                              LDLM_PLAIN, NULL, lock_modes[0], &flags,
                              mds_blocking_ast, ldlm_completion_ast, NULL, NULL,
                              NULL, 0, NULL, handles[0]);
        if (rc != ELDLM_OK)
                RETURN(-EIO);
        ldlm_lock_dump_handle(D_OTHER, handles[0]);

        if (memcmp(res_id[0], res_id[1], sizeof(*res_id[0])) == 0) {
                memcpy(handles[1], handles[0], sizeof(*(handles[1])));
                ldlm_lock_addref(handles[1], lock_modes[1]);
        } else if (res_id[1]->name[0] != 0) {
                flags = LDLM_FL_LOCAL_ONLY;
                rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace,
                                      *res_id[1], LDLM_PLAIN, NULL,
                                      lock_modes[1], &flags, mds_blocking_ast,
                                      ldlm_completion_ast, NULL, NULL, NULL, 0,
                                      NULL, handles[1]);
                if (rc != ELDLM_OK) {
                        ldlm_lock_decref(handles[0], lock_modes[0]);
                        RETURN(-EIO);
                }
                ldlm_lock_dump_handle(D_OTHER, handles[1]);
        }

        RETURN(0);
}

int enqueue_4ordered_locks(struct obd_device *obd,struct ldlm_res_id *p1_res_id,
                           struct lustre_handle *p1_lockh, int p1_lock_mode,
                           struct ldlm_res_id *p2_res_id,
                           struct lustre_handle *p2_lockh, int p2_lock_mode,
                           struct ldlm_res_id *c1_res_id,
                           struct lustre_handle *c1_lockh, int c1_lock_mode,
                           struct ldlm_res_id *c2_res_id,
                           struct lustre_handle *c2_lockh, int c2_lock_mode)
{
        struct ldlm_res_id *res_id[5] = { p1_res_id, p2_res_id,
                                          c1_res_id, c2_res_id };
        struct lustre_handle *dlm_handles[5] = { p1_lockh, p2_lockh,
                                                 c1_lockh, c2_lockh };
        int lock_modes[5] = { p1_lock_mode, p2_lock_mode,
                              c1_lock_mode, c2_lock_mode };
        int rc, i, j, sorted, flags;
        ENTRY;

        CDEBUG(D_DLMTRACE, "locks before: "LPU64"/"LPU64"/"LPU64"/"LPU64"\n",
               res_id[0]->name[0], res_id[1]->name[0], res_id[2]->name[0],
               res_id[3]->name[0]);

        /* simple insertion sort - we have at most 4 elements */
        for (i = 1; i < 4; i++) {
                j = i - 1;
                dlm_handles[4] = dlm_handles[i];
                res_id[4] = res_id[i];
                lock_modes[4] = lock_modes[i];

                sorted = 0;
                do {
                        if (res_gt(res_id[j], res_id[4])) {
                                dlm_handles[j + 1] = dlm_handles[j];
                                res_id[j + 1] = res_id[j];
                                lock_modes[j + 1] = lock_modes[j];
                                j--;
                        } else {
                                sorted = 1;
                        }
                } while (j >= 0 && !sorted);

                dlm_handles[j + 1] = dlm_handles[4];
                res_id[j + 1] = res_id[4];
                lock_modes[j + 1] = lock_modes[4];
        }

        CDEBUG(D_DLMTRACE, "lock order: "LPU64"/"LPU64"/"LPU64"/"LPU64"\n",
               res_id[0]->name[0], res_id[1]->name[0], res_id[2]->name[0],
               res_id[3]->name[0]);

        /* XXX we could send ASTs on all these locks first before blocking? */
        for (i = 0; i < 4; i++) {
                flags = 0;
                if (res_id[i]->name[0] == 0)
                        break;
                if (i != 0 &&
                    memcmp(res_id[i], res_id[i-1], sizeof(*res_id[i])) == 0) {
                        memcpy(dlm_handles[i], dlm_handles[i-1],
                               sizeof(*(dlm_handles[i])));
                        ldlm_lock_addref(dlm_handles[i], lock_modes[i]);
                } else {
                        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace,
                                              *res_id[i], LDLM_PLAIN, NULL,
                                              lock_modes[i], &flags,
                                              mds_blocking_ast,
                                              ldlm_completion_ast, NULL, NULL,
                                              NULL, 0, NULL, dlm_handles[i]);
                        if (rc != ELDLM_OK)
                                GOTO(out_err, rc = -EIO);
                        ldlm_lock_dump_handle(D_OTHER, dlm_handles[i]);
                }
        }

        RETURN(0);
out_err:
        while (i-- > 0)
                ldlm_lock_decref(dlm_handles[i], lock_modes[i]);

        return rc;
}

/* In the unlikely case that the child changed while we were waiting
 * on the lock, we need to drop the lock on the old child and either:
 * - if the child has a lower resource name, then we have to also
 *   drop the parent lock and regain the locks in the right order
 * - in the rename case, if the child has a lower resource name than one of
 *   the other parent/child resources (maxres) we also need to reget the locks
 * - if the child has a higher resource name (this is the common case)
 *   we can just get the lock on the new child (still in lock order)
 *
 * Returns 0 if the child did not change or if it changed but could be locked.
 * Returns 1 if the child changed and we need to re-lock (no locks held).
 * Returns -ve error with a valid dchild (no locks held). */
static int mds_verify_child(struct obd_device *obd,
                            struct ldlm_res_id *parent_res_id,
                            struct lustre_handle *parent_lockh,
                            struct dentry *dparent, int parent_mode,
                            struct ldlm_res_id *child_res_id,
                            struct lustre_handle *child_lockh,
                            struct dentry **dchildp, int child_mode,
                            const char *name, int namelen,
                            struct ldlm_res_id *maxres)
{
        struct dentry *vchild, *dchild = *dchildp;
        int rc = 0, cleanup_phase = 2; /* parent, child locks */
        ENTRY;

        vchild = ll_lookup_one_len(name, dparent, namelen - 1);
        if (IS_ERR(vchild))
                GOTO(cleanup, rc = PTR_ERR(vchild));

        if (likely((vchild->d_inode == NULL && child_res_id->name[0] == 0) ||
                   (vchild->d_inode != NULL &&
                    child_res_id->name[0] == vchild->d_inode->i_ino &&
                    child_res_id->name[1] == vchild->d_inode->i_generation))) {
                if (dchild != NULL)
                        l_dput(dchild);
                *dchildp = vchild;

                RETURN(0);
        }

        CDEBUG(D_DLMTRACE, "child inode changed: %p != %p (%lu != "LPU64")\n",
               vchild->d_inode, dchild ? dchild->d_inode : 0,
               vchild->d_inode ? vchild->d_inode->i_ino : 0,
               child_res_id->name[0]);
        if (child_res_id->name[0] != 0)
                ldlm_lock_decref(child_lockh, child_mode);
        if (dchild)
                l_dput(dchild);

        cleanup_phase = 1; /* parent lock only */
        *dchildp = dchild = vchild;

        if (dchild->d_inode) {
                int flags = 0;
                child_res_id->name[0] = dchild->d_inode->i_ino;
                child_res_id->name[1] = dchild->d_inode->i_generation;

                if (res_gt(parent_res_id, child_res_id) ||
                    res_gt(maxres, child_res_id)) {
                        CDEBUG(D_DLMTRACE, "relock "LPU64"<("LPU64"|"LPU64")\n",
                               child_res_id->name[0], parent_res_id->name[0],
                               maxres->name[0]);
                        GOTO(cleanup, rc = 1);
                }

                rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace,
                                      *child_res_id, LDLM_PLAIN, NULL,
                                      child_mode, &flags, mds_blocking_ast,
                                      ldlm_completion_ast, NULL, NULL, NULL, 0,
                                      NULL, child_lockh);
                if (rc != ELDLM_OK)
                        GOTO(cleanup, rc = -EIO);
        } else {
                memset(child_res_id, 0, sizeof(*child_res_id));
        }

        EXIT;
cleanup:
        if (rc) {
                switch(cleanup_phase) {
                case 2:
                        if (child_res_id->name[0] != 0)
                                ldlm_lock_decref(child_lockh, child_mode);
                case 1:
                        ldlm_lock_decref(parent_lockh, parent_mode);
                }
        }
        return rc;
}

int mds_get_parent_child_locked(struct obd_device *obd, struct mds_obd *mds,
                                struct ll_fid *fid,
                                struct lustre_handle *parent_lockh,
                                struct dentry **dparentp, int parent_mode,
                                char *name, int namelen,
                                struct lustre_handle *child_lockh,
                                struct dentry **dchildp, int child_mode)
{
        struct ldlm_res_id child_res_id = { .name = {0} };
        struct ldlm_res_id parent_res_id = { .name = {0} };
        struct inode *inode;
        int rc = 0, cleanup_phase = 0;
        ENTRY;

        /* Step 1: Lookup parent */
        *dparentp = mds_fid2dentry(mds, fid, NULL);
        if (IS_ERR(*dparentp))
                RETURN(rc = PTR_ERR(*dparentp));
        LASSERT((*dparentp)->d_inode);

        CDEBUG(D_INODE, "parent ino %lu, name %s\n",
               (*dparentp)->d_inode->i_ino, name);

        parent_res_id.name[0] = (*dparentp)->d_inode->i_ino;
        parent_res_id.name[1] = (*dparentp)->d_inode->i_generation;

        cleanup_phase = 1; /* parent dentry */

        /* Step 2: Lookup child (without DLM lock, to get resource name) */
        *dchildp = ll_lookup_one_len(name, *dparentp, namelen - 1);
        if (IS_ERR(*dchildp)) {
                rc = PTR_ERR(*dchildp);
                CDEBUG(D_INODE, "child lookup error %d\n", rc);
                GOTO(cleanup, rc);
        }

        inode = (*dchildp)->d_inode;
        if (inode != NULL)
                inode = igrab(inode);
        if (inode == NULL)
                goto retry_locks;

        child_res_id.name[0] = inode->i_ino;
        child_res_id.name[1] = inode->i_generation;
        iput(inode);

retry_locks:
        cleanup_phase = 2; /* child dentry */

        /* Step 3: Lock parent and child in resource order.  If child doesn't
         *         exist, we still have to lock the parent and re-lookup. */
        rc = enqueue_ordered_locks(obd, &parent_res_id,parent_lockh,parent_mode,
                                   &child_res_id, child_lockh, child_mode);
        if (rc)
                GOTO(cleanup, rc);

        if (!(*dchildp)->d_inode)
                cleanup_phase = 3; /* parent lock */
        else
                cleanup_phase = 4; /* child lock */

        /* Step 4: Re-lookup child to verify it hasn't changed since locking */
        rc = mds_verify_child(obd, &parent_res_id, parent_lockh, *dparentp,
                              parent_mode, &child_res_id, child_lockh, dchildp,
                              child_mode, name, namelen, &parent_res_id);
        if (rc > 0)
                goto retry_locks;
        if (rc < 0) {
                cleanup_phase = 3;
                GOTO(cleanup, rc);
        }

cleanup:
        if (rc) {
                switch (cleanup_phase) {
                case 4:
                        ldlm_lock_decref(child_lockh, child_mode);
                case 3:
                        ldlm_lock_decref(parent_lockh, parent_mode);
                case 2:
                        l_dput(*dchildp);
                case 1:
                        l_dput(*dparentp);
                default: ;
                }
        }
        return rc;
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
        struct dentry *dparent, *dchild;
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_body *body = NULL;
        struct inode *child_inode;
        struct lustre_handle parent_lockh, child_lockh, child_reuse_lockh;
        void *handle = NULL;
        int rc = 0, log_unlink = 0, cleanup_phase = 0;
        ENTRY;

        LASSERT(offset == 0 || offset == 2);

        DEBUG_REQ(D_INODE, req, "parent ino "LPU64"/%u, child %s",
                  rec->ur_fid1->id, rec->ur_fid1->generation, rec->ur_name);

        MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNLINK))
                GOTO(cleanup, rc = -ENOENT);

        rc = mds_get_parent_child_locked(obd, mds, rec->ur_fid1,
                                         &parent_lockh, &dparent, LCK_PW,
                                         rec->ur_name, rec->ur_namelen,
                                         &child_lockh, &dchild, LCK_EX);
        if (rc)
                GOTO(cleanup, rc);

        cleanup_phase = 1; /* dchild, dparent, locks */

        child_inode = dchild->d_inode;
        if (child_inode == NULL) {
                CDEBUG(D_INODE, "child doesn't exist (dir %lu, name %s)\n",
                       dparent->d_inode->i_ino, rec->ur_name);
                GOTO(cleanup, rc = -ENOENT);
        }

        cleanup_phase = 2; /* dchild has a lock */

        /* Step 4: Get a lock on the ino to sync with creation WRT inode
         * reuse (see bug 2029). */
        rc = mds_lock_new_child(obd, child_inode, &child_reuse_lockh);
        if (rc != ELDLM_OK)
                GOTO(cleanup, rc);

        cleanup_phase = 3; /* child inum lock */

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
                cleanup_phase = 4; /* transaction */
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
                cleanup_phase = 4; /* transaction */
                rc = vfs_rmdir(dparent->d_inode, dchild);
                break;
        case S_IFREG: {
                struct lov_mds_md *lmm = lustre_msg_buf(req->rq_repmsg,
                                                        offset + 1, 0);
                handle = fsfilt_start_log(obd, dparent->d_inode,
                                          FSFILT_OP_UNLINK, NULL,
                                          le32_to_cpu(lmm->lmm_stripe_count));
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));

                cleanup_phase = 4; /* transaction */
                rc = vfs_unlink(dparent->d_inode, dchild);

                if (!rc && log_unlink)
                        if (mds_log_op_unlink(obd, child_inode,
                                lustre_msg_buf(req->rq_repmsg, offset + 1, 0),
                                req->rq_repmsg->buflens[offset + 1],
                                lustre_msg_buf(req->rq_repmsg, offset + 2, 0),
                                req->rq_repmsg->buflens[offset + 2]) > 0)
                                body->valid |= OBD_MD_FLCOOKIE;
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
                cleanup_phase = 4; /* transaction */
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
        case 4:
                rc = mds_finish_transno(mds, dparent->d_inode, handle, req,
                                        rc, 0);
                if (!rc)
                        (void)obd_set_info(mds->mds_osc_exp, strlen("unlinked"),
                                           "unlinked", 0, NULL);
        case 3: /* child ino-reuse lock */
                if (rc && body != NULL) {
                        // Don't unlink the OST objects if the MDS unlink failed
                        body->valid = 0;
                }
                if (rc)
                        ldlm_lock_decref(&child_reuse_lockh, LCK_EX);
                else
                        ptlrpc_save_lock(req, &child_reuse_lockh, LCK_EX);
        case 2: /* child lock */
                ldlm_lock_decref(&child_lockh, LCK_EX);
        case 1: /* child and parent dentry, parent lock */
                if (rc)
                        ldlm_lock_decref(&parent_lockh, LCK_PW);
                else
                        ptlrpc_save_lock(req, &parent_lockh, LCK_PW);
                l_dput(dchild);
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
        int rc = 0, cleanup_phase = 0;
        ENTRY;

        LASSERT(offset == 0);

        DEBUG_REQ(D_INODE, req, "original "LPU64"/%u to "LPU64"/%u %s",
                  rec->ur_fid1->id, rec->ur_fid1->generation,
                  rec->ur_fid2->id, rec->ur_fid2->generation, rec->ur_name);

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
        src_res_id.name[0] = de_src->d_inode->i_ino;
        src_res_id.name[1] = de_src->d_inode->i_generation;
        tgt_dir_res_id.name[0] = de_tgt_dir->d_inode->i_ino;
        tgt_dir_res_id.name[1] = de_tgt_dir->d_inode->i_generation;

        rc = enqueue_ordered_locks(obd, &src_res_id, &src_lockh, LCK_EX,
                                   &tgt_dir_res_id, &tgt_dir_lockh, LCK_EX);
        if (rc)
                GOTO(cleanup, rc);

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
                        ldlm_lock_decref(&src_lockh, LCK_EX);
                        ldlm_lock_decref(&tgt_dir_lockh, LCK_EX);
                } else {
                        ptlrpc_save_lock(req, &src_lockh, LCK_EX);
                        ptlrpc_save_lock(req, &tgt_dir_lockh, LCK_EX);
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

/* The idea here is that we need to get four locks in the end:
 * one on each parent directory, one on each child.  We need to take
 * these locks in some kind of order (to avoid deadlocks), and the order
 * I selected is "increasing resource number" order.  We need to look up
 * the children, however, before we know what the resource number(s) are.
 * Thus the following plan:
 *
 * 1,2. Look up the parents
 * 3,4. Look up the children
 * 5. Take locks on the parents and children, in order
 * 6. Verify that the children haven't changed since they were looked up
 *
 * If there was a race and the children changed since they were first looked
 * up, it is possible that mds_verify_child() will be able to just grab the
 * lock on the new child resource (if it has a higher resource than any other)
 * but we need to compare against not only its parent, but also against the
 * parent and child of the "other half" of the rename, hence maxres_{src,tgt}.
 *
 * We need the fancy igrab() on the child inodes because we aren't holding a
 * lock on the parent after the lookup is done, so dentry->d_inode may change
 * at any time, and igrab() itself doesn't like getting passed a NULL argument.
 */
static int mds_get_parents_children_locked(struct obd_device *obd,
                                           struct mds_obd *mds,
                                           struct ll_fid *p1_fid,
                                           struct dentry **de_srcdirp,
                                           struct ll_fid *p2_fid,
                                           struct dentry **de_tgtdirp,
                                           int parent_mode,
                                           const char *old_name, int old_len,
                                           struct dentry **de_oldp,
                                           const char *new_name, int new_len,
                                           struct dentry **de_newp,
                                           struct lustre_handle *dlm_handles,
                                           int child_mode)
{
        struct ldlm_res_id p1_res_id = { .name = {0} };
        struct ldlm_res_id p2_res_id = { .name = {0} };
        struct ldlm_res_id c1_res_id = { .name = {0} };
        struct ldlm_res_id c2_res_id = { .name = {0} };
        struct ldlm_res_id *maxres_src, *maxres_tgt;
        struct inode *inode;
        int rc = 0, cleanup_phase = 0;
        ENTRY;

        /* Step 1: Lookup the source directory */
        *de_srcdirp = mds_fid2dentry(mds, p1_fid, NULL);
        if (IS_ERR(*de_srcdirp))
                GOTO(cleanup, rc = PTR_ERR(*de_srcdirp));

        cleanup_phase = 1; /* source directory dentry */

        p1_res_id.name[0] = (*de_srcdirp)->d_inode->i_ino;
        p1_res_id.name[1] = (*de_srcdirp)->d_inode->i_generation;

        /* Step 2: Lookup the target directory */
        if (memcmp(p1_fid, p2_fid, sizeof(*p1_fid)) == 0) {
                *de_tgtdirp = dget(*de_srcdirp);
        } else {
                *de_tgtdirp = mds_fid2dentry(mds, p2_fid, NULL);
                if (IS_ERR(*de_tgtdirp))
                        GOTO(cleanup, rc = PTR_ERR(*de_tgtdirp));
        }

        cleanup_phase = 2; /* target directory dentry */

        p2_res_id.name[0] = (*de_tgtdirp)->d_inode->i_ino;
        p2_res_id.name[1] = (*de_tgtdirp)->d_inode->i_generation;

        /* Step 3: Lookup the source child entry */
        *de_oldp = ll_lookup_one_len(old_name, *de_srcdirp, old_len - 1);
        if (IS_ERR(*de_oldp)) {
                rc = PTR_ERR(*de_oldp);
                CERROR("old child lookup error (%*s): %d\n",
                       old_len - 1, old_name, rc);
                GOTO(cleanup, rc);
        }

        cleanup_phase = 3; /* original name dentry */

        inode = (*de_oldp)->d_inode;
        if (inode != NULL)
                inode = igrab(inode);
        if (inode == NULL)
                GOTO(cleanup, rc = -ENOENT);

        c1_res_id.name[0] = inode->i_ino;
        c1_res_id.name[1] = inode->i_generation;
        iput(inode);

        /* Step 4: Lookup the target child entry */
        *de_newp = ll_lookup_one_len(new_name, *de_tgtdirp, new_len - 1);
        if (IS_ERR(*de_newp)) {
                rc = PTR_ERR(*de_newp);
                CERROR("new child lookup error (%*s): %d\n",
                       old_len - 1, old_name, rc);
                GOTO(cleanup, rc);
        }

        cleanup_phase = 4; /* target dentry */

        inode = (*de_newp)->d_inode;
        if (inode != NULL)
                inode = igrab(inode);
        if (inode == NULL)
                goto retry_locks;

        c2_res_id.name[0] = inode->i_ino;
        c2_res_id.name[1] = inode->i_generation;
        iput(inode);

retry_locks:
        /* Step 5: Take locks on the parents and child(ren) */
        maxres_src = &p1_res_id;
        maxres_tgt = &p2_res_id;
        cleanup_phase = 4; /* target dentry */

        if (c1_res_id.name[0] != 0 && res_gt(&c1_res_id, &p1_res_id))
                maxres_src = &c1_res_id;
        if (c2_res_id.name[0] != 0 && res_gt(&c2_res_id, &p2_res_id))
                maxres_tgt = &c2_res_id;

        rc = enqueue_4ordered_locks(obd, &p1_res_id,&dlm_handles[0],parent_mode,
                                    &p2_res_id, &dlm_handles[1], parent_mode,
                                    &c1_res_id, &dlm_handles[2], child_mode,
                                    &c2_res_id, &dlm_handles[3], child_mode);
        if (rc)
                GOTO(cleanup, rc);

        cleanup_phase = 6; /* parent and child(ren) locks */

        /* Step 6a: Re-lookup source child to verify it hasn't changed */
        rc = mds_verify_child(obd, &p1_res_id, &dlm_handles[0], *de_srcdirp,
                              parent_mode, &c1_res_id, &dlm_handles[2], de_oldp,
                              child_mode, old_name, old_len, maxres_tgt);
        if (rc) {
                if (c2_res_id.name[0] != 0)
                        ldlm_lock_decref(&dlm_handles[3], child_mode);
                ldlm_lock_decref(&dlm_handles[1], parent_mode);
                cleanup_phase = 4;
                if (rc > 0)
                        goto retry_locks;
                GOTO(cleanup, rc);
        }

        if ((*de_oldp)->d_inode == NULL)
                GOTO(cleanup, rc = -ENOENT);

        /* Step 6b: Re-lookup target child to verify it hasn't changed */
        rc = mds_verify_child(obd, &p2_res_id, &dlm_handles[1], *de_tgtdirp,
                              parent_mode, &c2_res_id, &dlm_handles[3], de_newp,
                              child_mode, new_name, new_len, maxres_src);
        if (rc) {
                ldlm_lock_decref(&dlm_handles[2], child_mode);
                ldlm_lock_decref(&dlm_handles[0], parent_mode);
                cleanup_phase = 4;
                if (rc > 0)
                        goto retry_locks;
                GOTO(cleanup, rc);
        }

        EXIT;
cleanup:
        if (rc) {
                switch (cleanup_phase) {
                case 6: /* child lock(s) */
                        if (c2_res_id.name[0] != 0)
                                ldlm_lock_decref(&dlm_handles[3], child_mode);
                        if (c1_res_id.name[0] != 0)
                                ldlm_lock_decref(&dlm_handles[2], child_mode);
                case 5: /* parent locks */
                        ldlm_lock_decref(&dlm_handles[1], parent_mode);
                        ldlm_lock_decref(&dlm_handles[0], parent_mode);
                case 4: /* target dentry */
                        l_dput(*de_newp);
                case 3: /* source dentry */
                        l_dput(*de_oldp);
                case 2: /* target directory dentry */
                        l_dput(*de_tgtdirp);
                case 1: /* source directry dentry */
                        l_dput(*de_srcdirp);
                }
        }

        return rc;
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
        struct mds_body *body = NULL;
        int rc = 0, lock_count = 3;
        int cleanup_phase = 0;
        void *handle = NULL;
        ENTRY;

        LASSERT(offset == 0);

        DEBUG_REQ(D_INODE, req, "parent "LPU64"/%u %s to "LPU64"/%u %s",
                  rec->ur_fid1->id, rec->ur_fid1->generation, rec->ur_name,
                  rec->ur_fid2->id, rec->ur_fid2->generation, rec->ur_tgt);

        MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));

        rc = mds_get_parents_children_locked(obd, mds, rec->ur_fid1, &de_srcdir,
                                             rec->ur_fid2, &de_tgtdir, LCK_PW,
                                             rec->ur_name, rec->ur_namelen,
                                             &de_old, rec->ur_tgt,
                                             rec->ur_tgtlen, &de_new,
                                             dlm_handles, LCK_EX);
        if (rc)
                GOTO(cleanup, rc);

        cleanup_phase = 1; /* parent(s), children, locks */

        if (de_new->d_inode)
                lock_count = 4;

        /* sanity check for src inode */
        if (de_old->d_inode->i_ino == de_srcdir->d_inode->i_ino ||
            de_old->d_inode->i_ino == de_tgtdir->d_inode->i_ino)
                GOTO(cleanup, rc = -EINVAL);

        /* sanity check for dest inode */
        if (de_new->d_inode &&
            (de_new->d_inode->i_ino == de_srcdir->d_inode->i_ino ||
             de_new->d_inode->i_ino == de_tgtdir->d_inode->i_ino))
                GOTO(cleanup, rc = -EINVAL);

        if (de_old->d_inode == de_new->d_inode) {
                GOTO(cleanup, rc = 0);
        }

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

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_RENAME_WRITE,
                       de_srcdir->d_inode->i_sb);

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

        GOTO(cleanup, rc);
cleanup:
        rc = mds_finish_transno(mds, de_tgtdir ? de_tgtdir->d_inode : NULL,
                                handle, req, rc, 0);
        switch (cleanup_phase) {
        case 1:
                if (rc) {
                        if (lock_count == 4)
                                ldlm_lock_decref(&(dlm_handles[3]), LCK_EX);
                        ldlm_lock_decref(&(dlm_handles[2]), LCK_EX);
                        ldlm_lock_decref(&(dlm_handles[1]), LCK_PW);
                        ldlm_lock_decref(&(dlm_handles[0]), LCK_PW);
                } else {
                        if (lock_count == 4)
                                ptlrpc_save_lock(req,
                                              &(dlm_handles[3]), LCK_EX);
                        ptlrpc_save_lock(req, &(dlm_handles[2]), LCK_EX);
                        ptlrpc_save_lock(req, &(dlm_handles[1]), LCK_PW);
                        ptlrpc_save_lock(req, &(dlm_handles[0]), LCK_PW);
                }
                l_dput(de_new);
                l_dput(de_old);
                l_dput(de_tgtdir);
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
        [REINT_LINK] mds_reint_link,
        [REINT_UNLINK] mds_reint_unlink,
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
