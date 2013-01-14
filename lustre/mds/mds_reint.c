/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mds/mds_reint.c
 *
 * Lustre Metadata Server (mds) reintegration routines
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/fs.h>
#include <obd_support.h>
#include <obd_class.h>
#include <obd.h>
#include <lustre_lib.h>
#include <lustre/lustre_idl.h>
#include <lustre_mds.h>
#include <lustre_dlm.h>
#include <lustre_fsfilt.h>
#include <lustre_ucache.h>
#include <lustre_net.h>

#include "mds_internal.h"

void mds_commit_cb(struct obd_device *obd, __u64 transno, void *data,
                   int error)
{
        struct obd_export *exp = data;
        LASSERTF(exp->exp_obd == obd,
                 "%s: bad export (%p), obd (%p) != exp->exp_obd (%p)\n",
                 obd->obd_name, exp, obd, exp->exp_obd);
        obd_transno_commit_cb(obd, transno, exp, error);
        class_export_put(exp);
}

struct mds_logcancel_data {
        struct lov_mds_md      *mlcd_lmm;
        int                     mlcd_size;
        int                     mlcd_cookielen;
        int                     mlcd_eadatalen;
        struct llog_cookie      mlcd_cookies[0];
};

/** lookup child dentry in parent dentry according to the name.
 *  if dentry is found, delete "lustre_mdt_attrs" EA (with name "lma")
 *  if it exists by checking OBD_INCOMPAT_FID.
 */
struct dentry *mds_lookup(struct obd_device *obd, const char *fid_name,
                          struct dentry *dparent, int fid_namelen)
{
        struct dentry *dchild;
        struct lr_server_data *lsd = obd->u.mds.mds_server_data;
        int rc;
        ENTRY;

        dchild = ll_lookup_one_len(fid_name, dparent, fid_namelen);

        if (!IS_ERR(dchild) && (dchild->d_inode != NULL) &&
            unlikely((lsd->lsd_feature_incompat & OBD_INCOMPAT_FID) ||
                      OBD_FAIL_CHECK(OBD_FAIL_MDS_REMOVE_COMMON_EA))) {
                struct inode *inode = dchild->d_inode;
                void         *handle;

                LOCK_INODE_MUTEX(inode);
                if (fsfilt_get_md(obd, inode, NULL, 0, "lma") > 0) {
                        int rc2;

                        handle = fsfilt_start(obd, inode,
                                              FSFILT_OP_SETATTR, NULL);
                        if (IS_ERR(handle))
                                GOTO(err, rc = PTR_ERR(handle));

                        rc = fsfilt_set_md(obd, inode, handle, NULL, 0, "lma");

                        /* Force sync. Needed to avoid a case when client gets
                         * IGIF, MDS fails to write this info to disk, upgrade
                         * happens and FID is alive but client caches IGIF.
                         * This is a performance killer, but happens only after
                         * upgrade, downgrade, only for the 1st access to files
                         * with LMA, i.e. created after upgrade.
                         * As downgrade is an emergency unexpected case, this
                         * is a feasible way. */
                        rc2 = fsfilt_commit(obd, inode, handle, 1);
                        if (rc != 0 || rc2 != 0)
                                GOTO(err, rc = rc ?: rc2);
                }
                UNLOCK_INODE_MUTEX(inode);
        }
        RETURN(dchild);
err:
        UNLOCK_INODE_MUTEX(dchild->d_inode);
        l_dput(dchild);
        return ERR_PTR(rc);
}

static void mds_cancel_cookies_cb(struct obd_device *obd, __u64 transno,
                                  void *cb_data, int error)
{
        struct mds_logcancel_data *mlcd = cb_data;
        struct lov_stripe_md *lsm = NULL;
        struct llog_ctxt *ctxt;
        int rc;

        obd_transno_commit_cb(obd, transno, NULL, error);

        CDEBUG(D_RPCTRACE, "cancelling %d cookies\n",
               (int)(mlcd->mlcd_cookielen / sizeof(*mlcd->mlcd_cookies)));

        rc = obd_unpackmd(obd->u.mds.mds_lov_exp, &lsm, mlcd->mlcd_lmm,
                          mlcd->mlcd_eadatalen);
        if (rc < 0) {
                CERROR("bad LSM cancelling %d log cookies: rc %d\n",
                       (int)(mlcd->mlcd_cookielen/sizeof(*mlcd->mlcd_cookies)),
                       rc);
        } else {
                rc = obd_checkmd(obd->u.mds.mds_lov_exp, obd->obd_self_export,
                                 lsm);
                if (rc)
                        CERROR("Can not revalidate lsm %p \n", lsm);

                ctxt = llog_get_context(obd,mlcd->mlcd_cookies[0].lgc_subsys+1);
                /* XXX 0 normally, SENDNOW for debug */
                rc = llog_cancel(ctxt, lsm, mlcd->mlcd_cookielen /
                                                sizeof(*mlcd->mlcd_cookies),
                                 mlcd->mlcd_cookies, OBD_LLOG_FL_SENDNOW);
                llog_ctxt_put(ctxt);

                if (rc)
                        CERROR("error cancelling %d log cookies: rc %d\n",
                               (int)(mlcd->mlcd_cookielen /
                                     sizeof(*mlcd->mlcd_cookies)), rc);
        }

        OBD_FREE(mlcd, mlcd->mlcd_size);
}

/* fsfilt_set_version return old version. use that here */
static void mds_versions_set(struct obd_device *obd,
                             struct inode **inodes, __u64 version)
{
        int i;

        if (inodes == NULL)
                return;

        for (i = 0; i < PTLRPC_NUM_VERSIONS; i++)
                if (inodes[i] != NULL)
                        fsfilt_set_version(obd, inodes[i], version);
}

int mds_version_get_check(struct ptlrpc_request *req, struct inode *inode,
                          int index)
{
        /* version recovery */
        struct obd_device *obd = req->rq_export->exp_obd;
        __u64 curr_version, *pre_versions;
        ENTRY;

        if (inode == NULL || !exp_connect_vbr(req->rq_export))
                RETURN(0);

        curr_version = fsfilt_get_version(obd, inode);
        if ((__s64)curr_version == -EOPNOTSUPP)
                RETURN(0);
        /* VBR: version is checked always because costs nothing */
        if (lustre_msg_get_transno(req->rq_reqmsg) != 0) {
                pre_versions = lustre_msg_get_versions(req->rq_reqmsg);
                LASSERT(index < PTLRPC_NUM_VERSIONS);
                /* Sanity check for malformed buffers */
                if (pre_versions == NULL) {
                        CERROR("No versions in request buffer\n");
                        spin_lock(&req->rq_export->exp_lock);
                        req->rq_export->exp_vbr_failed = 1;
                        spin_unlock(&req->rq_export->exp_lock);
                        RETURN(-EOVERFLOW);
                } else if (pre_versions[index] != curr_version) {
                        CDEBUG(D_INODE, "Version mismatch "LPX64" != "LPX64"\n",
                               pre_versions[index], curr_version);
                        spin_lock(&req->rq_export->exp_lock);
                        req->rq_export->exp_vbr_failed = 1;
                        spin_unlock(&req->rq_export->exp_lock);
                        RETURN(-EOVERFLOW);
                }
        }
        /* save pre-versions in reply */
        LASSERT(req->rq_repmsg != NULL);
        pre_versions = lustre_msg_get_versions(req->rq_repmsg);
        if (pre_versions)
                pre_versions[index] = curr_version;
        RETURN(0);
}

/* Assumes caller has already pushed us into the kernel context. */
int mds_finish_transno(struct mds_obd *mds, struct inode **inodes, void *handle,
                       struct ptlrpc_request *req, int rc, __u32 op_data,
                       int force_sync)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct lsd_client_data *lcd = med->med_lcd;
        struct obd_device *obd = req->rq_export->exp_obd;
        __u64 transno, prev_transno;
        int err;
        loff_t off;
        struct inode *inode = inodes ? inodes[0] : NULL;
        int version_set = handle ? 1 : 0;
        ENTRY;

        if (IS_ERR(handle)) {
                LASSERT(rc != 0);
                RETURN(rc);
        }

        /* if the export has already been failed, we have no last_rcvd slot */
        if (req->rq_export->exp_failed || obd->obd_fail) {
                CWARN("commit transaction for disconnected client %s: rc %d\n",
                      req->rq_export->exp_client_uuid.uuid, rc);
                if (rc == 0)
                        rc = -ENOTCONN;
                if (handle)
                        GOTO(commit, rc);
                RETURN(rc);
        }

        if (handle == NULL) {
                /* if we're starting our own xaction, use our own inode */
                inode = mds->mds_rcvd_filp->f_dentry->d_inode;
                handle = fsfilt_start(obd, inode, FSFILT_OP_SETATTR, NULL);
                if (IS_ERR(handle)) {
                        CERROR("fsfilt_start: %ld\n", PTR_ERR(handle));
                        RETURN(PTR_ERR(handle));
                }
        }

        off = med->med_lr_off;

        transno = lustre_msg_get_transno(req->rq_reqmsg);
        if (rc != 0) {
                if (transno != 0) {
                        CERROR("%s: replay %s transno "LPU64" failed: rc %d\n",
                               obd->obd_name,
                               libcfs_nid2str(req->rq_export->exp_connection->c_peer.nid),
                               transno, rc);
                }
        } else if (transno == 0) {
                spin_lock(&mds->mds_transno_lock);
                transno = ++mds->mds_last_transno;
                spin_unlock(&mds->mds_transno_lock);
                /* VBR: set versions */
                if (inodes && version_set)
                        mds_versions_set(obd, inodes, transno);
        } else {
                spin_lock(&mds->mds_transno_lock);
                if (transno > mds->mds_last_transno)
                        mds->mds_last_transno = transno;
                spin_unlock(&mds->mds_transno_lock);

                /* VBR: replay case. Copy version from replay req and
                 * set new versions */
                mds_versions_set(obd, inodes, transno);
        }

        req->rq_transno = transno;
        lustre_msg_set_transno(req->rq_repmsg, transno);

        if (transno == 0)
                LASSERT(rc != 0);
        if (lustre_msg_get_opc(req->rq_reqmsg) == MDS_CLOSE) {
                if (transno != 0)
                        lcd->lcd_last_close_transno = cpu_to_le64(transno);
                lcd->lcd_last_close_xid = cpu_to_le64(req->rq_xid);
                lcd->lcd_last_close_result = cpu_to_le32(rc);
                lcd->lcd_last_close_data = cpu_to_le32(op_data);
        } else {
                prev_transno = le64_to_cpu(lcd->lcd_last_transno);
                if (((lustre_msg_get_flags(req->rq_reqmsg) &
                      (MSG_RESENT | MSG_REPLAY)) == 0) ||
                    (transno > prev_transno)) {
                        /* VBR: save versions in last_rcvd for reconstruct. */
                        __u64 *pre_versions = lustre_msg_get_versions(req->rq_repmsg);
                        if (pre_versions) {
                                lcd->lcd_pre_versions[0] = cpu_to_le64(pre_versions[0]);
                                lcd->lcd_pre_versions[1] = cpu_to_le64(pre_versions[1]);
                                lcd->lcd_pre_versions[2] = cpu_to_le64(pre_versions[2]);
                                lcd->lcd_pre_versions[3] = cpu_to_le64(pre_versions[3]);
                        }
                        if (transno != 0)
                                lcd->lcd_last_transno = cpu_to_le64(transno);
                        lcd->lcd_last_xid     = cpu_to_le64(req->rq_xid);
                        lcd->lcd_last_result  = cpu_to_le32(rc);
                        lcd->lcd_last_data    = cpu_to_le32(op_data);
                }
        }
        /** update trans table */
        target_trans_table_update(req->rq_export, transno);

        if (off <= 0) {
                CERROR("client idx %d has offset %lld\n", med->med_lr_idx, off);
                err = -EINVAL;
        } else {
                struct obd_export *exp = req->rq_export;

                class_export_get(exp); /* released once the cb is called */
                if (!force_sync)
                        force_sync = fsfilt_add_journal_cb(obd, transno,
                                                           handle, mds_commit_cb,
                                                           exp);

                err = fsfilt_write_record(obd, mds->mds_rcvd_filp, lcd,
                                          sizeof(*lcd), &off,
                                          force_sync | exp->exp_need_sync);
                if (force_sync)
                        mds_commit_cb(obd, transno, exp, err);
        }

        DEBUG_REQ(err ? D_ERROR : D_INFO, req,
                  "wrote trans #"LPU64" rc %d client %s at idx %u: err = %d",
                  transno, rc, lcd->lcd_uuid, med->med_lr_idx, err);

        if (err) {
                if (rc == 0)
                        rc = err;
        }

        err = mds_lov_write_objids(obd);
        if (err) {
                CERROR("wrote objids: err = %d\n", err);
                if (rc == 0)
                        rc = err;
        }

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
        time_t now = CURRENT_SECONDS;
        struct iattr *attr = &rec->ur_iattr;
        unsigned int ia_valid = attr->ia_valid;
        int error, mode;
        ENTRY;

        if (ia_valid & ATTR_RAW)
                attr->ia_valid &= ~ATTR_RAW;

        if (!(ia_valid & ATTR_CTIME_SET))
                LTIME_S(attr->ia_ctime) = now;
        else
                attr->ia_valid &= ~ATTR_CTIME_SET;
        if (!(ia_valid & ATTR_ATIME_SET))
                LTIME_S(attr->ia_atime) = now;
        if (!(ia_valid & ATTR_MTIME_SET))
                LTIME_S(attr->ia_mtime) = now;

        if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
                RETURN((attr->ia_valid & ~ATTR_ATTR_FLAG) ? -EPERM : 0);

        /* times */
        if ((ia_valid & (ATTR_MTIME|ATTR_ATIME)) == (ATTR_MTIME|ATTR_ATIME)) {
                if (current_fsuid() != inode->i_uid &&
                    (error = ll_permission(inode, MAY_WRITE, NULL)) != 0)
                        RETURN(error);
        }

        if (ia_valid & ATTR_SIZE &&
            /* NFSD hack for open(O_CREAT|O_TRUNC)=mknod+truncate (bug 5781) */
            !(rec->ur_uc.luc_fsuid == inode->i_uid &&
              ia_valid & MDS_OPEN_OWNEROVERRIDE)) {
                if ((error = ll_permission(inode, MAY_WRITE, NULL)) != 0)
                        RETURN(error);
        }

        /* Some older clients are broken so we do the client's magic
         * here just in case */
        if ((attr->ia_valid & (ATTR_MODE|ATTR_FORCE|ATTR_SIZE)) ==
            (ATTR_SIZE|ATTR_MODE)) {
                mode = inode->i_mode;
                if (((mode & S_ISUID) && (!(attr->ia_mode & S_ISUID))) ||
                    ((mode & S_ISGID) && (mode & S_IXGRP) &&
                    (!(attr->ia_mode & S_ISGID))))
                        attr->ia_valid |= ATTR_FORCE;
        }

        if (ia_valid & (ATTR_UID | ATTR_GID)) {
                /* chown */
                error = -EPERM;
                if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
                        RETURN(-EPERM);
                if (attr->ia_uid == (uid_t) -1)
                        attr->ia_uid = inode->i_uid;
                if (attr->ia_gid == (gid_t) -1)
                        attr->ia_gid = inode->i_gid;
                if (!(ia_valid & ATTR_MODE))
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
                mode = attr->ia_mode;

                /* chmod */
                if (attr->ia_mode == (umode_t)-1)
                        mode = inode->i_mode;
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
        int                        i;

        /* CAVEAT EMPTOR: spinlock order */
        spin_lock(&exp->exp_lock);
        list_for_each (tmp, &exp->exp_outstanding_replies) {
                oldrep = list_entry(tmp, struct ptlrpc_reply_state,rs_exp_list);

                if (oldrep->rs_xid != req->rq_xid)
                        continue;

                if (lustre_msg_get_opc(oldrep->rs_msg) !=
                    lustre_msg_get_opc(req->rq_reqmsg))
                        CERROR ("Resent req xid "LPU64" has mismatched opc: "
                                "new %d old %d\n", req->rq_xid,
                                lustre_msg_get_opc(req->rq_reqmsg),
                                lustre_msg_get_opc(oldrep->rs_msg));

                svc = oldrep->rs_service;
                spin_lock (&svc->srv_lock);

                list_del_init (&oldrep->rs_exp_list);

                CWARN("Stealing %d locks from rs %p x"LPD64".t"LPD64
                      " o%d NID %s\n",
                      oldrep->rs_nlocks, oldrep,
                      oldrep->rs_xid, oldrep->rs_transno,
                      lustre_msg_get_opc(oldrep->rs_msg),
                      libcfs_nid2str(exp->exp_connection->c_peer.nid));

                for (i = 0; i < oldrep->rs_nlocks; i++)
                        ptlrpc_save_lock(req,
                                         &oldrep->rs_locks[i],
                                         oldrep->rs_modes[i]);
                oldrep->rs_nlocks = 0;

                DEBUG_REQ(D_DLMTRACE, req, "stole locks for");
                ptlrpc_schedule_difficult_reply (oldrep);

                spin_unlock (&svc->srv_lock);
                break;
        }
        spin_unlock(&exp->exp_lock);
}

/**
 * VBR: restore versions
 */
void mds_vbr_reconstruct(struct ptlrpc_request *req,
                         struct lsd_client_data *lcd)
{
        __u64 pre_versions[4] = {0};
        pre_versions[0] = le64_to_cpu(lcd->lcd_pre_versions[0]);
        pre_versions[1] = le64_to_cpu(lcd->lcd_pre_versions[1]);
        pre_versions[2] = le64_to_cpu(lcd->lcd_pre_versions[2]);
        pre_versions[3] = le64_to_cpu(lcd->lcd_pre_versions[3]);
        lustre_msg_set_versions(req->rq_repmsg, pre_versions);
}

void mds_req_from_lcd(struct ptlrpc_request *req, struct lsd_client_data *lcd)
{
        if (lustre_msg_get_opc(req->rq_reqmsg) == MDS_CLOSE) {
                req->rq_transno = le64_to_cpu(lcd->lcd_last_close_transno);
                req->rq_status = le32_to_cpu(lcd->lcd_last_close_result);
        } else {
                req->rq_transno = le64_to_cpu(lcd->lcd_last_transno);
                req->rq_status = le32_to_cpu(lcd->lcd_last_result);
                mds_vbr_reconstruct(req, lcd);
        }
        if (req->rq_status != 0)
                req->rq_transno = 0;
        lustre_msg_set_transno(req->rq_repmsg, req->rq_transno);
        lustre_msg_set_status(req->rq_repmsg, req->rq_status);
        DEBUG_REQ(D_RPCTRACE, req, "restoring transno "LPD64"/status %d",
                  req->rq_transno, req->rq_status);

        mds_steal_ack_locks(req);
}

static void reconstruct_reint_setattr(struct mds_update_record *rec,
                                      int offset, struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct mds_export_data *med = &exp->exp_mds_data;
        struct mds_obd *obd = &exp->exp_obd->u.mds;
        struct dentry *de;
        struct mds_body *body;

        mds_req_from_lcd(req, med->med_lcd);

        de = mds_fid2dentry(obd, rec->ur_fid1, NULL);
        if (IS_ERR(de)) {
                int rc;
                rc = PTR_ERR(de);
                LCONSOLE_WARN("FID "LPU64"/%u lookup error %d."
                              " Evicting client %s with export %s.\n",
                              rec->ur_fid1->id, rec->ur_fid1->generation, rc,
                              obd_uuid2str(&exp->exp_client_uuid),
                              obd_export_nid2str(exp));
                mds_export_evict(exp);
                EXIT;
                return;
        }

        body = lustre_msg_buf(req->rq_repmsg, offset, sizeof(*body));
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

int mds_osc_setattr_async(struct obd_device *obd, struct inode *inode,
                          struct lov_mds_md *lmm, int lmm_size,
                          struct llog_cookie *logcookies, struct ll_fid *fid)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_trans_info oti = { 0 };
        struct obd_info oinfo = { { { 0 } } };
        int rc;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OST_SETATTR))
                RETURN(0);

        /* first get memory EA */
        OBDO_ALLOC(oinfo.oi_oa);
        if (!oinfo.oi_oa)
                RETURN(-ENOMEM);

        LASSERT(lmm);

        rc = obd_unpackmd(mds->mds_lov_exp, &oinfo.oi_md, lmm, lmm_size);
        if (rc < 0) {
                CERROR("Error unpack md %p for inode %lu\n", lmm, inode->i_ino);
                GOTO(out, rc);
        }

        rc = obd_checkmd(mds->mds_lov_exp, obd->obd_self_export, oinfo.oi_md);
        if (rc) {
                CERROR("Error revalidate lsm %p \n", oinfo.oi_md);
                GOTO(out, rc);
        }

        /* then fill oa */
        obdo_from_inode(oinfo.oi_oa, inode, OBD_MD_FLUID | OBD_MD_FLGID);
        oinfo.oi_oa->o_valid |= OBD_MD_FLID | OBD_MD_FLGROUP;
        oinfo.oi_oa->o_id = oinfo.oi_md->lsm_object_id;
        oinfo.oi_oa->o_gr = 0;
        if (logcookies) {
                oinfo.oi_oa->o_valid |= OBD_MD_FLCOOKIE;
                oti.oti_logcookies = logcookies;
        }

        LASSERT(fid != NULL);
        oinfo.oi_oa->o_fid = fid->id;
        oinfo.oi_oa->o_generation = fid->generation;
        oinfo.oi_oa->o_valid |= OBD_MD_FLFID | OBD_MD_FLGENER;

        /* do async setattr from mds to ost not waiting for responses. */
        rc = obd_setattr_async(mds->mds_lov_exp, &oinfo, &oti, NULL);
        if (rc)
                CDEBUG(D_INODE, "mds to ost setattr objid 0x"LPX64
                       " on ost error %d\n", oinfo.oi_md->lsm_object_id, rc);
out:
        if (oinfo.oi_md)
                obd_free_memmd(mds->mds_lov_exp, &oinfo.oi_md);
        OBDO_FREE(oinfo.oi_oa);
        RETURN(rc);
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
        unsigned int ia_valid = rec->ur_iattr.ia_valid;
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_body *body;
        struct dentry *de;
        struct inode *inodes[PTLRPC_NUM_VERSIONS] = { NULL };
        struct inode *inode = NULL;
        struct lustre_handle lockh;
        void *handle = NULL;
        struct mds_logcancel_data *mlcd = NULL;
        struct lov_mds_md *lmm = NULL;
        struct llog_cookie *logcookies = NULL;
        int lmm_size = 0, need_lock = 1, cookie_size = 0;
        int rc = 0, cleanup_phase = 0, err = 0, locked = 0, sync = 0;
        int do_vbr = rec->ur_iattr.ia_valid &
                     (ATTR_MODE|ATTR_UID|ATTR_GID|
                      ATTR_FROM_OPEN|ATTR_RAW|ATTR_ATTR_FLAG);
        unsigned int qcids[MAXQUOTAS] = { 0, 0 };
        unsigned int qpids[MAXQUOTAS] = { rec->ur_iattr.ia_uid, 
                                          rec->ur_iattr.ia_gid };
        ENTRY;

        LASSERT(offset == REQ_REC_OFF);
        offset = REPLY_REC_OFF;

        DEBUG_REQ(D_INODE, req, "setattr "LPU64"/%u %x", rec->ur_fid1->id,
                  rec->ur_fid1->generation, rec->ur_iattr.ia_valid);
        mds_counter_incr(req->rq_export, LPROC_MDS_SETATTR);

        MDS_CHECK_RESENT(req, reconstruct_reint_setattr(rec, offset, req));

        if (rec->ur_dlm)
                ldlm_request_cancel(req, rec->ur_dlm, 0);

        if (rec->ur_iattr.ia_valid & ATTR_FROM_OPEN ||
            (req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)) {
                de = mds_fid2dentry(mds, rec->ur_fid1, NULL);
                if (IS_ERR(de))
                        GOTO(cleanup, rc = PTR_ERR(de));
                if (req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                        GOTO(cleanup, rc = -EROFS);
        } else {
                __u64 lockpart = MDS_INODELOCK_UPDATE;
                if (rec->ur_iattr.ia_valid & (ATTR_MODE|ATTR_UID|ATTR_GID))
                        lockpart |= MDS_INODELOCK_LOOKUP;

                de = mds_fid2locked_dentry(obd, rec->ur_fid1, NULL, LCK_EX,
                                           &lockh, NULL, 0, lockpart);
                if (IS_ERR(de))
                        GOTO(cleanup, rc = PTR_ERR(de));
                locked = 1;
        }

        cleanup_phase = 1;
        inode = de->d_inode;
        LASSERT(inode);

        if ((rec->ur_iattr.ia_valid & ATTR_FROM_OPEN) ||
            (rec->ur_iattr.ia_valid & ATTR_SIZE)) {
                /* Check write access for the O_TRUNC case */
                if (mds_query_write_access(inode) < 0)
                        GOTO(cleanup, rc = -ETXTBSY);
        }

        /* save uid/gid for quota acq/rel */
        qcids[USRQUOTA] = inode->i_uid;
        qcids[GRPQUOTA] = inode->i_gid;

        if ((S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)) &&
            rec->ur_eadata != NULL) {
                LOCK_INODE_MUTEX(inode);
                need_lock = 0;
        }

        OBD_FAIL_WRITE(obd, OBD_FAIL_MDS_REINT_SETATTR_WRITE, inode->i_sb);

        /* VBR: update version if attr changed are important for recovery */
        if (do_vbr) {
                rc = mds_version_get_check(req, inode, 0);
                if (rc)
                        GOTO(cleanup_no_trans, rc);
        }
        /* start a log jounal handle if needed */
        if (S_ISREG(inode->i_mode) &&
            rec->ur_iattr.ia_valid & (ATTR_UID | ATTR_GID)) {
                lmm_size = mds->mds_max_mdsize;
                OBD_ALLOC(lmm, lmm_size);
                if (lmm == NULL)
                        GOTO(cleanup, rc = -ENOMEM);

                cleanup_phase = 2;
                rc = mds_get_md(obd, inode, lmm, &lmm_size, need_lock, 0,
                                req->rq_export->exp_connect_flags);
                if (rc < 0)
                        GOTO(cleanup, rc);
                rc = 0;

                handle = fsfilt_start_log(obd, inode, FSFILT_OP_SETATTR, NULL,
                                          le32_to_cpu(lmm->lmm_stripe_count));
        } else {
                handle = fsfilt_start(obd, inode, FSFILT_OP_SETATTR, NULL);
        }
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));

        if (rec->ur_iattr.ia_valid & (ATTR_MTIME | ATTR_CTIME))
                CDEBUG(D_INODE, "setting mtime %lu, ctime %lu\n",
                       LTIME_S(rec->ur_iattr.ia_mtime),
                       LTIME_S(rec->ur_iattr.ia_ctime));
        rc = mds_fix_attr(inode, rec);
        if (rc)
                GOTO(cleanup, rc);

        if (rec->ur_iattr.ia_valid & ATTR_ATTR_FLAG) {  /* ioctl */
                rc = fsfilt_iocontrol(obd, de, FSFILT_IOC_SETFLAGS,
                                      (long)&rec->ur_flags);
        } else if (rec->ur_iattr.ia_valid) {            /* setattr */
                rc = fsfilt_setattr(obd, de, handle, &rec->ur_iattr, 0);
                /* journal chown/chgrp in llog, just like unlink */
                if (rc == 0 && lmm_size){
                        cookie_size = mds_get_cookie_size(obd, lmm);
                        OBD_ALLOC(logcookies, cookie_size);
                        if (logcookies == NULL)
                                GOTO(cleanup, rc = -ENOMEM);

                        if (mds_log_op_setattr(obd, inode, lmm, lmm_size,
                                               logcookies, cookie_size) <= 0) {
                                OBD_FREE(logcookies, cookie_size);
                                logcookies = NULL;
                        }
                }
        }

        if (rc == 0 && (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)) &&
            rec->ur_eadata != NULL) {
                struct lov_stripe_md *lsm = NULL;
                struct lov_user_md *lum = NULL;

                rc = ll_permission(inode, MAY_WRITE, NULL);
                if (rc < 0)
                        GOTO(cleanup, rc);

                lum = rec->ur_eadata;
                /* if { size, offset, count } = { 0, -1, 0 } and no pool
                 * (i.e. all default values specified) then delete default
                 * striping from dir. */
                if (S_ISDIR(inode->i_mode) &&
                    LOVEA_DELETE_VALUES(lum->lmm_stripe_size,
                                        lum->lmm_stripe_count,
                                        lum->lmm_stripe_offset) &&
                    (le32_to_cpu(lum->lmm_magic) != LOV_USER_MAGIC_V3)) {
                        rc = fsfilt_set_md(obd, inode, handle, NULL, 0, "lov");
                        if (rc)
                                GOTO(cleanup, rc);
                } else {
                        rc = obd_iocontrol(OBD_IOC_LOV_SETSTRIPE,
                                           mds->mds_lov_exp, 0,
                                           &lsm, rec->ur_eadata);
                        if (rc)
                                GOTO(cleanup, rc);

                        obd_free_memmd(mds->mds_lov_exp, &lsm);

                        rc = fsfilt_set_md(obd, inode, handle, rec->ur_eadata,
                                           rec->ur_eadatalen, "lov");
                        if (rc)
                                GOTO(cleanup, rc);
                }
        }

        body = lustre_msg_buf(req->rq_repmsg, offset, sizeof(*body));
        mds_pack_inode2body(body, inode);

        /* don't return OST-specific attributes if we didn't just set them. */
        if (ia_valid & ATTR_SIZE)
                body->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
        if (ia_valid & (ATTR_MTIME | ATTR_MTIME_SET))
                body->valid |= OBD_MD_FLMTIME;
        if (ia_valid & (ATTR_ATIME | ATTR_ATIME_SET))
                body->valid |= OBD_MD_FLATIME;

        if (rc == 0 && rec->ur_cookielen && !IS_ERR(mds->mds_lov_obd)) {
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
                sync = fsfilt_add_journal_cb(req->rq_export->exp_obd, 0, handle,
                                             mds_cancel_cookies_cb, mlcd);

        /* permission changes may require sync operation */
        if (rc == 0 && ia_valid & (ATTR_MODE|ATTR_UID|ATTR_GID))
                sync |= mds->mds_sync_permission;
        inodes[0] = inode;
        err = mds_finish_transno(mds, do_vbr ? inodes : NULL, handle, req,
                                 rc, 0, sync);

 cleanup_no_trans:
        /* do mds to ost setattr if needed */
        if (!rc && !err && lmm_size)
                mds_osc_setattr_async(obd, inode, lmm, lmm_size,
                                      logcookies, rec->ur_fid1);

        switch (cleanup_phase) {
        case 2:
                OBD_FREE(lmm, mds->mds_max_mdsize);
                if (logcookies)
                        OBD_FREE(logcookies, cookie_size);
        case 1:
                if ((S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)) &&
                    rec->ur_eadata != NULL)
                        UNLOCK_INODE_MUTEX(inode);
                l_dput(de);
                if (locked) {
                        if (rc) {
                                ldlm_lock_decref(&lockh, LCK_EX);
                        } else {
                                ptlrpc_save_lock (req, &lockh, LCK_EX);
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

        /* trigger dqrel/dqacq for original owner and new owner */
        if (ia_valid & (ATTR_UID | ATTR_GID))
                lquota_adjust(mds_quota_interface_ref, obd, qcids, qpids, rc,
                              FSFILT_OP_SETATTR);

        return 0;
}

static void reconstruct_reint_create(struct mds_update_record *rec, int offset,
                                     struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct mds_export_data *med = &exp->exp_mds_data;
        struct mds_obd *obd = &exp->exp_obd->u.mds;
        struct dentry *parent, *child;
        struct mds_body *body;
        int rc;

        mds_req_from_lcd(req, med->med_lcd);

        if (req->rq_status)
                return;

        parent = mds_fid2dentry(obd, rec->ur_fid1, NULL);
        if (IS_ERR(parent)) {
                rc = PTR_ERR(parent);
                LCONSOLE_WARN("Parent "LPU64"/%u lookup error %d." 
                              " Evicting client %s with export %s.\n",
                              rec->ur_fid1->id, rec->ur_fid1->generation, rc,
                              obd_uuid2str(&exp->exp_client_uuid),
                              obd_export_nid2str(exp));
                mds_export_evict(exp);
                EXIT;
                return;
        }
        child = mds_lookup(exp->exp_obd, rec->ur_name, parent,
                           rec->ur_namelen - 1);
        if (IS_ERR(child)) {
                rc = PTR_ERR(child);
                LCONSOLE_WARN("Child "LPU64"/%u lookup error %d." 
                              " Evicting client %s with export %s.\n",
                              rec->ur_fid1->id, rec->ur_fid1->generation, rc,
                              obd_uuid2str(&exp->exp_client_uuid),
                              obd_export_nid2str(exp));
                mds_export_evict(exp);
                l_dput(parent);
                EXIT;
                return;
        }

        body = lustre_msg_buf(req->rq_repmsg, offset, sizeof(*body));
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
        struct inode *inodes[PTLRPC_NUM_VERSIONS] = { NULL };
        struct inode *dir = NULL;
        void *handle = NULL;
        struct lustre_handle lockh;
        int rc = 0, err = 0, type = rec->ur_mode & S_IFMT, cleanup_phase = 0;
        int created = 0;
        unsigned int qcids[MAXQUOTAS] = { current_fsuid(), current_fsgid() };
        unsigned int qpids[MAXQUOTAS] = { 0, 0 };
        unsigned int ids[MAXQUOTAS] = { 0, 0 };
        struct lvfs_dentry_params dp = LVFS_DENTRY_PARAMS_INIT;
        int quota_pending[2] = {0, 0};
        unsigned int gid = current_fsgid();
        ENTRY;

        LASSERT(offset == REQ_REC_OFF);
        offset = REPLY_REC_OFF;

        LASSERT(!strcmp(req->rq_export->exp_obd->obd_type->typ_name,
                        LUSTRE_MDS_NAME));

        DEBUG_REQ(D_INODE, req, "parent "LPU64"/%u name %s mode %o",
                  rec->ur_fid1->id, rec->ur_fid1->generation,
                  rec->ur_name, rec->ur_mode);

        MDS_CHECK_RESENT(req, reconstruct_reint_create(rec, offset, req));

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_CREATE))
                GOTO(cleanup, rc = -ESTALE);

        if (rec->ur_dlm)
                ldlm_request_cancel(req, rec->ur_dlm, 0);

        dparent = mds_fid2locked_dentry(obd, rec->ur_fid1, NULL, LCK_EX, &lockh,
                                        rec->ur_name, rec->ur_namelen - 1,
                                        MDS_INODELOCK_UPDATE);
        if (IS_ERR(dparent)) {
                rc = PTR_ERR(dparent);
                CDEBUG(D_DENTRY, "parent "LPU64"/%u lookup error %d\n",
                               rec->ur_fid1->id, rec->ur_fid1->generation, rc);
                GOTO(cleanup, rc);
        }
        cleanup_phase = 1; /* locked parent dentry */
        dir = dparent->d_inode;
        LASSERT(dir);

        ldlm_lock_dump_handle(D_OTHER, &lockh);

        dchild = mds_lookup(obd, rec->ur_name, dparent, rec->ur_namelen - 1);
        if (IS_ERR(dchild)) {
                rc = PTR_ERR(dchild);
                dchild = NULL;
                CDEBUG(D_DENTRY, "child lookup error %d\n", rc);
                GOTO(cleanup, rc);
        }

        cleanup_phase = 2; /* child dentry */

        OBD_FAIL_WRITE(obd, OBD_FAIL_MDS_REINT_CREATE_WRITE, dir->i_sb);

        if (req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY) {
                if (dchild->d_inode)
                        GOTO(cleanup, rc = -EEXIST);
                GOTO(cleanup, rc = -EROFS);
        }

        /** check there is no stale orphan with same inode number */
        rc = mds_check_stale_orphan(obd, rec->ur_fid2);
        if (rc)
                GOTO(cleanup, rc);

        /* version recovery check */
        rc = mds_version_get_check(req, dir, 0);
        if (rc)
                GOTO(cleanup_no_trans, rc);

        if (dir->i_mode & S_ISGID && S_ISDIR(rec->ur_mode))
                rec->ur_mode |= S_ISGID;

        dchild->d_fsdata = (void *)&dp;
        dp.ldp_inum = (unsigned long)rec->ur_fid2->id;
        dp.ldp_ptr = req;

        if (dir->i_mode & S_ISGID)
                gid = dir->i_gid;
        else
                gid = current_fsgid();

        /* we try to get enough quota to write here, and let ldiskfs
         * decide if it is out of quota or not b=14783
         * FIXME: after CMD is used, pointer to obd_trans_info* couldn't
         * be NULL, b=14840 */
        ids[0] = current_fsuid();
        ids[1] = gid;
        lquota_chkquota(mds_quota_interface_ref, req->rq_export, ids[0], ids[1],
                        1, quota_pending, NULL, NULL, 0);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_DQACQ_NET))
                GOTO(cleanup, rc = -EINPROGRESS);

        switch (type) {
        case S_IFREG:{
                handle = fsfilt_start(obd, dir, FSFILT_OP_CREATE, NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                LOCK_INODE_MUTEX(dir);
                rc = ll_vfs_create(dir, dchild, rec->ur_mode, NULL);
                UNLOCK_INODE_MUTEX(dir);
                mds_counter_incr(req->rq_export, LPROC_MDS_MKNOD);
                EXIT;
                break;
        }
        case S_IFDIR:{
                handle = fsfilt_start(obd, dir, FSFILT_OP_MKDIR, NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                LOCK_INODE_MUTEX(dir);
                rc = ll_vfs_mkdir(dir, dchild, mds->mds_vfsmnt, rec->ur_mode);
                UNLOCK_INODE_MUTEX(dir);
                mds_counter_incr(req->rq_export, LPROC_MDS_MKDIR);
                EXIT;
                break;
        }
        case S_IFLNK:{
                handle = fsfilt_start(obd, dir, FSFILT_OP_SYMLINK, NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                LOCK_INODE_MUTEX(dir);
                if (rec->ur_tgt == NULL)        /* no target supplied */
                        rc = -EINVAL;           /* -EPROTO? */
                else
                        rc = ll_vfs_symlink(dir, dchild, mds->mds_vfsmnt, 
                                            rec->ur_tgt, S_IALLUGO);
                UNLOCK_INODE_MUTEX(dir);
                mds_counter_incr(req->rq_export, LPROC_MDS_MKNOD);
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
                        GOTO(cleanup, rc = PTR_ERR(handle));
                LOCK_INODE_MUTEX(dir);
                rc = ll_vfs_mknod(dir, dchild, mds->mds_vfsmnt, rec->ur_mode, 
                                  rdev);
                UNLOCK_INODE_MUTEX(dir);
                mds_counter_incr(req->rq_export, LPROC_MDS_MKNOD);
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
                iattr.ia_uid = current_fsuid();  /* set by push_ctxt already */
                iattr.ia_gid = gid;
                iattr.ia_valid = ATTR_UID | ATTR_GID | ATTR_ATIME |
                        ATTR_MTIME | ATTR_CTIME;

                if (rec->ur_fid2->id) {
                        if (rec->ur_fid2->id != inode->i_ino) {
                                if (req->rq_export->exp_delayed)
                                        rc = -EOVERFLOW;
                                else
                                        rc = -EFAULT;
                                GOTO(cleanup, rc);
                        }
                        inode->i_generation = rec->ur_fid2->generation;
                        /* Dirtied and committed by the upcoming setattr. */
                        CDEBUG(D_INODE, "recreated ino %lu with gen %u\n",
                               inode->i_ino, inode->i_generation);
                } else {
                        CDEBUG(D_INODE, "created ino %lu with gen %x\n",
                               inode->i_ino, inode->i_generation);
                }

                rc = fsfilt_setattr(obd, dchild, handle, &iattr, 0);
                if (rc)
                        CERROR("error on child setattr: rc = %d\n", rc);

                iattr.ia_valid = ATTR_MTIME | ATTR_CTIME;
                rc = fsfilt_setattr(obd, dparent, handle, &iattr, 0);
                if (rc)
                        CERROR("error on parent setattr: rc = %d\n", rc);

                if (S_ISDIR(inode->i_mode)) {
                        struct lov_mds_md_v3 lmm;
                        int lmm_size = sizeof(lmm);
                        rc = mds_get_md(obd, dir, &lmm, &lmm_size, 1, 0,
                                        req->rq_export->exp_connect_flags);
                        if (rc > 0) {
                                LOCK_INODE_MUTEX(inode);
                                rc = fsfilt_set_md(obd, inode, handle,
                                                   &lmm, lmm_size, "lov");
                                UNLOCK_INODE_MUTEX(inode);
                        }
                        if (rc)
                                CERROR("error on copy stripe info: rc = %d\n",
                                        rc);
                }

                body = lustre_msg_buf(req->rq_repmsg, offset, sizeof(*body));
                mds_pack_inode2body(body, inode);
        }
        EXIT;

cleanup:
        inodes[0] = dir;
        inodes[1] = dchild ? dchild->d_inode : NULL;
        err = mds_finish_transno(mds, inodes, handle, req, rc, 0, 0);

cleanup_no_trans:
        if (quota_pending[0] || quota_pending[1])
                lquota_pending_commit(mds_quota_interface_ref, obd,
                                      ids[0], ids[1], quota_pending);

        if (rc && created) {
                /* Destroy the file we just created.  This should not need
                 * extra journal credits, as we have already modified all of
                 * the blocks needed in order to create the file in the first
                 * place.
                 */
                switch (type) {
                case S_IFDIR:
                        LOCK_INODE_MUTEX(dir);
                        err = ll_vfs_rmdir(dir, dchild, mds->mds_vfsmnt);
                        UNLOCK_INODE_MUTEX(dir);
                        if (err)
                                CERROR("rmdir in error path: %d\n", err);
                        break;
                default:
                        LOCK_INODE_MUTEX(dir);
                        err = ll_vfs_unlink(dir, dchild, mds->mds_vfsmnt);
                        UNLOCK_INODE_MUTEX(dir);
                        if (err)
                                CERROR("unlink in error path: %d\n", err);
                        break;
                }
        } else if (created) {
                /* The inode we were allocated may have just been freed
                 * by an unlink operation.  We take this lock to
                 * synchronize against the matching reply-ack-lock taken
                 * in unlink, to avoid replay problems if this reply
                 * makes it out to the client but the unlink's does not.
                 * See bug 2029 for more detail.*/
                mds_lock_new_child(obd, dchild->d_inode, NULL);
                /* save uid/gid of create inode and parent */
                qpids[USRQUOTA] = dir->i_uid;
                qpids[GRPQUOTA] = dir->i_gid;
        } else {
                rc = err;
        }

        switch (cleanup_phase) {
        case 2: /* child dentry */
                l_dput(dchild);
        case 1: /* locked parent dentry */
                if (rc) {
                        ldlm_lock_decref(&lockh, LCK_EX);
                } else {
                        ptlrpc_save_lock (req, &lockh, LCK_EX);
                }
                l_dput(dparent);
        case 0:
                break;
        default:
                CERROR("invalid cleanup_phase %d\n", cleanup_phase);
                LBUG();
        }
        req->rq_status = rc;

        /* trigger dqacq on the owner of child and parent */
        lquota_adjust(mds_quota_interface_ref, obd, qcids, qpids, rc,
                      FSFILT_OP_CREATE);
        return 0;
}

int res_gt(struct ldlm_res_id *res1, struct ldlm_res_id *res2,
           ldlm_policy_data_t *p1, ldlm_policy_data_t *p2)
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
        if (!p1 || !p2)
                return 0;
        if (memcmp(p1, p2, sizeof(*p1)) < 0)
                return 1;
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
                          ldlm_policy_data_t *p1_policy,
                          struct ldlm_res_id *p2_res_id,
                          struct lustre_handle *p2_lockh, int p2_lock_mode,
                          ldlm_policy_data_t *p2_policy)
{
        struct ldlm_res_id *res_id[2] = { p1_res_id, p2_res_id };
        struct lustre_handle *handles[2] = { p1_lockh, p2_lockh };
        int lock_modes[2] = { p1_lock_mode, p2_lock_mode };
        ldlm_policy_data_t *policies[2] = {p1_policy, p2_policy};
        int rc, flags;
        ENTRY;

        LASSERT(p1_res_id != NULL && p2_res_id != NULL);

        CDEBUG(D_INFO, "locks before: "LPU64"/"LPU64"\n",
               res_id[0]->name[0], res_id[1]->name[0]);

        if (res_gt(p1_res_id, p2_res_id, p1_policy, p2_policy)) {
                handles[1] = p1_lockh;
                handles[0] = p2_lockh;
                res_id[1] = p1_res_id;
                res_id[0] = p2_res_id;
                lock_modes[1] = p1_lock_mode;
                lock_modes[0] = p2_lock_mode;
                policies[1] = p1_policy;
                policies[0] = p2_policy;
        }

        CDEBUG(D_DLMTRACE, "lock order: "LPU64"/"LPU64"\n",
               res_id[0]->name[0], res_id[1]->name[0]);

        flags = LDLM_FL_LOCAL_ONLY | LDLM_FL_ATOMIC_CB;
        rc = ldlm_cli_enqueue_local(obd->obd_namespace, res_id[0],
                                    LDLM_IBITS, policies[0], lock_modes[0],
                                    &flags, ldlm_blocking_ast, 
                                    ldlm_completion_ast, NULL, NULL, 0, 
                                    NULL, handles[0]);
        if (rc != ELDLM_OK)
                RETURN(-EIO);
        ldlm_lock_dump_handle(D_OTHER, handles[0]);

        if (memcmp(res_id[0], res_id[1], sizeof(*res_id[0])) == 0 &&
            (policies[0]->l_inodebits.bits & policies[1]->l_inodebits.bits)) {
                memcpy(handles[1], handles[0], sizeof(*(handles[1])));
                ldlm_lock_addref(handles[1], lock_modes[1]);
        } else if (res_id[1]->name[0] != 0) {
                flags = LDLM_FL_LOCAL_ONLY | LDLM_FL_ATOMIC_CB;
                rc = ldlm_cli_enqueue_local(obd->obd_namespace, res_id[1],
                                            LDLM_IBITS, policies[1],
                                            lock_modes[1], &flags, 
                                            ldlm_blocking_ast,
                                            ldlm_completion_ast, NULL, NULL,
                                            0, NULL, handles[1]);
                if (rc != ELDLM_OK) {
                        ldlm_lock_decref(handles[0], lock_modes[0]);
                        RETURN(-EIO);
                }
                ldlm_lock_dump_handle(D_OTHER, handles[1]);
        }

        RETURN(0);
}

static inline int res_eq(struct ldlm_res_id *res1, struct ldlm_res_id *res2)
{
        return !memcmp(res1, res2, sizeof(*res1));
}

static inline void
try_to_aggregate_locks(struct ldlm_res_id *res1, ldlm_policy_data_t *p1,
                        struct ldlm_res_id *res2, ldlm_policy_data_t *p2)
{
        if (!res_eq(res1, res2))
                return;
        /* XXX: any additional inodebits (to current LOOKUP and UPDATE)
         * should be taken with great care here */
        p1->l_inodebits.bits |= p2->l_inodebits.bits;
}

int enqueue_4ordered_locks(struct obd_device *obd,struct ldlm_res_id *p1_res_id,
                           struct lustre_handle *p1_lockh, int p1_lock_mode,
                           ldlm_policy_data_t *p1_policy, 
                           struct ldlm_res_id *p2_res_id,
                           struct lustre_handle *p2_lockh, int p2_lock_mode,
                           ldlm_policy_data_t *p2_policy, 
                           struct ldlm_res_id *c1_res_id,
                           struct lustre_handle *c1_lockh, int c1_lock_mode,
                           ldlm_policy_data_t *c1_policy, 
                           struct ldlm_res_id *c2_res_id,
                           struct lustre_handle *c2_lockh, int c2_lock_mode,
                           ldlm_policy_data_t *c2_policy)
{
        struct ldlm_res_id *res_id[5] = { p1_res_id, p2_res_id,
                                          c1_res_id, c2_res_id };
        struct lustre_handle *dlm_handles[5] = { p1_lockh, p2_lockh,
                                                 c1_lockh, c2_lockh };
        int lock_modes[5] = { p1_lock_mode, p2_lock_mode,
                              c1_lock_mode, c2_lock_mode };
        ldlm_policy_data_t *policies[5] = {p1_policy, p2_policy,
                                           c1_policy, c2_policy};
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
                policies[4] = policies[i];

                sorted = 0;
                do {
                        if (res_gt(res_id[j], res_id[4], policies[j],
                                   policies[4])) {
                                dlm_handles[j + 1] = dlm_handles[j];
                                res_id[j + 1] = res_id[j];
                                lock_modes[j + 1] = lock_modes[j];
                                policies[j + 1] = policies[j];
                                j--;
                        } else {
                                sorted = 1;
                        }
                } while (j >= 0 && !sorted);

                dlm_handles[j + 1] = dlm_handles[4];
                res_id[j + 1] = res_id[4];
                lock_modes[j + 1] = lock_modes[4];
                policies[j + 1] = policies[4];
        }

        CDEBUG(D_DLMTRACE, "lock order: "LPU64"/"LPU64"/"LPU64"/"LPU64"\n",
               res_id[0]->name[0], res_id[1]->name[0], res_id[2]->name[0],
               res_id[3]->name[0]);

        /* XXX we could send ASTs on all these locks first before blocking? */
        for (i = 0; i < 4; i++) {
                flags = LDLM_FL_ATOMIC_CB;
                if (res_id[i]->name[0] == 0)
                        break;
                if (i && res_eq(res_id[i], res_id[i-1])) {
                        memcpy(dlm_handles[i], dlm_handles[i-1],
                               sizeof(*(dlm_handles[i])));
                        ldlm_lock_addref(dlm_handles[i], lock_modes[i]);
                } else {
                        /* we need to enqueue locks with different inodebits
                         * at once, because otherwise concurrent thread can
                         * hit the windown between these two locks and we'll
                         * get to deadlock. see bug 10360. note also, that it
                         * is impossible to have >2 equal res. */
                        if (i < 3)
                                try_to_aggregate_locks(res_id[i], policies[i],
                                                       res_id[i+1], policies[i+1]);
                        rc = ldlm_cli_enqueue_local(obd->obd_namespace,
                                                    res_id[i], LDLM_IBITS,
                                                    policies[i], lock_modes[i],
                                                    &flags, ldlm_blocking_ast,
                                                    ldlm_completion_ast, NULL, 
                                                    NULL, 0, NULL, 
                                                    dlm_handles[i]);
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
                            ldlm_policy_data_t *child_policy,
                            const char *name, int namelen,
                            struct ldlm_res_id *maxres)
{
        struct dentry *vchild, *dchild = *dchildp;
        int rc = 0, cleanup_phase = child_lockh == NULL ? 1:2; /* parent, child locks */
        ENTRY;

        /* not want child - not check it */
        if (name == NULL)
                RETURN(0);

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
        /* resouce is changed, but not want child lock, return new child */
        if (child_lockh == NULL) {
                dput(dchild);
                *dchildp = vchild;
                GOTO(cleanup, rc = 0);
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
                int flags = LDLM_FL_ATOMIC_CB;
                child_res_id->name[0] = dchild->d_inode->i_ino;
                child_res_id->name[1] = dchild->d_inode->i_generation;

                /* Make sure that we don't try to re-enqueue a lock on the
                 * same resource if it happens that the source is renamed to
                 * the target by another thread (bug 9974, thanks racer :-) */
                if (!res_gt(child_res_id, parent_res_id, NULL, NULL) ||
                    !res_gt(child_res_id, maxres, NULL, NULL)) {
                        CDEBUG(D_DLMTRACE, "relock "LPU64"<("LPU64"|"LPU64")\n",
                               child_res_id->name[0], parent_res_id->name[0],
                               maxres->name[0]);
                        GOTO(cleanup, rc = 1);
                }

                rc = ldlm_cli_enqueue_local(obd->obd_namespace, child_res_id, 
                                            LDLM_IBITS, child_policy, 
                                            child_mode, &flags, 
                                            ldlm_blocking_ast, 
                                            ldlm_completion_ast, NULL, 
                                            NULL, 0, NULL, child_lockh);
                if (rc != ELDLM_OK)
                        GOTO(cleanup, rc = -EIO);
        } else {
                memset(child_res_id, 0, sizeof(*child_res_id));
                memset(child_lockh, 0, sizeof(*child_lockh));
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

#define INODE_CTIME_AGE (10)
#define INODE_CTIME_OLD(inode) (LTIME_S(inode->i_ctime) +               \
                                INODE_CTIME_AGE < CURRENT_SECONDS)

int mds_get_parent_child_locked(struct obd_device *obd, struct mds_obd *mds,
                                struct ll_fid *fid,
                                struct lustre_handle *parent_lockh,
                                struct dentry **dparentp, int parent_mode,
                                __u64 parent_lockpart,
                                char *name, int namelen,
                                struct lustre_handle *child_lockh,
                                struct dentry **dchildp, int child_mode,
                                __u64 child_lockpart, int it_op, __u32 flags)
{
        struct ldlm_res_id child_res_id = { .name = {0} };
        struct ldlm_res_id parent_res_id = { .name = {0} };
        ldlm_policy_data_t parent_policy = {.l_inodebits = { parent_lockpart }};
        ldlm_policy_data_t child_policy = {.l_inodebits = { child_lockpart }};
        static struct ldlm_res_id child_res_id_nolock = { .name = {0} };
        struct inode *inode;
        int rc = 0, cleanup_phase = 0;
        ENTRY;

        /* Step 1: Lookup parent */
        *dparentp = mds_fid2dentry(mds, fid, NULL);
        if (IS_ERR(*dparentp)) {
                rc = PTR_ERR(*dparentp);
                *dparentp = NULL;
                RETURN(rc);
        }

        CDEBUG(D_INODE, "parent ino %lu, name %s\n",
               (*dparentp)->d_inode->i_ino, name);

        parent_res_id.name[0] = (*dparentp)->d_inode->i_ino;
        parent_res_id.name[1] = (*dparentp)->d_inode->i_generation;

        cleanup_phase = 1; /* parent dentry */

        if (name == NULL)
                GOTO(retry_locks, rc);

        /* Step 2: Lookup child (without DLM lock, to get resource name) */
        *dchildp = mds_lookup(obd, name, *dparentp, namelen - 1);
        if (IS_ERR(*dchildp)) {
                rc = PTR_ERR(*dchildp);
                *dchildp = NULL;
                CDEBUG(D_INODE, "child lookup error %d\n", rc);
                GOTO(cleanup, rc);
        }

        cleanup_phase = 2; /* child dentry */

        inode = (*dchildp)->d_inode;
        if (inode != NULL) {
                if (is_bad_inode(inode)) {
                        CERROR("bad inode returned %lu/%u\n",
                               inode->i_ino, inode->i_generation);
                        GOTO(cleanup, rc = -ENOENT);
                }
                inode = igrab(inode);
        }
        if (inode == NULL)
                goto retry_locks;

        child_res_id.name[0] = inode->i_ino;
        child_res_id.name[1] = inode->i_generation;

        /* If we want a LCK_CR for a directory, and this directory has not been
           changed for some time, we return not only a LOOKUP lock, but also an 
           UPDATE lock to have negative dentry starts working for this dir.
           Also we apply same logic to non-directories. If the file is rarely
           changed - we return both locks and this might save us RPC on
           later STAT. */
        if ((child_mode & (LCK_CR|LCK_PR|LCK_CW)) && INODE_CTIME_OLD(inode))
                child_policy.l_inodebits.bits |= MDS_INODELOCK_UPDATE;

        if (it_op == IT_OPEN && !(flags & MDS_OPEN_LOCK)) {
                /*
                 * LU-146
                 * if this is an executable, and a non-nfsd client open write or
                 * execute it, revoke open lock in case other client holds an
                 * open lock which denies write/execute in mds_finish_open().
                 */
                LASSERT(child_lockh != NULL);
                if (!(S_ISREG(inode->i_mode) &&
                      (inode->i_mode & S_IXUGO) &&
                      (flags & (FMODE_WRITE | MDS_FMODE_EXEC))))
                        child_lockh = NULL;
        }

        iput(inode);

retry_locks:
        cleanup_phase = 2; /* child dentry */

        /* Step 3: Lock parent and child in resource order.  If child doesn't
         *         exist, we still have to lock the parent and re-lookup. */
        rc = enqueue_ordered_locks(obd,&parent_res_id,parent_lockh,parent_mode,
                                   &parent_policy,
                                   child_lockh ? &child_res_id :
                                                 &child_res_id_nolock,
                                   child_lockh, child_mode,
                                   &child_policy);
        if (rc)
                GOTO(cleanup, rc);

        if (IS_DEADDIR((*dparentp)->d_inode))
                GOTO(cleanup, -ENOENT);

        /* Step 4: Re-lookup child to verify it hasn't changed since locking */
        rc = mds_verify_child(obd, &parent_res_id, parent_lockh, *dparentp,
                              parent_mode, &child_res_id, child_lockh, dchildp,
                              child_mode,&child_policy, name, namelen, &parent_res_id);
        if (rc > 0)
                goto retry_locks;
        if (rc < 0) {
                GOTO(cleanup, rc);
        }

        if (it_op == IT_OPEN && !(flags & MDS_OPEN_LOCK) && child_lockh &&
            (*dchildp)->d_inode != NULL) {
                /*
                 * LU-146
                 * See above, revoke open lock only, no need to reply child
                 * lock back to client.
                 */
                ldlm_lock_decref(child_lockh, child_mode);
                memset(child_lockh, 0, sizeof(*child_lockh));
        }

cleanup:
        if (rc) {
                switch (cleanup_phase) {
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

        mds_req_from_lcd(req, med->med_lcd);
}

/* If we are unlinking an open file/dir (i.e. creating an orphan) then
 * we instead link the inode into the PENDING directory until it is
 * finally released.  We can't simply call mds_reint_rename() or some
 * part thereof, because we don't have the inode to check for link
 * count/open status until after it is locked.
 *
 * returns 1 on success
 * returns 0 if we lost a race and didn't make a new link
 * returns negative on error
 */
static int mds_orphan_add_link(struct mds_update_record *rec,
                               struct obd_device *obd, struct dentry *dentry)
{
        struct mds_obd *mds = &obd->u.mds;
        struct inode *pending_dir = mds->mds_pending_dir->d_inode;
        struct inode *inode = dentry->d_inode;
        struct dentry *pending_child;
        char fidname[LL_FID_NAMELEN];
        int fidlen = 0, rc, mode;
        int ignoring_quota;
        ENTRY;

        LASSERT(inode != NULL);
        LASSERT(!mds_inode_is_orphan(inode));
        LASSERT(TRYLOCK_INODE_MUTEX(pending_dir) == 0);

        fidlen = ll_fid2str(fidname, inode->i_ino, inode->i_generation);

        CDEBUG(D_INODE, "pending destroy of %dx open %d linked %s %s = %s\n",
               mds_orphan_open_count(inode), inode->i_nlink,
               S_ISDIR(inode->i_mode) ? "dir" :
                S_ISREG(inode->i_mode) ? "file" : "other",rec->ur_name,fidname);

        if (!mds_orphan_needed(obd, inode) || inode->i_nlink != 0)
                RETURN(0);

        pending_child = lookup_one_len(fidname, mds->mds_pending_dir, fidlen);
        if (IS_ERR(pending_child))
                RETURN(PTR_ERR(pending_child));

        if (pending_child->d_inode != NULL) {
                CERROR("re-destroying orphan file %s?\n", rec->ur_name);
                LASSERT(pending_child->d_inode == inode);
                GOTO(out_dput, rc = 0);
        }

        /* link() is semanticaly-wrong for S_IFDIR, so we set S_IFREG
         * for linking and return real mode back then -bzzz */
        mode = inode->i_mode;
        inode->i_mode = S_IFREG;
        /* avoid vfs_link upon 0 nlink inode, inc by 2 instead of 1 because
         * ext3_inc_count() can reset i_nlink for indexed directory */
        inode->i_nlink += 2;

        /* Temporarily raise the resource capability as we do not want to
         * get -EDQUOT from VFS during this unlink operation */
        ignoring_quota = lquota_enforce(mds_quota_interface_ref, obd, 1);

        rc = ll_vfs_link(dentry, mds->mds_vfsmnt, pending_dir, pending_child,
                         mds->mds_vfsmnt);
        if (rc)
                CERROR("error linking orphan %s %s to PENDING: rc = %d\n",
                       S_ISDIR(mode) ? "dir" : S_ISREG(mode) ? "file" : "other",
                       rec->ur_name, rc);
        else
                mds_inode_set_orphan(inode);

        /* return mode and correct i_nlink if inode is directory */
        inode->i_mode = mode;
        LASSERTF(rc || inode->i_nlink == 3, "%s nlink == %d\n",
                 S_ISDIR(mode) ? "dir" : S_ISREG(mode) ? "file" : "other",
                 inode->i_nlink);

        if (S_ISDIR(mode)) {
                pending_dir->i_nlink++;
                if (pending_dir->i_sb->s_op->dirty_inode)
                        pending_dir->i_sb->s_op->dirty_inode(pending_dir);
        }

        inode->i_nlink -= 2;
        if (inode->i_sb->s_op->dirty_inode)
                inode->i_sb->s_op->dirty_inode(inode);

        if (!ignoring_quota)
                lquota_enforce(mds_quota_interface_ref, obd, 0);

        if (rc)
                GOTO(out_dput, rc);

        GOTO(out_dput, rc = 1);
out_dput:
        l_dput(pending_child);
        RETURN(rc);
}

int mds_get_cookie_size(struct obd_device *obd, struct lov_mds_md *lmm)
{
        int count = le32_to_cpu(lmm->lmm_stripe_count);
        int real_csize = count * sizeof(struct llog_cookie);
        return real_csize;
}

static void mds_shrink_reply(struct ptlrpc_request *req,
                           int reply_mdoff, int have_md, int have_acl)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_body *reply_body;
        int cookie_size = 0, md_size = 0;
        ENTRY;

        /* LSM and cookie is always placed after mds_body */
        reply_body =  lustre_msg_buf(req->rq_repmsg, reply_mdoff,
                                     sizeof(*reply_body));
        if (reply_body == NULL)
                /* if there is no mds_body, no point in shrinking the reply */
                 return;

        reply_mdoff++;

        if (have_md || have_acl) {
                if (reply_body->valid & (OBD_MD_FLEASIZE | OBD_MD_FLDIREA)) {
                        md_size = reply_body->eadatasize;
                } else if (reply_body->valid & OBD_MD_LINKNAME)
                        md_size = reply_body->eadatasize;

                if (reply_body->valid & OBD_MD_FLCOOKIE) {
                        LASSERT(reply_body->valid & OBD_MD_FLEASIZE);
                        cookie_size = mds_get_cookie_size(obd, lustre_msg_buf(
                                                          req->rq_repmsg,
                                                          reply_mdoff, 0));
                } else if (reply_body->valid & OBD_MD_FLACL) {
                        cookie_size = reply_body->aclsize;
                }
        }
        CDEBUG(D_INFO, "Shrink %d/%d to md_size %d cookie_size %d \n",
               have_md, have_acl, md_size, cookie_size);

        if (likely(have_md))
                lustre_shrink_reply(req, reply_mdoff, md_size, 1);

        if (likely(have_acl))
                lustre_shrink_reply(req, reply_mdoff + (md_size > 0),
                                    cookie_size, 1);
}

void mds_shrink_body_reply(struct ptlrpc_request *req,
                           int req_mdoff,
                           int reply_mdoff)
{
        struct mds_body *rq_body;
        const long long have_acl = OBD_MD_FLCOOKIE | OBD_MD_FLACL;
        const long have_md = OBD_MD_FLEASIZE | OBD_MD_FLDIREA;
        ENTRY;

        /* LSM and cookie is always placed after mds_body */
        rq_body =  lustre_msg_buf(req->rq_reqmsg, req_mdoff,
                                  sizeof(*rq_body));
        LASSERT(rq_body);

        /* this check is need for avoid hit asset in case
         * OBD_MDS_FLFLAGS */
        mds_shrink_reply(req, reply_mdoff,
                         rq_body->valid & have_md,
                         rq_body->valid & have_acl);
}

void mds_shrink_intent_reply(struct ptlrpc_request *req,
                             int opc, int reply_mdoff)
{
        switch (opc) {
                case REINT_UNLINK:
                case REINT_RENAME:
                        mds_shrink_reply(req, reply_mdoff, 1, 1);
                        break;
                case REINT_OPEN:
                        mds_shrink_reply(req, reply_mdoff, 1, 0);
                        break;
                default:
                        break;
        }
}

static int mds_reint_unlink(struct mds_update_record *rec, int offset,
                            struct ptlrpc_request *req,
                            struct lustre_handle *lh)
{
        struct dentry *dparent = NULL, *dchild;
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_body *body = NULL;
        struct inode *inodes[PTLRPC_NUM_VERSIONS] = { NULL };
        struct inode *child_inode = NULL;
        struct lustre_handle parent_lockh, child_lockh, child_reuse_lockh;
        void *handle = NULL;
        int rc = 0, cleanup_phase = 0;
        unsigned int qcids[MAXQUOTAS] = { 0, 0 };
        unsigned int qpids[MAXQUOTAS] = { 0, 0 };
        ENTRY;

        LASSERT(offset == REQ_REC_OFF); /*  || offset == DLM_INTENT_REC_OFF); */
        offset = REPLY_REC_OFF;

        DEBUG_REQ(D_INODE, req, "parent ino "LPU64"/%u, child %s",
                  rec->ur_fid1->id, rec->ur_fid1->generation, rec->ur_name);

        MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNLINK))
                GOTO(cleanup, rc = -ENOENT);

        if (rec->ur_dlm)
                ldlm_request_cancel(req, rec->ur_dlm, 0);

        rc = mds_get_parent_child_locked(obd, mds, rec->ur_fid1,
                                         &parent_lockh, &dparent, LCK_EX,
                                         MDS_INODELOCK_UPDATE, 
                                         rec->ur_name, rec->ur_namelen,
                                         &child_lockh, &dchild, LCK_EX, 
                                         MDS_INODELOCK_FULL,
                                         IT_UNLINK, 0);
        if (rc)
                GOTO(cleanup, rc);

        cleanup_phase = 1; /* dchild, dparent, locks */

        dget(dchild);
        child_inode = dchild->d_inode;
        if (child_inode == NULL) {
                CDEBUG(D_INODE, "child doesn't exist (dir %lu, name %s)\n",
                       dparent->d_inode->i_ino, rec->ur_name);
                GOTO(cleanup, rc = -ENOENT);
        }

        /* save uid/gid for quota acquire/release */
        qcids[USRQUOTA] = child_inode->i_uid;
        qcids[GRPQUOTA] = child_inode->i_gid;
        qpids[USRQUOTA] = dparent->d_inode->i_uid;
        qpids[GRPQUOTA] = dparent->d_inode->i_gid;

        cleanup_phase = 2; /* dchild has a lock */

        /* VBR: version recovery check for parent */
        rc = mds_version_get_check(req, dparent->d_inode, 0);
        if (rc)
                GOTO(cleanup_no_trans, rc);

        /* version recovery check */
        rc = mds_version_get_check(req, child_inode, 1);
        if (rc)
                GOTO(cleanup_no_trans, rc);

        /* We have to do these checks ourselves, in case we are making an
         * orphan.  The client tells us whether rmdir() or unlink() was called,
         * so we need to return appropriate errors (bug 72). */
        if ((rec->ur_mode & S_IFMT) == S_IFDIR) {
                if (!S_ISDIR(child_inode->i_mode))
                        GOTO(cleanup, rc = -ENOTDIR);
        } else {
                if (S_ISDIR(child_inode->i_mode))
                        GOTO(cleanup, rc = -EISDIR);
        }

        /* Check for EROFS after we check ENODENT, ENOTDIR, and EISDIR */
        if (req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                GOTO(cleanup, rc = -EROFS);

        /* Step 3: Get a lock on the ino to sync with creation WRT inode
         * reuse (see bug 2029). */
        rc = mds_lock_new_child(obd, child_inode, &child_reuse_lockh);
        if (rc != ELDLM_OK)
                GOTO(cleanup, rc);

        cleanup_phase = 3; /* child inum lock */

        OBD_FAIL_WRITE(obd, OBD_FAIL_MDS_REINT_UNLINK_WRITE, dparent->d_inode->i_sb);

        /* ldlm_reply in buf[0] if called via intent */
        if (offset == DLM_INTENT_REC_OFF)
                offset = DLM_REPLY_REC_OFF;

        body = lustre_msg_buf(req->rq_repmsg, offset, sizeof(*body));
        LASSERT(body != NULL);

        /* child orphan sem protects orphan_dec_test && is_orphan race */
        MDS_DOWN_READ_ORPHAN_SEM(child_inode);
        cleanup_phase = 4; /* MDS_UP_READ_ORPHAN_SEM(new_inode) when finished */

        /* If this is potentially the last reference to this inode, get the
         * OBD EA data first so the client can destroy OST objects.  We
         * only do the object removal later if no open files/links remain. */
        if ((S_ISDIR(child_inode->i_mode) && child_inode->i_nlink == 2) ||
            child_inode->i_nlink == 1) {
                if (mds_orphan_needed(obd, child_inode)) {
                        /* need to lock pending_dir before transaction */
                        LOCK_INODE_MUTEX(mds->mds_pending_dir->d_inode);
                        cleanup_phase = 5; /* UNLOCK_INODE_MUTEX(mds->mds_pending_dir->d_inode); */
                } else if (S_ISREG(child_inode->i_mode)) {
                        mds_pack_inode2body(body, child_inode);
                        mds_pack_md(obd, req->rq_repmsg, offset + 1, body,
                                    child_inode, MDS_PACK_MD_LOCK, 0,
                                    req->rq_export->exp_connect_flags);
                }
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
                LOCK_INODE_MUTEX(dparent->d_inode);
                rc = ll_vfs_rmdir(dparent->d_inode, dchild, mds->mds_vfsmnt);
                UNLOCK_INODE_MUTEX(dparent->d_inode);
                mds_counter_incr(req->rq_export, LPROC_MDS_RMDIR);
                break;
        case S_IFREG: {
                struct lov_mds_md *lmm = lustre_msg_buf(req->rq_repmsg,
                                                        offset + 1, 0);
                int sz = lustre_msg_buflen(req->rq_repmsg, offset + 1) > 0 ?
                         le32_to_cpu(lmm->lmm_stripe_count) : 0;

                handle = fsfilt_start_log(obd, dparent->d_inode,
                                          FSFILT_OP_UNLINK, NULL, sz);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                LOCK_INODE_MUTEX(dparent->d_inode);
                rc = ll_vfs_unlink(dparent->d_inode, dchild, mds->mds_vfsmnt);
                UNLOCK_INODE_MUTEX(dparent->d_inode);
                mds_counter_incr(req->rq_export, LPROC_MDS_UNLINK);
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
                LOCK_INODE_MUTEX(dparent->d_inode);
                rc = ll_vfs_unlink(dparent->d_inode, dchild, mds->mds_vfsmnt);
                UNLOCK_INODE_MUTEX(dparent->d_inode);
                mds_counter_incr(req->rq_export, LPROC_MDS_UNLINK);
                break;
        default:
                CERROR("bad file type %o unlinking %s\n", rec->ur_mode,
                       rec->ur_name);
                LBUG();
                GOTO(cleanup, rc = -EINVAL);
        }

        if (rc == 0 && child_inode->i_nlink == 0) {
                if (mds_orphan_needed(obd, child_inode)) {
                        rc = mds_orphan_add_link(rec, obd, dchild);
                        if (rc == 1)
                                /* child inode was successfully linked
                                 * to PENDING */
                                GOTO(cleanup, rc = 0);
                        else
                                /* we failed to move the file to PENDING,
                                 * really unlink the file as if there were
                                 * no more openers */
                                rc = 0;
                }

                if (!S_ISREG(child_inode->i_mode))
                        GOTO(cleanup, rc);

                if (!(body->valid & OBD_MD_FLEASIZE)) {
                        body->valid |=(OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                       OBD_MD_FLATIME | OBD_MD_FLMTIME);
                } else if (mds_log_op_unlink(obd,
                                lustre_msg_buf(req->rq_repmsg, offset + 1, 0),
                                lustre_msg_buflen(req->rq_repmsg, offset + 1),
                                lustre_msg_buf(req->rq_repmsg, offset + 2, 0),
                                lustre_msg_buflen(req->rq_repmsg, offset+2)) >
                           0) {
                        body->valid |= OBD_MD_FLCOOKIE;
                }
        }

        GOTO(cleanup, rc);
cleanup:
        if (rc == 0) {
                struct iattr iattr;
                int err;

                if (child_inode->i_nlink > 0 ||
                    mds_orphan_open_count(child_inode) > 0) {
                        /* update ctime of unlinked file only if it is still
                         * opened or a link still exists */
                        iattr.ia_valid = ATTR_CTIME;
                        LTIME_S(iattr.ia_ctime) = rec->ur_time;
                        err = fsfilt_setattr(obd, dchild, handle, &iattr, 0);
                        if (err)
                                CERROR("error on unlinked inode time update: "
                                       "rc = %d\n", err);
                }

                /* update mtime and ctime of parent directory*/
                iattr.ia_valid = ATTR_MTIME | ATTR_CTIME;
                LTIME_S(iattr.ia_mtime) = rec->ur_time;
                LTIME_S(iattr.ia_ctime) = rec->ur_time;
                err = fsfilt_setattr(obd, dparent, handle, &iattr, 0);
                if (err)
                        CERROR("error on parent setattr: rc = %d\n", err);
        }
        inodes[0] = dparent ? dparent->d_inode : NULL;
        inodes[1] = child_inode;
        rc = mds_finish_transno(mds, inodes, handle, req, rc, 0, 0);

cleanup_no_trans:
        switch(cleanup_phase) {
        case 5: /* pending_dir semaphore */
                UNLOCK_INODE_MUTEX(mds->mds_pending_dir->d_inode);
        case 4: /* child inode semaphore */
                MDS_UP_READ_ORPHAN_SEM(child_inode);
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
                        ldlm_lock_decref(&parent_lockh, LCK_EX);
                else
                        ptlrpc_save_lock(req, &parent_lockh, LCK_EX);
                l_dput(dchild);
                l_dput(dchild);
                l_dput(dparent);
        case 0:
                break;
        default:
                CERROR("invalid cleanup_phase %d\n", cleanup_phase);
                LBUG();
        }
        req->rq_status = rc;

        /* trigger dqrel on the owner of child and parent */
        lquota_adjust(mds_quota_interface_ref, obd, qcids, qpids, rc,
                      FSFILT_OP_UNLINK);
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
        struct inode *inodes[PTLRPC_NUM_VERSIONS] = { NULL };
        struct mds_obd *mds = mds_req2mds(req);
        struct lustre_handle *handle = NULL, tgt_dir_lockh, src_lockh;
        struct ldlm_res_id src_res_id = { .name = {0} };
        struct ldlm_res_id tgt_dir_res_id = { .name = {0} };
        ldlm_policy_data_t src_policy ={.l_inodebits = {MDS_INODELOCK_UPDATE}};
        ldlm_policy_data_t tgt_dir_policy =
                                       {.l_inodebits = {MDS_INODELOCK_UPDATE}};
        int rc = 0, cleanup_phase = 0;
        ENTRY;

        LASSERT(offset == REQ_REC_OFF);

        DEBUG_REQ(D_INODE, req, "original "LPU64"/%u to "LPU64"/%u %s",
                  rec->ur_fid1->id, rec->ur_fid1->generation,
                  rec->ur_fid2->id, rec->ur_fid2->generation, rec->ur_name);

        mds_counter_incr(req->rq_export, LPROC_MDS_LINK);

        MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_LINK))
                GOTO(cleanup, rc = -ENOENT);

        if (rec->ur_dlm)
                ldlm_request_cancel(req, rec->ur_dlm, 0);

        /* Step 1: Lookup the source inode and target directory by FID */
        de_src = mds_fid2dentry(mds, rec->ur_fid1, NULL);
        if (IS_ERR(de_src))
                GOTO(cleanup, rc = PTR_ERR(de_src));

        cleanup_phase = 1; /* source dentry */

        de_tgt_dir = mds_fid2dentry(mds, rec->ur_fid2, NULL);
        if (IS_ERR(de_tgt_dir)) {
                rc = PTR_ERR(de_tgt_dir);
                de_tgt_dir = NULL;
                GOTO(cleanup, rc);
        }

        cleanup_phase = 2; /* target directory dentry */

        CDEBUG(D_INODE, "linking %.*s/%s to inode %lu\n",
               de_tgt_dir->d_name.len, de_tgt_dir->d_name.name, rec->ur_name,
               de_src->d_inode->i_ino);

        /* Step 2: Take the two locks */
        src_res_id.name[0] = de_src->d_inode->i_ino;
        src_res_id.name[1] = de_src->d_inode->i_generation;
        tgt_dir_res_id.name[0] = de_tgt_dir->d_inode->i_ino;
        tgt_dir_res_id.name[1] = de_tgt_dir->d_inode->i_generation;

        rc = enqueue_ordered_locks(obd, &src_res_id, &src_lockh, LCK_EX,
                                   &src_policy,
                                   &tgt_dir_res_id, &tgt_dir_lockh, LCK_EX,
                                   &tgt_dir_policy);
        if (rc)
                GOTO(cleanup, rc);

        cleanup_phase = 3; /* locks */

        /* version recovery check */
        /* directory check */
        rc = mds_version_get_check(req, de_tgt_dir->d_inode, 0);
        if (rc)
                GOTO(cleanup_no_trans, rc);
        /* inode version check */
        rc = mds_version_get_check(req, de_src->d_inode, 1);
        if (rc)
                GOTO(cleanup_no_trans, rc);

        if (mds_inode_is_orphan(de_src->d_inode)) {
                CDEBUG(D_INODE, "an attempt to link an orphan inode %lu/%u\n",
                       de_src->d_inode->i_ino,
                       de_src->d_inode->i_generation);
                GOTO(cleanup, rc = -ENOENT);
        }

        /* Step 3: Lookup the child */
        dchild = mds_lookup(obd, rec->ur_name, de_tgt_dir, rec->ur_namelen-1);
        if (IS_ERR(dchild)) {
                rc = PTR_ERR(dchild);
                dchild = NULL;
                if (rc != -EPERM && rc != -EACCES && rc != -ENAMETOOLONG)
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
        OBD_FAIL_WRITE(obd, OBD_FAIL_MDS_REINT_LINK_WRITE, de_src->d_inode->i_sb);

        if (req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                GOTO(cleanup, rc = -EROFS);

        handle = fsfilt_start(obd, de_tgt_dir->d_inode, FSFILT_OP_LINK, NULL);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));

        LOCK_INODE_MUTEX(de_tgt_dir->d_inode);
        rc = ll_vfs_link(de_src, mds->mds_vfsmnt, de_tgt_dir->d_inode, dchild,
                         mds->mds_vfsmnt);
        UNLOCK_INODE_MUTEX(de_tgt_dir->d_inode);
        if (rc && rc != -EPERM && rc != -EACCES)
                CERROR("vfs_link error %d\n", rc);
        if (rc == 0) {
                struct iattr iattr;
                int err;

                /* update ctime of old file */
                iattr.ia_valid = ATTR_CTIME;
                LTIME_S(iattr.ia_ctime) = rec->ur_time;
                err = fsfilt_setattr(obd, de_src, handle, &iattr, 0);
                if (err)
                        CERROR("error on old inode time update: "
                               "rc = %d\n", err);

                /* update mtime and ctime of target directory */
                iattr.ia_valid = ATTR_MTIME | ATTR_CTIME;
                LTIME_S(iattr.ia_mtime) = rec->ur_time;
                LTIME_S(iattr.ia_ctime) = rec->ur_time;
                err = fsfilt_setattr(obd, de_tgt_dir, handle, &iattr, 0);
                if (err)
                        CERROR("error on target dir inode time update: "
                               "rc = %d\n", err);
        }
cleanup:
        inodes[0] = de_tgt_dir ? de_tgt_dir->d_inode : NULL;
        inodes[1] = (dchild && !IS_ERR(dchild)) ? dchild->d_inode : NULL;
        rc = mds_finish_transno(mds, inodes, handle, req, rc, 0, 0);
        EXIT;

cleanup_no_trans:
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
int mds_get_parents_children_locked(struct obd_device *obd,
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
        ldlm_policy_data_t p_policy = {.l_inodebits = {MDS_INODELOCK_UPDATE}};
        /* Only dentry should disappear, but the inode itself would be
           intact otherwise. */
        ldlm_policy_data_t c1_policy = {.l_inodebits = {MDS_INODELOCK_LOOKUP}};
        /* If something is going to be replaced, both dentry and inode locks are
         * needed */
        ldlm_policy_data_t c2_policy = {.l_inodebits = {MDS_INODELOCK_FULL}};
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
                if (IS_ERR(*de_tgtdirp)) {
                        rc = PTR_ERR(*de_tgtdirp);
                        *de_tgtdirp = NULL;
                        GOTO(cleanup, rc);
                }
        }

        cleanup_phase = 2; /* target directory dentry */

        p2_res_id.name[0] = (*de_tgtdirp)->d_inode->i_ino;
        p2_res_id.name[1] = (*de_tgtdirp)->d_inode->i_generation;

        /* Step 3: Lookup the source child entry */
        *de_oldp = mds_lookup(obd, old_name, *de_srcdirp, old_len - 1);
        if (IS_ERR(*de_oldp)) {
                rc = PTR_ERR(*de_oldp);
                CDEBUG(D_INODE, "old child lookup error (%.*s): rc %d\n",
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
        if (!new_name)
                GOTO(retry_locks, rc);
        *de_newp = mds_lookup(obd, new_name, *de_tgtdirp, new_len - 1);
        if (IS_ERR(*de_newp)) {
                rc = PTR_ERR(*de_newp);
                CDEBUG(D_DENTRY, "new child lookup error (%.*s): rc %d\n",
                       old_len - 1, old_name, rc);
                GOTO(cleanup, rc);
        }

        cleanup_phase = 4; /* target dentry */

        inode = (*de_newp)->d_inode;
        if (inode != NULL) {
                if (is_bad_inode(inode)) {
                        CERROR("bad inode returned %lu/%u\n",
                               inode->i_ino, inode->i_generation);
                        GOTO(cleanup, rc = -ENOENT);
                }
                inode = igrab(inode);
        }
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

        if (c2_res_id.name[0] != 0 && res_gt(&c2_res_id, &p2_res_id,NULL,NULL))
                maxres_tgt = &c2_res_id;

        rc = enqueue_4ordered_locks(obd, &p1_res_id,&dlm_handles[0],parent_mode,
                                    &p_policy,
                                    &p2_res_id, &dlm_handles[1], parent_mode,
                                    &p_policy,
                                    &c1_res_id, &dlm_handles[2], child_mode,
                                    &c1_policy,
                                    &c2_res_id, &dlm_handles[3], child_mode,
                                    &c2_policy);
        if (rc)
                GOTO(cleanup, rc);

        cleanup_phase = 6; /* parent and child(ren) locks */

        /* Step 6a: Re-lookup source child to verify it hasn't changed */
        rc = mds_verify_child(obd, &p1_res_id, &dlm_handles[0], *de_srcdirp,
                              parent_mode, &c1_res_id, &dlm_handles[2], de_oldp,
                              child_mode, &c1_policy, old_name, old_len,
                              maxres_tgt);
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

        if (!new_name)
                GOTO(cleanup, rc);

        /* Safe to skip check for child res being all zero */
        if (res_gt(&c1_res_id, maxres_src, NULL, NULL))
                maxres_src = &c1_res_id;

        /* Step 6b: Re-lookup target child to verify it hasn't changed */
        rc = mds_verify_child(obd, &p2_res_id, &dlm_handles[1], *de_tgtdirp,
                              parent_mode, &c2_res_id, &dlm_handles[3], de_newp,
                              child_mode, &c2_policy, new_name, new_len,
                              maxres_src);
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
        struct dentry *trap;
        struct inode *old_inode = NULL, *new_inode = NULL;
        struct inode *inodes[PTLRPC_NUM_VERSIONS] = { NULL };
        struct mds_obd *mds = mds_req2mds(req);
        struct lustre_handle dlm_handles[4];
        struct mds_body *body = NULL;
        struct lov_mds_md *lmm = NULL;
        int rc = 0, lock_count = 3, cleanup_phase = 0, sz;
        void *handle = NULL;
        unsigned int qcids[MAXQUOTAS] = { 0, 0 };
        unsigned int qpids[4] = { 0, 0, 0, 0 };
        ENTRY;

        LASSERT(offset == REQ_REC_OFF);
        offset = REPLY_REC_OFF;

        DEBUG_REQ(D_INODE, req, "parent "LPU64"/%u %s to "LPU64"/%u %s",
                  rec->ur_fid1->id, rec->ur_fid1->generation, rec->ur_name,
                  rec->ur_fid2->id, rec->ur_fid2->generation, rec->ur_tgt);

        mds_counter_incr(req->rq_export, LPROC_MDS_RENAME);

        MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));

        if (rec->ur_dlm)
                ldlm_request_cancel(req, rec->ur_dlm, 0);

        rc = mds_get_parents_children_locked(obd, mds, rec->ur_fid1, &de_srcdir,
                                             rec->ur_fid2, &de_tgtdir, LCK_EX,
                                             rec->ur_name, rec->ur_namelen,
                                             &de_old, rec->ur_tgt,
                                             rec->ur_tgtlen, &de_new,
                                             dlm_handles, LCK_EX);
        if (rc)
                GOTO(cleanup, rc);

        cleanup_phase = 1; /* parent(s), children, locks */

        old_inode = de_old->d_inode;
        new_inode = de_new->d_inode;

        if (new_inode != NULL)
                lock_count = 4;

        /* version recovery check */
        rc = mds_version_get_check(req, de_srcdir->d_inode, 0);
        if (rc)
                GOTO(cleanup_no_trans, rc);
        rc = mds_version_get_check(req, old_inode, 1);
        if (rc)
                GOTO(cleanup_no_trans, rc);
        rc = mds_version_get_check(req, de_tgtdir->d_inode, 2);
        if (rc)
                GOTO(cleanup_no_trans, rc);
        rc = mds_version_get_check(req, new_inode, 3);
        if (rc)
                GOTO(cleanup_no_trans, rc);

        /* sanity check for src inode */
        if (old_inode->i_ino == de_srcdir->d_inode->i_ino ||
            old_inode->i_ino == de_tgtdir->d_inode->i_ino)
                GOTO(cleanup, rc = -EINVAL);

        if (req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                GOTO(cleanup, rc = -EROFS);

        if (new_inode == NULL)
                goto no_unlink;

        igrab(new_inode);
        cleanup_phase = 2; /* iput(new_inode) when finished */

        /* sanity check for dest inode */
        if (new_inode->i_ino == de_srcdir->d_inode->i_ino ||
            new_inode->i_ino == de_tgtdir->d_inode->i_ino)
                GOTO(cleanup, rc = -EINVAL);

        if (old_inode == new_inode)
                GOTO(cleanup, rc = 0);

        /* save uids/gids for qunit acquire/release */
        qcids[USRQUOTA] = old_inode->i_uid;
        qcids[GRPQUOTA] = old_inode->i_gid;
        qpids[USRQUOTA] = de_tgtdir->d_inode->i_uid;
        qpids[GRPQUOTA] = de_tgtdir->d_inode->i_gid;
        qpids[2] = de_srcdir->d_inode->i_uid;
        qpids[3] = de_srcdir->d_inode->i_gid;

        /* if we are about to remove the target at first, pass the EA of
         * that inode to client to perform and cleanup on OST */
        body = lustre_msg_buf(req->rq_repmsg, offset, sizeof(*body));
        LASSERT(body != NULL);

        /* child orphan sem protects orphan_dec_test && is_orphan race */
        MDS_DOWN_READ_ORPHAN_SEM(new_inode);
        cleanup_phase = 3; /* MDS_UP_READ_ORPHAN_SEM(new_inode) when finished */

        if ((S_ISDIR(new_inode->i_mode) && new_inode->i_nlink == 2) ||
            new_inode->i_nlink == 1) {
                if (mds_orphan_needed(obd, new_inode)) {
                        /* need to lock pending_dir before transaction */
                        LOCK_INODE_MUTEX(mds->mds_pending_dir->d_inode);
                        cleanup_phase = 4; /* UNLOCK_INODE_MUTEX(mds->mds_pending_dir->d_inode); */
                } else if (S_ISREG(new_inode->i_mode)) {
                        mds_pack_inode2body(body, new_inode);
                        mds_pack_md(obd, req->rq_repmsg, offset + 1, body,
                                    new_inode, MDS_PACK_MD_LOCK, 0,
                                    req->rq_export->exp_connect_flags);
                }
        }

no_unlink:
        OBD_FAIL_WRITE(obd, OBD_FAIL_MDS_REINT_RENAME_WRITE,
                       de_srcdir->d_inode->i_sb);

        lmm = lustre_msg_buf(req->rq_repmsg, offset + 1, 0);
        /* check that lmm size is not 0 */
        sz = lustre_msg_buflen(req->rq_repmsg, offset + 1) > 0 ?
             le32_to_cpu(lmm->lmm_stripe_count) : 0;

        handle = fsfilt_start_log(obd, de_tgtdir->d_inode, FSFILT_OP_RENAME,
                                  NULL, sz);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));

        trap = lock_rename(de_tgtdir, de_srcdir);
        /* source should not be ancestor of target */
        if (de_old == trap) {
                unlock_rename(de_tgtdir, de_srcdir);
                GOTO(cleanup, rc = -EINVAL);
        }
        /* target should not be an ancestor of source */
        if (de_new == trap) {
                unlock_rename(de_tgtdir, de_srcdir);
                GOTO(cleanup, rc = -ENOTEMPTY);
        }

        de_old->d_fsdata = req;
        de_new->d_fsdata = req;

        rc = ll_vfs_rename(de_srcdir->d_inode, de_old, mds->mds_vfsmnt,
                           de_tgtdir->d_inode, de_new, mds->mds_vfsmnt);

        unlock_rename(de_tgtdir, de_srcdir);

        if (rc == 0) {
                struct iattr iattr;
                int err;

                /* update ctime of renamed file */
                iattr.ia_valid = ATTR_CTIME;
                LTIME_S(iattr.ia_ctime) = rec->ur_time;
                if (S_ISDIR(de_old->d_inode->i_mode) &&
                    de_srcdir->d_inode != de_tgtdir->d_inode) {
                        /* cross directory rename of a directory, ".."
                           changed, update mtime also */
                        iattr.ia_valid |= ATTR_MTIME;
                        LTIME_S(iattr.ia_mtime) = rec->ur_time;
                }
                err = fsfilt_setattr(obd, de_old, handle, &iattr, 0);
                if (err)
                        CERROR("error on old inode time update: "
                               "rc = %d\n", err);

                if (de_new->d_inode) {
                        /* target file exists, update its ctime as it
                           gets unlinked */
                        iattr.ia_valid = ATTR_CTIME;
                        LTIME_S(iattr.ia_ctime) = rec->ur_time;
                        err = fsfilt_setattr(obd, de_new, handle, &iattr, 0);
                        if (err)
                                CERROR("error on target inode time update: "
                                       "rc = %d\n", err);
                }

                /* update mtime and ctime of old directory */
                iattr.ia_valid = ATTR_MTIME | ATTR_CTIME;
                LTIME_S(iattr.ia_mtime) = rec->ur_time;
                LTIME_S(iattr.ia_ctime) = rec->ur_time;
                err = fsfilt_setattr(obd, de_srcdir, handle, &iattr, 0); 
                if (err)
                        CERROR("error on old dir inode update: "
                               "rc = %d\n", err);

                if (de_srcdir->d_inode != de_tgtdir->d_inode) {
                        /* cross directory rename, update
                           mtime and ctime of new directory */
                        iattr.ia_valid = ATTR_MTIME | ATTR_CTIME;
                        LTIME_S(iattr.ia_mtime) = rec->ur_time;
                        LTIME_S(iattr.ia_ctime) = rec->ur_time;
                        err = fsfilt_setattr(obd, de_tgtdir, handle, &iattr, 0);
                        if (err)
                                CERROR("error on new dir inode time update: "
                                       "rc = %d\n", err);
                }
        }

        if (rc == 0 && new_inode != NULL && new_inode->i_nlink == 0) {
                if (mds_orphan_needed(obd, new_inode)) {
                        rc = mds_orphan_add_link(rec, obd, de_new);

                        if (rc == 1)
                                /* inode successfully linked to PENDING */
                                GOTO(cleanup, rc = 0);
                        else
                                /* we failed to move the file to PENDING,
                                 * really unlink the file as if there were
                                 * no more openers */
                                rc = 0;
                }

                if (!S_ISREG(new_inode->i_mode))
                        GOTO(cleanup, rc);

                if (!(body->valid & OBD_MD_FLEASIZE)) {
                        body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                        OBD_MD_FLATIME | OBD_MD_FLMTIME);
                } else if (mds_log_op_unlink(obd,
                                             lustre_msg_buf(req->rq_repmsg,
                                                            offset + 1, 0),
                                             lustre_msg_buflen(req->rq_repmsg,
                                                               offset + 1),
                                             lustre_msg_buf(req->rq_repmsg,
                                                            offset + 2, 0),
                                             lustre_msg_buflen(req->rq_repmsg,
                                                               offset + 2))
                           > 0) {
                        body->valid |= OBD_MD_FLCOOKIE;
                }
        }

        GOTO(cleanup, rc);
cleanup:
        inodes[0] = de_srcdir && !IS_ERR(de_srcdir) ? de_srcdir->d_inode : NULL;
        inodes[1] = old_inode;
        inodes[2] = de_tgtdir && !IS_ERR(de_tgtdir) ? de_tgtdir->d_inode : NULL;
        inodes[3] = new_inode;
        rc = mds_finish_transno(mds, inodes, handle, req, rc, 0, 0);

cleanup_no_trans:
        switch (cleanup_phase) {
        case 4:
                UNLOCK_INODE_MUTEX(mds->mds_pending_dir->d_inode);
        case 3:
                MDS_UP_READ_ORPHAN_SEM(new_inode);
        case 2:
                iput(new_inode);
        case 1:
                if (rc) {
                        if (lock_count == 4)
                                ldlm_lock_decref(&(dlm_handles[3]), LCK_EX);
                        ldlm_lock_decref(&(dlm_handles[2]), LCK_EX);
                        ldlm_lock_decref(&(dlm_handles[1]), LCK_EX);
                        ldlm_lock_decref(&(dlm_handles[0]), LCK_EX);
                } else {
                        if (lock_count == 4)
                                ptlrpc_save_lock(req,&(dlm_handles[3]), LCK_EX);
                        ptlrpc_save_lock(req, &(dlm_handles[2]), LCK_EX);
                        ptlrpc_save_lock(req, &(dlm_handles[1]), LCK_EX);
                        ptlrpc_save_lock(req, &(dlm_handles[0]), LCK_EX);
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

        /* acquire/release qunit */
        lquota_adjust(mds_quota_interface_ref, obd, qcids, qpids, rc,
                      FSFILT_OP_RENAME);
        return 0;
}

typedef int (*mds_reinter)(struct mds_update_record *, int offset,
                           struct ptlrpc_request *, struct lustre_handle *);

static mds_reinter reinters[REINT_MAX] = {
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
        struct mds_obd *mds = &obd->u.mds;
        struct lvfs_run_ctxt *saved;
        int rc;
#ifdef CRAY_XT3
        gid_t fsgid = rec->ur_uc.luc_fsgid;
#endif
        ENTRY;

        OBD_SLAB_ALLOC_PTR(saved, obd_lvfs_ctxt_cache);
        if (saved == NULL) {
                CERROR("cannot allocate memory for run ctxt\n");
                RETURN(-ENOMEM);
        }

#ifdef CRAY_XT3
        if (req->rq_uid != LNET_UID_ANY) {
                /* non-root local cluster client
                 * NB root's creds are believed... */
                LASSERT (req->rq_uid != 0);
                rec->ur_uc.luc_fsuid = req->rq_uid;
                cfs_kernel_cap_unpack(&rec->ur_uc.luc_cap, 0);
        }
#endif

        /* get group info of this user */
        rec->ur_uc.luc_uce = upcall_cache_get_entry(mds->mds_group_hash,
                                                    rec->ur_uc.luc_fsuid,
                                                    rec->ur_uc.luc_fsgid, 2,
                                                    &rec->ur_uc.luc_suppgid1);

        if (IS_ERR(rec->ur_uc.luc_uce)) {
                rc = PTR_ERR(rec->ur_uc.luc_uce);
                rec->ur_uc.luc_uce = NULL;
                goto out;
        }

        /* checked by unpacker */
        LASSERT(rec->ur_opcode < REINT_MAX && reinters[rec->ur_opcode] != NULL);

#ifdef CRAY_XT3
        if (rec->ur_uc.luc_uce)
                rec->ur_uc.luc_fsgid = rec->ur_uc.luc_uce->ue_primary;
#endif

        push_ctxt(saved, &obd->obd_lvfs_ctxt, &rec->ur_uc);

#ifdef CRAY_XT3
        if (rec->ur_uc.luc_uce && fsgid != rec->ur_uc.luc_fsgid &&
            in_group_p(fsgid)) {
                struct cred *cred;
                rec->ur_uc.luc_fsgid = saved->luc.luc_fsgid = fsgid;
                if ((cred = prepare_creds())) {
                        cred->fsgid = fsgid;
                        commit_creds(cred);
                }
        }
#endif

        rc = reinters[rec->ur_opcode] (rec, offset, req, lockh);
        pop_ctxt(saved, &obd->obd_lvfs_ctxt, &rec->ur_uc);
        upcall_cache_put_entry(mds->mds_group_hash, rec->ur_uc.luc_uce);

out:
        OBD_SLAB_FREE_PTR(saved, obd_lvfs_ctxt_cache);

        RETURN(rc);
}
