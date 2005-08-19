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
#include <linux/jbd.h>
#include <linux/namei.h>
#include <linux/ext3_fs.h>
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_log.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_acl.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_smfs.h>
#include "mds_internal.h"

struct mds_logcancel_data {
        struct lov_mds_md      *mlcd_lmm;
        int                     mlcd_size;
        int                     mlcd_cookielen;
        int                     mlcd_eadatalen;
        struct llog_cookie      mlcd_cookies[0];
};

static void mds_cancel_cookies_cb(struct obd_device *obd,
                                  __u64 transno, void *cb_data,
                                  int error)
{
        struct mds_logcancel_data *mlcd = cb_data;
        struct lov_stripe_md *lsm = NULL;
        struct llog_ctxt *ctxt;
        int rc;

        obd_transno_commit_cb(obd, transno, error);

        CDEBUG(D_HA, "cancelling %d cookies\n",
               (int)(mlcd->mlcd_cookielen / sizeof(*mlcd->mlcd_cookies)));

        rc = obd_unpackmd(obd->u.mds.mds_dt_exp, &lsm, mlcd->mlcd_lmm,
                          mlcd->mlcd_eadatalen);
        if (rc < 0) {
                CERROR("bad LSM cancelling %d log cookies: rc %d\n",
                       (int)(mlcd->mlcd_cookielen/sizeof(*mlcd->mlcd_cookies)),
                       rc);
        } else {
                ///* XXX 0 normally, SENDNOW for debug */);
                ctxt = llog_get_context(&obd->obd_llogs,
                                        mlcd->mlcd_cookies[0].lgc_subsys + 1);
                rc = llog_cancel(ctxt, mlcd->mlcd_cookielen /
                                 sizeof(*mlcd->mlcd_cookies),
                                 mlcd->mlcd_cookies, OBD_LLOG_FL_SENDNOW, lsm);
                if (rc)
                        CERROR("error cancelling %d log cookies: rc %d\n",
                               (int)(mlcd->mlcd_cookielen /
                                     sizeof(*mlcd->mlcd_cookies)), rc);
		obd_free_memmd(obd->u.mds.mds_dt_exp, &lsm);
        }

        OBD_FREE(mlcd, mlcd->mlcd_size);
}

/* Assumes caller has already pushed us into the kernel context. */
int mds_finish_transno(struct mds_obd *mds, struct inode *inode, void *handle,
                       struct ptlrpc_request *req, int rc, __u32 op_data)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_client_data *mcd = med->med_mcd;
        int err, log_pri = D_HA;
        __u64 transno;
        loff_t off;
        ENTRY;

        /* if the export has already been failed, we have no last_rcvd slot */
        if (req->rq_export->exp_failed) {
                CERROR("committing transaction for disconnected client\n");
                if (handle)
                        GOTO(out_commit, rc);
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
                LASSERTF(transno == 0, "BUG 3934, t"LPU64" rc %d\n", transno, rc);
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
        if (req->rq_reqmsg->opc == MDS_CLOSE) {
                mcd->mcd_last_close_transno = cpu_to_le64(transno);
                mcd->mcd_last_close_xid = cpu_to_le64(req->rq_xid);
                mcd->mcd_last_close_result = cpu_to_le32(rc);
                mcd->mcd_last_close_data = cpu_to_le32(op_data);
        } else {
                mcd->mcd_last_transno = cpu_to_le64(transno);
                mcd->mcd_last_xid = cpu_to_le64(req->rq_xid);
                mcd->mcd_last_result = cpu_to_le32(rc);
                mcd->mcd_last_data = cpu_to_le32(op_data);
        }

        fsfilt_add_journal_cb(obd, mds->mds_sb, transno, handle,
                              mds_commit_last_transno_cb, NULL);
        
        err = fsfilt_write_record(obd, mds->mds_rcvd_filp, mcd,
                                  sizeof(*mcd), &off, 0);

        if (err) {
                log_pri = D_ERROR;
                if (rc == 0)
                        rc = err;
        }

        DEBUG_REQ(log_pri, req,
                  "wrote trans #"LPU64" client %s at idx %u: err = %d",
                  transno, mcd->mcd_uuid, med->med_idx, err);

        err = mds_update_last_fid(obd, handle, 0);
        if (err) {
                log_pri = D_ERROR;
                if (rc == 0)
                        rc = err;
        }
                
        err = mds_dt_write_objids(obd);
        if (err) {
                log_pri = D_ERROR;
                if (rc == 0)
                        rc = err;
        }
        CDEBUG(log_pri, "wrote objids: err = %d\n", err);

        EXIT;
out_commit:
        err = fsfilt_commit(obd, mds->mds_sb, inode, handle, 
                            req->rq_export->exp_sync);
        if (err) {
                CERROR("error committing transaction: %d\n", err);
                if (!rc)
                        rc = err;
        }

        return rc;
}

/* this gives the same functionality as the code between
 * sys_chmod and inode_setattr
 * chown_common and inode_setattr
 * utimes and inode_setattr
 */
#ifndef ATTR_RAW
/* Just for the case if we have some clients that know about ATTR_RAW */
#define ATTR_RAW 8192
#endif
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
        char                       str[PTL_NALFMT_SIZE];
        struct list_head          *tmp;
        struct ptlrpc_reply_state *oldrep;
        struct ptlrpc_service     *svc;
        struct llog_create_locks  *lcl;
        unsigned long              flags;
        int                        i;

        /* CAVEAT EMPTOR: spinlock order */
        spin_lock_irqsave (&exp->exp_lock, flags);
        list_for_each (tmp, &exp->exp_outstanding_replies) {
                oldrep = list_entry(tmp, struct ptlrpc_reply_state,rs_exp_list);

                if (oldrep->rs_xid != req->rq_xid)
                        continue;

                if (oldrep->rs_msg->opc != req->rq_reqmsg->opc)
                        CERROR ("Resent req xid "LPX64" has mismatched opc: "
                                "new %d old %d\n", req->rq_xid,
                                req->rq_reqmsg->opc, oldrep->rs_msg->opc);

                svc = oldrep->rs_srv_ni->sni_service;
                spin_lock (&svc->srv_lock);

                list_del_init (&oldrep->rs_exp_list);

                CWARN("Stealing %d locks from rs %p x"LPD64".t"LPD64
                      " o%d NID %s\n", oldrep->rs_nlocks, oldrep,
                      oldrep->rs_xid, oldrep->rs_transno, oldrep->rs_msg->opc,
                      ptlrpc_peernid2str(&exp->exp_connection->c_peer, str));

                for (i = 0; i < oldrep->rs_nlocks; i++)
                        ptlrpc_save_lock(req,
                                         &oldrep->rs_locks[i],
                                         oldrep->rs_modes[i]);
                oldrep->rs_nlocks = 0;

                lcl = oldrep->rs_llog_locks;
                oldrep->rs_llog_locks = NULL;
                if (lcl != NULL)
                        ptlrpc_save_llog_lock(req, lcl);

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
        if (req->rq_reqmsg->opc == MDS_CLOSE) {
                DEBUG_REQ(D_HA, req, "restoring transno "LPD64"/status %d",
                          mcd->mcd_last_close_transno, mcd->mcd_last_close_result);
                req->rq_repmsg->transno = req->rq_transno = mcd->mcd_last_close_transno;
                req->rq_repmsg->status = req->rq_status = mcd->mcd_last_close_result;
        } else {
                DEBUG_REQ(D_HA, req, "restoring transno "LPD64"/status %d",
                          mcd->mcd_last_transno, mcd->mcd_last_result);
                req->rq_repmsg->transno = req->rq_transno = mcd->mcd_last_transno;
                req->rq_repmsg->status = req->rq_status = mcd->mcd_last_result;
        }

        mds_steal_ack_locks(req);
}

static void reconstruct_reint_setattr(struct mds_update_record *rec,
                                      int offset, struct ptlrpc_request *req)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_body *body;
        struct dentry *de;

        mds_req_from_mcd(req, med->med_mcd);

        de = mds_id2dentry(req2obd(req), rec->ur_id1, NULL);
        if (IS_ERR(de)) {
                LASSERT(PTR_ERR(de) == req->rq_status);
                return;
        }

        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*body));
        mds_pack_inode2body(req2obd(req), body, de->d_inode, 1);

        /* Don't return OST-specific attributes if we didn't just set them */
        if (rec->ur_iattr.ia_valid & ATTR_SIZE)
                body->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
        if (rec->ur_iattr.ia_valid & (ATTR_MTIME | ATTR_MTIME_SET))
                body->valid |= OBD_MD_FLMTIME;
        if (rec->ur_iattr.ia_valid & (ATTR_ATIME | ATTR_ATIME_SET))
                body->valid |= OBD_MD_FLATIME;

        l_dput(de);
}

static int mds_reint_remote_setfacl(struct obd_device *obd,
                                    struct mds_export_data *med,
                                    struct mds_update_record *rec,
                                    struct ptlrpc_request *req)
{
        struct rmtacl_upcall_desc desc;
        struct dentry   *de;
        struct inode    *inode;
        struct mds_body *body;
        int              rc = 0;
        int              repsize[2] = { sizeof(*body), LUSTRE_ACL_SIZE_MAX };
        ENTRY;

        rc = lustre_pack_reply(req, 2, repsize, NULL);
        if (rc)
                RETURN(rc);

        de = mds_id2dentry(obd, rec->ur_id1, NULL);
        if (IS_ERR(de))
                GOTO(out, rc = PTR_ERR(de));

        inode = de->d_inode;
        LASSERT(inode);

        /* setxattr from remote client:
         */
        memset(&desc, 0, sizeof(desc));
        desc.cmd = (char *) rec->ur_ea2data;
        desc.cmdlen = rec->ur_ea2datalen;
        desc.res = lustre_msg_buf(req->rq_repmsg, 1, LUSTRE_ACL_SIZE_MAX);
        desc.reslen = LUSTRE_ACL_SIZE_MAX;

        mds_do_remote_acl_upcall(&desc);
        if (desc.upcall_status)
                GOTO(out_put, rc = desc.upcall_status);

        if (desc.status < 0)
                desc.status = -desc.status;

        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*body));
        LASSERT(body);

        /* client (lmv) will do limited checking upon replied mds_body,
         * we pack it as normal, but "steal" field "flags" field to store
         * the acl execution status.
         */
        mds_pack_inode2body(obd, body, inode, 1);
        body->flags = desc.status;
        mds_body_do_reverse_map(med, body);

        EXIT;
out_put:
        l_dput(de);
out:
        req->rq_status = rc;
        return 0;
}

static int mds_get_md_type(char *name)
{
        if (!strcmp(name, XATTR_LUSTRE_MDS_LOV_EA)) 
                RETURN(EA_LOV);
        if (!strcmp(name, XATTR_LUSTRE_MDS_MEA_EA))
                RETURN(EA_MEA);
        if (!strcmp(name, XATTR_LUSTRE_MDS_SID_EA))
                RETURN(EA_SID);
        if (!strcmp(name, XATTR_LUSTRE_MDS_PID_EA))
                RETURN(EA_PID);
        if (!strcmp(name, XATTR_LUSTRE_MDS_KEY_EA))
                RETURN(EA_KEY);

        RETURN(0);
}

/* In the raw-setattr case, we lock the child inode.
 * In the write-back case or if being called from open, the client holds a lock
 * already.
 *
 * We use the ATTR_FROM_OPEN flag to tell these cases apart. */
static int mds_reint_setattr(struct mds_update_record *rec, int offset,
                             struct ptlrpc_request *req, struct lustre_handle *lh)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_export_data *med = &req->rq_export->u.eu_mds_data;
        struct mds_body *body;
        struct dentry *de = NULL;
        struct inode *inode = NULL;
        struct lustre_handle lockh[2] = {{0}, {0}};
        int parent_mode;
        void *handle = NULL;
        struct mds_logcancel_data *mlcd = NULL;
        int rc = 0, cleanup_phase = 0, err;
        int repcnt = 1, repsize[2] = { sizeof(*body) };
        int locked = 0, do_trunc = 0;
        ENTRY;

        LASSERT(offset == 1);

        DEBUG_REQ(D_INODE, req, "setattr "LPU64"/%u %x",
                  id_ino(rec->ur_id1), id_gen(rec->ur_id1),
                  rec->ur_iattr.ia_valid);

        /* remote setfacl need special handling */
        if ((rec->ur_iattr.ia_valid & ATTR_EA) &&
            !strcmp(rec->ur_eadata, XATTR_NAME_LUSTRE_ACL)) {
                return mds_reint_remote_setfacl(obd, med, rec, req);
        }

        if (rec->ur_iattr.ia_valid & ATTR_SIZE) {
                repsize[repcnt++] = sizeof(struct lustre_capa);
                do_trunc = 1; /* XXX: ATTR_SIZE will be cleared from ia_valid */
        }

        rc = lustre_pack_reply(req, repcnt, repsize, NULL);
        if (rc)
                RETURN(rc);

        MDS_CHECK_RESENT(req, reconstruct_reint_setattr(rec, offset, req));
        MD_COUNTER_INCREMENT(obd, setattr);

        if (med->med_remote) {
                if (rec->ur_iattr.ia_valid & ATTR_GID) {
                        CWARN("Deny chgrp from remote client\n");
                        GOTO(cleanup, rc = -EPERM);
                }
                if (rec->ur_iattr.ia_valid & ATTR_UID) {
                        uid_t uid;

                        uid = mds_idmap_lookup_uid(med->med_idmap, 0,
                                                   rec->ur_iattr.ia_uid);
                        if (uid == MDS_IDMAP_NOTFOUND) {
                                CWARN("Deny chown to uid %u\n",
                                      rec->ur_iattr.ia_uid);
                                GOTO(cleanup, rc = -EPERM);
                        }
                        rec->ur_iattr.ia_uid = uid;
                }
        }

        if (rec->ur_iattr.ia_valid & ATTR_FROM_OPEN) {
                de = mds_id2dentry(obd, rec->ur_id1, NULL);
                if (IS_ERR(de))
                        GOTO(cleanup, rc = PTR_ERR(de));
        } else {
                __u64 lockpart = MDS_INODELOCK_UPDATE;
                if (rec->ur_iattr.ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID))
                        lockpart |= MDS_INODELOCK_LOOKUP;
                de = mds_id2locked_dentry(obd, rec->ur_id1, NULL, LCK_PW,
                                          lockh, &parent_mode, NULL, 0, lockpart);
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

        if (rc == 0) {
                if (rec->ur_iattr.ia_valid & ATTR_EA) {
                        int flags = (int) rec->ur_iattr.ia_attr_flags;

                        rc = -EOPNOTSUPP;
                        if (!med->med_remote && inode->i_op &&
                            inode->i_op->setxattr) 
                                rc = inode->i_op->setxattr(
                                                de, rec->ur_eadata,
                                                rec->ur_ea2data,
                                                rec->ur_ea2datalen,
                                                flags);
                } else if (rec->ur_iattr.ia_valid & ATTR_EA_RM) {
                        rc = -EOPNOTSUPP;
                        if (inode->i_op && inode->i_op->removexattr) 
                                rc = inode->i_op->removexattr(de, 
                                                  rec->ur_eadata);
                } else if (rec->ur_iattr.ia_valid & ATTR_EA_CMOBD) {
                        char *name;
                        int type;
                        
                        LASSERT(rec->ur_eadata != NULL);
                        LASSERT(rec->ur_ea2data != NULL);
                        name = rec->ur_eadata;

                        /* XXX: tmp fix for setting LOV EA from CMOBD */
                        type = mds_get_md_type(name);

                        if (type == EA_LOV) {
                                CDEBUG(D_INFO, "set %s EA for cmobd\n", name);

                                rc = fsfilt_set_md(obd, inode, handle, 
                                                   rec->ur_ea2data,
                                                   rec->ur_ea2datalen,
                                                   type);
                                if (rc) {
                                        CERROR("fsfilt_set_md() failed, err %d\n",
                                               rc);
                                        GOTO(cleanup, rc);
                                }
                        }
                } else if ((S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)) &&
                           !((rec->ur_iattr.ia_valid & ATTR_KEY) || 
                             (rec->ur_iattr.ia_valid & ATTR_MAC))) {
                        
                        struct lov_stripe_md *lsm = NULL;
                        struct lov_user_md *lum = NULL;

                        if (rec->ur_eadata != NULL) {
                                rc = ll_permission(inode, MAY_WRITE, NULL);
                                if (rc < 0)
                                        GOTO(cleanup, rc);

                                lum = rec->ur_eadata;
                        
                                /* if lmm_stripe_size is -1 delete default
                                 * stripe from dir */
                                if (S_ISDIR(inode->i_mode) &&
                                    lum->lmm_stripe_size == (typeof(lum->lmm_stripe_size))(-1)){
                                        rc = fsfilt_set_md(obd, inode, handle, NULL, 0, EA_LOV);
                                        if (rc)
                                                GOTO(cleanup, rc);
                                } else {
                                        rc = obd_iocontrol(OBD_IOC_LOV_SETSTRIPE,
                                                           mds->mds_dt_exp, 0,
                                                           &lsm, rec->ur_eadata);
                                        if (rc)
                                                GOTO(cleanup, rc);
                                
                                        obd_free_memmd(mds->mds_dt_exp, &lsm);
                                        rc = fsfilt_set_md(obd, inode, handle, rec->ur_eadata,
                                                           rec->ur_eadatalen, EA_LOV);
                                        if (rc)
                                                GOTO(cleanup, rc);
                                }
                        }
                }
                
                if ((rec->ur_iattr.ia_valid & ATTR_KEY) || (rec->ur_iattr.ia_valid & ATTR_MAC)) {
                        void *key;
                        int keylen;
                        
                        LASSERT(rec->ur_eadatalen || rec->ur_ea3datalen); 
                        LASSERT(rec->ur_eadata || rec->ur_ea3data); 
                        key = rec->ur_ea3data ? rec->ur_ea3data : rec->ur_eadata;
                        keylen = rec->ur_ea3datalen ? rec->ur_ea3datalen : 
                                                     rec->ur_eadatalen;
                        mds_set_gskey(obd, handle, inode, key, keylen, 
                                      rec->ur_iattr.ia_valid); 
                }
        }

        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*body));
        mds_pack_inode2body(obd, body, inode, 1);

        /* Don't return OST-specific attributes if we didn't just set them */
        if (rec->ur_iattr.ia_valid & ATTR_SIZE)
                body->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
        if (rec->ur_iattr.ia_valid & (ATTR_MTIME | ATTR_MTIME_SET))
                body->valid |= OBD_MD_FLMTIME;
        if (rec->ur_iattr.ia_valid & (ATTR_ATIME | ATTR_ATIME_SET))
                body->valid |= OBD_MD_FLATIME;

        if (do_trunc) {
                struct lustre_capa capa = {
                        .lc_uid   = rec->ur_uc.luc_uid,
                        .lc_op    = MAY_WRITE,
                        .lc_ino   = inode->i_ino,
                        .lc_mdsid = mds->mds_num,
                };
                int offset = 1;

                LASSERT(capa.lc_mdsid == mds->mds_num);
                rc = mds_pack_capa(obd, med, NULL, &capa, req,
                                   &offset, body);
                if (rc < 0) {
                        CERROR("mds_pack_capa: rc = %d\n", rc);
                        RETURN(rc);
                }
        }

        mds_body_do_reverse_map(med, body);

        /* The logcookie should be no use anymore, why nobody remove
         * following code block?
         */
        LASSERT(rec->ur_cookielen == 0);
        if (rc == 0 && rec->ur_cookielen && !IS_ERR(mds->mds_dt_obd)) {
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
                fsfilt_add_journal_cb(req->rq_export->exp_obd, mds->mds_sb, 0,
                                      handle, mds_cancel_cookies_cb, mlcd);
        err = mds_finish_transno(mds, inode, handle, req, rc, 0);
        switch (cleanup_phase) {
        case 1:
                if ((S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)) &&
                    rec->ur_eadata != NULL)
                        up(&inode->i_sem);
                l_dput(de);
                if (locked) {
#ifdef S_PDIROPS
                        if (lockh[1].cookie != 0)
                                ldlm_lock_decref(lockh + 1, parent_mode);
#endif
                        if (rc) {
                                ldlm_lock_decref(lockh, LCK_PW);
                        } else {
                                ptlrpc_save_lock (req, lockh, LCK_PW);
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
        struct dentry *parent, *child;
        struct mds_body *body;
        ENTRY;

        mds_req_from_mcd(req, med->med_mcd);

        if (req->rq_status) {
                EXIT;
                return;
        }

        parent = mds_id2dentry(req2obd(req), rec->ur_id1, NULL);
        LASSERT(!IS_ERR(parent));
        child = ll_lookup_one_len(rec->ur_name, parent,
                                  rec->ur_namelen - 1);
        LASSERT(!IS_ERR(child));
        if ((child->d_flags & DCACHE_CROSS_REF)) {
                LASSERTF(child->d_inode == NULL, "BUG 3869\n");
                body = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*body));
                mds_pack_dentry2body(req2obd(req), body, child, 1);
        } else if (child->d_inode == NULL) {
                DEBUG_REQ(D_ERROR, req, "parent "DLID4" name %s mode %o",
                          OLID4(rec->ur_id1), rec->ur_name, rec->ur_mode);
                LASSERTF(child->d_inode != NULL, "BUG 3869\n");
        } else {
                body = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*body));
                mds_pack_inode2body(req2obd(req), body, child->d_inode, 1);
        }
        l_dput(parent);
        l_dput(child);
        EXIT;
}

static int mds_get_default_acl(struct inode *dir, void **pacl)
{
        struct dentry de = { .d_inode = dir };
        int size, size2;

        LASSERT(S_ISDIR(dir->i_mode));

        if (!dir->i_op->getxattr)
                return 0;

        size = dir->i_op->getxattr(&de, XATTR_NAME_ACL_DEFAULT, NULL, 0);
        if (size == 0 || size == -ENODATA || size == -EOPNOTSUPP)
                return 0;
        else if (size < 0)
                return size;

        OBD_ALLOC(*pacl, size);
        if (!*pacl)
                return -ENOMEM;

        size2 = dir->i_op->getxattr(&de, XATTR_NAME_ACL_DEFAULT, *pacl, size);
        if (size2 != size) {
                /* since we already locked the dir, it should not change
                 * between the 2 getxattr calls
                 */
                CERROR("2'nd getxattr got %d, expect %d\n", size2, size);
                OBD_FREE(*pacl, size);
                return -EIO;
        }

        return size;
}

static int mds_reint_create(struct mds_update_record *rec, int offset,
                            struct ptlrpc_request *req,
                            struct lustre_handle *lh)
{
        struct dentry *dparent = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_body *body = NULL;
        struct dentry *dchild = NULL;
        struct inode *dir = NULL;
        void *handle = NULL;
        struct lustre_handle lockh[2] = {{0}, {0}};
        int parent_mode;
        int rc = 0, err, type = rec->ur_mode & S_IFMT, cleanup_phase = 0;
        int created = 0;
        struct dentry_params dp;
        struct mea *mea = NULL;
        int mea_size;
        struct lustre_id sid;
        __u64 fid;
        ENTRY;

        LASSERT(offset == 1);
        
        LASSERT(!strcmp(req->rq_export->exp_obd->obd_type->typ_name,
                        OBD_MDS_DEVICENAME));

        DEBUG_REQ(D_INODE, req, "parent "LPU64"/%u name %s mode %o",
                  id_ino(rec->ur_id1), id_gen(rec->ur_id1),
                  rec->ur_name, rec->ur_mode);

        MDS_CHECK_RESENT(req, reconstruct_reint_create(rec, offset, req));

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_CREATE))
                GOTO(cleanup, rc = -ESTALE);

        dparent = mds_id2locked_dentry(obd, rec->ur_id1, NULL, LCK_PW,
                                       lockh, &parent_mode, rec->ur_name,
                                       rec->ur_namelen - 1, MDS_INODELOCK_UPDATE);
        if (IS_ERR(dparent)) {
                rc = PTR_ERR(dparent);
                CERROR("parent lookup error %d, id "DLID4"\n",
                       rc, OLID4(rec->ur_id1));
                GOTO(cleanup, rc);
        }
        cleanup_phase = 1; /* locked parent dentry */
        dir = dparent->d_inode;
        LASSERT(dir);

        ldlm_lock_dump_handle(D_OTHER, lockh);

        /* get parent id: ldlm lock on the parent protects ea */
        rc = mds_read_inode_sid(obd, dir, &sid);
        if (rc) {
                CERROR("can't read parent id. ino(%lu) rc(%d)\n",
                       dir->i_ino, rc);
                GOTO(cleanup, rc);
        }

        /* try to retrieve MEA data for this dir */
        rc = mds_md_get_attr(obd, dparent->d_inode, &mea, &mea_size);
        if (rc)
                GOTO(cleanup, rc);

        if (mea != NULL && mea->mea_count) {
                /*
                 * dir is already splitted, check is requested filename should
                 * live at this MDS or at another one.
                 */
                int i = mea_name2idx(mea, rec->ur_name, rec->ur_namelen - 1);
                if (mea->mea_master != id_group(&mea->mea_ids[i])) {
                        CDEBUG(D_OTHER, "inapropriate MDS(%d) for %lu/%u:%s."
                               " should be %lu(%d)\n",
                               mea->mea_master, dparent->d_inode->i_ino,
                               dparent->d_inode->i_generation, rec->ur_name,
                               (unsigned long)id_group(&mea->mea_ids[i]), i);
                        GOTO(cleanup, rc = -ERESTART);
                }
        }

        dchild = ll_lookup_one_len(rec->ur_name, dparent, 
                                   rec->ur_namelen - 1);
        if (IS_ERR(dchild)) {
                rc = PTR_ERR(dchild);
                CERROR("Can't find "DLID4"/%s, error %d\n",
                       OLID4(rec->ur_id1), rec->ur_name, rc);
                GOTO(cleanup, rc);
        }

        cleanup_phase = 2; /* child dentry */

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_CREATE_WRITE, dir->i_sb);

        if (type == S_IFREG || type == S_IFDIR) {
                rc = mds_try_to_split_dir(obd, dparent, &mea, 0, parent_mode);
                CDEBUG(D_OTHER, "%s: splitted %lu/%u - %d/%d\n",
                       obd->obd_name, dparent->d_inode->i_ino,
                       dparent->d_inode->i_generation, rc, parent_mode);
                if (rc > 0) {
                        /* dir got splitted */
                        GOTO(cleanup, rc = -ERESTART);
                } else if (rc < 0) {
                        /* error happened during spitting. */
                        GOTO(cleanup, rc);
                }
        }

        if (dir->i_mode & S_ISGID) {
                if (S_ISDIR(rec->ur_mode))
                        rec->ur_mode |= S_ISGID;
        }

        /* for reint case stor ecookie should be zero */
        if (rec->ur_flags & MDS_REINT_REQ) {
                LASSERT(id_ino(rec->ur_id1) == 0);
                LASSERT(id_ino(rec->ur_id2) == 0);
        }
        
        if (id_fid(rec->ur_id2))
                fid = id_fid(rec->ur_id2);
        else
                fid = mds_alloc_fid(obd);
        
        dchild->d_fsdata = (void *)&dp;
        dp.p_inum = (unsigned long)id_ino(rec->ur_id2);
        dp.p_ptr = req;

        dp.p_fid = fid;
        dp.p_group = mds->mds_num;

        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*body));

        switch (type) {
        case S_IFREG: {
                handle = fsfilt_start(obd, dir, FSFILT_OP_CREATE, NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                rc = ll_vfs_create(dir, dchild, rec->ur_mode, NULL);
                
                /* XXX: here we should check what type of EA is in ur_eadata 
                 * and do appropriate actions. --umka */
                if (rec->ur_eadata && rec->ur_eadatalen && 
                    rc == 0 && dchild->d_inode != NULL) {
                    if (rec->ur_flags & MDS_REINT_REQ) {
                        /* for CMOBD to set lov md info when cmobd reint
                         * create */
                        CDEBUG(D_INFO, "set lsm %p, len %d to inode %lu \n", 
                               rec->ur_eadata, rec->ur_eadatalen, 
                               dchild->d_inode->i_ino); 
                        rc = fsfilt_set_md(obd, dchild->d_inode, handle,
                                           rec->ur_eadata, rec->ur_eadatalen,
                                           EA_LOV);
                        if (rc) {
                                CERROR("fsfilt_set_md() failed, err %d\n",
                                       rc);
                                GOTO(cleanup, rc);
                        }
                    } else {
                        /* assumption: when ur_eadata is not NULL, 
                         * ur_eadata is crypto key, should fix it later, 
                         * --wangdi */
                        rc = mds_set_gskey(obd, handle, dchild->d_inode, 
                                           rec->ur_eadata, rec->ur_eadatalen, 
                                           ATTR_MAC | ATTR_KEY);
                        if (rc) {
                                CWARN("mds_set_gskey() failed, err %d\n",
                                      rc);
                        }
                    }
                }
                break;
        }
        case S_IFDIR: {
                int i;
                
                /*
                 * as Peter asked, mkdir() should distribute new directories
                 * over the whole cluster in order to distribute namespace
                 * processing load. first, we calculate which MDS to use to put
                 * new directory's inode in.
                 */

                /* XXX: here we order mds_choose_mdsnum() to use local mdsnum
                 * for reint requests. This should be gone when real flushing on
                 * LMV is fixed. --umka */
                i = mds_choose_mdsnum(obd, rec->ur_name, rec->ur_namelen - 1, 
                                      rec->ur_flags, &req->rq_peer, dir,
                                      (rec->ur_flags & MDS_REINT_REQ) ? 1 : 0);
                
                if (i == mds->mds_num) {
                        /* inode will be created locally */
                        handle = fsfilt_start(obd, dir, FSFILT_OP_MKDIR, NULL);
                        if (IS_ERR(handle))
                                GOTO(cleanup, rc = PTR_ERR(handle));

                        rc = vfs_mkdir(dir, dchild, rec->ur_mode);
                        if (rc) {
                                CDEBUG(D_OTHER,
                                       "Can't create dir \"%s\", rc = %d\n",
                                       dchild->d_name.name, rc);
                                GOTO(cleanup, rc);
                        }

                } else if (!DENTRY_VALID(dchild)) {
                        /* inode will be created on another MDS */
                        struct obdo *oa = NULL;
                        void *acl = NULL;
                        int acl_size;

                        /* first, create that inode */
                        oa = obdo_alloc();
                        if (!oa)
                                GOTO(cleanup, rc = -ENOMEM);

                        oa->o_mds = i;
                        oa->o_easize = 0;

                        if (rec->ur_eadata) {
                                /* user asks for creating splitted dir */
                                oa->o_easize = *((u16 *) rec->ur_eadata);
                        }

                        obdo_from_inode(oa, dir, OBD_MD_FLATIME |
                                        OBD_MD_FLMTIME | OBD_MD_FLCTIME);

                        /* adjust the uid/gid/mode bits */
                        oa->o_mode = rec->ur_mode;
                        oa->o_uid = current->fsuid;
                        oa->o_gid = (dir->i_mode & S_ISGID) ?
                                     dir->i_gid : current->fsgid;

                        /* letting remote MDS know that this is reint
                         * request. */
                        if (rec->ur_flags & MDS_REINT_REQ)
                                oa->o_flags |= OBD_FL_REINT;

                        /* transfer parent id to remote inode */
                        memcpy(obdo_id(oa), &sid, sizeof(sid));
                        oa->o_valid |= OBD_MD_FLTYPE | OBD_MD_FLUID | 
                                       OBD_MD_FLGID | OBD_MD_FLIFID;
                                                
                        CDEBUG(D_OTHER, "%s: create dir on MDS %u\n",
                               obd->obd_name, i);

                        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                                /*
                                 * here inode number and generation are
                                 * important, as this is replay request and we
                                 * need them to check if such an object is
                                 * already created.
                                 */
                                CDEBUG(D_HA, "%s: replay dir creation %*s -> %u/%u\n",
                                       obd->obd_name, rec->ur_namelen - 1,
                                       rec->ur_name, (unsigned)id_ino(rec->ur_id2),
                                       (unsigned)id_gen(rec->ur_id2));
                                oa->o_id = id_ino(rec->ur_id2);
                                oa->o_fid = id_fid(rec->ur_id2);
                                oa->o_generation = id_gen(rec->ur_id2);
                                oa->o_flags |= OBD_FL_RECREATE_OBJS;
                                LASSERT(oa->o_fid != 0);
                        }

                        /* obtain default ACL */
                        acl_size = mds_get_default_acl(dir, &acl);
                        if (acl_size < 0) {
                                obdo_free(oa);
                                GOTO(cleanup, rc = -ENOMEM);
                        }

                        /* 
                         * before obd_create() is called, o_fid is not known if
                         * this is not recovery of cause.
                         */
                        rc = obd_create(mds->mds_md_exp, oa, acl, acl_size,
                                        NULL, NULL);

                        if (acl)
                                OBD_FREE(acl, acl_size);

                        if (rc) {
                                CERROR("can't create remote inode: %d\n", rc);
                                DEBUG_REQ(D_ERROR, req, "parent "LPU64"/%u name %s mode %o",
                                          id_ino(rec->ur_id1), id_gen(rec->ur_id1),
                                          rec->ur_name, rec->ur_mode);
                                obdo_free(oa);
                                GOTO(cleanup, rc);
                        }

                        LASSERT(oa->o_fid != 0);
                        
                        /* now, add new dir entry for it */
                        handle = fsfilt_start(obd, dir, FSFILT_OP_MKDIR, NULL);
                        if (IS_ERR(handle)) {
	                        obdo_free(oa);
                                GOTO(cleanup, rc = PTR_ERR(handle));
                        }

                        /* creating local dentry for remote inode. */
                        rc = fsfilt_add_dir_entry(obd, dparent, rec->ur_name,
                                                  rec->ur_namelen - 1, oa->o_id,
                                                  oa->o_generation, i, oa->o_fid);

                        if (rc) {
                                CERROR("Can't create local entry %*s for "
                                       "remote inode.\n", rec->ur_namelen - 1,
                                        rec->ur_name);
                                GOTO(cleanup, rc);
                        }

                        /* fill reply */
                        body->valid |= OBD_MD_FLID | OBD_MD_MDS | OBD_MD_FID;

                        obdo2id(&body->id1, oa);
	                obdo_free(oa);
                } else {
                        /* requested name exists in the directory */
                        rc = -EEXIST;
                }
                break;
        }
        case S_IFLNK:{
                handle = fsfilt_start(obd, dir, FSFILT_OP_SYMLINK, NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                if (rec->ur_tgt == NULL)        /* no target supplied */
                        rc = -EINVAL;           /* -EPROTO? */
                else
                        rc = ll_vfs_symlink(dir, dchild, rec->ur_tgt, S_IALLUGO);
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
                break;
        }
        default:
                CERROR("bad file type %o creating %s\n", type, rec->ur_name);
                dchild->d_fsdata = NULL;
                GOTO(cleanup, rc = -EINVAL);
        }

        /* In case we stored the desired inum in here, we want to clean up. */
        if (dchild->d_fsdata == (void *)(unsigned long)id_ino(rec->ur_id2))
                dchild->d_fsdata = NULL;

        if (rc) {
                CDEBUG(D_INODE, "error during create: %d\n", rc);
                GOTO(cleanup, rc);
        } else if (dchild->d_inode) {
                struct mds_export_data *med = &req->rq_export->u.eu_mds_data;
                struct inode *inode = dchild->d_inode;
                struct iattr iattr;

                created = 1;
                iattr.ia_uid = rec->ur_fsuid;
                LTIME_S(iattr.ia_atime) = rec->ur_time;
                LTIME_S(iattr.ia_ctime) = rec->ur_time;
                LTIME_S(iattr.ia_mtime) = rec->ur_time;

                if (dir->i_mode & S_ISGID)
                        iattr.ia_gid = dir->i_gid;
                else
                        iattr.ia_gid = rec->ur_fsgid;

                iattr.ia_valid = ATTR_UID | ATTR_GID | ATTR_ATIME |
                        ATTR_MTIME | ATTR_CTIME;

                if (id_ino(rec->ur_id2)) {
                        LASSERT(id_ino(rec->ur_id2) == inode->i_ino);
                        inode->i_generation = id_gen(rec->ur_id2);
                        /* dirtied and committed by the upcoming setattr. */
                        CDEBUG(D_INODE, "recreated ino %lu with gen %u\n",
                               inode->i_ino, inode->i_generation);
                }
                mds_inode2id(obd, &body->id1, dchild->d_inode, fid);
                mds_update_inode_ids(obd, inode, handle, &body->id1, &sid);

                rc = fsfilt_setattr(obd, dchild, handle, &iattr, 0);
                if (rc)
                        CERROR("error on child setattr: rc = %d\n", rc);

                iattr.ia_valid = ATTR_MTIME | ATTR_CTIME;
                rc = fsfilt_setattr(obd, dparent, handle, &iattr, 0);
                if (rc)
                        CERROR("error on parent setattr: rc = %d\n", rc);
                else
                        MD_COUNTER_INCREMENT(obd, create);

                /* take care of default stripe inheritance */
                if (type == S_IFDIR) {
                        struct lov_mds_md lmm;
                        int lmm_size = sizeof(lmm), nstripes = 0;

                        rc = mds_get_md(obd, dir, &lmm, &lmm_size, 1, 0);
                        if (rc > 0) {
                                down(&inode->i_sem);
                                rc = fsfilt_set_md(obd, inode, handle, 
                                                   &lmm, lmm_size, EA_LOV);
                                up(&inode->i_sem);
                        }
                        if (rc) {
                                CERROR("error on copy stripe info: rc = %d\n", 
                                       rc);
                                rc = 0;
                        }
                        
                        if (rec->ur_eadata)
                                nstripes = *(u16 *)rec->ur_eadata;
                        
                        if (nstripes) {
                                /*
                                 * we pass LCK_EX to split routine to signal,
                                 * that we have exclusive access to the
                                 * directory. Simple because nobody knows it
                                 * already exists -bzzz
                                 */
                                rc = mds_try_to_split_dir(obd, dchild,
                                                          NULL, nstripes,
                                                          LCK_EX);
                                if (rc > 0) {
                                        /* dir got splitted */
                                        rc = 0;
                                } else if (rc < 0) {
                                        /* an error occured during
                                         * splitting. */
                                        GOTO(cleanup, rc);
                                }
                        }

                }
                
                mds_pack_inode2body(obd, body, inode, 1);
                mds_body_do_reverse_map(med, body);

                if (rec->ur_flags & MDS_REINT_REQ) {
                        LASSERT(body != NULL);
                        rc = mds_fidmap_add(obd, &body->id1);
                        if (rc < 0) {
                                CERROR("can't create fid->ino mapping, "
                                       "err %d\n", rc);
                        } else {
                                rc = 0;
                        }
                }
        }

        EXIT;
cleanup:
        err = mds_finish_transno(mds, dir, handle, req, rc, 0);

        if (rc && created) {
                /* Destroy the file we just created. This should not need extra
                 * journal credits, as we have already modified all of the
                 * blocks needed in order to create the file in the first
                 * place. */
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
        } else if (created) {
                /* The inode we were allocated may have just been freed
                 * by an unlink operation.  We take this lock to
                 * synchronize against the matching reply-ack-lock taken
                 * in unlink, to avoid replay problems if this reply
                 * makes it out to the client but the unlink's does not.
                 * See bug 2029 for more detail.*/
                mds_lock_new_child(obd, dchild->d_inode, NULL);
        } else {
                rc = err;
        }
        switch (cleanup_phase) {
        case 2: /* child dentry */
                l_dput(dchild);
        case 1: /* locked parent dentry */
#ifdef S_PDIROPS
                if (lockh[1].cookie != 0)
                        ldlm_lock_decref(lockh + 1, parent_mode);
#endif
                if (rc) {
                        ldlm_lock_decref(lockh, LCK_PW);
                } else {
                        ptlrpc_save_lock(req, lockh, LCK_PW);
                }
                l_dput(dparent);
        case 0:
                break;
        default:
                CERROR("invalid cleanup_phase %d\n", cleanup_phase);
                LBUG();
        }
        if (mea)
                OBD_FREE(mea, mea_size);
        req->rq_status = rc;
        return 0;
}

static inline int
res_gt(struct ldlm_res_id *res1, struct ldlm_res_id *res2,
       ldlm_policy_data_t *p1, ldlm_policy_data_t *p2)
{
        int i;

        for (i = 0; i < RES_NAME_SIZE; i++) {
                /* 
                 * this is needed to make zeroed res_id entries to be put at the
                 * end of list in *ordered_locks() .
                 */
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
        int lock_modes[2] = { p1_lock_mode, p2_lock_mode };
        struct ldlm_res_id *res_id[2] = { p1_res_id, p2_res_id };
        struct lustre_handle *handles[2] = { p1_lockh, p2_lockh };
        ldlm_policy_data_t *policies[2] = { p1_policy, p2_policy };
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
        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, *res_id[0],
                              LDLM_IBITS, policies[0], lock_modes[0], &flags,
                              mds_blocking_ast, ldlm_completion_ast, NULL, NULL,
                              NULL, 0, NULL, handles[0]);
        if (rc != ELDLM_OK)
                RETURN(-EIO);
        ldlm_lock_dump_handle(D_OTHER, handles[0]);

        if (!memcmp(res_id[0], res_id[1], sizeof(*res_id[0])) &&
            (policies[0]->l_inodebits.bits & policies[1]->l_inodebits.bits)) {
                memcpy(handles[1], handles[0], sizeof(*(handles[1])));
                ldlm_lock_addref(handles[1], lock_modes[1]);
        } else if (res_id[1]->name[0] != 0) {
                flags = LDLM_FL_LOCAL_ONLY | LDLM_FL_ATOMIC_CB;
                rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace,
                                      *res_id[1], LDLM_IBITS, policies[1],
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
        ldlm_policy_data_t *policies[5] = { p1_policy, p2_policy,
                                            c1_policy, c2_policy};
        int rc, i, j, sorted, flags;
        ENTRY;

        CDEBUG(D_DLMTRACE, "locks before: "LPU64"/"LPU64"/"LPU64"/"LPU64"\n",
               res_id[0]->name[0], res_id[1]->name[0], res_id[2]->name[0],
               res_id[3]->name[0]);

        /* 
         * simple insertion sort - we have at most 4 elements. Note, that zeroed
         * res_id should be at the end of list after sorting is finished.
         */
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

                /* 
                 * nevertheless zeroed res_ids should be at the end of list, and
                 * could use break here, I think, that it is more correctly for
                 * clear understanding of code to have continue here, as it
                 * clearly means, that zeroed res_id should be skipped and does
                 * not mean, that if we meet zeroed res_id we should stop
                 * locking loop.
                 */
                if (res_id[i]->name[0] == 0)
                        continue;
                
                if (i != 0 &&
                    !memcmp(res_id[i], res_id[i-1], sizeof(*res_id[i])) &&
                    (policies[i]->l_inodebits.bits &
                     policies[i-1]->l_inodebits.bits) ) {
                        memcpy(dlm_handles[i], dlm_handles[i-1],
                               sizeof(*(dlm_handles[i])));
                        ldlm_lock_addref(dlm_handles[i], lock_modes[i]);
                } else {
                        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace,
                                              *res_id[i], LDLM_IBITS,
                                              policies[i],
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
                            ldlm_policy_data_t *child_policy,
                            const char *name, int namelen,
                            struct ldlm_res_id *maxres,
			    unsigned long child_ino, __u32 child_gen)
{
        struct lustre_id sid;
        struct dentry *vchild, *dchild = *dchildp;
        int rc = 0, cleanup_phase = 2; /* parent, child locks */
        ENTRY;

        vchild = ll_lookup_one_len(name, dparent, namelen - 1);
        if (IS_ERR(vchild))
                GOTO(cleanup, rc = PTR_ERR(vchild));

        if ((vchild->d_flags & DCACHE_CROSS_REF)) {
                if (child_gen == vchild->d_generation &&
                    child_ino == vchild->d_inum) {
                        if (dchild)
                                l_dput(dchild);
                        *dchildp = vchild;
                        RETURN(0);
                }
                goto changed;
        }

        if (likely((vchild->d_inode == NULL && child_res_id->name[0] == 0) ||
                   (vchild->d_inode != NULL &&
                    child_gen == vchild->d_inode->i_generation &&
                    child_ino == vchild->d_inode->i_ino))) {
                if (dchild)
                        l_dput(dchild);
                *dchildp = vchild;
                RETURN(0);
        }

changed:
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

        if (dchild->d_inode || (dchild->d_flags & DCACHE_CROSS_REF)) {
                int flags = LDLM_FL_ATOMIC_CB;
                
                if (dchild->d_inode) {
                        down(&dchild->d_inode->i_sem);
                        rc = mds_read_inode_sid(obd, dchild->d_inode, &sid);
                        up(&dchild->d_inode->i_sem);
                        if (rc) {
                                CERROR("Can't read inode self id, inode %lu,"
                                       " rc %d\n",  dchild->d_inode->i_ino, rc);
                                GOTO(cleanup, rc);
                        }
                        child_res_id->name[0] = id_fid(&sid);
                        child_res_id->name[1] = id_group(&sid);
                } else {
                        child_res_id->name[0] = dchild->d_fid;
                        child_res_id->name[1] = dchild->d_mdsnum;
                }

                if (res_gt(parent_res_id, child_res_id, NULL, NULL) ||
                    res_gt(maxres, child_res_id, NULL, NULL)) {
                        CDEBUG(D_DLMTRACE, "relock "LPU64"<("LPU64"|"LPU64")\n",
                               child_res_id->name[0], parent_res_id->name[0],
                               maxres->name[0]);
                        GOTO(cleanup, rc = 1);
                }

                rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace,
                                      *child_res_id, LDLM_IBITS, child_policy,
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
                                struct lustre_id *id,
                                struct lustre_handle *parent_lockh,
                                struct dentry **dparentp, int parent_mode,
                                __u64 parent_lockpart, int *update_mode,
                                char *name, int namelen,
                                struct lustre_handle *child_lockh,
                                struct dentry **dchildp, int child_mode,
                                __u64 child_lockpart)
{
        ldlm_policy_data_t parent_policy = {.l_inodebits = { parent_lockpart }};
        ldlm_policy_data_t child_policy = {.l_inodebits = { child_lockpart }};
        struct ldlm_res_id parent_res_id = { .name = {0} };
        struct ldlm_res_id child_res_id = { .name = {0} };
	unsigned long child_ino = 0; __u32 child_gen = 0;
        int rc = 0, cleanup_phase = 0;
        struct lustre_id sid;
        struct inode *inode;
        ENTRY;

        /* Step 1: Lookup parent */
        *dparentp = mds_id2dentry(obd, id, NULL);
        if (IS_ERR(*dparentp)) {
                rc = PTR_ERR(*dparentp);
                *dparentp = NULL;
                RETURN(rc);
        }

        CDEBUG(D_INODE, "parent ino %lu, name %s\n",
               (*dparentp)->d_inode->i_ino, name);

        parent_res_id.name[0] = id_fid(id);
        parent_res_id.name[1] = id_group(id);
        
#ifdef S_PDIROPS
        parent_lockh[1].cookie = 0;
        if (name && IS_PDIROPS((*dparentp)->d_inode)) {
                struct ldlm_res_id res_id = { .name = {0} };
                ldlm_policy_data_t policy;
                int flags = LDLM_FL_ATOMIC_CB;

                *update_mode = mds_lock_mode_for_dir(obd, *dparentp, parent_mode);
                if (*update_mode) {
                        res_id.name[0] = id_fid(id);
                        res_id.name[1] = id_group(id);
                        policy.l_inodebits.bits = MDS_INODELOCK_UPDATE;

                        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace,
                                              res_id, LDLM_IBITS, &policy,
                                              *update_mode, &flags,
                                              mds_blocking_ast,
                                              ldlm_completion_ast,
                                              NULL, NULL, NULL, 0, NULL,
                                              parent_lockh + 1);
                        if (rc != ELDLM_OK)
                                RETURN(-ENOLCK);
                }

                parent_res_id.name[2] = full_name_hash((unsigned char *)name,
                                                       namelen - 1);
                
                CDEBUG(D_INFO, "take lock on %lu:%lu:"LPX64"\n",
                       (unsigned long)id_fid(id), (unsigned long)id_group(id),
                       parent_res_id.name[2]);
        }
#endif

        cleanup_phase = 1; /* parent dentry */

        /* Step 2: Lookup child (without DLM lock, to get resource name) */
        *dchildp = ll_lookup_one_len(name, *dparentp, namelen - 1);
        if (IS_ERR(*dchildp)) {
                rc = PTR_ERR(*dchildp);
                CDEBUG(D_INODE, "child lookup error %d\n", rc);
                GOTO(cleanup, rc);
        }

        if ((*dchildp)->d_flags & DCACHE_CROSS_REF) {
                /*
                 * inode lives on another MDS: return * fid/mdsnum and LOOKUP
                 * lock. Drop possible UPDATE lock!
                 */
                child_policy.l_inodebits.bits &= ~MDS_INODELOCK_UPDATE;
                child_policy.l_inodebits.bits |= MDS_INODELOCK_LOOKUP;

                child_res_id.name[0] = (*dchildp)->d_fid;
                child_res_id.name[1] = (*dchildp)->d_mdsnum;
		child_ino = (*dchildp)->d_inum;
		child_gen = (*dchildp)->d_generation;
                goto retry_locks;
        }

        inode = (*dchildp)->d_inode;
        if (inode != NULL)
                inode = igrab(inode);
        if (inode == NULL)
                goto retry_locks;

        down(&inode->i_sem);
        rc = mds_read_inode_sid(obd, inode, &sid);
        up(&inode->i_sem);
        if (rc) {
                CERROR("Can't read inode self id, inode %lu, "
                       "rc %d\n", inode->i_ino, rc);
                iput(inode);
                GOTO(cleanup, rc);
        }
        
	child_ino = inode->i_ino;
	child_gen = inode->i_generation;
        child_res_id.name[0] = id_fid(&sid);
        child_res_id.name[1] = id_group(&sid);
        iput(inode);

retry_locks:
        cleanup_phase = 2; /* child dentry */

        /* Step 3: Lock parent and child in resource order.  If child doesn't
         * exist, we still have to lock the parent and re-lookup. */
        rc = enqueue_ordered_locks(obd, &parent_res_id, parent_lockh, parent_mode,
                                   &parent_policy, &child_res_id, child_lockh,
                                   child_mode, &child_policy);
        if (rc)
                GOTO(cleanup, rc);

        if ((*dchildp)->d_inode || ((*dchildp)->d_flags & DCACHE_CROSS_REF))
                cleanup_phase = 4; /* child lock */
        else
                cleanup_phase = 3; /* parent lock */

        /* Step 4: Re-lookup child to verify it hasn't changed since locking */
        rc = mds_verify_child(obd, &parent_res_id, parent_lockh, *dparentp,
                              parent_mode, &child_res_id, child_lockh, 
                              dchildp, child_mode, &child_policy,
                              name, namelen, &parent_res_id, child_ino, 
			      child_gen);
        if (rc > 0)
                goto retry_locks;
        if (rc < 0) {
                cleanup_phase = 3;
                GOTO(cleanup, rc);
        }

        EXIT;
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
#ifdef S_PDIROPS
                        if (parent_lockh[1].cookie)
                                ldlm_lock_decref(parent_lockh + 1, *update_mode);
#endif
                        l_dput(*dparentp);
                }
        }
        return rc;
}

void mds_reconstruct_generic(struct ptlrpc_request *req)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        mds_req_from_mcd(req, med->med_mcd);
}

/* If we are unlinking an open file/dir (i.e. creating an orphan) then we
 * instead link the inode into the PENDING directory until it is finally
 * released. We can't simply call mds_reint_rename() or some part thereof,
 * because we don't have the inode to check for link count/open status until
 * after it is locked.
 *
 * For lock ordering, caller must get child->i_sem first, then pending->i_sem
 * before starting journal transaction.
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
        char idname[LL_ID_NAMELEN];
        int idlen = 0, rc, mode;
        ENTRY;

        LASSERT(inode != NULL);
        LASSERT(!mds_inode_is_orphan(inode));
#ifndef HAVE_I_ALLOC_SEM
        LASSERT(down_trylock(&inode->i_sem) != 0);
#endif
        LASSERT(down_trylock(&pending_dir->i_sem) != 0);

        idlen = ll_id2str(idname, inode->i_ino, inode->i_generation);

        CDEBUG(D_INODE, "pending destroy of %dx open %d linked %s %s = %s\n",
               mds_orphan_open_count(inode), inode->i_nlink,
               S_ISDIR(inode->i_mode) ? "dir" :
               S_ISREG(inode->i_mode) ? "file" : "other",
               rec->ur_name, idname);

        if (mds_orphan_open_count(inode) == 0 || inode->i_nlink != 0)
                RETURN(0);

        pending_child = lookup_one_len(idname, mds->mds_pending_dir, idlen);
        if (IS_ERR(pending_child))
                RETURN(PTR_ERR(pending_child));

        if (pending_child->d_inode != NULL) {
                CERROR("re-destroying orphan file %s?\n", rec->ur_name);
                LASSERT(pending_child->d_inode == inode);
                GOTO(out_dput, rc = 0);
        }

        /*
         * link() is semanticaly-wrong for S_IFDIR, so we set S_IFREG for
         * linking and return real mode back then -bzzz
         */
        mode = inode->i_mode;
        inode->i_mode = S_IFREG;
        rc = vfs_link(dentry, pending_dir, pending_child);
        if (rc)
                CERROR("error linking orphan %s to PENDING: rc = %d\n",
                       rec->ur_name, rc);
        else
                mds_inode_set_orphan(inode);

        /* return mode and correct i_nlink if inode is directory */
        inode->i_mode = mode;
        LASSERTF(inode->i_nlink == 1, "%s nlink == %d\n",
                 S_ISDIR(mode) ? "dir" : S_ISREG(mode) ? "file" : "other",
                 inode->i_nlink);
        if (S_ISDIR(mode)) {
                i_nlink_inc(inode);
                i_nlink_inc(pending_dir);
                mark_inode_dirty(inode);
                mark_inode_dirty(pending_dir);
        }

        GOTO(out_dput, rc = 1);
out_dput:
        l_dput(pending_child);
        return rc;
}

int mds_create_local_dentry(struct mds_update_record *rec,
                            struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct inode *id_dir = mds->mds_id_dir->d_inode;
        int idlen = 0, rc, cleanup_phase = 0;
        struct dentry *new_child = NULL;
        char *idname = rec->ur_name;
        struct dentry *child = NULL;
        struct lustre_handle lockh[2] = {{0}, {0}};
        struct lustre_id sid;
        void *handle;
        ENTRY;

        down(&id_dir->i_sem);
        idlen = ll_id2str(idname, id_ino(rec->ur_id1),
                          id_gen(rec->ur_id1));
        
        CDEBUG(D_OTHER, "look for local dentry '%s' for "DLID4"\n",
               idname, OLID4(rec->ur_id1));

        new_child = ll_lookup_one_len(idname, mds->mds_id_dir, 
                                      idlen);
        up(&id_dir->i_sem);
        if (IS_ERR(new_child)) {
                CERROR("can't lookup %s: %d\n", idname,
                       (int) PTR_ERR(new_child));
                GOTO(cleanup, rc = PTR_ERR(new_child));
        }
        cleanup_phase = 1;

        down(&id_dir->i_sem);
        rc = mds_read_inode_sid(obd, id_dir, &sid);
        up(&id_dir->i_sem);
        if (rc) {
                CERROR("Can't read inode self id, inode %lu, "
                       "rc %d\n", id_dir->i_ino, rc);
                GOTO(cleanup, rc);
        }
        
        if (new_child->d_inode != NULL) {
                /* nice. we've already have local dentry! */
                CDEBUG(D_OTHER, "found dentry in FIDS/: %u/%u\n", 
                       (unsigned)new_child->d_inode->i_ino,
                       (unsigned)new_child->d_inode->i_generation);
                
                id_ino(rec->ur_id1) = id_dir->i_ino;
                id_gen(rec->ur_id1) = id_dir->i_generation;
                rec->ur_namelen = idlen + 1;

                id_fid(rec->ur_id1) = id_fid(&sid);
                id_group(rec->ur_id1) = id_group(&sid);
                
                GOTO(cleanup, rc = 0);
        }

        /* new, local dentry will be added soon. we need no aliases here */
        d_drop(new_child);

        if (rec->ur_mode & MDS_MODE_DONT_LOCK) {
                child = mds_id2dentry(obd, rec->ur_id1, NULL);
        } else {
                child = mds_id2locked_dentry(obd, rec->ur_id1, NULL,
                                             LCK_EX, lockh, NULL, NULL, 0,
                                             MDS_INODELOCK_UPDATE);
        }

        if (IS_ERR(child)) {
                rc = PTR_ERR(child);
                if (rc != -ENOENT || !(rec->ur_mode & MDS_MODE_REPLAY))
                        CERROR("can't get victim: %d\n", rc);
                GOTO(cleanup, rc);
        }
        cleanup_phase = 2;

        handle = fsfilt_start(obd, id_dir, FSFILT_OP_LINK, NULL);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));

        rc = fsfilt_add_dir_entry(obd, mds->mds_id_dir, idname,
                                  idlen, id_ino(rec->ur_id1),
                                  id_gen(rec->ur_id1), mds->mds_num,
                                  id_fid(rec->ur_id1));
        if (rc)
                CERROR("error linking orphan %lu/%lu to FIDS: rc = %d\n",
                       (unsigned long)child->d_inode->i_ino,
                       (unsigned long)child->d_inode->i_generation, rc);
        else {
                if (S_ISDIR(child->d_inode->i_mode)) {
                        i_nlink_inc(id_dir);
                        mark_inode_dirty(id_dir);
                }
                mark_inode_dirty(child->d_inode);
        }
        fsfilt_commit(obd, mds->mds_sb, id_dir, handle, 0);

        id_ino(rec->ur_id1) = id_dir->i_ino;
        id_gen(rec->ur_id1) = id_dir->i_generation;
        rec->ur_namelen = idlen + 1;

        id_fid(rec->ur_id1) = id_fid(&sid);
        id_group(rec->ur_id1) = id_group(&sid);

        EXIT;
cleanup:
        switch(cleanup_phase) {
                case 2:
                        if (!(rec->ur_mode & MDS_MODE_DONT_LOCK))
                                ldlm_lock_decref(lockh, LCK_EX);
                        dput(child);
                case 1:
                        dput(new_child);
                case 0:
                       break; 
        }
        return rc;
}

static int mds_copy_unlink_reply(struct ptlrpc_request *master,
                                 struct ptlrpc_request *slave)
{
        void *cookie, *cookie2;
        struct mds_body *body2;
        struct mds_body *body;
        void *ea, *ea2;
        ENTRY;

        body = lustre_msg_buf(slave->rq_repmsg, 0, sizeof(*body));
        LASSERT(body != NULL);

        body2 = lustre_msg_buf(master->rq_repmsg, 0, sizeof (*body));
        LASSERT(body2 != NULL);

        if (!(body->valid & (OBD_MD_FLID | OBD_MD_FLGENER)))
                RETURN(0);

        memcpy(body2, body, sizeof(*body));
        body2->valid &= ~OBD_MD_FLCOOKIE;

        if (!(body->valid & OBD_MD_FLEASIZE) &&
            !(body->valid & OBD_MD_FLDIREA))
                RETURN(0);

        if (body->eadatasize == 0) {
                CERROR("OBD_MD_FLEASIZE set but eadatasize zero\n");
                RETURN(0);
        }

        LASSERT(master->rq_repmsg->buflens[1] >= body->eadatasize);
        
        ea = lustre_msg_buf(slave->rq_repmsg, 1, body->eadatasize);
        LASSERT(ea != NULL);
        
        ea2 = lustre_msg_buf(master->rq_repmsg, 1, body->eadatasize);
        LASSERT(ea2 != NULL);

        memcpy(ea2, ea, body->eadatasize);

        if (body->valid & OBD_MD_FLCOOKIE) {
                LASSERT(master->rq_repmsg->buflens[2] >=
                                slave->rq_repmsg->buflens[2]);
                cookie = lustre_msg_buf(slave->rq_repmsg, 2,
                                slave->rq_repmsg->buflens[2]);
                LASSERT(cookie != NULL);

                cookie2 = lustre_msg_buf(master->rq_repmsg, 2,
                                master->rq_repmsg->buflens[2]);
                LASSERT(cookie2 != NULL);
                memcpy(cookie2, cookie, slave->rq_repmsg->buflens[2]);
                body2->valid |= OBD_MD_FLCOOKIE;
        }
        RETURN(0);
}

static int mds_reint_unlink_remote(struct mds_update_record *rec,
                                   int offset, struct ptlrpc_request *req,
                                   struct lustre_handle *parent_lockh,
                                   int update_mode, struct dentry *dparent,
                                   struct lustre_handle *child_lockh,
                                   struct dentry *dchild)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_obd *mds = mds_req2mds(req);
        struct ptlrpc_request *request = NULL;
        int rc = 0, cleanup_phase = 0;
        struct mdc_op_data *op_data;
        void *handle;
        ENTRY;

        LASSERT(offset == 1 || offset == 3);

        /* time to drop i_nlink on remote MDS */
        OBD_ALLOC(op_data, sizeof(*op_data));
        if (op_data == NULL)
                RETURN(-ENOMEM);
        
        memset(op_data, 0, sizeof(*op_data));
        mds_pack_dentry2id(obd, &op_data->id1, dchild, 1);
        op_data->create_mode = rec->ur_mode;

        DEBUG_REQ(D_INODE, req, "unlink %*s (remote inode "DLID4")",
                  rec->ur_namelen - 1, rec->ur_name, OLID4(&op_data->id1));
        
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                DEBUG_REQ(D_HA, req, "unlink %*s (remote inode "DLID4")",
                          rec->ur_namelen - 1, rec->ur_name, OLID4(&op_data->id1));
        }

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY)
                op_data->create_mode |= MDS_MODE_REPLAY;
        
        rc = md_unlink(mds->mds_md_exp, op_data, &request);
        OBD_FREE(op_data, sizeof(*op_data));
        cleanup_phase = 2;

        if (request) {
                if (rc == 0)
                        mds_copy_unlink_reply(req, request);
                ptlrpc_req_finished(request);
        }

        if (rc == 0) {
                handle = fsfilt_start(obd, dparent->d_inode, FSFILT_OP_RMDIR,
                                      NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                rc = fsfilt_del_dir_entry(req->rq_export->exp_obd, dchild);
                rc = mds_finish_transno(mds, dparent->d_inode, handle, req,
                                        rc, 0);
        }
        EXIT;
cleanup:
        req->rq_status = rc;

#ifdef S_PDIROPS
        if (parent_lockh[1].cookie != 0)
                ldlm_lock_decref(parent_lockh + 1, update_mode);
#endif
        ldlm_lock_decref(child_lockh, LCK_EX);
        if (rc)
                ldlm_lock_decref(parent_lockh, LCK_PW);
        else
                ptlrpc_save_lock(req, parent_lockh, LCK_PW);
        l_dput(dchild);
        l_dput(dparent);

        return 0;
}

static int mds_reint_unlink(struct mds_update_record *rec, int offset,
                            struct ptlrpc_request *req, struct lustre_handle *lh)
{
        struct dentry *dparent = NULL, *dchild;
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_body *body = NULL;
        struct inode *child_inode = NULL;
        struct lustre_handle parent_lockh[2] = {{0}, {0}}; 
        struct lustre_handle child_lockh = {0};
        struct lustre_handle child_reuse_lockh = {0};
        struct lustre_handle *slave_lockh = NULL;
        char idname[LL_ID_NAMELEN];
        struct llog_create_locks *lcl = NULL;
        void *handle = NULL;
        int rc = 0, cleanup_phase = 0;
        int unlink_by_id = 0;
        int update_mode;
        ENTRY;

        LASSERT(offset == 1 || offset == 3);

        DEBUG_REQ(D_INODE, req, "parent ino "LPU64"/%u, child %s",
                  id_ino(rec->ur_id1), id_gen(rec->ur_id1),
                  rec->ur_name);

        MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                DEBUG_REQ(D_HA, req, "unlink replay");
                LASSERT(offset == 1); /* should not come from intent */
                memcpy(lustre_msg_buf(req->rq_repmsg, 2, 0),
                       lustre_msg_buf(req->rq_reqmsg, offset + 2, 0),
                       req->rq_repmsg->buflens[2]);
        }

        MD_COUNTER_INCREMENT(obd, unlink);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNLINK))
                GOTO(cleanup, rc = -ENOENT);

        if (rec->ur_namelen == 1) {
                /* this is request to drop i_nlink on local inode */
                unlink_by_id = 1;
                rec->ur_name = idname;
                rc = mds_create_local_dentry(rec, obd);
                if (rc == -ENOENT || (rec->ur_mode & MDS_MODE_REPLAY)) {
                        DEBUG_REQ(D_HA, req,
                                  "drop nlink on inode "DLID4" (replay)",
                                  OLID4(rec->ur_id1));
                        req->rq_status = 0;
                        RETURN(0);
                }
        }

        if (rec->ur_mode & MDS_MODE_DONT_LOCK) {
                /* master mds for directory asks slave removing inode is already
                 * locked */
                dparent = mds_id2locked_dentry(obd, rec->ur_id1, NULL,
                                               LCK_PW, parent_lockh,
                                               &update_mode, rec->ur_name,
                                               rec->ur_namelen,
                                               MDS_INODELOCK_UPDATE);
                if (IS_ERR(dparent))
                        GOTO(cleanup, rc = PTR_ERR(dparent));
                dchild = ll_lookup_one_len(rec->ur_name, dparent, 
                                           rec->ur_namelen - 1);
                if (IS_ERR(dchild))
                        GOTO(cleanup, rc = PTR_ERR(dchild));
                child_lockh.cookie = 0;
                LASSERT(!(dchild->d_flags & DCACHE_CROSS_REF));
                LASSERT(dchild->d_inode != NULL);
                LASSERT(S_ISDIR(dchild->d_inode->i_mode));
        } else {
                rc = mds_get_parent_child_locked(obd, mds, rec->ur_id1,
                                                 parent_lockh, &dparent,
                                                 LCK_PW, MDS_INODELOCK_UPDATE,
                                                 &update_mode, rec->ur_name,
                                                 rec->ur_namelen, &child_lockh,
                                                 &dchild, LCK_EX,
                                                 (MDS_INODELOCK_LOOKUP |
                                                  MDS_INODELOCK_UPDATE));
        }
        if (rc)
                GOTO(cleanup, rc);

        if (dchild->d_flags & DCACHE_CROSS_REF) {
                /* we should have parent lock only here */
                LASSERT(unlink_by_id == 0);
                LASSERT(dchild->d_mdsnum != mds->mds_num);
                mds_reint_unlink_remote(rec, offset, req, parent_lockh,
                                        update_mode, dparent, &child_lockh, dchild);
                RETURN(0);
        }

        cleanup_phase = 1; /* dchild, dparent, locks */

        dget(dchild);
        child_inode = dchild->d_inode;
        if (child_inode == NULL) {
                CDEBUG(D_INODE, "child doesn't exist (dir %lu, name %s)\n",
                       dparent ? dparent->d_inode->i_ino : 0, rec->ur_name);
                GOTO(cleanup, rc = -ENOENT);
        }

        cleanup_phase = 2; /* dchild has a lock */

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

        /* handle splitted dir */
        rc = mds_lock_slave_objs(obd, dchild, &slave_lockh);
        if (rc)
                GOTO(cleanup, rc);

        /* Step 4: Get a lock on the ino to sync with creation WRT inode
         * reuse (see bug 2029). */
        rc = mds_lock_new_child(obd, child_inode, &child_reuse_lockh);
        if (rc != ELDLM_OK)
                GOTO(cleanup, rc);
        cleanup_phase = 3; /* child inum lock */

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_UNLINK_WRITE, dparent->d_inode->i_sb);

        /* ldlm_reply in buf[0] if called via intent */
        if (offset == 3)
                offset = 1;
        else
                offset = 0;

        body = lustre_msg_buf(req->rq_repmsg, offset, sizeof (*body));
        LASSERT(body != NULL);

        /* child i_alloc_sem protects orphan_dec_test && is_orphan race */
        DOWN_READ_I_ALLOC_SEM(child_inode);
        cleanup_phase = 4; /* up(&child_inode->i_sem) when finished */

        /* If this is potentially the last reference to this inode, get the
         * OBD EA data first so the client can destroy OST objects.  We
         * only do the object removal later if no open files/links remain. */
        if ((S_ISDIR(child_inode->i_mode) && child_inode->i_nlink == 2) ||
            child_inode->i_nlink == 1) {
                if (mds_orphan_open_count(child_inode) > 0) {
                        /* need to lock pending_dir before transaction */
                        down(&mds->mds_pending_dir->d_inode->i_sem);
                        cleanup_phase = 5; /* up(&pending_dir->i_sem) */
                } else if (S_ISREG(child_inode->i_mode)) {
                        mds_pack_inode2body(obd, body, child_inode, 0);
                        mds_pack_md(obd, req->rq_repmsg, offset + 1,
                                    body, child_inode, MDS_PACK_MD_LOCK, 0);
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
                rc = vfs_rmdir(dparent->d_inode, dchild);
                break;
        case S_IFREG: {
#warning "optimization is possible here: we could drop nlink w/o removing local dentry in FIDS/"
                struct lov_mds_md *lmm = lustre_msg_buf(req->rq_repmsg,
                                                        offset + 1, 0);
                handle = fsfilt_start_log(obd, dparent->d_inode,
                                          FSFILT_OP_UNLINK, NULL,
                                          le32_to_cpu(lmm->lmm_stripe_count));
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                rc = vfs_unlink(dparent->d_inode, dchild);
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
                rc = vfs_unlink(dparent->d_inode, dchild);
                break;
        default:
                CERROR("bad file type %o unlinking %s\n", rec->ur_mode,
                       rec->ur_name);
                LBUG();
                GOTO(cleanup, rc = -EINVAL);
        }

        if (rc == 0 && child_inode->i_nlink == 0) {
                if (mds_orphan_open_count(child_inode) > 0)
                        rc = mds_orphan_add_link(rec, obd, dchild);

                if (rc == 1)
                        GOTO(cleanup, rc = 0);

                if (!S_ISREG(child_inode->i_mode))
                        GOTO(cleanup, rc);

                if (!(body->valid & OBD_MD_FLEASIZE)) {
                        body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                        OBD_MD_FLATIME | OBD_MD_FLMTIME);
                } else if (mds_log_op_unlink(obd, child_inode,
                                             lustre_msg_buf(req->rq_repmsg, offset + 1, 0),
                                             req->rq_repmsg->buflens[offset + 1],
                                             lustre_msg_buf(req->rq_repmsg, offset + 2, 0),
                                             req->rq_repmsg->buflens[offset + 2], 
                                             &lcl) > 0){
                        body->valid |= OBD_MD_FLCOOKIE;
                }
                
                rc = mds_destroy_object(obd, child_inode, 1);
                if (rc) {
                        CERROR("can't remove OST object, err %d\n",
                               rc);
                }

                if (child_inode->i_nlink == 0)
                        mds_fidmap_del(obd, &body->id1);
        }

        GOTO(cleanup, rc);

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
        rc = mds_finish_transno(mds, dparent ? dparent->d_inode : NULL,
                                handle, req, rc, 0);
        if (!rc)
                (void)obd_set_info(mds->mds_dt_exp, strlen("unlinked"),
                                   "unlinked", 0, NULL);
        switch(cleanup_phase) {
        case 5: /* pending_dir semaphore */
                up(&mds->mds_pending_dir->d_inode->i_sem);
        case 4: /* child inode semaphore */
                UP_READ_I_ALLOC_SEM(child_inode);
                 /* handle splitted dir */
                if (rc == 0) {
                        /* master directory can be non-empty or something else ... */
                        mds_unlink_slave_objs(obd, dchild);
                }
                if (lcl != NULL)
                        ptlrpc_save_llog_lock(req, lcl);
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
                mds_unlock_slave_objs(obd, dchild, slave_lockh);
                if (child_lockh.cookie)
                        ldlm_lock_decref(&child_lockh, LCK_EX);
        case 1: /* child and parent dentry, parent lock */
#ifdef S_PDIROPS
                if (parent_lockh[1].cookie != 0)
                        ldlm_lock_decref(parent_lockh + 1, update_mode);
#endif
                if (rc)
                        ldlm_lock_decref(parent_lockh, LCK_PW);
                else
                        ptlrpc_save_lock(req, parent_lockh, LCK_PW);
                if (dchild->d_inode && rc && (dchild->d_inode->i_nlink == 0 ||
                                mds_inode_is_orphan(dchild->d_inode)))
                        CDEBUG(D_ERROR, "unlink, but return %d\n", rc);
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
        return 0;
}

/*
 * to service requests from remote MDS to increment i_nlink
 */
static int mds_reint_link_acquire(struct mds_update_record *rec,
                                  int offset, struct ptlrpc_request *req,
                                  struct lustre_handle *lh)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct ldlm_res_id src_res_id = { .name = {0} };
        struct lustre_handle *handle = NULL, src_lockh = {0};
        struct mds_obd *mds = mds_req2mds(req);
        int rc = 0, cleanup_phase = 0;
        struct dentry *de_src = NULL;
        ldlm_policy_data_t policy;
        int flags = LDLM_FL_ATOMIC_CB;
        ENTRY;

        DEBUG_REQ(D_INODE, req, "%s: request to acquire i_nlinks "DLID4"\n",
                  obd->obd_name, OLID4(rec->ur_id1));

        /* Step 1: Lookup the source inode and target directory by ID */
        de_src = mds_id2dentry(obd, rec->ur_id1, NULL);
        if (IS_ERR(de_src))
                GOTO(cleanup, rc = PTR_ERR(de_src));
        cleanup_phase = 1; /* source dentry */

        src_res_id.name[0] = id_fid(rec->ur_id1);
        src_res_id.name[1] = id_group(rec->ur_id1);
        policy.l_inodebits.bits = MDS_INODELOCK_UPDATE;

        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace,
                              src_res_id, LDLM_IBITS, &policy,
                              LCK_EX, &flags, mds_blocking_ast,
                              ldlm_completion_ast, NULL, NULL,
                              NULL, 0, NULL, &src_lockh);
        if (rc != ELDLM_OK)
                GOTO(cleanup, rc = -ENOLCK);
        cleanup_phase = 2; /* lock */

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_LINK_WRITE, de_src->d_inode->i_sb);

        handle = fsfilt_start(obd, de_src->d_inode, FSFILT_OP_LINK, NULL);
        if (IS_ERR(handle)) {
                rc = PTR_ERR(handle);
                GOTO(cleanup, rc);
        }
        i_nlink_inc(de_src->d_inode);
        mark_inode_dirty(de_src->d_inode);

        EXIT;
cleanup:
        rc = mds_finish_transno(mds, de_src ? de_src->d_inode : NULL,
                                handle, req, rc, 0);
        switch (cleanup_phase) {
                case 2:
                        if (rc)
                                ldlm_lock_decref(&src_lockh, LCK_EX);
                        else
                                ptlrpc_save_lock(req, &src_lockh, LCK_EX);
                case 1:
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
 * request to link to foreign inode:
 *  - acquire i_nlinks on this inode
 *  - add dentry
 */
static int mds_reint_link_to_remote(struct mds_update_record *rec,
                                    int offset, struct ptlrpc_request *req,
                                    struct lustre_handle *lh)
{
        struct lustre_handle *handle = NULL, tgt_dir_lockh[2] = {{0}, {0}};
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *de_tgt_dir = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        int rc = 0, cleanup_phase = 0;
        struct mdc_op_data *op_data;
        struct ptlrpc_request *request = NULL;
        int update_mode;
        ENTRY;

        DEBUG_REQ(D_INODE, req, "%s: request to link "DLID4
                  ":%*s to foreign inode "DLID4"\n", obd->obd_name,
                  OLID4(rec->ur_id2), rec->ur_namelen - 1, rec->ur_name,
                  OLID4(rec->ur_id1));

        de_tgt_dir = mds_id2locked_dentry(obd, rec->ur_id2, NULL, LCK_EX,
                                          tgt_dir_lockh, &update_mode,
                                          rec->ur_name, rec->ur_namelen - 1,
                                          MDS_INODELOCK_UPDATE);
        if (IS_ERR(de_tgt_dir))
                GOTO(cleanup, rc = PTR_ERR(de_tgt_dir));
        cleanup_phase = 1;

        OBD_ALLOC(op_data, sizeof(*op_data));
        if (op_data == NULL)
                GOTO(cleanup, rc = -ENOMEM);

        memset(op_data, 0, sizeof(*op_data));
        op_data->id1 = *(rec->ur_id1);
        rc = md_link(mds->mds_md_exp, op_data, &request);
        OBD_FREE(op_data, sizeof(*op_data));

        if (request)
                ptlrpc_req_finished(request);
        if (rc)
                GOTO(cleanup, rc);

        cleanup_phase = 2;

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_LINK_WRITE, de_tgt_dir->d_inode->i_sb);

        handle = fsfilt_start(obd, de_tgt_dir->d_inode, FSFILT_OP_LINK, NULL);
        if (IS_ERR(handle)) {
                rc = PTR_ERR(handle);
                GOTO(cleanup, rc);
        }
        
        cleanup_phase = 3;

        rc = fsfilt_add_dir_entry(obd, de_tgt_dir, rec->ur_name,
                                  rec->ur_namelen - 1, id_ino(rec->ur_id1),
                                  id_gen(rec->ur_id1), id_group(rec->ur_id1),
                                  id_fid(rec->ur_id1));
        EXIT;
cleanup:
        rc = mds_finish_transno(mds, de_tgt_dir ? de_tgt_dir->d_inode : NULL,
                                handle, req, rc, 0);

        switch (cleanup_phase) {
                case 3:
                        if (rc) {
                                OBD_ALLOC(op_data, sizeof(*op_data));
                                if (op_data != NULL) {
                                        request = NULL;
                                        memset(op_data, 0, sizeof(*op_data));

                                        op_data->id1 = *(rec->ur_id1);
                                        op_data->create_mode = rec->ur_mode;
                                        
                                        rc = md_unlink(mds->mds_md_exp, op_data, &request);
                                        OBD_FREE(op_data, sizeof(*op_data));
                                        if (request)
                                                ptlrpc_req_finished(request);
                                        if (rc) {
                                                CERROR("error %d while dropping i_nlink on "
                                                       "remote inode\n", rc);
                                        }
                                } else {
                                        CERROR("rc %d prevented dropping i_nlink on "
                                               "remote inode\n", -ENOMEM);
                                }
                        }
                case 2:
                case 1:
                        if (rc) {
                                ldlm_lock_decref(tgt_dir_lockh, LCK_EX);
#ifdef S_PDIROPS
                                ldlm_lock_decref(tgt_dir_lockh + 1, update_mode);
#endif
                        } else {
                                ptlrpc_save_lock(req, tgt_dir_lockh, LCK_EX);
#ifdef S_PDIROPS
                                ptlrpc_save_lock(req, tgt_dir_lockh + 1, update_mode);
#endif
                        }
                        l_dput(de_tgt_dir);
                        break;
                default:
                        CERROR("invalid cleanup_phase %d\n", cleanup_phase);
                        LBUG();
        }
        req->rq_status = rc;
        return 0;
}

static int mds_reint_link(struct mds_update_record *rec, int offset,
                          struct ptlrpc_request *req, struct lustre_handle *lh)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *de_src = NULL;
        struct dentry *de_tgt_dir = NULL;
        struct dentry *dchild = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        struct lustre_handle *handle = NULL;
        struct lustre_handle tgt_dir_lockh[2] = {{0}, {0}}, src_lockh = {0};
        struct ldlm_res_id src_res_id = { .name = {0} };
        struct ldlm_res_id tgt_dir_res_id = { .name = {0} };
        ldlm_policy_data_t src_policy ={.l_inodebits = {MDS_INODELOCK_UPDATE}};
        ldlm_policy_data_t tgt_dir_policy =
                                       {.l_inodebits = {MDS_INODELOCK_UPDATE}};
        int rc = 0, cleanup_phase = 0;
#ifdef S_PDIROPS
        int update_mode = 0;
#endif
        ENTRY;

        LASSERT(offset == 1);

        DEBUG_REQ(D_INODE, req, "original "LPU64"/%u to "LPU64"/%u %s",
                  id_ino(rec->ur_id1), id_gen(rec->ur_id1),
                  id_ino(rec->ur_id2), id_gen(rec->ur_id2),
                  rec->ur_name);

        MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));
        MD_COUNTER_INCREMENT(obd, link);
        
        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_LINK))
                GOTO(cleanup, rc = -ENOENT);

        if (id_group(rec->ur_id1) != mds->mds_num) {
                rc = mds_reint_link_to_remote(rec, offset, req, lh);
                RETURN(rc);
        }
        
        if (rec->ur_namelen == 1) {
                rc = mds_reint_link_acquire(rec, offset, req, lh);
                RETURN(rc);
        }

        /* Step 1: Lookup the source inode and target directory by ID */
        de_src = mds_id2dentry(obd, rec->ur_id1, NULL);
        if (IS_ERR(de_src))
                GOTO(cleanup, rc = PTR_ERR(de_src));

        cleanup_phase = 1; /* source dentry */

        de_tgt_dir = mds_id2dentry(obd, rec->ur_id2, NULL);
        if (IS_ERR(de_tgt_dir)) {
                rc = PTR_ERR(de_tgt_dir);
                de_tgt_dir = NULL;
                GOTO(cleanup, rc);
        }

        cleanup_phase = 2; /* target directory dentry */

        CDEBUG(D_INODE, "linking %*s/%s to inode %lu\n",
               de_tgt_dir->d_name.len, de_tgt_dir->d_name.name,
               rec->ur_name, de_src->d_inode->i_ino);

        /* Step 2: Take the two locks */
        src_res_id.name[0] = id_fid(rec->ur_id1);
        src_res_id.name[1] = id_group(rec->ur_id1);
        tgt_dir_res_id.name[0] = id_fid(rec->ur_id2);
        tgt_dir_res_id.name[1] = id_group(rec->ur_id2);
        
#ifdef S_PDIROPS
        if (IS_PDIROPS(de_tgt_dir->d_inode)) {
                int flags = LDLM_FL_ATOMIC_CB;
                update_mode = mds_lock_mode_for_dir(obd, de_tgt_dir, LCK_EX);
                if (update_mode) {
                        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace,
                                              tgt_dir_res_id, LDLM_IBITS,
                                              &src_policy, update_mode, &flags,
                                              mds_blocking_ast,
                                              ldlm_completion_ast, NULL, NULL,
                                              NULL, 0, NULL, tgt_dir_lockh + 1);
                        if (rc != ELDLM_OK)
                                GOTO(cleanup, rc = -ENOLCK);
                }

                tgt_dir_res_id.name[2] = full_name_hash((unsigned char *)rec->ur_name,
                                                        rec->ur_namelen - 1);
                CDEBUG(D_INFO, "take lock on %lu:%lu:"LPX64"\n",
                       (unsigned long)id_fid(rec->ur_id2),
                       (unsigned long)id_group(rec->ur_id2),
                       tgt_dir_res_id.name[2]);
        }
#endif
        rc = enqueue_ordered_locks(obd, &src_res_id, &src_lockh, LCK_EX,
                                   &src_policy, &tgt_dir_res_id, tgt_dir_lockh,
                                   LCK_EX, &tgt_dir_policy);
        if (rc)
                GOTO(cleanup, rc);

        cleanup_phase = 3; /* locks */

        /* Step 3: Lookup the child */
        dchild = ll_lookup_one_len(rec->ur_name, de_tgt_dir, 
                                   rec->ur_namelen - 1);
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
                        ldlm_lock_decref(tgt_dir_lockh, LCK_EX);
                } else {
                        ptlrpc_save_lock(req, &src_lockh, LCK_EX);
                        ptlrpc_save_lock(req, tgt_dir_lockh, LCK_EX);
                }
        case 2: /* target dentry */
#ifdef S_PDIROPS
                if (tgt_dir_lockh[1].cookie && update_mode)
                        ldlm_lock_decref(tgt_dir_lockh + 1, update_mode);
#endif
                if (de_tgt_dir)
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
static int mds_get_parents_children_locked(struct obd_device *obd,
                                           struct mds_obd *mds,
                                           struct lustre_id *p1_id,
                                           struct dentry **de_srcdirp,
                                           struct lustre_id *p2_id,
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
           needed */
        ldlm_policy_data_t c2_policy = {.l_inodebits = {MDS_INODELOCK_FULL}};
        struct ldlm_res_id *maxres_src, *maxres_tgt;
        struct inode *inode;
        int rc = 0, cleanup_phase = 0;
	__u32 child_gen1 = 0;
        __u32 child_gen2 = 0;
	unsigned long child_ino1 = 0;
	unsigned long child_ino2 = 0;
        ENTRY;

        /* Step 1: Lookup the source directory */
        *de_srcdirp = mds_id2dentry(obd, p1_id, NULL);
        if (IS_ERR(*de_srcdirp))
                GOTO(cleanup, rc = PTR_ERR(*de_srcdirp));

        cleanup_phase = 1; /* source directory dentry */

        p1_res_id.name[0] = id_fid(p1_id);
        p1_res_id.name[1] = id_group(p1_id);

        /* Step 2: Lookup the target directory */
        if (id_equal_stc(p1_id, p2_id)) {
                *de_tgtdirp = dget(*de_srcdirp);
        } else {
                *de_tgtdirp = mds_id2dentry(obd, p2_id, NULL);
                if (IS_ERR(*de_tgtdirp)) {
                        rc = PTR_ERR(*de_tgtdirp);
                        *de_tgtdirp = NULL;
                        GOTO(cleanup, rc);
                }
        }

        cleanup_phase = 2; /* target directory dentry */

        p2_res_id.name[0] = id_fid(p2_id);
        p2_res_id.name[1] = id_group(p2_id);

#ifdef S_PDIROPS
        dlm_handles[5].cookie = 0;
        dlm_handles[6].cookie = 0;
        
        if (IS_PDIROPS((*de_srcdirp)->d_inode)) {
                /*
                 * get a temp lock on just fid, group to flush client cache and
                 * to protect dirs from concurrent splitting.
                 */
                rc = enqueue_ordered_locks(obd, &p1_res_id, &dlm_handles[5],
                                           LCK_PW, &p_policy, &p2_res_id,
                                           &dlm_handles[6], LCK_PW, &p_policy);
                if (rc != ELDLM_OK)
                        GOTO(cleanup, rc);
                
                p1_res_id.name[2] = full_name_hash((unsigned char *)old_name,
                                                   old_len - 1);
                p2_res_id.name[2] = full_name_hash((unsigned char *)new_name,
                                                   new_len - 1);

                CDEBUG(D_INFO, "take locks on "
                       LPX64":"LPX64":"LPX64", "LPX64":"LPX64":"LPX64"\n",
                       p1_res_id.name[0], p1_res_id.name[1], p1_res_id.name[2],
                       p2_res_id.name[0], p2_res_id.name[1], p2_res_id.name[2]);
        }
        cleanup_phase = 3;
#endif

        /* Step 3: Lookup the source child entry */
        *de_oldp = ll_lookup_one_len(old_name, *de_srcdirp, 
                                     old_len - 1);
        if (IS_ERR(*de_oldp)) {
                rc = PTR_ERR(*de_oldp);
                CERROR("old child lookup error (%.*s): %d\n",
                       old_len - 1, old_name, rc);
                GOTO(cleanup, rc);
        }

        cleanup_phase = 4; /* original name dentry */

        inode = (*de_oldp)->d_inode;
        if (inode != NULL) {
                struct lustre_id sid;
                
                inode = igrab(inode);
                if (inode == NULL)
                        GOTO(cleanup, rc = -ENOENT);

                down(&inode->i_sem);
                rc = mds_read_inode_sid(obd, inode, &sid);
                up(&inode->i_sem);
                if (rc) {
                        CERROR("Can't read inode self id, inode %lu, "
                               "rc %d\n", inode->i_ino, rc);
                        iput(inode);
                        GOTO(cleanup, rc);
                }

		child_ino1 = inode->i_ino;
		child_gen1 = inode->i_generation;
                c1_res_id.name[0] = id_fid(&sid);
                c1_res_id.name[1] = id_group(&sid);
                iput(inode);
        } else if ((*de_oldp)->d_flags & DCACHE_CROSS_REF) {
		child_ino1 = (*de_oldp)->d_inum;
		child_gen1 = (*de_oldp)->d_generation;
                c1_res_id.name[0] = (*de_oldp)->d_fid;
                c1_res_id.name[1] = (*de_oldp)->d_mdsnum;
        } else {
                GOTO(cleanup, rc = -ENOENT);
        }

        /* Step 4: Lookup the target child entry */
        *de_newp = ll_lookup_one_len(new_name, *de_tgtdirp, 
                                     new_len - 1);
        if (IS_ERR(*de_newp)) {
                rc = PTR_ERR(*de_newp);
                CERROR("new child lookup error (%.*s): %d\n",
                       old_len - 1, old_name, rc);
                GOTO(cleanup, rc);
        }

        cleanup_phase = 5; /* target dentry */

        inode = (*de_newp)->d_inode;
        if (inode != NULL) {
                struct lustre_id sid;

                inode = igrab(inode);
                if (inode == NULL)
                        goto retry_locks;

                down(&inode->i_sem);
                rc = mds_read_inode_sid(obd, inode, &sid);
                up(&inode->i_sem);
                if (rc) {
                        CERROR("Can't read inode self id, inode %lu, "
                               "rc %d\n", inode->i_ino, rc);
                        GOTO(cleanup, rc);
                }

		child_ino2 = inode->i_ino;
		child_gen2 = inode->i_generation;
                c2_res_id.name[0] = id_fid(&sid);
                c2_res_id.name[1] = id_group(&sid);
                iput(inode);
        } else if ((*de_newp)->d_flags & DCACHE_CROSS_REF) {
		child_ino2 = (*de_newp)->d_inum;
		child_gen2 = (*de_newp)->d_generation;
                c2_res_id.name[0] = (*de_newp)->d_fid;
                c2_res_id.name[1] = (*de_newp)->d_mdsnum;
        }

retry_locks:
        /* Step 5: Take locks on the parents and child(ren) */
        maxres_src = &p1_res_id;
        maxres_tgt = &p2_res_id;
        cleanup_phase = 5; /* target dentry */

        if (c1_res_id.name[0] != 0 && res_gt(&c1_res_id, &p1_res_id, NULL, NULL))
                maxres_src = &c1_res_id;
        if (c2_res_id.name[0] != 0 && res_gt(&c2_res_id, &p2_res_id, NULL, NULL))
                maxres_tgt = &c2_res_id;

        rc = enqueue_4ordered_locks(obd, &p1_res_id, &dlm_handles[0], parent_mode,
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
                              parent_mode, &c1_res_id, &dlm_handles[2],
                              de_oldp, child_mode, &c1_policy, old_name, old_len,
                              maxres_tgt, child_ino1, child_gen1);
        if (rc) {
                if (c2_res_id.name[0] != 0)
                        ldlm_lock_decref(&dlm_handles[3], child_mode);
                ldlm_lock_decref(&dlm_handles[1], parent_mode);
                cleanup_phase = 5;
                if (rc > 0)
                        goto retry_locks;
                GOTO(cleanup, rc);
        }

        if (!DENTRY_VALID(*de_oldp))
                GOTO(cleanup, rc = -ENOENT);

        /* Step 6b: Re-lookup target child to verify it hasn't changed */
        rc = mds_verify_child(obd, &p2_res_id, &dlm_handles[1], *de_tgtdirp,
                              parent_mode, &c2_res_id, &dlm_handles[3],
                              de_newp, child_mode, &c2_policy, new_name,
                              new_len, maxres_src, child_ino2, child_gen2);
        if (rc) {
                ldlm_lock_decref(&dlm_handles[2], child_mode);
                ldlm_lock_decref(&dlm_handles[0], parent_mode);
                cleanup_phase = 5;
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
                        if (dlm_handles[1].cookie != 0)
                                ldlm_lock_decref(&dlm_handles[1], parent_mode);
                        if (dlm_handles[0].cookie != 0)
                                ldlm_lock_decref(&dlm_handles[0], parent_mode);
                case 5: /* target dentry */
                        l_dput(*de_newp);
                case 4: /* source dentry */
                        l_dput(*de_oldp);
                case 3:
#ifdef S_PDIROPS
                        if (dlm_handles[5].cookie != 0)
                                ldlm_lock_decref(&(dlm_handles[5]), LCK_PW);
                        if (dlm_handles[6].cookie != 0)
                                ldlm_lock_decref(&(dlm_handles[6]), LCK_PW);
#endif
                case 2: /* target directory dentry */
                        l_dput(*de_tgtdirp);
                case 1: /* source directry dentry */
                        l_dput(*de_srcdirp);
                }
        }

        return rc;
}

/*
 * checks if dentry can be removed. This function also handles cross-ref
 * dentries.
 */
static int mds_check_for_rename(struct obd_device *obd,
                                struct dentry *dentry)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_handle *rlockh;
        struct ptlrpc_request *req;
        struct mdc_op_data *op_data;
        struct lookup_intent it;
        int handle_size, rc = 0;
        ENTRY;

        LASSERT(dentry != NULL);

        if (dentry->d_inode) {
                if (S_ISDIR(dentry->d_inode->i_mode) &&
                    !mds_is_dir_empty(obd, dentry))
                        rc = -ENOTEMPTY;
        } else {
                LASSERT((dentry->d_flags & DCACHE_CROSS_REF));
                handle_size = sizeof(struct lustre_handle);
        
                OBD_ALLOC(rlockh, handle_size);
                if (rlockh == NULL)
                        RETURN(-ENOMEM);

                memset(rlockh, 0, handle_size);
                OBD_ALLOC(op_data, sizeof(*op_data));
                if (op_data == NULL) {
                        OBD_FREE(rlockh, handle_size);
                        RETURN(-ENOMEM);
                }
                memset(op_data, 0, sizeof(*op_data));
                mds_pack_dentry2id(obd, &op_data->id1, dentry, 1);

                it.it_op = IT_UNLINK;
                OBD_ALLOC(it.d.fs_data, sizeof(struct lustre_intent_data));
                if (!it.d.fs_data)
                        RETURN(-ENOMEM);
                rc = md_enqueue(mds->mds_md_exp, LDLM_IBITS, &it, LCK_EX,
                                op_data, rlockh, NULL, 0, ldlm_completion_ast,
                                mds_blocking_ast, NULL);
                OBD_FREE(op_data, sizeof(*op_data));


                if (rc) {
                        OBD_FREE(it.d.fs_data,
                                 sizeof(struct lustre_intent_data));
                        RETURN(rc);
                }
                if (rlockh->cookie != 0)
                        ldlm_lock_decref(rlockh, LCK_EX);
                
                if (LUSTRE_IT(&it)->it_data) {
                        req = (struct ptlrpc_request *)LUSTRE_IT(&it)->it_data;
                        ptlrpc_req_finished(req);
                }

                if (LUSTRE_IT(&it)->it_status)
                        rc = LUSTRE_IT(&it)->it_status;
                OBD_FREE(it.d.fs_data, sizeof(struct lustre_intent_data));
                OBD_FREE(rlockh, handle_size);
        }
        RETURN(rc);
}

static int mds_add_local_dentry(struct mds_update_record *rec, int offset,
                                struct ptlrpc_request *req, struct lustre_id *id,
                                struct dentry *de_dir, struct dentry *de)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_obd *mds = mds_req2mds(req);
        void *handle = NULL;
        int rc = 0;
        ENTRY;

        if (de->d_inode) {
                /*
                 * name exists and points to local inode try to unlink this name
                 * and create new one.
                 */
                CDEBUG(D_OTHER, "%s: %s points to local inode %lu/%lu\n",
                       obd->obd_name, rec->ur_tgt, (unsigned long)de->d_inode->i_ino,
                       (unsigned long)de->d_inode->i_generation);

                /* checking if we can remove local dentry. */
                rc = mds_check_for_rename(obd, de);
                if (rc)
                        GOTO(cleanup, rc);

                handle = fsfilt_start(obd, de_dir->d_inode,
                                      FSFILT_OP_RENAME, NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                rc = fsfilt_del_dir_entry(req->rq_export->exp_obd, de);
                if (rc)
                        GOTO(cleanup, rc);
        } else if (de->d_flags & DCACHE_CROSS_REF) {
                CDEBUG(D_OTHER, "%s: %s points to remote inode %lu/%lu\n",
                       obd->obd_name, rec->ur_tgt, (unsigned long)de->d_mdsnum,
                        (unsigned long)de->d_fid);

                /* checking if we can remove local dentry. */
                rc = mds_check_for_rename(obd, de);
                if (rc)
                        GOTO(cleanup, rc);

                /*
                 * to be fully POSIX compatible, we should add one more check:
                 *
                 * if de_new is subdir of dir rec->ur_id1. If so - return
                 * -EINVAL.
                 *
                 * I do not know how to implement it right now, because
                 * inodes/dentries for new and old names lie on different MDS,
                 * so add this notice here just to make it visible for the rest
                 * of developers and do not forget about. And when this check
                 * will be added, del_cross_ref should gone, that is local
                 * dentry is able to be removed if all checks passed. --umka
                 */

                handle = fsfilt_start(obd, de_dir->d_inode,
                                      FSFILT_OP_RENAME, NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
                rc = fsfilt_del_dir_entry(req->rq_export->exp_obd, de);
                if (rc)
                        GOTO(cleanup, rc);
        } else {
                /* name doesn't exist. the simplest case. */
                handle = fsfilt_start(obd, de_dir->d_inode,
                                      FSFILT_OP_LINK, NULL);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));
        }

        rc = fsfilt_add_dir_entry(obd, de_dir, rec->ur_tgt,
                                  rec->ur_tgtlen - 1, id_ino(id),
                                  id_gen(id), id_group(id), id_fid(id));
        if (rc) {
                CERROR("add_dir_entry() returned error %d\n", rc);
                GOTO(cleanup, rc);
        }

        EXIT;
cleanup:
        rc = mds_finish_transno(mds, de_dir ? de_dir->d_inode : NULL,
                                handle, req, rc, 0);

        return rc;
}

static int mds_del_local_dentry(struct mds_update_record *rec, int offset,
                                struct ptlrpc_request *req, struct dentry *de_dir,
                                struct dentry *de)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_obd *mds = mds_req2mds(req);
        void *handle = NULL;
        int rc = 0;
        ENTRY;

        handle = fsfilt_start(obd, de_dir->d_inode, FSFILT_OP_UNLINK, NULL);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));
        rc = fsfilt_del_dir_entry(obd, de);
        d_drop(de);

        EXIT;
cleanup:
        rc = mds_finish_transno(mds, de_dir ? de_dir->d_inode : NULL,
                                handle, req, rc, 0);
        return rc;
}

static int mds_reint_rename_create_name(struct mds_update_record *rec,
                                        int offset, struct ptlrpc_request *req)
{
        struct lustre_handle parent_lockh[2] = {{0}, {0}};
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_obd *mds = mds_req2mds(req);
        struct lustre_handle child_lockh = {0};
        struct dentry *de_tgtdir = NULL;
        struct dentry *de_new = NULL;
        int cleanup_phase = 0;
        int update_mode, rc = 0;
        struct lustre_id ids[2]; /* sid, pid */
        struct obd_export *set_exp;
        ENTRY;

        /*
         * another MDS executing rename operation has asked us to create target
         * name. such a creation should destroy existing target name.
         */
        CDEBUG(D_OTHER, "%s: request to create name %s for "DLID4"\n",
               obd->obd_name, rec->ur_tgt, OLID4(rec->ur_id1));

        /* first, lookup the target */
        rc = mds_get_parent_child_locked(obd, mds, rec->ur_id2, parent_lockh,
                                         &de_tgtdir, LCK_PW, MDS_INODELOCK_UPDATE,
                                         &update_mode, rec->ur_tgt, rec->ur_tgtlen,
                                         &child_lockh, &de_new, LCK_EX,
                                         MDS_INODELOCK_LOOKUP);
        if (rc)
                GOTO(cleanup, rc);

        /* get parent id: ldlm lock on the parent protects ea */
        rc = mds_read_inode_sid(obd, de_tgtdir->d_inode, &ids[1]);

        if (rc)
                GOTO(cleanup, rc);
        cleanup_phase = 1;

        LASSERT(de_tgtdir);
        LASSERT(de_tgtdir->d_inode);
        LASSERT(de_new);

        rc = mds_add_local_dentry(rec, offset, req, rec->ur_id1,
                                  de_tgtdir, de_new);
        if (rc)
                GOTO(cleanup, rc);

        ids[0] = *(rec->ur_id1);
        if (id_group(ids) == mds->mds_num)
                set_exp = req->rq_export;
        else
                set_exp = mds->mds_md_exp;
        rc = obd_set_info(set_exp, strlen("ids"), "ids", 
                          sizeof(struct lustre_id) * 2, ids);
 
        EXIT;
cleanup:
        
        if (cleanup_phase == 1) {
#ifdef S_PDIROPS
                if (parent_lockh[1].cookie != 0)
                        ldlm_lock_decref(parent_lockh + 1, update_mode);
#endif
                ldlm_lock_decref(parent_lockh, LCK_PW);
                if (child_lockh.cookie != 0)
                        ldlm_lock_decref(&child_lockh, LCK_EX);
                l_dput(de_new);
                l_dput(de_tgtdir);
        }

        req->rq_status = rc;
        return 0;
}

static int mds_reint_rename_to_remote(struct mds_update_record *rec, int offset,
                                      struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct ptlrpc_request *req2 = NULL;
        struct dentry *de_srcdir = NULL;
        struct dentry *de_old = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        struct lustre_handle parent_lockh[2] = {{0}, {0}};
        struct lustre_handle child_lockh = {0};
        struct mdc_op_data *op_data;
        int update_mode, rc = 0;
        ENTRY;

        CDEBUG(D_OTHER, "%s: move name %s onto another mds #%lu\n",
               obd->obd_name, rec->ur_name, (unsigned long)id_group(rec->ur_id2));
        
        OBD_ALLOC(op_data, sizeof(*op_data));
        if (op_data == NULL)
                RETURN(-ENOMEM);
        memset(op_data, 0, sizeof(*op_data));

        rc = mds_get_parent_child_locked(obd, mds, rec->ur_id1, parent_lockh,
                                         &de_srcdir, LCK_PW, MDS_INODELOCK_UPDATE,
                                         &update_mode, rec->ur_name, 
                                         rec->ur_namelen, &child_lockh, &de_old,
                                         LCK_EX, MDS_INODELOCK_LOOKUP);
        if (rc) {
                OBD_FREE(op_data, sizeof(*op_data));
                RETURN(rc);
        }

        LASSERT(de_srcdir);
        LASSERT(de_srcdir->d_inode);
        LASSERT(de_old);
       
        /*
         * we already know the target should be created on another MDS so, we
         * have to request that MDS to do it.
         */

        /* prepare source id */
        if (de_old->d_flags & DCACHE_CROSS_REF) {
                LASSERT(de_old->d_inode == NULL);
                CDEBUG(D_OTHER, "request to move remote name\n");
                mds_pack_dentry2id(obd, &op_data->id1, de_old, 1);
        } else if (de_old->d_inode == NULL) {
                /* oh, source doesn't exist */
                OBD_FREE(op_data, sizeof(*op_data));
                GOTO(cleanup, rc = -ENOENT);
        } else {
                struct lustre_id sid;
                struct inode *inode = de_old->d_inode;
                
                LASSERT(inode != NULL);
                CDEBUG(D_OTHER, "request to move local name\n");
                id_ino(&op_data->id1) = inode->i_ino;
                id_group(&op_data->id1) = mds->mds_num;
                id_gen(&op_data->id1) = inode->i_generation;

                down(&inode->i_sem);
                rc = mds_read_inode_sid(obd, inode, &sid);
                up(&inode->i_sem);
                if (rc) {
                        CERROR("Can't read inode self id, "
                               "inode %lu, rc = %d\n",
                               inode->i_ino, rc);
                        GOTO(cleanup, rc);
                }

                id_fid(&op_data->id1) = id_fid(&sid);
        }

        op_data->id2 = *rec->ur_id2;
        rc = md_rename(mds->mds_md_exp, op_data, NULL, 0,
                       rec->ur_tgt, rec->ur_tgtlen - 1, &req2);
        OBD_FREE(op_data, sizeof(*op_data));
       
        if (rc)
                GOTO(cleanup, rc);
        
        rc = mds_del_local_dentry(rec, offset, req, de_srcdir,
                                  de_old);

        EXIT;
cleanup:
        if (req2)
                ptlrpc_req_finished(req2);

#ifdef S_PDIROPS
        if (parent_lockh[1].cookie != 0)
                ldlm_lock_decref(parent_lockh + 1, update_mode);
#endif
        ldlm_lock_decref(parent_lockh, LCK_PW);
        if (child_lockh.cookie != 0)
                ldlm_lock_decref(&child_lockh, LCK_EX);

        l_dput(de_old);
        l_dput(de_srcdir);

        req->rq_status = rc;
        return 0;
}

static int mds_reint_rename(struct mds_update_record *rec, int offset,
                            struct ptlrpc_request *req, struct lustre_handle *lockh)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *de_srcdir = NULL;
        struct dentry *de_tgtdir = NULL;
        struct dentry *de_old = NULL;
        struct dentry *de_new = NULL;
        struct inode *old_inode = NULL, *new_inode = NULL;
        struct mds_obd *mds = mds_req2mds(req);
        struct lustre_handle dlm_handles[7] = {{0},{0},{0},{0},{0},{0},{0}};
        struct mds_body *body = NULL;
        struct llog_create_locks *lcl = NULL;
        struct lov_mds_md *lmm = NULL;
        int rc = 0, cleanup_phase = 0;
        struct lustre_id ids[2];  /* sid, pid */
        void *handle = NULL;
        ENTRY;

        LASSERT(offset == 1);

        DEBUG_REQ(D_INODE, req, "parent "DLID4" %s to "DLID4" %s",
                  OLID4(rec->ur_id1), rec->ur_name, OLID4(rec->ur_id2),
                  rec->ur_tgt);

        MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                DEBUG_REQ(D_HA, req, "rename replay");
                memcpy(lustre_msg_buf(req->rq_repmsg, 2, 0),
                       lustre_msg_buf(req->rq_reqmsg, offset + 3, 0),
                       req->rq_repmsg->buflens[2]);
        }

        MD_COUNTER_INCREMENT(obd, rename);

        if (rec->ur_namelen == 1) {
                rc = mds_reint_rename_create_name(rec, offset, req);
                RETURN(rc);
        }

        /* check if new name should be located on remote target. */
        if (id_group(rec->ur_id2) != mds->mds_num) {
                rc = mds_reint_rename_to_remote(rec, offset, req);
                RETURN(rc);
        }
        
        rc = mds_get_parents_children_locked(obd, mds, rec->ur_id1, &de_srcdir,
                                             rec->ur_id2, &de_tgtdir, LCK_PW,
                                             rec->ur_name, rec->ur_namelen,
                                             &de_old, rec->ur_tgt,
                                             rec->ur_tgtlen, &de_new,
                                             dlm_handles, LCK_EX);
        if (rc)
                GOTO(cleanup, rc);

        cleanup_phase = 1; /* parent(s), children, locks */
        old_inode = de_old->d_inode;
        new_inode = de_new->d_inode;

        /* sanity check for src inode */
        if (de_old->d_flags & DCACHE_CROSS_REF) {
                LASSERT(de_old->d_inode == NULL);

                /*
                 * in the case of cross-ref dir, we can perform this check only
                 * if child and parent lie on the same mds. This is because
                 * otherwise they can have the same inode numbers.
                 */
                if (de_old->d_mdsnum == mds->mds_num) {
                        if (de_old->d_inum == de_srcdir->d_inode->i_ino ||
                            de_old->d_inum == de_tgtdir->d_inode->i_ino)
                                GOTO(cleanup, rc = -EINVAL);
                }
        } else {
                LASSERT(de_old->d_inode != NULL);
                if (de_old->d_inode->i_ino == de_srcdir->d_inode->i_ino ||
                    de_old->d_inode->i_ino == de_tgtdir->d_inode->i_ino)
                        GOTO(cleanup, rc = -EINVAL);
        }

        /* sanity check for dest inode */
        if (de_new->d_flags & DCACHE_CROSS_REF) {
                LASSERT(new_inode == NULL);

                /* the same check about target dentry. */
                if (de_new->d_mdsnum == mds->mds_num) {
                        if (de_new->d_inum == de_srcdir->d_inode->i_ino ||
                            de_new->d_inum == de_tgtdir->d_inode->i_ino)
                                GOTO(cleanup, rc = -EINVAL);
                }
                
                /*
                 * regular files usualy do not have ->rename() implemented. But
                 * we handle only this case when @de_new is cross-ref entry,
                 * because in other cases it will be handled by vfs_rename().
                 */
                if (de_old->d_inode && (!de_old->d_inode->i_op || 
                    !de_old->d_inode->i_op->rename))
                        GOTO(cleanup, rc = -EPERM);
        } else {
                if (new_inode &&
                    (new_inode->i_ino == de_srcdir->d_inode->i_ino ||
                     new_inode->i_ino == de_tgtdir->d_inode->i_ino))
                        GOTO(cleanup, rc = -EINVAL);

        }
        
        /*
         * check if inodes point to each other. This should be checked before
         * is_subdir() check, as for the same entries it will think that they
         * are subdirs.
         */
        if (!(de_old->d_flags & DCACHE_CROSS_REF) &&
            !(de_new->d_flags & DCACHE_CROSS_REF) &&
            old_inode == new_inode)
                GOTO(cleanup, rc = 0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
        /*
         * check if we are moving old entry into its child. 2.6 does not check
         * for this in vfs_rename() anymore.
         */
        if (is_subdir(de_new, de_old))
                GOTO(cleanup, rc = -EINVAL);
#endif
        
        /*
         * if we are about to remove the target at first, pass the EA of that
         * inode to client to perform and cleanup on OST.
         */
        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*body));
        LASSERT(body != NULL);

        /* get new parent id: ldlm lock on the parent protects ea */
        rc = mds_read_inode_sid(obd, de_tgtdir->d_inode, &ids[1]);
        if (rc)
                GOTO(cleanup, rc);

        /* child i_alloc_sem protects orphan_dec_test && is_orphan race */
        if (new_inode) 
                DOWN_READ_I_ALLOC_SEM(new_inode);
        
        cleanup_phase = 2; /* up(&new_inode->i_sem) when finished */

        if (new_inode && ((S_ISDIR(new_inode->i_mode) && 
            new_inode->i_nlink == 2) ||
            new_inode->i_nlink == 1)) {
                if (mds_orphan_open_count(new_inode) > 0) {
                        /* need to lock pending_dir before transaction */
                        down(&mds->mds_pending_dir->d_inode->i_sem);
                        cleanup_phase = 3; /* up(&pending_dir->i_sem) */
                } else if (S_ISREG(new_inode->i_mode)) {
                        mds_pack_inode2body(obd, body, new_inode, 0);
                        mds_pack_md(obd, req->rq_repmsg, 1, body, 
                                    new_inode, MDS_PACK_MD_LOCK, 0);
                 }
        }

        OBD_FAIL_WRITE(OBD_FAIL_MDS_REINT_RENAME_WRITE,
                       de_srcdir->d_inode->i_sb);

        if (de_old->d_flags & DCACHE_CROSS_REF) {
                struct lustre_id old_id;
                struct obd_export *set_exp;

                
                mds_pack_dentry2id(obd, &old_id, de_old, 1);

                rc = mds_add_local_dentry(rec, offset, req, &old_id,
                                          de_tgtdir, de_new);
                if (rc)
                        GOTO(cleanup, rc);
                
                rc = mds_del_local_dentry(rec, offset, req, de_srcdir,
                                          de_old);
                if (rc)
                        GOTO(cleanup, rc);
                
                ids[0] = old_id;
                if (id_group(ids) == mds->mds_num)
                        set_exp = req->rq_export;
                else
                        set_exp = mds->mds_md_exp;
                rc = obd_set_info(set_exp, strlen("ids"), "ids", 
                                  sizeof(struct lustre_id) * 2, ids);

                GOTO(cleanup, rc);
        }

        lmm = lustre_msg_buf(req->rq_repmsg, 1, 0);
        handle = fsfilt_start_log(obd, de_tgtdir->d_inode, FSFILT_OP_RENAME,
                                  NULL, le32_to_cpu(lmm->lmm_stripe_count));

        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));

        lock_kernel();
        de_old->d_fsdata = req;
        de_new->d_fsdata = req;
        rc = vfs_rename(de_srcdir->d_inode, de_old, de_tgtdir->d_inode, de_new);
        unlock_kernel();

        if (rc == 0 && new_inode != NULL && new_inode->i_nlink == 0) {
                if (mds_orphan_open_count(new_inode) > 0)
                        rc = mds_orphan_add_link(rec, obd, de_new);

                if (rc == 1)
                        GOTO(cleanup, rc = 0);

                if (!S_ISREG(new_inode->i_mode))
                        GOTO(cleanup, rc);

                if (!(body->valid & OBD_MD_FLEASIZE)) {
                        body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                        OBD_MD_FLATIME | OBD_MD_FLMTIME);
                } else if (mds_log_op_unlink(obd, new_inode,
                                             lustre_msg_buf(req->rq_repmsg,1,0),
                                             req->rq_repmsg->buflens[1],
                                             lustre_msg_buf(req->rq_repmsg,2,0),
                                             req->rq_repmsg->buflens[2], 
                                             &lcl) > 0) {
                        body->valid |= OBD_MD_FLCOOKIE;
                }
                
                rc = mds_destroy_object(obd, old_inode, 1);
                if (rc) {
                        CERROR("can't remove OST object, err %d\n",
                               rc);
                }
        }

        if (rc == 0)
               rc = mds_update_inode_ids(obd, de_old->d_inode,
                                         handle, NULL, &ids[1]);
        
        EXIT;
cleanup:
        rc = mds_finish_transno(mds, (de_tgtdir ? de_tgtdir->d_inode : NULL),
                                handle, req, rc, 0);

        switch (cleanup_phase) {
        case 3:
                up(&mds->mds_pending_dir->d_inode->i_sem);
        case 2:
                if (new_inode)
                        UP_READ_I_ALLOC_SEM(new_inode);
        case 1:
#ifdef S_PDIROPS
                if (dlm_handles[5].cookie != 0)
                        ldlm_lock_decref(&(dlm_handles[5]), LCK_PW);
                if (dlm_handles[6].cookie != 0)
                        ldlm_lock_decref(&(dlm_handles[6]), LCK_PW);
#endif
                if (lcl != NULL)
                        ptlrpc_save_llog_lock(req, lcl);

                if (rc) {
                        if (dlm_handles[3].cookie != 0)
                                ldlm_lock_decref(&(dlm_handles[3]), LCK_EX);
                        ldlm_lock_decref(&(dlm_handles[2]), LCK_EX);
                        ldlm_lock_decref(&(dlm_handles[1]), LCK_PW);
                        ldlm_lock_decref(&(dlm_handles[0]), LCK_PW);
                } else {
                        if (dlm_handles[3].cookie != 0)
                                ptlrpc_save_lock(req,&(dlm_handles[3]), LCK_EX);
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
        struct lvfs_run_ctxt saved;
        int rc;

        /* checked by unpacker */
        LASSERT(rec->ur_opcode <= REINT_MAX &&
                reinters[rec->ur_opcode] != NULL);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &rec->ur_uc);
        rc = reinters[rec->ur_opcode] (rec, offset, req, lockh);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &rec->ur_uc);

        return rc;
}
