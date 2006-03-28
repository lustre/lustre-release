#if 0
/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mds/handler.c
 *  Lustre Metadata Target (mdt) request handler
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Mike Shaver <shaver@clusterfs.com>
 *   Author: Nikita Danilov <nikita@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/lu_object.h>

#include "mdt.h"

int mdt_num_threads;

static int mdt_connect_internal(struct obd_export *exp,
                                struct obd_connect_data *data)
{
        struct obd_device *obd = exp->exp_obd;
        if (data != NULL) {
                data->ocd_connect_flags &= MDS_CONNECT_SUPPORTED;
                data->ocd_ibits_known &= MDS_INODELOCK_FULL;

                /* If no known bits (which should not happen, probably,
                   as everybody should support LOOKUP and UPDATE bits at least)
                   revert to compat mode with plain locks. */
                if (!data->ocd_ibits_known &&
                    data->ocd_connect_flags & OBD_CONNECT_IBITS)
                        data->ocd_connect_flags &= ~OBD_CONNECT_IBITS;

                if (!obd->u.mds.mdt_fl_acl)
                        data->ocd_connect_flags &= ~OBD_CONNECT_ACL;

                if (!obd->u.mds.mdt_fl_user_xattr)
                        data->ocd_connect_flags &= ~OBD_CONNECT_XATTR;

                exp->exp_connect_flags = data->ocd_connect_flags;
                data->ocd_version = LUSTRE_VERSION_CODE;
                exp->exp_mdt_data.med_ibits_known = data->ocd_ibits_known;
        }

        if (obd->u.mds.mdt_fl_acl &&
            ((exp->exp_connect_flags & OBD_CONNECT_ACL) == 0)) {
                CWARN("%s: MDS requires ACL support but client does not\n",
                      obd->obd_name);
                return -EBADE;
        }
        return 0;
}

static int mdt_reconnect(struct obd_export *exp, struct obd_device *obd,
                         struct obd_uuid *cluuid,
                         struct obd_connect_data *data)
{
        int rc;
        ENTRY;

        if (exp == NULL || obd == NULL || cluuid == NULL)
                RETURN(-EINVAL);

        rc = mdt_connect_internal(exp, data);

        RETURN(rc);
}

/* Establish a connection to the MDS.
 *
 * This will set up an export structure for the client to hold state data
 * about that client, like open files, the last operation number it did
 * on the server, etc.
 */
static int mdt_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct obd_connect_data *data)
{
        struct obd_export *exp;
        struct mdt_export_data *med;
        struct mdt_client_data *mcd = NULL;
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
        med = &exp->exp_mdt_data;

        rc = mdt_connect_internal(exp, data);
        if (rc)
                GOTO(out, rc);

        OBD_ALLOC_PTR(mcd);
        if (!mcd)
                GOTO(out, rc = -ENOMEM);

        memcpy(mcd->mcd_uuid, cluuid, sizeof(mcd->mcd_uuid));
        med->med_mcd = mcd;

        rc = mdt_client_add(obd, &obd->u.mds, med, -1);
        GOTO(out, rc);

out:
        if (rc) {
                if (mcd) {
                        OBD_FREE_PTR(mcd);
                        med->med_mcd = NULL;
                }
                class_disconnect(exp);
        } else {
                class_export_put(exp);
        }

        RETURN(rc);
}

int mdt_init_export(struct obd_export *exp)
{
        struct mdt_export_data *med = &exp->exp_mdt_data;

        INIT_LIST_HEAD(&med->med_open_head);
        spin_lock_init(&med->med_open_lock);
        exp->exp_connecting = 1;
        RETURN(0);
}

static int mdt_destroy_export(struct obd_export *export)
{
        struct mdt_export_data *med;
        struct obd_device *obd = export->exp_obd;
        struct lvfs_run_ctxt saved;
        int rc = 0;
        ENTRY;

        med = &export->exp_mdt_data;
        target_destroy_export(export);

        if (obd_uuid_equals(&export->exp_client_uuid, &obd->obd_uuid))
                RETURN(0);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        /* Close any open files (which may also cause orphan unlinking). */
        spin_lock(&med->med_open_lock);
        while (!list_empty(&med->med_open_head)) {
                struct list_head *tmp = med->med_open_head.next;
                struct mdt_file_data *mfd =
                        list_entry(tmp, struct mdt_file_data, mfd_list);
                struct dentry *dentry = mfd->mfd_dentry;

                /* Remove mfd handle so it can't be found again.
                 * We are consuming the mfd_list reference here. */
                mdt_mfd_unlink(mfd, 0);
                spin_unlock(&med->med_open_lock);

                /* If you change this message, be sure to update
                 * replay_single:test_46 */
                CDEBUG(D_INODE|D_IOCTL, "%s: force closing file handle for "
                       "%.*s (ino %lu)\n", obd->obd_name, dentry->d_name.len,
                       dentry->d_name.name, dentry->d_inode->i_ino);
                /* child orphan sem protects orphan_dec_test and
                 * is_orphan race, mdt_mfd_close drops it */
                MDT_DOWN_WRITE_ORPHAN_SEM(dentry->d_inode);
                rc = mdt_mfd_close(NULL, MDS_REQ_REC_OFF, obd, mfd,
                                   !(export->exp_flags & OBD_OPT_FAILOVER));

                if (rc)
                        CDEBUG(D_INODE|D_IOCTL, "Error closing file: %d\n", rc);
                spin_lock(&med->med_open_lock);
        }
        spin_unlock(&med->med_open_lock);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        mdt_client_free(export);

        RETURN(rc);
}

static int mdt_disconnect(struct obd_export *exp)
{
        unsigned long irqflags;
        int rc;
        ENTRY;

        LASSERT(exp);
        class_export_get(exp);

        /* Disconnect early so that clients can't keep using export */
        rc = class_disconnect(exp);
        ldlm_cancel_locks_for_export(exp);

        /* complete all outstanding replies */
        spin_lock_irqsave(&exp->exp_lock, irqflags);
        while (!list_empty(&exp->exp_outstanding_replies)) {
                struct ptlrpc_reply_state *rs =
                        list_entry(exp->exp_outstanding_replies.next,
                                   struct ptlrpc_reply_state, rs_exp_list);
                struct ptlrpc_service *svc = rs->rs_service;

                spin_lock(&svc->srv_lock);
                list_del_init(&rs->rs_exp_list);
                ptlrpc_schedule_difficult_reply(rs);
                spin_unlock(&svc->srv_lock);
        }
        spin_unlock_irqrestore(&exp->exp_lock, irqflags);

        class_export_put(exp);
        RETURN(rc);
}

static int mdt_getstatus(struct mdt_thread_info *info,
			 struct ptlrpc_request *req)
{
        struct md_device *mdd  = info->mti_mdt->mdt_mdd;
	int               size = sizeof *body;
	struct mds_body  *body;
	int               result;

        ENTRY;

        result = lustre_pack_reply(req, 1, &size, NULL);
	if (result)
                CERROR(LUSTRE_MDT0_NAME" out of memory for message: size=%d\n",
		       size);
        else if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETSTATUS_PACK))
                result = -ENOMEM;
        else {
		body = lustre_msg_buf(req->rq_repmsg, 0, sizeof *body);
		result = mdd->md_ops->mdo_root_get(mdd, &body->fid1);
	}

        /* the last_committed and last_xid fields are filled in for all
         * replies already - no need to do so here also.
         */
        RETURN(result);
}

static int mdt_getattr_internal(struct obd_device *obd, struct dentry *dentry,
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

        mdt_pack_inode2fid(&body->fid1, inode);
        mdt_pack_inode2body(body, inode);
        reply_off++;

        if ((S_ISREG(inode->i_mode) && (reqbody->valid & OBD_MD_FLEASIZE)) ||
            (S_ISDIR(inode->i_mode) && (reqbody->valid & OBD_MD_FLDIREA))) {
                rc = mdt_pack_md(obd, req->rq_repmsg, reply_off, body,
                                 inode, 1);

                /* If we have LOV EA data, the OST holds size, atime, mtime */
                if (!(body->valid & OBD_MD_FLEASIZE) &&
                    !(body->valid & OBD_MD_FLDIREA))
                        body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                        OBD_MD_FLATIME | OBD_MD_FLMTIME);

                lustre_shrink_reply(req, reply_off, body->eadatasize, 0);
                if (body->eadatasize)
                        reply_off++;
        } else if (S_ISLNK(inode->i_mode) &&
                   (reqbody->valid & OBD_MD_LINKNAME) != 0) {
                char *symname = lustre_msg_buf(req->rq_repmsg, reply_off, 0);
                int len;

                LASSERT (symname != NULL);       /* caller prepped reply */
                len = req->rq_repmsg->buflens[reply_off];

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
                reply_off++;
        }

        if (reqbody->valid & OBD_MD_FLMODEASIZE) {
                struct mdt_obd *mds = mdt_req2mds(req);
                body->max_cookiesize = mds->mdt_max_cookiesize;
                body->max_mdsize = mds->mdt_max_mdsize;
                body->valid |= OBD_MD_FLMODEASIZE;
        }

        if (rc)
                RETURN(rc);

        RETURN(rc);
}

static int mdt_getattr_pack_msg(struct ptlrpc_request *req, struct inode *inode,
                                int offset)
{
        struct mdt_obd *mds = mdt_req2mds(req);
        struct mds_body *body;
        int rc, size[2] = {sizeof(*body)}, bufcount = 1;
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*body));
        LASSERT(body != NULL);                 /* checked by caller */
        LASSERT_REQSWABBED(req, offset);       /* swabbed by caller */

        if ((S_ISREG(inode->i_mode) && (body->valid & OBD_MD_FLEASIZE)) ||
            (S_ISDIR(inode->i_mode) && (body->valid & OBD_MD_FLDIREA))) {
                LOCK_INODE_MUTEX(inode);
                rc = fsfilt_get_md(req->rq_export->exp_obd, inode, NULL, 0,
                                   "lov");
                UNLOCK_INODE_MUTEX(inode);
                CDEBUG(D_INODE, "got %d bytes MD data for inode %lu\n",
                       rc, inode->i_ino);
                if (rc < 0) {
                        if (rc != -ENODATA) {
                                CERROR("error getting inode %lu MD: rc = %d\n",
                                       inode->i_ino, rc);
                                RETURN(rc);
                        }
                        size[bufcount] = 0;
                } else if (rc > mds->mdt_max_mdsize) {
                        size[bufcount] = 0;
                        CERROR("MD size %d larger than maximum possible %u\n",
                               rc, mds->mdt_max_mdsize);
                } else {
                        size[bufcount] = rc;
                }
                bufcount++;
        } else if (S_ISLNK(inode->i_mode) && (body->valid & OBD_MD_LINKNAME)) {
                if (inode->i_size + 1 != body->eadatasize)
                        CERROR("symlink size: %Lu, reply space: %d\n",
                               inode->i_size + 1, body->eadatasize);
                size[bufcount] = min_t(int, inode->i_size+1, body->eadatasize);
                bufcount++;
                CDEBUG(D_INODE, "symlink size: %Lu, reply space: %d\n",
                       inode->i_size + 1, body->eadatasize);
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK)) {
                CERROR("failed MDT_GETATTR_PACK test\n");
                req->rq_status = -ENOMEM;
                RETURN(-ENOMEM);
        }

        rc = lustre_pack_reply(req, bufcount, size, NULL);
        if (rc) {
                CERROR("lustre_pack_reply failed: rc %d\n", rc);
                req->rq_status = rc;
                RETURN(rc);
        }

        RETURN(0);
}

static int mdt_getattr_name(int offset, struct ptlrpc_request *req,
                            int child_part, struct lustre_handle *child_lockh)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mdt_obd *mds = &obd->u.mds;
        struct ldlm_reply *rep = NULL;
        struct lvfs_run_ctxt saved;
        struct mds_body *body;
        struct dentry *dparent = NULL, *dchild = NULL;
        struct lvfs_ucred uc = {NULL,};
        struct lustre_handle parent_lockh;
        int namesize;
        int rc = 0, cleanup_phase = 0, resent_req = 0;
        char *name;
        ENTRY;

        LASSERT(!strcmp(obd->obd_type->typ_name, LUSTRE_MDT_NAME));

        /* Swab now, before anyone looks inside the request */

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mdt_body);
        if (body == NULL) {
                CERROR("Can't swab mdt_body\n");
                RETURN(-EFAULT);
        }

        LASSERT_REQSWAB(req, offset + 1);
        name = lustre_msg_string(req->rq_reqmsg, offset + 1, 0);
        if (name == NULL) {
                CERROR("Can't unpack name\n");
                RETURN(-EFAULT);
        }
        namesize = lustre_msg_buflen(req->rq_reqmsg, offset + 1);

        rc = mdt_init_ucred(&uc, req, offset);
        if (rc)
                GOTO(cleanup, rc);

        LASSERT (offset == MDS_REQ_REC_OFF || offset == MDS_REQ_INTENT_REC_OFF);
        /* if requests were at offset 2, the getattr reply goes back at 1 */
        if (offset == MDS_REQ_INTENT_REC_OFF) {
                rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*rep));
                offset = 1;
        }

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        cleanup_phase = 1; /* kernel context */
        intent_set_disposition(rep, DISP_LOOKUP_EXECD);

        if (lustre_handle_is_used(child_lockh)) {
                LASSERT(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT);
                resent_req = 1;
        }

        if (resent_req == 0) {
            if (name) {
                rc = mdt_get_parent_child_locked(obd, &obd->u.mds, &body->fid1,
                                                 &parent_lockh, &dparent,
                                                 LCK_CR,
                                                 MDS_INODELOCK_UPDATE,
                                                 name, namesize,
                                                 child_lockh, &dchild, LCK_CR,
                                                 child_part);
            } else {
                        /* For revalidate by fid we always take UPDATE lock */
                        dchild = mdt_fid2locked_dentry(obd, &body->fid2, NULL,
                                                       LCK_CR, child_lockh,
                                                       NULL, 0,
                                                       MDT_INODELOCK_UPDATE);
                        LASSERT(dchild);
                        if (IS_ERR(dchild))
                                rc = PTR_ERR(dchild);
            }
            if (rc)
                    GOTO(cleanup, rc);
        } else {
                struct ldlm_lock *granted_lock;
                struct ll_fid child_fid;
                struct ldlm_resource *res;
                DEBUG_REQ(D_DLMTRACE, req, "resent, not enqueuing new locks");
                granted_lock = ldlm_handle2lock(child_lockh);
                LASSERTF(granted_lock != NULL, LPU64"/%u lockh "LPX64"\n",
                         body->fid1.id, body->fid1.generation,
                         child_lockh->cookie);


                res = granted_lock->l_resource;
                child_fid.id = res->lr_name.name[0];
                child_fid.generation = res->lr_name.name[1];
                dchild = mdt_fid2dentry(&obd->u.mds, &child_fid, NULL);
                LASSERT(!IS_ERR(dchild));
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
                rc = mdt_getattr_pack_msg(req, dchild->d_inode, offset);
                if (rc != 0) {
                        CERROR ("mdt_getattr_pack_msg: %d\n", rc);
                        GOTO (cleanup, rc);
                }
        }

        rc = mdt_getattr_internal(obd, dchild, req, body, offset);
        GOTO(cleanup, rc); /* returns the lock to the client */

 cleanup:
        switch (cleanup_phase) {
        case 2:
                if (resent_req == 0) {
                        if (rc && dchild->d_inode)
                                ldlm_lock_decref(child_lockh, LCK_CR);
                        ldlm_lock_decref(&parent_lockh, LCK_CR);
                        l_dput(dparent);
                }
                l_dput(dchild);
        case 1:
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        default:
                mds_exit_ucred(&uc, mds);
                if (req->rq_reply_state == NULL) {
                        req->rq_status = rc;
                        lustre_pack_reply(req, 0, NULL, NULL);
                }
        }
        return rc;
}

static int mds_getattr(struct ptlrpc_request *req, int offset)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct lvfs_run_ctxt saved;
        struct dentry *de;
        struct mds_body *body;
        struct lvfs_ucred uc = {NULL,};
        int rc = 0;
        ENTRY;

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = mds_init_ucred(&uc, req, offset);
        if (rc)
                GOTO(out_ucred, rc);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        de = mds_fid2dentry(mds, &body->fid1, NULL);
        if (IS_ERR(de)) {
                rc = req->rq_status = PTR_ERR(de);
                GOTO(out_pop, rc);
        }

        rc = mds_getattr_pack_msg(req, de->d_inode, offset);
        if (rc != 0) {
                CERROR("mds_getattr_pack_msg: %d\n", rc);
                GOTO(out_pop, rc);
        }

        req->rq_status = mds_getattr_internal(obd, de, req, body, 0);

        l_dput(de);
        GOTO(out_pop, rc);
out_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
out_ucred:
        if (req->rq_reply_state == NULL) {
                req->rq_status = rc;
                lustre_pack_reply(req, 0, NULL, NULL);
        }
        mds_exit_ucred(&uc, mds);
        return rc;
}


static int mds_obd_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                          unsigned long max_age)
{
        int rc;

        spin_lock(&obd->obd_osfs_lock);
        rc = fsfilt_statfs(obd, obd->u.obt.obt_sb, max_age);
        if (rc == 0)
                memcpy(osfs, &obd->obd_osfs, sizeof(*osfs));
        spin_unlock(&obd->obd_osfs_lock);

        return rc;
}

static int mds_statfs(struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        int rc, size = sizeof(struct obd_statfs);
        ENTRY;

        /* This will trigger a watchdog timeout */
        OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_STATFS_LCW_SLEEP,
                         (MDS_SERVICE_WATCHDOG_TIMEOUT / 1000) + 1);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_STATFS_PACK)) {
                CERROR("mds: statfs lustre_pack_reply failed: rc = %d\n", rc);
                GOTO(out, rc);
        }

        /* We call this so that we can cache a bit - 1 jiffie worth */
        rc = mds_obd_statfs(obd, lustre_msg_buf(req->rq_repmsg, 0, size),
                            jiffies - HZ);
        if (rc) {
                CERROR("mds_obd_statfs failed: rc %d\n", rc);
                GOTO(out, rc);
        }

        EXIT;
out:
        req->rq_status = rc;
        return 0;
}

static int mds_set_info(struct obd_export *exp, struct ptlrpc_request *req)
{
        char *key;
        __u32 *val;
        int keylen, rc = 0;
        ENTRY;

        key = lustre_msg_buf(req->rq_reqmsg, 0, 1);
        if (key == NULL) {
                DEBUG_REQ(D_HA, req, "no set_info key");
                RETURN(-EFAULT);
        }
        keylen = req->rq_reqmsg->buflens[0];

        val = lustre_msg_buf(req->rq_reqmsg, 1, sizeof(*val));
        if (val == NULL) {
                DEBUG_REQ(D_HA, req, "no set_info val");
                RETURN(-EFAULT);
        }

        rc = lustre_pack_reply(req, 0, NULL, NULL);
        if (rc)
                RETURN(rc);
        req->rq_repmsg->status = 0;

        if (keylen < strlen("read-only") ||
            memcmp(key, "read-only", keylen) != 0)
                RETURN(-EINVAL);

        if (*val)
                exp->exp_connect_flags |= OBD_CONNECT_RDONLY;
        else
                exp->exp_connect_flags &= ~OBD_CONNECT_RDONLY;

        RETURN(0);
}

enum mdt_handler_flags {
	/*
	 * struct mds_body is passed in the 0-th incoming buffer.
	 */
	HABEO_CORPUS = (1 << 0)
};

struct mdt_handler {
	const char *mh_name;
	int         mh_fail_id;
	__u32       mh_opc;
	__u32       mh_flags;
	int (*mh_act)(struct mdt_thread_info *info, struct ptlrpc_request *req);
};

#define DEF_HNDL(prefix, base, flags, name, fn)			\
[prefix ## name - prefix ## base] = {				\
	.mh_name    = #name,					\
	.mh_fail_id = OBD_FAIL_ ## prefix ## _  ## opc ## _NET,	\
	.mh_opc     = prefix ## _  ## opc,			\
	.mh_flags   = flags,					\
	.mh_act     = fn					\
}

#define DEF_MDT_HNDL(flags, name, fn) DEF_HNDL(mdt, CONNECT, flags, name, fn)

static struct mdt_handler mdt_mds_ops[] = {
	DEF_MDT_HNDL(0,            CONNECT,        mdt_connect),
	DEF_MDT_HNDL(0,            DISCONNECT,     mdt_disconnect),
	DEF_MDT_HNDL(0,            GETSTATUS,      mdt_getstatus),
	DEF_MDT_HNDL(HABEO_CORPUS, GETATTR,        mdt_getattr),
	DEF_MDT_HNDL(HABEO_CORPUS, GETATTR_NAME,   mdt_getattr_name),
	DEF_MDT_HNDL(HABEO_CORPUS, SETXATTR,       mdt_setxattr),
	DEF_MDT_HNDL(HABEO_CORPUS, GETXATTR,       mdt_getxattr),
	DEF_MDT_HNDL(0,            STATFS,         mdt_statfs),
	DEF_MDT_HNDL(HABEO_CORPUS, READPAGE,       mdt_readpage),
	DEF_MDT_HNDL(0,            REINT,          mdt_reint),
	DEF_MDT_HNDL(HABEO_CORPUS, CLOSE,          mdt_close),
	DEF_MDT_HNDL(HABEO_CORPUS, DONE_WRITING,   mdt_done_writing),
	DEF_MDT_HNDL(0,            PIN,            mdt_pin),
	DEF_MDT_HNDL(HABEO_CORPUS, SYNC,           mdt_sync),
	DEF_MDT_HNDL(0,            0 /*SET_INFO*/, mdt_set_info),
	DEF_MDT_HNDL(0,            QUOTACHECK,     mdt_handle_quotacheck),
	DEF_MDT_HNDL(0,            QUOTACTL,       mdt_handle_quotactl)
};

static struct mdt_handler mdt_obd_ops[] = {
};

static struct mdt_handler mdt_dlm_ops[] = {
};

static struct mdt_handler mdt_llog_ops[] = {
};

static struct mdt_opc_slice {
	__u32               mos_opc_start;
	int                 mos_opc_end;
	struct mdt_handler *mos_hs;
} mdt_handlers[] = {
	{
		.mos_opc_start = MDS_GETATTR,
		.mos_opc_end   = MDS_LAST_OPC,
		.mos_hs        = mdt_mds_ops
	},
	{
		.mos_opc_start = OBD_PING,
		.mos_opc_end   = OBD_LAST_OPC,
		.mos_hs        = mdt_obd_ops
	},
	{
		.mos_opc_start = LDLM_ENQUEUE,
		.mos_opc_end   = LDLM_LAST_OPC,
		.mos_hs        = mdt_dlm_ops
	},
	{
		.mos_opc_start = LLOG_ORIGIN_HANDLE_CREATE,
		.mos_opc_end   = LLOG_LAST_OPC,
		.mos_hs        = mdt_llog_ops
	}
};

enum {
	MDT_REP_BUF_NR_MAX = 8
};

/*
 * Common data shared by mdt-level handlers. This is allocated per-thread to
 * reduce stack consumption.
 */
struct mdt_thread_info {
	struct mdt_device *mti_mdt;
	/*
	 * number of buffers in reply message.
	 */
	int                mti_rep_buf_nr;
	/*
	 * sizes of reply buffers.
	 */
	int                mti_rep_buf_size[MDT_REP_BUF_NR_MAX];
	/*
	 * Body for "habeo corpus" operations.
	 */
	struct mds_body   *mti_body;
	/*
	 * Host object. This is released at the end of mdt_handler().
	 */
	struct mdt_object *mti_object;
	/*
	 * Additional fail id that can be set by handler. Passed to
	 * target_send_reply().
	 */
	int                mti_fail_id;
	/*
	 * Offset of incoming buffers. 0 for top-level request processing. +ve
	 * for intent handling.
	 */
	int                mti_offset;
};

struct mdt_handler *mdt_handler_find(__u32 opc)
{
	int i;
	struct mdt_opc_slice *s;
	struct mdt_handler *h;

	h = NULL;
	for (i = 0, s = mdt_handlers; i < ARRAY_SIZE(mdt_handlers); i++, s++) {
		if (s->mos_opc_start <= opc && opc < s->mos_opc_end) {
			h = s->mos_hs + (opc - s->mos_opc_start);
			if (h->mos_opc != 0)
				LASSERT(h->mos_opc == opc);
			else
				h = NULL; /* unsupported opc */
			break;
		}
	}
	return h;
}

struct mdt_object *mdt_object_find(struct mdt_device *d, struct lfid *f)
{
	struct lu_object *o;

	o = lu_object_find(&d->mdt_lu_dev.ld_site, f);
	if (IS_ERR(o))
		return (struct mdd_object *)o;
	else
		return container_of(o, struct mdt_object, mot_obj.mo_lu);
}

void mdt_object_put(struct mdt_object *o)
{
	lu_object_put(&o->mot_obj.mo_lu);
}

static int mdt_req_handle(struct mdt_thread_info *info,
			  struct mdt_handler *h, struct ptlrpc_request *req,
			  int shift)
{
	int result;

	ENTRY;

	LASSERT(h->mh_act != NULL);
	LASSERT(h->mh_opc == req->rq_reqmsg->opc);

	DEBUG_REQ(D_INODE, req, "%s", h->mh_name);

	if (h->mh_fail_id != 0)
		OBD_FAIL_RETURN(h->mh_fail_id, 0);

	h->mh_offset = MDS_REQ_REC_OFF + shift;
	if (h->mh_flags & HABEO_CORPUS) {
		info->mti_body = lustre_swab_reqbuf(req, h->mh_offset,
						    sizeof *info->mti_body,
						    lustre_swab_mds_body);
		if (info->mti_body == NULL) {
			CERROR("Can't unpack body\n");
			result = req->rq_status = -EFAULT;
		}
		info->mti_object = mdt_object_find(info->mti_mdt,
						   info->mti_body.fid1);
		if (IS_ERR(info->mti_object))
			result = PTR_ERR(info->mti_object);
	}
	if (result == 0)
		result = h->mh_act(info, h, req);
	/*
	 * XXX result value is unconditionally shoved into ->rq_status
	 * (original code sometimes placed error code into ->rq_status, and
	 * sometimes returned it to the
	 * caller). ptlrpc_server_handle_request() doesn't check return value
	 * anyway.
	 */
	req->rq_status = result;
	RETURN(result);
}

static void mdt_thread_info_init(struct mdt_thread_info *info)
{
	memset(info, 0, sizeof *info);
	info->mti_fail_id = OBD_FAIL_MDS_ALL_REPLY_NET;
	/*
	 * Poison size array.
	 */
	for (info->mti_rep_buf_nr = 0;
	     info->mti_rep_buf_nr < MDT_REP_BUF_NR_MAX; info->mti_rep_buf_nr++)
		info->mti_rep_buf_size[info->mti_rep_buf_nr] = ~0;
}

static void mdt_thread_info_fini(struct mdt_thread_info *info)
{
	if (info->mti_object != NULL) {
		mdt_object_put(info->mti_object);
		info->mti_object = NULL;
	}
}

int mdt_handle(struct ptlrpc_request *req)
{
        int should_process,
        int rc = 0;
        struct mds_obd *mds = NULL; /* quell gcc overwarning */
        struct obd_device *obd = NULL;
	struct mdt_thread_info info; /* XXX on stack for now */
	struct mdt_handler *h;

        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_MDS_ALL_REQUEST_NET | OBD_FAIL_ONCE, 0);

        LASSERT(current->journal_info == NULL);

        rc = mds_msg_check_version(req->rq_reqmsg);
        if (rc) {
                CERROR(LUSTRE_MDT0_NAME" drops mal-formed request\n");
                RETURN(rc);
        }

        /* XXX identical to OST */
        if (req->rq_reqmsg->opc != MDS_CONNECT) {
                struct mds_export_data *med;
                int recovering, abort_recovery;

                if (req->rq_export == NULL) {
                        CERROR("operation %d on unconnected MDS from %s\n",
                               req->rq_reqmsg->opc,
                               libcfs_id2str(req->rq_peer));
                        req->rq_status = -ENOTCONN;
                        GOTO(out, rc = -ENOTCONN);
                }

                med = &req->rq_export->exp_mds_data;
                obd = req->rq_export->exp_obd;
                mds = &obd->u.mds;

                /* sanity check: if the xid matches, the request must
                 * be marked as a resent or replayed */
                if (req->rq_xid == med->med_mcd->mcd_last_xid)
                        LASSERTF(lustre_msg_get_flags(req->rq_reqmsg) &
                                 (MSG_RESENT | MSG_REPLAY),
                                 "rq_xid "LPU64" matches last_xid, "
                                 "expected RESENT flag\n",
                                 req->rq_xid);
                /* else: note the opposite is not always true; a
                 * RESENT req after a failover will usually not match
                 * the last_xid, since it was likely never
                 * committed. A REPLAYed request will almost never
                 * match the last xid, however it could for a
                 * committed, but still retained, open. */

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

	h = mdt_handler_find(req->rq_reqmsg->opc);
	if (h != NULL) {
		rc = mdt_handle_req(&info, h, req, 0);
	} else {
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req);
                RETURN(rc);
	}

        LASSERT(current->journal_info == NULL);

        /* If we're DISCONNECTing, the mds_export_data is already freed */
        if (!rc && req->rq_reqmsg->opc != MDS_DISCONNECT) {
                struct mds_export_data *med = &req->rq_export->exp_mds_data;
                req->rq_repmsg->last_xid =
                        le64_to_cpu(med->med_mcd->mcd_last_xid);

                target_committed_to_req(req);
        }

        EXIT;
 out:

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_LAST_REPLAY) {
                if (obd && obd->obd_recovering) {
                        DEBUG_REQ(D_HA, req, "LAST_REPLAY, queuing reply");
                        return target_queue_final_reply(req, rc);
                }
                /* Lost a race with recovery; let the error path DTRT. */
                rc = req->rq_status = -ENOTCONN;
        }

        target_send_reply(req, rc, info.mti_fail_id);
        return 0;
}

static int mdt_intent_policy(struct ldlm_namespace *ns,
                             struct ldlm_lock **lockp, void *req_cookie,
                             ldlm_mode_t mode, int flags, void *data)
{
	RETURN(ELDLM_LOCK_ABORTED);
}

struct ptlrpc_service *ptlrpc_init_svc_conf(struct ptlrpc_service_conf *c,
					    svc_handler_t h, char *name,
					    struct proc_dir_entry *proc_entry,
					    svcreq_printfn_t prntfn)
{
	return ptlrpc_init_svc(c->psc_nbufs, c->psc_bufsize,
			       c->psc_max_req_size, c->psc_max_reply_size,
			       c->psc_req_portal, c->psc_rep_portal,
			       c->psc_watchdog_timeout,
			       h, char name, proc_entry,
			       prntfn, c->psc_num_threads);
}

int md_device_init(struct md_device *md)
{
	return lu_device_init(&md->md_lu_dev);
}

void md_device_fini(struct md_device *md)
{
	lu_device_fini(&md->md_lu_dev);
}

static struct lu_device_operations mdt_lu_ops;

static int mdt_device_init(struct mdt_device *m)
{
	md_device_init(&m->mdt_md_dev);

	m->mdt_md_dev.md_lu_dev.ld_ops = &mdt_lu_ops;

	m->mdt_service_conf.psc_nbufs            = MDS_NBUFS;
	m->mdt_service_conf.psc_bufsize          = MDS_BUFSIZE;
	m->mdt_service_conf.psc_max_req_size     = MDS_MAXREQSIZE;
	m->mdt_service_conf.psc_max_reply_size   = MDS_MAXREPSIZE;
	m->mdt_service_conf.psc_req_portal       = MDS_REQUEST_PORTAL;
	m->mdt_service_conf.psc_rep_portal       = MDC_REPLY_PORTAL;
	m->mdt_service_conf.psc_watchdog_timeout = MDS_SERVICE_WATCHDOG_TIMEOUT;
	/*
	 * We'd like to have a mechanism to set this on a per-device basis,
	 * but alas...
	 */
        if (mds_num_threads < 2)
                mds_num_threads = MDS_DEF_THREADS;
	m->mdt_service_conf.psc_num_threads = min(mds_num_threads,
						  MDS_MAX_THREADS);
	return 0;
}

static void mdt_device_fini(struct mdt_device *m)
{
	md_device_fini(&m->mdt_md_dev);
}

static int lu_device_is_mdt(struct lu_device *d)
{
	/*
	 * XXX for now. Tags in lu_device_type->ldt_something are needed.
	 */
	return ergo(d->ld_ops != NULL, d->ld_ops == &mdt_lu_ops);
}

static struct mdt_device *mdt_dev(struct lu_device *d)
{
	LASSERT(lu_device_is_mdt(d));
	return container_of(d, struct mdt_device, mdt_lu_dev);
}

static struct mdt_object *mdt_obj(struct lu_object *o)
{
	LASSERT(lu_device_is_mdt(o->lo_dev));
	return container_of(o, struct mdt_object, mot_obj.mo_lu);
}

static void mdt_fini(struct lu_device *d)
{
	struct mdt_device *m = mdt_dev(d);

	if (d->ld_site != NULL) {
		lu_site_fini(d->ld_site);
		d->ld_site = NULL;
	}
	if (m->mdt_service != NULL) {
		ptlrpc_unregister_service(m->mdt_service);
		m->mdt_service = NULL;
	}
	if (m->mdt_namespace != NULL) {
		ldlm_namespace_free(m->mdt_namespace, 0);
		m->mdt_namespace = NULL;
	}
	
	LASSERT(atomic_read(&d->ld_ref) == 0);
}

static int mdt_init0(struct lu_device *d)
{
	struct mdt_device *m = mdt_dev(d);
	struct lu_site *s;
        char   ns_name[48];

        ENTRY;

	OBD_ALLOC_PTR(s);
	if (s == NULL)
		return -ENOMEM;

	mdt_device_init(m);
	lu_site_init(s, m);

        snprintf(ns_name, sizeof ns_name, LUSTRE_MDT0_NAME"-%p", m);
        m->mdt_namespace = ldlm_namespace_new(ns_name, LDLM_NAMESPACE_SERVER);
        if (m->mdt_namespace == NULL)
		return -ENOMEM;
        ldlm_register_intent(m->mst_namespace, mdt_intent_policy);

        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "mdt_ldlm_client", &m->mdt_ldlm_client);

        m->mdt_service = ptlrpc_init_svc_conf(&mdt->mdt_service_conf,
					      mdt_handle, LUSTRE_MDT0_NAME,
					      mdt->mdt_lu_dev.ld_proc_entry
					      NULL);
	if (m->mdt_service == NULL)
		return -ENOMEM;

	return ptlrpc_start_threads(NULL, m->mdt_service, LUSTRE_MDT0_NAME);
}

static int mdt_init(struct lu_device *d)
{
	int result;

	result = mdt_init0(d);
	if (result != 0)
		mdt_fini(d);
	return result;
}

struct lu_object *mdt_object_alloc(struct lu_device *d)
{
	struct mdt_object *mo;

	OBD_ALLOC_PTR(mo);
	if (mo != NULL) {
		struct lu_object *o;
		struct lu_object_header *h;

		o = &mo->mot_obj.mo_lu;
		h = &mo->mot_header;
		lu_object_header_init(h);
		lu_object_init(o, h, d);
		/* ->lo_depth and ->lo_flags are automatically 0 */
		lu_object_add_top(h, o);
	} else
		return NULL;
}

int mdt_object_init(struct lu_object *o)
{
	struct mdt_device *d = mdt_dev(o->lo_dev);
	struct lu_device  *under;
	struct lu_object  *below;

	under = &d->mdt_mdd->md_lu_dev;
	below = under->ld_ops->ldo_alloc(under);
	if (below != NULL) {
		lu_object_add(o, below);
		return 0;
	} else
		return -ENOMEM;
}

void mdt_object_free(struct lu_object *o)
{
	struct lu_object_header;

	h = o->lo_header;
	lu_object_fini(o);
	lu_object_header_fini(h);
}

void mdt_object_release(struct lu_object *o)
{
}

int mdt_object_print(struct seq_file *f, const struct lu_object *o)
{
	return seq_printf(f, LUSTRE_MDT0_NAME"-object@%p", o);
}

static struct lu_device_operations mdt_lu_ops = {
	.ldo_init           = mdt_init,
	.ldo_fini           = mdt_fini,
	.ldo_object_alloc   = mdt_object_alloc,
	.ldo_object_init    = mdt_object_init,
	.ldo_object_free    = mdt_object_free,
	.ldo_object_release = mdt_object_release,
	.ldo_object_print   = mdt_object_print
}

int mdt_mkdir(struct mdt_device *d, struct lfid *pfid, const char *name)
{
	struct mdt_object *o;
	struct lock_handle lh;
	int result;

	o = mdt_object_find(d, pfid);
	if (IS_ERR(o))
		return PTR_ERR(o);
	result = fid_lock(pfid, LCK_PW, &lh);
	if (result == 0) {
		result = d->mdt_dev.md_ops->mdo_mkdir(o, name);
		fid_unlock(&lh);
	}
	mdt_object_put(o);
	return result;
}

static struct obd_ops mdt_ops = {
        .o_owner           = THIS_MODULE,
        .o_connect         = mds_connect,
        .o_reconnect       = mds_reconnect,
        .o_init_export     = mds_init_export,
        .o_destroy_export  = mds_destroy_export,
        .o_disconnect      = mds_disconnect,
        .o_setup           = mds_setup,
        .o_precleanup      = mds_precleanup,
        .o_cleanup         = mds_cleanup,
        .o_postrecov       = mds_postrecov,
        .o_statfs          = mds_obd_statfs,
        .o_iocontrol       = mds_iocontrol,
        .o_create          = mds_obd_create,
        .o_destroy         = mds_obd_destroy,
        .o_llog_init       = mds_llog_init,
        .o_llog_finish     = mds_llog_finish,
        .o_notify          = mds_notify,
        .o_health_check    = mds_health_check,
};

static int __init mdt_mod_init(void)
{
	return 0;
}

static void __exit mdt_mod_exit(void)
{
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Meta-data Target Prototype ("LUSTRE_MDT0_NAME")");
MODULE_LICENSE("GPL");

CFS_MODULE_PARM(mdt_num_threads, "i", int, 0444,
                "number of mdt service threads to start");

cfs_module(mdt, "0.0.2", mdt_mod_init, mdt_mod_exit);

#endif /* 0 */
