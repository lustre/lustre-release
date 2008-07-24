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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mds/mds_xattr.c
 *
 * Lustre Metadata Server (mds) extended attributes handling
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

#include "mds_internal.h" 

#ifndef XATTR_NAME_ACL_ACCESS
#define XATTR_NAME_ACL_ACCESS   "system.posix_acl_access"
#endif

static int mds_getxattr_pack_msg(struct ptlrpc_request *req,
                                 struct dentry *de,
                                 struct mds_body *body)
{
        struct inode *inode = de->d_inode;
        char *xattr_name;
        int size[3] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        int bufcnt = 2, rc = -EOPNOTSUPP, rc2;

        if (inode == NULL)
                return -ENOENT;

        if (body->valid & OBD_MD_FLXATTR) {
                xattr_name = lustre_msg_string(req->rq_reqmsg, REQ_REC_OFF+1,0);
                if (!xattr_name) {
                        CERROR("can't extract xattr name\n");
                        return -EFAULT;
                }

                if (!(req->rq_export->exp_connect_flags & OBD_CONNECT_XATTR) &&
                    (strncmp(xattr_name, "user.", 5) == 0))
                        return -EOPNOTSUPP;

                if (inode->i_op && inode->i_op->getxattr)
                        rc = inode->i_op->getxattr(de, xattr_name, NULL, 0);
        } else if (body->valid & OBD_MD_FLXATTRLS) {
                if (inode->i_op && inode->i_op->listxattr)
                        rc = inode->i_op->listxattr(de, NULL, 0);
        } else {
                CERROR("valid bits: "LPX64"\n", body->valid);
                return -EINVAL;
        }

        if (rc < 0) {
                if (rc != -ENODATA && rc != -EOPNOTSUPP)
                        CWARN("get inode %lu EA size error: %d\n",
                              inode->i_ino, rc);
                bufcnt = 1;
        } else {
                size[bufcnt++] = min_t(int, body->eadatasize, rc);
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETXATTR_PACK)) {
                CERROR("failed MDS_GETXATTR_PACK test\n");
                req->rq_status = -ENOMEM;
                return -ENOMEM;
        }

        rc2 = lustre_pack_reply(req, bufcnt, size, NULL);
        if (rc2)
                return rc2;

        if (rc < 0)
                req->rq_status = rc;
        return 0;
}

static int mds_getxattr_internal(struct obd_device *obd,
                                 struct dentry *dentry,
                                 struct ptlrpc_request *req,
                                 struct mds_body *reqbody)
{
        struct mds_body *repbody;
        struct inode *inode = dentry->d_inode;
        char *xattr_name;
        void *buf = NULL;
        int buflen, rc = -EOPNOTSUPP;
        ENTRY;

        if (inode == NULL)
                GOTO(out, rc = -ENOENT);

        repbody = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                 sizeof(*repbody));
        LASSERT(repbody != NULL);

        buflen = lustre_msg_buflen(req->rq_repmsg, REPLY_REC_OFF + 1);
        if (buflen)
                buf = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF + 1, buflen);

        if (reqbody->valid & OBD_MD_FLXATTR) {
                xattr_name = lustre_msg_string(req->rq_reqmsg, REQ_REC_OFF+1,0);
                DEBUG_REQ(D_INODE, req, "getxattr %s", xattr_name);

                if (inode->i_op && inode->i_op->getxattr) {
                        lock_24kernel();
                        rc = inode->i_op->getxattr(dentry, xattr_name,
                                                   buf, buflen);
                        unlock_24kernel();
                }

                if (rc < 0 && rc != -ENODATA && rc != -EOPNOTSUPP &&
                    rc != -ERANGE)
                        CDEBUG(D_OTHER, "getxattr failed: %d\n", rc);
        } else if (reqbody->valid & OBD_MD_FLXATTRLS) {
                DEBUG_REQ(D_INODE, req, "listxattr");

                if (inode->i_op && inode->i_op->listxattr) {
                        lock_24kernel();
                        rc = inode->i_op->listxattr(dentry, buf, buflen);
                        unlock_24kernel();
                }
                if (rc < 0)
                        CDEBUG(D_OTHER, "listxattr failed: %d\n", rc);
        } else
                LBUG();

        if (rc >= 0) {
                repbody->eadatasize = rc;
                rc = 0;
        }
out:
        req->rq_status = rc;
        RETURN(0);
}

int mds_getxattr(struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct lvfs_run_ctxt saved;
        struct dentry *de;
        struct mds_body *body;
        struct lvfs_ucred uc = { NULL, };
        int rc = 0;
        ENTRY;

        mds_counter_incr(req->rq_export, LPROC_MDS_GETXATTR);

        body = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = mds_init_ucred(&uc, req, REQ_REC_OFF);
        if (rc)
                GOTO(out_ucred, rc);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        de = mds_fid2dentry(mds, &body->fid1, NULL);
        if (IS_ERR(de)) {
                rc = req->rq_status = PTR_ERR(de);
                GOTO(out_pop, rc);
        }

        rc = mds_getxattr_pack_msg(req, de, body);
        if (rc != 0 || req->rq_status)
                GOTO(out_dput, rc);

        rc = mds_getxattr_internal(obd, de, req, body);

out_dput:
        l_dput(de);
out_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
out_ucred:
        mds_exit_ucred(&uc, mds);
        return rc;
}

/*
 * alwasy return 0, and set req->rq_status as error number in case
 * of failures.
 */
static
int mds_setxattr_internal(struct ptlrpc_request *req, struct mds_body *body)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *de;
        struct inode *inode = NULL;
        struct inode *inodes[PTLRPC_NUM_VERSIONS] = { NULL };
        struct lustre_handle lockh;
        void *handle = NULL;
        char *xattr_name;
        char *xattr = NULL;
        int xattrlen;
        int rc = -EOPNOTSUPP, err = 0, sync = 0;
        __u64 lockpart;
        ENTRY;

        LASSERT(body);

        DEBUG_REQ(D_INODE, req, "setxattr "LPU64"/%u",
                  body->fid1.id, body->fid1.generation);

        MDS_CHECK_RESENT(req, mds_reconstruct_generic(req));

        lockpart = MDS_INODELOCK_UPDATE;

        /* various sanity check for xattr name */
        xattr_name = lustre_msg_string(req->rq_reqmsg, REQ_REC_OFF + 1, 0);
        if (!xattr_name) {
                CERROR("can't extract xattr name\n");
                GOTO(out, rc = -EPROTO);
        }

        DEBUG_REQ(D_INODE, req, "%sxattr %s",
                  body->valid & OBD_MD_FLXATTR ? "set" : "remove",
                  xattr_name);

        if (strncmp(xattr_name, "trusted.", 8) == 0) {
                if (strcmp(xattr_name + 8, XATTR_LUSTRE_MDS_LOV_EA) == 0)
                        GOTO(out, rc = -EACCES);
        }

        if (!(req->rq_export->exp_connect_flags & OBD_CONNECT_XATTR) &&
            (strncmp(xattr_name, "user.", 5) == 0)) {
                GOTO(out, rc = -EOPNOTSUPP);
        }

        if (!strcmp(xattr_name, XATTR_NAME_ACL_ACCESS))
                lockpart |= MDS_INODELOCK_LOOKUP;

        de = mds_fid2locked_dentry(obd, &body->fid1, NULL, LCK_EX,
                                   &lockh, NULL, 0, lockpart);
        if (IS_ERR(de))
                GOTO(out, rc = PTR_ERR(de));

        inode = de->d_inode;
        LASSERT(inode);

        OBD_FAIL_WRITE(obd, OBD_FAIL_MDS_SETXATTR_WRITE, inode->i_sb);

        /* version recovery check */
        rc = mds_version_get_check(req, inode, 0);
        if (rc)
                GOTO(out_dput, rc);

        /* filter_op simply use setattr one */
        handle = fsfilt_start(obd, inode, FSFILT_OP_SETATTR, NULL);
        if (IS_ERR(handle))
                GOTO(out_dput, rc = PTR_ERR(handle));

        if (body->valid & OBD_MD_FLXATTR) {
                if (inode->i_op && inode->i_op->setxattr) {
                        if (lustre_msg_bufcount(req->rq_reqmsg) < 4) {
                                CERROR("no xattr data supplied\n");
                                GOTO(out_trans, rc = -EFAULT);
                        }

                        xattrlen = lustre_msg_buflen(req->rq_reqmsg,
                                                     REQ_REC_OFF + 2);
                        if (xattrlen)
                                xattr = lustre_msg_buf(req->rq_reqmsg,
                                                       REQ_REC_OFF+2, xattrlen);

                        LOCK_INODE_MUTEX(inode);
                        lock_24kernel();
                        rc = inode->i_op->setxattr(de, xattr_name, xattr,
                                                   xattrlen, body->flags);
                        unlock_24kernel();
                        UNLOCK_INODE_MUTEX(inode);
                }
        } else if (body->valid & OBD_MD_FLXATTRRM) {
                if (inode->i_op && inode->i_op->removexattr) {
                        LOCK_INODE_MUTEX(inode);
                        lock_24kernel();
                        rc = inode->i_op->removexattr(de, xattr_name);
                        unlock_24kernel();
                        UNLOCK_INODE_MUTEX(inode);
                }
        } else {
                CERROR("valid bits: "LPX64"\n", body->valid);
                rc = -EINVAL;
        }

        LASSERT(rc <= 0);
out_trans:
        /* security-replated changes may require sync */
        if (!strcmp(xattr_name, XATTR_NAME_ACL_ACCESS))
                sync = mds->mds_sync_permission;
        inodes[0] = inode;
        err = mds_finish_transno(mds, inodes, handle, req, rc, 0, sync);
out_dput:
        l_dput(de);
        if (rc)
                ldlm_lock_decref(&lockh, LCK_EX);
        else
                ptlrpc_save_lock (req, &lockh, LCK_EX);

        if (err && !rc)
                rc = err;
out:
        req->rq_status = rc;
        return 0;
}

int mds_setxattr(struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct lvfs_run_ctxt saved;
        struct mds_body *body;
        struct lvfs_ucred uc = { NULL, };
        int rc;
        ENTRY;

        mds_counter_incr(req->rq_export, LPROC_MDS_SETXATTR);

        body = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL)
                RETURN(-EFAULT);

        if (lustre_msg_bufcount(req->rq_reqmsg) < 3)
                RETURN(-EFAULT);

        rc = mds_init_ucred(&uc, req, REQ_REC_OFF);
        if (rc)
                GOTO(out_ucred, rc);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);

        rc = lustre_pack_reply(req, 1, NULL, NULL);
        if (rc)
                GOTO(out_pop, rc);

        rc = mds_setxattr_internal(req, body);

out_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
out_ucred:
        mds_exit_ucred(&uc, mds);
        return rc;
}
