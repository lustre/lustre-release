/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mdt/mdt_xattr.c
 *  Lustre Metadata Target (mdt) extended attributes management.
 *
 *  Copyright (C) 2002-2006 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Huang Hua <huanghua@clusterfs.com>
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

/* prerequisite for linux/xattr.h */
#include <linux/types.h>
/* prerequisite for linux/xattr.h */
#include <linux/fs.h>
/* XATTR_{REPLACE,CREATE} */
#include <linux/xattr.h>

#include "mdt_internal.h"


/* return EADATA length to the caller. negative value means error */
static int mdt_getxattr_pack_reply(struct mdt_thread_info * info)
{
        struct req_capsule     *pill = &info->mti_pill ;
        struct ptlrpc_request  *req = mdt_info_req(info);
        char                   *xattr_name;
        __u64                   valid = info->mti_body->valid;
        static const char       user_string[] = "user.";
        int                     size, rc;
        ENTRY;
        
        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_GETXATTR_PACK))
                RETURN(-ENOMEM);

        /* Determine how many bytes we need */
        if ((valid & OBD_MD_FLXATTR) == OBD_MD_FLXATTR) {
                xattr_name = req_capsule_client_get(pill, &RMF_NAME);
                if (!xattr_name)
                        RETURN(-EFAULT);

                if (!(req->rq_export->exp_connect_flags & OBD_CONNECT_XATTR) &&
                    !strncmp(xattr_name, user_string, sizeof(user_string) - 1))
                        RETURN(-EOPNOTSUPP);
                
                if (!strcmp(xattr_name, XATTR_NAME_LUSTRE_ACL))
                        size = RMTACL_SIZE_MAX;
                else
                        size = mo_xattr_get(info->mti_env,
                                            mdt_object_child(info->mti_object),
                                            &LU_BUF_NULL, xattr_name);
        } else if ((valid & OBD_MD_FLXATTRLS) == OBD_MD_FLXATTRLS) {
                size = mo_xattr_list(info->mti_env,
                                     mdt_object_child(info->mti_object),
                                     &LU_BUF_NULL);
        } else {
                CERROR("Valid bits: "LPX64"\n", info->mti_body->valid);
                RETURN(-EINVAL);
        }

        if (size < 0) {
                if (size == -ENODATA)
                        size = 0;
                else if (size != -EOPNOTSUPP) {
                        CERROR("Error geting EA size: %d\n", size);
                        RETURN(size);
                }
        }

        if (info->mti_body->eadatasize != 0 &&
            info->mti_body->eadatasize < size)
                RETURN(-ERANGE);

        req_capsule_set_size(pill, &RMF_EADATA, RCL_SERVER,
                             min_t(int, size, info->mti_body->eadatasize));

        rc = req_capsule_pack(pill);
        if (rc) {
                LASSERT(rc < 0);
                RETURN(rc);
        }

        RETURN(size);
}

static int do_remote_getfacl(struct mdt_thread_info *info, struct lu_buf *buf)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        char *cmd;
        int rc;
        ENTRY;

        if (!buf->lb_buf || (buf->lb_len != RMTACL_SIZE_MAX))
                RETURN(-EINVAL);

        cmd = req_capsule_client_get(&info->mti_pill, &RMF_EADATA);
        if (!cmd) {
                CERROR("missing getfacl command!\n");
                RETURN(-EFAULT);
        }

        rc = mdt_rmtacl_upcall(info, cmd, buf);
        if (rc)
                CERROR("remote acl upcall failed: %d\n", rc);

        lustre_shrink_reply(req, REPLY_REC_OFF + 1, strlen(buf->lb_buf) + 1, 0);
        RETURN(rc ?: strlen(buf->lb_buf) + 1);
}

int mdt_getxattr(struct mdt_thread_info *info)
{
        struct  mdt_body       *reqbody;
        struct  mdt_body       *repbody;
        struct  md_object      *next;
        struct  lu_buf         *buf;
        int                     easize, rc;
        ENTRY;

        LASSERT(info->mti_object != NULL);
        LASSERT(lu_object_assert_exists(&info->mti_object->mot_obj.mo_lu));

        CDEBUG(D_INODE, "getxattr "DFID"\n", PFID(&info->mti_body->fid1));

        reqbody = req_capsule_client_get(&info->mti_pill, &RMF_MDT_BODY);
        if (reqbody == NULL)
                RETURN(err_serious(-EFAULT));

        rc = mdt_init_ucred(info, reqbody);
        if (rc)
                RETURN(err_serious(rc));

        easize = mdt_getxattr_pack_reply(info);
        if (easize < 0)
                GOTO(out, rc = err_serious(easize));

        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        LASSERT(repbody != NULL);

        /* No need further getxattr. */
        if (easize == 0 || reqbody->eadatasize == 0)
                GOTO(out, rc = easize);

        buf = &info->mti_buf;
        buf->lb_buf = req_capsule_server_get(&info->mti_pill, &RMF_EADATA);
        buf->lb_len = easize;
        next = mdt_object_child(info->mti_object);

        if (info->mti_body->valid & OBD_MD_FLXATTR) {
                char *xattr_name = req_capsule_client_get(&info->mti_pill,
                                                          &RMF_NAME);
                CDEBUG(D_INODE, "getxattr %s\n", xattr_name);

                if (!strcmp(xattr_name, XATTR_NAME_LUSTRE_ACL))
                        rc = do_remote_getfacl(info, buf);
                else
                        rc = mo_xattr_get(info->mti_env, next, buf, xattr_name);

                if (rc < 0)
                        CERROR("getxattr failed: %d\n", rc);
        } else if (info->mti_body->valid & OBD_MD_FLXATTRLS) {
                CDEBUG(D_INODE, "listxattr\n");

                rc = mo_xattr_list(info->mti_env, next, buf);
                if (rc < 0)
                        CERROR("listxattr failed: %d\n", rc);
        } else
                LBUG();

        EXIT;
out:
        if (rc >= 0) {
                repbody->eadatasize = rc;
                rc = 0;
        }
        mdt_exit_ucred(info);
        return rc;
}

/* return EADATA length to the caller. negative value means error */
static int mdt_setxattr_pack_reply(struct mdt_thread_info * info)
{
        struct req_capsule     *pill = &info->mti_pill ;
        __u64                   valid = info->mti_body->valid;
        int                     rc = 0, rc1;

        if ((valid & OBD_MD_FLXATTR) == OBD_MD_FLXATTR) {
                char *xattr_name;

                xattr_name = req_capsule_client_get(pill, &RMF_NAME);
                if (!xattr_name)
                        return -EFAULT;

                if (!strcmp(xattr_name, XATTR_NAME_LUSTRE_ACL))
                        rc = RMTACL_SIZE_MAX;
        }

        req_capsule_set_size(pill, &RMF_EADATA, RCL_SERVER, rc);

        rc1 = req_capsule_pack(pill);

        return rc = rc1 ? rc1 : rc;
}

static int do_remote_setfacl(struct mdt_thread_info *info)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        struct lu_buf         *buf = &info->mti_buf;
        char *cmd;
        int rc;
        ENTRY;

        cmd = req_capsule_client_get(&info->mti_pill, &RMF_EADATA);
        if (!cmd) {
                CERROR("missing setfacl command!\n");
                RETURN(-EFAULT);
        }

        buf->lb_buf = req_capsule_server_get(&info->mti_pill, &RMF_EADATA);
        LASSERT(buf->lb_buf);
        buf->lb_len = RMTACL_SIZE_MAX;

        rc = mdt_rmtacl_upcall(info, cmd, buf);
        if (rc)
                CERROR("remote acl upcall failed: %d\n", rc);

        lustre_shrink_reply(req, REPLY_REC_OFF, strlen(buf->lb_buf) + 1, 0);
        RETURN(rc);
}

int mdt_setxattr(struct mdt_thread_info *info)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct mdt_body         *reqbody;
        const char               user_string[] = "user.";
        const char               trust_string[] = "trusted.";
        struct mdt_lock_handle  *lh;
        struct req_capsule      *pill = &info->mti_pill;
        struct mdt_object       *obj  = info->mti_object;
        struct mdt_body         *body = (struct mdt_body *)info->mti_body;
        const struct lu_env     *env  = info->mti_env;
        struct md_object        *child  = mdt_object_child(obj);
        struct lu_buf           *buf  = &info->mti_buf;
        __u64                    valid  = body->valid;
        char                    *xattr_name;
        int                      xattr_len;
        __u64                    lockpart;
        int                      rc;
        ENTRY;

        CDEBUG(D_INODE, "setxattr "DFID"\n", PFID(&body->fid1));

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_SETXATTR))
                RETURN(err_serious(-ENOMEM));

        reqbody = req_capsule_client_get(pill, &RMF_MDT_BODY);
        if (reqbody == NULL)
                RETURN(err_serious(-EFAULT));

        rc = mdt_init_ucred(info, reqbody);
        if (rc)
                RETURN(err_serious(rc));

        rc = mdt_setxattr_pack_reply(info);
        if (rc < 0)
                GOTO(out, rc = err_serious(rc));

        /* various sanity check for xattr name */
        xattr_name = req_capsule_client_get(pill, &RMF_NAME);
        if (!xattr_name)
                GOTO(out, rc = err_serious(-EFAULT));

        CDEBUG(D_INODE, "%s xattr %s\n",
                  body->valid & OBD_MD_FLXATTR ? "set" : "remove", xattr_name);

        if (((valid & OBD_MD_FLXATTR) == OBD_MD_FLXATTR) &&
            (!strcmp(xattr_name, XATTR_NAME_LUSTRE_ACL))) {
                rc = do_remote_setfacl(info);
                GOTO(out, rc);
        }

        if (strncmp(xattr_name, trust_string, sizeof(trust_string) - 1) == 0) {
                if (strcmp(xattr_name + 8, XATTR_NAME_LOV) == 0)
                        GOTO(out, rc = -EACCES);
        }

        if (!(req->rq_export->exp_connect_flags & OBD_CONNECT_XATTR) &&
            (strncmp(xattr_name, user_string, sizeof(user_string) - 1) == 0)) {
                GOTO(out, rc = -EOPNOTSUPP);
        }

        lockpart = MDS_INODELOCK_UPDATE;
        if (!strcmp(xattr_name, XATTR_NAME_ACL_ACCESS))
                lockpart |= MDS_INODELOCK_LOOKUP;

        lh = &info->mti_lh[MDT_LH_PARENT];
        mdt_lock_pdo_init(lh, LCK_PW, NULL, 0);
        rc = mdt_object_lock(info, obj, lh, lockpart, MDT_LOCAL_LOCK);
        if (rc != 0)
                GOTO(out, rc);

        if ((valid & OBD_MD_FLXATTR) == OBD_MD_FLXATTR) {
                char * xattr;
                if (!req_capsule_field_present(pill, &RMF_EADATA, RCL_CLIENT)) {
                        CERROR("no xattr data supplied\n");
                        GOTO(out_unlock, rc = -EFAULT);
                }

                xattr_len = req_capsule_get_size(pill, &RMF_EADATA, RCL_CLIENT);
                if (xattr_len) {
                        int flags = 0;
                        xattr = req_capsule_client_get(pill, &RMF_EADATA);

                        if (body->flags & XATTR_REPLACE)
                                flags |= LU_XATTR_REPLACE;

                        if (body->flags & XATTR_CREATE)
                                flags |= LU_XATTR_CREATE;

                        mdt_fail_write(env, info->mti_mdt->mdt_bottom,
                                       OBD_FAIL_MDS_SETXATTR_WRITE);

                        buf->lb_buf = xattr;
                        buf->lb_len = xattr_len;
                        rc = mo_xattr_set(env, child, buf, xattr_name, flags);
                }
        } else if ((valid & OBD_MD_FLXATTRRM) == OBD_MD_FLXATTRRM) {
                rc = mo_xattr_del(env, child, xattr_name);
        } else {
                CERROR("valid bits: "LPX64"\n", body->valid);
                rc = -EINVAL;
        }
        EXIT;
out_unlock:
        mdt_object_unlock(info, obj, lh, rc);
out:
        mdt_exit_ucred(info);
        return rc;
}
