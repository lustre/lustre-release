/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mdt/mdt_reint.c
 *  Lustre Metadata Target (mdt) reintegration routines
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

#include "mdt_internal.h"


/* return EADATA length to the caller. negative value means error */
static int mdt_getxattr_pack_reply(struct mdt_thread_info * info)
{
        char *xattr_name;
        int rc = -EOPNOTSUPP, rc2;
        struct req_capsule *pill;
        struct ptlrpc_request *req = mdt_info_req(info);

        pill = &info->mti_pill;

        /* Imagine how many bytes we need */
        if (info->mti_body->valid & OBD_MD_FLXATTR) {
                xattr_name = req_capsule_client_get(pill, &RMF_NAME);
                if (!xattr_name) {
                        CERROR("can't extract xattr name for getxattr\n");
                        return -EFAULT;
                }

                if (!(req->rq_export->exp_connect_flags & OBD_CONNECT_XATTR) &&
                    (strncmp(xattr_name, "user.", 5) == 0))
                        return -EOPNOTSUPP;

                rc = mo_xattr_get(info->mti_ctxt, 
                                  mdt_object_child(info->mti_object), 
                                  NULL, 0, xattr_name);
        } else if (info->mti_body->valid & OBD_MD_FLXATTRLS) {
                rc = mo_xattr_list(info->mti_ctxt, 
                                   mdt_object_child(info->mti_object),
                                   NULL, 0);
        } else {
                CERROR("valid bits: "LPX64"\n", info->mti_body->valid);
                return -EINVAL;
        }

        if (rc < 0) {
                if (rc != -ENODATA && rc != -EOPNOTSUPP)
                        CWARN("get EA size error: %d\n", rc);
                /* return empty to client */
                req_capsule_extend(&info->mti_pill, &RQF_MDS_SETXATTR);
        } else {
                rc =  min_t(int, info->mti_body->eadatasize, rc);
                req_capsule_set_size(pill, &RMF_EADATA, RCL_SERVER, rc);
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETXATTR_PACK)) {
                CERROR("failed MDS_GETXATTR_PACK test\n");
                req->rq_status = -ENOMEM;
                return -ENOMEM;
        }

        rc2 = req_capsule_pack(pill);
        if (rc2)
                return rc2;

        if (rc < 0)
                req->rq_status = rc;
        return rc;
}


int mdt_getxattr(struct mdt_thread_info *info)
{
        int     rc;
        struct  md_object *next;
        char   *buf;
        int     buflen;
        struct  mdt_body *rep_body;

        ENTRY;

        LASSERT(info->mti_object != NULL);
        LASSERT(lu_object_exists(info->mti_ctxt,
                                 &info->mti_object->mot_obj.mo_lu));
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETXATTR_PACK)) {
                CERROR(LUSTRE_MDT0_NAME": getxattr lustre_pack_reply failed\n");
                RETURN(rc = -ENOMEM);
        }

        next = mdt_object_child(info->mti_object);

        buflen = mdt_getxattr_pack_reply(info);
        if (buflen < 0)
                RETURN(rc = buflen);
        buf = req_capsule_server_get(&info->mti_pill,
                                     &RMF_EADATA);
        rep_body = req_capsule_server_get(&info->mti_pill,
                                          &RMF_MDT_BODY);

        if (info->mti_body->valid & OBD_MD_FLXATTR) {
                char *xattr_name = req_capsule_client_get(&info->mti_pill, 
                                                          &RMF_NAME);
                CDEBUG(S_MDS, "getxattr %s\n", xattr_name);

                rc = mo_xattr_get(info->mti_ctxt, next, 
                                   buf, buflen, xattr_name);

                if (rc < 0 && rc != -ENODATA && rc != -EOPNOTSUPP &&
                    rc != -ERANGE)
                        CDEBUG(S_MDS, "getxattr failed: %d\n", rc);
        } else if (info->mti_body->valid & OBD_MD_FLXATTRLS) {
                CDEBUG(S_MDS, "listxattr\n");

                rc = mo_xattr_list(info->mti_ctxt, next, buf, buflen);
                if (rc < 0)
                        CDEBUG(D_OTHER, "listxattr failed: %d\n", rc);
        } else
                LBUG();

        if (rc >= 0) {
                rep_body->eadatasize = rc;
                rc = 0;
        }

        RETURN(rc);
        return 0;
}


int mdt_setxattr(struct mdt_thread_info *info)
{
        int    rc;
        char  *xattr_name;
        int    xattr_len;
        struct ptlrpc_request *req = mdt_info_req(info);
        __u64 lockpart;
        struct mdt_lock_handle *lh;
        ENTRY;

        lh = &info->mti_lh[MDT_LH_PARENT];
        lh->mlh_mode = LCK_EX;

/*        if (req->rq_reqmsg->bufcount < 2)
 *                RETURN(-EFAULT);
 */
        DEBUG_REQ(D_INODE, req, "setxattr "DFID3,
                  PFID3(&info->mti_body->fid1));

/*        MDS_CHECK_RESENT(req, mds_reconstruct_generic(req)); */

        lockpart = MDS_INODELOCK_UPDATE;

        /* various sanity check for xattr name */
        xattr_name = req_capsule_client_get(&info->mti_pill, &RMF_NAME);
        if (!xattr_name) {
                CERROR("can't extract xattr name\n");
                GOTO(out, rc = -EPROTO);
        }

        CDEBUG(D_INODE, "%sxattr %s\n",
                  info->mti_body->valid & OBD_MD_FLXATTR ? "set" : "remove",
                  xattr_name);

        if (strncmp(xattr_name, "trusted.", 8) == 0) {
                if (strcmp(xattr_name + 8, "lov") == 0)
                        GOTO(out, rc = -EACCES);
        }

        if (!(req->rq_export->exp_connect_flags & OBD_CONNECT_XATTR) &&
            (strncmp(xattr_name, "user.", 5) == 0)) {
                GOTO(out, rc = -EOPNOTSUPP);
        }

#define XATTR_NAME_ACL_ACCESS   "system.posix_acl_access"

        if (!strcmp(xattr_name, XATTR_NAME_ACL_ACCESS))
                lockpart |= MDS_INODELOCK_LOOKUP;

        rc = mdt_object_lock(info->mti_mdt->mdt_namespace, info->mti_object, 
                                 lh, lockpart);
        if (rc != 0)
                GOTO(out, rc);


        if (info->mti_body->valid & OBD_MD_FLXATTR) {
                char * xattr; 
                if (!req_capsule_field_present(&info->mti_pill, &RMF_EADATA)) {
                        CERROR("no xattr data supplied\n");
                        GOTO(out_unlock, rc = -EFAULT);
                }

                xattr_len = req_capsule_get_size(&info->mti_pill, 
                                                 &RMF_EADATA, RCL_CLIENT);
                if (xattr_len)
                {
                        xattr = req_capsule_client_get(&info->mti_pill, 
                                                       &RMF_EADATA);

                        rc = mo_xattr_set(info->mti_ctxt, 
                                          mdt_object_child(info->mti_object),
                                          xattr, xattr_len, xattr_name);
                }
        } else if (info->mti_body->valid & OBD_MD_FLXATTRRM) {
                rc = mo_xattr_del(info->mti_ctxt, 
                                     mdt_object_child(info->mti_object),
                                     xattr_name);
        } else {
                CERROR("valid bits: "LPX64"\n", info->mti_body->valid);
                rc = -EINVAL;
        }

out_unlock:
        mdt_object_unlock(info->mti_mdt->mdt_namespace, 
                          info->mti_object, lh);
out:
        return rc;
}
