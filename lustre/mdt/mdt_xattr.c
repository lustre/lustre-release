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

#include "mdt_internal.h"


/* return EADATA length to the caller. negative value means error */
static int mdt_getxattr_pack_reply(struct mdt_thread_info * info)
{
        struct req_capsule     *pill = &info->mti_pill ;
        struct ptlrpc_request  *req = mdt_info_req(info);
        char                   *xattr_name;
        __u64                   valid = info->mti_body->valid;
        static const char       user_string[] = "user.";
        int                     rc;

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_GETXATTR_PACK))
                return -ENOMEM;

        /* Determine how many bytes we need */
        if ((valid & OBD_MD_FLXATTR) == OBD_MD_FLXATTR) {
                xattr_name = req_capsule_client_get(pill, &RMF_NAME);
                if (!xattr_name)
                        return -EFAULT;

                if (!(req->rq_export->exp_connect_flags & OBD_CONNECT_XATTR) &&
                    strncmp(xattr_name, user_string,
                            sizeof(user_string) - 1) == 0)
                        return -EOPNOTSUPP;

                rc = mo_xattr_get(info->mti_ctxt,
                                  mdt_object_child(info->mti_object),
                                  NULL, 0, xattr_name);
        } else if ((valid & OBD_MD_FLXATTRLS) == OBD_MD_FLXATTRLS) {
                rc = mo_xattr_list(info->mti_ctxt,
                                   mdt_object_child(info->mti_object),
                                   NULL, 0);
        } else {
                CERROR("valid bits: "LPX64"\n", info->mti_body->valid);
                return -EINVAL;
        }

        if (rc < 0) {
                if (rc != -ENODATA && rc != -EOPNOTSUPP) {
                        CWARN("get EA size error: %d\n", rc);
                        return rc;
                }
                rc = 0;
        } else {
                rc =  min_t(int, info->mti_body->eadatasize, rc);
        }
        req_capsule_set_size(pill, &RMF_EADATA, RCL_SERVER, rc);

        rc = req_capsule_pack(pill);
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
        LASSERT(lu_object_assert_exists(info->mti_ctxt,
                                 &info->mti_object->mot_obj.mo_lu));

        CDEBUG(D_INODE, "getxattr "DFID3"\n",
                        PFID3(&info->mti_body->fid1));

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_GETXATTR_PACK)) 
                RETURN(-ENOMEM);

        next = mdt_object_child(info->mti_object);

        rc = mdt_getxattr_pack_reply(info);
        if (rc != 0)
                RETURN(rc);

        buf = req_capsule_server_get(&info->mti_pill, &RMF_EADATA);
        rep_body = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        buflen = req_capsule_get_size(&info->mti_pill, &RMF_EADATA, RCL_SERVER);
        if (buflen == 0)
                GOTO(no_xattr, rc = 0);

        if (info->mti_body->valid & OBD_MD_FLXATTR) {
                char *xattr_name = req_capsule_client_get(&info->mti_pill,
                                                          &RMF_NAME);
                CDEBUG(D_INODE, "getxattr %s\n", xattr_name);

                rc = mo_xattr_get(info->mti_ctxt, next,
                                   buf, buflen, xattr_name);

                if (rc < 0 && rc != -ENODATA && rc != -EOPNOTSUPP &&
                    rc != -ERANGE)
                        CDEBUG(D_INODE, "getxattr failed: %d\n", rc);
        } else if (info->mti_body->valid & OBD_MD_FLXATTRLS) {
                CDEBUG(D_INODE, "listxattr\n");

                rc = mo_xattr_list(info->mti_ctxt, next, buf, buflen);
                if (rc < 0)
                        CDEBUG(D_OTHER, "listxattr failed: %d\n", rc);
        } else
                LBUG();

        if (rc >= 0) {
no_xattr:
                rep_body->eadatasize = rc;
                rc = 0;
        }

        RETURN(rc);
}


int mdt_setxattr(struct mdt_thread_info *info)
{
        struct ptlrpc_request  *req = mdt_info_req(info);
        const char              user_string[] = "user.";
        const char              trust_string[] = "trusted.";
        struct mdt_lock_handle *lh;
        __u64                   valid = info->mti_body->valid;
        char                   *xattr_name;
        int                     xattr_len;
        __u64                   lockpart;
        int                     rc;
        ENTRY;

        CDEBUG(D_INODE, "setxattr "DFID3"\n",
                        PFID3(&info->mti_body->fid1));

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_SETXATTR)) 
                RETURN(-ENOMEM);

        /* various sanity check for xattr name */
        xattr_name = req_capsule_client_get(&info->mti_pill, &RMF_NAME);
        if (!xattr_name)
                GOTO(out, rc = -EFAULT);

        CDEBUG(D_INODE, "%s xattr %s\n",
                  info->mti_body->valid & OBD_MD_FLXATTR ? "set" : "remove",
                  xattr_name);

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
        lh->mlh_mode = LCK_EX;
        rc = mdt_object_lock(info, info->mti_object, lh, lockpart);
        if (rc != 0)
                GOTO(out, rc);

        if ((valid & OBD_MD_FLXATTR) == OBD_MD_FLXATTR) {
                char * xattr;
                if (!req_capsule_field_present(&info->mti_pill, &RMF_EADATA)) {
                        CERROR("no xattr data supplied\n");
                        GOTO(out_unlock, rc = -EFAULT);
                }

                xattr_len = req_capsule_get_size(&info->mti_pill,
                                                 &RMF_EADATA, RCL_CLIENT);
                if (xattr_len) {
                        xattr = req_capsule_client_get(&info->mti_pill,
                                                       &RMF_EADATA);

                        rc = mo_xattr_set(info->mti_ctxt,
                                          mdt_object_child(info->mti_object),
                                          xattr, xattr_len, xattr_name);
                }
        } else if ((valid & OBD_MD_FLXATTRRM) == OBD_MD_FLXATTRRM) {
                rc = mo_xattr_del(info->mti_ctxt,
                                  mdt_object_child(info->mti_object),
                                  xattr_name);
        } else {
                CERROR("valid bits: "LPX64"\n", info->mti_body->valid);
                rc = -EINVAL;
        }
        EXIT;
out_unlock:
        mdt_object_unlock(info, info->mti_object, lh, rc);
out:
        return rc;
}
