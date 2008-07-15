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
        struct req_capsule     *pill = info->mti_pill ;
        struct ptlrpc_request  *req = mdt_info_req(info);
        char                   *xattr_name;
        __u64                   valid = info->mti_body->valid;
        static const char       user_string[] = "user.";
        int                     size, rc;
        ENTRY;
        
        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETXATTR_PACK))
                RETURN(-ENOMEM);

        /* Determine how many bytes we need */
        if (valid & OBD_MD_FLXATTR) {
                xattr_name = req_capsule_client_get(pill, &RMF_NAME);
                if (!xattr_name)
                        RETURN(-EFAULT);

                if (!(req->rq_export->exp_connect_flags & OBD_CONNECT_XATTR) &&
                    !strncmp(xattr_name, user_string, sizeof(user_string) - 1))
                        RETURN(-EOPNOTSUPP);
                
                size = mo_xattr_get(info->mti_env,
                                    mdt_object_child(info->mti_object),
                                    &LU_BUF_NULL, xattr_name);
        } else if (valid & OBD_MD_FLXATTRLS) {
                size = mo_xattr_list(info->mti_env,
                                     mdt_object_child(info->mti_object),
                                     &LU_BUF_NULL);
        } else {
                CDEBUG(D_INFO, "Valid bits: "LPX64"\n", info->mti_body->valid);
                RETURN(-EINVAL);
        }

        if (size < 0) {
                if (size == -ENODATA)
                        size = 0;
                else if (size != -EOPNOTSUPP) {
                        CDEBUG(D_INFO, "Error geting EA size: %d\n", size);
                        RETURN(size);
                }
        }

        if (info->mti_body->eadatasize != 0 &&
            info->mti_body->eadatasize < size)
                RETURN(-ERANGE);

        req_capsule_set_size(pill, &RMF_EADATA, RCL_SERVER,
                             min_t(int, size, info->mti_body->eadatasize));

        rc = req_capsule_server_pack(pill);
        if (rc) {
                LASSERT(rc < 0);
                RETURN(rc);
        }

        RETURN(size);
}

int mdt_getxattr(struct mdt_thread_info *info)
{
        struct ptlrpc_request  *req = mdt_info_req(info);
        struct mdt_export_data *med = mdt_req2med(req);
        struct md_ucred        *uc  = mdt_ucred(info);
        struct mdt_body        *reqbody;
        struct mdt_body        *repbody = NULL;
        struct md_object       *next;
        struct lu_buf          *buf;
        int                     easize, rc;
        ENTRY;

        LASSERT(info->mti_object != NULL);
        LASSERT(lu_object_assert_exists(&info->mti_object->mot_obj.mo_lu));

        CDEBUG(D_INODE, "getxattr "DFID"\n", PFID(&info->mti_body->fid1));

        reqbody = req_capsule_client_get(info->mti_pill, &RMF_MDT_BODY);
        if (reqbody == NULL)
                RETURN(err_serious(-EFAULT));

        rc = mdt_init_ucred(info, reqbody);
        if (rc)
                RETURN(err_serious(rc));

        next = mdt_object_child(info->mti_object);

        if (info->mti_body->valid & OBD_MD_FLRMTRGETFACL) {
                __u32 perm = mdt_identity_get_perm(uc->mu_identity,
                                                   med->med_rmtclient,
                                                   req->rq_peer.nid);

                LASSERT(med->med_rmtclient);
                if (!(perm & CFS_RMTACL_PERM))
                        GOTO(out, rc = err_serious(-EPERM));

                rc = mo_permission(info->mti_env, NULL, next, NULL,
                                   MAY_RGETFACL);
                if (rc)
                        GOTO(out, rc = err_serious(rc));
        }

        easize = mdt_getxattr_pack_reply(info);
        if (easize < 0)
                GOTO(out, rc = err_serious(easize));

        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
        LASSERT(repbody != NULL);

        /* No need further getxattr. */
        if (easize == 0 || reqbody->eadatasize == 0)
                GOTO(out, rc = easize);

        buf = &info->mti_buf;
        buf->lb_buf = req_capsule_server_get(info->mti_pill, &RMF_EADATA);
        buf->lb_len = easize;

        if (info->mti_body->valid & OBD_MD_FLXATTR) {
                int flags = CFS_IC_NOTHING;
                char *xattr_name = req_capsule_client_get(info->mti_pill,
                                                          &RMF_NAME);
                CDEBUG(D_INODE, "getxattr %s\n", xattr_name);

                rc = mo_xattr_get(info->mti_env, next, buf, xattr_name);
                if (rc < 0) {
                        CERROR("getxattr failed: %d\n", rc);
                        GOTO(out, rc);
                }

                if (info->mti_body->valid &
                    (OBD_MD_FLRMTLSETFACL | OBD_MD_FLRMTLGETFACL))
                        flags = CFS_IC_ALL;
                else if (info->mti_body->valid & OBD_MD_FLRMTRGETFACL)
                        flags = CFS_IC_MAPPED;

                if (rc > 0 && flags != CFS_IC_NOTHING) {
                        int rc1;

                        LASSERT(med->med_rmtclient);
                        rc1 = lustre_posix_acl_xattr_id2client(uc,
                                        med->med_idmap,
                                        (posix_acl_xattr_header *)(buf->lb_buf),
                                        rc, flags);
                        if (unlikely(rc1 < 0))
                                rc = rc1;
                }
        } else if (info->mti_body->valid & OBD_MD_FLXATTRLS) {
                CDEBUG(D_INODE, "listxattr\n");

                rc = mo_xattr_list(info->mti_env, next, buf);
                if (rc < 0)
                        CDEBUG(D_INFO, "listxattr failed: %d\n", rc);
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

static int mdt_rmtlsetfacl(struct mdt_thread_info *info,
                           struct md_object *next,
                           const char *xattr_name,
                           ext_acl_xattr_header *header,
                           posix_acl_xattr_header **out)
{
        struct ptlrpc_request  *req = mdt_info_req(info);
        struct mdt_export_data *med = mdt_req2med(req);
        struct md_ucred        *uc = mdt_ucred(info);
        struct lu_buf          *buf = &info->mti_buf;
        int                     rc;
        ENTRY;

        rc = lustre_ext_acl_xattr_id2server(uc, med->med_idmap, header);
        if (rc)
                RETURN(rc);
 
        rc = mo_xattr_get(info->mti_env, next, &LU_BUF_NULL, xattr_name);
        if (rc == -ENODATA)
                rc = 0;
        else if (rc < 0)
                RETURN(rc);

        buf->lb_len = rc;
        if (buf->lb_len > 0) {
                OBD_ALLOC(buf->lb_buf, buf->lb_len);
                if (unlikely(buf->lb_buf == NULL))
                        RETURN(-ENOMEM);

                rc = mo_xattr_get(info->mti_env, next, buf, xattr_name);
                if (rc < 0) {
                        CERROR("getxattr failed: %d\n", rc);
                        GOTO(_out, rc);
                }
        } else
                buf->lb_buf = NULL;

        rc = lustre_acl_xattr_merge2posix((posix_acl_xattr_header *)(buf->lb_buf),
                                          buf->lb_len, header, out);
        EXIT;

_out:
        if (rc <= 0 && buf->lb_buf != NULL)
                OBD_FREE(buf->lb_buf, buf->lb_len);
        return rc;
}

int mdt_reint_setxattr(struct mdt_thread_info *info,
                       struct mdt_lock_handle *unused)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct mdt_export_data  *med = mdt_req2med(req);
        struct md_ucred         *uc  = mdt_ucred(info);
        const char               user_string[] = "user.";
        const char               trust_string[] = "trusted.";
        struct mdt_lock_handle  *lh;
        struct req_capsule      *pill = info->mti_pill;
        const struct lu_env     *env  = info->mti_env;
        struct lu_buf           *buf  = &info->mti_buf;
        struct mdt_reint_record *rr   = &info->mti_rr;
        struct md_attr          *ma = &info->mti_attr;
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct mdt_object       *obj; 
        struct md_object        *child;
        __u64                    valid = attr->la_valid;
        const char              *xattr_name;
        int                      xattr_len = 0;
        __u64                    lockpart;
        int                      rc;
        posix_acl_xattr_header  *new_xattr = NULL;
        ENTRY;

        CDEBUG(D_INODE, "setxattr for "DFID"\n", PFID(rr->rr_fid1));

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SETXATTR))
                RETURN(err_serious(-ENOMEM));

        xattr_name = rr->rr_name;

        CDEBUG(D_INODE, "%s xattr %s\n",
               valid & OBD_MD_FLXATTR ? "set" : "remove", xattr_name);

        rc = mdt_init_ucred_reint(info);
        if (rc != 0)
                RETURN(rc);

        if (valid & OBD_MD_FLRMTRSETFACL) {
                __u32 perm = mdt_identity_get_perm(uc->mu_identity,
                                                   med->med_rmtclient,
                                                   req->rq_peer.nid);

                LASSERT(med->med_rmtclient);
                if (!(perm & CFS_RMTACL_PERM))
                        GOTO(out, rc = err_serious(-EPERM));
        }

        /* various sanity check for xattr name */
        xattr_name = req_capsule_client_get(pill, &RMF_NAME);
        if (!xattr_name)
                GOTO(out, rc = err_serious(-EFAULT));

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
        mdt_lock_reg_init(lh, LCK_PW);
        obj = mdt_object_find_lock(info, rr->rr_fid1, lh, lockpart);
        if (IS_ERR(obj))
                GOTO(out, rc =  PTR_ERR(obj));

        if (unlikely(!(valid & OBD_MD_FLCTIME))) {
                CWARN("client miss to set OBD_MD_FLCTIME when "
                      "setxattr: [object "DFID"] [valid %llu]\n",
                      PFID(rr->rr_fid1), valid);
                attr->la_ctime = cfs_time_current_sec();
        }
        attr->la_valid = LA_CTIME;
        child = mdt_object_child(obj);
        if (valid & OBD_MD_FLXATTR) {
                char * xattr;

                if (!req_capsule_field_present(pill, &RMF_EADATA, RCL_CLIENT)) {
                        CDEBUG(D_INFO, "no xattr data supplied\n");
                        GOTO(out_unlock, rc = -EFAULT);
                }

                xattr_len = req_capsule_get_size(pill, &RMF_EADATA, RCL_CLIENT);
                if (xattr_len) {
                        int flags = 0;

                        xattr = req_capsule_client_get(pill, &RMF_EADATA);

                        if (valid & OBD_MD_FLRMTLSETFACL) {
                                LASSERT(med->med_rmtclient);
                                xattr_len = mdt_rmtlsetfacl(info, child,
                                                xattr_name,
                                                (ext_acl_xattr_header *)xattr,
                                                &new_xattr);
                                if (xattr_len < 0)
                                        GOTO(out_unlock, rc = xattr_len);

                                xattr = (char *)new_xattr;
                        }

                        if (attr->la_flags & XATTR_REPLACE)
                                flags |= LU_XATTR_REPLACE;

                        if (attr->la_flags & XATTR_CREATE)
                                flags |= LU_XATTR_CREATE;

                        mdt_fail_write(env, info->mti_mdt->mdt_bottom,
                                       OBD_FAIL_MDS_SETXATTR_WRITE);

                        buf->lb_buf = xattr;
                        buf->lb_len = xattr_len;
                        rc = mo_xattr_set(env, child, buf, xattr_name, flags);
                        /* update ctime after xattr changed */
                        if (rc == 0) {
                                ma->ma_attr_flags |= MDS_PERM_BYPASS;
                                mo_attr_set(env, child, ma);
                        }
                }
        } else if (valid & OBD_MD_FLXATTRRM) {
                rc = mo_xattr_del(env, child, xattr_name);
                /* update ctime after xattr changed */
                if (rc == 0) {
                        ma->ma_attr_flags |= MDS_PERM_BYPASS;
                        mo_attr_set(env, child, ma);
                }
        } else {
                CDEBUG(D_INFO, "valid bits: "LPX64"\n", valid);
                rc = -EINVAL;
        }
        EXIT;
out_unlock:
        mdt_object_unlock_put(info, obj, lh, rc);
        if (unlikely(new_xattr != NULL))
                lustre_posix_acl_xattr_free(new_xattr, xattr_len);
out:
        mdt_exit_ucred(info);
        return rc;
}
