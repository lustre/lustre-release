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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp_lock.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_support.h>
#include <lustre_lite.h>
#include <lustre_dlm.h>
#include <linux/lustre_version.h>

#ifndef POSIX_ACL_XATTR_ACCESS
#ifndef XATTR_NAME_ACL_ACCESS
#define XATTR_NAME_ACL_ACCESS   "system.posix_acl_access"
#endif
#define POSIX_ACL_XATTR_ACCESS XATTR_NAME_ACL_ACCESS
#endif
#ifndef POSIX_ACL_XATTR_DEFAULT
#ifndef XATTR_NAME_ACL_DEFAULT
#define XATTR_NAME_ACL_DEFAULT  "system.posix_acl_default"
#endif
#define POSIX_ACL_XATTR_DEFAULT XATTR_NAME_ACL_DEFAULT
#endif

#include "llite_internal.h"

#define XATTR_USER_PREFIX       "user."
#define XATTR_TRUSTED_PREFIX    "trusted."
#define XATTR_SECURITY_PREFIX   "security."
#define XATTR_LUSTRE_PREFIX     "lustre."

#define XATTR_USER_T            (1)
#define XATTR_TRUSTED_T         (2)
#define XATTR_SECURITY_T        (3)
#define XATTR_ACL_ACCESS_T      (4)
#define XATTR_ACL_DEFAULT_T     (5)
#define XATTR_LUSTRE_T          (6)
#define XATTR_OTHER_T           (7)

static
int get_xattr_type(const char *name)
{
        if (!strcmp(name, POSIX_ACL_XATTR_ACCESS))
                return XATTR_ACL_ACCESS_T;

        if (!strcmp(name, POSIX_ACL_XATTR_DEFAULT))
                return XATTR_ACL_DEFAULT_T;

        if (!strncmp(name, XATTR_USER_PREFIX,
                     sizeof(XATTR_USER_PREFIX) - 1))
                return XATTR_USER_T;

        if (!strncmp(name, XATTR_TRUSTED_PREFIX,
                     sizeof(XATTR_TRUSTED_PREFIX) - 1))
                return XATTR_TRUSTED_T;

        if (!strncmp(name, XATTR_SECURITY_PREFIX,
                     sizeof(XATTR_SECURITY_PREFIX) - 1))
                return XATTR_SECURITY_T;

        if (!strncmp(name, XATTR_LUSTRE_PREFIX,
                     sizeof(XATTR_LUSTRE_PREFIX) - 1))
                return XATTR_LUSTRE_T;

        return XATTR_OTHER_T;
}

static
int xattr_type_filter(struct ll_sb_info *sbi, int xattr_type)
{
        if ((xattr_type == XATTR_ACL_ACCESS_T ||
             xattr_type == XATTR_ACL_DEFAULT_T) &&
            !(sbi->ll_flags & LL_SBI_ACL))
                return -EOPNOTSUPP;

        if (xattr_type == XATTR_USER_T && !(sbi->ll_flags & LL_SBI_USER_XATTR))
                return -EOPNOTSUPP;
        if (xattr_type == XATTR_TRUSTED_T && !cfs_capable(CFS_CAP_SYS_ADMIN))
                return -EPERM;
        if (xattr_type == XATTR_OTHER_T)
                return -EOPNOTSUPP;

        return 0;
}

static
int ll_setxattr_common(struct inode *inode, const char *name,
                       const void *value, size_t size,
                       int flags, __u64 valid)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ptlrpc_request *req;
        struct ll_fid fid;
        int xattr_type, rc;
        ENTRY;


        xattr_type = get_xattr_type(name);
        rc = xattr_type_filter(sbi, xattr_type);
        if (rc)
                RETURN(rc);

        /* b10667: ignore lustre special xattr for now */
        if ((xattr_type == XATTR_TRUSTED_T && strcmp(name, "trusted.lov") == 0) ||
            (xattr_type == XATTR_LUSTRE_T && strcmp(name, "lustre.lov") == 0))
                RETURN(0);

        /* b15587: ignore security.capability xattr for now */
        if ((xattr_type == XATTR_SECURITY_T &&
            strcmp(name, "security.capability") == 0))
                RETURN(0);

        ll_inode2fid(&fid, inode);
        rc = mdc_setxattr(sbi->ll_mdc_exp, &fid, valid,
                          name, value, size, 0, flags, &req);
        if (rc) {
                if (rc == -EOPNOTSUPP && xattr_type == XATTR_USER_T) {
                        LCONSOLE_INFO("Disabling user_xattr feature because "
                                      "it is not supported on the server\n");
                        sbi->ll_flags &= ~LL_SBI_USER_XATTR;
                }
                RETURN(rc);
        }

        ptlrpc_req_finished(req);
        RETURN(0);
}

int ll_setxattr(struct dentry *dentry, const char *name,
                const void *value, size_t size, int flags)
{
        struct inode *inode = dentry->d_inode;

        LASSERT(inode);
        LASSERT(name);

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), xattr %s\n",
               inode->i_ino, inode->i_generation, inode, name);

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_SETXATTR, 1);

        if ((strncmp(name, XATTR_TRUSTED_PREFIX,
                    sizeof(XATTR_TRUSTED_PREFIX) - 1) == 0 &&
             strcmp(name + sizeof(XATTR_TRUSTED_PREFIX) - 1, "lov") == 0) ||
            (strncmp(name, XATTR_LUSTRE_PREFIX,
                    sizeof(XATTR_LUSTRE_PREFIX) - 1) == 0 &&
             strcmp(name + sizeof(XATTR_LUSTRE_PREFIX) - 1, "lov") == 0)) {
                struct lov_user_md *lump = (struct lov_user_md *)value;
                int rc = 0;

                /* Attributes that are saved via getxattr will always have
                 * the stripe_offset as 0.  Instead, the MDS should be
                 * allowed to pick the starting OST index.   b=17846 */
                if (lump != NULL && lump->lmm_stripe_offset == 0)
                        lump->lmm_stripe_offset = -1;

                if (lump != NULL && S_ISREG(inode->i_mode)) {
                        struct file f;
                        int flags = FMODE_WRITE;

                        f.f_dentry = dentry;
                        ll_lov_setstripe_ea_info(inode, &f, flags, lump, size);
                        /* b10667: rc always be 0 here for now */
                } else if (S_ISDIR(inode->i_mode)) {
                        rc = ll_dir_setstripe(inode, lump, 0);
                }

                return rc;
        } else if (strcmp(name, "trusted.lma") == 0 &&
                   !OBD_FAIL_CHECK(OBD_FAIL_MDS_ALLOW_COMMON_EA_SETTING))
                return 0;


        return ll_setxattr_common(inode, name, value, size, flags,
                                  OBD_MD_FLXATTR);
}

int ll_removexattr(struct dentry *dentry, const char *name)
{
        struct inode *inode = dentry->d_inode;

        LASSERT(inode);
        LASSERT(name);

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), xattr %s\n",
               inode->i_ino, inode->i_generation, inode, name);

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_REMOVEXATTR, 1);
        return ll_setxattr_common(inode, name, NULL, 0, 0,
                                  OBD_MD_FLXATTRRM);
}

static
int ll_getxattr_common(struct inode *inode, const char *name,
                       void *buffer, size_t size, __u64 valid)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ptlrpc_request *req = NULL;
        struct mds_body *body;
        struct ll_fid fid;
        void *xdata;
        int xattr_type, rc;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n",
               inode->i_ino, inode->i_generation, inode);


        /* listxattr have slightly different behavior from of ext3:
         * without 'user_xattr' ext3 will list all xattr names but
         * filtered out "^user..*"; we list them all for simplicity.
         */
        if (!name) {
                xattr_type = XATTR_OTHER_T;
                goto do_getxattr;
        }

        xattr_type = get_xattr_type(name);
        rc = xattr_type_filter(sbi, xattr_type);
        if (rc)
                RETURN(rc);

        /* b15587: ignore security.capability xattr for now */
        if ((xattr_type == XATTR_SECURITY_T &&
            strcmp(name, "security.capability") == 0))
                RETURN(-ENODATA);

        /* posix acl is under protection of LOOKUP lock. when calling to this,
         * we just have path resolution to the target inode, so we have great
         * chance that cached ACL is uptodate.
         */
#ifdef CONFIG_FS_POSIX_ACL
        if (xattr_type == XATTR_ACL_ACCESS_T) {
                struct ll_inode_info *lli = ll_i2info(inode);
                struct posix_acl *acl;

                spin_lock(&lli->lli_lock);
                acl = posix_acl_dup(lli->lli_posix_acl);
                spin_unlock(&lli->lli_lock);

                if (!acl)
                        RETURN(-ENODATA);

                rc = posix_acl_to_xattr(acl, buffer, size);
                posix_acl_release(acl);
                RETURN(rc);
        }
        if (xattr_type == XATTR_ACL_DEFAULT_T && !S_ISDIR(inode->i_mode))
                RETURN(-ENODATA);
#endif

do_getxattr:
        ll_inode2fid(&fid, inode);
        rc = mdc_getxattr(sbi->ll_mdc_exp, &fid, valid, name, NULL, 0, size,
                          &req);
        if (rc) {
                if (rc == -EOPNOTSUPP && xattr_type == XATTR_USER_T) {
                        LCONSOLE_INFO("Disabling user_xattr feature because "
                                      "it is not supported on the server\n");
                        sbi->ll_flags &= ~LL_SBI_USER_XATTR;
                }
                RETURN(rc);
        }

        body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof(*body));
        LASSERT(body);
        LASSERT(lustre_rep_swabbed(req, REPLY_REC_OFF));

        /* only detect the xattr size */
        if (size == 0)
                GOTO(out, rc = body->eadatasize);

        if (size < body->eadatasize) {
                CERROR("server bug: replied size %u > %u\n",
                       body->eadatasize, (int)size);
                GOTO(out, rc = -ERANGE);
        }

        if (lustre_msg_bufcount(req->rq_repmsg) < 3) {
                CERROR("reply bufcount %u\n",
                       lustre_msg_bufcount(req->rq_repmsg));
                GOTO(out, rc = -EFAULT);
        }

        /* do not need swab xattr data */
        lustre_set_rep_swabbed(req, REPLY_REC_OFF + 1);
        xdata = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF + 1,
                               body->eadatasize);
        if (!xdata) {
                CERROR("can't extract: %u : %u\n", body->eadatasize,
                       lustre_msg_buflen(req->rq_repmsg, REPLY_REC_OFF + 1));
                GOTO(out, rc = -EFAULT);
        }

        LASSERT(buffer);
        memcpy(buffer, xdata, body->eadatasize);
        rc = body->eadatasize;
out:
        ptlrpc_req_finished(req);
        RETURN(rc);
}

ssize_t ll_getxattr(struct dentry *dentry, const char *name,
                    void *buffer, size_t size)
{
        struct inode *inode = dentry->d_inode;

        LASSERT(inode);
        LASSERT(name);

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), xattr %s\n",
               inode->i_ino, inode->i_generation, inode, name);

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_GETXATTR, 1);

        if ((strncmp(name, XATTR_TRUSTED_PREFIX,
                    sizeof(XATTR_TRUSTED_PREFIX) - 1) == 0 &&
             strcmp(name + sizeof(XATTR_TRUSTED_PREFIX) - 1, "lov") == 0) ||
            (strncmp(name, XATTR_LUSTRE_PREFIX,
                    sizeof(XATTR_LUSTRE_PREFIX) - 1) == 0 &&
             strcmp(name + sizeof(XATTR_LUSTRE_PREFIX) - 1, "lov") == 0)) {
                struct lov_user_md *lump;
                struct lov_mds_md *lmm = NULL;
                struct ptlrpc_request *request = NULL;
                int rc = 0, lmmsize = 0;

                if (S_ISREG(inode->i_mode)) {
                        rc = ll_lov_getstripe_ea_info(dentry->d_parent->d_inode,
                                                      dentry->d_name.name, &lmm,
                                                      &lmmsize, &request);
                } else if (S_ISDIR(inode->i_mode)) {
                        rc = ll_dir_getstripe(inode, &lmm, &lmmsize, &request);
                } else {
                        rc = -ENODATA;
                }

                if (rc < 0)
                       GOTO(out, rc);
                if (size == 0)
                       GOTO(out, rc = lmmsize);

                if (size < lmmsize) {
                        CERROR("server bug: replied size %d > %d for %s (%s)\n",
                               lmmsize, (int)size, dentry->d_name.name, name);
                        GOTO(out, rc = -ERANGE);
                }

                lump = (struct lov_user_md *)buffer;
                memcpy(lump, lmm, lmmsize);

                rc = lmmsize;
out:
                ptlrpc_req_finished(request);
                return(rc);
        }

        return ll_getxattr_common(inode, name, buffer, size, OBD_MD_FLXATTR);
}

ssize_t ll_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
        struct inode *inode = dentry->d_inode;
        int rc = 0, rc2 = 0;
        struct lov_mds_md *lmm = NULL;
        struct ptlrpc_request *request = NULL;
        int lmmsize;

        LASSERT(inode);

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n",
               inode->i_ino, inode->i_generation, inode);

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_LISTXATTR, 1);

        rc = ll_getxattr_common(inode, NULL, buffer, size, OBD_MD_FLXATTRLS);
        if (rc < 0)
                GOTO(out, rc);

	if (buffer != NULL) {
		struct ll_sb_info *sbi = ll_i2sbi(inode);
		char *xattr_name = buffer;
		int xlen, rem = rc;

		while (rem > 0) {
			xlen = strnlen(xattr_name, rem - 1) + 1;
			rem -= xlen;
			if (xattr_type_filter(sbi,
					get_xattr_type(xattr_name)) == 0) {
				/* skip OK xattr type
				 * leave it in buffer
				 */
				xattr_name += xlen;
				continue;
			}
			/* move up remaining xattrs in buffer
			 * removing the xattr that is not OK
			 */
			memmove(xattr_name, xattr_name + xlen, rem);
			rc -= xlen;
		}
	}

        if (S_ISREG(inode->i_mode)) {
                struct ll_inode_info *lli = ll_i2info(inode);
                struct lov_stripe_md *lsm = NULL;
                lsm = lli->lli_smd;
                if (lsm == NULL)
                        rc2 = -1;
        } else if (S_ISDIR(inode->i_mode)) {
                rc2 = ll_dir_getstripe(inode, &lmm, &lmmsize, &request);
        }

        if (rc2 < 0) {
                GOTO(out, rc2 = 0);
        } else if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)) {
                const int prefix_len = sizeof(XATTR_LUSTRE_PREFIX) - 1;
                const size_t name_len   = sizeof("lov") - 1;
                const size_t total_len  = prefix_len + name_len + 1;

                if (buffer && (rc + total_len) <= size) {
                        buffer += rc;
                        memcpy(buffer,XATTR_LUSTRE_PREFIX, prefix_len);
                        memcpy(buffer+prefix_len, "lov", name_len);
                        buffer[prefix_len + name_len] = '\0';
                }
                rc2 = total_len;
        }
out:
        ptlrpc_req_finished(request);
        rc = rc + rc2;

        return rc;
}
