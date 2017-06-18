/*
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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/xattr.h>
#include <linux/selinux.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_support.h>
#include <lustre_dlm.h>
#include <lustre_ver.h>
#include <lustre_eacl.h>

#include "llite_internal.h"

/* xattr related to IMA(Integrity Measurement Architecture) */
#ifndef XATTR_NAME_IMA
#define XATTR_NAME_IMA		"security.ima"
#endif
#ifndef XATTR_NAME_EVM
#define XATTR_NAME_EVM		"security.evm"
#endif

static
int get_xattr26_type(const char *name)
{
	if (!strcmp(name, XATTR_NAME_POSIX_ACL_ACCESS))
		return XATTR_ACL_ACCESS_T;

	if (!strcmp(name, XATTR_NAME_POSIX_ACL_DEFAULT))
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
	struct ptlrpc_request *req = NULL;
	int xattr_type, rc;
	const char *pv = value;
	ENTRY;

	/*FIXME: enable IMA when the conditions are ready */
	if (strncmp(name, XATTR_NAME_IMA,
		    sizeof(XATTR_NAME_IMA)) == 0 ||
	    strncmp(name, XATTR_NAME_EVM,
		    sizeof(XATTR_NAME_EVM)) == 0)
		return -EOPNOTSUPP;

	xattr_type = get_xattr26_type(name);
	rc = xattr_type_filter(sbi, xattr_type);
	if (rc)
		RETURN(rc);

	if ((xattr_type == XATTR_ACL_ACCESS_T ||
	     xattr_type == XATTR_ACL_DEFAULT_T) &&
#ifdef HAVE_INODE_OWNER_OR_CAPABLE
	    !inode_owner_or_capable(inode))
#else
	    !is_owner_or_cap(inode))
#endif
		return -EPERM;

	/* b10667: ignore lustre special xattr for now */
	if (strcmp(name, XATTR_NAME_HSM) == 0 ||
		(xattr_type == XATTR_TRUSTED_T &&
		strcmp(name, XATTR_NAME_LOV) == 0) ||
		(xattr_type == XATTR_LUSTRE_T &&
		 strcmp(name, "lustre.lov") == 0))
		RETURN(0);

	/* LU-549:  Disable security.selinux when selinux is disabled */
	if (xattr_type == XATTR_SECURITY_T && !selinux_is_enabled() &&
	    strcmp(name, "security.selinux") == 0)
		RETURN(-EOPNOTSUPP);

	/* In user.* namespace, only regular files and directories can have
	 * extended attributes. */
	if (xattr_type == XATTR_USER_T) {
		if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
			RETURN(-EPERM);
	}

	rc = md_setxattr(sbi->ll_md_exp, ll_inode2fid(inode), valid, name, pv,
			 size, 0, flags, ll_i2suppgid(inode), &req);
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

static int get_hsm_state(struct inode *inode, __u32 *hus_states)
{
	struct md_op_data *op_data;
	struct hsm_user_state *hus;
	int rc;

	OBD_ALLOC_PTR(hus);
	if (hus == NULL)
		return -ENOMEM;

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, hus);
	if (!IS_ERR(op_data)) {
		rc = obd_iocontrol(LL_IOC_HSM_STATE_GET, ll_i2mdexp(inode),
				   sizeof(*op_data), op_data, NULL);
		if (rc == 0)
			*hus_states = hus->hus_states;
		else
			CDEBUG(D_VFSTRACE, "obd_iocontrol failed. rc = %d\n",
			       rc);

		ll_finish_md_op_data(op_data);
	} else {
		rc = PTR_ERR(op_data);
		CDEBUG(D_VFSTRACE, "Could not prepare the opdata. rc = %d\n",
		       rc);
	}
	OBD_FREE_PTR(hus);
	return rc;
}

static int ll_adjust_lum(struct inode *inode, struct lov_user_md *lump)
{
	struct lov_comp_md_v1 *comp_v1 = (struct lov_comp_md_v1 *)lump;
	struct lov_user_md *v1 = lump;
	bool release_checked = false;
	bool need_clear_release = false;
	__u16 entry_count = 1;
	bool is_composite = false;
	int rc = 0;
	int i;

	if (lump == NULL)
		return 0;

	if (lump->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		entry_count = comp_v1->lcm_entry_count;
		is_composite = true;
	}

	for (i = 0; i < entry_count; i++) {
		if (lump->lmm_magic == LOV_USER_MAGIC_COMP_V1)
			v1 = (struct lov_user_md *)((char *)comp_v1 +
					comp_v1->lcm_entries[i].lcme_offset);

		/* Attributes that are saved via getxattr will always
		 * have the stripe_offset as 0.  Instead, the MDS
		 * should be allowed to pick the starting OST index.
		 * b=17846 */
		if (!is_composite && v1->lmm_stripe_offset == 0)
			v1->lmm_stripe_offset = -1;

		/* Avoid anyone directly setting the RELEASED flag. */
		if (v1->lmm_pattern & LOV_PATTERN_F_RELEASED) {
			if (!release_checked) {
				__u32 state = HS_NONE;
				rc = get_hsm_state(inode, &state);
				if (rc)
					return rc;
				if (!(state & HS_ARCHIVED))
					need_clear_release = true;
				release_checked = true;
			}
			if (need_clear_release)
				v1->lmm_pattern ^= LOV_PATTERN_F_RELEASED;
		}
	}

	return rc;
}

static int ll_setstripe_ea(struct dentry *dentry, struct lov_user_md *lump,
			   size_t size)
{
	struct inode *inode = dentry->d_inode;
	int rc = 0;

	rc = ll_adjust_lum(inode, lump);
	if (rc)
		return rc;

	if (lump != NULL && S_ISREG(inode->i_mode)) {
		u64 it_flags = FMODE_WRITE;
		int lum_size;

		lum_size = ll_lov_user_md_size(lump);
		if (lum_size < 0 || size < lum_size)
			return -ERANGE;

		rc = ll_lov_setstripe_ea_info(inode, dentry, it_flags, lump,
					      lum_size);
		/**
		 * b=10667: ignore -EEXIST.
		 * Silently eat error on setting trusted.lov/lustre.lov
		 * attribute for SuSE 9, it added default option to copy
		 * all attributes in 'cp' command. rsync, tar --xattrs
		 * also will try to set LOVEA for existing files.
		 */
		if (rc == -EEXIST)
			rc = 0;
	} else if (S_ISDIR(inode->i_mode)) {
		rc = ll_dir_setstripe(inode, lump, 0);
	}

	return rc;
}

int ll_setxattr(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;

	LASSERT(inode);
	LASSERT(name);

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p), xattr %s\n",
	       PFID(ll_inode2fid(inode)), inode, name);

	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_SETXATTR, 1);

	/* lustre/trusted.lov.xxx would be passed through xattr API */
	if (strcmp(name, XATTR_NAME_LOV) == 0 ||
	    strcmp(name, XATTR_LUSTRE_LOV) == 0)
		return ll_setstripe_ea(dentry, (struct lov_user_md *)value,
				       size);
	else if (strcmp(name, XATTR_NAME_LMA) == 0 ||
		 strcmp(name, XATTR_NAME_LINK) == 0)
		return 0;

	return ll_setxattr_common(inode, name, value, size, flags,
				  OBD_MD_FLXATTR);
}

int ll_removexattr(struct dentry *dentry, const char *name)
{
	struct inode *inode = dentry->d_inode;

	LASSERT(inode);
	LASSERT(name);

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p), xattr %s\n",
	       PFID(ll_inode2fid(inode)), inode, name);

	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_REMOVEXATTR, 1);
	return ll_setxattr_common(inode, name, NULL, 0, 0,
				  OBD_MD_FLXATTRRM);
}

int ll_getxattr_common(struct inode *inode, const char *name,
		       void *buffer, size_t size, __u64 valid)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ptlrpc_request *req = NULL;
	struct mdt_body *body;
	int xattr_type, rc;
	void *xdata;
	struct ll_inode_info *lli = ll_i2info(inode);
	ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p)\n",
	       PFID(ll_inode2fid(inode)), inode);

	/* listxattr have slightly different behavior from of ext3:
	 * without 'user_xattr' ext3 will list all xattr names but
	 * filtered out "^user..*"; we list them all for simplicity.
	 */
	if (!name) {
		xattr_type = XATTR_OTHER_T;
		goto do_getxattr;
	}

	xattr_type = get_xattr26_type(name);
	rc = xattr_type_filter(sbi, xattr_type);
	if (rc)
		RETURN(rc);

	/* LU-549:  Disable security.selinux when selinux is disabled */
	if (xattr_type == XATTR_SECURITY_T && !selinux_is_enabled() &&
	    strcmp(name, "security.selinux") == 0)
		RETURN(-EOPNOTSUPP);

#ifdef CONFIG_FS_POSIX_ACL
	/* posix acl is under protection of LOOKUP lock. when calling to this,
	 * we just have path resolution to the target inode, so we have great
	 * chance that cached ACL is uptodate.
	 */
	if (xattr_type == XATTR_ACL_ACCESS_T) {
		struct posix_acl *acl;

		spin_lock(&lli->lli_lock);
		acl = posix_acl_dup(lli->lli_posix_acl);
		spin_unlock(&lli->lli_lock);

		if (!acl)
			RETURN(-ENODATA);

		rc = posix_acl_to_xattr(&init_user_ns, acl, buffer, size);
		posix_acl_release(acl);
		RETURN(rc);
	}
	if (xattr_type == XATTR_ACL_DEFAULT_T && !S_ISDIR(inode->i_mode))
		RETURN(-ENODATA);
#endif

do_getxattr:
	if (sbi->ll_xattr_cache_enabled &&
	    xattr_type != XATTR_ACL_ACCESS_T &&
	    (xattr_type != XATTR_SECURITY_T ||
		strcmp(name, "security.selinux") != 0)) {
		rc = ll_xattr_cache_get(inode, name, buffer, size, valid);
		if (rc == -EAGAIN)
			goto getxattr_nocache;
		if (rc < 0)
			GOTO(out_xattr, rc);

		/* Add "system.posix_acl_access" to the list */
		if (lli->lli_posix_acl != NULL && valid & OBD_MD_FLXATTRLS) {
			if (size == 0) {
				rc += sizeof(XATTR_NAME_ACL_ACCESS);
			} else if (size - rc >= sizeof(XATTR_NAME_ACL_ACCESS)) {
				memcpy(buffer + rc, XATTR_NAME_ACL_ACCESS,
				       sizeof(XATTR_NAME_ACL_ACCESS));
				rc += sizeof(XATTR_NAME_ACL_ACCESS);
			} else {
				GOTO(out_xattr, rc = -ERANGE);
			}
		}
	} else {
getxattr_nocache:
		rc = md_getxattr(sbi->ll_md_exp, ll_inode2fid(inode),
				valid, name, NULL, 0, size, 0, &req);

		if (rc < 0)
			GOTO(out_xattr, rc);

		body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
		LASSERT(body);

		/* only detect the xattr size */
		if (size == 0)
			GOTO(out, rc = body->mbo_eadatasize);

		if (size < body->mbo_eadatasize) {
			CERROR("server bug: replied size %u > %u\n",
				body->mbo_eadatasize, (int)size);
			GOTO(out, rc = -ERANGE);
		}

		if (body->mbo_eadatasize == 0)
			GOTO(out, rc = -ENODATA);

		/* do not need swab xattr data */
		xdata = req_capsule_server_sized_get(&req->rq_pill, &RMF_EADATA,
							body->mbo_eadatasize);
		if (!xdata)
			GOTO(out, rc = -EFAULT);

		memcpy(buffer, xdata, body->mbo_eadatasize);
		rc = body->mbo_eadatasize;
	}

	EXIT;

out_xattr:
	if (rc == -EOPNOTSUPP && xattr_type == XATTR_USER_T) {
		LCONSOLE_INFO("%s: disabling user_xattr feature because "
				"it is not supported on the server: rc = %d\n",
				ll_get_fsname(inode->i_sb, NULL, 0), rc);
		sbi->ll_flags &= ~LL_SBI_USER_XATTR;
	}
out:
	ptlrpc_req_finished(req);
	return rc;
}

static ssize_t ll_getxattr_lov(struct inode *inode, void *buf, size_t buf_size)
{
	ssize_t rc;

	if (S_ISREG(inode->i_mode)) {
		struct cl_object *obj = ll_i2info(inode)->lli_clob;
		struct lu_env *env;
		struct cl_layout cl = {
			.cl_buf.lb_buf = buf,
			.cl_buf.lb_len = buf_size,
		};
		__u16 refcheck;

		if (obj == NULL)
			RETURN(-ENODATA);

		env = cl_env_get(&refcheck);
		if (IS_ERR(env))
			RETURN(PTR_ERR(env));

		rc = cl_object_layout_get(env, obj, &cl);
		if (rc < 0)
			GOTO(out_env, rc);

		if (cl.cl_size == 0)
			GOTO(out_env, rc = -ENODATA);

		rc = cl.cl_size;

		if (buf_size == 0)
			GOTO(out_env, rc);

		LASSERT(buf != NULL && rc <= buf_size);

		/* Do not return layout gen for getxattr() since
		 * otherwise it would confuse tar --xattr by
		 * recognizing layout gen as stripe offset when the
		 * file is restored. See LU-2809. */
		if (((struct lov_mds_md *)buf)->lmm_magic == LOV_MAGIC_COMP_V1)
			goto out_env;

		((struct lov_mds_md *)buf)->lmm_layout_gen = 0;
out_env:
		cl_env_put(env, &refcheck);

		RETURN(rc);
	} else if (S_ISDIR(inode->i_mode)) {
		struct lov_mds_md *lmm = NULL;
		int lmm_size = 0;
		struct ptlrpc_request *req = NULL;

		rc = ll_dir_getstripe(inode, (void **)&lmm, &lmm_size,
				      &req, 0);
		if (rc < 0)
			GOTO(out_req, rc);

		if (buf_size == 0)
			GOTO(out_req, rc = lmm_size);

		if (buf_size < lmm_size)
			GOTO(out_req, rc = -ERANGE);

		memcpy(buf, lmm, lmm_size);
		GOTO(out_req, rc = lmm_size);
out_req:
		if (req != NULL)
			ptlrpc_req_finished(req);

		return rc;
	} else {
		RETURN(-ENODATA);
	}
}

ssize_t ll_getxattr(struct dentry *dentry, const char *name, void *buf,
		    size_t buf_size)
{
	struct inode *inode = dentry->d_inode;

	LASSERT(inode);
	LASSERT(name);

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p), xattr %s\n",
	       PFID(ll_inode2fid(inode)), inode, name);

	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_GETXATTR, 1);

	if (strcmp(name, XATTR_LUSTRE_LOV) == 0 ||
	    strcmp(name, XATTR_NAME_LOV) == 0)
		return ll_getxattr_lov(inode, buf, buf_size);
	else
		return ll_getxattr_common(inode, name, buf, buf_size,
					  OBD_MD_FLXATTR);
}

ssize_t ll_listxattr(struct dentry *dentry, char *buf, size_t buf_size)
{
	struct inode *inode = dentry->d_inode;
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	char *xattr_name;
	ssize_t rc, rc2;
	size_t len, rem;

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p)\n",
	       PFID(ll_inode2fid(inode)), inode);

	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_LISTXATTR, 1);

	rc = ll_getxattr_common(inode, NULL, buf, buf_size, OBD_MD_FLXATTRLS);
	if (rc < 0)
		RETURN(rc);

	/* If we're being called to get the size of the xattr list
	 * (buf_size == 0) then just assume that a lustre.lov xattr
	 * exists. */
	if (buf_size == 0)
		RETURN(rc + sizeof(XATTR_LUSTRE_LOV));

	xattr_name = buf;
	rem = rc;

	while (rem > 0) {
		len = strnlen(xattr_name, rem - 1) + 1;
		rem -= len;
		if (xattr_type_filter(sbi, get_xattr26_type(xattr_name)) == 0) {
			/* Skip OK xattr type, leave it in buffer. */
			xattr_name += len;
			continue;
		}

		/* Move up remaining xattrs in buffer removing the
		 * xattr that is not OK. */
		memmove(xattr_name, xattr_name + len, rem);
		rc -= len;
	}

	rc2 = ll_getxattr_lov(inode, NULL, 0);
	if (rc2 == -ENODATA)
		RETURN(rc);

	if (rc2 < 0)
		RETURN(rc2);

	if (buf_size < rc + sizeof(XATTR_LUSTRE_LOV))
		RETURN(-ERANGE);

	memcpy(buf + rc, XATTR_LUSTRE_LOV, sizeof(XATTR_LUSTRE_LOV));

	RETURN(rc + sizeof(XATTR_LUSTRE_LOV));
}
