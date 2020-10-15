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
 * Copyright (c) 2020 Intel Corporation.
 */
#define DEBUG_SUBSYSTEM S_LLITE

#include "llite_internal.h"

static void ll_manage_foreign_file(struct inode *inode,
				   struct lov_foreign_md *lfm)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);

	if (le32_to_cpu(lfm->lfm_type) == LU_FOREIGN_TYPE_SYMLINK) {
		CDEBUG(D_INFO,
		       "%s: inode %p of fid "DFID": Foreign file of type symlink, faking a symlink\n",
		       sbi->ll_fsname, inode, PFID(ll_inode2fid(inode)));
		/* change inode_operations to add symlink methods, and clear
		 * IOP_NOFOLLOW to ensure file will be treated as a symlink
		 * by Kernel (see in * d_flags_for_inode()).
		 */
		inode->i_op = &ll_foreign_file_symlink_inode_operations;
		inode->i_opflags &= ~IOP_NOFOLLOW;
	} else {
		CDEBUG(D_INFO,
		       "%s: inode %p of fid "DFID": Foreign file of type %ux, nothing special to do\n",
		       sbi->ll_fsname, inode, PFID(ll_inode2fid(inode)),
		       le32_to_cpu(lfm->lfm_type));
	}
}

static void ll_manage_foreign_dir(struct inode *inode,
				  struct lmv_foreign_md *lfm)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);

	if (lfm->lfm_type == LU_FOREIGN_TYPE_SYMLINK) {
		CDEBUG(D_INFO,
		       "%s: inode %p of fid "DFID": Foreign dir of type symlink, faking a symlink\n",
		       sbi->ll_fsname, inode, PFID(ll_inode2fid(inode)));
		/* change inode_operations to add symlink methods
		 * IOP_NOFOLLOW should not be set for dirs
		 */
		inode->i_op = &ll_foreign_dir_symlink_inode_operations;
	} else {
		CDEBUG(D_INFO,
		       "%s: inode %p of fid "DFID": Foreign dir of type %ux, nothing special to do\n",
		       sbi->ll_fsname, inode, PFID(ll_inode2fid(inode)),
		       le32_to_cpu(lfm->lfm_type));
	}
}

int ll_manage_foreign(struct inode *inode, struct lustre_md *lmd)
{
	int rc = 0;

	ENTRY;
	/* apply any foreign file/dir policy */
	if (S_ISREG((inode)->i_mode)) {
		struct ll_inode_info *lli = ll_i2info(inode);
		struct cl_object *obj = lli->lli_clob;

		if (lmd->layout.lb_buf != NULL && lmd->layout.lb_len != 0) {
			struct lov_foreign_md *lfm = lmd->layout.lb_buf;

			if (lfm->lfm_magic == LOV_MAGIC_FOREIGN)
				ll_manage_foreign_file(inode, lfm);
			GOTO(out, rc);
		}

		if (obj) {
			struct lov_foreign_md lfm = {
				.lfm_magic = LOV_MAGIC,
			};
			struct cl_layout cl = {
				.cl_buf.lb_buf = &lfm,
				.cl_buf.lb_len = sizeof(lfm),
			};
			struct lu_env *env;
			u16 refcheck;

			env = cl_env_get(&refcheck);
			if (IS_ERR(env))
				GOTO(out, rc = PTR_ERR(env));
			rc = cl_object_layout_get(env, obj, &cl);
			/* error is likely to be -ERANGE because of the small
			 * buffer we use, only the content is significant here
			 */
			if (rc < 0 && rc != -ERANGE) {
				cl_env_put(env, &refcheck);
				GOTO(out, rc);
			}
			if (lfm.lfm_magic == LOV_MAGIC_FOREIGN)
				ll_manage_foreign_file(inode, &lfm);
			cl_env_put(env, &refcheck);
		}
	} else if (S_ISDIR((inode)->i_mode)) {
		if (lmd->lfm != NULL &&
		    lmd->lfm->lfm_magic == LMV_MAGIC_FOREIGN) {
			ll_manage_foreign_dir(inode, lmd->lfm);
		} else {
			struct ll_inode_info *lli = ll_i2info(inode);
			struct lmv_foreign_md *lfm;

			down_read(&lli->lli_lsm_sem);
			lfm = (struct lmv_foreign_md *)(lli->lli_lsm_md);
			if (lfm &&  lfm->lfm_magic == LMV_MAGIC_FOREIGN)
				ll_manage_foreign_dir(inode, lfm);
			up_read(&lli->lli_lsm_sem);
		}
	}
out:
	RETURN(rc);
}

/* dentry must be spliced to inode (dentry->d_inode != NULL) !!! */
bool ll_foreign_is_openable(struct dentry *dentry, unsigned int flags)
{
	/* check for faked symlink here as they should not be opened (unless
	 * O_NOFOLLOW!) and thus wants ll_atomic_open() to return 1 from
	 * finish_no_open() in order to get follow_link() to be called in both
	 * path_lookupat() and path_openupat().
	 * This will not break regular symlink handling as they have
	 * been treated/filtered upstream.
	 */
	if (d_is_symlink(dentry) && !S_ISLNK(dentry->d_inode->i_mode) &&
	    !(flags & O_NOFOLLOW))
		return false;

	return true;
}

static bool should_preserve_foreign_file(struct lov_foreign_md *lfm,
					 struct ll_inode_info *lli, bool unset)
{
	/* for now, only avoid foreign fake symlink file removal */

	if (unset)
		if (lfm->lfm_type == LU_FOREIGN_TYPE_SYMLINK) {
			set_bit(LLIF_FOREIGN_REMOVABLE, &lli->lli_flags);
			return true;
		} else {
			return false;
		}
	else
		return lfm->lfm_type == LU_FOREIGN_TYPE_SYMLINK &&
			!test_bit(LLIF_FOREIGN_REMOVABLE, &lli->lli_flags);
}

static bool should_preserve_foreign_dir(struct lmv_foreign_md *lfm,
					struct ll_inode_info *lli, bool unset)
{
	/* for now, only avoid foreign fake symlink dir removal */

	if (unset)
		if (lfm->lfm_type == LU_FOREIGN_TYPE_SYMLINK) {
			set_bit(LLIF_FOREIGN_REMOVABLE, &lli->lli_flags);
			return true;
		} else {
			return false;
		}
	else
		return lfm->lfm_type == LU_FOREIGN_TYPE_SYMLINK &&
			!test_bit(LLIF_FOREIGN_REMOVABLE, &lli->lli_flags);
}

/* XXX
 * instead of fetching type from foreign LOV/LMV, we may simply
 * check (d_is_symlink(dentry) && !S_ISLNK(dentry->d_inode->i_mode))
 * to identify a fake symlink
 */
bool ll_foreign_is_removable(struct dentry *dentry, bool unset)
{
	struct inode *inode = dentry->d_inode;
	struct qstr *name = &dentry->d_name;
	bool preserve_foreign = false;
	int rc = 0;

	ENTRY;
	if (inode == NULL)
		return 0;

	/* some foreign types may not be allowed to be unlinked in order to
	 * keep references with external objects
	 */
	if (S_ISREG(inode->i_mode)) {
		struct ll_inode_info *lli = ll_i2info(inode);
		struct cl_object *obj = lli->lli_clob;

		if (obj) {
			struct lov_foreign_md lfm = {
				.lfm_magic = LOV_MAGIC,
			};
			struct cl_layout cl = {
				.cl_buf.lb_buf = &lfm,
				.cl_buf.lb_len = sizeof(lfm),
			};
			struct lu_env *env;
			u16 refcheck;

			env = cl_env_get(&refcheck);
			if (IS_ERR(env))
				GOTO(out, rc = PTR_ERR(env));
			rc = cl_object_layout_get(env, obj, &cl);
			/* error is likely to be -ERANGE because of the small
			 * buffer we use, only the content is significant here
			 */
			if (rc < 0 && rc != -ERANGE) {
				cl_env_put(env, &refcheck);
				goto out;
			} else {
				rc = 0;
			}
			if (lfm.lfm_magic == LOV_MAGIC_FOREIGN)
				preserve_foreign =
					should_preserve_foreign_file(&lfm, lli,
								     unset);
			cl_env_put(env, &refcheck);
			if (preserve_foreign) {
				CDEBUG(D_INFO,
				       "%s unlink of foreign file (%.*s, "DFID")\n",
				       unset ? "allow" : "prevent",
				       name->len, name->name,
				       PFID(ll_inode2fid(inode)));
				RETURN(false);
			}
		} else {
			CDEBUG(D_INFO,
			       "unable to check if file (%.*s, "DFID") is foreign...\n",
			       name->len, name->name,
			       PFID(ll_inode2fid(inode)));
			/* XXX should we prevent removal ?? */
		}
	} else if (S_ISDIR(inode->i_mode)) {
		struct ll_inode_info *lli = ll_i2info(inode);
		struct lmv_foreign_md *lfm;

		down_read(&lli->lli_lsm_sem);
		lfm = (struct lmv_foreign_md *)(lli->lli_lsm_md);
		if (!lfm)
			CDEBUG(D_INFO,
			       "unable to check if dir (%.*s, "DFID") is foreign...\n",
			       name->len, name->name,
			       PFID(ll_inode2fid(inode)));
		else if (lfm->lfm_magic == LMV_MAGIC_FOREIGN)
			preserve_foreign = should_preserve_foreign_dir(lfm, lli,
								       unset);
		up_read(&lli->lli_lsm_sem);
		if (preserve_foreign) {
			CDEBUG(D_INFO,
			       "%s unlink of foreign dir (%.*s, "DFID")\n",
			       unset ? "allow" : "prevent",
			       name->len, name->name,
			       PFID(ll_inode2fid(inode)));
			RETURN(false);
		}
	}

out:
	RETURN(true);
}
