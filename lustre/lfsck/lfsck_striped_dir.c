/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2014, Intel Corporation.
 */
/*
 * lustre/lfsck/lfsck_striped_dir.c
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LFSCK

#include <lustre/lustre_idl.h>
#include <lu_object.h>
#include <dt_object.h>
#include <md_object.h>
#include <lustre_fid.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <lustre_lmv.h>
#include <lustre/lustre_user.h>

#include "lfsck_internal.h"

void lfsck_lmv_put(const struct lu_env *env, struct lfsck_lmv *llmv)
{
	if (llmv != NULL && atomic_dec_and_test(&llmv->ll_ref)) {
		if (llmv->ll_lslr != NULL)
			OBD_FREE_LARGE(llmv->ll_lslr,
				sizeof(struct lfsck_slave_lmv_rec) *
				llmv->ll_stripes_allocated);

		OBD_FREE_PTR(llmv);
	}
}

static inline bool lfsck_is_valid_slave_lmv(struct lmv_mds_md_v1 *lmv)
{
	return lmv->lmv_stripe_count >= 1 &&
	       lmv->lmv_stripe_count <= LFSCK_LMV_MAX_STRIPES &&
	       lmv->lmv_stripe_count > lmv->lmv_master_mdt_index &&
	       lmv_is_known_hash_type(lmv->lmv_hash_type);
}

int lfsck_read_stripe_lmv(const struct lu_env *env, struct dt_object *obj,
			  struct lmv_mds_md_v1 *lmv)
{
	struct dt_object *bottom;
	int		  rc;

	/* Currently, we only store the LMV header on disk. It is the LOD's
	 * duty to iterate the master MDT-object's directory to compose the
	 * integrated LMV EA. But here, we only want to load the LMV header,
	 * so we need to bypass LOD to avoid unnecessary iteration in LOD. */
	bottom = lu2dt(container_of0(obj->do_lu.lo_header->loh_layers.prev,
				     struct lu_object, lo_linkage));
	if (unlikely(bottom == NULL))
		return -ENOENT;

	dt_read_lock(env, bottom, 0);
	rc = dt_xattr_get(env, bottom, lfsck_buf_get(env, lmv, sizeof(*lmv)),
			  XATTR_NAME_LMV, BYPASS_CAPA);
	dt_read_unlock(env, bottom);
	if (rc != sizeof(*lmv))
		return rc > 0 ? -EINVAL : rc;

	lfsck_lmv_header_le_to_cpu(lmv, lmv);
	if ((lmv->lmv_magic == LMV_MAGIC &&
	     !(lmv->lmv_hash_type & LMV_HASH_FLAG_MIGRATION)) ||
	    (lmv->lmv_magic == LMV_MAGIC_STRIPE &&
	     !(lmv->lmv_hash_type & LMV_HASH_FLAG_DEAD)))
		return 0;

	return -ENODATA;
}

/**
 * Parse the shard's index from the given shard name.
 *
 * The valid shard name/type should be:
 * 1) The type must be S_IFDIR
 * 2) The name should be $FID:$index
 * 3) the index should within valid range.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] name	the shard name
 * \param[in] namelen	the name length
 * \param[in] type	the entry's type
 * \param[in] fid	the entry's FID
 *
 * \retval		zero or positive number for the index from the name
 * \retval		negative error number on failure
 */
int lfsck_shard_name_to_index(const struct lu_env *env, const char *name,
			      int namelen, __u16 type, const struct lu_fid *fid)
{
	char	*name2	= lfsck_env_info(env)->lti_tmpbuf2;
	int	 len;
	int	 idx	= 0;

	if (!S_ISDIR(type))
		return -ENOTDIR;

	LASSERT(name != name2);

	len = snprintf(name2, sizeof(lfsck_env_info(env)->lti_tmpbuf2),
		       DFID":", PFID(fid));
	if (namelen < len + 1 || memcmp(name, name2, len) != 0)
		return -EINVAL;

	do {
		if (!isdigit(name[len]))
			return -EINVAL;

		idx = idx * 10 + name[len++] - '0';
	} while (len < namelen);

	if (idx >= LFSCK_LMV_MAX_STRIPES)
		return -EINVAL;

	return idx;
}

bool lfsck_is_valid_slave_name_entry(const struct lu_env *env,
				     struct lfsck_lmv *llmv,
				     const char *name, int namelen)
{
	struct lmv_mds_md_v1	*lmv;
	int			 idx;

	if (llmv == NULL || !llmv->ll_lmv_slave || !llmv->ll_lmv_verified)
		return true;

	lmv = &llmv->ll_lmv;
	idx = lmv_name_to_stripe_index(lmv->lmv_hash_type,
				       lmv->lmv_stripe_count,
				       name, namelen);
	if (unlikely(idx != lmv->lmv_master_mdt_index))
		return false;

	return true;
}

/**
 * Check whether the given name is a valid entry under the @parent.
 *
 * If the @parent is a striped directory then the @child should one
 * shard of the striped directory, its name should be $FID:$index.
 *
 * If the @parent is a shard of a striped directory, then the name hash
 * should match the MDT, otherwise it is invalid.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] parent	the parent directory
 * \param[in] child	the child object to be checked
 * \param[in] cname	the name for the @child in the parent directory
 *
 * \retval		positive number for invalid name entry
 * \retval		0 if the name is valid or uncertain
 * \retval		negative error number on failure
 */
int lfsck_namespace_check_name(const struct lu_env *env,
			       struct dt_object *parent,
			       struct dt_object *child,
			       const struct lu_name *cname)
{
	struct lmv_mds_md_v1	*lmv = &lfsck_env_info(env)->lti_lmv;
	int			 idx;
	int			 rc;

	rc = lfsck_read_stripe_lmv(env, parent, lmv);
	if (rc != 0)
		RETURN(rc == -ENODATA ? 0 : rc);

	if (lmv->lmv_magic == LMV_MAGIC_STRIPE) {
		if (!lfsck_is_valid_slave_lmv(lmv))
			return 0;

		idx = lmv_name_to_stripe_index(lmv->lmv_hash_type,
					       lmv->lmv_stripe_count,
					       cname->ln_name,
					       cname->ln_namelen);
		if (unlikely(idx != lmv->lmv_master_mdt_index))
			return 1;
	} else if (lfsck_shard_name_to_index(env, cname->ln_name,
			cname->ln_namelen, lfsck_object_type(child),
			lfsck_dto2fid(child)) < 0) {
		return 1;
	}

	return 0;
}

int lfsck_namespace_verify_stripe_slave(const struct lu_env *env,
					struct lfsck_component *com,
					struct dt_object *obj,
					struct lfsck_lmv *llmv)
{
	/* XXX: TBD */
	return 0;
}
