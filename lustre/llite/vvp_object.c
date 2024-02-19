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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * cl_object implementation for VVP layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/user_namespace.h>
#include <linux/uidgid.h>

#include <libcfs/libcfs.h>

#include <obd.h>
#include "llite_internal.h"
#include "vvp_internal.h"

/* Object operations.*/
int vvp_object_invariant(const struct cl_object *obj)
{
	struct inode		*inode	= vvp_object_inode(obj);
	struct ll_inode_info	*lli	= ll_i2info(inode);

	return (S_ISREG(inode->i_mode) || inode->i_mode == 0) &&
	       lli->lli_clob == obj;
}

static int vvp_object_print(const struct lu_env *env, void *cookie,
			    lu_printer_t p, const struct lu_object *o)
{
	struct vvp_object    *obj   = lu2vvp(o);
	struct inode         *inode = obj->vob_inode;
	struct ll_inode_info *lli;

	(*p)(env, cookie, "(%d) inode: %p ",
	     atomic_read(&obj->vob_mmap_cnt),
	     inode);
	if (inode) {
		lli = ll_i2info(inode);
		(*p)(env, cookie, "%lu/%u %o %u %d %p "DFID,
		     inode->i_ino, inode->i_generation, inode->i_mode,
		     inode->i_nlink, atomic_read(&inode->i_count),
		     lli->lli_clob, PFID(&lli->lli_fid));
	}
	return 0;
}

static int vvp_attr_get(const struct lu_env *env, struct cl_object *obj,
			struct cl_attr *attr)
{
	struct inode *inode = vvp_object_inode(obj);

	/*
	 * lov overwrites most of these fields in
	 * lov_attr_get()->...lov_merge_lvb_kms(), except when inode
	 * attributes are newer.
	 */

	attr->cat_size = i_size_read(inode);
	attr->cat_mtime = inode_get_mtime_sec(inode);
	attr->cat_atime = inode_get_atime_sec(inode);
	attr->cat_ctime = inode_get_ctime_sec(inode);
	attr->cat_blocks = inode->i_blocks;
	attr->cat_uid = from_kuid(&init_user_ns, inode->i_uid);
	attr->cat_gid = from_kgid(&init_user_ns, inode->i_gid);
	attr->cat_projid = ll_i2info(inode)->lli_projid;
	/* KMS is not known by this layer */
	return 0; /* layers below have to fill in the rest */
}

static int vvp_attr_update(const struct lu_env *env, struct cl_object *obj,
			   const struct cl_attr *attr, unsigned int valid)
{
	struct inode *inode = vvp_object_inode(obj);

	if (valid & CAT_UID)
		inode->i_uid = make_kuid(&init_user_ns, attr->cat_uid);
	if (valid & CAT_GID)
		inode->i_gid = make_kgid(&init_user_ns, attr->cat_gid);
	if (valid & CAT_ATIME)
		inode_set_atime(inode, attr->cat_atime, 0);
	if (valid & CAT_MTIME)
		inode_set_mtime(inode, attr->cat_mtime, 0);
	if (valid & CAT_CTIME)
		inode_set_ctime(inode, attr->cat_ctime, 0);
	if (valid & CAT_PROJID)
		ll_i2info(inode)->lli_projid = attr->cat_projid;
	return 0;
}

static void vvp_dirty_for_sync(const struct lu_env *env, struct cl_object *obj)
{
	struct inode *inode = vvp_object_inode(obj);

	__mark_inode_dirty(inode, I_DIRTY_DATASYNC);
}

static int vvp_conf_set(const struct lu_env *env, struct cl_object *obj,
			const struct cl_object_conf *conf)
{
	struct ll_inode_info *lli = ll_i2info(conf->coc_inode);

	if (conf->coc_opc == OBJECT_CONF_INVALIDATE) {
		CDEBUG(D_VFSTRACE, DFID ": losing layout lock\n",
		       PFID(&lli->lli_fid));

		ll_layout_version_set(lli, CL_LAYOUT_GEN_NONE);

		/* Clean up page mmap for this inode.
		 * The reason for us to do this is that if the page has
		 * already been installed into memory space, the process
		 * can access it without interacting with lustre, so this
		 * page may be stale due to layout change, and the process
		 * will never be notified.
		 * This operation is expensive but mmap processes have to pay
		 * a price themselves.
		 */
		unmap_mapping_range(conf->coc_inode->i_mapping,
				    0, OBD_OBJECT_EOF, 0);
		pcc_layout_invalidate(conf->coc_inode);
	}
	return 0;
}

static int vvp_prune(const struct lu_env *env, struct cl_object *obj)
{
	struct inode *inode = vvp_object_inode(obj);
	int rc;

	ENTRY;

	rc = cl_sync_file_range(inode, 0, OBD_OBJECT_EOF, CL_FSYNC_LOCAL, 1);
	if (rc < 0) {
		CDEBUG(D_VFSTRACE, DFID ": writeback failed: %d\n",
		       PFID(lu_object_fid(&obj->co_lu)), rc);
		RETURN(rc);
	}

	if (ll_get_inode_lock_owner(inode) != current)
		/* ask LOV get inode lock then lo_type_guard */
		RETURN(-EAGAIN);

	LASSERTF(inode_is_locked(inode), DFID ":inode %p lli_flags %#lx\n",
		 PFID(lu_object_fid(&obj->co_lu)), inode,
		 ll_i2info(inode)->lli_flags);

	ll_truncate_inode_pages_final(inode);
	mapping_clear_exiting(inode->i_mapping);

	RETURN(0);
}

static int vvp_object_glimpse(const struct lu_env *env,
			      const struct cl_object *obj, struct ost_lvb *lvb)
{
	struct inode *inode = vvp_object_inode(obj);

	ENTRY;
	lvb->lvb_mtime = inode_get_mtime_sec(inode);
	lvb->lvb_atime = inode_get_atime_sec(inode);
	lvb->lvb_ctime = inode_get_ctime_sec(inode);

	/*
	 * LU-417: Add dirty pages block count lest i_blocks reports 0, some
	 * "cp" or "tar" on remote node may think it's a completely sparse file
	 * and skip it.
	 */
	if (lvb->lvb_size > 0 && lvb->lvb_blocks == 0)
		lvb->lvb_blocks = dirty_cnt(inode);

	RETURN(0);
}

static void vvp_req_attr_set(const struct lu_env *env, struct cl_object *obj,
			     struct cl_req_attr *attr)
{
	struct inode *inode;
	struct obdo  *oa;
	struct ll_inode_info *lli;
	u64 valid_flags = OBD_MD_FLTYPE | OBD_MD_FLUID | OBD_MD_FLGID |
			  OBD_MD_FLPROJID;

	oa = attr->cra_oa;
	inode = vvp_object_inode(obj);
	lli = ll_i2info(inode);

	if (attr->cra_type == CRT_WRITE) {
		valid_flags |= OBD_MD_FLMTIME | OBD_MD_FLCTIME;
		obdo_set_o_projid(oa, ll_i2info(inode)->lli_projid);
	} else if (attr->cra_type == CRT_READ) {
		valid_flags |= OBD_MD_FLATIME;
	}
	obdo_from_inode(oa, inode, valid_flags & attr->cra_flags);
	obdo_set_parent_fid(oa, &ll_i2info(inode)->lli_fid);
	if (CFS_FAIL_CHECK(OBD_FAIL_LFSCK_INVALID_PFID))
		oa->o_parent_oid++;

	attr->cra_uid = lli->lli_uid;
	attr->cra_gid = lli->lli_gid;

	memcpy(attr->cra_jobid, &lli->lli_jobid, sizeof(attr->cra_jobid));
}

static int vvp_inode_ops(const struct lu_env *env, struct cl_object *obj,
			 enum coo_inode_opc opc, void *data)
{
	struct inode *inode = vvp_object_inode(obj);
	struct ll_inode_info *lli = ll_i2info(inode);
	int rc = 0;

	ENTRY;
	switch (opc) {
	case COIO_INODE_LOCK:
		if (ll_get_inode_lock_owner(inode) != current)
			ll_inode_lock(inode);
		else
			rc = -EALREADY;
		break;
	case COIO_INODE_UNLOCK:
		if (ll_get_inode_lock_owner(inode) == current)
			ll_inode_unlock(inode);
		else
			rc = -ENOLCK;
		break;
	case COIO_SIZE_LOCK:
		if (lli->lli_size_lock_owner != current)
			ll_inode_size_lock(inode);
		else
			rc = -EALREADY;
		break;
	case COIO_SIZE_UNLOCK:
		if (lli->lli_size_lock_owner == current)
			ll_inode_size_unlock(inode);
		else
			rc = -ENOLCK;
		break;
	default:
		rc = -EINVAL;
		break;
	}

	RETURN(rc);
}

static const struct cl_object_operations vvp_ops = {
	.coo_page_init    = vvp_page_init,
	.coo_io_init      = vvp_io_init,
	.coo_attr_get     = vvp_attr_get,
	.coo_attr_update  = vvp_attr_update,
	.coo_dirty_for_sync = vvp_dirty_for_sync,
	.coo_conf_set     = vvp_conf_set,
	.coo_prune        = vvp_prune,
	.coo_glimpse      = vvp_object_glimpse,
	.coo_req_attr_set = vvp_req_attr_set,
	.coo_inode_ops    = vvp_inode_ops,
};

static int vvp_object_init0(const struct lu_env *env,
			    struct vvp_object *vob,
			    const struct cl_object_conf *conf)
{
	vob->vob_inode = conf->coc_inode;
	cl_object_page_init(&vob->vob_cl, sizeof(struct cl_page_slice));
	return 0;
}

static int vvp_object_init(const struct lu_env *env, struct lu_object *obj,
			   const struct lu_object_conf *conf)
{
	struct vvp_device *dev = lu2vvp_dev(obj->lo_dev);
	struct vvp_object *vob = lu2vvp(obj);
	struct lu_object  *below;
	struct lu_device  *under;
	int result;

	under = &dev->vdv_next->cd_lu_dev;
	below = under->ld_ops->ldo_object_alloc(env, obj->lo_header, under);
	if (below != NULL) {
		const struct cl_object_conf *cconf;

		cconf = lu2cl_conf(conf);
		lu_object_add(obj, below);
		result = vvp_object_init0(env, vob, cconf);
	} else
		result = -ENOMEM;

	return result;
}

static void vvp_object_free_rcu(struct rcu_head *head)
{
	struct vvp_object *vob = container_of(head, struct vvp_object,
					      vob_header.coh_lu.loh_rcu);

	kmem_cache_free(vvp_object_kmem, vob);
}

static void vvp_object_free(const struct lu_env *env, struct lu_object *obj)
{
	struct vvp_object *vob = lu2vvp(obj);

	lu_object_fini(obj);
	lu_object_header_fini(obj->lo_header);
	OBD_FREE_PRE(vob, sizeof(*vob), "slab-freed");
	call_rcu(&vob->vob_header.coh_lu.loh_rcu, vvp_object_free_rcu);
}

static const struct lu_object_operations vvp_lu_obj_ops = {
	.loo_object_init	= vvp_object_init,
	.loo_object_free	= vvp_object_free,
	.loo_object_print	= vvp_object_print,
};

struct vvp_object *cl_inode2vvp(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct cl_object     *obj = lli->lli_clob;
	struct lu_object     *lu;

	LASSERT(obj != NULL);
	lu = lu_object_locate(obj->co_lu.lo_header, &vvp_device_type);
	LASSERT(lu != NULL);

	return lu2vvp(lu);
}

struct lu_object *vvp_object_alloc(const struct lu_env *env,
				   const struct lu_object_header *unused,
				   struct lu_device *dev)
{
	struct vvp_object *vob;
	struct lu_object  *obj;

	OBD_SLAB_ALLOC_PTR_GFP(vob, vvp_object_kmem, GFP_NOFS);
	if (vob != NULL) {
		struct cl_object_header *hdr;

		obj = &vob->vob_cl.co_lu;
		hdr = &vob->vob_header;
		cl_object_header_init(hdr);
		hdr->coh_page_bufsize = round_up(sizeof(struct cl_page), 8);

		lu_object_init(obj, &hdr->coh_lu, dev);
		lu_object_add_top(&hdr->coh_lu, obj);

		vob->vob_cl.co_ops = &vvp_ops;
		obj->lo_ops = &vvp_lu_obj_ops;
	} else
		obj = NULL;
	return obj;
}
