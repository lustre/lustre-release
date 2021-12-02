/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2017, Intel Corporation.
 */
/*
 * lustre/mdt/mdt_som.c
 *
 * Size on MDS revival
 *
 * Author: Jinshan Xiong <jinshan.xiong@intel.com>
 * Author: Yingjin Qian <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"

/*
 * Swab and extract SOM attributes from on-disk xattr.
 *
 * \param buf - is a buffer containing the on-disk LSOM extended attribute.
 * \param rc  - is the SOM xattr stored in \a buf
 * \param ms  - is the md_som structure where to extract SOM attributes.
 */
int lustre_buf2som(void *buf, int rc, struct md_som *ms)
{
	struct lustre_som_attrs *attrs = (struct lustre_som_attrs *)buf;
	ENTRY;

	if (rc == 0 || rc == -ENODATA)
		/* no LSOM attributes */
		RETURN(-ENODATA);

	if (rc < 0)
		/* error hit while fetching xattr */
		RETURN(rc);

	/* unpack LSOM attributes */
	lustre_som_swab(attrs);

	/* fill in-memory md_som structure */
	ms->ms_valid = attrs->lsa_valid;
	ms->ms_size = attrs->lsa_size;
	ms->ms_blocks = attrs->lsa_blocks;

	RETURN(0);
}

int mdt_get_som(struct mdt_thread_info *info, struct mdt_object *obj,
		struct md_attr *ma)
{
	struct lu_buf *buf = &info->mti_buf;
	struct lu_attr *attr = &ma->ma_attr;
	int rc;

	buf->lb_buf = info->mti_xattr_buf;
	buf->lb_len = sizeof(info->mti_xattr_buf);
	BUILD_BUG_ON(sizeof(struct lustre_som_attrs) >
		     sizeof(info->mti_xattr_buf));
	rc = mo_xattr_get(info->mti_env, mdt_object_child(obj), buf,
			  XATTR_NAME_SOM);
	rc = lustre_buf2som(info->mti_xattr_buf, rc, &ma->ma_som);
	if (rc == 0) {
		struct md_som *som = &ma->ma_som;

		ma->ma_valid |= MA_SOM;

		CDEBUG(D_INODE, DFID": Reading som attrs: "
		       "valid: %x, size: %lld, blocks: %lld\n",
		       PFID(mdt_object_fid(obj)), som->ms_valid,
		       som->ms_size, som->ms_blocks);

		if (som->ms_valid & SOM_FL_STRICT) {
			attr->la_valid |= LA_SIZE | LA_BLOCKS;

			/*
			 * Size on MDS is valid and could be returned
			 * to client.
			 */
			attr->la_size = som->ms_size;
			attr->la_blocks = som->ms_blocks;
			info->mti_som_valid = 1;
		} else if (!obj->mot_lsom_inited &&
			   (som->ms_valid & SOM_FL_LAZY) &&
			   !mutex_is_locked(&obj->mot_som_mutex)) {
			mutex_lock(&obj->mot_som_mutex);
			obj->mot_lsom_size = som->ms_size;
			obj->mot_lsom_blocks = som->ms_blocks;
			obj->mot_lsom_inited = true;
			mutex_unlock(&obj->mot_som_mutex);
		}
	} else if (rc == -ENODATA) {
		rc = 0;
	}

	return rc;
}

/**
 * Update SOM on-disk attributes.
 */
int mdt_set_som(struct mdt_thread_info *info, struct mdt_object *obj,
		enum lustre_som_flags flag, __u64 size, __u64 blocks)
{
	struct md_object *next = mdt_object_child(obj);
	struct lu_buf *buf = &info->mti_buf;
	struct lustre_som_attrs *som;
	int rc;

	ENTRY;

	CDEBUG(D_INODE,
	       DFID": Set SOM attrs S/B/F: %lld/%lld/%x.\n",
	       PFID(mdt_object_fid(obj)), size, blocks, flag);

	som = (struct lustre_som_attrs *)info->mti_xattr_buf;
	BUILD_BUG_ON(sizeof(info->mti_xattr_buf) < sizeof(*som));

	som->lsa_valid = flag;
	som->lsa_size = size;
	som->lsa_blocks = blocks;
	memset(&som->lsa_reserved, 0, sizeof(som->lsa_reserved));
	lustre_som_swab(som);

	/* update SOM attributes */
	buf->lb_buf = som;
	buf->lb_len = sizeof(*som);
	rc = mo_xattr_set(info->mti_env, next, buf, XATTR_NAME_SOM, 0);
	if (!rc && flag == SOM_FL_LAZY) {
		obj->mot_lsom_size = size;
		obj->mot_lsom_blocks = blocks;
		obj->mot_lsom_inited = true;
	}
	RETURN(rc);
}

/**
 * SOM state transition from STRICT to STALE,
 */
int mdt_lsom_downgrade(struct mdt_thread_info *info, struct mdt_object *o)
{
	struct md_attr *tmp_ma;
	int rc;

	ENTRY;

	mutex_lock(&o->mot_som_mutex);
	tmp_ma = &info->mti_u.som.attr;
	tmp_ma->ma_need = MA_SOM;
	tmp_ma->ma_valid = 0;

	rc = mdt_get_som(info, o, tmp_ma);
	if (rc < 0)
		GOTO(out_lock, rc);

	if (tmp_ma->ma_valid & MA_SOM) {
		struct md_som *som = &tmp_ma->ma_som;

		info->mti_som_valid = 0;
		/* The size and blocks info should be still correct. */
		if (som->ms_valid & SOM_FL_STRICT)
			rc = mdt_set_som(info, o, SOM_FL_STALE,
					 som->ms_size, som->ms_blocks);
	}
out_lock:
	mutex_unlock(&o->mot_som_mutex);
	RETURN(rc);
}

int mdt_lsom_update(struct mdt_thread_info *info,
		    struct mdt_object *o, bool truncate)
{
	struct md_attr *ma, *tmp_ma;
	struct lu_attr *la;
	int rc = 0;

	ENTRY;

	ma = &info->mti_attr;
	la = &ma->ma_attr;

	if (!(la->la_valid & (LA_SIZE | LA_LSIZE) &&
	      o->mot_lsom_size < la->la_size) &&
	    !(la->la_valid & (LA_BLOCKS | LA_LBLOCKS) &&
	      o->mot_lsom_blocks < la->la_blocks) && !truncate &&
	    o->mot_lsom_inited)
		RETURN(0);

	tmp_ma = &info->mti_u.som.attr;
	tmp_ma->ma_need = MA_INODE | MA_SOM;
	tmp_ma->ma_valid = 0;

	rc = mdt_attr_get_complex(info, o, tmp_ma);
	if (rc)
		RETURN(rc);

	/**
	 * If mti_big_lmm_used is set, it indicates that mti_big_lmm
	 * should contain valid LOV EA data, and can be used directly.
	 */
	if (!info->mti_big_lmm_used) {
		rc = mdt_big_xattr_get(info, o, XATTR_NAME_LOV);
		if (rc < 0 && rc != -ENODATA)
			RETURN(rc);

		/* No LOV EA */
		if (rc == -ENODATA)
			RETURN(0);

		rc = 0;
	}

	/**
	 * Check if a Lazy Size-on-MDS update is needed. Skip the
	 * file with no LOV EA, unlink files or DoM-only file.
	 * MDS only updates LSOM of the file if the size or block
	 * size is being increased or the file is being truncated.
	 */
	if (!mdt_lmm_dom_only(info->mti_big_lmm) &&
	    !(tmp_ma->ma_valid & MA_INODE && tmp_ma->ma_attr.la_nlink == 0)) {
		__u64 size;
		__u64 blocks;
		bool changed = false;
		struct md_som *som = &tmp_ma->ma_som;

		if (truncate) {
			size = la->la_size;
			if (size == 0) {
				blocks = 0;
			} else if (!(tmp_ma->ma_valid & MA_SOM) ||
				    size < som->ms_size) {
				/* We cannot rely to blocks after
				 * truncate especially for spare file,
				 * and the truncate operation is usually
				 * followed with a close, so just set blocks
				 * to 1 here, and the following close will
				 * update it accordingly.
				 */
				blocks = 1;
			} else {
				blocks = som->ms_blocks;
			}
		} else {
			if (!(tmp_ma->ma_valid & MA_SOM)) {
				/* Only set initial SOM Xattr data when both
				 * size and blocks are valid.
				 */
				if (la->la_valid & (LA_SIZE | LA_LSIZE) &&
				    la->la_valid & (LA_BLOCKS | LA_LBLOCKS)) {
					changed = true;
					size = la->la_size;
					blocks = la->la_blocks;
				}
			} else {
				/* Double check whether it is already set
				 * to SOM_FL_STRICT in mdt_mfd_close.
				 * If file is in SOM_FL_STALE state, and
				 * the close indicates there is no data
				 * modified, skip to transimit to LAZY
				 * state.
				 */
				if (som->ms_valid & SOM_FL_STRICT ||
				    (som->ms_valid & SOM_FL_STALE &&
				     !(ma->ma_attr_flags & MDS_DATA_MODIFIED)))
					RETURN(rc);

				size = som->ms_size;
				blocks = som->ms_blocks;
				if (la->la_valid & (LA_SIZE | LA_LSIZE) &&
				    la->la_size > som->ms_size) {
					changed = true;
					size = la->la_size;
				}
				if (la->la_valid & (LA_BLOCKS | LA_LBLOCKS) &&
				    la->la_blocks > som->ms_blocks) {
					changed = true;
					blocks = la->la_blocks;
				}
			}
		}
		if (truncate || changed) {
			mutex_lock(&o->mot_som_mutex);
			if (size <= o->mot_lsom_size &&
			    blocks <= o->mot_lsom_blocks && !truncate &&
			    o->mot_lsom_inited) {
				mutex_unlock(&o->mot_som_mutex);
				RETURN(0);
			}
			if (!truncate && size < o->mot_lsom_size)
				size = o->mot_lsom_size;
			if (!truncate && blocks < o->mot_lsom_blocks)
				blocks = o->mot_lsom_blocks;
			rc = mdt_set_som(info, o, SOM_FL_LAZY, size, blocks);
			mutex_unlock(&o->mot_som_mutex);
		}
	}

	RETURN(rc);
}
