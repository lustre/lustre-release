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
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"

int mdt_get_som(struct mdt_thread_info *info, struct mdt_object *obj,
		struct lu_attr *attr)
{
	struct lu_buf *buf = &info->mti_buf;
	struct lustre_som_attrs *som;
	int rc;

	som = buf->lb_buf = info->mti_xattr_buf;
	buf->lb_len = sizeof(info->mti_xattr_buf);
	rc = mo_xattr_get(info->mti_env, mdt_object_child(obj), buf,
			  XATTR_NAME_SOM);
	if (rc >= (int)sizeof(*som) && (som->lsa_valid & LSOM_FL_VALID)) {
		attr->la_valid |= LA_SIZE | LA_BLOCKS;
		attr->la_size = som->lsa_size;
		attr->la_blocks = som->lsa_blocks;

		/* Size on MDS is valid and could be returned to client */
		info->mti_som_valid = 1;

		CDEBUG(D_INODE, DFID": Reading som attrs: "
		       "valid: %x, size: %lld, blocks: %lld, rc: %d.\n",
		       PFID(mdt_object_fid(obj)), som->lsa_valid,
		       som->lsa_size, som->lsa_blocks, rc);
	}

	return (rc > 0 || rc == -ENODATA) ? 0 : rc;
}

int mdt_set_som(struct mdt_thread_info *info, struct mdt_object *obj,
		struct lu_attr *attr)
{
	struct md_object *next = mdt_object_child(obj);
	struct lu_buf *buf = &info->mti_buf;
	struct lustre_som_attrs *som;
	int rc;
	ENTRY;

	buf->lb_buf = info->mti_xattr_buf;
	buf->lb_len = sizeof(info->mti_xattr_buf);
	rc = mo_xattr_get(info->mti_env, next, buf, XATTR_NAME_SOM);
	if (rc < 0 && rc != -ENODATA)
		RETURN(rc);

	som = buf->lb_buf;

	CDEBUG(D_INODE,
	       DFID": Set som attrs: S/B: %lld/%lld to %lld/%lld, rc: %d\n",
	       PFID(mdt_object_fid(obj)), som->lsa_size, som->lsa_blocks,
	       attr->la_size, attr->la_blocks, rc);

	if (rc == -ENODATA)
		memset(som, 0, sizeof(*som));
	if (attr->la_valid & (LA_SIZE | LA_BLOCKS)) {
		som->lsa_valid |= LSOM_FL_VALID;
		som->lsa_size = attr->la_size;
		som->lsa_blocks = attr->la_blocks;
	}
	buf->lb_len = sizeof(*som);
	rc = mo_xattr_set(info->mti_env, next, buf, XATTR_NAME_SOM, 0);
	RETURN(rc);
}
