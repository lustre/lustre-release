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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012 Intel Corporation
 * Use is subject to license terms.
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"

/**
 * Update on-disk HSM attributes.
 */
int mdt_hsm_attr_set(struct mdt_thread_info *info, struct mdt_object *obj,
		     struct md_hsm *mh)
{
	struct md_object	*next = mdt_object_child(obj);
	struct lu_buf		*buf = &info->mti_buf;
	struct hsm_attrs	*attrs;
	int			 rc;
	ENTRY;

	attrs = (struct hsm_attrs *)info->mti_xattr_buf;
	CLASSERT(sizeof(info->mti_xattr_buf) >= sizeof(*attrs));

	/* pack HSM attributes */
	lustre_hsm2buf(info->mti_xattr_buf, mh);

	/* update SOM attributes */
	buf->lb_buf = attrs;
	buf->lb_len = sizeof(*attrs);
	rc = mo_xattr_set(info->mti_env, next, buf, XATTR_NAME_HSM, 0);

	RETURN(rc);
}
