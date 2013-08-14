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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/ofd_recovery.c
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mikhail Pershin <tappro@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

struct thandle *ofd_trans_create(const struct lu_env *env,
				 struct ofd_device *ofd)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct thandle		*th;

	LASSERT(info);

	th = dt_trans_create(env, ofd->ofd_osd);
	if (IS_ERR(th))
		return th;

	/* export can require sync operations */
	if (info->fti_exp != NULL)
		th->th_sync |= info->fti_exp->exp_need_sync;
	return th;
}

int ofd_trans_start(const struct lu_env *env, struct ofd_device *ofd,
		    struct ofd_object *obj, struct thandle *th)
{
	/* version change is required for this object */
	if (obj != NULL)
		tgt_vbr_obj_set(env, ofd_object_child(obj));

	return dt_trans_start(env, ofd->ofd_osd, th);
}

void ofd_trans_stop(const struct lu_env *env, struct ofd_device *ofd,
		    struct thandle *th, int rc)
{
	th->th_result = rc;
	dt_trans_stop(env, ofd->ofd_osd, th);
}
