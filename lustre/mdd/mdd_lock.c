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
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/mdd/mdd_lock.c
 *
 * Lustre Metadata Server (mdd) routines
 *
 * Author: Mike Pershin <tappro@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include "mdd_internal.h"

void mdd_write_lock(const struct lu_env *env, struct mdd_object *obj,
		    enum dt_object_role role)
{
	struct dt_object *next = mdd_object_child(obj);

	dt_write_lock(env, next, role);
}

void mdd_read_lock(const struct lu_env *env, struct mdd_object *obj,
		   enum dt_object_role role)
{
	struct dt_object *next = mdd_object_child(obj);

	dt_read_lock(env, next, role);
}

void mdd_write_unlock(const struct lu_env *env, struct mdd_object *obj)
{
	struct dt_object *next = mdd_object_child(obj);

	dt_write_unlock(env, next);
}

void mdd_read_unlock(const struct lu_env *env, struct mdd_object *obj)
{
	struct dt_object *next = mdd_object_child(obj);

	dt_read_unlock(env, next);
}

int mdd_write_locked(const struct lu_env *env, struct mdd_object *obj)
{
	struct dt_object *next = mdd_object_child(obj);

	return dt_write_locked(env, next);
}
