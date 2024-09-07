// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
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
