/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mdd/mdd_lock.c
 *
 * Lustre Metadata Server (mdd) routines
 *
 * Author: Mike Pershin <tappro@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <lustre_ver.h>
#include "mdd_internal.h"

void mdd_write_lock(const struct lu_env *env, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_write_lock(env, next);
}

void mdd_read_lock(const struct lu_env *env, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);
        next->do_ops->do_read_lock(env, next);
}

void mdd_write_unlock(const struct lu_env *env, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_write_unlock(env, next);
}

void mdd_read_unlock(const struct lu_env *env, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_read_unlock(env, next);
}


/* Methods for parallel directory locking */

void mdd_pdlock_init(struct mdd_object *obj)
{
        dynlock_init(&obj->mod_pdlock);

}

unsigned long mdd_name2hash(const char *name)
{
        return full_name_hash((unsigned char*)name, strlen(name));
}

struct dynlock_handle *mdd_pdo_write_lock(const struct lu_env *env,
                                          struct mdd_object *obj,
                                          const char *name)
{
        unsigned long value = mdd_name2hash(name);
        return dynlock_lock(&obj->mod_pdlock, value, DLT_WRITE, GFP_NOFS);
}

struct dynlock_handle *mdd_pdo_read_lock(const struct lu_env *env,
                                         struct mdd_object *obj,
                                         const char *name)
{
        unsigned long value = mdd_name2hash(name);
        return dynlock_lock(&obj->mod_pdlock, value, DLT_READ, GFP_NOFS);
}

void mdd_pdo_write_unlock(const struct lu_env *env, struct mdd_object *obj,
                          struct dynlock_handle *dlh)
{
        return dynlock_unlock(&obj->mod_pdlock, dlh);
}

void mdd_pdo_read_unlock(const struct lu_env *env, struct mdd_object *obj,
                         struct dynlock_handle *dlh)
{
        return dynlock_unlock(&obj->mod_pdlock, dlh);
}
