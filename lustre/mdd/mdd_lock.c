/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  mdd/mdd_handler.c
 *  Lustre Metadata Server (mdd) routines
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Mike Pershin <tappro@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
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
        unsigned long value = 0;
        int namelen = strlen(name);
        int i = 0;
        while (namelen > i) {
                value += name[i] * (i << 7);
                i++;
        }
        return value;
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

