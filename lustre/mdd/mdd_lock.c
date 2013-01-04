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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
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

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <lustre_ver.h>
#include "mdd_internal.h"

void mdd_write_lock(const struct lu_env *env, struct mdd_object *obj,
                    enum mdd_object_role role)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_write_lock(env, next, role);
}

void mdd_read_lock(const struct lu_env *env, struct mdd_object *obj,
                   enum mdd_object_role role)
{
        struct dt_object  *next = mdd_object_child(obj);

        next->do_ops->do_read_lock(env, next, role);
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

int mdd_write_locked(const struct lu_env *env, struct mdd_object *obj)
{
        struct dt_object  *next = mdd_object_child(obj);

        return next->do_ops->do_write_locked(env, next);
}

unsigned long mdd_name2hash(const char *name)
{
        return full_name_hash((unsigned char*)name, strlen(name));
}

/* Methods for parallel directory locking */
#if MDD_DISABLE_PDO_LOCK

static void *pdo_handle = (void *)0xbabecafe;

void mdd_pdlock_init(struct mdd_object *obj)
{
}

void *mdd_pdo_write_lock(const struct lu_env *env, struct mdd_object *obj,
                         const char *name, enum mdd_object_role role)
{
        return pdo_handle;
}

void *mdd_pdo_read_lock(const struct lu_env *env, struct mdd_object *obj,
                        const char *name, enum mdd_object_role role)
{
        return pdo_handle;
}

void mdd_pdo_write_unlock(const struct lu_env *env, struct mdd_object *obj,
                          void *dlh)
{
        LASSERT(dlh == pdo_handle);
}

void mdd_pdo_read_unlock(const struct lu_env *env, struct mdd_object *obj,
                         void *dlh)
{
        LASSERT(dlh == pdo_handle);
}

#else /* !MDD_DISABLE_PDO_LOCK */

#ifdef CONFIG_LOCKDEP
static struct lock_class_key mdd_pdirop_key;

#define RETIP ((unsigned long)__builtin_return_address(0))

static void mdd_lockdep_init(struct mdd_object *obj)
{
        lockdep_set_class_and_name(obj, &mdd_pdirop_key, "pdir");
}

static void mdd_lockdep_pd_acquire(struct mdd_object *obj,
                                   enum mdd_object_role role)
{
#ifdef HAVE_LOCK_MAP_ACQUIRE
        lock_map_acquire(&obj->dep_map);
#else
        lock_acquire(&obj->dep_map, role, 0, 1, 2, RETIP);
#endif
}

static void mdd_lockdep_pd_release(struct mdd_object *obj)
{
#ifdef HAVE_LOCK_MAP_ACQUIRE
        lock_map_release(&obj->dep_map);
#else
        lock_release(&obj->dep_map, 0, RETIP);
#endif
}

#else /* !CONFIG_LOCKDEP */

static void mdd_lockdep_init(struct mdd_object *obj)
{}
static void mdd_lockdep_pd_acquire(struct mdd_object *obj,
                                   enum mdd_object_role role)
{}
static void mdd_lockdep_pd_release(struct mdd_object *obj)
{}

#endif /* !CONFIG_LOCKDEP */

void mdd_pdlock_init(struct mdd_object *obj)
{
        dynlock_init(&obj->mod_pdlock);
        mdd_lockdep_init(obj);
}

void *mdd_pdo_write_lock(const struct lu_env *env, struct mdd_object *obj,
                         const char *name, enum mdd_object_role role)
{
        struct dynlock_handle *handle;
        unsigned long value = mdd_name2hash(name);

        handle = dynlock_lock(&obj->mod_pdlock, value, DLT_WRITE, GFP_NOFS);
        if (handle != NULL)
                mdd_lockdep_pd_acquire(obj, role);
        return handle;
}

void *mdd_pdo_read_lock(const struct lu_env *env, struct mdd_object *obj,
                        const char *name, enum mdd_object_role role)
{
        struct dynlock_handle *handle;
        unsigned long value = mdd_name2hash(name);
        handle = dynlock_lock(&obj->mod_pdlock, value, DLT_READ, GFP_NOFS);
        if (handle != NULL)
                mdd_lockdep_pd_acquire(obj, role);
        return handle;
}

void mdd_pdo_write_unlock(const struct lu_env *env, struct mdd_object *obj,
                          void *dlh)
{
        mdd_lockdep_pd_release(obj);
        return dynlock_unlock(&obj->mod_pdlock, dlh);
}

void mdd_pdo_read_unlock(const struct lu_env *env, struct mdd_object *obj,
                         void *dlh)
{
        mdd_lockdep_pd_release(obj);
        return dynlock_unlock(&obj->mod_pdlock, dlh);
}

#endif /* MDD_DISABLE_PDO_LOCK */
