/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Dt Object.
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
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
 *
 * Generic functions from dt_object.h
 */

#define DEBUG_SUBSYSTEM S_CLASS
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#include <obd.h>
#include <dt_object.h>
#include <libcfs/list.h>

/* no lock is necessary to protect the list, because call-backs 
 * are added during system startup. Please refer to "struct dt_device".
 */
void dt_txn_callback_add(struct dt_device *dev, struct dt_txn_callback *cb)
{
        list_add(&cb->dtc_linkage, &dev->dd_txn_callbacks);
}
EXPORT_SYMBOL(dt_txn_callback_add);

void dt_txn_callback_del(struct dt_device *dev, struct dt_txn_callback *cb)
{
        list_del_init(&cb->dtc_linkage);
}
EXPORT_SYMBOL(dt_txn_callback_del);

int dt_txn_hook_start(const struct lu_context *ctxt,
                      struct dt_device *dev, struct txn_param *param)
{
        int result;
        struct dt_txn_callback *cb;

        result = 0;
        list_for_each_entry(cb, &dev->dd_txn_callbacks, dtc_linkage) {
                if (cb->dtc_txn_start == NULL)
                        continue;
                result = cb->dtc_txn_start(ctxt, param, cb->dtc_cookie);
                if (result < 0)
                        break;
        }
        return result;
}
EXPORT_SYMBOL(dt_txn_hook_start);

int dt_txn_hook_stop(const struct lu_context *ctxt, struct thandle *txn)
{
        struct dt_device       *dev = txn->th_dev;
        struct dt_txn_callback *cb;
        int                     result;

        result = 0;
        list_for_each_entry(cb, &dev->dd_txn_callbacks, dtc_linkage) {
                if (cb->dtc_txn_stop == NULL)
                        continue;
                result = cb->dtc_txn_stop(ctxt, txn, cb->dtc_cookie);
                if (result < 0)
                        break;
        }
        return result;
}
EXPORT_SYMBOL(dt_txn_hook_stop);

int dt_txn_hook_commit(const struct lu_context *ctxt, struct thandle *txn)
{
        struct dt_device       *dev = txn->th_dev;
        struct dt_txn_callback *cb;
        int                     result;

        result = 0;
        list_for_each_entry(cb, &dev->dd_txn_callbacks, dtc_linkage) {
                if (cb->dtc_txn_commit == NULL)
                        continue;
                result = cb->dtc_txn_commit(ctxt, txn, cb->dtc_cookie);
                if (result < 0)
                        break;
        }
        return result;
}
EXPORT_SYMBOL(dt_txn_hook_commit);

int dt_device_init(struct dt_device *dev, struct lu_device_type *t)
{
        int rc;

        CFS_INIT_LIST_HEAD(&dev->dd_txn_callbacks);
        rc = lu_context_init(&dev->dd_ctx_for_commit, LCT_MD_THREAD);
        if (rc == 0) {
                lu_context_enter(&dev->dd_ctx_for_commit);
                rc = lu_device_init(&dev->dd_lu_dev, t);
                if (rc != 0) {
                        lu_context_exit(&dev->dd_ctx_for_commit);
                        lu_context_fini(&dev->dd_ctx_for_commit);
                }
        }
        return rc;
}
EXPORT_SYMBOL(dt_device_init);

void dt_device_fini(struct dt_device *dev)
{
        lu_context_exit(&dev->dd_ctx_for_commit);
        lu_context_fini(&dev->dd_ctx_for_commit);
        lu_device_fini(&dev->dd_lu_dev);
}
EXPORT_SYMBOL(dt_device_fini);

int dt_object_init(struct dt_object *obj,
                   struct lu_object_header *h, struct lu_device *d)

{
        return lu_object_init(&obj->do_lu, h, d);
}
EXPORT_SYMBOL(dt_object_init);

void dt_object_fini(struct dt_object *obj)
{
        lu_object_fini(&obj->do_lu);
}
EXPORT_SYMBOL(dt_object_fini);

int dt_try_as_dir(const struct lu_context *ctx, struct dt_object *obj)
{
        if (obj->do_index_ops == NULL)
                obj->do_ops->do_index_try(ctx, obj, &dt_directory_features);
        return obj->do_index_ops != NULL;
}
EXPORT_SYMBOL(dt_try_as_dir);

static int dt_lookup(const struct lu_context *ctx, struct dt_object *dir,
                     const char *name, struct lu_fid *fid)
{
        struct dt_rec       *rec = (struct dt_rec *)fid;
        const struct dt_key *key = (const struct dt_key *)name;
        int result;

        if (dt_try_as_dir(ctx, dir))
                result = dir->do_index_ops->dio_lookup(ctx, dir, rec, key);
        else
                result = -ENOTDIR;
        return result;
}

static struct dt_object *dt_locate(const struct lu_context *ctx,
                                   struct dt_device *dev,
                                   const struct lu_fid *fid)
{
        struct lu_object *obj;
        struct dt_object *dt;

        obj = lu_object_find(ctx, dev->dd_lu_dev.ld_site, fid);
        if (!IS_ERR(obj)) {
                obj = lu_object_locate(obj->lo_header, dev->dd_lu_dev.ld_type);
                LASSERT(obj != NULL);
                dt = container_of(obj, struct dt_object, do_lu);
        } else
                dt = (void *)obj;
        return dt;
}

struct dt_object *dt_store_open(const struct lu_context *ctx,
                                struct dt_device *dt, const char *name,
                                struct lu_fid *fid)
{
        int result;

        struct dt_object *root;
        struct dt_object *child;

        result = dt->dd_ops->dt_root_get(ctx, dt, fid);
        if (result == 0) {
                root = dt_locate(ctx, dt, fid);
                if (!IS_ERR(root)) {
                        result = dt_lookup(ctx, root, name, fid);
                        if (result == 0)
                                child = dt_locate(ctx, dt, fid);
                        else
                                child = ERR_PTR(result);
                        lu_object_put(ctx, &root->do_lu);
                } else {
                        CERROR("No root\n");
                        child = (void *)root;
                }
        } else
                child = ERR_PTR(result);
        return child;
}
EXPORT_SYMBOL(dt_store_open);

const struct dt_index_features dt_directory_features;
EXPORT_SYMBOL(dt_directory_features);

