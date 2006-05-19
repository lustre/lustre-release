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

#include <dt_object.h>
#include <libcfs/list.h>

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

int dt_txn_hook_start(struct lu_context *ctx,
                      struct dt_device *dev, struct txn_param *param)
{
        int result;
        struct dt_txn_callback *cb;

        result = 0;
        list_for_each_entry(cb, &dev->dd_txn_callbacks, dtc_linkage) {
                if (cb->dtc_txn_start == NULL)
                        continue;
                result = cb->dtc_txn_start(ctx, dev, param, cb->dtc_cookie);
                if (result < 0)
                        break;
        }
        return result;
}
EXPORT_SYMBOL(dt_txn_hook_start);

int dt_txn_hook_stop(struct lu_context *ctx,
                     struct dt_device *dev, struct thandle *txn)
{
        int result;
        struct dt_txn_callback *cb;

        result = 0;
        list_for_each_entry(cb, &dev->dd_txn_callbacks, dtc_linkage) {
                if (cb->dtc_txn_stop == NULL)
                        continue;
                result = cb->dtc_txn_stop(ctx, dev, txn, cb->dtc_cookie);
                if (result < 0)
                        break;
        }
        return result;
}
EXPORT_SYMBOL(dt_txn_hook_stop);

int dt_txn_hook_commit(struct lu_context *ctx,
                       struct dt_device *dev, struct thandle *txn)
{
        int result;
        struct dt_txn_callback *cb;

        result = 0;
        list_for_each_entry(cb, &dev->dd_txn_callbacks, dtc_linkage) {
                if (cb->dtc_txn_commit == NULL)
                        continue;
                result = cb->dtc_txn_commit(ctx, dev, txn, cb->dtc_cookie);
                if (result < 0)
                        break;
        }
        return result;
}
EXPORT_SYMBOL(dt_txn_hook_commit);

int dt_device_init(struct dt_device *dev, struct lu_device_type *t)
{
        CFS_INIT_LIST_HEAD(&dev->dd_txn_callbacks);
        return lu_device_init(&dev->dd_lu_dev, t);
}
EXPORT_SYMBOL(dt_device_init);

void dt_device_fini(struct dt_device *dev)
{
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
