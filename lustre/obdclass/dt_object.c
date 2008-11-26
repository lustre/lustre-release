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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/dt_object.c
 *
 * Dt Object.
 * Generic functions from dt_object.h
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#include <obd.h>
#include <dt_object.h>
#include <libcfs/list.h>
/* fid_be_to_cpu() */
#include <lustre_fid.h>

struct dt_find_hint {
        struct lu_fid        *dfh_fid;
        struct dt_device     *dfh_dt;
        struct dt_object     *dfh_o;
};

struct dt_thread_info {
        char                    dti_buf[DT_MAX_PATH];
        struct lu_fid_pack      dti_pack;
        struct dt_find_hint     dti_dfh;
};

/* context key constructor/destructor: dt_global_key_init, dt_global_key_fini */
LU_KEY_INIT(dt_global, struct dt_thread_info);
LU_KEY_FINI(dt_global, struct dt_thread_info);

static struct lu_context_key dt_key = {
        .lct_tags = LCT_MD_THREAD|LCT_DT_THREAD,
        .lct_init = dt_global_key_init,
        .lct_fini = dt_global_key_fini
};

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

int dt_txn_hook_start(const struct lu_env *env,
                      struct dt_device *dev, struct txn_param *param)
{
        int result;
        struct dt_txn_callback *cb;

        result = 0;
        list_for_each_entry(cb, &dev->dd_txn_callbacks, dtc_linkage) {
                if (cb->dtc_txn_start == NULL)
                        continue;
                result = cb->dtc_txn_start(env, param, cb->dtc_cookie);
                if (result < 0)
                        break;
        }
        return result;
}
EXPORT_SYMBOL(dt_txn_hook_start);

int dt_txn_hook_stop(const struct lu_env *env, struct thandle *txn)
{
        struct dt_device       *dev = txn->th_dev;
        struct dt_txn_callback *cb;
        int                     result;

        result = 0;
        list_for_each_entry(cb, &dev->dd_txn_callbacks, dtc_linkage) {
                if (cb->dtc_txn_stop == NULL)
                        continue;
                result = cb->dtc_txn_stop(env, txn, cb->dtc_cookie);
                if (result < 0)
                        break;
        }
        return result;
}
EXPORT_SYMBOL(dt_txn_hook_stop);

int dt_txn_hook_commit(const struct lu_env *env, struct thandle *txn)
{
        struct dt_device       *dev = txn->th_dev;
        struct dt_txn_callback *cb;
        int                     result;

        result = 0;
        list_for_each_entry(cb, &dev->dd_txn_callbacks, dtc_linkage) {
                if (cb->dtc_txn_commit == NULL)
                        continue;
                result = cb->dtc_txn_commit(env, txn, cb->dtc_cookie);
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

int dt_try_as_dir(const struct lu_env *env, struct dt_object *obj)
{
        if (obj->do_index_ops == NULL)
                obj->do_ops->do_index_try(env, obj, &dt_directory_features);
        return obj->do_index_ops != NULL;
}
EXPORT_SYMBOL(dt_try_as_dir);

enum dt_format_type dt_mode_to_dft(__u32 mode)
{
        enum dt_format_type result;

        switch (mode & S_IFMT) {
        case S_IFDIR:
                result = DFT_DIR;
                break;
        case S_IFREG:
                result = DFT_REGULAR;
                break;
        case S_IFLNK:
                result = DFT_SYM;
                break;
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:
                result = DFT_NODE;
                break;
        default:
                LBUG();
                break;
        }
        return result;
}

EXPORT_SYMBOL(dt_mode_to_dft);
/**
 * lookup fid for object named \a name in directory \a dir.
 */

static int dt_lookup(const struct lu_env *env, struct dt_object *dir,
                     const char *name, struct lu_fid *fid)
{
        struct dt_thread_info *info = lu_context_key_get(&env->le_ctx,
                                                         &dt_key);
        struct lu_fid_pack *pack = &info->dti_pack;
        struct dt_rec       *rec = (struct dt_rec *)pack;
        const struct dt_key *key = (const struct dt_key *)name;
        int result;

        if (dt_try_as_dir(env, dir)) {
                result = dir->do_index_ops->dio_lookup(env, dir, rec, key,
                                                       BYPASS_CAPA);
                if (result > 0)
                        result = fid_unpack(pack, fid);
                else if (result == 0)
                        result = -ENOENT;
        } else
                result = -ENOTDIR;
        return result;
}

/**
 * get object for given \a fid.
 */
struct dt_object *dt_locate(const struct lu_env *env,
                            struct dt_device *dev,
                            const struct lu_fid *fid)
{
        struct lu_object *obj;
        struct dt_object *dt;

        obj = lu_object_find(env, &dev->dd_lu_dev, fid, NULL);
        if (!IS_ERR(obj)) {
                obj = lu_object_locate(obj->lo_header, dev->dd_lu_dev.ld_type);
                LASSERT(obj != NULL);
                dt = container_of(obj, struct dt_object, do_lu);
        } else
                dt = (struct dt_object *)obj;
        return dt;
}
EXPORT_SYMBOL(dt_locate);

/**
 * find a object named \a entry in given \a dfh->dfh_o directory.
 */
static int dt_find_entry(const struct lu_env *env, const char *entry, void *data)
{
        struct dt_find_hint  *dfh = data;
        struct dt_device     *dt = dfh->dfh_dt;
        struct lu_fid        *fid = dfh->dfh_fid;
        struct dt_object     *obj = dfh->dfh_o;
        int                   result;

        result = dt_lookup(env, obj, entry, fid);
        lu_object_put(env, &obj->do_lu);
        if (result == 0) {
                obj = dt_locate(env, dt, fid);
                if (IS_ERR(obj))
                        result = PTR_ERR(obj);
        }
        dfh->dfh_o = obj;
        return result;
}

/**
 * Abstract function which parses path name. This function feeds
 * path component to \a entry_func.
 */
int dt_path_parser(const struct lu_env *env,
                   char *path, dt_entry_func_t entry_func,
                   void *data)
{
        char *e;
        int rc = 0;

        while (1) {
                e = strsep(&path, "/");
                if (e == NULL)
                        break;

                if (e[0] == 0) {
                        if (!path || path[0] == '\0')
                                break;
                        continue;
                }
                rc = entry_func(env, e, data);
                if (rc)
                        break;
        }

        return rc;
}

static struct dt_object *dt_store_resolve(const struct lu_env *env,
                                          struct dt_device *dt,
                                          const char *path,
                                          struct lu_fid *fid)
{
        struct dt_thread_info *info = lu_context_key_get(&env->le_ctx,
                                                         &dt_key);
        struct dt_find_hint *dfh = &info->dti_dfh;
        struct dt_object     *obj;
        char *local = info->dti_buf;
        int result;

        dfh->dfh_dt = dt;
        dfh->dfh_fid = fid;

        strncpy(local, path, DT_MAX_PATH);
        local[DT_MAX_PATH - 1] = '\0';

        result = dt->dd_ops->dt_root_get(env, dt, fid);
        if (result == 0) {
                obj = dt_locate(env, dt, fid);
                if (!IS_ERR(obj)) {
                        dfh->dfh_o = obj;
                        result = dt_path_parser(env, local, dt_find_entry, dfh);
                        if (result != 0)
                                obj = ERR_PTR(result);
                        else
                                obj = dfh->dfh_o;
                }
        } else {
                obj = ERR_PTR(result);
        }
        return obj;
}

static struct dt_object *dt_reg_open(const struct lu_env *env,
                                     struct dt_device *dt,
                                     struct dt_object *p,
                                     const char *name,
                                     struct lu_fid *fid)
{
        struct dt_object *o;
        int result;

        result = dt_lookup(env, p, name, fid);
        if (result == 0){
                o = dt_locate(env, dt, fid);
        }
        else
                o = ERR_PTR(result);

        return o;
}

/**
 * Open dt object named \a filename from \a dirname directory.
 *      \param  dt      dt device
 *      \param  fid     on success, object fid is stored in *fid
 */
struct dt_object *dt_store_open(const struct lu_env *env,
                                struct dt_device *dt,
                                const char *dirname,
                                const char *filename,
                                struct lu_fid *fid)
{
        struct dt_object *file;
        struct dt_object *dir;

        dir = dt_store_resolve(env, dt, dirname, fid);
        if (!IS_ERR(dir)) {
                file = dt_reg_open(env, dt, dir,
                                   filename, fid);
                lu_object_put(env, &dir->do_lu);
        } else {
                file = dir;
        }
        return file;
}
EXPORT_SYMBOL(dt_store_open);

/* dt class init function. */
int dt_global_init(void)
{
        int result;

        LU_CONTEXT_KEY_INIT(&dt_key);
        result = lu_context_key_register(&dt_key);
        return result;
}

void dt_global_fini(void)
{
        lu_context_key_degister(&dt_key);
}

const struct dt_index_features dt_directory_features;
EXPORT_SYMBOL(dt_directory_features);
