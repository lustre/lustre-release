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
 * lustre/mdd/mdd_orphans.c
 *
 * Orphan handling code
 *
 * Author: Mike Pershin <tappro@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <lustre_fid.h>
#include "mdd_internal.h"

const char orph_index_name[] = "orphans";

static const struct dt_index_features orph_index_features = {
        .dif_flags       = DT_IND_UPDATE,
        .dif_keysize_min = sizeof(struct orph_key),
        .dif_keysize_max = sizeof(struct orph_key),
        .dif_recsize_min = sizeof(loff_t),
        .dif_recsize_max = sizeof(loff_t)
};

enum {
        ORPH_OP_UNLINK,
        ORPH_OP_TRUNCATE
};

static struct orph_key *orph_key_fill(const struct lu_env *env,
                                      const struct lu_fid *lf, __u32 op)
{
        struct orph_key *key = &mdd_env_info(env)->mti_orph_key;
        LASSERT(key);
        fid_cpu_to_be(&key->ok_fid, lf);
        key->ok_op = cpu_to_be32(op);
        return key;
}

static int orph_index_insert(const struct lu_env *env,
                             struct mdd_object *obj, __u32 op,
                             loff_t *offset, struct thandle *th)
{
        struct mdd_device *mdd = mdo2mdd(&obj->mod_obj);
        struct dt_object *dor = mdd->mdd_orphans;
        struct orph_key *key = orph_key_fill(env, mdo2fid(obj), op);
        int rc;
        ENTRY;

        rc = dor->do_index_ops->dio_insert(env, dor, (struct dt_rec *)offset,
                                           (struct dt_key *)key, th,
                                           BYPASS_CAPA, 1);
        RETURN(rc);
}

static int orph_index_delete(const struct lu_env *env,
                             struct mdd_object *obj, __u32 op,
                             struct thandle *th)
{
        struct mdd_device *mdd = mdo2mdd(&obj->mod_obj);
        struct dt_object *dor = mdd->mdd_orphans;
        struct orph_key *key = orph_key_fill(env, mdo2fid(obj), op);
        int rc;
        ENTRY;
        LASSERT(dor);
        rc = dor->do_index_ops->dio_delete(env, dor,
                                           (struct dt_key *)key, th,
                                           BYPASS_CAPA);
        RETURN(rc);

}

static inline struct orph_key *orph_key_empty(const struct lu_env *env,
                                              __u32 op)
{
        struct orph_key *key = &mdd_env_info(env)->mti_orph_key;
        LASSERT(key);
        fid_zero(&key->ok_fid);
        key->ok_op = cpu_to_be32(op);
        return key;
}

static void orph_key_test_and_del(const struct lu_env *env,
                                  struct mdd_device *mdd,
                                  const struct orph_key *key)
{
        struct mdd_object *mdo;

        mdo = mdd_object_find(env, mdd, &key->ok_fid);
        if (IS_ERR(mdo))
                CERROR("Invalid orphan!\n");
        else {
                mdd_write_lock(env, mdo, MOR_TGT_CHILD);
                if (mdo->mod_count == 0) {
                        /* non-opened orphan, let's delete it */
                        struct md_attr *ma = &mdd_env_info(env)->mti_ma;
                        CWARN("Found orphan!\n");
                        mdd_object_kill(env, mdo, ma);
                        /* TODO: now handle OST objects */
                        //mdd_ost_objects_destroy(env, ma);
                        /* TODO: destroy index entry */
                }
                mdd_write_unlock(env, mdo);
                mdd_object_put(env, mdo);
        }
}

static int orph_index_iterate(const struct lu_env *env,
                              struct mdd_device *mdd)
{
        struct dt_object *dt_obj = mdd->mdd_orphans;
        struct dt_it     *it;
        const struct dt_it_ops *iops;
        struct orph_key  *key = orph_key_empty(env, 0);
        int result;
        ENTRY;

        iops = &dt_obj->do_index_ops->dio_it;
        it = iops->init(env, dt_obj, 1, BYPASS_CAPA);
        if (it != NULL) {
                result = iops->get(env, it, (const void *)key);
                if (result > 0) {
                        int i;
                        /* main cycle */
                        for (result = 0, i = 0; result == +1; ++i) {
                                key = (void *)iops->key(env, it);
                                fid_be_to_cpu(&key->ok_fid, &key->ok_fid);
                                orph_key_test_and_del(env, mdd, key);
                                result = iops->next(env, it);
                        }
                } else if (result == 0)
                        /* Index contains no zero key? */
                        result = -EIO;

                iops->put(env, it);
                iops->fini(env, it);
        } else
                result = -ENOMEM;

        RETURN(result);
}

int orph_index_init(const struct lu_env *env, struct mdd_device *mdd)
{
        struct lu_fid fid;
        struct dt_object *d;
        int rc;
        ENTRY;

        d = dt_store_open(env, mdd->mdd_child, orph_index_name, &fid);
        if (!IS_ERR(d)) {
                mdd->mdd_orphans = d;
                rc = d->do_ops->do_index_try(env, d, &orph_index_features);
                if (rc == 0)
                        LASSERT(d->do_index_ops != NULL);
                else
                        CERROR("\"%s\" is not an index!\n", orph_index_name);
        } else {
                CERROR("cannot find \"%s\" obj %d\n",
                       orph_index_name, (int)PTR_ERR(d));
                rc = PTR_ERR(d);
        }

        RETURN(rc);
}

void orph_index_fini(const struct lu_env *env, struct mdd_device *mdd)
{
        ENTRY;
        if (mdd->mdd_orphans != NULL) {
                lu_object_put(env, &mdd->mdd_orphans->do_lu);
                mdd->mdd_orphans = NULL;
        }
        EXIT;
}

int __mdd_orphan_cleanup(const struct lu_env *env, struct mdd_device *d)
{
        return orph_index_iterate(env, d);
}

int __mdd_orphan_add(const struct lu_env *env,
                     struct mdd_object *obj, struct thandle *th)
{
        loff_t offset = 0;
        return orph_index_insert(env, obj, ORPH_OP_UNLINK, &offset, th);
}

int __mdd_orphan_del(const struct lu_env *env,
                     struct mdd_object *obj, struct thandle *th)
{
        return orph_index_delete(env, obj, ORPH_OP_UNLINK, th);
}
