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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 *
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
 *         Pravin B Shelar <pravin.shelar@sun.com>
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

const char orph_index_name[] = "PENDING";

enum {
        ORPH_OP_UNLINK,
        ORPH_OP_TRUNCATE
};

#define ORPHAN_FILE_NAME_FORMAT         "%016llx:%08x:%08x:%2x"
#define ORPHAN_FILE_NAME_FORMAT_18      "%llx:%08x"

static struct dt_key* orph_key_fill(const struct lu_env *env,
                                    const struct lu_fid *lf, __u32 op)
{
        char *key = mdd_env_info(env)->mti_orph_key;
        int rc;

        LASSERT(key);
        rc = snprintf(key, NAME_MAX + 1, ORPHAN_FILE_NAME_FORMAT,
                      (long long unsigned int)fid_seq(lf),
                      fid_oid(lf), fid_ver(lf), op);
        if (rc > 0)
                return (struct dt_key*) key;
        else
                return ERR_PTR(rc);
}

static struct dt_key* orph_key_fill_18(const struct lu_env *env,
                                       const struct lu_fid *lf)
{
        char *key = mdd_env_info(env)->mti_orph_key;
        int rc;

        LASSERT(key);
        rc = snprintf(key, NAME_MAX + 1, ORPHAN_FILE_NAME_FORMAT_18,
                      (unsigned long long)fid_seq(lf), fid_oid(lf));
        if (rc > 0)
                return (struct dt_key*) key;
        else
                return ERR_PTR(rc);
}

static int orphan_key_to_fid(char *key, struct lu_fid *lf)
{
        int rc = 0;
        unsigned int op;

        rc = sscanf(key, ORPHAN_FILE_NAME_FORMAT,
                    (long long unsigned int *)&lf->f_seq, &lf->f_oid,
                    &lf->f_ver, &op);
        if (rc == 4)
                return 0;

        /* build igif */
        rc = sscanf(key, ORPHAN_FILE_NAME_FORMAT_18,
                    (long long unsigned int *)&lf->f_seq, &lf->f_oid);
        if (rc == 2) {
                lf->f_ver = 0;
                return 0;
        }

        CERROR("can not parse orphan file name %s\n",key);
        return -EINVAL;
}

static inline void mdd_orphan_write_lock(const struct lu_env *env,
                                    struct mdd_device *mdd)
{

        struct dt_object        *dor    = mdd->mdd_orphans;
        dor->do_ops->do_write_lock(env, dor, MOR_TGT_ORPHAN);
}

static inline void mdd_orphan_write_unlock(const struct lu_env *env,
                                           struct mdd_device *mdd)
{

        struct dt_object        *dor    = mdd->mdd_orphans;
        dor->do_ops->do_write_unlock(env, dor);
}

static inline int mdd_orphan_insert_obj(const struct lu_env *env,
                                        struct mdd_device *mdd,
                                        struct mdd_object *obj,
                                        __u32 op,
                                        struct thandle *th)
{
        struct dt_object        *dor    = mdd->mdd_orphans;
        const struct lu_fid     *lf     = mdo2fid(obj);
        struct dt_key           *key    = orph_key_fill(env, lf, op);
        ENTRY;

        return  dor->do_index_ops->dio_insert(env, dor,
                                              (struct dt_rec *)lf,
                                              key, th,
                                              BYPASS_CAPA, 1);
}

static inline int mdd_orphan_delete_obj(const struct lu_env *env,
                                        struct mdd_device  *mdd ,
                                        struct dt_key *key,
                                        struct thandle *th)
{
        struct dt_object        *dor    = mdd->mdd_orphans;

        return  dor->do_index_ops->dio_delete(env, dor,
                                              key, th,
                                              BYPASS_CAPA);
}

static inline void mdd_orphan_ref_add(const struct lu_env *env,
                                 struct mdd_device *mdd,
                                 struct thandle *th)
{
        struct dt_object        *dor    = mdd->mdd_orphans;
        dor->do_ops->do_ref_add(env, dor, th);
}

static inline void mdd_orphan_ref_del(const struct lu_env *env,
                                 struct mdd_device *mdd,
                                 struct thandle *th)
{
        struct dt_object        *dor    = mdd->mdd_orphans;
        dor->do_ops->do_ref_del(env, dor, th);
}


static int orph_index_insert(const struct lu_env *env,
                             struct mdd_object *obj,
                             __u32 op,
                             struct thandle *th)
{
        struct mdd_device       *mdd    = mdo2mdd(&obj->mod_obj);
        struct dt_object        *dor    = mdd->mdd_orphans;
        const struct lu_fid     *lf_dor = lu_object_fid(&dor->do_lu);
        struct dt_object        *next   = mdd_object_child(obj);
        const struct dt_key     *dotdot = (const struct dt_key *) "..";
        int rc;
        ENTRY;

        LASSERT(mdd_write_locked(env, obj) != 0);
        LASSERT(!(obj->mod_flags & ORPHAN_OBJ));
        LASSERT(obj->mod_count > 0);

        mdd_orphan_write_lock(env, mdd);

        rc = mdd_orphan_insert_obj(env, mdd, obj, op, th);
        if (rc)
                GOTO(out, rc);

        mdo_ref_add(env, obj, th);
        if (!S_ISDIR(mdd_object_type(obj)))
                goto out;

        mdo_ref_add(env, obj, th);
        mdd_orphan_ref_add(env, mdd, th);

        /* try best to fixup directory, dont return errors
         * from here */
        if (!dt_try_as_dir(env, next))
                goto out;
        next->do_index_ops->dio_delete(env, next,
                                       dotdot, th, BYPASS_CAPA);

        next->do_index_ops->dio_insert(env, next,
                                       (struct dt_rec *) lf_dor,
                                       dotdot, th, BYPASS_CAPA, 1);

out:
        if (rc == 0)
                obj->mod_flags |= ORPHAN_OBJ;

        mdd_orphan_write_unlock(env, mdd);

        RETURN(rc);
}

/**
 * destroy osd object on mdd and associated ost objects.
 *
 * \param obj orphan object
 * \param mdd used for sending llog msg to osts
 *
 * \retval  0   success
 * \retval -ve  error
 */
static int orphan_object_kill(const struct lu_env *env,
                              struct mdd_object *obj,
                              struct mdd_device *mdd,
                              struct thandle *th)
{
        struct lu_attr *la = &mdd_env_info(env)->mti_la;
        int rc = 0;
        ENTRY;

        /* No need to lock this object as its recovery phase, and
         * no other thread can access it. But we need to lock it
         * as its precondition for osd api we using. */

        mdo_ref_del(env, obj, th);
        if (S_ISDIR(mdd_object_type(obj))) {
                mdo_ref_del(env, obj, th);
                mdd_orphan_ref_del(env, mdd, th);
        } else {
                /* regular file , cleanup linked ost objects */
                rc = mdd_la_get(env, obj, la, BYPASS_CAPA);
                if (rc == 0)
                        rc = mdd_lov_destroy(env, mdd, obj, la);
        }
        RETURN(rc);
}

static int orph_index_delete(const struct lu_env *env,
                             struct mdd_object *obj,
                             __u32 op,
                             struct thandle *th)
{
        struct mdd_device *mdd = mdo2mdd(&obj->mod_obj);
        struct dt_object *dor = mdd->mdd_orphans;
        struct dt_key *key;
        int rc;

        ENTRY;

        LASSERT(mdd_write_locked(env, obj) != 0);
        LASSERT(obj->mod_flags & ORPHAN_OBJ);
        LASSERT(obj->mod_count == 0);

        LASSERT(dor);

        key = orph_key_fill(env, mdo2fid(obj), op);
        mdd_orphan_write_lock(env, mdd);

        rc = mdd_orphan_delete_obj(env, mdd, key, th);

        if (rc == -ENOENT) {
                key = orph_key_fill_18(env, mdo2fid(obj));
                rc = mdd_orphan_delete_obj(env, mdd, key, th);
        }

        if (!rc) {
                /* lov objects will be destroyed by caller */
                mdo_ref_del(env, obj, th);
                if (S_ISDIR(mdd_object_type(obj))) {
                        mdo_ref_del(env, obj, th);
                        mdd_orphan_ref_del(env, mdd, th);
                }
                obj->mod_flags &= ~ORPHAN_OBJ;
        } else {
                CERROR("could not delete object: rc = %d\n",rc);
        }

        mdd_orphan_write_unlock(env, mdd);
        RETURN(rc);
}


static int orphan_object_destroy(const struct lu_env *env,
                                 struct mdd_object *obj,
                                 struct dt_key *key)
{
        struct thandle *th = NULL;
        struct mdd_device *mdd = mdo2mdd(&obj->mod_obj);
        struct md_attr *ma = &mdd_env_info(env)->mti_ma;
        int rc = 0;
        ENTRY;

        /* init ma */
        ma->ma_lmm_size = mdd_lov_mdsize(env, mdd);
        ma->ma_lmm = mdd_max_lmm_get(env, mdd);
        ma->ma_cookie_size = mdd_lov_cookiesize(env, mdd);
        ma->ma_cookie = mdd_max_cookie_get(env, mdd);
        ma->ma_need = MA_INODE | MA_LOV | MA_COOKIE;
        ma->ma_valid = 0;

        mdd_log_txn_param_build(env, &obj->mod_obj, ma, MDD_TXN_UNLINK_OP, 0);
        th = mdd_trans_start(env, mdd);
        if (IS_ERR(th)) {
                CERROR("Cannot get thandle\n");
                RETURN(-ENOMEM);
        }

        mdd_write_lock(env, obj, MOR_TGT_CHILD);
        if (likely(obj->mod_count == 0)) {
                mdd_orphan_write_lock(env, mdd);
                rc = mdd_orphan_delete_obj(env, mdd, key, th);
                if (!rc)
                        orphan_object_kill(env, obj, mdd, th);
                else
                        CERROR("could not delete object: rc = %d\n",rc);
                mdd_orphan_write_unlock(env, mdd);
        }
        mdd_write_unlock(env, obj);
        mdd_trans_stop(env, mdd, 0, th);

        RETURN(rc);
}

static int orph_key_test_and_del(const struct lu_env *env,
                                 struct mdd_device *mdd,
                                 struct lu_fid *lf,
                                 struct dt_key *key)
{
        struct mdd_object *mdo;
        int rc;

        mdo = mdd_object_find(env, mdd, lf);

        if (IS_ERR(mdo))
                return PTR_ERR(mdo);

        rc = -EBUSY;
        if (mdo->mod_count == 0) {
                CWARN("Found orphan! Delete it\n");
                rc = orphan_object_destroy(env, mdo, key);
        } else {
                mdd_write_lock(env, mdo, MOR_TGT_CHILD);
                if (likely(mdo->mod_count > 0)) {
                        CDEBUG(D_HA, "Found orphan, open count = %d\n",
                               mdo->mod_count);
                        mdo->mod_flags |= ORPHAN_OBJ;
                }
                mdd_write_unlock(env, mdo);
        }

        mdd_object_put(env, mdo);
        return rc;
}

static int orph_index_iterate(const struct lu_env *env,
                              struct mdd_device *mdd)
{
        struct dt_object *dor = mdd->mdd_orphans;
        char             *mti_key = mdd_env_info(env)->mti_orph_key;
        const struct dt_it_ops *iops;
        struct dt_it     *it;
        char             *key;
        struct lu_fid     fid;
        int               result = 0;
        int               key_sz = 0;
        int               rc;
        __u64             cookie;
        ENTRY;

        /* In recovery phase, do not need for any lock here */

        iops = &dor->do_index_ops->dio_it;
        it = iops->init(env, dor, LUDA_64BITHASH, BYPASS_CAPA);
        if (!IS_ERR(it)) {
                result = iops->load(env, it, 0);
                if (result > 0) {
                        /* main cycle */
                        do {

                                key = (void *)iops->key(env, it);
                                if (IS_ERR(key)) {
                                        CERROR("key failed when clean pending.\n");
                                        goto next;
                                }
                                key_sz = iops->key_size(env, it);

                                /* filter out "." and ".." entries from
                                 * PENDING dir. */
                                if (key_sz < 8)
                                        goto next;

                                memcpy(mti_key, key, key_sz);
                                mti_key[key_sz] = 0;

                                if (orphan_key_to_fid(mti_key, &fid))
                                        goto next;
                                if (!fid_is_sane(&fid)) {
                                        CERROR("fid is not sane when clean pending.\n");
                                        goto next;
                                }

                                /* kill orphan object */
                                cookie =  iops->store(env, it);
                                iops->put(env, it);
                                rc = orph_key_test_and_del(env, mdd, &fid,
                                                (struct dt_key *)mti_key);

                                /* after index delete reset iterator */
                                if (!rc)
                                        result = iops->get(env, it,
                                                           (const void *)"");
                                else
                                        result = iops->load(env, it, cookie);
next:
                                result = iops->next(env, it);
                        } while (result == 0);
                        result = 0;
                } else if (result == 0) {
                        CERROR("Input/Output for clean pending.\n");
                        /* Index contains no zero key? */
                        result = -EIO;
                }
                iops->put(env, it);
                iops->fini(env, it);
        } else {
                result = PTR_ERR(it);
                CERROR("Cannot clean pending (%d).\n", result);
        }

        RETURN(result);
}

int orph_index_init(const struct lu_env *env, struct mdd_device *mdd)
{
        struct lu_fid fid;
        struct dt_object *d;
        int rc = 0;
        ENTRY;

        d = dt_store_open(env, mdd->mdd_child, "", orph_index_name, &fid);
        if (!IS_ERR(d)) {
                mdd->mdd_orphans = d;
                if (!dt_try_as_dir(env, d)) {
                        rc = -ENOTDIR;
                        CERROR("\"%s\" is not an index! : rc = %d\n",
                                        orph_index_name, rc);
                }
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

/**
 *  Iterate orphan index to cleanup orphan objects in case of recovery.
 *  \param d   mdd device in recovery.
 *
 */

int __mdd_orphan_cleanup(const struct lu_env *env, struct mdd_device *d)
{
        return orph_index_iterate(env, d);
}

/**
 *  delete an orphan \a obj from orphan index.
 *  \param obj file or directory.
 *  \param th  transaction for index insert.
 *
 *  \pre obj nlink == 0 && obj->mod_count != 0
 *
 *  \retval 0  success
 *  \retval  -ve index operation error.
 */

int __mdd_orphan_add(const struct lu_env *env,
                     struct mdd_object *obj, struct thandle *th)
{
        return orph_index_insert(env, obj, ORPH_OP_UNLINK, th);
}

/**
 *  delete an orphan \a obj from orphan index.
 *  \param obj file or directory.
 *  \param th  transaction for index deletion and object destruction.
 *
 *  \pre obj->mod_count == 0 && ORPHAN_OBJ is set for obj.
 *
 *  \retval 0  success
 *  \retval  -ve index operation error.
 */

int __mdd_orphan_del(const struct lu_env *env,
                     struct mdd_object *obj, struct thandle *th)
{
        return orph_index_delete(env, obj, ORPH_OP_UNLINK, th);
}
