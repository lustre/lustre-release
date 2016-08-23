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
 * Copyright (c) 2011, 2014, Intel Corporation.
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

#define DEBUG_SUBSYSTEM S_MDS

#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <lustre_fid.h>
#include "mdd_internal.h"

const char orph_index_name[] = "PENDING";
static const char dotdot[] = "..";

enum {
        ORPH_OP_UNLINK,
        ORPH_OP_TRUNCATE
};

#define ORPHAN_FILE_NAME_FORMAT         "%016llx:%08x:%08x:%2x"
#define ORPHAN_FILE_NAME_FORMAT_18      "%llx:%08x"

static struct dt_key* orph_key_fill(const struct lu_env *env,
                                    const struct lu_fid *lf, __u32 op)
{
	char *key = mdd_env_info(env)->mti_key;
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
	char *key = mdd_env_info(env)->mti_key;
        int rc;

        LASSERT(key);
        rc = snprintf(key, NAME_MAX + 1, ORPHAN_FILE_NAME_FORMAT_18,
                      (unsigned long long)fid_seq(lf), fid_oid(lf));
        if (rc > 0)
                return (struct dt_key*) key;
        else
                return ERR_PTR(rc);
}

static inline void mdd_orphan_write_lock(const struct lu_env *env,
					 struct mdd_device *mdd)
{
	struct dt_object *dor = mdd->mdd_orphans;
	dt_write_lock(env, dor, MOR_TGT_ORPHAN);
}

static inline void mdd_orphan_write_unlock(const struct lu_env *env,
					   struct mdd_device *mdd)
{
	struct dt_object *dor = mdd->mdd_orphans;
	dt_write_unlock(env, dor);
}

static inline int mdd_orphan_insert_obj(const struct lu_env *env,
					struct mdd_device *mdd,
					struct mdd_object *obj,
					__u32 op, struct thandle *th)
{
	struct dt_insert_rec	*rec	= &mdd_env_info(env)->mti_dt_rec;
	struct dt_object	*dor	= mdd->mdd_orphans;
	const struct lu_fid	*lf	= mdo2fid(obj);
	struct dt_key		*key	= orph_key_fill(env, lf, op);

	rec->rec_fid = lf;
	rec->rec_type = mdd_object_type(obj);

	return dt_insert(env, dor, (const struct dt_rec *)rec, key, th, 1);
}

static inline int mdd_orphan_delete_obj(const struct lu_env *env,
                                        struct mdd_device  *mdd ,
                                        struct dt_key *key,
                                        struct thandle *th)
{
	struct dt_object *dor = mdd->mdd_orphans;

	return dt_delete(env, dor, key, th);
}

static inline int mdd_orphan_ref_add(const struct lu_env *env,
				     struct mdd_device *mdd,
				     struct thandle *th)
{
	struct dt_object *dor = mdd->mdd_orphans;
	return dt_ref_add(env, dor, th);
}

static inline int mdd_orphan_ref_del(const struct lu_env *env,
				     struct mdd_device *mdd,
				     struct thandle *th)
{
	struct dt_object *dor = mdd->mdd_orphans;
	return dt_ref_del(env, dor, th);
}


int orph_declare_index_insert(const struct lu_env *env,
			      struct mdd_object *obj,
			      umode_t mode, struct thandle *th)
{
	struct dt_insert_rec	*rec = &mdd_env_info(env)->mti_dt_rec;
	struct mdd_device	*mdd = mdo2mdd(&obj->mod_obj);
	struct dt_key		*key;
	int			rc;

	key = orph_key_fill(env, mdo2fid(obj), ORPH_OP_UNLINK);

	rec->rec_fid = mdo2fid(obj);
	rec->rec_type = mode;
	rc = dt_declare_insert(env, mdd->mdd_orphans,
			       (const struct dt_rec *)rec, key, th);
	if (rc != 0)
		return rc;

	rc = mdo_declare_ref_add(env, obj, th);
	if (rc)
		return rc;

	if (!S_ISDIR(mode))
		return 0;

	rc = mdo_declare_ref_add(env, obj, th);
	if (rc)
		return rc;

	rc = dt_declare_ref_add(env, mdd->mdd_orphans, th);
	if (rc)
		return rc;

	rc = mdo_declare_index_delete(env, obj, dotdot, th);
	if (rc)
		return rc;

	rc = mdo_declare_index_insert(env, obj,
				      lu_object_fid(&mdd->mdd_orphans->do_lu),
				      S_IFDIR, dotdot, th);

	return rc;
}

static int orph_index_insert(const struct lu_env *env,
			     struct mdd_object *obj,
			     __u32 op, struct thandle *th)
{
	struct mdd_device	*mdd	= mdo2mdd(&obj->mod_obj);
	struct dt_object	*dor	= mdd->mdd_orphans;
	const struct lu_fid	*lf_dor	= lu_object_fid(&dor->do_lu);
	struct dt_object	*next	= mdd_object_child(obj);
	struct dt_insert_rec	*rec	= &mdd_env_info(env)->mti_dt_rec;
	int			 rc;
        ENTRY;

        LASSERT(mdd_write_locked(env, obj) != 0);
        LASSERT(!(obj->mod_flags & ORPHAN_OBJ));

        mdd_orphan_write_lock(env, mdd);

        rc = mdd_orphan_insert_obj(env, mdd, obj, op, th);
        if (rc)
                GOTO(out, rc);

        mdo_ref_add(env, obj, th);
        if (!S_ISDIR(mdd_object_type(obj)))
		GOTO(out, rc = 0);

        mdo_ref_add(env, obj, th);
        mdd_orphan_ref_add(env, mdd, th);

        /* try best to fixup directory, dont return errors
         * from here */
        if (!dt_try_as_dir(env, next))
		GOTO(out, rc = 0);

	dt_delete(env, next, (const struct dt_key *)dotdot, th);

	rec->rec_fid = lf_dor;
	rec->rec_type = S_IFDIR;
	dt_insert(env, next, (const struct dt_rec *)rec,
		  (const struct dt_key *)dotdot, th, 1);

out:
        if (rc == 0)
                obj->mod_flags |= ORPHAN_OBJ;

        mdd_orphan_write_unlock(env, mdd);

        RETURN(rc);
}

int orph_declare_index_delete(const struct lu_env *env,
                              struct mdd_object *obj,

                              struct thandle *th)
{
        struct mdd_device *mdd = mdo2mdd(&obj->mod_obj);
	struct dt_key	  *key;
        int                rc;

	key = orph_key_fill(env, mdo2fid(obj), ORPH_OP_UNLINK);

	rc = dt_declare_delete(env, mdd->mdd_orphans, key, th);
        if (rc)
                return rc;

        rc = mdo_declare_ref_del(env, obj, th);
        if (rc)
                return rc;

        if (S_ISDIR(mdd_object_type(obj))) {
                rc = mdo_declare_ref_del(env, obj, th);
                if (rc)
                        return rc;

                rc = dt_declare_ref_del(env, mdd->mdd_orphans, th);
        }

        return rc;
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
	int rc = 0;
	ENTRY;

	th = mdd_trans_create(env, mdd);
	if (IS_ERR(th)) {
		CERROR("Cannot get thandle\n");
		RETURN(PTR_ERR(th));
	}

	rc = orph_declare_index_delete(env, obj, th);
	if (rc)
		GOTO(stop, rc);

	rc = mdo_declare_destroy(env, obj, th);
	if (rc)
		GOTO(stop, rc);

	rc = mdd_trans_start(env, mdd, th);
	if (rc)
		GOTO(stop, rc);

	mdd_write_lock(env, obj, MOR_TGT_CHILD);
	if (likely(obj->mod_count == 0)) {
		mdd_orphan_write_lock(env, mdd);
		rc = mdd_orphan_delete_obj(env, mdd, key, th);
		if (rc == 0) {
			mdo_ref_del(env, obj, th);
			if (S_ISDIR(mdd_object_type(obj))) {
				mdo_ref_del(env, obj, th);
				mdd_orphan_ref_del(env, mdd, th);
			}
			rc = mdo_destroy(env, obj, th);
		} else
			CERROR("could not delete object: rc = %d\n", rc);
		mdd_orphan_write_unlock(env, mdd);
	}
	mdd_write_unlock(env, obj);

stop:
	rc = mdd_trans_stop(env, mdd, 0, th);

	RETURN(rc);
}

/**
 * Delete unused orphan with FID \a lf from PENDING directory
 *
 * \param mdd  MDD device finishing recovery
 * \param lf   FID of file or directory to delete
 * \param key  cookie for this entry in index iterator
 *
 * \retval 0   success
 * \retval -ve error
 */
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
                CDEBUG(D_HA, "Found orphan "DFID", delete it\n", PFID(lf));
                rc = orphan_object_destroy(env, mdo, key);
                if (rc) /* so replay-single.sh test_37 works */
                        CERROR("%s: error unlinking orphan "DFID" from "
                               "PENDING: rc = %d\n",
			       mdd2obd_dev(mdd)->obd_name, PFID(lf), rc);
        } else {
                mdd_write_lock(env, mdo, MOR_TGT_CHILD);
                if (likely(mdo->mod_count > 0)) {
                        CDEBUG(D_HA, "Found orphan "DFID" count %d, skip it\n",
                               PFID(lf), mdo->mod_count);
                        mdo->mod_flags |= ORPHAN_OBJ;
                }
                mdd_write_unlock(env, mdo);
        }

        mdd_object_put(env, mdo);
        return rc;
}

/**
 * delete unreferenced files and directories in the PENDING directory
 *
 * Files that remain in PENDING after client->MDS recovery has completed
 * have to be referenced (opened) by some client during recovery, or they
 * will be deleted here (for clients that did not complete recovery).
 *
 * \param thread  info about orphan cleanup thread
 *
 * \retval 0   success
 * \retval -ve error
 */
static int orph_index_iterate(const struct lu_env *env,
			      struct mdd_generic_thread *thread)
{
	struct mdd_device *mdd = (struct mdd_device *)thread->mgt_data;
	struct dt_object *dor = mdd->mdd_orphans;
	struct lu_dirent *ent = &mdd_env_info(env)->mti_ent;
	const struct dt_it_ops *iops;
	struct dt_it     *it;
	struct lu_fid     fid;
        int               key_sz = 0;
        int               rc;
        __u64             cookie;
        ENTRY;

        iops = &dor->do_index_ops->dio_it;
	it = iops->init(env, dor, LUDA_64BITHASH);
        if (IS_ERR(it)) {
                rc = PTR_ERR(it);
                CERROR("%s: cannot clean PENDING: rc = %d\n",
		       mdd2obd_dev(mdd)->obd_name, rc);
                GOTO(out, rc);
        }

        rc = iops->load(env, it, 0);
        if (rc < 0)
                GOTO(out_put, rc);
        if (rc == 0) {
                CERROR("%s: error loading iterator to clean PENDING\n",
		       mdd2obd_dev(mdd)->obd_name);
                /* Index contains no zero key? */
                GOTO(out_put, rc = -EIO);
        }

	do {
		if (thread->mgt_abort)
			break;

		key_sz = iops->key_size(env, it);
		/* filter out "." and ".." entries from PENDING dir. */
		if (key_sz < 8)
			goto next;

		rc = iops->rec(env, it, (struct dt_rec *)ent, LUDA_64BITHASH);
		if (rc != 0) {
			CERROR("%s: fail to get FID for orphan it: rc = %d\n",
			       mdd2obd_dev(mdd)->obd_name, rc);
			goto next;
		}

		fid_le_to_cpu(&fid, &ent->lde_fid);
		if (!fid_is_sane(&fid)) {
			CERROR("%s: bad FID "DFID" cleaning PENDING\n",
			       mdd2obd_dev(mdd)->obd_name, PFID(&fid));
			goto next;
		}

		/* kill orphan object */
		cookie = iops->store(env, it);
		iops->put(env, it);
		rc = orph_key_test_and_del(env, mdd, &fid,
					   (struct dt_key *)ent->lde_name);

		/* after index delete reset iterator */
		if (rc == 0)
			rc = iops->get(env, it, (const void *)"");
		else
			rc = iops->load(env, it, cookie);
next:
		rc = iops->next(env, it);
	} while (rc == 0);

	GOTO(out_put, rc = 0);
out_put:
	iops->put(env, it);
	iops->fini(env, it);

out:
	return rc;
}

/**
 * open the PENDING directory for device \a mdd
 *
 * The PENDING directory persistently tracks files and directories that were
 * unlinked from the namespace (nlink == 0) but are still held open by clients.
 * Those inodes shouldn't be deleted if the MDS crashes, because the clients
 * would not be able to recover and reopen those files.  Instead, these inodes
 * are linked into the PENDING directory on disk, and only deleted if all
 * clients close them, or the MDS finishes client recovery without any client
 * reopening them (i.e. former clients didn't join recovery).
 *  \param d   mdd device being started.
 *
 *  \retval 0  success
 *  \retval  -ve index operation error.
 *
 */
int orph_index_init(const struct lu_env *env, struct mdd_device *mdd)
{
	struct lu_fid		 fid;
	struct dt_object	*d;
	int			 rc = 0;

	ENTRY;

	/* create PENDING dir */
	fid_zero(&fid);
	rc = mdd_local_file_create(env, mdd, &mdd->mdd_local_root_fid,
				   orph_index_name, S_IFDIR | S_IRUGO |
				   S_IWUSR | S_IXUGO, &fid);
	if (rc < 0)
		RETURN(rc);

	d = dt_locate(env, mdd->mdd_child, &fid);
	if (IS_ERR(d))
		RETURN(PTR_ERR(d));
	LASSERT(lu_object_exists(&d->do_lu));
	if (!dt_try_as_dir(env, d)) {
		CERROR("%s: \"%s\" is not an index: rc = %d\n",
		       mdd2obd_dev(mdd)->obd_name, orph_index_name, rc);
		lu_object_put(env, &d->do_lu);
		RETURN(-ENOTDIR);
	}
	mdd->mdd_orphans = d;
	RETURN(0);
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

static int __mdd_orphan_cleanup(void *args)
{
	struct mdd_generic_thread *thread = (struct mdd_generic_thread *)args;
	struct lu_env		  *env = NULL;
	int			   rc;
	ENTRY;

	complete(&thread->mgt_started);

	OBD_ALLOC_PTR(env);
	if (env == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = lu_env_init(env, LCT_MD_THREAD);
	if (rc)
		GOTO(out, rc);

	rc = orph_index_iterate(env, thread);

	lu_env_fini(env);
	GOTO(out, rc);
out:
	if (env)
		OBD_FREE_PTR(env);
	complete(&thread->mgt_finished);
	return rc;
}

/**
 *  Iterate orphan index to cleanup orphan objects after recovery is done.
 *  \param d   mdd device in recovery.
 */
int mdd_orphan_cleanup(const struct lu_env *env, struct mdd_device *d)
{
	int rc = -ENOMEM;
	char *name = NULL;

	OBD_ALLOC(name, MTI_NAME_MAXLEN);
	if (name == NULL)
		goto out;

	snprintf(name, MTI_NAME_MAXLEN, "orph_cleanup_%s",
		 mdd2obd_dev(d)->obd_name);

	rc = mdd_generic_thread_start(&d->mdd_orph_cleanup_thread,
				      __mdd_orphan_cleanup, (void *)d, name);
out:
	if (rc)
		CERROR("%s: start orphan cleanup thread failed:%d\n",
		       mdd2obd_dev(d)->obd_name, rc);
	if (name)
		OBD_FREE(name, MTI_NAME_MAXLEN);
	return rc;
}

/**
 *  add an orphan \a obj to the orphan index.
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
