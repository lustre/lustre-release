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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
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
#include <obd_support.h>
#include <lustre_fid.h>
#include "mdd_internal.h"

static const char mdd_orphan_index_name[] = MDT_ORPHAN_DIR;
static const char dotdot[] = "..";

enum {
	ORPH_OP_UNLINK,
};

/* obsolete after 2.11, needed for upgrades from older 2.x versions */
#define ORPHAN_FILE_NAME_FORMAT_20      "%016llx:%08x:%08x:%2x"

static struct dt_key *mdd_orphan_key_fill(const struct lu_env *env,
					  const struct lu_fid *lf)
{
	char *key = mdd_env_info(env)->mti_key;

	LASSERT(key);
	if (!(MTI_KEEP_KEY & mdd_env_info(env)->mti_flags))
		snprintf(key, sizeof(mdd_env_info(env)->mti_key),
			 DFID_NOBRACE, PFID(lf));

	return (struct dt_key *)key;
}

/* compatibility with orphan files created in versions before 2.11 */
static struct dt_key *mdd_orphan_key_fill_20(const struct lu_env *env,
					     const struct lu_fid *lf)
{
	char *key = mdd_env_info(env)->mti_key;

	LASSERT(key);
	if (!(MTI_KEEP_KEY & mdd_env_info(env)->mti_flags))
		snprintf(key, sizeof(mdd_env_info(env)->mti_key),
			 ORPHAN_FILE_NAME_FORMAT_20,
			 fid_seq(lf), fid_oid(lf), fid_ver(lf),
			 ORPH_OP_UNLINK);

	return (struct dt_key *)key;
}

static inline int mdd_orphan_insert_obj(const struct lu_env *env,
					struct mdd_device *mdd,
					struct mdd_object *obj,
					struct thandle *th)
{
	struct dt_insert_rec *rec = &mdd_env_info(env)->mti_dt_rec;
	struct dt_object *dor = mdd->mdd_orphans;
	const struct lu_fid *lf = mdd_object_fid(obj);
	struct dt_key *key = mdd_orphan_key_fill(env, lf);

	rec->rec_fid = lf;
	rec->rec_type = mdd_object_type(obj);

	return dt_insert(env, dor, (const struct dt_rec *)rec, key, th);
}

int mdd_orphan_declare_insert(const struct lu_env *env, struct mdd_object *obj,
			      umode_t mode, struct thandle *th)
{
	struct dt_insert_rec *rec = &mdd_env_info(env)->mti_dt_rec;
	struct mdd_device *mdd = mdo2mdd(&obj->mod_obj);
	struct dt_key *key;
	int rc;

	key = mdd_orphan_key_fill(env, mdd_object_fid(obj));

	rec->rec_fid = mdd_object_fid(obj);
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
int mdd_orphan_insert(const struct lu_env *env, struct mdd_object *obj,
		      struct thandle *th)
{
	struct mdd_device *mdd = mdo2mdd(&obj->mod_obj);
	struct dt_object *dor = mdd->mdd_orphans;
	const struct lu_fid *lf_dor = lu_object_fid(&dor->do_lu);
	struct dt_object *next = mdd_object_child(obj);
	struct dt_insert_rec *rec = &mdd_env_info(env)->mti_dt_rec;
	int rc;
	ENTRY;

	LASSERT(mdd_write_locked(env, obj) != 0);
	LASSERT(!(obj->mod_flags & ORPHAN_OBJ));

	dt_write_lock(env, mdd->mdd_orphans, DT_TGT_ORPHAN);

	rc = mdd_orphan_insert_obj(env, mdd, obj, th);
	if (rc)
		GOTO(out, rc);

	mdo_ref_add(env, obj, th);
	if (!S_ISDIR(mdd_object_type(obj)))
		GOTO(out, rc = 0);

	mdo_ref_add(env, obj, th);
	dt_ref_add(env, mdd->mdd_orphans, th);

	/* try best to fixup directory, do not return errors from here */
	if (!dt_try_as_dir(env, next))
		GOTO(out, rc = 0);

	dt_delete(env, next, (const struct dt_key *)dotdot, th);

	rec->rec_fid = lf_dor;
	rec->rec_type = S_IFDIR;
	dt_insert(env, next, (const struct dt_rec *)rec,
		  (const struct dt_key *)dotdot, th);

out:
	if (rc == 0)
		obj->mod_flags |= ORPHAN_OBJ;

	dt_write_unlock(env, mdd->mdd_orphans);

	RETURN(rc);
}

int mdd_orphan_declare_delete(const struct lu_env *env, struct mdd_object *obj,
			      struct thandle *th)
{
	struct mdd_device *mdd = mdo2mdd(&obj->mod_obj);
	struct dt_key *key;
	int rc;

	key = mdd_orphan_key_fill(env, mdd_object_fid(obj));

	rc = dt_declare_delete(env, mdd->mdd_orphans, key, th);
	if (rc)
		return rc;

	if (!mdd_object_exists(obj))
		return -ENOENT;

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
int mdd_orphan_delete(const struct lu_env *env, struct mdd_object *obj,
		      struct thandle *th)
{
	struct mdd_device *mdd = mdo2mdd(&obj->mod_obj);
	struct dt_object *dor = mdd->mdd_orphans;
	struct dt_key *key;
	int rc = 0;

	ENTRY;

	LASSERT(mdd_write_locked(env, obj) != 0);
	LASSERT(obj->mod_flags & ORPHAN_OBJ);
	LASSERT(obj->mod_count == 0);

	LASSERT(dor);

	key = mdd_orphan_key_fill(env, mdd_object_fid(obj));
	dt_write_lock(env, mdd->mdd_orphans, DT_TGT_ORPHAN);

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_ORPHAN_DELETE))
		goto ref_del;

	rc = dt_delete(env, mdd->mdd_orphans, key, th);
	if (rc == -ENOENT) {
		key = mdd_orphan_key_fill_20(env, mdd_object_fid(obj));
		rc = dt_delete(env, mdd->mdd_orphans, key, th);
	}

ref_del:
	if (!rc) {
		/* lov objects will be destroyed by caller */
		mdo_ref_del(env, obj, th);
		if (S_ISDIR(mdd_object_type(obj))) {
			mdo_ref_del(env, obj, th);
			dt_ref_del(env, mdd->mdd_orphans, th);
		}
		obj->mod_flags &= ~ORPHAN_OBJ;
	} else {
		CERROR("%s: could not delete orphan object "DFID": rc = %d\n",
		       mdd_obj_dev_name(obj), PFID(mdd_object_fid(obj)), rc);
	}

	dt_write_unlock(env, mdd->mdd_orphans);
	RETURN(rc);
}


static int mdd_orphan_destroy(const struct lu_env *env, struct mdd_object *obj,
			      struct dt_key *key)
{
	struct thandle *th = NULL;
	struct mdd_device *mdd = mdo2mdd(&obj->mod_obj);
	int rc = 0, rc1 = 0;
	ENTRY;

	th = mdd_trans_create(env, mdd);
	if (IS_ERR(th)) {
		rc = PTR_ERR(th);
		if (rc != -EINPROGRESS)
			CERROR("%s: cannot get orphan thandle: rc = %d\n",
			       mdd2obd_dev(mdd)->obd_name, rc);
		RETURN(rc);
	}

	rc = mdd_orphan_declare_delete(env, obj, th);
	if (rc && rc != -ENOENT)
		GOTO(stop, rc);

	if (rc != -ENOENT) {
		rc = mdo_declare_destroy(env, obj, th);
		if (rc && rc != -ENOENT)
			GOTO(stop, rc);
	}

	rc = mdd_trans_start(env, mdd, th);
	if (rc)
		GOTO(stop, rc);

	mdd_write_lock(env, obj, DT_TGT_CHILD);
	if (likely(obj->mod_count == 0)) {
		dt_write_lock(env, mdd->mdd_orphans, DT_TGT_ORPHAN);
		rc = dt_delete(env, mdd->mdd_orphans, key, th);
		/* We should remove object even dt_delete failed */
		if (mdd_object_exists(obj) &&
		    !lu_object_is_dying(obj->mod_obj.mo_lu.lo_header)) {
			mdo_ref_del(env, obj, th);
			if (S_ISDIR(mdd_object_type(obj))) {
				mdo_ref_del(env, obj, th);
				dt_ref_del(env, mdd->mdd_orphans, th);
			}
			rc1 = mdo_destroy(env, obj, th);
		}
		dt_write_unlock(env, mdd->mdd_orphans);
	}
	mdd_write_unlock(env, obj);
stop:
	mdd_trans_stop(env, mdd, 0, th);

	RETURN(rc ? rc : rc1);
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
static int mdd_orphan_key_test_and_delete(const struct lu_env *env,
					  struct mdd_device *mdd,
					  struct lu_fid *lf, struct dt_key *key)
{
	struct mdd_object *mdo;
	int rc;

	mdo = mdd_object_find(env, mdd, lf);

	if (IS_ERR(mdo))
		return PTR_ERR(mdo);

	rc = -EBUSY;
	if (mdo->mod_count == 0) {
		CDEBUG(D_HA, "Found orphan "DFID", delete it\n", PFID(lf));
		rc = mdd_orphan_destroy(env, mdo, key);
		if (rc) /* below message checked in replay-single.sh test_37 */
			CERROR("%s: error unlinking orphan "DFID": rc = %d\n",
			       mdd2obd_dev(mdd)->obd_name, PFID(lf), rc);
        } else {
		mdd_write_lock(env, mdo, DT_TGT_CHILD);
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
static int mdd_orphan_index_iterate(const struct lu_env *env,
				    struct mdd_generic_thread *thread)
{
	struct mdd_device *mdd = (struct mdd_device *)thread->mgt_data;
	struct dt_object *dor = mdd->mdd_orphans;
	struct lu_dirent *ent = &mdd_env_info(env)->mti_ent;
	const struct dt_it_ops *iops;
	struct dt_it *it;
	struct lu_fid fid;
	int key_sz = 0;
	int rc;
	ENTRY;

	iops = &dor->do_index_ops->dio_it;
	it = iops->init(env, dor, LUDA_64BITHASH);
	if (IS_ERR(it)) {
		rc = PTR_ERR(it);
		CERROR("%s: cannot clean '%s': rc = %d\n",
		       mdd2obd_dev(mdd)->obd_name, mdd_orphan_index_name, rc);
		GOTO(out, rc);
	}

	rc = iops->load(env, it, 0);
	if (rc < 0)
		GOTO(out_put, rc);
	if (rc == 0) {
		CERROR("%s: error loading iterator to clean '%s'\n",
		       mdd2obd_dev(mdd)->obd_name, mdd_orphan_index_name);
		/* Index contains no zero key? */
		GOTO(out_put, rc = -EIO);
	}

	mdd_env_info(env)->mti_flags |= MTI_KEEP_KEY;
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
			CERROR("%s: bad FID "DFID" cleaning '%s'\n",
			       mdd2obd_dev(mdd)->obd_name, PFID(&fid),
			       mdd_orphan_index_name);
			goto next;
		}

		/* kill orphan object */
		iops->put(env, it);
		rc = mdd_orphan_key_test_and_delete(env, mdd, &fid,
						(struct dt_key *)ent->lde_name);
		/* after index delete reset iterator */
		if (rc == 0)
			rc = iops->get(env, it, (const void *)"");
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
int mdd_orphan_index_init(const struct lu_env *env, struct mdd_device *mdd)
{
	struct lu_fid fid;
	struct dt_object *d;
	int rc = 0;

	ENTRY;

	/* create PENDING dir */
	fid_zero(&fid);
	rc = mdd_local_file_create(env, mdd, &mdd->mdd_local_root_fid,
				   mdd_orphan_index_name, S_IFDIR | S_IRUGO |
				   S_IWUSR | S_IXUGO, &fid);
	if (rc < 0)
		RETURN(rc);

	d = dt_locate(env, mdd->mdd_child, &fid);
	if (IS_ERR(d))
		RETURN(PTR_ERR(d));
	LASSERT(lu_object_exists(&d->do_lu));
	if (!dt_try_as_dir(env, d)) {
		CERROR("%s: orphan dir '%s' is not an index: rc = %d\n",
		       mdd2obd_dev(mdd)->obd_name, mdd_orphan_index_name, rc);
		dt_object_put(env, d);
		RETURN(-ENOTDIR);
	}
	mdd->mdd_orphans = d;
	RETURN(0);
}

void mdd_orphan_index_fini(const struct lu_env *env, struct mdd_device *mdd)
{
	ENTRY;
	if (mdd->mdd_orphans != NULL) {
		dt_object_put(env, mdd->mdd_orphans);
		mdd->mdd_orphans = NULL;
	}
	EXIT;
}

static int mdd_orphan_cleanup_thread(void *args)
{
	struct mdd_generic_thread *thread = (struct mdd_generic_thread *)args;
	struct lu_env *env = NULL;
	int rc;
	ENTRY;

	complete(&thread->mgt_started);

	OBD_ALLOC_PTR(env);
	if (env == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = lu_env_init(env, LCT_MD_THREAD);
	if (rc)
		GOTO(out, rc);

	rc = mdd_orphan_index_iterate(env, thread);

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

	snprintf(name, MTI_NAME_MAXLEN, "orph_%s", mdd2obd_dev(d)->obd_name);

	rc = mdd_generic_thread_start(&d->mdd_orphan_cleanup_thread,
				      mdd_orphan_cleanup_thread, d, name);
out:
	if (rc)
		CERROR("%s: start orphan cleanup thread failed: rc = %d\n",
		       mdd2obd_dev(d)->obd_name, rc);
	if (name)
		OBD_FREE(name, MTI_NAME_MAXLEN);

	return rc;
}
