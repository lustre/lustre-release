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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, 2015, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

/*
 * The disk API is used by both the QMT and QSD to access/update on-disk index
 * files. The API consists of the following functions:
 *
 * - lquota_disk_dir_find_create: look-up quota directory, create it if not
 *				  found.
 * - lquota_disk_glb_find_create: look-up global index file, create it if not
 *				  found.
 * - lquota_disk_slv_find:	  look-up a slave index file.
 * - lquota_disk_slv_find_create: look-up a slave index file. Allocate a FID if
 *				  required and create the index file on disk if
 *				  it does not exist.
 * - lquota_disk_for_each_slv:	  iterate over all existing slave index files
 * - lquota_disk_read:		  read quota settings from an index file
 * - lquota_disk_declare_write:	  reserve credits to update a record in an index
 *				  file
 * - lquota_disk_write:		  update a record in an index file
 * - lquota_disk_update_ver:	  update version of an index file
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include "lquota_internal.h"

#define LQUOTA_MODE (S_IFREG | S_IRUGO | S_IWUSR)

/*
 * Helper function looking up & creating if not found an index file with a
 * dynamic fid.
 */
static struct dt_object *
lquota_disk_find_create(const struct lu_env *env, struct dt_device *dev,
			struct dt_object *parent, struct lu_fid *fid,
			const struct dt_index_features *idx_feat,
			char *name)
{
	struct lquota_thread_info *qti = lquota_info(env);
	struct dt_object *obj;
	struct local_oid_storage *los;
	int rc;
	ENTRY;

	/* Set up local storage */
	rc = local_oid_storage_init(env, dev, fid, &los);
	if (rc)
		RETURN(ERR_PTR(rc));

	/* lookup/create slave index file */
	obj = local_index_find_or_create(env, los, parent, name, LQUOTA_MODE,
					 idx_feat);
	if (IS_ERR(obj))
		GOTO(out, obj);

	/* local_oid_storage_fini() will finalize the local storage device,
	 * we have to open the object in another device stack */
	qti->qti_fid = obj->do_lu.lo_header->loh_fid;
	dt_object_put_nocache(env, obj);
	obj = dt_locate(env, dev, &qti->qti_fid);
	if (IS_ERR(obj))
		GOTO(out, obj);
out:
	local_oid_storage_fini(env, los);
	RETURN(obj);
}

/*
 * helper function to generate the filename associated with a slave index file
 */
static inline int lquota_disk_slv_filename(const struct lu_fid *glb_fid,
					   struct obd_uuid *uuid,
					   char *filename)
{
	char	*name, *uuid_str;

	/* In most case, the uuid is NULL terminated */
	if (uuid->uuid[sizeof(*uuid) - 1] != '\0') {
		OBD_ALLOC(uuid_str, sizeof(*uuid));
		if (uuid_str == NULL)
			RETURN(-ENOMEM);
		memcpy(uuid_str, uuid->uuid, sizeof(*uuid) - 1);
	} else {
		uuid_str = (char *)uuid->uuid;
	}

	/* we strip the slave's UUID (in the form of fsname-OST0001_UUID) of
	 * the filesystem name in case this one is changed in the future */
	name = strrchr(uuid_str, '-');
	if (name == NULL) {
		name = strrchr(uuid_str, ':');
		if (name == NULL) {
			CERROR("Failed to extract extract filesystem "
			       "name from UUID %s\n", uuid_str);
			if (uuid_str != uuid->uuid)
				OBD_FREE(uuid_str, sizeof(*uuid));
			return -EINVAL;
		}
	}
	name++;

	/* the filename is composed of the most signicant bits of the global
	 * FID, that's to say the oid which encodes the pool id, pool type and
	 * quota type, followed by the export UUID */
	sprintf(filename, "0x%x-%s", glb_fid->f_oid, name);

	if (uuid_str != uuid->uuid)
		OBD_FREE(uuid_str, sizeof(*uuid));

	return 0;
}

/*
 * Set up quota directory (either "quota_master" or "quota_slave") for a QMT or
 * QSD instance. This function is also used to create per-pool directory on
 * the quota master.
 * The directory is created with a local sequence if it does not exist already.
 * This function is called at ->ldo_prepare time when the full device stack is
 * configured.
 *
 * \param env  - is the environment passed by the caller
 * \param dev  - is the dt_device where to create the quota directory
 * \param parent  - is the parent directory. If not specified, the directory
 *                  will be created under the root directory
 * \param name - is the name of quota directory to be created
 *
 * \retval     - pointer to quota root dt_object on success, appropriate error
 *               on failure
 */
struct dt_object *lquota_disk_dir_find_create(const struct lu_env *env,
					      struct dt_device *dev,
					      struct dt_object *parent,
					      const char *name)
{
	struct lquota_thread_info	*qti = lquota_info(env);
	struct dt_object		*qt_dir = NULL;
	struct local_oid_storage	*los = NULL;
	int				 rc;
	ENTRY;

	/* Set up local storage to create the quota directory.
	 * We use the sequence reserved for local named objects */
	lu_local_name_obj_fid(&qti->qti_fid, 1);
	rc = local_oid_storage_init(env, dev, &qti->qti_fid, &los);
	if (rc)
		RETURN(ERR_PTR(rc));

	if (parent == NULL) {
		/* Fetch dt object associated with root directory */
		rc = dt_root_get(env, dev, &qti->qti_fid);
		if (rc)
			GOTO(out, rc);

		parent = dt_locate_at(env, dev, &qti->qti_fid,
				      dev->dd_lu_dev.ld_site->ls_top_dev, NULL);
		if (IS_ERR(parent))
			GOTO(out, rc = PTR_ERR(parent));
	} else {
		lu_object_get(&parent->do_lu);
	}

	/* create quota directory to be used for all quota index files */
	qt_dir = local_file_find_or_create(env, los, parent, name, S_IFDIR |
					   S_IRUGO | S_IWUSR | S_IXUGO);
	if (IS_ERR(qt_dir))
		GOTO(out, rc = PTR_ERR(qt_dir));

	/* local_oid_storage_fini() will finalize the local storage device,
	 * we have to open the object in another device stack */
	qti->qti_fid = qt_dir->do_lu.lo_header->loh_fid;
	dt_object_put_nocache(env, qt_dir);
	qt_dir = dt_locate(env, dev, &qti->qti_fid);
	if (IS_ERR(qt_dir))
		GOTO(out, rc = PTR_ERR(qt_dir));

	if (!dt_try_as_dir(env, qt_dir))
		GOTO(out, rc = -ENOTDIR);
	EXIT;
out:
	if (parent != NULL && !IS_ERR(parent))
		dt_object_put(env, parent);
	if (los != NULL)
		local_oid_storage_fini(env, los);
	if (rc) {
		if (qt_dir != NULL && !IS_ERR(qt_dir))
			dt_object_put(env, qt_dir);
		qt_dir = ERR_PTR(rc);
	}
	return qt_dir;
}

/*
 * Look-up/create a global index file.
 *
 * \param env - is the environment passed by the caller
 * \parap dev - is the dt_device where to lookup/create the global index file
 * \param parent - is the parent directory where to create the global index if
 *                 not found
 * \param fid - is the fid of the global index to be looked up/created
 * \parap local - indicates whether the index should be created with a local
 *                generated fid or with \fid
 *
 * \retval     - pointer to the dt_object of the global index on success,
 *               appropriate error on failure
 */
struct dt_object *lquota_disk_glb_find_create(const struct lu_env *env,
					      struct dt_device *dev,
					      struct dt_object *parent,
					      struct lu_fid *fid, bool local)
{
	struct lquota_thread_info	*qti = lquota_info(env);
	struct dt_object		*glb_idx;
	const struct dt_index_features	*idx_feat;
	ENTRY;

	CDEBUG(D_QUOTA, "look-up/create %sglobal idx file ("DFID")\n",
	       local ? "local " : "", PFID(fid));

	idx_feat = &dt_quota_glb_features;

	/* the filename is composed of the most signicant bits of the FID,
	 * that's to say the oid which encodes the pool id, pool type and quota
	 * type */
	sprintf(qti->qti_buf, "0x%x", fid->f_oid);

	if (local) {
		/* We use the sequence reserved for local named objects */
		lu_local_name_obj_fid(&qti->qti_fid, 1);
		glb_idx = lquota_disk_find_create(env, dev, parent,
						  &qti->qti_fid, idx_feat,
						  qti->qti_buf);
	} else {
		/* look-up/create global index on disk */
		glb_idx = local_index_find_or_create_with_fid(env, dev, fid,
							      parent,
							      qti->qti_buf,
							      LQUOTA_MODE,
							      idx_feat);
	}

	if (IS_ERR(glb_idx)) {
		CERROR("%s: failed to look-up/create idx file "DFID" rc:%ld "
		       "local:%d\n", dev->dd_lu_dev.ld_obd->obd_name,
		       PFID(fid), PTR_ERR(glb_idx), local);
		RETURN(glb_idx);
	}

	/* install index operation vector */
	if (glb_idx->do_index_ops == NULL) {
		int rc;

		rc = glb_idx->do_ops->do_index_try(env, glb_idx, idx_feat);
		if (rc) {
			CERROR("%s: failed to setup index operations for "DFID
			       " rc:%d\n", dev->dd_lu_dev.ld_obd->obd_name,
			       PFID(lu_object_fid(&glb_idx->do_lu)), rc);
			dt_object_put(env, glb_idx);
			glb_idx = ERR_PTR(rc);
		}
	}

	RETURN(glb_idx);
}

/*
 * Look-up a slave index file.
 *
 * \param env - is the environment passed by the caller
 * \param dev - is the backend dt_device where to look-up/create the slave index
 * \param parent - is the parent directory where to lookup the slave index
 * \param glb_fid - is the fid of the global index file associated with this
 *                  slave index.
 * \param uuid    - is the uuid of slave which is (re)connecting to the master
 *                  target
 *
 * \retval     - pointer to the dt_object of the slave index on success,
 *               appropriate error on failure
 */
struct dt_object *lquota_disk_slv_find(const struct lu_env *env,
				       struct dt_device *dev,
				       struct dt_object *parent,
				       const struct lu_fid *glb_fid,
				       struct obd_uuid *uuid)
{
	struct lquota_thread_info	*qti = lquota_info(env);
	struct dt_object		*slv_idx;
	int				 rc;
	ENTRY;

	LASSERT(uuid != NULL);

	CDEBUG(D_QUOTA, "lookup slave index file for %s\n",
	       obd_uuid2str(uuid));

	/* generate filename associated with the slave */
	rc = lquota_disk_slv_filename(glb_fid, uuid, qti->qti_buf);
	if (rc)
		RETURN(ERR_PTR(rc));

	/* lookup slave index file */
	rc = dt_lookup_dir(env, parent, qti->qti_buf, &qti->qti_fid);
	if (rc)
                RETURN(ERR_PTR(rc));

	/* name is found, get the object */
	slv_idx = dt_locate(env, dev, &qti->qti_fid);
	if (IS_ERR(slv_idx))
		RETURN(slv_idx);

	if (slv_idx->do_index_ops == NULL) {
		rc = slv_idx->do_ops->do_index_try(env, slv_idx,
						   &dt_quota_slv_features);
		if (rc) {
			CERROR("%s: failed to setup slave index operations for "
			       "%s, rc:%d\n", dev->dd_lu_dev.ld_obd->obd_name,
			       obd_uuid2str(uuid), rc);
			dt_object_put(env, slv_idx);
			slv_idx = ERR_PTR(rc);
		}
	}

	RETURN(slv_idx);
}

/*
 * Look-up a slave index file. If the slave index isn't found:
 * - if local is set to false, we allocate a FID from FID_SEQ_QUOTA sequence and
 *   create the index.
 * - otherwise, we create the index file with a local reserved FID (see
 *   lquota_local_oid)
 *
 * \param env - is the environment passed by the caller
 * \param dev - is the backend dt_device where to look-up/create the slave index
 * \param parent - is the parent directory where to create the slave index if
 *                 it does not exist already
 * \param glb_fid - is the fid of the global index file associated with this
 *                  slave index.
 * \param uuid    - is the uuid of slave which is (re)connecting to the master
 *                  target
 * \param local   - indicate whether to use local reserved FID (LQUOTA_USR_OID
 *                  & LQUOTA_GRP_OID) for the slave index creation or to
 *                  allocate a new fid from sequence FID_SEQ_QUOTA
 *
 * \retval     - pointer to the dt_object of the slave index on success,
 *               appropriate error on failure
 */
struct dt_object *lquota_disk_slv_find_create(const struct lu_env *env,
					      struct dt_device *dev,
					      struct dt_object *parent,
					      struct lu_fid *glb_fid,
					      struct obd_uuid *uuid,
					      bool local)
{
	struct lquota_thread_info	*qti = lquota_info(env);
	struct dt_object		*slv_idx;
	int				 rc;
	ENTRY;

	LASSERT(uuid != NULL);

	CDEBUG(D_QUOTA, "lookup/create slave index file for %s\n",
	       obd_uuid2str(uuid));

	/* generate filename associated with the slave */
	rc = lquota_disk_slv_filename(glb_fid, uuid, qti->qti_buf);
	if (rc)
		RETURN(ERR_PTR(rc));

	/* Slave indexes uses the FID_SEQ_QUOTA sequence since they can be read
	 * through the network */
	qti->qti_fid.f_seq = FID_SEQ_QUOTA;
	qti->qti_fid.f_ver = 0;
	if (local) {
		int type;

		rc = lquota_extract_fid(glb_fid, NULL, NULL, &type);
		if (rc)
			RETURN(ERR_PTR(rc));

		/* use predefined fid in the reserved oid list */
		qti->qti_fid.f_oid = qtype2slv_oid(type);

		slv_idx = local_index_find_or_create_with_fid(env, dev,
							      &qti->qti_fid,
							      parent,
							      qti->qti_buf,
							      LQUOTA_MODE,
							&dt_quota_slv_features);
	} else {
		/* allocate fid dynamically if index does not exist already */
		qti->qti_fid.f_oid = LQUOTA_GENERATED_OID;

		/* lookup/create slave index file */
		slv_idx = lquota_disk_find_create(env, dev, parent,
						  &qti->qti_fid,
						  &dt_quota_slv_features,
						  qti->qti_buf);
	}

	if (IS_ERR(slv_idx))
		RETURN(slv_idx);

	/* install index operation vector */
	if (slv_idx->do_index_ops == NULL) {
		rc = slv_idx->do_ops->do_index_try(env, slv_idx,
						   &dt_quota_slv_features);
		if (rc) {
			CERROR("%s: failed to setup index operations for "DFID
			       " rc:%d\n", dev->dd_lu_dev.ld_obd->obd_name,
			       PFID(lu_object_fid(&slv_idx->do_lu)), rc);
			dt_object_put(env, slv_idx);
			slv_idx = ERR_PTR(rc);
		}
	}

	RETURN(slv_idx);
}

/*
 * Iterate over all slave index files associated with global index \glb_fid and
 * invoke a callback function for each slave index file.
 *
 * \param env     - is the environment passed by the caller
 * \param parent  - is the parent directory where the slave index files are
 *                  stored
 * \param glb_fid - is the fid of the global index file associated with the
 *                  slave indexes to scan
 * \param func    - is the callback function to call each time a slave index
 *                  file is found
 * \param arg     - is an opaq argument passed to the callback function \func
 */
int lquota_disk_for_each_slv(const struct lu_env *env, struct dt_object *parent,
			     struct lu_fid *glb_fid, lquota_disk_slv_cb_t func,
			     void *arg)
{
	struct lquota_thread_info	*qti = lquota_info(env);
	struct dt_it			*it;
	const struct dt_it_ops		*iops;
	char				*name;
	int				 rc;
	ENTRY;

	OBD_ALLOC(name, LQUOTA_NAME_MAX);
	if (name == NULL)
		RETURN(-ENOMEM);

	/* filename associated with slave index files are prefixed with the most
	 * signicant bits of the global FID */
	sprintf(name, "0x%x-", glb_fid->f_oid);

	iops = &parent->do_index_ops->dio_it;
	it = iops->init(env, parent, 0);
	if (IS_ERR(it)) {
		OBD_FREE(name, LQUOTA_NAME_MAX);
		RETURN(PTR_ERR(it));
	}

	rc = iops->load(env, it, 0);
	if (rc == 0) {
		/*
		 * Iterator didn't find record with exactly the key requested.
		 *
		 * It is currently either
		 *
		 *     - positioned above record with key less than
		 *     requested---skip it.
		 *
		 *     - or not positioned at all (is in IAM_IT_SKEWED
		 *     state)---position it on the next item.
		 */
		rc = iops->next(env, it);
	} else if (rc > 0)
		rc = 0;

	while (rc == 0) {
		struct dt_key	*key;
		int		 len;

		len = iops->key_size(env, it);
		/* IAM iterator can return record with zero len. */
		if (len == 0 || len <= strlen(name) || len >= LQUOTA_NAME_MAX)
			goto next;

		key = iops->key(env, it);
		if (IS_ERR(key)) {
			rc = PTR_ERR(key);
			break;
		}

		if (strncmp((char *)key, name, strlen(name)) != 0)
			goto next;

		/* ldiskfs OSD returns filename as stored in directory entry
		 * which does not end up with '\0' */
		memcpy(&qti->qti_buf, key, len);
		qti->qti_buf[len] = '\0';

		/* lookup fid associated with this slave index file */
		rc = dt_lookup_dir(env, parent, qti->qti_buf, &qti->qti_fid);
		if (rc)
			break;

		if (qti->qti_fid.f_seq != FID_SEQ_QUOTA)
			goto next;

		rc = func(env, glb_fid, (char *)key, &qti->qti_fid, arg);
		if (rc)
			break;
next:
		do {
			rc = iops->next(env, it);
		} while (rc == -ESTALE);
	}

	iops->put(env, it);
	iops->fini(env, it);
	OBD_FREE(name, LQUOTA_NAME_MAX);
	if (rc > 0)
		rc = 0;
	RETURN(rc);
}

/*
 * Retrieve quota settings from disk for a particular identifier.
 *
 * \param env - is the environment passed by the caller
 * \param obj - is the on-disk index where quota settings are stored.
 * \param id  - is the key to be updated
 * \param rec - is the output record where to store quota settings.
 *
 * \retval    - 0 on success, appropriate error on failure
 */
int lquota_disk_read(const struct lu_env *env, struct dt_object *obj,
		     union lquota_id *id, struct dt_rec *rec)
{
	int	rc;
	ENTRY;

	LASSERT(dt_object_exists(obj));
	LASSERT(obj->do_index_ops != NULL);

	/* lookup on-disk record from index file */
	dt_read_lock(env, obj, 0);
	rc = dt_lookup(env, obj, rec, (struct dt_key *)&id->qid_uid);
	dt_read_unlock(env, obj);

	RETURN(rc);
}

/*
 * Reserve enough credits to update a record in a quota index file.
 *
 * \param env - is the environment passed by the caller
 * \param th  - is the transaction to use for disk writes
 * \param obj - is the on-disk index where quota settings are stored.
 * \param id  - is the key to be updated
 *
 * \retval    - 0 on success, appropriate error on failure
 */
int lquota_disk_declare_write(const struct lu_env *env, struct thandle *th,
			      struct dt_object *obj, union lquota_id *id)
{
	struct lquota_thread_info	*qti = lquota_info(env);
	struct dt_key			*key = (struct dt_key *)&id->qid_uid;
	int				 rc;
	ENTRY;

	LASSERT(dt_object_exists(obj));
	LASSERT(obj->do_index_ops != NULL);

	/* speculative delete declaration in case there is already an existing
	 * record in the index */
	rc = dt_declare_delete(env, obj, key, th);
	if (rc)
		RETURN(rc);

	/* declare insertion of updated record */
	rc = dt_declare_insert(env, obj, (struct dt_rec *)&qti->qti_rec, key,
			       th);
	if (rc)
		RETURN(rc);

	/* we might have to update the version of the global index too */
	rc = dt_declare_version_set(env, obj, th);

	RETURN(rc);
}

/*
 * Update a record in a quota index file.
 *
 * \param env - is the environment passed by the caller
 * \param th  - is the transaction to use for disk writes
 * \param obj - is the on-disk index to be updated.
 * \param id  - is the key to be updated
 * \param rec - is the input record containing the new quota settings.
 * \param flags - can be LQUOTA_BUMP_VER or LQUOTA_SET_VER.
 * \param ver   - is the new version of the index if LQUOTA_SET_VER is set or is
 *                used to return the new version of the index when
 *                LQUOTA_BUMP_VER is set.
 *
 * \retval    - 0 on success, appropriate error on failure
 */
int lquota_disk_write(const struct lu_env *env, struct thandle *th,
		      struct dt_object *obj, union lquota_id *id,
		      struct dt_rec *rec, __u32 flags, __u64 *ver)
{
	struct lquota_thread_info	*qti = lquota_info(env);
	struct dt_key			*key = (struct dt_key *)&id->qid_uid;
	int				 rc;
	ENTRY;

	LASSERT(dt_object_exists(obj));
	LASSERT(obj->do_index_ops != NULL);

	/* lock index */
	dt_write_lock(env, obj, 0);

	/* check whether there is already an existing record for this ID */
	rc = dt_lookup(env, obj, (struct dt_rec *)&qti->qti_rec, key);
	if (rc == 0) {
		/* delete existing record in order to replace it */
		rc = dt_delete(env, obj, key, th);
		if (rc)
			GOTO(out, rc);
	} else if (rc == -ENOENT) {
		/* probably first insert */
		rc = 0;
	} else {
		GOTO(out, rc);
	}

	if (rec != NULL) {
		/* insert record with updated quota settings */
		rc = dt_insert(env, obj, rec, key, th, 1);
		if (rc) {
			/* try to insert the old one */
			rc = dt_insert(env, obj, (struct dt_rec *)&qti->qti_rec,
				       key, th, 1);
			LASSERTF(rc == 0, "failed to insert record in quota "
				 "index "DFID"\n",
				 PFID(lu_object_fid(&obj->do_lu)));
			GOTO(out, rc);
		}
	}

	if (flags != 0) {
		LASSERT(ver);
		if (flags & LQUOTA_BUMP_VER) {
			/* caller wants to bump the version, let's first read
			 * it */
			*ver = dt_version_get(env, obj);
			(*ver)++;
		} else {
			LASSERT(flags & LQUOTA_SET_VER);
		}
		dt_version_set(env, obj, *ver, th);
	}

	EXIT;
out:
	dt_write_unlock(env, obj);
	return rc;
}

/*
 * Update version of an index file
 *
 * \param env - is the environment passed by the caller
 * \param dev - is the backend dt device storing the index file
 * \param obj - is the on-disk index that should be updated
 * \param ver - is the new version
 */
int lquota_disk_update_ver(const struct lu_env *env, struct dt_device *dev,
			   struct dt_object *obj, __u64 ver)
{
	struct thandle	*th;
	int		 rc;
	ENTRY;

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_version_set(env, obj, th);
	if (rc)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc)
		GOTO(out, rc);
	th->th_sync = 1;

	dt_version_set(env, obj, ver, th);
	EXIT;
out:
	dt_trans_stop(env, dev, th);
	return rc;
}

/*
 * Write a global record
 *
 * \param env - is the environment passed by the caller
 * \param obj - is the on-disk global index to be updated
 * \param id  - index to be updated
 * \param rec - record to be written
 */
int lquota_disk_write_glb(const struct lu_env *env, struct dt_object *obj,
			  __u64 id, struct lquota_glb_rec *rec)
{
	struct dt_device	*dev = lu2dt_dev(obj->do_lu.lo_dev);
	struct thandle		*th;
	struct dt_key		*key = (struct dt_key *)&id;
	int			 rc;
	ENTRY;

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	/* the entry with 0 key can always be found in IAM file. */
	if (id == 0) {
		rc = dt_declare_delete(env, obj, key, th);
		if (rc)
			GOTO(out, rc);
	}

	rc = dt_declare_insert(env, obj, (struct dt_rec *)rec, key, th);
	if (rc)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc)
		GOTO(out, rc);

	dt_write_lock(env, obj, 0);

	if (id == 0) {
		struct lquota_glb_rec *tmp;

		OBD_ALLOC_PTR(tmp);
		if (tmp == NULL)
			GOTO(out_lock, rc = -ENOMEM);

		rc = dt_lookup(env, obj, (struct dt_rec *)tmp, key);

		OBD_FREE_PTR(tmp);
		if (rc == 0) {
			rc = dt_delete(env, obj, key, th);
			if (rc)
				GOTO(out_lock, rc);
		}
		rc = 0;
	}

	rc = dt_insert(env, obj, (struct dt_rec *)rec, key, th, 1);
out_lock:
	dt_write_unlock(env, obj);
out:
	dt_trans_stop(env, dev, th);
	RETURN(rc);
}
