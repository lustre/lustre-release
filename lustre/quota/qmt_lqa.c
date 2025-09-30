// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025, DataDirect Networks Inc, all rights reserved.
 */
/*
 * Lustre quota aggregation(LQA) API
 *
 * Author: Sergey Cheremencev <scherementsev@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include <uapi/linux/lustre/lustre_user.h>
#include "qmt_internal.h"

/**
 * LQA range record format uses struct lqa_id_range from lustre_user.h
 * @lir_start: Range start ID (inclusive)
 * @lir_end: Range end ID (inclusive)
 *
 * This structure defines the record format used to store LQA ranges
 * in indexed storage. Each range is stored as a separate IAM record with
 * the range start ID as the key and this structure as the record value.
 *
 * The key for IAM operations is the range start ID (__u32).
 * The record contains both start and end IDs for completeness and validation.
 */

/* LQA range index features */
static const struct dt_index_features dt_lqa_range_features = {
	.dif_flags		= DT_IND_UPDATE,
	.dif_keysize_min	= sizeof(((struct lqa_id_range *)
					{0})->lir_start),
	.dif_keysize_max	= sizeof(((struct lqa_id_range *)
					{0})->lir_start),
	.dif_recsize_min	= sizeof(struct lqa_id_range), /* 8 bytes */
	.dif_recsize_max	= sizeof(struct lqa_id_range), /* 8 bytes */
	.dif_ptrsize		= 4
};

static int qmt_lqa_save_range_to_disk(struct lu_env *env,
				      struct qmt_pool_info *qpi,
				      __u32 start, __u32 end);
static int qmt_lqa_remove_range_from_disk(struct lu_env *env,
					  struct qmt_pool_info *qpi,
					  __u32 start, __u32 end);
static int qmt_lqa_load_ranges_from_disk(struct lu_env *env,
					 struct qmt_pool_info *qpi);

int qmt_lqa_create(struct obd_device *obd, struct qmt_device *qmt, char *name)
{
	int rc;

	ENTRY;
	rc = qmt_pool_create(obd, LQUOTA_RES_DT, name, true);
	if (rc)
		RETURN(rc);

	rc = qmt_pool_create(obd, LQUOTA_RES_MD, name, true);
	if (rc)
		GOTO(out, rc);

	atomic_inc(&qmt->qmt_lqa_num);
	RETURN(0);
out:
	qmt_pool_destroy(obd, LQUOTA_RES_DT, name, true);
	RETURN(rc);
}

int qmt_lqa_destroy(struct obd_device *obd, struct qmt_device *qmt, char *name)
{
	int rc, rc2;

	ENTRY;

	rc = qmt_pool_destroy(obd, LQUOTA_RES_DT, name, true);
	if (rc)
		CERROR("%s: cannot destroy lqa-dt-%s: rc = %d\n", obd->obd_name,
		       name, rc);

	rc2 = qmt_pool_destroy(obd, LQUOTA_RES_MD, name, true);
	if (rc2)
		CERROR("%s: cannot destroy lqa-md-%s: rc = %d\n",
		       obd->obd_name, name, rc2);

	if (!rc && !rc2)
		atomic_dec(&qmt->qmt_lqa_num);

	RETURN(rc ? rc : rc2);
}

/* Disk persistence functions */

#define QMT_LQA_RANGE_NAME "ranges"

/**
 * qmt_lqa_get_range_obj() - Get or create LQA range index for a pool
 * @env: Lustre environment
 * @qpi: QMT pool info structure
 *
 * Range indexes are stored as "ranges" IAM index in the pool directory:
 * quota_master/lqa-dt-<pool>/ranges or quota_master/lqa-md-<pool>/ranges
 *
 * Return: dt_object pointer on success, ERR_PTR on failure
 */
static struct dt_object *qmt_lqa_get_range_obj(const struct lu_env *env,
					       struct qmt_pool_info *qpi)
{
	struct qmt_thread_info *qti = qmt_info(env);
	struct dt_object *range_obj, *root;
	struct local_oid_storage *los = NULL;
	char name[LQUOTA_NAME_MAX];
	int rc;

	ENTRY;

	/* Create filename: ranges */
	snprintf(name, sizeof(name), QMT_LQA_RANGE_NAME);

	CDEBUG(D_QUOTA, "%s: Looking for LQA range file %s in pool %s\n",
	       qpi->qpi_qmt->qmt_svname, name, qpi->qpi_name);

	/* Use the pool's root directory for storing range files */
	if (!qpi->qpi_root) {
		CERROR("%s: Pool root directory not initialized for pool %s: rc = %d\n",
		       qpi->qpi_qmt->qmt_svname, qpi->qpi_name, -EINVAL);
		RETURN(ERR_PTR(-EINVAL));
	}

	/* Get reference to pool root directory */
	root = qpi->qpi_root;
	lu_object_get(&root->do_lu);

	/* Look up the file first */
	rc = dt_lookup_dir(env, root, name, &qti->qti_fid);
	if (rc == 0) {
		/* File exists, get the object */
		range_obj = dt_locate(env, qpi->qpi_qmt->qmt_child,
				      &qti->qti_fid);
		if (IS_ERR(range_obj)) {
			CERROR("%s: Failed to locate LQA range file %s: rc = %ld\n",
			       qpi->qpi_qmt->qmt_svname, name,
			       PTR_ERR(range_obj));
		}
		CDEBUG(D_QUOTA, "%s: Found existing LQA range file %s\n",
		       qpi->qpi_qmt->qmt_svname, name);
		GOTO(success, range_obj);
	} else if (rc != -ENOENT) {
		CERROR("%s: Failed to lookup LQA range file %s: rc = %d\n",
		       qpi->qpi_qmt->qmt_svname, name, rc);
		dt_object_put(env, root);
		RETURN(ERR_PTR(rc));
	}

	/* File doesn't exist, create it */

	/* Set up local storage to create the LQA range file */
	lu_local_name_obj_fid(&qti->qti_fid, 1);
	rc = local_oid_storage_init(env, qpi->qpi_qmt->qmt_child, &qti->qti_fid,
				    &los);
	if (rc) {
		CERROR("%s: Failed to initialize LQA local OID storage: rc = %d\n",
		       qpi->qpi_qmt->qmt_svname, rc);
		dt_object_put(env, root);
		RETURN(ERR_PTR(rc));
	}

	CDEBUG(D_QUOTA, "%s: Creating LQA range IAM index %s using local storage\n",
	       qpi->qpi_qmt->qmt_svname, name);

	/* Create IAM index using local storage mechanism with root parent */
	range_obj = local_index_find_or_create(env, los, root, name,
					       S_IFREG | 0644,
					       &dt_lqa_range_features);
	if (IS_ERR(range_obj)) {
		rc = PTR_ERR(range_obj);
		CERROR("%s: Failed to create LQA range IAM index %s in pool %s: rc = %d\n",
		       qpi->qpi_qmt->qmt_svname, name, qpi->qpi_name, rc);
	} else {
		CDEBUG(D_QUOTA, "%s: LQA range IAM index %s created successfully in pool %s\n",
		       qpi->qpi_qmt->qmt_svname, name, qpi->qpi_name);
	}

	local_oid_storage_fini(env, los);

success:
	/* Set up index operations */
	if (!IS_ERR(range_obj) && range_obj->do_index_ops == NULL) {
		rc = range_obj->do_ops->do_index_try(env, range_obj,
						     &dt_lqa_range_features);
		if (rc) {
			CERROR("%s: Failed to set up operations: rc = %d\n",
			       qpi->qpi_qmt->qmt_svname, rc);
			range_obj = ERR_PTR(rc);
		}
	}

	dt_object_put(env, root);
	RETURN(range_obj);
}

/**
 * qmt_lqa_insert_range() - Insert a range into the red-black tree
 * @qpi: QMT pool info structure
 * @start: Start of range
 * @end: End of range
 *
 * Return: 0 on success, negative error code on failure
 */
static int qmt_lqa_insert_range(struct qmt_pool_info *qpi,
				__u32 start, __u32 end)
{
	struct rb_node **node = &qpi->qpi_lqa_rbroot.rb_node;
	struct rb_node *parent = NULL;
	struct qmt_lqa_range *cur;
	struct qmt_lqa_range *new_range;

	/* Allocate and insert range */
	OBD_ALLOC_PTR(new_range);
	if (!new_range) {
		CERROR("%s: Failed to allocate LQA range: rc = %d\n",
		       qpi->qpi_qmt->qmt_svname, -ENOMEM);
		return -ENOMEM;
	}

	new_range->qlr_start = start;
	new_range->qlr_end = end;
	RB_CLEAR_NODE(&new_range->qlr_rbnode);

	write_lock(&qpi->qpi_lqa_lock);
	while (*node) {
		parent = *node;
		cur = rb_entry(*node, struct qmt_lqa_range, qlr_rbnode);

		/* New range is equal or a subset of existed */
		if (start >= cur->qlr_start && end <= cur->qlr_end) {
			CERROR("%s: LQA range %u-%u is subset of existing range %u-%u: rc = %d\n",
			       qpi->qpi_qmt->qmt_svname, new_range->qlr_start,
			       new_range->qlr_end, cur->qlr_start, cur->qlr_end,
			       -EEXIST);
			goto error;
		}

		/* Check for partial overlaps */
		if ((end >= cur->qlr_start && start <= cur->qlr_start)
		    || (start <= cur->qlr_end && end >= cur->qlr_end)) {
			CERROR("%s: LQA range %u-%u partially overlaps with existing range %u-%u: rc = %d\n",
			       qpi->qpi_qmt->qmt_svname, start, end,
			       cur->qlr_start, cur->qlr_end,
			       -ERANGE);
			goto error;
		}

		/* Navigate the tree */
		if (end < cur->qlr_start)
			node = &((*node)->rb_left);
		else if (start > cur->qlr_end)
			node = &((*node)->rb_right);
	}

	rb_link_node(&new_range->qlr_rbnode, parent, node);
	rb_insert_color(&new_range->qlr_rbnode, &qpi->qpi_lqa_rbroot);
	write_unlock(&qpi->qpi_lqa_lock);
	return 0;

error:
	write_unlock(&qpi->qpi_lqa_lock);
	OBD_FREE_PTR(new_range);
	return -EEXIST;
}



/**
 * qmt_lqa_save_range_to_disk() - Save a single LQA range to disk
 * @env: Lustre environment
 * @qpi: QMT pool info structure
 * @start: Range start ID
 * @end: Range end ID
 *
 * Simple disk storage logic:
 * 1. Check if range already exists on disk
 * 2. If exists and matches, return -EEXIST
 * 3. If exists but different, return error
 * 4. If doesn't exist, insert new range
 *
 * Return: 0 on success, negative error code on failure
 */
static int qmt_lqa_save_range_to_disk(struct lu_env *env,
				      struct qmt_pool_info *qpi, __u32 start,
				      __u32 end)
{
	struct dt_object *range_obj = NULL;
	struct thandle *th = NULL;
	struct lqa_id_range rec;
	__u32 range_key = start;
	int rc;

	ENTRY;

	/* Get the range IAM index */
	range_obj = qmt_lqa_get_range_obj(env, qpi);
	if (IS_ERR(range_obj))
		RETURN(rc = PTR_ERR(range_obj));

	/* Check if range already exists on disk */
	rc = dt_lookup(env, range_obj, (struct dt_rec *)&rec,
		       (struct dt_key *)&range_key);
	if (rc == 0) {
		/* Range exists - check if it matches */
		if (rec.lir_start == start && rec.lir_end == end) {
			CDEBUG(D_QUOTA, "%s: Range [%u-%u] already exists on disk: rc = %d\n",
			       qpi->qpi_qmt->qmt_svname, start, end, -EEXIST);
			GOTO(out_obj, rc = -EEXIST);
		} else {
			CERROR("%s: Disk range mismatch for key %u: disk=[%u-%u], new=[%u-%u]: rc = %d\n",
			       qpi->qpi_qmt->qmt_svname, start,
			       rec.lir_start, rec.lir_end, start, end, -EINVAL);
			GOTO(out_obj, rc = -EINVAL);
		}
	} else if (rc != -ENOENT) {
		CERROR("%s: Failed to lookup range key %u: rc = %d\n",
		       qpi->qpi_qmt->qmt_svname, start, rc);
		GOTO(out_obj, rc);
	}

	/* Range doesn't exist on disk - insert it */
	rec.lir_start = start;
	rec.lir_end = end;

	/* Start transaction */
	th = dt_trans_create(env, qpi->qpi_qmt->qmt_child);
	if (IS_ERR(th))
		GOTO(out_obj, rc = PTR_ERR(th));

	/* Declare insert operation */
	rc = dt_declare_insert(env, range_obj, (struct dt_rec *)&rec,
			       (struct dt_key *)&range_key, th);
	if (rc)
		GOTO(out_trans, rc);

	rc = dt_trans_start_local(env, qpi->qpi_qmt->qmt_child, th);
	if (rc)
		GOTO(out_trans, rc);

	/* Insert the new range */
	rc = dt_insert(env, range_obj, (struct dt_rec *)&rec,
		       (struct dt_key *)&range_key, th);
	if (rc) {
		CERROR("%s: Failed to insert LQA range [%u-%u]: rc = %d\n",
		       qpi->qpi_qmt->qmt_svname, start, end, rc);
		GOTO(out_trans, rc);
	}

	CDEBUG(D_QUOTA, "%s: Successfully inserted LQA range [%u-%u] to disk\n",
	       qpi->qpi_qmt->qmt_svname, start, end);

	/* Success */
	rc = 0;

out_trans:
	dt_trans_stop(env, qpi->qpi_qmt->qmt_child, th);
out_obj:
	dt_object_put(env, range_obj);
	RETURN(rc);
}

/**
 * qmt_lqa_remove_range_from_disk() - Remove a single LQA range from disk
 * @env: Lustre environment
 * @qpi: QMT pool info structure
 * @start: Range start ID
 * @end: Range end ID
 *
 * Simple disk removal logic:
 * 1. Check if range exists on disk
 * 2. If doesn't exist, return -ENOENT
 * 3. If exists but different, return error
 * 4. If exists and matches, delete it
 *
 * Return: 0 on success, negative error code on failure
 */
static int qmt_lqa_remove_range_from_disk(struct lu_env *env,
					  struct qmt_pool_info *qpi,
					  __u32 start, __u32 end)
{
	struct dt_object *range_obj = NULL;
	struct thandle *th = NULL;
	struct lqa_id_range rec;
	__u32 range_key = start;
	int rc;

	ENTRY;

	/* Get the range IAM index */
	range_obj = qmt_lqa_get_range_obj(env, qpi);
	if (IS_ERR(range_obj))
		RETURN(rc = PTR_ERR(range_obj));

	/* Check if range exists on disk */
	rc = dt_lookup(env, range_obj, (struct dt_rec *)&rec,
		       (struct dt_key *)&range_key);
	if (rc == -ENOENT) {
		CDEBUG(D_QUOTA, "%s: Range [%u-%u] doesn't exist on disk\n",
		       qpi->qpi_qmt->qmt_svname, start, end);
		GOTO(out_obj, rc);
	} else if (rc != 0) {
		CERROR("%s: Failed to lookup range key %u: rc = %d\n",
		       qpi->qpi_qmt->qmt_svname, start, rc);
		GOTO(out_obj, rc);
	}

	/* Range exists - check if it matches */
	if (rec.lir_start != start || rec.lir_end != end) {
		rc = -EINVAL;
		CERROR("%s: Disk range mismatch for key %u: disk=[%u-%u], expected=[%u-%u]: rc =%d\n",
		       qpi->qpi_qmt->qmt_svname, start, rec.lir_start,
		       rec.lir_end, start, end, rc);
		GOTO(out_obj, rc);
	}

	/* Range matches - delete it */
	th = dt_trans_create(env, qpi->qpi_qmt->qmt_child);
	if (IS_ERR(th))
		GOTO(out_obj, rc = PTR_ERR(th));

	/* Declare delete operation */
	rc = dt_declare_delete(env, range_obj, (struct dt_key *)&range_key, th);
	if (rc)
		GOTO(out_trans, rc);

	rc = dt_trans_start_local(env, qpi->qpi_qmt->qmt_child, th);
	if (rc)
		GOTO(out_trans, rc);

	/* Delete the range */
	rc = dt_delete(env, range_obj, (struct dt_key *)&range_key, th);
	if (rc) {
		CERROR("%s: Failed to delete LQA range [%u-%u]: rc = %d\n",
		       qpi->qpi_qmt->qmt_svname, start, end, rc);
		GOTO(out_trans, rc);
	}

	CDEBUG(D_QUOTA, "%s: Successfully deleted LQA range [%u-%u] from disk\n",
	       qpi->qpi_qmt->qmt_svname, start, end);

	/* Success */
	rc = 0;

out_trans:
	dt_trans_stop(env, qpi->qpi_qmt->qmt_child, th);
out_obj:
	dt_object_put(env, range_obj);
	RETURN(rc);
}

/**
 * qmt_lqa_load_ranges_from_disk() - Load LQA ranges from IAM index to pool
 * @env: Lustre environment
 * @qpi: QMT pool info structure
 *
 * Return: 0 on success, negative error code on failure
 */
static int qmt_lqa_load_ranges_from_disk(struct lu_env *env,
					 struct qmt_pool_info *qpi)
{
	struct dt_object *range_obj = NULL;
	struct lqa_id_range rec;
	const struct dt_it_ops *iops;
	struct dt_it *it = NULL;
	struct dt_key *key;
	__u32 range_key;
	int rc, loaded = 0;

	ENTRY;

	/* Get the range IAM index */
	range_obj = qmt_lqa_get_range_obj(env, qpi);
	if (IS_ERR(range_obj)) {
		CERROR("%s: Get failed for %s (res_type %d): rc = %ld\n",
		       qpi->qpi_qmt->qmt_svname, qpi->qpi_name, qpi->qpi_rtype,
		       PTR_ERR(range_obj));
		RETURN(rc = PTR_ERR(range_obj));
	}

	/* Initialize iterator for the IAM index */
	iops = &range_obj->do_index_ops->dio_it;
	it = iops->init(env, range_obj, 0);
	if (IS_ERR(it)) {
		CERROR("%s: Failed to initialize IAM iterator: rc = %ld\n",
		       qpi->qpi_qmt->qmt_svname, PTR_ERR(it));
		GOTO(out_obj, rc = PTR_ERR(it));
	}

	rc = iops->load(env, it, 0);
	if (rc < 0) {
		CERROR("%s: Failed to load IAM iterator: rc = %d\n",
		       qpi->qpi_qmt->qmt_svname, rc);
		GOTO(out_it, rc);
	} else if (rc == 0) {
		rc = iops->next(env, it);
		if (rc != 0)
			GOTO(out_it, rc = (rc < 0) ? rc : 0);
	}

	/* Iterate through all records in the IAM index */
	do {
		/* Get the key (range start ID) */
		key = iops->key(env, it);
		if (IS_ERR(key)) {
			rc = PTR_ERR(key);
			CERROR("%s: Failed to get key from IAM iterator: rc = %d\n",
			       qpi->qpi_qmt->qmt_svname, rc);
			break;
		}
		range_key = *(__u32 *)key;

		/* Get the record (range data) */
		rc = iops->rec(env, it, (struct dt_rec *)&rec, 0);
		if (rc) {
			CERROR("%s: Failed to get record from IAM iterator: rc = %d\n",
			       qpi->qpi_qmt->qmt_svname, rc);
			break;
		}
		/*
		 * Newly created ldiskfs IAM indexes may include a
		 * zeroed-out key and record. Ignore it here.
		 */
		if (range_key == 0 && rec.lir_start == 0 && rec.lir_end == 0) {
			CDEBUG(D_QUOTA, "%s: Zeroed-out key and record: key=%u, rec_start=%u, rec_end=%u\n",
			       qpi->qpi_qmt->qmt_svname, range_key,
			       rec.lir_start, rec.lir_end);
			goto next;
		}

		/* Validate the record */
		if (rec.lir_start != range_key) {
			CERROR("%s: mismatch: key=%u, rec_start=%u: rc = %d\n",
			       qpi->qpi_qmt->qmt_svname, range_key,
			       rec.lir_start, -EINVAL);
			rc = -EINVAL;
			break;
		}

		if (rec.lir_start > rec.lir_end) {
			CERROR("%s: Invalid LQA range %u-%u: rc = %d\n",
			       qpi->qpi_qmt->qmt_svname, rec.lir_start,
			       rec.lir_end, -EINVAL);
			rc = -EINVAL;
			break;
		}

		/* Insert into red-black tree */
		rc = qmt_lqa_insert_range(qpi, rec.lir_start, rec.lir_end);
		if (rc) {
			CERROR("%s: Failed to insert range %u-%u: rc = %d\n",
			       qpi->qpi_qmt->qmt_svname, rec.lir_start,
			       rec.lir_end, rc);
			break;
		}

		loaded++;
		CDEBUG(D_QUOTA, "%s: Loaded LQA range %u-%u for pool %s\n",
		       qpi->qpi_qmt->qmt_svname, rec.lir_start,
		       rec.lir_end, qpi->qpi_name);
next:
		rc = iops->next(env, it);
		if (rc < 0) {
			CERROR("%s: Failed to iterate IAM iterator: rc = %d\n",
			       qpi->qpi_qmt->qmt_svname, rc);
		}
	} while (rc == 0);

	if (rc >= 0) {
		CDEBUG(D_QUOTA, "%s: Loaded %d ranges for pool %s (res_type %d)\n",
		       qpi->qpi_qmt->qmt_svname, loaded, qpi->qpi_name,
		       qpi->qpi_rtype);
		rc = 0;
	}

out_it:
	iops->put(env, it);
	iops->fini(env, it);

out_obj:
	dt_object_put(env, range_obj);
	RETURN(rc);
}

bool qmt_lqa_contain_id(struct qmt_pool_info *qpi, __u64 id)
{
	struct qmt_lqa_range *cur;
	struct rb_node *node;
	bool found = false;

	LASSERT(qpi->qpi_lqa);
	if (id > UINT_MAX) {
		CERROR("%s: lqa:%s id:%llu is greater UNIT_MAX: rc = %d\n",
		       qpi->qpi_qmt->qmt_svname, qpi->qpi_name, id, -ERANGE);
		return false;
	}

	read_lock(&qpi->qpi_lqa_lock);
	node = qpi->qpi_lqa_rbroot.rb_node;
	while (node) {
		cur = rb_entry(node, struct qmt_lqa_range, qlr_rbnode);

		if (id >= cur->qlr_start && id <= cur->qlr_end) {
			found = true;
			break;
		} else if (id < cur->qlr_start) {
			node = node->rb_left;
		} else { /*  id > cur->qlr_end) */
			node = node->rb_right;
		}
	}
	read_unlock(&qpi->qpi_lqa_lock);

	return found;
}

int qmt_lqa_add(struct qmt_device *qmt, char *name, __u32 start, __u32 end)
{
	struct qmt_pool_info *qpi;
	struct lu_env env;
	int res, rc = 0;

	ENTRY;

	rc = lu_env_init(&env, LCT_MD_THREAD);
	if (rc) {
		CERROR("%s: can't init env: rc = %d\n", qmt->qmt_svname, rc);
		RETURN(rc);
	}

	for (res = LQUOTA_FIRST_RES; res < LQUOTA_LAST_RES; res++) {
		qpi = qmt_pool_lookup_name_lqa(&env, qmt, res, name, true);
		if (IS_ERR(qpi)) {
			rc = PTR_ERR(qpi);
			break;
		}

		rc = qmt_lqa_insert_range(qpi, start, end);
		if (rc) {
			qpi_putref(&env, qpi);
			break;
		}

		CDEBUG(D_QUOTA, "Insert a new range: %u:%u for %s\n",
		       start, end, name);
		qmt_start_pool_recalc(&env, qpi);
		qpi_putref(&env, qpi);
	}

	/* Save range to disk */
	if (rc == 0) {
		int save_rc = qmt_lqa_save_range_to_disk(&env, qpi, start, end);

		if (save_rc && save_rc != -EEXIST) {
			CWARN("%s: Failed to save LQA range [%u-%u] to disk: rc = %d\n",
			      qmt->qmt_svname, start, end, save_rc);
			/* Don't fail the operation for disk save errors */
		}
	}

	lu_env_fini(&env);
	if (rc)
		CERROR("%s: lqa:%s can't add range %u:%u: rc = %d\n",
		       qmt->qmt_svname, name, start, end, rc);
	RETURN(rc);
}

int qmt_lqa_list(struct qmt_device *qmt, char *name,
		 struct obd_ioctl_data *data)
{
	struct qmt_lqa_range *range;
	struct qmt_pool_info *qpi;
	struct rb_node *node;
	struct lu_env env;
	char *buf = NULL;
	__u32 *p;
	int buf_size, max;
	int rc = 0;
	int i = 0;

	ENTRY;
	if (!name) {
		int lqa_num = atomic_read(&qmt->qmt_lqa_num);
		int max_names = data->ioc_plen2 / LQA_NAME_MAX;

		if (!max_names)
			RETURN(-EINVAL);

		if (!lqa_num) {
			data->ioc_plen2 = 0;
			RETURN(0);
		}

		lqa_num = min(max_names, lqa_num);
		buf_size = LQA_NAME_MAX * lqa_num;
		OBD_ALLOC(buf, buf_size);
		if (!buf) {
			data->ioc_plen2 = 0;
			RETURN(-ENOMEM);
		}
		down_read(&qmt->qmt_pool_lock);
		/* Metadata LQAs duplicate Data LQAs. It is enough to go only
		 * through the pool data list.
		 */
		list_for_each_entry(qpi, &qmt->qmt_pool_list, qpi_linkage) {
			if (!qpi->qpi_lqa || qpi->qpi_rtype != LQUOTA_RES_DT)
				continue;

			memcpy(buf + i * LQA_NAME_MAX, qpi->qpi_name,
			       LQA_NAME_MAX);

			if (lqa_num == ++i)
				break;
		}
		up_read(&qmt->qmt_pool_lock);

		data->ioc_plen2 = buf_size;
		if (copy_to_user(data->ioc_pbuf2, buf, buf_size))
			rc = -EFAULT;

		GOTO(out_buf, rc);
	}

	buf_size = data->ioc_plen2;
	if (buf_size < LQA_RANGE_SIZE)
		RETURN(-EINVAL);

	rc = lu_env_init(&env, LCT_MD_THREAD);
	if (rc) {
		CERROR("%s: can't init env: rc = %d\n", qmt->qmt_svname, rc);
		RETURN(rc);
	}

	qpi = qmt_pool_lookup_name_lqa(&env, qmt, LQUOTA_RES_DT, name, true);
	if (IS_ERR(qpi))
		GOTO(out_env, rc = PTR_ERR(qpi));

	OBD_ALLOC(buf, buf_size);
	if (!buf)
		GOTO(out_qpi, rc = -ENOMEM);

	max = buf_size / LQA_RANGE_SIZE;
	p = (__u32 *)buf;
	read_lock(&qpi->qpi_lqa_lock);
	for (node = rb_first(&qpi->qpi_lqa_rbroot); node && i < max;
	     node = rb_next(node), i++, p += 2) {
		range = rb_entry(node, struct qmt_lqa_range, qlr_rbnode);
		p[0] = range->qlr_start;
		p[1] = range->qlr_end;
	}
	read_unlock(&qpi->qpi_lqa_lock);
	data->ioc_plen2 = LQA_RANGE_SIZE * i;
	if (copy_to_user(data->ioc_pbuf2, buf, data->ioc_plen2))
		rc = -EFAULT;

	GOTO(out_qpi, rc);
out_qpi:
	qpi_putref(&env, qpi);
out_env:
	lu_env_fini(&env);
out_buf:
	OBD_FREE(buf, buf_size);

	return rc;
}

int qmt_lqa_remove(struct qmt_device *qmt, char *name, __u32 start, __u32 end)
{
	struct qmt_pool_info *qpi;
	struct qmt_lqa_range *range;
	struct rb_node **node;
	struct lu_env env;
	char *qmt_name;
	bool found = false;
	int res, rc;

	ENTRY;

	rc = lu_env_init(&env, LCT_MD_THREAD);
	if (rc) {
		CERROR("%s: can't init env: rc = %d\n", qmt->qmt_svname, rc);
		RETURN(rc);
	}

	qmt_name = qmt->qmt_svname;
	for (res = LQUOTA_FIRST_RES; res < LQUOTA_LAST_RES; res++) {
		qpi = qmt_pool_lookup_name_lqa(&env, qmt, res, name, true);
		if (IS_ERR(qpi)) {
			CERROR("%s: cannot find lqa-%s-%s to remove range %u:%u: rc = %d\n",
			       qmt_name, RES_NAME(res), name, start, end, rc);
			rc = PTR_ERR(qpi);
			break;
		}

		found = false;
		range = NULL;
		write_lock(&qpi->qpi_lqa_lock);
		node = &qpi->qpi_lqa_rbroot.rb_node;
		while (*node) {
			range = rb_entry(*node, struct qmt_lqa_range, qlr_rbnode);
			if (start < range->qlr_start) {
				node = &((*node)->rb_left);
			} else if (start > range->qlr_start) {
				node = &((*node)->rb_right);
			} else if (end == range->qlr_end) {
				found = true;
				rb_erase(*node, &qpi->qpi_lqa_rbroot);
				break;
			} else {
				break;
			}
		}
		write_unlock(&qpi->qpi_lqa_lock);

		if (found) {
			OBD_FREE_PTR(range);
		} else {
			rc = -ENOENT;
			CERROR("%s: lqa-%s-%s cannot remove range %u:%u: rc = %d\n",
			       qmt_name, RES_NAME(res), name, start, end, rc);
		}
		qpi_putref(&env, qpi);
	}

	if (found) {
		int remove_rc;

		/* Remove range from disk */
		remove_rc = qmt_lqa_remove_range_from_disk(&env, qpi, start,
							   end);
		if (remove_rc && remove_rc != -ENOENT) {
			CWARN("%s: Failed to remove LQA range [%u-%u] from disk: rc = %d\n",
			      qmt->qmt_svname, start, end, remove_rc);
			/* Don't fail the operation for disk remove errors */
		}
	}

	lu_env_fini(&env);
	RETURN(rc);
}

/**
 * qmt_lqa_recreate_pools_from_disk() - Recreate LQA pools
 * @qmt: QMT device
 *
 * This function scans the quota_master directory for LQA pool directories
 * and recreates LQA pools that have persistent range data. It discovers
 * LQA pools by looking for directories with names matching:
 * - "lqa-dt-<lqa_name>" (data target pools)
 * - "lqa-md-<lqa_name>" (metadata target pools)
 *
 * Return: 0 on success, negative error code on failure
 */
static int qmt_lqa_recreate_pools_from_disk(struct qmt_device *qmt)
{
	struct lu_env env;
	struct dt_it *it = NULL;
	const struct dt_it_ops *iops;
	char lqa_name[LQUOTA_NAME_MAX];
	char entry_name[LQUOTA_NAME_MAX];
	int rc = 0, pools_created = 0;

	ENTRY;

	CDEBUG(D_QUOTA, "%s: Scanning quota_master for LQA pools to recreate\n",
	       qmt->qmt_svname);

	rc = lu_env_init(&env, LCT_MD_THREAD);
	if (rc)
		RETURN(rc);

	/* Get iterator for quota_master directory */
	iops = &qmt->qmt_root->do_index_ops->dio_it;
	it = iops->init(&env, qmt->qmt_root, LUDA_64BITHASH);
	if (IS_ERR(it))
		GOTO(out_env, rc = PTR_ERR(it));

	rc = iops->load(&env, it, 0);
	if (rc <= 0)
		GOTO(out_it, rc = rc < 0 ? rc : 0);

	/* Iterate through all entries in quota_master */
	do {
		struct dt_key *key;
		int keylen;

		key = iops->key(&env, it);
		if (IS_ERR(key)) {
			rc = PTR_ERR(key);
			break;
		}

		keylen = iops->key_size(&env, it);
		if (keylen >= sizeof(entry_name)) {
			CWARN("%s: LQA pool name too long (size %d)\n",
			       qmt->qmt_svname, keylen);
			goto next;
		}

		memcpy(entry_name, key, keylen);
		entry_name[keylen] = '\0';

		/* Check if this is an LQA pool directory */
		if (strncmp(entry_name, "lqa-dt-", 7) == 0 ||
		    strncmp(entry_name, "lqa-md-", 7) == 0) {
			/* "lqa-dt-<lqa_name>" or "lqa-md-<lqa_name>" */
			strscpy(lqa_name, entry_name + 7,
				sizeof(lqa_name));
		} else {
			/* Not an LQA directory, skip */
			goto next;
		}

		CDEBUG(D_QUOTA, "%s: Found ranges for LQA pool %s, recreating\n",
			qmt->qmt_svname, lqa_name);

		/* Recreate the LQA pool */
		rc = qmt_lqa_create(qmt2lu_dev(qmt)->ld_obd, qmt,
					lqa_name);
		if (rc == 0) {
			pools_created++;
			CDEBUG(D_QUOTA, "%s: Successfully recreated LQA pool %s from disk\n",
				qmt->qmt_svname, lqa_name);
		} else if (rc == -EEXIST) {
			/* LQA pool already exists, that's fine */
			pools_created++;
			CDEBUG(D_QUOTA, "%s: LQA pool %s already exists\n",
				qmt->qmt_svname, lqa_name);
			rc = 0;
		} else {
			CERROR("%s: Failed to recreate LQA pool %s: rc = %d\n",
				qmt->qmt_svname, lqa_name, rc);
			/* Return error and expect that cleanup code will clean
			 * created LQA
			 */
			goto out_it;
		}

next:
		rc = iops->next(&env, it);
	} while (rc == 0);

	/* Successfully processed last entry */
	rc = 0;
	CDEBUG(D_QUOTA, "%s: Recreated %d LQA pools from disk\n",
		       qmt->qmt_svname, pools_created);
out_it:
	iops->fini(&env, it);
out_env:
	lu_env_fini(&env);
	RETURN(rc);
}



/**
 * qmt_lqa_init_from_disk() - Initialize LQA ranges from disk at startup
 * @qmt: QMT device
 *
 * On-disk LQA state format:
 * ========================
 *
 * Directory Structure:
 * quota_master/
 * ├── lqa-dt-<lqa_name>/   # Data target pool for <lqa_name>
 * │   └── ranges           # Binary file containing DT ranges
 * └── lqa-md-<lqa_name>/   # Metadata target pool for <lqa_name>
 *     └── ranges           # Binary file containing MD ranges
 *
 * Return: 0 on success, negative error code on failure
 */
int qmt_lqa_init_from_disk(struct qmt_device *qmt)
{
	struct lu_env env;
	struct qmt_pool_info *qpi;
	int rc = 0;

	ENTRY;

	rc = lu_env_init(&env, LCT_MD_THREAD);
	if (rc) {
		CERROR("%s: Failed to init env: rc = %d\n",
		       qmt->qmt_svname, rc);
		RETURN(rc);
	}

	CDEBUG(D_QUOTA, "%s: Initializing LQA ranges from disk\n",
	       qmt->qmt_svname);
	/* Recreate LQA pools from range files on disk */
	rc = qmt_lqa_recreate_pools_from_disk(qmt);
	if (rc) {
		CDEBUG(D_QUOTA, "%s: Failed to recreate LQA pools from disk: %d\n",
			qmt->qmt_svname, rc);
		GOTO(out_env, rc);
	}

	/* Load ranges for any existing pools */
	down_read(&qmt->qmt_pool_lock);
	list_for_each_entry(qpi, &qmt->qmt_pool_list, qpi_linkage) {
		/* Only process LQA pools */
		if (!qpi->qpi_lqa)
			continue;

		CDEBUG(D_QUOTA,
		       "%s: Loading LQA ranges for pool %s (res_type %d)\n",
		       qmt->qmt_svname, qpi->qpi_name, qpi->qpi_rtype);

		rc = qmt_lqa_load_ranges_from_disk(&env, qpi);
		if (rc) {
			CDEBUG(D_QUOTA,
			       "%s: No ranges for pool %s (res_type %d): %d\n",
			       qmt->qmt_svname, qpi->qpi_name, qpi->qpi_rtype,
			       rc);
			/* Continue with other pools, don't fail startup */
		}
	}
	up_read(&qmt->qmt_pool_lock);

out_env:
	lu_env_fini(&env);
	RETURN(rc);
}
