// SPDX-License-Identifier: LGPL-2.0
/*
 * Copyright (c) 2025, DataDirect Networks Inc, all rights reserved.
 */
/*
 * Lustre quota aggregation(LQA) API
 *
 * Author: Sergey Cheremencev <scherementsev@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include "qmt_internal.h"

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
	struct rb_node **node;
	struct rb_node *parent = NULL;
	struct qmt_lqa_range *cur, *range;
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

		OBD_ALLOC_PTR(range);
		if (!range) {
			rc = -ENOMEM;
			break;
		}

		range->qlr_start = start;
		range->qlr_end = end;
		RB_CLEAR_NODE(&range->qlr_rbnode);

		write_lock(&qpi->qpi_lqa_lock);
		node = &qpi->qpi_lqa_rbroot.rb_node;
		while (*node) {
			parent = *node;
			cur = rb_entry(*node, struct qmt_lqa_range, qlr_rbnode);

			/* New range is equal or a subset of existed */
			if (start >= cur->qlr_start && end <= cur->qlr_end) {
				rc = -EEXIST;
				break;
			}

			if ((end >= cur->qlr_start && start <= cur->qlr_start)
			    || (start <= cur->qlr_end && end >= cur->qlr_end)) {
				rc = -ERANGE;
				break;
			}

			if (end < cur->qlr_start)
				node = &((*node)->rb_left);
			else if (start > cur->qlr_end)
				node = &((*node)->rb_right);
		}

		if (!rc) {
			range->qlr_start = start;
			range->qlr_end = end;
			rb_link_node(&range->qlr_rbnode, parent, node);
			rb_insert_color(&range->qlr_rbnode,
					&qpi->qpi_lqa_rbroot);
		}
		write_unlock(&qpi->qpi_lqa_lock);

		if (rc) {
			qpi_putref(&env, qpi);
			OBD_FREE_PTR(range);
			break;
		} else {
			CDEBUG(D_QUOTA, "Insert a new range: %u:%u for %s\n",
			       start, end, name);
			qmt_start_pool_recalc(&env, qpi);
		}
		qpi_putref(&env, qpi);
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

	lu_env_fini(&env);
	RETURN(rc);
}
