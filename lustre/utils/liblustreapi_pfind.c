// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (c) 2024 DataDirect Networks Storage, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * implement thread worker pool for parallel work queue operations.
 *
 * Author: Patrick Farrell <pfarrell@whamcloud.com>
 */

#include <pthread.h>
#include <sys/xattr.h>
#include "lustreapi_internal.h"
#include "lstddef.h"



static void work_unit_free(struct find_work_unit *unit);

/* Placeholder worker function - just for testing thread creation */
static void *find_worker(void *arg)
{
	struct find_work_queue *queue = (struct find_work_queue *) arg;
	struct find_work_unit *unit = NULL;
	char *fail_loc = getenv("LLAPI_FAIL_LOC");
	int rc = 0;

	while (!queue->fwq_shutdown) {
		/* Get work unit from queue */
		pthread_mutex_lock(&queue->fwq_lock);
		while (queue->fwq_head == NULL && !queue->fwq_shutdown) {
			pthread_cond_wait(&queue->fwq_sleep_cond,
					  &queue->fwq_lock);
		}

		if (queue->fwq_shutdown) {
			pthread_mutex_unlock(&queue->fwq_lock);
			break;
		}

		/* Dequeue work unit */
		unit = queue->fwq_head;

		queue->fwq_head = unit->fwu_next;
		if (queue->fwq_head == NULL)
			queue->fwq_tail = NULL;
		pthread_mutex_unlock(&queue->fwq_lock);

		rc = llapi_semantic_traverse(unit->fwu_path, 2 * PATH_MAX, -1,
					     cb_find_init, cb_common_fini,
					     unit->fwu_param, NULL);
		if (rc && queue->fwq_error == 0)
			queue->fwq_error = rc;
		if ((rc < 0 && rc != -EALREADY &&
		     unit->fwu_param->fp_stop_on_error) ||
		    (fail_loc && !strcmp(fail_loc, "LLAPI_FAIL_PFIND_SEM"))) {
			if (fail_loc && !strcmp(fail_loc,
						"LLAPI_FAIL_PFIND_SEM"))
				rc = -EIO;
			queue->fwq_shutdown = 1;
			queue->fwq_error = rc;
		}

		work_unit_free(unit);
		ll_atomic_fetch_sub(&queue->fwq_active_units, 1);
	}

	return NULL;
}

/* Initialize the work queue */
static void find_work_queue_init(struct find_work_queue *queue)
{
	queue->fwq_head = NULL;
	queue->fwq_tail = NULL;
	queue->fwq_active_units = 0;
	pthread_mutex_init(&queue->fwq_lock, NULL);
	pthread_cond_init(&queue->fwq_sleep_cond, NULL);
	queue->fwq_shutdown = false;
	queue->fwq_error = 0;
}

static int find_threads_init(pthread_t *threads, struct find_work_queue *queue,
			     int numthreads)
{
	int ret;
	int i;

	for (i = 0; i < numthreads; i++) {
		ret = pthread_create(&threads[i], NULL, find_worker, queue);
		if (ret) {
			/* Set shutdown flag for any created threads */
			queue->fwq_shutdown = true;
			/* wake up queue... */
			pthread_cond_broadcast(&queue->fwq_sleep_cond);
			/* Wait for already-created threads to exit */
			while (--i >= 0)
				pthread_join(threads[i], NULL);
			return -ENOMEM;
		}
	}

	return 0;
}

void free_find_param(struct find_param *fp)
{
	if (!fp)
		return;

	free(fp->fp_pattern);
	free(fp->fp_obd_uuid);
	free(fp->fp_obd_indexes);
	free(fp->fp_mdt_uuid);
	free(fp->fp_mdt_indexes);
	free(fp->fp_lmd);
	free(fp->fp_lmv_md);

	/* Deep free xattr match info */
	if (fp->fp_xattr_match_info) {
		struct xattr_match_info *xmi = fp->fp_xattr_match_info;
		int i;

		free(xmi->xattr_regex_exclude);
		free(xmi->xattr_regex_matched);

		if (xmi->xattr_regex_name) {
			for (i = 0; i < xmi->xattr_regex_count; i++)
				free(xmi->xattr_regex_name[i]);
			free(xmi->xattr_regex_name);
		}

		if (xmi->xattr_regex_value) {
			for (i = 0; i < xmi->xattr_regex_count; i++)
				free(xmi->xattr_regex_value[i]);
			free(xmi->xattr_regex_value);
		}

		free(xmi->xattr_name_buf);
		free(xmi->xattr_value_buf);
		free(fp->fp_xattr_match_info);
	}

	free(fp->fp_format_printf_str);
	free(fp);
}

struct find_param *copy_find_param(const struct find_param *src)
{
	struct find_param *dst = calloc(1, sizeof(struct find_param));

	if (!dst)
		return NULL;

	/* Copy all scalar fields */
	memcpy(dst, src, sizeof(struct find_param));

	/* Clear all pointer fields to avoid double-free in error path */
	dst->fp_pattern = NULL;
	dst->fp_obd_uuid = NULL;
	dst->fp_obd_indexes = NULL;
	dst->fp_mdt_uuid = NULL;
	dst->fp_mdt_indexes = NULL;
	dst->fp_lmd = NULL;
	dst->fp_lmv_md = NULL;
	dst->fp_xattr_match_info = NULL;
	dst->fp_format_printf_str = NULL;

	/* Deep copy dynamically allocated fields */
	if (src->fp_pattern) {
		dst->fp_pattern = strdup(src->fp_pattern);
		if (!dst->fp_pattern)
			goto error;
	}

	/* OBD UUIDs */
	if (src->fp_obd_uuid && src->fp_num_alloc_obds > 0) {
		dst->fp_obd_uuid = calloc(src->fp_num_alloc_obds,
					  sizeof(struct obd_uuid));
		if (!dst->fp_obd_uuid)
			goto error;
		memcpy(dst->fp_obd_uuid, src->fp_obd_uuid,
			src->fp_num_alloc_obds * sizeof(struct obd_uuid));
	}

	if (src->fp_obd_indexes && src->fp_num_obds > 0) {
		dst->fp_obd_indexes = calloc(src->fp_num_obds,
					     sizeof(int));
		if (!dst->fp_obd_indexes)
			goto error;
		memcpy(dst->fp_obd_indexes, src->fp_obd_indexes,
			src->fp_num_obds * sizeof(int));
	}

	/* MDT UUIDs */
	if (src->fp_mdt_uuid && src->fp_num_alloc_mdts > 0) {
		dst->fp_mdt_uuid = calloc(src->fp_num_alloc_mdts,
					  sizeof(struct obd_uuid));
		if (!dst->fp_mdt_uuid)
			goto error;
		memcpy(dst->fp_mdt_uuid, src->fp_mdt_uuid,
		       src->fp_num_alloc_mdts * sizeof(struct obd_uuid));
	}

	if (src->fp_mdt_indexes && src->fp_num_mdts > 0) {
		dst->fp_mdt_indexes = calloc(src->fp_num_mdts,
					     sizeof(int));
		if (!dst->fp_mdt_indexes)
			goto error;
		memcpy(dst->fp_mdt_indexes, src->fp_mdt_indexes,
		       src->fp_num_mdts * sizeof(int));
	}

	/* LMD and LMV data */
	if (src->fp_lmd && src->fp_lum_size > 0) {
		size_t lmd_size = offsetof(typeof(*src->fp_lmd), lmd_lmm) +
				  src->fp_lum_size;

		dst->fp_lmd = malloc(lmd_size);
		if (!dst->fp_lmd)
			goto error;
		memcpy(dst->fp_lmd, src->fp_lmd, lmd_size);
	}

	if (src->fp_lmv_md) {
		size_t lmv_size = lmv_user_md_size(src->fp_lmv_stripe_count,
						   LMV_USER_MAGIC_SPECIFIC);
		dst->fp_lmv_md = malloc(lmv_size);
		if (!dst->fp_lmv_md)
			goto error;
		memcpy(dst->fp_lmv_md, src->fp_lmv_md, lmv_size);
	}

	/* xattr match info - deep copy all pointer fields */
	if (src->fp_xattr_match_info) {
		struct xattr_match_info *src_xmi = src->fp_xattr_match_info;
		struct xattr_match_info *dst_xmi;
		int i;

		dst->fp_xattr_match_info =
			calloc(1, sizeof(struct xattr_match_info));
		if (!dst->fp_xattr_match_info)
			goto error;

		dst_xmi = dst->fp_xattr_match_info;
		dst_xmi->xattr_regex_count = src_xmi->xattr_regex_count;

		/* Deep copy all pointer fields */
		if (src_xmi->xattr_regex_count > 0) {
			/* Copy exclude array */
			if (src_xmi->xattr_regex_exclude) {
				dst_xmi->xattr_regex_exclude =
					malloc(src_xmi->xattr_regex_count *
					       sizeof(bool));
				if (!dst_xmi->xattr_regex_exclude)
					goto error;
				memcpy(dst_xmi->xattr_regex_exclude,
				       src_xmi->xattr_regex_exclude,
				       src_xmi->xattr_regex_count *
				       sizeof(bool));
			}

			/* Copy matched array */
			if (src_xmi->xattr_regex_matched) {
				dst_xmi->xattr_regex_matched =
					malloc(src_xmi->xattr_regex_count *
					       sizeof(bool));
				if (!dst_xmi->xattr_regex_matched)
					goto error;
				memcpy(dst_xmi->xattr_regex_matched,
				       src_xmi->xattr_regex_matched,
				       src_xmi->xattr_regex_count *
				       sizeof(bool));
			}

			/* Copy regex name array */
			if (src_xmi->xattr_regex_name) {
				dst_xmi->xattr_regex_name =
					malloc(src_xmi->xattr_regex_count *
					       sizeof(regex_t *));
				if (!dst_xmi->xattr_regex_name)
					goto error;
				for (i = 0; i < src_xmi->xattr_regex_count;
				     i++) {
					if (!src_xmi->xattr_regex_name[i]) {
						dst_xmi->xattr_regex_name[i] =
							NULL;
						continue;
					}
					dst_xmi->xattr_regex_name[i] =
						malloc(sizeof(regex_t));
					if (!dst_xmi->xattr_regex_name[i])
						goto error;
					memcpy(dst_xmi->xattr_regex_name[i],
					       src_xmi->xattr_regex_name[i],
					       sizeof(regex_t));
				}
			}

			/* Copy regex value array */
			if (src_xmi->xattr_regex_value) {
				dst_xmi->xattr_regex_value =
					malloc(src_xmi->xattr_regex_count *
					       sizeof(regex_t *));
				if (!dst_xmi->xattr_regex_value)
					goto error;
				for (i = 0; i < src_xmi->xattr_regex_count;
				     i++) {
					if (!src_xmi->xattr_regex_value[i]) {
						dst_xmi->xattr_regex_value[i] =
							NULL;
						continue;
					}
					dst_xmi->xattr_regex_value[i] =
						malloc(sizeof(regex_t));
					if (!dst_xmi->xattr_regex_value[i])
						goto error;
					memcpy(dst_xmi->xattr_regex_value[i],
					       src_xmi->xattr_regex_value[i],
					       sizeof(regex_t));
				}
			}
		}

		/* Copy name buffer */
		if (src_xmi->xattr_name_buf) {
			dst_xmi->xattr_name_buf = malloc(XATTR_LIST_MAX);
			if (!dst_xmi->xattr_name_buf)
				goto error;
			memcpy(dst_xmi->xattr_name_buf,
			       src_xmi->xattr_name_buf, XATTR_LIST_MAX);
		}

		/* Copy value buffer */
		if (src_xmi->xattr_value_buf) {
			dst_xmi->xattr_value_buf = malloc(XATTR_SIZE_MAX);
			if (!dst_xmi->xattr_value_buf)
				goto error;
			memcpy(dst_xmi->xattr_value_buf,
			       src_xmi->xattr_value_buf, XATTR_SIZE_MAX);
		}
	}

	/* Format string */
	if (src->fp_format_printf_str) {
		dst->fp_format_printf_str = strdup(src->fp_format_printf_str);
		if (!dst->fp_format_printf_str)
			goto error;
	}

	return dst;

error:
	/* Cleanup on error */
	if (dst)
		free_find_param(dst);
	return NULL;
}

/* Free a work unit */
static void work_unit_free(struct find_work_unit *unit)
{
	if (!unit)
		return;

	free(unit->fwu_path);
	free(unit->fwu_de);
	free_find_param(unit->fwu_param);
	free(unit);
}

/* Create a new work unit */
static struct find_work_unit *work_unit_create(const char *path,
					       struct find_param *param,
					       struct dirent64 *de)
{
	struct find_work_unit *unit;

	unit = malloc(sizeof(*unit));
	if (!unit)
		return NULL;

	/* Initialize with zeros to ensure clean error handling */
	memset(unit, 0, sizeof(*unit));

	/* Copy the path */
	unit->fwu_path = (char *)malloc(PATH_MAX + 1);
	if (!unit->fwu_path)
		goto error;
	snprintf(unit->fwu_path, PATH_MAX + 1, "%s", path);

	/* Copy the directory entry if provided */
	if (de) {
		unit->fwu_de = malloc(sizeof(*de));
		if (!unit->fwu_de)
			goto error;
		memcpy(unit->fwu_de, de, sizeof(*de));
	}


	unit->fwu_param = copy_find_param(param);
	if (!unit->fwu_param)
		goto error;

	return unit;

error:
	work_unit_free(unit);
	return NULL;
}

int work_unit_create_and_add(const char *path, struct find_param *param,
			     struct dirent64 *dent)
{
	struct find_work_queue *queue = param->fp_queue;
	struct find_work_unit *unit;
	int rc = 0;

	unit = work_unit_create(path, param, dent);
	if (!unit) {
		rc = -ENOMEM;
		goto out;
	}

	ll_atomic_fetch_add(&queue->fwq_active_units, 1);

	pthread_mutex_lock(&queue->fwq_lock);

	/* add to queue, at tail if there's already something on the queue */
	if (queue->fwq_tail) {
		queue->fwq_tail->fwu_next = unit;
	} else {
		queue->fwq_head = unit;
	}
	queue->fwq_tail = unit;

	/* wake up any waiting workers */
	pthread_cond_signal(&queue->fwq_sleep_cond);
	pthread_mutex_unlock(&queue->fwq_lock);

out:
	return rc;
}

void cleanup_work_queue(struct find_work_queue *queue)
{
	struct find_work_unit *unit, *next;

	pthread_mutex_lock(&queue->fwq_lock);
	unit = queue->fwq_head;
	while (unit) {
		next = unit->fwu_next;
		work_unit_free(unit);
		ll_atomic_fetch_sub(&queue->fwq_active_units, 1);
		unit = next;
	}
	queue->fwq_head = queue->fwq_tail = NULL;
	pthread_mutex_unlock(&queue->fwq_lock);
}

static int pfind_param_callback(char *path, struct find_param *param,
				struct find_work_queue *queue)
{
	char *buf;
	int ret;

	if (strlen(path) > PATH_MAX) {
		ret = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, ret,
			    "Path name '%s' is too long", path);
		return ret;
	}

	buf = (char *)malloc(PATH_MAX + 1);
	if (!buf)
		return -ENOMEM;

	snprintf(buf, PATH_MAX + 1, "%s", path);
	ret = common_param_init(param, buf);
	if (ret)
		goto out;

	param->fp_queue = queue;
	ret = work_unit_create_and_add(buf, param, NULL);
	if (ret)
		goto out;

	/* Wait for all work to complete */
	while (ll_atomic_fetch_add(&queue->fwq_active_units, 0) > 0) {
		/* if a worker hit an error, it forces shutdown... */
		if (queue->fwq_shutdown)
			cleanup_work_queue(queue);
		else
			sched_yield();
	}
	/* collect error if one occurred... */
	ret = queue->fwq_error;

out:
	find_param_fini(param);
	free(buf);
	return ret < 0 ? ret : 0;
}

int parallel_find(char *path, struct find_param *param)
{
	struct find_work_queue queue = { 0 };
	pthread_t *threads = NULL;
	int numthreads = param->fp_thread_count;
	int rc;
	int i;

	if (param->fp_format_printf_str)
		validate_printf_str(param);

	/* require at least one thread */
	if (numthreads < 1)
		return -EINVAL;

	find_work_queue_init(&queue);

	threads = malloc(numthreads * sizeof(pthread_t));
	if (!threads)
		return -ENOMEM;

	rc = find_threads_init(threads, &queue, numthreads);
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Failed to initialize thread pool");
		goto cleanup;
	}
	/* Normal find - no parallelism yet */
	rc = pfind_param_callback(path, param, &queue);


	/* Signal shutdown and wait for threads before cleanup */
	pthread_mutex_lock(&queue.fwq_lock);
	queue.fwq_shutdown = true;
	pthread_cond_broadcast(&queue.fwq_sleep_cond);
	pthread_mutex_unlock(&queue.fwq_lock);
	for (i = 0; i < numthreads; i++)
		pthread_join(threads[i], NULL);

cleanup:
	free(threads);
	pthread_mutex_destroy(&queue.fwq_lock);
	pthread_cond_destroy(&queue.fwq_sleep_cond);

	return rc;
}
