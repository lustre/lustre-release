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
#include "lustreapi_internal.h"
#include "lstddef.h"



static void work_unit_free(struct find_work_unit *unit);

/* Placeholder worker function - just for testing thread creation */
static void *find_worker(void *arg)
{
	struct find_work_queue *queue = (struct find_work_queue *) arg;
	struct find_work_unit *unit;

	/* TODO: Implement actual work processing */
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

		/* TODO: processing goes here */
		sleep(0.1);

		work_unit_free(unit);
		__sync_fetch_and_sub(&queue->fwq_active_units, 1);
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

/* Free a work unit */
static void work_unit_free(struct find_work_unit *unit)
{
	if (!unit)
		return;

	free(unit->fwu_path);
	free(unit->fwu_de);
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

	/* TODO: deep copy of param
	unit->fwu_param = param; */

	return unit;

error:
	work_unit_free(unit);
	return NULL;
}

static int work_unit_create_and_add(const char *path, struct find_param *param,
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
	while (ll_atomic_fetch_add(&queue->fwq_active_units, 0) > 0)
		sched_yield();

out:
	find_param_fini(param);
	free(buf);
	return ret < 0 ? ret : 0;
}

int parallel_find(char *path, struct find_param *param)
{
	struct find_work_queue queue;
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
	queue.fwq_shutdown = true;
	pthread_cond_broadcast(&queue.fwq_sleep_cond);
	for (i = 0; i < numthreads; i++)
		pthread_join(threads[i], NULL);

cleanup:
	free(threads);
	pthread_mutex_destroy(&queue.fwq_lock);
	pthread_cond_destroy(&queue.fwq_sleep_cond);

	return rc;
}
