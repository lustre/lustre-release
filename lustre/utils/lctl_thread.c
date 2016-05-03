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
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/lctl_thread.c
 *
 * Author: Rajeev Mishra <rajeevm@hpe.com>
 */
 #include <errno.h>
 #include <stdio.h>
 #include <stdarg.h>
 #include <ctype.h>
 #include "lctl_thread.h"
 #include <stdlib.h>
 #include <libcfs/util/string.h>
#if HAVE_LIBPTHREAD
/**
 * Initialize the given set_param work queue.
 *
 * \param[out] wq  the work queue to initialize
 * \param[in] popt the options passed to set_param
 *
 * \retval 0 if successful
 * \retval -errno if unsuccessful
 */
int spwq_init(struct sp_workq *wq, struct param_opts *popt)
{
	if (!wq)
		return -EINVAL;

	memset(wq, 0, sizeof(*wq));
	wq->spwq_popt = popt;

	/* pthread_mutex_init returns 0 for success, or errno for failure */
	return -pthread_mutex_init(&wq->spwq_mutex, NULL);
}

/**
 * Destroy and free space used by a set_param work queue.
 *
 * \param[in] wq the work queue to destroy
 *
 * \retval 0 if successful
 * \retval -errno if unsuccessful
 */
int spwq_destroy(struct sp_workq *wq)
{
	int rc;

	if (!wq)
		return 0;

	if (wq->spwq_items) {
		int i;

		for (i = 0; i < wq->spwq_len; i++) {
			free(wq->spwq_items[i].spwi_path);
			free(wq->spwq_items[i].spwi_param_name);
			/* wq->spwq_items[i].spwi_value was not malloc'd */
		}
		free(wq->spwq_items);
	}

	/* pthread_mutex_destroy returns 0 for success, or errno for failure */
	rc = -pthread_mutex_destroy(&wq->spwq_mutex);

	memset(wq, 0, sizeof(*wq));

	return rc;
}

/**
 * Expand the size of a work queue to fit the requested number of items.
 *
 * \param[in,out] wq    the work queue to expand
 * \param[in] num_items the number of items to make room for in \a wq
 *
 * \retval 0 if successful
 * \retval -errno if unsuccessful
 */
int spwq_expand(struct sp_workq *wq, size_t num_items)
{
	int space;
	int new_size;
	struct sp_work_item *tmp;

	if (!wq)
		return -EINVAL;

	space = wq->spwq_size - wq->spwq_len;

	/* First check if there's already enough room. */
	if (space >= num_items)
		return 0;

	new_size = wq->spwq_len + num_items;

	/* When spwq_items is NULL, realloc behaves like malloc */
	tmp = realloc(wq->spwq_items, new_size * sizeof(struct sp_work_item));

	if (!tmp)
		return -ENOMEM;

	wq->spwq_items = tmp;
	wq->spwq_size = new_size;

	return 0;
}

/**
 * Add an item to a set_param work queue. Not thread-safe.
 *
 * \param[in,out] wq     the work queue to which the item should be added
 * \param[in] path       the full path to the parameter file (will be copied)
 * \param[in] param_name the name of the parameter (will be copied)
 * \param[in] value      the value for the parameter (will not be copied)
 *
 * \retval 0 if successful
 * \retval -errno if unsuccessful
 */
int spwq_add_item(struct sp_workq *wq, char *path,
			 char *param_name, char *value)
{
	char *path_copy;
	char *param_name_copy;
	int rc;

	if (!(wq && path && param_name && value))
		return -EINVAL;

	/* Hopefully the caller has expanded the work queue before calling this
	 * function, but make sure there's room just in case.
	 */
	rc = spwq_expand(wq, 1);
	if (rc < 0)
		return rc;

	path_copy = strdup(path);
	if (!path_copy)
		return -ENOMEM;

	param_name_copy = strdup(param_name);
	if (!param_name_copy) {
		free(path_copy);
		return -ENOMEM;
	}

	wq->spwq_items[wq->spwq_len].spwi_param_name = param_name_copy;
	wq->spwq_items[wq->spwq_len].spwi_path = path_copy;
	wq->spwq_items[wq->spwq_len].spwi_value = value;

	wq->spwq_len++;

	return 0;
}

/**
 * Gets the next item from the set_param \a wq in a thread-safe manner.
 *
 * \param[in] wq  the workq from which to obtain the next item
 * \param[out] wi the next work item in \a wa, will be set to NULL if \wq empty
 *
 * \retval 0 if successful (empty work queue is considered successful)
 * \retval -errno if unsuccessful
 */
static int spwq_next_item(struct sp_workq *wq, struct sp_work_item **wi)
{
	int rc_lock;
	int rc_unlock;

	if (!(wq && wi))
		return -EINVAL;

	*wi = NULL;

	rc_lock = pthread_mutex_lock(&wq->spwq_mutex);
	if (rc_lock == 0) {
		if (wq->spwq_cur_index < wq->spwq_len)
			*wi = &wq->spwq_items[wq->spwq_cur_index++];
		rc_unlock = pthread_mutex_unlock(&wq->spwq_mutex);
	}

	return rc_lock != 0 ? -rc_lock : -rc_unlock;
}

/**
 * A set_param worker thread which sets params from the workq.
 *
 * \param[in] arg a pointer to a struct sp_workq
 *
 * \retval 0 if successful
 * \retval -errno if unsuccessful
 */
static void *sp_thread(void *arg)
{
	struct sp_workq *wq = (struct sp_workq *)arg;
	struct param_opts *popt = wq->spwq_popt;
	struct sp_work_item *work_item;
	long int rc = 0;

	rc = spwq_next_item(wq, &work_item);
	if (rc < 0)
		return (void *)rc;

	while (work_item) {
		char *path = work_item->spwi_path;
		char *param_name = work_item->spwi_param_name;
		char *value = work_item->spwi_value;
		int rc2;

		rc2 = write_param(path, param_name, popt, value);
		if (rc2 < 0)
			rc = rc2;
		rc2 = spwq_next_item(wq, &work_item);
		if (rc2 < 0)
			rc = rc2;
	}

	return (void *)rc;
}

/**
 * Spawn threads and set parameters in a work queue in parallel.
 *
 * \param[in] wq the work queue containing parameters to set
 *
 * \retval 0 if successful
 * \retval -errno if unsuccessful
 */
int sp_run_threads(struct sp_workq *wq)
{
	int rc = 0;
	int i;
	int j;
	int num_threads;
	pthread_t *sp_threads;

	if (!wq)
		return -EINVAL;

	if (wq->spwq_len == 0)
		return 0;

	num_threads = wq->spwq_popt->po_parallel_threads;
	if (num_threads > wq->spwq_len)
		num_threads = wq->spwq_len;

	sp_threads = malloc(sizeof(pthread_t) * num_threads);
	if (!sp_threads)
		return -ENOMEM;

	for (i = 0; i < num_threads; i++) {
		rc = -pthread_create(&sp_threads[i], NULL, &sp_thread, wq);
		if (rc != 0)
			break;
	}

	/* check if we failed to create any threads at all */
	if (i == 0)
		goto out_free;

	/* ignore thread creation errors if at least one was created */
	rc = 0;

	for (j = 0; j < i; j++) {
		int join_rc;
		void *res = NULL;

		join_rc = -pthread_join(sp_threads[j], &res);
		if (join_rc && rc == 0)
			rc = join_rc;
		if (res)
			/* this error takes priority over join errors */
			rc = (long int)res;
	}

out_free:
	free(sp_threads);
	return rc;
}
#else
#define popt_is_parallel(popt) 0
#define spwq_init(wq, popt) 0
#define spwq_expand(wq, num_items) 0
#define spwq_add_item(wq, path, param_name, value) 0
#define sp_run_threads(wq) 0
#define spwq_destroy(wq) 0
struct sp_workq { int unused; }
#endif /* HAVE_LIBPTHREAD */
