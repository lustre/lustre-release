/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * (C) Copyright 2012 Commissariat a l'energie atomique et aux energies
 *     alternatives
 *
 * Copyright (c) 2016, 2017, Intel Corporation.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 or (at your discretion) any later version.
 * (LGPL) version 2.1 accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * LGPL HEADER END
 */
/*
 *
 * lustre/utils/lctl_thread.h
 *
 * Author: Rajeev Mishra <rajeevm@hpe.com>
 */
#if HAVE_LIBPTHREAD
#include <pthread.h>
#endif
#ifndef STRINGIFY
#define STRINGIFY(a) #a
#endif

struct param_opts {
	unsigned int po_only_name:1;
	unsigned int po_show_name:1;
	unsigned int po_only_pathname:1;
	unsigned int po_show_type:1;
	unsigned int po_recursive:1;
	unsigned int po_perm:1;
	unsigned int po_delete:1;
	unsigned int po_only_dir:1;
	unsigned int po_file:1;
	unsigned int po_yaml:1;
	unsigned int po_detail:1;
	unsigned int po_header:1;
	unsigned int po_follow_symlinks:1;
	unsigned int po_parallel_threads;
	unsigned int po_permissions;
};

#ifdef HAVE_LIBPTHREAD
#define popt_is_parallel(popt) ((popt).po_parallel_threads > 0)

int write_param(const char *path, const char *param_name,
		struct param_opts *popt, const char *value);

#define LCFG_THREADS_DEF 8

/* A work item for parallel set_param */
struct sp_work_item {
	/* The full path to the parameter file */
	char *spwi_path;

	/* The parameter name as returned by display_name */
	char *spwi_param_name;

	/* The value to which the parameter is to be set */
	char *spwi_value;
};

/* A work queue struct for parallel set_param */
struct sp_workq {
	/* The parameter options passed to set_param */
	struct param_opts *spwq_popt;

	/* The number of valid items in spwq_items */
	int spwq_len;

	/* The size of the spwq_items list */
	int spwq_size;

	/* The current index into the spwq_items list */
	int spwq_cur_index;

	/* Array of work items. */
	struct sp_work_item *spwq_items;

	/* A mutex to control access to the work queue */
	pthread_mutex_t spwq_mutex;
};

int spwq_init(struct sp_workq *wq, struct param_opts *popt);
int spwq_destroy(struct sp_workq *wq);
int spwq_expand(struct sp_workq *wq, size_t num_items);
int spwq_add_item(struct sp_workq *wq, char *path, char *param_name,
		  char *value);
int sp_run_threads(struct sp_workq *wq);
#else
#define popt_is_parallel(popt) 0

struct sp_workq { int unused; };

static inline int spwq_init(struct sp_workq *wq, struct param_opts *popt)
{ return 0; }
static inline int spwq_destroy(struct sp_workq *wq)
{ return 0; }
static inline int spwq_expand(struct sp_workq *wq, size_t num_items)
{ return 0; }
static inline int spwq_add_item(struct sp_workq *wq, char *path,
				char *param_name, char *value)
{ return 0; }
static inline int sp_run_threads(struct sp_workq *wq)
{ return 0; }

#endif
