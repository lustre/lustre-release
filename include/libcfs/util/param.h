/* SPDX-License-Identifier: LGPL-2.1+ */

/*
 * Copyright (c) 2015, James Simmons
 */

/*
 * Author: James Simmons <jsimmons@infradead.org>
 */

#ifndef _LIBCFS_UTIL_PARAM_H_
#define _LIBCFS_UTIL_PARAM_H_

#include <glob.h>
#include <stdbool.h>
#include <libcfs/util/string.h>

#define CFS_MODULE_PARAM_DIR	"/sys/module"

static inline void cfs_free_param_data(glob_t *paths)
{
	globfree(paths);
}

__printf(2, 3)
int cfs_get_param_paths(glob_t *paths, const char *pattern, ...);
__printf(2, 3)
int cfs_get_param_paths_modules(glob_t *paths, const char *pattern, ...);

#endif /* _LIBCFS_UTIL_PARAM_H_ */
