/* SPDX-License-Identifier: LGPL-2.1 */

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

static inline void cfs_free_param_data(glob_t *paths)
{
	globfree(paths);
}

int cfs_get_param_paths(glob_t *paths, const char *pattern, ...)
		       __attribute__((__format__(__printf__, 2, 3)));

#endif /* _LIBCFS_UTIL_PARAM_H_ */
