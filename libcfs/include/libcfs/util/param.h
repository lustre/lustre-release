/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 * LGPL HEADER END
 *
 * Copyright (c) 2015, James Simmons
 *
 * Author:
 *   James Simmons <jsimmons@infradead.org>
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
