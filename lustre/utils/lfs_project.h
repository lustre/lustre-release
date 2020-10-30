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
 * Copyright (c) 2017, DataDirect Networks Storage.
 * Copyright (c) 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/lfs_project.h
 *
 * Author: Wang Shilong <wshilong@ddn.com>
 * Author: Fan Yong <fan.yong@intel.com>
 */
#ifndef	_LFS_PROJECT_H
#define	_LFS_PROJECT_H
#include <stdbool.h>
#include <linux/types.h>

extern const char	*progname;

enum lfs_project_ops_t {
	LFS_PROJECT_CHECK	= 0,
	LFS_PROJECT_CLEAR	= 1,
	LFS_PROJECT_SET		= 2,
	LFS_PROJECT_LIST	= 3,
	LFS_PROJECT_MAX		= 4,
};

struct project_handle_control {
	__u32	projid;
	bool	assign_projid;
	bool	set_inherit;
	bool	set_projid;
	bool	newline;
	bool	keep_projid;
	bool	recursive;
	bool	dironly;
};

int lfs_project_list(const char *pathname,
		     struct project_handle_control *phc);
int lfs_project_check(const char *pathname,
		      struct project_handle_control *phc);
int lfs_project_clear(const char *pathname,
		      struct project_handle_control *phc);
int lfs_project_set(const char *pathname,
		    struct project_handle_control *phc);
#endif	/* _LFS_PROJECT_H */
