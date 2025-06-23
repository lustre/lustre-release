/* SPDX-License-Identifier: GPL-2.0-only */
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
