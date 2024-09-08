/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Generic string manipulation functions.
 *
 * Author: Nathan Rutman <nathan.rutman@sun.com>
 */

#ifndef __LIBCFS_STRING_H__
#define __LIBCFS_STRING_H__

/* libcfs_string.c */
/* Convert a text string to a bitmask */
int cfs_str2mask(const char *str, const char *(*bit2str)(int bit),
		 u64 *oldmask, u64 minmask, u64 allmask, u64 defmask);
int cfs_mask2str(char *str, int size, u64 mask, const char *(*bit2str)(int),
		 char sep);

/*
 * Structure to represent \<range_expr\> token of the syntax.
 */
struct cfs_range_expr {
	/*
	 * Link to cfs_expr_list::el_exprs.
	 */
	struct list_head	re_link;
	u32			re_lo;
	u32			re_hi;
	u32			re_stride;
};

struct cfs_expr_list {
	struct list_head	el_link;
	struct list_head	el_exprs;
};

int cfs_expr_list_match(u32 value, struct cfs_expr_list *expr_list);
int cfs_expr_list_values(struct cfs_expr_list *expr_list,
			 int max, u32 **values);
void cfs_expr_list_free(struct cfs_expr_list *expr_list);
int cfs_expr_list_parse(char *str, int len, unsigned int min, unsigned int max,
			struct cfs_expr_list **elpp);
void cfs_expr_list_free_list(struct list_head *list);
#define cfs_expr_list_values_free(values, num)	CFS_FREE_PTR_ARRAY(values, num)

#endif
