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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * libcfs/include/libcfs/libcfs_string.h
 *
 * Generic string manipulation functions.
 *
 * Author: Nathan Rutman <nathan.rutman@sun.com>
 */

#ifndef __LIBCFS_UTIL_STRING_H__
#define __LIBCFS_UTIL_STRING_H__

#include <stddef.h>
#include <stdarg.h>

#include <linux/types.h>
#include <linux/lnet/lnet-types.h>
#include <libcfs/util/list.h>

static inline
int vscnprintf(char *buf, size_t bufsz, const char *format, va_list args)
{
	int ret;

	if (!bufsz)
		return 0;

	ret = vsnprintf(buf, bufsz, format, args);
	return (bufsz > ret) ? ret : bufsz - 1;
}

/* __printf from linux kernel */
#ifndef __printf
#define __printf(a, b)		__attribute__((__format__(printf, a, b)))
#endif

__printf(3, 4)
static inline int scnprintf(char *buf, size_t bufsz, const char *format, ...)
{
	int ret;
	va_list args;

	va_start(args, format);
	ret = vscnprintf(buf, bufsz, format, args);
	va_end(args);

	return ret;
}

struct netstrfns {
	__u32	nf_type;
	char	*nf_name;
	char	*nf_modname;
	void	(*nf_addr2str)(__u32 addr, char *str, size_t size);
	int	(*nf_str2addr)(const char *str, int nob, __u32 *addr);
	int	(*nf_parse_addrlist)(char *str, int len,
				     struct list_head *list);
	int	(*nf_print_addrlist)(char *buffer, int count,
				     struct list_head *list);
	int	(*nf_match_addr)(__u32 addr, struct list_head *list);
	int	(*nf_min_max)(struct list_head *nidlist, __u32 *min_nid,
			      __u32 *max_nid);
	int	(*nf_expand_addrrange)(struct list_head *addrranges,
				       __u32 *addrs, int max_addrs);
};

/**
 * Structure to represent NULL-less strings.
 */
struct cfs_lstr {
	char		*ls_str;
	int		ls_len;
};

/*
 * Structure to represent \<range_expr\> token of the syntax.
 */
struct cfs_range_expr {
	/*
	 * Link to cfs_expr_list::el_exprs.
	 */
	struct list_head	re_link;
	__u32			re_lo;
	__u32			re_hi;
	__u32			re_stride;
};

struct cfs_expr_list {
	struct list_head	el_link;
	struct list_head	el_exprs;
};

int cfs_expr_list_values(struct cfs_expr_list *expr_list, int max, __u32 **valpp);
int cfs_gettok(struct cfs_lstr *next, char delim, struct cfs_lstr *res);
int cfs_str2num_check(char *str, int nob, unsigned *num,
		      unsigned min, unsigned max);
int cfs_expr2str(struct list_head *list, char *str, size_t size);
int cfs_expr_list_match(__u32 value, struct cfs_expr_list *expr_list);
int cfs_expr_list_print(char *buffer, int count,
			struct cfs_expr_list *expr_list);
int cfs_expr_list_parse(char *str, int len, unsigned min, unsigned max,
			struct cfs_expr_list **elpp);
void cfs_expr_list_free(struct cfs_expr_list *expr_list);
void cfs_expr_list_free_list(struct list_head *list);
int cfs_ip_addr_parse(char *str, int len, struct list_head *list);
int cfs_ip_addr_range_gen(__u32 *ip_list, int count,
			  struct list_head *ip_addr_expr);
int cfs_ip_addr_match(__u32 addr, struct list_head *list);
int cfs_expand_nidlist(struct list_head *nidlist, lnet_nid_t *lnet_nidlist,
		       int max_nids);
int cfs_parse_nid_parts(char *str, struct list_head *addr,
			struct list_head *net_num, __u32 *net_type);
int cfs_abs_path(const char *request_path, char **resolved_path);

#endif
