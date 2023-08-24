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
 * String manipulation functions.
 *
 * libcfs/libcfs/libcfs_string.c
 *
 * Author: Nathan Rutman <nathan.rutman@sun.com>
 */

#include <linux/ctype.h>
#include <libcfs/libcfs.h>
#include <libcfs/libcfs_string.h>

/* Convert a text string to a bitmask */
int cfs_str2mask(const char *str, const char *(*bit2str)(int bit),
		 int *oldmask, int minmask, int allmask, int defmask)
{
	const char *debugstr;
	char op = 0;
	int newmask = minmask, i, len, found = 0;

	ENTRY;
	/* <str> must be a list of tokens separated by whitespace or comma,
	 * and optionally an operator ('+' or '-').  If an operator
	 * appears first in <str>, '*oldmask' is used as the starting point
	 * (relative), otherwise minmask is used (absolute).  An operator
	 * applies to all following tokens up to the next operator.
	 */
	while (*str != 0) {
		while (isspace(*str) || *str == ',')
			str++;
		if (*str == 0)
			break;
		if (*str == '+' || *str == '-') {
			op = *str++;
			if (!found)
				/* only if first token is relative */
				newmask = *oldmask;
			while (isspace(*str))
				str++;
			if (*str == 0)		/* trailing op */
				return -EINVAL;
		}

		/* find token length */
		for (len = 0; str[len] != 0 && !isspace(str[len]) &&
			str[len] != '+' && str[len] != '-' && str[len] != ',';
		     len++);

		/* match token */
		found = 0;
		for (i = 0; i < 32; i++) {
			debugstr = bit2str(i);
			if (debugstr != NULL &&
			    strlen(debugstr) == len &&
			    strncasecmp(str, debugstr, len) == 0) {
				if (op == '-')
					newmask &= ~BIT(i);
				else
					newmask |= BIT(i);
				found = 1;
				break;
			}
		}
		if (!found && len == 3 &&
		    (strncasecmp(str, "ALL", len) == 0)) {
			if (op == '-')
				newmask = minmask;
			else
				newmask = allmask;
			found = 1;
		}
		if (!found && strcasecmp(str, "DEFAULT") == 0) {
			if (op == '-')
				newmask = (newmask & ~defmask) | minmask;
			else if (op == '+')
				newmask |= defmask;
			else
				newmask = defmask;
			found = 1;
		}
		if (!found) {
			CWARN("unknown mask '%.*s'.\n"
			      "mask usage: [+|-]<all|type> ...\n", len, str);
			return -EINVAL;
		}
		str += len;
	}

	*oldmask = newmask;
	return 0;
}
EXPORT_SYMBOL(cfs_str2mask);

/**
 * Parses \<range_expr\> token of the syntax. If \a bracketed is false,
 * \a src should only have a single token which can be \<number\> or  \*
 *
 * \retval pointer to allocated range_expr and initialized
 * range_expr::re_lo, range_expr::re_hi and range_expr:re_stride if \a
 `* src parses to
 * \<number\> |
 * \<number\> '-' \<number\> |
 * \<number\> '-' \<number\> '/' \<number\>
 * \retval 0 will be returned if it can be parsed, otherwise -EINVAL or
 * -ENOMEM will be returned.
 */
static int
cfs_range_expr_parse(char *src, unsigned int min, unsigned int max,
		     int bracketed, struct cfs_range_expr **expr)
{
	struct cfs_range_expr *re;
	char *tok;
	unsigned int num;

	LIBCFS_ALLOC(re, sizeof(*re));
	if (re == NULL)
		return -ENOMEM;

	src = strim(src);
	if (strcmp(src, "*") == 0) {
		re->re_lo = min;
		re->re_hi = max;
		re->re_stride = 1;
		goto out;
	}

	if (kstrtouint(src, 0, &num) == 0) {
		if (num < min || num > max)
			goto failed;
		/* <number> is parsed */
		re->re_lo = num;
		re->re_hi = re->re_lo;
		re->re_stride = 1;
		goto out;
	}

	if (!bracketed)
		goto failed;
	tok = strim(strsep(&src, "-"));
	if (!src)
		goto failed;
	if (kstrtouint(tok, 0, &num) != 0 ||
	    num < min || num > max)
		goto failed;
	re->re_lo = num;

	/* <number> - */
	if (kstrtouint(strim(src), 0, &num) == 0) {
		if (num < min || num > max)
			goto failed;
		re->re_hi = num;
		/* <number> - <number> is parsed */
		re->re_stride = 1;
		goto out;
	}

	/* go to check <number> '-' <number> '/' <number> */
	tok = strim(strsep(&src, "/"));
	if (!src)
		goto failed;
	if (kstrtouint(tok, 0, &num) != 0 ||
	    num < min || num > max)
		goto failed;
	re->re_hi = num;
	if (kstrtouint(strim(src), 0, &num) != 0 ||
	    num < min || num > max)
		goto failed;
	re->re_stride = num;

out:
	*expr = re;
	return 0;

failed:
	LIBCFS_FREE(re, sizeof(*re));
	return -EINVAL;
}

/**
 * Matches value (\a value) against ranges expression list \a expr_list.
 *
 * \retval 1 if \a value matches
 * \retval 0 otherwise
 */
int
cfs_expr_list_match(__u32 value, struct cfs_expr_list *expr_list)
{
	struct cfs_range_expr *expr;

	list_for_each_entry(expr, &expr_list->el_exprs, re_link) {
		if (value >= expr->re_lo && value <= expr->re_hi &&
		    ((value - expr->re_lo) % expr->re_stride) == 0)
			return 1;
	}

	return 0;
}
EXPORT_SYMBOL(cfs_expr_list_match);

/**
 * Convert express list (\a expr_list) to an array of all matched values
 *
 * \retval N N is total number of all matched values
 * \retval 0 if expression list is empty
 * \retval < 0 for failure
 */
int
cfs_expr_list_values(struct cfs_expr_list *expr_list, int max, __u32 **valpp)
{
	struct cfs_range_expr *expr;
	__u32 *val;
	int count = 0;
	int i;

	list_for_each_entry(expr, &expr_list->el_exprs, re_link) {
		for (i = expr->re_lo; i <= expr->re_hi; i++) {
			if (((i - expr->re_lo) % expr->re_stride) == 0)
				count++;
		}
	}

	if (count == 0) /* empty expression list */
		return 0;

	if (count > max) {
		CERROR("Number of values %d exceeds max allowed %d\n",
		       max, count);
		return -EINVAL;
	}

	CFS_ALLOC_PTR_ARRAY(val, count);
	if (val == NULL)
		return -ENOMEM;

	count = 0;
	list_for_each_entry(expr, &expr_list->el_exprs, re_link) {
		for (i = expr->re_lo; i <= expr->re_hi; i++) {
			if (((i - expr->re_lo) % expr->re_stride) == 0)
				val[count++] = i;
		}
	}

	*valpp = val;
	return count;
}
EXPORT_SYMBOL(cfs_expr_list_values);

void
cfs_expr_list_values_free(__u32 *values, int num)
{
	/* This array is allocated by LIBCFS_ALLOC(), so it shouldn't be freed
	 * by OBD_FREE() if it's called by module other than libcfs & LNet,
	 * otherwise we will see fake memory leak */
	CFS_FREE_PTR_ARRAY(values, num);
}
EXPORT_SYMBOL(cfs_expr_list_values_free);

/**
 * Frees cfs_range_expr structures of \a expr_list.
 *
 * \retval none
 */
void
cfs_expr_list_free(struct cfs_expr_list *expr_list)
{
	while (!list_empty(&expr_list->el_exprs)) {
		struct cfs_range_expr *expr;

		expr = list_first_entry(&expr_list->el_exprs,
					struct cfs_range_expr, re_link);
		list_del(&expr->re_link);
		LIBCFS_FREE(expr, sizeof(*expr));
	}

	LIBCFS_FREE(expr_list, sizeof(*expr_list));
}
EXPORT_SYMBOL(cfs_expr_list_free);

/**
 * Parses \<cfs_expr_list\> token of the syntax.
 *
 * \retval 0 if \a str parses to \<number\> | \<expr_list\>
 * \retval -errno otherwise
 */
int
cfs_expr_list_parse(char *str, int len, unsigned min, unsigned max,
		    struct cfs_expr_list **elpp)
{
	struct cfs_expr_list *expr_list;
	struct cfs_range_expr *expr;
	char *src;
	int rc;

	CFS_ALLOC_PTR(expr_list);
	if (expr_list == NULL)
		return -ENOMEM;

	str = kstrndup(str, len, GFP_KERNEL);
	if (!str) {
		CFS_FREE_PTR(expr_list);
		return -ENOMEM;
	}

	src = str;

	INIT_LIST_HEAD(&expr_list->el_exprs);

	if (src[0] == '[' &&
	    src[strlen(src) - 1] == ']') {
		src++;
		src[strlen(src)-1] = '\0';

		rc = -EINVAL;
		while (src) {
			char *tok = strim(strsep(&src, ","));

			rc = cfs_range_expr_parse(tok, min, max, 1, &expr);
			if (rc != 0)
				break;

			list_add_tail(&expr->re_link, &expr_list->el_exprs);
		}
	} else {
		rc = cfs_range_expr_parse(src, min, max, 0, &expr);
		if (rc == 0)
			list_add_tail(&expr->re_link, &expr_list->el_exprs);
	}
	kfree(str);

	if (rc != 0)
		cfs_expr_list_free(expr_list);
	else
		*elpp = expr_list;

	return rc;
}
EXPORT_SYMBOL(cfs_expr_list_parse);

/**
 * Frees cfs_expr_list structures of \a list.
 *
 * For each struct cfs_expr_list structure found on \a list it frees
 * range_expr list attached to it and frees the cfs_expr_list itself.
 *
 * \retval none
 */
void
cfs_expr_list_free_list(struct list_head *list)
{
	struct cfs_expr_list *el;

	while (!list_empty(list)) {
		el = list_first_entry(list,
				      struct cfs_expr_list, el_link);
		list_del(&el->el_link);
		cfs_expr_list_free(el);
	}
}
EXPORT_SYMBOL(cfs_expr_list_free_list);
