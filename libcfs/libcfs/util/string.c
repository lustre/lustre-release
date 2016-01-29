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
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * String manipulation functions.
 *
 * libcfs/libcfs/util/string.c
 *
 * Author: Nathan Rutman <nathan.rutman@sun.com>
 */
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libcfs/util/string.h>

/*
 * According manual of strlcpy() and strlcat() the functions should return
 * the total length of the string they tried to create. For strlcpy() that
 * means the length of src. For strlcat() that means the initial length of
 * dst plus the length of src. So, the function strnlen() cannot be used
 * otherwise the return value will be wrong.
 */
#ifndef HAVE_STRLCPY /* not in glibc for RHEL 5.x, remove when obsolete */
size_t strlcpy(char *dst, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size - 1 : ret;
		memcpy(dst, src, len);
		dst[len] = '\0';
	}
	return ret;
}
#endif

#ifndef HAVE_STRLCAT /* not in glibc for RHEL 5.x, remove when obsolete */
size_t strlcat(char *dst, const char *src, size_t size)
{
	size_t dsize = strlen(dst);
	size_t len = strlen(src);
	size_t ret = dsize + len;

	dst  += dsize;
	size -= dsize;
	if (len >= size)
		len = size-1;
	memcpy(dst, src, len);
	dst[len] = '\0';
	return ret;
}
#endif

/**
 * Extracts tokens from strings.
 *
 * Looks for \a delim in string \a next, sets \a res to point to
 * substring before the delimiter, sets \a next right after the found
 * delimiter.
 *
 * \retval 1 if \a res points to a string of non-whitespace characters
 * \retval 0 otherwise
 */
int
cfs_gettok(struct cfs_lstr *next, char delim, struct cfs_lstr *res)
{
	char *end;

	if (next->ls_str == NULL)
		return 0;

	/* skip leading white spaces */
	while (next->ls_len) {
		if (!isspace(*next->ls_str))
			break;
		next->ls_str++;
		next->ls_len--;
	}

	if (next->ls_len == 0) /* whitespaces only */
		return 0;

	if (*next->ls_str == delim) {
		/* first non-writespace is the delimiter */
		return 0;
	}

	res->ls_str = next->ls_str;
	end = memchr(next->ls_str, delim, next->ls_len);
	if (end == NULL) {
		/* there is no the delimeter in the string */
		end = next->ls_str + next->ls_len;
		next->ls_str = NULL;
	} else {
		next->ls_str = end + 1;
		next->ls_len -= (end - res->ls_str + 1);
	}

	/* skip ending whitespaces */
	while (--end != res->ls_str) {
		if (!isspace(*end))
			break;
	}

	res->ls_len = end - res->ls_str + 1;
	return 1;
}

/**
 * Converts string to integer.
 *
 * Accepts decimal and hexadecimal number recordings.
 *
 * \retval 1 if first \a nob chars of \a str convert to decimal or
 * hexadecimal integer in the range [\a min, \a max]
 * \retval 0 otherwise
 */
int
cfs_str2num_check(char *str, int nob, unsigned *num,
		  unsigned min, unsigned max)
{
	char	*endp;

	*num = strtoul(str, &endp, 0);
	if (endp == str)
		return 0;

	for (; endp < str + nob; endp++) {
		if (!isspace(*endp))
			return 0;
	}

	return (*num >= min && *num <= max);
}

/**
 * Parses \<range_expr\> token of the syntax. If \a bracketed is false,
 * \a src should only have a single token which can be \<number\> or  \*
 *
 * \retval pointer to allocated range_expr and initialized
 * range_expr::re_lo, range_expr::re_hi and range_expr:re_stride if \a
 * src parses to
 * \<number\> |
 * \<number\> '-' \<number\> |
 * \<number\> '-' \<number\> '/' \<number\>
 * \retval 0 will be returned if it can be parsed, otherwise -EINVAL or
 * -ENOMEM will be returned.
 */
static int
cfs_range_expr_parse(struct cfs_lstr *src, unsigned min, unsigned max,
		     int bracketed, struct cfs_range_expr **expr)
{
	struct cfs_range_expr	*re;
	struct cfs_lstr		tok;

	re = calloc(1, sizeof(*re));
	if (re == NULL)
		return -ENOMEM;

	if (src->ls_len == 1 && src->ls_str[0] == '*') {
		re->re_lo = min;
		re->re_hi = max;
		re->re_stride = 1;
		goto out;
	}

	if (cfs_str2num_check(src->ls_str, src->ls_len,
			      &re->re_lo, min, max)) {
		/* <number> is parsed */
		re->re_hi = re->re_lo;
		re->re_stride = 1;
		goto out;
	}

	if (!bracketed || !cfs_gettok(src, '-', &tok))
		goto failed;

	if (!cfs_str2num_check(tok.ls_str, tok.ls_len,
			       &re->re_lo, min, max))
		goto failed;

	/* <number> - */
	if (cfs_str2num_check(src->ls_str, src->ls_len,
			      &re->re_hi, min, max)) {
		/* <number> - <number> is parsed */
		re->re_stride = 1;
		goto out;
	}

	/* go to check <number> '-' <number> '/' <number> */
	if (cfs_gettok(src, '/', &tok)) {
		if (!cfs_str2num_check(tok.ls_str, tok.ls_len,
				       &re->re_hi, min, max))
			goto failed;

		/* <number> - <number> / ... */
		if (cfs_str2num_check(src->ls_str, src->ls_len,
				      &re->re_stride, min, max)) {
			/* <number> - <number> / <number> is parsed */
			goto out;
		}
	}

 out:
	*expr = re;
	return 0;

 failed:
	free(re);
	return -EINVAL;
}

/**
 * Print the range expression \a re into specified \a buffer.
 * If \a bracketed is true, expression does not need additional
 * brackets.
 *
 * \retval number of characters written
 */
static int
cfs_range_expr_print(char *buffer, int count, struct cfs_range_expr *expr,
		     bool bracketed)
{
	int i;
	char s[] = "[";
	char e[] = "]";

	if (bracketed)
		s[0] = e[0] = '\0';

	if (expr->re_lo == expr->re_hi)
		i = snprintf(buffer, count, "%u", expr->re_lo);
	else if (expr->re_stride == 1)
		i = snprintf(buffer, count, "%s%u-%u%s",
				  s, expr->re_lo, expr->re_hi, e);
	else
		i = snprintf(buffer, count, "%s%u-%u/%u%s",
				  s, expr->re_lo, expr->re_hi,
				  expr->re_stride, e);
	return i;
}

/**
 * Print a list of range expressions (\a expr_list) into specified \a buffer.
 * If the list contains several expressions, separate them with comma
 * and surround the list with brackets.
 *
 * \retval number of characters written
 */
int
cfs_expr_list_print(char *buffer, int count, struct cfs_expr_list *expr_list)
{
	struct cfs_range_expr *expr;
	int i = 0, j = 0;
	int numexprs = 0;

	if (count <= 0)
		return 0;

	list_for_each_entry(expr, &expr_list->el_exprs, re_link)
		numexprs++;

	if (numexprs > 1)
		i += snprintf(buffer + i, count - i, "[");

	list_for_each_entry(expr, &expr_list->el_exprs, re_link) {
		if (j++ != 0)
			i += snprintf(buffer + i, count - i, ",");
		i += cfs_range_expr_print(buffer + i, count - i, expr,
					  numexprs > 1);
	}

	if (numexprs > 1)
		i += snprintf(buffer + i, count - i, "]");

	return i;
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
	struct cfs_range_expr	*expr;

	list_for_each_entry(expr, &expr_list->el_exprs, re_link) {
		if (value >= expr->re_lo && value <= expr->re_hi &&
		    ((value - expr->re_lo) % expr->re_stride) == 0)
			return 1;
	}

	return 0;
}

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
	struct cfs_range_expr	*expr;
	__u32			*val;
	int			count = 0;
	int			i;

	list_for_each_entry(expr, &expr_list->el_exprs, re_link) {
		for (i = expr->re_lo; i <= expr->re_hi; i++) {
			if (((i - expr->re_lo) % expr->re_stride) == 0)
				count++;
		}
	}

	if (count == 0) /* empty expression list */
		return 0;

	if (count > max)
		return -EINVAL;

	val = calloc(sizeof(val[0]), count);
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

void
cfs_expr_list_values_free(__u32 *values, int num)
{
	/* This array is allocated by LIBCFS_ALLOC(), so it shouldn't be freed
	 * by OBD_FREE() if it's called by module other than libcfs & LNet,
	 * otherwise we will see fake memory leak */
	free(values);
}

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

		expr = list_entry(expr_list->el_exprs.next,
				  struct cfs_range_expr, re_link);
		list_del(&expr->re_link);
		free(expr);
	}

	free(expr_list);
}

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
	struct cfs_expr_list	*expr_list;
	struct cfs_range_expr	*expr;
	struct cfs_lstr		src;
	int			rc;

	expr_list = calloc(1, sizeof(*expr_list));
	if (expr_list == NULL)
		return -ENOMEM;

	src.ls_str = str;
	src.ls_len = len;

	INIT_LIST_HEAD(&expr_list->el_exprs);

	if (src.ls_str[0] == '[' &&
	    src.ls_str[src.ls_len - 1] == ']') {
		src.ls_str++;
		src.ls_len -= 2;

		rc = -EINVAL;
		while (src.ls_str != NULL) {
			struct cfs_lstr tok;

			if (!cfs_gettok(&src, ',', &tok)) {
				rc = -EINVAL;
				break;
			}

			rc = cfs_range_expr_parse(&tok, min, max, 1, &expr);
			if (rc != 0)
				break;

			list_add_tail(&expr->re_link,
					  &expr_list->el_exprs);
		}
	} else {
		rc = cfs_range_expr_parse(&src, min, max, 0, &expr);
		if (rc == 0) {
			list_add_tail(&expr->re_link,
					  &expr_list->el_exprs);
		}
	}

	if (rc != 0)
		cfs_expr_list_free(expr_list);
	else
		*elpp = expr_list;

	return rc;
}

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
		el = list_entry(list->next,
				    struct cfs_expr_list, el_link);
		list_del(&el->el_link);
		cfs_expr_list_free(el);
	}
}
