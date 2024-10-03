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


/* convert a binary mask to a string of bit names */
int cfs_mask2str(char *str, int size, u64 mask, const char *(*bit2str)(int bit),
		 char sep)
{
	int len = 0;
	const char *token;
	int i;

	if (mask == 0) {			/* "0" */
		if (size > 0)
			str[0] = '0';
		len = 1;
	} else {				/* space-separated tokens */
		for (i = 0; i < 64; i++) {
			if ((mask & BIT(i)) == 0)
				continue;

			token = bit2str(i);
			if (!token)		/* unused bit */
				continue;

			if (len > 0) {		/* separator? */
				if (len < size)
					str[len] = sep;
				len++;
			}

			while (*token != 0) {
				if (len < size)
					str[len] = *token;
				token++;
				len++;
			}
		}
	}

	/* terminate 'str' */
	if (len < size)
		str[len++] = '\n';
	if (len < size)
		str[len] = '\0';
	else
		str[size - 1] = '\0';

	return len;
}
EXPORT_SYMBOL(cfs_mask2str);

/* Convert a text string to a bitmask */
int cfs_str2mask(const char *str, const char *(*bit2str)(int bit),
		 u64 *oldmask, u64 minmask, u64 allmask, u64 defmask)
{
	const char *debugstr;
	u64 newmask = *oldmask, found = 0;

	ENTRY;
	/* <str> must be a list of tokens separated by whitespace or comma,
	 * and optionally an operator ('+' or '-').  If an operator
	 * appears first in <str>, '*oldmask' is used as the starting point
	 * (relative), otherwise minmask is used (absolute).  An operator
	 * applies to all following tokens up to the next operator.
	 */
	while (*str != 0) {
		int i, len;
		char op = 0;

		while (isspace(*str) || *str == ',')
			str++;
		if (*str == 0)
			break;
		if (*str == '+' || *str == '-') {
			op = *str++;
			while (isspace(*str))
				str++;
			if (*str == 0)		/* trailing op */
				return -EINVAL;
		} else if (!found)
			newmask = minmask;


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
