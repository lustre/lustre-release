/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * String manipulation functions.
 *
 * libcfs/libcfs/libcfs_string.c
 *
 * Author: Nathan Rutman <nathan.rutman@sun.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#include <libcfs/libcfs.h>

/* non-0 = don't match */
static int cfs_strncasecmp(const char *s1, const char *s2, size_t n)
{
        if (s1 == NULL || s2 == NULL)
                return 1;

        if (n == 0)
                return 0;

        while (n-- != 0 && tolower(*s1) == tolower(*s2)) {
                if (n == 0 || *s1 == '\0' || *s2 == '\0')
                        break;
                s1++;
                s2++;
        }

        return tolower(*(unsigned char *)s1) - tolower(*(unsigned char *)s2);
}

/* Convert a text string to a bitmask */
int cfs_str2mask(const char *str, const char *(*bit2str)(int bit),
                 int *oldmask, int minmask, int allmask)
{
        const char *debugstr;
        char op = 0;
        int newmask = minmask, i, len, found = 0;
        ENTRY;

        /* <str> must be a list of tokens separated by whitespace
         * and optionally an operator ('+' or '-').  If an operator
         * appears first in <str>, '*oldmask' is used as the starting point
         * (relative), otherwise minmask is used (absolute).  An operator
         * applies to all following tokens up to the next operator. */
        while (*str != 0) {
                while (isspace(*str))
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
                        if (*str == 0)          /* trailing op */
                                return -EINVAL;
                }

                /* find token length */
                for (len = 0; str[len] != 0 && !isspace(str[len]) &&
                      str[len] != '+' && str[len] != '-'; len++);

                /* match token */
                found = 0;
                for (i = 0; i < 32; i++) {
                        debugstr = bit2str(i);
                        if (debugstr != NULL &&
                            strlen(debugstr) == len &&
                            cfs_strncasecmp(str, debugstr, len) == 0) {
                                if (op == '-')
                                        newmask &= ~(1 << i);
                                else
                                        newmask |= (1 << i);
                                found = 1;
                                break;
                        }
                }
                if (!found && len == 3 &&
                    (cfs_strncasecmp(str, "ALL", len) == 0)) {
                        if (op == '-')
                                newmask = minmask;
                        else
                                newmask = allmask;
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

/* Duplicate a string in a platform-independent way */
char *cfs_strdup(const char *str, u_int32_t flags)
{
        size_t lenz; /* length of str + zero byte */
        char *dup_str;

        lenz = strlen(str) + 1;

        dup_str = cfs_alloc(lenz, flags);
        if (dup_str == NULL)
                return NULL;

        memcpy(dup_str, str, lenz);

        return dup_str;
}
EXPORT_SYMBOL(cfs_strdup);

/**
 * cfs_{v}snprintf() return the actual size that is printed rather than
 * the size that would be printed in standard functions.
 */
/* safe vsnprintf */
int cfs_vsnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
        int i;

        LASSERT(size > 0);
        i = vsnprintf(buf, size, fmt, args);

        return  (i >= size ? size - 1 : i);
}
EXPORT_SYMBOL(cfs_vsnprintf);

/* safe snprintf */
int cfs_snprintf(char *buf, size_t size, const char *fmt, ...)
{
        va_list args;
        int i;

        va_start(args, fmt);
        i = cfs_vsnprintf(buf, size, fmt, args);
        va_end(args);

        return  i;
}
EXPORT_SYMBOL(cfs_snprintf);

/* get the first string out of @str */
char *cfs_firststr(char *str, size_t size)
{
        size_t i = 0;
        char  *end;

        /* trim leading spaces */
        while (i < size && *str && isspace(*str)) {
                ++i;
                ++str;
        }

        /* string with all spaces */
        if (*str == '\0')
                goto out;

        end = str;
        while (i < size && *end != '\0' && !isspace(*end)) {
                ++i;
                ++end;
        }

        *end= '\0';
out:
        return str;
}
EXPORT_SYMBOL(cfs_firststr);
