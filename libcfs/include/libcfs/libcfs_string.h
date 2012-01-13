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
 * libcfs/include/libcfs/libcfs_string.h
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
                 int *oldmask, int minmask, int allmask);

/* Allocate space for and copy an existing string.
 * Must free with cfs_free().
 */
char *cfs_strdup(const char *str, u_int32_t flags);

/* safe vsnprintf */
int cfs_vsnprintf(char *buf, size_t size, const char *fmt, va_list args);

/* safe snprintf */
int cfs_snprintf(char *buf, size_t size, const char *fmt, ...);

/* trim leading and trailing space characters */
char *cfs_firststr(char *str, size_t size);
#endif
