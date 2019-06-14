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
 * version 2 along with this program; if not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2019, DDN Storage Corporation.
 */
/*
 * lustre/utils/libhsm_scanner.h
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */
#ifndef _LIBHSM_SCANNER_H
#define _LIBHSM_SCANNER_H

#include <lustre/lustreapi.h>

struct hsm_scan_control;

typedef int (*hsm_scan_func_t)(const char *pname, const char *fname,
			       struct hsm_scan_control *hsc);

struct hsm_scan_control {
	enum hsmtool_type	 hsc_type;
	const char		*hsc_mntpath;
	const char		*hsc_hsmpath;
	hsm_scan_func_t		 hsc_func;
	int			 hsc_errnum;
};

int hsm_scan_process(struct hsm_scan_control *hsc);

static inline bool endswith(const char *str, const char *s)
{
	size_t len1 = strlen(str);
	size_t len2 = strlen(s);

	if (len1 < len2)
		return false;

	return !strcmp(str + len1 - len2, s);
}

#endif /* LIBHSM_SCANNER_H */
