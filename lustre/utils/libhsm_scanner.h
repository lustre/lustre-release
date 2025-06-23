/* SPDX-License-Identifier: GPL-2.0-only */
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
	int			 hsc_mntfd;
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
