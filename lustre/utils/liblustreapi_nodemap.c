// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2013, Trustees of Indiana University
 *
 * Copyright (c) 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustreapi library for nodemap calls
 *
 * Author: Joshua Walgenbach <jjw@iu.edu>
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libcfs/util/param.h>
#include <lustre/lustreapi.h>

int llapi_nodemap_exists(const char *nodemap)
{
	glob_t param;
	int rc;

	rc = cfs_get_param_paths(&param, "nodemap/%s", nodemap);
	cfs_free_param_data(&param);
	return rc != 0 ? 1 : 0;
}
