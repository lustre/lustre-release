/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * (C) Copyright 2012 Commissariat a l'energie atomique et aux energies
 *
 * Copyright (c) 2016, Intel Corporation.
 *     alternatives
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 or (at your discretion) any later version.
 * (LGPL) version 2.1 accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * LGPL HEADER END
 */
/*
 *
 * lustre/utils/lustreapi_internal.h
 *
 * Copyright (c) 2016 Intel Corporation.
 *
 * Author: Aurelien Degremont <aurelien.degremont@cea.fr>
 * Author: JC Lafoucriere <jacques-charles.lafoucriere@cea.fr>
 * Author: Thomas Leibovici <thomas.leibovici@cea.fr>
 */

#ifndef _LUSTREAPI_INTERNAL_H_
#define _LUSTREAPI_INTERNAL_H_

#include <limits.h>
#include <stdint.h>

#include <libcfs/util/ioctl.h>
#include <libcfs/util/param.h>

#include <linux/lustre_ioctl.h>
#include <uapi_kernelcomm.h>

#define WANT_PATH   0x1
#define WANT_FSNAME 0x2
#define WANT_FD     0x4
#define WANT_INDEX  0x8
#define WANT_ERROR  0x10

/* mount point listings in /proc/mounts */
#ifndef PROC_MOUNTS
#define PROC_MOUNTS "/proc/mounts"
#endif

int get_root_path(int want, char *fsname, int *outfd, char *path, int index);
int root_ioctl(const char *mdtname, int opc, void *data, int *mdtidxp,
	       int want_error);
int obd_ioctl_pack(struct obd_ioctl_data *data, char **pbuf, int max_len);
int obd_ioctl_unpack(struct obd_ioctl_data *data, char *pbuf, int max_len);
int sattr_cache_get_defaults(const char *const fsname,
			     const char *const pathname, unsigned int *scount,
			     unsigned int *ssize, unsigned int *soffset);

/**
 * Often when determining the parameter path in sysfs/procfs we
 * are often only interest set of data. This enum gives use the
 * ability to return data of parameters for:
 *
 * FILTER_BY_FS_NAME: a specific file system mount
 * FILTER_BY_PATH:    Using a Lustre file path to determine which
 *		      file system is of interest
 * FILTER_BY_EXACT:   The default behavior. Search the parameter
 *		      path as is.
 */
enum param_filter {
	FILTER_BY_NONE,
	FILTER_BY_EXACT,
	FILTER_BY_FS_NAME,
	FILTER_BY_PATH
};

int get_lustre_param_path(const char *obd_type, const char *filter,
			  enum param_filter type, const char *param_name,
			  glob_t *param);
int get_lustre_param_value(const char *obd_type, const char *filter,
			   enum param_filter type, const char *param_name,
			   char *value, size_t val_len);

static inline int
poolpath(glob_t *pool_path, const char *fsname, char *pathname)
{
	int rc;

	if (fsname != NULL)
		rc = get_lustre_param_path("lov", fsname, FILTER_BY_FS_NAME,
					   "pools", pool_path);
	else
		rc = get_lustre_param_path("lov", pathname, FILTER_BY_PATH,
					   "pools", pool_path);
	return rc;
}

#define LLAPI_LAYOUT_MAGIC 0x11AD1107 /* LLAPILOT */

/* Helper functions for testing validity of stripe attributes. */

static inline bool llapi_stripe_size_is_aligned(uint64_t size)
{
	return (size & (LOV_MIN_STRIPE_SIZE - 1)) == 0;
}

static inline bool llapi_stripe_size_is_too_big(uint64_t size)
{
	return size >= (1ULL << 32);
}

static inline bool llapi_stripe_count_is_valid(int64_t count)
{
	return count >= -1 && count <= LOV_MAX_STRIPE_COUNT;
}

static inline bool llapi_stripe_index_is_valid(int64_t index)
{
	return index >= -1 && index <= LOV_V1_INSANE_STRIPE_COUNT;
}

/* Compatibility macro for legacy llapi functions that use "offset"
 * terminology instead of the preferred "index". */
#define llapi_stripe_offset_is_valid(os) llapi_stripe_index_is_valid(os)

/*
 * Kernel communication for Changelogs and HSM requests.
 */
int libcfs_ukuc_start(struct lustre_kernelcomm *l, int groups, int rfd_flags);
int libcfs_ukuc_stop(struct lustre_kernelcomm *l);
int libcfs_ukuc_get_rfd(struct lustre_kernelcomm *link);
int libcfs_ukuc_msg_get(struct lustre_kernelcomm *l, char *buf, int maxsize,
			int transport);
#endif /* _LUSTREAPI_INTERNAL_H_ */
