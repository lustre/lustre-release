// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * (Un)packing of OST/MDS requests
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/statfs.h>
#include <lustre_export.h>
#include <lustre_net.h>
#include <obd_support.h>
#include <obd_class.h>

void statfs_pack(struct obd_statfs *osfs, struct kstatfs *sfs)
{
	memset(osfs, 0, sizeof(*osfs));
	osfs->os_type = sfs->f_type;
	osfs->os_blocks = sfs->f_blocks;
	osfs->os_bfree = sfs->f_bfree;
	osfs->os_bavail = sfs->f_bavail;
	osfs->os_files = sfs->f_files;
	osfs->os_ffree = sfs->f_ffree;
	osfs->os_bsize = sfs->f_bsize;
	osfs->os_namelen = sfs->f_namelen;
}
EXPORT_SYMBOL(statfs_pack);

void statfs_unpack(struct kstatfs *sfs, struct obd_statfs *osfs)
{
	memset(sfs, 0, sizeof(*sfs));
	sfs->f_type = osfs->os_type;
	sfs->f_blocks = osfs->os_blocks;
	sfs->f_bfree = osfs->os_bfree;
	sfs->f_bavail = osfs->os_bavail;
	sfs->f_files = osfs->os_files;
	sfs->f_ffree = osfs->os_ffree;
	sfs->f_bsize = osfs->os_bsize;
	sfs->f_namelen = osfs->os_namelen;
}
EXPORT_SYMBOL(statfs_unpack);
