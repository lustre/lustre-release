/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 *
 * (Un)packing of OST/MDS requests
 *
 */

#define DEBUG_SUBSYSTEM S_CLASS

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#ifndef __KERNEL__
#include <liblustre.h>
#endif

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

EXPORT_SYMBOL(statfs_pack);
EXPORT_SYMBOL(statfs_unpack);
