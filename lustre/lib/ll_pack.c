/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc. <adilger@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * (Un)packing of OST/MDS requests
 *
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/lustre_net.h>
#include <linux/obd_support.h>

void obd_statfs_pack(struct obd_statfs *osfs, struct statfs *sfs)
{
        if (osfs == NULL || sfs == NULL)
                LBUG();

        osfs->os_type = HTON__u64(sfs->f_type);
        osfs->os_blocks = HTON__u64(sfs->f_blocks);
        osfs->os_bfree = HTON__u64(sfs->f_bfree);
        osfs->os_bavail = HTON__u64(sfs->f_bavail);
        osfs->os_files = HTON__u64(sfs->f_files);
        osfs->os_ffree = HTON__u64(sfs->f_ffree);
        osfs->os_bsize = HTON__u32(sfs->f_bsize);
        osfs->os_namelen = HTON__u32(sfs->f_namelen);
}

void obd_statfs_unpack(struct obd_statfs *osfs, struct statfs *sfs)
{
        if (osfs == NULL || sfs == NULL)
                LBUG();

        sfs->f_type = NTOH__u64(osfs->os_type);
        sfs->f_blocks = NTOH__u64(osfs->os_blocks);
        sfs->f_bfree = NTOH__u64(osfs->os_bfree);
        sfs->f_bavail = NTOH__u64(osfs->os_bavail);
        sfs->f_files = NTOH__u64(osfs->os_files);
        sfs->f_ffree = NTOH__u64(osfs->os_ffree);
        sfs->f_bsize = NTOH__u32(osfs->os_bsize);
        sfs->f_namelen = NTOH__u32(osfs->os_namelen);
}

