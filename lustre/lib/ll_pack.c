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

#if BITS_PER_LONG > 32
#define statfs_max(val) val
#else
static inline long statfs_max(__u64 val)
{
        return ((long)val < val) ? (long)-1 : val;
}
#endif

/*
 * Note: since linux statfs is limited to a "long" for the statfs
 * fields, we quickly overflow that.  If we wanted, we could start
 * playing games with the blocksize until the blocks count fit into
 * a long.  Note that it also appears that userspace interprets these
 * fields as an unsigned long, which is helps us a bit, and it also
 * appears to do 64-bit math for at least some of the computations.
 */
void obd_statfs_unpack(struct obd_statfs *osfs, struct statfs *sfs)
{
        if (osfs == NULL || sfs == NULL)
                LBUG();

        sfs->f_type = NTOH__u64(osfs->os_type);
        sfs->f_blocks = statfs_max(NTOH__u64(osfs->os_blocks));
        sfs->f_bfree = statfs_max(NTOH__u64(osfs->os_bfree));
        sfs->f_bavail = statfs_max(NTOH__u64(osfs->os_bavail));
        sfs->f_files = statfs_max(NTOH__u64(osfs->os_files));
        sfs->f_ffree = statfs_max(NTOH__u64(osfs->os_ffree));
        sfs->f_bsize = NTOH__u32(osfs->os_bsize);
        sfs->f_namelen = NTOH__u32(osfs->os_namelen);
}

