/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <asm/statfs.h>
#endif
#include <linux/lustre_lite.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lprocfs_status.h>

#ifndef LPROCFS
struct lprocfs_vars lprocfs_mds_obd_vars[]  = { {0} };
struct lprocfs_vars lprocfs_mds_module_vars[] = { {0} };
struct lprocfs_vars lprocfs_mdt_obd_vars[] = { {0} };
struct lprocfs_vars lprocfs_mdt_module_vars[] = { {0} };

#else

static inline
int lprocfs_mds_statfs(void *data, struct statfs *sfs)
{
        struct obd_device* dev = (struct obd_device*) data;
        struct mds_obd *mds;

        LASSERT(dev != NULL);
        mds = &dev->u.mds;
        return vfs_statfs(mds->mds_sb, sfs);
}

DEFINE_LPROCFS_STATFS_FCT(rd_blksize,     lprocfs_mds_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_kbytestotal, lprocfs_mds_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_kbytesfree,  lprocfs_mds_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_filestotal,  lprocfs_mds_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_filesfree,   lprocfs_mds_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_filegroups,  lprocfs_mds_statfs);

int rd_fstype(char *page, char **start, off_t off, int count, int *eof,
              void *data)
{
        struct obd_device *obd = (struct obd_device *)data;

        LASSERT(obd != NULL);
        LASSERT(obd->obd_fsops != NULL);
        LASSERT(obd->obd_fsops->fs_type != NULL);
        return snprintf(page, count, "%s\n", obd->obd_fsops->fs_type);
}

int lprocfs_mds_rd_mntdev(char *page, char **start, off_t off, int count,
                    int *eof, void *data)
{
        struct obd_device* obd = (struct obd_device *)data;

        LASSERT(obd != NULL);
        LASSERT(obd->u.mds.mds_vfsmnt->mnt_devname);
        *eof = 1;
        return snprintf(page, count, "%s\n", 
                        obd->u.mds.mds_vfsmnt->mnt_devname);
}

struct lprocfs_vars lprocfs_mds_obd_vars[] = {
        { "uuid",       lprocfs_rd_uuid, 0, 0 },
        { "blocksize",  rd_blksize,      0, 0 },
        { "bytestotal", rd_kbytestotal,  0, 0 },
        { "kbytesfree", rd_kbytesfree,   0, 0 },
        { "fstype",     rd_fstype,       0, 0 },
        { "filestotal", rd_filestotal,   0, 0 },
        { "filesfree",  rd_filesfree,    0, 0 },
        { "filegroups", rd_filegroups,   0, 0 },
        { "mntdev",      lprocfs_mds_rd_mntdev,    0, 0 },
        { 0 }
};

struct lprocfs_vars lprocfs_mds_module_vars[] = {
        { "num_refs",   lprocfs_rd_numrefs, 0, 0 },
        { 0 }
};

struct lprocfs_vars lprocfs_mdt_obd_vars[] = {
        { "uuid",       lprocfs_rd_uuid, 0, 0 },
        { 0 }
};

struct lprocfs_vars lprocfs_mdt_module_vars[] = {
        { "num_refs",   lprocfs_rd_numrefs, 0, 0 },
        { 0 }
};

#endif
struct lprocfs_static_vars lprocfs_array_vars[] = { {lprocfs_mds_module_vars,
                                                     lprocfs_mds_obd_vars},
                                                    {lprocfs_mdt_module_vars,
                                                     lprocfs_mdt_obd_vars}};

LPROCFS_INIT_MULTI_VARS(lprocfs_array_vars,
                        (sizeof(lprocfs_array_vars)/
                         sizeof(struct lprocfs_static_vars))) 
