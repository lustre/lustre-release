/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Andreas Dilger <adilger@clusterfs.com>
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

#define DEBUG_SUBSYSTEM S_CLASS

#define EXPORT_SYMTAB
#ifndef __KERNEL__
#include <liblustre.h>
#else
#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <asm/statfs.h>
#endif
#endif

#include <linux/lustre_export.h>
#include <linux/lustre_net.h>
#include <linux/obd_support.h>
#include <linux/obd_class.h>

void statfs_pack(struct obd_statfs *osfs, struct statfs *sfs)
{
        osfs->os_type = sfs->f_type;
        osfs->os_blocks = sfs->f_blocks;
        osfs->os_bfree = sfs->f_bfree;
        osfs->os_bavail = sfs->f_bavail;
        osfs->os_files = sfs->f_files;
        osfs->os_ffree = sfs->f_ffree;
        osfs->os_bsize = sfs->f_bsize;
        osfs->os_namelen = sfs->f_namelen;
}

void statfs_unpack(struct statfs *sfs, struct obd_statfs *osfs)
{
        sfs->f_type = osfs->os_type;
        sfs->f_blocks = osfs->os_blocks;
        sfs->f_bfree = osfs->os_bfree;
        sfs->f_bavail = osfs->os_bavail;
        sfs->f_files = osfs->os_files;
        sfs->f_ffree = osfs->os_ffree;
        sfs->f_bsize = osfs->os_bsize;
        sfs->f_namelen = osfs->os_namelen;
}

int obd_self_statfs(struct obd_device *obd, struct statfs *sfs)
{
        struct lustre_handle conn;
        struct obd_export *export, *my_export = NULL;
        struct obd_statfs osfs = { 0 };
        int rc;
        ENTRY;

        if (list_empty(&obd->obd_exports)) {
                export = my_export = class_new_export(obd);
                if (export == NULL)
                        RETURN(-ENOMEM);
        } else {
                export = list_entry(obd->obd_exports.next, typeof(*export),
                                    exp_obd_chain);
        }
        memset(&conn.addr, 0x69, sizeof conn.addr);
        conn.cookie = export->exp_handle.h_cookie;

        rc = obd_statfs(&conn, &osfs);
        if (!rc)
                statfs_unpack(sfs, &osfs);

        if (my_export)
                class_destroy_export(my_export);
        RETURN(rc);
}

EXPORT_SYMBOL(statfs_pack);
EXPORT_SYMBOL(statfs_unpack);
EXPORT_SYMBOL(obd_self_statfs);
