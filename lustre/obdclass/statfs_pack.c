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
#include <linux/lustre_net.h>
#include <linux/obd_support.h>
#include <linux/obd_class.h>

void obd_statfs_pack(struct obd_statfs *tgt, struct obd_statfs *src)
{
        tgt->os_type = HTON__u64(src->os_type);
        tgt->os_blocks = HTON__u64(src->os_blocks);
        tgt->os_bfree = HTON__u64(src->os_bfree);
        tgt->os_bavail = HTON__u64(src->os_bavail);
        tgt->os_files = HTON__u64(src->os_files);
        tgt->os_ffree = HTON__u64(src->os_ffree);
        tgt->os_bsize = HTON__u32(src->os_bsize);
        tgt->os_namelen = HTON__u32(src->os_namelen);
}

void obd_statfs_unpack(struct obd_statfs *tgt, struct obd_statfs *src)
{
        obd_statfs_pack(tgt, src);
}

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
        } else
                export = list_entry(obd->obd_exports.next, typeof(*export),
                                    exp_obd_chain);
        conn.addr = (unsigned long)export;
        conn.cookie = export->exp_cookie;

        rc = obd_statfs(&conn, &osfs);
        if (!rc)
                statfs_unpack(sfs, &osfs);

        if (my_export)
                class_destroy_export(my_export);
        RETURN(rc);
}

EXPORT_SYMBOL(obd_statfs_pack);
EXPORT_SYMBOL(obd_statfs_unpack);
EXPORT_SYMBOL(statfs_pack);
EXPORT_SYMBOL(statfs_unpack);
EXPORT_SYMBOL(obd_self_statfs);
