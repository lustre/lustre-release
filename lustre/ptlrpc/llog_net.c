/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
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
 * OST<->MDS recovery logging infrastructure.
 *
 * Invariants in implementation:
 * - we do not share logs among different OST<->MDS connections, so that
 *   if an OST or MDS fails it need only look at log(s) relevant to itself
 */

#define DEBUG_SUBSYSTEM S_LOG

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#include <linux/fs.h>
#include <linux/obd_class.h>
#include <linux/lustre_log.h>
#include <portals/list.h>
#include <linux/lvfs.h>


/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
static int llog_net_create(struct obd_device *obd, struct llog_handle **res,
                            struct llog_logid *logid, char *name)
{
        struct llog_handle *handle;
        ENTRY;

        handle = llog_alloc_handle();
        if (handle == NULL)
                RETURN(-ENOMEM);
        *res = handle;

        if (!logid) {
                CERROR("llog_net_create: must pass logid\n");
                llog_free_handle(handle);
                RETURN(-EINVAL);
        }

        handle->lgh_file = NULL;
        handle->lgh_obd = obd;
        handle->lgh_id.lgl_ogr = 1;
        handle->lgh_id.lgl_oid =
                handle->lgh_file->f_dentry->d_inode->i_ino;
        handle->lgh_id.lgl_ogen =
                handle->lgh_file->f_dentry->d_inode->i_generation;

        RETURN(0);
}

struct llog_operations llog_net_ops = {
        //lop_next_block:  llog_lvfs_next_block,
        //lop_read_header: llog_lvfs_read_header,
        lop_create:      llog_net_create,
};

EXPORT_SYMBOL(llog_lvfs_ops);
