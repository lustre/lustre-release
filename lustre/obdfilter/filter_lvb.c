/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/fs/obdfilter/filter_log.c
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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
 */

#define DEBUG_SUBSYSTEM S_FILTER

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/version.h>

#include <libcfs/list.h>
#include <obd_class.h>
#include <lustre_dlm.h>

#include "filter_internal.h"

/* Called with res->lr_lvb_sem held */
static int filter_lvbo_init(struct ldlm_resource *res)
{
        struct ost_lvb *lvb = NULL;
        struct obd_device *obd;
        struct dentry *dentry;
        int rc = 0;
        ENTRY;

        LASSERT(res);
        LASSERT_SEM_LOCKED(&res->lr_lvb_sem);

        if (res->lr_lvb_data)
                RETURN(0);

        OBD_ALLOC(lvb, sizeof(*lvb));
        if (lvb == NULL)
                RETURN(-ENOMEM);

        res->lr_lvb_data = lvb;
        res->lr_lvb_len = sizeof(*lvb);

        obd = res->lr_namespace->ns_lvbp;
        LASSERT(obd != NULL);

        dentry = filter_fid2dentry(obd, NULL, res->lr_name.name[1], 
                                              res->lr_name.name[0]);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("%s: bad object "LPU64"/"LPU64": rc %d\n", obd->obd_name,
                       res->lr_name.name[0], res->lr_name.name[1], rc);
                RETURN(rc);
        }

        if (dentry->d_inode == NULL)
                /* This is always true for test_brw */
                GOTO(out_dentry, rc = -ENOENT);

        inode_init_lvb(dentry->d_inode, lvb);

        CDEBUG(D_DLMTRACE, "res: "LPX64" initial lvb size: "LPX64", "
               "mtime: "LPX64", blocks: "LPX64"\n",
               res->lr_name.name[0], lvb->lvb_size,
               lvb->lvb_mtime, lvb->lvb_blocks);

        EXIT;
out_dentry:
        f_dput(dentry);

        if (rc)
                OST_LVB_SET_ERR(lvb->lvb_blocks, rc);
        /* Don't free lvb data on lookup error */
        return rc;
}

/* This will be called in two ways:
 *
 *   m != NULL : called by the DLM itself after a glimpse callback
 *   m == NULL : called by the filter after a disk write
 *
 *   If 'increase_only' is true, don't allow values to move backwards.
 */
static int filter_lvbo_update(struct ldlm_resource *res, struct lustre_msg *m,
                              int buf_idx, int increase_only)
{
        int rc = 0;
        struct ost_lvb *lvb;
        struct obd_device *obd;
        struct dentry *dentry;
        ENTRY;

        LASSERT(res);

        down(&res->lr_lvb_sem);
        lvb = res->lr_lvb_data;
        if (lvb == NULL) {
                CERROR("No lvb when running lvbo_update!\n");
                GOTO(out, rc = 0);
        }

        /* Update the LVB from the network message */
        if (m != NULL) {
                struct ost_lvb *new;

                new = lustre_swab_buf(m, buf_idx, sizeof(*new),
                                      lustre_swab_ost_lvb);
                if (new == NULL) {
                        CERROR("lustre_swab_buf failed\n");
                        goto disk_update;
                }
                if (new->lvb_size > lvb->lvb_size || !increase_only) {
                        CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb size: "
                               LPU64" -> "LPU64"\n", res->lr_name.name[0],
                               lvb->lvb_size, new->lvb_size);
                        lvb->lvb_size = new->lvb_size;
                }
                if (new->lvb_mtime > lvb->lvb_mtime || !increase_only) {
                        CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb mtime: "
                               LPU64" -> "LPU64"\n", res->lr_name.name[0],
                               lvb->lvb_mtime, new->lvb_mtime);
                        lvb->lvb_mtime = new->lvb_mtime;
                }
                if (new->lvb_atime > lvb->lvb_atime || !increase_only) {
                        CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb atime: "
                               LPU64" -> "LPU64"\n", res->lr_name.name[0],
                               lvb->lvb_atime, new->lvb_atime);
                        lvb->lvb_atime = new->lvb_atime;
                }
                if (new->lvb_ctime > lvb->lvb_ctime || !increase_only) {
                        CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb ctime: "
                               LPU64" -> "LPU64"\n", res->lr_name.name[0],
                               lvb->lvb_ctime, new->lvb_ctime);
                        lvb->lvb_ctime = new->lvb_ctime;
                }
        }

 disk_update:
        /* Update the LVB from the disk inode */
        obd = res->lr_namespace->ns_lvbp;
        LASSERT(obd);
        
        dentry = filter_fid2dentry(obd, NULL, res->lr_name.name[1], 
                                              res->lr_name.name[0]);
        if (IS_ERR(dentry))
                GOTO(out, rc = PTR_ERR(dentry));

        if (dentry->d_inode == NULL)
                GOTO(out_dentry, rc = -ENOENT);

        if (i_size_read(dentry->d_inode) > lvb->lvb_size || !increase_only) {
                CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb size from disk: "
                       LPU64" -> %llu\n", res->lr_name.name[0],
                       lvb->lvb_size, i_size_read(dentry->d_inode));
                lvb->lvb_size = i_size_read(dentry->d_inode);
        }

        if (LTIME_S(dentry->d_inode->i_mtime) >lvb->lvb_mtime|| !increase_only){
                CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb mtime from disk: "
                       LPU64" -> %lu\n", res->lr_name.name[0],
                       lvb->lvb_mtime, LTIME_S(dentry->d_inode->i_mtime));
                lvb->lvb_mtime = LTIME_S(dentry->d_inode->i_mtime);
        }
        if (LTIME_S(dentry->d_inode->i_atime) >lvb->lvb_atime|| !increase_only){
                CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb atime from disk: "
                       LPU64" -> %lu\n", res->lr_name.name[0],
                       lvb->lvb_atime, LTIME_S(dentry->d_inode->i_atime));
                lvb->lvb_atime = LTIME_S(dentry->d_inode->i_atime);
        }
        if (LTIME_S(dentry->d_inode->i_ctime) >lvb->lvb_ctime|| !increase_only){
                CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb ctime from disk: "
                       LPU64" -> %lu\n", res->lr_name.name[0],
                       lvb->lvb_ctime, LTIME_S(dentry->d_inode->i_ctime));
                lvb->lvb_ctime = LTIME_S(dentry->d_inode->i_ctime);
        }
        if (lvb->lvb_blocks != dentry->d_inode->i_blocks) {
                CDEBUG(D_DLMTRACE,"res: "LPU64" updating lvb blocks from disk: "
                       LPU64" -> %llu\n", res->lr_name.name[0],
                       lvb->lvb_blocks, (unsigned long long)dentry->d_inode->i_blocks);
                lvb->lvb_blocks = dentry->d_inode->i_blocks;
        }

out_dentry:
        f_dput(dentry);

out:
        up(&res->lr_lvb_sem);
        return rc;
}

struct ldlm_valblock_ops filter_lvbo = {
        lvbo_init: filter_lvbo_init,
        lvbo_update: filter_lvbo_update
};
