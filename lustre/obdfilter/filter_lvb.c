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
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>

#include <portals/list.h>
#include <linux/obd_class.h>
#include <linux/lustre_dlm.h>

#include "filter_internal.h"

static int filter_lvbo_init(struct ldlm_resource *res)
{
        int rc = 0;
        struct ost_lvb *lvb = NULL;
        struct obd_device *obd;
        struct obdo *oa = NULL;
        struct dentry *dentry;
        ENTRY;

        LASSERT(res);

        /* we only want lvb's for object resources */
        /* check for internal locks: these have name[1] != 0 */
        if (res->lr_name.name[1])
                RETURN(0);

        down(&res->lr_lvb_sem);
        if (res->lr_lvb_data)
                GOTO(out, rc = 0);

        OBD_ALLOC(lvb, sizeof(*lvb));
        if (!lvb)
                GOTO(out, rc = -ENOMEM);

        res->lr_lvb_data = lvb;
        res->lr_lvb_len = sizeof(*lvb);

        obd = res->lr_namespace->ns_lvbp;
        LASSERT(obd);

        oa = obdo_alloc();
        if (!oa)
                GOTO(out, rc = -ENOMEM);

        oa->o_id = res->lr_name.name[0];
        oa->o_gr = 0;
        dentry = filter_oa2dentry(obd, oa);
        if (IS_ERR(dentry))
                GOTO(out, rc = PTR_ERR(dentry));

        /* Limit the valid bits in the return data to what we actually use */
        oa->o_valid = OBD_MD_FLID;
        obdo_from_inode(oa, dentry->d_inode, FILTER_VALID_FLAGS);
        f_dput(dentry);

        lvb->lvb_size = dentry->d_inode->i_size;
        lvb->lvb_time = LTIME_S(dentry->d_inode->i_mtime);

 out:
        if (oa)
                obdo_free(oa);
        if (rc && lvb) {
                OBD_FREE(lvb, sizeof(*lvb));
                res->lr_lvb_data = NULL;
                res->lr_lvb_len = 0;
        }
        up(&res->lr_lvb_sem);
        return rc;
}

/* This will be called in two ways:
 *
 *   m != NULL : called by the DLM itself after a glimpse callback
 *   m == NULL : called by the filter after a disk write
 */
static int filter_lvbo_update(struct ldlm_resource *res, struct lustre_msg *m,
                              int buf_idx)
{
        int rc = 0;
        struct ost_lvb *lvb = res->lr_lvb_data;
        struct obd_device *obd;
        struct obdo *oa = NULL;
        struct dentry *dentry;
        ENTRY;

        LASSERT(res);

        /* we only want lvb's for object resources */
        /* check for internal locks: these have name[1] != 0 */
        if (res->lr_name.name[1])
                RETURN(0);

        down(&res->lr_lvb_sem);
        if (!res->lr_lvb_data) {
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
                        //GOTO(out, rc = -EPROTO);
                        GOTO(out, rc = 0);
                }
                if (new->lvb_size > lvb->lvb_size) {
                        CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb size: "
                               LPU64" -> "LPU64, res->lr_name.name[0],
                               lvb->lvb_size, new->lvb_size);
                        lvb->lvb_size = new->lvb_size;
                }
                if (new->lvb_time > lvb->lvb_time) {
                        CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb time: "
                               LPU64" -> "LPU64, res->lr_name.name[0],
                               lvb->lvb_time, new->lvb_time);
                        lvb->lvb_time = new->lvb_time;
                }
                GOTO(out, rc = 0);
        }

        /* Update the LVB from the disk inode */
        obd = res->lr_namespace->ns_lvbp;
        LASSERT(obd);

        oa = obdo_alloc();
        if (oa == NULL)
                GOTO(out, rc = -ENOMEM);

        oa->o_id = res->lr_name.name[0];
        oa->o_gr = 0;
        dentry = filter_oa2dentry(obd, oa);
        if (IS_ERR(dentry))
                GOTO(out, rc = PTR_ERR(dentry));

        /* Limit the valid bits in the return data to what we actually use */
        oa->o_valid = OBD_MD_FLID;
        obdo_from_inode(oa, dentry->d_inode, FILTER_VALID_FLAGS);

        CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb size: "LPU64" -> "LPU64,
               res->lr_name.name[0], lvb->lvb_size, dentry->d_inode->i_size);
        lvb->lvb_size = dentry->d_inode->i_size;
        CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb time: "LPU64" -> "LPU64,
               res->lr_name.name[0], lvb->lvb_time,
               (__u64)LTIME_S(dentry->d_inode->i_mtime));
        lvb->lvb_time = LTIME_S(dentry->d_inode->i_mtime);
        f_dput(dentry);

 out:
        if (oa != NULL)
                obdo_free(oa);
        up(&res->lr_lvb_sem);
        return rc;
}



struct ldlm_valblock_ops filter_lvbo = {
        lvbo_init: filter_lvbo_init,
        lvbo_update: filter_lvbo_update
};
