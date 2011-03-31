/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdfilter/filter_lvb.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
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

static int filter_lvbo_free(struct ldlm_resource *res) {
        if (res->lr_lvb_inode) {
                iput(res->lr_lvb_inode);
                res->lr_lvb_inode = NULL;
        }

        if (res->lr_lvb_data)
                OBD_FREE(res->lr_lvb_data, res->lr_lvb_len);

        return 0;
}

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

        obd = ldlm_res_to_ns(res)->ns_lvbp;
        LASSERT(obd != NULL);

        CDEBUG(D_INODE, "%s: filter_lvbo_init(o_seq="LPU64", o_id="
               LPU64")\n", obd->obd_name, res->lr_name.name[1],
               res->lr_name.name[0]);

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

        res->lr_lvb_inode = igrab(dentry->d_inode);

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
 *   r != NULL : called by the DLM itself after a glimpse callback
 *   r == NULL : called by the filter after a disk write
 *
 *   If 'increase_only' is true, don't allow values to move backwards.
 */
static int filter_lvbo_update(struct ldlm_resource *res,
                              struct ptlrpc_request *r, int increase_only)
{
        int rc = 0;
        struct ost_lvb *lvb;
        struct obd_device *obd;
        struct inode *inode;
        struct inode *tmpinode = NULL;
        ENTRY;

        LASSERT(res);

        lock_res(res);
        lvb = res->lr_lvb_data;
        if (lvb == NULL) {
                CERROR("No lvb when running lvbo_update!\n");
                GOTO(out, rc = 0);
        }

        /* Update the LVB from the network message */
        if (r != NULL) {
                struct ost_lvb *new;

                /* XXX update always from reply buffer */
                new = req_capsule_server_get(&r->rq_pill, &RMF_DLM_LVB);

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
        obd = ldlm_res_to_ns(res)->ns_lvbp;
        LASSERT(obd);

        inode = res->lr_lvb_inode;
        /* filter_fid2dentry could fail, esp. in OBD_FAIL_OST_ENOENT test case */
        if (unlikely(inode == NULL)) {
                struct dentry *dentry;

                unlock_res(res);

                dentry = filter_fid2dentry(obd, NULL, res->lr_name.name[1],
                                           res->lr_name.name[0]);
                if (IS_ERR(dentry))
                        RETURN(PTR_ERR(dentry));

                if (dentry->d_inode)
                        tmpinode = igrab(dentry->d_inode);
                f_dput(dentry);
                /* tmpinode could be NULL, but it does not matter if other
                 * have set res->lr_lvb_inode */
                lock_res(res);
                if (res->lr_lvb_inode == NULL) {
                        res->lr_lvb_inode = tmpinode;
                        tmpinode = NULL;
                }
                inode = res->lr_lvb_inode;
        }

        if (!inode || !inode->i_nlink)
                GOTO(out, rc = -ENOENT);

        if (i_size_read(inode) > lvb->lvb_size || !increase_only) {
                CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb size from disk: "
                       LPU64" -> %llu\n", res->lr_name.name[0],
                       lvb->lvb_size, i_size_read(inode));
                lvb->lvb_size = i_size_read(inode);
        }

        if (LTIME_S(inode->i_mtime) >lvb->lvb_mtime|| !increase_only){
                CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb mtime from disk: "
                       LPU64" -> %lu\n", res->lr_name.name[0],
                       lvb->lvb_mtime, LTIME_S(inode->i_mtime));
                lvb->lvb_mtime = LTIME_S(inode->i_mtime);
        }
        if (LTIME_S(inode->i_atime) >lvb->lvb_atime|| !increase_only){
                CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb atime from disk: "
                       LPU64" -> %lu\n", res->lr_name.name[0],
                       lvb->lvb_atime, LTIME_S(inode->i_atime));
                lvb->lvb_atime = LTIME_S(inode->i_atime);
        }
        if (LTIME_S(inode->i_ctime) >lvb->lvb_ctime|| !increase_only){
                CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb ctime from disk: "
                       LPU64" -> %lu\n", res->lr_name.name[0],
                       lvb->lvb_ctime, LTIME_S(inode->i_ctime));
                lvb->lvb_ctime = LTIME_S(inode->i_ctime);
        }
        if (lvb->lvb_blocks != inode->i_blocks) {
                CDEBUG(D_DLMTRACE,"res: "LPU64" updating lvb blocks from disk: "
                       LPU64" -> %llu\n", res->lr_name.name[0],
                       lvb->lvb_blocks, (unsigned long long)inode->i_blocks);
                lvb->lvb_blocks = inode->i_blocks;
        }

out:
        unlock_res(res);
        if (tmpinode)
                iput(tmpinode);
        return rc;
}

struct ldlm_valblock_ops filter_lvbo = {
        lvbo_init: filter_lvbo_init,
        lvbo_update: filter_lvbo_update,
        lvbo_free: filter_lvbo_free
};
