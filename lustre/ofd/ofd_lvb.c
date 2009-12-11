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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/ofd_lvb.c
 *
 * Author: Mike Pershin <tappro@sun.com>
 * Author: Alex Tomas <alex.tomas@sun.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <lustre_dlm.h>

#include "ofd_internal.h"

/* Called with res->lr_lvb_sem held */
static int filter_lvbo_init(struct ldlm_resource *res)
{
        struct ost_lvb *lvb = NULL;
        struct filter_device *ofd;
        struct filter_object *fo;
        struct filter_thread_info *info;
        struct lu_env env;
        int rc = 0;
        ENTRY;

        LASSERT(res);

        /* we only want lvb's for object resources */
        /* check for internal locks: these have name[1] != 0 */
        if (res->lr_name.name[1])
                RETURN(0);

        if (res->lr_lvb_data)
                RETURN(0);

        ofd = res->lr_namespace->ns_lvbp;
        LASSERT(ofd != NULL);

        rc = lu_env_init(&env, LCT_DT_THREAD);
        if (rc)
                RETURN(rc);

        OBD_ALLOC_PTR(lvb);
        if (lvb == NULL)
                GOTO(out, rc = -ENOMEM);

        info = filter_info_init(&env, NULL);
        lu_idif_from_resid(&info->fti_fid, &res->lr_name);

        fo = filter_object_find(&env, ofd, &info->fti_fid);
        if (IS_ERR(fo)) {
                OBD_FREE_PTR(lvb);
                GOTO(out, rc = PTR_ERR(fo));
        }

        rc = filter_attr_get(&env, fo, &info->fti_attr);
        filter_object_put(&env, fo);
        if (rc == 0) {
                lvb->lvb_size = info->fti_attr.la_size;
                lvb->lvb_blocks = info->fti_attr.la_blocks;
                lvb->lvb_mtime = info->fti_attr.la_mtime;
                lvb->lvb_atime = info->fti_attr.la_atime;
                lvb->lvb_ctime = info->fti_attr.la_ctime;
        } else {
                OBD_FREE_PTR(lvb);
                GOTO(out, rc);
        }

        res->lr_lvb_data = lvb;
        res->lr_lvb_len = sizeof(*lvb);

        CDEBUG(D_DLMTRACE, "res: "LPX64" initial lvb size: "LPX64", "
               "mtime: "LPX64", blocks: "LPX64"\n",
               res->lr_name.name[0], lvb->lvb_size,
               lvb->lvb_mtime, lvb->lvb_blocks);

        EXIT;

out:
        lu_env_fini(&env);

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
static int filter_lvbo_update(struct ldlm_resource *res,
                              struct ptlrpc_request *r,
                              int increase_only)
{
        struct filter_device *ofd;
        struct filter_object *fo;
        struct filter_thread_info *info;
        struct ost_lvb *lvb;
        struct lu_env env;
        int rc = 0;
        ENTRY;

        LASSERT(res);

        /* we only want lvb's for object resources */
        /* check for internal locks: these have name[1] != 0 */
        if (res->lr_name.name[1])
                RETURN(0);

        mutex_down(&res->lr_lvb_sem);
        lvb = res->lr_lvb_data;
        if (lvb == NULL) {
                CERROR("No lvb when running lvbo_update!\n");
                GOTO(out_mutex, rc = 0);
        }

        rc = lu_env_init(&env, LCT_DT_THREAD);
        if (rc)
                GOTO(out_mutex, rc);

        info = filter_info_init(&env, NULL);
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
        ofd = res->lr_namespace->ns_lvbp;
        LASSERT(ofd != NULL);

        lu_idif_from_resid(&info->fti_fid, &res->lr_name);

        fo = filter_object_find(&env, ofd, &info->fti_fid);
        if (IS_ERR(fo))
                GOTO(out_env, rc = PTR_ERR(fo));

        rc = filter_attr_get(&env, fo, &info->fti_attr);
        if (rc)
                GOTO(out_obj, rc);

        if (info->fti_attr.la_size > lvb->lvb_size || !increase_only) {
                CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb size from disk: "
                       LPU64" -> %llu\n", res->lr_name.name[0],
                       lvb->lvb_size, info->fti_attr.la_size);
                lvb->lvb_size = info->fti_attr.la_size;
        }

        if (info->fti_attr.la_mtime >lvb->lvb_mtime || !increase_only) {
                CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb mtime from disk: "
                       LPU64" -> "LPU64"\n", res->lr_name.name[0],
                       lvb->lvb_mtime, info->fti_attr.la_mtime);
                lvb->lvb_mtime = info->fti_attr.la_mtime;
        }
        if (info->fti_attr.la_atime >lvb->lvb_atime || !increase_only) {
                CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb atime from disk: "
                       LPU64" -> "LPU64"\n", res->lr_name.name[0],
                       lvb->lvb_atime, info->fti_attr.la_atime);
                lvb->lvb_atime = info->fti_attr.la_atime;
        }
        if (info->fti_attr.la_ctime >lvb->lvb_ctime || !increase_only) {
                CDEBUG(D_DLMTRACE, "res: "LPU64" updating lvb ctime from disk: "
                       LPU64" -> "LPU64"\n", res->lr_name.name[0],
                       lvb->lvb_ctime, info->fti_attr.la_ctime);
                lvb->lvb_ctime = info->fti_attr.la_ctime;
        }
        if (lvb->lvb_blocks != info->fti_attr.la_blocks) {
                CDEBUG(D_DLMTRACE,"res: "LPU64" updating lvb blocks from disk: "
                       LPU64" -> %llu\n", res->lr_name.name[0],
                       lvb->lvb_blocks,
                       (unsigned long long)info->fti_attr.la_blocks);
                lvb->lvb_blocks = info->fti_attr.la_blocks;
        }

out_obj:
        filter_object_put(&env, fo);
out_env:
        lu_env_fini(&env);
out_mutex:
        mutex_up(&res->lr_lvb_sem);
        return rc;
}

struct ldlm_valblock_ops filter_lvbo = {
        lvbo_init: filter_lvbo_init,
        lvbo_update: filter_lvbo_update
};
