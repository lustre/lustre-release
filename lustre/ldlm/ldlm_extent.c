/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * by Cluster File Systems, Inc.
 * authors, Peter Braam <braam@clusterfs.com> & 
 * Phil Schwan <phil@clusterfs.com>
 */

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/unistd.h>

#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_dlm.h>

/* This function will be called to judge if the granted queue of another child
 * (read: another extent) is conflicting and needs its granted queue walked to
 * issue callbacks.
 *
 * This helps to find conflicts between read and write locks on overlapping
 * extents. */
int ldlm_extent_compat(struct ldlm_resource *child, struct ldlm_resource *new)
{
        struct ldlm_extent *child_ex, *new_ex;

        child_ex = ldlm_res2extent(child);
        new_ex = ldlm_res2extent(new);

        if (MAX(child_ex->start, new_ex->start) <=
            MIN(child_ex->end, new_ex->end))
                return 0;

        return 1;
}

/* The purpose of this function is to return:
 * - the maximum extent
 * - containing the requested extent
 * - and not overlapping existing extents outside the requested one
 *
 * An alternative policy is to not shrink the new extent when conflicts exist.
 *
 * To reconstruct our formulas, take a deep breath. */
int ldlm_extent_policy(struct ldlm_resource *parent,
                       __u64 *res_id_in, __u64 *res_id_out,
                       ldlm_mode_t mode, void *data)
{
        struct ldlm_extent *new_ex, *req_ex;
        struct list_head *tmp;
        int rc = 0;

        req_ex = (struct ldlm_extent *)res_id_in;

        new_ex = (struct ldlm_extent *)res_id_out;
        new_ex->start = 0;
        new_ex->end = ~0;

        list_for_each(tmp, &parent->lr_children) {
                struct ldlm_resource *res;
                struct ldlm_extent *exist_ex;
                res = list_entry(tmp, struct ldlm_resource, lr_childof);

                exist_ex = ldlm_res2extent(res);

                if (exist_ex->end < req_ex->start)
                        new_ex->start = MIN(exist_ex->end, new_ex->start);
                else {
                        if (exist_ex->start < req_ex->start &&
                            !lockmode_compat(res->lr_most_restr, mode))
                                /* Policy: minimize conflict overlap */
                                new_ex->start = req_ex->start;
                }
                if (exist_ex->start > req_ex->end)
                        new_ex->end = MAX(exist_ex->start, new_ex->end);
                else {
                        if (exist_ex->end > req_ex->end &&
                            !lockmode_compat(res->lr_most_restr, mode))
                                /* Policy: minimize conflict overlap */
                                new_ex->end = req_ex->end;
                }
        }

        if (new_ex->end != req_ex->end || new_ex->start != req_ex->start)
                rc = ELDLM_RES_CHANGED;

        return rc;
}

