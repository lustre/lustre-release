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
int ldlm_extent_compat(struct ldlm_lock *a, struct ldlm_lock *b)
{
        if (MAX(a->l_extent.start, b->l_extent.start) <=
            MIN(a->l_extent.end, b->l_extent.end))
                return 0;

        return 1;
}

static void policy_internal(struct list_head *queue, struct ldlm_extent *req_ex,
                            struct ldlm_extent *new_ex, ldlm_mode_t mode)
{
        struct list_head *tmp;

        list_for_each(tmp, queue) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (lock->l_extent.end < req_ex->start)
                        new_ex->start = MIN(lock->l_extent.end, new_ex->start);
                else {
                        if (lock->l_extent.start < req_ex->start &&
                            !lockmode_compat(lock->l_req_mode, mode))
                                /* Policy: minimize conflict overlap */
                                new_ex->start = req_ex->start;
                }
                if (lock->l_extent.start > req_ex->end)
                        new_ex->end = MAX(lock->l_extent.start, new_ex->end);
                else {
                        if (lock->l_extent.end > req_ex->end &&
                            !lockmode_compat(lock->l_req_mode, mode))
                                /* Policy: minimize conflict overlap */
                                new_ex->end = req_ex->end;
                }
        }
}

/* The purpose of this function is to return:
 * - the maximum extent
 * - containing the requested extent
 * - and not overlapping existing extents outside the requested one
 *
 * An alternative policy is to not shrink the new extent when conflicts exist.
 *
 * To reconstruct our formulas, take a deep breath. */
int ldlm_extent_policy(struct ldlm_resource *res, struct ldlm_extent *req_ex,
                       struct ldlm_extent *new_ex, ldlm_mode_t mode, void *data)
{
        new_ex->start = 0;
        new_ex->end = ~0;

        if (!res)
                LBUG();

        policy_internal(&res->lr_granted, req_ex, new_ex, mode);
        policy_internal(&res->lr_converting, req_ex, new_ex, mode);
        policy_internal(&res->lr_waiting, req_ex, new_ex, mode);

        if (new_ex->end != req_ex->end || new_ex->start != req_ex->start)
                return ELDLM_LOCK_CHANGED;
        return 0;
}
