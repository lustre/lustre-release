/*
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
 * version 2 along with this program; If not, see http://www.gnu.org/licenses
 *
 * Please contact Oracle Corporation, Inc., 500 Oracle Parkway, Redwood Shores,
 * CA 94065 USA or visit www.oracle.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Oracle Corporation, Inc.
 */

#ifndef __KERNEL__
#include <liblustre.h>
#else
#include <libcfs/libcfs.h>
#endif

unsigned long cfs_fail_loc = 0;
unsigned int cfs_fail_val = 0;
cfs_waitq_t cfs_race_waitq;
int cfs_race_state;

CFS_EXPORT_SYMBOL(cfs_fail_loc);
CFS_EXPORT_SYMBOL(cfs_fail_val);
CFS_EXPORT_SYMBOL(cfs_race_waitq);
CFS_EXPORT_SYMBOL(cfs_race_state);

int __cfs_fail_check_set(__u32 id, __u32 value, int set)
{
        static cfs_atomic_t cfs_fail_count = CFS_ATOMIC_INIT(0);

        LASSERT(!(id & CFS_FAIL_ONCE));

        if ((cfs_fail_loc & (CFS_FAILED | CFS_FAIL_ONCE)) ==
            (CFS_FAILED | CFS_FAIL_ONCE)) {
                cfs_atomic_set(&cfs_fail_count, 0); /* paranoia */
                return 0;
        }

        /* Fail 1/cfs_fail_val times */
        if (cfs_fail_loc & CFS_FAIL_RAND) {
                if (cfs_fail_val < 2 || cfs_rand() % cfs_fail_val > 0)
                        return 0;
        }

        /* Skip the first cfs_fail_val, then fail */
        if (cfs_fail_loc & CFS_FAIL_SKIP) {
                if (cfs_atomic_inc_return(&cfs_fail_count) <= cfs_fail_val)
                        return 0;
        }

        /* check cfs_fail_val... */
        if (set == CFS_FAIL_LOC_VALUE) {
                if (cfs_fail_val != -1 && cfs_fail_val != value)
                        return 0;
        }

        /* Fail cfs_fail_val times, overridden by FAIL_ONCE */
        if (cfs_fail_loc & CFS_FAIL_SOME &&
            (!(cfs_fail_loc & CFS_FAIL_ONCE) || cfs_fail_val <= 1)) {
                int count = cfs_atomic_inc_return(&cfs_fail_count);

                if (count >= cfs_fail_val) {
			set_bit(CFS_FAIL_ONCE_BIT, &cfs_fail_loc);
                        cfs_atomic_set(&cfs_fail_count, 0);
                        /* we are lost race to increase  */
                        if (count > cfs_fail_val)
                                return 0;
                }
        }

        if ((set == CFS_FAIL_LOC_ORSET || set == CFS_FAIL_LOC_RESET) &&
            (value & CFS_FAIL_ONCE))
		set_bit(CFS_FAIL_ONCE_BIT, &cfs_fail_loc);
        /* Lost race to set CFS_FAILED_BIT. */
	if (test_and_set_bit(CFS_FAILED_BIT, &cfs_fail_loc)) {
                /* If CFS_FAIL_ONCE is valid, only one process can fail,
                 * otherwise multi-process can fail at the same time. */
                if (cfs_fail_loc & CFS_FAIL_ONCE)
                        return 0;
        }

        switch (set) {
                case CFS_FAIL_LOC_NOSET:
                case CFS_FAIL_LOC_VALUE:
                        break;
                case CFS_FAIL_LOC_ORSET:
                        cfs_fail_loc |= value & ~(CFS_FAILED | CFS_FAIL_ONCE);
                        break;
                case CFS_FAIL_LOC_RESET:
                        cfs_fail_loc = value;
                        break;
                default:
                        LASSERTF(0, "called with bad set %u\n", set);
                        break;
        }

        return 1;
}
CFS_EXPORT_SYMBOL(__cfs_fail_check_set);

int __cfs_fail_timeout_set(__u32 id, __u32 value, int ms, int set)
{
        int ret = 0;

        ret = __cfs_fail_check_set(id, value, set);
        if (ret) {
                CERROR("cfs_fail_timeout id %x sleeping for %dms\n",
                       id, ms);
                cfs_schedule_timeout_and_set_state(CFS_TASK_UNINT,
                                                   cfs_time_seconds(ms) / 1000);
                cfs_set_current_state(CFS_TASK_RUNNING);
                CERROR("cfs_fail_timeout id %x awake\n", id);
        }
        return ret;
}
CFS_EXPORT_SYMBOL(__cfs_fail_timeout_set);
