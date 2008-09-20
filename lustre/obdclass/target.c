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
 * lustre/obdclass/class_target.c
 *
 * Common methods for target devices
 *
 * Author: Mikhail Pershin
 */
#define DEBUG_SUBSYSTEM S_CLASS
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#include <obd_class.h>
#include <lustre_fsfilt.h>
#include <libcfs/list.h>
#include <lustre_disk.h>
#include <lustre_lib.h>
#include <linux/slab.h>
#include <lustre_param.h>
#include <obd.h>

/**
 * Calculate time by index. All expiration time is divided by LR_EXPIRE_INTERVALS,
 * so time of each index is calculated from time of first index
 */
static inline
__u32 target_trans_table_slot2time(struct obd_device_target *obt, int idx)
{
        __u32 time = le32_to_cpu(obt->obt_lsd->lsd_trans_table_time);
        __u32 age;

        age = obt->obt_stale_export_age /
              le32_to_cpu(obt->obt_lsd->lsd_expire_intervals) * idx;
        return cfs_time_sub(time, age);
}

/**
 * Check trans table in server_data to get last time this export was seen
 */
__u32 target_trans_table_last_time(struct obd_export *exp)
{
        struct obd_device_target *obt = &exp->exp_obd->u.obt;
        const __u32 slots = le32_to_cpu(obt->obt_lsd->lsd_expire_intervals);
        __u32 time = cfs_time_current_sec();
        int i, idx = slots;

        /** return current time */
        if (obt->obt_stale_export_age == 0)
                return time;

        spin_lock(&obt->obt_trans_table_lock);
        for (i = 0; i < slots; i++)
                if (exp->exp_last_committed <=
                    le64_to_cpu(obt->obt_lsd->lsd_trans_table[i]))
                        idx = i;
        if (idx < slots)
                time = target_trans_table_slot2time(obt, idx);
        spin_unlock(&obt->obt_trans_table_lock);
        return time;
}
EXPORT_SYMBOL(target_trans_table_last_time);

/**
 * Recalculate trans_table slots data if stale_export_age is changed
 */
void target_trans_table_recalc(struct obd_device *obd, __u32 new_age)
{
        struct obd_device_target *obt = &obd->u.obt;
        __u32 old_age = obt->obt_stale_export_age;
        const __u32 slots = le32_to_cpu(obt->obt_lsd->lsd_expire_intervals);
        __u64 *table = obt->obt_lsd->lsd_trans_table;
        int i, j;

        /** there is no old info to recalc */
        if (obt->obt_stale_export_age == 0)
                return;

        /** Expand table */
        spin_lock(&obt->obt_trans_table_lock);
        if (old_age < new_age) {
                for (j = 0; j < slots; j++) {
                        i = j * new_age / old_age;
                        /** no more data for new age */
                        if (i >= slots)
                                table[j] = 0;
                        else
                                table[j] = table[i];
                }
        } else {
                for (j = slots; j > 0; j--) {
                        i = (j - 1) * new_age / old_age;
                        table[j] = table[i];
                }
        }
        spin_unlock(&obt->obt_trans_table_lock);
}
EXPORT_SYMBOL(target_trans_table_recalc);

/**
 * New transno is arrived and it is time for new slot
 */
void target_trans_table_update(struct obd_export *exp, __u64 transno)
{
        struct obd_device_target *obt = &exp->exp_obd->u.obt;
        __u32 shift = cfs_time_sub(cfs_time_current_sec(),
                              le32_to_cpu(obt->obt_lsd->lsd_trans_table_time));
        __u64 *table = obt->obt_lsd->lsd_trans_table;
        const __u32 slots = le32_to_cpu(obt->obt_lsd->lsd_expire_intervals);
        int n = 0, i, j;

        /** how many slots are in shift */
        if (obt->obt_stale_export_age > 0)
                n = shift * slots / obt->obt_stale_export_age;
        /** it is not time to update */
        if (n == 0)
                return;
        spin_lock(&obt->obt_trans_table_lock);
        /** shift table if there is overlapping or fill with latest transno */
        for (i = slots - 1; i >= 1; i--) {
                j = i > n ? i - n : 0;
                table[i] = table[j];
        }
        /** now update first slot with new data */
        obt->obt_lsd->lsd_trans_table_time = cpu_to_le32(cfs_time_current_sec());
        obt->obt_lsd->lsd_trans_table[0] = cpu_to_le64(transno);
        spin_unlock(&obt->obt_trans_table_lock);
}
EXPORT_SYMBOL(target_trans_table_update);
