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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/libcfs_prim.h
 *
 * General primitives.
 *
 */

#ifndef __LIBCFS_PRIM_H__
#define __LIBCFS_PRIM_H__

#ifndef CFS_EXPORT_SYMBOL
# define CFS_EXPORT_SYMBOL(s)
#endif

/*
 * Schedule
 */
void cfs_schedule_timeout_and_set_state(cfs_task_state_t state,
                                        int64_t timeout);
void cfs_schedule_timeout(int64_t timeout);
void cfs_schedule(void);
void cfs_pause(cfs_duration_t ticks);
int  cfs_need_resched(void);
void cfs_cond_resched(void);

/*
 * Wait Queues
 */
void cfs_waitq_init(cfs_waitq_t *waitq);
void cfs_waitlink_init(cfs_waitlink_t *link);
void cfs_waitq_add(cfs_waitq_t *waitq, cfs_waitlink_t *link);
void cfs_waitq_add_exclusive(cfs_waitq_t *waitq,
                             cfs_waitlink_t *link);
void cfs_waitq_add_exclusive_head(cfs_waitq_t *waitq,
                                  cfs_waitlink_t *link);
void cfs_waitq_del(cfs_waitq_t *waitq, cfs_waitlink_t *link);
int  cfs_waitq_active(cfs_waitq_t *waitq);
void cfs_waitq_signal(cfs_waitq_t *waitq);
void cfs_waitq_signal_nr(cfs_waitq_t *waitq, int nr);
void cfs_waitq_broadcast(cfs_waitq_t *waitq);
void cfs_waitq_wait(cfs_waitlink_t *link, cfs_task_state_t state);
int64_t cfs_waitq_timedwait(cfs_waitlink_t *link, cfs_task_state_t state, 
			    int64_t timeout);

/*
 * Timer
 */
typedef  void (cfs_timer_func_t)(ulong_ptr_t);

void cfs_init_timer(cfs_timer_t *t);
void cfs_timer_init(cfs_timer_t *t, cfs_timer_func_t *func, void *arg);
void cfs_timer_done(cfs_timer_t *t);
void cfs_timer_arm(cfs_timer_t *t, cfs_time_t deadline);
void cfs_timer_disarm(cfs_timer_t *t);
int  cfs_timer_is_armed(cfs_timer_t *t);
cfs_time_t cfs_timer_deadline(cfs_timer_t *t);

/*
 * Memory
 */
#ifndef cfs_memory_pressure_get
#define cfs_memory_pressure_get() (0)
#endif
#ifndef cfs_memory_pressure_set
#define cfs_memory_pressure_set() do {} while (0)
#endif
#ifndef cfs_memory_pressure_clr
#define cfs_memory_pressure_clr() do {} while (0)
#endif

static inline int cfs_memory_pressure_get_and_set(void)
{
        int old = cfs_memory_pressure_get();

        if (!old)
                cfs_memory_pressure_set();
        return old;
}

static inline void cfs_memory_pressure_restore(int old)
{
        if (old)
                cfs_memory_pressure_set();
        else
                cfs_memory_pressure_clr();
        return;
}
#endif
