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
 * Internal cl interfaces.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 */
#ifndef _CL_INTERNAL_H
#define _CL_INTERNAL_H

#define CLT_PVEC_SIZE (14)

/**
 * Thread local state internal for generic cl-code.
 */
struct cl_thread_info {
        /*
         * Common fields.
         */
        struct cl_io         clt_io;
        struct cl_2queue     clt_queue;

        /*
         * Fields used by cl_lock.c
         */
        struct cl_lock_descr clt_descr;
        struct cl_page_list  clt_list;
        /**
         * \name debugging.
         *
         * Counters used to check correctness of cl_lock interface usage.
         * @{
         */
        /**
         * Number of outstanding calls to cl_lock_mutex_get() made by the
         * current thread. For debugging.
         */
        int                  clt_nr_locks_locked;
        /** List of locked locks. */
        struct lu_ref        clt_locks_locked;
        /** Number of outstanding holds on the top-level locks. */
        int                  clt_nr_held;
        /** Number of outstanding uses on the top-level locks. */
        int                  clt_nr_used;
        /** Number of held top-level extent locks. */
        int                  clt_nr_locks_acquired;
        /** @} debugging */

        /*
         * Fields used by cl_page.c
         */
        struct cl_page      *clt_pvec[CLT_PVEC_SIZE];

        /*
         * Fields used by cl_io.c
         */
        /**
         * Pointer to the topmost ongoing IO in this thread.
         */
        struct cl_io        *clt_current_io;
};

struct cl_thread_info *cl_env_info(const struct lu_env *env);

#endif /* _CL_INTERNAL_H */
