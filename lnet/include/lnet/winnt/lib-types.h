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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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
 */

#ifndef __LNET_WINNT_LIB_TYPES_H__
#define __LNET_WINNT_LIB_TYPES_H__

#ifndef __LNET_LIB_TYPES_H__
#error Do not #include this file directly. #include <lnet/lib-types.h> instead
#endif

#include <libcfs/libcfs.h>

typedef struct {
    spinlock_t lock;
} lib_ni_lock_t;

static inline void lib_ni_lock_init(lib_ni_lock_t *l)
{
        spin_lock_init(&l->lock);
}

static inline void lib_ni_lock_fini(lib_ni_lock_t *l)
{}

static inline void lib_ni_lock(lib_ni_lock_t *l)
{
        int     flags;
        spin_lock_irqsave(&l->lock, flags);
}

static inline void lib_ni_unlock(lib_ni_lock_t *l)
{
        spin_unlock_irqrestore(&l->lock, 0);
}

#endif
