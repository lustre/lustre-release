/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=4:tabstop=4:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
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
 *
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
