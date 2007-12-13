/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/lvfs/lvfs_lib.c
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2007 Cluster File Systems, Inc.
 *   Author: Andreas Dilger <adilger@clusterfs.com>
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
 */
#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/random.h>
#else
#include <liblustre.h>
#endif
#include <lustre_lib.h>

unsigned int obd_fail_val = 0;
unsigned int obd_fail_loc = 0;
unsigned int obd_alloc_fail_rate = 0;

int obd_alloc_fail(const void *ptr, const char *name, const char *type,
                   size_t size, const char *file, int line)
{
        if (ptr == NULL ||
            (ll_rand() & OBD_ALLOC_FAIL_MASK) < obd_alloc_fail_rate) {
                CERROR("%s%salloc of %s ("LPU64" bytes) failed at %s:%d\n",
                       ptr ? "force " :"", type, name, (__u64)size, file,
                       line);
                CERROR(LPU64" total bytes and "LPU64" total pages "
                       "("LPU64" bytes) allocated by Lustre, "
                       "%d total bytes by LNET\n",
                       obd_memory_sum(),
                       obd_pages_sum() << CFS_PAGE_SHIFT,
                       obd_pages_sum(),
                       atomic_read(&libcfs_kmemory));                
                return 1;
        }
        return 0;
}
EXPORT_SYMBOL(obd_alloc_fail);

EXPORT_SYMBOL(obd_fail_loc);
EXPORT_SYMBOL(obd_alloc_fail_rate);
EXPORT_SYMBOL(obd_fail_val);
