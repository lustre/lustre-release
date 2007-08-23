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

int obd_alloc_fail(const void *ptr, const char *name, const char *type,
                   size_t size, const char *file, int line)
{
        if (ptr == NULL ||
            (ll_rand() & OBD_ALLOC_FAIL_MASK) < obd_alloc_fail_rate) {
                CERROR("%s%salloc of %s (%u bytes) failed at %s:%d\n",
                       ptr ? "force " :"", type, name, (unsigned int)size, file,
                       line);
                CERROR("%d total bytes allocated by Lustre, %d by Portals\n",
                       atomic_read(&obd_memory), atomic_read(&libcfs_kmemory));
                return 1;
        }
        return 0;
}
EXPORT_SYMBOL(obd_alloc_fail);
