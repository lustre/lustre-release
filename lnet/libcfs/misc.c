/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

# define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>

/*
 * On-wire format is native kdev_t format of Linux kernel 2.6
 */
enum {
	WIRE_RDEV_MINORBITS = 20,
	WIRE_RDEV_MINORMASK = ((1U << WIRE_RDEV_MINORBITS) - 1)
};

cfs_wire_rdev_t cfs_wire_rdev_build(cfs_major_nr_t major, cfs_minor_nr_t minor)
{
        return (major << WIRE_RDEV_MINORBITS) | minor;
}

cfs_major_nr_t  cfs_wire_rdev_major(cfs_wire_rdev_t rdev)
{
        return rdev >> WIRE_RDEV_MINORBITS;
}

cfs_minor_nr_t  cfs_wire_rdev_minor(cfs_wire_rdev_t rdev)
{
        return rdev & WIRE_RDEV_MINORMASK;
}

