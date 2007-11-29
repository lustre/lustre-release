/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 * Author: Nikita Danilov <nikita@clusterfs.com>
 *
 * This file is part of Lustre, http://www.lustre.org.
 *
 * Lustre is free software; you can redistribute it and/or modify it under the
 * terms of version 2 of the GNU General Public License as published by the
 * Free Software Foundation.
 *
 * Lustre is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with Lustre; if not, write to the Free Software Foundation, Inc., 675 Mass
 * Ave, Cambridge, MA 02139, USA.
 *
 * Implementation of portable time API for user-level.
 *
 */

#ifndef __LIBCFS_USER_BITOPS_H__
#define __LIBCFS_USER_BITOPS_H__

unsigned long find_next_bit(const unsigned int *addr,
                unsigned long size, unsigned long offset);

unsigned long find_next_zero_bit(const unsigned int *addr,
                unsigned long size, unsigned long offset);

#define find_first_bit(addr,size)       (find_next_bit((addr),(size),0))
#define find_first_zero_bit(addr,size)  (find_next_zero_bit((addr),(size),0))

#endif
