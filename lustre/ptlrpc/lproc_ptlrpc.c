/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/lprocfs_status.h>

#ifndef LPROCFS
struct lprocfs_vars lprocfs_obd_vars[]  = { {0} };
struct lprocfs_vars lprocfs_module_vars[] = { {0} };
#else
struct lprocfs_vars lprocfs_obd_vars[] = {
        { "uuid",     lprocfs_rd_uuid,    0, 0},
        { 0 }
};

struct lprocfs_vars lprocfs_module_vars[] = {
        { "num_refs", lprocfs_rd_numrefs, 0, 0},
        { 0 }
};

#endif /* LPROCFS */
LPROCFS_INIT_VARS(lprocfs_module_vars, lprocfs_obd_vars)
