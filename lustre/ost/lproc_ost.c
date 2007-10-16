/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 *
 */
#define DEBUG_SUBSYSTEM S_OST

#include <obd_class.h>
#include <lprocfs_status.h>
#include <linux/seq_file.h>
#include "ost_internal.h"

#ifdef LPROCFS
static struct lprocfs_vars lprocfs_obd_vars[] = {
        { "uuid",            lprocfs_rd_uuid,   0, 0 },
        { 0 }
};

static struct lprocfs_vars lprocfs_module_vars[] = {
        { "num_refs",       lprocfs_rd_numrefs, 0, 0 },
        { 0 }
};

LPROCFS_INIT_VARS(ost, lprocfs_module_vars, lprocfs_obd_vars)
#endif /* LPROCFS */
