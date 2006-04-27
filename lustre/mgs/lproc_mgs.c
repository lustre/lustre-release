/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <asm/statfs.h>
#endif
#include <obd.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include "mgs_internal.h"

#ifdef LPROCFS
struct lprocfs_vars lprocfs_mgs_obd_vars[] = {
        { 0 }
};

struct lprocfs_vars lprocfs_mgs_module_vars[] = {
        { 0 }
};

struct lprocfs_vars lprocfs_mgt_obd_vars[] = {
        { 0 }
};

struct lprocfs_vars lprocfs_mgt_module_vars[] = {
        { 0 }
};

LPROCFS_INIT_VARS(mgs, lprocfs_mgs_module_vars, lprocfs_mgs_obd_vars);
LPROCFS_INIT_VARS(mgt, lprocfs_mgt_module_vars, lprocfs_mgt_obd_vars);
#endif
