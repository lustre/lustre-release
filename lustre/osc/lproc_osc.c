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

#include <linux/obd_class.h>
#include <linux/lprocfs_status.h>

#ifndef LPROCFS
struct lprocfs_vars status_var_nm_1[]  = { {0} };
struct lprocfs_vars status_class_var[] = { {0} };
#else 

DEFINE_LPROCFS_STATFS_FCT(rd_blksize,     obd_self_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_kbytestotal, obd_self_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_kbytesfree,  obd_self_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_filestotal,  obd_self_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_filesfree,   obd_self_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_filegroups,  obd_self_statfs);

struct lprocfs_vars status_var_nm_1[] = {
        {"uuid", lprocfs_rd_uuid, 0, 0},
        {"blocksize",rd_blksize, 0, 0},
        {"kbytestotal", rd_kbytestotal, 0, 0},
        {"kbytesfree", rd_kbytesfree, 0, 0},
        {"filestotal", rd_filestotal, 0, 0},
        {"filesfree", rd_filesfree, 0, 0},
        {"filegroups", rd_filegroups, 0, 0},
        {"ost_server_uuid", lprocfs_rd_server_uuid, 0, 0},
        {"ost_conn_uuid", lprocfs_rd_conn_uuid, 0, 0},
        {0}
};

struct lprocfs_vars status_class_var[] = {
        {"num_refs", lprocfs_rd_numrefs, 0, 0},
        {0}
};

#endif /* LPROCFS */
