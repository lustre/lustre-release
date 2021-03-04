/*
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
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/include/lustre/lustre_rsync.h
 *
 */

#ifndef _LUSTRE_RSYNC_H_
#define _LUSTRE_RSYNC_H_

#define LR_NAME_MAXLEN 64
#define LR_FID_STR_LEN 128

/* Structure used by lustre_rsync. On-disk structures stored in a log
 * file. This is used to determine the next start record and other
 * parameters. */

struct lustre_rsync_status {
        __u32   ls_version;           /* Version of the log entry */
        __u32   ls_size;              /* Size of the log entry */
        __u64   ls_last_recno;        /* Last replicated record no. */
        char    ls_registration[LR_NAME_MAXLEN + 1]; /* Changelog registration*/
        char    ls_mdt_device[LR_NAME_MAXLEN + 1]; /* MDT device */
        char    ls_source_fs[LR_NAME_MAXLEN + 1]; /* Source Lustre FS */
        char    ls_source[PATH_MAX + 1];/* Source FS path */
        __u32   ls_num_targets;       /* No of replication targets */
        char    ls_targets[0][PATH_MAX + 1]; /* Target FS path */
};

struct lr_parent_child_log {
        char pcl_pfid[LR_FID_STR_LEN];
        char pcl_tfid[LR_FID_STR_LEN];
        char pcl_name[PATH_MAX];
};

#endif /* _LUSTRE_RSYNC_H_ */
