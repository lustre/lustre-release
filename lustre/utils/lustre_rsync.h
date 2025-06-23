/* SPDX-License-Identifier: GPL-2.0-only */
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
