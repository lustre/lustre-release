/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/osd/osd_internal.h
 *  Shared definitions and declarations for osd module
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
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
 */

#ifndef _OSD_INTERNAL_H
#define _OSD_INTERNAL_H

#if defined(__KERNEL__)

/* struct rw_semaphore */
#include <linux/rwsem.h>
/* handle_t, journal_start(), journal_stop() */
#include <linux/jbd.h>
/* struct dx_hash_info */
#include <linux/ldiskfs_fs.h>
/* struct dentry */
#include <linux/dcache.h>
#include <linux/lustre_iam.h>

#include <dt_object.h>
#include "osd_oi.h"

struct inode;

struct osd_thread_info {
        const struct lu_env *oti_env;

        struct lu_fid       oti_fid;
        struct osd_inode_id oti_id;
        /*
         * XXX temporary: for ->i_op calls.
         */
        struct qstr         oti_str;
        struct txn_param    oti_txn;
        /*
         * XXX temporary: fake dentry used by xattr calls.
         */
        struct dentry       oti_dentry;
        /*
         * XXX temporary: fake file for body operations.
         */
        struct timespec     oti_time;
        int                 oti_r_locks;
        int                 oti_w_locks;
        int                 oti_txns;

        /*
         * XXX temporary: for capa operations.
         */
        struct lustre_capa_key oti_capa_key;
        struct lustre_capa     oti_capa;
};

#endif /* __KERNEL__ */
#endif /* _OSD_INTERNAL_H */
