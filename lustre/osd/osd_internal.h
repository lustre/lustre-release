/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd/osd_internal.h
 *
 * Shared definitions and declarations for osd module
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
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

/* LUSTRE_OSD_NAME */
#include <obd.h>
/* class_register_type(), class_unregister_type(), class_get_type() */
#include <obd_class.h>
#include <lustre_disk.h>

#include <dt_object.h>
#include "osd_oi.h"

struct inode;

#define OSD_COUNTERS (0)

/*
 * osd device.
 */
struct osd_device {
        /* super-class */
        struct dt_device          od_dt_dev;
        /* information about underlying file system */
        struct lustre_mount_info *od_mount;
        /* object index */
        struct osd_oi             od_oi;
        /*
         * XXX temporary stuff for object index: directory where every object
         * is named by its fid.
         */
        struct dentry            *od_obj_area;

        /* Environment for transaction commit callback.
         * Currently, OSD is based on ext3/JBD. Transaction commit in ext3/JBD
         * is serialized, that is there is no more than one transaction commit
         * at a time (JBD journal_commit_transaction() is serialized).
         * This means that it's enough to have _one_ lu_context.
         */
        struct lu_env             od_env_for_commit;

        /*
         * Fid Capability
         */
        unsigned int              od_fl_capa:1;
        unsigned long             od_capa_timeout;
        __u32                     od_capa_alg;
        struct lustre_capa_key   *od_capa_keys;
        struct hlist_head        *od_capa_hash;
        
        cfs_proc_dir_entry_t     *od_proc_entry;
        struct lprocfs_stats     *od_stats;
        /*
         * statfs optimization: we cache a bit.
         */
        cfs_time_t                od_osfs_age;
        struct kstatfs            od_kstatfs;
        spinlock_t                od_osfs_lock;
};


struct osd_thread_info {
        const struct lu_env   *oti_env;

        struct lu_fid          oti_fid;
        struct osd_inode_id    oti_id;
        /*
         * XXX temporary: for ->i_op calls.
         */
        struct qstr            oti_str;
        struct txn_param       oti_txn;
        /*
         * XXX temporary: fake dentry used by xattr calls.
         */
        struct dentry          oti_dentry;
        struct timespec        oti_time;
        /*
         * XXX temporary: for capa operations.
         */
        struct lustre_capa_key oti_capa_key;
        struct lustre_capa     oti_capa;

        struct lu_fid_pack     oti_pack;

        /* union to guarantee that ->oti_ipd[] has proper alignment. */
        union {
        char                   oti_ipd[DX_IPD_MAX_SIZE];
                long long      oti_alignment_lieutenant;
        };
#if OSD_COUNTERS
        int                    oti_r_locks;
        int                    oti_w_locks;
        int                    oti_txns;
#endif
};

#ifdef LPROCFS
/* osd_lproc.c */
void lprocfs_osd_init_vars(struct lprocfs_static_vars *lvars);
int osd_procfs_init(struct osd_device *osd, const char *name);
int osd_procfs_fini(struct osd_device *osd);
void osd_lprocfs_time_start(const struct lu_env *env);
void osd_lprocfs_time_end(const struct lu_env *env,
                          struct osd_device *osd, int op);
#endif
int osd_statfs(const struct lu_env *env, struct dt_device *dev,
               struct kstatfs *sfs);

#endif /* __KERNEL__ */
#endif /* _OSD_INTERNAL_H */
