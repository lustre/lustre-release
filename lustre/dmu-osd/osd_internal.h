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
 * Shared definitions and declarations for osd module
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef _OSD_INTERNAL_H
#define _OSD_INTERNAL_H

#include <dt_object.h>

struct inode;

#define OSD_COUNTERS (0)
#define DMU_RESERVED_MIN (1<<20)
#define DMU_RESERVED_MAX (64ULL * DMU_RESERVED_MIN)

/**
 * Storage representation for fids.
 *
 * Variable size, first byte contains the length of the whole record.
 */
struct osd_fid_pack {
        unsigned char fp_len;
        char fp_area[sizeof(struct lu_fid)];
};

struct osd_thread_info {
        const struct lu_env   *oti_env;

        struct lu_fid          oti_fid;
        /*
         * XXX temporary: for ->i_op calls.
         */
        struct timespec        oti_time;
        /*
         * XXX temporary: for capa operations.
         */
        struct lustre_capa_key oti_capa_key;
        struct lustre_capa     oti_capa;

        struct osd_fid_pack    oti_fid_pack;
};

/*
 * osd device.
 */
struct osd_device {
        /* super-class */
        struct dt_device          od_dt_dev;
        /* information about underlying file system */
        udmu_objset_t             od_objset;

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

        /*
         * statfs optimization: we cache a bit.
         */
        cfs_time_t                od_osfs_age;
        struct kstatfs            od_kstatfs;
        spinlock_t                od_osfs_lock;

        cfs_proc_dir_entry_t     *od_proc_entry;
        struct lprocfs_stats     *od_stats;

        dmu_buf_t                *od_root_db;
        dmu_buf_t                *od_objdir_db;

        unsigned int              od_rdonly:1;
        char                      od_label[MAXNAMELEN];
};

int osd_statfs(const struct lu_env *env, struct dt_device *d, struct kstatfs *sfs);

void lprocfs_osd_init_vars(struct lprocfs_static_vars *lvars);
int osd_procfs_fini(struct osd_device *osd);
int osd_procfs_init(struct osd_device *osd, const char *name);

#endif /* _OSD_INTERNAL_H */
