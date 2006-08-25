/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/osd/osd_oi.c
 *  Object Index.
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
/*
 * oi uses two mechanisms to implement fid->cookie mapping:
 *
 *     - persistent index, where cookie is a record and fid is a key, and
 *
 *     - algorithmic mapping for "igif" fids.
 *
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>

/* LUSTRE_VERSION_CODE */
#include <lustre_ver.h>
/*
 * struct OBD_{ALLOC,FREE}*()
 * OBD_FAIL_CHECK
 */
#include <obd.h>
#include <obd_support.h>

/* fid_is_local() */
#include <lustre_fid.h>

#include "osd_oi.h"
/* osd_lookup(), struct osd_thread_info */
#include "osd_internal.h"
/* lu_fid_is_igif() */
#include "osd_igif.h"
#include "dt_object.h"

static const struct dt_key *oi_fid_key(struct osd_thread_info *info,
                                       const struct lu_fid *fid);
static const char oi_dirname[] = "oi";

static const struct dt_index_features oi_index_features = {
        .dif_flags       = DT_IND_UPDATE,
        .dif_keysize_min = sizeof(struct lu_fid),
        .dif_keysize_max = sizeof(struct lu_fid),
        .dif_recsize_min = sizeof(struct osd_inode_id),
        .dif_recsize_max = sizeof(struct osd_inode_id)
};

int osd_oi_init(struct osd_thread_info *info,
                struct osd_oi *oi, struct dt_device *dev)
{
        int rc;
        struct dt_object        *obj;
        const struct lu_context *ctx;

        ctx = info->oti_ctx;
        /*
         * Initialize ->oi_lock first, because of possible oi re-entrance in
         * dt_store_open().
         */
        init_rwsem(&oi->oi_lock);

        obj = dt_store_open(ctx, dev, oi_dirname, &info->oti_fid);
        if (!IS_ERR(obj)) {
                rc = obj->do_ops->do_index_try(ctx, obj, &oi_index_features);
                if (rc == 0) {
                        LASSERT(obj->do_index_ops != NULL);
                        oi->oi_dir = obj;
                } else {
                        CERROR("Wrong index \"%s\": %d\n", oi_dirname, rc);
                        lu_object_put(ctx, &obj->do_lu);
                }
        } else {
                rc = PTR_ERR(obj);
                CERROR("Cannot open \"%s\": %d\n", oi_dirname, rc);
        }
        return rc;
}

void osd_oi_fini(struct osd_thread_info *info, struct osd_oi *oi)
{
        if (oi->oi_dir != NULL) {
                lu_object_put(info->oti_ctx, &oi->oi_dir->do_lu);
                oi->oi_dir = NULL;
        }
}

void osd_oi_read_lock(struct osd_oi *oi)
{
        down_read(&oi->oi_lock);
}

void osd_oi_read_unlock(struct osd_oi *oi)
{
        up_read(&oi->oi_lock);
}

void osd_oi_write_lock(struct osd_oi *oi)
{
        down_write(&oi->oi_lock);
}

void osd_oi_write_unlock(struct osd_oi *oi)
{
        up_write(&oi->oi_lock);
}

static const struct dt_key *oi_fid_key(struct osd_thread_info *info,
                                       const struct lu_fid *fid)
{
        fid_to_be(&info->oti_fid, fid);
        return (const struct dt_key *)&info->oti_fid;
}

enum {
        OI_TXN_INSERT_CREDITS = 20,
        OI_TXN_DELETE_CREDITS = 20
};

static inline void osd_inode_id_init(struct osd_inode_id *id,
                                     __u64 ino, __u32 gen)
{
        id->oii_ino = be64_to_cpu(ino);
        id->oii_gen = be32_to_cpu(gen);
}

/*
 * Locking: requires at least read lock on oi.
 */
int osd_oi_lookup(struct osd_thread_info *info, struct osd_oi *oi,
                  const struct lu_fid *fid, struct osd_inode_id *id)
{
        int rc;

        if (lu_fid_is_igif(fid)) {
                lu_igif_to_id(fid, id);
                rc = 0;
        } else {
                rc = oi->oi_dir->do_index_ops->dio_lookup
                        (info->oti_ctx, oi->oi_dir,
                         (struct dt_rec *)id, oi_fid_key(info, fid));
                osd_inode_id_init(id, id->oii_ino, id->oii_gen);
        }
        return rc;
}

/*
 * Locking: requires write lock on oi.
 */
int osd_oi_insert(struct osd_thread_info *info, struct osd_oi *oi,
                  const struct lu_fid *fid, const struct osd_inode_id *id0,
                  struct thandle *th)
{
        struct dt_object    *idx;
        struct dt_device    *dev;
        struct osd_inode_id *id;

        if (lu_fid_is_igif(fid))
                return 0;

        idx = oi->oi_dir;
        dev = lu2dt_dev(idx->do_lu.lo_dev);
        id = &info->oti_id;
        osd_inode_id_init(id, id0->oii_ino, id0->oii_gen);
        return idx->do_index_ops->dio_insert(info->oti_ctx, idx,
                                             (const struct dt_rec *)id,
                                             oi_fid_key(info, fid), th);
}

/*
 * Locking: requires write lock on oi.
 */
int osd_oi_delete(struct osd_thread_info *info,
                  struct osd_oi *oi, const struct lu_fid *fid,
                  struct thandle *th)
{
        struct dt_object *idx;
        struct dt_device *dev;

        if (lu_fid_is_igif(fid))
                return 0;

        idx = oi->oi_dir;
        dev = lu2dt_dev(idx->do_lu.lo_dev);
        return idx->do_index_ops->dio_delete(info->oti_ctx, idx,
                                             oi_fid_key(info, fid), th);
}

