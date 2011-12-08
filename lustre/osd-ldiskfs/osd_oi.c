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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd/osd_oi.c
 *
 * Object Index.
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
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

/* fid_cpu_to_be() */
#include <lustre_fid.h>

#include "osd_oi.h"
/* osd_lookup(), struct osd_thread_info */
#include "osd_internal.h"
#include "osd_igif.h"
#include "dt_object.h"

#define OSD_OI_FID_NR         (1UL << OSD_OI_FID_OID_BITS)
#define OSD_OI_FID_NR_MAX     (1UL << OSD_OI_FID_OID_BITS_MAX)

static unsigned int osd_oi_num = OSD_OI_FID_NR;
CFS_MODULE_PARM(osd_oi_num, "i", int, 0444,
                "Number of Object Index containers to be created, "
                "it's only valid for new filesystem.");

/** to serialize concurrent OI index initialization */
static cfs_mutex_t oi_init_lock;

static struct dt_index_features oi_feat = {
        .dif_flags       = DT_IND_UPDATE,
        .dif_recsize_min = sizeof(struct osd_inode_id),
        .dif_recsize_max = sizeof(struct osd_inode_id),
        .dif_ptrsize     = 4
};

#define OSD_OI_NAME_BASE        "oi.16"

/**
 * Open an OI(Ojbect Index) container.
 *
 * \param       name    Name of OI container
 * \param       objp    Pointer of returned OI
 *
 * \retval      0       success
 * \retval      -ve     failure
 */
static int
osd_oi_open(struct osd_thread_info *info,
            struct dt_device *dev, char *name, struct dt_object **objp)
{
        const struct lu_env *env = info->oti_env;
        struct dt_object    *obj;
        int                  rc;

        obj = dt_store_open(env, dev, "", name, &info->oti_fid);
        if (IS_ERR(obj))
                return PTR_ERR(obj);

        oi_feat.dif_keysize_min = sizeof(info->oti_fid);
        oi_feat.dif_keysize_max = sizeof(info->oti_fid);

        rc = obj->do_ops->do_index_try(env, obj, &oi_feat);
        if (rc != 0) {
                lu_object_put(info->oti_env, &obj->do_lu);
                CERROR("%s: wrong index %s: rc = %d\n",
                       dev->dd_lu_dev.ld_obd->obd_name, name, rc);
                return rc;
        }

        *objp = obj;
        return 0;
}


static void
osd_oi_table_put(struct osd_thread_info *info,
                 struct osd_oi *oi_table, unsigned oi_count)
{
        int     i;

        for (i = 0; i < oi_count; i++) {
                LASSERT(oi_table[i].oi_dir != NULL);

                lu_object_put(info->oti_env, &oi_table[i].oi_dir->do_lu);
                oi_table[i].oi_dir = NULL;
        }
}

/**
 * Open OI(Object Index) table.
 * If \a oi_count is zero, which means caller doesn't know how many OIs there
 * will be, this function can either return 0 for new filesystem, or number
 * of OIs on existed filesystem.
 *
 * If \a oi_count is non-zero, which means caller does know number of OIs on
 * filesystem, this function should return the exactly same number on
 * success, or error code in failure.
 *
 * \param     oi_count  Number of expected OI containers
 * \param     try_all   Try to open all OIs even see failures
 *
 * \retval    +ve       number of opened OI containers
 * \retval      0       no OI containers found
 * \retval    -ve       failure
 */
static int
osd_oi_table_open(struct osd_thread_info *info, struct dt_device *dev,
                  struct osd_oi *oi_table, unsigned oi_count, int try_all)
{
        int     count = 0;
        int     rc = 0;
        int     i;

        /* NB: oi_count != 0 means that we have already created/known all OIs
         * and have known exact number of OIs. */
        LASSERT(oi_count <= OSD_OI_FID_NR_MAX);

        for (i = 0; i < (oi_count != 0 ? oi_count : OSD_OI_FID_NR_MAX); i++) {
                char name[12];

                sprintf(name, "%s.%d", OSD_OI_NAME_BASE, i);
                rc = osd_oi_open(info, dev, name, &oi_table[i].oi_dir);
                if (rc == 0) {
                        count++;
                        continue;
                }

                if (try_all)
                        continue;

                if (rc == -ENOENT && oi_count == 0)
                        return count;

                CERROR("%s: can't open %s: rc = %d\n",
                       dev->dd_lu_dev.ld_obd->obd_name, name, rc);

                if (oi_count > 0) {
                        CERROR("%s: expect to open total %d OI files.\n",
                               dev->dd_lu_dev.ld_obd->obd_name, oi_count);
                }

                break;
        }

        if (try_all)
                return count;

        if (rc < 0) {
                osd_oi_table_put(info, oi_table, count);
                return rc;
        }

        return count;
}

static int osd_oi_table_create(struct osd_thread_info *info,
                               struct dt_device *dev,
                               struct md_device *mdev, int oi_count)
{
        const struct lu_env *env;
        struct md_object *mdo;
        int i;

        env = info->oti_env;
        for (i = 0; i < oi_count; ++i) {
                char name[12];

                sprintf(name, "%s.%d", OSD_OI_NAME_BASE, i);

                lu_local_obj_fid(&info->oti_fid, OSD_OI_FID_OID_FIRST + i);
                oi_feat.dif_keysize_min = sizeof(info->oti_fid);
                oi_feat.dif_keysize_max = sizeof(info->oti_fid);

                mdo = llo_store_create_index(env, mdev, dev, "", name,
                                             &info->oti_fid, &oi_feat);
                if (IS_ERR(mdo)) {
                        CERROR("Failed to create OI[%d] on %s: %d\n",
                               i, dev->dd_lu_dev.ld_obd->obd_name,
                               (int)PTR_ERR(mdo));
                        RETURN(PTR_ERR(mdo));
                }

                lu_object_put(env, &mdo->mo_lu);
        }
        return 0;
}

int osd_oi_init(struct osd_thread_info *info,
                struct osd_oi **oi_table,
                struct dt_device *dev,
                struct md_device *mdev)
{
        struct osd_oi *oi;
        int rc;

        OBD_ALLOC(oi, sizeof(*oi) * OSD_OI_FID_NR_MAX);
        if (oi == NULL)
                return -ENOMEM;

        cfs_mutex_lock(&oi_init_lock);

        rc = osd_oi_table_open(info, dev, oi, 0, 0);
        if (rc != 0)
                goto out;

        rc = osd_oi_open(info, dev, OSD_OI_NAME_BASE, &oi[0].oi_dir);
        if (rc == 0) { /* found single OI from old filesystem */
                rc = 1;
                goto out;
        }

        if (rc != -ENOENT) {
                CERROR("%s: can't open %s: rc = %d\n",
                       dev->dd_lu_dev.ld_obd->obd_name, OSD_OI_NAME_BASE, rc);
                goto out;
        }

        /* create OI objects */
        rc = osd_oi_table_create(info, dev, mdev, osd_oi_num);
        if (rc != 0)
                goto out;

        rc = osd_oi_table_open(info, dev, oi, osd_oi_num, 0);
        LASSERT(rc == osd_oi_num || rc < 0);

 out:
        if (rc < 0)
                OBD_FREE(oi, sizeof(*oi) * OSD_OI_FID_NR_MAX);
        else
                *oi_table = oi;

        cfs_mutex_unlock(&oi_init_lock);
        return rc;
}

void osd_oi_fini(struct osd_thread_info *info,
                 struct osd_oi **oi_table, unsigned oi_count)
{
        struct osd_oi *oi = *oi_table;

        osd_oi_table_put(info, oi, oi_count);

        OBD_FREE(oi, sizeof(*oi) * OSD_OI_FID_NR_MAX);
        *oi_table = NULL;
}

int osd_oi_lookup(struct osd_thread_info *info, struct osd_oi *oi,
                  const struct lu_fid *fid, struct osd_inode_id *id)
{
        struct lu_fid *oi_fid = &info->oti_fid;
        int rc;

        if (osd_fid_is_igif(fid)) {
                lu_igif_to_id(fid, id);
                rc = 0;
        } else {
                struct dt_object    *idx;
                const struct dt_key *key;

                if (!fid_is_norm(fid))
                        return -ENOENT;

                idx = oi->oi_dir;
                fid_cpu_to_be(oi_fid, fid);
                key = (struct dt_key *) oi_fid;
                rc = idx->do_index_ops->dio_lookup(info->oti_env, idx,
                                                   (struct dt_rec *)id, key,
                                                   BYPASS_CAPA);
                if (rc > 0) {
                        id->oii_ino = be32_to_cpu(id->oii_ino);
                        id->oii_gen = be32_to_cpu(id->oii_gen);
                        rc = 0;
                } else if (rc == 0)
                        rc = -ENOENT;
        }
        return rc;
}

int osd_oi_insert(struct osd_thread_info *info, struct osd_oi *oi,
                  const struct lu_fid *fid, const struct osd_inode_id *id0,
                  struct thandle *th, int ignore_quota)
{
        struct lu_fid *oi_fid = &info->oti_fid;
        struct dt_object    *idx;
        struct osd_inode_id *id;
        const struct dt_key *key;

        if (!fid_is_norm(fid))
                return 0;

        idx = oi->oi_dir;
        fid_cpu_to_be(oi_fid, fid);
        key = (struct dt_key *) oi_fid;

        id  = &info->oti_id;
        id->oii_ino = cpu_to_be32(id0->oii_ino);
        id->oii_gen = cpu_to_be32(id0->oii_gen);
        return idx->do_index_ops->dio_insert(info->oti_env, idx,
                                             (struct dt_rec *)id,
                                             key, th, BYPASS_CAPA,
                                             ignore_quota);
}

int osd_oi_delete(struct osd_thread_info *info,
                  struct osd_oi *oi, const struct lu_fid *fid,
                  struct thandle *th)
{
        struct lu_fid *oi_fid = &info->oti_fid;
        struct dt_object    *idx;
        const struct dt_key *key;

        if (!fid_is_norm(fid))
                return 0;

        idx = oi->oi_dir;
        fid_cpu_to_be(oi_fid, fid);
        key = (struct dt_key *) oi_fid;
        return idx->do_index_ops->dio_delete(info->oti_env, idx,
                                             key, th, BYPASS_CAPA);
}

int osd_oi_mod_init()
{
        if (osd_oi_num == 0 || osd_oi_num > OSD_OI_FID_NR_MAX)
                osd_oi_num = OSD_OI_FID_NR;

        cfs_mutex_init(&oi_init_lock);
        return 0;
}
