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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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

struct oi_descr {
        int   fid_size;
        char *name;
};

static const struct oi_descr oi_descr[OSD_OI_FID_NR] = {
        [OSD_OI_FID_SMALL] = {
                .fid_size = 5,
                .name     = "oi.5"
        },
        [OSD_OI_FID_OTHER] = {
                .fid_size = sizeof(struct lu_fid),
                .name     = "oi.16"
        }
};

int osd_oi_init(struct osd_thread_info *info,
                struct osd_oi *oi, struct dt_device *dev)
{
        int rc;
        int i;
        const struct lu_env *env;

        CLASSERT(ARRAY_SIZE(oi->oi_dir) == ARRAY_SIZE(oi_descr));

        env = info->oti_env;

        memset(oi, 0, sizeof *oi);

        for (i = rc = 0; i < ARRAY_SIZE(oi->oi_dir) && rc == 0; ++i) {
                const char       *name;
                /*
                 * Allocate on stack---this is initialization.
                 */
                const struct dt_index_features feat = {
                        .dif_flags       = DT_IND_UPDATE,
                        .dif_keysize_min = oi_descr[i].fid_size,
                        .dif_keysize_max = oi_descr[i].fid_size,
                        .dif_recsize_min = sizeof(struct osd_inode_id),
                        .dif_recsize_max = sizeof(struct osd_inode_id)
                };
                struct dt_object *obj;

                name = oi_descr[i].name;
                obj = dt_store_open(env, dev, name, &info->oti_fid);
                if (!IS_ERR(obj)) {
                        rc = obj->do_ops->do_index_try(env, obj, &feat);
                        if (rc == 0) {
                                LASSERT(obj->do_index_ops != NULL);
                                oi->oi_dir[i] = obj;
                        } else {
                                CERROR("Wrong index \"%s\": %d\n", name, rc);
                                lu_object_put(env, &obj->do_lu);
                        }
                } else {
                        rc = PTR_ERR(obj);
                        CERROR("Cannot open \"%s\": %d\n", name, rc);
                }
        }
        if (rc != 0)
                osd_oi_fini(info, oi);
        return rc;
}

void osd_oi_fini(struct osd_thread_info *info, struct osd_oi *oi)
{
        int i;
        for (i = 0; i < ARRAY_SIZE(oi->oi_dir); ++i) {
                if (oi->oi_dir[i] != NULL) {
                        lu_object_put(info->oti_env, &oi->oi_dir[i]->do_lu);
                        oi->oi_dir[i] = NULL;
                }
        }
}

static const struct dt_key *oi_fid_key(struct osd_thread_info *info,
                                       struct osd_oi *oi,
                                       const struct lu_fid *fid,
                                       struct dt_object **idx)
{
        int i;
        struct lu_fid_pack *pack;

        pack = &info->oti_pack;
        fid_pack(pack, fid, &info->oti_fid);
        for (i = 0; i < ARRAY_SIZE(oi->oi_dir); ++i) {
                if (pack->fp_len == oi_descr[i].fid_size + sizeof pack->fp_len){
                        *idx = oi->oi_dir[i];
                        return (const struct dt_key *)&pack->fp_area;
                }
        }
        CERROR("Unsupported packed fid size: %d ("DFID")\n",
               pack->fp_len, PFID(fid));
        LBUG();
        return NULL;
}

int osd_oi_lookup(struct osd_thread_info *info, struct osd_oi *oi,
                  const struct lu_fid *fid, struct osd_inode_id *id)
{
        int rc;

        if (fid_is_igif(fid)) {
                lu_igif_to_id(fid, id);
                rc = 0;
        } else {
                struct dt_object    *idx;
                const struct dt_key *key;

                key = oi_fid_key(info, oi, fid, &idx);
                rc = idx->do_index_ops->dio_lookup(info->oti_env, idx,
                                                   (struct dt_rec *)id, key,
                                                   BYPASS_CAPA);
                id->oii_ino = be32_to_cpu(id->oii_ino);
                id->oii_gen = be32_to_cpu(id->oii_gen);
        }
        return rc;
}

int osd_oi_insert(struct osd_thread_info *info, struct osd_oi *oi,
                  const struct lu_fid *fid, const struct osd_inode_id *id0,
                  struct thandle *th)
{
        struct dt_object    *idx;
        struct osd_inode_id *id;
        const struct dt_key *key;

        if (fid_is_igif(fid))
                return 0;

        key = oi_fid_key(info, oi, fid, &idx);
        id  = &info->oti_id;
        id->oii_ino = cpu_to_be32(id0->oii_ino);
        id->oii_gen = cpu_to_be32(id0->oii_gen);
        return idx->do_index_ops->dio_insert(info->oti_env, idx,
                                             (const struct dt_rec *)id,
                                             key, th, BYPASS_CAPA);
}

int osd_oi_delete(struct osd_thread_info *info,
                  struct osd_oi *oi, const struct lu_fid *fid,
                  struct thandle *th)
{
        struct dt_object    *idx;
        const struct dt_key *key;

        if (fid_is_igif(fid))
                return 0;

        key = oi_fid_key(info, oi, fid, &idx);
        return idx->do_index_ops->dio_delete(info->oti_env, idx,
                                             key, th, BYPASS_CAPA);
}
