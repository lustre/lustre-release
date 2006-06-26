/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/mds_lov.c
 *  Lustre Metadata Server (mds) handling of striped file data
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *           wangdi <wangdi@clusterfs.com>
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
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>

#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <obd_lov.h>
#include <lprocfs_status.h>

#include <lu_object.h>
#include <md_object.h>
#include <dt_object.h>

#include "mdd_internal.h"

const char *mdd_lov_objid_name = "lov_objid";

static int mdd_lov_read_objids(const struct lu_context *ctxt, 
                               struct mdd_device *mdd)
{
        struct mdd_lov_info *lov_info = &mdd->mdd_lov_info;
        struct dt_object *obj_ids = lov_info->mdd_lov_objid_obj;
        struct lu_attr *lu_attr = NULL;
        obd_id *ids;
        loff_t off = 0;
        int i, rc;
        ENTRY;

        LASSERT(!lov_info->mdd_lov_objids_size);
        LASSERT(!lov_info->mdd_lov_objids_dirty);
        
        /* Read everything in the file, even if our current lov desc 
           has fewer targets. Old targets not in the lov descriptor 
           during mds setup may still have valid objids. */
        OBD_ALLOC_PTR(lu_attr);
        if (!lu_attr) 
                RETURN(-ENOMEM);
       
        rc = obj_ids->do_ops->do_attr_get(ctxt, obj_ids, lu_attr);
        if (rc)
                GOTO(out, rc);
        
        if (lu_attr->la_size == 0)
                RETURN(0);

        OBD_ALLOC(ids, lu_attr->la_size);
        if (ids == NULL)
                RETURN(-ENOMEM);

        lov_info->mdd_lov_objids = ids;
        lov_info->mdd_lov_objids_size = lu_attr->la_size;

        rc = obj_ids->do_body_ops->dbo_read(ctxt, obj_ids, ids, 
                                            lu_attr->la_size, &off);
        if (rc < 0) {
                CERROR("Error reading objids %d\n", rc);
                RETURN(rc);
        }
                
        lov_info->mdd_lov_objids_in_file = lu_attr->la_size / sizeof(*ids);

        for (i = 0; i < lov_info->mdd_lov_objids_in_file; i++) {
                CDEBUG(D_INFO, "read last object "LPU64" for idx %d\n",
                       lov_info->mdd_lov_objids[i], i);
        }
out:
        if (lu_attr)
                OBD_FREE_PTR(lu_attr);
        RETURN(0);
}

/* Update the lov desc for a new size lov. */
static int mdd_lov_update_desc(const struct lu_context *ctxt, 
                               struct mdd_device *mdd)
{
        struct mdd_lov_info *lov_info = &mdd->mdd_lov_info;
        __u32 size, stripes, valsize = sizeof(lov_info->mdd_lov_desc);
        struct lov_desc *ld;
        struct obd_device *lov_obd = lov_info->mdd_lov_obd;
        int rc = 0;
        ENTRY;

        OBD_ALLOC(ld, sizeof(*ld));
        if (!ld)
                RETURN(-ENOMEM);

        rc = obd_get_info(lov_obd->obd_self_export, strlen(KEY_LOVDESC) + 1, 
                          KEY_LOVDESC, &valsize, ld);
        if (rc)
                GOTO(out, rc);

        /* The size of the LOV target table may have increased. */
        size = ld->ld_tgt_count * sizeof(obd_id);
        if ((lov_info->mdd_lov_objids_size == 0) || 
            (size > lov_info->mdd_lov_objids_size)) {
                obd_id *ids;

                /* add room by powers of 2 */
                size = 1;
                while (size < ld->ld_tgt_count)
                        size = size << 1;
                size = size * sizeof(obd_id);

                OBD_ALLOC(ids, size);
                if (ids == NULL)
                        GOTO(out, rc = -ENOMEM);
                memset(ids, 0, size);
                if (lov_info->mdd_lov_objids_size) {
                        obd_id *old_ids = lov_info->mdd_lov_objids;
                        memcpy(ids, lov_info->mdd_lov_objids,
                               lov_info->mdd_lov_objids_size);
                        lov_info->mdd_lov_objids = ids;
                        OBD_FREE(old_ids, lov_info->mdd_lov_objids_size);
                }
                lov_info->mdd_lov_objids = ids;
                lov_info->mdd_lov_objids_size = size;
        }

        /* Don't change the mds_lov_desc until the objids size matches the
           count (paranoia) */
        lov_info->mdd_lov_desc = *ld;
        CDEBUG(D_CONFIG, "updated lov_desc, tgt_count: %d\n",
               lov_info->mdd_lov_desc.ld_tgt_count);

        stripes = min((__u32)LOV_MAX_STRIPE_COUNT,
                      max(lov_info->mdd_lov_desc.ld_tgt_count,
                          lov_info->mdd_lov_objids_in_file));
        mdd->mdd_max_mdsize = lov_mds_md_size(stripes);
        mdd->mdd_max_cookiesize = stripes * sizeof(struct llog_cookie);
        CDEBUG(D_CONFIG, "updated max_mdsize/max_cookiesize: %d/%d\n",
               mdd->mdd_max_mdsize, mdd->mdd_max_cookiesize);
out:
        OBD_FREE(ld, sizeof(*ld));
        RETURN(rc);
}

int mdd_lov_write_objids(const struct lu_context *ctxt, 
                         struct mdd_lov_info *lov_info)
{
        struct dt_object *ids_obj = lov_info->mdd_lov_objid_obj;
        loff_t off = 0;
        int i, rc, tgts;
        ENTRY;

        if (!lov_info->mdd_lov_objids_dirty)
                RETURN(0);

        tgts = max(lov_info->mdd_lov_desc.ld_tgt_count, 
                   lov_info->mdd_lov_objids_in_file);
        if (!tgts)
                RETURN(0);

        for (i = 0; i < tgts; i++)
                CDEBUG(D_INFO, "writing last object "LPU64" for idx %d\n",
                       lov_info->mdd_lov_objids[i], i);

        rc = ids_obj->do_body_ops->dbo_write(ctxt, ids_obj,
                                             lov_info->mdd_lov_objids,
                                             tgts * sizeof(obd_id), &off);
        if (rc >= 0) {
                lov_info->mdd_lov_objids_dirty = 0;
                rc = 0;
        }

        RETURN(rc);
}

static int mdd_lov_connect(const struct lu_context *ctxt, 
                           struct mdd_device *mdd, char *lov_name)
{
        struct mdd_lov_info *lov_info = &mdd->mdd_lov_info;
        struct lustre_handle conn = {0,};
        struct obd_connect_data *data;
        int rc = 0;
        ENTRY;

        /*connect to obd*/
        OBD_ALLOC(data, sizeof(*data));
        if (data == NULL)
                RETURN(-ENOMEM);
        data->ocd_connect_flags = OBD_CONNECT_VERSION | OBD_CONNECT_INDEX |
                                  OBD_CONNECT_REQPORTAL;
        data->ocd_version = LUSTRE_VERSION_CODE;
        /* NB: lov_connect() needs to fill in .ocd_index for each OST */
        rc = obd_connect(&conn, lov_info->mdd_lov_obd, &lov_info->mdd_lov_uuid,
                         data);
        OBD_FREE(data, sizeof(*data));
        if (rc) {
                CERROR("MDS cannot connect to LOV %s (%d)\n", lov_name, rc);
                lov_info->mdd_lov_obd = ERR_PTR(rc);
                RETURN(rc);
        }
#if 0
        /*FIXME: register observer of lov, need obd method, 
         * but mdd is not obd now*/
        rc = md_register_observer(mds->mds_osc_obd, obd);
        if (rc) {
                CERROR("MDS cannot register as observer of LOV %s (%d)\n",
                       lov_name, rc);
                GOTO(err_discon, rc);
        }
#endif
        /* open and test the lov objd file */

        rc = mdd_lov_read_objids(ctxt, mdd);
        if (rc) {
                CERROR("cannot read %s: rc = %d\n", "lov_objids", rc);
                GOTO(out, rc);
        }

        rc = mdd_lov_update_desc(ctxt, mdd);
        if (rc)
                GOTO(out, rc);
#if 0
        /* tgt_count may be 0! */
        rc = llog_cat_initialize(obd, mds->mds_lov_desc.ld_tgt_count);
        if (rc) {
                CERROR("failed to initialize catalog %d\n", rc);
                GOTO(err_reg, rc);
        }
#endif
        /* If we're mounting this code for the first time on an existing FS,
         * we need to populate the objids array from the real OST values */
        if (lov_info->mdd_lov_desc.ld_tgt_count > 
                      lov_info->mdd_lov_objids_in_file) {
                int size = sizeof(obd_id) * lov_info->mdd_lov_desc.ld_tgt_count;
                int i;

                rc = obd_get_info(lov_info->mdd_lov_obd->obd_self_export, 
                                  strlen("last_id"), "last_id", &size, 
                                  lov_info->mdd_lov_objids);
                if (!rc) {
                        for (i = 0; i < lov_info->mdd_lov_desc.ld_tgt_count; i++)
                                CWARN("got last object "LPU64" from OST %d\n",
                                      lov_info->mdd_lov_objids[i], i);
                        lov_info->mdd_lov_objids_dirty = 1;
                        rc = mdd_lov_write_objids(ctxt, lov_info);
                        if (rc)
                                CERROR("got last objids from OSTs, but error "
                                       "writing objids file: %d\n", rc);
                }
        }
        /* I want to see a callback happen when the OBD moves to a
         * "For General Use" state, and that's when we'll call
         * set_nextid().  The class driver can help us here, because
         * it can use the obd_recovering flag to determine when the
         * the OBD is full available. */
#if 0
        if (!obd->obd_recovering)
                rc = mds_postrecov(obd);
#endif
out:
        RETURN(rc);
}

int mdd_lov_fini(const struct lu_context *ctxt, struct mdd_device *mdd)
{
        struct mdd_lov_info *lov_info = &mdd->mdd_lov_info;
        
        dt_object_fini(lov_info->mdd_lov_objid_obj);
        return 0;
}

int mdd_lov_init(const struct lu_context *ctxt, struct mdd_device *mdd,
                 struct lustre_cfg *cfg)
{
        struct mdd_lov_info *lov_info = &mdd->mdd_lov_info;
        struct dt_object *obj_id;
        char *lov_name = NULL;
        int rc = 0;
        ENTRY;
 
        if (IS_ERR(lov_info->mdd_lov_obd))
                RETURN(PTR_ERR(lov_info->mdd_lov_obd));

        lov_name = lustre_cfg_string(cfg, 3);
        LASSERTF(lov_name != NULL, "MDD need lov \n");
        lov_info->mdd_lov_obd = class_name2obd(lov_name);
        if (!lov_info->mdd_lov_obd) {
                CERROR("MDS cannot locate LOV %s\n", lov_name);
                lov_info->mdd_lov_obd = ERR_PTR(-ENOTCONN);
                RETURN(-ENOTCONN);
        }

        obj_id = dt_store_open(ctxt, mdd->mdd_child, mdd_lov_objid_name,
                               &lov_info->mdd_lov_objid_fid);
        if (IS_ERR(obj_id)){
                rc = PTR_ERR(obj_id);
                RETURN(rc); 
        }

        LASSERT(obj_id != NULL);
        lov_info->mdd_lov_objid_obj = obj_id;

        obd_str2uuid(&lov_info->mdd_lov_uuid, lustre_cfg_string(cfg, 1));

        rc = mdd_lov_connect(ctxt, mdd, lov_name);
        if (rc)
                GOTO(out, rc);
        EXIT;
out: 
        if (rc)
                mdd_lov_fini(ctxt, mdd);
        return rc;
}

/* update the LOV-OSC knowledge of the last used object id's */
int mdd_lov_set_nextid(struct mdd_device *mdd)
{
        struct mdd_lov_info *lov_info = &mdd->mdd_lov_info;
        int rc;
        ENTRY;

        LASSERT(lov_info->mdd_lov_objids != NULL);

        rc = obd_set_info_async(lov_info->mdd_lov_obd->obd_self_export, 
                                strlen(KEY_NEXT_ID), KEY_NEXT_ID,
                                lov_info->mdd_lov_desc.ld_tgt_count,
                                lov_info->mdd_lov_objids, NULL);

        if (rc) 
                CERROR ("mdd_lov_set_nextid failed (%d)\n", rc);

        RETURN(rc);
}
