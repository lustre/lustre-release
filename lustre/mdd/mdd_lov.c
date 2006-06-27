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
                GOTO(out, rc);

        OBD_ALLOC(ids, lu_attr->la_size);
        if (ids == NULL)
                RETURN(-ENOMEM);

        lov_info->mdd_lov_objids = ids;
        lov_info->mdd_lov_objids_size = lu_attr->la_size;

#if 0
        rc = obj_ids->do_body_ops->dbo_read(ctxt, obj_ids, ids, 
                                            lu_attr->la_size, &off);
        if (rc < 0) {
                CERROR("Error reading objids %d\n", rc);
                RETURN(rc);
        }
#endif                
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
        int i, rc = 0, tgts;
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
#if 0
        rc = ids_obj->do_body_ops->dbo_write(ctxt, ids_obj,
                                             lov_info->mdd_lov_objids,
                                             tgts * sizeof(obd_id), &off);
        if (rc >= 0) {
                lov_info->mdd_lov_objids_dirty = 0;
                rc = 0;
        }
#endif
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
        if (rc)
                obd_disconnect(lov_info->mdd_lov_obd->obd_self_export);
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
        struct obd_device *obd = NULL;
        char *lov_name = NULL, *srv = NULL;
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

        /*register the obd server for lov*/
        srv = lustre_cfg_string(cfg, 0);
        obd = class_name2obd(srv);
        if (obd == NULL) {
                CERROR("No such OBD %s\n", srv);
                LBUG();
        }
        rc = obd_register_observer(lov_info->mdd_lov_obd, obd);
        if (rc) {
                CERROR("MDS cannot register as observer of LOV %s (%d)\n",
                       lov_name, rc);
                GOTO(out, rc);
        }
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

struct mdd_lov_sync_info {
        struct lu_context *mlsi_ctxt;
        struct lu_device  *mlsi_ld;     /* the lov device to sync */
        struct obd_device *mlsi_watched; /* target osc */
        __u32              mlsi_index;   /* index of target */
};

#define MDSLOV_NO_INDEX -1

/* Inform MDS about new/updated target */
static int mdd_lov_update_mds(struct lu_context *ctxt,
                              struct lu_device *ld,
                              struct obd_device *watched, 
                              __u32 idx)
{
        struct mdd_device *mdd = lu2mdd_dev(ld);
        struct mdd_lov_info *lov_info = &mdd->mdd_lov_info;
        int old_count;
        int rc = 0;
        ENTRY;

        old_count = lov_info->mdd_lov_desc.ld_tgt_count;
        rc = mdd_lov_update_desc(ctxt, mdd);
        if (rc)
                RETURN(rc);

        /* 
         * idx is set as data from lov_notify. 
         * XXX did not consider recovery here
         */
        if (idx != MDSLOV_NO_INDEX) {
                if (idx >= lov_info->mdd_lov_desc.ld_tgt_count) {
                        CERROR("index %d > count %d!\n", idx, 
                               lov_info->mdd_lov_desc.ld_tgt_count);
                        RETURN(-EINVAL);
                }
                
                if (idx >= lov_info->mdd_lov_objids_in_file) {
                        /* We never read this lastid; ask the osc */
                        obd_id lastid;
                        __u32 size = sizeof(lastid);
                        rc = obd_get_info(watched->obd_self_export,
                                          strlen("last_id"), 
                                          "last_id", &size, &lastid);
                        if (rc)
                                RETURN(rc);
                        lov_info->mdd_lov_objids[idx] = lastid;
                        lov_info->mdd_lov_objids_dirty = 1;
                        mdd_lov_write_objids(ctxt, lov_info);
                } else {
                        /* We have read this lastid from disk; tell the osc.
                           Don't call this during recovery. */ 
                        rc = mdd_lov_set_nextid(mdd);
                }
        
                CDEBUG(D_CONFIG, "last object "LPU64" from OST %d\n",
                      lov_info->mdd_lov_objids[idx], idx);
        }

        RETURN(rc);
}

/* We only sync one osc at a time, so that we don't have to hold
   any kind of lock on the whole mds_lov_desc, which may change 
   (grow) as a result of mds_lov_add_ost.  This also avoids any
   kind of mismatch between the lov_desc and the mds_lov_desc, 
   which are not in lock-step during lov_add_obd */
static int __mdd_lov_synchronize(void *data)
{
        struct mdd_lov_sync_info *mlsi = data;
        struct lu_device *ld = mlsi->mlsi_ld;
        struct obd_device *watched = mlsi->mlsi_watched;
        struct lu_context *ctxt = mlsi->mlsi_ctxt;
        struct mdd_device *mdd = lu2mdd_dev(ld);
        struct obd_uuid *uuid;
        __u32  idx = mlsi->mlsi_index;
        int rc = 0;
        ENTRY;

        OBD_FREE(mlsi, sizeof(*mlsi));

        LASSERT(ld);
        LASSERT(watched);
        uuid = &watched->u.cli.cl_target_uuid;
        LASSERT(uuid);

        rc = mdd_lov_update_mds(ctxt, ld, watched, idx);
        if (rc != 0)
                GOTO(out, rc);
        
        rc = obd_set_info_async(mdd->mdd_lov_info.mdd_lov_obd->obd_self_export,
                                strlen(KEY_MDS_CONN), KEY_MDS_CONN, 0, uuid, 
                                NULL);
        if (rc != 0)
                GOTO(out, rc);
out:
        lu_device_put(ld);
        RETURN(rc);
}

int mdd_lov_synchronize(void *data)
{
        struct mdd_lov_sync_info *mlsi = data;
        char name[20];

        sprintf(name, "ll_mlov_sync_%02u", mlsi->mlsi_index);
        ptlrpc_daemonize(name);

        RETURN(__mdd_lov_synchronize(data));
}

int mdd_lov_start_synchronize(const struct lu_context *ctxt, 
                              struct lu_device *ld,
                              struct obd_device *watched,
                              void *data, int nonblock)
{
        struct mdd_lov_sync_info *mlsi;
        int rc;

        ENTRY;

        LASSERT(watched);

        OBD_ALLOC(mlsi, sizeof(*mlsi));
        if (mlsi == NULL)
                RETURN(-ENOMEM);

        mlsi->mlsi_ctxt = (struct lu_context *)ctxt;
        mlsi->mlsi_ld = ld;
        mlsi->mlsi_watched = watched;
        if (data)
                mlsi->mlsi_index = *(__u32 *)data;
        else
                mlsi->mlsi_index = MDSLOV_NO_INDEX;

        /* Although class_export_get(obd->obd_self_export) would lock
           the MDS in place, since it's only a self-export
           it doesn't lock the LOV in place.  The LOV can be disconnected
           during MDS precleanup, leaving nothing for __mdd_lov_synchronize.
           Simply taking an export ref on the LOV doesn't help, because it's
           still disconnected. Taking an obd reference insures that we don't
           disconnect the LOV.  This of course means a cleanup won't
           finish for as long as the sync is blocking. */
        lu_device_get(ld);
        
        if (nonblock) {
                /* Synchronize in the background */
                rc = cfs_kernel_thread(mdd_lov_synchronize, mlsi,
                                       CLONE_VM | CLONE_FILES);
                if (rc < 0) {
                        CERROR("error starting mdd_lov_synchronize: %d\n", rc);
                        lu_device_put(ld);
                } else {
                        CDEBUG(D_HA, "mdd_lov_synchronize idx=%d thread=%d\n", 
                               mlsi->mlsi_index, rc);
                        rc = 0;
                }
        } else {
                rc = __mdd_lov_synchronize((void *)mlsi);
        }

        RETURN(rc);
}

int mdd_notify(const struct lu_context *ctxt, struct lu_device *ld,
               struct obd_device *watched, enum obd_notify_event ev,
               void *data)
{
        struct mdd_device *mdd = lu2mdd_dev(ld);
        struct obd_device *obd = ld->ld_site->ls_top_dev->ld_obd;
        int rc = 0;
        ENTRY;

        switch (ev) {
        /* We only handle these: */
        case OBD_NOTIFY_ACTIVE:
        case OBD_NOTIFY_SYNC:
        case OBD_NOTIFY_SYNC_NONBLOCK:
                break;
        default:
                RETURN(0);
        }

        CDEBUG(D_CONFIG, "notify %s ev=%d\n", watched->obd_name, ev);

        if (strcmp(watched->obd_type->typ_name, LUSTRE_OSC_NAME) != 0) {
                CERROR("unexpected notification of %s %s!\n",
                       watched->obd_type->typ_name, watched->obd_name);
                RETURN(-EINVAL);
        }

        /*FIXME later, Recovery stuff still not be designed */
        if (obd->obd_recovering) {
                CWARN("MDS %s: in recovery, not resetting orphans on %s\n",
                      obd->obd_name,
                      obd_uuid2str(&watched->u.cli.cl_target_uuid));
                /* We still have to fix the lov descriptor for ost's added
                   after the mdt in the config log. They didn't make it into
                   mds_lov_connect. */
                rc = mdd_lov_update_desc(ctxt, mdd);
                RETURN(rc);
        }

        rc = mdd_lov_start_synchronize(ctxt, ld, watched, data,
                                       !(ev == OBD_NOTIFY_SYNC));
        RETURN(rc);
}
