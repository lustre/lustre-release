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
 * lustre/cmm/mdc_device.c
 *
 * Lustre Metadata Client (mdc)
 *
 * Author: Mike Pershin <tappro@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <obd.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <lustre_ver.h>
#include "cmm_internal.h"
#include "mdc_internal.h"

static const struct lu_device_operations mdc_lu_ops;
/**
 * \addtogroup cmm_mdc
 * @{
 */
/**
 * The md_device_operation for mdc. It is empty.
 */
static const struct md_device_operations mdc_md_ops = { 0 };

/**
 * Upcall handler in mdc. Analog of obd_device::o_notify().
 */
static int mdc_obd_update(struct obd_device *host,
                          struct obd_device *watched,
                          enum obd_notify_event ev, void *owner, void *data)
{
        struct mdc_device *mc = owner;
        int rc = 0;
        ENTRY;

        LASSERT(mc != NULL);
        CDEBUG(D_CONFIG, "notify %s ev=%d\n", watched->obd_name, ev);
        if (ev == OBD_NOTIFY_ACTIVE) {
                CDEBUG(D_INFO|D_WARNING, "Device %s is active now\n",
                       watched->obd_name);
        } else if (ev == OBD_NOTIFY_INACTIVE) {
                CDEBUG(D_INFO|D_WARNING, "Device %s is inactive now\n",
                       watched->obd_name);
        } else if (ev == OBD_NOTIFY_OCD) {
                struct obd_connect_data *conn_data =
                                  &watched->u.cli.cl_import->imp_connect_data;
                /*
                 * Update exp_connect_flags.
                 */
                mc->mc_desc.cl_exp->exp_connect_flags =
                                                conn_data->ocd_connect_flags;
                CDEBUG(D_INFO, "Update connect_flags: "LPX64"\n",
                       conn_data->ocd_connect_flags);
        }

        RETURN(rc);
}
/**
 * Add new mdc device.
 * Invoked by configuration command LCFG_ADD_MDC.
 *
 * MDC OBD is set up already and connected to the proper MDS
 * mdc_add_obd() find that obd by uuid and connects to it.
 * Local MDT uuid is used for connection.
 */
static int mdc_obd_add(const struct lu_env *env,
                       struct mdc_device *mc, struct lustre_cfg *cfg)
{
        struct mdc_cli_desc *desc = &mc->mc_desc;
        struct obd_device *mdc;
        const char *uuid_str = lustre_cfg_string(cfg, 1);
        const char *index = lustre_cfg_string(cfg, 2);
        const char *mdc_uuid_str = lustre_cfg_string(cfg, 4);
        struct md_site *ms = lu_site2md(mdc2lu_dev(mc)->ld_site);
        char *p;
        int rc = 0;

        ENTRY;
        LASSERT(uuid_str);
        LASSERT(index);

        mc->mc_num = simple_strtol(index, &p, 10);
        if (*p) {
                CERROR("Invalid index in lustre_cgf, offset 2\n");
                RETURN(-EINVAL);
        }

        obd_str2uuid(&desc->cl_srv_uuid, uuid_str);
        obd_str2uuid(&desc->cl_cli_uuid, mdc_uuid_str);
        /* try to find MDC OBD connected to the needed MDT */
        mdc = class_find_client_obd(&desc->cl_srv_uuid, LUSTRE_MDC_NAME,
                                    &desc->cl_cli_uuid);
        if (!mdc) {
                CERROR("Cannot find MDC OBD connected to %s\n", uuid_str);
                rc = -ENOENT;
        } else if (!mdc->obd_set_up) {
                CERROR("target %s not set up\n", mdc->obd_name);
                rc = -EINVAL;
        } else {
                struct obd_connect_data *ocd;

                CDEBUG(D_CONFIG, "connect to %s(%s)\n",
                       mdc->obd_name, mdc->obd_uuid.uuid);

                OBD_ALLOC_PTR(ocd);
                if (!ocd)
                        RETURN(-ENOMEM);
                /*
                 * The connection between MDS must be local,
                 * IBITS are needed for rename_lock (INODELOCK_UPDATE)
                 */
                ocd->ocd_ibits_known = MDS_INODELOCK_UPDATE;
                ocd->ocd_connect_flags = OBD_CONNECT_VERSION |
                                         OBD_CONNECT_ACL |
                                         OBD_CONNECT_RMT_CLIENT |
                                         OBD_CONNECT_MDS_CAPA |
                                         OBD_CONNECT_OSS_CAPA |
                                         OBD_CONNECT_IBITS |
                                         OBD_CONNECT_MDS_MDS |
                                         OBD_CONNECT_FID |
                                         OBD_CONNECT_AT |
                                         OBD_CONNECT_FULL20 |
                                         OBD_CONNECT_64BITHASH;
                rc = obd_connect(env, &desc->cl_exp, mdc, &mdc->obd_uuid, ocd, NULL);
                OBD_FREE_PTR(ocd);
                if (rc) {
                        CERROR("target %s connect error %d\n",
                               mdc->obd_name, rc);
                } else {
                        /* set seq controller export for MDC0 if exists */
                        if (mc->mc_num == 0)
                                ms->ms_control_exp =
                                        class_export_get(desc->cl_exp);
                        rc = obd_fid_init(desc->cl_exp);
                        if (rc)
                                CERROR("fid init error %d \n", rc);
                        else {
                                /* obd notify mechanism */
                                mdc->obd_upcall.onu_owner = mc;
                                mdc->obd_upcall.onu_upcall = mdc_obd_update;
                        }
                }

                if (rc) {
                        obd_disconnect(desc->cl_exp);
                        desc->cl_exp = NULL;
                }
        }

        RETURN(rc);
}

/**
 * Delete mdc device.
 * Called when configuration command LCFG_CLEANUP is issued.
 *
 * This disconnects MDC OBD and cleanup it.
 */
static int mdc_obd_del(const struct lu_env *env, struct mdc_device *mc,
                       struct lustre_cfg *cfg)
{
        struct mdc_cli_desc *desc = &mc->mc_desc;
        const char *dev = lustre_cfg_string(cfg, 0);
        struct obd_device *mdc_obd = class_exp2obd(desc->cl_exp);
        struct obd_device *mdt_obd;
        int rc;

        ENTRY;

        CDEBUG(D_CONFIG, "Disconnect from %s\n",
               mdc_obd->obd_name);

        /* Set mdt_obd flags in shutdown. */
        mdt_obd = class_name2obd(dev);
        LASSERT(mdt_obd != NULL);
        if (mdc_obd) {
                mdc_obd->obd_no_recov = mdt_obd->obd_no_recov;
                mdc_obd->obd_force = mdt_obd->obd_force;
                mdc_obd->obd_fail = 0;
        }

        rc = obd_fid_fini(desc->cl_exp);
        if (rc)
                CERROR("Fid fini error %d\n", rc);

        obd_register_observer(mdc_obd, NULL);
        mdc_obd->obd_upcall.onu_owner = NULL;
        mdc_obd->obd_upcall.onu_upcall = NULL;
        rc = obd_disconnect(desc->cl_exp);
        if (rc) {
                CERROR("Target %s disconnect error %d\n",
                       mdc_obd->obd_name, rc);
        }
        class_manual_cleanup(mdc_obd);
        desc->cl_exp = NULL;

        RETURN(0);
}

/**
 * Process config command. Passed to the mdc from mdt.
 * Supports two commands only - LCFG_ADD_MDC and LCFG_CLEANUP
 */
static int mdc_process_config(const struct lu_env *env,
                              struct lu_device *ld,
                              struct lustre_cfg *cfg)
{
        struct mdc_device *mc = lu2mdc_dev(ld);
        int rc;

        ENTRY;
        switch (cfg->lcfg_command) {
        case LCFG_ADD_MDC:
                rc = mdc_obd_add(env, mc, cfg);
                break;
        case LCFG_CLEANUP:
                rc = mdc_obd_del(env, mc, cfg);
                break;
        default:
                rc = -EOPNOTSUPP;
        }
        RETURN(rc);
}

/**
 * lu_device_operations instance for mdc.
 */
static const struct lu_device_operations mdc_lu_ops = {
        .ldo_object_alloc   = mdc_object_alloc,
        .ldo_process_config = mdc_process_config
};

/**
 * Initialize proper easize and cookie size.
 */
void cmm_mdc_init_ea_size(const struct lu_env *env, struct mdc_device *mc,
                      int max_mdsize, int max_cookiesize)
{
        struct obd_device *obd = class_exp2obd(mc->mc_desc.cl_exp);

        obd->u.cli.cl_max_mds_easize = max_mdsize;
        obd->u.cli.cl_max_mds_cookiesize = max_cookiesize;
}

/** Start mdc device */
static int mdc_device_init(const struct lu_env *env, struct lu_device *ld,
                           const char *name, struct lu_device *next)
{
        return 0;
}

/** Stop mdc device. */
static struct lu_device *mdc_device_fini(const struct lu_env *env,
                                         struct lu_device *ld)
{
        ENTRY;
        RETURN (NULL);
}

/** Allocate new mdc device */
static struct lu_device *mdc_device_alloc(const struct lu_env *env,
                                          struct lu_device_type *ldt,
                                          struct lustre_cfg *cfg)
{
        struct lu_device  *ld;
        struct mdc_device *mc;
        ENTRY;

        OBD_ALLOC_PTR(mc);
        if (mc == NULL) {
                ld = ERR_PTR(-ENOMEM);
        } else {
                md_device_init(&mc->mc_md_dev, ldt);
                mc->mc_md_dev.md_ops = &mdc_md_ops;
                ld = mdc2lu_dev(mc);
                ld->ld_ops = &mdc_lu_ops;
                cfs_sema_init(&mc->mc_fid_sem, 1);
        }

        RETURN (ld);
}

/** Free mdc device */
static struct lu_device *mdc_device_free(const struct lu_env *env,
                                         struct lu_device *ld)
{
        struct mdc_device *mc = lu2mdc_dev(ld);

        LASSERTF(cfs_atomic_read(&ld->ld_ref) == 0,
                 "Refcount = %d\n", cfs_atomic_read(&ld->ld_ref));
        LASSERT(cfs_list_empty(&mc->mc_linkage));
        md_device_fini(&mc->mc_md_dev);
        OBD_FREE_PTR(mc);
        return NULL;
}

/** context key constructor/destructor: mdc_key_init, mdc_key_fini */
LU_KEY_INIT_FINI(mdc, struct mdc_thread_info);

/** context key: mdc_thread_key */
LU_CONTEXT_KEY_DEFINE(mdc, LCT_MD_THREAD|LCT_CL_THREAD);

/** type constructor/destructor: mdc_type_init, mdc_type_fini */
LU_TYPE_INIT_FINI(mdc, &mdc_thread_key);

static struct lu_device_type_operations mdc_device_type_ops = {
        .ldto_init = mdc_type_init,
        .ldto_fini = mdc_type_fini,

        .ldto_start = mdc_type_start,
        .ldto_stop  = mdc_type_stop,

        .ldto_device_alloc = mdc_device_alloc,
        .ldto_device_free  = mdc_device_free,

        .ldto_device_init = mdc_device_init,
        .ldto_device_fini = mdc_device_fini
};

struct lu_device_type mdc_device_type = {
        .ldt_tags     = LU_DEVICE_MD,
        .ldt_name     = LUSTRE_CMM_MDC_NAME,
        .ldt_ops      = &mdc_device_type_ops,
        .ldt_ctx_tags = LCT_MD_THREAD|LCT_CL_THREAD
};
/** @} */
