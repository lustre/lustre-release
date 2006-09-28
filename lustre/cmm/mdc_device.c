/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/cmm/cmm_mdc.c
 *  Lustre Metadata Client (mdc)
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Mike Pershin <tappro@clusterfs.com>
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

#include <obd.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <lustre_ver.h>
#include "cmm_internal.h"
#include "mdc_internal.h"

static struct lu_device_operations mdc_lu_ops;

static inline int lu_device_is_mdc(struct lu_device *ld)
{
	return ergo(ld != NULL && ld->ld_ops != NULL,
                    ld->ld_ops == &mdc_lu_ops);
}

static struct md_device_operations mdc_md_ops = { 0 };

static int mdc_obd_update(struct obd_device *host,
                          struct obd_device *watched,
                          enum obd_notify_event ev, void *owner)
{
        struct mdc_device *mc = owner;
        int rc = 0;
        ENTRY;

        LASSERT(mc != NULL);
        CDEBUG(D_CONFIG, "notify %s ev=%d\n", watched->obd_name, ev);
        RETURN(rc);
}
/* MDC OBD is set up already and connected to the proper MDS
 * mdc_add_obd() find that obd by uuid and connects to it.
 * Local MDT uuid is used for connection
 * */
static int mdc_add_obd(const struct lu_env *env,
                       struct mdc_device *mc, struct lustre_cfg *cfg)
{
        struct mdc_cli_desc *desc = &mc->mc_desc;
        struct obd_device *mdc;
        const char *uuid_str = lustre_cfg_string(cfg, 1);
        const char *index = lustre_cfg_string(cfg, 2);
        const char *mdc_uuid_str = lustre_cfg_string(cfg, 4);
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
                struct lustre_handle *conn = &desc->cl_conn;
                struct obd_connect_data *ocd;

                CDEBUG(D_CONFIG, "connect to %s(%s)\n",
                       mdc->obd_name, mdc->obd_uuid.uuid);

                OBD_ALLOC_PTR(ocd);
                if (!ocd)
                        RETURN(-ENOMEM);
                /* The connection between MDS must be local */
                ocd->ocd_connect_flags |= OBD_CONNECT_LCL_CLIENT;
                rc = obd_connect(env, conn, mdc, &mdc->obd_uuid, ocd);
                OBD_FREE_PTR(ocd);
                if (rc) {
                        CERROR("target %s connect error %d\n",
                               mdc->obd_name, rc);
                } else {
                        desc->cl_exp = class_conn2export(conn);

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

static int mdc_del_obd(struct mdc_device *mc)
{
        struct mdc_cli_desc *desc = &mc->mc_desc;
        struct obd_device *mdc_obd = class_exp2obd(desc->cl_exp);
        int rc;

        ENTRY;

        CDEBUG(D_CONFIG, "disconnect from %s\n",
               mdc_obd->obd_name);

        rc = obd_fid_fini(desc->cl_exp);
        if (rc)
                CERROR("fid init error %d \n", rc);

        obd_register_observer(mdc_obd, NULL);

        /*TODO: Give the same shutdown flags as we have */
        /*
        desc->cl_exp->exp_obd->obd_force = mdt_obd->obd_force;
        desc->cl_exp->exp_obd->obd_fail = mdt_obd->obd_fail;
        */
        rc = obd_disconnect(desc->cl_exp);
        if (rc) {
                CERROR("target %s disconnect error %d\n",
                       mdc_obd->obd_name, rc);
        }
        class_manual_cleanup(mdc_obd);
        desc->cl_exp = NULL;

        RETURN(rc);
}

static int mdc_process_config(const struct lu_env *env,
                              struct lu_device *ld, struct lustre_cfg *cfg)
{
        struct mdc_device *mc = lu2mdc_dev(ld);
        int rc;

        ENTRY;
        switch (cfg->lcfg_command) {
        case LCFG_ADD_MDC:
                rc = mdc_add_obd(env, mc, cfg);
                break;
        default:
                rc = -EOPNOTSUPP;
        }
        RETURN(rc);
}

static struct lu_device_operations mdc_lu_ops = {
	.ldo_object_alloc   = mdc_object_alloc,
        .ldo_process_config = mdc_process_config
};

static int mdc_device_init(const struct lu_env *env,
                           struct lu_device *ld, struct lu_device *next)
{
        return 0;
}

static struct lu_device *mdc_device_fini(const struct lu_env *env,
                                         struct lu_device *ld)
{
	struct mdc_device *mc = lu2mdc_dev(ld);

        ENTRY;

        mdc_del_obd(mc);

        RETURN (NULL);
}

struct lu_device *mdc_device_alloc(const struct lu_env *env,
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
                mc->mc_md_dev.md_ops =  &mdc_md_ops;
	        ld = mdc2lu_dev(mc);
                ld->ld_ops = &mdc_lu_ops;
        }

        RETURN (ld);
}
void mdc_device_free(const struct lu_env *env, struct lu_device *ld)
{
        struct mdc_device *mc = lu2mdc_dev(ld);

	LASSERT(atomic_read(&ld->ld_ref) == 0);
        LASSERT(list_empty(&mc->mc_linkage));
	md_device_fini(&mc->mc_md_dev);
        OBD_FREE_PTR(mc);
}

/* context key constructor/destructor */

static void *mdc_key_init(const struct lu_context *ctx,
                          struct lu_context_key *key)
{
        struct mdc_thread_info *info;

        CLASSERT(CFS_PAGE_SIZE >= sizeof *info);
        OBD_ALLOC_PTR(info);
        if (info == NULL)
                info = ERR_PTR(-ENOMEM);
        return info;
}

static void mdc_key_fini(const struct lu_context *ctx,
                         struct lu_context_key *key, void *data)
{
        struct mdc_thread_info *info = data;
        OBD_FREE_PTR(info);
}

struct lu_context_key mdc_thread_key = {
        .lct_tags = LCT_MD_THREAD|LCT_CL_THREAD,
        .lct_init = mdc_key_init,
        .lct_fini = mdc_key_fini
};

int mdc_type_init(struct lu_device_type *ldt)
{
        return lu_context_key_register(&mdc_thread_key);
}

void mdc_type_fini(struct lu_device_type *ldt)
{
        lu_context_key_degister(&mdc_thread_key);
}

static struct lu_device_type_operations mdc_device_type_ops = {
        .ldto_init = mdc_type_init,
        .ldto_fini = mdc_type_fini,

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

