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
#include "mdc_internal.h"

static struct lu_device_operations mdc_lu_ops;

static inline int lu_device_is_mdc(struct lu_device *ld)
{
	/*
	 * XXX for now. Tags in lu_device_type->ldt_something are needed.
	 */
	return ergo(ld != NULL && ld->ld_ops != NULL,
                    ld->ld_ops == &mdc_lu_ops);
}

static int mdc_root_get(const struct lu_context *ctx, struct md_device *md,
                        struct lu_fid *fid)
{
        //struct mdc_device *mdc_dev = md2mdc_dev(md);

        return -EOPNOTSUPP;
}

static int mdc_config(const struct lu_context *ctx,
                      struct md_device *md, const char *name,
                      void *buf, int size, int mode)
{
        //struct mdc_device *mdc_dev = md2mdc_dev(md);
        int rc;
        ENTRY;
        rc = -EOPNOTSUPP;
        RETURN(rc);
}

static int mdc_statfs(const struct lu_context *ctx,
                      struct md_device *md, struct kstatfs *sfs) {
        //struct mdc_device *mdc_dev = md2mdc_dev(md);
	int rc;

        ENTRY;
        rc = -EOPNOTSUPP;
        RETURN (rc);
}

static struct md_device_operations mdc_md_ops = {
        .mdo_root_get       = mdc_root_get,
        .mdo_config         = mdc_config,
        .mdo_statfs         = mdc_statfs,
};

static int mdc_add_obd(struct mdc_device *mc, struct lustre_cfg *cfg)
{
        struct mdc_cli_desc *desc = &mc->mc_desc;
        struct obd_device *mdc, *mdt;
        const char *srv = lustre_cfg_string(cfg, 0);
        const char *uuid_str = lustre_cfg_string(cfg, 1);
        const char *index = lustre_cfg_string(cfg, 2);
        struct obd_uuid uuid;
        int rc = 0;

        //find mdt obd to get group uuid
        mdt = class_name2obd(srv);
        if (mdt == NULL) {
                CERROR("No such OBD %s\n", srv);
                LBUG();
        }
        obd_str2uuid(&uuid, uuid_str);
        mdc = class_find_client_obd(&uuid, LUSTRE_MDC_NAME, &mdt->obd_uuid);
        if (!mdc) {
                CERROR("Cannot find MDC OBD connected to %s\n", uuid_str);
                rc = -ENOENT;
        } else if (!mdc->obd_set_up) {
                CERROR("target %s not set up\n", mdc->obd_name);
                rc = -EINVAL;
        } else {
                struct lustre_handle conn = {0, };

                CDEBUG(D_CONFIG, "connect to %s(%s)\n",
                       mdc->obd_name, mdc->obd_uuid.uuid);

                rc = obd_connect(&conn, mdc, &mdt->obd_uuid, NULL);

                if (rc) {
                        CERROR("target %s connect error %d\n",
                               mdc->obd_name, rc);
                } else {
                        desc->cl_exp = class_conn2export(&conn);
                        mc->mc_num = simple_strtol(index, NULL, 10);
                }
        }

        RETURN(rc);
}

static int mdc_process_config(const struct lu_context *ctx,
                              struct lu_device *ld, struct lustre_cfg *cfg)
{
        struct mdc_device *mc = lu2mdc_dev(ld);
        int rc;

        ENTRY;
        switch (cfg->lcfg_command) {
        case LCFG_ADD_MDC:
                rc = mdc_add_obd(mc, cfg);
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
#if 0
static int mdc_device_connect(struct mdc_device *mc)
{
        struct mdc_cli_desc *desc = &mc->mc_desc;
        struct obd_device *obd = mdc2lu_dev(mc)->ld_obd;
        //struct client_obd *cli = &obd->u.cli;
        struct obd_uuid mdc_uuid = { "MDT_MDC_UUID" };
        struct lustre_handle conn = { 0 };
        struct obd_import *imp = desc->cl_import;
        int rc;

        /* obd_connect */
        rc = class_connect(&conn, obd, &mdc_uuid);
        imp->imp_dlm_handle = conn;

        rc = ptlrpc_init_import(imp);
        if (rc != 0)
                RETURN(rc);

        rc = ptlrpc_connect_import(imp, NULL);
        if (rc != 0) {
                LASSERT (imp->imp_state == LUSTRE_IMP_DISCON);
                RETURN(rc);
        }

        ptlrpc_pinger_add_import(imp);
        //TODO other initializations
        LASSERT(imp->imp_connection);

        RETURN(0);
}

static int mdc_device_init(const struct lu_context *ctx,
                           struct lu_device *ld, struct lu_device *next)
{
        struct mdc_device *mc = lu2mdc_dev(ld);
        struct mdc_cli_desc *desc = &mc->mc_desc;
        struct obd_device *obd = ld->ld_obd;
        struct client_obd *cli = &obd->u.cli;
        struct obd_import *imp;
        int rq_portal, rp_portal, connect_op;
        int rc = 0;

        ENTRY;
        //alloc rpc_lock
        ptlrpcd_addref();

        rq_portal = MDS_REQUEST_PORTAL;
        rp_portal = MDC_REPLY_PORTAL;
        connect_op = MDS_CONNECT;

        sema_init(&cli->cl_sem, 1);
        cli->cl_conn_count = 0;

        rc = ldlm_get_ref();
        if (rc != 0) {
                CERROR("ldlm_get_ref failed: %d\n", rc);
                GOTO(err, rc);
        }

        ptlrpc_init_client(rq_portal, rp_portal, obd->obd_type->typ_name,
                           &desc->cl_ldlm_client);

        imp = class_new_import(obd);
        if (imp == NULL)
                GOTO(err_ldlm, rc = -ENOENT);

        imp->imp_client = &desc->cl_ldlm_client;
        imp->imp_connect_op = connect_op;
        imp->imp_initial_recov = 1;
        imp->imp_initial_recov_bk = 0;
        INIT_LIST_HEAD(&imp->imp_pinger_chain);
        cli->cl_target_uuid = desc->cl_target_uuid;
        class_import_put(imp);
        rc = client_import_add_conn(imp, &desc->cl_server_uuid, 1);
        if (rc) {
                CERROR("can't add initial connection\n");
                GOTO(err_import, rc);
        }

        desc->cl_import = imp;
        cli->cl_import = imp;

        rc = mdc_device_connect(mc);

        RETURN(0);

err_import:
        class_destroy_import(imp);
err_ldlm:
        ldlm_put_ref(0);
err:
        //free rpc_lock
        ptlrpcd_decref();
        RETURN(rc);
}

static struct lu_device *mdc_device_fini(const struct lu_context *ctx,
                                         struct lu_device *ld)
{
	struct mdc_device *mc = lu2mdc_dev(ld);
        struct mdc_cli_desc *desc = &mc->mc_desc;

        ENTRY;

        class_destroy_import(desc->cl_import);
        //TODO: force param
        ldlm_put_ref(1);
        ptlrpcd_decref();

        RETURN (NULL);
}

struct lu_device *mdc_device_alloc(const struct lu_context *ctx,
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
                memcpy(mc->mc_desc.cl_server_uuid.uuid,
                       lustre_cfg_buf(cfg, 2),
                       min_t(unsigned int, LUSTRE_CFG_BUFLEN(cfg, 2),
                             sizeof(struct obd_uuid)));
                memcpy(mc->mc_desc.cl_target_uuid.uuid,
                       lustre_cfg_buf(cfg, 1),
                       min_t(unsigned int, LUSTRE_CFG_BUFLEN(cfg, 1),
                             sizeof(struct obd_uuid)));

        }

        RETURN (ld);
}
#endif
static int mdc_device_init(const struct lu_context *ctx,
                           struct lu_device *ld, struct lu_device *next)
{
        /* struct mdc_device *mc = lu2mdc_dev(ld); */
        int rc = 0;

        ENTRY;

        RETURN(rc);
}

static struct lu_device *mdc_device_fini(const struct lu_context *ctx,
                                         struct lu_device *ld)
{
	/* struct mdc_device *mc = lu2mdc_dev(ld); */

        ENTRY;

        RETURN (NULL);
}

struct lu_device *mdc_device_alloc(const struct lu_context *ctx,
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
        }

        RETURN (ld);
}
void mdc_device_free(const struct lu_context *ctx, struct lu_device *ld)
{
        struct mdc_device *mc = lu2mdc_dev(ld);

	LASSERT(atomic_read(&ld->ld_ref) == 0);
	md_device_fini(&mc->mc_md_dev);
        OBD_FREE_PTR(mc);
}

int mdc_type_init(struct lu_device_type *ldt)
{
        return 0;
}

void mdc_type_fini(struct lu_device_type *ldt)
{
        return;
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
        .ldt_tags = LU_DEVICE_MD,
        .ldt_name = LUSTRE_MDC0_NAME,
        .ldt_ops  = &mdc_device_type_ops
};
#if 0
static struct obd_ops mdc0_obd_device_ops = {
        .o_owner           = THIS_MODULE
};

struct lprocfs_vars lprocfs_mdc0_obd_vars[] = {
        { 0 }
};

struct lprocfs_vars lprocfs_mdc0_module_vars[] = {
        { 0 }
};

LPROCFS_INIT_VARS(mdc0, lprocfs_mdc0_module_vars, lprocfs_mdc0_obd_vars);

static int __init mdc0_mod_init(void)
{
        struct lprocfs_static_vars lvars;

        printk(KERN_INFO "Lustre: Metadata Client; info@clusterfs.com\n");

        lprocfs_init_vars(mdc0, &lvars);
        return class_register_type(&mdc0_obd_device_ops, NULL,
                                   lvars.module_vars, LUSTRE_MDC0_NAME,
                                   &mdc_device_type);
}

static void __exit mdc0_mod_exit(void)
{
        class_unregister_type(LUSTRE_MDC0_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Metadata Client Prototype ("LUSTRE_MDC0_NAME")");
MODULE_LICENSE("GPL");

cfs_module(mdc, "0.0.1", mdc0_mod_init, mdc0_mod_exit);
#endif
