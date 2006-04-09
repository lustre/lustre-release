/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/cmm/cmm_device.c
 *  Lustre Cluster Metadata Manager (cmm)
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

#include <linux/module.h>

#include <linux/obd.h>
#include <linux/obd_class.h>

#include "cmm_internal.h"

#include <linux/lprocfs_status.h>
#include <linux/lustre_ver.h>

static struct obd_ops cmm_obd_device_ops = {
        .o_owner           = THIS_MODULE
};

static struct lu_device_operations cmm_lu_ops;

static inline int lu_device_is_cmm(struct lu_device *d)
{
	/*
	 * XXX for now. Tags in lu_device_type->ldt_something are needed.
	 */
	return ergo(d->ld_ops != NULL, d->ld_ops == &cmm_lu_ops);
}

static struct lu_device_operations cmm_lu_ops = {
	.ldo_object_alloc   = cmm_object_alloc,
	.ldo_object_init    = cmm_object_init,
	.ldo_object_free    = cmm_object_free,
	.ldo_object_release = cmm_object_release,
	.ldo_object_print   = cmm_object_print
};

static struct md_device_operations cmm_md_ops = {
        .mdo_root_get   = cmm_root_get,
        .mdo_mkdir      = cmm_mkdir,
//        .mdo_rename     = cmm_rename,
//        .mdo_link       = cmm_link,
//        .mdo_attr_get   = cmm_attr_get,
//        .mdo_attr_set   = cmm_attr_set,
//        .mdo_index_insert = cmm_index_insert,
//       .mdo_index_delete = cmm_index_delete,
//        .mdo_object_create = cmm_object_create,
};

#if 0
int mds_md_connect(struct obd_device *obd, char *md_name)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_handle conn = {0};
        unsigned long sec_flags = PTLRPC_SEC_FL_MDS;
        int rc, value;
        __u32 valsize;
        ENTRY;

        if (IS_ERR(mds->mds_md_obd))
                RETURN(PTR_ERR(mds->mds_md_obd));

        if (mds->mds_md_connected)
                RETURN(0);

        down(&mds->mds_md_sem);
        if (mds->mds_md_connected) {
                up(&mds->mds_md_sem);
                RETURN(0);
        }

        mds->mds_md_obd = class_name2obd(md_name);
        if (!mds->mds_md_obd) {
                CERROR("MDS cannot locate MD(LMV) %s\n",
                       md_name);
                mds->mds_md_obd = ERR_PTR(-ENOTCONN);
                GOTO(err_last, rc = -ENOTCONN);
        }

        rc = obd_connect(&conn, mds->mds_md_obd, &obd->obd_uuid, NULL,
                         OBD_OPT_MDS_CONNECTION);
        if (rc) {
                CERROR("MDS cannot connect to MD(LMV) %s (%d)\n",
                       md_name, rc);
                mds->mds_md_obd = ERR_PTR(rc);
                GOTO(err_last, rc);
        }
        mds->mds_md_exp = class_conn2export(&conn);
        if (mds->mds_md_exp == NULL)
                CERROR("can't get export!\n");

        rc = obd_register_observer(mds->mds_md_obd, obd);
        if (rc) {
                CERROR("MDS cannot register as observer of MD(LMV) %s, "
                       "rc = %d\n", md_name, rc);
                GOTO(err_discon, rc);
        }

        /* retrieve size of EA */
        rc = obd_get_info(mds->mds_md_exp, strlen("mdsize"),
                          "mdsize", &valsize, &value);
        if (rc)
                GOTO(err_reg, rc);

        if (value > mds->mds_max_mdsize)
                mds->mds_max_mdsize = value;

        /* find our number in LMV cluster */
        rc = obd_get_info(mds->mds_md_exp, strlen("mdsnum"),
                          "mdsnum", &valsize, &value);
        if (rc)
                GOTO(err_reg, rc);

        mds->mds_num = value;

        rc = obd_set_info(mds->mds_md_exp, strlen("inter_mds"),
                          "inter_mds", 0, NULL);
        if (rc)
                GOTO(err_reg, rc);

        if (mds->mds_mds_sec) {
                rc = obd_set_info(mds->mds_md_exp, strlen("sec"), "sec",
                                  strlen(mds->mds_mds_sec), mds->mds_mds_sec);
                if (rc)
                        GOTO(err_reg, rc);
        }

        rc = obd_set_info(mds->mds_md_exp, strlen("sec_flags"), "sec_flags",
                          sizeof(sec_flags), &sec_flags);
        if (rc)
                GOTO(err_reg, rc);

        mds->mds_md_connected = 1;
        up(&mds->mds_md_sem);
	RETURN(0);

err_reg:
        obd_register_observer(mds->mds_md_obd, NULL);
err_discon:
        obd_disconnect(mds->mds_md_exp, 0);
        mds->mds_md_exp = NULL;
        mds->mds_md_obd = ERR_PTR(rc);
err_last:
        up(&mds->mds_md_sem);
        return rc;
}
int mds_md_disconnect(struct obd_device *obd, int flags)
{
        struct mds_obd *mds = &obd->u.mds;
        int rc = 0;
        ENTRY;

        if (!mds->mds_md_connected)
                RETURN(0);

        down(&mds->mds_md_sem);
        if (!IS_ERR(mds->mds_md_obd) && mds->mds_md_exp != NULL) {
                LASSERT(mds->mds_md_connected);

                obd_register_observer(mds->mds_md_obd, NULL);

                if (flags & OBD_OPT_FORCE) {
                        struct obd_device *lmv_obd;
                        struct obd_ioctl_data ioc_data = { 0 };

                        lmv_obd = class_exp2obd(mds->mds_md_exp);
                        if (lmv_obd == NULL)
                                GOTO(out, rc = 0);

                        /*
                         * making disconnecting lmv stuff do not send anything
                         * to all remote MDSs from LMV. This is needed to
                         * prevent possible hanging with endless recovery, when
                         * MDS sends disconnect to already disconnected
                         * target. Probably this is wrong, but client does the
                         * same in --force mode and I do not see why can't we do
                         * it here. --umka.
                         */
                        lmv_obd->obd_no_recov = 1;
                        obd_iocontrol(IOC_OSC_SET_ACTIVE, mds->mds_md_exp,
                                      sizeof(ioc_data), &ioc_data, NULL);
                }

                /*
                 * if obd_disconnect() fails (probably because the export was
                 * disconnected by class_disconnect_exports()) then we just need
                 * to drop our ref.
                 */
                mds->mds_md_connected = 0;
                rc = obd_disconnect(mds->mds_md_exp, flags);
                if (rc)
                        class_export_put(mds->mds_md_exp);

        out:
                mds->mds_md_exp = NULL;
                mds->mds_md_obd = NULL;
        }
        up(&mds->mds_md_sem);
        RETURN(rc);
}
#endif
static int cmm_init(struct cmm_device *m,
                    struct lu_device_type *t, struct lustre_cfg *cfg)
{
        struct lu_device *lu_dev = cmm2lu_dev(m);
        struct obd_device * obd = NULL;
        char * child = lustre_cfg_string(cfg, 1);

        ENTRY;

	md_device_init(&m->cmm_md_dev, t);
        
        m->cmm_md_dev.md_ops = &cmm_md_ops;
	lu_dev->ld_ops = &cmm_lu_ops;
        
        /* get next layer */
        obd = class_name2obd(child);
        if (obd && obd->obd_lu_dev) {
                CDEBUG(D_INFO, "Child device is %s\n", child);
                m->cmm_child = lu2md_dev(obd->obd_lu_dev);
        } else {
                CDEBUG(D_INFO, "Child device %s not found\n", child);
        }

	return 0;
}

struct lu_device *cmm_device_alloc(struct lu_device_type *t,
                                   struct lustre_cfg *cfg)
{
        struct lu_device  *l;
        struct cmm_device *m;

        int err;
        
        ENTRY;
        
        OBD_ALLOC_PTR(m);
        if (m == NULL) {
                l = ERR_PTR(-ENOMEM);
        } else {
                err = cmm_init(m, t, cfg);
                if (err)
                        l = ERR_PTR(err);
                else
                        l = cmm2lu_dev(m);
        }

        EXIT;
        return l;
}

static void cmm_fini(struct lu_device *d)
{
	struct cmm_device *m = lu2cmm_dev(d);

	LASSERT(atomic_read(&d->ld_ref) == 0);
	md_device_fini(&m->cmm_md_dev);
}

void cmm_device_free(struct lu_device *m)
{
        cmm_fini(m);
        OBD_FREE_PTR(m);
}

int cmm_type_init(struct lu_device_type *t)
{
        return 0;
}

void cmm_type_fini(struct lu_device_type *t)
{
        return;
}

static struct lu_device_type_operations cmm_device_type_ops = {
        .ldto_init = cmm_type_init,
        .ldto_fini = cmm_type_fini,

        .ldto_device_alloc = cmm_device_alloc,
        .ldto_device_free  = cmm_device_free
};

static struct lu_device_type cmm_device_type = {
        .ldt_tags = LU_DEVICE_MD,
        .ldt_name = LUSTRE_CMM0_NAME,
        .ldt_ops  = &cmm_device_type_ops
};

struct lprocfs_vars lprocfs_cmm_obd_vars[] = {
        { 0 }
};

struct lprocfs_vars lprocfs_cmm_module_vars[] = {
        { 0 }
};

LPROCFS_INIT_VARS(cmm, lprocfs_cmm_module_vars, lprocfs_cmm_obd_vars);

static int __init cmm_mod_init(void)
{
        struct lprocfs_static_vars lvars;
        struct obd_type *type;
        int result;

        lprocfs_init_vars(cmm, &lvars);
        result = class_register_type(&cmm_obd_device_ops,
                                     lvars.module_vars, LUSTRE_CMM0_NAME);
        if (result == 0) {
                type = class_get_type(LUSTRE_CMM0_NAME);
                LASSERT(type != NULL);
                type->typ_lu = &cmm_device_type;
                result = type->typ_lu->ldt_ops->ldto_init(type->typ_lu);
                if (result != 0)
                        class_unregister_type(LUSTRE_CMM0_NAME);
        }
	return result;
}

static void __exit cmm_mod_exit(void)
{
        class_unregister_type(LUSTRE_CMM0_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Clustered Meta-data Manager Prototype ("LUSTRE_CMM0_NAME")");
MODULE_LICENSE("GPL");

cfs_module(cmm, "0.0.1", cmm_mod_init, cmm_mod_exit);
