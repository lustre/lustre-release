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

static struct md_device_operations cmm_md_ops = {
        .mdo_root_get   = cmm_root_get,
        .mdo_config     = cmm_config,
        .mdo_statfs     = cmm_statfs,
        .mdo_mkdir      = cmm_mkdir,
        .mdo_attr_get   = cmm_attr_get,
//        .mdo_rename     = cmm_rename,
//        .mdo_link       = cmm_link,
//        .mdo_attr_get   = cmm_attr_get,
//        .mdo_attr_set   = cmm_attr_set,
//        .mdo_index_insert = cmm_index_insert,
//       .mdo_index_delete = cmm_index_delete,
//        .mdo_object_create = cmm_object_create,
};

static int cmm_device_init(struct lu_device *d, const char *top)
{
        struct cmm_device *m = lu2cmm_dev(d);
        struct lu_device *next;
        int err;

        ENTRY;

        LASSERT(m->cmm_child);
        next = md2lu_dev(m->cmm_child);

        LASSERT(next->ld_type->ldt_ops->ldto_device_init != NULL);
        err = next->ld_type->ldt_ops->ldto_device_init(next, top);
        RETURN(err);
}

static void cmm_device_fini(struct lu_device *d)
{
	struct cmm_device *m = lu2cmm_dev(d);
        struct lu_device *next;

	LASSERT(m->cmm_child);
        next = md2lu_dev(m->cmm_child);

        LASSERT(next->ld_type->ldt_ops->ldto_device_fini != NULL);
        next->ld_type->ldt_ops->ldto_device_fini(next);
}

static struct lu_device_operations cmm_lu_ops = {
	.ldo_object_alloc   = cmm_object_alloc,
	.ldo_object_init    = cmm_object_init,
	.ldo_object_free    = cmm_object_free,
	.ldo_object_release = cmm_object_release,
	.ldo_object_print   = cmm_object_print
};

struct lu_device *cmm_device_alloc(struct lu_device_type *t,
                                   struct lustre_cfg *cfg)
{
        struct lu_device  *l;
        struct cmm_device *m;
        struct obd_device * obd = NULL;
        char * child = lustre_cfg_string(cfg, 1);

        ENTRY;

        OBD_ALLOC_PTR(m);
        if (m == NULL) {
                l = ERR_PTR(-ENOMEM);
        } else {
                md_device_init(&m->cmm_md_dev, t);
                m->cmm_md_dev.md_ops = &cmm_md_ops;
	        l = cmm2lu_dev(m);
                l->ld_ops = &cmm_lu_ops;

                /* get next layer */
                obd = class_name2obd(child);
                if (obd && obd->obd_lu_dev) {
                        CDEBUG(D_INFO, "Child device is %s\n", child);
                        m->cmm_child = lu2md_dev(obd->obd_lu_dev);
                } else {
                        CDEBUG(D_INFO, "Child device %s not found\n", child);
                        l = ERR_PTR(-EINVAL);
                }
        }

        EXIT;
        return l;
}

void cmm_device_free(struct lu_device *d)
{
        struct cmm_device *m = lu2cmm_dev(d);

	LASSERT(atomic_read(&d->ld_ref) == 0);
	md_device_fini(&m->cmm_md_dev);
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
        .ldto_device_free  = cmm_device_free,

        .ldto_device_init = cmm_device_init,
        .ldto_device_fini = cmm_device_fini
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

        printk(KERN_INFO "Lustre: Clustered Metadata Manager; info@clusterfs.com\n");

        lprocfs_init_vars(cmm, &lvars);
        return class_register_type(&cmm_obd_device_ops, lvars.module_vars,
                                   LUSTRE_CMM0_NAME, &cmm_device_type);
}

static void __exit cmm_mod_exit(void)
{
        class_unregister_type(LUSTRE_CMM0_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Clustered Meta-data Manager Prototype ("LUSTRE_CMM0_NAME")");
MODULE_LICENSE("GPL");

cfs_module(cmm, "0.0.3", cmm_mod_init, cmm_mod_exit);
