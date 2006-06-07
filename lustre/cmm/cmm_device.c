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

#include <obd.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <lustre_ver.h>
#include "cmm_internal.h"
#include "mdc_internal.h"

static struct obd_ops cmm_obd_device_ops = {
        .o_owner           = THIS_MODULE
};

static struct lu_device_operations cmm_lu_ops;

static inline int lu_device_is_cmm(struct lu_device *d)
{
	/*
	 * XXX for now. Tags in lu_device_type->ldt_something are needed.
	 */
	return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &cmm_lu_ops);
}

static int cmm_root_get(const struct lu_context *ctx, struct md_device *md,
                 struct lu_fid *fid)
{
        struct cmm_device *cmm_dev = md2cmm_dev(md);

        return cmm_child_ops(cmm_dev)->mdo_root_get(ctx,
                                                    cmm_dev->cmm_child, fid);
}

static int cmm_config(const struct lu_context *ctxt, struct md_device *md,
               const char *name, void *buf, int size, int mode)
{
        struct cmm_device *cmm_dev = md2cmm_dev(md);
        int rc;
        ENTRY;
        rc = cmm_child_ops(cmm_dev)->mdo_config(ctxt, cmm_dev->cmm_child,
                                                    name, buf, size, mode);
        RETURN(rc);
}

static int cmm_statfs(const struct lu_context *ctxt, struct md_device *md,
               struct kstatfs *sfs) {
        struct cmm_device *cmm_dev = md2cmm_dev(md);
	int rc;

        ENTRY;
        rc = cmm_child_ops(cmm_dev)->mdo_statfs(ctxt,
                                                cmm_dev->cmm_child, sfs);
        RETURN (rc);
}

static struct md_device_operations cmm_md_ops = {
        .mdo_root_get       = cmm_root_get,
        .mdo_config         = cmm_config,
        .mdo_statfs         = cmm_statfs,
};

extern struct lu_device_type mdc_device_type;

/* --- cmm_lu_operations --- */
/* add new MDC to the CMM, create MDC lu_device and connect it to mdc_obd */
static int cmm_add_mdc(const struct lu_context *ctx,
                       struct cmm_device * cm, struct lustre_cfg *cfg)
{
        struct lu_device_type *ldt = &mdc_device_type;
        struct lu_device *ld;
        struct mdc_device *mc;
#ifdef CMM_CODE
        struct mdc_device *tmp;
        __u32 mdc_num;
#endif
        int rc;
        ENTRY;

#ifdef CMM_CODE
        /* find out that there is no such mdc */
        LASSERT(lustre_cfg_string(cfg, 2));
        mdc_num = simple_strtol(lustre_cfg_string(cfg, 2), NULL, 10);
        spin_lock(&cm->cmm_tgt_guard);
        list_for_each_entry_safe(mc, tmp, &cm->cmm_targets,
                                 mc_linkage) {
                if (mc->mc_num == mdc_num)
                        RETURN(-EEXIST);
        }
        spin_unlock(&cm->cmm_tgt_guard);
#endif        
        ld = ldt->ldt_ops->ldto_device_alloc(ctx, ldt, cfg);
        ld->ld_site = cmm2lu_dev(cm)->ld_site;

        rc = ldt->ldt_ops->ldto_device_init(ctx, ld, NULL);
        if (rc)
                ldt->ldt_ops->ldto_device_free(ctx, ld);

        /* pass config to the just created MDC */
        rc = ld->ld_ops->ldo_process_config(ctx, ld, cfg);
        if (rc == 0) {
                mc = lu2mdc_dev(ld);
#ifdef CMM_CODE
                spin_lock(&cm->cmm_tgt_guard);
#endif
                list_add_tail(&mc->mc_linkage, &cm->cmm_targets);
                cm->cmm_tgt_count++;
#ifdef CMM_CODE
                spin_unlock(&cm->cmm_tgt_guard);
#endif                
                lu_device_get(cmm2lu_dev(cm));
        }
        RETURN(rc);
}


static int cmm_process_config(const struct lu_context *ctx,
                              struct lu_device *d, struct lustre_cfg *cfg)
{
        struct cmm_device *m = lu2cmm_dev(d);
        struct lu_device *next = md2lu_dev(m->cmm_child);
        int err;

        switch(cfg->lcfg_command) {
        case LCFG_ADD_MDC:
                err = cmm_add_mdc(ctx, m, cfg);
                break;
        case LCFG_SETUP:
        {
                const char *index = lustre_cfg_string(cfg, 2);
                LASSERT(index);
                m->cmm_local_num = simple_strtol(index, NULL, 10);
                /* no break; to pass cfg further */
        }
        default:
                err = next->ld_ops->ldo_process_config(ctx, next, cfg);
        }
        RETURN(err);
}

static struct lu_device_operations cmm_lu_ops = {
	.ldo_object_alloc   = cmm_object_alloc,
        .ldo_process_config = cmm_process_config
};

/* --- lu_device_type operations --- */

static struct lu_device *cmm_device_alloc(const struct lu_context *ctx,
                                   struct lu_device_type *t,
                                   struct lustre_cfg *cfg)
{
        struct lu_device  *l;
        struct cmm_device *m;

        ENTRY;

        OBD_ALLOC_PTR(m);
        if (m == NULL) {
                l = ERR_PTR(-ENOMEM);
        } else {
                md_device_init(&m->cmm_md_dev, t);
                m->cmm_md_dev.md_ops = &cmm_md_ops;
	        l = cmm2lu_dev(m);
                l->ld_ops = &cmm_lu_ops;
        }

        EXIT;
        return l;
}

static void cmm_device_free(const struct lu_context *ctx, struct lu_device *d)
{
        struct cmm_device *m = lu2cmm_dev(d);

	LASSERT(atomic_read(&d->ld_ref) == 0);
	md_device_fini(&m->cmm_md_dev);
        OBD_FREE_PTR(m);
}

static int cmm_type_init(struct lu_device_type *t)
{
        return 0;
}

static void cmm_type_fini(struct lu_device_type *t)
{
        return;
}

static int cmm_device_init(const struct lu_context *ctx,
                           struct lu_device *d, struct lu_device *next)
{
        struct cmm_device *m = lu2cmm_dev(d);
        int err = 0;

        ENTRY;
        
#ifdef CMM_CODE
        spin_lock_init(&m->cmm_tgt_guard);
#endif
        INIT_LIST_HEAD(&m->cmm_targets);
        m->cmm_tgt_count = 0;
        m->cmm_child = lu2md_dev(next);

        RETURN(err);
}

static struct lu_device *cmm_device_fini(const struct lu_context *ctx,
                                         struct lu_device *ld)
{
	struct cmm_device *cm = lu2cmm_dev(ld);
        struct mdc_device *mc, *tmp;
        ENTRY;

        /* finish all mdc devices */
        list_for_each_entry_safe(mc, tmp, &cm->cmm_targets, mc_linkage) {
                struct lu_device *ld_m = mdc2lu_dev(mc);

                list_del(&mc->mc_linkage);
                lu_device_put(cmm2lu_dev(cm));
                ld->ld_type->ldt_ops->ldto_device_fini(ctx, ld_m);
                ld->ld_type->ldt_ops->ldto_device_free(ctx, ld_m);
        }

        EXIT;
        return md2lu_dev(cm->cmm_child);
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
        return class_register_type(&cmm_obd_device_ops, NULL, lvars.module_vars,
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
