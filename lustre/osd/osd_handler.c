/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/osd/osd_handler.c
 *  Top-level entry points into osd module
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
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

/* LUSTRE_VERSION_CODE */
#include <linux/lustre_ver.h>
/*
 * struct OBD_{ALLOC,FREE}*()
 * OBD_FAIL_CHECK
 */
#include <linux/obd_support.h>
/* struct ptlrpc_thread */
#include <linux/lustre_net.h>
/* LUSTRE_OSD0_NAME */
#include <linux/obd.h>
/* class_register_type(), class_unregister_type(), class_get_type() */
#include <linux/obd_class.h>
#include <linux/lustre_disk.h>

#include "osd_internal.h"

static int   lu_device_is_osd  (const struct lu_device *d);
static void  osd_mod_exit      (void) __exit;
static int   osd_mod_init      (void) __init;
static void *osd_thread_init   (struct ptlrpc_thread *t);
static void  osd_thread_fini   (struct ptlrpc_thread *t, void *data);
static int   osd_type_init     (struct lu_device_type *t);
static void  osd_type_fini     (struct lu_device_type *t);
static int   osd_object_init   (struct lu_object *l);
static void  osd_object_release(struct lu_object *l);
static int   osd_object_print  (struct seq_file *f, const struct lu_object *o);
static void  osd_device_free   (struct lu_device *m);
static void  osd_device_fini   (struct osd_device *d);
static int   osd_device_init   (struct osd_device *m, struct lu_device_type *t,
                                struct lustre_cfg *cfg);

static struct lu_object  *osd_object_alloc(struct lu_device *d);
static struct osd_object *osd_obj         (const struct lu_object *o);
static struct osd_device *osd_dev         (const struct lu_device *d);
static struct lu_device  *osd_device_alloc(struct lu_device_type *t,
                                           struct lustre_cfg *cfg);


static struct lu_device_type_operations osd_device_type_ops;
static struct lu_device_type            osd_device_type;
static struct ptlrpc_thread_key         osd_thread_key;
static struct obd_ops                   osd_obd_device_ops;
static struct lprocfs_vars              lprocfs_osd_module_vars[];
static struct lprocfs_vars              lprocfs_osd_obd_vars[];
static struct lu_device_operations      osd_lu_ops;

/*
 * OSD object methods.
 */

static struct lu_object *osd_object_alloc(struct lu_device *d)
{
        struct osd_object *mo;

        OBD_ALLOC_PTR(mo);
        if (mo != NULL) {
                struct lu_object *l;

                l = &mo->oo_dt.do_lu;
                lu_object_init(l, NULL, d);
                return l;
        } else
                return NULL;
}

static int osd_object_init(struct lu_object *l)
{
        struct osd_device  *d = osd_dev(l->lo_dev);
        struct osd_object  *o = osd_obj(l);
        struct lu_fid      *f = lu_object_fid(l);

        /*
         * use object index to locate dentry/inode by fid.
         */
        return 0;
}

static void osd_object_free(struct lu_object *l)
{
        struct osd_object  *o = osd_obj(l);

        if (o->oo_dentry != NULL)
                dput(o->oo_dentry);
}

static void osd_object_delete(struct lu_object *l)
{
}

static void osd_object_release(struct lu_object *l)
{
}

static int osd_object_print(struct seq_file *f, const struct lu_object *l)
{
        struct osd_object  *o = osd_obj(l);

        return seq_printf(f, LUSTRE_OSD0_NAME"-object@%p(d:%p)",
                          o, o->oo_dentry);
}

struct osd_thread_info {
};

/*
 * ptlrpc_key call-backs.
 */
static void *osd_thread_init(struct ptlrpc_thread *t)
{
        struct osd_thread_info *info;

        return OBD_ALLOC_PTR(info) ? : ERR_PTR(-ENOMEM);
}

static void osd_thread_fini(struct ptlrpc_thread *t, void *data)
{
        struct osd_thread_info *info = data;
        OBD_FREE_PTR(info);
}


static struct ptlrpc_thread_key osd_thread_key = {
        .ptk_init = osd_thread_init,
        .ptk_fini = osd_thread_fini
};

/*
 * OSD device type methods
 */
static int osd_type_init(struct lu_device_type *t)
{
        return ptlrpc_thread_key_register(&osd_thread_key);
}

static void osd_type_fini(struct lu_device_type *t)
{
}

static int osd_device_init(struct osd_device *d,
                           struct lu_device_type *t, struct lustre_cfg *cfg)
{
        struct lustre_mount_info *lmi = NULL;
        struct vfsmount *mnt = NULL;
        char *disk = lustre_cfg_string(cfg, 0);
        char *name = lustre_cfg_string(cfg, 1);
        
        lu_device_init(&d->od_dt_dev.dd_lu_dev, t);
        d->od_dt_dev.dd_lu_dev.ld_ops = &osd_lu_ops;
        
        if (!disk) {
                CERROR("No obd device for OSD!\n");
#if 1
        } else {

                lmi = server_get_mount(disk);
                if (lmi) {
                        /* We already mounted in lustre_fill_super */
                        struct lustre_sb_info *lsi = s2lsi(lmi->lmi_sb);
                        struct lustre_disk_data *ldd = lsi->lsi_ldd;
                        struct lustre_mount_data *lmd = lsi->lsi_lmd;
                        
                        CDEBUG(D_INFO, "%s info: device=%s,\n opts=%s,\n",
                                        name, lmd->lmd_dev, ldd->ldd_mount_opts);
                        mnt = lmi->lmi_mnt;
                        
                } else {
                        CERROR("Cannot get mount info for %s!\n", disk);
                }
#endif
        }
        // to be continued...

        if (lmi) {
                server_put_mount(disk, mnt);
        }
        return 0;
}

static void osd_device_fini(struct osd_device *d)
{
        /*
         * umount file system.
         */
        lu_device_fini(&d->od_dt_dev.dd_lu_dev);
}

static struct lu_device *osd_device_alloc(struct lu_device_type *t,
                                          struct lustre_cfg *cfg)
{
        struct lu_device  *l;
        struct osd_device *o;

        OBD_ALLOC_PTR(o);
        if (o != NULL) {
                int result;

                l = &o->od_dt_dev.dd_lu_dev;
                result = osd_device_init(o, t, cfg);
                if (result != 0) {
                        osd_device_fini(o);
                        l = ERR_PTR(result);
                }
        } else
                l = ERR_PTR(-ENOMEM);
        
        return l;
}

static void osd_device_free(struct lu_device *d)
{
        struct osd_device *o = osd_dev(d);

        osd_device_fini(o);
        OBD_FREE_PTR(o);
}

/*
 * Helpers.
 */

static int lu_device_is_osd(const struct lu_device *d)
{
        /*
         * XXX for now. Tags in lu_device_type->ldt_something are needed.
         */
        return ergo(d->ld_ops != NULL, d->ld_ops == &osd_lu_ops);
}

static struct osd_object *osd_obj(const struct lu_object *o)
{
        LASSERT(lu_device_is_osd(o->lo_dev));
        return container_of(o, struct osd_object, oo_dt.do_lu);
}

static struct osd_device *osd_dev(const struct lu_device *d)
{
        LASSERT(lu_device_is_osd(d));
        return container_of(d, struct osd_device, od_dt_dev.dd_lu_dev);
}

static struct lu_device_operations osd_lu_ops = {
        .ldo_object_alloc   = osd_object_alloc,
        .ldo_object_init    = osd_object_init,
        .ldo_object_free    = osd_object_free,
        .ldo_object_release = osd_object_release,
        .ldo_object_delete  = osd_object_delete,
        .ldo_object_print   = osd_object_print
};

static struct lu_device_type_operations osd_device_type_ops = {
        .ldto_init = osd_type_init,
        .ldto_fini = osd_type_fini,

        .ldto_device_alloc = osd_device_alloc,
        .ldto_device_free  = osd_device_free
};

static struct lu_device_type osd_device_type = {
        .ldt_tags = LU_DEVICE_DT,
        .ldt_name = LUSTRE_OSD0_NAME,
        .ldt_ops  = &osd_device_type_ops
};

/*
 * lprocfs legacy support.
 */
static struct lprocfs_vars lprocfs_osd_obd_vars[] = {
        { 0 }
};

static struct lprocfs_vars lprocfs_osd_module_vars[] = {
        { 0 }
};

static struct obd_ops osd_obd_device_ops = {
        .o_owner = THIS_MODULE
};

LPROCFS_INIT_VARS(osd, lprocfs_osd_module_vars, lprocfs_osd_obd_vars);

static int __init osd_mod_init(void)
{
        struct lprocfs_static_vars lvars;
        struct obd_type *type;
        int result;

        lprocfs_init_vars(osd, &lvars);
        result = class_register_type(&osd_obd_device_ops,
                                     lvars.module_vars, LUSTRE_OSD0_NAME);
        if (result == 0) {
                type = class_get_type(LUSTRE_OSD0_NAME);
                LASSERT(type != NULL);
                type->typ_lu = &osd_device_type;
                result = type->typ_lu->ldt_ops->ldto_init(type->typ_lu);
                if (result != 0)
                        class_unregister_type(LUSTRE_OSD0_NAME);
        }
        return result;
}

static void __exit osd_mod_exit(void)
{
        class_unregister_type(LUSTRE_OSD0_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Object Storage Device ("LUSTRE_OSD0_NAME")");
MODULE_LICENSE("GPL");

cfs_module(osd, "0.0.2", osd_mod_init, osd_mod_exit);
