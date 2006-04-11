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

static int   osd_root_get      (struct dt_device *dev, struct lu_fid *f);

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
static void  osd_device_fini   (struct lu_device *d);
static int   osd_device_init   (struct lu_device *d, const char *conf);

static struct lu_object  *osd_object_alloc(struct lu_device *d);
static struct osd_object *osd_obj         (const struct lu_object *o);
static struct osd_device *osd_dev         (const struct lu_device *d);
static struct osd_device *osd_dt_dev      (const struct dt_device *d);
static struct lu_device  *osd_device_alloc(struct lu_device_type *t,
                                           struct lustre_cfg *cfg);


static struct lu_device_type_operations osd_device_type_ops;
static struct lu_device_type            osd_device_type;
static struct ptlrpc_thread_key         osd_thread_key;
static struct obd_ops                   osd_obd_device_ops;
static struct lprocfs_vars              lprocfs_osd_module_vars[];
static struct lprocfs_vars              lprocfs_osd_obd_vars[];
static struct lu_device_operations      osd_lu_ops;


static struct lu_fid *lu_inode_get_fid(const struct inode *inode)
{
        static struct lu_fid stub = {
                .f_seq = 42,
                .f_oid = 42,
                .f_ver = 0
        };
        return &stub;
}

/*
 * DT methods.
 */
static int osd_root_get(struct dt_device *dev, struct lu_fid *f)
{
        struct osd_device *od = osd_dt_dev(dev);

        *f = *lu_inode_get_fid(od->od_mount->lmi_sb->s_root->d_inode);
        return 0;
}


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

static int osd_inode_unlinked(const struct inode *inode)
{
        return inode->i_nlink == !!S_ISDIR(inode->i_mode);
}

static void osd_object_release(struct lu_object *l)
{
        struct osd_object *o = osd_obj(l);

        if (o->oo_dentry != NULL && osd_inode_unlinked(o->oo_dentry->d_inode))
                set_bit(LU_OBJECT_HEARD_BANSHEE, &l->lo_header->loh_flags);
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

static int osd_config(struct dt_device *d, const char *name,
                      void *buf, int size, int mode)
{
	struct osd_device *osd = dt2osd_dev(d);
        struct super_block *sb = osd->od_dt_dev.dd_lmi->lmi_sb;
        int result = -EOPNOTSUPP;

        ENTRY;

        if (mode == LUSTRE_CONFIG_GET) {
                /* to be continued */
        } else {
                /* to be continued */
        }

        RETURN (result);
}

static int osd_statfs(struct dt_device *d, struct kstatfs *sfs)
{
	struct osd_device *osd = dt2osd_dev(d);
        struct super_block *sb = osd->od_dt_dev.dd_lmi->lmi_sb;
        int result = -EOPNOTSUPP;

        ENTRY;

        memset(sfs, 0, sizeof(*sfs));
        result = sb->s_op->statfs(sb, sfs);

        RETURN (result);
}

static struct dt_device_operations osd_dt_ops = {
        .dt_root_get = osd_root_get,
        .dt_config   = osd_config,
        .dt_statfs   = osd_statfs
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

static int osd_device_init(struct lu_device *d, const char *top)
{
        struct osd_device *o = osd_dev(d);
        struct lustre_mount_info *lmi;
        struct vfsmount          *mnt;
        int result;

        ENTRY;

        lmi = server_get_mount(top);
        if (lmi != NULL) {
                struct lustre_sb_info    *lsi;
                struct lustre_disk_data  *ldd;
                struct lustre_mount_data *lmd;

                /* We already mounted in lustre_fill_super */
                lsi = s2lsi(lmi->lmi_sb);
                ldd = lsi->lsi_ldd;
                lmd = lsi->lsi_lmd;

                CDEBUG(D_INFO, "OSD info: device=%s,\n opts=%s,\n",
                       lmd->lmd_dev, ldd->ldd_mount_opts);
                mnt = lmi->lmi_mnt;

                /* save lustre_moint_info in dt_device */
                o->od_mount = lmi;
                result = 0;
        } else {
                CERROR("Cannot get mount info for %s!\n", top);
                result = -EFAULT;
        }
        RETURN(result);
}

static void osd_device_fini(struct lu_device *d)
{
        /*
         * umount file system.
         */
}

static struct lu_device *osd_device_alloc(struct lu_device_type *t,
                                          struct lustre_cfg *cfg)
{
        struct lu_device  *l;
        struct osd_device *o;

        OBD_ALLOC_PTR(o);
        if (o != NULL) {
                l = &o->od_dt_dev.dd_lu_dev;
                lu_device_init(&o->od_dt_dev.dd_lu_dev, t);
                o->od_dt_dev.dd_lu_dev.ld_ops = &osd_lu_ops;
                o->od_dt_dev.dd_ops = &osd_dt_ops;
        } else
                l = ERR_PTR(-ENOMEM);
        return l;
}

static void osd_device_free(struct lu_device *d)
{
        struct osd_device *o = osd_dev(d);

        lu_device_fini(d);
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

static struct osd_device *osd_dt_dev(const struct dt_device *d)
{
        LASSERT(lu_device_is_osd(&d->dd_lu_dev));
        return container_of(d, struct osd_device, od_dt_dev);
}

static struct osd_device *osd_dev(const struct lu_device *d)
{
        LASSERT(lu_device_is_osd(d));
        return osd_dt_dev(container_of(d, struct dt_device, dd_lu_dev));
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
        .ldto_device_free  = osd_device_free,

        .ldto_device_init    = osd_device_init,
        .ldto_device_fini    = osd_device_fini
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
