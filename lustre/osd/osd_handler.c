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

/* fid_is_local() */
#include <linux/lustre_fid.h>

#include "osd_internal.h"

static int   osd_root_get      (struct lu_context *ctxt,
                                struct dt_device *dev, struct lu_fid *f);
static int   osd_statfs        (struct lu_context *ctxt,
                                struct dt_device *dev, struct kstatfs *sfs);

static int   lu_device_is_osd  (const struct lu_device *d);
static void  osd_mod_exit      (void) __exit;
static int   osd_mod_init      (void) __init;
static int   osd_type_init     (struct lu_device_type *t);
static void  osd_type_fini     (struct lu_device_type *t);
static int   osd_object_init   (struct lu_context *ctxt, struct lu_object *l);
static void  osd_object_release(struct lu_context *ctxt, struct lu_object *l);
static int   osd_object_print  (struct lu_context *ctx,
                                struct seq_file *f, const struct lu_object *o);
static void  osd_device_free   (struct lu_device *m);
static int   osd_device_init   (struct lu_device *d, struct lu_device *);
static void *osd_key_init      (struct lu_context *ctx);
static void  osd_key_fini      (struct lu_context *ctx, void *data);
static int   osd_fid_lookup    (struct lu_context *ctx, struct osd_object *obj,
                                const struct lu_fid *fid);
static int   osd_inode_getattr (struct lu_context *ctx,
                                struct inode *inode, struct lu_attr *attr);

static struct osd_object  *osd_obj          (const struct lu_object *o);
static struct osd_device  *osd_dev          (const struct lu_device *d);
static struct osd_device  *osd_dt_dev       (const struct dt_device *d);
static struct lu_device   *osd_device_fini  (struct lu_device *d);
static struct lu_device   *osd_device_alloc (struct lu_device_type *t,
                                             struct lustre_cfg *cfg);
static struct lu_object   *osd_object_alloc (struct lu_context *ctx,
                                             struct lu_device *d);
static struct inode       *osd_iget         (struct osd_thread_info *info,
                                             struct osd_device *dev,
                                             const struct osd_inode_id *id);
static struct super_block *osd_sb           (const struct osd_device *dev);
static struct lu_fid      *osd_inode_get_fid(const struct inode *inode,
                                             struct lu_fid *fid);

static struct lu_device_type_operations osd_device_type_ops;
static struct lu_device_type            osd_device_type;
static struct obd_ops                   osd_obd_device_ops;
static struct lprocfs_vars              lprocfs_osd_module_vars[];
static struct lprocfs_vars              lprocfs_osd_obd_vars[];
static struct lu_device_operations      osd_lu_ops;
static struct lu_context_key            osd_key;
static struct dt_object_operations      osd_obj_ops;

/*
 * DT methods.
 */
static int osd_root_get(struct lu_context *ctx,
                        struct dt_device *dev, struct lu_fid *f)
{
        osd_inode_get_fid(osd_dt_dev(dev)->od_root_dir->d_inode, f);
        return 0;
}


/*
 * OSD object methods.
 */

static struct lu_object *osd_object_alloc(struct lu_context *ctx,
                                          struct lu_device *d)
{
        struct osd_object *mo;

        OBD_ALLOC_PTR(mo);
        if (mo != NULL) {
                struct lu_object *l;

                l = &mo->oo_dt.do_lu;
                lu_object_init(l, NULL, d);
                mo->oo_dt.do_ops = &osd_obj_ops;
                return l;
        } else
                return NULL;
}

static int osd_object_init(struct lu_context *ctxt, struct lu_object *l)
{
        return osd_fid_lookup(ctxt, osd_obj(l), lu_object_fid(l));
}

static void osd_object_free(struct lu_context *ctx, struct lu_object *l)
{
        struct osd_object *obj = osd_obj(l);
        OBD_FREE_PTR(obj);
}

static void osd_object_delete(struct lu_context *ctx, struct lu_object *l)
{
        struct osd_object *o = osd_obj(l);

        if (o->oo_inode != NULL)
                iput(o->oo_inode);
}

static int osd_inode_unlinked(const struct inode *inode)
{
        return inode->i_nlink == !!S_ISDIR(inode->i_mode);
}

static void osd_object_release(struct lu_context *ctxt, struct lu_object *l)
{
        struct osd_object *o = osd_obj(l);

        if (o->oo_inode != NULL && osd_inode_unlinked(o->oo_inode))
                set_bit(LU_OBJECT_HEARD_BANSHEE, &l->lo_header->loh_flags);
}

static int osd_object_print(struct lu_context *ctx,
                            struct seq_file *f, const struct lu_object *l)
{
        struct osd_object  *o = osd_obj(l);

        return seq_printf(f, LUSTRE_OSD0_NAME"-object@%p(i:%p:%lu/%u)",
                          o, o->oo_inode,
                          o->oo_inode ? o->oo_inode->i_ino : 0UL,
                          o->oo_inode ? o->oo_inode->i_generation : 0);
}

static int osd_config(struct lu_context *ctx,
                      struct dt_device *d, const char *name,
                      void *buf, int size, int mode)
{
        if (mode == LUSTRE_CONFIG_GET) {
                /* to be continued */
                return 0;
        } else {
                /* to be continued */
                return 0;
        }
}

static int osd_statfs(struct lu_context *ctx,
                      struct dt_device *d, struct kstatfs *sfs)
{
	struct osd_device *osd = dt2osd_dev(d);
        struct super_block *sb = osd_sb(osd);
        int result;

        ENTRY;

        memset(sfs, 0, sizeof(*sfs));
        result = sb->s_op->statfs(sb, sfs);

        RETURN (result);
}

static int osd_attr_get(struct lu_context *ctxt, struct dt_object *dt,
                        struct lu_attr *attr)
{
        return osd_inode_getattr(ctxt, dt2osd_obj(dt)->oo_inode, attr);
}

static struct dt_object_operations osd_obj_ops = {
        .do_attr_get = osd_attr_get
};

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
        return lu_context_key_register(&osd_key);
}

static void osd_type_fini(struct lu_device_type *t)
{
        lu_context_key_degister(&osd_key);
}

static struct lu_context_key osd_key = {
        .lct_init = osd_key_init,
        .lct_fini = osd_key_fini
};

static void *osd_key_init(struct lu_context *ctx)
{
        struct osd_thread_info *info;

        OBD_ALLOC_PTR(info);
        if (info == NULL)
                info = ERR_PTR(-ENOMEM);
        return info;
}

static void osd_key_fini(struct lu_context *ctx, void *data)
{
        struct osd_thread_info *info = data;
        OBD_FREE_PTR(info);
}

static int osd_device_init(struct lu_device *d, struct lu_device *next)
{
        return 0;
}

static int osd_mount(struct osd_device *o, struct lustre_cfg *cfg)
{
        struct lustre_mount_info *lmi;
        const char *dev = lustre_cfg_string(cfg, 0);
        int result;

        ENTRY;

        /* get mount */
        lmi = server_get_mount(dev);
        if (lmi == NULL) {
                CERROR("Cannot get mount info for %s!\n", dev);
                RETURN(-EFAULT);
        }

        LASSERT(lmi != NULL);
        /* save lustre_mount_info in dt_device */
        o->od_mount = lmi;
        result = osd_oi_init(&o->od_oi, osd_sb(o)->s_root,
                             o->od_dt_dev.dd_lu_dev.ld_site);

        if (result == 0) {
                o->od_root_dir = osd_open(osd_sb(o)->s_root,
                                          "ROOT", S_IFDIR);
                if (IS_ERR(o->od_root_dir)) {
                        result = PTR_ERR(o->od_root_dir);
                        o->od_root_dir = NULL;
                }
        }

        RETURN(result);
}

static struct lu_device *osd_device_fini(struct lu_device *d)
{
        struct osd_device *o = osd_dev(d);
        ENTRY;
        if (o->od_root_dir != NULL) {
                dput(o->od_root_dir);
                o->od_root_dir = NULL;
        }
        osd_oi_fini(&o->od_oi);

        if (o->od_mount)
                server_put_mount(o->od_mount->lmi_name, o->od_mount->lmi_mnt);

        o->od_mount = NULL;

	return NULL;
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

static int osd_process_config(struct lu_device *d, struct lustre_cfg *cfg)
{
        struct osd_device *o = lu2osd_dev(d);
        int err;

        switch(cfg->lcfg_command) {
        case LCFG_SETUP:
                err = osd_mount(o, cfg);
                break;
        default:
                err = -ENOTTY;
        }

        RETURN(err);
}

/*
 * fid<->inode<->object functions.
 */

static struct lu_fid *osd_inode_get_fid(const struct inode *inode,
                                        struct lu_fid *fid)
{
        /*
         * XXX: Should return fid stored together with inode in memory.
         */
        fid->f_seq = inode->i_ino;
        fid->f_oid = inode->i_generation;
        return fid;
}

struct dentry *osd_open(struct dentry *parent, const char *name, mode_t mode)
{
        struct dentry *dentry;
        struct dentry *result;

        result = dentry = osd_lookup(parent, name);
        if (IS_ERR(dentry)) {
                CERROR("Error opening %s: %ld\n", name, PTR_ERR(dentry));
                dentry = NULL; /* dput(NULL) below is OK */
        } else if (dentry->d_inode == NULL) {
                CERROR("Not found: %s\n", name);
                result = ERR_PTR(-ENOENT);
        } else if ((dentry->d_inode->i_mode & S_IFMT) != mode) {
                CERROR("Wrong mode: %s: %o != %o\n", name,
                       dentry->d_inode->i_mode, mode);
                result = ERR_PTR(mode == S_IFDIR ? -ENOTDIR : -EISDIR);
        }

        if (IS_ERR(result))
                dput(dentry);
        return result;
}

struct dentry *osd_lookup(struct dentry *parent, const char *name)
{
        struct dentry *dentry;

        CDEBUG(D_INODE, "looking up object %s\n", name);
        down(&parent->d_inode->i_sem);
        dentry = lookup_one_len(name, parent, strlen(name));
        up(&parent->d_inode->i_sem);

        if (IS_ERR(dentry)) {
                CERROR("error getting %s: %ld\n", name, PTR_ERR(dentry));
        } else if (dentry->d_inode != NULL && is_bad_inode(dentry->d_inode)) {
                CERROR("got bad object %s inode %lu\n",
                       name, dentry->d_inode->i_ino);
                dput(dentry);
                dentry = ERR_PTR(-ENOENT);
        }
        return dentry;
}

static struct inode *osd_iget(struct osd_thread_info *info,
                              struct osd_device *dev,
                              const struct osd_inode_id *id)
{
        struct inode *inode;

	inode = iget(osd_sb(dev), id->oii_ino);
	if (inode == NULL) {
                CERROR("no inode\n");
		inode = ERR_PTR(-EACCES);
	} else if (is_bad_inode(inode)) {
                CERROR("bad inode\n");
		iput(inode);
		inode = ERR_PTR(-ENOENT);
	} else if (inode->i_generation != id->oii_gen &&
                   id->oii_gen != OSD_GEN_IGNORE) {
                CERROR("stale inode\n");
		iput(inode);
		inode = ERR_PTR(-ESTALE);
        }
        return inode;

}

static int osd_fid_lookup(struct lu_context *ctx,
                          struct osd_object *obj, const struct lu_fid *fid)
{
        struct osd_thread_info *info;
        struct lu_device       *ldev = obj->oo_dt.do_lu.lo_dev;
        struct osd_device      *dev;
        struct osd_inode_id     id;
        struct inode           *inode;
        int                     result;

        LASSERT(obj->oo_inode == NULL);
        LASSERT(fid_is_sane(fid));
        LASSERT(fid_is_local(ldev->ld_site, fid));

        ENTRY;

        info = lu_context_key_get(ctx, &osd_key);
        dev  = osd_dev(ldev);

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_ENOENT))
                RETURN(-ENOENT);

        osd_oi_read_lock(&dev->od_oi);
        result = osd_oi_lookup(info, &dev->od_oi, fid, &id);
        if (result == 0) {
                inode = osd_iget(info, dev, &id);
                if (!IS_ERR(inode)) {
                        obj->oo_inode = inode;
                        result = 0;
                } else
                        result = PTR_ERR(inode);
        }
        osd_oi_read_unlock(&dev->od_oi);
        RETURN(result);
}

static int osd_inode_getattr(struct lu_context *ctx,
                             struct inode *inode, struct lu_attr *attr)
{
        //attr->la_atime      = inode->i_atime;
        //attr->la_mtime      = inode->i_mtime;
        //attr->la_ctime      = inode->i_ctime;
        attr->la_mode       = inode->i_mode;
        attr->la_size       = inode->i_size;
        attr->la_blocks     = inode->i_blocks;
        attr->la_uid        = inode->i_uid;
        attr->la_gid        = inode->i_gid;
        attr->la_flags      = inode->i_flags;
        attr->la_nlink      = inode->i_nlink;
        return 0;
}

/*
 * Helpers.
 */

static int lu_device_is_osd(const struct lu_device *d)
{
        /*
         * XXX for now. Tags in lu_device_type->ldt_something are needed.
         */
        return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &osd_lu_ops);
}

static struct osd_object *osd_obj(const struct lu_object *o)
{
        LASSERT(lu_device_is_osd(o->lo_dev));
        return container_of0(o, struct osd_object, oo_dt.do_lu);
}

static struct osd_device *osd_dt_dev(const struct dt_device *d)
{
        LASSERT(lu_device_is_osd(&d->dd_lu_dev));
        return container_of0(d, struct osd_device, od_dt_dev);
}

static struct osd_device *osd_dev(const struct lu_device *d)
{
        LASSERT(lu_device_is_osd(d));
        return osd_dt_dev(container_of0(d, struct dt_device, dd_lu_dev));
}

static struct super_block *osd_sb(const struct osd_device *dev)
{
        return dev->od_mount->lmi_mnt->mnt_sb;
}

static struct lu_device_operations osd_lu_ops = {
        .ldo_object_alloc   = osd_object_alloc,
        .ldo_object_init    = osd_object_init,
        .ldo_object_free    = osd_object_free,
        .ldo_object_release = osd_object_release,
        .ldo_object_delete  = osd_object_delete,
        .ldo_object_print   = osd_object_print,
        .ldo_process_config = osd_process_config
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

        lprocfs_init_vars(osd, &lvars);
        return class_register_type(&osd_obd_device_ops, NULL, lvars.module_vars,
                                   LUSTRE_OSD0_NAME, &osd_device_type);
}

static void __exit osd_mod_exit(void)
{
        class_unregister_type(LUSTRE_OSD0_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Object Storage Device ("LUSTRE_OSD0_NAME")");
MODULE_LICENSE("GPL");

cfs_module(osd, "0.0.2", osd_mod_init, osd_mod_exit);
