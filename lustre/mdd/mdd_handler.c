/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mdd/mdd_reint.c
 *  Lustre Metadata Server (mdd) routines
 *
 *  Copyright (C) 2002-2005 Cluster File Systems, Inc.
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
#define DEBUG_SUBSYSTEM S_MDD

#include <linux/module.h>

#include <linux/lustre_ver.h>
#include <linux/obd_support.h>

#include <linux/lu_object.h>

#include "mdd_internal.h"

static int 
mdd_init(struct lu_device *lu)
{
        return 0;
}

static int
mdd_fini(struct lu_device *lu)
{
        return 0;
}

static struct lu_device_operations mdd_lu_ops;

static int lu_device_is_mdd(struct lu_device *d)
{
	/*
	 * XXX for now. Tags in lu_device_type->ldt_something are needed.
	 */
	return ergo(d->ld_ops != NULL, d->ld_ops == &mdd_lu_ops);
}

static struct mdd_object *mdd_obj(struct lu_object *o)
{
	LASSERT(lu_device_is_mdd(o->lo_dev));
	return container_of(o, struct mdd_object, mod_obj.mo_lu);
}

static struct mdd_device *mdd_dev(struct lu_device *d)
{
	LASSERT(lu_device_is_mdd(d));
	return container_of(d, struct mdd_device, mdd_md_dev.md_lu_dev);
}

static struct mdd_device* mdo2mdd(struct mdd_object *mdo)
{
        return mdd_dev(mdo->mo_lu->lu_device);
}

struct lu_object *mdd_object_alloc(struct lu_device *d)
{
        struct mdd_object *mdo;
        ENTRY;

        OBD_ALLOC_PTR(mdo);
        if (mdo != NULL) {
		lu_object_init(o, NULL, d);
                return (&mdo->mod_obj);
        } else
                return(NULL);
}

int mdd_object_init(struct lu_object *o)
{
	struct mdd_device *d = mdd_dev(o->lo_dev);
	struct lu_object_header *loh;
	struct lu_object  *below, *upper;
        struct lu_device  *under;
        ENTRY;

	under = &d->mdd_child->md_lu_dev;
	below = under->ld_ops->ldo_object_alloc(under);

        if (below == NULL)
		RETURN(-ENOMEM);
        
        if (o->lo_header) 
                lu_object_add_top(o->lo_header, o);
	
        lu_object_add(o, below);
        RETURN(0);
}

void mdd_object_free(struct lu_object *o)
{
	struct lu_object_header *h;
        struct mdd_object *mdd = mdd_obj(o);

	h = o->lo_header;
	lu_object_fini(o);
        OBD_FREE_PTR(mdd);
}

void mdd_object_release(struct lu_object *o)
{
        struct mdt_device *d = mdt_dev(o->lo_dev); 

        lu_object_release(o);        
}

static struct lu_device_operations mdd_lu_ops = {
	.ldo_init           = mdd_init,
	.ldo_fini           = mdd_fini,
	.ldo_object_alloc   = mdd_object_alloc,
	.ldo_object_init    = mdd_object_init,
	.ldo_object_free    = mdd_object_free,
	.ldo_object_release = mdd_object_release,
	.ldo_object_print   = mdd_object_print
}

struct lu_object* mdd_object_child(struct mdd_object *o)
{
       return lu_object_next(&o->mod_obj.mo_lu);
}

static void 
mdd_lock(struct mdd_device *mdd, struct mdd_obj *obj, __u32 mode)
{
        mdd->mdd_child->osd_ops->osd_lock_obj(osd, mdd_object_child(obj), mode);
}

static void
mdd_unlock(struct mdd_device *mdd, struct mdd_obj *obj, __u32 mode)
{
        mdd->mdd_child->osd_ops->osd_unlock_obj(osd, mdd_object_child(obj),
                                                mode);
}

static void* mdd_trans_start(struct mdd_device *mdd, struct mdd_object *obj)
{
        return mdd->mdd_child->osd_ops->osd_trans_start(obj);
}

static void mdd_trans_stop(struct mdd_device *mdd, void *handle)
{
        mdd->mdd_child->osd_ops->osd_trans_stop(handle);
}

static int
__mdd_object_create(struct mdd_device *mdd, struct mdd_object *pobj,
                    struct context *uc_context, void *handle)
{
        struct mdd_object *mdd_obj;
        struct lu_object *lu;
        int rc;
        ENTRY;

        rc = mdd->mdd_child->osd_ops->osd_create_obj(mdd->mdd_child, mdd_obj_child(pobj),
                                                     &lu, uctxt, handle);
        /*XXX increase the refcount of the object or not?*/
exit:
        RETURN(rc);
}

static int
mdd_object_create(struct mdd_obj *pobj, struct context *uc_context)
{
        struct mdd_device *mdd = mdo2mdd(pobj); 
        void *handle = NULL;
        int rc;
        ENTRY;

        handle = mdd_trans_start(mdd, obj);
        if (!handle)
                RETURN(-ENOMEM);

        rc = __mdd_object_create(mdd, obj, uc_context, handle);

        mdd_trans_stop(handle);

        RETURN(rc);
}

static int mdd_add_orphan(struct obd_device *obd, struct mdd_object *mdd_obj,
                          void *handle)
{
        int rc = 0;
        ENTRY;

        RETURN(rc);
}

static int
_mdd_object_destroy(struct mdd_device *mdd, struct mdd_obj *obj,
                    void *handle)
{
        int rc = 0;

        rc = mdd->mdd_child->osd_ops->osd_object_destroy(mdd->mdd_child, 
                                              mdd_object_child(obj), handle);

        RETURN(rc); 
}                

static int 
mdd_object_destroy(struct mdd_object *pobj, struct mdd_object *obj)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        void *handle;
        ENTRY;
 
        handle = mdd_trans_start(mdd, pobj);
        if (!handle)
                RETURN(-ENOMEM);

        mdd_lock(mdd, pobj, WRITE_LOCK);
        if (open_orphan(mdd_obj))
                rc = mdd_add_orphan(mdd, mdd_obj, handle);
        else {
                rc = __mdd_object_destroy(mdd, mdd_obj, handle);
                if (rc)
                        GOTO(exit, rc);

                rc = mdd_add_unlink_log(mdd, mdd_obj, handle);
        }
exit:
        mdd_unlock(mdd, pobj, WRITE_LOCK);
        mdd_trans_stop(handle);
        RETURN(rc);
}

static void
mdd_object_get(struct mdd_device *mdd, struct mdd_obj *obj)
{
        mdd->mdd_child->osd_ops->osd_object_get(mdd->mdd_child,
                                                mdd_object_child(obj));
}

static int
mdd_attr_get(struct mdd_device *mdd, struct mdd_obj *obj, void *buf,
             int buf_len, const char *name, struct context *uc_context)
{
        int rc;
        ENTRY;

        mdd_object_get(mdd, obj);
        rc = mdd->mdd_child->osd_ops->osd_attr_get(mdd->mdd_child, 
                                                   mdd_object_child(obj),
                                                   buf, buf_len, name,
                                                   uc_context);
        mdd_object_put(mdd, obj);
        RETURN(rc);
}

static int
__mdd_attr_set(struct mdd_device *mdd, struct mdd_obj *obj, void *buf,
               int buf_len, const char *name, struct context *uc_context,
               void *handle)
{
        return mdd->mdd_child->osd_ops->osd_attr_set(mdd->mdd_child, 
                                                     mdd_object_child(obj),
                                                     buf, buf_len, 
                                                     name, uc_context,
                                                     handle);
}

static int 
mdd_attr_set(struct mdd_device *mdd, struct mdd_obj *obj, void *buf,
             int buf_len, const char *name, struct context *uc_context)
{
        int  rc;
        void *handle = NULL;
        ENTRY;

        handle = mdd_trans_start(mdd, obj);
        if (!handle)
                RETURN(-ENOMEM);

        __mdd_attr_set(mdd, obj, buf, buf_len, name, uc_context, handle);
        
        mdd_trans_stop(mdd, handle);
        
        RETURN(rc);
}


static int 
mdd_object_put(struct mdd_device *mdd, struct mdd_obj *obj)
{
        int nlink, rc = 0;       
 
        mdd->mdd_child->osd_ops->osd_object_put(mdd->mdd_child,
                                                mdd_object_child(obj));

        if ((mdd_object_count(obj)) == 0) {
                rc = mdd_attr_get(mdd, obj, &nlink, sizeof(nlink), 
                                  "NLINK", uc_context);
                if (!rc)
                        RETURN(-EINVAL);
        }
        if (nlink == 0)
                rc = mdd_object_destroy(mdd, obj);
        
        RETURN(rc);
}

static struct ll_fid *mdd_object_getfid(struct mdd_object *obj)
{
        return &(obj->mod_obj.mo_lu->lo_header->loh_fid);
}

static int 
__mdd_index_insert(struct mdd_device *mdd, struct mdd_obj *obj,
                   const char *name, struct mdd_obj *obj,
                   struct uc_context *uc_context, void *handle)
{
        mdd_object_get(mdd, mdd_pobj);
        mdd_lock(mdd, mdd_pobj, WRITE_LOCK);
        mdd_lock(mdd, mdd_obj, WRITE_LOCK);

        mdd->mdd_child->osd_ops->osd_insert_index(mdd->mdd_child, 
                                                  mdd_object_child(obj),
                                                  name, mdd_object_getfid(obj), 
                                                  uctxt, handle);
        mdd_unlock(mdd, mdd_pobj, WRITE_LOCK);
        mdd_unlock(mdd, mdd_obj, WRITE_LOCK);
        mdd_put_obj(mdd, mdd_pobj);
}

static int
mdd_index_insert(struct mdd_device *mdd, struct mdd_obj *pobj,
                 const char *name, struct mdd_obj *obj,
                 struct uc_context *uc_context)
{
        void *handle = NULL;
        ENTRY;

        handle = mdd_trans_start(mdd, obj);
        if (!handle)
                RETURN(-ENOMEM);

        __mdd_index_insert(mdd, pobj, name, obj, uc_context, handle);
 
        mdd_trans_stop(mdd, handle);
}

static int 
__mdd_index_delete(struct mdd_device *mdd, struct mdd_obj *pobj,
                   const char *name, struct mdd_obj *obj,
                   struct uc_context *uc_context, void *handle)
{
        mdd_object_get(mdd, mdd_pobj);
        mdd_lock(mdd, mdd_pobj, WRITE_LOCK);
        mdd_lock(mdd, mdd_obj, WRITE_LOCK);

        mdd->mdd_child->osd_ops->osd_insert_delete(mdd->mdd_child, 
                                                   mdd_object_child(obj),
                                                   name, mdd_object_getfid(obj), 
                                                   uctxt, handle);
        mdd_unlock(mdd, mdd_pobj, WRITE_LOCK);
        mdd_unlock(mdd, mdd_obj, WRITE_LOCK);
        mdd_put_obj(mdd, mdd_pobj);

}

static int
mdd_index_delete(struct mdd_device *obd, struct lustre_obj *pobj,
                 const char *name, struct lustre_obj *obj,
                 struct uc_context *uc_context)
{
        void *handle = NULL;
        ENTRY;

        handle = mdd_trans_start(mdd, obj);
        if (!handle)
                RETURN(-ENOMEM);

        __mdd_index_delete(mdd, pobj, name, obj, uc_context, handle);

        mdd_trans_stop(handle);
}

static int
mdd_link(struct mdd_device *mdd, struct mdd_object *tgt_obj,
         struct mdd_object *src_obj, const char *name,
         struct context *uc_context)
{
        void *handle = NULL; 
        int rc, nlink;
        ENTRY;

        handle = mdd_trans_start(mdd, src_obj);
        if (!handle)
                RETURN(-ENOMEM);

        mdd_lock(mdd, tgt_obj, WRITE_LOCK);
        mdd_lock(mdd, src_obj, WRITE_LOCK);
        
        rc = __mdd_index_insert(mdd, tgt_obj, name, src_obj
                                uctxt, handle);
        if (rc)
                GOTO(trans_exit, rc);

        rc = mdd_attr_get(mdd, src_obj, &nlink, sizeof(nlink), 
                          "NLINK", uc_context);
        ++nlink;
       
        rc = __mdd_attr_set(mdd, obj, &nlink, sizeof(nlink), "NLINK", 
                            uc_context, handle);

exit:                          
        mdd_unlock(tgt_obj->mdd_obj, WRITE_LOCK);
        mdd_unlock(src_obj->mdd_obj, WRITE_LOCK);
        
        mdd_trans_stop(mdd, handle);
        RETURN(rc);
}

static void mdd_rename_lock(struct mdd_device *mdd, struct mdd_object *src_pobj,
                            struct mdd_object *tgt_pobj, struct mdd_object *sobj,
                            struct mdd_object *tobj)
{
        return;
}

static void mdd_rename_unlock(struct mdd_device *mdd, struct mdd_object *src_pobj,
                              struct mdd_object *tgt_pobj, struct mdd_object *sobj,
                              struct mdd_object *tobj)
{
        return;
}

static int 
int mdd_rename(struct mdd_device *mdd, struct mdd_object *src_pobj,
               struct lustre_obj *tgt_pobj, struct lustre_obj *sobj,
               const char *sname, struct lustre_obj, *tobj,
               const char *tname, struct context *uctxt)
{
        
        handle = mdd_trans_start(mdd, src_pobj);
        if (!handle)
                GOTO(cleanup, rc);
        
        mdd_rename_lock(mdd, src_pobj, tgt_pobj, sobj, tobj);
       
        rc = __mdd_index_delete(mdd, src_pobj, sname, sobj, uctxt, handle);
        if (rc)
                GOTO(cleanup, rc);

        rc = __mdd_index_delete(mdd, tgt_pobj, tname, tobj, uctxt, handle);
        if (rc)
                GOTO(cleanup, rc);

        rc = __mdd_index_insert(mdd, src_pobj, tname, tobj, uctxt, handle);
        if (rc)
                GOTO(cleanup, rc);
        
        rc = __mdd_obj_destroy(mdd, src_pobj, sname, sobj, uctxt, handle);
        if (rc)
                GOTO(cleanup, rc);
cleanup:
        mdd_rename_unlock(mdd, src_pobj, tgt_pobj, sobj, tobj);
        mdd_trans_stop(mdd, handle);
        RETURN(rc);
}

static int mdd_fs_setup(struct mdd_device *mdd)
{
        return 0;
}
static int mdd_setup(struct mdd_device *mdd, obd_count len, void *buf)
{
        struct lprocfs_static_vars lvars;
        struct lustre_cfg* lcfg = buf;
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_mount_info *lmi;
        struct vfsmount *mnt;
        struct obd_uuid uuid;
        __u8 *uuid_ptr;
        char *options, *str, *label;
        char ns_name[48];
        unsigned long page;
        int rc = 0;
        ENTRY;


        sema_init(&mdd->mdd_orphan_recovery_sem, 1);
        sema_init(&mdd->mdd_epoch_sem, 1);
        spin_lock_init(&mds->mds_transno_lock);
        mds->mds_max_mdsize = sizeof(struct lov_mds_md);
        mds->mds_max_cookiesize = sizeof(struct llog_cookie);
        mds->mds_atime_diff = MAX_ATIME_DIFF;

        rc = mdd_fs_setup(mdd);
        if (rc) {
                CERROR("%s: MDS filesystem method init failed: rc = %d\n",
                       obd->obd_name, rc);
                GOTO(err_ns, rc);
        }

        rc = lquota_setup(quota_interface, obd, lcfg);
        if (rc)
                GOTO(err_fs, rc);

        RETURN(rc);
err_qctxt:
        lquota_cleanup(quota_interface, obd);
err_fs:
        /* No extra cleanup needed for llog_init_commit_thread() */
        mdd_fs_cleanup(mdd);
        RETURN(rc);
}

static struct obd_ops mdt_ops = {
        .o_owner           = THIS_MODULE,
        .o_connect         = mdd_connect,
        .o_reconnect       = mdd_reconnect,
        .o_init_export     = mdd_init_export,
        .o_destroy_export  = mdd_destroy_export,
        .o_disconnect      = mdd_disconnect,
        .o_setup           = mdd_setup,
        .o_precleanup      = mdd_precleanup,
        .o_cleanup         = mdd_cleanup,
        .o_postrecov       = mdd_postrecov,
        .o_statfs          = mdd_obd_statfs,
        .o_iocontrol       = mdd_iocontrol,
        .o_create          = mdd_obd_create,
        .o_destroy         = mdd_obd_destroy,
        .o_llog_init       = mdd_llog_init,
        .o_llog_finish     = mdd_llog_finish,
        .o_notify          = mdd_notify,
        .o_health_check    = mdd_health_check,
};

static int __init mdd_mod_init(void)
{
	return 0;
}

static void __exit mdd_mod_exit(void)
{
        return;
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Meta-data Target Prototype ("LUSTRE_MDD_NAME")");
MODULE_LICENSE("GPL");

cfs_module(mdd, "0.0.2", mdd_mod_init, mdd_mod_exit);

