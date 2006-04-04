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
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>

#include <linux/lustre_ver.h>
#include <linux/obd_support.h>

#include <linux/lu_object.h>
#include <linux/md_object.h>

#include "mdd_internal.h"

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

static struct mdd_device* mdd_dev(struct lu_device *d)
{
	LASSERT(lu_device_is_mdd(d));
	return container_of(d, struct mdd_device, mdd_md_dev.md_lu_dev);
}

static struct mdd_device* mdo2mdd(struct md_object *mdo)
{
        return mdd_dev(mdo->mo_lu.lo_dev);
}

static struct mdd_object* mdo2mddo(struct md_object *mdo)
{
        return container_of(mdo, struct mdd_object, mod_obj);
}

static inline struct osd_device_operations *mdd_child_ops(struct mdd_device *d)
{
        return d->mdd_child->osd_ops;
}

struct lu_object *mdd_object_alloc(struct lu_device *d)
{
        struct mdd_object *mdo;
        ENTRY;

        OBD_ALLOC_PTR(mdo);
        if (mdo != NULL) {
                struct lu_object *o;
		
                o = &mdo->mod_obj.mo_lu; 
                lu_object_init(o, NULL, d);
                return (&mdo->mod_obj.mo_lu);
        } else
                return(NULL);
}

int mdd_object_init(struct lu_object *o)
{
	struct mdd_device *d = mdd_dev(o->lo_dev);
	struct lu_object  *below;
        struct lu_device  *under;
        ENTRY;

	under = &d->mdd_child->osd_lu_dev;
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
}

int mdd_object_print(struct seq_file *f, const struct lu_object *o)
{
        return seq_printf(f, LUSTRE_MDD_NAME"-object@%p", o);
}

static struct lu_device_operations mdd_lu_ops = {
	.ldo_object_alloc   = mdd_object_alloc,
	.ldo_object_init    = mdd_object_init,
	.ldo_object_free    = mdd_object_free,
	.ldo_object_release = mdd_object_release,
	.ldo_object_print   = mdd_object_print
};

struct lu_object* mdd_object_child(struct mdd_object *o)
{
       return lu_object_next(&o->mod_obj.mo_lu);
}

static void
mdd_lock(struct mdd_device *mdd, struct mdd_object *obj, __u32 mode)
{
        mdd_child_ops(mdd)->osd_object_lock(mdd_object_child(obj), mode);
}

static void
mdd_unlock(struct mdd_device *mdd, struct mdd_object *obj, __u32 mode)
{
        mdd_child_ops(mdd)->osd_object_unlock(mdd_object_child(obj), mode);
}

static void* mdd_trans_start(struct mdd_device *mdd, struct mdd_object *obj)
{
        return mdd_child_ops(mdd)->osd_trans_start(mdd_object_child(obj));
}

static void mdd_trans_stop(struct mdd_device *mdd, void *handle)
{
        mdd_child_ops(mdd)->osd_trans_stop(handle);
}

static int
__mdd_object_create(struct mdd_device *mdd, struct mdd_object *pobj,
                    struct mdd_object *child, struct context *uctxt,
                    void *handle)
{
        int rc;
        ENTRY;

        rc = mdd_child_ops(mdd)->osd_object_create(mdd_object_child(pobj),
                                                   mdd_object_child(child),
                                                   uctxt, handle);
        /*XXX increase the refcount of the object or not?*/
        RETURN(rc);
}

static int
mdd_object_create(struct md_object *pobj, struct md_object *child,
                  struct context *uctxt)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        struct mdd_object *mdd_pobj = mdo2mddo(pobj); 
        struct mdd_object *mdd_child = mdo2mddo(child); 
        void *handle = NULL;
        int rc;
        ENTRY;

        handle = mdd_trans_start(mdd, mdd_pobj);
        if (!handle)
                RETURN(-ENOMEM);

        rc = __mdd_object_create(mdd, mdd_pobj, mdd_child, uctxt, handle);

        mdd_trans_stop(mdd, handle);

        RETURN(rc);
}

static int mdd_add_orphan(struct mdd_device *mdd, struct mdd_object *obj,
                          void *handle)
{
        int rc = 0;
        ENTRY;

        RETURN(rc);
}

static int
__mdd_object_destroy(struct mdd_device *mdd, struct mdd_object *obj,
                    void *handle)
{
        int rc = 0;

        rc = mdd_child_ops(mdd)->osd_object_destroy(mdd_object_child(obj),
                                                    handle);
        RETURN(rc);
}

static int
open_orphan(struct mdd_object *obj)
{
        return 0;
}

static int
mdd_add_unlink_log(struct mdd_device *mdd, struct mdd_object *obj,
                   void *handle)
{
        return 0;
}

static int
mdd_object_destroy(struct md_object *obj)
{
        struct mdd_device *mdd = mdo2mdd(obj);
        struct mdd_object *mdd_obj = mdo2mddo(obj);
        void *handle;
        int rc ;
        ENTRY;
 
        handle = mdd_trans_start(mdd, mdd_obj);
        if (!handle)
                RETURN(-ENOMEM);

        mdd_lock(mdd, mdd_obj, WRITE_LOCK);
        if (open_orphan(mdd_obj))
                rc = mdd_add_orphan(mdd, mdd_obj, handle);
        else {
                rc = __mdd_object_destroy(mdd, mdd_obj, handle);
                if (rc)
                        GOTO(exit, rc);

                rc = mdd_add_unlink_log(mdd, mdd_obj, handle);
        }
exit:
        mdd_unlock(mdd, mdd_obj, WRITE_LOCK);
        mdd_trans_stop(mdd, handle);
        RETURN(rc);
}

void mdd_object_get(struct mdd_device *mdd, struct mdd_object *obj)
{
        mdd_child_ops(mdd)->osd_object_get(mdd_object_child(obj));
}

static int
__mdd_attr_set(struct mdd_device *mdd, struct mdd_object *obj, void *buf,
               int buf_len, const char *name, struct context *uc_context,
               void *handle)
{
        return mdd_child_ops(mdd)->osd_attr_set(mdd_object_child(obj),
                                                buf, buf_len, 
                                                name, uc_context,
                                                handle);
}

static int
mdd_attr_set(struct md_object *obj, void *buf, int buf_len, const char *name,
             struct context *uc_context)
{
        struct mdd_device *mdd = mdo2mdd(obj);
        void *handle = NULL;
        int  rc;
        ENTRY;

        handle = mdd_trans_start(mdd, mdo2mddo(obj));
        if (!handle)
                RETURN(-ENOMEM);

        rc = __mdd_attr_set(mdd, mdo2mddo(obj), buf, buf_len, name, uc_context,
                            handle);

        mdd_trans_stop(mdd, handle);

        RETURN(rc);
}

static int
mdd_object_dec_check(struct mdd_device *mdd, struct mdd_object *obj)
{
        return mdd_child_ops(mdd)->osd_object_dec_check(mdd_object_child(obj));
}


static struct lu_fid *mdd_object_getfid(struct mdd_object *obj)
{
        return &(obj->mod_obj.mo_lu.lo_header->loh_fid);
}

static int
mdd_attr_get(struct md_object *obj, void *buf, int buf_len, const char *name,
             struct context *uctxt)
{
        struct mdd_object *mdd_obj = mdo2mddo(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        int rc;
        
        ENTRY;

        mdd_object_get(mdd, mdd_obj);
        rc = mdd_child_ops(mdd)->osd_attr_get(mdd_object_child(mdd_obj),
                                              buf, buf_len, name, uctxt);
        mdd_object_put(mdd, mdd_obj);
        RETURN(rc);
}

int mdd_object_put(struct mdd_device *mdd, struct mdd_object *obj)
{
        int rc = 0;
 
        if ((mdd_object_dec_check(mdd, obj)) == 0) {
                int nlink;

                rc = mdd_attr_get(&obj->mod_obj, &nlink, sizeof(nlink), "NLINK",
                                  NULL);
                if (!rc)
                        RETURN(-EINVAL);
                
                if (nlink == 0)
                        rc = mdd_object_destroy(&obj->mod_obj);
        }

        RETURN(rc);
}

static int
__mdd_index_insert(struct mdd_device *mdd, struct mdd_object *pobj,
                   struct mdd_object *obj, const char *name,
                   struct context *uctxt, void *handle)
{
        int rc;
        ENTRY;

        mdd_object_get(mdd, pobj);
        mdd_lock(mdd, pobj, WRITE_LOCK);
        mdd_lock(mdd, obj, WRITE_LOCK);

        rc = mdd_child_ops(mdd)->osd_index_insert(mdd_object_child(pobj),
                                             mdd_object_getfid(obj), name,
                                             uctxt, handle);
        mdd_unlock(mdd, pobj, WRITE_LOCK);
        mdd_unlock(mdd, obj, WRITE_LOCK);
        mdd_object_put(mdd, pobj);

        RETURN(rc);
}

static int
mdd_index_insert(struct md_object *pobj, struct md_object *obj, const char *name,
                 struct context *uctxt)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        int rc;
        void *handle = NULL;
        ENTRY;

        handle = mdd_trans_start(mdd, mdo2mddo(pobj));
        if (!handle)
                RETURN(-ENOMEM);

        rc = __mdd_index_insert(mdd, mdo2mddo(pobj), mdo2mddo(obj), name, uctxt,
                                handle);
 
        mdd_trans_stop(mdd, handle);
        RETURN(rc);
}

static int 
__mdd_index_delete(struct mdd_device *mdd, struct mdd_object *pobj,
                   struct mdd_object *obj, const char *name, 
                   struct context *uctxt, void *handle)
{
        int rc;
        ENTRY;

        mdd_object_get(mdd, pobj);
        mdd_lock(mdd, pobj, WRITE_LOCK);
        mdd_lock(mdd, obj, WRITE_LOCK);

        rc = mdd_child_ops(mdd)->osd_index_delete(mdd_object_child(pobj),
                                              mdd_object_getfid(obj), name, 
                                              uctxt, handle);
        mdd_unlock(mdd, pobj, WRITE_LOCK);
        mdd_unlock(mdd, obj, WRITE_LOCK);
        mdd_object_put(mdd, pobj);

        RETURN(rc);
}

static int
mdd_index_delete(struct md_object *pobj, struct md_object *obj, 
                 const char *name, struct context *uctxt)
{
        struct mdd_object *mdd_pobj = mdo2mddo(pobj);
        struct mdd_object *mdd_obj = mdo2mddo(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        void *handle = NULL;
        int rc;
        ENTRY;

        handle = mdd_trans_start(mdd, mdo2mddo(obj));
        if (!handle)
                RETURN(-ENOMEM);

        rc = __mdd_index_delete(mdd, mdd_pobj, mdd_obj, name, uctxt, handle);

        mdd_trans_stop(mdd, handle);
        
        RETURN(rc);
}

static int
mdd_link(struct md_object *tgt_obj, struct md_object *src_obj, 
         const char *name, struct context *uctxt)
{
        struct mdd_object *mdd_tobj = mdo2mddo(tgt_obj);
        struct mdd_object *mdd_sobj = mdo2mddo(src_obj);
        struct mdd_device *mdd = mdo2mdd(src_obj);
        void *handle = NULL;
        int rc, nlink;
        ENTRY;

        handle = mdd_trans_start(mdd, mdd_sobj);
        if (!handle)
                RETURN(-ENOMEM);

        mdd_lock(mdd, mdd_tobj, WRITE_LOCK);
        mdd_lock(mdd, mdd_sobj, WRITE_LOCK);

        rc = __mdd_index_insert(mdd, mdd_tobj, mdd_sobj, name, uctxt, handle);
        if (rc)
                GOTO(exit, rc);

        rc = mdd_attr_get(src_obj, &nlink, sizeof(nlink), "NLINK", uctxt);
        ++nlink;

        rc = __mdd_attr_set(mdd, mdd_sobj, &nlink, sizeof(nlink), "NLINK", 
                            uctxt, handle);
exit:
        mdd_unlock(mdd, mdd_tobj, WRITE_LOCK);
        mdd_unlock(mdd, mdd_sobj, WRITE_LOCK);

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
mdd_rename(struct md_object *src_pobj, struct md_object *tgt_pobj, 
           struct md_object *sobj, const char *sname, struct md_object *tobj,
           const char *tname, struct context *uctxt)
{
        struct mdd_device *mdd = mdo2mdd(src_pobj);
        struct mdd_object *mdd_spobj = mdo2mddo(src_pobj);
        struct mdd_object *mdd_tpobj = mdo2mddo(tgt_pobj);
        struct mdd_object *mdd_sobj = mdo2mddo(sobj);
        struct mdd_object *mdd_tobj = mdo2mddo(tobj);
        int rc; 
        void *handle = NULL;
 
        handle = mdd_trans_start(mdd, mdd_spobj);
        if (!handle)
                RETURN(-ENOMEM);

        mdd_rename_lock(mdd, mdd_spobj, mdd_tpobj, mdd_sobj, mdd_tobj);

        rc = __mdd_index_delete(mdd, mdd_spobj, mdd_sobj, sname, uctxt, handle);
        if (rc)
                GOTO(cleanup, rc);

        rc = __mdd_index_delete(mdd, mdd_tpobj, mdd_tobj, tname, uctxt, handle);
        if (rc)
                GOTO(cleanup, rc);

        rc = __mdd_index_insert(mdd, mdd_spobj, mdd_tobj, tname, uctxt, handle);
        if (rc)
                GOTO(cleanup, rc);

        rc = __mdd_object_destroy(mdd, mdd_sobj, handle);
        if (rc)
                GOTO(cleanup, rc);
cleanup:
        mdd_rename_unlock(mdd, mdd_spobj, mdd_tpobj, mdd_sobj, mdd_tobj);
        mdd_trans_stop(mdd, handle);
        RETURN(rc);
}

static int
mdd_mkdir(struct md_object *pobj, const char *name, struct md_object *child)
{
        struct mdd_device *mdd = mdo2mdd(pobj);
        void *handle;
        int rc = 0;
        ENTRY;

        handle = mdd_trans_start(mdd, mdo2mddo(pobj));
        if (!handle)
                RETURN(-ENOMEM);

        mdd_lock(mdd, mdo2mddo(pobj), WRITE_LOCK);

        rc = __mdd_object_create(mdd, mdo2mddo(pobj), mdo2mddo(child), NULL,
                                 handle);
        if (rc)
                GOTO(cleanup, rc);

        rc = __mdd_index_insert(mdd, mdo2mddo(pobj), mdo2mddo(child), name,
                                NULL, handle);
        if (rc)
                GOTO(cleanup, rc);
cleanup:
        mdd_unlock(mdd, mdo2mddo(pobj), WRITE_LOCK);
        mdd_trans_stop(mdd, handle);
        RETURN(rc);
}

static int mdd_root_get(struct md_device *m, struct lu_fid *f)
{
        return 0;
}

struct md_device_operations mdd_ops = {
        .mdo_root_get   = mdd_root_get,
        .mdo_mkdir      = mdd_mkdir,
        .mdo_rename     = mdd_rename,
        .mdo_link       = mdd_link,
        .mdo_attr_get   = mdd_attr_get,
        .mdo_attr_set   = mdd_attr_set,
        .mdo_index_insert = mdd_index_insert,
        .mdo_index_delete = mdd_index_delete,
        .mdo_object_create = mdd_object_create,
};

static int mdd_fs_setup(struct mdd_device *mdd)
{
        return 0;
}

static int mdd_fs_cleanup(struct mdd_device *mdd)
{
        return 0;
}

static int mdd_setup(struct mdd_device *mdd, struct lustre_cfg* lcfg)
{
        int rc = 0;
        ENTRY;

        rc = mdd_fs_setup(mdd);
        if (rc) 
                GOTO(err, rc);
        
        RETURN(rc);
err:
        mdd_fs_cleanup(mdd);
        RETURN(rc);
}

static int __init mdd_mod_init(void)
{
	return 0;
}

static void __exit mdd_mod_exit(void)
{
        return;
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Meta-data Device Prototype ("LUSTRE_MDD_NAME")");
MODULE_LICENSE("GPL");

cfs_module(mdd, "0.0.2", mdd_mod_init, mdd_mod_exit);

