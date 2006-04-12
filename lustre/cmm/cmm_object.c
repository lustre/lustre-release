/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/cmm/cmm_object.c
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

#include "cmm_internal.h"

static struct md_object_operations cmm_mo_ops;

struct cmm_object *cmm_object_find(struct cmm_device *d, struct lu_fid *f)
{
	struct lu_object *o;

	o = lu_object_find(d->cmm_md_dev.md_lu_dev.ld_site, f);
	if (IS_ERR(o))
		return (struct cmm_object *)o;
	else
		return container_of(o, struct cmm_object, cmo_obj.mo_lu);
}

void cmm_object_put(struct cmm_object *o)
{
	lu_object_put(&o->cmo_obj.mo_lu);
}

struct lu_object *cmm_object_alloc(struct lu_device *d)
{
	struct cmm_object *mo;
        ENTRY;

	OBD_ALLOC_PTR(mo);
	if (mo != NULL) {
		struct lu_object *o;

		o = &mo->cmo_obj.mo_lu;
                lu_object_init(o, NULL, d);
                mo->cmo_obj.mo_ops = &cmm_mo_ops;
		RETURN(o);
	} else
		RETURN(NULL);
}

int cmm_object_init(struct lu_object *o)
{
	struct cmm_device *d = lu2cmm_dev(o->lo_dev);
	struct lu_device  *under;
	struct lu_object  *below;
        ENTRY;

	under = &d->cmm_child->md_lu_dev;
	below = under->ld_ops->ldo_object_alloc(under);
	if (below != NULL) {
		lu_object_add(o, below);
		RETURN(0);
	} else
		RETURN(-ENOMEM);
}

void cmm_object_free(struct lu_object *o)
{
	lu_object_fini(o);
}

void cmm_object_release(struct lu_object *o)
{
        return;
}

int cmm_object_print(struct seq_file *f, const struct lu_object *o)
{
	return seq_printf(f, LUSTRE_CMM0_NAME"-object@%p", o);
}

/* Locking API */
#if 0
static void cmm_lock(struct md_object *obj, __u32 mode)
{
        struct cmm_object *cmm_obj = md2cmm_obj(obj);
        struct cmm_device *cmm_dev = cmm_obj2dev(cmm_obj);

        CMM_DO_CHILD(cmm_dev)->ldo_lock_obj(cmm2child_obj(cmm_obj), mode);
        return;
}

static void cmm_unlock(struct md_object *obj, __u32 mode)
{
        struct cmm_object *cmm_obj = md2cmm_obj(obj);
        struct cmm_device *cmm_dev = cmm_obj2dev(cmm_obj);

        CMM_DO_CHILD(cmm_dev)->ldo_unlock_obj(cmm2child_obj(cmm_obj), mode);
        return;
}
#endif
/* Llog API */
/* Object API */
/* Metadata API */
int cmm_root_get(struct md_device *md, struct lu_fid *fid) {
        struct cmm_device *cmm_dev = md2cmm_dev(md);

        return cmm_child_ops(cmm_dev)->mdo_root_get(cmm_dev->cmm_child, fid);
}

int cmm_config(struct md_device *md, const char *name,
               void *buf, int size, int mode)
{
        struct cmm_device *cmm_dev = md2cmm_dev(md);
        int result;
        ENTRY;
        result = cmm_child_ops(cmm_dev)->mdo_config(cmm_dev->cmm_child,
                                                    name, buf, size, mode);
        RETURN(result);
}

int cmm_statfs(struct md_device *md, struct kstatfs *sfs) {
        struct cmm_device *cmm_dev = md2cmm_dev(md);
	int result;

        ENTRY;
        result = cmm_child_ops(cmm_dev)->mdo_statfs(cmm_dev->cmm_child, sfs);
        RETURN (result);
}

int cmm_mkdir(struct md_object *md_parent, const char *name,
                     struct md_object *md_child)
{
	struct cmm_object *cmm_parent = md2cmm_obj(md_parent);

        return md_parent->mo_ops->moo_mkdir(cmm2child_obj(cmm_parent),
                                            name, md_child);
}

static struct md_object_operations cmm_mo_ops = {
        .moo_mkdir      = cmm_mkdir,
        .moo_mkdir      = cmm_mkdir,
        .moo_attr_get   = cmm_attr_get,
//        .moo_rename     = cmm_rename,
//        .moo_link       = cmm_link,
//        .moo_attr_set   = cmm_attr_set,
//        .moo_index_insert = cmm_index_insert,
//        .moo_index_delete = cmm_index_delete,
//        .moo_object_create = cmm_object_create,
};

int cmm_attr_get(struct md_object *obj, void *buf, int size,
                 const char *name, struct context *ctxt)
{
        struct md_object *next = cmm2child_obj(md2cmm_obj(obj));

        LASSERT((void *)obj->mo_ops > (void *)0x100);
        return obj->mo_ops->moo_attr_get(next, buf, size, name, ctxt);
}

