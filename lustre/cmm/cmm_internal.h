/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/cmm/cmm_internal.h
 *  Lustre Cluster Metadata Manager (cmm)
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
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

#ifndef _CMM_INTERNAL_H
#define _CMM_INTERNAL_H

#if defined(__KERNEL__)

#include <obd.h>
#include <lustre_fld.h>
#include <md_object.h>

struct cmm_device {
        struct md_device       cmm_md_dev;
        /* device flags, taken from enum cmm_flags */
        __u32                 cmm_flags;
        /* underlaying device in MDS stack, usually MDD */
        struct md_device      *cmm_child;
        /* other MD servers in cluster */
        mdsno_t               cmm_local_num;
        __u32                 cmm_tgt_count;
        struct list_head      cmm_targets;
        spinlock_t            cmm_tgt_guard;
};

enum cmm_flags {
        /*
         * Device initialization complete.
         */
        CMM_INITIALIZED = 1 << 0
};

static inline struct md_device_operations *cmm_child_ops(struct cmm_device *d)
{
        return (d->cmm_child->md_ops);
}

static inline struct cmm_device *md2cmm_dev(struct md_device *m)
{
        return container_of0(m, struct cmm_device, cmm_md_dev);
}

static inline struct cmm_device *lu2cmm_dev(struct lu_device *d)
{
        return container_of0(d, struct cmm_device, cmm_md_dev.md_lu_dev);
}

static inline struct lu_device *cmm2lu_dev(struct cmm_device *d)
{
        return (&d->cmm_md_dev.md_lu_dev);
}

struct cmm_object {
        struct md_object cmo_obj;
};

/* local CMM object */
struct cml_object {
        struct cmm_object cmm_obj;
};

/* remote CMM object */
struct cmr_object {
        struct cmm_object cmm_obj;
        /* mds number where object is placed */
        mdsno_t           cmo_num;
};

struct cmm_thread_info {
        struct md_attr  cmi_ma;
};

static inline struct cmm_device *cmm_obj2dev(struct cmm_object *c)
{
        return (md2cmm_dev(md_obj2dev(&c->cmo_obj)));
}

static inline struct cmm_object *lu2cmm_obj(struct lu_object *o)
{
        //LASSERT(lu_device_is_cmm(o->lo_dev));
        return container_of0(o, struct cmm_object, cmo_obj.mo_lu);
}

/* get cmm object from md_object */
static inline struct cmm_object *md2cmm_obj(struct md_object *o)
{
        return container_of0(o, struct cmm_object, cmo_obj);
}
/* get lower-layer object */
static inline struct md_object *cmm2child_obj(struct cmm_object *o)
{
        return (o ? lu2md(lu_object_next(&o->cmo_obj.mo_lu)) : NULL);
}

/* cmm_object.c */
struct lu_object *cmm_object_alloc(const struct lu_context *ctx,
                                   const struct lu_object_header *hdr,
                                   struct lu_device *);


int cmm_upcall(const struct lu_context *ctxt, struct md_device *md,
               enum md_upcall_event ev);
#ifdef HAVE_SPLIT_SUPPORT
/* cmm_split.c */
int cml_try_to_split(const struct lu_context *ctx, struct md_object *mo);
#endif

#endif /* __KERNEL__ */
#endif /* _CMM_INTERNAL_H */

