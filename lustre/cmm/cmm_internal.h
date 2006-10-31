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
#include <linux/lustre_acl.h>


struct cmm_device {
        struct md_device      cmm_md_dev;
        /* device flags, taken from enum cmm_flags */
        __u32                 cmm_flags;
        /* underlaying device in MDS stack, usually MDD */
        struct md_device      *cmm_child;
        /* FLD client to talk to FLD */
        struct lu_client_fld *cmm_fld;
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

#ifdef HAVE_SPLIT_SUPPORT
enum {
        CMM_SPLIT_UNKNOWN,
        CMM_SPLIT_NONE,
        CMM_SPLIT_NEEDED,
        CMM_SPLIT_DONE,
        CMM_SPLIT_DENIED
};
#endif
struct cmm_object {
        struct md_object cmo_obj;
};

/* local CMM object */
struct cml_object {
        struct cmm_object cmm_obj;
#ifdef HAVE_SPLIT_SUPPORT
        /* split state of object (for dirs only)*/
        __u32             clo_split;
#endif
};

/* remote CMM object */
struct cmr_object {
        struct cmm_object cmm_obj;
        /* mds number where object is placed */
        mdsno_t           cmo_num;
};

struct cmm_thread_info {
        struct md_attr  cmi_ma;
        struct lu_buf   cmi_buf;
        char            cmi_xattr_buf[LUSTRE_POSIX_ACL_MAX_SIZE];
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

static inline struct lu_fid* cmm2fid(struct cmm_object *obj)
{
       return &(obj->cmo_obj.mo_lu.lo_header->loh_fid);
}

struct cmm_thread_info *cmm_env_info(const struct lu_env *env);
/* cmm_object.c */
struct lu_object *cmm_object_alloc(const struct lu_env *env,
                                   const struct lu_object_header *hdr,
                                   struct lu_device *);

/*
 * local CMM object operations. cml_...
 */
static inline struct cml_object *lu2cml_obj(struct lu_object *o)
{
        return container_of0(o, struct cml_object, cmm_obj.cmo_obj.mo_lu);
}
static inline struct cml_object *md2cml_obj(struct md_object *mo)
{
        return container_of0(mo, struct cml_object, cmm_obj.cmo_obj);
}
static inline struct cml_object *cmm2cml_obj(struct cmm_object *co)
{
        return container_of0(co, struct cml_object, cmm_obj);
}

int cmm_upcall(const struct lu_env *env, struct md_device *md,
               enum md_upcall_event ev);
#ifdef HAVE_SPLIT_SUPPORT

/* cmm_split.c */
static inline struct lu_buf *cmm_buf_get(const struct lu_env *env,
                                         void *area, ssize_t len)
{
        struct lu_buf *buf;

        buf = &cmm_env_info(env)->cmi_buf;
        buf->lb_buf = area;
        buf->lb_len = len;
        return buf;
}

int cmm_split_check(const struct lu_env *env, struct md_object *mp,
                    const char *name);

int cmm_split_expect(const struct lu_env *env, struct md_object *mo,
                     struct md_attr *ma, int *split);

int cmm_split_try(const struct lu_env *env, struct md_object *mo);

int cmm_split_access(const struct lu_env *env, struct md_object *mo,
                     mdl_mode_t lm);
#endif

int cmm_fld_lookup(struct cmm_device *cm, const struct lu_fid *fid,
                   mdsno_t *mds, const struct lu_env *env);

#endif /* __KERNEL__ */
#endif /* _CMM_INTERNAL_H */

