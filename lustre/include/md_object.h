/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Extention of lu_object.h for metadata objects
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef _LUSTRE_MD_OBJECT_H
#define _LUSTRE_MD_OBJECT_H

/*
 * Sub-class of lu_object with methods common for "meta-data" objects in MDT
 * stack.
 *
 * Meta-data objects implement namespace operations: you can link, unlink
 * them, and treat them as directories.
 *
 * Examples: mdt, cmm, and mdt are implementations of md interface.
 */


/*
 * super-class definitions.
 */
#include <lu_object.h>

struct md_device;
struct md_device_operations;
struct md_object;

/*
 * Operations implemented for each md object (both directory and leaf).
 */
struct md_object_operations {
        int (*moo_attr_get)(const struct lu_context *ctxt, struct md_object *dt,
                            struct lu_attr *attr);
        int (*moo_attr_set)(const struct lu_context *ctxt, struct md_object *dt,
                            struct lu_attr *attr);

        int (*moo_xattr_get)(const struct lu_context *ctxt,
                             struct md_object *obj,
                             void *buf, int buf_len, const char *name);

        int (*moo_xattr_set)(const struct lu_context *ctxt,
                             struct md_object *obj,
                             void *buf, int buf_len, const char *name);
        /* part of cross-ref operation */
        int (*moo_object_create)(const struct lu_context *,
                                 struct md_object *, struct lu_attr *);
        int (*moo_ref_add)(const struct lu_context *, struct md_object *);
        int (*moo_ref_del)(const struct lu_context *, struct md_object *);
        int (*moo_open)(const struct lu_context *, struct md_object *);
        int (*moo_close)(const struct lu_context *, struct md_object *);
};

/*
 * Operations implemented for each directory object.
 */
struct md_dir_operations {
        int (*mdo_lookup)(const struct lu_context *, struct md_object *,
                          const char *, struct lu_fid *);

        int (*mdo_mkdir)(const struct lu_context *, struct lu_attr *,
                         struct md_object *, const char *,
                         struct md_object *);

        int (*mdo_create)(const struct lu_context *, struct md_object *,
                          const char *, struct md_object *,
                          struct lu_attr *);

        int (*mdo_rename)(const struct lu_context *ctxt,
                          struct md_object *spobj, struct md_object *tpobj,
                          const struct lu_fid *lf, const char *sname,
                          struct md_object *tobj, const char *tname);

        int (*mdo_link)(const struct lu_context *ctxt, struct md_object *tobj,
                        struct md_object *sobj, const char *name);

        int (*mdo_unlink)(const struct lu_context *, struct md_object *,
                          struct md_object *, const char *);

        /* partial ops for cross-ref case */
        int (*mdo_name_insert)(const struct lu_context *, struct md_object *,
                               const char *, const struct lu_fid *);
        int (*mdo_name_remove)(const struct lu_context *, struct md_object *,
                               const char *);
        int (*mdo_rename_tgt)(const struct lu_context *, struct md_object *,
                              struct md_object *, const struct lu_fid *,
                              const char *);
};

struct md_device_operations {
        /* method for getting/setting device wide back stored config data, like
         * last used meta-sequence, etc. */
        int (*mdo_config) (const struct lu_context *ctx,
                           struct md_device *m, const char *name,
                           void *buf, int size, int mode);

        /* meta-data device related handlers. */
        int (*mdo_root_get)(const struct lu_context *ctx,
                            struct md_device *m, struct lu_fid *f);
        int (*mdo_statfs)(const struct lu_context *ctx,
                          struct md_device *m, struct kstatfs *sfs);

};

struct md_device {
        struct lu_device             md_lu_dev;
        struct md_device_operations *md_ops;
};

struct md_object {
        struct lu_object             mo_lu;
        struct md_object_operations *mo_ops;
        struct md_dir_operations    *mo_dir_ops;
};

static inline int lu_device_is_md(const struct lu_device *d)
{
        return ergo(d != NULL, d->ld_type->ldt_tags & LU_DEVICE_MD);
}

static inline struct md_device *lu2md_dev(const struct lu_device *d)
{
        LASSERT(lu_device_is_md(d));
        return container_of0(d, struct md_device, md_lu_dev);
}

static inline struct lu_device *md2lu_dev(struct md_device *d)
{
        return &d->md_lu_dev;
}

static inline struct md_object *lu2md(const struct lu_object *o)
{
        LASSERT(lu_device_is_md(o->lo_dev));
        return container_of0(o, struct md_object, mo_lu);
}

static inline struct md_object *md_object_next(const struct md_object *obj)
{
        return lu2md(lu_object_next(&obj->mo_lu));
}

static inline struct md_device *md_device_get(const struct md_object *o)
{
        LASSERT(lu_device_is_md(o->mo_lu.lo_dev));
        return container_of0(o->mo_lu.lo_dev, struct md_device, md_lu_dev);
}

static inline int md_device_init(struct md_device *md, struct lu_device_type *t)
{
	return lu_device_init(&md->md_lu_dev, t);
}

static inline void md_device_fini(struct md_device *md)
{
	lu_device_fini(&md->md_lu_dev);
}

/* md operations */
static inline int mo_attr_get(const struct lu_context *cx, struct md_object *m,
                              struct lu_attr *at)
{
        LASSERT(m->mo_ops->moo_attr_get);
        return m->mo_ops->moo_attr_get(cx, m, at);
}

static inline int mo_xattr_get(const struct lu_context *cx,
                               struct md_object *m,
                               void *buf, int buf_len, const char *name)
{
        LASSERT(m->mo_ops->moo_xattr_get);
        return m->mo_ops->moo_xattr_get(cx, m, buf, buf_len, name);
}


static inline int mo_open(const struct lu_context *cx, struct md_object *m)
{
        LASSERT(m->mo_ops->moo_open);
        return m->mo_ops->moo_open(cx, m);
}

static inline int mo_object_create(const struct lu_context *cx,
                                   struct md_object *m, struct lu_attr *at)
{
        LASSERT(m->mo_ops->moo_object_create);
        return m->mo_ops->moo_object_create(cx, m, at);
}

static inline int mdo_lookup(const struct lu_context *cx, struct md_object *p,
                             const char *name, struct lu_fid *f)
{
        LASSERT(p->mo_dir_ops->mdo_lookup);
        return p->mo_dir_ops->mdo_lookup(cx, p, name, f);
}

static inline int mdo_mkdir(const struct lu_context *cx, struct lu_attr *at,
                            struct md_object *p, const char *name,
                            struct md_object *c)
{
        LASSERT(p->mo_dir_ops->mdo_mkdir);
        return p->mo_dir_ops->mdo_mkdir(cx, at, p, name, c);
}

static inline int mdo_create(const struct lu_context *cx,
                             struct md_object *p, const char *name,
                             struct md_object *c, struct lu_attr *at)
{
        LASSERT(c->mo_dir_ops->mdo_create);
        return c->mo_dir_ops->mdo_create(cx, p, name, c, at);
}

static inline int mdo_rename(const struct lu_context *cx,
                             struct md_object *sp, struct md_object *tp,
                             const struct lu_fid *lf, const char *sname,
                             struct md_object *t, const char *tname)
{
        LASSERT(tp->mo_dir_ops->mdo_rename);
        return tp->mo_dir_ops->mdo_rename(cx, sp, tp, lf, sname, t, tname);
}

static inline int mdo_link(const struct lu_context *cx, struct md_object *p,
                           struct md_object *s, const char *name)
{
        LASSERT(s->mo_dir_ops->mdo_link);
        return s->mo_dir_ops->mdo_link(cx, p, s, name);
}

static inline int mdo_unlink(const struct lu_context *cx, struct md_object *p,
                             struct md_object *c, const char *name)
{
        LASSERT(c->mo_dir_ops->mdo_unlink);
        return c->mo_dir_ops->mdo_unlink(cx, p, c, name);
}

static inline int mdo_name_insert(const struct lu_context *cx,
                                  struct md_object *p,
                                  const char *name, const struct lu_fid *f)
{
        LASSERT(p->mo_dir_ops->mdo_name_insert);
        return p->mo_dir_ops->mdo_name_insert(cx, p, name, f);
}

static inline int mdo_name_remove(const struct lu_context *cx,
                                  struct md_object *p,
                                  const char *name)
{
        LASSERT(p->mo_dir_ops->mdo_name_remove);
        return p->mo_dir_ops->mdo_name_remove(cx, p, name);
}

static inline int mdo_rename_tgt(const struct lu_context *cx,
                                 struct md_object *p, struct md_object *t,
                                 const struct lu_fid *lf, const char *name)
{
        if (t) {
                LASSERT(t->mo_dir_ops->mdo_rename_tgt);
                return t->mo_dir_ops->mdo_rename_tgt(cx, p, t, lf, name);
        } else {
                LASSERT(p->mo_dir_ops->mdo_rename_tgt);
                return p->mo_dir_ops->mdo_rename_tgt(cx, p, t, lf, name);
        }
}
#endif /* _LINUX_MD_OBJECT_H */
