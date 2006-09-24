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
#include <lvfs.h>

struct md_device;
struct md_device_operations;
struct md_object;


typedef enum {
        UCRED_INVALID   = -1,
        UCRED_INIT      = 0,
        UCRED_OLD       = 1,
        UCRED_NEW       = 2,
} ucred_t;

struct md_ucred {
        ucred_t                 mu_valid;
        __u32                   mu_o_uid;
        __u32                   mu_o_gid;
        __u32                   mu_o_fsuid;
        __u32                   mu_o_fsgid;
        __u32                   mu_uid;
        __u32                   mu_gid;
        __u32                   mu_fsuid;
        __u32                   mu_fsgid;
        __u32                   mu_cap;
        __u32                   mu_umask;
	struct group_info      *mu_ginfo;
	struct mdt_identity    *mu_identity;
};

/* metadata attributes */
enum ma_valid {
        MA_INODE = (1 << 0),
        MA_LOV   = (1 << 1),
        MA_COOKIE = (1 << 2),
        MA_FLAGS = (1 << 3),
        MA_LMV   = (1 << 4)
};

struct md_attr {
        __u64                   ma_valid;
        __u64                   ma_need;
        __u64                   ma_attr_flags;
        struct lu_attr          ma_attr;
        struct lov_mds_md      *ma_lmm;
        int                     ma_lmm_size;
        struct lmv_stripe_md   *ma_lmv;
        int                     ma_lmv_size;
        struct llog_cookie     *ma_cookie;
        int                     ma_cookie_size;
};

/* additional parameters for create */
struct md_create_spec {
        union {
                /* symlink target */
                const char               *sp_symname;
                /* parent FID for cross-ref mkdir */
                const struct lu_fid      *sp_pfid;
                /* eadata for regular files */
                struct md_spec_reg {
                        /* lov objs exist already */
                        const struct lu_fid   *fid;
                        int no_lov_create;
                        const void *eadata;
                        int  eadatalen;
                } sp_ea;
        } u;
        /* create flag from client: such as MDS_OPEN_CREAT, and others */
        __u32 sp_cr_flags;
};

/*
 * Operations implemented for each md object (both directory and leaf).
 */
struct md_object_operations {
        int (*moo_permission)(const struct lu_context *ctxt,
                              struct md_object *obj,
                              int mask,
                              struct md_ucred *uc);

        int (*moo_attr_get)(const struct lu_context *ctxt,
                            struct md_object *obj,
                            struct md_attr *attr,
                            struct md_ucred *uc);

        int (*moo_attr_set)(const struct lu_context *ctxt,
                            struct md_object *obj,
                            const struct md_attr *attr,
                            struct md_ucred *uc);

        int (*moo_xattr_get)(const struct lu_context *ctxt,
                             struct md_object *obj,
                             void *buf,
                             int buf_len,
                             const char *name,
                             struct md_ucred *uc);

        int (*moo_xattr_list)(const struct lu_context *ctxt,
                              struct md_object *obj,
                              void *buf,
                              int buf_len,
                              struct md_ucred *uc);

        int (*moo_xattr_set)(const struct lu_context *ctxt,
                             struct md_object *obj,
                             const void *buf,
                             int buf_len,
                             const char *name,
                             int fl,
                             struct md_ucred *uc);

        int (*moo_xattr_del)(const struct lu_context *ctxt,
                             struct md_object *obj,
                             const char *name,
                             struct md_ucred *uc);

        int (*moo_readpage)(const struct lu_context *ctxt,
                            struct md_object *obj,
                            const struct lu_rdpg *rdpg,
                            struct md_ucred *uc);

        int (*moo_readlink)(const struct lu_context *ctxt,
                            struct md_object *obj,
                            void *buf,
                            int buf_len,
                            struct md_ucred *uc);

        /* part of cross-ref operation */
        int (*moo_object_create)(const struct lu_context *ctxt,
                                 struct md_object *obj,
                                 const struct md_create_spec *spec,
                                 struct md_attr *ma,
                                 struct md_ucred *uc);

        int (*moo_ref_add)(const struct lu_context * ctxt,
                           struct md_object *obj,
                           struct md_ucred *uc);

        int (*moo_ref_del)(const struct lu_context *ctxt,
                           struct md_object *obj,
                           struct md_attr *ma,
                           struct md_ucred *uc);

        int (*moo_open)(const struct lu_context *ctxt,
                        struct md_object *obj,
                        int flag,
                        struct md_ucred *uc);

        int (*moo_close)(const struct lu_context *ctxt,
                         struct md_object *obj,
                         struct md_attr *ma,
                         struct md_ucred *uc);
};

/*
 * Operations implemented for each directory object.
 */
struct md_dir_operations {
        int (*mdo_is_subdir) (const struct lu_context *ctxt,
                              struct md_object *obj,
                              const struct lu_fid *fid,
                              struct lu_fid *sfid,
                              struct md_ucred *uc);
        
        int (*mdo_lookup)(const struct lu_context *ctxt,
                          struct md_object *obj,
                          const char *name,
                          struct lu_fid *fid,
                          struct md_ucred *uc);

        int (*mdo_create)(const struct lu_context *ctxt,
                          struct md_object *pobj,
                          const char *name,
                          struct md_object *child,
                          const struct md_create_spec *spec,
                          struct md_attr *ma,
                          struct md_ucred *uc);

        /* This method is used for creating data object for this meta object*/
        int (*mdo_create_data)(const struct lu_context *ctxt,
                               struct md_object *p,
                               struct md_object *o,
                               const struct md_create_spec *spec,
                               struct md_attr *ma,
                               struct md_ucred *uc);

        int (*mdo_rename)(const struct lu_context *ctxt,
                          struct md_object *spobj,
                          struct md_object *tpobj,
                          const struct lu_fid *lf,
                          const char *sname,
                          struct md_object *tobj,
                          const char *tname,
                          struct md_attr *ma,
                          struct md_ucred *uc);

        int (*mdo_link)(const struct lu_context *ctxt,
                        struct md_object *tgt_obj,
                        struct md_object *src_obj,
                        const char *name,
                        struct md_attr *ma,
                        struct md_ucred *uc);

        int (*mdo_unlink)(const struct lu_context *ctxt,
                          struct md_object *pobj,
                          struct md_object *cobj,
                          const char *name,
                          struct md_attr *ma,
                          struct md_ucred *uc);

        /* partial ops for cross-ref case */
        int (*mdo_name_insert)(const struct lu_context *ctxt,
                               struct md_object *obj,
                               const char *name,
                               const struct lu_fid *fid,
                               int isdir,
                               struct md_ucred *uc);

        int (*mdo_name_remove)(const struct lu_context *ctxt,
                               struct md_object *obj, const char *name,
                               struct md_ucred *uc);

        int (*mdo_rename_tgt)(const struct lu_context *ctxt,
                              struct md_object *pobj,
                              struct md_object *tobj,
                              const struct lu_fid *fid,
                              const char *name,
                              struct md_attr *ma,
                              struct md_ucred *uc);
};

struct md_device_operations {
        /* meta-data device related handlers. */
        int (*mdo_root_get)(const struct lu_context *ctx,
                            struct md_device *m,
                            struct lu_fid *f,
                            struct md_ucred *uc);

        int (*mdo_maxsize_get)(const struct lu_context *ctx,
                               struct md_device *m,
                               int *md_size,
                               int *cookie_size,
                               struct md_ucred *uc);

        int (*mdo_statfs)(const struct lu_context *ctx,
                          struct md_device *m,
                          struct kstatfs *sfs,
                          struct md_ucred *uc);
};

enum md_upcall_event {
        /*sync the md layer*/
        MD_LOV_SYNC = (1 << 0),
        MD_NO_TRANS = (1 << 1), /* Just for split, no need trans, for replay */
};

struct md_upcall {
        struct md_device            *mu_upcall_dev;
        int (*mu_upcall)(const struct lu_context *ctxt, struct md_device *md,
                         enum md_upcall_event ev);
};

struct md_device {
        struct lu_device             md_lu_dev;
        struct md_device_operations *md_ops;
        struct md_upcall             md_upcall;
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
        return (obj ? lu2md(lu_object_next(&obj->mo_lu)) : NULL);
}

static inline struct md_device *md_obj2dev(const struct md_object *o)
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
static inline int mo_permission(const struct lu_context *cx,
                                struct md_object *m,
                                int mask,
                                struct md_ucred *uc)
{
        LASSERT(m->mo_ops->moo_permission);
        return m->mo_ops->moo_permission(cx, m, mask, uc);
}

static inline int mo_attr_get(const struct lu_context *cx,
                              struct md_object *m,
                              struct md_attr *at,
                              struct md_ucred *uc)
{
        LASSERT(m->mo_ops->moo_attr_get);
        return m->mo_ops->moo_attr_get(cx, m, at, uc);
}

static inline int mo_readlink(const struct lu_context *cx,
                              struct md_object *m,
                              void *buf,
                              int buf_len,
                              struct md_ucred *uc)
{
        LASSERT(m->mo_ops->moo_readlink);
        return m->mo_ops->moo_readlink(cx, m, buf, buf_len, uc);
}

static inline int mo_attr_set(const struct lu_context *cx,
                              struct md_object *m,
                              const struct md_attr *at,
                              struct md_ucred *uc)
{
        LASSERT(m->mo_ops->moo_attr_set);
        return m->mo_ops->moo_attr_set(cx, m, at, uc);
}

static inline int mo_xattr_get(const struct lu_context *cx,
                               struct md_object *m,
                               void *buf,
                               int buf_len,
                               const char *name,
                               struct md_ucred *uc)
{
        LASSERT(m->mo_ops->moo_xattr_get);
        return m->mo_ops->moo_xattr_get(cx, m, buf, buf_len, name, uc);
}

static inline int mo_xattr_del(const struct lu_context *cx,
                               struct md_object *m,
                               const char *name,
                               struct md_ucred *uc)
{
        LASSERT(m->mo_ops->moo_xattr_del);
        return m->mo_ops->moo_xattr_del(cx, m, name, uc);
}

static inline int mo_xattr_set(const struct lu_context *cx,
                               struct md_object *m,
                               const void *buf,
                               int buf_len,
                               const char *name,
                               int flags,
                               struct md_ucred *uc)
{
        LASSERT(m->mo_ops->moo_xattr_set);
        return m->mo_ops->moo_xattr_set(cx, m, buf, buf_len, name, flags, uc);
}

static inline int mo_xattr_list(const struct lu_context *cx,
                                struct md_object *m,
                                void *buf,
                                int buf_len,
                                struct md_ucred *uc)
{
        LASSERT(m->mo_ops->moo_xattr_list);
        return m->mo_ops->moo_xattr_list(cx, m, buf, buf_len, uc);
}

static inline int mo_open(const struct lu_context *cx,
                          struct md_object *m,
                          int flags,
                          struct md_ucred *uc)
{
        LASSERT(m->mo_ops->moo_open);
        return m->mo_ops->moo_open(cx, m, flags, uc);
}

static inline int mo_close(const struct lu_context *cx,
                           struct md_object *m,
                           struct md_attr *ma,
                           struct md_ucred *uc)
{
        LASSERT(m->mo_ops->moo_close);
        return m->mo_ops->moo_close(cx, m, ma, uc);
}

static inline int mo_readpage(const struct lu_context *cx,
                              struct md_object *m,
                              const struct lu_rdpg *rdpg,
                              struct md_ucred *uc)
{
        LASSERT(m->mo_ops->moo_readpage);
        return m->mo_ops->moo_readpage(cx, m, rdpg, uc);
}

static inline int mo_object_create(const struct lu_context *cx,
                                   struct md_object *m,
                                   const struct md_create_spec *spc,
                                   struct md_attr *at,
                                   struct md_ucred *uc)
{
        LASSERT(m->mo_ops->moo_object_create);
        return m->mo_ops->moo_object_create(cx, m, spc, at, uc);
}

static inline int mo_ref_add(const struct lu_context *cx,
                             struct md_object *m,
                             struct md_ucred *uc)
{
        LASSERT(m->mo_ops->moo_ref_add);
        return m->mo_ops->moo_ref_add(cx, m, uc);
}

static inline int mo_ref_del(const struct lu_context *cx,
                             struct md_object *m,
                             struct md_attr *ma,
                             struct md_ucred *uc)
{
        LASSERT(m->mo_ops->moo_ref_del);
        return m->mo_ops->moo_ref_del(cx, m, ma, uc);
}

static inline int mdo_lookup(const struct lu_context *cx,
                             struct md_object *p,
                             const char *name,
                             struct lu_fid *f,
                             struct md_ucred *uc)
{
        LASSERT(p->mo_dir_ops->mdo_lookup);
        return p->mo_dir_ops->mdo_lookup(cx, p, name, f, uc);
}

static inline int mdo_create(const struct lu_context *cx,
                             struct md_object *p,
                             const char *child_name,
                             struct md_object *c,
                             const struct md_create_spec *spc,
                             struct md_attr *at,
                             struct md_ucred *uc)
{
        LASSERT(c->mo_dir_ops->mdo_create);
        return c->mo_dir_ops->mdo_create(cx, p, child_name, c, spc, at, uc);
}

static inline int mdo_create_data(const struct lu_context *cx,
                                  struct md_object *p,
                                  struct md_object *c,
                                  const struct md_create_spec *spec,
                                  struct md_attr *ma,
                                  struct md_ucred *uc)
{
        LASSERT(c->mo_dir_ops->mdo_create_data);
        return c->mo_dir_ops->mdo_create_data(cx, p, c, spec, ma, uc);
}

static inline int mdo_rename(const struct lu_context *cx,
                             struct md_object *sp,
                             struct md_object *tp,
                             const struct lu_fid *lf,
                             const char *sname,
                             struct md_object *t,
                             const char *tname,
                             struct md_attr *ma,
                             struct md_ucred *uc)
{
        LASSERT(tp->mo_dir_ops->mdo_rename);
        return tp->mo_dir_ops->mdo_rename(cx, sp, tp, lf, sname, t, tname,
                                          ma, uc);
}

static inline int mdo_is_subdir(const struct lu_context *cx,
                                struct md_object *mo,
                                const struct lu_fid *fid,
                                struct lu_fid *sfid,
                                struct md_ucred *uc)
{
        LASSERT(mo->mo_dir_ops->mdo_is_subdir);
        return mo->mo_dir_ops->mdo_is_subdir(cx, mo, fid, sfid, uc);
}

static inline int mdo_link(const struct lu_context *cx,
                           struct md_object *p,
                           struct md_object *s,
                           const char *name,
                           struct md_attr *ma,
                           struct md_ucred *uc)
{
        LASSERT(s->mo_dir_ops->mdo_link);
        return s->mo_dir_ops->mdo_link(cx, p, s, name, ma, uc);
}

static inline int mdo_unlink(const struct lu_context *cx,
                             struct md_object *p,
                             struct md_object *c,
                             const char *name,
                             struct md_attr *ma,
                             struct md_ucred *uc)
{
        LASSERT(c->mo_dir_ops->mdo_unlink);
        return c->mo_dir_ops->mdo_unlink(cx, p, c, name, ma, uc);
}

static inline int mdo_name_insert(const struct lu_context *cx,
                                  struct md_object *p,
                                  const char *name,
                                  const struct lu_fid *f,
                                  int isdir,
                                  struct md_ucred *uc)
{
        LASSERT(p->mo_dir_ops->mdo_name_insert);
        return p->mo_dir_ops->mdo_name_insert(cx, p, name, f, isdir, uc);
}

static inline int mdo_name_remove(const struct lu_context *cx,
                                  struct md_object *p,
                                  const char *name,
                                  struct md_ucred *uc)
{
        LASSERT(p->mo_dir_ops->mdo_name_remove);
        return p->mo_dir_ops->mdo_name_remove(cx, p, name, uc);
}

static inline int mdo_rename_tgt(const struct lu_context *cx,
                                 struct md_object *p,
                                 struct md_object *t,
                                 const struct lu_fid *lf,
                                 const char *name,
                                 struct md_attr *ma,
                                 struct md_ucred *uc)
{
        if (t) {
                LASSERT(t->mo_dir_ops->mdo_rename_tgt);
                return t->mo_dir_ops->mdo_rename_tgt(cx, p, t, lf, name,
                                                     ma, uc);
        } else {
                LASSERT(p->mo_dir_ops->mdo_rename_tgt);
                return p->mo_dir_ops->mdo_rename_tgt(cx, p, t, lf, name,
                                                     ma, uc);
        }
}

#endif /* _LINUX_MD_OBJECT_H */
