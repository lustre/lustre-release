/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mdd/mdd_object.c
 *
 * Lustre Metadata Server (mdd) routines
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lprocfs_status.h>
/* fid_be_cpu(), fid_cpu_to_be(). */
#include <lustre_fid.h>
#include <obd_lov.h>

#include <lustre_param.h>
#include <lustre_mds.h>
#include <lustre/lustre_idl.h>

#include "mdd_internal.h"

static const struct lu_object_operations mdd_lu_obj_ops;

static int mdd_xattr_get(const struct lu_env *env,
                         struct md_object *obj, struct lu_buf *buf,
                         const char *name);

int mdd_data_get(const struct lu_env *env, struct mdd_object *obj,
                 void **data)
{
        if (mdd_object_exists(obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(obj), PFID(mdd_object_fid(obj)));
                return -ENOENT;
        }
        mdo_data_get(env, obj, data);
        return 0;
}

int mdd_la_get(const struct lu_env *env, struct mdd_object *obj,
               struct lu_attr *la, struct lustre_capa *capa)
{
        if (mdd_object_exists(obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(obj), PFID(mdd_object_fid(obj)));
                return -ENOENT;
        }
        return mdo_attr_get(env, obj, la, capa);
}

static void mdd_flags_xlate(struct mdd_object *obj, __u32 flags)
{
        obj->mod_flags &= ~(APPEND_OBJ|IMMUTE_OBJ);

        if (flags & LUSTRE_APPEND_FL)
                obj->mod_flags |= APPEND_OBJ;

        if (flags & LUSTRE_IMMUTABLE_FL)
                obj->mod_flags |= IMMUTE_OBJ;
}

struct mdd_thread_info *mdd_env_info(const struct lu_env *env)
{
        struct mdd_thread_info *info;

        info = lu_context_key_get(&env->le_ctx, &mdd_thread_key);
        LASSERT(info != NULL);
        return info;
}

struct lu_buf *mdd_buf_get(const struct lu_env *env, void *area, ssize_t len)
{
        struct lu_buf *buf;

        buf = &mdd_env_info(env)->mti_buf;
        buf->lb_buf = area;
        buf->lb_len = len;
        return buf;
}

void mdd_buf_put(struct lu_buf *buf)
{
        if (buf == NULL || buf->lb_buf == NULL)
                return;
        OBD_FREE_LARGE(buf->lb_buf, buf->lb_len);
        buf->lb_buf = NULL;
        buf->lb_len = 0;
}

const struct lu_buf *mdd_buf_get_const(const struct lu_env *env,
                                       const void *area, ssize_t len)
{
        struct lu_buf *buf;

        buf = &mdd_env_info(env)->mti_buf;
        buf->lb_buf = (void *)area;
        buf->lb_len = len;
        return buf;
}

struct lu_buf *mdd_buf_alloc(const struct lu_env *env, ssize_t len)
{
        struct lu_buf *buf = &mdd_env_info(env)->mti_big_buf;

        if ((len > buf->lb_len) && (buf->lb_buf != NULL)) {
                OBD_FREE_LARGE(buf->lb_buf, buf->lb_len);
                buf->lb_buf = NULL;
        }
        if (buf->lb_buf == NULL) {
                buf->lb_len = len;
                OBD_ALLOC_LARGE(buf->lb_buf, buf->lb_len);
                if (buf->lb_buf == NULL)
                        buf->lb_len = 0;
        }
        return buf;
}

/** Increase the size of the \a mti_big_buf.
 * preserves old data in buffer
 * old buffer remains unchanged on error
 * \retval 0 or -ENOMEM
 */
int mdd_buf_grow(const struct lu_env *env, ssize_t len)
{
        struct lu_buf *oldbuf = &mdd_env_info(env)->mti_big_buf;
        struct lu_buf buf;

        LASSERT(len >= oldbuf->lb_len);
        OBD_ALLOC_LARGE(buf.lb_buf, len);

        if (buf.lb_buf == NULL)
                return -ENOMEM;

        buf.lb_len = len;
        memcpy(buf.lb_buf, oldbuf->lb_buf, oldbuf->lb_len);

        OBD_FREE_LARGE(oldbuf->lb_buf, oldbuf->lb_len);

        memcpy(oldbuf, &buf, sizeof(buf));

        return 0;
}

struct llog_cookie *mdd_max_cookie_get(const struct lu_env *env,
                                       struct mdd_device *mdd)
{
        struct mdd_thread_info *mti = mdd_env_info(env);
        int                     max_cookie_size;

        max_cookie_size = mdd_lov_cookiesize(env, mdd);
        if (unlikely(mti->mti_max_cookie_size < max_cookie_size)) {
                if (mti->mti_max_cookie)
                        OBD_FREE_LARGE(mti->mti_max_cookie,
                                       mti->mti_max_cookie_size);
                mti->mti_max_cookie = NULL;
                mti->mti_max_cookie_size = 0;
        }
        if (unlikely(mti->mti_max_cookie == NULL)) {
                OBD_ALLOC_LARGE(mti->mti_max_cookie, max_cookie_size);
                if (likely(mti->mti_max_cookie != NULL))
                        mti->mti_max_cookie_size = max_cookie_size;
        }
        if (likely(mti->mti_max_cookie != NULL))
                memset(mti->mti_max_cookie, 0, mti->mti_max_cookie_size);
        return mti->mti_max_cookie;
}

struct lov_mds_md *mdd_max_lmm_buffer(const struct lu_env *env, int size)
{
        struct mdd_thread_info *mti = mdd_env_info(env);

        if (unlikely(mti->mti_max_lmm_size < size)) {
                int rsize = size_roundup_power2(size);

                if (mti->mti_max_lmm_size > 0) {
                        LASSERT(mti->mti_max_lmm);
                        OBD_FREE_LARGE(mti->mti_max_lmm,
                                       mti->mti_max_lmm_size);
                        mti->mti_max_lmm = NULL;
                        mti->mti_max_lmm_size = 0;
                }

                OBD_ALLOC_LARGE(mti->mti_max_lmm, rsize);
                if (likely(mti->mti_max_lmm != NULL))
                        mti->mti_max_lmm_size = rsize;
        }
        return mti->mti_max_lmm;
}

struct lov_mds_md *mdd_max_lmm_get(const struct lu_env *env,
                                   struct mdd_device *mdd)
{
        int max_lmm_size;

        max_lmm_size = mdd_lov_mdsize(env, mdd);
        return mdd_max_lmm_buffer(env, max_lmm_size);
}

struct lu_object *mdd_object_alloc(const struct lu_env *env,
                                   const struct lu_object_header *hdr,
                                   struct lu_device *d)
{
        struct mdd_object *mdd_obj;

        OBD_ALLOC_PTR(mdd_obj);
        if (mdd_obj != NULL) {
                struct lu_object *o;

                o = mdd2lu_obj(mdd_obj);
                lu_object_init(o, NULL, d);
                mdd_obj->mod_obj.mo_ops = &mdd_obj_ops;
                mdd_obj->mod_obj.mo_dir_ops = &mdd_dir_ops;
                mdd_obj->mod_count = 0;
                o->lo_ops = &mdd_lu_obj_ops;
                return o;
        } else {
                return NULL;
        }
}

static int mdd_object_init(const struct lu_env *env, struct lu_object *o,
                           const struct lu_object_conf *unused)
{
        struct mdd_device *d = lu2mdd_dev(o->lo_dev);
        struct mdd_object *mdd_obj = lu2mdd_obj(o);
        struct lu_object  *below;
        struct lu_device  *under;
        ENTRY;

        mdd_obj->mod_cltime = 0;
        under = &d->mdd_child->dd_lu_dev;
        below = under->ld_ops->ldo_object_alloc(env, o->lo_header, under);
        mdd_pdlock_init(mdd_obj);
        if (below == NULL)
                RETURN(-ENOMEM);

        lu_object_add(o, below);

        RETURN(0);
}

static int mdd_object_start(const struct lu_env *env, struct lu_object *o)
{
        if (lu_object_exists(o))
                return mdd_get_flags(env, lu2mdd_obj(o));
        else
                return 0;
}

static void mdd_object_free(const struct lu_env *env, struct lu_object *o)
{
        struct mdd_object *mdd = lu2mdd_obj(o);

        lu_object_fini(o);
        OBD_FREE_PTR(mdd);
}

static int mdd_object_print(const struct lu_env *env, void *cookie,
                            lu_printer_t p, const struct lu_object *o)
{
        struct mdd_object *mdd = lu2mdd_obj((struct lu_object *)o);
        return (*p)(env, cookie, LUSTRE_MDD_NAME"-object@%p(open_count=%d, "
                    "valid=%x, cltime="LPU64", flags=%lx)",
                    mdd, mdd->mod_count, mdd->mod_valid,
                    mdd->mod_cltime, mdd->mod_flags);
}

static const struct lu_object_operations mdd_lu_obj_ops = {
        .loo_object_init    = mdd_object_init,
        .loo_object_start   = mdd_object_start,
        .loo_object_free    = mdd_object_free,
        .loo_object_print   = mdd_object_print,
};

struct mdd_object *mdd_object_find(const struct lu_env *env,
                                   struct mdd_device *d,
                                   const struct lu_fid *f)
{
        return md2mdd_obj(md_object_find_slice(env, &d->mdd_md_dev, f));
}

static int mdd_path2fid(const struct lu_env *env, struct mdd_device *mdd,
                        const char *path, struct lu_fid *fid)
{
        struct lu_buf *buf;
        struct lu_fid *f = &mdd_env_info(env)->mti_fid;
        struct mdd_object *obj;
        struct lu_name *lname = &mdd_env_info(env)->mti_name;
        char *name;
        int rc = 0;
        ENTRY;

        /* temp buffer for path element */
        buf = mdd_buf_alloc(env, PATH_MAX);
        if (buf->lb_buf == NULL)
                RETURN(-ENOMEM);

        lname->ln_name = name = buf->lb_buf;
        lname->ln_namelen = 0;
        *f = mdd->mdd_root_fid;

        while(1) {
                while (*path == '/')
                        path++;
                if (*path == '\0')
                        break;
                while (*path != '/' && *path != '\0') {
                        *name = *path;
                        path++;
                        name++;
                        lname->ln_namelen++;
                }

                *name = '\0';
                /* find obj corresponding to fid */
                obj = mdd_object_find(env, mdd, f);
                if (obj == NULL)
                        GOTO(out, rc = -EREMOTE);
                if (IS_ERR(obj))
                        GOTO(out, rc = PTR_ERR(obj));
                /* get child fid from parent and name */
                rc = mdd_lookup(env, &obj->mod_obj, lname, f, NULL);
                mdd_object_put(env, obj);
                if (rc)
                        break;

                name = buf->lb_buf;
                lname->ln_namelen = 0;
        }

        if (!rc)
                *fid = *f;
out:
        RETURN(rc);
}

/** The maximum depth that fid2path() will search.
 * This is limited only because we want to store the fids for
 * historical path lookup purposes.
 */
#define MAX_PATH_DEPTH 100

/** mdd_path() lookup structure. */
struct path_lookup_info {
        __u64                pli_recno;        /**< history point */
        __u64                pli_currec;       /**< current record */
        struct lu_fid        pli_fid;
        struct lu_fid        pli_fids[MAX_PATH_DEPTH]; /**< path, in fids */
        struct mdd_object   *pli_mdd_obj;
        char                *pli_path;         /**< full path */
        int                  pli_pathlen;
        int                  pli_linkno;       /**< which hardlink to follow */
        int                  pli_fidcount;     /**< number of \a pli_fids */
};

static int mdd_path_current(const struct lu_env *env,
                            struct path_lookup_info *pli)
{
        struct mdd_device *mdd = mdo2mdd(&pli->pli_mdd_obj->mod_obj);
        struct mdd_object *mdd_obj;
        struct lu_buf     *buf = NULL;
        struct link_ea_header *leh;
        struct link_ea_entry  *lee;
        struct lu_name *tmpname = &mdd_env_info(env)->mti_name;
        struct lu_fid  *tmpfid = &mdd_env_info(env)->mti_fid;
        char *ptr;
        int reclen;
        int rc;
        ENTRY;

        ptr = pli->pli_path + pli->pli_pathlen - 1;
        *ptr = 0;
        --ptr;
        pli->pli_fidcount = 0;
        pli->pli_fids[0] = *(struct lu_fid *)mdd_object_fid(pli->pli_mdd_obj);

        while (!mdd_is_root(mdd, &pli->pli_fids[pli->pli_fidcount])) {
                mdd_obj = mdd_object_find(env, mdd,
                                          &pli->pli_fids[pli->pli_fidcount]);
                if (mdd_obj == NULL)
                        GOTO(out, rc = -EREMOTE);
                if (IS_ERR(mdd_obj))
                        GOTO(out, rc = PTR_ERR(mdd_obj));
                rc = lu_object_exists(&mdd_obj->mod_obj.mo_lu);
                if (rc <= 0) {
                        mdd_object_put(env, mdd_obj);
                        if (rc == -1)
                                rc = -EREMOTE;
                        else if (rc == 0)
                                /* Do I need to error out here? */
                                rc = -ENOENT;
                        GOTO(out, rc);
                }

                /* Get parent fid and object name */
                mdd_read_lock(env, mdd_obj, MOR_TGT_CHILD);
                buf = mdd_links_get(env, mdd_obj);
                mdd_read_unlock(env, mdd_obj);
                mdd_object_put(env, mdd_obj);
                if (IS_ERR(buf))
                        GOTO(out, rc = PTR_ERR(buf));

                leh = buf->lb_buf;
                lee = (struct link_ea_entry *)(leh + 1); /* link #0 */
                mdd_lee_unpack(lee, &reclen, tmpname, tmpfid);

                /* If set, use link #linkno for path lookup, otherwise use
                   link #0.  Only do this for the final path element. */
                if ((pli->pli_fidcount == 0) &&
                    (pli->pli_linkno < leh->leh_reccount)) {
                        int count;
                        for (count = 0; count < pli->pli_linkno; count++) {
                                lee = (struct link_ea_entry *)
                                     ((char *)lee + reclen);
                                mdd_lee_unpack(lee, &reclen, tmpname, tmpfid);
                        }
                        if (pli->pli_linkno < leh->leh_reccount - 1)
                                /* indicate to user there are more links */
                                pli->pli_linkno++;
                }

                /* Pack the name in the end of the buffer */
                ptr -= tmpname->ln_namelen;
                if (ptr - 1 <= pli->pli_path)
                        GOTO(out, rc = -EOVERFLOW);
                strncpy(ptr, tmpname->ln_name, tmpname->ln_namelen);
                *(--ptr) = '/';

                /* Store the parent fid for historic lookup */
                if (++pli->pli_fidcount >= MAX_PATH_DEPTH)
                        GOTO(out, rc = -EOVERFLOW);
                pli->pli_fids[pli->pli_fidcount] = *tmpfid;
        }

        /* Verify that our path hasn't changed since we started the lookup.
           Record the current index, and verify the path resolves to the
           same fid. If it does, then the path is correct as of this index. */
        cfs_spin_lock(&mdd->mdd_cl.mc_lock);
        pli->pli_currec = mdd->mdd_cl.mc_index;
        cfs_spin_unlock(&mdd->mdd_cl.mc_lock);
        rc = mdd_path2fid(env, mdd, ptr, &pli->pli_fid);
        if (rc) {
                CDEBUG(D_INFO, "mdd_path2fid(%s) failed %d\n", ptr, rc);
                GOTO (out, rc = -EAGAIN);
        }
        if (!lu_fid_eq(&pli->pli_fids[0], &pli->pli_fid)) {
                CDEBUG(D_INFO, "mdd_path2fid(%s) found another FID o="DFID
                       " n="DFID"\n", ptr, PFID(&pli->pli_fids[0]),
                       PFID(&pli->pli_fid));
                GOTO(out, rc = -EAGAIN);
        }
        ptr++; /* skip leading / */
        memmove(pli->pli_path, ptr, pli->pli_path + pli->pli_pathlen - ptr);

        EXIT;
out:
        if (buf && !IS_ERR(buf) && buf->lb_len > OBD_ALLOC_BIG)
                /* if we vmalloced a large buffer drop it */
                mdd_buf_put(buf);

        return rc;
}

static int mdd_path_historic(const struct lu_env *env,
                             struct path_lookup_info *pli)
{
        return 0;
}

/* Returns the full path to this fid, as of changelog record recno. */
static int mdd_path(const struct lu_env *env, struct md_object *obj,
                    char *path, int pathlen, __u64 *recno, int *linkno)
{
        struct path_lookup_info *pli;
        int tries = 3;
        int rc = -EAGAIN;
        ENTRY;

        if (pathlen < 3)
                RETURN(-EOVERFLOW);

        if (mdd_is_root(mdo2mdd(obj), mdd_object_fid(md2mdd_obj(obj)))) {
                path[0] = '\0';
                RETURN(0);
        }

        OBD_ALLOC_PTR(pli);
        if (pli == NULL)
                RETURN(-ENOMEM);

        pli->pli_mdd_obj = md2mdd_obj(obj);
        pli->pli_recno = *recno;
        pli->pli_path = path;
        pli->pli_pathlen = pathlen;
        pli->pli_linkno = *linkno;

        /* Retry multiple times in case file is being moved */
        while (tries-- && rc == -EAGAIN)
                rc = mdd_path_current(env, pli);

        /* For historical path lookup, the current links may not have existed
         * at "recno" time.  We must switch over to earlier links/parents
         * by using the changelog records.  If the earlier parent doesn't
         * exist, we must search back through the changelog to reconstruct
         * its parents, then check if it exists, etc.
         * We may ignore this problem for the initial implementation and
         * state that an "original" hardlink must still exist for us to find
         * historic path name. */
        if (pli->pli_recno != -1) {
                rc = mdd_path_historic(env, pli);
        } else {
                *recno = pli->pli_currec;
                /* Return next link index to caller */
                *linkno = pli->pli_linkno;
        }

        OBD_FREE_PTR(pli);

        RETURN (rc);
}

int mdd_get_flags(const struct lu_env *env, struct mdd_object *obj)
{
        struct lu_attr *la = &mdd_env_info(env)->mti_la;
        int rc;

        ENTRY;
        rc = mdd_la_get(env, obj, la, BYPASS_CAPA);
        if (rc == 0) {
                mdd_flags_xlate(obj, la->la_flags);
        }
        RETURN(rc);
}

/* get only inode attributes */
int mdd_iattr_get(const struct lu_env *env, struct mdd_object *mdd_obj,
                  struct md_attr *ma)
{
        int rc = 0;
        ENTRY;

        if (ma->ma_valid & MA_INODE)
                RETURN(0);

        rc = mdd_la_get(env, mdd_obj, &ma->ma_attr,
                          mdd_object_capa(env, mdd_obj));
        if (rc == 0)
                ma->ma_valid |= MA_INODE;
        RETURN(rc);
}

int mdd_get_default_md(struct mdd_object *mdd_obj, struct lov_mds_md *lmm)
{
        struct lov_desc *ldesc;
        struct mdd_device *mdd = mdo2mdd(&mdd_obj->mod_obj);
        struct lov_user_md *lum = (struct lov_user_md*)lmm;
        ENTRY;

        if (!lum)
                RETURN(0);

        ldesc = &mdd->mdd_obd_dev->u.mds.mds_lov_desc;
        LASSERT(ldesc != NULL);

        lum->lmm_magic = LOV_MAGIC_V1;
        lum->lmm_object_seq = FID_SEQ_LOV_DEFAULT;
        lum->lmm_pattern = ldesc->ld_pattern;
        lum->lmm_stripe_size = ldesc->ld_default_stripe_size;
        lum->lmm_stripe_count = ldesc->ld_default_stripe_count;
        lum->lmm_stripe_offset = ldesc->ld_default_stripe_offset;

        RETURN(sizeof(*lum));
}

static int is_rootdir(struct mdd_object *mdd_obj)
{
        const struct mdd_device *mdd_dev = mdd_obj2mdd_dev(mdd_obj);
        const struct lu_fid *fid = mdo2fid(mdd_obj);

        return lu_fid_eq(&mdd_dev->mdd_root_fid, fid);
}

int mdd_big_lmm_get(const struct lu_env *env, struct mdd_object *obj,
                    struct md_attr *ma)
{
	struct mdd_thread_info *info = mdd_env_info(env);
	int			size;
	int			rc   = -EINVAL;
	ENTRY;

	LASSERT(info != NULL);
	LASSERT(ma->ma_big_lmm_used == 0);

	if (ma->ma_lmm_size == 0) {
		CERROR("No buffer to hold %s xattr of object "DFID"\n",
		       XATTR_NAME_LOV, PFID(mdd_object_fid(obj)));
		RETURN(rc);
	}

        rc = mdo_xattr_get(env, obj, &LU_BUF_NULL, XATTR_NAME_LOV,
                           mdd_object_capa(env, obj));
        if (rc < 0)
                RETURN(rc);

        /* big_lmm may need to grow */
        size = rc;
        mdd_max_lmm_buffer(env, size);
        if (info->mti_max_lmm == NULL)
                RETURN(-ENOMEM);

        LASSERT(info->mti_max_lmm_size >= size);
        rc = mdd_get_md(env, obj, info->mti_max_lmm, &size,
                        XATTR_NAME_LOV);
        if (rc < 0)
                RETURN(rc);

        ma->ma_big_lmm_used = 1;
        ma->ma_valid |= MA_LOV;
        ma->ma_lmm = info->mti_max_lmm;
        ma->ma_lmm_size = size;
        LASSERT(size == rc);
        RETURN(rc);
}

/* get lov EA only */
static int __mdd_lmm_get(const struct lu_env *env,
                         struct mdd_object *mdd_obj, struct md_attr *ma)
{
        int rc;
        ENTRY;

        if (ma->ma_valid & MA_LOV)
                RETURN(0);

        rc = mdd_get_md(env, mdd_obj, ma->ma_lmm, &ma->ma_lmm_size,
                        XATTR_NAME_LOV);
        if (rc == -ERANGE)
                rc = mdd_big_lmm_get(env, mdd_obj, ma);
        else if (rc == 0 && (ma->ma_need & MA_LOV_DEF) && is_rootdir(mdd_obj))
                rc = mdd_get_default_md(mdd_obj, ma->ma_lmm);

        if (rc > 0) {
                ma->ma_lmm_size = rc;
                ma->ma_layout_gen = ma->ma_lmm->lmm_layout_gen;
                ma->ma_valid |= MA_LOV | MA_LAY_GEN;
                rc = 0;
        }
        RETURN(rc);
}

/* get the first parent fid from link EA */
static int mdd_pfid_get(const struct lu_env *env,
                        struct mdd_object *mdd_obj, struct md_attr *ma)
{
        struct lu_buf *buf;
        struct link_ea_header *leh;
        struct link_ea_entry *lee;
        struct lu_fid *pfid = &ma->ma_pfid;
        ENTRY;

        if (ma->ma_valid & MA_PFID)
                RETURN(0);

        buf = mdd_links_get(env, mdd_obj);
        if (IS_ERR(buf))
                RETURN(PTR_ERR(buf));

        leh = buf->lb_buf;
        lee = (struct link_ea_entry *)(leh + 1);
        memcpy(pfid, &lee->lee_parent_fid, sizeof(*pfid));
        fid_be_to_cpu(pfid, pfid);
        ma->ma_valid |= MA_PFID;
        if (buf->lb_len > OBD_ALLOC_BIG)
                /* if we vmalloced a large buffer drop it */
                mdd_buf_put(buf);
        RETURN(0);
}

int mdd_lmm_get_locked(const struct lu_env *env, struct mdd_object *mdd_obj,
                       struct md_attr *ma)
{
        int rc;
        ENTRY;

        mdd_read_lock(env, mdd_obj, MOR_TGT_CHILD);
        rc = __mdd_lmm_get(env, mdd_obj, ma);
        mdd_read_unlock(env, mdd_obj);
        RETURN(rc);
}

/* get lmv EA only*/
static int __mdd_lmv_get(const struct lu_env *env,
                         struct mdd_object *mdd_obj, struct md_attr *ma)
{
        int rc;
        ENTRY;

        if (ma->ma_valid & MA_LMV)
                RETURN(0);

        rc = mdd_get_md(env, mdd_obj, ma->ma_lmv, &ma->ma_lmv_size,
                        XATTR_NAME_LMV);
        if (rc > 0) {
                ma->ma_valid |= MA_LMV;
                rc = 0;
        }
        RETURN(rc);
}

static int __mdd_lma_get(const struct lu_env *env, struct mdd_object *mdd_obj,
                         struct md_attr *ma)
{
        struct mdd_thread_info *info = mdd_env_info(env);
        struct lustre_mdt_attrs *lma =
                                 (struct lustre_mdt_attrs *)info->mti_xattr_buf;
        int lma_size;
        int rc;
        ENTRY;

        /* If all needed data are already valid, nothing to do */
        if ((ma->ma_valid & (MA_HSM | MA_SOM)) ==
            (ma->ma_need & (MA_HSM | MA_SOM)))
                RETURN(0);

        /* Read LMA from disk EA */
        lma_size = sizeof(info->mti_xattr_buf);
        rc = mdd_get_md(env, mdd_obj, lma, &lma_size, XATTR_NAME_LMA);
        if (rc <= 0)
                RETURN(rc);

        /* Useless to check LMA incompatibility because this is already done in
         * osd_ea_fid_get(), and this will fail long before this code is
         * called.
         * So, if we are here, LMA is compatible.
         */

        lustre_lma_swab(lma);

        /* Swab and copy LMA */
        if (ma->ma_need & MA_HSM) {
                if (lma->lma_compat & LMAC_HSM)
                        ma->ma_hsm.mh_flags = lma->lma_flags & HSM_FLAGS_MASK;
                else
                        ma->ma_hsm.mh_flags = 0;
                ma->ma_valid |= MA_HSM;
        }

        /* Copy SOM */
        if (ma->ma_need & MA_SOM && lma->lma_compat & LMAC_SOM) {
                LASSERT(ma->ma_som != NULL);
                ma->ma_som->msd_ioepoch = lma->lma_ioepoch;
                ma->ma_som->msd_size    = lma->lma_som_size;
                ma->ma_som->msd_blocks  = lma->lma_som_blocks;
                ma->ma_som->msd_mountid = lma->lma_som_mountid;
                ma->ma_valid |= MA_SOM;
        }

        RETURN(0);
}

int mdd_attr_get_internal(const struct lu_env *env, struct mdd_object *mdd_obj,
                                 struct md_attr *ma)
{
        int rc = 0;
        ENTRY;

        if (ma->ma_need & MA_INODE)
                rc = mdd_iattr_get(env, mdd_obj, ma);

        if (rc == 0 && ma->ma_need & MA_LOV) {
                if (S_ISREG(mdd_object_type(mdd_obj)) ||
                    S_ISDIR(mdd_object_type(mdd_obj)))
                        rc = __mdd_lmm_get(env, mdd_obj, ma);
        }
        if (rc == 0 && ma->ma_need & MA_PFID && !(ma->ma_valid & MA_LOV)) {
                if (S_ISREG(mdd_object_type(mdd_obj)))
                        rc = mdd_pfid_get(env, mdd_obj, ma);
        }
        if (rc == 0 && ma->ma_need & MA_LMV) {
                if (S_ISDIR(mdd_object_type(mdd_obj)))
                        rc = __mdd_lmv_get(env, mdd_obj, ma);
        }
        if (rc == 0 && ma->ma_need & (MA_HSM | MA_SOM)) {
                if (S_ISREG(mdd_object_type(mdd_obj)))
                        rc = __mdd_lma_get(env, mdd_obj, ma);
        }
#ifdef CONFIG_FS_POSIX_ACL
        if (rc == 0 && ma->ma_need & MA_ACL_DEF) {
                if (S_ISDIR(mdd_object_type(mdd_obj)))
                        rc = mdd_def_acl_get(env, mdd_obj, ma);
        }
#endif
        CDEBUG(D_INODE, "after getattr rc = %d, ma_valid = "LPX64" ma_lmm=%p\n",
               rc, ma->ma_valid, ma->ma_lmm);
        RETURN(rc);
}

int mdd_attr_get_internal_locked(const struct lu_env *env,
                                 struct mdd_object *mdd_obj, struct md_attr *ma)
{
        int rc;
        int needlock = ma->ma_need &
                       (MA_LOV | MA_LMV | MA_ACL_DEF | MA_HSM | MA_SOM | MA_PFID);

        if (needlock)
                mdd_read_lock(env, mdd_obj, MOR_TGT_CHILD);
        rc = mdd_attr_get_internal(env, mdd_obj, ma);
        if (needlock)
                mdd_read_unlock(env, mdd_obj);
        return rc;
}

/*
 * No permission check is needed.
 */
int mdd_attr_get(const struct lu_env *env, struct md_object *obj,
		 struct md_attr *ma)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int                rc;

        ENTRY;
        rc = mdd_attr_get_internal_locked(env, mdd_obj, ma);
        RETURN(rc);
}

/*
 * No permission check is needed.
 */
static int mdd_xattr_get(const struct lu_env *env,
                         struct md_object *obj, struct lu_buf *buf,
                         const char *name)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int rc;

        ENTRY;

        if (mdd_object_exists(mdd_obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(mdd_obj),PFID(mdd_object_fid(mdd_obj)));
                return -ENOENT;
        }

        mdd_read_lock(env, mdd_obj, MOR_TGT_CHILD);
        rc = mdo_xattr_get(env, mdd_obj, buf, name,
                           mdd_object_capa(env, mdd_obj));
        mdd_read_unlock(env, mdd_obj);

        RETURN(rc);
}

/*
 * Permission check is done when open,
 * no need check again.
 */
static int mdd_readlink(const struct lu_env *env, struct md_object *obj,
                        struct lu_buf *buf)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct dt_object  *next;
        loff_t             pos = 0;
        int                rc;
        ENTRY;

        if (mdd_object_exists(mdd_obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(mdd_obj),PFID(mdd_object_fid(mdd_obj)));
                return -ENOENT;
        }

        next = mdd_object_child(mdd_obj);
        mdd_read_lock(env, mdd_obj, MOR_TGT_CHILD);
        rc = next->do_body_ops->dbo_read(env, next, buf, &pos,
                                         mdd_object_capa(env, mdd_obj));
        mdd_read_unlock(env, mdd_obj);
        RETURN(rc);
}

/*
 * No permission check is needed.
 */
static int mdd_xattr_list(const struct lu_env *env, struct md_object *obj,
                          struct lu_buf *buf)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int rc;

        ENTRY;

        mdd_read_lock(env, mdd_obj, MOR_TGT_CHILD);
        rc = mdo_xattr_list(env, mdd_obj, buf, mdd_object_capa(env, mdd_obj));
        mdd_read_unlock(env, mdd_obj);

        RETURN(rc);
}

int mdd_declare_object_create_internal(const struct lu_env *env,
                                       struct mdd_object *p,
                                       struct mdd_object *c,
                                       struct md_attr *ma,
                                       struct thandle *handle,
                                       const struct md_op_spec *spec)
{
        struct dt_object_format *dof = &mdd_env_info(env)->mti_dof;
        const struct dt_index_features *feat = spec->sp_feat;
        int rc;
        ENTRY;

        if (feat != &dt_directory_features && feat != NULL)
                dof->dof_type = DFT_INDEX;
        else
                dof->dof_type = dt_mode_to_dft(ma->ma_attr.la_mode);

        dof->u.dof_idx.di_feat = feat;

        rc = mdo_declare_create_obj(env, c, &ma->ma_attr, NULL, dof, handle);

        RETURN(rc);
}

int mdd_object_create_internal(const struct lu_env *env, struct mdd_object *p,
                               struct mdd_object *c, struct md_attr *ma,
                               struct thandle *handle,
                               const struct md_op_spec *spec)
{
        struct lu_attr *attr = &ma->ma_attr;
        struct dt_allocation_hint *hint = &mdd_env_info(env)->mti_hint;
        struct dt_object_format *dof = &mdd_env_info(env)->mti_dof;
        const struct dt_index_features *feat = spec->sp_feat;
        int rc;
        ENTRY;

        if (!mdd_object_exists(c)) {
                struct dt_object *next = mdd_object_child(c);
                LASSERT(next);

                if (feat != &dt_directory_features && feat != NULL)
                        dof->dof_type = DFT_INDEX;
                else
                        dof->dof_type = dt_mode_to_dft(attr->la_mode);

                dof->u.dof_idx.di_feat = feat;

                /* @hint will be initialized by underlying device. */
                next->do_ops->do_ah_init(env, hint,
                                         p ? mdd_object_child(p) : NULL,
                                         attr->la_mode & S_IFMT);

                rc = mdo_create_obj(env, c, attr, hint, dof, handle);
                LASSERT(ergo(rc == 0, mdd_object_exists(c)));
        } else
                rc = -EEXIST;

        RETURN(rc);
}

/**
 * Make sure the ctime is increased only.
 */
static inline int mdd_attr_check(const struct lu_env *env,
                                 struct mdd_object *obj,
                                 struct lu_attr *attr)
{
        struct lu_attr *tmp_la = &mdd_env_info(env)->mti_la;
        int rc;
        ENTRY;

        if (attr->la_valid & LA_CTIME) {
                rc = mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
                if (rc)
                        RETURN(rc);

                if (attr->la_ctime < tmp_la->la_ctime)
                        attr->la_valid &= ~(LA_MTIME | LA_CTIME);
                else if (attr->la_valid == LA_CTIME &&
                         attr->la_ctime == tmp_la->la_ctime)
                        attr->la_valid &= ~LA_CTIME;
        }
        RETURN(0);
}

int mdd_attr_set_internal(const struct lu_env *env,
                          struct mdd_object *obj,
                          struct lu_attr *attr,
                          struct thandle *handle,
                          int needacl)
{
        int rc;
        ENTRY;

        rc = mdo_attr_set(env, obj, attr, handle, mdd_object_capa(env, obj));
#ifdef CONFIG_FS_POSIX_ACL
        if (!rc && (attr->la_valid & LA_MODE) && needacl)
                rc = mdd_acl_chmod(env, obj, attr->la_mode, handle);
#endif
        RETURN(rc);
}

int mdd_attr_check_set_internal(const struct lu_env *env,
                                struct mdd_object *obj,
                                struct lu_attr *attr,
                                struct thandle *handle,
                                int needacl)
{
        int rc;
        ENTRY;

        rc = mdd_attr_check(env, obj, attr);
        if (rc)
                RETURN(rc);

        if (attr->la_valid)
                rc = mdd_attr_set_internal(env, obj, attr, handle, needacl);
        RETURN(rc);
}

static int mdd_attr_set_internal_locked(const struct lu_env *env,
                                        struct mdd_object *obj,
                                        struct lu_attr *attr,
                                        struct thandle *handle,
                                        int needacl)
{
        int rc;
        ENTRY;

        needacl = needacl && (attr->la_valid & LA_MODE);
        if (needacl)
                mdd_write_lock(env, obj, MOR_TGT_CHILD);
        rc = mdd_attr_set_internal(env, obj, attr, handle, needacl);
        if (needacl)
                mdd_write_unlock(env, obj);
        RETURN(rc);
}

int mdd_attr_check_set_internal_locked(const struct lu_env *env,
                                       struct mdd_object *obj,
                                       struct lu_attr *attr,
                                       struct thandle *handle,
                                       int needacl)
{
        int rc;
        ENTRY;

        needacl = needacl && (attr->la_valid & LA_MODE);
        if (needacl)
                mdd_write_lock(env, obj, MOR_TGT_CHILD);
        rc = mdd_attr_check_set_internal(env, obj, attr, handle, needacl);
        if (needacl)
                mdd_write_unlock(env, obj);
        RETURN(rc);
}

int __mdd_xattr_set(const struct lu_env *env, struct mdd_object *obj,
                    const struct lu_buf *buf, const char *name,
                    int fl, struct thandle *handle)
{
        struct lustre_capa *capa = mdd_object_capa(env, obj);
        int rc = -EINVAL;
        ENTRY;

        if (buf->lb_buf && buf->lb_len > 0)
                rc = mdo_xattr_set(env, obj, buf, name, 0, handle, capa);
        else if (buf->lb_buf == NULL && buf->lb_len == 0)
                rc = mdo_xattr_del(env, obj, name, handle, capa);

        RETURN(rc);
}

/*
 * This gives the same functionality as the code between
 * sys_chmod and inode_setattr
 * chown_common and inode_setattr
 * utimes and inode_setattr
 * This API is ported from mds_fix_attr but remove some unnecesssary stuff.
 */
static int mdd_fix_attr(const struct lu_env *env, struct mdd_object *obj,
                        struct lu_attr *la, const struct md_attr *ma)
{
        struct lu_attr   *tmp_la     = &mdd_env_info(env)->mti_la;
        struct md_ucred  *uc;
        int               rc;
        ENTRY;

        if (!la->la_valid)
                RETURN(0);

        /* Do not permit change file type */
        if (la->la_valid & LA_TYPE)
                RETURN(-EPERM);

        /* They should not be processed by setattr */
        if (la->la_valid & (LA_NLINK | LA_RDEV | LA_BLKSIZE))
                RETURN(-EPERM);

        /* export destroy does not have ->le_ses, but we may want
         * to drop LUSTRE_SOM_FL. */
        if (!env->le_ses)
                RETURN(0);

        uc = md_ucred(env);

        rc = mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
        if (rc)
                RETURN(rc);

        if (la->la_valid == LA_CTIME) {
                if (!(ma->ma_attr_flags & MDS_PERM_BYPASS))
                        /* This is only for set ctime when rename's source is
                         * on remote MDS. */
                        rc = mdd_may_delete(env, NULL, obj,
                                            (struct md_attr *)ma, 1, 0);
                if (rc == 0 && la->la_ctime <= tmp_la->la_ctime)
                        la->la_valid &= ~LA_CTIME;
                RETURN(rc);
        }

        if (la->la_valid == LA_ATIME) {
                /* This is atime only set for read atime update on close. */
                if (la->la_atime >= tmp_la->la_atime &&
                    la->la_atime < (tmp_la->la_atime +
                                    mdd_obj2mdd_dev(obj)->mdd_atime_diff))
                        la->la_valid &= ~LA_ATIME;
                RETURN(0);
        }

        /* Check if flags change. */
        if (la->la_valid & LA_FLAGS) {
                unsigned int oldflags = 0;
                unsigned int newflags = la->la_flags &
                                (LUSTRE_IMMUTABLE_FL | LUSTRE_APPEND_FL);

                if ((uc->mu_fsuid != tmp_la->la_uid) &&
                    !mdd_capable(uc, CFS_CAP_FOWNER))
                        RETURN(-EPERM);

                /* XXX: the IMMUTABLE and APPEND_ONLY flags can
                 * only be changed by the relevant capability. */
                if (mdd_is_immutable(obj))
                        oldflags |= LUSTRE_IMMUTABLE_FL;
                if (mdd_is_append(obj))
                        oldflags |= LUSTRE_APPEND_FL;
                if ((oldflags ^ newflags) &&
                    !mdd_capable(uc, CFS_CAP_LINUX_IMMUTABLE))
                        RETURN(-EPERM);

                if (!S_ISDIR(tmp_la->la_mode))
                        la->la_flags &= ~LUSTRE_DIRSYNC_FL;
        }

        if ((mdd_is_immutable(obj) || mdd_is_append(obj)) &&
            (la->la_valid & ~LA_FLAGS) &&
            !(ma->ma_attr_flags & MDS_PERM_BYPASS))
                RETURN(-EPERM);

        /* Check for setting the obj time. */
        if ((la->la_valid & (LA_MTIME | LA_ATIME | LA_CTIME)) &&
            !(la->la_valid & ~(LA_MTIME | LA_ATIME | LA_CTIME))) {
                if ((uc->mu_fsuid != tmp_la->la_uid) &&
                    !mdd_capable(uc, CFS_CAP_FOWNER)) {
                        rc = mdd_permission_internal_locked(env, obj, tmp_la,
                                                            MAY_WRITE,
                                                            MOR_TGT_CHILD);
                        if (rc)
                                RETURN(rc);
                }
        }

        if (la->la_valid & LA_KILL_SUID) {
                la->la_valid &= ~LA_KILL_SUID;
                if ((tmp_la->la_mode & S_ISUID) &&
                    !(la->la_valid & LA_MODE)) {
                        la->la_mode = tmp_la->la_mode;
                        la->la_valid |= LA_MODE;
                }
                la->la_mode &= ~S_ISUID;
        }

        if (la->la_valid & LA_KILL_SGID) {
                la->la_valid &= ~LA_KILL_SGID;
                if (((tmp_la->la_mode & (S_ISGID | S_IXGRP)) ==
                                        (S_ISGID | S_IXGRP)) &&
                    !(la->la_valid & LA_MODE)) {
                        la->la_mode = tmp_la->la_mode;
                        la->la_valid |= LA_MODE;
                }
                la->la_mode &= ~S_ISGID;
        }

        /* Make sure a caller can chmod. */
        if (la->la_valid & LA_MODE) {
                if (!(ma->ma_attr_flags & MDS_PERM_BYPASS) &&
                    (uc->mu_fsuid != tmp_la->la_uid) &&
                    !mdd_capable(uc, CFS_CAP_FOWNER))
                        RETURN(-EPERM);

                if (la->la_mode == (cfs_umode_t) -1)
                        la->la_mode = tmp_la->la_mode;
                else
                        la->la_mode = (la->la_mode & S_IALLUGO) |
                                      (tmp_la->la_mode & ~S_IALLUGO);

                /* Also check the setgid bit! */
                if (!lustre_in_group_p(uc, (la->la_valid & LA_GID) ?
                                       la->la_gid : tmp_la->la_gid) &&
                    !mdd_capable(uc, CFS_CAP_FSETID))
                        la->la_mode &= ~S_ISGID;
        } else {
               la->la_mode = tmp_la->la_mode;
        }

        /* Make sure a caller can chown. */
        if (la->la_valid & LA_UID) {
                if (la->la_uid == (uid_t) -1)
                        la->la_uid = tmp_la->la_uid;
                if (((uc->mu_fsuid != tmp_la->la_uid) ||
                    (la->la_uid != tmp_la->la_uid)) &&
                    !mdd_capable(uc, CFS_CAP_CHOWN))
                        RETURN(-EPERM);

                /* If the user or group of a non-directory has been
                 * changed by a non-root user, remove the setuid bit.
                 * 19981026 David C Niemi <niemi@tux.org>
                 *
                 * Changed this to apply to all users, including root,
                 * to avoid some races. This is the behavior we had in
                 * 2.0. The check for non-root was definitely wrong
                 * for 2.2 anyway, as it should have been using
                 * CAP_FSETID rather than fsuid -- 19990830 SD. */
                if (((tmp_la->la_mode & S_ISUID) == S_ISUID) &&
                    !S_ISDIR(tmp_la->la_mode)) {
                        la->la_mode &= ~S_ISUID;
                        la->la_valid |= LA_MODE;
                }
        }

        /* Make sure caller can chgrp. */
        if (la->la_valid & LA_GID) {
                if (la->la_gid == (gid_t) -1)
                        la->la_gid = tmp_la->la_gid;
                if (((uc->mu_fsuid != tmp_la->la_uid) ||
                    ((la->la_gid != tmp_la->la_gid) &&
                    !lustre_in_group_p(uc, la->la_gid))) &&
                    !mdd_capable(uc, CFS_CAP_CHOWN))
                        RETURN(-EPERM);

                /* Likewise, if the user or group of a non-directory
                 * has been changed by a non-root user, remove the
                 * setgid bit UNLESS there is no group execute bit
                 * (this would be a file marked for mandatory
                 * locking).  19981026 David C Niemi <niemi@tux.org>
                 *
                 * Removed the fsuid check (see the comment above) --
                 * 19990830 SD. */
                if (((tmp_la->la_mode & (S_ISGID | S_IXGRP)) ==
                     (S_ISGID | S_IXGRP)) && !S_ISDIR(tmp_la->la_mode)) {
                        la->la_mode &= ~S_ISGID;
                        la->la_valid |= LA_MODE;
                }
        }

        /* For both Size-on-MDS case and truncate case,
         * "la->la_valid & (LA_SIZE | LA_BLOCKS)" are ture.
         * We distinguish them by "ma->ma_attr_flags & MDS_SOM".
         * For SOM case, it is true, the MAY_WRITE perm has been checked
         * when open, no need check again. For truncate case, it is false,
         * the MAY_WRITE perm should be checked here. */
        if (ma->ma_attr_flags & MDS_SOM) {
                /* For the "Size-on-MDS" setattr update, merge coming
                 * attributes with the set in the inode. BUG 10641 */
                if ((la->la_valid & LA_ATIME) &&
                    (la->la_atime <= tmp_la->la_atime))
                        la->la_valid &= ~LA_ATIME;

                /* OST attributes do not have a priority over MDS attributes,
                 * so drop times if ctime is equal. */
                if ((la->la_valid & LA_CTIME) &&
                    (la->la_ctime <= tmp_la->la_ctime))
                        la->la_valid &= ~(LA_MTIME | LA_CTIME);
        } else {
                if (la->la_valid & (LA_SIZE | LA_BLOCKS)) {
                        if (!((ma->ma_attr_flags & MDS_OPEN_OWNEROVERRIDE) &&
                              (uc->mu_fsuid == tmp_la->la_uid)) &&
                            !(ma->ma_attr_flags & MDS_PERM_BYPASS)) {
                                rc = mdd_permission_internal_locked(env, obj,
                                                            tmp_la, MAY_WRITE,
                                                            MOR_TGT_CHILD);
                                if (rc)
                                        RETURN(rc);
                        }
                }
                if (la->la_valid & LA_CTIME) {
                        /* The pure setattr, it has the priority over what is
                         * already set, do not drop it if ctime is equal. */
                        if (la->la_ctime < tmp_la->la_ctime)
                                la->la_valid &= ~(LA_ATIME | LA_MTIME |
                                                  LA_CTIME);
                }
        }

        RETURN(0);
}

/** Store a data change changelog record
 * If this fails, we must fail the whole transaction; we don't
 * want the change to commit without the log entry.
 * \param mdd_obj - mdd_object of change
 * \param handle - transacion handle
 */
static int mdd_changelog_data_store(const struct lu_env     *env,
                                    struct mdd_device       *mdd,
                                    enum changelog_rec_type type,
                                    int                     flags,
                                    struct mdd_object       *mdd_obj,
                                    struct thandle          *handle)
{
        const struct lu_fid *tfid = mdo2fid(mdd_obj);
        struct llog_changelog_rec *rec;
        struct thandle *th = NULL;
        struct lu_buf *buf;
        int reclen;
        int rc;

        /* Not recording */
        if (!(mdd->mdd_cl.mc_flags & CLM_ON))
                RETURN(0);
        if ((mdd->mdd_cl.mc_mask & (1 << type)) == 0)
                RETURN(0);

        LASSERT(mdd_obj != NULL);
        LASSERT(handle != NULL);

        if ((type >= CL_MTIME) && (type <= CL_ATIME) &&
            cfs_time_before_64(mdd->mdd_cl.mc_starttime, mdd_obj->mod_cltime)) {
                /* Don't need multiple updates in this log */
                /* Don't check under lock - no big deal if we get an extra
                   entry */
                RETURN(0);
        }

        reclen = llog_data_len(sizeof(*rec));
        buf = mdd_buf_alloc(env, reclen);
        if (buf->lb_buf == NULL)
                RETURN(-ENOMEM);
        rec = (struct llog_changelog_rec *)buf->lb_buf;

        rec->cr.cr_flags = CLF_VERSION | (CLF_FLAGMASK & flags);
        rec->cr.cr_type = (__u32)type;
        rec->cr.cr_tfid = *tfid;
        rec->cr.cr_namelen = 0;
        mdd_obj->mod_cltime = cfs_time_current_64();

        rc = mdd_changelog_llog_write(mdd, rec, handle ? : th);

        if (th)
                mdd_trans_stop(env, mdd, rc, th);

        if (rc < 0) {
                CERROR("changelog failed: rc=%d op%d t"DFID"\n",
                       rc, type, PFID(tfid));
                return -EFAULT;
        }

        return 0;
}

int mdd_changelog(const struct lu_env *env, enum changelog_rec_type type,
                  int flags, struct md_object *obj)
{
        struct thandle *handle;
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        int rc;
        ENTRY;

        handle = mdd_trans_create(env, mdd);
        if (IS_ERR(handle))
                return(PTR_ERR(handle));

        rc = mdd_declare_changelog_store(env, mdd, NULL, handle);
        if (rc)
                GOTO(stop, rc);

        rc = mdd_trans_start(env, mdd, handle);
        if (rc)
                GOTO(stop, rc);

        rc = mdd_changelog_data_store(env, mdd, type, flags, mdd_obj,
                                      handle);

stop:
        mdd_trans_stop(env, mdd, rc, handle);

        RETURN(rc);
}

/**
 * Should be called with write lock held.
 *
 * \see mdd_lma_set_locked().
 */
static int __mdd_lma_set(const struct lu_env *env, struct mdd_object *mdd_obj,
                       const struct md_attr *ma, struct thandle *handle)
{
        struct mdd_thread_info *info = mdd_env_info(env);
        struct lu_buf *buf;
        struct lustre_mdt_attrs *lma =
                                (struct lustre_mdt_attrs *) info->mti_xattr_buf;
        int lmasize = sizeof(struct lustre_mdt_attrs);
        int rc = 0;

        ENTRY;

        /* Either HSM or SOM part is not valid, we need to read it before */
        if ((!ma->ma_valid) & (MA_HSM | MA_SOM)) {
                rc = mdd_get_md(env, mdd_obj, lma, &lmasize, XATTR_NAME_LMA);
                if (rc <= 0)
                        RETURN(rc);

                lustre_lma_swab(lma);
        } else {
                memset(lma, 0, lmasize);
        }

        /* Copy HSM data */
        if (ma->ma_valid & MA_HSM) {
                lma->lma_flags  |= ma->ma_hsm.mh_flags & HSM_FLAGS_MASK;
                lma->lma_compat |= LMAC_HSM;
        }

        /* Copy SOM data */
        if (ma->ma_valid & MA_SOM) {
                LASSERT(ma->ma_som != NULL);
                if (ma->ma_som->msd_ioepoch == IOEPOCH_INVAL) {
                        lma->lma_compat     &= ~LMAC_SOM;
                } else {
                        lma->lma_compat     |= LMAC_SOM;
                        lma->lma_ioepoch     = ma->ma_som->msd_ioepoch;
                        lma->lma_som_size    = ma->ma_som->msd_size;
                        lma->lma_som_blocks  = ma->ma_som->msd_blocks;
                        lma->lma_som_mountid = ma->ma_som->msd_mountid;
                }
        }

        /* Copy FID */
        memcpy(&lma->lma_self_fid, mdo2fid(mdd_obj), sizeof(lma->lma_self_fid));

        lustre_lma_swab(lma);
        buf = mdd_buf_get(env, lma, lmasize);
        rc = __mdd_xattr_set(env, mdd_obj, buf, XATTR_NAME_LMA, 0, handle);

        RETURN(rc);
}

/**
 * Save LMA extended attributes with data from \a ma.
 *
 * HSM and Size-On-MDS data will be extracted from \ma if they are valid, if
 * not, LMA EA will be first read from disk, modified and write back.
 *
 */
static int mdd_lma_set_locked(const struct lu_env *env,
                              struct mdd_object *mdd_obj,
                              const struct md_attr *ma, struct thandle *handle)
{
        int rc;

        mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);
        rc = __mdd_lma_set(env, mdd_obj, ma, handle);
        mdd_write_unlock(env, mdd_obj);
        return rc;
}

/* Precedence for choosing record type when multiple
 * attributes change: setattr > mtime > ctime > atime
 * (ctime changes when mtime does, plus chmod/chown.
 * atime and ctime are independent.) */
static int mdd_attr_set_changelog(const struct lu_env *env,
                                  struct md_object *obj, struct thandle *handle,
                                  __u64 valid)
{
        struct mdd_device *mdd = mdo2mdd(obj);
        int bits, type = 0;

        bits = (valid & ~(LA_CTIME|LA_MTIME|LA_ATIME)) ? 1 << CL_SETATTR : 0;
        bits |= (valid & LA_MTIME) ? 1 << CL_MTIME : 0;
        bits |= (valid & LA_CTIME) ? 1 << CL_CTIME : 0;
        bits |= (valid & LA_ATIME) ? 1 << CL_ATIME : 0;
        bits = bits & mdd->mdd_cl.mc_mask;
        if (bits == 0)
                return 0;

        /* The record type is the lowest non-masked set bit */
        while (bits && ((bits & 1) == 0)) {
                bits = bits >> 1;
                type++;
        }

        /* FYI we only store the first CLF_FLAGMASK bits of la_valid */
        return mdd_changelog_data_store(env, mdd, type, (int)valid,
                                        md2mdd_obj(obj), handle);
}

static int mdd_declare_attr_set(const struct lu_env *env,
                                struct mdd_device *mdd,
                                struct mdd_object *obj,
                                const struct md_attr *ma,
                                struct lov_mds_md *lmm,
                                struct thandle *handle)
{
        struct lu_buf  *buf = &mdd_env_info(env)->mti_buf;
        int             rc, i;

        rc = mdo_declare_attr_set(env, obj, &ma->ma_attr, handle);
        if (rc)
                return rc;

        rc = mdd_declare_changelog_store(env, mdd, NULL, handle);
        if (rc)
                return rc;

        if (ma->ma_valid & MA_LOV) {
                buf->lb_buf = NULL;
                buf->lb_len = ma->ma_lmm_size;
                rc = mdo_declare_xattr_set(env, obj, buf, XATTR_NAME_LOV,
                                           0, handle);
                if (rc)
                        return rc;
        }

        if (ma->ma_valid & (MA_HSM | MA_SOM)) {
                buf->lb_buf = NULL;
                buf->lb_len = sizeof(struct lustre_mdt_attrs);
                rc = mdo_declare_xattr_set(env, obj, buf, XATTR_NAME_LMA,
                                           0, handle);
                if (rc)
                        return rc;
        }

#ifdef CONFIG_FS_POSIX_ACL
        if (ma->ma_attr.la_valid & LA_MODE) {
                mdd_read_lock(env, obj, MOR_TGT_CHILD);
                rc = mdo_xattr_get(env, obj, &LU_BUF_NULL,XATTR_NAME_ACL_ACCESS,
                                   BYPASS_CAPA);
                mdd_read_unlock(env, obj);
                if (rc == -EOPNOTSUPP || rc == -ENODATA)
                        rc = 0;
                else if (rc < 0)
                        return rc;

                if (rc != 0) {
                        buf->lb_buf = NULL;
                        buf->lb_len = rc;
                        rc = mdo_declare_xattr_set(env, obj, buf,
                                                   XATTR_NAME_ACL_ACCESS, 0,
                                                   handle);
                        if (rc)
                                return rc;
                }
        }
#endif

        /* basically the log is the same as in unlink case */
        if (lmm) {
                __u16 stripe;

                if (le32_to_cpu(lmm->lmm_magic) != LOV_MAGIC_V1 &&
                                le32_to_cpu(lmm->lmm_magic) != LOV_MAGIC_V3) {
                        CERROR("%s: invalid LOV_MAGIC %08x on object "DFID"\n",
                               mdd->mdd_obd_dev->obd_name,
                               le32_to_cpu(lmm->lmm_magic),
                               PFID(lu_object_fid(&obj->mod_obj.mo_lu)));
                        return -EINVAL;
                }

                stripe = le16_to_cpu(lmm->lmm_stripe_count);
                if (stripe == LOV_ALL_STRIPES) {
                        struct lov_desc *ldesc;

                        ldesc = &mdd->mdd_obd_dev->u.mds.mds_lov_desc;
                        LASSERT(ldesc != NULL);
                        stripe = ldesc->ld_tgt_count;
                }

                for (i = 0; i < stripe; i++) {
                        rc = mdd_declare_llog_record(env, mdd,
                                        sizeof(struct llog_unlink_rec),
                                        handle);
                        if (rc)
                                return rc;
                }
        }

        return rc;
}

/* set attr and LOV EA at once, return updated attr */
int mdd_attr_set(const struct lu_env *env, struct md_object *obj,
		 const struct md_attr *ma)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        struct lov_mds_md *lmm = NULL;
        struct llog_cookie *logcookies = NULL;
        int  rc, lmm_size = 0, cookie_size = 0;
        struct lu_attr *la_copy = &mdd_env_info(env)->mti_la_for_fix;
#ifdef HAVE_QUOTA_SUPPORT
        struct obd_device *obd = mdd->mdd_obd_dev;
        struct mds_obd *mds = &obd->u.mds;
        unsigned int qnids[MAXQUOTAS] = { 0, 0 };
        unsigned int qoids[MAXQUOTAS] = { 0, 0 };
        int quota_opc = 0, block_count = 0;
        int inode_pending[MAXQUOTAS] = { 0, 0 };
        int block_pending[MAXQUOTAS] = { 0, 0 };
#endif
        ENTRY;

        *la_copy = ma->ma_attr;
        rc = mdd_fix_attr(env, mdd_obj, la_copy, ma);
        if (rc != 0)
                RETURN(rc);

        /* setattr on "close" only change atime, or do nothing */
        if (ma->ma_valid == MA_INODE &&
            ma->ma_attr.la_valid == LA_ATIME && la_copy->la_valid == 0)
                RETURN(0);

        if (S_ISREG(mdd_object_type(mdd_obj)) &&
            ma->ma_attr.la_valid & (LA_UID | LA_GID)) {
                lmm_size = mdd_lov_mdsize(env, mdd);
                lmm = mdd_max_lmm_get(env, mdd);
                if (lmm == NULL)
                        RETURN(-ENOMEM);

                rc = mdd_get_md_locked(env, mdd_obj, lmm, &lmm_size,
                                XATTR_NAME_LOV);

                if (rc < 0)
                        RETURN(rc);
        }

        handle = mdd_trans_create(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        rc = mdd_declare_attr_set(env, mdd, mdd_obj, ma,
                                  lmm_size > 0 ? lmm : NULL, handle);
        if (rc)
                GOTO(stop, rc);

        rc = mdd_trans_start(env, mdd, handle);
        if (rc)
                GOTO(stop, rc);

        /* permission changes may require sync operation */
        if (ma->ma_attr.la_valid & (LA_MODE|LA_UID|LA_GID))
                handle->th_sync |= !!mdd->mdd_sync_permission;

        if (ma->ma_attr.la_valid & (LA_MTIME | LA_CTIME))
                CDEBUG(D_INODE, "setting mtime "LPU64", ctime "LPU64"\n",
                       ma->ma_attr.la_mtime, ma->ma_attr.la_ctime);

#ifdef HAVE_QUOTA_SUPPORT
        if (mds->mds_quota && la_copy->la_valid & (LA_UID | LA_GID)) {
                struct obd_export *exp = md_quota(env)->mq_exp;
                struct lu_attr *la_tmp = &mdd_env_info(env)->mti_la;

                rc = mdd_la_get(env, mdd_obj, la_tmp, BYPASS_CAPA);
                if (!rc) {
                        quota_opc = FSFILT_OP_SETATTR;
                        mdd_quota_wrapper(la_copy, qnids);
                        mdd_quota_wrapper(la_tmp, qoids);
                        /* get file quota for new owner */
                        lquota_chkquota(mds_quota_interface_ref, obd, exp,
                                        qnids, inode_pending, 1, NULL, 0,
                                        NULL, 0);
                        block_count = (la_tmp->la_blocks + 7) >> 3;
                        if (block_count) {
                                void *data = NULL;
                                mdd_data_get(env, mdd_obj, &data);
                                /* get block quota for new owner */
                                lquota_chkquota(mds_quota_interface_ref, obd,
                                                exp, qnids, block_pending,
                                                block_count, NULL,
                                                LQUOTA_FLAGS_BLK, data, 1);
                        }
                }
        }
#endif

        if (la_copy->la_valid & LA_FLAGS) {
                rc = mdd_attr_set_internal_locked(env, mdd_obj, la_copy,
                                                  handle, 1);
                if (rc == 0)
                        mdd_flags_xlate(mdd_obj, la_copy->la_flags);
        } else if (la_copy->la_valid) {            /* setattr */
                rc = mdd_attr_set_internal_locked(env, mdd_obj, la_copy,
                                                  handle, 1);
                /* journal chown/chgrp in llog, just like unlink */
                if (rc == 0 && lmm_size){
                        cookie_size = mdd_lov_cookiesize(env, mdd);
                        logcookies = mdd_max_cookie_get(env, mdd);
                        if (logcookies == NULL)
                                GOTO(cleanup, rc = -ENOMEM);

                        if (mdd_setattr_log(env, mdd, ma, lmm, lmm_size,
                                            logcookies, cookie_size) <= 0)
                                logcookies = NULL;
                }
        }

        if (rc == 0 && ma->ma_valid & MA_LOV) {
                cfs_umode_t mode;

                mode = mdd_object_type(mdd_obj);
                if (S_ISREG(mode) || S_ISDIR(mode)) {
                        rc = mdd_lsm_sanity_check(env, mdd_obj);
                        if (rc)
                                GOTO(cleanup, rc);

                        rc = mdd_lov_set_md(env, NULL, mdd_obj, ma->ma_lmm,
                                            ma->ma_lmm_size, handle, 1);
                }

        }
        if (rc == 0 && ma->ma_valid & (MA_HSM | MA_SOM)) {
                cfs_umode_t mode;

                mode = mdd_object_type(mdd_obj);
                if (S_ISREG(mode))
                        rc = mdd_lma_set_locked(env, mdd_obj, ma, handle);

        }
cleanup:
        if (rc == 0)
                rc = mdd_attr_set_changelog(env, obj, handle,
                                            ma->ma_attr.la_valid);
stop:
        mdd_trans_stop(env, mdd, rc, handle);
        if (rc == 0 && (lmm != NULL && lmm_size > 0 )) {
                /*set obd attr, if needed*/
                rc = mdd_lov_setattr_async(env, mdd_obj, lmm, lmm_size,
                                           logcookies);
        }
#ifdef HAVE_QUOTA_SUPPORT
        if (quota_opc) {
                lquota_pending_commit(mds_quota_interface_ref, obd, qnids,
                                      inode_pending, 0);
                lquota_pending_commit(mds_quota_interface_ref, obd, qnids,
                                      block_pending, 1);
                /* Trigger dqrel/dqacq for original owner and new owner.
                 * If failed, the next call for lquota_chkquota will
                 * process it. */
                lquota_adjust(mds_quota_interface_ref, obd, qnids, qoids, rc,
                              quota_opc);
        }
#endif
        RETURN(rc);
}

int mdd_xattr_set_txn(const struct lu_env *env, struct mdd_object *obj,
                      const struct lu_buf *buf, const char *name, int fl,
                      struct thandle *handle)
{
        int  rc;
        ENTRY;

        mdd_write_lock(env, obj, MOR_TGT_CHILD);
        rc = __mdd_xattr_set(env, obj, buf, name, fl, handle);
        mdd_write_unlock(env, obj);

        RETURN(rc);
}

static int mdd_xattr_sanity_check(const struct lu_env *env,
                                  struct mdd_object *obj)
{
        struct lu_attr  *tmp_la = &mdd_env_info(env)->mti_la;
        struct md_ucred *uc     = md_ucred(env);
        int rc;
        ENTRY;

        if (mdd_is_immutable(obj) || mdd_is_append(obj))
                RETURN(-EPERM);

        rc = mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
        if (rc)
                RETURN(rc);

        if ((uc->mu_fsuid != tmp_la->la_uid) &&
            !mdd_capable(uc, CFS_CAP_FOWNER))
                RETURN(-EPERM);

        RETURN(rc);
}

static int mdd_declare_xattr_set(const struct lu_env *env,
                                 struct mdd_device *mdd,
                                 struct mdd_object *obj,
                                 const struct lu_buf *buf,
                                 const char *name,
                                 struct thandle *handle)

{
        int rc;

        rc = mdo_declare_xattr_set(env, obj, buf, name, 0, handle);
        if (rc)
                return rc;

        /* Only record user xattr changes */
        if ((strncmp("user.", name, 5) == 0))
                rc = mdd_declare_changelog_store(env, mdd, NULL, handle);

        return rc;
}

/**
 * The caller should guarantee to update the object ctime
 * after xattr_set if needed.
 */
static int mdd_xattr_set(const struct lu_env *env, struct md_object *obj,
                         const struct lu_buf *buf, const char *name,
                         int fl)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int  rc;
        ENTRY;

        rc = mdd_xattr_sanity_check(env, mdd_obj);
        if (rc)
                RETURN(rc);

        handle = mdd_trans_create(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        rc = mdd_declare_xattr_set(env, mdd, mdd_obj, buf, name, handle);
        if (rc)
                GOTO(stop, rc);

        rc = mdd_trans_start(env, mdd, handle);
        if (rc)
                GOTO(stop, rc);

        /* security-replated changes may require sync */
        if (!strcmp(name, XATTR_NAME_ACL_ACCESS))
                handle->th_sync |= !!mdd->mdd_sync_permission;

        rc = mdd_xattr_set_txn(env, mdd_obj, buf, name, fl, handle);

        /* Only record system & user xattr changes */
        if ((rc == 0) && (strncmp(XATTR_USER_PREFIX, name,
                                  sizeof(XATTR_USER_PREFIX) - 1) == 0 ||
                          strncmp(POSIX_ACL_XATTR_ACCESS, name,
                                  sizeof(POSIX_ACL_XATTR_ACCESS) - 1) == 0 ||
                          strncmp(POSIX_ACL_XATTR_DEFAULT, name,
                                  sizeof(POSIX_ACL_XATTR_DEFAULT) - 1) == 0))
                rc = mdd_changelog_data_store(env, mdd, CL_XATTR, 0, mdd_obj,
                                              handle);

stop:
        mdd_trans_stop(env, mdd, rc, handle);

        RETURN(rc);
}

static int mdd_declare_xattr_del(const struct lu_env *env,
                                 struct mdd_device *mdd,
                                 struct mdd_object *obj,
                                 const char *name,
                                 struct thandle *handle)
{
        int rc;

        rc = mdo_declare_xattr_del(env, obj, name, handle);
        if (rc)
                return rc;

        /* Only record user xattr changes */
        if ((strncmp("user.", name, 5) == 0))
                rc = mdd_declare_changelog_store(env, mdd, NULL, handle);

        return rc;
}

/**
 * The caller should guarantee to update the object ctime
 * after xattr_set if needed.
 */
int mdd_xattr_del(const struct lu_env *env, struct md_object *obj,
                  const char *name)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int  rc;
        ENTRY;

        rc = mdd_xattr_sanity_check(env, mdd_obj);
        if (rc)
                RETURN(rc);

        handle = mdd_trans_create(env, mdd);
        if (IS_ERR(handle))
                RETURN(PTR_ERR(handle));

        rc = mdd_declare_xattr_del(env, mdd, mdd_obj, name, handle);
        if (rc)
                GOTO(stop, rc);

        rc = mdd_trans_start(env, mdd, handle);
        if (rc)
                GOTO(stop, rc);

        mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);
        rc = mdo_xattr_del(env, mdd_obj, name, handle,
                           mdd_object_capa(env, mdd_obj));
        mdd_write_unlock(env, mdd_obj);

        /* Only record system & user xattr changes */
        if ((rc == 0) && (strncmp(XATTR_USER_PREFIX, name,
                                  sizeof(XATTR_USER_PREFIX) - 1) == 0 ||
                          strncmp(POSIX_ACL_XATTR_ACCESS, name,
                                  sizeof(POSIX_ACL_XATTR_ACCESS) - 1) == 0 ||
                          strncmp(POSIX_ACL_XATTR_DEFAULT, name,
                                  sizeof(POSIX_ACL_XATTR_DEFAULT) - 1) == 0))
                rc = mdd_changelog_data_store(env, mdd, CL_XATTR, 0, mdd_obj,
                                              handle);

stop:
        mdd_trans_stop(env, mdd, rc, handle);

        RETURN(rc);
}

/* partial unlink */
static int mdd_ref_del(const struct lu_env *env, struct md_object *obj,
                       struct md_attr *ma)
{
        struct lu_attr *la_copy = &mdd_env_info(env)->mti_la_for_fix;
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
#ifdef HAVE_QUOTA_SUPPORT
        struct obd_device *obd = mdd->mdd_obd_dev;
        struct mds_obd *mds = &obd->u.mds;
        unsigned int qids[MAXQUOTAS] = { 0, 0 };
        int quota_opc = 0;
#endif
        int rc;
        ENTRY;

        /* XXX: this code won't be used ever:
         * DNE uses slightly different approach */
        LBUG();

        /*
         * Check -ENOENT early here because we need to get object type
         * to calculate credits before transaction start
         */
        if (mdd_object_exists(mdd_obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(mdd_obj),PFID(mdd_object_fid(mdd_obj)));
                RETURN(-ENOENT);
        }

        LASSERT(mdd_object_exists(mdd_obj) > 0);

        handle = mdd_trans_create(env, mdd);
        if (IS_ERR(handle))
                RETURN(-ENOMEM);

        rc = mdd_trans_start(env, mdd, handle);

        mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);

        rc = mdd_unlink_sanity_check(env, NULL, mdd_obj, ma);
        if (rc)
                GOTO(cleanup, rc);

        mdo_ref_del(env, mdd_obj, handle);

        if (S_ISDIR(lu_object_attr(&obj->mo_lu))) {
                /* unlink dot */
                mdo_ref_del(env, mdd_obj, handle);
        }

        LASSERT(ma->ma_attr.la_valid & LA_CTIME);
        la_copy->la_ctime = ma->ma_attr.la_ctime;

        la_copy->la_valid = LA_CTIME;
        rc = mdd_attr_check_set_internal(env, mdd_obj, la_copy, handle, 0);
        if (rc)
                GOTO(cleanup, rc);

        rc = mdd_finish_unlink(env, mdd_obj, ma, handle);
#ifdef HAVE_QUOTA_SUPPORT
        if (mds->mds_quota && ma->ma_valid & MA_INODE &&
            ma->ma_attr.la_nlink == 0 && mdd_obj->mod_count == 0) {
                quota_opc = FSFILT_OP_UNLINK_PARTIAL_CHILD;
                mdd_quota_wrapper(&ma->ma_attr, qids);
        }
#endif


        EXIT;
cleanup:
        mdd_write_unlock(env, mdd_obj);
        mdd_trans_stop(env, mdd, rc, handle);
#ifdef HAVE_QUOTA_SUPPORT
        if (quota_opc)
                /* Trigger dqrel on the owner of child. If failed,
                 * the next call for lquota_chkquota will process it */
                lquota_adjust(mds_quota_interface_ref, obd, qids, 0, rc,
                              quota_opc);
#endif
        return rc;
}

/* partial operation */
static int mdd_oc_sanity_check(const struct lu_env *env,
                               struct mdd_object *obj,
                               struct md_attr *ma)
{
        int rc;
        ENTRY;

        switch (ma->ma_attr.la_mode & S_IFMT) {
        case S_IFREG:
        case S_IFDIR:
        case S_IFLNK:
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:
                rc = 0;
                break;
        default:
                rc = -EINVAL;
                break;
        }
        RETURN(rc);
}

static int mdd_object_create(const struct lu_env *env,
                             struct md_object *obj,
                             const struct md_op_spec *spec,
                             struct md_attr *ma)
{

        struct mdd_device *mdd = mdo2mdd(obj);
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        const struct lu_fid *pfid = spec->u.sp_pfid;
        struct thandle *handle;
#ifdef HAVE_QUOTA_SUPPORT
        struct obd_device *obd = mdd->mdd_obd_dev;
        struct obd_export *exp = md_quota(env)->mq_exp;
        struct mds_obd *mds = &obd->u.mds;
        unsigned int qids[MAXQUOTAS] = { 0, 0 };
        int quota_opc = 0, block_count = 0;
        int inode_pending[MAXQUOTAS] = { 0, 0 };
        int block_pending[MAXQUOTAS] = { 0, 0 };
#endif
        int rc = 0;
        ENTRY;

        /* XXX: this code won't be used ever:
         * DNE uses slightly different approach */
        LBUG();

#ifdef HAVE_QUOTA_SUPPORT
        if (mds->mds_quota) {
                quota_opc = FSFILT_OP_CREATE_PARTIAL_CHILD;
                mdd_quota_wrapper(&ma->ma_attr, qids);
                /* get file quota for child */
                lquota_chkquota(mds_quota_interface_ref, obd, exp,
                                qids, inode_pending, 1, NULL, 0,
                                NULL, 0);
                switch (ma->ma_attr.la_mode & S_IFMT) {
                case S_IFLNK:
                case S_IFDIR:
                        block_count = 2;
                        break;
                case S_IFREG:
                        block_count = 1;
                        break;
                }
                /* get block quota for child */
                if (block_count)
                        lquota_chkquota(mds_quota_interface_ref, obd, exp,
                                        qids, block_pending, block_count,
                                        NULL, LQUOTA_FLAGS_BLK, NULL, 0);
        }
#endif

        handle = mdd_trans_create(env, mdd);
        if (IS_ERR(handle))
                GOTO(out_pending, rc = PTR_ERR(handle));

        rc = mdd_trans_start(env, mdd, handle);

        mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);
        rc = mdd_oc_sanity_check(env, mdd_obj, ma);
        if (rc)
                GOTO(unlock, rc);

        rc = mdd_object_create_internal(env, NULL, mdd_obj, ma, handle, spec);
        if (rc)
                GOTO(unlock, rc);

        if (spec->sp_cr_flags & MDS_CREATE_SLAVE_OBJ) {
                /* If creating the slave object, set slave EA here. */
                int lmv_size = spec->u.sp_ea.eadatalen;
                struct lmv_stripe_md *lmv;

                lmv = (struct lmv_stripe_md *)spec->u.sp_ea.eadata;
                LASSERT(lmv != NULL && lmv_size > 0);

                rc = __mdd_xattr_set(env, mdd_obj,
                                     mdd_buf_get_const(env, lmv, lmv_size),
                                     XATTR_NAME_LMV, 0, handle);
                if (rc)
                        GOTO(unlock, rc);

                rc = mdd_attr_set_internal(env, mdd_obj, &ma->ma_attr,
                                           handle, 0);
        } else {
#ifdef CONFIG_FS_POSIX_ACL
                if (spec->sp_cr_flags & MDS_CREATE_RMT_ACL) {
                        struct lu_buf *buf = &mdd_env_info(env)->mti_buf;

                        buf->lb_buf = (void *)spec->u.sp_ea.eadata;
                        buf->lb_len = spec->u.sp_ea.eadatalen;
                        if ((buf->lb_len > 0) && (buf->lb_buf != NULL)) {
                                rc = __mdd_acl_init(env, mdd_obj, buf,
                                                    &ma->ma_attr.la_mode,
                                                    handle);
                                if (rc)
                                        GOTO(unlock, rc);
                                else
                                        ma->ma_attr.la_valid |= LA_MODE;
                        }

                        pfid = spec->u.sp_ea.fid;
                }
#endif
                rc = mdd_object_initialize(env, pfid, NULL, mdd_obj, ma, handle,
                                           spec);
        }
        EXIT;
unlock:
        if (rc == 0)
                rc = mdd_attr_get_internal(env, mdd_obj, ma);
        mdd_write_unlock(env, mdd_obj);

        mdd_trans_stop(env, mdd, rc, handle);
out_pending:
#ifdef HAVE_QUOTA_SUPPORT
        if (quota_opc) {
                lquota_pending_commit(mds_quota_interface_ref, obd, qids,
                                      inode_pending, 0);
                lquota_pending_commit(mds_quota_interface_ref, obd, qids,
                                      block_pending, 1);
                /* Trigger dqacq on the owner of child. If failed,
                 * the next call for lquota_chkquota will process it. */
                lquota_adjust(mds_quota_interface_ref, obd, qids, 0, rc,
                              quota_opc);
        }
#endif
        return rc;
}

/* partial link */
static int mdd_ref_add(const struct lu_env *env, struct md_object *obj,
                       const struct md_attr *ma)
{
        struct lu_attr *la_copy = &mdd_env_info(env)->mti_la_for_fix;
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle *handle;
        int rc;
        ENTRY;

        /* XXX: this code won't be used ever:
         * DNE uses slightly different approach */
        LBUG();

        handle = mdd_trans_create(env, mdd);
        if (IS_ERR(handle))
                RETURN(-ENOMEM);

        rc = mdd_trans_start(env, mdd, handle);

        mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);
        rc = mdd_link_sanity_check(env, NULL, NULL, mdd_obj);
        if (rc == 0)
                mdo_ref_add(env, mdd_obj, handle);
        mdd_write_unlock(env, mdd_obj);
        if (rc == 0) {
                LASSERT(ma->ma_attr.la_valid & LA_CTIME);
                la_copy->la_ctime = ma->ma_attr.la_ctime;

                la_copy->la_valid = LA_CTIME;
                rc = mdd_attr_check_set_internal_locked(env, mdd_obj, la_copy,
                                                        handle, 0);
        }
        mdd_trans_stop(env, mdd, 0, handle);

        RETURN(rc);
}

/*
 * do NOT or the MAY_*'s, you'll get the weakest
 */
int accmode(const struct lu_env *env, struct lu_attr *la, int flags)
{
        int res = 0;

        /* Sadly, NFSD reopens a file repeatedly during operation, so the
         * "acc_mode = 0" allowance for newly-created files isn't honoured.
         * NFSD uses the MDS_OPEN_OWNEROVERRIDE flag to say that a file
         * owner can write to a file even if it is marked readonly to hide
         * its brokenness. (bug 5781) */
        if (flags & MDS_OPEN_OWNEROVERRIDE) {
                struct md_ucred *uc = md_ucred(env);

                if ((uc == NULL) || (uc->mu_valid == UCRED_INIT) ||
                    (la->la_uid == uc->mu_fsuid))
                        return 0;
        }

        if (flags & FMODE_READ)
                res |= MAY_READ;
        if (flags & (FMODE_WRITE | MDS_OPEN_TRUNC | MDS_OPEN_APPEND))
                res |= MAY_WRITE;
        if (flags & MDS_FMODE_EXEC)
                res = MAY_EXEC;
        return res;
}

static int mdd_open_sanity_check(const struct lu_env *env,
                                 struct mdd_object *obj, int flag)
{
        struct lu_attr *tmp_la = &mdd_env_info(env)->mti_la;
        int mode, rc;
        ENTRY;

        /* EEXIST check */
        if (mdd_is_dead_obj(obj))
                RETURN(-ENOENT);

        rc = mdd_la_get(env, obj, tmp_la, BYPASS_CAPA);
        if (rc)
               RETURN(rc);

        if (S_ISLNK(tmp_la->la_mode))
                RETURN(-ELOOP);

        mode = accmode(env, tmp_la, flag);

        if (S_ISDIR(tmp_la->la_mode) && (mode & MAY_WRITE))
                RETURN(-EISDIR);

        if (!(flag & MDS_OPEN_CREATED)) {
                rc = mdd_permission_internal(env, obj, tmp_la, mode);
                if (rc)
                        RETURN(rc);
        }

        if (S_ISFIFO(tmp_la->la_mode) || S_ISSOCK(tmp_la->la_mode) ||
            S_ISBLK(tmp_la->la_mode) || S_ISCHR(tmp_la->la_mode))
                flag &= ~MDS_OPEN_TRUNC;

        /* For writing append-only file must open it with append mode. */
        if (mdd_is_append(obj)) {
                if ((flag & FMODE_WRITE) && !(flag & MDS_OPEN_APPEND))
                        RETURN(-EPERM);
                if (flag & MDS_OPEN_TRUNC)
                        RETURN(-EPERM);
        }

#if 0
        /*
         * Now, flag -- O_NOATIME does not be packed by client.
         */
        if (flag & O_NOATIME) {
                struct md_ucred *uc = md_ucred(env);

                if (uc && ((uc->mu_valid == UCRED_OLD) ||
                    (uc->mu_valid == UCRED_NEW)) &&
                    (uc->mu_fsuid != tmp_la->la_uid) &&
                    !mdd_capable(uc, CFS_CAP_FOWNER))
                        RETURN(-EPERM);
        }
#endif

        RETURN(0);
}

static int mdd_open(const struct lu_env *env, struct md_object *obj,
                    int flags)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int rc = 0;

        mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);

        rc = mdd_open_sanity_check(env, mdd_obj, flags);
        if (rc == 0)
                mdd_obj->mod_count++;

        mdd_write_unlock(env, mdd_obj);
        return rc;
}

int mdd_declare_object_kill(const struct lu_env *env, struct mdd_object *obj,
                            struct md_attr *ma, struct thandle *handle)
{
        int rc;

        rc = mdd_declare_unlink_log(env, obj, ma, handle);
        if (rc)
                return rc;

        return mdo_declare_destroy(env, obj, handle);
}

/* return md_attr back,
 * if it is last unlink then return lov ea + llog cookie*/
int mdd_object_kill(const struct lu_env *env, struct mdd_object *obj,
                    struct md_attr *ma, struct thandle *handle)
{
        int rc = 0;
        ENTRY;

        if (S_ISREG(mdd_object_type(obj))) {
                /* Return LOV & COOKIES unconditionally here. We clean evth up.
                 * Caller must be ready for that. */
                rc = __mdd_lmm_get(env, obj, ma);
                if ((ma->ma_valid & MA_LOV))
                        rc = mdd_unlink_log(env, mdo2mdd(&obj->mod_obj),
                                            obj, ma);
        }

        if (rc == 0)
                rc = mdo_destroy(env, obj, handle);

        RETURN(rc);
}

static int mdd_declare_close(const struct lu_env *env,
                             struct mdd_object *obj,
                             struct md_attr *ma,
                             struct thandle *handle)
{
        int rc;

        rc = orph_declare_index_delete(env, obj, handle);
        if (rc)
                return rc;

        return mdd_declare_object_kill(env, obj, ma, handle);
}

/*
 * No permission check is needed.
 */
static int mdd_close(const struct lu_env *env, struct md_object *obj,
                     struct md_attr *ma, int mode)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        struct mdd_device *mdd = mdo2mdd(obj);
        struct thandle    *handle = NULL;
        int rc;
        int is_orphan = 0, reset = 1;

#ifdef HAVE_QUOTA_SUPPORT
        struct obd_device *obd = mdo2mdd(obj)->mdd_obd_dev;
        struct mds_obd *mds = &obd->u.mds;
        unsigned int qids[MAXQUOTAS] = { 0, 0 };
        int quota_opc = 0;
#endif
        ENTRY;

        if (ma->ma_valid & MA_FLAGS && ma->ma_attr_flags & MDS_KEEP_ORPHAN) {
		mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);
		mdd_obj->mod_count--;
		mdd_write_unlock(env, mdd_obj);

                if (mdd_obj->mod_flags & ORPHAN_OBJ && !mdd_obj->mod_count)
                        CDEBUG(D_HA, "Object "DFID" is retained in orphan "
                               "list\n", PFID(mdd_object_fid(mdd_obj)));
                RETURN(0);
        }

	/* mdd_finish_unlink() will always set orphan object as DEAD_OBJ, but
	 * it might fail to add the object to orphan list (w/o ORPHAN_OBJ). */
	/* check without any lock */
	is_orphan = mdd_obj->mod_count == 1 &&
		    (mdd_obj->mod_flags & (ORPHAN_OBJ | DEAD_OBJ)) != 0;
 again:
	if (is_orphan) {
                handle = mdd_trans_create(env, mdo2mdd(obj));
                if (IS_ERR(handle))
                        RETURN(PTR_ERR(handle));

                rc = mdd_declare_close(env, mdd_obj, ma, handle);
                if (rc)
                        GOTO(stop, rc);

                rc = mdd_declare_changelog_store(env, mdd, NULL, handle);
                if (rc)
                        GOTO(stop, rc);

                rc = mdd_trans_start(env, mdo2mdd(obj), handle);
                if (rc)
                        GOTO(stop, rc);
        }

        mdd_write_lock(env, mdd_obj, MOR_TGT_CHILD);
	rc = mdd_iattr_get(env, mdd_obj, ma);
	if (rc != 0) {
		CERROR("Failed to get iattr of "DFID": %d\n",
		       PFID(mdd_object_fid(mdd_obj)), rc);
		GOTO(out, rc);
	}

	/* check again with lock */
	is_orphan = (mdd_obj->mod_count == 1) &&
		    ((mdd_obj->mod_flags & (ORPHAN_OBJ | DEAD_OBJ)) != 0 ||
		     ma->ma_attr.la_nlink == 0);

	if (is_orphan && handle == NULL) {
		mdd_write_unlock(env, mdd_obj);
		goto again; /* create transaction handle */
	}

	mdd_obj->mod_count--; /* release open count */

	if (!is_orphan)
		GOTO(out, rc = 0);

	/* Orphan object */
	/* NB: Object maybe not in orphan list originally, it is rare case for
	 * mdd_finish_unlink() failure, in that case, the object doesn't have
	 * ORPHAN_OBJ flag. */
	if ((mdd_obj->mod_flags & ORPHAN_OBJ) != 0) {
		/* remove link to object from orphan index */
		rc = __mdd_orphan_del(env, mdd_obj, handle);
		if (rc != 0) {
			CERROR("Object "DFID" can not be deleted from orphan "
			       "list, maybe cause OST objects can not be "
			       "destroyed (err: %d).\n",
			       PFID(mdd_object_fid(mdd_obj)), rc);
			/* If object was not deleted from orphan list, do not
			 * destroy OSS objects, which will be done when next
			 * recovery. */
			GOTO(out, rc);
		}

		CDEBUG(D_HA, "Object "DFID" is deleted from orphan "
		       "list, OSS objects to be destroyed.\n",
		       PFID(mdd_object_fid(mdd_obj)));
	}

	/* refresh ma after _mdd_orphan_del */
	ma->ma_valid &= ~MA_INODE;
	rc = mdd_iattr_get(env, mdd_obj, ma);
	if (rc != 0) {
		CERROR("Failed to get iattr of "DFID": %d\n",
		       PFID(mdd_object_fid(mdd_obj)), rc);
		GOTO(out, rc);
	}

#ifdef HAVE_QUOTA_SUPPORT
	if (mds->mds_quota) {
		quota_opc = FSFILT_OP_UNLINK_PARTIAL_CHILD;
		mdd_quota_wrapper(&ma->ma_attr, qids);
	}
#endif
	/* MDS_CLOSE_CLEANUP means destroy OSS objects by MDS. */
	if ((ma->ma_valid & MA_FLAGS) != 0 &&
	    (ma->ma_attr_flags & MDS_CLOSE_CLEANUP) != 0) {
		rc = mdd_lov_destroy(env, mdd, mdd_obj, &ma->ma_attr);
	} else {
		rc = mdd_object_kill(env, mdd_obj, ma, handle);
		if (rc == 0)
			reset = 0;
	}

	if (rc != 0) {
		CERROR("Error when prepare to delete Object "DFID" , "
		       "which will cause OST objects can not be "
		       "destroyed.\n",  PFID(mdd_object_fid(mdd_obj)));
	}
        EXIT;

out:
        if (reset)
                ma->ma_valid &= ~(MA_LOV | MA_COOKIE);

        mdd_write_unlock(env, mdd_obj);

        if (rc == 0 &&
            (mode & (FMODE_WRITE | MDS_OPEN_APPEND | MDS_OPEN_TRUNC)) &&
            !(ma->ma_valid & MA_FLAGS && ma->ma_attr_flags & MDS_RECOV_OPEN)) {
                if (handle == NULL) {
                        handle = mdd_trans_create(env, mdo2mdd(obj));
                        if (IS_ERR(handle))
                                GOTO(stop, rc = IS_ERR(handle));

                        rc = mdd_declare_changelog_store(env, mdd, NULL,
                                                         handle);
                        if (rc)
                                GOTO(stop, rc);

                        rc = mdd_trans_start(env, mdo2mdd(obj), handle);
                        if (rc)
                                GOTO(stop, rc);
                }

                mdd_changelog_data_store(env, mdd, CL_CLOSE, mode,
                                         mdd_obj, handle);
        }

stop:
        if (handle != NULL)
                mdd_trans_stop(env, mdd, rc, handle);
#ifdef HAVE_QUOTA_SUPPORT
        if (quota_opc)
                /* Trigger dqrel on the owner of child. If failed,
                 * the next call for lquota_chkquota will process it */
                lquota_adjust(mds_quota_interface_ref, obd, qids, 0, rc,
                              quota_opc);
#endif
        return rc;
}

/*
 * Permission check is done when open,
 * no need check again.
 */
static int mdd_readpage_sanity_check(const struct lu_env *env,
                                     struct mdd_object *obj)
{
        struct dt_object *next = mdd_object_child(obj);
        int rc;
        ENTRY;

        if (S_ISDIR(mdd_object_type(obj)) && dt_try_as_dir(env, next))
                rc = 0;
        else
                rc = -ENOTDIR;

        RETURN(rc);
}

static int mdd_dir_page_build(const struct lu_env *env, struct mdd_device *mdd,
                              struct lu_dirpage *dp, int nob,
                              const struct dt_it_ops *iops, struct dt_it *it,
                              __u32 attr)
{
        void                   *area = dp;
        int                     result;
        __u64                   hash = 0;
        struct lu_dirent       *ent;
        struct lu_dirent       *last = NULL;
        int                     first = 1;

        memset(area, 0, sizeof (*dp));
        area += sizeof (*dp);
        nob  -= sizeof (*dp);

        ent  = area;
        do {
                int    len;
                int    recsize;

                len = iops->key_size(env, it);

                /* IAM iterator can return record with zero len. */
                if (len == 0)
                        goto next;

                hash = iops->store(env, it);
                if (unlikely(first)) {
                        first = 0;
                        dp->ldp_hash_start = cpu_to_le64(hash);
                }

                /* calculate max space required for lu_dirent */
                recsize = lu_dirent_calc_size(len, attr);

                if (nob >= recsize) {
                        result = iops->rec(env, it, (struct dt_rec *)ent, attr);
                        if (result == -ESTALE)
                                goto next;
                        if (result != 0)
                                goto out;

                        /* osd might not able to pack all attributes,
                         * so recheck rec length */
                        recsize = le16_to_cpu(ent->lde_reclen);
                } else {
                        result = (last != NULL) ? 0 :-EINVAL;
                        goto out;
                }
                last = ent;
                ent = (void *)ent + recsize;
                nob -= recsize;

next:
                result = iops->next(env, it);
                if (result == -ESTALE)
                        goto next;
        } while (result == 0);

out:
        dp->ldp_hash_end = cpu_to_le64(hash);
        if (last != NULL) {
                if (last->lde_hash == dp->ldp_hash_end)
                        dp->ldp_flags |= cpu_to_le32(LDF_COLLIDE);
                last->lde_reclen = 0; /* end mark */
        }
        return result;
}

static int __mdd_readpage(const struct lu_env *env, struct mdd_object *obj,
                          const struct lu_rdpg *rdpg)
{
        struct dt_it      *it;
        struct dt_object  *next = mdd_object_child(obj);
        const struct dt_it_ops  *iops;
        struct page       *pg;
        struct mdd_device *mdd = mdo2mdd(&obj->mod_obj);
        int i;
        int nlupgs = 0;
        int rc;
        int nob;

        LASSERT(rdpg->rp_pages != NULL);
        LASSERT(next->do_index_ops != NULL);

        if (rdpg->rp_count <= 0)
                return -EFAULT;

        /*
         * iterate through directory and fill pages from @rdpg
         */
        iops = &next->do_index_ops->dio_it;
        it = iops->init(env, next, rdpg->rp_attrs, mdd_object_capa(env, obj));
        if (IS_ERR(it))
                return PTR_ERR(it);

        rc = iops->load(env, it, rdpg->rp_hash);

        if (rc == 0) {
                /*
                 * Iterator didn't find record with exactly the key requested.
                 *
                 * It is currently either
                 *
                 *     - positioned above record with key less than
                 *     requested---skip it.
                 *
                 *     - or not positioned at all (is in IAM_IT_SKEWED
                 *     state)---position it on the next item.
                 */
                rc = iops->next(env, it);
        } else if (rc > 0)
                rc = 0;

        /*
         * At this point and across for-loop:
         *
         *  rc == 0 -> ok, proceed.
         *  rc >  0 -> end of directory.
         *  rc <  0 -> error.
         */
        for (i = 0, nob = rdpg->rp_count; rc == 0 && nob > 0;
             i++, nob -= CFS_PAGE_SIZE) {
                struct lu_dirpage *dp;

                LASSERT(i < rdpg->rp_npages);
                pg = rdpg->rp_pages[i];
                dp = cfs_kmap(pg);
#if CFS_PAGE_SIZE > LU_PAGE_SIZE
repeat:
#endif
                rc = mdd_dir_page_build(env, mdd, dp,
                                        min_t(int, nob, LU_PAGE_SIZE),
                                        iops, it, rdpg->rp_attrs);
                if (rc > 0) {
                        /*
                         * end of directory.
                         */
                        dp->ldp_hash_end = cpu_to_le64(MDS_DIR_END_OFF);
                        nlupgs++;
                } else if (rc < 0) {
                        CWARN("build page failed: %d!\n", rc);
                } else {
                        nlupgs++;
#if CFS_PAGE_SIZE > LU_PAGE_SIZE
                        dp = (struct lu_dirpage *)((char *)dp + LU_PAGE_SIZE);
                        if ((unsigned long)dp & ~CFS_PAGE_MASK)
                                goto repeat;
#endif
                }
                cfs_kunmap(pg);
        }
        if (rc >= 0) {
                struct lu_dirpage *dp;

                dp = cfs_kmap(rdpg->rp_pages[0]);
                dp->ldp_hash_start = cpu_to_le64(rdpg->rp_hash);
                if (nlupgs == 0) {
                        /*
                         * No pages were processed, mark this for first page
                         * and send back.
                         */
                        dp->ldp_flags  = cpu_to_le32(LDF_EMPTY);
                        nlupgs = 1;
                }
                cfs_kunmap(rdpg->rp_pages[0]);

                rc = min_t(unsigned int, nlupgs * LU_PAGE_SIZE, rdpg->rp_count);
        }
        iops->put(env, it);
        iops->fini(env, it);

        return rc;
}

int mdd_readpage(const struct lu_env *env, struct md_object *obj,
                 const struct lu_rdpg *rdpg)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);
        int rc;
        ENTRY;

        if (mdd_object_exists(mdd_obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(mdd_obj),PFID(mdd_object_fid(mdd_obj)));
                return -ENOENT;
        }

        mdd_read_lock(env, mdd_obj, MOR_TGT_CHILD);
        rc = mdd_readpage_sanity_check(env, mdd_obj);
        if (rc)
                GOTO(out_unlock, rc);

        if (mdd_is_dead_obj(mdd_obj)) {
                struct page *pg;
                struct lu_dirpage *dp;

                /*
                 * According to POSIX, please do not return any entry to client:
                 * even dot and dotdot should not be returned.
                 */
                CWARN("readdir from dead object: "DFID"\n",
                        PFID(mdd_object_fid(mdd_obj)));

                if (rdpg->rp_count <= 0)
                        GOTO(out_unlock, rc = -EFAULT);
                LASSERT(rdpg->rp_pages != NULL);

                pg = rdpg->rp_pages[0];
                dp = (struct lu_dirpage*)cfs_kmap(pg);
                memset(dp, 0 , sizeof(struct lu_dirpage));
                dp->ldp_hash_start = cpu_to_le64(rdpg->rp_hash);
                dp->ldp_hash_end   = cpu_to_le64(MDS_DIR_END_OFF);
                dp->ldp_flags = cpu_to_le32(LDF_EMPTY);
                cfs_kunmap(pg);
                GOTO(out_unlock, rc = LU_PAGE_SIZE);
        }

        rc = __mdd_readpage(env, mdd_obj, rdpg);

        EXIT;
out_unlock:
        mdd_read_unlock(env, mdd_obj);
        return rc;
}

static int mdd_object_sync(const struct lu_env *env, struct md_object *obj)
{
        struct mdd_object *mdd_obj = md2mdd_obj(obj);

        if (mdd_object_exists(mdd_obj) == 0) {
                CERROR("%s: object "DFID" not found: rc = -2\n",
                       mdd_obj_dev_name(mdd_obj),PFID(mdd_object_fid(mdd_obj)));
                return -ENOENT;
        }
        return dt_object_sync(env, mdd_object_child(mdd_obj));
}

const struct md_object_operations mdd_obj_ops = {
        .moo_permission    = mdd_permission,
        .moo_attr_get      = mdd_attr_get,
        .moo_attr_set      = mdd_attr_set,
        .moo_xattr_get     = mdd_xattr_get,
        .moo_xattr_set     = mdd_xattr_set,
        .moo_xattr_list    = mdd_xattr_list,
        .moo_xattr_del     = mdd_xattr_del,
        .moo_object_create = mdd_object_create,
        .moo_ref_add       = mdd_ref_add,
        .moo_ref_del       = mdd_ref_del,
        .moo_open          = mdd_open,
        .moo_close         = mdd_close,
        .moo_readpage      = mdd_readpage,
        .moo_readlink      = mdd_readlink,
        .moo_changelog     = mdd_changelog,
        .moo_capa_get      = mdd_capa_get,
        .moo_object_sync   = mdd_object_sync,
        .moo_path          = mdd_path,
        .moo_file_lock     = mdd_file_lock,
        .moo_file_unlock   = mdd_file_unlock,
};
