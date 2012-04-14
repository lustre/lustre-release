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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/cmm/mdc_object.c
 *
 * Lustre Cluster Metadata Manager (cmm)
 *
 * Author: Mike Pershin <tappro@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS
#include <obd_support.h>
#include <lustre_lib.h>
#include <obd_class.h>
#include <lustre_mdc.h>
#include "cmm_internal.h"
#include "mdc_internal.h"

static const struct md_object_operations mdc_mo_ops;
static const struct md_dir_operations mdc_dir_ops;
static const struct lu_object_operations mdc_obj_ops;

extern struct lu_context_key mdc_thread_key;
/**
 * \addtogroup cmm_mdc
 * @{
 */
/**
 * Allocate new mdc object.
 */
struct lu_object *mdc_object_alloc(const struct lu_env *env,
                                   const struct lu_object_header *hdr,
                                   struct lu_device *ld)
{
        struct mdc_object *mco;
        ENTRY;

        OBD_ALLOC_PTR(mco);
        if (mco != NULL) {
                struct lu_object *lo;

                lo = &mco->mco_obj.mo_lu;
                lu_object_init(lo, NULL, ld);
                mco->mco_obj.mo_ops = &mdc_mo_ops;
                mco->mco_obj.mo_dir_ops = &mdc_dir_ops;
                lo->lo_ops = &mdc_obj_ops;
                RETURN(lo);
        } else
                RETURN(NULL);
}

/** Free current mdc object */
static void mdc_object_free(const struct lu_env *env, struct lu_object *lo)
{
        struct mdc_object *mco = lu2mdc_obj(lo);
        lu_object_fini(lo);
        OBD_FREE_PTR(mco);
}

/**
 * Initialize mdc object. All of them have loh_attr::LOHA_REMOTE set.
 */
static int mdc_object_init(const struct lu_env *env, struct lu_object *lo,
                           const struct lu_object_conf *unused)
{
        ENTRY;
        lo->lo_header->loh_attr |= LOHA_REMOTE;
        RETURN(0);
}

/**
 * Instance of lu_object_operations for mdc.
 */
static const struct lu_object_operations mdc_obj_ops = {
        .loo_object_init    = mdc_object_init,
        .loo_object_free    = mdc_object_free,
};

/**
 * \name The set of md_object_operations.
 * @{
 */
/**
 * Get mdc_thread_info from lu_context
 */
static
struct mdc_thread_info *mdc_info_get(const struct lu_env *env)
{
        struct mdc_thread_info *mci;

        mci = lu_context_key_get(&env->le_ctx, &mdc_thread_key);
        LASSERT(mci);
        return mci;
}

/**
 * Initialize mdc_thread_info.
 */
static
struct mdc_thread_info *mdc_info_init(const struct lu_env *env)
{
        struct mdc_thread_info *mci = mdc_info_get(env);
        memset(mci, 0, sizeof(*mci));
        return mci;
}

/**
 * Convert attributes from mdt_body to the md_attr.
 */
static void mdc_body2attr(struct mdt_body *body, struct md_attr *ma)
{
        struct lu_attr *la = &ma->ma_attr;
        /* update time */
        if (body->valid & OBD_MD_FLCTIME && body->ctime >= la->la_ctime) {
                la->la_ctime = body->ctime;
                if (body->valid & OBD_MD_FLMTIME)
                        la->la_mtime = body->mtime;
        }

        if (body->valid & OBD_MD_FLMODE)
                la->la_mode = body->mode;
        if (body->valid & OBD_MD_FLSIZE)
                la->la_size = body->size;
        if (body->valid & OBD_MD_FLBLOCKS)
                la->la_blocks = body->blocks;
        if (body->valid & OBD_MD_FLUID)
                la->la_uid = body->uid;
        if (body->valid & OBD_MD_FLGID)
                la->la_gid = body->gid;
        if (body->valid & OBD_MD_FLFLAGS)
                la->la_flags = body->flags;
        if (body->valid & OBD_MD_FLNLINK)
                la->la_nlink = body->nlink;
        if (body->valid & OBD_MD_FLRDEV)
                la->la_rdev = body->rdev;

        la->la_valid = body->valid;
        ma->ma_valid = MA_INODE;
}

/**
 * Fill the md_attr \a ma with attributes from request.
 */
static int mdc_req2attr_update(const struct lu_env *env,
                               struct md_attr *ma)
{
        struct mdc_thread_info *mci;
        struct ptlrpc_request *req;
        struct mdt_body *body;
        struct lov_mds_md *md;
        struct llog_cookie *cookie;
        void *acl;

        ENTRY;
        mci = mdc_info_get(env);
        req = mci->mci_req;
        LASSERT(req);
        body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
        LASSERT(body);
        mdc_body2attr(body, ma);

        if (body->valid & OBD_MD_FLMDSCAPA) {
                struct lustre_capa *capa;

                /* create for cross-ref will fetch mds capa from remote obj */
                capa = req_capsule_server_get(&req->rq_pill, &RMF_CAPA1);
                LASSERT(capa != NULL);
                LASSERT(ma->ma_capa != NULL);
                *ma->ma_capa = *capa;
        }

        if ((body->valid & OBD_MD_FLEASIZE) || (body->valid & OBD_MD_FLDIREA)) {
                if (body->eadatasize == 0) {
                        CERROR("No size defined for easize field\n");
                        RETURN(-EPROTO);
                }

                md = req_capsule_server_sized_get(&req->rq_pill, &RMF_MDT_MD,
                                                  body->eadatasize);
                if (md == NULL)
                        RETURN(-EPROTO);

                LASSERT(ma->ma_lmm != NULL);
                LASSERT(ma->ma_lmm_size >= body->eadatasize);
                ma->ma_lmm_size = body->eadatasize;
                memcpy(ma->ma_lmm, md, ma->ma_lmm_size);
                ma->ma_valid |= MA_LOV;
        }

        if (body->valid & OBD_MD_FLCOOKIE) {
                /*
                 * ACL and cookie share the same body->aclsize, we need
                 * to make sure that they both never come here.
                 */
                LASSERT(!(body->valid & OBD_MD_FLACL));

                if (body->aclsize == 0) {
                        CERROR("No size defined for cookie field\n");
                        RETURN(-EPROTO);
                }

                cookie = req_capsule_server_sized_get(&req->rq_pill,
                                                      &RMF_LOGCOOKIES,
                                                      body->aclsize);
                if (cookie == NULL)
                        RETURN(-EPROTO);

                LASSERT(ma->ma_cookie != NULL);
                LASSERT(ma->ma_cookie_size == body->aclsize);
                memcpy(ma->ma_cookie, cookie, ma->ma_cookie_size);
                ma->ma_valid |= MA_COOKIE;
        }

#ifdef CONFIG_FS_POSIX_ACL
        if (body->valid & OBD_MD_FLACL) {
                if (body->aclsize == 0) {
                        CERROR("No size defined for acl field\n");
                        RETURN(-EPROTO);
                }

                acl = req_capsule_server_sized_get(&req->rq_pill,
                                                   &RMF_ACL,
                                                   body->aclsize);
                if (acl == NULL)
                        RETURN(-EPROTO);

                LASSERT(ma->ma_acl != NULL);
                LASSERT(ma->ma_acl_size == body->aclsize);
                memcpy(ma->ma_acl, acl, ma->ma_acl_size);
                ma->ma_valid |= MA_ACL_DEF;
        }
#endif

        RETURN(0);
}

/**
 * The md_object_operations::moo_attr_get() in mdc.
 */
static int mdc_attr_get(const struct lu_env *env, struct md_object *mo,
                        struct md_attr *ma)
{
        struct mdc_device *mc = md2mdc_dev(md_obj2dev(mo));
        struct mdc_thread_info *mci;
        int rc;
        ENTRY;

        mci = lu_context_key_get(&env->le_ctx, &mdc_thread_key);
        LASSERT(mci);

        memset(&mci->mci_opdata, 0, sizeof(mci->mci_opdata));

        memcpy(&mci->mci_opdata.op_fid1, lu_object_fid(&mo->mo_lu),
               sizeof (struct lu_fid));
        mci->mci_opdata.op_valid = OBD_MD_FLMODE | OBD_MD_FLUID |
                                   OBD_MD_FLGID | OBD_MD_FLFLAGS |
                                   OBD_MD_FLCROSSREF;

        rc = md_getattr(mc->mc_desc.cl_exp, &mci->mci_opdata, &mci->mci_req);
        if (rc == 0) {
                /* get attr from request */
                rc = mdc_req2attr_update(env, ma);
        }

        ptlrpc_req_finished(mci->mci_req);

        RETURN(rc);
}

/**
 * Helper to init timspec \a t.
 */
static inline struct timespec *mdc_attr_time(struct timespec *t, obd_time seconds)
{
        t->tv_sec = seconds;
        t->tv_nsec = 0;
        return t;
}

/**
 * The md_object_operations::moo_attr_set() in mdc.
 *
 * \note It is only used for set ctime when rename's source on remote MDS.
 */
static int mdc_attr_set(const struct lu_env *env, struct md_object *mo,
                        const struct md_attr *ma)
{
        struct mdc_device *mc = md2mdc_dev(md_obj2dev(mo));
        const struct lu_attr *la = &ma->ma_attr;
        struct mdc_thread_info *mci;
        struct md_ucred *uc = md_ucred(env);
        int rc;
        ENTRY;

        LASSERT(ma->ma_attr.la_valid & LA_CTIME);

        mci = lu_context_key_get(&env->le_ctx, &mdc_thread_key);
        LASSERT(mci);

        memset(&mci->mci_opdata, 0, sizeof(mci->mci_opdata));

        mci->mci_opdata.op_fid1 = *lu_object_fid(&mo->mo_lu);
        mdc_attr_time(&mci->mci_opdata.op_attr.ia_ctime, la->la_ctime);
        mci->mci_opdata.op_attr.ia_mode = la->la_mode;
        mci->mci_opdata.op_attr.ia_valid = ATTR_CTIME_SET;
        if (uc &&
            ((uc->mu_valid == UCRED_OLD) || (uc->mu_valid == UCRED_NEW))) {
                mci->mci_opdata.op_fsuid = uc->mu_fsuid;
                mci->mci_opdata.op_fsgid = uc->mu_fsgid;
                mci->mci_opdata.op_cap = uc->mu_cap;
                if (uc->mu_ginfo || (uc->mu_valid == UCRED_OLD)) {
                        mci->mci_opdata.op_suppgids[0] = uc->mu_suppgids[0];
                        mci->mci_opdata.op_suppgids[1] = uc->mu_suppgids[1];
                } else {
                        mci->mci_opdata.op_suppgids[0] =
                                mci->mci_opdata.op_suppgids[1] = -1;
                }
        } else {
                mci->mci_opdata.op_fsuid = la->la_uid;
                mci->mci_opdata.op_fsgid = la->la_gid;
                mci->mci_opdata.op_cap = cfs_curproc_cap_pack();
                mci->mci_opdata.op_suppgids[0] =
                                mci->mci_opdata.op_suppgids[1] = -1;
        }

        rc = md_setattr(mc->mc_desc.cl_exp, &mci->mci_opdata,
                        NULL, 0, NULL, 0, &mci->mci_req, NULL);

        ptlrpc_req_finished(mci->mci_req);

        RETURN(rc);
}

/**
 * The md_object_operations::moo_object_create() in mdc.
 */
static int mdc_object_create(const struct lu_env *env,
                             struct md_object *mo,
                             const struct md_op_spec *spec,
                             struct md_attr *ma)
{
        struct mdc_device *mc = md2mdc_dev(md_obj2dev(mo));
        struct lu_attr *la = &ma->ma_attr;
        struct mdc_thread_info *mci;
        const void *symname;
        struct md_ucred *uc = md_ucred(env);
        int rc, symlen;
        uid_t uid;
        gid_t gid;
        cfs_cap_t cap;
        ENTRY;

        LASSERT(S_ISDIR(la->la_mode));
        LASSERT(spec->u.sp_pfid != NULL);

        mci = mdc_info_init(env);
        mci->mci_opdata.op_bias = MDS_CROSS_REF;
        mci->mci_opdata.op_fid2 = *lu_object_fid(&mo->mo_lu);

        /* Parent fid is needed to create dotdot on the remote node. */
        mci->mci_opdata.op_fid1 = *(spec->u.sp_pfid);
        mci->mci_opdata.op_mod_time = la->la_ctime;
        if (uc &&
            ((uc->mu_valid == UCRED_OLD) || (uc->mu_valid == UCRED_NEW))) {
                uid = uc->mu_fsuid;
                if (la->la_mode & S_ISGID)
                        gid = la->la_gid;
                else
                        gid = uc->mu_fsgid;
                cap = uc->mu_cap;
                if (uc->mu_ginfo || (uc->mu_valid == UCRED_OLD))
                        mci->mci_opdata.op_suppgids[0] = uc->mu_suppgids[0];
                else
                        mci->mci_opdata.op_suppgids[0] = -1;
        } else {
                uid = la->la_uid;
                gid = la->la_gid;
                cap = 0;
                mci->mci_opdata.op_suppgids[0] = -1;
        }

        /* get data from spec */
        if (spec->sp_cr_flags & MDS_CREATE_SLAVE_OBJ) {
                symname = spec->u.sp_ea.eadata;
                symlen = spec->u.sp_ea.eadatalen;
                mci->mci_opdata.op_fid1 = *(spec->u.sp_ea.fid);
                mci->mci_opdata.op_flags |= MDS_CREATE_SLAVE_OBJ;
#ifdef CONFIG_FS_POSIX_ACL
        } else if (spec->sp_cr_flags & MDS_CREATE_RMT_ACL) {
                symname = spec->u.sp_ea.eadata;
                symlen = spec->u.sp_ea.eadatalen;
                mci->mci_opdata.op_fid1 = *(spec->u.sp_ea.fid);
                mci->mci_opdata.op_flags |= MDS_CREATE_RMT_ACL;
#endif
        } else {
                symname = spec->u.sp_symname;
                symlen = symname ? strlen(symname) + 1 : 0;
        }

        rc = md_create(mc->mc_desc.cl_exp, &mci->mci_opdata,
                       symname, symlen, la->la_mode, uid, gid,
                       cap, la->la_rdev, &mci->mci_req);

        if (rc == 0) {
                /* get attr from request */
                rc = mdc_req2attr_update(env, ma);
        }

        ptlrpc_req_finished(mci->mci_req);

        RETURN(rc);
}

/**
 * The md_object_operations::moo_ref_add() in mdc.
 */
static int mdc_ref_add(const struct lu_env *env, struct md_object *mo,
                       const struct md_attr *ma)
{
        struct mdc_device *mc = md2mdc_dev(md_obj2dev(mo));
        const struct lu_attr *la = &ma->ma_attr;
        struct mdc_thread_info *mci;
        struct md_ucred *uc = md_ucred(env);
        int rc;
        ENTRY;

        mci = lu_context_key_get(&env->le_ctx, &mdc_thread_key);
        LASSERT(mci);

        memset(&mci->mci_opdata, 0, sizeof(mci->mci_opdata));
        mci->mci_opdata.op_bias = MDS_CROSS_REF;
        mci->mci_opdata.op_fid1 = *lu_object_fid(&mo->mo_lu);
        mci->mci_opdata.op_mod_time = la->la_ctime;
        if (uc &&
            ((uc->mu_valid == UCRED_OLD) || (uc->mu_valid == UCRED_NEW))) {
                mci->mci_opdata.op_fsuid = uc->mu_fsuid;
                mci->mci_opdata.op_fsgid = uc->mu_fsgid;
                mci->mci_opdata.op_cap = uc->mu_cap;
                if (uc->mu_ginfo || (uc->mu_valid == UCRED_OLD)) {
                        mci->mci_opdata.op_suppgids[0] = uc->mu_suppgids[0];
                        mci->mci_opdata.op_suppgids[1] = uc->mu_suppgids[1];
                } else {
                        mci->mci_opdata.op_suppgids[0] =
                                mci->mci_opdata.op_suppgids[1] = -1;
                }
        } else {
                mci->mci_opdata.op_fsuid = la->la_uid;
                mci->mci_opdata.op_fsgid = la->la_gid;
                mci->mci_opdata.op_cap = cfs_curproc_cap_pack();
                mci->mci_opdata.op_suppgids[0] =
                                mci->mci_opdata.op_suppgids[1] = -1;
        }


        rc = md_link(mc->mc_desc.cl_exp, &mci->mci_opdata, &mci->mci_req);

        ptlrpc_req_finished(mci->mci_req);

        RETURN(rc);
}

/**
 * The md_object_operations::moo_ref_del() in mdc.
 */
static int mdc_ref_del(const struct lu_env *env, struct md_object *mo,
                       struct md_attr *ma)
{
        struct mdc_device *mc = md2mdc_dev(md_obj2dev(mo));
        struct lu_attr *la = &ma->ma_attr;
        struct mdc_thread_info *mci;
        struct md_ucred *uc = md_ucred(env);
        int rc;
        ENTRY;

        mci = mdc_info_init(env);
        mci->mci_opdata.op_bias = MDS_CROSS_REF;
        if (ma->ma_attr_flags & MDS_VTX_BYPASS)
                mci->mci_opdata.op_bias |= MDS_VTX_BYPASS;
        else
                mci->mci_opdata.op_bias &= ~MDS_VTX_BYPASS;
        mci->mci_opdata.op_fid1 = *lu_object_fid(&mo->mo_lu);
        mci->mci_opdata.op_mode = la->la_mode;
        mci->mci_opdata.op_mod_time = la->la_ctime;
        if (uc &&
            ((uc->mu_valid == UCRED_OLD) || (uc->mu_valid == UCRED_NEW))) {
                mci->mci_opdata.op_fsuid = uc->mu_fsuid;
                mci->mci_opdata.op_fsgid = uc->mu_fsgid;
                mci->mci_opdata.op_cap = uc->mu_cap;
                if (uc->mu_ginfo || (uc->mu_valid == UCRED_OLD))
                        mci->mci_opdata.op_suppgids[0] = uc->mu_suppgids[0];
                else
                        mci->mci_opdata.op_suppgids[0] = -1;
        } else {
                mci->mci_opdata.op_fsuid = la->la_uid;
                mci->mci_opdata.op_fsgid = la->la_gid;
                mci->mci_opdata.op_cap = cfs_curproc_cap_pack();
                mci->mci_opdata.op_suppgids[0] = -1;
        }

        rc = md_unlink(mc->mc_desc.cl_exp, &mci->mci_opdata, &mci->mci_req);
        if (rc == 0) {
                /* get attr from request */
                rc = mdc_req2attr_update(env, ma);
        }

        ptlrpc_req_finished(mci->mci_req);

        RETURN(rc);
}

#ifdef HAVE_SPLIT_SUPPORT
/** Send page with directory entries to another MDS. */
int mdc_send_page(struct cmm_device *cm, const struct lu_env *env,
                  struct md_object *mo, struct page *page, __u32 offset)
{
        struct mdc_device *mc = md2mdc_dev(md_obj2dev(mo));
        int rc;
        ENTRY;

        rc = mdc_sendpage(mc->mc_desc.cl_exp, lu_object_fid(&mo->mo_lu),
                          page, offset);
        CDEBUG(rc ? D_ERROR : D_INFO, "send page %p  offset %d fid "DFID
               " rc %d \n", page, offset, PFID(lu_object_fid(&mo->mo_lu)), rc);
        RETURN(rc);
}
#endif

/**
 * Instance of md_object_operations for mdc.
 */
static const struct md_object_operations mdc_mo_ops = {
        .moo_attr_get       = mdc_attr_get,
        .moo_attr_set       = mdc_attr_set,
        .moo_object_create  = mdc_object_create,
        .moo_ref_add        = mdc_ref_add,
        .moo_ref_del        = mdc_ref_del,
};
/** @} */

/**
 * \name The set of md_dir_operations.
 * @{
 */
/**
 * The md_dir_operations::mdo_rename_tgt in mdc.
 */
static int mdc_rename_tgt(const struct lu_env *env, struct md_object *mo_p,
                          struct md_object *mo_t, const struct lu_fid *lf,
                          const struct lu_name *lname, struct md_attr *ma)
{
        struct mdc_device *mc = md2mdc_dev(md_obj2dev(mo_p));
        struct lu_attr *la = &ma->ma_attr;
        struct mdc_thread_info *mci;
        struct md_ucred *uc = md_ucred(env);
        int rc;
        ENTRY;

        mci = mdc_info_init(env);
        mci->mci_opdata.op_bias = MDS_CROSS_REF;
        if (ma->ma_attr_flags & MDS_VTX_BYPASS)
                mci->mci_opdata.op_bias |= MDS_VTX_BYPASS;
        else
                mci->mci_opdata.op_bias &= ~MDS_VTX_BYPASS;
        mci->mci_opdata.op_fid1 = *lu_object_fid(&mo_p->mo_lu);
        mci->mci_opdata.op_fid2 = *lf;
        mci->mci_opdata.op_mode = la->la_mode;
        mci->mci_opdata.op_mod_time = la->la_ctime;
        if (uc &&
            ((uc->mu_valid == UCRED_OLD) || (uc->mu_valid == UCRED_NEW))) {
                mci->mci_opdata.op_fsuid = uc->mu_fsuid;
                mci->mci_opdata.op_fsgid = uc->mu_fsgid;
                mci->mci_opdata.op_cap = uc->mu_cap;
                if (uc->mu_ginfo || (uc->mu_valid == UCRED_OLD)) {
                        mci->mci_opdata.op_suppgids[0] = uc->mu_suppgids[0];
                        mci->mci_opdata.op_suppgids[1] = uc->mu_suppgids[1];
                } else {
                        mci->mci_opdata.op_suppgids[0] =
                                mci->mci_opdata.op_suppgids[1] = -1;
                }
        } else {
                mci->mci_opdata.op_fsuid = la->la_uid;
                mci->mci_opdata.op_fsgid = la->la_gid;
                mci->mci_opdata.op_cap = cfs_curproc_cap_pack();
                mci->mci_opdata.op_suppgids[0] =
                                mci->mci_opdata.op_suppgids[1] = -1;
        }

        rc = md_rename(mc->mc_desc.cl_exp, &mci->mci_opdata, NULL, 0,
                       lname->ln_name, lname->ln_namelen, &mci->mci_req);
        if (rc == 0) {
                /* get attr from request */
                mdc_req2attr_update(env, ma);
        }

        ptlrpc_req_finished(mci->mci_req);

        RETURN(rc);
}
/**
 * Check the fids are not relatives.
 * The md_dir_operations::mdo_is_subdir() in mdc.
 *
 * Return resulting fid in sfid.
 * \retval \a sfid = 0 fids are not relatives
 * \retval \a sfid = FID at which search stopped
 */
static int mdc_is_subdir(const struct lu_env *env, struct md_object *mo,
                         const struct lu_fid *fid, struct lu_fid *sfid)
{
        struct mdc_device *mc = md2mdc_dev(md_obj2dev(mo));
        struct mdc_thread_info *mci;
        struct mdt_body *body;
        int rc;
        ENTRY;

        mci = mdc_info_init(env);

        rc = md_is_subdir(mc->mc_desc.cl_exp, lu_object_fid(&mo->mo_lu),
                          fid, &mci->mci_req);
        if (rc == 0 || rc == -EREMOTE) {
                body = req_capsule_server_get(&mci->mci_req->rq_pill,
                                              &RMF_MDT_BODY);
                LASSERT(body->valid & OBD_MD_FLID);

                CDEBUG(D_INFO, "Remote mdo_is_subdir(), new src "DFID"\n",
                       PFID(&body->fid1));
                *sfid = body->fid1;
        }
        ptlrpc_req_finished(mci->mci_req);
        RETURN(rc);
}

/** Instance of md_dir_operations for mdc. */
static const struct md_dir_operations mdc_dir_ops = {
        .mdo_is_subdir   = mdc_is_subdir,
        .mdo_rename_tgt  = mdc_rename_tgt
};
/** @} */
