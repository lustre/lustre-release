/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/cmm/mdc_object.c
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
#include <obd_support.h>
#include <lustre_lib.h>
#include <obd_class.h>
#include <lustre_mdc.h>
#include "cmm_internal.h"
#include "mdc_internal.h"

static struct md_object_operations mdc_mo_ops;
static struct md_dir_operations mdc_dir_ops;
static struct lu_object_operations mdc_obj_ops;

extern struct lu_context_key mdc_thread_key;

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

static void mdc_object_free(const struct lu_env *env, struct lu_object *lo)
{
        struct mdc_object *mco = lu2mdc_obj(lo);
	lu_object_fini(lo);
        OBD_FREE_PTR(mco);
}

static int mdc_object_init(const struct lu_env *env, struct lu_object *lo)
{
        ENTRY;
        lo->lo_header->loh_attr |= LOHA_REMOTE;
        RETURN(0);
}

static int mdc_object_print(const struct lu_env *env, void *cookie,
                            lu_printer_t p, const struct lu_object *lo)
{
	return (*p)(env, cookie, LUSTRE_CMM_MDC_NAME"-object@%p", lo);
}

static struct lu_object_operations mdc_obj_ops = {
        .loo_object_init    = mdc_object_init,
        .loo_object_free    = mdc_object_free,
	.loo_object_print   = mdc_object_print,
};

/* md_object_operations */
static
struct mdc_thread_info *mdc_info_get(const struct lu_env *env)
{
        struct mdc_thread_info *mci;

        mci = lu_context_key_get(&env->le_ctx, &mdc_thread_key);
        LASSERT(mci);
        return mci;
}

static
struct mdc_thread_info *mdc_info_init(const struct lu_env *env)
{
        struct mdc_thread_info *mci;

        mci = mdc_info_get(env);

        memset(mci, 0, sizeof(*mci));

        return mci;
}

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

        ma->ma_valid = MA_INODE;
}

static int mdc_req2attr_update(const struct lu_env *env,
                                struct md_attr *ma)
{
        struct mdc_thread_info *mci;
        struct ptlrpc_request *req;
        struct mdt_body *body;
        struct lov_mds_md *lov;
        struct llog_cookie *cookie;

        ENTRY;
        mci = mdc_info_get(env);
        req = mci->mci_req;
        LASSERT(req);
        body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof(*body));
        LASSERT(body);
        mdc_body2attr(body, ma);

        if (!(body->valid & OBD_MD_FLEASIZE))
                RETURN(0);

        if (body->eadatasize == 0) {
                CERROR("OBD_MD_FLEASIZE is set but eadatasize is zero\n");
                RETURN(-EPROTO);
        }

        lov = lustre_swab_repbuf(req, REPLY_REC_OFF + 1,
                                 body->eadatasize, NULL);
        if (lov == NULL) {
                CERROR("Can't unpack MDS EA data\n");
                RETURN(-EPROTO);
        }

        LASSERT(ma->ma_lmm != NULL);
        LASSERT(ma->ma_lmm_size >= body->eadatasize); 
        ma->ma_lmm_size = body->eadatasize;
        memcpy(ma->ma_lmm, lov, ma->ma_lmm_size);
        ma->ma_valid |= MA_LOV;
        if (!(body->valid & OBD_MD_FLCOOKIE))
                RETURN(0);

        if (body->aclsize == 0) {
                CERROR("OBD_MD_FLCOOKIE is set but cookie size is zero\n");
                RETURN(-EPROTO);
        }

        cookie = lustre_msg_buf(req->rq_repmsg,
                                REPLY_REC_OFF + 2, body->aclsize);
        if (cookie == NULL) {
                CERROR("Can't unpack unlink cookie data\n");
                RETURN(-EPROTO);
        }

        LASSERT(ma->ma_cookie != NULL);
        LASSERT(ma->ma_cookie_size == body->aclsize);
        memcpy(ma->ma_cookie, cookie, ma->ma_cookie_size);
        ma->ma_valid |= MA_COOKIE;
        RETURN(0);
}

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

        /* FIXME: split capability */
        rc = md_getattr(mc->mc_desc.cl_exp, lu_object_fid(&mo->mo_lu), NULL,
                        OBD_MD_FLMODE | OBD_MD_FLUID | OBD_MD_FLGID |
                        OBD_MD_FLFLAGS,
                        0, &mci->mci_req);

        if (rc == 0) {
                /* get attr from request */
                rc = mdc_req2attr_update(env, ma);
        }

        ptlrpc_req_finished(mci->mci_req);

        RETURN(rc);
}


static int mdc_object_create(const struct lu_env *env,
                             struct md_object *mo,
                             const struct md_create_spec *spec,
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
        __u32 cap;
        ENTRY;

        LASSERT(spec->u.sp_pfid != NULL);
        mci = mdc_info_init(env);
        mci->mci_opdata.fid2 = *lu_object_fid(&mo->mo_lu);
        /* parent fid is needed to create dotdot on the remote node */
        mci->mci_opdata.fid1 = *(spec->u.sp_pfid);
        mci->mci_opdata.mod_time = la->la_mtime;
        if (uc &&
            ((uc->mu_valid == UCRED_OLD) || (uc->mu_valid == UCRED_NEW))) {
                uid = uc->mu_fsuid;
                if (la->la_mode & S_ISGID)
                        gid = la->la_gid;
                else
                        gid = uc->mu_fsgid;
                cap = uc->mu_cap;
                if (uc->mu_ginfo || (uc->mu_valid == UCRED_OLD))
                        mci->mci_opdata.suppgids[0] = uc->mu_suppgids[0];
                else
                        mci->mci_opdata.suppgids[0] = -1;
        } else {
                uid = la->la_uid;
                gid = la->la_gid;
                cap = 0;
                mci->mci_opdata.suppgids[0] = -1;
        }

        /* get data from spec */
        if (spec->sp_cr_flags & MDS_CREATE_SLAVE_OBJ) {
                symname = spec->u.sp_ea.eadata;
                symlen = spec->u.sp_ea.eadatalen;
                mci->mci_opdata.fid1 = *(spec->u.sp_ea.fid);
                mci->mci_opdata.flags |= MDS_CREATE_SLAVE_OBJ;
        } else {
                symname = spec->u.sp_symname;
                symlen = symname ? strlen(symname) + 1 : 0;
        }

        rc = md_create(mc->mc_desc.cl_exp, &mci->mci_opdata,
                       symname, symlen,
                       la->la_mode, uid, gid, cap, la->la_rdev,
                       &mci->mci_req);

        if (rc == 0) {
                /* get attr from request */
                rc = mdc_req2attr_update(env, ma);
        }

        ptlrpc_req_finished(mci->mci_req);

        RETURN(rc);
}

static int mdc_ref_add(const struct lu_env *env, struct md_object *mo)
{
        struct mdc_device *mc = md2mdc_dev(md_obj2dev(mo));
        struct mdc_thread_info *mci;
        struct md_ucred *uc = md_ucred(env);
        int rc;
        ENTRY;

        mci = lu_context_key_get(&env->le_ctx, &mdc_thread_key);
        LASSERT(mci);

        memset(&mci->mci_opdata, 0, sizeof(mci->mci_opdata));
        mci->mci_opdata.fid1 = *lu_object_fid(&mo->mo_lu);
        //mci->mci_opdata.mod_time = la->la_ctime;
        //mci->mci_opdata.fsuid = la->la_uid;
        //mci->mci_opdata.fsgid = la->la_gid;
        mci->mci_opdata.mod_time = CURRENT_SECONDS;
        if (uc &&
            ((uc->mu_valid == UCRED_OLD) || (uc->mu_valid == UCRED_NEW))) {
                mci->mci_opdata.fsuid = uc->mu_fsuid;
                mci->mci_opdata.fsgid = uc->mu_fsgid;
                mci->mci_opdata.cap = uc->mu_cap;
                if (uc->mu_ginfo || (uc->mu_valid == UCRED_OLD)) {
                        mci->mci_opdata.suppgids[0] = uc->mu_suppgids[0];
                        mci->mci_opdata.suppgids[1] = uc->mu_suppgids[1];
                } else {
                        mci->mci_opdata.suppgids[0] =
                                mci->mci_opdata.suppgids[1] = -1;
                }
        } else {
                mci->mci_opdata.fsuid = current->fsuid;
                mci->mci_opdata.fsgid = current->fsgid;
                mci->mci_opdata.cap = current->cap_effective;
                mci->mci_opdata.suppgids[0] = mci->mci_opdata.suppgids[1] = -1;
        }


        rc = md_link(mc->mc_desc.cl_exp, &mci->mci_opdata, &mci->mci_req);

        ptlrpc_req_finished(mci->mci_req);

        RETURN(rc);
}

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
        mci->mci_opdata.fid1 = *lu_object_fid(&mo->mo_lu);
        mci->mci_opdata.mode = la->la_mode;
        mci->mci_opdata.mod_time = la->la_ctime;
        if (uc &&
            ((uc->mu_valid == UCRED_OLD) || (uc->mu_valid == UCRED_NEW))) {
                mci->mci_opdata.fsuid = uc->mu_fsuid;
                mci->mci_opdata.fsgid = uc->mu_fsgid;
                mci->mci_opdata.cap = uc->mu_cap;
                if (uc->mu_ginfo || (uc->mu_valid == UCRED_OLD))
                        mci->mci_opdata.suppgids[0] = uc->mu_suppgids[0];
                else
                        mci->mci_opdata.suppgids[0] = -1;
        } else {
                mci->mci_opdata.fsuid = la->la_uid;
                mci->mci_opdata.fsgid = la->la_gid;
                mci->mci_opdata.cap = current->cap_effective;
                mci->mci_opdata.suppgids[0] = -1;
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
int mdc_send_page(struct cmm_device *cm, const struct lu_env *env,
                  struct md_object *mo, struct page *page, __u32 offset)
{
        struct mdc_device *mc = md2mdc_dev(md_obj2dev(mo));
        int rc;
        ENTRY;

        rc = mdc_sendpage(mc->mc_desc.cl_exp, lu_object_fid(&mo->mo_lu),
                          page, offset);
        CDEBUG(D_INFO, "send page %p  offset %d fid "DFID" rc %d \n",
               page, offset, PFID(lu_object_fid(&mo->mo_lu)), rc);
        RETURN(rc);
}
#endif

static struct md_object_operations mdc_mo_ops = {
        .moo_attr_get       = mdc_attr_get,
        .moo_object_create  = mdc_object_create,
        .moo_ref_add        = mdc_ref_add,
        .moo_ref_del        = mdc_ref_del,
};

/* md_dir_operations */
static int mdc_rename_tgt(const struct lu_env *env, struct md_object *mo_p,
                          struct md_object *mo_t, const struct lu_fid *lf,
                          const char *name, struct md_attr *ma)
{
        struct mdc_device *mc = md2mdc_dev(md_obj2dev(mo_p));
        struct lu_attr *la = &ma->ma_attr;
        struct mdc_thread_info *mci;
        struct md_ucred *uc = md_ucred(env);
        int rc;
        ENTRY;

        mci = mdc_info_init(env);
        mci->mci_opdata.fid1 = *lu_object_fid(&mo_p->mo_lu);
        mci->mci_opdata.fid2 = *lf;
        mci->mci_opdata.mode = la->la_mode;
        mci->mci_opdata.mod_time = la->la_ctime;
        if (uc &&
            ((uc->mu_valid == UCRED_OLD) || (uc->mu_valid == UCRED_NEW))) {
                mci->mci_opdata.fsuid = uc->mu_fsuid;
                mci->mci_opdata.fsgid = uc->mu_fsgid;
                mci->mci_opdata.cap = uc->mu_cap;
                if (uc->mu_ginfo || (uc->mu_valid == UCRED_OLD)) {
                        mci->mci_opdata.suppgids[0] = uc->mu_suppgids[0];
                        mci->mci_opdata.suppgids[1] = uc->mu_suppgids[1];
                } else {
                        mci->mci_opdata.suppgids[0] =
                                mci->mci_opdata.suppgids[1] = -1;
                }
        } else {
                mci->mci_opdata.fsuid = la->la_uid;
                mci->mci_opdata.fsgid = la->la_gid;
                mci->mci_opdata.cap = current->cap_effective;
                mci->mci_opdata.suppgids[0] = mci->mci_opdata.suppgids[1] = -1;
        }

        rc = md_rename(mc->mc_desc.cl_exp, &mci->mci_opdata, NULL, 0,
                       name, strlen(name), &mci->mci_req);
        if (rc == 0) {
                /* get attr from request */
                mdc_req2attr_update(env, ma);
        }

        ptlrpc_req_finished(mci->mci_req);

        RETURN(rc);
}

static int mdc_is_subdir(const struct lu_env *env, struct md_object *mo,
                         const struct lu_fid *fid, struct lu_fid *sfid)
{
        struct mdc_device *mc = md2mdc_dev(md_obj2dev(mo));
        struct mdc_thread_info *mci;
        struct mdt_body *body;
        int rc;
        ENTRY;

        mci = mdc_info_init(env);

        /* FIXME: capability for split! */
        rc = md_is_subdir(mc->mc_desc.cl_exp, lu_object_fid(&mo->mo_lu),
                          fid, NULL, NULL, &mci->mci_req);
        if (rc)
                GOTO(out, rc);

        body = lustre_msg_buf(mci->mci_req->rq_repmsg, REPLY_REC_OFF,
                              sizeof(*body));

        LASSERT(body->valid & (OBD_MD_FLMODE | OBD_MD_FLID) &&
                (body->mode == 0 || body->mode == 1 || body->mode == EREMOTE));

        rc = body->mode;
        if (rc == EREMOTE) {
                CDEBUG(D_INFO, "Remote mdo_is_subdir(), new src "
                       DFID"\n", PFID(&body->fid1));
                *sfid = body->fid1;
        }
        EXIT;
out:
        ptlrpc_req_finished(mci->mci_req);
        return rc;
}

static struct md_dir_operations mdc_dir_ops = {
        .mdo_is_subdir   = mdc_is_subdir,
        .mdo_rename_tgt  = mdc_rename_tgt
};
