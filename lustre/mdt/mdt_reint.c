/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mdt/mdt_reint.c
 *  Lustre Metadata Target (mdt) reintegration routines
 *
 *  Copyright (C) 2002-2006 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Huang Hua <huanghua@clusterfs.com>
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

#include "mdt_internal.h"


/* object operations */
static int mdt_md_open(struct mdt_thread_info *info, struct mdt_object *child)
{
        return mo_open(info->mti_ctxt, mdt_object_child(child));
                             
}

static int mdt_md_create(struct mdt_thread_info *info)
{
        struct mdt_device      *mdt = info->mti_mdt;
        struct mdt_object      *parent;
        struct mdt_object      *child;
        struct mdt_lock_handle *lh;

        int result;

        lh = &info->mti_lh[MDT_LH_PARENT];
        lh->mlh_mode = LCK_PW;

        parent = mdt_object_find_lock(info->mti_ctxt, mdt, info->mti_rr.rr_fid1,
                                      lh, MDS_INODELOCK_UPDATE);
        if (IS_ERR(parent))
                return PTR_ERR(parent);

        child = mdt_object_find(info->mti_ctxt, mdt, info->mti_rr.rr_fid2);
        if (!IS_ERR(child)) {
                struct md_object *next = mdt_object_child(parent);

                result = mdo_create(info->mti_ctxt, next, info->mti_rr.rr_name,
                                    mdt_object_child(child), &info->mti_attr);
                mdt_object_put(info->mti_ctxt, child);
        } else
                result = PTR_ERR(child);
        mdt_object_unlock(mdt->mdt_namespace, parent, lh);
        mdt_object_put(info->mti_ctxt, parent);
        return result;
}

static int mdt_md_mkdir(struct mdt_thread_info *info)
{
        struct mdt_device      *mdt = info->mti_mdt;
        struct mdt_object      *parent;
        struct mdt_object      *child;
        struct mdt_lock_handle *lh;

        int result;

        lh = &info->mti_lh[MDT_LH_PARENT];
        lh->mlh_mode = LCK_PW;

        parent = mdt_object_find_lock(info->mti_ctxt, mdt, info->mti_rr.rr_fid1,
                                      lh, MDS_INODELOCK_UPDATE);
        if (IS_ERR(parent))
                return PTR_ERR(parent);

        child = mdt_object_find(info->mti_ctxt, mdt, info->mti_rr.rr_fid2);
        if (!IS_ERR(child)) {
                struct md_object *next = mdt_object_child(parent);

                result = mdo_mkdir(info->mti_ctxt, &info->mti_attr, next,
                                   info->mti_rr.rr_name,
                                   mdt_object_child(child));
                mdt_object_put(info->mti_ctxt, child);
        } else
                result = PTR_ERR(child);
        mdt_object_unlock(mdt->mdt_namespace, parent, lh);
        mdt_object_put(info->mti_ctxt, parent);
        return result;
}

/* partial request to create object only */
static int mdt_md_mkobj(struct mdt_thread_info *info)
{
        struct mdt_device      *mdt = info->mti_mdt;
        struct mdt_object      *o;
        int result;

        ENTRY;

        o = mdt_object_find(info->mti_ctxt, mdt, info->mti_rr.rr_fid1);
        if (!IS_ERR(o)) {
                struct md_object *next = mdt_object_child(o);

                result = mo_object_create(info->mti_ctxt, next,
                                          &info->mti_attr);
                mdt_object_put(info->mti_ctxt, o);
        } else
                result = PTR_ERR(o);

        RETURN(result);
}


static int mdt_reint_setattr(struct mdt_thread_info *info)
{
        ENTRY;
        RETURN(-EOPNOTSUPP);
}


static int mdt_reint_create(struct mdt_thread_info *info)
{
        int rc;
        ENTRY;

        switch (info->mti_attr.la_mode & S_IFMT) {
        case S_IFREG:{
                rc = -EOPNOTSUPP;
                break;
        }
        case S_IFDIR:{
                if (strlen(info->mti_rr.rr_name) > 0)
                        rc = mdt_md_mkdir(info);
                else
                        rc = mdt_md_mkobj(info);

                /* return fid to client. */
                if (rc == 0) {
                        struct mdt_body *body;

                        body = info->mti_reint_rep.mrr_body;
                        body->fid1   = *info->mti_rr.rr_fid2;
                        body->valid |= OBD_MD_FLID;
                }
                break;
        }
        case S_IFLNK:{
                rc = -EOPNOTSUPP;
                break;
        }
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:{
                rc = -EOPNOTSUPP;
                break;
        }
        default:
                rc = -EOPNOTSUPP;
        }
        RETURN(rc);
}


static int mdt_reint_unlink(struct mdt_thread_info *info)
{
        ENTRY;
        RETURN(-EOPNOTSUPP);
}

static int mdt_reint_link(struct mdt_thread_info *info)
{
        ENTRY;
        RETURN(-EOPNOTSUPP);
}


static int mdt_reint_rename(struct mdt_thread_info *info)
{
        ENTRY;
        RETURN(-EOPNOTSUPP);
}

static int mdt_reint_open(struct mdt_thread_info *info)
{
        struct mdt_device      *mdt = info->mti_mdt;
        struct mdt_object      *parent;
        struct mdt_object      *child;
        struct mdt_lock_handle *lh;
        int                     result;
        struct ldlm_reply      *ldlm_rep;
        struct ptlrpc_request  *req = mdt_info_req(info);
        __u32                   mode = info->mti_attr.la_mode; /*save a backup*/
        struct mdt_body        *body = info->mti_reint_rep.mrr_body;
         struct lov_mds_md     *lmm  = info->mti_reint_rep.mrr_md;

        ENTRY;

        lh = &info->mti_lh[MDT_LH_PARENT];
        lh->mlh_mode = LCK_PW;

        ldlm_rep = req_capsule_server_get(&info->mti_pill, &RMF_DLM_REP);

        parent = mdt_object_find_lock(info->mti_ctxt,
                                      mdt, info->mti_rr.rr_fid1,
                                      lh,
                                      MDS_INODELOCK_UPDATE);
        if (IS_ERR(parent))
                RETURN(PTR_ERR(parent));

        result = mdo_lookup(info->mti_ctxt, mdt_object_child(parent),
                            info->mti_rr.rr_name, info->mti_rr.rr_fid2);
        if (result && result != -ENOENT) {
                GOTO(out_parent, result);
        }

        intent_set_disposition(ldlm_rep, DISP_LOOKUP_EXECD);

        if (result == -ENOENT)
                intent_set_disposition(ldlm_rep, DISP_LOOKUP_NEG);
        else
                intent_set_disposition(ldlm_rep, DISP_LOOKUP_POS);

        if (result == -ENOENT) {
                if(!(info->mti_rr.rr_flags & MDS_OPEN_CREAT))
                        GOTO(out_parent, result);
                if (req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                        GOTO(out_parent, result = -EROFS);
        }

        child = mdt_object_find(info->mti_ctxt, mdt, info->mti_rr.rr_fid2);
        if (IS_ERR(child))
                GOTO(out_parent, PTR_ERR(child));

       if (info->mti_rr.rr_flags & MDS_OPEN_CREAT) {
                if (result == -ENOENT) {
                        /* let's create something */
                        result = mdo_create(info->mti_ctxt,
                                            mdt_object_child(parent),
                                            info->mti_rr.rr_name,
                                            mdt_object_child(child),
                                            &info->mti_attr);
                        intent_set_disposition(ldlm_rep, DISP_OPEN_CREATE);
                } else if (info->mti_rr.rr_flags & MDS_OPEN_EXCL) {
                        GOTO(out_child, result = -EEXIST);
                }
        }

        if (result != 0)
                GOTO(out_child, result);

        result = mo_attr_get(info->mti_ctxt,
                             mdt_object_child(child),
                             &info->mti_attr);
        if (result != 0)
                GOTO(out_child, result);

        mdt_pack_attr2body(body, &info->mti_attr);
        body->fid1 = *mdt_object_fid(child);
        body->valid |= OBD_MD_FLID;

        /* To be continued: we should return "struct lov_mds_md" back*/
        lmm = req_capsule_server_get(&info->mti_pill,
                                     &RMF_MDT_MD);

        result = mo_xattr_get(info->mti_ctxt, mdt_object_child(child), 
                              lmm, MAX_MD_SIZE, "lov");
        if (result <= 0)
                GOTO(out_child, result = -EINVAL);

        if (S_ISDIR(info->mti_attr.la_mode))
                body->valid |= OBD_MD_FLDIREA;
        else
                body->valid |= OBD_MD_FLEASIZE;
        body->eadatasize = result;
        result = 0;

        /* FIXME Let me fake it until the underlying works */
        lmm->lmm_magic   = LOV_MAGIC;           /* magic number = LOV_MAGIC_V1 */
        lmm->lmm_pattern = LOV_PATTERN_RAID0;   /* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
        lmm->lmm_object_id = 1;                 /* LOV object ID */
        lmm->lmm_object_gr = 1;                 /* LOV object group */
        lmm->lmm_stripe_size = 4096 * 1024;     /* size of stripe in bytes */
        lmm->lmm_stripe_count = 1;              /* num stripes in use for this object */
                                                /* per-stripe data */
        lmm->lmm_objects[0].l_object_id = 1;    /* OST object ID */
        lmm->lmm_objects[0].l_object_gr = 1;    /* OST object group (creating MDS number) */
        lmm->lmm_objects[0].l_ost_gen   = 1;    /* generation of this l_ost_idx */
        lmm->lmm_objects[0].l_ost_idx   = 0;    /* OST index in LOV (lov_tgt_desc->tgts) */
        body->eadatasize = sizeof(struct lov_mds_md) + sizeof(struct lov_ost_data);



        /*FIXME add permission checking here */
        if (S_ISREG(mode))
                ;
        /* Open it now. */
        result = mdt_md_open(info, child);

out_child:
        mdt_object_put(info->mti_ctxt, child);
out_parent:
        mdt_object_unlock(mdt->mdt_namespace, parent, lh);
        mdt_object_put(info->mti_ctxt, parent);
        RETURN(result);
}


typedef int (*mdt_reinter)(struct mdt_thread_info *info);

static mdt_reinter reinters[REINT_MAX] = {
        [REINT_SETATTR]  = mdt_reint_setattr,
        [REINT_CREATE] = mdt_reint_create,
        [REINT_LINK] = mdt_reint_link,
        [REINT_UNLINK] = mdt_reint_unlink,
        [REINT_RENAME] = mdt_reint_rename,
        [REINT_OPEN] = mdt_reint_open
};

int mdt_reint_rec(struct mdt_thread_info *info)
{
        int rc;
        ENTRY;

        rc = reinters[info->mti_rr.rr_opcode](info);

        RETURN(rc);
}
