/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mdt/mdt_lib.c
 *  Lustre Metadata Target (mdt) request unpacking helper.
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Mike Shaver <shaver@clusterfs.com>
 *   Author: Nikita Danilov <nikita@clusterfs.com>
 *   Author: Huang Hua <huanghua@clusterfs.com>
 *
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


/* copied from lov/lov_ea.c, just for debugging, will be removed later */
void mdt_dump_lmm(int level, struct lov_mds_md *lmm)
{
        struct lov_ost_data_v1 *lod;
        int i;
        __s16 stripe_count =
                le16_to_cpu(((struct lov_user_md*)lmm)->lmm_stripe_count);

        CDEBUG(level, "objid "LPX64", magic 0x%08X, pattern %#X\n",
               le64_to_cpu(lmm->lmm_object_id), le32_to_cpu(lmm->lmm_magic),
               le32_to_cpu(lmm->lmm_pattern));
        CDEBUG(level,"stripe_size=0x%x, stripe_count=0x%x\n",
               le32_to_cpu(lmm->lmm_stripe_size),
               le32_to_cpu(lmm->lmm_stripe_count));
        LASSERT(stripe_count < (__s16)LOV_MAX_STRIPE_COUNT);
        for (i = 0, lod = lmm->lmm_objects; i < stripe_count; i++, lod++) {
                CDEBUG(level, "stripe %u idx %u subobj "LPX64"/"LPX64"\n",
                       i, le32_to_cpu(lod->l_ost_idx),
                       le64_to_cpu(lod->l_object_gr),
                       le64_to_cpu(lod->l_object_id));
        }
}

void mdt_shrink_reply(struct mdt_thread_info *info, int offset)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        struct mdt_body *body;
        int acl_size = 0;
        int md_size = 0;

        body = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        LASSERT(body != NULL);

        md_size = body->eadatasize;
        acl_size = body->aclsize;

        CDEBUG(D_INFO, "Shrink to md_size %d cookie_size %d \n",
                       md_size, acl_size);

        lustre_shrink_reply(req, offset, md_size, 1);
        lustre_shrink_reply(req, md_size ? offset + 1: offset, acl_size, 0);
}


/* if object is dying, pack the lov/llog data,
 * parameter info->mti_attr should be valid at this point! */
int mdt_handle_last_unlink(struct mdt_thread_info *info, struct mdt_object *mo,
                           const struct md_attr *ma)
{
        struct mdt_body       *repbody;
        const struct lu_attr *la = &ma->ma_attr;
        ENTRY;

        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);

        if (ma->ma_valid & MA_INODE)
                mdt_pack_attr2body(repbody, la, mdt_object_fid(mo));

        if (ma->ma_valid & MA_LOV) {
                __u32 mode;

                mode = lu_object_attr(&mo->mot_obj.mo_lu);
                LASSERT(ma->ma_lmm_size);
                mdt_dump_lmm(D_INFO, ma->ma_lmm);
                repbody->eadatasize = ma->ma_lmm_size;
                if (S_ISREG(mode))
                        repbody->valid |= OBD_MD_FLEASIZE;
                else if (S_ISDIR(mode))
                        repbody->valid |= OBD_MD_FLDIREA;
                else
                        LBUG();
        }

        if (ma->ma_cookie_size && (ma->ma_valid & MA_COOKIE)) {
                repbody->aclsize = ma->ma_cookie_size;
                repbody->valid |= OBD_MD_FLCOOKIE;
        }

        RETURN(0);
}

static __u64 mdt_attr_valid_xlate(__u64 in, struct mdt_reint_record *rr,
                                  struct md_attr *ma)
{
        __u64 out;

        out = 0;
        if (in & ATTR_MODE)
                out |= LA_MODE;
        if (in & ATTR_UID)
                out |= LA_UID;
        if (in & ATTR_GID)
                out |= LA_GID;
        if (in & ATTR_SIZE)
                out |= LA_SIZE;

        if (in & ATTR_FROM_OPEN)
                rr->rr_flags |= MRF_SETATTR_LOCKED;

        if (in & ATTR_ATIME_SET)
                out |= LA_ATIME;

        if (in & ATTR_CTIME_SET)
                out |= LA_CTIME;

        if (in & ATTR_MTIME_SET)
                out |= LA_MTIME;

        if (in & ATTR_ATTR_FLAG)
                out |= LA_FLAGS;

        /*XXX need ATTR_RAW?*/
        in &= ~(ATTR_MODE|ATTR_UID|ATTR_GID|ATTR_SIZE|
                ATTR_ATIME|ATTR_MTIME|ATTR_CTIME|ATTR_FROM_OPEN|
                ATTR_ATIME_SET|ATTR_CTIME_SET|ATTR_MTIME_SET|
                ATTR_ATTR_FLAG|ATTR_RAW);
        if (in != 0)
                CERROR("Unknown attr bits: %#llx\n", in);
        return out;
}
/* unpacking */
static int mdt_setattr_unpack(struct mdt_thread_info *info)
{
        struct mdt_rec_setattr  *rec;
        struct md_attr          *ma = &info->mti_attr;
        struct lu_attr          *la = &ma->ma_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule      *pill = &info->mti_pill;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_SETATTR);

        if (rec == NULL)
                RETURN(-EFAULT);

        rr->rr_fid1 = &rec->sa_fid;
        la->la_valid = mdt_attr_valid_xlate(rec->sa_valid, rr, ma);
        la->la_mode  = rec->sa_mode;
        la->la_flags = rec->sa_attr_flags;
        la->la_uid   = rec->sa_uid;
        la->la_gid   = rec->sa_gid;
        la->la_size  = rec->sa_size;
        la->la_ctime = rec->sa_ctime;
        la->la_atime = rec->sa_atime;
        la->la_mtime = rec->sa_mtime;
        ma->ma_valid = MA_INODE;

        if (req_capsule_field_present(pill, &RMF_EADATA)) {
                ma->ma_lmm = req_capsule_client_get(pill, &RMF_EADATA);
                ma->ma_lmm_size = req_capsule_get_size(pill, &RMF_EADATA,
                                                       RCL_CLIENT);
                ma->ma_valid |= MA_LOV;
        }
        if (req_capsule_field_present(pill, &RMF_LOGCOOKIES)) {
                ma->ma_cookie = req_capsule_client_get(pill,
                                                       &RMF_LOGCOOKIES);
                ma->ma_cookie_size = req_capsule_get_size(pill,
                                                          &RMF_LOGCOOKIES,
                                                          RCL_CLIENT);
                ma->ma_valid |= MA_COOKIE;
        }

        RETURN(0);
}

static int mdt_create_unpack(struct mdt_thread_info *info)
{
        struct mdt_rec_create   *rec;
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule      *pill = &info->mti_pill;
        int                     result = 0;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_CREATE);
        if (rec != NULL) {
                rr->rr_fid1 = &rec->cr_fid1;
                rr->rr_fid2 = &rec->cr_fid2;
                attr->la_mode = rec->cr_mode;
                attr->la_rdev  = rec->cr_rdev;
                attr->la_uid   = rec->cr_fsuid;
                attr->la_gid   = rec->cr_fsgid;
                attr->la_ctime = rec->cr_time;
                attr->la_mtime = rec->cr_time;
                attr->la_atime = rec->cr_time;
                attr->la_valid = LA_MODE | LA_RDEV | LA_UID | LA_GID |
                                 LA_CTIME | LA_MTIME | LA_ATIME;
                info->mti_spec.sp_cr_flags = rec->cr_flags;

                rr->rr_name = req_capsule_client_get(pill, &RMF_NAME);
                if (rr->rr_name) {
                        if (req_capsule_field_present(pill, &RMF_SYMTGT)) {
                                const char *tgt;
                                tgt = req_capsule_client_get(pill,
                                                             &RMF_SYMTGT);
                                if (tgt == NULL)
                                        result = -EFAULT;
                                info->mti_spec.u.sp_symname = tgt;
                        }
                } else
                        result = -EFAULT;
        } else
                result = -EFAULT;
        RETURN(result);
}

static int mdt_link_unpack(struct mdt_thread_info *info)
{
        struct mdt_rec_link     *rec;
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule      *pill = &info->mti_pill;
        int                      result = 0;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_LINK);
        if (rec != NULL) {
                attr->la_uid = rec->lk_fsuid;
                attr->la_gid = rec->lk_fsgid;
                rr->rr_fid1 = &rec->lk_fid1;
                rr->rr_fid2 = &rec->lk_fid2;
                attr->la_ctime = rec->lk_time;
                attr->la_mtime = rec->lk_time;
                attr->la_valid = LA_UID | LA_GID | LA_CTIME | LA_MTIME;
                rr->rr_name = req_capsule_client_get(pill, &RMF_NAME);
                if (rr->rr_name == NULL)
                        result = -EFAULT;
        } else
                result = -EFAULT;
        RETURN(result);
}

static int mdt_unlink_unpack(struct mdt_thread_info *info)
{
        struct mdt_rec_unlink   *rec;
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule      *pill = &info->mti_pill;
        int                      result = 0;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_UNLINK);
        if (rec != NULL) {
                attr->la_uid = rec->ul_fsuid;
                attr->la_gid = rec->ul_fsgid;
                rr->rr_fid1 = &rec->ul_fid1;
                rr->rr_fid2 = &rec->ul_fid2;
                attr->la_ctime = rec->ul_time;
                attr->la_mtime = rec->ul_time;
                attr->la_mode  = rec->ul_mode;

                attr->la_valid = LA_UID | LA_GID | LA_CTIME | LA_MTIME | LA_MODE;
                rr->rr_name = req_capsule_client_get(pill, &RMF_NAME);
                if (rr->rr_name == NULL)
                        result = -EFAULT;
        } else
                result = -EFAULT;
        RETURN(result);
}

static int mdt_rename_unpack(struct mdt_thread_info *info)
{
        struct mdt_rec_rename   *rec;
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule      *pill = &info->mti_pill;
        int                      result = 0;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_RENAME);
        if (rec != NULL) {
                attr->la_uid = rec->rn_fsuid;
                attr->la_gid = rec->rn_fsgid;
                rr->rr_fid1 = &rec->rn_fid1;
                rr->rr_fid2 = &rec->rn_fid2;
                attr->la_ctime = rec->rn_time;
                attr->la_mtime = rec->rn_time;
                attr->la_valid = LA_UID | LA_GID | LA_CTIME | LA_MTIME;
                rr->rr_name = req_capsule_client_get(pill, &RMF_NAME);
                rr->rr_tgt = req_capsule_client_get(pill, &RMF_SYMTGT);
                if (rr->rr_name == NULL || rr->rr_tgt == NULL)
                        result = -EFAULT;
        } else
                result = -EFAULT;
        RETURN(result);
}

static int mdt_open_unpack(struct mdt_thread_info *info)
{
        struct mdt_rec_create   *rec;
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct req_capsule      *pill = &info->mti_pill;
        struct mdt_reint_record *rr   = &info->mti_rr;
        int                     result;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_CREATE);
        if (rec != NULL) {
                rr->rr_fid1   = &rec->cr_fid1;
                rr->rr_fid2   = &rec->cr_fid2;
                attr->la_mode = rec->cr_mode;
                attr->la_rdev  = rec->cr_rdev;
                attr->la_uid   = rec->cr_fsuid;
                attr->la_gid   = rec->cr_fsgid;
                attr->la_ctime = rec->cr_time;
                attr->la_mtime = rec->cr_time;
                attr->la_atime = rec->cr_time;
                attr->la_valid = LA_MODE | LA_RDEV | LA_UID | LA_GID | LA_CTIME
                                 | LA_MTIME | LA_ATIME;
                info->mti_spec.sp_cr_flags = rec->cr_flags;
                rr->rr_name = req_capsule_client_get(pill, &RMF_NAME);
                if (rr->rr_name == NULL)
                        /*XXX: what about open by FID? */
                        result = -EFAULT;
                else
                        result = 0;
        } else
                result = -EFAULT;

        if (req_capsule_field_present(pill, &RMF_EADATA)) {
                struct md_create_spec *sp = &info->mti_spec;
                sp->u.sp_ea.eadata = req_capsule_client_get(pill,
                                                            &RMF_EADATA);
                sp->u.sp_ea.eadatalen = req_capsule_get_size(pill,
                                                             &RMF_EADATA,
                                                             RCL_CLIENT);
        }

        RETURN(result);
}

typedef int (*reint_unpacker)(struct mdt_thread_info *info);

static reint_unpacker mdt_reint_unpackers[REINT_MAX] = {
        [REINT_SETATTR]  = mdt_setattr_unpack,
        [REINT_CREATE]   = mdt_create_unpack,
        [REINT_LINK]     = mdt_link_unpack,
        [REINT_UNLINK]   = mdt_unlink_unpack,
        [REINT_RENAME]   = mdt_rename_unpack,
        [REINT_OPEN]     = mdt_open_unpack
};

int mdt_reint_unpack(struct mdt_thread_info *info, __u32 op)
{
        int rc;

        ENTRY;

        if (op < REINT_MAX && mdt_reint_unpackers[op] != NULL) {
                info->mti_rr.rr_opcode = op;
                rc = mdt_reint_unpackers[op](info);
        } else {
                CERROR("Unexpected opcode %d\n", op);
                rc = -EFAULT;
        }
        RETURN(rc);
}
