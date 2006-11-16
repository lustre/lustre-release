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


typedef enum ucred_init_type {
        NONE_INIT       = 0,
        BODY_INIT       = 1,
        REC_INIT        = 2
} ucred_init_type_t;

int groups_from_list(struct group_info *ginfo, gid_t *glist)
{
        int i;
        int count = ginfo->ngroups;

        /* fill group_info from gid array */
        for (i = 0; i < ginfo->nblocks; i++) {
                int cp_count = min(NGROUPS_PER_BLOCK, count);
                int off = i * NGROUPS_PER_BLOCK;
                int len = cp_count * sizeof(*glist);

                if (memcpy(ginfo->blocks[i], glist + off, len))
                        return -EFAULT;

                count -= cp_count;
        }
        return 0;
}

/* groups_sort() is copied from linux kernel! */
/* a simple shell-metzner sort */
void groups_sort(struct group_info *group_info)
{
        int base, max, stride;
        int gidsetsize = group_info->ngroups;

        for (stride = 1; stride < gidsetsize; stride = 3 * stride + 1)
                ; /* nothing */
        stride /= 3;

        while (stride) {
                max = gidsetsize - stride;
                for (base = 0; base < max; base++) {
                        int left = base;
                        int right = left + stride;
                        gid_t tmp = GROUP_AT(group_info, right);

                        while (left >= 0 && GROUP_AT(group_info, left) > tmp) {
                                GROUP_AT(group_info, right) =
                                    GROUP_AT(group_info, left);
                                right = left;
                                left -= stride;
                        }
                        GROUP_AT(group_info, right) = tmp;
                }
                stride /= 3;
        }
}

void mdt_exit_ucred(struct mdt_thread_info *info)
{
        struct md_ucred   *uc  = mdt_ucred(info);
        struct mdt_device *mdt = info->mti_mdt;

        if (uc->mu_valid != UCRED_INIT) {
                uc->mu_suppgids[0] = uc->mu_suppgids[1] = -1;
                if (uc->mu_ginfo) {
                        groups_free(uc->mu_ginfo);
                        uc->mu_ginfo = NULL;
                }
                if (uc->mu_identity) {
                        mdt_identity_put(mdt->mdt_identity_cache,
                                         uc->mu_identity);
                        uc->mu_identity = NULL;
                }
                uc->mu_valid = UCRED_INIT;
        }
}

static int old_init_ucred(struct mdt_thread_info *info,
                          struct mdt_body *body)
{
        struct md_ucred     *uc  = mdt_ucred(info);
        struct mdt_device   *mdt = info->mti_mdt;
        struct mdt_identity *identity = NULL;

        ENTRY;

        uc->mu_valid = UCRED_INVALID;

        if (!is_identity_get_disabled(mdt->mdt_identity_cache)) {
                /* get identity info of this user */
                identity = mdt_identity_get(mdt->mdt_identity_cache,
                                            body->fsuid);
                if (!identity) {
                        CERROR("Deny access without identity: uid %d\n",
                               body->fsuid);
                        RETURN(-EACCES);
                }
        }

        uc->mu_valid = UCRED_OLD;
        uc->mu_squash = SQUASH_NONE;
        uc->mu_o_uid = uc->mu_uid = body->uid;
        uc->mu_o_gid = uc->mu_gid = body->gid;
        uc->mu_o_fsuid = uc->mu_fsuid = body->fsuid;
        uc->mu_o_fsgid = uc->mu_fsgid = body->fsgid;
        uc->mu_suppgids[0] = body->suppgid;
        uc->mu_suppgids[1] = -1;
        if (uc->mu_fsuid)
                uc->mu_cap = body->capability & ~CAP_FS_MASK;
        else
                uc->mu_cap = body->capability;
        uc->mu_ginfo = NULL;
        uc->mu_identity = identity;

        RETURN(0);
}

static int old_init_ucred_reint(struct mdt_thread_info *info)
{
        struct md_ucred     *uc  = mdt_ucred(info);
        struct mdt_device   *mdt = info->mti_mdt;
        struct mdt_identity *identity = NULL;

        ENTRY;

        uc->mu_valid = UCRED_INVALID;

        if (!is_identity_get_disabled(mdt->mdt_identity_cache)) {
                /* get identity info of this user */
                identity = mdt_identity_get(mdt->mdt_identity_cache,
                                            uc->mu_fsuid);
                if (!identity) {
                        CERROR("Deny access without identity: uid %d\n",
                               uc->mu_fsuid);
                        RETURN(-EACCES);
                }
        }

        uc->mu_valid = UCRED_OLD;
        uc->mu_squash = SQUASH_NONE;
        uc->mu_o_uid = uc->mu_o_fsuid = uc->mu_uid = uc->mu_fsuid;
        uc->mu_o_gid = uc->mu_o_fsgid = uc->mu_gid = uc->mu_fsgid;
        if (uc->mu_fsuid)
                uc->mu_cap &= ~CAP_FS_MASK;
        uc->mu_ginfo = NULL;
        uc->mu_identity = identity;

        RETURN(0);
}

static int nid_nosquash(struct mdt_device *mdt, lnet_nid_t nid)
{
        struct rootsquash_info *rsi = mdt->mdt_rootsquash_info;
        int i;

        for (i = 0; i < rsi->rsi_n_nosquash_nids; i++)
                if ((rsi->rsi_nosquash_nids[i] == nid) ||
                    (rsi->rsi_nosquash_nids[i] == LNET_NID_ANY))
                        return 1;

        return 0;
}

static int mdt_squash_root(struct mdt_device *mdt, struct md_ucred *ucred,
                           struct ptlrpc_user_desc *pud, lnet_nid_t peernid)
{
        struct rootsquash_info *rsi = mdt->mdt_rootsquash_info;

        if (!rsi || (!rsi->rsi_uid && !rsi->rsi_gid) ||
            nid_nosquash(mdt, peernid))
                return 0;

        CDEBUG(D_SEC, "squash req from "LPX64":"
               "(%u:%u-%u:%u/%x)=>(%u:%u-%u:%u/%x)\n", peernid,
               pud->pud_uid, pud->pud_gid,
               pud->pud_fsuid, pud->pud_fsgid, pud->pud_cap,
               pud->pud_uid ? pud->pud_uid : rsi->rsi_uid,
               pud->pud_uid ? pud->pud_gid : rsi->rsi_gid,
               pud->pud_fsuid ? pud->pud_fsuid : rsi->rsi_uid,
               pud->pud_fsuid ? pud->pud_fsgid : rsi->rsi_gid,
               pud->pud_cap & ~CAP_FS_MASK);

        if (rsi->rsi_uid) {
                if (!pud->pud_uid) {
                        ucred->mu_uid = rsi->rsi_uid;
                        ucred->mu_squash |= SQUASH_UID;
                } else {
                        ucred->mu_uid = pud->pud_uid;
                }

                if (!pud->pud_fsuid) {
                        ucred->mu_fsuid = rsi->rsi_uid;
                        ucred->mu_squash |= SQUASH_UID;
                } else {
                        ucred->mu_fsuid = pud->pud_fsuid;
                }
        } else {
                ucred->mu_uid   = pud->pud_uid;
                ucred->mu_fsuid = pud->pud_fsuid;
        }

        if (rsi->rsi_gid) {
                int i;

                if (!pud->pud_gid) {
                        ucred->mu_gid = rsi->rsi_gid;
                        ucred->mu_squash |= SQUASH_GID;
                } else {
                        ucred->mu_gid = pud->pud_gid;
                }

                if (!pud->pud_fsgid) {
                        ucred->mu_fsgid = rsi->rsi_gid;
                        ucred->mu_squash |= SQUASH_GID;
                } else {
                        ucred->mu_fsgid = pud->pud_fsgid;
                }

                for (i = 0; i < 2; i++) {
                        if (!ucred->mu_suppgids[i]) {
                                ucred->mu_suppgids[i] = rsi->rsi_gid;
                                ucred->mu_squash |= SQUASH_GID;
                        }
                }

                for (i = 0; i < pud->pud_ngroups; i++) {
                        if (!pud->pud_groups[i]) {
                                pud->pud_groups[i] = rsi->rsi_gid;
                                ucred->mu_squash |= SQUASH_GID;
                        }
                }
        } else {
                ucred->mu_gid   = pud->pud_gid;
                ucred->mu_fsgid = pud->pud_fsgid;
        }

        return 1;
}

static int new_init_ucred(struct mdt_thread_info *info, ucred_init_type_t type,
                          void *buf)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct mdt_export_data  *med = mdt_req2med(req);
        struct mdt_device       *mdt = info->mti_mdt;
        struct ptlrpc_user_desc *pud = req->rq_user_desc;
        struct md_ucred         *ucred = mdt_ucred(info);
        struct mdt_identity     *identity = NULL;
        lnet_nid_t              peernid = req->rq_peer.nid;
        __u32                   setxid_perm = 0;
        int                     setuid;
        int                     setgid;
        int                     rc = 0;

        ENTRY;

        ucred->mu_valid = UCRED_INVALID;

        if (req->rq_auth_gss && req->rq_auth_uid == INVALID_UID) {
                CWARN("user not authenticated, deny access!\n");
                RETURN(-EACCES);
        }

        ucred->mu_o_uid   = pud->pud_uid;
        ucred->mu_o_gid   = pud->pud_gid;
        ucred->mu_o_fsuid = pud->pud_fsuid;
        ucred->mu_o_fsgid = pud->pud_fsgid;

        if (type == BODY_INIT) {
                struct mdt_body *body = (struct mdt_body *)buf;

                ucred->mu_suppgids[0] = body->suppgid;
                ucred->mu_suppgids[1] = -1;
        }

        /* sanity check: if we use strong authentication, we expect the
         * uid which client claimed is true */
        if (req->rq_auth_gss) {
                if (med->med_rmtclient) {
                        if (ptlrpc_user_desc_do_idmap(req, pud))
                                RETURN(-EACCES);

                        if (req->rq_auth_mapped_uid != pud->pud_uid) {
                                CERROR("remote client "LPU64": auth uid %u "
                                       "while client claim %u:%u/%u:%u\n",
                                       peernid, req->rq_auth_uid, pud->pud_uid,
                                       pud->pud_gid, pud->pud_fsuid,
                                       pud->pud_fsgid);
                                RETURN(-EACCES);
                        }
                } else {
                        if (req->rq_auth_uid != pud->pud_uid) {
                                CERROR("local client "LPU64": auth uid %u "
                                       "while client claim %u:%u/%u:%u\n",
                                       peernid, req->rq_auth_uid, pud->pud_uid,
                                       pud->pud_gid, pud->pud_fsuid,
                                       pud->pud_fsgid);
                                RETURN(-EACCES);
                        }
                }
        }

        if (is_identity_get_disabled(mdt->mdt_identity_cache)) {
                if (med->med_rmtclient) {
                        CERROR("remote client must run with identity_get "
                               "enabled!\n");
                        RETURN(-EACCES);
                } else {
                        setxid_perm |= LUSTRE_SETGRP_PERM;
                        goto check_squash;
                }
        }

        identity = mdt_identity_get(mdt->mdt_identity_cache, pud->pud_uid);
        if (!identity) {
                CERROR("Deny access without identity: uid %d\n", pud->pud_uid);
                RETURN(-EACCES);
        }

        setxid_perm = mdt_identity_get_setxid_perm(identity,
                                                   med->med_rmtclient,
                                                   peernid);

        /* find out the setuid/setgid attempt */
        setuid = (pud->pud_uid != pud->pud_fsuid);
        setgid = (pud->pud_gid != pud->pud_fsgid ||
                  pud->pud_gid != identity->mi_gid);

        /* check permission of setuid */
        if (setuid && !(setxid_perm & LUSTRE_SETUID_PERM)) {
                CWARN("mdt blocked setuid attempt (%u -> %u) from "
                      LPX64"\n", pud->pud_uid, pud->pud_fsuid, peernid);
                GOTO(out, rc = -EACCES);
        }

        /* check permission of setgid */
        if (setgid && !(setxid_perm & LUSTRE_SETGID_PERM)) {
                CWARN("mdt blocked setgid attempt (%u:%u/%u:%u -> %u) "
                      "from "LPX64"\n", pud->pud_uid, pud->pud_gid,
                      pud->pud_fsuid, pud->pud_fsgid, identity->mi_gid,
                      peernid);
                GOTO(out, rc = -EACCES);
        }

check_squash:
        /* FIXME: The exact behavior of root_squash is not defined. */
        ucred->mu_squash = SQUASH_NONE;
        if (mdt_squash_root(mdt, ucred, pud, peernid) == 0) {
                ucred->mu_uid   = pud->pud_uid;
                ucred->mu_gid   = pud->pud_gid;
                ucred->mu_fsuid = pud->pud_fsuid;
                ucred->mu_fsgid = pud->pud_fsgid;
        }

        /* remove fs privilege for non-root user */
        if (ucred->mu_fsuid)
                ucred->mu_cap = pud->pud_cap & ~CAP_FS_MASK;
        else
                ucred->mu_cap = pud->pud_cap;

        /*
         * NB: remote client not allowed to setgroups anyway.
         */
        if (!med->med_rmtclient && pud->pud_ngroups &&
            (setxid_perm & LUSTRE_SETGRP_PERM)) {
                struct group_info *ginfo;

                /* setgroups for local client */
                ginfo = groups_alloc(pud->pud_ngroups);
                if (!ginfo) {
                        CERROR("failed to alloc %d groups\n",
                               pud->pud_ngroups);
                        GOTO(out, rc = -ENOMEM);
                }
                groups_from_list(ginfo, pud->pud_groups);
                groups_sort(ginfo);
                ucred->mu_ginfo = ginfo;
        } else {
                ucred->mu_ginfo = NULL;
        }

        ucred->mu_identity = identity;
        ucred->mu_valid = UCRED_NEW;

        EXIT;

out:
        if (rc && identity)
                mdt_identity_put(mdt->mdt_identity_cache, identity);

        return rc;
}

int mdt_check_ucred(struct mdt_thread_info *info)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct mdt_export_data  *med = mdt_req2med(req);
        struct mdt_device       *mdt = info->mti_mdt;
        struct ptlrpc_user_desc *pud = req->rq_user_desc;
        struct md_ucred         *ucred = mdt_ucred(info);
        struct mdt_identity     *identity;
        lnet_nid_t              peernid = req->rq_peer.nid;

        ENTRY;

        if ((ucred->mu_valid == UCRED_OLD) || (ucred->mu_valid == UCRED_NEW))
                RETURN(0);

        if (!req->rq_user_desc)
                RETURN(0);

        if (req->rq_auth_gss && req->rq_auth_uid == INVALID_UID) {
                CWARN("user not authenticated, deny access!\n");
                RETURN(-EACCES);
        }

        /* sanity check: if we use strong authentication, we expect the
         * uid which client claimed is true */
        if (req->rq_auth_gss) {
                if (med->med_rmtclient) {
                        if (ptlrpc_user_desc_do_idmap(req, pud))
                                RETURN(-EACCES);

                        if (req->rq_auth_mapped_uid != pud->pud_uid) {
                                CERROR("remote client "LPU64": auth uid %u "
                                       "while client claim %u:%u/%u:%u\n",
                                       peernid, req->rq_auth_uid, pud->pud_uid,
                                       pud->pud_gid, pud->pud_fsuid,
                                       pud->pud_fsgid);
                                RETURN(-EACCES);
                        }
                } else {
                        if (req->rq_auth_uid != pud->pud_uid) {
                                CERROR("local client "LPU64": auth uid %u "
                                       "while client claim %u:%u/%u:%u\n",
                                       peernid, req->rq_auth_uid, pud->pud_uid,
                                       pud->pud_gid, pud->pud_fsuid,
                                       pud->pud_fsgid);
                                RETURN(-EACCES);
                        }
                }
        }

        if (is_identity_get_disabled(mdt->mdt_identity_cache)) {
                if (med->med_rmtclient) {
                        CERROR("remote client must run with "
                               "identity_get enabled!\n");
                        RETURN(-EACCES);
                }
        } else {
                identity = mdt_identity_get(mdt->mdt_identity_cache,
                                            pud->pud_uid);
                if (!identity) {
                        CERROR("Deny access without identity: uid %d\n",
                               pud->pud_uid);
                        RETURN(-EACCES);
                }

                mdt_identity_put(mdt->mdt_identity_cache, identity);
        }

        RETURN(0);
}

int mdt_init_ucred(struct mdt_thread_info *info, struct mdt_body *body)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        struct md_ucred       *uc  = mdt_ucred(info);

        if ((uc->mu_valid == UCRED_OLD) || (uc->mu_valid == UCRED_NEW))
                return 0;

        mdt_exit_ucred(info);

        if (req->rq_auth_usr_mdt || !req->rq_user_desc)
                return old_init_ucred(info, body);
        else
                return new_init_ucred(info, BODY_INIT, body);
}

int mdt_init_ucred_reint(struct mdt_thread_info *info)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        struct md_ucred       *uc  = mdt_ucred(info);

        if ((uc->mu_valid == UCRED_OLD) || (uc->mu_valid == UCRED_NEW))
                return 0;

        mdt_exit_ucred(info);

        if (req->rq_auth_usr_mdt || !req->rq_user_desc)
                return old_init_ucred_reint(info);
        else
                return new_init_ucred(info, REC_INIT, NULL);
}

/* copied from lov/lov_ea.c, just for debugging, will be removed later */
void mdt_dump_lmm(int level, const struct lov_mds_md *lmm)
{
        const struct lov_ost_data_v1 *lod;
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

void mdt_shrink_reply(struct mdt_thread_info *info, int offset,
                      int mdscapa, int osscapa)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        struct mdt_body *body;
        int acl_size, md_size;

        body = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        LASSERT(body != NULL);

        if (body->valid & (OBD_MD_FLDIREA | OBD_MD_FLEASIZE | OBD_MD_LINKNAME))
                md_size = body->eadatasize;
        else
                md_size = 0;

        acl_size = body->aclsize;

        CDEBUG(D_INFO, "Shrink to md_size %d cookie_size %d \n",
               md_size, acl_size);

        lustre_shrink_reply(req, offset, md_size, 1);
        offset += !!md_size;
        lustre_shrink_reply(req, offset, acl_size, 1);
        offset += !!acl_size;
        if (mdscapa && !(body->valid & OBD_MD_FLMDSCAPA))
                lustre_shrink_reply(req, offset, 0, 1);
        offset += mdscapa;
        if (osscapa && !(body->valid & OBD_MD_FLOSSCAPA))
                lustre_shrink_reply(req, offset, 0, 0);
        offset += osscapa;
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
        LASSERT(repbody != NULL);

        if (ma->ma_valid & MA_INODE)
                mdt_pack_attr2body(info, repbody, la, mdt_object_fid(mo));

        if (ma->ma_valid & MA_LOV) {
                __u32 mode;

                if (mdt_object_exists(mo) < 0)
                        /* If it is a remote object, and we do not retrieve
                         * EA back unlink reg file*/
                        mode = S_IFREG;
                else
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
        if (in & ATTR_BLOCKS)
                out |= LA_BLOCKS;

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
        in &= ~(ATTR_MODE|ATTR_UID|ATTR_GID|ATTR_SIZE|ATTR_BLOCKS|
                ATTR_ATIME|ATTR_MTIME|ATTR_CTIME|ATTR_FROM_OPEN|
                ATTR_ATIME_SET|ATTR_CTIME_SET|ATTR_MTIME_SET|
                ATTR_ATTR_FLAG|ATTR_RAW);
        if (in != 0)
                CERROR("Unknown attr bits: %#llx\n", in);
        return out;
}
/* unpacking */

static int mdt_setattr_unpack_rec(struct mdt_thread_info *info)
{
        struct md_ucred         *uc  = mdt_ucred(info);
        struct md_attr          *ma = &info->mti_attr;
        struct lu_attr          *la = &ma->ma_attr;
        struct req_capsule      *pill = &info->mti_pill;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct mdt_rec_setattr  *rec;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_SETATTR);
        if (rec == NULL)
                RETURN(-EFAULT);

        uc->mu_fsuid = rec->sa_fsuid;
        uc->mu_fsgid = rec->sa_fsgid;
        uc->mu_cap   = rec->sa_cap;
        uc->mu_suppgids[0] = rec->sa_suppgid;
        uc->mu_suppgids[1] = -1;

        rr->rr_fid1 = &rec->sa_fid;
        la->la_valid = mdt_attr_valid_xlate(rec->sa_valid, rr, ma);
        la->la_mode  = rec->sa_mode;
        la->la_flags = rec->sa_attr_flags;
        la->la_uid   = rec->sa_uid;
        la->la_gid   = rec->sa_gid;
        la->la_size  = rec->sa_size;
        la->la_blocks = rec->sa_blocks;
        la->la_ctime = rec->sa_ctime;
        la->la_atime = rec->sa_atime;
        la->la_mtime = rec->sa_mtime;
        ma->ma_valid = MA_INODE;

        if (req_capsule_get_size(pill, &RMF_CAPA1, RCL_CLIENT))
                mdt_set_capainfo(info, 0, rr->rr_fid1,
                                 req_capsule_client_get(pill, &RMF_CAPA1));

        RETURN(0);
}

static int mdt_epoch_unpack(struct mdt_thread_info *info)
{
        struct req_capsule *pill = &info->mti_pill;
        ENTRY;

        if (req_capsule_get_size(pill, &RMF_MDT_EPOCH, RCL_CLIENT))
                info->mti_epoch = req_capsule_client_get(pill, &RMF_MDT_EPOCH);
        else
                info->mti_epoch = NULL;
        RETURN(info->mti_epoch == NULL ? -EFAULT : 0);
}

static int mdt_setattr_unpack(struct mdt_thread_info *info)
{
        struct md_attr          *ma = &info->mti_attr;
        struct req_capsule      *pill = &info->mti_pill;
        int rc;
        ENTRY;

        rc = mdt_setattr_unpack_rec(info);
        if (rc)
                RETURN(rc);

        /* Epoch may be absent */
        mdt_epoch_unpack(info);

        if (req_capsule_field_present(pill, &RMF_EADATA, RCL_CLIENT)) {
                ma->ma_lmm = req_capsule_client_get(pill, &RMF_EADATA);
                ma->ma_lmm_size = req_capsule_get_size(pill, &RMF_EADATA,
                                                       RCL_CLIENT);
                ma->ma_valid |= MA_LOV;
        }

        if (req_capsule_field_present(pill, &RMF_LOGCOOKIES, RCL_CLIENT)) {
                ma->ma_cookie = req_capsule_client_get(pill,
                                                       &RMF_LOGCOOKIES);
                ma->ma_cookie_size = req_capsule_get_size(pill,
                                                          &RMF_LOGCOOKIES,
                                                          RCL_CLIENT);
                ma->ma_valid |= MA_COOKIE;
        }

        RETURN(0);
}

int mdt_close_unpack(struct mdt_thread_info *info)
{
        int rc;
        ENTRY;

        rc = mdt_epoch_unpack(info);
        if (rc)
                RETURN(rc);

        RETURN(mdt_setattr_unpack_rec(info));
}

static int mdt_create_unpack(struct mdt_thread_info *info)
{
        struct md_ucred         *uc  = mdt_ucred(info);
        struct mdt_rec_create   *rec;
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule      *pill = &info->mti_pill;
        struct md_op_spec       *sp = &info->mti_spec;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_CREATE);
        if (rec == NULL)
                RETURN(-EFAULT);

        uc->mu_fsuid = rec->cr_fsuid;
        uc->mu_fsgid = rec->cr_fsgid;
        uc->mu_cap   = rec->cr_cap;
        uc->mu_suppgids[0] = rec->cr_suppgid;
        uc->mu_suppgids[1] = -1;

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
        memset(&sp->u, 0, sizeof(sp->u));
        sp->sp_cr_flags = rec->cr_flags;
        sp->sp_ck_split = !!(rec->cr_bias & MDS_CHECK_SPLIT);
        info->mti_cross_ref = !!(rec->cr_bias & MDS_CROSS_REF);

        if (req_capsule_get_size(pill, &RMF_CAPA1, RCL_CLIENT))
                mdt_set_capainfo(info, 0, rr->rr_fid1,
                                 req_capsule_client_get(pill, &RMF_CAPA1));
        mdt_set_capainfo(info, 1, rr->rr_fid2, BYPASS_CAPA);

        rr->rr_name = req_capsule_client_get(pill, &RMF_NAME);
        rr->rr_namelen = req_capsule_get_size(pill, &RMF_NAME, RCL_CLIENT);
        
#ifdef CONFIG_FS_POSIX_ACL
        if (sp->sp_cr_flags & MDS_CREATE_RMT_ACL) {
                if (S_ISDIR(attr->la_mode))
                        sp->u.sp_pfid = rr->rr_fid1;
                req_capsule_extend(pill, &RQF_MDS_REINT_CREATE_RMT_ACL);
                LASSERT(req_capsule_field_present(pill, &RMF_EADATA,
                                                  RCL_CLIENT));
                sp->u.sp_ea.eadata = req_capsule_client_get(pill, &RMF_EADATA);
                sp->u.sp_ea.eadatalen = req_capsule_get_size(pill, &RMF_EADATA,
                                                                RCL_CLIENT);
                RETURN(0);
        }
#endif
        if (S_ISDIR(attr->la_mode)) {
                /* pass parent fid for cross-ref cases */
                sp->u.sp_pfid = rr->rr_fid1;
                if (sp->sp_cr_flags & MDS_CREATE_SLAVE_OBJ) {
                        /* create salve object req, need
                         * unpack split ea here
                         */
                       req_capsule_extend(pill, &RQF_MDS_REINT_CREATE_SLAVE);
                       LASSERT(req_capsule_field_present(pill, &RMF_EADATA,
                                                         RCL_CLIENT));
                       sp->u.sp_ea.eadata = req_capsule_client_get(pill,
                                                                   &RMF_EADATA);
                       sp->u.sp_ea.eadatalen = req_capsule_get_size(pill,
                                                                    &RMF_EADATA,
                                                                    RCL_CLIENT);
                       sp->u.sp_ea.fid = rr->rr_fid1;
                }
        } else if (S_ISLNK(attr->la_mode)) {
                const char *tgt = NULL;

                req_capsule_extend(pill, &RQF_MDS_REINT_CREATE_SYM);
                if (req_capsule_field_present(pill, &RMF_SYMTGT, RCL_CLIENT)) {
                        tgt = req_capsule_client_get(pill, &RMF_SYMTGT);
                        sp->u.sp_symname = tgt;
                }
                if (tgt == NULL)
                        RETURN(-EFAULT);
        }
        RETURN(0);
}

static int mdt_link_unpack(struct mdt_thread_info *info)
{
        struct md_ucred         *uc  = mdt_ucred(info);
        struct mdt_rec_link     *rec;
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule      *pill = &info->mti_pill;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_LINK);
        if (rec == NULL)
                RETURN(-EFAULT);

        uc->mu_fsuid = rec->lk_fsuid;
        uc->mu_fsgid = rec->lk_fsgid;
        uc->mu_cap   = rec->lk_cap;
        uc->mu_suppgids[0] = rec->lk_suppgid1;
        uc->mu_suppgids[1] = rec->lk_suppgid2;

        attr->la_uid = rec->lk_fsuid;
        attr->la_gid = rec->lk_fsgid;
        rr->rr_fid1 = &rec->lk_fid1;
        rr->rr_fid2 = &rec->lk_fid2;
        attr->la_ctime = rec->lk_time;
        attr->la_mtime = rec->lk_time;
        attr->la_valid = LA_UID | LA_GID | LA_CTIME | LA_MTIME;

        if (req_capsule_get_size(pill, &RMF_CAPA1, RCL_CLIENT))
                mdt_set_capainfo(info, 0, rr->rr_fid1,
                                 req_capsule_client_get(pill, &RMF_CAPA1));
        if (req_capsule_get_size(pill, &RMF_CAPA2, RCL_CLIENT))
                mdt_set_capainfo(info, 1, rr->rr_fid2,
                                 req_capsule_client_get(pill, &RMF_CAPA2));

        rr->rr_name = req_capsule_client_get(pill, &RMF_NAME);
        if (rr->rr_name == NULL)
                RETURN(-EFAULT);
        rr->rr_namelen = req_capsule_get_size(pill, &RMF_NAME, RCL_CLIENT);
        info->mti_spec.sp_ck_split = !!(rec->lk_bias & MDS_CHECK_SPLIT);
        info->mti_cross_ref = !!(rec->lk_bias & MDS_CROSS_REF);

        RETURN(0);
}

static int mdt_unlink_unpack(struct mdt_thread_info *info)
{
        struct md_ucred         *uc  = mdt_ucred(info);
        struct mdt_rec_unlink   *rec;
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule      *pill = &info->mti_pill;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_UNLINK);
        if (rec == NULL)
                RETURN(-EFAULT);

        uc->mu_fsuid = rec->ul_fsuid;
        uc->mu_fsgid = rec->ul_fsgid;
        uc->mu_cap   = rec->ul_cap;
        uc->mu_suppgids[0] = rec->ul_suppgid;
        uc->mu_suppgids[1] = -1;

        attr->la_uid = rec->ul_fsuid;
        attr->la_gid = rec->ul_fsgid;
        rr->rr_fid1 = &rec->ul_fid1;
        rr->rr_fid2 = &rec->ul_fid2;
        attr->la_ctime = rec->ul_time;
        attr->la_mtime = rec->ul_time;
        attr->la_mode  = rec->ul_mode;
        attr->la_valid = LA_UID | LA_GID | LA_CTIME | LA_MTIME | LA_MODE;

        if (req_capsule_get_size(pill, &RMF_CAPA1, RCL_CLIENT))
                mdt_set_capainfo(info, 0, rr->rr_fid1,
                                 req_capsule_client_get(pill, &RMF_CAPA1));

        rr->rr_name = req_capsule_client_get(pill, &RMF_NAME);
        if (rr->rr_name == NULL)
                RETURN(-EFAULT);
        rr->rr_namelen = req_capsule_get_size(pill, &RMF_NAME, RCL_CLIENT);
        info->mti_spec.sp_ck_split = !!(rec->ul_bias & MDS_CHECK_SPLIT);
        info->mti_cross_ref = !!(rec->ul_bias & MDS_CROSS_REF);

        RETURN(0);
}

static int mdt_rename_unpack(struct mdt_thread_info *info)
{
        struct md_ucred         *uc = mdt_ucred(info);
        struct mdt_rec_rename   *rec;
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule      *pill = &info->mti_pill;
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_RENAME);
        if (rec == NULL)
                RETURN(-EFAULT);

        uc->mu_fsuid = rec->rn_fsuid;
        uc->mu_fsgid = rec->rn_fsgid;
        uc->mu_cap   = rec->rn_cap;
        uc->mu_suppgids[0] = rec->rn_suppgid1;
        uc->mu_suppgids[1] = rec->rn_suppgid2;

        attr->la_uid = rec->rn_fsuid;
        attr->la_gid = rec->rn_fsgid;
        rr->rr_fid1 = &rec->rn_fid1;
        rr->rr_fid2 = &rec->rn_fid2;
        attr->la_ctime = rec->rn_time;
        attr->la_mtime = rec->rn_time;
        /* rename_tgt contains the mode already */
        attr->la_mode = rec->rn_mode;
        attr->la_valid = LA_UID | LA_GID | LA_CTIME | LA_MTIME | LA_MODE;

        if (req_capsule_get_size(pill, &RMF_CAPA1, RCL_CLIENT))
                mdt_set_capainfo(info, 0, rr->rr_fid1,
                                 req_capsule_client_get(pill, &RMF_CAPA1));
        if (req_capsule_get_size(pill, &RMF_CAPA2, RCL_CLIENT))
                mdt_set_capainfo(info, 1, rr->rr_fid2,
                                 req_capsule_client_get(pill, &RMF_CAPA2));

        rr->rr_name = req_capsule_client_get(pill, &RMF_NAME);
        rr->rr_tgt = req_capsule_client_get(pill, &RMF_SYMTGT);
        if (rr->rr_name == NULL || rr->rr_tgt == NULL)
                RETURN(-EFAULT);
        rr->rr_namelen = req_capsule_get_size(pill, &RMF_NAME, RCL_CLIENT);
        rr->rr_tgtlen = req_capsule_get_size(pill, &RMF_SYMTGT, RCL_CLIENT);
        info->mti_spec.sp_ck_split = !!(rec->rn_bias & MDS_CHECK_SPLIT);
        info->mti_cross_ref = !!(rec->rn_bias & MDS_CROSS_REF);

        RETURN(0);
}

static int mdt_open_unpack(struct mdt_thread_info *info)
{
        struct md_ucred         *uc = mdt_ucred(info);
        struct mdt_rec_create   *rec;
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct req_capsule      *pill = &info->mti_pill;
        struct mdt_reint_record *rr   = &info->mti_rr;
        struct ptlrpc_request   *req  = mdt_info_req(info);
        ENTRY;

        rec = req_capsule_client_get(pill, &RMF_REC_CREATE);
        if (rec == NULL)
                RETURN(-EFAULT);

        uc->mu_fsuid = rec->cr_fsuid;
        uc->mu_fsgid = rec->cr_fsgid;
        uc->mu_cap   = rec->cr_cap;
        uc->mu_suppgids[0] = rec->cr_suppgid;
        uc->mu_suppgids[1] = -1;

        rr->rr_fid1   = &rec->cr_fid1;
        rr->rr_fid2   = &rec->cr_fid2;
        attr->la_mode = rec->cr_mode;
        attr->la_rdev  = rec->cr_rdev;
        attr->la_uid   = rec->cr_fsuid;
        attr->la_gid   = rec->cr_fsgid;
        attr->la_ctime = rec->cr_time;
        attr->la_mtime = rec->cr_time;
        attr->la_atime = rec->cr_time;
        attr->la_valid = LA_MODE  | LA_RDEV  | LA_UID   | LA_GID |
                         LA_CTIME | LA_MTIME | LA_ATIME;
        memset(&info->mti_spec.u, 0, sizeof(info->mti_spec.u));
        info->mti_spec.sp_cr_flags = rec->cr_flags;
        info->mti_replayepoch = rec->cr_ioepoch;

        info->mti_spec.sp_ck_split = !!(rec->cr_bias & MDS_CHECK_SPLIT);
        info->mti_cross_ref = !!(rec->cr_bias & MDS_CROSS_REF);

        if (req_capsule_get_size(pill, &RMF_CAPA1, RCL_CLIENT))
                mdt_set_capainfo(info, 0, rr->rr_fid1,
                                 req_capsule_client_get(pill, &RMF_CAPA1));
        if ((lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) &&
            (req_capsule_get_size(pill, &RMF_CAPA2, RCL_CLIENT)))
                mdt_set_capainfo(info, 1, rr->rr_fid2,
                                 req_capsule_client_get(pill, &RMF_CAPA2));

        rr->rr_name = req_capsule_client_get(pill, &RMF_NAME);
        if (rr->rr_name == NULL)
                RETURN(-EFAULT);
        rr->rr_namelen = req_capsule_get_size(pill, &RMF_NAME, RCL_CLIENT);

        if (req_capsule_field_present(pill, &RMF_EADATA, RCL_CLIENT)) {
                struct md_op_spec *sp = &info->mti_spec;
                sp->u.sp_ea.eadata = req_capsule_client_get(pill,
                                                            &RMF_EADATA);
                sp->u.sp_ea.eadatalen = req_capsule_get_size(pill,
                                                             &RMF_EADATA,
                                                             RCL_CLIENT);
                if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY)
                        sp->u.sp_ea.no_lov_create = 1;
        }

        RETURN(0);
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

        memset(&info->mti_rr, 0, sizeof(info->mti_rr));
        if (op < REINT_MAX && mdt_reint_unpackers[op] != NULL) {
                info->mti_rr.rr_opcode = op;
                rc = mdt_reint_unpackers[op](info);
        } else {
                CERROR("Unexpected opcode %d\n", op);
                rc = -EFAULT;
        }
        RETURN(rc);
}
