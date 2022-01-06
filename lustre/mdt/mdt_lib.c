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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/mdt/mdt_lib.c
 *
 * Lustre Metadata Target (mdt) request unpacking helper.
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Mike Shaver <shaver@clusterfs.com>
 * Author: Nikita Danilov <nikita@clusterfs.com>
 * Author: Huang Hua <huanghua@clusterfs.com>
 * Author: Fan Yong <fanyong@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/user_namespace.h>
#include <linux/uidgid.h>

#include "mdt_internal.h"
#include <uapi/linux/lnet/nidstr.h>
#include <lustre_nodemap.h>

typedef enum ucred_init_type {
        NONE_INIT       = 0,
        BODY_INIT       = 1,
        REC_INIT        = 2
} ucred_init_type_t;

static __u64 get_mrc_cr_flags(struct mdt_rec_create *mrc)
{
	return (__u64)(mrc->cr_flags_l) | ((__u64)mrc->cr_flags_h << 32);
}

void mdt_exit_ucred(struct mdt_thread_info *info)
{
	struct lu_ucred   *uc  = mdt_ucred(info);
	struct mdt_device *mdt = info->mti_mdt;

	LASSERT(uc != NULL);
	if (uc->uc_valid != UCRED_INIT) {
		uc->uc_suppgids[0] = uc->uc_suppgids[1] = -1;
		if (uc->uc_ginfo) {
			put_group_info(uc->uc_ginfo);
			uc->uc_ginfo = NULL;
		}
		if (uc->uc_identity) {
			mdt_identity_put(mdt->mdt_identity_cache,
					 uc->uc_identity);
			uc->uc_identity = NULL;
		}
		uc->uc_valid = UCRED_INIT;
	}
}

static int match_nosquash_list(struct spinlock *rsi_lock,
			       struct list_head *nidlist,
			       lnet_nid_t peernid)
{
	int rc;
	ENTRY;
	spin_lock(rsi_lock);
	rc = cfs_match_nid(peernid, nidlist);
	spin_unlock(rsi_lock);
	RETURN(rc);
}

/* root_squash for inter-MDS operations */
static int mdt_root_squash(struct mdt_thread_info *info, lnet_nid_t peernid)
{
	struct lu_ucred *ucred = mdt_ucred(info);
	struct root_squash_info *squash = &info->mti_mdt->mdt_squash;
	ENTRY;

	LASSERT(ucred != NULL);
	if (!squash->rsi_uid || ucred->uc_fsuid)
		RETURN(0);

	if (match_nosquash_list(&squash->rsi_lock,
				&squash->rsi_nosquash_nids,
				peernid)) {
		CDEBUG(D_OTHER, "%s is in nosquash_nids list\n",
		       libcfs_nid2str(peernid));
		RETURN(0);
	}

	CDEBUG(D_OTHER, "squash req from %s, (%d:%d/%x)=>(%d:%d/%x)\n",
	       libcfs_nid2str(peernid),
	       ucred->uc_fsuid, ucred->uc_fsgid, ucred->uc_cap.cap[0],
	       squash->rsi_uid, squash->rsi_gid, 0);

	ucred->uc_fsuid = squash->rsi_uid;
	ucred->uc_fsgid = squash->rsi_gid;
	ucred->uc_cap = CAP_EMPTY_SET;
	ucred->uc_suppgids[0] = -1;
	ucred->uc_suppgids[1] = -1;

	RETURN(0);
}

static void ucred_set_jobid(struct mdt_thread_info *info, struct lu_ucred *uc)
{
	struct ptlrpc_request	*req = mdt_info_req(info);
	const char		*jobid = mdt_req_get_jobid(req);

	/* set jobid if specified. */
	if (jobid)
		strlcpy(uc->uc_jobid, jobid, sizeof(uc->uc_jobid));
	else
		uc->uc_jobid[0] = '\0';
}

static void ucred_set_nid(struct mdt_thread_info *info, struct lu_ucred *uc)
{
	if (info && info->mti_exp && info->mti_exp->exp_connection)
		uc->uc_nid = lnet_nid_to_nid4(
			&info->mti_exp->exp_connection->c_peer.nid);
	else
		uc->uc_nid = LNET_NID_ANY;
}

static void ucred_set_audit_enabled(struct mdt_thread_info *info,
				    struct lu_ucred *uc)
{
	struct lu_nodemap *nodemap = NULL;
	bool audit = true;

	if (info && info->mti_exp) {
		nodemap = nodemap_get_from_exp(info->mti_exp);
		if (nodemap && !IS_ERR(nodemap)) {
			audit = nodemap->nmf_enable_audit;
			nodemap_putref(nodemap);
		}
	}

	uc->uc_enable_audit = audit;
}

static int new_init_ucred(struct mdt_thread_info *info, ucred_init_type_t type,
			  void *buf)
{
	struct ptlrpc_request *req = mdt_info_req(info);
	struct mdt_device *mdt = info->mti_mdt;
	struct ptlrpc_user_desc *pud = req->rq_user_desc;
	struct lu_ucred *ucred = mdt_ucred(info);
	struct lu_nodemap *nodemap;
	lnet_nid_t peernid = req->rq_peer.nid;
	__u32 perm = 0;
	int setuid;
	int setgid;
	bool is_nm_gid_squashed = false;
	int rc = 0;

	ENTRY;

	LASSERT(req->rq_auth_gss);
	LASSERT(!req->rq_auth_usr_mdt);
	LASSERT(req->rq_user_desc);
	LASSERT(ucred != NULL);

	ucred->uc_valid = UCRED_INVALID;

	nodemap = nodemap_get_from_exp(info->mti_exp);
	if (IS_ERR(nodemap))
		RETURN(PTR_ERR(nodemap));

	pud->pud_uid = nodemap_map_id(nodemap, NODEMAP_UID,
				       NODEMAP_CLIENT_TO_FS, pud->pud_uid);
	pud->pud_gid = nodemap_map_id(nodemap, NODEMAP_GID,
				       NODEMAP_CLIENT_TO_FS, pud->pud_gid);
	pud->pud_fsuid = nodemap_map_id(nodemap, NODEMAP_UID,
				       NODEMAP_CLIENT_TO_FS, pud->pud_fsuid);
	pud->pud_fsgid = nodemap_map_id(nodemap, NODEMAP_GID,
				       NODEMAP_CLIENT_TO_FS, pud->pud_fsgid);

	ucred->uc_o_uid = pud->pud_uid;
	ucred->uc_o_gid = pud->pud_gid;
	ucred->uc_o_fsuid = pud->pud_fsuid;
	ucred->uc_o_fsgid = pud->pud_fsgid;

	if (nodemap && ucred->uc_o_uid == nodemap->nm_squash_uid) {
		/* deny access before we get identity ref */
		if (nodemap->nmf_deny_unknown) {
			nodemap_putref(nodemap);
			RETURN(-EACCES);
		}

		ucred->uc_suppgids[0] = -1;
		ucred->uc_suppgids[1] = -1;
	}

	if (nodemap && ucred->uc_o_gid == nodemap->nm_squash_gid)
		is_nm_gid_squashed = true;

	nodemap_putref(nodemap);

	if (type == BODY_INIT) {
		struct mdt_body *body = (struct mdt_body *)buf;

		ucred->uc_suppgids[0] = body->mbo_suppgid;
		ucred->uc_suppgids[1] = -1;
	}

	if (!flvr_is_rootonly(req->rq_flvr.sf_rpc) &&
	    req->rq_auth_uid != pud->pud_uid) {
		CDEBUG(D_SEC, "local client %s: auth uid %u "
		       "while client claims %u:%u/%u:%u\n",
		       libcfs_nid2str(peernid), req->rq_auth_uid,
		       pud->pud_uid, pud->pud_gid,
		       pud->pud_fsuid, pud->pud_fsgid);
		RETURN(-EACCES);
	}

	if (is_identity_get_disabled(mdt->mdt_identity_cache)) {
		ucred->uc_identity = NULL;
		perm = CFS_SETUID_PERM | CFS_SETGID_PERM | CFS_SETGRP_PERM;
	} else {
		struct md_identity *identity;

		identity = mdt_identity_get(mdt->mdt_identity_cache,
					    pud->pud_uid);
		if (IS_ERR(identity)) {
			if (unlikely(PTR_ERR(identity) == -EREMCHG)) {
				ucred->uc_identity = NULL;
				perm = CFS_SETUID_PERM | CFS_SETGID_PERM |
				       CFS_SETGRP_PERM;
			} else {
				CDEBUG(D_SEC,
				       "Deny access without identity: uid %u\n",
				       pud->pud_uid);
				RETURN(-EACCES);
			}
		} else {
			ucred->uc_identity = identity;
			perm = mdt_identity_get_perm(ucred->uc_identity,
						     peernid);
		}
	}

	/* find out the setuid/setgid attempt */
	setuid = (pud->pud_uid != pud->pud_fsuid);
	setgid = ((pud->pud_gid != pud->pud_fsgid) ||
		  (ucred->uc_identity &&
		   (pud->pud_gid != ucred->uc_identity->mi_gid)));

	/* check permission of setuid */
	if (setuid && !(perm & CFS_SETUID_PERM)) {
		CDEBUG(D_SEC, "mdt blocked setuid attempt (%u -> %u) from %s\n",
		       pud->pud_uid, pud->pud_fsuid, libcfs_nid2str(peernid));
		GOTO(out, rc = -EACCES);
	}

	/* check permission of setgid */
	if (setgid && !(perm & CFS_SETGID_PERM)) {
		CDEBUG(D_SEC, "mdt blocked setgid attempt (%u:%u/%u:%u -> %u) "
		       "from %s\n", pud->pud_uid, pud->pud_gid,
		       pud->pud_fsuid, pud->pud_fsgid,
		       ucred->uc_identity->mi_gid, libcfs_nid2str(peernid));
		GOTO(out, rc = -EACCES);
	}

	if (perm & CFS_SETGRP_PERM) {
		/* only set groups if GID is not squashed */
		if (pud->pud_ngroups && !is_nm_gid_squashed) {
			/* setgroups for local client */
			ucred->uc_ginfo = groups_alloc(pud->pud_ngroups);
			if (!ucred->uc_ginfo) {
				CERROR("failed to alloc %d groups\n",
				       pud->pud_ngroups);
				GOTO(out, rc = -ENOMEM);
			}

			lustre_groups_from_list(ucred->uc_ginfo,
						pud->pud_groups);
			lustre_groups_sort(ucred->uc_ginfo);
		} else {
			ucred->uc_suppgids[0] = -1;
			ucred->uc_suppgids[1] = -1;
			ucred->uc_ginfo = NULL;
		}
	} else {
		ucred->uc_suppgids[0] = -1;
		ucred->uc_suppgids[1] = -1;
		ucred->uc_ginfo = NULL;
	}

	ucred->uc_uid = pud->pud_uid;
	ucred->uc_gid = pud->pud_gid;

	ucred->uc_cap = CAP_EMPTY_SET;
	if (!nodemap || ucred->uc_o_uid != nodemap->nm_squash_uid)
		ucred->uc_cap.cap[0] = pud->pud_cap;

	ucred->uc_fsuid = pud->pud_fsuid;
	ucred->uc_fsgid = pud->pud_fsgid;

	/* process root_squash here. */
	mdt_root_squash(info, peernid);

	ucred->uc_valid = UCRED_NEW;
	ucred_set_jobid(info, ucred);
	ucred_set_nid(info, ucred);
	ucred_set_audit_enabled(info, ucred);

	EXIT;

out:
	if (rc) {
		if (ucred->uc_ginfo) {
			put_group_info(ucred->uc_ginfo);
			ucred->uc_ginfo = NULL;
		}
		if (ucred->uc_identity) {
			mdt_identity_put(mdt->mdt_identity_cache,
					 ucred->uc_identity);
			ucred->uc_identity = NULL;
		}
	}

	return rc;
}

/**
 * Check whether allow the client to set supplementary group IDs or not.
 *
 * \param[in] info	pointer to the thread context
 * \param[in] uc	pointer to the RPC user descriptor
 *
 * \retval		true if allow to set supplementary group IDs
 * \retval		false for other cases
 */
bool allow_client_chgrp(struct mdt_thread_info *info, struct lu_ucred *uc)
{
	__u32 perm;

	/* 1. If identity_upcall is disabled,
	 *    permit local client to do anything. */
	if (is_identity_get_disabled(info->mti_mdt->mdt_identity_cache))
		return true;

	/* 2. If fail to get related identities, then forbid any client to
	 *    set supplementary group IDs. */
	if (uc->uc_identity == NULL)
		return false;

	/* 3. Check the permission in the identities. */
	perm = mdt_identity_get_perm(uc->uc_identity,
				     mdt_info_req(info)->rq_peer.nid);
	if (perm & CFS_SETGRP_PERM)
		return true;

	return false;
}

int mdt_check_ucred(struct mdt_thread_info *info)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct mdt_device       *mdt = info->mti_mdt;
        struct ptlrpc_user_desc *pud = req->rq_user_desc;
	struct lu_ucred         *ucred = mdt_ucred(info);
        struct md_identity      *identity = NULL;
        lnet_nid_t               peernid = req->rq_peer.nid;
        __u32                    perm = 0;
        int                      setuid;
        int                      setgid;
        int                      rc = 0;

        ENTRY;

	LASSERT(ucred != NULL);
	if ((ucred->uc_valid == UCRED_OLD) || (ucred->uc_valid == UCRED_NEW))
		RETURN(0);

	if (!req->rq_auth_gss || req->rq_auth_usr_mdt || !req->rq_user_desc)
		RETURN(0);

	/* sanity check: if we use strong authentication, we expect the
	 * uid which client claimed is true */
	if (!flvr_is_rootonly(req->rq_flvr.sf_rpc) &&
	    req->rq_auth_uid != pud->pud_uid) {
		CDEBUG(D_SEC, "local client %s: auth uid %u "
		       "while client claims %u:%u/%u:%u\n",
		       libcfs_nid2str(peernid), req->rq_auth_uid,
		       pud->pud_uid, pud->pud_gid,
		       pud->pud_fsuid, pud->pud_fsgid);
		RETURN(-EACCES);
	}

	if (is_identity_get_disabled(mdt->mdt_identity_cache))
		RETURN(0);

	identity = mdt_identity_get(mdt->mdt_identity_cache, pud->pud_uid);
	if (IS_ERR(identity)) {
		if (unlikely(PTR_ERR(identity) == -EREMCHG)) {
			RETURN(0);
		} else {
			CDEBUG(D_SEC, "Deny access without identity: uid %u\n",
			       pud->pud_uid);
			RETURN(-EACCES);
		}
	}

	perm = mdt_identity_get_perm(identity, peernid);
        /* find out the setuid/setgid attempt */
        setuid = (pud->pud_uid != pud->pud_fsuid);
        setgid = (pud->pud_gid != pud->pud_fsgid ||
                  pud->pud_gid != identity->mi_gid);

        /* check permission of setuid */
        if (setuid && !(perm & CFS_SETUID_PERM)) {
                CDEBUG(D_SEC, "mdt blocked setuid attempt (%u -> %u) from %s\n",
                       pud->pud_uid, pud->pud_fsuid, libcfs_nid2str(peernid));
                GOTO(out, rc = -EACCES);
        }

        /* check permission of setgid */
        if (setgid && !(perm & CFS_SETGID_PERM)) {
                CDEBUG(D_SEC, "mdt blocked setgid attempt (%u:%u/%u:%u -> %u) "
                       "from %s\n", pud->pud_uid, pud->pud_gid,
                       pud->pud_fsuid, pud->pud_fsgid, identity->mi_gid,
                       libcfs_nid2str(peernid));
                GOTO(out, rc = -EACCES);
        }

        EXIT;

out:
        mdt_identity_put(mdt->mdt_identity_cache, identity);
        return rc;
}

static int old_init_ucred_common(struct mdt_thread_info *info,
				 struct lu_nodemap *nodemap)
{
	struct lu_ucred		*uc = mdt_ucred(info);
	struct mdt_device	*mdt = info->mti_mdt;
	struct md_identity	*identity = NULL;

	if (nodemap && uc->uc_o_uid == nodemap->nm_squash_uid) {
		/* deny access before we get identity ref */
		if (nodemap->nmf_deny_unknown)
			RETURN(-EACCES);

		uc->uc_cap = CAP_EMPTY_SET;
		uc->uc_suppgids[0] = -1;
		uc->uc_suppgids[1] = -1;
	}

	if (!is_identity_get_disabled(mdt->mdt_identity_cache)) {
		identity = mdt_identity_get(mdt->mdt_identity_cache,
					    uc->uc_fsuid);
		if (IS_ERR(identity)) {
			if (unlikely(PTR_ERR(identity) == -EREMCHG ||
				     cap_raised(uc->uc_cap,
						CAP_DAC_READ_SEARCH))) {
				identity = NULL;
			} else {
				CDEBUG(D_SEC, "Deny access without identity: "
				       "uid %u\n", uc->uc_fsuid);
				RETURN(-EACCES);
			}
		}
	}
	uc->uc_identity = identity;

	/* process root_squash here. */
	mdt_root_squash(info, mdt_info_req(info)->rq_peer.nid);

	uc->uc_valid = UCRED_OLD;
	ucred_set_jobid(info, uc);
	ucred_set_nid(info, uc);
	ucred_set_audit_enabled(info, uc);

	EXIT;

	return 0;
}

static int old_init_ucred(struct mdt_thread_info *info,
			  struct mdt_body *body)
{
	struct lu_ucred *uc = mdt_ucred(info);
	struct lu_nodemap *nodemap;
	int rc;
	ENTRY;

	nodemap = nodemap_get_from_exp(info->mti_exp);
	if (IS_ERR(nodemap))
		RETURN(PTR_ERR(nodemap));

	body->mbo_uid = nodemap_map_id(nodemap, NODEMAP_UID,
				       NODEMAP_CLIENT_TO_FS, body->mbo_uid);
	body->mbo_gid = nodemap_map_id(nodemap, NODEMAP_GID,
				       NODEMAP_CLIENT_TO_FS, body->mbo_gid);
	body->mbo_fsuid = nodemap_map_id(nodemap, NODEMAP_UID,
				       NODEMAP_CLIENT_TO_FS, body->mbo_fsuid);
	body->mbo_fsgid = nodemap_map_id(nodemap, NODEMAP_GID,
				       NODEMAP_CLIENT_TO_FS, body->mbo_fsgid);

	LASSERT(uc != NULL);
	uc->uc_valid = UCRED_INVALID;
	uc->uc_o_uid = uc->uc_uid = body->mbo_uid;
	uc->uc_o_gid = uc->uc_gid = body->mbo_gid;
	uc->uc_o_fsuid = uc->uc_fsuid = body->mbo_fsuid;
	uc->uc_o_fsgid = uc->uc_fsgid = body->mbo_fsgid;
	uc->uc_suppgids[0] = body->mbo_suppgid;
	uc->uc_suppgids[1] = -1;
	uc->uc_ginfo = NULL;
	uc->uc_cap = CAP_EMPTY_SET;
	uc->uc_cap.cap[0] = body->mbo_capability;

	rc = old_init_ucred_common(info, nodemap);
	nodemap_putref(nodemap);

	RETURN(rc);
}

static int old_init_ucred_reint(struct mdt_thread_info *info)
{
	struct lu_ucred *uc = mdt_ucred(info);
	struct lu_nodemap *nodemap;
	int rc;
	ENTRY;

	nodemap = nodemap_get_from_exp(info->mti_exp);
	if (IS_ERR(nodemap))
		RETURN(PTR_ERR(nodemap));

	LASSERT(uc != NULL);

	uc->uc_fsuid = nodemap_map_id(nodemap, NODEMAP_UID,
				      NODEMAP_CLIENT_TO_FS, uc->uc_fsuid);
	uc->uc_fsgid = nodemap_map_id(nodemap, NODEMAP_GID,
				      NODEMAP_CLIENT_TO_FS, uc->uc_fsgid);

	uc->uc_valid = UCRED_INVALID;
	uc->uc_o_uid = uc->uc_o_fsuid = uc->uc_uid = uc->uc_fsuid;
	uc->uc_o_gid = uc->uc_o_fsgid = uc->uc_gid = uc->uc_fsgid;
	uc->uc_ginfo = NULL;

	rc = old_init_ucred_common(info, nodemap);
	nodemap_putref(nodemap);

	RETURN(rc);
}

static inline int __mdt_init_ucred(struct mdt_thread_info *info,
				   struct mdt_body *body)
{
	struct ptlrpc_request	*req = mdt_info_req(info);
	struct lu_ucred		*uc  = mdt_ucred(info);

	LASSERT(uc != NULL);
	if ((uc->uc_valid == UCRED_OLD) || (uc->uc_valid == UCRED_NEW))
		return 0;

	mdt_exit_ucred(info);

	if (!req->rq_auth_gss || req->rq_auth_usr_mdt || !req->rq_user_desc)
		return old_init_ucred(info, body);
	else
		return new_init_ucred(info, BODY_INIT, body);
}

int mdt_init_ucred(struct mdt_thread_info *info, struct mdt_body *body)
{
	return __mdt_init_ucred(info, body);
}

int mdt_init_ucred_reint(struct mdt_thread_info *info)
{
	struct ptlrpc_request *req = mdt_info_req(info);
	struct lu_ucred       *uc  = mdt_ucred(info);
	struct md_attr        *ma  = &info->mti_attr;

	LASSERT(uc != NULL);
	if ((uc->uc_valid == UCRED_OLD) || (uc->uc_valid == UCRED_NEW))
		return 0;

	/* LU-5564: for normal close request, skip permission check */
	if (lustre_msg_get_opc(req->rq_reqmsg) == MDS_CLOSE &&
	    !(ma->ma_attr_flags & (MDS_HSM_RELEASE | MDS_CLOSE_LAYOUT_SWAP))) {
		cap_raise_nfsd_set(uc->uc_cap, CAP_FULL_SET);
		cap_raise_fs_set(uc->uc_cap, CAP_FULL_SET);
	}

	mdt_exit_ucred(info);

	if (!req->rq_auth_gss || req->rq_auth_usr_mdt || !req->rq_user_desc)
		return old_init_ucred_reint(info);
	else
		return new_init_ucred(info, REC_INIT, NULL);
}

/* copied from lov/lov_ea.c, just for debugging, will be removed later */
void mdt_dump_lmm(int level, const struct lov_mds_md *lmm, __u64 valid)
{
	const struct lov_ost_data_v1 *lod;
	__u32 lmm_magic = le32_to_cpu(lmm->lmm_magic);
	__u16 count;
	int i;

	if (likely(!cfs_cdebug_show(level, DEBUG_SUBSYSTEM)))
		return;

	CDEBUG(level, "objid "DOSTID", magic 0x%08X, pattern %#X\n",
	       POSTID(&lmm->lmm_oi), lmm_magic,
	       le32_to_cpu(lmm->lmm_pattern));

	/* No support for compount layouts yet */
	if (lmm_magic != LOV_MAGIC_V1 && lmm_magic != LOV_MAGIC_V3)
		return;

	count = le16_to_cpu(((struct lov_user_md *)lmm)->lmm_stripe_count);
	CDEBUG(level, "stripe_size=0x%x, stripe_count=0x%x\n",
	       le32_to_cpu(lmm->lmm_stripe_size), count);

	/* If it's a directory or a released file, then there are
	 * no actual objects to print, so bail out. */
	if (valid & OBD_MD_FLDIREA ||
	    le32_to_cpu(lmm->lmm_pattern) & LOV_PATTERN_F_RELEASED)
		return;

	LASSERT(count <= LOV_MAX_STRIPE_COUNT);
	for (i = 0, lod = lmm->lmm_objects; i < count; i++, lod++) {
		struct ost_id oi;

		ostid_le_to_cpu(&lod->l_ost_oi, &oi);
		CDEBUG(level, "stripe %u idx %u subobj "DOSTID"\n",
		       i, le32_to_cpu(lod->l_ost_idx), POSTID(&oi));
	}
}

void mdt_dump_lmv(unsigned int level, const union lmv_mds_md *lmv)
{
	const struct lmv_mds_md_v1 *lmm1;
	const struct lmv_foreign_md *lfm;
	int			   i;

	if (likely(!cfs_cdebug_show(level, DEBUG_SUBSYSTEM)))
		return;

	/* foreign LMV case */
	lfm = &lmv->lmv_foreign_md;
	if (le32_to_cpu(lfm->lfm_magic) == LMV_MAGIC_FOREIGN) {
		CDEBUG_LIMIT(level,
			     "foreign magic 0x%08X, length %u, type %u, flags %u, value '%.*s'\n",
			     le32_to_cpu(lfm->lfm_magic),
			     le32_to_cpu(lfm->lfm_length),
			     le32_to_cpu(lfm->lfm_type),
			     le32_to_cpu(lfm->lfm_flags),
			     le32_to_cpu(lfm->lfm_length), lfm->lfm_value);
		return;
	}

	lmm1 = &lmv->lmv_md_v1;
	CDEBUG(level,
	       "magic 0x%08X, master %#X stripe_count %d hash_type %#x\n",
	       le32_to_cpu(lmm1->lmv_magic),
	       le32_to_cpu(lmm1->lmv_master_mdt_index),
	       le32_to_cpu(lmm1->lmv_stripe_count),
	       le32_to_cpu(lmm1->lmv_hash_type));

	if (le32_to_cpu(lmm1->lmv_magic) == LMV_MAGIC_STRIPE)
		return;

	if (le32_to_cpu(lmm1->lmv_stripe_count) > LMV_MAX_STRIPE_COUNT)
		return;

	for (i = 0; i < le32_to_cpu(lmm1->lmv_stripe_count); i++) {
		struct lu_fid fid;

		fid_le_to_cpu(&fid, &lmm1->lmv_stripe_fids[i]);
		CDEBUG(level, "idx %u subobj "DFID"\n", i, PFID(&fid));
	}
}

/* Shrink and/or grow reply buffers */
int mdt_fix_reply(struct mdt_thread_info *info)
{
        struct req_capsule *pill = info->mti_pill;
        struct mdt_body    *body;
        int                md_size, md_packed = 0;
        int                acl_size;
        int                rc = 0;
        ENTRY;

        body = req_capsule_server_get(pill, &RMF_MDT_BODY);
        LASSERT(body != NULL);

	if (body->mbo_valid & (OBD_MD_FLDIREA | OBD_MD_FLEASIZE |
			       OBD_MD_LINKNAME))
		md_size = body->mbo_eadatasize;
	else
		md_size = 0;

	acl_size = body->mbo_aclsize;

	/* this replay - not send info to client */
	if (info->mti_spec.no_create) {
		md_size = 0;
		acl_size = 0;
	}

	CDEBUG(D_INFO, "Shrink to md_size = %d cookie/acl_size = %d\n",
	       md_size, acl_size);
/*
            &RMF_MDT_BODY,
            &RMF_MDT_MD,
            &RMF_ACL, or &RMF_LOGCOOKIES
(optional)  &RMF_CAPA1,
(optional)  &RMF_CAPA2,
(optional)  something else
*/

        /* MDT_MD buffer may be bigger than packed value, let's shrink all
         * buffers before growing it */
	if (info->mti_big_lmm_used) {
		/* big_lmm buffer may be used even without packing the result
		 * into reply, just for internal server needs */
		if (req_capsule_has_field(pill, &RMF_MDT_MD, RCL_SERVER))
			md_packed = req_capsule_get_size(pill, &RMF_MDT_MD,
							 RCL_SERVER);

		/* free big lmm if md_size is not needed */
		if (md_size == 0 || md_packed == 0) {
			info->mti_big_lmm_used = 0;
		} else {
			/* buffer must be allocated separately */
			LASSERT(info->mti_attr.ma_lmm !=
				req_capsule_server_get(pill, &RMF_MDT_MD));
			req_capsule_shrink(pill, &RMF_MDT_MD, 0, RCL_SERVER);
		}
	} else if (req_capsule_has_field(pill, &RMF_MDT_MD, RCL_SERVER)) {
		req_capsule_shrink(pill, &RMF_MDT_MD, md_size, RCL_SERVER);
	}

	if (info->mti_big_acl_used) {
		if (acl_size == 0)
			info->mti_big_acl_used = 0;
		else
			req_capsule_shrink(pill, &RMF_ACL, 0, RCL_SERVER);
	} else if (req_capsule_has_field(pill, &RMF_ACL, RCL_SERVER)) {
		req_capsule_shrink(pill, &RMF_ACL, acl_size, RCL_SERVER);
	} else if (req_capsule_has_field(pill, &RMF_LOGCOOKIES, RCL_SERVER)) {
		req_capsule_shrink(pill, &RMF_LOGCOOKIES, acl_size, RCL_SERVER);
	}

	/* Shrink optional SECCTX buffer if it is not used */
	if (req_capsule_has_field(pill, &RMF_FILE_SECCTX, RCL_SERVER) &&
	    req_capsule_get_size(pill, &RMF_FILE_SECCTX, RCL_SERVER) != 0 &&
	    !(body->mbo_valid & OBD_MD_SECCTX))
		req_capsule_shrink(pill, &RMF_FILE_SECCTX, 0, RCL_SERVER);

	/* Shrink optional ENCCTX buffer if it is not used */
	if (req_capsule_has_field(pill, &RMF_FILE_ENCCTX, RCL_SERVER) &&
	    req_capsule_get_size(pill, &RMF_FILE_ENCCTX, RCL_SERVER) != 0 &&
	    !(body->mbo_valid & OBD_MD_ENCCTX))
		req_capsule_shrink(pill, &RMF_FILE_ENCCTX, 0, RCL_SERVER);

	/*
	 * Some more field should be shrinked if needed.
	 * This should be done by those who added fields to reply message.
	 */

	/* Grow MD buffer if needed finally */
	if (info->mti_big_lmm_used) {
                void *lmm;

                LASSERT(md_size > md_packed);
                CDEBUG(D_INFO, "Enlarge reply buffer, need extra %d bytes\n",
                       md_size - md_packed);
                rc = req_capsule_server_grow(pill, &RMF_MDT_MD, md_size);
                if (rc) {
                        /* we can't answer with proper LOV EA, drop flags,
                         * the rc is also returned so this request is
                         * considered as failed */
			body->mbo_valid &= ~(OBD_MD_FLDIREA | OBD_MD_FLEASIZE);
                        /* don't return transno along with error */
                        lustre_msg_set_transno(pill->rc_req->rq_repmsg, 0);
                } else {
			/* now we need to pack right LOV/LMV EA */
			lmm = req_capsule_server_get(pill, &RMF_MDT_MD);
			if (info->mti_attr.ma_valid & MA_LOV) {
				LASSERT(req_capsule_get_size(pill, &RMF_MDT_MD,
							     RCL_SERVER) ==
						info->mti_attr.ma_lmm_size);
				memcpy(lmm, info->mti_attr.ma_lmm,
				       info->mti_attr.ma_lmm_size);
			} else if (info->mti_attr.ma_valid & MA_LMV) {
				LASSERT(req_capsule_get_size(pill, &RMF_MDT_MD,
							     RCL_SERVER) ==
						info->mti_attr.ma_lmv_size);
				memcpy(lmm, info->mti_attr.ma_lmv,
				       info->mti_attr.ma_lmv_size);
			}
		}

		/* update mdt_max_mdsize so clients will be aware about that */
		if (info->mti_mdt->mdt_max_mdsize < info->mti_attr.ma_lmm_size)
			info->mti_mdt->mdt_max_mdsize =
						info->mti_attr.ma_lmm_size;
		info->mti_big_lmm_used = 0;
	}

	if (info->mti_big_acl_used) {
		CDEBUG(D_INFO, "Enlarge reply ACL buffer to %d bytes\n",
		       acl_size);

		rc = req_capsule_server_grow(pill, &RMF_ACL, acl_size);
		if (rc) {
			body->mbo_valid &= ~OBD_MD_FLACL;
		} else {
			void *acl = req_capsule_server_get(pill, &RMF_ACL);

			memcpy(acl, info->mti_big_acl, acl_size);
		}

		info->mti_big_acl_used = 0;
	}

	RETURN(rc);
}


/* if object is dying, pack the lov/llog data,
 * parameter info->mti_attr should be valid at this point!
 * Also implements RAoLU policy */
int mdt_handle_last_unlink(struct mdt_thread_info *info, struct mdt_object *mo,
			   struct md_attr *ma)
{
	struct mdt_body *repbody = NULL;
        const struct lu_attr *la = &ma->ma_attr;
	struct coordinator *cdt = &info->mti_mdt->mdt_coordinator;
	int rc;
	__u64 need = 0;
	struct hsm_action_item hai = {
		.hai_len = sizeof(hai),
		.hai_action = HSMA_REMOVE,
		.hai_extent.length = -1,
		.hai_cookie = 0,
		.hai_gid = 0,
	};
	int archive_id;

        ENTRY;

	if (mdt_info_req(info) != NULL) {
		repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
		LASSERT(repbody != NULL);
	} else {
		CDEBUG(D_INFO, "not running in a request/reply context\n");
	}

	if ((ma->ma_valid & MA_INODE) && repbody != NULL)
                mdt_pack_attr2body(info, repbody, la, mdt_object_fid(mo));

	if (ma->ma_valid & MA_LOV) {
		CERROR("No need in LOV EA upon unlink\n");
		dump_stack();
	}
	if (repbody != NULL)
		repbody->mbo_eadatasize = 0;

	/* Only check unlinked and archived if RAoLU and upon last close */
	if (!cdt->cdt_remove_archive_on_last_unlink ||
	    atomic_read(&mo->mot_open_count) != 0)
		RETURN(0);

	/* mdt_attr_get_complex will clear ma_valid, so check here first */
	if ((ma->ma_valid & MA_INODE) && (ma->ma_attr.la_nlink != 0))
		RETURN(0);

	if ((ma->ma_valid & MA_HSM) && (!(ma->ma_hsm.mh_flags & HS_EXISTS)))
		RETURN(0);

	need |= (MA_INODE | MA_HSM) & ~ma->ma_valid;
	if (need != 0) {
		/* ma->ma_valid is missing either MA_INODE, MA_HSM, or both,
		 * try setting them */
		ma->ma_need |= need;
		rc = mdt_attr_get_complex(info, mo, ma);
		if (rc) {
			CERROR("%s: unable to fetch missing attributes of"
			       DFID": rc=%d\n", mdt_obd_name(info->mti_mdt),
			       PFID(mdt_object_fid(mo)), rc);
			RETURN(0);
		}

		if (need & MA_INODE) {
			if (ma->ma_valid & MA_INODE) {
				if (ma->ma_attr.la_nlink != 0)
					RETURN(0);
			} else {
				RETURN(0);
			}
		}

		if (need & MA_HSM) {
			if (ma->ma_valid & MA_HSM) {
				if (!(ma->ma_hsm.mh_flags & HS_EXISTS))
					RETURN(0);
			} else {
				RETURN(0);
			}
		}
	}

	/* RAoLU policy is active, last close on file has occured,
	 * file is unlinked, file is archived, so create remove request
	 * for copytool!
	 * If CDT is not running, requests will be logged for later. */
	if (ma->ma_hsm.mh_arch_id != 0)
		archive_id = ma->ma_hsm.mh_arch_id;
	else
		archive_id = cdt->cdt_default_archive_id;

	hai.hai_fid = *mdt_object_fid(mo);

	rc = mdt_agent_record_add(info->mti_env, info->mti_mdt, archive_id, 0,
				  &hai);
	if (rc)
		CERROR("%s: unable to add HSM remove request for "DFID
		       ": rc=%d\n", mdt_obd_name(info->mti_mdt),
		       PFID(mdt_object_fid(mo)), rc);

        RETURN(0);
}

static __u64 mdt_attr_valid_xlate(enum mds_attr_flags in,
				  struct mdt_reint_record *rr,
                                  struct md_attr *ma)
{
	__u64 out;

	out = 0;
	if (in & MDS_ATTR_MODE)
		out |= LA_MODE;
	if (in & MDS_ATTR_UID)
		out |= LA_UID;
	if (in & MDS_ATTR_GID)
		out |= LA_GID;
	if (in & MDS_ATTR_SIZE)
		out |= LA_SIZE;
	if (in & MDS_ATTR_BLOCKS)
		out |= LA_BLOCKS;
	if (in & MDS_ATTR_ATIME_SET)
		out |= LA_ATIME;
	if (in & MDS_ATTR_CTIME_SET)
		out |= LA_CTIME;
	if (in & MDS_ATTR_MTIME_SET)
		out |= LA_MTIME;
	if (in & MDS_ATTR_ATTR_FLAG)
		out |= LA_FLAGS;
	if (in & MDS_ATTR_KILL_SUID)
		out |= LA_KILL_SUID;
	if (in & MDS_ATTR_KILL_SGID)
		out |= LA_KILL_SGID;
	if (in & MDS_ATTR_PROJID)
		out |= LA_PROJID;
	if (in & MDS_ATTR_LSIZE)
		out |= LA_LSIZE;
	if (in & MDS_ATTR_LBLOCKS)
		out |= LA_LBLOCKS;

	if (in & MDS_ATTR_FROM_OPEN)
		rr->rr_flags |= MRF_OPEN_TRUNC;
	if (in & MDS_ATTR_OVERRIDE)
		ma->ma_attr_flags |= MDS_OWNEROVERRIDE;
	if (in & MDS_ATTR_FORCE)
		ma->ma_attr_flags |= MDS_PERM_BYPASS;

	in &= ~(MDS_ATTR_MODE | MDS_ATTR_UID | MDS_ATTR_GID | MDS_ATTR_PROJID |
		MDS_ATTR_ATIME | MDS_ATTR_MTIME | MDS_ATTR_CTIME |
		MDS_ATTR_ATIME_SET | MDS_ATTR_CTIME_SET | MDS_ATTR_MTIME_SET |
		MDS_ATTR_SIZE | MDS_ATTR_BLOCKS | MDS_ATTR_ATTR_FLAG |
		MDS_ATTR_FORCE | MDS_ATTR_KILL_SUID | MDS_ATTR_KILL_SGID |
		MDS_ATTR_FROM_OPEN | MDS_ATTR_LSIZE | MDS_ATTR_LBLOCKS |
		MDS_ATTR_OVERRIDE);
	if (in != 0)
		CDEBUG(D_INFO, "Unknown attr bits: %#llx\n", (u64)in);

	return out;
}

/* unpacking */

int mdt_name_unpack(struct req_capsule *pill,
		    const struct req_msg_field *field,
		    struct lu_name *ln,
		    enum mdt_name_flags flags)
{
	ln->ln_name = req_capsule_client_get(pill, field);
	ln->ln_namelen = req_capsule_get_size(pill, field, RCL_CLIENT) - 1;

	if (!lu_name_is_valid(ln)) {
		ln->ln_name = NULL;
		ln->ln_namelen = 0;

		return -EPROTO;
	}

	if ((flags & MNF_FIX_ANON) &&
	    ln->ln_namelen == 1 && ln->ln_name[0] == '/') {
		/* Newer (3.x) kernels use a name of "/" for the
		 * "anonymous" disconnected dentries from NFS
		 * filehandle conversion. See d_obtain_alias(). */
		ln->ln_name = NULL;
		ln->ln_namelen = 0;
	}

	return 0;
}

static int mdt_file_secctx_unpack(struct req_capsule *pill,
				  const char **secctx_name,
				  void **secctx, size_t *secctx_size)
{
	const char *name;
	size_t name_size;

	*secctx_name = NULL;
	*secctx = NULL;
	*secctx_size = 0;

	if (!req_capsule_has_field(pill, &RMF_FILE_SECCTX_NAME, RCL_CLIENT) ||
	    !req_capsule_field_present(pill, &RMF_FILE_SECCTX_NAME, RCL_CLIENT))
		return 0;

	name_size = req_capsule_get_size(pill, &RMF_FILE_SECCTX_NAME,
					 RCL_CLIENT);
	if (name_size == 0)
		return 0;

	if (name_size > XATTR_NAME_MAX + 1)
		return -EPROTO;

	name = req_capsule_client_get(pill, &RMF_FILE_SECCTX_NAME);
	if (strnlen(name, name_size) != name_size - 1)
		return -EPROTO;

	if (!req_capsule_has_field(pill, &RMF_FILE_SECCTX, RCL_CLIENT) ||
	    !req_capsule_field_present(pill, &RMF_FILE_SECCTX, RCL_CLIENT))
		return -EPROTO;

	*secctx_name = name;
	*secctx = req_capsule_client_get(pill, &RMF_FILE_SECCTX);
	*secctx_size = req_capsule_get_size(pill, &RMF_FILE_SECCTX, RCL_CLIENT);

	return 0;
}

static int mdt_file_encctx_unpack(struct req_capsule *pill,
				  void **encctx, size_t *encctx_size)
{
	*encctx = NULL;
	*encctx_size = 0;

	if (!exp_connect_encrypt(pill->rc_req->rq_export))
		return 0;

	if (!req_capsule_has_field(pill, &RMF_FILE_ENCCTX, RCL_CLIENT) ||
	    !req_capsule_field_present(pill, &RMF_FILE_ENCCTX, RCL_CLIENT))
		return -EPROTO;

	*encctx_size = req_capsule_get_size(pill, &RMF_FILE_ENCCTX, RCL_CLIENT);
	if (*encctx_size == 0)
		return 0;

	*encctx = req_capsule_client_get(pill, &RMF_FILE_ENCCTX);

	return 0;
}

static int mdt_setattr_unpack_rec(struct mdt_thread_info *info)
{
	struct lu_ucred *uc = mdt_ucred(info);
	struct md_attr *ma = &info->mti_attr;
	struct lu_attr *la = &ma->ma_attr;
	struct req_capsule *pill = info->mti_pill;
	struct mdt_reint_record *rr = &info->mti_rr;
	struct mdt_rec_setattr *rec;
	struct lu_nodemap *nodemap;

	ENTRY;

	BUILD_BUG_ON(sizeof(*rec) != sizeof(struct mdt_rec_reint));
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);
	if (rec == NULL)
		RETURN(-EFAULT);

	/* This prior initialization is needed for old_init_ucred_reint() */
	uc->uc_fsuid = rec->sa_fsuid;
	uc->uc_fsgid = rec->sa_fsgid;
	uc->uc_cap = CAP_EMPTY_SET;
	uc->uc_cap.cap[0] = rec->sa_cap;
	uc->uc_suppgids[0] = rec->sa_suppgid;
	uc->uc_suppgids[1] = -1;

        rr->rr_fid1 = &rec->sa_fid;
	la->la_valid = mdt_attr_valid_xlate(rec->sa_valid, rr, ma);
	la->la_mode  = rec->sa_mode;
	la->la_flags = rec->sa_attr_flags;

	nodemap = nodemap_get_from_exp(info->mti_exp);
	if (IS_ERR(nodemap))
		RETURN(PTR_ERR(nodemap));

	la->la_uid = nodemap_map_id(nodemap, NODEMAP_UID,
				    NODEMAP_CLIENT_TO_FS, rec->sa_uid);
	la->la_gid = nodemap_map_id(nodemap, NODEMAP_GID,
				    NODEMAP_CLIENT_TO_FS, rec->sa_gid);
	la->la_projid = nodemap_map_id(nodemap, NODEMAP_PROJID,
				       NODEMAP_CLIENT_TO_FS, rec->sa_projid);
	nodemap_putref(nodemap);

	la->la_size  = rec->sa_size;
	la->la_blocks = rec->sa_blocks;
	la->la_ctime = rec->sa_ctime;
	la->la_atime = rec->sa_atime;
	la->la_mtime = rec->sa_mtime;
	ma->ma_valid = MA_INODE;

	ma->ma_attr_flags |= rec->sa_bias & (MDS_CLOSE_INTENT |
				MDS_DATA_MODIFIED | MDS_TRUNC_KEEP_LEASE |
				MDS_PCC_ATTACH);
	RETURN(0);
}

static int mdt_close_handle_unpack(struct mdt_thread_info *info)
{
	struct req_capsule *pill = info->mti_pill;
	struct mdt_ioepoch *ioepoch;
	ENTRY;

	if (req_capsule_get_size(pill, &RMF_MDT_EPOCH, RCL_CLIENT))
		ioepoch = req_capsule_client_get(pill, &RMF_MDT_EPOCH);
	else
		ioepoch = NULL;

	if (ioepoch == NULL)
		RETURN(-EPROTO);

	info->mti_open_handle = ioepoch->mio_open_handle;

	RETURN(0);
}

static inline int mdt_dlmreq_unpack(struct mdt_thread_info *info) {
        struct req_capsule      *pill = info->mti_pill;

        if (req_capsule_get_size(pill, &RMF_DLM_REQ, RCL_CLIENT)) {
                info->mti_dlm_req = req_capsule_client_get(pill, &RMF_DLM_REQ);
                if (info->mti_dlm_req == NULL)
                        RETURN(-EFAULT);
        }

        RETURN(0);
}

static int mdt_setattr_unpack(struct mdt_thread_info *info)
{
        struct mdt_reint_record *rr = &info->mti_rr;
        struct md_attr          *ma = &info->mti_attr;
        struct req_capsule      *pill = info->mti_pill;
        int rc;
        ENTRY;

        rc = mdt_setattr_unpack_rec(info);
        if (rc)
                RETURN(rc);

        if (req_capsule_field_present(pill, &RMF_EADATA, RCL_CLIENT)) {
                rr->rr_eadata = req_capsule_client_get(pill, &RMF_EADATA);
                rr->rr_eadatalen = req_capsule_get_size(pill, &RMF_EADATA,
                                                        RCL_CLIENT);

		if (rr->rr_eadatalen > 0) {
			const struct lmv_user_md	*lum;

			lum = rr->rr_eadata;
			/* Sigh ma_valid(from req) does not indicate whether
			 * it will set LOV/LMV EA, so we have to check magic */
			if (le32_to_cpu(lum->lum_magic) == LMV_USER_MAGIC) {
				ma->ma_valid |= MA_LMV;
				ma->ma_lmv = (void *)rr->rr_eadata;
				ma->ma_lmv_size = rr->rr_eadatalen;
			} else {
				ma->ma_valid |= MA_LOV;
				ma->ma_lmm = (void *)rr->rr_eadata;
				ma->ma_lmm_size = rr->rr_eadatalen;
			}
		}
	}

	rc = mdt_dlmreq_unpack(info);
	RETURN(rc);
}

static int mdt_close_intent_unpack(struct mdt_thread_info *info)
{
	struct md_attr          *ma = &info->mti_attr;
	struct req_capsule	*pill = info->mti_pill;
	ENTRY;

	if (!(ma->ma_attr_flags & MDS_CLOSE_INTENT))
		RETURN(0);

	req_capsule_extend(pill, &RQF_MDS_CLOSE_INTENT);

	if (!(req_capsule_has_field(pill, &RMF_CLOSE_DATA, RCL_CLIENT) &&
	    req_capsule_field_present(pill, &RMF_CLOSE_DATA, RCL_CLIENT)))
		RETURN(-EFAULT);

	RETURN(0);
}

int mdt_close_unpack(struct mdt_thread_info *info)
{
	int rc;
	ENTRY;

	rc = mdt_close_handle_unpack(info);
        if (rc)
                RETURN(rc);

	rc = mdt_setattr_unpack_rec(info);
	if (rc)
		RETURN(rc);

	rc = mdt_close_intent_unpack(info);
	if (rc)
		RETURN(rc);

	RETURN(mdt_init_ucred_reint(info));
}

static int mdt_create_unpack(struct mdt_thread_info *info)
{
	struct lu_ucred *uc  = mdt_ucred(info);
	struct mdt_rec_create *rec;
	struct lu_attr *attr = &info->mti_attr.ma_attr;
	struct mdt_reint_record *rr = &info->mti_rr;
	struct req_capsule      *pill = info->mti_pill;
	struct md_op_spec       *sp = &info->mti_spec;
	int rc;

	ENTRY;

	BUILD_BUG_ON(sizeof(*rec) != sizeof(struct mdt_rec_reint));
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);
	if (rec == NULL)
		RETURN(-EFAULT);

	/* This prior initialization is needed for old_init_ucred_reint() */
	uc->uc_fsuid = rec->cr_fsuid;
	uc->uc_fsgid = rec->cr_fsgid;
	uc->uc_cap = CAP_EMPTY_SET;
	uc->uc_cap.cap[0] = rec->cr_cap;
	uc->uc_suppgids[0] = rec->cr_suppgid1;
	uc->uc_suppgids[1] = -1;
	uc->uc_umask = rec->cr_umask;

	rr->rr_fid1 = &rec->cr_fid1;
	rr->rr_fid2 = &rec->cr_fid2;
	attr->la_mode = rec->cr_mode;
	attr->la_rdev  = rec->cr_rdev;
	attr->la_uid   = rec->cr_fsuid;
	attr->la_gid   = rec->cr_fsgid;
	attr->la_ctime = rec->cr_time;
	attr->la_mtime = rec->cr_time;
	attr->la_atime = rec->cr_time;
	attr->la_valid = LA_MODE | LA_RDEV | LA_UID | LA_GID | LA_TYPE |
		LA_CTIME | LA_MTIME | LA_ATIME;
	memset(&sp->u, 0, sizeof(sp->u));
	sp->sp_cr_flags = get_mrc_cr_flags(rec);

	rc = mdt_name_unpack(pill, &RMF_NAME, &rr->rr_name, 0);
	if (rc < 0)
		RETURN(rc);

	if (S_ISLNK(attr->la_mode)) {
		const char *tgt = NULL;
		int sz;

		req_capsule_extend(pill, &RQF_MDS_REINT_CREATE_SYM);
		sz = req_capsule_get_size(pill, &RMF_SYMTGT, RCL_CLIENT);
		if (sz) {
			tgt = req_capsule_client_get(pill, &RMF_SYMTGT);
			sp->u.sp_symname.ln_name = tgt;
			sp->u.sp_symname.ln_namelen = sz - 1; /* skip NUL */
		}
		if (tgt == NULL)
			RETURN(-EFAULT);
	} else {
		req_capsule_extend(pill, &RQF_MDS_REINT_CREATE_ACL);
		if (S_ISDIR(attr->la_mode) &&
		    req_capsule_get_size(pill, &RMF_EADATA, RCL_CLIENT) > 0) {
			sp->u.sp_ea.eadata =
				req_capsule_client_get(pill, &RMF_EADATA);
			sp->u.sp_ea.eadatalen =
				req_capsule_get_size(pill, &RMF_EADATA,
						     RCL_CLIENT);
			sp->sp_cr_flags |= MDS_OPEN_HAS_EA;
		}
	}

	rc = mdt_file_secctx_unpack(pill, &sp->sp_cr_file_secctx_name,
				    &sp->sp_cr_file_secctx,
				    &sp->sp_cr_file_secctx_size);
	if (rc < 0)
		RETURN(rc);

	rc = mdt_file_encctx_unpack(pill, &sp->sp_cr_file_encctx,
				    &sp->sp_cr_file_encctx_size);
	if (rc < 0)
		RETURN(rc);

	rc = req_check_sepol(pill);
	if (rc)
		RETURN(rc);

	rc = mdt_dlmreq_unpack(info);
	RETURN(rc);
}

static int mdt_link_unpack(struct mdt_thread_info *info)
{
	struct lu_ucred *uc  = mdt_ucred(info);
	struct mdt_rec_link *rec;
	struct lu_attr *attr = &info->mti_attr.ma_attr;
	struct mdt_reint_record *rr = &info->mti_rr;
	struct req_capsule *pill = info->mti_pill;
	int rc;

	ENTRY;

	BUILD_BUG_ON(sizeof(*rec) != sizeof(struct mdt_rec_reint));
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);
	if (rec == NULL)
		RETURN(-EFAULT);

	/* This prior initialization is needed for old_init_ucred_reint() */
	uc->uc_fsuid = rec->lk_fsuid;
	uc->uc_fsgid = rec->lk_fsgid;
	uc->uc_cap = CAP_EMPTY_SET;
	uc->uc_cap.cap[0] = rec->lk_cap;
	uc->uc_suppgids[0] = rec->lk_suppgid1;
	uc->uc_suppgids[1] = rec->lk_suppgid2;

        attr->la_uid = rec->lk_fsuid;
        attr->la_gid = rec->lk_fsgid;
        rr->rr_fid1 = &rec->lk_fid1;
        rr->rr_fid2 = &rec->lk_fid2;
        attr->la_ctime = rec->lk_time;
        attr->la_mtime = rec->lk_time;
        attr->la_valid = LA_UID | LA_GID | LA_CTIME | LA_MTIME;

	rc = mdt_name_unpack(pill, &RMF_NAME, &rr->rr_name, 0);
	if (rc < 0)
		RETURN(rc);

	rc = req_check_sepol(pill);
	if (rc)
		RETURN(rc);

	rc = mdt_dlmreq_unpack(info);

	RETURN(rc);
}

static int mdt_unlink_unpack(struct mdt_thread_info *info)
{
	struct lu_ucred *uc  = mdt_ucred(info);
	struct mdt_rec_unlink *rec;
	struct lu_attr *attr = &info->mti_attr.ma_attr;
	struct mdt_reint_record *rr = &info->mti_rr;
	struct req_capsule      *pill = info->mti_pill;
	int rc;

	ENTRY;

	BUILD_BUG_ON(sizeof(*rec) != sizeof(struct mdt_rec_reint));
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);
	if (rec == NULL)
		RETURN(-EFAULT);

	/* This prior initialization is needed for old_init_ucred_reint() */
	uc->uc_fsuid = rec->ul_fsuid;
	uc->uc_fsgid = rec->ul_fsgid;
	uc->uc_cap = CAP_EMPTY_SET;
	uc->uc_cap.cap[0] = rec->ul_cap;
	uc->uc_suppgids[0] = rec->ul_suppgid1;
	uc->uc_suppgids[1] = -1;

	attr->la_uid = rec->ul_fsuid;
	attr->la_gid = rec->ul_fsgid;
	rr->rr_fid1 = &rec->ul_fid1;
	rr->rr_fid2 = &rec->ul_fid2;
	attr->la_ctime = rec->ul_time;
	attr->la_mtime = rec->ul_time;
	attr->la_mode  = rec->ul_mode;
	attr->la_valid = LA_UID | LA_GID | LA_CTIME | LA_MTIME | LA_MODE;
	if (rec->ul_bias & MDS_FID_OP)
		info->mti_spec.sp_cr_flags |= MDS_OP_WITH_FID;
	else
		info->mti_spec.sp_cr_flags &= ~MDS_OP_WITH_FID;

	rc = mdt_name_unpack(pill, &RMF_NAME, &rr->rr_name, 0);
	if (rc < 0)
		RETURN(rc);

	info->mti_spec.no_create = !!req_is_replay(mdt_info_req(info));

	rc = req_check_sepol(pill);
	if (rc)
		RETURN(rc);

	rc = mdt_dlmreq_unpack(info);
	RETURN(rc);
}

static int mdt_rmentry_unpack(struct mdt_thread_info *info)
{
	info->mti_spec.sp_rm_entry = 1;
	return mdt_unlink_unpack(info);
}

static int mdt_rename_unpack(struct mdt_thread_info *info)
{
	struct lu_ucred *uc = mdt_ucred(info);
	struct mdt_rec_rename *rec;
	struct lu_attr *attr = &info->mti_attr.ma_attr;
	struct mdt_reint_record *rr = &info->mti_rr;
	struct req_capsule *pill = info->mti_pill;
	struct md_op_spec *spec = &info->mti_spec;
	int rc;

	ENTRY;

	BUILD_BUG_ON(sizeof(*rec) != sizeof(struct mdt_rec_reint));
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);
	if (rec == NULL)
		RETURN(-EFAULT);

	/* This prior initialization is needed for old_init_ucred_reint() */
	uc->uc_fsuid = rec->rn_fsuid;
	uc->uc_fsgid = rec->rn_fsgid;
	uc->uc_cap = CAP_EMPTY_SET;
	uc->uc_cap.cap[0] = rec->rn_cap;
	uc->uc_suppgids[0] = rec->rn_suppgid1;
	uc->uc_suppgids[1] = rec->rn_suppgid2;

	attr->la_uid = rec->rn_fsuid;
	attr->la_gid = rec->rn_fsgid;
	rr->rr_fid1 = &rec->rn_fid1;
	rr->rr_fid2 = &rec->rn_fid2;
	attr->la_ctime = rec->rn_time;
	attr->la_mtime = rec->rn_time;
	/* rename_tgt contains the mode already */
	attr->la_mode = rec->rn_mode;
	attr->la_valid = LA_UID | LA_GID | LA_CTIME | LA_MTIME | LA_MODE;

	rc = mdt_name_unpack(pill, &RMF_NAME, &rr->rr_name, 0);
	if (rc < 0)
		RETURN(rc);

	rc = mdt_name_unpack(pill, &RMF_SYMTGT, &rr->rr_tgt_name, 0);
	if (rc < 0)
		RETURN(rc);

	spec->no_create = !!req_is_replay(mdt_info_req(info));

	rc = req_check_sepol(pill);
	if (rc)
		RETURN(rc);

	rc = mdt_dlmreq_unpack(info);

	RETURN(rc);
}

static int mdt_migrate_unpack(struct mdt_thread_info *info)
{
	struct lu_ucred *uc = mdt_ucred(info);
	struct mdt_rec_rename *rec;
	struct lu_attr *attr = &info->mti_attr.ma_attr;
	struct mdt_reint_record *rr = &info->mti_rr;
	struct req_capsule *pill = info->mti_pill;
	struct md_op_spec *spec = &info->mti_spec;
	int rc;

	ENTRY;

	BUILD_BUG_ON(sizeof(*rec) != sizeof(struct mdt_rec_reint));
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);
	if (rec == NULL)
		RETURN(-EFAULT);

	/* This prior initialization is needed for old_init_ucred_reint() */
	uc->uc_fsuid = rec->rn_fsuid;
	uc->uc_fsgid = rec->rn_fsgid;
	uc->uc_cap = CAP_EMPTY_SET;
	uc->uc_cap.cap[0] = rec->rn_cap;
	uc->uc_suppgids[0] = rec->rn_suppgid1;
	uc->uc_suppgids[1] = rec->rn_suppgid2;

	attr->la_uid = rec->rn_fsuid;
	attr->la_gid = rec->rn_fsgid;
	rr->rr_fid1 = &rec->rn_fid1;
	rr->rr_fid2 = &rec->rn_fid2;
	attr->la_ctime = rec->rn_time;
	attr->la_mtime = rec->rn_time;
	/* rename_tgt contains the mode already */
	attr->la_mode = rec->rn_mode;
	attr->la_valid = LA_UID | LA_GID | LA_CTIME | LA_MTIME | LA_MODE;
	spec->sp_cr_flags = 0;

	rc = mdt_name_unpack(pill, &RMF_NAME, &rr->rr_name, 0);
	if (rc < 0)
		RETURN(rc);

	if (rec->rn_bias & MDS_CLOSE_MIGRATE) {
		rc = mdt_close_handle_unpack(info);
		if (rc)
			RETURN(rc);

		spec->sp_migrate_close = 1;
	} else {
		spec->sp_migrate_close = 0;
	}

	spec->sp_migrate_nsonly = !!(rec->rn_bias & MDS_MIGRATE_NSONLY);

	/* lustre version > 2.11 migration packs lum */
	if (req_capsule_has_field(pill, &RMF_EADATA, RCL_CLIENT)) {
		if (req_capsule_field_present(pill, &RMF_EADATA, RCL_CLIENT)) {
			rr->rr_eadatalen = req_capsule_get_size(pill,
								&RMF_EADATA,
								RCL_CLIENT);

			if (rr->rr_eadatalen > 0) {
				struct lmv_user_md_v1 *lmu;

				lmu = req_capsule_client_get(pill, &RMF_EADATA);
				lmu->lum_hash_type |=
					cpu_to_le32(LMV_HASH_FLAG_FIXED);
				rr->rr_eadata = lmu;
				spec->u.sp_ea.eadatalen = rr->rr_eadatalen;
				spec->u.sp_ea.eadata = rr->rr_eadata;
				spec->sp_cr_flags |= MDS_OPEN_HAS_EA;
			}
		} else {
			/* old client doesn't provide lum. */
			RETURN(-EOPNOTSUPP);
		}
	}

	spec->no_create = !!req_is_replay(mdt_info_req(info));

	rc = mdt_dlmreq_unpack(info);

	RETURN(rc);
}

/*
 * please see comment above LOV_MAGIC_V1_DEFINED
 */
void mdt_fix_lov_magic(struct mdt_thread_info *info, void *eadata)
{
	struct lov_user_md_v1   *v1 = eadata;

	LASSERT(v1);

	if (unlikely(req_is_replay(mdt_info_req(info)))) {
		if ((v1->lmm_magic & LOV_MAGIC_MASK) == LOV_MAGIC_MAGIC)
			v1->lmm_magic |= LOV_MAGIC_DEFINED;
		else if ((v1->lmm_magic & __swab32(LOV_MAGIC_MAGIC)) ==
			 __swab32(LOV_MAGIC_MAGIC))
			v1->lmm_magic |= __swab32(LOV_MAGIC_DEFINED);
	}
}

static int mdt_open_unpack(struct mdt_thread_info *info)
{
	struct lu_ucred *uc = mdt_ucred(info);
	struct mdt_rec_create *rec;
	struct lu_attr *attr = &info->mti_attr.ma_attr;
	struct req_capsule *pill = info->mti_pill;
	struct mdt_reint_record *rr = &info->mti_rr;
	struct ptlrpc_request *req = mdt_info_req(info);
	struct md_op_spec *sp = &info->mti_spec;
	int rc;
	ENTRY;

	BUILD_BUG_ON(sizeof(struct mdt_rec_create) !=
		     sizeof(struct mdt_rec_reint));
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);
	if (rec == NULL)
		RETURN(-EFAULT);

	/* This prior initialization is needed for old_init_ucred_reint() */
	uc->uc_fsuid = rec->cr_fsuid;
	uc->uc_fsgid = rec->cr_fsgid;
	uc->uc_cap = CAP_EMPTY_SET;
	uc->uc_cap.cap[0] = rec->cr_cap;
	uc->uc_suppgids[0] = rec->cr_suppgid1;
	uc->uc_suppgids[1] = rec->cr_suppgid2;
	uc->uc_umask = rec->cr_umask;

	rr->rr_fid1   = &rec->cr_fid1;
	rr->rr_fid2   = &rec->cr_fid2;
	rr->rr_open_handle = &rec->cr_open_handle_old;
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
        info->mti_spec.sp_cr_flags = get_mrc_cr_flags(rec);
        /* Do not trigger ASSERTION if client miss to set such flags. */
        if (unlikely(info->mti_spec.sp_cr_flags == 0))
                RETURN(-EPROTO);

        info->mti_cross_ref = !!(rec->cr_bias & MDS_CROSS_REF);

	mdt_name_unpack(pill, &RMF_NAME, &rr->rr_name, MNF_FIX_ANON);

        if (req_capsule_field_present(pill, &RMF_EADATA, RCL_CLIENT)) {
                rr->rr_eadatalen = req_capsule_get_size(pill, &RMF_EADATA,
                                                        RCL_CLIENT);

                if (rr->rr_eadatalen > 0) {
                        rr->rr_eadata = req_capsule_client_get(pill,
                                                               &RMF_EADATA);
                        sp->u.sp_ea.eadatalen = rr->rr_eadatalen;
                        sp->u.sp_ea.eadata = rr->rr_eadata;
			sp->sp_archive_id = rec->cr_archive_id;
                        sp->no_create = !!req_is_replay(req);
			mdt_fix_lov_magic(info, rr->rr_eadata);
                }

                /*
                 * Client default md_size may be 0 right after client start,
                 * until all osc are connected, set here just some reasonable
                 * value to prevent misbehavior.
                 */
                if (rr->rr_eadatalen == 0 &&
                    !(info->mti_spec.sp_cr_flags & MDS_OPEN_DELAY_CREATE))
			rr->rr_eadatalen = MIN_MD_SIZE;
	}

	rc = mdt_file_secctx_unpack(pill, &sp->sp_cr_file_secctx_name,
				    &sp->sp_cr_file_secctx,
				    &sp->sp_cr_file_secctx_size);
	if (rc < 0)
		RETURN(rc);

	rc = mdt_file_encctx_unpack(pill, &sp->sp_cr_file_encctx,
				    &sp->sp_cr_file_encctx_size);
	if (rc < 0)
		RETURN(rc);

	rc = req_check_sepol(pill);
	if (rc)
		RETURN(rc);

	RETURN(rc);
}

static int mdt_setxattr_unpack(struct mdt_thread_info *info)
{
	struct mdt_reint_record *rr = &info->mti_rr;
	struct lu_ucred *uc = mdt_ucred(info);
	struct lu_attr *attr = &info->mti_attr.ma_attr;
	struct req_capsule *pill = info->mti_pill;
	struct mdt_rec_setxattr *rec;
	int rc;
	ENTRY;


	BUILD_BUG_ON(sizeof(struct mdt_rec_setxattr) !=
		     sizeof(struct mdt_rec_reint));
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);
	if (rec == NULL)
		RETURN(-EFAULT);

	/* This prior initialization is needed for old_init_ucred_reint() */
	uc->uc_fsuid  = rec->sx_fsuid;
	uc->uc_fsgid  = rec->sx_fsgid;
	uc->uc_cap = CAP_EMPTY_SET;
	uc->uc_cap.cap[0] = rec->sx_cap;
	uc->uc_suppgids[0] = rec->sx_suppgid1;
	uc->uc_suppgids[1] = -1;

        rr->rr_opcode = rec->sx_opcode;
        rr->rr_fid1   = &rec->sx_fid;
        attr->la_valid = rec->sx_valid;
        attr->la_ctime = rec->sx_time;
        attr->la_size = rec->sx_size;
        attr->la_flags = rec->sx_flags;

	rc = mdt_name_unpack(pill, &RMF_NAME, &rr->rr_name, 0);
	if (rc < 0)
		RETURN(rc);

        if (req_capsule_field_present(pill, &RMF_EADATA, RCL_CLIENT)) {
                rr->rr_eadatalen = req_capsule_get_size(pill, &RMF_EADATA,
                                                        RCL_CLIENT);

		if (rr->rr_eadatalen > info->mti_mdt->mdt_max_ea_size)
			RETURN(-E2BIG);

                if (rr->rr_eadatalen > 0) {
                        rr->rr_eadata = req_capsule_client_get(pill,
                                                               &RMF_EADATA);
                        if (rr->rr_eadata == NULL)
                                RETURN(-EFAULT);
                } else {
                        rr->rr_eadata = NULL;
                }
        } else if (!(attr->la_valid & OBD_MD_FLXATTRRM)) {
                CDEBUG(D_INFO, "no xattr data supplied\n");
                RETURN(-EFAULT);
        }

	rc = req_check_sepol(pill);
	if (rc)
		RETURN(rc);

	if (mdt_dlmreq_unpack(info) < 0)
		RETURN(-EPROTO);

        RETURN(0);
}

static int mdt_resync_unpack(struct mdt_thread_info *info)
{
	struct req_capsule      *pill = info->mti_pill;
	struct mdt_reint_record *rr   = &info->mti_rr;
	struct lu_ucred		*uc	= mdt_ucred(info);
	struct mdt_rec_resync	*rec;
	ENTRY;

	BUILD_BUG_ON(sizeof(*rec) != sizeof(struct mdt_rec_reint));
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);
	if (rec == NULL)
		RETURN(-EFAULT);

	/* This prior initialization is needed for old_init_ucred_reint() */
	uc->uc_fsuid = rec->rs_fsuid;
	uc->uc_fsgid = rec->rs_fsgid;
	uc->uc_cap = CAP_EMPTY_SET;
	uc->uc_cap.cap[0] = rec->rs_cap;

	rr->rr_fid1   = &rec->rs_fid;
	rr->rr_mirror_id = rec->rs_mirror_id;

	/* cookie doesn't need to be swapped but it has been swapped
	 * in lustre_swab_mdt_rec_reint() as rr_mtime, so here it needs
	 * restoring. */
	if (req_capsule_req_need_swab(pill))
		__swab64s(&rec->rs_lease_handle.cookie);
	rr->rr_lease_handle = &rec->rs_lease_handle;

	RETURN(mdt_dlmreq_unpack(info));
}

typedef int (*reint_unpacker)(struct mdt_thread_info *info);

static reint_unpacker mdt_reint_unpackers[REINT_MAX] = {
	[REINT_SETATTR]  = mdt_setattr_unpack,
	[REINT_CREATE]   = mdt_create_unpack,
	[REINT_LINK]     = mdt_link_unpack,
	[REINT_UNLINK]   = mdt_unlink_unpack,
	[REINT_RENAME]   = mdt_rename_unpack,
	[REINT_OPEN]     = mdt_open_unpack,
	[REINT_SETXATTR] = mdt_setxattr_unpack,
	[REINT_RMENTRY]  = mdt_rmentry_unpack,
	[REINT_MIGRATE]  = mdt_migrate_unpack,
	[REINT_RESYNC]   = mdt_resync_unpack,
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

int mdt_pack_secctx_in_reply(struct mdt_thread_info *info,
			     struct mdt_object *child)
{
	char *secctx_name;
	struct lu_buf *buffer;
	struct mdt_body *repbody;
	struct req_capsule *pill = info->mti_pill;
	int rc = 0;

	if (req_capsule_has_field(pill, &RMF_FILE_SECCTX, RCL_SERVER) &&
	    req_capsule_get_size(pill, &RMF_FILE_SECCTX, RCL_SERVER) != 0) {
		secctx_name =
			req_capsule_client_get(pill, &RMF_FILE_SECCTX_NAME);
		buffer = &info->mti_buf;

		/* fill reply buffer with security context now */
		buffer->lb_len = req_capsule_get_size(pill, &RMF_FILE_SECCTX,
						      RCL_SERVER);
		buffer->lb_buf = req_capsule_server_get(info->mti_pill,
							&RMF_FILE_SECCTX);
		rc = mo_xattr_get(info->mti_env, mdt_object_child(child),
				  buffer, secctx_name);
		if (rc >= 0) {
			CDEBUG(D_SEC,
			       "found security context of size %d for "DFID"\n",
			       rc, PFID(mdt_object_fid(child)));

			repbody = req_capsule_server_get(pill, &RMF_MDT_BODY);
			repbody->mbo_valid |= OBD_MD_SECCTX;
			if (rc < buffer->lb_len)
				req_capsule_shrink(pill, &RMF_FILE_SECCTX, rc,
						   RCL_SERVER);
			rc = 0;
		} else {
			CDEBUG(D_SEC,
			     "security context not found for "DFID": rc = %d\n",
			     PFID(mdt_object_fid(child)), rc);
			req_capsule_shrink(pill, &RMF_FILE_SECCTX, 0,
					   RCL_SERVER);
			/* handling -ENOENT is important because it may change
			 * object state in DNE env dropping LOHA_EXISTS flag,
			 * it is important to return that to the caller.
			 * Check LU-13115 for details.
			 */
			if (rc != -ENOENT)
				rc = 0;
		}
	}
	return rc;
}

/* check whether two FIDs belong to different MDT. */
static int mdt_fids_different_target(struct mdt_thread_info *info,
				     const struct lu_fid *fid1,
				     const struct lu_fid *fid2)
{
	const struct lu_env *env = info->mti_env;
	struct mdt_device *mdt = info->mti_mdt;
	struct lu_seq_range *range = &info->mti_range;
	struct seq_server_site *ss;
	__u32 index1, index2;
	int rc;

	if (fid_seq(fid1) == fid_seq(fid2))
		return 0;

	ss = mdt->mdt_lu_dev.ld_site->ld_seq_site;

	range->lsr_flags = LU_SEQ_RANGE_MDT;
	rc = fld_server_lookup(env, ss->ss_server_fld, fid1->f_seq, range);
	if (rc)
		return rc;

	index1 = range->lsr_index;

	rc = fld_server_lookup(env, ss->ss_server_fld, fid2->f_seq, range);
	if (rc)
		return rc;

	index2 = range->lsr_index;

	return index1 != index2;
}

/**
 * Check whether \a child is remote object on \a parent.
 *
 * \param[in]  info	thread environment
 * \param[in]  parent	parent object, it's the same as child object in
 *			getattr_by_fid
 * \param[in]  child	child object
 *
 * \retval 1	is remote object.
 * \retval 0	isn't remote object.
 * \retval < 1  error code
 */
int mdt_is_remote_object(struct mdt_thread_info *info,
			 struct mdt_object *parent,
			 struct mdt_object *child)
{
	struct lu_buf *buf = &info->mti_big_buf;
	struct linkea_data ldata = { NULL };
	struct link_ea_header *leh;
	struct link_ea_entry *lee;
	struct lu_name name;
	struct lu_fid pfid;
	int reclen;
	int i;
	int rc;

	ENTRY;

	if (fid_is_root(mdt_object_fid(child)))
		RETURN(0);

	if (likely(parent != child)) {
		if (mdt_object_remote(parent) ^ mdt_object_remote(child))
			RETURN(1);

		if (!mdt_object_remote(parent) && !mdt_object_remote(child))
			RETURN(0);

		rc = mdt_fids_different_target(info, mdt_object_fid(parent),
					       mdt_object_fid(child));
		RETURN(rc);
	}

	/* client < 2.13.52 getattr_by_fid parent and child are the same */
	buf = lu_buf_check_and_alloc(buf, PATH_MAX);
	if (!buf->lb_buf)
		RETURN(-ENOMEM);

	ldata.ld_buf = buf;
	rc = mdt_links_read(info, child, &ldata);
	/* can't read linkea, just assume it's remote object */
	if (rc == -ENOENT || rc == -ENODATA)
		RETURN(1);
	if (rc)
		RETURN(rc);

	leh = buf->lb_buf;
	lee = (struct link_ea_entry *)(leh + 1);
	for (i = 0; i < leh->leh_reccount; i++) {
		linkea_entry_unpack(lee, &reclen, &name, &pfid);
		lee = (struct link_ea_entry *) ((char *)lee + reclen);
		if (mdt_fids_different_target(info, &pfid,
					      mdt_object_fid(child)))
			RETURN(1);
	}

	RETURN(0);
}

int mdt_pack_encctx_in_reply(struct mdt_thread_info *info,
			     struct mdt_object *child)
{
	struct lu_buf *buffer;
	struct mdt_body *repbody;
	struct req_capsule *pill = info->mti_pill;
	struct obd_export *exp = mdt_info_req(info)->rq_export;
	int rc = 0;

	if (!exp_connect_encrypt(exp))
		return rc;

	if (req_capsule_has_field(pill, &RMF_FILE_ENCCTX, RCL_SERVER) &&
	    req_capsule_get_size(pill, &RMF_FILE_ENCCTX, RCL_SERVER) != 0) {
		struct lu_attr la = { 0 };
		struct dt_object *dt = mdt_obj2dt(child);

		if (dt && dt->do_ops && dt->do_ops->do_attr_get)
			dt_attr_get(info->mti_env, mdt_obj2dt(child), &la);

		if (la.la_valid & LA_FLAGS && la.la_flags & LUSTRE_ENCRYPT_FL) {
			buffer = &info->mti_buf;

			/* fill reply buffer with encryption context now */
			buffer->lb_len =
				req_capsule_get_size(pill, &RMF_FILE_ENCCTX,
						     RCL_SERVER);
			buffer->lb_buf =
				req_capsule_server_get(pill, &RMF_FILE_ENCCTX);
			rc = mo_xattr_get(info->mti_env,
					  mdt_object_child(child),
					  buffer,
					  LL_XATTR_NAME_ENCRYPTION_CONTEXT);
			if (unlikely(rc == -ENODATA))
				/* For compatibility with 2.14 */
				rc = mo_xattr_get(info->mti_env,
					  mdt_object_child(child),
					  buffer,
					  LL_XATTR_NAME_ENCRYPTION_CONTEXT_OLD);
			if (rc >= 0) {
				CDEBUG(D_SEC,
				       "found encryption ctx of size %d for "DFID"\n",
				       rc, PFID(mdt_object_fid(child)));

				repbody = req_capsule_server_get(pill,
								 &RMF_MDT_BODY);
				repbody->mbo_valid |= OBD_MD_ENCCTX;
				if (rc < buffer->lb_len)
					req_capsule_shrink(pill,
							   &RMF_FILE_ENCCTX, rc,
							   RCL_SERVER);
				rc = 0;
			} else {
				CDEBUG(D_SEC,
				       "encryption ctx not found for "DFID": rc = %d\n",
				       PFID(mdt_object_fid(child)), rc);
				req_capsule_shrink(pill, &RMF_FILE_ENCCTX, 0,
						   RCL_SERVER);
				/* handling -ENOENT is important because it may
				 * change object state in DNE env dropping
				 * LOHA_EXISTS flag, it is important to return
				 * that to the caller.
				 * Check LU-13115 for details.
				 */
				if (rc != -ENOENT)
					rc = 0;
			}
		} else {
			req_capsule_shrink(pill, &RMF_FILE_ENCCTX, 0,
					   RCL_SERVER);
		}
	}
	return rc;
}
