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
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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

#include "mdt_internal.h"
#include <lnet/nidstr.h>
#include <lustre_nodemap.h>

typedef enum ucred_init_type {
        NONE_INIT       = 0,
        BODY_INIT       = 1,
        REC_INIT        = 2
} ucred_init_type_t;

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

static int match_nosquash_list(struct rw_semaphore *sem,
			       struct list_head *nidlist,
			       lnet_nid_t peernid)
{
	int rc;
	ENTRY;
	down_read(sem);
	rc = cfs_match_nid(peernid, nidlist);
	up_read(sem);
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

	if (match_nosquash_list(&squash->rsi_sem,
				&squash->rsi_nosquash_nids,
				peernid)) {
		CDEBUG(D_OTHER, "%s is in nosquash_nids list\n",
		       libcfs_nid2str(peernid));
		RETURN(0);
	}

	CDEBUG(D_OTHER, "squash req from %s, (%d:%d/%x)=>(%d:%d/%x)\n",
	       libcfs_nid2str(peernid),
	       ucred->uc_fsuid, ucred->uc_fsgid, ucred->uc_cap,
	       squash->rsi_uid, squash->rsi_gid, 0);

	ucred->uc_fsuid = squash->rsi_uid;
	ucred->uc_fsgid = squash->rsi_gid;
	ucred->uc_cap = 0;
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

static int new_init_ucred(struct mdt_thread_info *info, ucred_init_type_t type,
                          void *buf)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct mdt_device       *mdt = info->mti_mdt;
        struct ptlrpc_user_desc *pud = req->rq_user_desc;
	struct lu_ucred         *ucred = mdt_ucred(info);
        lnet_nid_t               peernid = req->rq_peer.nid;
        __u32                    perm = 0;
        __u32                    remote = exp_connect_rmtclient(info->mti_exp);
        int                      setuid;
        int                      setgid;
        int                      rc = 0;

        ENTRY;

        LASSERT(req->rq_auth_gss);
        LASSERT(!req->rq_auth_usr_mdt);
        LASSERT(req->rq_user_desc);
	LASSERT(ucred != NULL);

	ucred->uc_valid = UCRED_INVALID;

	ucred->uc_o_uid   = pud->pud_uid;
	ucred->uc_o_gid   = pud->pud_gid;
	ucred->uc_o_fsuid = pud->pud_fsuid;
	ucred->uc_o_fsgid = pud->pud_fsgid;

	if (type == BODY_INIT) {
		struct mdt_body *body = (struct mdt_body *)buf;

		ucred->uc_suppgids[0] = body->mbo_suppgid;
		ucred->uc_suppgids[1] = -1;
	}

	/* sanity check: we expect the uid which client claimed is true */
	if (remote) {
		if (!uid_valid(make_kuid(&init_user_ns, req->rq_auth_mapped_uid))) {
			CDEBUG(D_SEC, "remote user not mapped, deny access!\n");
			RETURN(-EACCES);
		}

		if (ptlrpc_user_desc_do_idmap(req, pud))
			RETURN(-EACCES);

                if (req->rq_auth_mapped_uid != pud->pud_uid) {
                        CDEBUG(D_SEC, "remote client %s: auth/mapped uid %u/%u "
                               "while client claims %u:%u/%u:%u\n",
                               libcfs_nid2str(peernid), req->rq_auth_uid,
                               req->rq_auth_mapped_uid,
                               pud->pud_uid, pud->pud_gid,
                               pud->pud_fsuid, pud->pud_fsgid);
                        RETURN(-EACCES);
                }
        } else {
                if (req->rq_auth_uid != pud->pud_uid) {
                        CDEBUG(D_SEC, "local client %s: auth uid %u "
                               "while client claims %u:%u/%u:%u\n",
                               libcfs_nid2str(peernid), req->rq_auth_uid,
                               pud->pud_uid, pud->pud_gid,
                               pud->pud_fsuid, pud->pud_fsgid);
                        RETURN(-EACCES);
                }
        }

        if (is_identity_get_disabled(mdt->mdt_identity_cache)) {
                if (remote) {
                        CDEBUG(D_SEC, "remote client must run with identity_get "
                               "enabled!\n");
                        RETURN(-EACCES);
                } else {
			ucred->uc_identity = NULL;
                        perm = CFS_SETUID_PERM | CFS_SETGID_PERM |
                               CFS_SETGRP_PERM;
                }
        } else {
                struct md_identity *identity;

                identity = mdt_identity_get(mdt->mdt_identity_cache,
                                            pud->pud_uid);
                if (IS_ERR(identity)) {
                        if (unlikely(PTR_ERR(identity) == -EREMCHG &&
                                     !remote)) {
				ucred->uc_identity = NULL;
                                perm = CFS_SETUID_PERM | CFS_SETGID_PERM |
                                       CFS_SETGRP_PERM;
                        } else {
                                CDEBUG(D_SEC, "Deny access without identity: uid %u\n",
                                       pud->pud_uid);
                                RETURN(-EACCES);
                        }
                } else {
			ucred->uc_identity = identity;
			perm = mdt_identity_get_perm(ucred->uc_identity,
						     remote, peernid);
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

        /*
         * NB: remote client not allowed to setgroups anyway.
         */
	if (!remote && perm & CFS_SETGRP_PERM) {
		if (pud->pud_ngroups) {
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
			ucred->uc_ginfo = NULL;
		}
	} else {
		ucred->uc_suppgids[0] = -1;
		ucred->uc_suppgids[1] = -1;
		ucred->uc_ginfo = NULL;
	}

	ucred->uc_uid   = pud->pud_uid;
	ucred->uc_gid   = pud->pud_gid;
	ucred->uc_fsuid = pud->pud_fsuid;
	ucred->uc_fsgid = pud->pud_fsgid;

	/* process root_squash here. */
	mdt_root_squash(info, peernid);

	/* remove fs privilege for non-root user. */
	if (ucred->uc_fsuid)
		ucred->uc_cap = pud->pud_cap & ~CFS_CAP_FS_MASK;
	else
		ucred->uc_cap = pud->pud_cap;
	if (remote && !(perm & CFS_RMTOWN_PERM))
		ucred->uc_cap &= ~(CFS_CAP_SYS_RESOURCE_MASK |
				   CFS_CAP_CHOWN_MASK);
	ucred->uc_valid = UCRED_NEW;
	ucred_set_jobid(info, ucred);

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

int mdt_check_ucred(struct mdt_thread_info *info)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct mdt_device       *mdt = info->mti_mdt;
        struct ptlrpc_user_desc *pud = req->rq_user_desc;
	struct lu_ucred         *ucred = mdt_ucred(info);
        struct md_identity      *identity = NULL;
        lnet_nid_t               peernid = req->rq_peer.nid;
        __u32                    perm = 0;
        __u32                    remote = exp_connect_rmtclient(info->mti_exp);
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
        if (remote) {
		if (!uid_valid(make_kuid(&init_user_ns, req->rq_auth_mapped_uid))) {
                        CDEBUG(D_SEC, "remote user not mapped, deny access!\n");
                        RETURN(-EACCES);
                }

                if (ptlrpc_user_desc_do_idmap(req, pud))
                        RETURN(-EACCES);

                if (req->rq_auth_mapped_uid != pud->pud_uid) {
                        CDEBUG(D_SEC, "remote client %s: auth/mapped uid %u/%u "
                               "while client claims %u:%u/%u:%u\n",
                               libcfs_nid2str(peernid), req->rq_auth_uid,
                               req->rq_auth_mapped_uid,
                               pud->pud_uid, pud->pud_gid,
                               pud->pud_fsuid, pud->pud_fsgid);
                        RETURN(-EACCES);
                }
        } else {
                if (req->rq_auth_uid != pud->pud_uid) {
                        CDEBUG(D_SEC, "local client %s: auth uid %u "
                               "while client claims %u:%u/%u:%u\n",
                               libcfs_nid2str(peernid), req->rq_auth_uid,
                               pud->pud_uid, pud->pud_gid,
                               pud->pud_fsuid, pud->pud_fsgid);
                        RETURN(-EACCES);
                }
        }

        if (is_identity_get_disabled(mdt->mdt_identity_cache)) {
                if (remote) {
                        CDEBUG(D_SEC, "remote client must run with identity_get "
                               "enabled!\n");
                        RETURN(-EACCES);
                }
                RETURN(0);
        }

        identity = mdt_identity_get(mdt->mdt_identity_cache, pud->pud_uid);
        if (IS_ERR(identity)) {
                if (unlikely(PTR_ERR(identity) == -EREMCHG &&
                             !remote)) {
                        RETURN(0);
                } else {
                        CDEBUG(D_SEC, "Deny access without identity: uid %u\n",
                               pud->pud_uid);
                        RETURN(-EACCES);
               }
        }

        perm = mdt_identity_get_perm(identity, remote, peernid);
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

static void mdt_squash_nodemap_id(struct lu_ucred *ucred,
				  struct lu_nodemap *nodemap)
{
	if (ucred->uc_o_uid == nodemap->nm_squash_uid) {
		ucred->uc_fsuid = nodemap->nm_squash_uid;
		ucred->uc_fsgid = nodemap->nm_squash_gid;
		ucred->uc_cap = 0;
		ucred->uc_suppgids[0] = -1;
		ucred->uc_suppgids[1] = -1;
	}
}


static int old_init_ucred(struct mdt_thread_info *info,
			  struct mdt_body *body)
{
	struct lu_ucred		*uc = mdt_ucred(info);
	struct mdt_device	*mdt = info->mti_mdt;
	struct md_identity	*identity = NULL;
	struct lu_nodemap	*nodemap =
		info->mti_exp->exp_target_data.ted_nodemap;
	ENTRY;

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
	if (!is_identity_get_disabled(mdt->mdt_identity_cache)) {
		identity = mdt_identity_get(mdt->mdt_identity_cache,
					    uc->uc_fsuid);
		if (IS_ERR(identity)) {
			if (unlikely(PTR_ERR(identity) == -EREMCHG)) {
				identity = NULL;
			} else {
				CDEBUG(D_SEC, "Deny access without identity: "
				       "uid %u\n", uc->uc_fsuid);
				RETURN(-EACCES);
			}
		}
	}
	uc->uc_identity = identity;

	mdt_squash_nodemap_id(uc, nodemap);

	/* process root_squash here. */
	mdt_root_squash(info, mdt_info_req(info)->rq_peer.nid);

	/* remove fs privilege for non-root user. */
	if (uc->uc_fsuid)
		uc->uc_cap = body->mbo_capability & ~CFS_CAP_FS_MASK;
	else
		uc->uc_cap = body->mbo_capability;
	uc->uc_valid = UCRED_OLD;
	ucred_set_jobid(info, uc);

	RETURN(0);
}

static int old_init_ucred_reint(struct mdt_thread_info *info)
{
	struct lu_ucred		*uc = mdt_ucred(info);
	struct mdt_device	*mdt = info->mti_mdt;
	struct md_identity	*identity = NULL;
	struct lu_nodemap	*nodemap =
		info->mti_exp->exp_target_data.ted_nodemap;
	ENTRY;

	LASSERT(uc != NULL);

	uc->uc_fsuid = nodemap_map_id(nodemap, NODEMAP_UID,
				      NODEMAP_CLIENT_TO_FS, uc->uc_fsuid);
	uc->uc_fsgid = nodemap_map_id(nodemap, NODEMAP_GID,
				      NODEMAP_CLIENT_TO_FS, uc->uc_fsgid);

	uc->uc_valid = UCRED_INVALID;
	uc->uc_o_uid = uc->uc_o_fsuid = uc->uc_uid = uc->uc_fsuid;
	uc->uc_o_gid = uc->uc_o_fsgid = uc->uc_gid = uc->uc_fsgid;
	uc->uc_ginfo = NULL;

	if (!is_identity_get_disabled(mdt->mdt_identity_cache)) {
		identity = mdt_identity_get(mdt->mdt_identity_cache,
					    uc->uc_fsuid);
		if (IS_ERR(identity)) {
			if (unlikely(PTR_ERR(identity) == -EREMCHG)) {
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

	/* remove fs privilege for non-root user. */
	if (uc->uc_fsuid)
		uc->uc_cap &= ~CFS_CAP_FS_MASK;
	uc->uc_valid = UCRED_OLD;
	ucred_set_jobid(info, uc);

	RETURN(0);
}

int mdt_init_ucred(struct mdt_thread_info *info, struct mdt_body *body)
{
        struct ptlrpc_request *req = mdt_info_req(info);
	struct lu_ucred       *uc  = mdt_ucred(info);

	LASSERT(uc != NULL);
	if ((uc->uc_valid == UCRED_OLD) || (uc->uc_valid == UCRED_NEW))
		return 0;

        mdt_exit_ucred(info);

        if (!req->rq_auth_gss || req->rq_auth_usr_mdt || !req->rq_user_desc)
                return old_init_ucred(info, body);
        else
                return new_init_ucred(info, BODY_INIT, body);
}

int mdt_init_ucred_reint(struct mdt_thread_info *info)
{
        struct ptlrpc_request *req = mdt_info_req(info);
	struct lu_ucred       *uc  = mdt_ucred(info);

	LASSERT(uc != NULL);
	if ((uc->uc_valid == UCRED_OLD) || (uc->uc_valid == UCRED_NEW))
		return 0;

        mdt_exit_ucred(info);

        if (!req->rq_auth_gss || req->rq_auth_usr_mdt || !req->rq_user_desc)
                return old_init_ucred_reint(info);
        else
                return new_init_ucred(info, REC_INIT, NULL);
}

/* copied from lov/lov_ea.c, just for debugging, will be removed later */
void mdt_dump_lmm(int level, const struct lov_mds_md *lmm, __u64 valid)
{
	const struct lov_ost_data_v1	*lod;
	int				 i;
	__u16				 count;

	if (likely(!cfs_cdebug_show(level, DEBUG_SUBSYSTEM)))
		return;

	count = le16_to_cpu(((struct lov_user_md *)lmm)->lmm_stripe_count);

	CDEBUG(level, "objid "DOSTID", magic 0x%08X, pattern %#X\n",
	       POSTID(&lmm->lmm_oi), le32_to_cpu(lmm->lmm_magic),
	       le32_to_cpu(lmm->lmm_pattern));
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
	int			   i;

	if (likely(!cfs_cdebug_show(level, DEBUG_SUBSYSTEM)))
		return;

	lmm1 = &lmv->lmv_md_v1;
	CDEBUG(level, "magic 0x%08X, master %#X stripe_count %#x\n",
	       le32_to_cpu(lmm1->lmv_magic),
	       le32_to_cpu(lmm1->lmv_master_mdt_index),
	       le32_to_cpu(lmm1->lmv_stripe_count));

	if (le32_to_cpu(lmm1->lmv_magic) == LMV_MAGIC_STRIPE)
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

        CDEBUG(D_INFO, "Shrink to md_size = %d cookie/acl_size = %d"
	       " MDSCAPA = %llx, OSSCAPA = %llx\n",
	       md_size, acl_size,
	       (unsigned long long)(body->mbo_valid & OBD_MD_FLMDSCAPA),
	       (unsigned long long)(body->mbo_valid & OBD_MD_FLOSSCAPA));
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

        if (req_capsule_has_field(pill, &RMF_ACL, RCL_SERVER))
                req_capsule_shrink(pill, &RMF_ACL, acl_size, RCL_SERVER);
        else if (req_capsule_has_field(pill, &RMF_LOGCOOKIES, RCL_SERVER))
                req_capsule_shrink(pill, &RMF_LOGCOOKIES,
                                   acl_size, RCL_SERVER);

        if (req_capsule_has_field(pill, &RMF_CAPA1, RCL_SERVER) &&
	    !(body->mbo_valid & OBD_MD_FLMDSCAPA))
		req_capsule_shrink(pill, &RMF_CAPA1, 0, RCL_SERVER);

	if (req_capsule_has_field(pill, &RMF_CAPA2, RCL_SERVER) &&
	    !(body->mbo_valid & OBD_MD_FLOSSCAPA))
		req_capsule_shrink(pill, &RMF_CAPA2, 0, RCL_SERVER);

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
        RETURN(rc);
}


/* if object is dying, pack the lov/llog data,
 * parameter info->mti_attr should be valid at this point! */
int mdt_handle_last_unlink(struct mdt_thread_info *info, struct mdt_object *mo,
                           const struct md_attr *ma)
{
        struct mdt_body       *repbody;
        const struct lu_attr *la = &ma->ma_attr;
        int rc;
        ENTRY;

        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
        LASSERT(repbody != NULL);

        if (ma->ma_valid & MA_INODE)
                mdt_pack_attr2body(info, repbody, la, mdt_object_fid(mo));

        if (ma->ma_valid & MA_LOV) {
		CERROR("No need in LOV EA upon unlink\n");
		dump_stack();
        }
	repbody->mbo_eadatasize = 0;

	if (info->mti_mdt->mdt_lut.lut_oss_capa &&
	    exp_connect_flags(info->mti_exp) & OBD_CONNECT_OSS_CAPA &&
	    repbody->mbo_valid & OBD_MD_FLEASIZE) {
                struct lustre_capa *capa;

                capa = req_capsule_server_get(info->mti_pill, &RMF_CAPA2);
                LASSERT(capa);
                capa->lc_opc = CAPA_OPC_OSS_DESTROY;
                rc = mo_capa_get(info->mti_env, mdt_object_child(mo), capa, 0);
                if (rc)
                        RETURN(rc);

		repbody->mbo_valid |= OBD_MD_FLOSSCAPA;
        }

        RETURN(0);
}

static __u64 mdt_attr_valid_xlate(__u64 in, struct mdt_reint_record *rr,
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

	if (in & MDS_ATTR_FROM_OPEN)
		rr->rr_flags |= MRF_OPEN_TRUNC;
	if (in & MDS_OPEN_OWNEROVERRIDE)
		ma->ma_attr_flags |= MDS_OWNEROVERRIDE;
	if (in & MDS_ATTR_FORCE)
		ma->ma_attr_flags |= MDS_PERM_BYPASS;

	in &= ~(MDS_ATTR_MODE | MDS_ATTR_UID | MDS_ATTR_GID |
		MDS_ATTR_ATIME | MDS_ATTR_MTIME | MDS_ATTR_CTIME |
		MDS_ATTR_ATIME_SET | MDS_ATTR_CTIME_SET | MDS_ATTR_MTIME_SET |
		MDS_ATTR_SIZE | MDS_ATTR_BLOCKS | MDS_ATTR_ATTR_FLAG |
		MDS_ATTR_FORCE | MDS_ATTR_KILL_SUID | MDS_ATTR_KILL_SGID |
		MDS_ATTR_FROM_OPEN | MDS_OPEN_OWNEROVERRIDE);
	if (in != 0)
		CERROR("Unknown attr bits: "LPX64"\n", in);
	return out;
}

void mdt_set_capainfo(struct mdt_thread_info *info, int offset,
		      const struct lu_fid *fid, struct lustre_capa *capa)
{
	struct lu_capainfo *lci;

	LASSERT(offset >= 0 && offset < LU_CAPAINFO_MAX);
	if (!info->mti_mdt->mdt_lut.lut_mds_capa ||
	    !(exp_connect_flags(info->mti_exp) & OBD_CONNECT_MDS_CAPA))
		return;

	lci = lu_capainfo_get(info->mti_env);
	LASSERT(lci);
	lci->lci_fid[offset]  = *fid;
	lci->lci_capa[offset] = capa;
}

#ifdef DEBUG_CAPA
void mdt_dump_capainfo(struct mdt_thread_info *info)
{
	struct lu_capainfo *lci = lu_capainfo_get(info->mti_env);
	int i;

	if (lci == NULL)
		return;

	for (i = 0; i < LU_CAPAINFO_MAX; i++) {
		if (lci->lci_capa[i] == NULL) {
			CERROR("no capa for index %d "DFID"\n",
			       i, PFID(&lci->lci_fid[i]));
			continue;
		}
		if (lci->lci_capa[i] == BYPASS_CAPA) {
			CERROR("bypass for index %d "DFID"\n",
			       i, PFID(&lci->lci_fid[i]));
			continue;
		}
		DEBUG_CAPA(D_ERROR, lci->lci_capa[i], "index %d", i);
	}
}
#endif /* DEBUG_CAPA */

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

static int mdt_setattr_unpack_rec(struct mdt_thread_info *info)
{
	struct lu_ucred		*uc = mdt_ucred(info);
	struct md_attr		*ma = &info->mti_attr;
	struct lu_attr		*la = &ma->ma_attr;
	struct req_capsule	*pill = info->mti_pill;
	struct mdt_reint_record	*rr = &info->mti_rr;
	struct mdt_rec_setattr	*rec;
	struct lu_nodemap	*nodemap =
		info->mti_exp->exp_target_data.ted_nodemap;
        ENTRY;

        CLASSERT(sizeof(struct mdt_rec_setattr)== sizeof(struct mdt_rec_reint));
        rec = req_capsule_client_get(pill, &RMF_REC_REINT);
        if (rec == NULL)
                RETURN(-EFAULT);

	/* This prior initialization is needed for old_init_ucred_reint() */
	uc->uc_fsuid = rec->sa_fsuid;
	uc->uc_fsgid = rec->sa_fsgid;
	uc->uc_cap   = rec->sa_cap;
	uc->uc_suppgids[0] = rec->sa_suppgid;
	uc->uc_suppgids[1] = -1;

        rr->rr_fid1 = &rec->sa_fid;
	la->la_valid = mdt_attr_valid_xlate(rec->sa_valid, rr, ma);
	/*  If MDS_ATTR_xTIME is set without MDS_ATTR_xTIME_SET and
	 *  the client does not have OBD_CONNECT_FULL20, convert it
	 *  to LA_xTIME. LU-3036 */
	if (!(exp_connect_flags(info->mti_exp) & OBD_CONNECT_FULL20)) {
		if (!(rec->sa_valid & MDS_ATTR_ATIME_SET) &&
		     (rec->sa_valid & MDS_ATTR_ATIME))
			la->la_valid |= LA_ATIME;
		if (!(rec->sa_valid & MDS_ATTR_MTIME_SET) &&
		     (rec->sa_valid & MDS_ATTR_MTIME))
			la->la_valid |= LA_MTIME;
		if (!(rec->sa_valid & MDS_ATTR_CTIME_SET) &&
		     (rec->sa_valid & MDS_ATTR_CTIME))
			la->la_valid |= LA_CTIME;
	}
	la->la_mode  = rec->sa_mode;
	la->la_flags = rec->sa_attr_flags;
	la->la_uid   = nodemap_map_id(nodemap, NODEMAP_UID,
				      NODEMAP_CLIENT_TO_FS, rec->sa_uid);
	la->la_gid   = nodemap_map_id(nodemap, NODEMAP_GID,
				      NODEMAP_CLIENT_TO_FS, rec->sa_gid);
	la->la_size  = rec->sa_size;
	la->la_blocks = rec->sa_blocks;
	la->la_ctime = rec->sa_ctime;
	la->la_atime = rec->sa_atime;
	la->la_mtime = rec->sa_mtime;
	ma->ma_valid = MA_INODE;

	if (rec->sa_bias & MDS_DATA_MODIFIED)
		ma->ma_attr_flags |= MDS_DATA_MODIFIED;
	else
		ma->ma_attr_flags &= ~MDS_DATA_MODIFIED;

	if (rec->sa_bias & MDS_HSM_RELEASE)
		ma->ma_attr_flags |= MDS_HSM_RELEASE;
	else
		ma->ma_attr_flags &= ~MDS_HSM_RELEASE;

	if (req_capsule_get_size(pill, &RMF_CAPA1, RCL_CLIENT))
		mdt_set_capainfo(info, 0, rr->rr_fid1,
				 req_capsule_client_get(pill, &RMF_CAPA1));

	RETURN(0);
}

static int mdt_ioepoch_unpack(struct mdt_thread_info *info)
{
        struct req_capsule *pill = info->mti_pill;
        ENTRY;

        if (req_capsule_get_size(pill, &RMF_MDT_EPOCH, RCL_CLIENT))
                info->mti_ioepoch =
                        req_capsule_client_get(pill, &RMF_MDT_EPOCH);
        else
                info->mti_ioepoch = NULL;
        RETURN(info->mti_ioepoch == NULL ? -EFAULT : 0);
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

        /* Epoch may be absent */
        mdt_ioepoch_unpack(info);

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

static int mdt_hsm_release_unpack(struct mdt_thread_info *info)
{
	struct md_attr          *ma = &info->mti_attr;
	struct req_capsule      *pill = info->mti_pill;
	ENTRY;

	if (!(ma->ma_attr_flags & MDS_HSM_RELEASE))
		RETURN(0);

	req_capsule_extend(pill, &RQF_MDS_RELEASE_CLOSE);

	if (!(req_capsule_has_field(pill, &RMF_CLOSE_DATA, RCL_CLIENT) &&
	    req_capsule_field_present(pill, &RMF_CLOSE_DATA, RCL_CLIENT)))
		RETURN(-EFAULT);

	RETURN(0);
}

int mdt_close_unpack(struct mdt_thread_info *info)
{
        int rc;
        ENTRY;

        rc = mdt_ioepoch_unpack(info);
        if (rc)
                RETURN(rc);

	rc = mdt_setattr_unpack_rec(info);
	if (rc)
		RETURN(rc);

	rc = mdt_hsm_release_unpack(info);
	if (rc)
		RETURN(rc);

	RETURN(mdt_init_ucred_reint(info));
}

static int mdt_create_unpack(struct mdt_thread_info *info)
{
	struct lu_ucred         *uc  = mdt_ucred(info);
        struct mdt_rec_create   *rec;
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule      *pill = info->mti_pill;
        struct md_op_spec       *sp = &info->mti_spec;
        int rc;
        ENTRY;

        CLASSERT(sizeof(struct mdt_rec_create) == sizeof(struct mdt_rec_reint));
        rec = req_capsule_client_get(pill, &RMF_REC_REINT);
        if (rec == NULL)
                RETURN(-EFAULT);

	/* This prior initialization is needed for old_init_ucred_reint() */
	uc->uc_fsuid = rec->cr_fsuid;
	uc->uc_fsgid = rec->cr_fsgid;
	uc->uc_cap   = rec->cr_cap;
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

        if (req_capsule_get_size(pill, &RMF_CAPA1, RCL_CLIENT))
                mdt_set_capainfo(info, 0, rr->rr_fid1,
                                 req_capsule_client_get(pill, &RMF_CAPA1));
        mdt_set_capainfo(info, 1, rr->rr_fid2, BYPASS_CAPA);

	rc = mdt_name_unpack(pill, &RMF_NAME, &rr->rr_name, 0);
	if (rc < 0)
		RETURN(rc);

	if (S_ISLNK(attr->la_mode)) {
                const char *tgt = NULL;

                req_capsule_extend(pill, &RQF_MDS_REINT_CREATE_SYM);
                if (req_capsule_get_size(pill, &RMF_SYMTGT, RCL_CLIENT)) {
                        tgt = req_capsule_client_get(pill, &RMF_SYMTGT);
                        sp->u.sp_symname = tgt;
                }
                if (tgt == NULL)
                        RETURN(-EFAULT);
        } else {
                req_capsule_extend(pill, &RQF_MDS_REINT_CREATE_RMT_ACL);
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

	rc = mdt_dlmreq_unpack(info);
	RETURN(rc);
}

static int mdt_link_unpack(struct mdt_thread_info *info)
{
	struct lu_ucred         *uc  = mdt_ucred(info);
        struct mdt_rec_link     *rec;
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule      *pill = info->mti_pill;
        int rc;
        ENTRY;

        CLASSERT(sizeof(struct mdt_rec_link) == sizeof(struct mdt_rec_reint));
        rec = req_capsule_client_get(pill, &RMF_REC_REINT);
        if (rec == NULL)
                RETURN(-EFAULT);

	/* This prior initialization is needed for old_init_ucred_reint() */
	uc->uc_fsuid = rec->lk_fsuid;
	uc->uc_fsgid = rec->lk_fsgid;
	uc->uc_cap   = rec->lk_cap;
	uc->uc_suppgids[0] = rec->lk_suppgid1;
	uc->uc_suppgids[1] = rec->lk_suppgid2;

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

	rc = mdt_name_unpack(pill, &RMF_NAME, &rr->rr_name, 0);
	if (rc < 0)
		RETURN(rc);

	rc = mdt_dlmreq_unpack(info);

	RETURN(rc);
}

static int mdt_unlink_unpack(struct mdt_thread_info *info)
{
	struct lu_ucred         *uc  = mdt_ucred(info);
        struct mdt_rec_unlink   *rec;
        struct md_attr          *ma = &info->mti_attr;
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule      *pill = info->mti_pill;
        int rc;
        ENTRY;

        CLASSERT(sizeof(struct mdt_rec_unlink) == sizeof(struct mdt_rec_reint));
        rec = req_capsule_client_get(pill, &RMF_REC_REINT);
        if (rec == NULL)
                RETURN(-EFAULT);

	/* This prior initialization is needed for old_init_ucred_reint() */
	uc->uc_fsuid = rec->ul_fsuid;
	uc->uc_fsgid = rec->ul_fsgid;
	uc->uc_cap   = rec->ul_cap;
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

        if (req_capsule_get_size(pill, &RMF_CAPA1, RCL_CLIENT))
                mdt_set_capainfo(info, 0, rr->rr_fid1,
                                 req_capsule_client_get(pill, &RMF_CAPA1));

	rc = mdt_name_unpack(pill, &RMF_NAME, &rr->rr_name, 0);
	if (rc < 0)
		RETURN(rc);

        if (rec->ul_bias & MDS_VTX_BYPASS)
                ma->ma_attr_flags |= MDS_VTX_BYPASS;
        else
                ma->ma_attr_flags &= ~MDS_VTX_BYPASS;

	info->mti_spec.no_create = !!req_is_replay(mdt_info_req(info));

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
	struct lu_ucred         *uc = mdt_ucred(info);
        struct mdt_rec_rename   *rec;
        struct md_attr          *ma = &info->mti_attr;
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct req_capsule      *pill = info->mti_pill;
        int rc;
        ENTRY;

        CLASSERT(sizeof(struct mdt_rec_rename) == sizeof(struct mdt_rec_reint));
        rec = req_capsule_client_get(pill, &RMF_REC_REINT);
        if (rec == NULL)
                RETURN(-EFAULT);

	/* This prior initialization is needed for old_init_ucred_reint() */
	uc->uc_fsuid = rec->rn_fsuid;
	uc->uc_fsgid = rec->rn_fsgid;
	uc->uc_cap   = rec->rn_cap;
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

        if (req_capsule_get_size(pill, &RMF_CAPA1, RCL_CLIENT))
                mdt_set_capainfo(info, 0, rr->rr_fid1,
                                 req_capsule_client_get(pill, &RMF_CAPA1));
        if (req_capsule_get_size(pill, &RMF_CAPA2, RCL_CLIENT))
                mdt_set_capainfo(info, 1, rr->rr_fid2,
                                 req_capsule_client_get(pill, &RMF_CAPA2));

	rc = mdt_name_unpack(pill, &RMF_NAME, &rr->rr_name, 0);
	if (rc < 0)
		RETURN(rc);

	rc = mdt_name_unpack(pill, &RMF_SYMTGT, &rr->rr_tgt_name, 0);
	if (rc < 0)
		RETURN(rc);

        if (rec->rn_bias & MDS_VTX_BYPASS)
                ma->ma_attr_flags |= MDS_VTX_BYPASS;
        else
                ma->ma_attr_flags &= ~MDS_VTX_BYPASS;

        info->mti_spec.no_create = !!req_is_replay(mdt_info_req(info));


	rc = mdt_dlmreq_unpack(info);

	RETURN(rc);
}

/*
 * please see comment above LOV_MAGIC_V1_DEF
 */
static void mdt_fix_lov_magic(struct mdt_thread_info *info)
{
	struct mdt_reint_record *rr = &info->mti_rr;
	struct lov_user_md_v1   *v1;

	v1 = (void *)rr->rr_eadata;
	LASSERT(v1);

	if (unlikely(req_is_replay(mdt_info_req(info)))) {
		if (v1->lmm_magic == LOV_USER_MAGIC_V1) {
			v1->lmm_magic = LOV_MAGIC_V1_DEF;
		} else if (v1->lmm_magic == __swab32(LOV_USER_MAGIC_V1)) {
			v1->lmm_magic = __swab32(LOV_MAGIC_V1_DEF);
		} else if (v1->lmm_magic == LOV_USER_MAGIC_V3) {
			v1->lmm_magic = LOV_MAGIC_V3_DEF;
		} else if (v1->lmm_magic == __swab32(LOV_USER_MAGIC_V3)) {
			v1->lmm_magic = __swab32(LOV_MAGIC_V3_DEF);
		}
	}
}

static int mdt_open_unpack(struct mdt_thread_info *info)
{
	struct lu_ucred         *uc = mdt_ucred(info);
        struct mdt_rec_create   *rec;
        struct lu_attr          *attr = &info->mti_attr.ma_attr;
        struct req_capsule      *pill = info->mti_pill;
        struct mdt_reint_record *rr   = &info->mti_rr;
        struct ptlrpc_request   *req  = mdt_info_req(info);
        struct md_op_spec       *sp   = &info->mti_spec;
        ENTRY;

        CLASSERT(sizeof(struct mdt_rec_create) == sizeof(struct mdt_rec_reint));
        rec = req_capsule_client_get(pill, &RMF_REC_REINT);
        if (rec == NULL)
                RETURN(-EFAULT);

	/* This prior initialization is needed for old_init_ucred_reint() */
	uc->uc_fsuid = rec->cr_fsuid;
	uc->uc_fsgid = rec->cr_fsgid;
	uc->uc_cap   = rec->cr_cap;
	uc->uc_suppgids[0] = rec->cr_suppgid1;
	uc->uc_suppgids[1] = rec->cr_suppgid2;
	uc->uc_umask = rec->cr_umask;

        rr->rr_fid1   = &rec->cr_fid1;
        rr->rr_fid2   = &rec->cr_fid2;
        rr->rr_handle = &rec->cr_old_handle;
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
        info->mti_replayepoch = rec->cr_ioepoch;

        info->mti_cross_ref = !!(rec->cr_bias & MDS_CROSS_REF);

        if (req_capsule_get_size(pill, &RMF_CAPA1, RCL_CLIENT))
                mdt_set_capainfo(info, 0, rr->rr_fid1,
                                 req_capsule_client_get(pill, &RMF_CAPA1));
        if (req_is_replay(req) &&
            req_capsule_get_size(pill, &RMF_CAPA2, RCL_CLIENT)) {
#if 0
                mdt_set_capainfo(info, 1, rr->rr_fid2,
                                 req_capsule_client_get(pill, &RMF_CAPA2));
#else
                /*
                 * FIXME: capa in replay open request might have expired,
                 * bypass capa check. Security hole?
                 */
                mdt_set_capainfo(info, 0, rr->rr_fid1, BYPASS_CAPA);
                mdt_set_capainfo(info, 1, rr->rr_fid2, BYPASS_CAPA);
#endif
        }

	mdt_name_unpack(pill, &RMF_NAME, &rr->rr_name, MNF_FIX_ANON);

        if (req_capsule_field_present(pill, &RMF_EADATA, RCL_CLIENT)) {
                rr->rr_eadatalen = req_capsule_get_size(pill, &RMF_EADATA,
                                                        RCL_CLIENT);
                if (rr->rr_eadatalen > 0) {
                        rr->rr_eadata = req_capsule_client_get(pill,
                                                               &RMF_EADATA);
                        sp->u.sp_ea.eadatalen = rr->rr_eadatalen;
                        sp->u.sp_ea.eadata = rr->rr_eadata;
                        sp->no_create = !!req_is_replay(req);
			mdt_fix_lov_magic(info);
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

        RETURN(0);
}

static int mdt_setxattr_unpack(struct mdt_thread_info *info)
{
	struct mdt_reint_record	*rr	= &info->mti_rr;
	struct lu_ucred		*uc	= mdt_ucred(info);
	struct lu_attr		*attr	= &info->mti_attr.ma_attr;
	struct req_capsule	*pill	= info->mti_pill;
	struct mdt_rec_setxattr	*rec;
	int			 rc;
	ENTRY;


        CLASSERT(sizeof(struct mdt_rec_setxattr) ==
                         sizeof(struct mdt_rec_reint));

        rec = req_capsule_client_get(pill, &RMF_REC_REINT);
        if (rec == NULL)
                RETURN(-EFAULT);

	/* This prior initialization is needed for old_init_ucred_reint() */
	uc->uc_fsuid  = rec->sx_fsuid;
	uc->uc_fsgid  = rec->sx_fsgid;
	uc->uc_cap    = rec->sx_cap;
	uc->uc_suppgids[0] = rec->sx_suppgid1;
	uc->uc_suppgids[1] = -1;

        rr->rr_opcode = rec->sx_opcode;
        rr->rr_fid1   = &rec->sx_fid;
        attr->la_valid = rec->sx_valid;
        attr->la_ctime = rec->sx_time;
        attr->la_size = rec->sx_size;
        attr->la_flags = rec->sx_flags;

        if (req_capsule_get_size(pill, &RMF_CAPA1, RCL_CLIENT))
                mdt_set_capainfo(info, 0, rr->rr_fid1,
                                 req_capsule_client_get(pill, &RMF_CAPA1));
        else
                mdt_set_capainfo(info, 0, rr->rr_fid1, BYPASS_CAPA);

	rc = mdt_name_unpack(pill, &RMF_NAME, &rr->rr_name, 0);
	if (rc < 0)
		RETURN(rc);

        if (req_capsule_field_present(pill, &RMF_EADATA, RCL_CLIENT)) {
                rr->rr_eadatalen = req_capsule_get_size(pill, &RMF_EADATA,
                                                        RCL_CLIENT);
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

	if (mdt_dlmreq_unpack(info) < 0)
		RETURN(-EPROTO);

        RETURN(0);
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
	[REINT_MIGRATE]  = mdt_rename_unpack,
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
