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
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mdt/mdt_idmap.c
 *
 * Author: Lai Siyao <lsy@clusterfs.com>
 * Author: Fan Yong <fanyong@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/kmod.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

#include <libcfs/libcfs.h>
#include <libcfs/lucache.h>
#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_dlm.h>
#include <lustre_sec.h>
#include <lustre_lib.h>

#include "mdt_internal.h"

int mdt_init_idmap(struct tgt_session_info *tsi)
{
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	struct mdt_export_data *med = mdt_req2med(req);
	struct obd_export *exp = req->rq_export;
	char *client = libcfs_nid2str(req->rq_peer.nid);
	int rc = 0;
	ENTRY;

	if (exp_connect_rmtclient(exp)) {
		mutex_lock(&med->med_idmap_mutex);
		if (!med->med_idmap)
			med->med_idmap = lustre_idmap_init();
		mutex_unlock(&med->med_idmap_mutex);

		if (IS_ERR(med->med_idmap)) {
			long err = PTR_ERR(med->med_idmap);

			med->med_idmap = NULL;
			CERROR("%s: client %s -> target %s "
			       "failed to init idmap [%ld]!\n",
			       tgt_name(tsi->tsi_tgt), client,
			       tgt_name(tsi->tsi_tgt), err);
			RETURN(err);
		} else if (!med->med_idmap) {
			CERROR("%s: client %s -> target %s "
			       "failed to init(2) idmap!\n",
			       tgt_name(tsi->tsi_tgt), client,
			       tgt_name(tsi->tsi_tgt));
			RETURN(-ENOMEM);
		}

		CDEBUG(D_SEC, "%s: client %s -> target %s is remote.\n",
			tgt_name(tsi->tsi_tgt), client,
			tgt_name(tsi->tsi_tgt));
		/* NB, MDS_CONNECT establish root idmap too! */
		rc = mdt_handle_idmap(tsi);
	}
	RETURN(rc);
}

void mdt_cleanup_idmap(struct mdt_export_data *med)
{
	mutex_lock(&med->med_idmap_mutex);
        if (med->med_idmap != NULL) {
                lustre_idmap_fini(med->med_idmap);
                med->med_idmap = NULL;
        }
	mutex_unlock(&med->med_idmap_mutex);
}

static inline void mdt_revoke_export_locks(struct obd_export *exp)
{
        /* don't revoke locks during recovery */
        if (exp->exp_obd->obd_recovering)
                return;

        ldlm_revoke_export_locks(exp);
}

int mdt_handle_idmap(struct tgt_session_info *tsi)
{
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	struct mdt_device	*mdt = mdt_exp2dev(req->rq_export);
        struct mdt_export_data *med;
        struct ptlrpc_user_desc *pud = req->rq_user_desc;
        struct md_identity *identity;
        __u32 opc;
        int rc = 0;
        ENTRY;

        if (!req->rq_export)
                RETURN(0);

        med = mdt_req2med(req);
	if (!exp_connect_rmtclient(req->rq_export))
                RETURN(0);

        opc = lustre_msg_get_opc(req->rq_reqmsg);
        /* Bypass other opc */
        if ((opc != SEC_CTX_INIT) && (opc != SEC_CTX_INIT_CONT) &&
            (opc != SEC_CTX_FINI) && (opc != MDS_CONNECT))
                RETURN(0);

        LASSERT(med->med_idmap);

        if (unlikely(!pud)) {
                CDEBUG(D_SEC, "remote client must run with rq_user_desc "
                       "present\n");
                RETURN(-EACCES);
        }

	if (!uid_valid(make_kuid(&init_user_ns, req->rq_auth_mapped_uid))) {
                CDEBUG(D_SEC, "invalid authorized mapped uid, please check "
                       "/etc/lustre/idmap.conf!\n");
                RETURN(-EACCES);
        }

        if (is_identity_get_disabled(mdt->mdt_identity_cache)) {
                CDEBUG(D_SEC, "remote client must run with identity_get "
                       "enabled!\n");
                RETURN(-EACCES);
        }

        identity = mdt_identity_get(mdt->mdt_identity_cache,
                                    req->rq_auth_mapped_uid);
        if (IS_ERR(identity)) {
                CDEBUG(D_SEC, "can't get mdt identity(%u), no mapping added\n",
                       req->rq_auth_mapped_uid);
                RETURN(-EACCES);
        }

        switch (opc) {
                case SEC_CTX_INIT:
                case SEC_CTX_INIT_CONT:
                case MDS_CONNECT:
                        rc = lustre_idmap_add(med->med_idmap,
                                              pud->pud_uid, identity->mi_uid,
                                              pud->pud_gid, identity->mi_gid);
                        break;
                case SEC_CTX_FINI:
                        rc = lustre_idmap_del(med->med_idmap,
                                              pud->pud_uid, identity->mi_uid,
                                              pud->pud_gid, identity->mi_gid);
                        break;
        }

        mdt_identity_put(mdt->mdt_identity_cache, identity);

        if (rc)
                RETURN(rc);

        switch (opc) {
                case SEC_CTX_INIT:
                case SEC_CTX_INIT_CONT:
                case SEC_CTX_FINI:
                        mdt_revoke_export_locks(req->rq_export);
                        break;
        }

        RETURN(0);
}

int ptlrpc_user_desc_do_idmap(struct ptlrpc_request *req,
                              struct ptlrpc_user_desc *pud)
{
        struct mdt_export_data    *med = mdt_req2med(req);
        struct lustre_idmap_table *idmap = med->med_idmap;
        uid_t uid, fsuid;
        gid_t gid, fsgid;

        /* Only remote client need desc_to_idmap. */
        if (!exp_connect_rmtclient(req->rq_export))
                return 0;

        uid = lustre_idmap_lookup_uid(NULL, idmap, 0, pud->pud_uid);
        if (uid == CFS_IDMAP_NOTFOUND) {
                CDEBUG(D_SEC, "no mapping for uid %u\n", pud->pud_uid);
                return -EACCES;
        }

        if (pud->pud_uid == pud->pud_fsuid) {
                fsuid = uid;
        } else {
                fsuid = lustre_idmap_lookup_uid(NULL, idmap, 0, pud->pud_fsuid);
                if (fsuid == CFS_IDMAP_NOTFOUND) {
                        CDEBUG(D_SEC, "no mapping for fsuid %u\n",
                               pud->pud_fsuid);
                        return -EACCES;
                }
        }

        gid = lustre_idmap_lookup_gid(NULL, idmap, 0, pud->pud_gid);
        if (gid == CFS_IDMAP_NOTFOUND) {
                CDEBUG(D_SEC, "no mapping for gid %u\n", pud->pud_gid);
                return -EACCES;
        }

        if (pud->pud_gid == pud->pud_fsgid) {
                fsgid = gid;
        } else {
                fsgid = lustre_idmap_lookup_gid(NULL, idmap, 0, pud->pud_fsgid);
                if (fsgid == CFS_IDMAP_NOTFOUND) {
                        CDEBUG(D_SEC, "no mapping for fsgid %u\n",
                               pud->pud_fsgid);
                        return -EACCES;
                }
        }

        pud->pud_uid = uid;
        pud->pud_gid = gid;
        pud->pud_fsuid = fsuid;
        pud->pud_fsgid = fsgid;

        return 0;
}

/*
 * Reverse mapping
 */
void mdt_body_reverse_idmap(struct mdt_thread_info *info, struct mdt_body *body)
{
        struct ptlrpc_request     *req = mdt_info_req(info);
	struct lu_ucred           *uc = mdt_ucred(info);
        struct mdt_export_data    *med = mdt_req2med(req);
        struct lustre_idmap_table *idmap = med->med_idmap;

        if (!exp_connect_rmtclient(info->mti_exp))
                return;

	if (body->mbo_valid & OBD_MD_FLUID) {
		uid_t uid;

		uid = lustre_idmap_lookup_uid(uc, idmap, 1, body->mbo_uid);

		if (uid == CFS_IDMAP_NOTFOUND) {
			uid = NOBODY_UID;
			if (body->mbo_valid & OBD_MD_FLMODE)
				body->mbo_mode = (body->mbo_mode & ~S_IRWXU) |
					     ((body->mbo_mode & S_IRWXO) << 6);
		}

		body->mbo_uid = uid;
	}

	if (body->mbo_valid & OBD_MD_FLGID) {
		gid_t gid;

		gid = lustre_idmap_lookup_gid(uc, idmap, 1, body->mbo_gid);

		if (gid == CFS_IDMAP_NOTFOUND) {
			gid = NOBODY_GID;
			if (body->mbo_valid & OBD_MD_FLMODE)
				body->mbo_mode = (body->mbo_mode & ~S_IRWXG) |
					     ((body->mbo_mode & S_IRWXO) << 3);
		}

		body->mbo_gid = gid;
        }
}

/* Do not ignore root_squash for non-setattr case. */
int mdt_fix_attr_ucred(struct mdt_thread_info *info, __u32 op)
{
        struct ptlrpc_request     *req = mdt_info_req(info);
	struct lu_ucred           *uc = mdt_ucred_check(info);
        struct lu_attr            *attr = &info->mti_attr.ma_attr;
        struct mdt_export_data    *med = mdt_req2med(req);
        struct lustre_idmap_table *idmap = med->med_idmap;

	if (uc == NULL)
		return -EINVAL;

        if (op != REINT_SETATTR) {
		if ((attr->la_valid & LA_UID) && (attr->la_uid != -1))
			attr->la_uid = uc->uc_fsuid;
		/* for S_ISGID, inherit gid from his parent, such work will be
		 * done in cmm/mdd layer, here set all cases as uc->uc_fsgid. */
		if ((attr->la_valid & LA_GID) && (attr->la_gid != -1))
			attr->la_gid = uc->uc_fsgid;
        } else if (exp_connect_rmtclient(info->mti_exp)) {
                /* NB: -1 case will be handled by mdt_fix_attr() later. */
                if ((attr->la_valid & LA_UID) && (attr->la_uid != -1)) {
                        uid_t uid = lustre_idmap_lookup_uid(uc, idmap, 0,
                                                            attr->la_uid);

                        if (uid == CFS_IDMAP_NOTFOUND) {
                                CDEBUG(D_SEC, "Deny chown to uid %u\n",
                                       attr->la_uid);
                                return -EPERM;
                        }

                        attr->la_uid = uid;
                }
                if ((attr->la_valid & LA_GID) && (attr->la_gid != -1)) {
                        gid_t gid = lustre_idmap_lookup_gid(uc, idmap, 0,
                                                            attr->la_gid);

                        if (gid == CFS_IDMAP_NOTFOUND) {
                                CDEBUG(D_SEC, "Deny chown to gid %u\n",
                                       attr->la_gid);
                                return -EPERM;
                        }

                        attr->la_gid = gid;
                }
        }

        return 0;
}
