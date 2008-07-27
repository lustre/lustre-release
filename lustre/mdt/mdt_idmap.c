/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
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

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/kmod.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

#include <libcfs/libcfs.h>
#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_dlm.h>
#include <lustre_sec.h>
#include <lustre_lib.h>
#include <lustre_ucache.h>

#include "mdt_internal.h"

int mdt_init_idmap(struct mdt_thread_info *info)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        char *client = libcfs_nid2str(req->rq_peer.nid);
        struct mdt_export_data *med = mdt_req2med(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct obd_connect_data *data, *reply;
        int rc = 0, remote;
        ENTRY;

        data = req_capsule_client_get(info->mti_pill, &RMF_CONNECT_DATA);
        reply = req_capsule_server_get(info->mti_pill, &RMF_CONNECT_DATA);
        if (data == NULL || reply == NULL)
                RETURN(-EFAULT);

        if (!req->rq_auth_gss || req->rq_auth_usr_mdt) {
                med->med_rmtclient = 0;
                reply->ocd_connect_flags &= ~OBD_CONNECT_RMT_CLIENT;
                RETURN(0);
        }

        remote = data->ocd_connect_flags & OBD_CONNECT_RMT_CLIENT;

        if (remote) {
                med->med_rmtclient = 1;
                if (!req->rq_auth_remote)
                        CDEBUG(D_SEC, "client (local realm) %s -> target %s "
                               "asked to be remote!\n", client, obd->obd_name);
        } else if (req->rq_auth_remote) {
                med->med_rmtclient = 1;
                CDEBUG(D_SEC, "client (remote realm) %s -> target %s forced "
                       "to be remote!\n", client, obd->obd_name);
        }

        if (med->med_rmtclient) {
                down(&med->med_idmap_sem);
                if (!med->med_idmap)
                        med->med_idmap = lustre_idmap_init();
                up(&med->med_idmap_sem);

                if (IS_ERR(med->med_idmap)) {
                        long err = PTR_ERR(med->med_idmap);

                        med->med_idmap = NULL;
                        CERROR("client %s -> target %s "
                               "failed to init idmap [%ld]!\n",
                               client, obd->obd_name, err);
                        RETURN(err);
                } else if (!med->med_idmap) {
                        CERROR("client %s -> target %s "
                               "failed to init(2) idmap!\n",
                               client, obd->obd_name);
                        RETURN(-ENOMEM);
                }

                reply->ocd_connect_flags &= ~OBD_CONNECT_LCL_CLIENT;
                CDEBUG(D_SEC, "client %s -> target %s is remote.\n",
                       client, obd->obd_name);

                /* NB, MDS_CONNECT establish root idmap too! */
                rc = mdt_handle_idmap(info);
        } else {
                if (req->rq_auth_uid == INVALID_UID) {
                        CDEBUG(D_SEC, "client %s -> target %s: user is not "
                               "authenticated!\n", client, obd->obd_name);
                        RETURN(-EACCES);
                }
                reply->ocd_connect_flags &= ~OBD_CONNECT_RMT_CLIENT;
        }

        RETURN(rc);
}

void mdt_cleanup_idmap(struct mdt_export_data *med)
{
        LASSERT(med->med_rmtclient);

        down(&med->med_idmap_sem);
        if (med->med_idmap != NULL) {
                lustre_idmap_fini(med->med_idmap);
                med->med_idmap = NULL;
        }
        up(&med->med_idmap_sem);
}

static inline void mdt_revoke_export_locks(struct obd_export *exp)
{
        /* don't revoke locks during recovery */
        if (exp->exp_obd->obd_recovering)
                return;

        ldlm_revoke_export_locks(exp);
}

int mdt_handle_idmap(struct mdt_thread_info *info)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        struct mdt_device *mdt = info->mti_mdt;
        struct mdt_export_data *med;
        struct ptlrpc_user_desc *pud = req->rq_user_desc;
        struct md_identity *identity;
        __u32 opc;
        int rc = 0;
        ENTRY;

        if (!req->rq_export)
                RETURN(0);

        med = mdt_req2med(req);
        if (!med->med_rmtclient)
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

        if (req->rq_auth_mapped_uid == INVALID_UID) {
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
        if (!med->med_rmtclient)
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
        struct md_ucred           *uc = mdt_ucred(info);
        struct mdt_export_data    *med = mdt_req2med(req);
        struct lustre_idmap_table *idmap = med->med_idmap;

        if (!med->med_rmtclient)
                return;

        if (body->valid & OBD_MD_FLUID) {
                uid_t uid = lustre_idmap_lookup_uid(uc, idmap, 1, body->uid);

                if (uid == CFS_IDMAP_NOTFOUND) {
                        uid = NOBODY_UID;
                        if (body->valid & OBD_MD_FLMODE)
                                body->mode = (body->mode & ~S_IRWXU) |
                                             ((body->mode & S_IRWXO) << 6);
                }

                body->uid = uid;
        }

        if (body->valid & OBD_MD_FLGID) {
                gid_t gid = lustre_idmap_lookup_gid(uc, idmap, 1, body->gid);

                if (gid == CFS_IDMAP_NOTFOUND) {
                        gid = NOBODY_GID;
                        if (body->valid & OBD_MD_FLMODE)
                                body->mode = (body->mode & ~S_IRWXG) |
                                             ((body->mode & S_IRWXO) << 3);
                }

                body->gid = gid;
        }
}

/* Do not ignore root_squash for non-setattr case. */
int mdt_fix_attr_ucred(struct mdt_thread_info *info, __u32 op)
{
        struct ptlrpc_request     *req = mdt_info_req(info);
        struct md_ucred           *uc = mdt_ucred(info);
        struct lu_attr            *attr = &info->mti_attr.ma_attr;
        struct mdt_export_data    *med = mdt_req2med(req);
        struct lustre_idmap_table *idmap = med->med_idmap;

        if ((uc->mu_valid != UCRED_OLD) && (uc->mu_valid != UCRED_NEW))
                return -EINVAL;

        if (op != REINT_SETATTR) {
                if ((attr->la_valid & LA_UID) && (attr->la_uid != -1))
                        attr->la_uid = uc->mu_fsuid;
                /* for S_ISGID, inherit gid from his parent, such work will be
                 * done in cmm/mdd layer, here set all cases as uc->mu_fsgid. */
                if ((attr->la_valid & LA_GID) && (attr->la_gid != -1))
                        attr->la_gid = uc->mu_fsgid;
        } else if (med->med_rmtclient) {
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
