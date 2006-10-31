/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004-2006 Cluster File Systems, Inc.
 *   Author: Lai Siyao <lsy@clusterfs.com>
 *   Author: Fan Yong <fanyong@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/config.h>
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
#include <asm/segment.h>

#include <libcfs/kp30.h>
#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_dlm.h>
#include <lustre_lib.h>
#include <lustre_ucache.h>

#include "mdt_internal.h"

static void mdt_identity_entry_init(struct upcall_cache_entry *entry,
                                    void *unused)
{
        entry->u.identity.mi_uc_entry = entry;
}

static void mdt_identity_entry_free(struct upcall_cache *cache,
                                    struct upcall_cache_entry *entry)
{
        struct mdt_identity *identity = &entry->u.identity;

        if (identity->mi_ginfo)
                groups_free(identity->mi_ginfo);

        if (identity->mi_nperms) {
                LASSERT(identity->mi_perms);
                OBD_FREE(identity->mi_perms,
                         identity->mi_nperms * sizeof(struct mdt_setxid_perm));
        }
}

static int mdt_identity_do_upcall(struct upcall_cache *cache,
                                  struct upcall_cache_entry *entry)
{
        char keystr[16];
        char *argv[] = {
                  [0] = cache->uc_upcall,
                  [1] = cache->uc_name,
                  [2] = keystr,
                  [3] = NULL
        };
        char *envp[] = {
                  [0] = "HOME=/",
                  [1] = "PATH=/sbin:/usr/sbin",
                  [2] = NULL
        };
        int rc;
        ENTRY;

        snprintf(keystr, sizeof(keystr), LPU64, entry->ue_key);

        LASSERTF(strcmp(cache->uc_upcall, "NONE"), "no upcall set!");
        CDEBUG(D_INFO, "The upcall is: %s \n", cache->uc_upcall);

        rc = USERMODEHELPER(argv[0], argv, envp);
        if (rc < 0) {
                CERROR("%s: error invoking upcall %s %s %s: rc %d; "
                       "check /proc/fs/lustre/mdt/%s/identity_upcall\n",
                       cache->uc_name, argv[0], argv[1], argv[2], rc,
                       cache->uc_name);
        } else {
                CDEBUG(D_HA, "%s: invoked upcall %s %s %s\n", cache->uc_name,
                       argv[0], argv[1], argv[2]);
                rc = 0;
        }
        RETURN(rc);
}

static int mdt_identity_parse_downcall(struct upcall_cache *cache,
                                       struct upcall_cache_entry *entry,
                                       void *args)
{
        struct mdt_identity *identity = &entry->u.identity;
        struct identity_downcall_data *data = args;
        struct group_info *ginfo;
        struct mdt_setxid_perm *perms = NULL;
        int size, i;
        ENTRY;

        LASSERT(data);
        if (data->idd_ngroups > NGROUPS_MAX)
                return -E2BIG;

        ginfo = groups_alloc(data->idd_ngroups);
        if (!ginfo) {
                CERROR("failed to alloc %d groups\n", data->idd_ngroups);
                RETURN(-ENOMEM);
        }

        groups_from_list(ginfo, data->idd_groups);
        groups_sort(ginfo);
        identity->mi_ginfo = ginfo;

        if (data->idd_nperms) {
                size = data->idd_nperms * sizeof(*perms);
                OBD_ALLOC(perms, size);
                if (!perms) {
                        CERROR("failed to alloc %d permissions\n",
                               data->idd_nperms);
                        put_group_info(ginfo);
                        RETURN(-ENOMEM);
                }
                for (i = 0; i < data->idd_nperms; i++) {
                        perms[i].mp_nid = data->idd_perms[i].pdd_nid;
                        perms[i].mp_perm = data->idd_perms[i].pdd_perm;
                }
        }

        identity->mi_uid = data->idd_uid;
        identity->mi_gid = data->idd_gid;
        identity->mi_ginfo = ginfo;
        identity->mi_nperms = data->idd_nperms;
        identity->mi_perms = perms;

        CDEBUG(D_OTHER, "parse mdt identity@%p: %d:%d, ngroups %u, nperms %u\n",
               identity, identity->mi_uid, identity->mi_gid,
               identity->mi_ginfo->ngroups, identity->mi_nperms);

        RETURN(0);
}

struct mdt_identity *mdt_identity_get(struct upcall_cache *cache, __u32 uid)
{
        struct upcall_cache_entry *entry;

        if (!cache)
                return NULL;

        entry = upcall_cache_get_entry(cache, (__u64)uid, NULL);
        if (IS_ERR(entry)) {
                CERROR("upcall_cache_get_entry failed: %ld\n", PTR_ERR(entry));
                return NULL;
        }

        return &entry->u.identity;
}

void mdt_identity_put(struct upcall_cache *cache, struct mdt_identity *identity)
{
        if (!cache)
                return;

        LASSERT(identity);
        upcall_cache_put_entry(cache, identity->mi_uc_entry);
}

struct upcall_cache_ops mdt_identity_upcall_cache_ops = {
        .init_entry     = mdt_identity_entry_init,
        .free_entry     = mdt_identity_entry_free,
        .do_upcall      = mdt_identity_do_upcall,
        .parse_downcall = mdt_identity_parse_downcall,
};

void mdt_flush_identity(struct upcall_cache *cache, int uid)
{
        if (uid < 0)
                upcall_cache_flush_idle(cache);
        else
                upcall_cache_flush_one(cache, (__u64)uid, NULL);
}

__u32 mdt_identity_get_setxid_perm(struct mdt_identity *identity,
                                   __u32 is_rmtclient, lnet_nid_t nid)
{
        struct mdt_setxid_perm *perm = identity->mi_perms;
        int i;

        for (i = 0; i < identity->mi_nperms; i++) {
                if ((perm[i].mp_nid != LNET_NID_ANY) && (perm[i].mp_nid != nid))
                        continue;
                return perm[i].mp_perm;
        }

        /* default */
        return is_rmtclient ? 0 : LUSTRE_SETGRP_PERM;
}

int mdt_pack_remote_perm(struct mdt_thread_info *info, struct mdt_object *o,
                         void *buf)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct md_ucred         *uc = mdt_ucred(info);
        struct md_object        *next = mdt_object_child(o);
        struct mdt_export_data  *med = mdt_req2med(req);
        struct mdt_remote_perm  *perm = buf;

        ENTRY;

        /* remote client request always pack ptlrpc_user_desc! */
        LASSERT(perm);

        if (!med->med_rmtclient)
                RETURN(-EBADE);

        if ((uc->mu_valid != UCRED_OLD) && (uc->mu_valid != UCRED_NEW))
                RETURN(-EINVAL);

        perm->rp_uid = uc->mu_o_uid;
        perm->rp_gid = uc->mu_o_gid;
        perm->rp_fsuid = uc->mu_o_fsuid;
        perm->rp_fsgid = uc->mu_o_fsgid;

        perm->rp_access_perm = 0;
        if (mo_permission(info->mti_env, next, MAY_READ) == 0)
                perm->rp_access_perm |= MAY_READ;
        if (mo_permission(info->mti_env, next, MAY_WRITE) == 0)
                perm->rp_access_perm |= MAY_WRITE;
        if (mo_permission(info->mti_env, next, MAY_EXEC) == 0)
                perm->rp_access_perm |= MAY_EXEC;

        RETURN(0);
}
