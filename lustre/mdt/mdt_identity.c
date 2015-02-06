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
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mdt/mdt_identity.c
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
#include <lustre_lib.h>

#include "mdt_internal.h"

static void mdt_identity_entry_init(struct upcall_cache_entry *entry,
                                    void *unused)
{
        entry->u.identity.mi_uc_entry = entry;
}

static void mdt_identity_entry_free(struct upcall_cache *cache,
				    struct upcall_cache_entry *entry)
{
	struct md_identity *identity = &entry->u.identity;

	if (identity->mi_ginfo) {
		put_group_info(identity->mi_ginfo);
		identity->mi_ginfo = NULL;
	}

	if (identity->mi_nperms) {
		LASSERT(identity->mi_perms);
		OBD_FREE(identity->mi_perms,
			 identity->mi_nperms * sizeof(struct md_perm));
		identity->mi_nperms = 0;
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
        struct timeval start, end;
        int rc;
        ENTRY;

        /* There is race condition:
         * "uc_upcall" was changed just after "is_identity_get_disabled" check.
         */
	read_lock(&cache->uc_upcall_rwlock);
        CDEBUG(D_INFO, "The upcall is: '%s'\n", cache->uc_upcall);

        if (unlikely(!strcmp(cache->uc_upcall, "NONE"))) {
                CERROR("no upcall set\n");
                GOTO(out, rc = -EREMCHG);
        }

        argv[0] = cache->uc_upcall;
        snprintf(keystr, sizeof(keystr), LPU64, entry->ue_key);

	do_gettimeofday(&start);
	rc = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	do_gettimeofday(&end);
	if (rc < 0) {
                CERROR("%s: error invoking upcall %s %s %s: rc %d; "
                       "check /proc/fs/lustre/mdt/%s/identity_upcall, "
                       "time %ldus\n",
                       cache->uc_name, argv[0], argv[1], argv[2], rc,
                       cache->uc_name, cfs_timeval_sub(&end, &start, NULL));
        } else {
                CDEBUG(D_HA, "%s: invoked upcall %s %s %s, time %ldus\n",
                       cache->uc_name, argv[0], argv[1], argv[2],
                       cfs_timeval_sub(&end, &start, NULL));
                rc = 0;
        }
        EXIT;
out:
	read_unlock(&cache->uc_upcall_rwlock);
        return rc;
}

static int mdt_identity_parse_downcall(struct upcall_cache *cache,
				       struct upcall_cache_entry *entry,
				       void *args)
{
	struct md_identity *identity = &entry->u.identity;
	struct identity_downcall_data *data = args;
	struct group_info *ginfo = NULL;
	struct md_perm *perms = NULL;
	int size, i;
	ENTRY;

	LASSERT(data);
	if (data->idd_ngroups > NGROUPS_MAX)
		RETURN(-E2BIG);

	if (data->idd_ngroups > 0) {
		ginfo = groups_alloc(data->idd_ngroups);
		if (!ginfo) {
			CERROR("failed to alloc %d groups\n", data->idd_ngroups);
			RETURN(-ENOMEM);
		}

		lustre_groups_from_list(ginfo, data->idd_groups);
		lustre_groups_sort(ginfo);
	}

	if (data->idd_nperms) {
		size = data->idd_nperms * sizeof(*perms);
		OBD_ALLOC(perms, size);
		if (!perms) {
			CERROR("failed to alloc %d permissions\n",
			       data->idd_nperms);
			if (ginfo != NULL)
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
	       data->idd_ngroups, data->idd_nperms);

	RETURN(0);
}

struct md_identity *mdt_identity_get(struct upcall_cache *cache, __u32 uid)
{
        struct upcall_cache_entry *entry;

        if (!cache)
                return ERR_PTR(-ENOENT);

        entry = upcall_cache_get_entry(cache, (__u64)uid, NULL);
        if (IS_ERR(entry))
                return ERR_PTR(PTR_ERR(entry));
        else if (unlikely(!entry))
                return ERR_PTR(-ENOENT);
        else
                return &entry->u.identity;
}

void mdt_identity_put(struct upcall_cache *cache, struct md_identity *identity)
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

/*
 * If there is LNET_NID_ANY in perm[i].mp_nid,
 * it must be perm[0].mp_nid, and act as default perm.
 */
__u32 mdt_identity_get_perm(struct md_identity *identity,
                            __u32 is_rmtclient, lnet_nid_t nid)
{
        struct md_perm *perm;
        int i;

        if (!identity) {
                LASSERT(is_rmtclient == 0);
                return CFS_SETGRP_PERM;
        }

        perm = identity->mi_perms;
        /* check exactly matched nid first */
        for (i = identity->mi_nperms - 1; i > 0; i--) {
                if (perm[i].mp_nid != nid)
                        continue;
                return perm[i].mp_perm;
        }

        /* check LNET_NID_ANY then */
        if ((identity->mi_nperms > 0) &&
            ((perm[0].mp_nid == nid) || (perm[0].mp_nid == LNET_NID_ANY)))
                return perm[0].mp_perm;

        /* return default last */
        return is_rmtclient ? 0 : CFS_SETGRP_PERM;
}

int mdt_pack_remote_perm(struct mdt_thread_info *info, struct mdt_object *o,
                         void *buf)
{
	struct lu_ucred         *uc = mdt_ucred_check(info);
        struct md_object        *next = mdt_object_child(o);
        struct mdt_remote_perm  *perm = buf;

        ENTRY;

        /* remote client request always pack ptlrpc_user_desc! */
        LASSERT(perm);

        if (!exp_connect_rmtclient(info->mti_exp))
                RETURN(-EBADE);

	if (uc == NULL)
		RETURN(-EINVAL);

	perm->rp_uid = uc->uc_o_uid;
	perm->rp_gid = uc->uc_o_gid;
	perm->rp_fsuid = uc->uc_o_fsuid;
	perm->rp_fsgid = uc->uc_o_fsgid;

        perm->rp_access_perm = 0;
        if (mo_permission(info->mti_env, NULL, next, NULL, MAY_READ) == 0)
                perm->rp_access_perm |= MAY_READ;
        if (mo_permission(info->mti_env, NULL, next, NULL, MAY_WRITE) == 0)
                perm->rp_access_perm |= MAY_WRITE;
        if (mo_permission(info->mti_env, NULL, next, NULL, MAY_EXEC) == 0)
                perm->rp_access_perm |= MAY_EXEC;

        RETURN(0);
}
