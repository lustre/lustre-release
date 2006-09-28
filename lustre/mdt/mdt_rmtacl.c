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

#define MAX_CMD_LEN     256

static void mdt_rmtacl_entry_init(struct upcall_cache_entry *entry, void *args)
{
        struct rmtacl_upcall_data *data = args;
        struct mdt_rmtacl *acl = &entry->u.acl;
        char *cmd;

        /* we use address of this cache entry as handle */
        acl->ra_handle = (__u32)entry;
        OBD_ALLOC(cmd, strlen(data->aud_cmd) + 1);
        if (!cmd)
                return; /* upcall will fail later! */

        strcpy(cmd, data->aud_cmd);
        entry->u.acl.ra_cmd = cmd;
}

static void mdt_rmtacl_entry_free(struct upcall_cache *cache,
                                  struct upcall_cache_entry *entry)
{
        struct mdt_rmtacl *acl = &entry->u.acl;
        int len;

        if (acl->ra_cmd) {
                len = strlen(acl->ra_cmd) + 1;
                OBD_FREE(acl->ra_cmd, len);
        }

        if (acl->ra_buf) {
                len = strlen(acl->ra_buf) + 1;
                OBD_FREE(acl->ra_buf, len);
        }
}

static int mdt_rmtacl_upcall_compare(struct upcall_cache *cache,
                                     struct upcall_cache_entry *entry,
                                     __u64 key, void *args)
{
        struct rmtacl_upcall_data *data = args;

        LASSERT(entry && data);
        LASSERT(entry->u.acl.ra_cmd && data->aud_cmd);
        return strncmp(entry->u.acl.ra_cmd, data->aud_cmd, MAX_CMD_LEN);
}

static int mdt_rmtacl_downcall_compare(struct upcall_cache *cache,
                                       struct upcall_cache_entry *entry,
                                       __u64 key, void *args)
{
        struct rmtacl_downcall_data *data = args;

        return entry->u.acl.ra_handle - data->add_handle;
}

static int mdt_rmtacl_do_upcall(struct upcall_cache *cache,
                                struct upcall_cache_entry *entry)
{
        struct mdt_rmtacl *acl = &entry->u.acl;
        char handle[20] = "";
        char keystr[20] = "";
        char *argv[] = {
                  [0] = cache->uc_upcall,
                  [1] = cache->uc_name,
                  [2] = keystr,
                  [3] = handle,
                  [4] = acl->ra_cmd,
                  [5] = NULL
        };
        char *envp[] = {
                  [0] = "HOME=/",
                  [1] = "PATH=/bin:/usr/bin:/sbin:/usr/sbin",
                  [2] = NULL
        };
        int rc;
        ENTRY;

        if (!acl->ra_cmd)
                RETURN(-ENOMEM);

        snprintf(keystr, sizeof(keystr), LPU64, entry->ue_key);
        snprintf(handle, sizeof(handle), "%u", acl->ra_handle);

        LASSERTF(strcmp(cache->uc_upcall, "NONE"), "no upcall set!");

        CDEBUG(D_INFO, "%s: remote acl upcall %s %s %s %s %s\n",
               cache->uc_name, argv[0], argv[1], argv[2], argv[3], argv[4]);

        rc = USERMODEHELPER(argv[0], argv, envp);
        if (rc < 0) {
                CERROR("%s: error invoking upcall %s %s %s %s %s: rc %d; "
                       "check /proc/fs/lustre/mdt/%s/rmtacl_upcall\n",
                       cache->uc_name, argv[0], argv[1], argv[2], argv[3],
                       argv[4], rc, cache->uc_name);
        } else {
                CDEBUG(D_HA, "%s: invoked upcall %s %s %s %s %s\n",
                       cache->uc_name, argv[0], argv[1], argv[2], argv[3],
                       argv[4]);
                rc = 0;
        }
        RETURN(rc);
}

static int mdt_rmtacl_parse_downcall(struct upcall_cache *cache,
                                     struct upcall_cache_entry *entry,
                                     void *args)
{
        struct mdt_rmtacl *acl = &entry->u.acl;
        struct rmtacl_downcall_data *data;
        char *buf;
        int len;
        ENTRY;

        data = (struct rmtacl_downcall_data *)args;
        LASSERT(data);

        len = strlen(data->add_buf) + 1;
        OBD_ALLOC(buf, len);
        if (!buf)
                RETURN(-ENOMEM);

        memcpy(buf, data->add_buf, len);
        acl->ra_buf = buf;

        CDEBUG(D_OTHER, "parse mdt acl@%p: %s %s\n",
               acl, acl->ra_cmd, acl->ra_buf);

        RETURN(0);
}

struct upcall_cache_ops mdt_rmtacl_upcall_cache_ops = {
        .init_entry       = mdt_rmtacl_entry_init,
        .free_entry       = mdt_rmtacl_entry_free,
        .upcall_compare   = mdt_rmtacl_upcall_compare,
        .downcall_compare = mdt_rmtacl_downcall_compare,
        .do_upcall        = mdt_rmtacl_do_upcall,
        .parse_downcall   = mdt_rmtacl_parse_downcall,
};

int mdt_rmtacl_upcall(struct mdt_thread_info *info, unsigned long key,
                      char *cmd, struct lu_buf *buf)
{
        struct ptlrpc_request           *req = mdt_info_req(info);
        struct obd_device               *obd = req->rq_export->exp_obd;
        struct mdt_device               *mdt = info->mti_mdt;
        struct lvfs_ucred               uc;
        struct lvfs_run_ctxt            saved;
        struct rmtacl_upcall_data       data;
        struct upcall_cache_entry       *entry;
        char                            *tmp = NULL;
        int                             rc = 0;
        ENTRY;

        OBD_ALLOC(tmp, PAGE_SIZE);
        if (!tmp)
                RETURN(-ENOMEM);

        data.aud_cmd = cmd;

        uc.luc_uid      = info->mti_uc.mu_uid;
        uc.luc_gid      = info->mti_uc.mu_gid;
        uc.luc_fsuid    = info->mti_uc.mu_fsuid;
        uc.luc_fsgid    = info->mti_uc.mu_fsgid;
        uc.luc_cap      = info->mti_uc.mu_cap;
        uc.luc_umask    = info->mti_uc.mu_umask;
        uc.luc_ginfo    = info->mti_uc.mu_ginfo;
        uc.luc_identity = info->mti_uc.mu_identity;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        entry = upcall_cache_get_entry(mdt->mdt_rmtacl_cache, (__u64)key,
                                       &data);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);

        if (IS_ERR(entry))
                GOTO(out, rc = PTR_ERR(entry));

        if (buf->lb_len <= strlen(entry->u.acl.ra_buf))
                GOTO(out, rc = -EFAULT);

        memcpy(buf->lb_buf, entry->u.acl.ra_buf, strlen(entry->u.acl.ra_buf));
        /* remote acl operation expire at once! */
        UC_CACHE_SET_EXPIRED(entry);
        upcall_cache_put_entry(mdt->mdt_rmtacl_cache, entry);

out:
        if (rc)
                sprintf(buf->lb_buf, "server processing error: %d\n", rc);
        OBD_FREE(tmp, PAGE_SIZE);
        RETURN(0);
}
