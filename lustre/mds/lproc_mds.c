/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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
 *
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <asm/statfs.h>
#endif
#include <linux/obd.h>
#include <linux/obd_class.h>
#include <linux/lprocfs_status.h>
#include "mds_internal.h"

#ifndef LPROCFS
struct lprocfs_vars lprocfs_mds_obd_vars[]  = { {0} };
struct lprocfs_vars lprocfs_mds_module_vars[] = { {0} };
struct lprocfs_vars lprocfs_mdt_obd_vars[] = { {0} };
struct lprocfs_vars lprocfs_mdt_module_vars[] = { {0} };

atomic_t * lprocfs_alloc_mds_counters()
{
        return NULL;
}
void lprocfs_free_mds_counters(atomic_t *ptr)
{
        return;
}

#else

struct ll_mdscounters_opcode {
     __u32       opcode;
     const char *opname;
} ll_mdscounters_opcode_table[MDS_LAST_OPC_COUNT] = {
       { MDS_OPEN_COUNT,          "mds_open" },
       { MDS_CREATE_COUNT,        "mds_create" },
       { MDS_CLOSE_COUNT,         "mds_close" },
       { MDS_LINK_COUNT,          "mds_link" },
       { MDS_UNLINK_COUNT,        "mds_unlink" },
       { MDS_GETATTR_COUNT,       "mds_getattr" },
       { MDS_GETATTR_NAME_COUNT,  "mds_getattr_name" },
       { MDS_SETATTR_COUNT,       "mds_setattr" },
       { MDS_RENAME_COUNT,        "mds_rename" },
       { MDS_STATFS_COUNT,        "mds_statfs" },
};

const char* ll_mds_count_opcode2str(__u32 opcode)
{
        __u32 offset = opcode;

        LASSERT(offset < MDS_LAST_OPC_COUNT);
        LASSERT(ll_mdscounters_opcode_table[offset].opcode == opcode);
        return ll_mdscounters_opcode_table[offset].opname;
}

struct lprocfs_stats * lprocfs_alloc_mds_counters()
{
        struct lprocfs_stats *counters;
        int i;

        counters = lprocfs_alloc_stats(MDS_LAST_OPC_COUNT);

        for (i = 0; i < MDS_LAST_OPC_COUNT; i ++) {         
            lprocfs_counter_init(counters, i, 0, 
                                 (char *)ll_mds_count_opcode2str(i), "reqs");
        }
        return counters;
}

void lprocfs_free_mds_counters(struct lprocfs_stats *ptr)
{
        lprocfs_free_stats(ptr);
}

static int lprocfs_mds_rd_mntdev(char *page, char **start, off_t off, int count,
                                 int *eof, void *data)
{
        struct obd_device* obd = (struct obd_device *)data;

        LASSERT(obd != NULL);
        LASSERT(obd->u.mds.mds_vfsmnt->mnt_devname);
        *eof = 1;

        return snprintf(page, count, "%s\n",obd->u.mds.mds_vfsmnt->mnt_devname);
}

static int lprocfs_rd_mds_counters(char *page, char **start, off_t off,
                                          int count, int *eof, void *data)
{
        struct obd_device* obd = (struct obd_device *)data;
        int len = 0, n, i, j;
        struct lprocfs_counter  t, ret = { .lc_min = ~(__u64)0 };
        struct lprocfs_stats *stats;
        struct timeval now;

        LASSERT(obd != NULL);
        if (obd->u.mds.mds_counters == NULL)
                return 0;

        do_gettimeofday(&now);

        n = snprintf(page, count, "%-25s %lu.%lu secs.usecs\n",
                               "snapshot_time", now.tv_sec, now.tv_usec);
        page += n; len +=n; count -=n;

        stats = obd->u.mds.mds_counters;

        *eof = 1;
        for (i = 0; i < MDS_LAST_OPC_COUNT; i ++) {
                ret.lc_count = 0; 
                for (j = 0; j < num_online_cpus(); j++) {
                        struct lprocfs_counter *percpu_cntr =
                                &(stats->ls_percpu[j])->lp_cntr[i];
                        int centry;
                        do {
                                centry = 
                                   atomic_read(&percpu_cntr->lc_cntl.la_entry); 
                                t.lc_count = percpu_cntr->lc_count;
                        } while (centry != 
                                 atomic_read(&percpu_cntr->lc_cntl.la_entry) &&
                                 centry != 
                                 atomic_read(&percpu_cntr->lc_cntl.la_exit));
                        ret.lc_count += t.lc_count;
               } 
                n = snprintf(page, count, "%-25s "LPU64" \n", 
                                   ll_mds_count_opcode2str(i), ret.lc_count);
                page += n; len +=n; count -=n;
        }
        return (len);
}

static int lprocfs_mds_wr_evict_client(struct file *file, const char *buffer,
                                       unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct obd_export *doomed_exp = NULL;
        struct obd_uuid doomed;
        struct list_head *p;
        char tmpbuf[sizeof(doomed)];

        sscanf(buffer, "%40s", tmpbuf);
        obd_str2uuid(&doomed, tmpbuf);

        spin_lock(&obd->obd_dev_lock);
        list_for_each(p, &obd->obd_exports) {
                doomed_exp = list_entry(p, struct obd_export, exp_obd_chain);
                if (obd_uuid_equals(&doomed, &doomed_exp->exp_client_uuid)) {
                        class_export_get(doomed_exp);
                        break;
                }
                doomed_exp = NULL;
        }
        spin_unlock(&obd->obd_dev_lock);

        if (doomed_exp == NULL) {
                CERROR("can't disconnect %s: no export found\n",
                       doomed.uuid);
        } else {
                CERROR("evicting %s at adminstrative request\n",
                       doomed.uuid);
                ptlrpc_fail_export(doomed_exp);
                class_export_put(doomed_exp);
        }
        return count;
}

static int lprocfs_mds_wr_config_update(struct file *file, const char *buffer,
                                        unsigned long count, void *data)
{
        struct obd_device *obd = data;
        ENTRY;

        RETURN(mds_lov_update_config(obd, 0));
}

struct lprocfs_vars lprocfs_mds_obd_vars[] = {
        { "uuid",         lprocfs_rd_uuid,        0, 0 },
        { "blocksize",    lprocfs_rd_blksize,     0, 0 },
        { "kbytestotal",  lprocfs_rd_kbytestotal, 0, 0 },
        { "kbytesfree",   lprocfs_rd_kbytesfree,  0, 0 },
        { "kbytesavail",  lprocfs_rd_kbytesavail, 0, 0 },
        { "fstype",       lprocfs_rd_fstype,      0, 0 },
        { "filestotal",   lprocfs_rd_filestotal,  0, 0 },
        { "filesfree",    lprocfs_rd_filesfree,   0, 0 },
        { "mntdev",       lprocfs_mds_rd_mntdev,  0, 0 },
        { "recovery_status", lprocfs_obd_rd_recovery_status, 0, 0 },
        { "evict_client", 0, lprocfs_mds_wr_evict_client, 0 },
        { "config_update", 0, lprocfs_mds_wr_config_update, 0 },
        { "num_exports",  lprocfs_rd_num_exports, 0, 0 },
        { "counters", lprocfs_rd_mds_counters, 0, 0 },
        { 0 }
};

/*
 * group hash proc entries handler
 */
static int lprocfs_wr_group_info(struct file *file, const char *buffer,
                                 unsigned long count, void *data)
{
        struct {
                int             err;
                uid_t           uid;
                uint32_t        ngroups;
                gid_t          *groups;
        } param;
        gid_t   gids_local[NGROUPS_SMALL];
        gid_t  *gids = NULL;

        if (count != sizeof(param)) {
                CERROR("invalid data size %lu\n", count);
                return count;
        }
        if (copy_from_user(&param, buffer, count)) {
                CERROR("broken downcall\n");
                return count;
        }
        if (param.ngroups > NGROUPS_MAX) {
                CERROR("%d groups?\n", param.ngroups);
                return count;
        }

        if (param.ngroups <= NGROUPS_SMALL)
                gids = gids_local;
        else {
                OBD_ALLOC(gids, param.ngroups * sizeof(gid_t));
                if (!gids) {
                        CERROR("fail to alloc memory for %d gids\n",
                                param.ngroups);
                        return count;
                }
        }
        if (copy_from_user(gids, param.groups,
                           param.ngroups * sizeof(gid_t))) {
                CERROR("broken downcall\n");
                goto out;
        }

        mds_handle_group_downcall(param.err, param.uid,
                                  param.ngroups, gids);

out:
        if (gids && gids != gids_local)
                OBD_FREE(gids, param.ngroups * sizeof(gid_t));
        return count;
}
static int lprocfs_rd_expire(char *page, char **start, off_t off, int count,
                             int *eof, void *data)
{
        struct mds_grp_hash *hash = __mds_get_global_group_hash();

        *eof = 1;
        return snprintf(page, count, "%d\n", hash->gh_entry_expire);
}
static int lprocfs_wr_expire(struct file *file, const char *buffer,
                             unsigned long count, void *data)
{
        struct mds_grp_hash *hash = __mds_get_global_group_hash();
        char buf[32];

        if (copy_from_user(buf, buffer, min(count, 32UL)))
                return count;
        buf[31] = 0;
        sscanf(buf, "%d", &hash->gh_entry_expire);
        return count;
}
static int lprocfs_rd_ac_expire(char *page, char **start, off_t off, int count,
                                int *eof, void *data)
{
        struct mds_grp_hash *hash = __mds_get_global_group_hash();

        *eof = 1;
        return snprintf(page, count, "%d\n", hash->gh_acquire_expire);
}
static int lprocfs_wr_ac_expire(struct file *file, const char *buffer,
                                unsigned long count, void *data)
{
        struct mds_grp_hash *hash = __mds_get_global_group_hash();
        char buf[32];

        if (copy_from_user(buf, buffer, min(count, 32UL)))
                return count;
        buf[31] = 0;
        sscanf(buf, "%d", &hash->gh_acquire_expire);
        return count;
}
static int lprocfs_rd_hash_upcall(char *page, char **start, off_t off, int count,
                                int *eof, void *data)
{
        struct mds_grp_hash *hash = __mds_get_global_group_hash();

        *eof = 1;
        return snprintf(page, count, "%s\n", hash->gh_upcall);
}
static int lprocfs_wr_hash_upcall(struct file *file, const char *buffer,
                                  unsigned long count, void *data)
{
        struct mds_grp_hash *hash = __mds_get_global_group_hash();

        if (count < MDSGRP_UPCALL_MAXPATH) {
                sscanf(buffer, "%1024s", hash->gh_upcall);
                hash->gh_upcall[MDSGRP_UPCALL_MAXPATH-1] = 0;
        }
        return count;
}
static int lprocfs_wr_hash_flush(struct file *file, const char *buffer,
                                  unsigned long count, void *data)
{
        mds_group_hash_flush_idle();
        return count;
}
static int lprocfs_rd_allow_setgroups(char *page, char **start, off_t off,
                                      int count, int *eof, void *data)
{
        struct mds_grp_hash *hash = __mds_get_global_group_hash();

        *eof = 1;
        return snprintf(page, count, "%d\n", hash->gh_allow_setgroups);
}
static int lprocfs_wr_allow_setgroups(struct file *file, const char *buffer,
                                      unsigned long count, void *data)
{
        struct mds_grp_hash *hash = __mds_get_global_group_hash();
        char buf[8];
        int val;

        if (copy_from_user(buf, buffer, min(count, 8UL)))
                return count;
        buf[7] = 0;
        sscanf(buf, "%d", &val);
        hash->gh_allow_setgroups = (val != 0);
        return count;
}

struct lprocfs_vars lprocfs_mds_module_vars[] = {
        { "num_refs",     lprocfs_rd_numrefs,     0, 0 },
        { "grp_hash_expire_interval", lprocfs_rd_expire, lprocfs_wr_expire, 0},
        { "grp_hash_acquire_expire", lprocfs_rd_ac_expire,
                                     lprocfs_wr_ac_expire, 0},
        { "grp_hash_upcall", lprocfs_rd_hash_upcall, lprocfs_wr_hash_upcall, 0},
        { "grp_hash_flush", 0, lprocfs_wr_hash_flush, 0},
        { "group_info", 0,  lprocfs_wr_group_info,   0 },
        { "allow_setgroups", lprocfs_rd_allow_setgroups,
                             lprocfs_wr_allow_setgroups, 0},
        { 0 }
};

struct lprocfs_vars lprocfs_mdt_obd_vars[] = {
        { "uuid",         lprocfs_rd_uuid,        0, 0 },
        { 0 }
};

struct lprocfs_vars lprocfs_mdt_module_vars[] = {
        { "num_refs",     lprocfs_rd_numrefs,     0, 0 },
        { 0 }
};

#endif /* LPROCFS */

struct lprocfs_static_vars lprocfs_array_vars[] = { {lprocfs_mds_module_vars,
                                                     lprocfs_mds_obd_vars},
                                                    {lprocfs_mdt_module_vars,
                                                     lprocfs_mdt_obd_vars}};

LPROCFS_INIT_MULTI_VARS(lprocfs_array_vars,
                        (sizeof(lprocfs_array_vars) /
                         sizeof(struct lprocfs_static_vars)))
