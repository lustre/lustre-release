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

#ifndef LPROCFS
struct lprocfs_vars lprocfs_mds_obd_vars[]  = { {0} };
struct lprocfs_vars lprocfs_mds_module_vars[] = { {0} };
struct lprocfs_vars lprocfs_mdt_obd_vars[] = { {0} };
struct lprocfs_vars lprocfs_mdt_module_vars[] = { {0} };

#else

static int lprocfs_mds_rd_mntdev(char *page, char **start, off_t off, int count,
                                 int *eof, void *data)
{
        struct obd_device* obd = (struct obd_device *)data;

        LASSERT(obd != NULL);
        LASSERT(obd->u.mds.mds_vfsmnt->mnt_devname);
        *eof = 1;

        return snprintf(page, count, "%s\n",obd->u.mds.mds_vfsmnt->mnt_devname);
}

static int lprocfs_mds_rd_recovery_status(char *page, char **start, off_t off,
                                          int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        int len = 0, n,
                connected = obd->obd_connected_clients,
                max_recoverable = obd->obd_max_recoverable_clients,
                recoverable = obd->obd_recoverable_clients,
                completed = max_recoverable - recoverable,
                queue_len = obd->obd_requests_queued_for_recovery,
                replayed = obd->obd_replayed_requests;
        __u64 next_transno = obd->obd_next_recovery_transno;

        LASSERT(obd != NULL);
        *eof = 1;

        n = snprintf(page, count, "status: ");
        page += n; len += n; count -= n;
        if (obd->obd_max_recoverable_clients == 0) {
                n = snprintf(page, count, "INACTIVE\n");
                return len + n;
        }

        if (obd->obd_recoverable_clients == 0) {
                n = snprintf(page, count, "COMPLETE\n");
                page += n; len += n; count -= n;
                n = snprintf(page, count, "recovered_clients: %d\n",
                             max_recoverable);
                page += n; len += n; count -= n;
                n = snprintf(page, count, "last_transno: "LPD64"\n",
                             next_transno - 1);
                page += n; len += n; count -= n;
                n = snprintf(page, count, "replayed_requests: %d\n", replayed);
                return len + n;
        }

        /* sampled unlocked, but really... */
        if (obd->obd_recovering == 0) {
                n = snprintf(page, count, "ABORTED\n");
                return len + n;
        }

        n = snprintf(page, count, "RECOVERING\n");
        page += n; len += n; count -= n;
        n = snprintf(page, count, "connected_clients: %d/%d\n",
                     connected, max_recoverable);
        page += n; len += n; count -= n;
        n = snprintf(page, count, "completed_clients: %d/%d\n",
                     completed, max_recoverable);
        page += n; len += n; count -= n;
        n = snprintf(page, count, "replayed_requests: %d/??\n", replayed);
        page += n; len += n; count -= n;
        n = snprintf(page, count, "queued_requests: %d\n", queue_len);
        page += n; len += n; count -= n;
        n = snprintf(page, count, "next_transno: "LPD64"\n", next_transno);
        return len + n;
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

struct lprocfs_vars lprocfs_mds_obd_vars[] = {
        { "uuid",         lprocfs_rd_uuid,        0, 0 },
        { "blocksize",    lprocfs_rd_blksize,     0, 0 },
        { "kbytestotal",  lprocfs_rd_kbytestotal, 0, 0 },
        { "kbytesfree",   lprocfs_rd_kbytesfree,  0, 0 },
        { "fstype",       lprocfs_rd_fstype,      0, 0 },
        { "filestotal",   lprocfs_rd_filestotal,  0, 0 },
        { "filesfree",    lprocfs_rd_filesfree,   0, 0 },
        //{ "filegroups",   lprocfs_rd_filegroups,  0, 0 },
        { "mntdev",       lprocfs_mds_rd_mntdev,  0, 0 },
        { "recovery_status", lprocfs_mds_rd_recovery_status, 0, 0 },
        { "evict_client", 0, lprocfs_mds_wr_evict_client, 0 },
        { 0 }
};

struct lprocfs_vars lprocfs_mds_module_vars[] = {
        { "num_refs",     lprocfs_rd_numrefs,     0, 0 },
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

#endif
struct lprocfs_static_vars lprocfs_array_vars[] = { {lprocfs_mds_module_vars,
                                                     lprocfs_mds_obd_vars},
                                                    {lprocfs_mdt_module_vars,
                                                     lprocfs_mdt_obd_vars}};

LPROCFS_INIT_MULTI_VARS(lprocfs_array_vars,
                        (sizeof(lprocfs_array_vars) /
                         sizeof(struct lprocfs_static_vars)))
