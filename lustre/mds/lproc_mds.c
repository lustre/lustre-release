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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/version.h>
#include <asm/statfs.h>
#include <obd.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include "mds_internal.h"

#ifdef LPROCFS
static int lprocfs_mds_rd_evictostnids(char *page, char **start, off_t off,
                                       int count, int *eof, void *data)
{
        struct obd_device* obd = (struct obd_device *)data;

        LASSERT(obd != NULL);

        return snprintf(page, count, "%d\n", obd->u.mds.mds_evict_ost_nids);
}

static int lprocfs_mds_wr_evictostnids(struct file *file, const char *buffer,
                                       unsigned long count, void *data)
{
        struct obd_device *obd = data;
        int val, rc;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        obd->u.mds.mds_evict_ost_nids = !!val;

        return count;
}

#define BUFLEN (UUID_MAX + 4)

static int lprocfs_mds_wr_evict_client(struct file *file, const char *buffer,
                                       unsigned long count, void *data)
{
        struct ptlrpc_request_set *set;
        struct obd_device         *obd = data;
        struct mds_obd            *mds = &obd->u.mds;
        char                      *kbuf;
        char                      *tmpbuf;
        int                        rc;

        OBD_ALLOC(kbuf, BUFLEN);
        if (kbuf == NULL)
                return -ENOMEM;

        /*
         * OBD_ALLOC() will zero kbuf, but we only copy BUFLEN - 1
         * bytes into kbuf, to ensure that the string is NUL-terminated.
         * UUID_MAX should include a trailing NUL already.
         */
        if (cfs_copy_from_user(kbuf, buffer,
                               min_t(unsigned long, BUFLEN - 1, count))) {
                count = -EFAULT;
                goto out;
        }
        tmpbuf = cfs_firststr(kbuf, min_t(unsigned long, BUFLEN - 1, count));

        if (strncmp(tmpbuf, "nid:", 4) != 0) {
                count = lprocfs_wr_evict_client(file, buffer, count, data);
                goto out;
        }

        set = ptlrpc_prep_set();
        if (set == NULL) {
                count = -ENOMEM;
                goto out;
        }

        if (obd->u.mds.mds_evict_ost_nids) {
                rc = obd_set_info_async(mds->mds_lov_exp,
                                        sizeof(KEY_EVICT_BY_NID),
                                        KEY_EVICT_BY_NID, strlen(tmpbuf + 4) + 1,
                                        tmpbuf + 4, set);
                if (rc)
                        CERROR("Failed to evict nid %s from OSTs: rc %d\n",
                               tmpbuf + 4, rc);

                ptlrpc_check_set(NULL, set);
        }

        /* See the comments in function lprocfs_wr_evict_client()
         * in ptlrpc/lproc_ptlrpc.c for details. - jay */
        class_incref(obd, __FUNCTION__, cfs_current());
        LPROCFS_EXIT();

        obd_export_evict_by_nid(obd, tmpbuf + 4);


        rc = ptlrpc_set_wait(set);
        if (rc)
                CERROR("Failed to evict nid %s from OSTs: rc %d\n", tmpbuf + 4,
                       rc);

        LPROCFS_ENTRY();
        class_decref(obd,  __FUNCTION__, cfs_current());

        ptlrpc_set_destroy(set);
out:
        OBD_FREE(kbuf, BUFLEN);
        return count;
}

#undef BUFLEN

static int lprocfs_wr_atime_diff(struct file *file, const char *buffer,
                                 unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mds_obd *mds = &obd->u.mds;
        char kernbuf[20], *end;
        unsigned long diff = 0;

        if (count > (sizeof(kernbuf) - 1))
                return -EINVAL;

        if (cfs_copy_from_user(kernbuf, buffer, count))
                return -EFAULT;

        kernbuf[count] = '\0';

        diff = simple_strtoul(kernbuf, &end, 0);
        if (kernbuf == end)
                return -EINVAL;

        mds->mds_atime_diff = diff;
        return count;
}

static int lprocfs_rd_atime_diff(char *page, char **start, off_t off,
                                 int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mds_obd *mds = &obd->u.mds;

        *eof = 1;
        return snprintf(page, count, "%lu\n", mds->mds_atime_diff);
}

struct lprocfs_vars lprocfs_mds_obd_vars[] = {
        { "uuid",            lprocfs_rd_uuid,        0, 0 },
        { "blocksize",       lprocfs_rd_blksize,     0, 0 },
        { "kbytestotal",     lprocfs_rd_kbytestotal, 0, 0 },
        { "kbytesfree",      lprocfs_rd_kbytesfree,  0, 0 },
        { "kbytesavail",     lprocfs_rd_kbytesavail, 0, 0 },
        { "filestotal",      lprocfs_rd_filestotal,  0, 0 },
        { "filesfree",       lprocfs_rd_filesfree,   0, 0 },
        { "fstype",          lprocfs_rd_fstype,      0, 0 },
        { "mntdev",          lprocfs_obd_rd_mntdev,  0, 0 },
        { "recovery_status", lprocfs_obd_rd_recovery_status, 0, 0 },
        { "hash_stats",      lprocfs_obd_rd_hash,    0, 0 },
        { "evict_client",    0,                lprocfs_mds_wr_evict_client, 0 },
        { "evict_ost_nids",  lprocfs_mds_rd_evictostnids,
                                               lprocfs_mds_wr_evictostnids, 0 },
        { "num_exports",     lprocfs_rd_num_exports, 0, 0 },
        { "atime_diff",      lprocfs_rd_atime_diff, lprocfs_wr_atime_diff, 0 },
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

void lprocfs_mds_init_vars(struct lprocfs_static_vars *lvars)
{
    lvars->module_vars = lprocfs_mds_module_vars;
    lvars->obd_vars = lprocfs_mds_obd_vars;
}

#endif
