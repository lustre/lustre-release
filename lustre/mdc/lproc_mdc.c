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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/version.h>
#include <linux/vfs.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <lustre_log.h>

#ifdef LPROCFS

static int mdc_rd_max_rpcs_in_flight(char *page, char **start, off_t off,
                                     int count, int *eof, void *data)
{
        struct obd_device *dev = data;
        struct client_obd *cli = &dev->u.cli;
        int rc;

        spin_lock(&cli->cl_loi_list_lock);
        rc = snprintf(page, count, "%u\n", cli->cl_max_rpcs_in_flight);
        spin_unlock(&cli->cl_loi_list_lock);
        return rc;
}

static int mdc_wr_max_rpcs_in_flight(struct file *file, const char *buffer,
                                     unsigned long count, void *data)
{
        struct obd_device *dev = data;
        struct client_obd *cli = &dev->u.cli;
        int val, rc;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val < 1 || val > MDC_MAX_RIF_MAX)
                return -ERANGE;

        spin_lock(&cli->cl_loi_list_lock);
        cli->cl_max_rpcs_in_flight = val;
        spin_unlock(&cli->cl_loi_list_lock);

        return count;
}

static int mdc_changelog_seq_release(struct inode *inode, struct file *file)
{
        struct seq_file *seq = file->private_data;
        struct changelog_seq_iter *csi = seq->private;

        if (csi && csi->csi_llh)
                llog_cat_put(csi->csi_llh);
        if (csi && csi->csi_ctxt)
                llog_ctxt_put(csi->csi_ctxt);

        return (changelog_seq_release(inode, file));
}

static int mdc_changelog_seq_open(struct inode *inode, struct file *file)
{
        struct changelog_seq_iter *csi;
        int rc;
        ENTRY;

        rc = changelog_seq_open(inode, file, &csi);
        if (rc)
                RETURN(rc);

        /* Set up the remote catalog handle */
        /* Note the proc file is set up with obd in data, not mdc_device */
        csi->csi_ctxt = llog_get_context((struct obd_device *)csi->csi_dev,
                                         LLOG_CHANGELOG_REPL_CTXT);
        if (csi->csi_ctxt == NULL)
                GOTO(out, rc = -ENOENT);
        rc = llog_create(csi->csi_ctxt, &csi->csi_llh, NULL, CHANGELOG_CATALOG);
        if (rc) {
                CERROR("llog_create() failed %d\n", rc);
                GOTO(out, rc);
        }
        rc = llog_init_handle(csi->csi_llh, LLOG_F_IS_CAT, NULL);
        if (rc) {
                CERROR("llog_init_handle failed %d\n", rc);
                GOTO(out, rc);
        }

out:
        if (rc)
                mdc_changelog_seq_release(inode, file);
        RETURN(rc);
}

static struct file_operations mdc_changelog_fops = {
        .owner   = THIS_MODULE,
        .open    = mdc_changelog_seq_open,
        .read    = seq_read,
        .llseek  = changelog_seq_lseek,
        .release = mdc_changelog_seq_release,
};

static struct lprocfs_vars lprocfs_mdc_obd_vars[] = {
        { "uuid",            lprocfs_rd_uuid,        0, 0 },
        { "ping",            0, lprocfs_wr_ping,     0, 0, 0222 },
        { "connect_flags",   lprocfs_rd_connect_flags, 0, 0 },
        { "blocksize",       lprocfs_rd_blksize,     0, 0 },
        { "kbytestotal",     lprocfs_rd_kbytestotal, 0, 0 },
        { "kbytesfree",      lprocfs_rd_kbytesfree,  0, 0 },
        { "kbytesavail",     lprocfs_rd_kbytesavail, 0, 0 },
        { "filestotal",      lprocfs_rd_filestotal,  0, 0 },
        { "filesfree",       lprocfs_rd_filesfree,   0, 0 },
        /*{ "filegroups",      lprocfs_rd_filegroups,  0, 0 },*/
        { "mds_server_uuid", lprocfs_rd_server_uuid, 0, 0 },
        { "mds_conn_uuid",   lprocfs_rd_conn_uuid,   0, 0 },
        { "max_rpcs_in_flight", mdc_rd_max_rpcs_in_flight,
                                mdc_wr_max_rpcs_in_flight, 0 },
        { "timeouts",        lprocfs_rd_timeouts,    0, 0 },
        { "import",          lprocfs_rd_import,      0, 0 },
        { "state",           lprocfs_rd_state,       0, 0 },
        { "changelog",       0, 0, 0, &mdc_changelog_fops, 0400 },
        { 0 }
};

static struct lprocfs_vars lprocfs_mdc_module_vars[] = {
        { "num_refs",        lprocfs_rd_numrefs,     0, 0 },
        { 0 }
};

void lprocfs_mdc_init_vars(struct lprocfs_static_vars *lvars)
{
    lvars->module_vars  = lprocfs_mdc_module_vars;
    lvars->obd_vars     = lprocfs_mdc_obd_vars;
}
#endif /* LPROCFS */
