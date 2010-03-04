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

        client_obd_list_lock(&cli->cl_loi_list_lock);
        rc = snprintf(page, count, "%u\n", cli->cl_max_rpcs_in_flight);
        client_obd_list_unlock(&cli->cl_loi_list_lock);
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

        client_obd_list_lock(&cli->cl_loi_list_lock);
        cli->cl_max_rpcs_in_flight = val;
        client_obd_list_unlock(&cli->cl_loi_list_lock);

        return count;
}

static struct lnl_hdr *changelog_lnl_alloc(int len, int flags)
{
        struct lnl_hdr *lh;

        OBD_ALLOC(lh, len);
        if (lh == NULL)
                RETURN(NULL);

        lh->lnl_magic = LNL_MAGIC;
        lh->lnl_transport = LNL_TRANSPORT_CHANGELOG;
        lh->lnl_flags = flags;
        lh->lnl_msgtype = CL_RECORD;
        lh->lnl_msglen = len;
        return lh;
}

#define D_CHANGELOG 0

static int changelog_show_cb(struct llog_handle *llh, struct llog_rec_hdr *hdr,
                             void *data)
{
        struct changelog_show *cs = data;
        struct llog_changelog_rec *rec = (struct llog_changelog_rec *)hdr;
        struct lnl_hdr *lh;
        int len, rc;
        ENTRY;

        if ((rec->cr_hdr.lrh_type != CHANGELOG_REC) ||
            (rec->cr.cr_type >= CL_LAST)) {
                CERROR("Not a changelog rec %d/%d\n", rec->cr_hdr.lrh_type,
                       rec->cr.cr_type);
                RETURN(-EINVAL);
        }

        if (rec->cr.cr_index < cs->cs_startrec) {
                /* Skip entries earlier than what we are interested in */
                CDEBUG(D_CHANGELOG, "rec="LPU64" start="LPU64"\n",
                       rec->cr.cr_index, cs->cs_startrec);
                RETURN(0);
        }

        CDEBUG(D_CHANGELOG, LPU64" %02d%-5s "LPU64" 0x%x t="DFID" p="DFID
               " %.*s\n", rec->cr.cr_index, rec->cr.cr_type,
               changelog_type2str(rec->cr.cr_type), rec->cr.cr_time,
               rec->cr.cr_flags & CLF_FLAGMASK,
               PFID(&rec->cr.cr_tfid), PFID(&rec->cr.cr_pfid),
               rec->cr.cr_namelen, rec->cr.cr_name);

        len = sizeof(*lh) + sizeof(rec->cr) + rec->cr.cr_namelen;

        /* Set up the netlink message */
        lh = changelog_lnl_alloc(len, cs->cs_flags);
        if (lh == NULL)
                RETURN(-ENOMEM);
        memcpy(lh + 1, &rec->cr, len - sizeof(*lh));

        rc = libcfs_klnl_msg_put(cs->cs_pid, 0, lh);
        CDEBUG(D_CHANGELOG, "nlmsg pid %d len %d rc %d\n", cs->cs_pid, len, rc);

        OBD_FREE(lh, len);

        RETURN(rc);
}

static int lproc_mdc_wr_changelog(struct file *file, const char *buffer,
                                  unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct llog_ctxt *ctxt;
        struct llog_handle *llh;
        struct lnl_hdr *lnlh;
        struct changelog_show cs = {};
        int rc;

        if (count != sizeof(cs))
                return -EINVAL;

        if (cfs_copy_from_user(&cs, buffer, sizeof(cs)))
                return -EFAULT;

        CDEBUG(D_CHANGELOG, "changelog to pid=%d start "LPU64"\n",
               cs.cs_pid, cs.cs_startrec);

        /* Set up the remote catalog handle */
        ctxt = llog_get_context(obd, LLOG_CHANGELOG_REPL_CTXT);
        if (ctxt == NULL)
                RETURN(-ENOENT);
        rc = llog_create(ctxt, &llh, NULL, CHANGELOG_CATALOG);
        if (rc) {
                CERROR("llog_create() failed %d\n", rc);
                GOTO(out, rc);
        }
        rc = llog_init_handle(llh, LLOG_F_IS_CAT, NULL);
        if (rc) {
                CERROR("llog_init_handle failed %d\n", rc);
                GOTO(out, rc);
        }

        rc = llog_cat_process(llh, changelog_show_cb, &cs, 0, 0);

        /* Send EOF */
        if ((lnlh = changelog_lnl_alloc(sizeof(*lnlh), cs.cs_flags))) {
                lnlh->lnl_msgtype = CL_EOF;
                libcfs_klnl_msg_put(cs.cs_pid, 0, lnlh);
                OBD_FREE(lnlh, sizeof(*lnlh));
        }

out:
        if (llh)
                llog_cat_put(llh);
        if (ctxt)
                llog_ctxt_put(ctxt);
        if (rc < 0)
                return rc;
        return count;
}

/* temporary for testing */
static int mdc_wr_netlink(struct file *file, const char *buffer,
                          unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct lnl_hdr *lh;
        struct hsm_action_list *hal;
        struct hsm_action_item *hai;
        int len;
        int pid, rc;

        rc = lprocfs_write_helper(buffer, count, &pid);
        if (rc)
                return rc;

        if (pid < 0)
                return -ERANGE;
        CWARN("message to pid %d\n", pid);

        len = sizeof(*lh) + sizeof(*hal) + MTI_NAME_MAXLEN +
                /* for mockup below */ 2 * cfs_size_round(sizeof(*hai));

        OBD_ALLOC(lh, len);

        lh->lnl_magic = LNL_MAGIC;
        lh->lnl_transport = LNL_TRANSPORT_HSM;
        lh->lnl_msgtype = HMT_ACTION_LIST;
        lh->lnl_msglen = len;

        hal = (struct hsm_action_list *)(lh + 1);
        hal->hal_version = HAL_VERSION;
        hal->hal_archive_num = 1;
        obd_uuid2fsname(hal->hal_fsname, obd->obd_name, MTI_NAME_MAXLEN);

        /* mock up an action list */
        hal->hal_count = 2;
        hai = hai_zero(hal);
        hai->hai_action = HSMA_ARCHIVE;
        hai->hai_fid.f_oid = 5;
        hai->hai_len = sizeof(*hai);
        hai = hai_next(hai);
        hai->hai_action = HSMA_RESTORE;
        hai->hai_fid.f_oid = 10;
        hai->hai_len = sizeof(*hai);

        /* This works for either broadcast or unicast to a single pid */
        rc = libcfs_klnl_msg_put(pid, pid == 0 ? LNL_GRP_HSM : 0, lh);

        OBD_FREE(lh, len);
        if (rc < 0)
                return rc;
        return count;
}

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
        { "changelog_trigger",0,lproc_mdc_wr_changelog, 0 },
        { "hsm_nl",          0, mdc_wr_netlink,      0, 0, 0222 },
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
