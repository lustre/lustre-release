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
 *
 * lustre/mdd/mdd_lproc.c
 *
 * Lustre Metadata Server (mdd) routines
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/poll.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>
#include <lprocfs_status.h>
#include <lu_time.h>
#include <lustre_log.h>
#include <lustre/lustre_idl.h>
#include <libcfs/libcfs_string.h>

#include "mdd_internal.h"

static const char *mdd_counter_names[LPROC_MDD_NR] = {
};

int mdd_procfs_init(struct mdd_device *mdd, const char *name)
{
        struct lprocfs_static_vars lvars;
        struct lu_device    *ld = &mdd->mdd_md_dev.md_lu_dev;
        struct obd_type     *type;
        int                  rc;
        ENTRY;

        type = ld->ld_type->ldt_obd_type;

        LASSERT(name != NULL);
        LASSERT(type != NULL);

        /* Find the type procroot and add the proc entry for this device */
        lprocfs_mdd_init_vars(&lvars);
        mdd->mdd_proc_entry = lprocfs_register(name, type->typ_procroot,
                                               lvars.obd_vars, mdd);
        if (IS_ERR(mdd->mdd_proc_entry)) {
                rc = PTR_ERR(mdd->mdd_proc_entry);
                CERROR("Error %d setting up lprocfs for %s\n",
                       rc, name);
                mdd->mdd_proc_entry = NULL;
                GOTO(out, rc);
        }

        rc = lu_time_init(&mdd->mdd_stats,
                          mdd->mdd_proc_entry,
                          mdd_counter_names, ARRAY_SIZE(mdd_counter_names));

        EXIT;
out:
        if (rc)
               mdd_procfs_fini(mdd);
        return rc;
}

int mdd_procfs_fini(struct mdd_device *mdd)
{
        if (mdd->mdd_stats)
                lu_time_fini(&mdd->mdd_stats);

        if (mdd->mdd_proc_entry) {
                 lprocfs_remove(&mdd->mdd_proc_entry);
                 mdd->mdd_proc_entry = NULL;
        }
        RETURN(0);
}

void mdd_lprocfs_time_start(const struct lu_env *env)
{
        lu_lprocfs_time_start(env);
}

void mdd_lprocfs_time_end(const struct lu_env *env, struct mdd_device *mdd,
                          int idx)
{
        lu_lprocfs_time_end(env, mdd->mdd_stats, idx);
}

static int lprocfs_wr_atime_diff(struct file *file, const char *buffer,
                                 unsigned long count, void *data)
{
        struct mdd_device *mdd = data;
        char kernbuf[20], *end;
        unsigned long diff = 0;

        if (count > (sizeof(kernbuf) - 1))
                return -EINVAL;

        if (copy_from_user(kernbuf, buffer, count))
                return -EFAULT;

        kernbuf[count] = '\0';

        diff = simple_strtoul(kernbuf, &end, 0);
        if (kernbuf == end)
                return -EINVAL;

        mdd->mdd_atime_diff = diff;
        return count;
}

static int lprocfs_rd_atime_diff(char *page, char **start, off_t off,
                                 int count, int *eof, void *data)
{
        struct mdd_device *mdd = data;

        *eof = 1;
        return snprintf(page, count, "%lu\n", mdd->mdd_atime_diff);
}


/**** changelogs ****/
DECLARE_CHANGELOG_NAMES;

const char *changelog_bit2str(int bit)
{
        if (bit < CL_LAST)
                return changelog_str[bit];
        return NULL;
}

static int lprocfs_rd_changelog_mask(char *page, char **start, off_t off,
                                     int count, int *eof, void *data)
{
        struct mdd_device *mdd = data;
        int i = 0, rc = 0;

        *eof = 1;
        while (i < CL_LAST) {
                if (mdd->mdd_cl.mc_mask & (1 << i))
                        rc += snprintf(page + rc, count - rc, "%s ",
                                       changelog_str[i]);
                i++;
        }
        return rc;
}

static int lprocfs_wr_changelog_mask(struct file *file, const char *buffer,
                                     unsigned long count, void *data)
{
        struct mdd_device *mdd = data;
        char *kernbuf;
        int rc;
        ENTRY;

        if (count >= CFS_PAGE_SIZE)
                RETURN(-EINVAL);
        OBD_ALLOC(kernbuf, CFS_PAGE_SIZE);
        if (kernbuf == NULL)
                RETURN(-ENOMEM);
        if (copy_from_user(kernbuf, buffer, count))
                GOTO(out, rc = -EFAULT);
        kernbuf[count] = 0;

        rc = libcfs_str2mask(kernbuf, changelog_bit2str, &mdd->mdd_cl.mc_mask,
                             CHANGELOG_MINMASK, CHANGELOG_ALLMASK);
        if (rc == 0)
                rc = count;
out:
        OBD_FREE(kernbuf, CFS_PAGE_SIZE);
        return rc;
}

struct cucb_data {
        char *page;
        int count;
        int idx;
};

static int lprocfs_changelog_users_cb(struct llog_handle *llh,
                                      struct llog_rec_hdr *hdr, void *data)
{
        struct llog_changelog_user_rec *rec;
        struct cucb_data *cucb = (struct cucb_data *)data;

        LASSERT(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN);

        rec = (struct llog_changelog_user_rec *)hdr;

        cucb->idx += snprintf(cucb->page + cucb->idx, cucb->count - cucb->idx,
                              CHANGELOG_USER_PREFIX"%-3d "LPU64"\n",
                              rec->cur_id, rec->cur_endrec);
        if (cucb->idx >= cucb->count)
                return -ENOSPC;

        return 0;
}

static int lprocfs_rd_changelog_users(char *page, char **start, off_t off,
                                      int count, int *eof, void *data)
{
        struct mdd_device *mdd = data;
        struct llog_ctxt *ctxt;
        struct cucb_data cucb;
        __u64 cur;

        *eof = 1;

        ctxt = llog_get_context(mdd2obd_dev(mdd),LLOG_CHANGELOG_USER_ORIG_CTXT);
        if (ctxt == NULL)
                return -ENXIO;
        LASSERT(ctxt->loc_handle->lgh_hdr->llh_flags & LLOG_F_IS_CAT);

        spin_lock(&mdd->mdd_cl.mc_lock);
        cur = mdd->mdd_cl.mc_index;
        spin_unlock(&mdd->mdd_cl.mc_lock);

        cucb.count = count;
        cucb.page = page;
        cucb.idx = 0;

        cucb.idx += snprintf(cucb.page + cucb.idx, cucb.count - cucb.idx,
                              "current index: "LPU64"\n", cur);

        cucb.idx += snprintf(cucb.page + cucb.idx, cucb.count - cucb.idx,
                              "%-5s %s\n", "ID", "index");

        llog_cat_process(ctxt->loc_handle, lprocfs_changelog_users_cb,
                         &cucb, 0, 0);

        llog_ctxt_put(ctxt);
        return cucb.idx;
}

/* non-seq version for direct calling by class_process_proc_param */
static int mdd_changelog_write(struct file *file, const char *buffer,
                               unsigned long count, void *data)
{
        struct mdd_device *mdd = (struct mdd_device *)data;
        char kernbuf[32];
        char *end;
        int rc;

        if (count > (sizeof(kernbuf) - 1))
                goto out_usage;

        count = min_t(unsigned long, count, sizeof(kernbuf));
        if (copy_from_user(kernbuf, buffer, count))
                return -EFAULT;

        kernbuf[count] = '\0';
        /* strip trailing newline from "echo blah" */
        if (kernbuf[count - 1] == '\n')
                kernbuf[count - 1] = '\0';

        if (strcmp(kernbuf, "on") == 0) {
                LCONSOLE_INFO("changelog on\n");
                if (mdd->mdd_cl.mc_flags & CLM_ERR) {
                        CERROR("Changelogs cannot be enabled due to error "
                               "condition.\n");
                } else {
                        spin_lock(&mdd->mdd_cl.mc_lock);
                        mdd->mdd_cl.mc_flags |= CLM_ON;
                        spin_unlock(&mdd->mdd_cl.mc_lock);
                        rc = mdd_changelog_write_header(mdd, CLM_START);
                        if (rc)
                              return rc;
                }
        } else if (strcmp(kernbuf, "off") == 0) {
                LCONSOLE_INFO("changelog off\n");
                rc = mdd_changelog_write_header(mdd, CLM_FINI);
                if (rc)
                      return rc;
                spin_lock(&mdd->mdd_cl.mc_lock);
                mdd->mdd_cl.mc_flags &= ~CLM_ON;
                spin_unlock(&mdd->mdd_cl.mc_lock);
        } else {
                /* purge to an index */
                long long unsigned endrec;

                endrec = (long long)simple_strtoull(kernbuf, &end, 0);
                if (end == kernbuf)
                        goto out_usage;

                LCONSOLE_INFO("changelog purge to %llu\n", endrec);

                rc = mdd_changelog_llog_cancel(mdd, endrec);
                if (rc < 0)
                        return rc;
        }

        return count;

out_usage:
        CWARN("changelog write usage: [on|off] | <purge_idx (0=all)>\n");
        return -EINVAL;
}

static ssize_t mdd_changelog_seq_write(struct file *file, const char *buffer,
                                       size_t count, loff_t *off)
{
        struct seq_file *seq = file->private_data;
        struct changelog_seq_iter *csi = seq->private;
        struct mdd_device *mdd = (struct mdd_device *)csi->csi_dev;

        return mdd_changelog_write(file, buffer, count, mdd);
}

static int mdd_changelog_done(struct changelog_seq_iter *csi)
{
        struct mdd_device *mdd = (struct mdd_device *)csi->csi_dev;
        int done = 0;

        spin_lock(&mdd->mdd_cl.mc_lock);
        done = (csi->csi_endrec >= mdd->mdd_cl.mc_index);
        spin_unlock(&mdd->mdd_cl.mc_lock);
        return done;
}

/* handle nonblocking */
static ssize_t mdd_changelog_seq_read(struct file *file, char __user *buf,
                                      size_t count, loff_t *ppos)
{
        struct seq_file *seq = (struct seq_file *)file->private_data;
        struct changelog_seq_iter *csi = seq->private;
        int rc;
        ENTRY;

        if ((file->f_flags & O_NONBLOCK) && mdd_changelog_done(csi))
                RETURN(-EAGAIN);

        csi->csi_done = 0;
        rc = seq_read(file, buf, count, ppos);
        RETURN(rc);
}

/* handle nonblocking */
static unsigned int mdd_changelog_seq_poll(struct file *file, poll_table *wait)
{
        struct seq_file *seq = (struct seq_file *)file->private_data;
        struct changelog_seq_iter *csi = seq->private;
        struct mdd_device *mdd = (struct mdd_device *)csi->csi_dev;
        ENTRY;

        csi->csi_done = 0;
        poll_wait(file, &mdd->mdd_cl.mc_waitq, wait);
        if (!mdd_changelog_done(csi))
                RETURN(POLLIN | POLLRDNORM);

        RETURN(0);
}

static int mdd_changelog_seq_open(struct inode *inode, struct file *file)
{
        struct changelog_seq_iter *csi;
        struct obd_device *obd;
        int rc;
        ENTRY;

        rc = changelog_seq_open(inode, file, &csi);
        if (rc)
                RETURN(rc);

        /* The proc file is set up with mdd in data, not obd */
        obd = mdd2obd_dev((struct mdd_device *)csi->csi_dev);
        csi->csi_ctxt = llog_get_context(obd, LLOG_CHANGELOG_ORIG_CTXT);
        if (csi->csi_ctxt == NULL) {
                changelog_seq_release(inode, file);
                RETURN(-ENOENT);
        }
        /* The handle is set up in llog_obd_origin_setup */
        csi->csi_llh = csi->csi_ctxt->loc_handle;
        RETURN(rc);
}

static int mdd_changelog_seq_release(struct inode *inode, struct file *file)
{
        struct seq_file *seq = file->private_data;
        struct changelog_seq_iter *csi = seq->private;

        if (csi && csi->csi_ctxt)
                llog_ctxt_put(csi->csi_ctxt);

        return (changelog_seq_release(inode, file));
}

/* mdd changelog proc can handle nonblocking ops and writing to purge recs */
struct file_operations mdd_changelog_fops = {
        .owner   = THIS_MODULE,
        .open    = mdd_changelog_seq_open,
        .read    = mdd_changelog_seq_read,
        .write   = mdd_changelog_seq_write,
        .llseek  = changelog_seq_lseek,
        .poll    = mdd_changelog_seq_poll,
        .release = mdd_changelog_seq_release,
};

#ifdef HAVE_QUOTA_SUPPORT
static int mdd_lprocfs_quota_rd_type(char *page, char **start, off_t off,
                                     int count, int *eof, void *data)
{
        struct mdd_device *mdd = data;
        return lprocfs_quota_rd_type(page, start, off, count, eof,
                                     mdd->mdd_obd_dev);
}

static int mdd_lprocfs_quota_wr_type(struct file *file, const char *buffer,
                                     unsigned long count, void *data)
{
        struct mdd_device *mdd = data;
        return lprocfs_quota_wr_type(file, buffer, count, mdd->mdd_obd_dev);
}
#endif

static struct lprocfs_vars lprocfs_mdd_obd_vars[] = {
        { "atime_diff",      lprocfs_rd_atime_diff, lprocfs_wr_atime_diff, 0 },
        { "changelog_mask",  lprocfs_rd_changelog_mask,
                             lprocfs_wr_changelog_mask, 0 },
        { "changelog_users", lprocfs_rd_changelog_users, 0, 0},
        { "changelog", 0, mdd_changelog_write, 0, &mdd_changelog_fops, 0600 },
#ifdef HAVE_QUOTA_SUPPORT
        { "quota_type",      mdd_lprocfs_quota_rd_type,
                             mdd_lprocfs_quota_wr_type, 0 },
#endif
        { 0 }
};

static struct lprocfs_vars lprocfs_mdd_module_vars[] = {
        { "num_refs",   lprocfs_rd_numrefs, 0, 0 },
        { 0 }
};

void lprocfs_mdd_init_vars(struct lprocfs_static_vars *lvars)
{
        lvars->module_vars  = lprocfs_mdd_module_vars;
        lvars->obd_vars     = lprocfs_mdd_obd_vars;
}

