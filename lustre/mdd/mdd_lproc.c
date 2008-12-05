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

#ifndef SEEK_CUR /* SLES10 needs this */
#define SEEK_CUR        1
#define SEEK_END        2
#endif

static const char *mdd_counter_names[LPROC_MDD_NR] = {
};

/* from LPROC_SEQ_FOPS(mdd_changelog) below */
extern struct file_operations mdd_changelog_fops;

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

/* match enum changelog_rec_type */
static const char *changelog_str[] = {"MARK","CREAT","MKDIR","HLINK","SLINK",
        "MKNOD","UNLNK","RMDIR","RNMFM","RNMTO","OPEN","CLOSE","IOCTL",
        "TRUNC","SATTR","XATTR"};

const char *changelog_bit2str(int bit)
{
        if (bit < CL_LAST)
                return changelog_str[bit];
        return NULL;
}

static int lprocfs_rd_cl_mask(char *page, char **start, off_t off,
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

static int lprocfs_wr_cl_mask(struct file *file, const char *buffer,
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

        rc = libcfs_str2mask(kernbuf, changelog_bit2str,
                             &mdd->mdd_cl.mc_mask, CL_MINMASK, CL_ALLMASK);
        if (rc == 0)
                rc = count;
out:
        OBD_FREE(kernbuf, CFS_PAGE_SIZE);
        return rc;
}

/** struct for holding changelog data for seq_file processing */
struct cl_seq_iter {
        struct mdd_device *csi_mdd;
        __u64 csi_startrec;
        __u64 csi_endrec;
        loff_t csi_pos;
        int csi_wrote;
        int csi_startcat;
        int csi_startidx;
        int csi_fill:1;
};

/* non-seq version for direct calling by class_process_proc_param */
static int lprocfs_wr_cl(struct file *file, const char *buffer,
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
                long long unsigned endrec, cur;

                spin_lock(&mdd->mdd_cl.mc_lock);
                cur = (long long)mdd->mdd_cl.mc_index;
                spin_unlock(&mdd->mdd_cl.mc_lock);

                if (strcmp(kernbuf, "0") == 0)
                        /* purge to "0" is shorthand for everything */
                        endrec = cur;
                else
                        endrec = (long long)simple_strtoull(kernbuf, &end, 0);
                if ((kernbuf == end) || (endrec == 0))
                        goto out_usage;
                if (endrec > cur)
                        endrec = cur;

                /* If purging all records, write a header entry so we
                   don't have an empty catalog and
                   we're sure to have a valid starting index next time.  In
                   case of crash, we just restart with old log so we're
                   allright. */
                if (endrec == cur) {
                        rc = mdd_changelog_write_header(mdd, CLM_PURGE);
                        if (rc)
                              return rc;
                }

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

static ssize_t mdd_cl_seq_write(struct file *file, const char *buffer,
                                size_t count, loff_t *off)
{
        struct seq_file *seq = file->private_data;
        struct cl_seq_iter *csi = seq->private;
        struct mdd_device *mdd = csi->csi_mdd;

        return lprocfs_wr_cl(file, buffer, count, mdd);
}

#define D_CL 0

/* How many records per seq_show.  Too small, we spawn llog_process threads
   too often; too large, we run out of buffer space */
#define CL_CHUNK_SIZE 100

static int changelog_show_cb(struct llog_handle *llh, struct llog_rec_hdr *hdr,
                             void *data)
{
        struct seq_file *seq = (struct seq_file *)data;
        struct cl_seq_iter *csi = seq->private;
        struct llog_changelog_rec *rec = (struct llog_changelog_rec *)hdr;
        int rc;
        ENTRY;

        if ((rec->cr_hdr.lrh_type != CHANGELOG_REC) ||
            (rec->cr_type >= CL_LAST)) {
                CERROR("Not a changelog rec? %d/%d\n", rec->cr_hdr.lrh_type,
                       rec->cr_type);
                RETURN(-EINVAL);
        }

        CDEBUG(D_CL, "rec="LPU64" start="LPU64" cat=%d:%d start=%d:%d\n",
               rec->cr_index, csi->csi_startrec,
               llh->lgh_hdr->llh_cat_idx, llh->lgh_cur_idx,
               csi->csi_startcat, csi->csi_startidx);

        if (rec->cr_index < csi->csi_startrec)
                RETURN(0);
        if (rec->cr_index == csi->csi_startrec) {
                /* Remember where we started, since seq_read will re-read
                 * the data when it reallocs space.  Sigh, if only there was
                 * a way to tell seq_file how big the buf should be in the
                 * first place... */
                csi->csi_startcat = llh->lgh_hdr->llh_cat_idx;
                csi->csi_startidx = rec->cr_hdr.lrh_index - 1;
        }
        if (csi->csi_wrote > CL_CHUNK_SIZE) {
                /* Stop at some point with a reasonable seq_file buffer size.
                 * Start from here the next time.
                 */
                csi->csi_endrec = rec->cr_index - 1;
                csi->csi_startcat = llh->lgh_hdr->llh_cat_idx;
                csi->csi_startidx = rec->cr_hdr.lrh_index - 1;
                csi->csi_wrote = 0;
                RETURN(LLOG_PROC_BREAK);
        }

        rc = seq_printf(seq, LPU64" %02d%-5s "LPU64" 0x%x t="DFID,
                        rec->cr_index, rec->cr_type,
                        changelog_str[rec->cr_type], rec->cr_time,
                        rec->cr_flags & CLF_FLAGMASK, PFID(&rec->cr_tfid));

        if (rec->cr_namelen)
                /* namespace rec includes parent and filename */
                rc += seq_printf(seq, " p="DFID" %.*s\n", PFID(&rec->cr_pfid),
                                 rec->cr_namelen, rec->cr_name);
        else
                rc += seq_puts(seq, "\n");

        if (rc < 0) {
                /* seq_read will dump the whole buffer and re-seq_start with a
                   larger one; no point in continuing the llog_process */
                CDEBUG(D_CL, "rec="LPU64" overflow "LPU64"<-"LPU64"\n",
                       rec->cr_index, csi->csi_startrec, csi->csi_endrec);
                csi->csi_endrec = csi->csi_startrec - 1;
                csi->csi_wrote = 0;
                RETURN(LLOG_PROC_BREAK);
        }

        csi->csi_wrote++;
        csi->csi_endrec = rec->cr_index;

        RETURN(0);
}

static int mdd_cl_seq_show(struct seq_file *seq, void *v)
{
        struct cl_seq_iter *csi = seq->private;
        struct obd_device *obd = mdd2obd_dev(csi->csi_mdd);
        struct llog_ctxt *ctxt;
        int rc;

        if (csi->csi_fill) {
                /* seq_read wants more data to fill his buffer. But we already
                   filled the buf as much as we cared to; force seq_read to
                   accept that. */
                while ((rc = seq_putc(seq, 0)) == 0);
                return 0;
        }

        ctxt = llog_get_context(obd, LLOG_CHANGELOG_ORIG_CTXT);
        if (ctxt == NULL)
                return -ENOENT;

        /* Since we have to restart the llog_cat_process for each chunk of the
           seq_ functions, start from where we left off. */
        rc = llog_cat_process(ctxt->loc_handle, changelog_show_cb, seq,
                              csi->csi_startcat, csi->csi_startidx);

        CDEBUG(D_CL, "seq_show "LPU64"-"LPU64" cat=%d:%d wrote=%d rc=%d\n",
               csi->csi_startrec, csi->csi_endrec, csi->csi_startcat,
               csi->csi_startidx, csi->csi_wrote, rc);

        llog_ctxt_put(ctxt);

        if (rc == LLOG_PROC_BREAK)
                rc = 0;

        return rc;
}

static int mdd_cl_done(struct cl_seq_iter *csi)
{
        int done = 0;
        spin_lock(&csi->csi_mdd->mdd_cl.mc_lock);
        done = (csi->csi_endrec >= csi->csi_mdd->mdd_cl.mc_index);
        spin_unlock(&csi->csi_mdd->mdd_cl.mc_lock);
        return done;
}


static void *mdd_cl_seq_start(struct seq_file *seq, loff_t *pos)
{
        struct cl_seq_iter *csi = seq->private;
        LASSERT(csi);

        CDEBUG(D_CL, "start "LPU64"-"LPU64" pos="LPU64"\n",
               csi->csi_startrec, csi->csi_endrec, *pos);

        csi->csi_fill = 0;

        if (mdd_cl_done(csi))
                /* no more records, seq_read should return 0 if buffer
                   is empty */
                return NULL;

        if (*pos > csi->csi_pos) {
                /* The seq_read implementation sucks.  It may call start
                   multiple times, using pos to indicate advances, if any,
                   by arbitrarily increasing it by 1. So ignore the actual
                   value of pos, and just register any increase as
                   "seq_read wants the next values". */
                csi->csi_startrec = csi->csi_endrec + 1;
                csi->csi_pos = *pos;
        }
        /* else use old startrec/startidx */

        return csi;
}

static void mdd_cl_seq_stop(struct seq_file *seq, void *v)
{
        struct cl_seq_iter *csi = seq->private;

        CDEBUG(D_CL, "stop "LPU64"-"LPU64"\n",
               csi->csi_startrec, csi->csi_endrec);
}

static void *mdd_cl_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
        struct cl_seq_iter *csi = seq->private;

        CDEBUG(D_CL, "next "LPU64"-"LPU64" pos="LPU64"\n",
               csi->csi_startrec, csi->csi_endrec, *pos);

        csi->csi_fill = 1;

        return csi;
}

struct seq_operations mdd_cl_sops = {
        .start = mdd_cl_seq_start,
        .stop = mdd_cl_seq_stop,
        .next = mdd_cl_seq_next,
        .show = mdd_cl_seq_show,
};

static int mdd_cl_seq_open(struct inode *inode, struct file *file)
{
        struct cl_seq_iter *csi;
        struct proc_dir_entry *dp = PDE(inode);
        struct seq_file *seq;
        int rc;

        LPROCFS_ENTRY_AND_CHECK(dp);

        rc = seq_open(file, &mdd_cl_sops);
        if (rc)
                goto out;

        OBD_ALLOC_PTR(csi);
        if (csi == NULL) {
                rc = -ENOMEM;
                goto out;
        }
        csi->csi_mdd = dp->data;
        seq = file->private_data;
        seq->private = csi;

out:
        if (rc)
                LPROCFS_EXIT();
        return rc;
}

static int mdd_cl_seq_release(struct inode *inode, struct file *file)
{
        struct seq_file *seq = file->private_data;
        struct cl_seq_iter *csi = seq->private;

        OBD_FREE_PTR(csi);

        return lprocfs_seq_release(inode, file);
}

static loff_t mdd_cl_seq_lseek(struct file *file, loff_t offset, int origin)
{
        struct seq_file *seq = (struct seq_file *)file->private_data;
        struct cl_seq_iter *csi = seq->private;

        CDEBUG(D_CL, "seek "LPU64"-"LPU64" off="LPU64":%d fpos="LPU64"\n",
               csi->csi_startrec, csi->csi_endrec, offset, origin, file->f_pos);

        LL_SEQ_LOCK(seq);

        switch (origin) {
                case SEEK_CUR:
                        offset += csi->csi_endrec;
                        break;
                case SEEK_END:
                        spin_lock(&csi->csi_mdd->mdd_cl.mc_lock);
                        offset += csi->csi_mdd->mdd_cl.mc_index;
                        spin_unlock(&csi->csi_mdd->mdd_cl.mc_lock);
                        break;
        }

        /* SEEK_SET */

        if (offset < 0) {
                LL_SEQ_UNLOCK(seq);
                return -EINVAL;
        }

        csi->csi_startrec = offset;
        csi->csi_endrec = offset ? offset - 1 : 0;

        /* drop whatever is left in sucky seq_read's buffer */
        seq->count = 0;
        seq->from = 0;
        seq->index++;
        LL_SEQ_UNLOCK(seq);
        file->f_pos = csi->csi_startrec;
        return csi->csi_startrec;
}

static ssize_t mdd_cl_seq_read(struct file *file, char __user *buf,
                               size_t count, loff_t *ppos)
{
        struct seq_file *seq = (struct seq_file *)file->private_data;
        struct cl_seq_iter *csi = seq->private;

        if ((file->f_flags & O_NONBLOCK) && mdd_cl_done(csi))
                return -EAGAIN;
        return seq_read(file, buf, count, ppos);
}

static unsigned int mdd_cl_seq_poll(struct file *file, poll_table *wait)
{   /* based on kmsg_poll */
        struct seq_file *seq = (struct seq_file *)file->private_data;
        struct cl_seq_iter *csi = seq->private;

        poll_wait(file, &csi->csi_mdd->mdd_cl.mc_waitq, wait);
        if (!mdd_cl_done(csi))
                return POLLIN | POLLRDNORM;

        return 0;
}

struct file_operations mdd_changelog_fops = {
        .owner   = THIS_MODULE,
        .open    = mdd_cl_seq_open,
        .read    = mdd_cl_seq_read,
        .write   = mdd_cl_seq_write,
        .llseek  = mdd_cl_seq_lseek,
        .poll    = mdd_cl_seq_poll,
        .release = mdd_cl_seq_release,
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
        { "atime_diff", lprocfs_rd_atime_diff, lprocfs_wr_atime_diff, 0 },
        { "changelog_mask", lprocfs_rd_cl_mask, lprocfs_wr_cl_mask, 0 },
        { "changelog", 0, lprocfs_wr_cl, 0, &mdd_changelog_fops, 0600 },
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

