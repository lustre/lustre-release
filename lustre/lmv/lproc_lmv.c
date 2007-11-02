/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/version.h>
#include <linux/seq_file.h>
#include <asm/statfs.h>
#include <lprocfs_status.h>
#include <obd_class.h>

#ifndef LPROCFS
static struct lprocfs_vars lprocfs_module_vars[] = { {0} };
static struct lprocfs_vars lprocfs_obd_vars[] = { {0} };
#else
static int lmv_rd_numobd(char *page, char **start, off_t off, int count,
                         int *eof, void *data)
{
        struct obd_device *dev = (struct obd_device*)data;
        struct lmv_desc *desc;

        LASSERT(dev != NULL);
        desc = &dev->u.lmv.desc;
        *eof = 1;
        return snprintf(page, count, "%u\n", desc->ld_tgt_count);

}

static int lmv_rd_activeobd(char *page, char **start, off_t off, int count,
                            int *eof, void *data)
{
        struct obd_device* dev = (struct obd_device*)data;
        struct lmv_desc *desc;

        LASSERT(dev != NULL);
        desc = &dev->u.lmv.desc;
        *eof = 1;
        return snprintf(page, count, "%u\n", desc->ld_active_tgt_count);
}

static int lmv_rd_desc_uuid(char *page, char **start, off_t off, int count,
                            int *eof, void *data)
{
        struct obd_device *dev = (struct obd_device*) data;
        struct lmv_obd *lmv;

        LASSERT(dev != NULL);
        lmv = &dev->u.lmv;
        *eof = 1;
        return snprintf(page, count, "%s\n", lmv->desc.ld_uuid.uuid);
}

static void *lmv_tgt_seq_start(struct seq_file *p, loff_t *pos)
{
        struct obd_device *dev = p->private;
        struct lmv_obd *lmv = &dev->u.lmv;

        return (*pos >= lmv->desc.ld_tgt_count) ? NULL : &(lmv->tgts[*pos]);

}

static void lmv_tgt_seq_stop(struct seq_file *p, void *v)
{
        return;
}

static void *lmv_tgt_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
        struct obd_device *dev = p->private;
        struct lmv_obd *lmv = &dev->u.lmv;

        ++*pos;
        return (*pos >=lmv->desc.ld_tgt_count) ? NULL : &(lmv->tgts[*pos]);
}

static int lmv_tgt_seq_show(struct seq_file *p, void *v)
{
        struct lmv_tgt_desc *tgt = v;
        struct obd_device *dev = p->private;
        struct lmv_obd *lmv = &dev->u.lmv;
        int idx = tgt - &(lmv->tgts[0]);
        
        return seq_printf(p, "%d: %s %sACTIVE\n", idx, tgt->ltd_uuid.uuid,
                          tgt->ltd_active ? "" : "IN");
}

struct seq_operations lmv_tgt_sops = {
        .start = lmv_tgt_seq_start,
        .stop = lmv_tgt_seq_stop,
        .next = lmv_tgt_seq_next,
        .show = lmv_tgt_seq_show,
};

static int lmv_target_seq_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = PDE(inode);
        struct seq_file *seq;
        int rc = seq_open(file, &lmv_tgt_sops);

        if (rc)
                return rc;

        seq = file->private_data;
        seq->private = dp->data;

        return 0;
}

struct lprocfs_vars lprocfs_obd_vars[] = {
        { "numobd",       lmv_rd_numobd,          0, 0 },
        { "activeobd",    lmv_rd_activeobd,       0, 0 },
        { "uuid",         lprocfs_rd_uuid,        0, 0 },
        { "desc_uuid",    lmv_rd_desc_uuid,       0, 0 },
        { 0 }
};

static struct lprocfs_vars lprocfs_module_vars[] = {
        { "num_refs",     lprocfs_rd_numrefs,     0, 0 },
        { 0 }
};

struct file_operations lmv_proc_target_fops = {
        .owner   = THIS_MODULE,
        .open    = lmv_target_seq_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
        .release = seq_release,
};

#endif /* LPROCFS */
LPROCFS_INIT_VARS(lmv, lprocfs_module_vars, lprocfs_obd_vars)
