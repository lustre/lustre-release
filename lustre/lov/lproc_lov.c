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
#include <linux/lprocfs_status.h>
#include <linux/obd_class.h>
#include <linux/seq_file.h>

#ifndef LPROCFS
static struct lprocfs_vars lprocfs_module_vars[] = { {0} };
static struct lprocfs_vars lprocfs_obd_vars[] = { {0} };
#else

static int lov_rd_stripesize(char *page, char **start, off_t off, int count,
                             int *eof, void *data)
{
        struct obd_device *dev = (struct obd_device *)data;
        struct lov_desc *desc;

        LASSERT(dev != NULL);
        desc = &dev->u.lov.desc;
        *eof = 1;
        return snprintf(page, count, LPU64"\n", desc->ld_default_stripe_size);
}

static int lov_rd_stripeoffset(char *page, char **start, off_t off, int count,
                               int *eof, void *data)
{
        struct obd_device *dev = (struct obd_device *)data;
        struct lov_desc *desc;

        LASSERT(dev != NULL);
        desc = &dev->u.lov.desc;
        *eof = 1;
        return snprintf(page, count, LPU64"\n", desc->ld_default_stripe_offset);
}

static int lov_rd_stripetype(char *page, char **start, off_t off, int count,
                             int *eof, void *data)
{
        struct obd_device* dev = (struct obd_device*)data;
        struct lov_desc *desc;

        LASSERT(dev != NULL);
        desc = &dev->u.lov.desc;
        *eof = 1;
        return snprintf(page, count, "%u\n", desc->ld_pattern);
}

static int lov_rd_stripecount(char *page, char **start, off_t off, int count,
                              int *eof, void *data)
{
        struct obd_device *dev = (struct obd_device *)data;
        struct lov_desc *desc;

        LASSERT(dev != NULL);
        desc = &dev->u.lov.desc;
        *eof = 1;
        return snprintf(page, count, "%u\n", desc->ld_default_stripe_count);
}

static int lov_rd_numobd(char *page, char **start, off_t off, int count,
                         int *eof, void *data)
{
        struct obd_device *dev = (struct obd_device*)data;
        struct lov_desc *desc;

        LASSERT(dev != NULL);
        desc = &dev->u.lov.desc;
        *eof = 1;
        return snprintf(page, count, "%u\n", desc->ld_tgt_count);

}

static int lov_rd_activeobd(char *page, char **start, off_t off, int count,
                            int *eof, void *data)
{
        struct obd_device* dev = (struct obd_device*)data;
        struct lov_desc *desc;

        LASSERT(dev != NULL);
        desc = &dev->u.lov.desc;
        *eof = 1;
        return snprintf(page, count, "%u\n", desc->ld_active_tgt_count);
}

static int lov_rd_desc_uuid(char *page, char **start, off_t off, int count,
                            int *eof, void *data)
{
        struct obd_device *dev = (struct obd_device*) data;
        struct lov_obd *lov;

        LASSERT(dev != NULL);
        lov = &dev->u.lov;
        *eof = 1;
        return snprintf(page, count, "%s\n", lov->desc.ld_uuid.uuid);
}

static void *lov_tgt_seq_start(struct seq_file *p, loff_t *pos)
{
        struct obd_device *dev = p->private;
        struct lov_obd *lov = &dev->u.lov;

        return (*pos >= lov->desc.ld_tgt_count) ? NULL : &(lov->tgts[*pos]);

}

static void lov_tgt_seq_stop(struct seq_file *p, void *v)
{
}

static void *lov_tgt_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
        struct obd_device *dev = p->private;
        struct lov_obd *lov = &dev->u.lov;

        ++*pos;
        return (*pos >=lov->desc.ld_tgt_count) ? NULL : &(lov->tgts[*pos]);
}

static int lov_tgt_seq_show(struct seq_file *p, void *v)
{
        struct lov_tgt_desc *tgt = v;
        struct obd_device *dev = p->private;
        struct lov_obd *lov = &dev->u.lov;
        int idx = tgt - &(lov->tgts[0]);
        return seq_printf(p, "%d: %s %sACTIVE\n", idx, tgt->uuid.uuid,
                          tgt->active ? "" : "IN");
}

struct seq_operations lov_tgt_sops = {
        .start = lov_tgt_seq_start,
        .stop = lov_tgt_seq_stop,
        .next = lov_tgt_seq_next,
        .show = lov_tgt_seq_show,
};

static int lov_target_seq_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = PDE(inode);
        struct seq_file *seq;
        int rc = seq_open(file, &lov_tgt_sops);

        if (rc)
                return rc;

        seq = file->private_data;
        seq->private = dp->data;

        return 0;
}

struct lprocfs_vars lprocfs_obd_vars[] = {
        { "uuid",         lprocfs_rd_uuid,        0, 0 },
        { "stripesize",   lov_rd_stripesize,      0, 0 },
        { "stripeoffset", lov_rd_stripeoffset,    0, 0 },
        { "stripecount",  lov_rd_stripecount,     0, 0 },
        { "stripetype",   lov_rd_stripetype,      0, 0 },
        { "numobd",       lov_rd_numobd,          0, 0 },
        { "activeobd",    lov_rd_activeobd,       0, 0 },
        { "filestotal",   lprocfs_rd_filestotal,  0, 0 },
        { "filesfree",    lprocfs_rd_filesfree,   0, 0 },
        //{ "filegroups",   lprocfs_rd_filegroups,  0, 0 },
        { "blocksize",    lprocfs_rd_blksize,     0, 0 },
        { "kbytestotal",  lprocfs_rd_kbytestotal, 0, 0 },
        { "kbytesfree",   lprocfs_rd_kbytesfree,  0, 0 },
        { "desc_uuid",    lov_rd_desc_uuid,       0, 0 },
        { 0 }
};

static struct lprocfs_vars lprocfs_module_vars[] = {
        { "num_refs",     lprocfs_rd_numrefs,     0, 0 },
        { 0 }
};

struct file_operations lov_proc_target_fops = {
        .open = lov_target_seq_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = seq_release,
};

#endif /* LPROCFS */
LPROCFS_INIT_VARS(lov, lprocfs_module_vars, lprocfs_obd_vars)
