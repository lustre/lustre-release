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
struct lprocfs_vars lprocfs_module_vars[] = { {0} };
struct lprocfs_vars lprocfs_obd_vars[] = { {0} };
#else

DEFINE_LPROCFS_STATFS_FCT(rd_blksize,     obd_self_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_kbytestotal, obd_self_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_kbytesfree,  obd_self_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_filestotal,  obd_self_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_filesfree,   obd_self_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_filegroups,  obd_self_statfs);

int rd_stripesize(char *page, char **start, off_t off, int count, int *eof,
                  void *data)
{
        struct obd_device *dev = (struct obd_device *)data;
        struct lov_desc *desc;

        LASSERT(dev != NULL);
        desc = &dev->u.lov.desc;
        *eof = 1;
        return snprintf(page, count, LPU64"\n", desc->ld_default_stripe_size);
}

int rd_stripeoffset(char *page, char **start, off_t off, int count, int *eof,
                    void *data)
{
        struct obd_device *dev = (struct obd_device *)data;
        struct lov_desc *desc;

        LASSERT(dev != NULL);
        desc = &dev->u.lov.desc;
        *eof = 1;
        return snprintf(page, count, LPU64"\n", desc->ld_default_stripe_offset);
}

int rd_stripetype(char *page, char **start, off_t off, int count, int *eof,
                  void *data)
{
        struct obd_device* dev = (struct obd_device*)data;
        struct lov_desc *desc;

        LASSERT(dev != NULL);
        desc = &dev->u.lov.desc;
        *eof = 1;
        return snprintf(page, count, "%u\n", desc->ld_pattern);
}

int rd_stripecount(char *page, char **start, off_t off, int count, int *eof,
                   void *data)
{
        struct obd_device *dev = (struct obd_device *)data;
        struct lov_desc *desc;

        LASSERT(dev != NULL);
        desc = &dev->u.lov.desc;
        *eof = 1;
        return snprintf(page, count, "%u\n", desc->ld_default_stripe_count);
}

int rd_numobd(char *page, char **start, off_t off, int count, int *eof,
              void *data)
{
        struct obd_device *dev = (struct obd_device*)data;
        struct lov_desc *desc;

        LASSERT(dev != NULL);
        desc = &dev->u.lov.desc;
        *eof = 1;
        return snprintf(page, count, "%u\n", desc->ld_tgt_count);

}

int rd_activeobd(char *page, char **start, off_t off, int count, int *eof,
                 void *data)
{
        struct obd_device* dev = (struct obd_device*)data;
        struct lov_desc *desc;

        LASSERT(dev != NULL);
        desc = &dev->u.lov.desc;
        *eof = 1;
        return snprintf(page, count, "%u\n", desc->ld_active_tgt_count);
}

int rd_mdc(char *page, char **start, off_t off, int count, int *eof, void *data)
{
        struct obd_device *dev = (struct obd_device*) data;
        struct lov_obd *lov;

        LASSERT(dev != NULL);
        lov = &dev->u.lov;
        *eof = 1;
        return snprintf(page, count, "%s\n", lov->mdcobd->obd_uuid.uuid);
}

static void *ll_tgt_seq_start(struct seq_file *p, loff_t *pos)
{
        struct obd_device *dev = p->private;
        struct lov_obd *lov = &dev->u.lov;

        return (*pos >= lov->desc.ld_tgt_count) ? NULL : &(lov->tgts[*pos]);

}
static void ll_tgt_seq_stop(struct seq_file *p, void *v)
{

}

static void *ll_tgt_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
        struct obd_device *dev = p->private;
        struct lov_obd *lov = &dev->u.lov;

        ++*pos;
        return (*pos >=lov->desc.ld_tgt_count) ? NULL : &(lov->tgts[*pos]);
}

static int ll_tgt_seq_show(struct seq_file *p, void *v)
{
        struct lov_tgt_desc *tgt = v;
        struct obd_device *dev = p->private;
        struct lov_obd *lov = &dev->u.lov;
        int idx = tgt - &(lov->tgts[0]);
        return seq_printf(p, "%d: %s %sACTIVE\n", idx+1, tgt->uuid.uuid,
                          tgt->active ? "" : "IN");
}

struct seq_operations ll_tgt_sops = {
        .start = ll_tgt_seq_start,
        .stop = ll_tgt_seq_stop,
        .next = ll_tgt_seq_next,
        .show = ll_tgt_seq_show,
};

static int ll_target_seq_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = inode->u.generic_ip;
        struct seq_file *seq;
        int rc = seq_open(file, &ll_tgt_sops);

        if (rc)
                return rc;

        seq = file->private_data;
        seq->private = dp->data;

        return 0;
}
struct lprocfs_vars lprocfs_obd_vars[] = {
        { "uuid",         lprocfs_rd_uuid, 0, 0 },
        { "stripesize",   rd_stripesize,   0, 0 },
        { "stripeoffset", rd_stripeoffset, 0, 0 },
        { "stripecount",  rd_stripecount,  0, 0 },
        { "stripetype",   rd_stripetype,   0, 0 },
        { "numobd",       rd_numobd,       0, 0 },
        { "activeobd",    rd_activeobd,    0, 0 },
        { "filestotal",   rd_filestotal,   0, 0 },
        { "filesfree",    rd_filesfree,    0, 0 },
        { "filegroups",   rd_filegroups,   0, 0 },
        { "blocksize",    rd_blksize,      0, 0 },
        { "kbytestotal",  rd_kbytestotal,  0, 0 },
        { "kbytesfree",   rd_kbytesfree,   0, 0 },
        { "target_mdc",   rd_mdc,          0, 0 },
        { 0 }
};

struct lprocfs_vars lprocfs_module_vars[] = {
        { "num_refs",     lprocfs_rd_numrefs, 0, 0 },
        { 0 }
};

struct file_operations ll_proc_target_fops = {
        .open = ll_target_seq_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = seq_release,
};

#endif /* LPROCFS */
LPROCFS_INIT_VARS(lprocfs_module_vars, lprocfs_obd_vars)
