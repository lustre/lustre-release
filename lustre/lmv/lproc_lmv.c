/*
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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/version.h>
#include <linux/seq_file.h>
#include <asm/statfs.h>
#include <lprocfs_status.h>
#include <obd_class.h>

#include "lmv_internal.h"

#ifndef CONFIG_PROC_FS
static struct lprocfs_vars lprocfs_module_vars[] = { {0} };
static struct lprocfs_vars lprocfs_obd_vars[] = { {0} };
#else
static int lmv_numobd_seq_show(struct seq_file *m, void *v)
{
	struct obd_device	*dev = (struct obd_device *)m->private;
        struct lmv_desc         *desc;

        LASSERT(dev != NULL);
        desc = &dev->u.lmv.desc;
	seq_printf(m, "%u\n", desc->ld_tgt_count);
	return 0;
}
LPROC_SEQ_FOPS_RO(lmv_numobd);

static int lmv_activeobd_seq_show(struct seq_file *m, void *v)
{
	struct obd_device	*dev = (struct obd_device *)m->private;
        struct lmv_desc         *desc;

        LASSERT(dev != NULL);
        desc = &dev->u.lmv.desc;
	seq_printf(m, "%u\n", desc->ld_active_tgt_count);
	return 0;
}
LPROC_SEQ_FOPS_RO(lmv_activeobd);

static int lmv_desc_uuid_seq_show(struct seq_file *m, void *v)
{
	struct obd_device	*dev = (struct obd_device*)m->private;
        struct lmv_obd          *lmv;

        LASSERT(dev != NULL);
        lmv = &dev->u.lmv;
	seq_printf(m, "%s\n", lmv->desc.ld_uuid.uuid);
	return 0;
}
LPROC_SEQ_FOPS_RO(lmv_desc_uuid);

static void *lmv_tgt_seq_start(struct seq_file *p, loff_t *pos)
{
	struct obd_device       *dev = p->private;
	struct lmv_obd          *lmv = &dev->u.lmv;

	while (*pos < lmv->tgts_size) {
		if (lmv->tgts[*pos] != NULL)
			return lmv->tgts[*pos];

		++*pos;
	}

	return  NULL;
}

static void lmv_tgt_seq_stop(struct seq_file *p, void *v)
{
        return;
}

static void *lmv_tgt_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct obd_device       *dev = p->private;
	struct lmv_obd          *lmv = &dev->u.lmv;

	++*pos;
	while (*pos < lmv->tgts_size) {
		if (lmv->tgts[*pos] != NULL)
			return lmv->tgts[*pos];

		++*pos;
	}

	return  NULL;
}

static int lmv_tgt_seq_show(struct seq_file *p, void *v)
{
	struct lmv_tgt_desc     *tgt = v;

	if (tgt == NULL)
		return 0;
	seq_printf(p, "%u: %s %sACTIVE\n", tgt->ltd_idx,
		  tgt->ltd_uuid.uuid, tgt->ltd_active ? "" : "IN");
	return 0;
}

static const struct seq_operations lmv_tgt_sops = {
        .start                 = lmv_tgt_seq_start,
        .stop                  = lmv_tgt_seq_stop,
        .next                  = lmv_tgt_seq_next,
        .show                  = lmv_tgt_seq_show,
};

static int lmv_target_seq_open(struct inode *inode, struct file *file)
{
        struct seq_file         *seq;
        int                     rc;

        rc = seq_open(file, &lmv_tgt_sops);
        if (rc)
                return rc;

	seq = file->private_data;
	seq->private = PDE_DATA(inode);
	return 0;
}

LPROC_SEQ_FOPS_RO_TYPE(lmv, uuid);

struct lprocfs_vars lprocfs_lmv_obd_vars[] = {
	{ .name	=	"numobd",
	  .fops	=	&lmv_numobd_fops	},
	{ .name	=	"activeobd",
	  .fops	=	&lmv_activeobd_fops	},
	{ .name	=	"uuid",
	  .fops	=	&lmv_uuid_fops		},
	{ .name	=	"desc_uuid",
	  .fops	=	&lmv_desc_uuid_fops	},
	{ NULL }
};

struct file_operations lmv_proc_target_fops = {
        .owner                = THIS_MODULE,
        .open                 = lmv_target_seq_open,
        .read                 = seq_read,
        .llseek               = seq_lseek,
        .release              = seq_release,
};
#endif /* CONFIG_PROC_FS */
