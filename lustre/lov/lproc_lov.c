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

#include <linux/lprocfs_status.h>
#include <linux/obd_class.h>

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
        struct lov_desc *desc = &dev->u.lov.desc;

        *eof = 1;
        return snprintf(page, count, LPU64"\n", desc->ld_default_stripe_size);
}

int rd_stripeoffset(char *page, char **start, off_t off, int count, int *eof,
                    void *data)
{
        struct obd_device *dev = (struct obd_device *)data;
        struct lov_desc *desc = &dev->u.lov.desc;

        *eof = 1;
        return snprintf(page, count, LPU64"\n", desc->ld_default_stripe_offset);
}

int rd_stripetype(char *page, char **start, off_t off, int count, int *eof,
                  void *data)
{
        struct obd_device* dev = (struct obd_device*)data;
        struct lov_desc *desc = &dev->u.lov.desc;

        *eof = 1;
        return snprintf(page, count, "%u\n", desc->ld_pattern);
}

int rd_stripecount(char *page, char **start, off_t off, int count, int *eof,
                   void *data)
{
        struct obd_device *dev = (struct obd_device *)data;
        struct lov_desc *desc = &dev->u.lov.desc;

        *eof = 1;
        return snprintf(page, count, "%u\n", desc->ld_default_stripe_count);
}

int rd_numobd(char *page, char **start, off_t off, int count, int *eof,
              void *data)
{
        struct obd_device *dev = (struct obd_device*)data;
        struct lov_desc *desc = &dev->u.lov.desc;

        *eof = 1;
        return snprintf(page, count, "%u\n", desc->ld_tgt_count);

}

int rd_activeobd(char *page, char **start, off_t off, int count, int *eof,
                 void *data)
{
        struct obd_device* dev = (struct obd_device*)data;
        struct lov_desc *desc = &dev->u.lov.desc;

        *eof = 1;
        return snprintf(page, count, "%u\n", desc->ld_active_tgt_count);
}

int rd_target(char *page, char **start, off_t off, int count, int *eof,
              void *data)
{
        struct obd_device *dev = (struct obd_device*) data;
        int len = 0, i;
        struct lov_obd *lov = &dev->u.lov;
        struct lov_tgt_desc *tgts = lov->tgts;

        for (i = 0; i < lov->desc.ld_tgt_count; i++, tgts++) {
                int cur;
                cur = snprintf(&page[len], count, "%d: %s %sACTIVE\n",
                                i, tgts->uuid.uuid, tgts->active ? "" : "IN");
                len += cur;
                count -= cur;
        }

        *eof = 1;
        return len;
}

int rd_mdc(char *page, char **start, off_t off, int count, int *eof, void *data)
{
        struct obd_device *dev = (struct obd_device*) data;
        struct lov_obd *lov = &dev->u.lov;

        *eof = 1;
        return snprintf(page, count, "%s\n", lov->mdcobd->obd_uuid.uuid);
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
        { "target_obd",   rd_target,       0, 0 },
        { "target_mdc",   rd_mdc,          0, 0 },
        { 0 }
};

struct lprocfs_vars lprocfs_module_vars[] = {
        { "num_refs",     lprocfs_rd_numrefs, 0, 0 },
        { 0 }
};

#endif /* LPROCFS */
LPROCFS_INIT_VARS(lprocfs_module_vars, lprocfs_obd_vars)
