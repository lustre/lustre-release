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

#include <linux/lustre_lite.h>
#include <linux/lprocfs_status.h>

#ifndef LPROCFS
static struct lprocfs_vars lprocfs_obd_vars[] = { {0} };
static struct lprocfs_vars lprocfs_module_vars[] = { {0} };
#else
/* Common STATUS namespace */
static int cobd_rd_target(char *page, char **start, off_t off, int count,
                          int *eof, void *data)
{
        struct obd_device *cobd = (struct obd_device *)data;
        int    rc;

        LASSERT(cobd != NULL);

        if (!cobd->obd_set_up) {
                rc = snprintf(page, count, "not set up\n");
        } else {
                struct obd_device *tgt =
                        class_exp2obd(cobd->u.cobd.cobd_target_exp);
                LASSERT(tgt != NULL);
                rc = snprintf(page, count, "%s\n", tgt->obd_uuid.uuid);
        }
        return rc;
}

static int cobd_rd_cache(char *page, char **start, off_t off, int count,
                         int *eof, void *data)
{
        struct obd_device *cobd = (struct obd_device*)data;
        int    rc;

        LASSERT(cobd != NULL);

        if (!cobd->obd_set_up) {
                rc = snprintf(page, count, "not set up\n");
        } else {
                struct obd_device *cache =
                        class_exp2obd(cobd->u.cobd.cobd_cache_exp);
                LASSERT(cache != NULL);
                rc = snprintf(page, count, "%s\n", cache->obd_uuid.uuid);
        }
        return rc;
}

static struct lprocfs_vars lprocfs_obd_vars[] = {
        { "uuid",         lprocfs_rd_uuid,        0, 0 },
        { "target_uuid",  cobd_rd_target,         0, 0 },
        { "cache_uuid",   cobd_rd_cache,          0, 0 },
        { 0 }
};

struct lprocfs_vars lprocfs_module_vars[] = {
        { "num_refs",     lprocfs_rd_numrefs,     0, 0 },
        { 0 }
};
#endif /* LPROCFS */

LPROCFS_INIT_VARS(cobd, lprocfs_module_vars, lprocfs_obd_vars)
