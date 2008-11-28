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

#include <lustre/lustre_idl.h>

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
