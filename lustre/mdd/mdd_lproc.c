/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  mdd/mdd_handler.c
 *  Lustre Metadata Server (mdd) routines
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Wang Di <wangdi@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
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

#include <lustre/lustre_idl.h>

#include "mdd_internal.h"

static int mdd_procfs_init_stats(struct mdd_device *mdd, int num_stats)
{
        struct lprocfs_stats *stats;
        int rc;
        ENTRY;
        
        stats = lprocfs_alloc_stats(num_stats);
        if (!stats)
                RETURN(-ENOMEM);

        rc = lprocfs_register_stats(mdd->mdd_proc_entry, "stats", stats);
        if (rc != 0)
                GOTO(cleanup, rc);

        mdd->mdd_stats = stats;

        lprocfs_counter_init(mdd->mdd_stats, LPROC_MDD_OPEN,
                             LPROCFS_CNTR_AVGMINMAX, "open", "time");
        lprocfs_counter_init(mdd->mdd_stats, LPROC_MDD_CREATE,
                             LPROCFS_CNTR_AVGMINMAX, "create", "time");
        lprocfs_counter_init(mdd->mdd_stats, LPROC_MDD_INDEX_INSERT,
                             LPROCFS_CNTR_AVGMINMAX, "index_insert", "time");
        lprocfs_counter_init(mdd->mdd_stats, LPROC_MDD_INDEX_DELETE,
                             LPROCFS_CNTR_AVGMINMAX, "index_delete", "time");
        lprocfs_counter_init(mdd->mdd_stats, LPROC_MDD_UNLINK,
                             LPROCFS_CNTR_AVGMINMAX, "unlink", "time");
        lprocfs_counter_init(mdd->mdd_stats, LPROC_MDD_UNLINK_LOG,
                             LPROCFS_CNTR_AVGMINMAX, "unlink_log", "time");
        lprocfs_counter_init(mdd->mdd_stats, LPROC_MDD_LOV_CREATE,
                             LPROCFS_CNTR_AVGMINMAX, "lov_create", "time");
        lprocfs_counter_init(mdd->mdd_stats, LPROC_MDD_SET_MD,
                             LPROCFS_CNTR_AVGMINMAX, "set_md", "time");
        lprocfs_counter_init(mdd->mdd_stats, LPROC_MDD_GET_MD,
                             LPROCFS_CNTR_AVGMINMAX, "get_md", "time");
        lprocfs_counter_init(mdd->mdd_stats, LPROC_MDD_LOOKUP,
                             LPROCFS_CNTR_AVGMINMAX, "lookup", "lookup");
cleanup:
        if (rc) {
                lprocfs_free_stats(stats);
                mdd->mdd_stats = NULL;
        }
        RETURN(rc);
}

int mdd_procfs_fini(struct mdd_device *mdd)
{
        if (mdd->mdd_stats) {
                lprocfs_free_stats(mdd->mdd_stats);
                mdd->mdd_stats = NULL;
        }
        if (mdd->mdd_proc_entry) {
                 lprocfs_remove(mdd->mdd_proc_entry);
                 mdd->mdd_proc_entry = NULL;
        }
        RETURN(0);
}

int mdd_procfs_init(struct mdd_device *mdd, const char *name)
{
        struct lu_device    *ld = &mdd->mdd_md_dev.md_lu_dev;
        struct obd_type     *type;
        int                  rc;
        ENTRY;

        type = ld->ld_type->ldt_obd_type;
        
        LASSERT(name != NULL);
        LASSERT(type != NULL);

        /* Find the type procroot and add the proc entry for this device */
        mdd->mdd_proc_entry = lprocfs_register(name, type->typ_procroot,
                                               NULL, NULL);
        if (IS_ERR(mdd->mdd_proc_entry)) {
                rc = PTR_ERR(mdd->mdd_proc_entry);
                CERROR("Error %d setting up lprocfs for %s\n", 
                       rc, name);
                mdd->mdd_proc_entry = NULL;
                GOTO(out, rc);
        }

        rc = mdd_procfs_init_stats(mdd, LPROC_MDD_LAST);
        EXIT;
out:
        if (rc)
               mdd_procfs_fini(mdd); 
	return rc;
}

void mdd_lproc_time_start(struct mdd_device *mdd, struct timeval *start, int op)
{
        do_gettimeofday(start);
}

void mdd_lproc_time_end(struct mdd_device *mdd, struct timeval *start, int op)
{
        struct timeval end;
        long timediff;

        do_gettimeofday(&end);
        timediff = cfs_timeval_sub(&end, start, NULL);

        if (mdd->mdd_stats)
                lprocfs_counter_add(mdd->mdd_stats, op, timediff);
        return;
}
