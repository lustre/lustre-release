/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  cmm/cmm_lproc.c
 *  CMM lprocfs stuff
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Wang Di      <wangdi@clusterfs.com>
 *   Author: Yury Umanets <umka@clusterfs.com>
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

#include "cmm_internal.h"

static int cmm_procfs_init_stats(struct cmm_device *cmm, int num_stats)
{
        struct lprocfs_stats *stats;
        int rc;
        ENTRY;
        
        stats = lprocfs_alloc_stats(num_stats);
        if (!stats)
                RETURN(-ENOMEM);

        rc = lprocfs_register_stats(cmm->cmm_proc_entry, "stats", stats);
        if (rc != 0)
                GOTO(cleanup, rc);

        cmm->cmm_stats = stats;

        lprocfs_counter_init(cmm->cmm_stats, LPROC_CMM_LOOKUP,
                             LPROCFS_CNTR_AVGMINMAX, "lookup", "time");
        lprocfs_counter_init(cmm->cmm_stats, LPROC_CMM_SPLIT,
                             LPROCFS_CNTR_AVGMINMAX, "split", "time");
        lprocfs_counter_init(cmm->cmm_stats, LPROC_CMM_SPLIT_CHECK,
                             LPROCFS_CNTR_AVGMINMAX, "split_check", "time");
        EXIT;
cleanup:
        if (rc) {
                lprocfs_free_stats(stats);
                cmm->cmm_stats = NULL;
        }
        return rc;
}

int cmm_procfs_init(struct cmm_device *cmm, const char *name)
{
        struct lu_device    *ld = &cmm->cmm_md_dev.md_lu_dev;
        struct obd_type     *type;
        int                  rc;
        ENTRY;

        type = ld->ld_type->ldt_obd_type;
        
        LASSERT(name != NULL);
        LASSERT(type != NULL);

        /* Find the type procroot and add the proc entry for this device. */
        cmm->cmm_proc_entry = lprocfs_register(name, type->typ_procroot,
                                               NULL, NULL);
        if (IS_ERR(cmm->cmm_proc_entry)) {
                rc = PTR_ERR(cmm->cmm_proc_entry);
                CERROR("Error %d setting up lprocfs for %s\n", 
                       rc, name);
                cmm->cmm_proc_entry = NULL;
                GOTO(out, rc);
        }

        rc = cmm_procfs_init_stats(cmm, LPROC_CMM_LAST);
        EXIT;
out:
        if (rc)
               cmm_procfs_fini(cmm); 
	return rc;
}

int cmm_procfs_fini(struct cmm_device *cmm)
{
        if (cmm->cmm_stats) {
                lprocfs_free_stats(cmm->cmm_stats);
                cmm->cmm_stats = NULL;
        }
        if (cmm->cmm_proc_entry) {
                 lprocfs_remove(cmm->cmm_proc_entry);
                 cmm->cmm_proc_entry = NULL;
        }
        RETURN(0);
}

void cmm_lprocfs_time_start(struct cmm_device *cmm,
			    struct timeval *start, int op)
{
        do_gettimeofday(start);
}

void cmm_lprocfs_time_end(struct cmm_device *cmm,
			  struct timeval *start, int op)
{
        struct timeval end;
        long timediff;

        do_gettimeofday(&end);
        timediff = cfs_timeval_sub(&end, start, NULL);

        if (cmm->cmm_stats)
                lprocfs_counter_add(cmm->cmm_stats, op, timediff);
        return;
}
