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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/cmm/cmm_lproc.c
 *
 * CMM lprocfs stuff
 *
 * Author: Wang Di      <wangdi@clusterfs.com>
 * Author: Yury Umanets <umka@clusterfs.com>
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

#include "cmm_internal.h"
/**
 * \addtogroup cmm
 * @{
 */
static const char *cmm_counter_names[LPROC_CMM_NR] = {
        [LPROC_CMM_SPLIT_CHECK] = "split_check",
        [LPROC_CMM_SPLIT]       = "split",
        [LPROC_CMM_LOOKUP]      = "lookup",
        [LPROC_CMM_CREATE]      = "create"
};

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

        rc = lu_time_init(&cmm->cmm_stats,
                          cmm->cmm_proc_entry,
                          cmm_counter_names, ARRAY_SIZE(cmm_counter_names));

        EXIT;
out:
        if (rc)
               cmm_procfs_fini(cmm);
	return rc;
}

int cmm_procfs_fini(struct cmm_device *cmm)
{
        if (cmm->cmm_stats)
                lu_time_fini(&cmm->cmm_stats);

        if (cmm->cmm_proc_entry) {
                 lprocfs_remove(&cmm->cmm_proc_entry);
                 cmm->cmm_proc_entry = NULL;
        }
        RETURN(0);
}

void cmm_lprocfs_time_start(const struct lu_env *env)
{
        lu_lprocfs_time_start(env);
}

void cmm_lprocfs_time_end(const struct lu_env *env, struct cmm_device *cmm,
                          int idx)
{
        lu_lprocfs_time_end(env, cmm->cmm_stats, idx);
}
/** @} */
