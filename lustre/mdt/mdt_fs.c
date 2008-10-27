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
 * lustre/mdt/mdt_fs.c
 *
 * Lustre Metadata Server (MDS) filesystem interface code
 */
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"

int mdt_export_stats_init(struct obd_device *obd,
                          struct obd_export *exp,
                          void              *localdata)
{
        lnet_nid_t *client_nid = localdata;
        int        rc, newnid;

        rc = lprocfs_exp_setup(exp, client_nid, &newnid);
        if (rc) {
                /* Mask error for already created
                 * /proc entries */
                if (rc == -EALREADY)
                        rc = 0;
                return rc;
        }

        if ((obd->md_stats == NULL) &&
            (rc = lprocfs_alloc_md_stats(obd, LPROC_MDT_NR)))
                return rc;
        if (newnid) {
                /* Always add in ldlm_stats */
                exp->exp_nid_stats->nid_ldlm_stats =
                        lprocfs_alloc_stats(LDLM_LAST_OPC - LDLM_FIRST_OPC, 0);
                if (exp->exp_nid_stats->nid_ldlm_stats == NULL)
                        return -ENOMEM;
                lprocfs_init_ldlm_stats(exp->exp_nid_stats->nid_ldlm_stats);
                rc = lprocfs_register_stats(exp->exp_nid_stats->nid_proc,
                                            "ldlm_stats",
                                            exp->exp_nid_stats->nid_ldlm_stats);
        }
        return rc;
}
