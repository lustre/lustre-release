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
 */
#define DEBUG_SUBSYSTEM S_OST

#include <obd_class.h>
#include <lprocfs_status.h>
#include <linux/seq_file.h>
#include "ost_internal.h"

#ifdef LPROCFS
static char *sync_on_cancel_states[] = {"never",
                                        "blocking",
                                        "always" };

int lprocfs_ost_rd_ost_sync_on_lock_cancel(char *page, char **start, off_t off,
                                           int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        int rc;

        rc = snprintf(page, count, "%s\n",
                     sync_on_cancel_states[obd->u.ost.ost_sync_on_lock_cancel]);
        return rc;
}

int lprocfs_ost_wr_ost_sync_on_lock_cancel(struct file *file,
                                           const char *buffer,
                                           unsigned long count, void *data)
{
        struct obd_device *obd = data;
        int val = -1;
        int i;

        for (i = 0 ; i < NUM_SYNC_ON_CANCEL_STATES; i++) {
                if (memcmp(buffer, sync_on_cancel_states[i],
                    strlen(sync_on_cancel_states[i])) == 0) {
                        val = i;
                        break;
                }
        }
        if (val == -1) {
                int rc;
                rc = lprocfs_write_helper(buffer, count, &val);
                if (rc)
                        return rc;
        }

        if (val < 0 || val > 2)
                return -EINVAL;

        obd->u.ost.ost_sync_on_lock_cancel = val;
        return count;
}

static struct lprocfs_vars lprocfs_ost_obd_vars[] = {
        { "uuid",            lprocfs_rd_uuid,   0, 0 },
        { "sync_on_lock_cancel", lprocfs_ost_rd_ost_sync_on_lock_cancel,
                                 lprocfs_ost_wr_ost_sync_on_lock_cancel, 0 },
        { 0 }
};

static struct lprocfs_vars lprocfs_ost_module_vars[] = {
        { "num_refs",       lprocfs_rd_numrefs, 0, 0 },
        { 0 }
};

void lprocfs_ost_init_vars(struct lprocfs_static_vars *lvars)
{
    lvars->module_vars  = lprocfs_ost_module_vars;
    lvars->obd_vars     = lprocfs_ost_obd_vars;
}
#endif /* LPROCFS */
