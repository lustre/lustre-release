/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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
 *
 */
#define DEBUG_SUBSYSTEM S_OST

#include <obd_class.h>
#include <lprocfs_status.h>
#include <linux/seq_file.h>
#include "ost_internal.h"

#ifdef LPROCFS
static struct lprocfs_vars lprocfs_obd_vars[] = {
        { "uuid",            lprocfs_rd_uuid,   0, 0 },
        { 0 }
};

static struct lprocfs_vars lprocfs_module_vars[] = {
        { "num_refs",       lprocfs_rd_numrefs, 0, 0 },
        { 0 }
};

void
ost_print_req(void *seq_file, struct ptlrpc_request *req)
{
        /* Called holding srv_lock with irqs disabled.
         * Print specific req contents and a newline.
         * CAVEAT EMPTOR: check request message length before printing!!!
         * You might have received any old crap so you must be just as
         * careful here as the service's request parser!!! */
        struct seq_file *sf = seq_file;

        switch (req->rq_phase) {
        case RQ_PHASE_NEW:
                /* still awaiting a service thread's attention, or rejected
                 * because the generic request message didn't unpack */
                seq_printf(sf, "<not swabbed>\n");
                break;
                
        case RQ_PHASE_INTERPRET:
                /* being handled, so basic msg swabbed, and opc is valid
                 * but racing with ost_handle() */
                seq_printf(sf, "opc %d\n", lustre_msg_get_opc(req->rq_reqmsg));
                break;
                
        case RQ_PHASE_COMPLETE:
                /* been handled by ost_handle() reply state possibly still
                 * volatile */
                seq_printf(sf, "opc %d\n", lustre_msg_get_opc(req->rq_reqmsg));
                break;

        default:
                LBUG();
        }
}

LPROCFS_INIT_VARS(ost, lprocfs_module_vars, lprocfs_obd_vars)
#endif /* LPROCFS */
