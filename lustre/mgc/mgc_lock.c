/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2005 Cluster File Systems, Inc.
 *   Author LinSongTao <lincent@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org
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
 *  For testing and management it is treated as an obd_device,
 *  although * it does not export a full OBD method table (the
 *  requests are coming * in over the wire, so object target modules
 *  do not have a full * method table.)
 */
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MGC

#ifdef __KERNEL__
# include <linux/module.h>
# include <linux/pagemap.h>
# include <linux/miscdevice.h>
# include <linux/init.h>
#else
# include <liblustre.h>
#endif

#include <linux/obd_class.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_log.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_disk.h>

#include "mgc_internal.h"

int mgc_enqueue(struct obd_export *exp, int lock_mode, 
                struct mgc_op_data *data, struct lustre_handle *lockh,
                ldlm_completion_callback cb_completion,
                ldlm_blocking_callback cb_blocking,
                void *cb_data)
{    
        struct ptlrpc_request *req;
        struct obd_device *obddev = class_exp2obd(exp);
        struct ldlm_res_id res_id =
                { .name = {data->obj_id, 
                           data->obj_version} 
                };
        int rc = 0, flags = 0;
        struct ldlm_reply *dlm_rep;
        struct ldlm_request *lockreq;
        unsigned long irqflags;
        int   reply_buffers = 0;
        ENTRY;

        /* Search for already existing locks.*/
        rc = ldlm_lock_match(obd->obd_namespace, 0, &res_id, LDLM_LLOG, 
                             NULL, mode, lockh);
        if (rc == 1) 
                RETURN(ELDLM_OK);

        rc = ldlm_cli_enqueue(exp, req, obd->obd_namespace, res_id, LDLM_LLOG,
                              NULL, mode, flags, bl_cb, cp_cb, gl_cb, data,
                              NULL, 0, NULL, lockh);

        if (req != NULL) {
                if (rc == ELDLM_LOCK_ABORTED) {
                        /* swabbed by ldlm_cli_enqueue() */
                        LASSERT_REPSWABBED(req, 0);
                        rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*rep));
                        LASSERT(rep != NULL);
                        if (rep->lock_policy_res1)
                                rc = rep->lock_policy_res1;
                }
                ptlrpc_req_finished(req);
        }

        RETURN(rc);
}
EXPORT_SYMBOL(mgc_enqueue)
