/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Lite recovery infrastructure.
 *
 * Copyright (C) 2002 Cluster File Systems Inc.
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_idl.h>

static int ll_retry_recovery(struct ptlrpc_connection *conn)
{
        ENTRY;
        RETURN(0);
}

int ll_recover(struct recovd_data *rd, int phase)
{
        struct ptlrpc_connection *conn = class_rd2conn(rd);
        struct list_head *tmp;

        LASSERT(conn);
        ENTRY;

        switch (phase) {
            case PTLRPC_RECOVD_PHASE_PREPARE:
            case PTLRPC_RECOVD_PHASE_RECOVER:
                list_for_each(tmp, &conn->c_imports) {
                        struct obd_import *imp = 
                                list_entry(tmp, struct obd_import, imp_chain);

                        if (phase == PTLRPC_RECOVD_PHASE_PREPARE) {
                                spin_lock(&imp->imp_lock);
                                imp->imp_level = LUSTRE_CONN_RECOVD;
                                spin_unlock(&imp->imp_lock);
                        }
                        imp->imp_recover(imp, phase);
                }
                
                if (phase == PTLRPC_RECOVD_PHASE_PREPARE)
                        RETURN(ptlrpc_run_recovery_upcall(conn));
                RETURN(0);
                        
            case PTLRPC_RECOVD_PHASE_FAILURE:
                RETURN(ll_retry_recovery(conn));
        }

        LBUG();
        RETURN(-ENOSYS);
}
