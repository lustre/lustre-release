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

static int ll_retry_recovery(struct ptlrpc_connection *conn)
{
    ENTRY;
    RETURN(0);
}

int ll_recover(struct recovd_data *rd, int phase)
{
        struct ptlrpc_connection *conn = class_rd2conn(rd);

        LASSERT(conn);
        ENTRY;

        switch (phase) {
            case PTLRPC_RECOVD_PHASE_PREPARE:
                RETURN(ptlrpc_run_recovery_upcall(conn));
            case PTLRPC_RECOVD_PHASE_RECOVER:
                RETURN(ptlrpc_reconnect_and_replay(conn));
            case PTLRPC_RECOVD_PHASE_FAILURE:
                RETURN(ll_retry_recovery(conn));
        }

        LBUG();
        RETURN(-ENOSYS);
}
