/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _LUSTRE_HA_H
#define _LUSTRE_HA_H

#define LUSTRE_HA_NAME "ptlrpc"

struct recovd_data {
        struct list_head rd_managed_chain;
        int (*rd_recover)(struct recovd_data *);
};

struct recovd_obd;
struct ptlrpc_connection;

void recovd_conn_fail(struct ptlrpc_connection *conn);
void recovd_conn_manage(struct recovd_obd *mgr, struct ptlrpc_connection *conn);
void recovd_conn_fixed(struct ptlrpc_connection *conn);
int recovd_setup(struct recovd_obd *mgr);
int recovd_cleanup(struct recovd_obd *mgr);

#endif
