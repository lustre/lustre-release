/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _LUSTRE_HA_H
#define _LUSTRE_HA_H

#define LUSTRE_HA_NAME "ptlrpc"

struct recovd_data;
struct recovd_obd;
struct ptlrpc_connection;

/* recovd_phase values */
#define RECOVD_IDLE              0
#define RECOVD_PREPARING         1
#define RECOVD_PREPARED          2
#define RECOVD_RECOVERING        3
#define RECOVD_RECOVERED         4

/* recovd_flags bits */
#define RECOVD_STOPPING          1  /* how cleanup tells recovd to quit */
#define RECOVD_STOPPED           2  /* after recovd has stopped */
#define RECOVD_FAILED            4  /* the current recovery has failed */

#define PTLRPC_RECOVD_PHASE_PREPARE  1
#define PTLRPC_RECOVD_PHASE_RECOVER  2
#define PTLRPC_RECOVD_PHASE_FAILURE  3

typedef int (*ptlrpc_recovery_cb_t)(struct recovd_data *, int);

struct recovd_data {
        struct list_head     rd_managed_chain;
        ptlrpc_recovery_cb_t rd_recover;
        struct recovd_obd   *rd_recovd;
};

void recovd_conn_fail(struct ptlrpc_connection *conn);
void recovd_conn_manage(struct ptlrpc_connection *conn, struct recovd_obd *mgr,
                        ptlrpc_recovery_cb_t recover);
void recovd_conn_fixed(struct ptlrpc_connection *conn);
int recovd_setup(struct recovd_obd *mgr);
int recovd_cleanup(struct recovd_obd *mgr);

extern struct recovd_obd *ptlrpc_recovd;

int ll_recover(struct recovd_data *rd, int phase);

#endif
