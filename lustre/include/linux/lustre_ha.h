/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _LUSTRE_HA_H
#define _LUSTRE_HA_H

#define LUSTRE_HA_NAME "ptlrpc"

struct recovd_data;
struct recovd_obd;
struct obd_import;
struct ptlrpc_connection;

/* rd_phase/rd_next_phase values */
#define RD_IDLE              0
#define RD_TROUBLED          1
#define RD_PREPARING         2
#define RD_PREPARED          3
#define RD_RECOVERING        4
#define RD_RECOVERED         5
#define RD_FAILED            6

/* recovd_state values */
#define RECOVD_READY             1
#define RECOVD_STOPPING          2  /* how cleanup tells recovd to quit */
#define RECOVD_STOPPED           4  /* after recovd has stopped */

#define PTLRPC_RECOVD_PHASE_PREPARE  1
#define PTLRPC_RECOVD_PHASE_RECOVER  2
#define PTLRPC_RECOVD_PHASE_FAILURE  3
#define PTLRPC_RECOVD_PHASE_NOTCONN  4

typedef int (*ptlrpc_recovery_cb_t)(struct recovd_data *, int);

struct recovd_data {
        /* you must hold recovd->recovd_lock when touching rd_managed_chain */
        struct list_head     rd_managed_chain;
        ptlrpc_recovery_cb_t rd_recover;
        struct recovd_obd   *rd_recovd;
        __u32                rd_phase;
        __u32                rd_next_phase;
        __u32                rd_flags;
};

void recovd_conn_fail(struct ptlrpc_connection *conn);
void recovd_conn_manage(struct ptlrpc_connection *conn, struct recovd_obd *mgr,
                        ptlrpc_recovery_cb_t recover);
void recovd_conn_unmanage(struct ptlrpc_connection *conn);
void recovd_conn_fixed(struct ptlrpc_connection *conn);
int recovd_setup(struct recovd_obd *mgr);
int recovd_cleanup(struct recovd_obd *mgr);

extern struct recovd_obd *ptlrpc_recovd;
struct ptlrpc_request;

int ptlrpc_run_recovery_upcall(struct ptlrpc_connection *conn);
int ptlrpc_reconnect_import(struct obd_import *imp, int rq_opc,
                            struct ptlrpc_request **reqptr);
int ptlrpc_replay(struct obd_import *imp);
int ptlrpc_resend(struct obd_import *imp);
void ptlrpc_free_committed(struct obd_import *imp);
void ptlrpc_wake_delayed(struct obd_import *imp);
#endif
