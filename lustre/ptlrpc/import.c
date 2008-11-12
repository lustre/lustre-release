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
 * lustre/ptlrpc/import.c
 *
 * Author: Mike Shaver <shaver@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_RPC
#ifndef __KERNEL__
# include <liblustre.h>
#endif

#include <obd_support.h>
#include <lustre_ha.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_export.h>
#include <obd.h>
#include <obd_cksum.h>
#include <obd_class.h>

#include "ptlrpc_internal.h"

struct ptlrpc_connect_async_args {
         __u64 pcaa_peer_committed;
        int pcaa_initial_connect;
};

/* A CLOSED import should remain so. */
#define IMPORT_SET_STATE_NOLOCK(imp, state)                                    \
do {                                                                           \
        if (imp->imp_state != LUSTRE_IMP_CLOSED) {                             \
               CDEBUG(D_HA, "%p %s: changing import state from %s to %s\n",    \
                      imp, obd2cli_tgt(imp->imp_obd),                          \
                      ptlrpc_import_state_name(imp->imp_state),                \
                      ptlrpc_import_state_name(state));                        \
               imp->imp_state = state;                                         \
        }                                                                      \
} while(0)

#define IMPORT_SET_STATE(imp, state)            \
do {                                            \
        spin_lock(&imp->imp_lock);              \
        IMPORT_SET_STATE_NOLOCK(imp, state);    \
        spin_unlock(&imp->imp_lock);            \
} while(0)


static int ptlrpc_connect_interpret(const struct lu_env *env,
                                    struct ptlrpc_request *request,
                                    void * data, int rc);
int ptlrpc_import_recovery_state_machine(struct obd_import *imp);

/* Only this function is allowed to change the import state when it is
 * CLOSED. I would rather refcount the import and free it after
 * disconnection like we do with exports. To do that, the client_obd
 * will need to save the peer info somewhere other than in the import,
 * though. */
int ptlrpc_init_import(struct obd_import *imp)
{
        spin_lock(&imp->imp_lock);

        imp->imp_generation++;
        imp->imp_state =  LUSTRE_IMP_NEW;

        spin_unlock(&imp->imp_lock);

        return 0;
}
EXPORT_SYMBOL(ptlrpc_init_import);

#define UUID_STR "_UUID"
static void deuuidify(char *uuid, const char *prefix, char **uuid_start,
                      int *uuid_len)
{
        *uuid_start = !prefix || strncmp(uuid, prefix, strlen(prefix))
                ? uuid : uuid + strlen(prefix);

        *uuid_len = strlen(*uuid_start);

        if (*uuid_len < strlen(UUID_STR))
                return;

        if (!strncmp(*uuid_start + *uuid_len - strlen(UUID_STR),
                    UUID_STR, strlen(UUID_STR)))
                *uuid_len -= strlen(UUID_STR);
}

/* Returns true if import was FULL, false if import was already not
 * connected.
 * @imp - import to be disconnected
 * @conn_cnt - connection count (epoch) of the request that timed out
 *             and caused the disconnection.  In some cases, multiple
 *             inflight requests can fail to a single target (e.g. OST
 *             bulk requests) and if one has already caused a reconnection
 *             (increasing the import->conn_cnt) the older failure should
 *             not also cause a reconnection.  If zero it forces a reconnect.
 */
int ptlrpc_set_import_discon(struct obd_import *imp, __u32 conn_cnt)
{
        int rc = 0;

        spin_lock(&imp->imp_lock);

        if (imp->imp_state == LUSTRE_IMP_FULL &&
            (conn_cnt == 0 || conn_cnt == imp->imp_conn_cnt)) {
                char *target_start;
                int   target_len;

                deuuidify(obd2cli_tgt(imp->imp_obd), NULL,
                          &target_start, &target_len);

                if (imp->imp_replayable) {
                        LCONSOLE_WARN("%s: Connection to service %.*s via nid "
                               "%s was lost; in progress operations using this "
                               "service will wait for recovery to complete.\n",
                               imp->imp_obd->obd_name, target_len, target_start,
                               libcfs_nid2str(imp->imp_connection->c_peer.nid));
                } else {
                        LCONSOLE_ERROR_MSG(0x166, "%s: Connection to service "
                                           "%.*s via nid %s was lost; in progress"
                                           "operations using this service will"
                                           "fail.\n",
                                           imp->imp_obd->obd_name,
                                           target_len, target_start,
                                 libcfs_nid2str(imp->imp_connection->c_peer.nid));
                }
                ptlrpc_deactivate_timeouts(imp);
                IMPORT_SET_STATE_NOLOCK(imp, LUSTRE_IMP_DISCON);
                spin_unlock(&imp->imp_lock);

                if (obd_dump_on_timeout)
                        libcfs_debug_dumplog();

                obd_import_event(imp->imp_obd, imp, IMP_EVENT_DISCON);
                rc = 1;
        } else {
                spin_unlock(&imp->imp_lock);
                CDEBUG(D_HA, "%s: import %p already %s (conn %u, was %u): %s\n",
                       imp->imp_client->cli_name, imp,
                       (imp->imp_state == LUSTRE_IMP_FULL &&
                        imp->imp_conn_cnt > conn_cnt) ?
                       "reconnected" : "not connected", imp->imp_conn_cnt,
                       conn_cnt, ptlrpc_import_state_name(imp->imp_state));
        }

        return rc;
}

/* Must be called with imp_lock held! */
static void ptlrpc_deactivate_and_unlock_import(struct obd_import *imp)
{
        ENTRY;
        LASSERT_SPIN_LOCKED(&imp->imp_lock);

        CDEBUG(D_HA, "setting import %s INVALID\n", obd2cli_tgt(imp->imp_obd));
        imp->imp_invalid = 1;
        imp->imp_generation++;
        spin_unlock(&imp->imp_lock);

        ptlrpc_abort_inflight(imp);
        obd_import_event(imp->imp_obd, imp, IMP_EVENT_INACTIVE);

        EXIT;
}

/*
 * This acts as a barrier; all existing requests are rejected, and
 * no new requests will be accepted until the import is valid again.
 */
void ptlrpc_deactivate_import(struct obd_import *imp)
{
        spin_lock(&imp->imp_lock);
        ptlrpc_deactivate_and_unlock_import(imp);
}

static unsigned int 
ptlrpc_inflight_deadline(struct ptlrpc_request *req, time_t now)
{
        long dl;

        if (!(((req->rq_phase == RQ_PHASE_RPC) && !req->rq_waiting) ||
              (req->rq_phase == RQ_PHASE_BULK) || 
              (req->rq_phase == RQ_PHASE_NEW)))
                return 0;

        if (req->rq_timedout)
                return 0;

        if (req->rq_phase == RQ_PHASE_NEW)
                dl = req->rq_sent;
        else
                dl = req->rq_deadline;

        if (dl <= now)
                return 0;

        return dl - now;
}

static unsigned int ptlrpc_inflight_timeout(struct obd_import *imp)
{
        time_t now = cfs_time_current_sec();
        struct list_head *tmp, *n;
        struct ptlrpc_request *req;
        unsigned int timeout = 0;

        spin_lock(&imp->imp_lock);
        list_for_each_safe(tmp, n, &imp->imp_sending_list) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                timeout = max(ptlrpc_inflight_deadline(req, now), timeout);
        }
        spin_unlock(&imp->imp_lock);
        return timeout;
}

/*
 * This function will invalidate the import, if necessary, then block
 * for all the RPC completions, and finally notify the obd to
 * invalidate its state (ie cancel locks, clear pending requests,
 * etc).
 */
void ptlrpc_invalidate_import(struct obd_import *imp)
{
        struct list_head *tmp, *n;
        struct ptlrpc_request *req;
        struct l_wait_info lwi;
        unsigned int timeout;
        int rc;

        atomic_inc(&imp->imp_inval_count);

        /*
         * If this is an invalid MGC connection, then don't bother
         * waiting for imp_inflight to drop to 0.
         */
        if (imp->imp_invalid && imp->imp_recon_bk && !imp->imp_obd->obd_no_recov)
                goto out;

        if (!imp->imp_invalid || imp->imp_obd->obd_no_recov)
                ptlrpc_deactivate_import(imp);

        LASSERT(imp->imp_invalid);

        /* Wait forever until inflight == 0. We really can't do it another
         * way because in some cases we need to wait for very long reply 
         * unlink. We can't do anything before that because there is really
         * no guarantee that some rdma transfer is not in progress right now. */
        do {
                /* Calculate max timeout for waiting on rpcs to error 
                 * out. Use obd_timeout if calculated value is smaller
                 * than it. */
                timeout = ptlrpc_inflight_timeout(imp);
                timeout += timeout / 3;
             
                if (timeout == 0)
                        timeout = obd_timeout;
             
                CDEBUG(D_RPCTRACE, "Sleeping %d sec for inflight to error out\n",
                       timeout);

                /* Wait for all requests to error out and call completion
                 * callbacks. Cap it at obd_timeout -- these should all
                 * have been locally cancelled by ptlrpc_abort_inflight. */
                lwi = LWI_TIMEOUT_INTERVAL(
                        cfs_timeout_cap(cfs_time_seconds(timeout)),
                        cfs_time_seconds(1), NULL, NULL);
                rc = l_wait_event(imp->imp_recovery_waitq,
                                (atomic_read(&imp->imp_inflight) == 0), &lwi);
                if (rc) {
                        const char *cli_tgt = obd2cli_tgt(imp->imp_obd);

                        CERROR("%s: rc = %d waiting for callback (%d != 0)\n",
                               cli_tgt, rc, atomic_read(&imp->imp_inflight));

                        spin_lock(&imp->imp_lock);
                        list_for_each_safe(tmp, n, &imp->imp_sending_list) {
                                req = list_entry(tmp, struct ptlrpc_request, 
                                                 rq_list);
                                DEBUG_REQ(D_ERROR, req, "still on sending list");
                        }
                        list_for_each_safe(tmp, n, &imp->imp_delayed_list) {
                                req = list_entry(tmp, struct ptlrpc_request, 
                                                 rq_list);
                                DEBUG_REQ(D_ERROR, req, "still on delayed list");
                        }
                     
                        if (atomic_read(&imp->imp_unregistering) == 0) {
                                /* We know that only "unregistering" rpcs may
                                 * still survive in sending or delaying lists
                                 * (They are waiting for long reply unlink in
                                 * sluggish nets). Let's check this. If there
                                 * is no unregistering and inflight != 0 this
                                 * is bug. */
                                LASSERT(atomic_read(&imp->imp_inflight) == 0);
                             
                                /* Let's save one loop as soon as inflight have
                                 * dropped to zero. No new inflights possible at
                                 * this point. */
                                rc = 0;
                        } else {
                                CERROR("%s: RPCs in \"%s\" phase found (%d). "
                                       "Network is sluggish? Waiting them "
                                       "to error out.\n", cli_tgt,
                                       ptlrpc_phase2str(RQ_PHASE_UNREGISTERING),
                                       atomic_read(&imp->imp_unregistering));
                        }
                        spin_unlock(&imp->imp_lock);
                  }
        } while (rc != 0);

        /* 
         * Let's additionally check that no new rpcs added to import in
         * "invalidate" state. 
         */
        LASSERT(atomic_read(&imp->imp_inflight) == 0);
out:
        obd_import_event(imp->imp_obd, imp, IMP_EVENT_INVALIDATE);
        sptlrpc_import_flush_all_ctx(imp);

        atomic_dec(&imp->imp_inval_count);
        cfs_waitq_signal(&imp->imp_recovery_waitq);
}

/* unset imp_invalid */
void ptlrpc_activate_import(struct obd_import *imp)
{
        struct obd_device *obd = imp->imp_obd;

        spin_lock(&imp->imp_lock);
        imp->imp_invalid = 0;
        ptlrpc_activate_timeouts(imp);
        spin_unlock(&imp->imp_lock);
        obd_import_event(obd, imp, IMP_EVENT_ACTIVE);
}

void ptlrpc_fail_import(struct obd_import *imp, __u32 conn_cnt)
{
        ENTRY;

        LASSERT(!imp->imp_dlm_fake);

        if (ptlrpc_set_import_discon(imp, conn_cnt)) {
                if (!imp->imp_replayable) {
                        CDEBUG(D_HA, "import %s@%s for %s not replayable, "
                               "auto-deactivating\n",
                               obd2cli_tgt(imp->imp_obd),
                               imp->imp_connection->c_remote_uuid.uuid,
                               imp->imp_obd->obd_name);
                        ptlrpc_deactivate_import(imp);
                }

                CDEBUG(D_HA, "%s: waking up pinger\n",
                       obd2cli_tgt(imp->imp_obd));

                spin_lock(&imp->imp_lock);
                imp->imp_force_verify = 1;
                spin_unlock(&imp->imp_lock);

                ptlrpc_pinger_wake_up();
        }
        EXIT;
}

int ptlrpc_reconnect_import(struct obd_import *imp)
{
        ptlrpc_set_import_discon(imp, 0);
        /* Force a new connect attempt */
        ptlrpc_invalidate_import(imp);
        /* Do a fresh connect next time by zeroing the handle */
        ptlrpc_disconnect_import(imp, 1);
        /* Wait for all invalidate calls to finish */
        if (atomic_read(&imp->imp_inval_count) > 0) {
                int rc;
                struct l_wait_info lwi = LWI_INTR(LWI_ON_SIGNAL_NOOP, NULL);
                rc = l_wait_event(imp->imp_recovery_waitq,
                                  (atomic_read(&imp->imp_inval_count) == 0),
                                  &lwi);
                if (rc)
                        CERROR("Interrupted, inval=%d\n",
                               atomic_read(&imp->imp_inval_count));
        }

        /* Allow reconnect attempts */
        imp->imp_obd->obd_no_recov = 0;
        /* Remove 'invalid' flag */
        ptlrpc_activate_import(imp);
        /* Attempt a new connect */
        ptlrpc_recover_import(imp, NULL);
        return 0;
}

EXPORT_SYMBOL(ptlrpc_reconnect_import);

static int import_select_connection(struct obd_import *imp)
{
        struct obd_import_conn *imp_conn = NULL, *conn;
        struct obd_export *dlmexp;
        int tried_all = 1;
        ENTRY;

        spin_lock(&imp->imp_lock);

        if (list_empty(&imp->imp_conn_list)) {
                CERROR("%s: no connections available\n",
                        imp->imp_obd->obd_name);
                spin_unlock(&imp->imp_lock);
                RETURN(-EINVAL);
        }

        list_for_each_entry(conn, &imp->imp_conn_list, oic_item) {
                CDEBUG(D_HA, "%s: connect to NID %s last attempt "LPU64"\n",
                       imp->imp_obd->obd_name,
                       libcfs_nid2str(conn->oic_conn->c_peer.nid),
                       conn->oic_last_attempt);
                /* Don't thrash connections */
                if (cfs_time_before_64(cfs_time_current_64(),
                                     conn->oic_last_attempt +
                                     cfs_time_seconds(CONNECTION_SWITCH_MIN))) {
                        continue;
                }

                /* If we have not tried this connection since the
                   the last successful attempt, go with this one */
                if ((conn->oic_last_attempt == 0) ||
                    cfs_time_beforeq_64(conn->oic_last_attempt,
                                       imp->imp_last_success_conn)) {
                        imp_conn = conn;
                        tried_all = 0;
                        break;
                }

                /* If all of the connections have already been tried
                   since the last successful connection; just choose the
                   least recently used */
                if (!imp_conn)
                        imp_conn = conn;
                else if (cfs_time_before_64(conn->oic_last_attempt,
                                            imp_conn->oic_last_attempt))
                        imp_conn = conn;
        }

        /* if not found, simply choose the current one */
        if (!imp_conn) {
                LASSERT(imp->imp_conn_current);
                imp_conn = imp->imp_conn_current;
                tried_all = 0;
        }
        LASSERT(imp_conn->oic_conn);

        /* If we've tried everything, and we're back to the beginning of the
           list, increase our timeout and try again. It will be reset when
           we do finally connect. (FIXME: really we should wait for all network
           state associated with the last connection attempt to drain before
           trying to reconnect on it.) */
        if (tried_all && (imp->imp_conn_list.next == &imp_conn->oic_item) &&
            !imp->imp_recon_bk /* not retrying */) {
                if (at_get(&imp->imp_at.iat_net_latency) <
                    CONNECTION_SWITCH_MAX) {
                        at_add(&imp->imp_at.iat_net_latency,
                               at_get(&imp->imp_at.iat_net_latency) +
                               CONNECTION_SWITCH_INC);
                }
                LASSERT(imp_conn->oic_last_attempt);
                CWARN("%s: tried all connections, increasing latency to %ds\n",
                      imp->imp_obd->obd_name,
                      at_get(&imp->imp_at.iat_net_latency));
        }

        imp_conn->oic_last_attempt = cfs_time_current_64();

        /* switch connection, don't mind if it's same as the current one */
        if (imp->imp_connection)
                ptlrpc_connection_put(imp->imp_connection);
        imp->imp_connection = ptlrpc_connection_addref(imp_conn->oic_conn);

        dlmexp =  class_conn2export(&imp->imp_dlm_handle);
        LASSERT(dlmexp != NULL);
        if (dlmexp->exp_connection)
                ptlrpc_connection_put(dlmexp->exp_connection);
        dlmexp->exp_connection = ptlrpc_connection_addref(imp_conn->oic_conn);
        class_export_put(dlmexp);

        if (imp->imp_conn_current != imp_conn) {
                if (imp->imp_conn_current)
                        LCONSOLE_INFO("Changing connection for %s to %s/%s\n",
                                      imp->imp_obd->obd_name,
                                      imp_conn->oic_uuid.uuid,
                                      libcfs_nid2str(imp_conn->oic_conn->c_peer.nid));
                imp->imp_conn_current = imp_conn;
        }

        CDEBUG(D_HA, "%s: import %p using connection %s/%s\n",
               imp->imp_obd->obd_name, imp, imp_conn->oic_uuid.uuid,
               libcfs_nid2str(imp_conn->oic_conn->c_peer.nid));

        spin_unlock(&imp->imp_lock);

        RETURN(0);
}

/*
 * must be called under imp_lock
 */
int ptlrpc_first_transno(struct obd_import *imp, __u64 *transno)
{
        struct ptlrpc_request *req;
        struct list_head *tmp;

        if (list_empty(&imp->imp_replay_list))
                return 0;
        tmp = imp->imp_replay_list.next;
        req = list_entry(tmp, struct ptlrpc_request, rq_replay_list);
        *transno = req->rq_transno;
        if (req->rq_transno == 0) {
                DEBUG_REQ(D_ERROR, req, "zero transno in replay");
                LBUG();
        }

        return 1;
}

int ptlrpc_connect_import(struct obd_import *imp, char *new_uuid)
{
        struct obd_device *obd = imp->imp_obd;
        int initial_connect = 0;
        int set_transno = 0;
        __u64 committed_before_reconnect = 0;
        struct ptlrpc_request *request;
        char *bufs[] = { NULL,
                         obd2cli_tgt(imp->imp_obd),
                         obd->obd_uuid.uuid,
                         (char *)&imp->imp_dlm_handle,
                         (char *)&imp->imp_connect_data };
        struct ptlrpc_connect_async_args *aa;
        int rc;
        ENTRY;

        spin_lock(&imp->imp_lock);
        if (imp->imp_state == LUSTRE_IMP_CLOSED) {
                spin_unlock(&imp->imp_lock);
                CERROR("can't connect to a closed import\n");
                RETURN(-EINVAL);
        } else if (imp->imp_state == LUSTRE_IMP_FULL) {
                spin_unlock(&imp->imp_lock);
                CERROR("already connected\n");
                RETURN(0);
        } else if (imp->imp_state == LUSTRE_IMP_CONNECTING) {
                spin_unlock(&imp->imp_lock);
                CERROR("already connecting\n");
                RETURN(-EALREADY);
        }

        IMPORT_SET_STATE_NOLOCK(imp, LUSTRE_IMP_CONNECTING);

        imp->imp_conn_cnt++;
        imp->imp_resend_replay = 0;

        if (!lustre_handle_is_used(&imp->imp_remote_handle))
                initial_connect = 1;
        else
                committed_before_reconnect = imp->imp_peer_committed_transno;

        set_transno = ptlrpc_first_transno(imp, &imp->imp_connect_data.ocd_transno);
        spin_unlock(&imp->imp_lock);

        if (new_uuid) {
                struct obd_uuid uuid;

                obd_str2uuid(&uuid, new_uuid);
                rc = import_set_conn_priority(imp, &uuid);
                if (rc)
                        GOTO(out, rc);
        }

        rc = import_select_connection(imp);
        if (rc)
                GOTO(out, rc);

        /* last in connection list */
        if (imp->imp_conn_current->oic_item.next == &imp->imp_conn_list) {
                if (imp->imp_initial_recov_bk && initial_connect) {
                        CDEBUG(D_HA, "Last connection attempt (%d) for %s\n",
                               imp->imp_conn_cnt, obd2cli_tgt(imp->imp_obd));
                        /* Don't retry if connect fails */
                        rc = 0;
                        obd_set_info_async(obd->obd_self_export,
                                           sizeof(KEY_INIT_RECOV),
                                           KEY_INIT_RECOV,
                                           sizeof(rc), &rc, NULL);
                }
                if (imp->imp_recon_bk) {
                        CDEBUG(D_HA, "Last reconnection attempt (%d) for %s\n",
                               imp->imp_conn_cnt, obd2cli_tgt(imp->imp_obd));
                        spin_lock(&imp->imp_lock);
                        imp->imp_last_recon = 1;
                        spin_unlock(&imp->imp_lock);
                }
        }

        rc = sptlrpc_import_sec_adapt(imp, NULL, 0);
        if (rc)
                GOTO(out, rc);

        /* Reset connect flags to the originally requested flags, in case
         * the server is updated on-the-fly we will get the new features. */
        imp->imp_connect_data.ocd_connect_flags = imp->imp_connect_flags_orig;
        imp->imp_msghdr_flags &= ~MSGHDR_AT_SUPPORT;

        rc = obd_reconnect(NULL, imp->imp_obd->obd_self_export, obd,
                           &obd->obd_uuid, &imp->imp_connect_data, NULL);
        if (rc)
                GOTO(out, rc);

        request = ptlrpc_request_alloc(imp, &RQF_MDS_CONNECT);
        if (request == NULL)
                GOTO(out, rc = -ENOMEM);

        rc = ptlrpc_request_bufs_pack(request, LUSTRE_OBD_VERSION,
                                      imp->imp_connect_op, bufs, NULL);
        if (rc) {
                ptlrpc_request_free(request);
                GOTO(out, rc);
        }

#ifndef __KERNEL__
        lustre_msg_add_op_flags(request->rq_reqmsg, MSG_CONNECT_LIBCLIENT);
#endif
        lustre_msg_add_op_flags(request->rq_reqmsg, MSG_CONNECT_NEXT_VER);

        request->rq_no_resend = request->rq_no_delay = 1;
        request->rq_send_state = LUSTRE_IMP_CONNECTING;
        /* Allow a slightly larger reply for future growth compatibility */
        req_capsule_set_size(&request->rq_pill, &RMF_CONNECT_DATA, RCL_SERVER,
                             sizeof(struct obd_connect_data)+16*sizeof(__u64));
        ptlrpc_request_set_replen(request);
        request->rq_interpret_reply = ptlrpc_connect_interpret;

        CLASSERT(sizeof (*aa) <= sizeof (request->rq_async_args));
        aa = ptlrpc_req_async_args(request);
        memset(aa, 0, sizeof *aa);

        aa->pcaa_peer_committed = committed_before_reconnect;
        aa->pcaa_initial_connect = initial_connect;

        if (aa->pcaa_initial_connect) {
                spin_lock(&imp->imp_lock);
                imp->imp_replayable = 1;
                spin_unlock(&imp->imp_lock);
                lustre_msg_add_op_flags(request->rq_reqmsg,
                                        MSG_CONNECT_INITIAL);
                if (AT_OFF)
                        /* AT will use INITIAL_CONNECT_TIMEOUT the first
                           time, adaptive after that. */
                        request->rq_timeout = INITIAL_CONNECT_TIMEOUT;
        }

        if (set_transno)
                lustre_msg_add_op_flags(request->rq_reqmsg,
                                        MSG_CONNECT_TRANSNO);

        DEBUG_REQ(D_RPCTRACE, request, "(re)connect request");
        ptlrpcd_add_req(request, PSCOPE_OTHER);
        rc = 0;
out:
        if (rc != 0) {
                IMPORT_SET_STATE(imp, LUSTRE_IMP_DISCON);
        }

        RETURN(rc);
}
EXPORT_SYMBOL(ptlrpc_connect_import);

static void ptlrpc_maybe_ping_import_soon(struct obd_import *imp)
{
#ifdef __KERNEL__
        struct obd_import_conn *imp_conn;
#endif
        int wake_pinger = 0;

        ENTRY;

        spin_lock(&imp->imp_lock);
        if (list_empty(&imp->imp_conn_list))
                GOTO(unlock, 0);

#ifdef __KERNEL__
        imp_conn = list_entry(imp->imp_conn_list.prev,
                              struct obd_import_conn,
                              oic_item);

        /* XXX: When the failover node is the primary node, it is possible
         * to have two identical connections in imp_conn_list. We must
         * compare not conn's pointers but NIDs, otherwise we can defeat
         * connection throttling. (See bug 14774.) */
        if (imp->imp_conn_current->oic_conn->c_peer.nid !=
                                imp_conn->oic_conn->c_peer.nid) {
                ptlrpc_ping_import_soon(imp);
                wake_pinger = 1;
        }
#else
        /* liblustre has no pinger thead, so we wakup pinger anyway */
        wake_pinger = 1;
#endif

 unlock:
        spin_unlock(&imp->imp_lock);

        if (wake_pinger)
                ptlrpc_pinger_wake_up();

        EXIT;
}

static int ptlrpc_connect_interpret(const struct lu_env *env,
                                    struct ptlrpc_request *request,
                                    void * data, int rc)
{
        struct ptlrpc_connect_async_args *aa = data;
        struct obd_import *imp = request->rq_import;
        struct client_obd *cli = &imp->imp_obd->u.cli;
        struct lustre_handle old_hdl;
        int msg_flags;
        ENTRY;

        spin_lock(&imp->imp_lock);
        if (imp->imp_state == LUSTRE_IMP_CLOSED) {
                spin_unlock(&imp->imp_lock);
                RETURN(0);
        }
        spin_unlock(&imp->imp_lock);

        if (rc)
                GOTO(out, rc);

        LASSERT(imp->imp_conn_current);

        msg_flags = lustre_msg_get_op_flags(request->rq_repmsg);

        /* All imports are pingable */
        spin_lock(&imp->imp_lock);
        imp->imp_pingable = 1;

        if (aa->pcaa_initial_connect) {
                if (msg_flags & MSG_CONNECT_REPLAYABLE) {
                        imp->imp_replayable = 1;
                        spin_unlock(&imp->imp_lock);
                        CDEBUG(D_HA, "connected to replayable target: %s\n",
                               obd2cli_tgt(imp->imp_obd));
                } else {
                        imp->imp_replayable = 0;
                        spin_unlock(&imp->imp_lock);
                }

                /* if applies, adjust the imp->imp_msg_magic here
                 * according to reply flags */

                imp->imp_remote_handle =
                                *lustre_msg_get_handle(request->rq_repmsg);

                /* Initial connects are allowed for clients with non-random
                 * uuids when servers are in recovery.  Simply signal the
                 * servers replay is complete and wait in REPLAY_WAIT. */
                if (msg_flags & MSG_CONNECT_RECOVERING) {
                        CDEBUG(D_HA, "connect to %s during recovery\n",
                               obd2cli_tgt(imp->imp_obd));
                        IMPORT_SET_STATE(imp, LUSTRE_IMP_REPLAY_LOCKS);
                } else {
                        IMPORT_SET_STATE(imp, LUSTRE_IMP_FULL);
                }

                spin_lock(&imp->imp_lock);
                if (imp->imp_invalid) {
                        spin_unlock(&imp->imp_lock);
                        ptlrpc_activate_import(imp);
                } else {
                        spin_unlock(&imp->imp_lock);
                }

                GOTO(finish, rc = 0);
        } else {
                spin_unlock(&imp->imp_lock);
        }

        /* Determine what recovery state to move the import to. */
        if (MSG_CONNECT_RECONNECT & msg_flags) {
                memset(&old_hdl, 0, sizeof(old_hdl));
                if (!memcmp(&old_hdl, lustre_msg_get_handle(request->rq_repmsg),
                            sizeof (old_hdl))) {
                        CERROR("%s@%s didn't like our handle "LPX64
                               ", failed\n", obd2cli_tgt(imp->imp_obd),
                               imp->imp_connection->c_remote_uuid.uuid,
                               imp->imp_dlm_handle.cookie);
                        GOTO(out, rc = -ENOTCONN);
                }

                if (memcmp(&imp->imp_remote_handle,
                           lustre_msg_get_handle(request->rq_repmsg),
                           sizeof(imp->imp_remote_handle))) {
                        int level = msg_flags & MSG_CONNECT_RECOVERING ? D_HA :
                                                                         D_WARNING;

                        /* Bug 16611/14775: if server handle have changed,
                         * that means some sort of disconnection happened.
                         * If the server is not in recovery, that also means it
                         * already erased all of our state because of previous
                         * eviction. If it is in recovery - we are safe to
                         * participate since we can reestablish all of our state
                         * with server again */
                        CDEBUG(level,"%s@%s changed server handle from "
                                     LPX64" to "LPX64"%s \n" "but is still in recovery \n",
                                     obd2cli_tgt(imp->imp_obd),
                                     imp->imp_connection->c_remote_uuid.uuid,
                                     imp->imp_remote_handle.cookie,
                                     lustre_msg_get_handle(request->rq_repmsg)->
                                                                        cookie,
                                     (MSG_CONNECT_RECOVERING & msg_flags) ?
                                         "but is still in recovery" : "");

                        imp->imp_remote_handle =
                                     *lustre_msg_get_handle(request->rq_repmsg);

                        if (!(MSG_CONNECT_RECOVERING & msg_flags)) {
                                IMPORT_SET_STATE(imp, LUSTRE_IMP_EVICTED);
                                GOTO(finish, rc = 0);
                        }

                } else {
                        CDEBUG(D_HA, "reconnected to %s@%s after partition\n",
                               obd2cli_tgt(imp->imp_obd),
                               imp->imp_connection->c_remote_uuid.uuid);
                }

                if (imp->imp_invalid) {
                        CDEBUG(D_HA, "%s: reconnected but import is invalid; "
                               "marking evicted\n", imp->imp_obd->obd_name);
                        IMPORT_SET_STATE(imp, LUSTRE_IMP_EVICTED);
                } else if (MSG_CONNECT_RECOVERING & msg_flags) {
                        CDEBUG(D_HA, "%s: reconnected to %s during replay\n",
                               imp->imp_obd->obd_name,
                               obd2cli_tgt(imp->imp_obd));

                        spin_lock(&imp->imp_lock);
                        imp->imp_resend_replay = 1;
                        spin_unlock(&imp->imp_lock);

                        IMPORT_SET_STATE(imp, LUSTRE_IMP_REPLAY);
                } else {
                        IMPORT_SET_STATE(imp, LUSTRE_IMP_RECOVER);
                }
        } else if ((MSG_CONNECT_RECOVERING & msg_flags) && !imp->imp_invalid) {
                LASSERT(imp->imp_replayable);
                imp->imp_remote_handle =
                                *lustre_msg_get_handle(request->rq_repmsg);
                imp->imp_last_replay_transno = 0;
                IMPORT_SET_STATE(imp, LUSTRE_IMP_REPLAY);
        } else {
                DEBUG_REQ(D_HA, request, "%s: evicting (reconnect/recover flags"
                          " not set: %x)", imp->imp_obd->obd_name, msg_flags);
                imp->imp_remote_handle =
                                *lustre_msg_get_handle(request->rq_repmsg);
                IMPORT_SET_STATE(imp, LUSTRE_IMP_EVICTED);
        }

        /* Sanity checks for a reconnected import. */
        if (!(imp->imp_replayable) != !(msg_flags & MSG_CONNECT_REPLAYABLE)) {
                CERROR("imp_replayable flag does not match server "
                       "after reconnect. We should LBUG right here.\n");
        }

        if (lustre_msg_get_last_committed(request->rq_repmsg) <
            aa->pcaa_peer_committed) {
                CERROR("%s went back in time (transno "LPD64
                       " was previously committed, server now claims "LPD64
                       ")!  See https://bugzilla.lustre.org/show_bug.cgi?"
                       "id=9646\n",
                       obd2cli_tgt(imp->imp_obd), aa->pcaa_peer_committed,
                       lustre_msg_get_last_committed(request->rq_repmsg));
        }

finish:
        rc = ptlrpc_import_recovery_state_machine(imp);
        if (rc != 0) {
                if (rc == -ENOTCONN) {
                        CDEBUG(D_HA, "evicted/aborted by %s@%s during recovery;"
                               "invalidating and reconnecting\n",
                               obd2cli_tgt(imp->imp_obd),
                               imp->imp_connection->c_remote_uuid.uuid);
                        ptlrpc_connect_import(imp, NULL);
                        RETURN(0);
                }
        } else {
                struct obd_connect_data *ocd;
                struct obd_export *exp;
                int ret;
                ret = req_capsule_get_size(&request->rq_pill, &RMF_CONNECT_DATA,
                                           RCL_SERVER);
                /* server replied obd_connect_data is always bigger */
                ocd = req_capsule_server_sized_get(&request->rq_pill,
                                                   &RMF_CONNECT_DATA, ret);

                spin_lock(&imp->imp_lock);
                list_del(&imp->imp_conn_current->oic_item);
                list_add(&imp->imp_conn_current->oic_item, &imp->imp_conn_list);
                imp->imp_last_success_conn =
                        imp->imp_conn_current->oic_last_attempt;

                if (ocd == NULL) {
                        spin_unlock(&imp->imp_lock);
                        CERROR("Wrong connect data from server\n");
                        rc = -EPROTO;
                        GOTO(out, rc);
                }

                imp->imp_connect_data = *ocd;

                exp = class_conn2export(&imp->imp_dlm_handle);
                spin_unlock(&imp->imp_lock);

                /* check that server granted subset of flags we asked for. */
                LASSERTF((ocd->ocd_connect_flags &
                          imp->imp_connect_flags_orig) ==
                         ocd->ocd_connect_flags, LPX64" != "LPX64,
                         imp->imp_connect_flags_orig, ocd->ocd_connect_flags);

                if (!exp) {
                        /* This could happen if export is cleaned during the
                           connect attempt */
                        CERROR("Missing export for %s\n",
                               imp->imp_obd->obd_name);
                        GOTO(out, rc = -ENODEV);
                }
                exp->exp_connect_flags = ocd->ocd_connect_flags;
                imp->imp_obd->obd_self_export->exp_connect_flags =
                                                        ocd->ocd_connect_flags;
                class_export_put(exp);

                obd_import_event(imp->imp_obd, imp, IMP_EVENT_OCD);

                if (!ocd->ocd_ibits_known &&
                    ocd->ocd_connect_flags & OBD_CONNECT_IBITS)
                        CERROR("Inodebits aware server returned zero compatible"
                               " bits?\n");

                if ((ocd->ocd_connect_flags & OBD_CONNECT_VERSION) &&
                    (ocd->ocd_version > LUSTRE_VERSION_CODE +
                                        LUSTRE_VERSION_OFFSET_WARN ||
                     ocd->ocd_version < LUSTRE_VERSION_CODE -
                                        LUSTRE_VERSION_OFFSET_WARN)) {
                        /* Sigh, some compilers do not like #ifdef in the middle
                           of macro arguments */
#ifdef __KERNEL__
                        const char *older =
                                "older. Consider upgrading this client";
#else
                        const char *older =
                                "older. Consider recompiling this application";
#endif
                        const char *newer = "newer than client version";

                        LCONSOLE_WARN("Server %s version (%d.%d.%d.%d) "
                                      "is much %s (%s)\n",
                                      obd2cli_tgt(imp->imp_obd),
                                      OBD_OCD_VERSION_MAJOR(ocd->ocd_version),
                                      OBD_OCD_VERSION_MINOR(ocd->ocd_version),
                                      OBD_OCD_VERSION_PATCH(ocd->ocd_version),
                                      OBD_OCD_VERSION_FIX(ocd->ocd_version),
                                      ocd->ocd_version > LUSTRE_VERSION_CODE ?
                                      newer : older, LUSTRE_VERSION_STRING);
                }

                if (ocd->ocd_connect_flags & OBD_CONNECT_CKSUM) {
                        /* We sent to the server ocd_cksum_types with bits set
                         * for algorithms we understand. The server masked off
                         * the checksum types it doesn't support */
                        if ((ocd->ocd_cksum_types & OBD_CKSUM_ALL) == 0) {
                                LCONSOLE_WARN("The negotiation of the checksum "
                                              "alogrithm to use with server %s "
                                              "failed (%x/%x), disabling "
                                              "checksums\n",
                                              obd2cli_tgt(imp->imp_obd),
                                              ocd->ocd_cksum_types,
                                              OBD_CKSUM_ALL);
                                cli->cl_checksum = 0;
                                cli->cl_supp_cksum_types = OBD_CKSUM_CRC32;
                                cli->cl_cksum_type = OBD_CKSUM_CRC32;
                        } else {
                                cli->cl_supp_cksum_types = ocd->ocd_cksum_types;

                                if (ocd->ocd_cksum_types & OSC_DEFAULT_CKSUM)
                                        cli->cl_cksum_type = OSC_DEFAULT_CKSUM;
                                else if (ocd->ocd_cksum_types & OBD_CKSUM_ADLER)
                                        cli->cl_cksum_type = OBD_CKSUM_ADLER;
                                else
                                        cli->cl_cksum_type = OBD_CKSUM_CRC32;
                        }
                } else {
                        /* The server does not support OBD_CONNECT_CKSUM.
                         * Enforce CRC32 for backward compatibility*/
                        cli->cl_supp_cksum_types = OBD_CKSUM_CRC32;
                        cli->cl_cksum_type = OBD_CKSUM_CRC32;
                }

                if (ocd->ocd_connect_flags & OBD_CONNECT_BRW_SIZE) {
                        cli->cl_max_pages_per_rpc =
                                ocd->ocd_brw_size >> CFS_PAGE_SHIFT;
                }

                imp->imp_obd->obd_namespace->ns_connect_flags =
                                                        ocd->ocd_connect_flags;
                imp->imp_obd->obd_namespace->ns_orig_connect_flags =
                                                        ocd->ocd_connect_flags;

                if ((ocd->ocd_connect_flags & OBD_CONNECT_AT) &&
                    (imp->imp_msg_magic == LUSTRE_MSG_MAGIC_V2))
                        /* We need a per-message support flag, because
                           a. we don't know if the incoming connect reply
                              supports AT or not (in reply_in_callback)
                              until we unpack it.
                           b. failovered server means export and flags are gone
                              (in ptlrpc_send_reply).
                           Can only be set when we know AT is supported at
                           both ends */
                        imp->imp_msghdr_flags |= MSGHDR_AT_SUPPORT;
                else
                        imp->imp_msghdr_flags &= ~MSGHDR_AT_SUPPORT;

                LASSERT((cli->cl_max_pages_per_rpc <= PTLRPC_MAX_BRW_PAGES) &&
                        (cli->cl_max_pages_per_rpc > 0));
        }

out:
        if (rc != 0) {
                IMPORT_SET_STATE(imp, LUSTRE_IMP_DISCON);
                spin_lock(&imp->imp_lock);
                if (aa->pcaa_initial_connect && !imp->imp_initial_recov &&
                    (request->rq_import_generation == imp->imp_generation))
                        ptlrpc_deactivate_and_unlock_import(imp);
                else
                        spin_unlock(&imp->imp_lock);

                if ((imp->imp_recon_bk && imp->imp_last_recon) ||
                    (rc == -EACCES)) {
                        /*
                         * Give up trying to reconnect
                         * EACCES means client has no permission for connection
                         */
                        imp->imp_obd->obd_no_recov = 1;
                        ptlrpc_deactivate_import(imp);
                }

                if (rc == -EPROTO) {
                        struct obd_connect_data *ocd;

                        /* reply message might not be ready */
                        if (request->rq_repmsg == NULL)
                                RETURN(-EPROTO);

                        ocd = req_capsule_server_get(&request->rq_pill,
                                                     &RMF_CONNECT_DATA);
                        if (ocd &&
                            (ocd->ocd_connect_flags & OBD_CONNECT_VERSION) &&
                            (ocd->ocd_version != LUSTRE_VERSION_CODE)) {
                           /* Actually servers are only supposed to refuse
                              connection from liblustre clients, so we should
                              never see this from VFS context */
                                LCONSOLE_ERROR_MSG(0x16a, "Server %s version "
                                        "(%d.%d.%d.%d)"
                                        " refused connection from this client "
                                        "with an incompatible version (%s).  "
                                        "Client must be recompiled\n",
                                        obd2cli_tgt(imp->imp_obd),
                                        OBD_OCD_VERSION_MAJOR(ocd->ocd_version),
                                        OBD_OCD_VERSION_MINOR(ocd->ocd_version),
                                        OBD_OCD_VERSION_PATCH(ocd->ocd_version),
                                        OBD_OCD_VERSION_FIX(ocd->ocd_version),
                                        LUSTRE_VERSION_STRING);
                                ptlrpc_deactivate_import(imp);
                                IMPORT_SET_STATE(imp, LUSTRE_IMP_CLOSED);
                        }
                        RETURN(-EPROTO);
                }

                ptlrpc_maybe_ping_import_soon(imp);

                CDEBUG(D_HA, "recovery of %s on %s failed (%d)\n",
                       obd2cli_tgt(imp->imp_obd),
                       (char *)imp->imp_connection->c_remote_uuid.uuid, rc);
        }

        spin_lock(&imp->imp_lock);
        imp->imp_last_recon = 0;
        spin_unlock(&imp->imp_lock);

        cfs_waitq_signal(&imp->imp_recovery_waitq);
        RETURN(rc);
}

static int completed_replay_interpret(const struct lu_env *env,
                                      struct ptlrpc_request *req,
                                      void * data, int rc)
{
        ENTRY;
        atomic_dec(&req->rq_import->imp_replay_inflight);
        if (req->rq_status == 0) {
                ptlrpc_import_recovery_state_machine(req->rq_import);
        } else {
                CDEBUG(D_HA, "%s: LAST_REPLAY message error: %d, "
                       "reconnecting\n",
                       req->rq_import->imp_obd->obd_name, req->rq_status);
                ptlrpc_connect_import(req->rq_import, NULL);
        }

        RETURN(0);
}

static int signal_completed_replay(struct obd_import *imp)
{
        struct ptlrpc_request *req;
        ENTRY;

        LASSERT(atomic_read(&imp->imp_replay_inflight) == 0);
        atomic_inc(&imp->imp_replay_inflight);

        req = ptlrpc_request_alloc_pack(imp, &RQF_OBD_PING, LUSTRE_OBD_VERSION,
                                        OBD_PING);
        if (req == NULL) {
                atomic_dec(&imp->imp_replay_inflight);
                RETURN(-ENOMEM);
        }

        ptlrpc_request_set_replen(req);
        req->rq_send_state = LUSTRE_IMP_REPLAY_WAIT;
        lustre_msg_add_flags(req->rq_reqmsg,
                             MSG_LOCK_REPLAY_DONE | MSG_REQ_REPLAY_DONE);
        req->rq_timeout *= 3;
        req->rq_interpret_reply = completed_replay_interpret;

        ptlrpcd_add_req(req, PSCOPE_OTHER);
        RETURN(0);
}

#ifdef __KERNEL__
static int ptlrpc_invalidate_import_thread(void *data)
{
        struct obd_import *imp = data;

        ENTRY;

        ptlrpc_daemonize("ll_imp_inval");

        CDEBUG(D_HA, "thread invalidate import %s to %s@%s\n",
               imp->imp_obd->obd_name, obd2cli_tgt(imp->imp_obd),
               imp->imp_connection->c_remote_uuid.uuid);

        ptlrpc_invalidate_import(imp);

        if (obd_dump_on_eviction) {
                CERROR("dump the log upon eviction\n");
                libcfs_debug_dumplog();
        }

        IMPORT_SET_STATE(imp, LUSTRE_IMP_RECOVER);
        ptlrpc_import_recovery_state_machine(imp);

        RETURN(0);
}
#endif

int ptlrpc_import_recovery_state_machine(struct obd_import *imp)
{
        int rc = 0;
        int inflight;
        char *target_start;
        int target_len;

        ENTRY;
        if (imp->imp_state == LUSTRE_IMP_EVICTED) {
                deuuidify(obd2cli_tgt(imp->imp_obd), NULL,
                          &target_start, &target_len);
                /* Don't care about MGC eviction */
                if (strcmp(imp->imp_obd->obd_type->typ_name,
                           LUSTRE_MGC_NAME) != 0) {
                        LCONSOLE_ERROR_MSG(0x167, "This client was evicted by "
                                           "%.*s; in progress operations using "
                                           "this service will fail.\n",
                                           target_len, target_start);
                }
                CDEBUG(D_HA, "evicted from %s@%s; invalidating\n",
                       obd2cli_tgt(imp->imp_obd),
                       imp->imp_connection->c_remote_uuid.uuid);

#ifdef __KERNEL__
                rc = cfs_kernel_thread(ptlrpc_invalidate_import_thread, imp,
                                       CLONE_VM | CLONE_FILES);
                if (rc < 0)
                        CERROR("error starting invalidate thread: %d\n", rc);
                else
                        rc = 0;
                RETURN(rc);
#else
                ptlrpc_invalidate_import(imp);

                IMPORT_SET_STATE(imp, LUSTRE_IMP_RECOVER);
#endif
        }

        if (imp->imp_state == LUSTRE_IMP_REPLAY) {
                CDEBUG(D_HA, "replay requested by %s\n",
                       obd2cli_tgt(imp->imp_obd));
                rc = ptlrpc_replay_next(imp, &inflight);
                if (inflight == 0 &&
                    atomic_read(&imp->imp_replay_inflight) == 0) {
                        IMPORT_SET_STATE(imp, LUSTRE_IMP_REPLAY_LOCKS);
                        rc = ldlm_replay_locks(imp);
                        if (rc)
                                GOTO(out, rc);
                }
                rc = 0;
        }

        if (imp->imp_state == LUSTRE_IMP_REPLAY_LOCKS) {
                if (atomic_read(&imp->imp_replay_inflight) == 0) {
                        IMPORT_SET_STATE(imp, LUSTRE_IMP_REPLAY_WAIT);
                        rc = signal_completed_replay(imp);
                        if (rc)
                                GOTO(out, rc);
                }

        }

        if (imp->imp_state == LUSTRE_IMP_REPLAY_WAIT) {
                if (atomic_read(&imp->imp_replay_inflight) == 0) {
                        IMPORT_SET_STATE(imp, LUSTRE_IMP_RECOVER);
                }
        }

        if (imp->imp_state == LUSTRE_IMP_RECOVER) {
                CDEBUG(D_HA, "reconnected to %s@%s\n",
                       obd2cli_tgt(imp->imp_obd),
                       imp->imp_connection->c_remote_uuid.uuid);

                rc = ptlrpc_resend(imp);
                if (rc)
                        GOTO(out, rc);
                IMPORT_SET_STATE(imp, LUSTRE_IMP_FULL);
                ptlrpc_activate_import(imp);

                deuuidify(obd2cli_tgt(imp->imp_obd), NULL,
                          &target_start, &target_len);
                LCONSOLE_INFO("%s: Connection restored to service %.*s "
                              "using nid %s.\n", imp->imp_obd->obd_name,
                              target_len, target_start,
                              libcfs_nid2str(imp->imp_connection->c_peer.nid));
        }

        if (imp->imp_state == LUSTRE_IMP_FULL) {
                cfs_waitq_signal(&imp->imp_recovery_waitq);
                ptlrpc_wake_delayed(imp);
        }

out:
        RETURN(rc);
}

static int back_to_sleep(void *unused)
{
        return 0;
}

int ptlrpc_disconnect_import(struct obd_import *imp, int noclose)
{
        struct ptlrpc_request *req;
        int rq_opc, rc = 0;
        int nowait = imp->imp_obd->obd_force;
        ENTRY;

        if (nowait)
                GOTO(set_state, rc);

        switch (imp->imp_connect_op) {
        case OST_CONNECT: rq_opc = OST_DISCONNECT; break;
        case MDS_CONNECT: rq_opc = MDS_DISCONNECT; break;
        case MGS_CONNECT: rq_opc = MGS_DISCONNECT; break;
        default:
                CERROR("don't know how to disconnect from %s (connect_op %d)\n",
                       obd2cli_tgt(imp->imp_obd), imp->imp_connect_op);
                RETURN(-EINVAL);
        }

        if (ptlrpc_import_in_recovery(imp)) {
                struct l_wait_info lwi;
                cfs_duration_t timeout;


                if (AT_OFF) {
                        if (imp->imp_server_timeout)
                                timeout = cfs_time_seconds(obd_timeout / 2);
                        else
                                timeout = cfs_time_seconds(obd_timeout);
                } else {
                        int idx = import_at_get_index(imp,
                                imp->imp_client->cli_request_portal);
                        timeout = cfs_time_seconds(
                                at_get(&imp->imp_at.iat_service_estimate[idx]));
                }

                lwi = LWI_TIMEOUT_INTR(cfs_timeout_cap(timeout),
                                       back_to_sleep, LWI_ON_SIGNAL_NOOP, NULL);
                rc = l_wait_event(imp->imp_recovery_waitq,
                                  !ptlrpc_import_in_recovery(imp), &lwi);

        }

        spin_lock(&imp->imp_lock);
        if (imp->imp_state != LUSTRE_IMP_FULL)
                GOTO(out, 0);

        spin_unlock(&imp->imp_lock);

        req = ptlrpc_request_alloc_pack(imp, &RQF_MDS_DISCONNECT,
                                        LUSTRE_OBD_VERSION, rq_opc);
        if (req) {
                /* We are disconnecting, do not retry a failed DISCONNECT rpc if
                 * it fails.  We can get through the above with a down server
                 * if the client doesn't know the server is gone yet. */
                req->rq_no_resend = 1;

#ifndef CRAY_XT3
                /* We want client umounts to happen quickly, no matter the
                   server state... */
                req->rq_timeout = min_t(int, req->rq_timeout,
                                        INITIAL_CONNECT_TIMEOUT);
#else
                /* ... but we always want liblustre clients to nicely
                   disconnect, so only use the adaptive value. */
                if (AT_OFF)
                        req->rq_timeout = obd_timeout / 3;
#endif

                IMPORT_SET_STATE(imp, LUSTRE_IMP_CONNECTING);
                req->rq_send_state =  LUSTRE_IMP_CONNECTING;
                ptlrpc_request_set_replen(req);
                rc = ptlrpc_queue_wait(req);
                ptlrpc_req_finished(req);
        }

set_state:
        spin_lock(&imp->imp_lock);
out:
        if (noclose)
                IMPORT_SET_STATE_NOLOCK(imp, LUSTRE_IMP_DISCON);
        else
                IMPORT_SET_STATE_NOLOCK(imp, LUSTRE_IMP_CLOSED);
        memset(&imp->imp_remote_handle, 0, sizeof(imp->imp_remote_handle));
        imp->imp_conn_cnt = 0;
        /* Try all connections in the future - bz 12758 */
        imp->imp_last_recon = 0;
        spin_unlock(&imp->imp_lock);

        RETURN(rc);
}


/* Adaptive Timeout utils */
extern unsigned int at_min, at_max, at_history;

/* Bin into timeslices using AT_BINS bins.
   This gives us a max of the last binlimit*AT_BINS secs without the storage,
   but still smoothing out a return to normalcy from a slow response.
   (E.g. remember the maximum latency in each minute of the last 4 minutes.) */
int at_add(struct adaptive_timeout *at, unsigned int val)
{
        unsigned int old = at->at_current;
        time_t now = cfs_time_current_sec();
        time_t binlimit = max_t(time_t, at_history / AT_BINS, 1);

        LASSERT(at);
#if 0
        CDEBUG(D_INFO, "add %u to %p time=%lu v=%u (%u %u %u %u)\n",
               val, at, now - at->at_binstart, at->at_current,
               at->at_hist[0], at->at_hist[1], at->at_hist[2], at->at_hist[3]);
#endif
        if (val == 0)
                /* 0's don't count, because we never want our timeout to
                   drop to 0, and because 0 could mean an error */
                return 0;

        spin_lock(&at->at_lock);

        if (unlikely(at->at_binstart == 0)) {
                /* Special case to remove default from history */
                at->at_current = val;
                at->at_worst_ever = val;
                at->at_worst_time = now;
                at->at_hist[0] = val;
                at->at_binstart = now;
        } else if (now - at->at_binstart < binlimit ) {
                /* in bin 0 */
                at->at_hist[0] = max(val, at->at_hist[0]);
                at->at_current = max(val, at->at_current);
        } else {
                int i, shift;
                unsigned int maxv = val;
                /* move bins over */
                shift = (now - at->at_binstart) / binlimit;
                LASSERT(shift > 0);
                for(i = AT_BINS - 1; i >= 0; i--) {
                        if (i >= shift) {
                                at->at_hist[i] = at->at_hist[i - shift];
                                maxv = max(maxv, at->at_hist[i]);
                        } else {
                                at->at_hist[i] = 0;
                        }
                }
                at->at_hist[0] = val;
                at->at_current = maxv;
                at->at_binstart += shift * binlimit;
        }

        if (at->at_current > at->at_worst_ever) {
                at->at_worst_ever = at->at_current;
                at->at_worst_time = now;
        }

        if (at->at_flags & AT_FLG_NOHIST)
                /* Only keep last reported val; keeping the rest of the history
                   for proc only */
                at->at_current = val;

        if (at_max > 0)
                at->at_current =  min(at->at_current, at_max);
        at->at_current =  max(at->at_current, at_min);

#if 0
        if (at->at_current != old)
                CDEBUG(D_ADAPTTO, "AT %p change: old=%u new=%u delta=%d "
                       "(val=%u) hist %u %u %u %u\n", at,
                       old, at->at_current, at->at_current - old, val,
                       at->at_hist[0], at->at_hist[1], at->at_hist[2],
                       at->at_hist[3]);
#endif

        /* if we changed, report the old value */
        old = (at->at_current != old) ? old : 0;

        spin_unlock(&at->at_lock);
        return old;
}

/* Find the imp_at index for a given portal; assign if space available */
int import_at_get_index(struct obd_import *imp, int portal)
{
        struct imp_at *at = &imp->imp_at;
        int i;

        for (i = 0; i < IMP_AT_MAX_PORTALS; i++) {
                if (at->iat_portal[i] == portal)
                        return i;
                if (at->iat_portal[i] == 0)
                        /* unused */
                        break;
        }

        /* Not found in list, add it under a lock */
        spin_lock(&imp->imp_lock);

        /* Check unused under lock */
        for (; i < IMP_AT_MAX_PORTALS; i++) {
                if (at->iat_portal[i] == portal)
                        goto out;
                if (at->iat_portal[i] == 0)
                        /* unused */
                        break;
        }

        /* Not enough portals? */
        LASSERT(i < IMP_AT_MAX_PORTALS);

        at->iat_portal[i] = portal;
out:
        spin_unlock(&imp->imp_lock);
        return i;
}
