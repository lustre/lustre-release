/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#ifndef __IMPORT_H
#define __IMPORT_H

#include <linux/lustre_handles.h>
#include <linux/lustre_idl.h>

enum lustre_imp_state {
        LUSTRE_IMP_CLOSED     = 1,
        LUSTRE_IMP_NEW        = 2,
        LUSTRE_IMP_DISCON     = 3,
        LUSTRE_IMP_CONNECTING = 4,
        LUSTRE_IMP_REPLAY     = 5,
        LUSTRE_IMP_REPLAY_LOCKS = 6,
        LUSTRE_IMP_REPLAY_WAIT  = 7,
        LUSTRE_IMP_RECOVER    = 8,
        LUSTRE_IMP_FULL       = 9,
        LUSTRE_IMP_EVICTED    = 10,
};

static inline char * ptlrpc_import_state_name(enum lustre_imp_state state)
{
        
        static char* import_state_names[] = {
                "<UNKNOWN>", "CLOSED",  "NEW", "DISCONN", 
                "CONNECTING", "REPLAY", "REPLAY_LOCKS", "REPLAY_WAIT", 
                "RECOVER", "FULL", "EVICTED",
        };

        LASSERT (state <= LUSTRE_IMP_EVICTED);
        return import_state_names[state];
}


struct obd_import {
        struct portals_handle     imp_handle;
        atomic_t                  imp_refcount;
        struct lustre_handle      imp_dlm_handle; /* client's ldlm export */
        struct ptlrpc_connection *imp_connection;
        struct ptlrpc_client     *imp_client;
        struct list_head          imp_observers;
        struct list_head          imp_pinger_chain;

        /* Lists of requests that are retained for replay, waiting for a reply,
         * or waiting for recovery to complete, respectively.
         */
        struct list_head          imp_replay_list;
        struct list_head          imp_sending_list;
        struct list_head          imp_delayed_list;

        struct obd_device        *imp_obd;
        wait_queue_head_t         imp_recovery_waitq;
        __u64                     imp_last_replay_transno;
        atomic_t                  imp_replay_inflight;
        enum lustre_imp_state     imp_state;
        int                       imp_generation;
        __u32                     imp_conn_cnt;
        __u64                     imp_max_transno;
        __u64                     imp_peer_committed_transno;
        struct obd_uuid           imp_target_uuid; /* XXX -> lustre_name */
        struct lustre_handle      imp_remote_handle;
        unsigned long             imp_next_ping;
        
        /* Protects flags, level, generation, conn_cnt, *_list */
        spinlock_t                imp_lock;

        /* flags */
        int                       imp_invalid:1, imp_replayable:1,
                                  imp_dlm_fake:1, imp_server_timeout:1,
                                  imp_initial_recov:1;
        __u32                     imp_connect_op;
};

typedef void (*obd_import_callback)(struct obd_import *imp, void *closure,
                                    int event, void *event_arg, void *cb_data);

struct obd_import_observer {
        struct list_head     oio_chain;
        obd_import_callback  oio_cb;
        void                *oio_cb_data;
};

void class_observe_import(struct obd_import *imp, obd_import_callback cb,
                          void *cb_data);
void class_unobserve_import(struct obd_import *imp, obd_import_callback cb,
                            void *cb_data);
void class_notify_import_observers(struct obd_import *imp, int event,
                                   void *event_arg);

#define IMP_EVENT_ACTIVE   1
#define IMP_EVENT_INACTIVE 2

/* genops.c */
struct obd_export;
extern struct obd_import *class_exp2cliimp(struct obd_export *);
extern struct obd_import *class_conn2cliimp(struct lustre_handle *);

#endif /* __IMPORT_H */
