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
        int                       imp_level;
        int                       imp_generation;
        __u64                     imp_max_transno;
        __u64                     imp_peer_committed_transno;
        struct obd_uuid           imp_target_uuid; /* XXX -> lustre_name */
        struct lustre_handle      imp_remote_handle;

        /* Protects flags, level, generation, *_list */
        spinlock_t                imp_lock;

        /* flags */
        int                       imp_invalid:1, imp_replayable:1,
                                  imp_dlm_fake:1;
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
extern struct obd_import *class_conn2cliimp(struct lustre_handle *);
extern struct obd_import *class_conn2ldlmimp(struct lustre_handle *);

#endif /* __IMPORT_H */
