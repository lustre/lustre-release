/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#ifndef __EXPORT_H
#define __EXPORT_H

#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>

struct mds_client_data;

struct mds_export_data {
        struct list_head        med_open_head;
        spinlock_t              med_open_lock;
        struct mds_client_data *med_mcd;
        loff_t                  med_off;
        int                     med_idx;
};

struct osc_creator {
        spinlock_t              oscc_lock;
        struct list_head        oscc_list;
        struct obd_export      *oscc_exp;
        obd_id                  oscc_last_id;//last available pre-created object
        obd_id                  oscc_next_id;// what object id to give out next
        int                     oscc_initial_create_count;
        int                     oscc_grow_count;
        int                     oscc_kick_barrier;
        struct osc_created     *oscc_osccd;
        struct obdo             oscc_oa;
        int                     oscc_flags;
        wait_queue_head_t       oscc_waitq; /* creating procs wait on this */
};

struct osc_export_data {
        struct osc_creator      oed_oscc;
};

struct ldlm_export_data {
        struct list_head       led_held_locks; /* protected by namespace lock */
};

struct ec_export_data { /* echo client */
        struct list_head eced_locks;
};

/* In-memory access to client data from OST struct */
struct filter_client_data;
struct filter_export_data {
        spinlock_t                 fed_lock;      /* protects fed_open_head */
        struct filter_client_data *fed_fcd;
        loff_t                     fed_lr_off;
        int                        fed_lr_idx;
        unsigned long              fed_dirty;    /* in bytes */
        unsigned long              fed_grant;    /* in bytes */
        unsigned long              fed_pending;  /* bytes just being written */
};

struct obd_export {
        struct portals_handle     exp_handle;
        atomic_t                  exp_refcount;
        struct obd_uuid           exp_client_uuid;
        struct list_head          exp_obd_chain;
        struct obd_device        *exp_obd;
        struct obd_import        *exp_imp_reverse; /* to make RPCs backwards */
        struct ptlrpc_connection *exp_connection;
        __u32                     exp_conn_cnt;
        struct ldlm_export_data   exp_ldlm_data;
        struct list_head          exp_outstanding_replies;
        time_t                    exp_last_request_time;
        spinlock_t                exp_lock; /* protects flags int below */
        /* ^ protects exp_outstanding_replies too */
        int                       exp_flags;
        int                       exp_failed:1;
        int                       exp_libclient:1; /* liblustre client? */
        union {
                struct mds_export_data    eu_mds_data;
                struct filter_export_data eu_filter_data;
                struct ec_export_data     eu_ec_data;
                struct osc_export_data    eu_osc_data;
        } u;
};

#define exp_mds_data    u.eu_mds_data
#define exp_lov_data    u.eu_lov_data
#define exp_filter_data u.eu_filter_data
#define exp_osc_data    u.eu_osc_data
#define exp_ec_data     u.eu_ec_data

extern struct obd_export *class_conn2export(struct lustre_handle *conn);
extern struct obd_device *class_conn2obd(struct lustre_handle *conn);

#endif /* __EXPORT_H */
