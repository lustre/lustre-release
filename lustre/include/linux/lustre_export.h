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
struct mds_idmap_table;

struct mds_export_data {
        struct list_head        med_open_head;
        spinlock_t              med_open_lock;
        struct mds_client_data *med_mcd;
        loff_t                  med_off;
        int                     med_idx;
        unsigned int            med_initialized:1,
                                med_remote:1;
        __u32                   med_nllu;
        __u32                   med_nllg;
        struct mds_idmap_table *med_idmap;
};

struct osc_creator {
        spinlock_t              oscc_lock;
        struct obd_device      *oscc_obd;
        int                     oscc_flags;
        obd_id                  oscc_next_id;
        wait_queue_head_t       oscc_waitq;
};

struct ldlm_export_data {
        struct list_head       led_held_locks; /* protected by namespace lock */
        spinlock_t             led_lock;
};

struct ec_export_data { /* echo client */
        struct list_head eced_locks;
};

/* In-memory access to client data from OST struct */
struct filter_client_data;
struct obd_llogs;
struct filter_export_data {
        spinlock_t                 fed_lock;      /* protects fed_open_head */
        __u32                      fed_group;
        struct filter_client_data *fed_fcd;
        loff_t                     fed_lr_off;
        int                        fed_lr_idx;
        long                       fed_dirty;    /* in bytes */
        long                       fed_grant;    /* in bytes */
        long                       fed_pending;  /* bytes just being written */
};

struct obd_export {
        struct portals_handle     exp_handle;
        atomic_t                  exp_refcount;
        atomic_t                  exp_rpc_count;
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
        unsigned long             exp_flags;
        int                       exp_failed:1,
                                  exp_req_replay_needed:1,
                                  exp_lock_replay_needed:1,
                                  exp_connected:1,
                                  exp_libclient:1, /* liblustre client? */
                                  exp_sync:1;
        union {
                struct mds_export_data    eu_mds_data;
                struct filter_export_data eu_filter_data;
                struct ec_export_data     eu_ec_data;
        } u;
};

#define exp_mds_data    u.eu_mds_data
#define exp_lov_data    u.eu_lov_data
#define exp_filter_data u.eu_filter_data
#define exp_ec_data     u.eu_ec_data

extern struct obd_export *class_conn2export(struct lustre_handle *conn);
extern struct obd_device *class_conn2obd(struct lustre_handle *conn);

#endif /* __EXPORT_H */
