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

struct ldlm_export_data {
        struct list_head       led_held_locks; /* protected by namespace lock */
        struct obd_import     *led_import;
};

struct lov_export_data {
        spinlock_t       led_lock;
        struct list_head led_open_head;
};

struct ec_export_data { /* echo client */
        struct list_head eced_open_head;
        struct list_head eced_locks;
};

/* In-memory access to client data from OST struct */
struct filter_client_data;
struct filter_export_data {
        struct list_head           fed_open_head; //files to close on disconnect
        spinlock_t                 fed_lock;      /* protects fed_open_head */
        struct filter_client_data *fed_fcd;
        loff_t                     fed_lr_off;
        int                        fed_lr_idx;
};

struct obd_export {
        struct portals_handle     exp_handle;
        atomic_t                  exp_refcount;
        struct obd_uuid           exp_client_uuid;
        struct list_head          exp_obd_chain;
        struct obd_device        *exp_obd;
        struct ptlrpc_connection *exp_connection;
        struct ldlm_export_data   exp_ldlm_data;
        struct ptlrpc_request    *exp_outstanding_reply;
        time_t                    exp_last_request_time;
        spinlock_t                exp_lock; /* protects flags int below */
        int                       exp_failed:1;
        int                       exp_flags;
        union {
                struct mds_export_data    eu_mds_data;
                struct filter_export_data eu_filter_data;
                struct lov_export_data    eu_lov_data;
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
