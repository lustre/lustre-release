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

#ifdef __KERNEL__

#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_mds.h>
#include <linux/obd_filter.h>

struct lov_export_data {
        spinlock_t       led_lock;
        struct list_head led_open_head;
};

struct ec_export_data { /* echo client */
        struct list_head eced_open_head;
        struct list_head eced_locks;
};

struct obd_export {
        __u64                     exp_cookie;
        struct obd_uuid           exp_client_uuid;
        struct list_head          exp_obd_chain;
        struct list_head          exp_conn_chain;
        struct obd_device        *exp_obd;
        struct ptlrpc_connection *exp_connection;
        struct ldlm_export_data   exp_ldlm_data;
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
#endif /* __KERNEL__ */

#endif /* __EXPORT_H */
