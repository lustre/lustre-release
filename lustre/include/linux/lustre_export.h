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

struct obd_export {
        __u64                     exp_cookie;
        struct lustre_handle      exp_impconnh;
        struct list_head          exp_obd_chain;
        struct list_head          exp_conn_chain;
        struct obd_device        *exp_obd;
        struct ptlrpc_connection *exp_connection;
        struct mds_export_data    exp_mds_data;
        struct ldlm_export_data   exp_ldlm_data;
#if NOTYET && 0
        struct ost_export_data    exp_ost_data;
#endif
        void                     *exp_data; /* device specific data */
        int                       exp_desclen;
        char                     *exp_desc;
        obd_uuid_t                exp_uuid;
};

extern struct obd_export *class_conn2export(struct lustre_handle *conn);
extern struct obd_device *class_conn2obd(struct lustre_handle *conn);
#endif /* __KERNEL__ */

#endif /* __EXPORT_H */
