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

#ifdef __KERNEL__

#include <linux/lustre_idl.h>
struct obd_import {
        struct ptlrpc_connection *imp_connection;
        struct ptlrpc_client     *imp_client;
        struct lustre_handle      imp_handle;
        struct list_head          imp_chain;
        struct obd_device        *imp_obd;
        /* XXX need a UUID here, I think
         * XXX what about client_obd.cl_target_uuid?
         */
};

extern struct obd_import *class_conn2cliimp(struct lustre_handle *);
extern struct obd_import *class_conn2ldlmimp(struct lustre_handle *);

#endif /* __KERNEL__ */

#endif /* __IMPORT_H */
