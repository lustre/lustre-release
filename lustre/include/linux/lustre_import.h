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

#define IMP_INVALID       1
#define IMP_REPLAYABLE    2

#include <linux/lustre_idl.h>
struct obd_import {
        struct ptlrpc_connection *imp_connection;
        struct ptlrpc_client     *imp_client;
        struct lustre_handle      imp_handle;
        struct list_head          imp_chain;
        struct list_head          imp_request_list;
        struct obd_device        *imp_obd;
        int                       imp_flags;
        int                       imp_level;
        __u64                     imp_last_xid;
        __u64                     imp_max_transno;
        __u64                     imp_peer_last_xid;
        __u64                     imp_peer_committed_transno;

        /* Protects flags, level, *_xid, request_list */
        spinlock_t                imp_lock;
};

extern struct obd_import *class_conn2cliimp(struct lustre_handle *);
extern struct obd_import *class_conn2ldlmimp(struct lustre_handle *);

#endif /* __KERNEL__ */

#endif /* __IMPORT_H */
