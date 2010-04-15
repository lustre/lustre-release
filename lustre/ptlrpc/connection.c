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
 */

#define DEBUG_SUBSYSTEM S_RPC
#ifdef __KERNEL__
#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>
#else
#include <liblustre.h>
#endif

#include "ptlrpc_internal.h"

static cfs_hash_t *conn_hash = NULL;
static cfs_hash_ops_t conn_hash_ops;

struct ptlrpc_connection *
ptlrpc_connection_get(lnet_process_id_t peer, lnet_nid_t self,
                      struct obd_uuid *uuid)
{
        struct ptlrpc_connection *conn, *conn2;
        ENTRY;

        conn = cfs_hash_lookup(conn_hash, &peer);
        if (conn)
                GOTO(out, conn);

        OBD_ALLOC_PTR(conn);
        if (!conn)
                RETURN(NULL);

        conn->c_peer = peer;
        conn->c_self = self;
        CFS_INIT_HLIST_NODE(&conn->c_hash);
        cfs_atomic_set(&conn->c_refcount, 1);
        if (uuid)
                obd_str2uuid(&conn->c_remote_uuid, uuid->uuid);

        /*
         * Add the newly created conn to the hash, on key collision we
         * lost a racing addition and must destroy our newly allocated
         * connection.  The object which exists in the has will be
         * returned and may be compared against out object.
         */
        conn2 = cfs_hash_findadd_unique(conn_hash, &peer, &conn->c_hash);
        if (conn != conn2) {
                OBD_FREE_PTR(conn);
                conn = conn2;
        }
        EXIT;
out:
        CDEBUG(D_INFO, "conn=%p refcount %d to %s\n",
               conn, cfs_atomic_read(&conn->c_refcount),
               libcfs_nid2str(conn->c_peer.nid));
        return conn;
}

int ptlrpc_connection_put(struct ptlrpc_connection *conn)
{
        int rc = 0;
        ENTRY;

        if (!conn)
                RETURN(rc);

        LASSERT(!cfs_hlist_unhashed(&conn->c_hash));

        /*
         * We do not remove connection from hashtable and
         * do not free it even if last caller released ref,
         * as we want to have it cached for the case it is
         * needed again.
         *
         * Deallocating it and later creating new connection
         * again would be wastful. This way we also avoid
         * expensive locking to protect things from get/put
         * race when found cached connection is freed by
         * ptlrpc_connection_put().
         *
         * It will be freed later in module unload time,
         * when ptlrpc_connection_fini()->lh_exit->conn_exit()
         * path is called.
         */
        if (cfs_atomic_dec_return(&conn->c_refcount) == 1)
                rc = 1;

        CDEBUG(D_INFO, "PUT conn=%p refcount %d to %s\n",
               conn, cfs_atomic_read(&conn->c_refcount),
               libcfs_nid2str(conn->c_peer.nid));

        RETURN(rc);
}

struct ptlrpc_connection *
ptlrpc_connection_addref(struct ptlrpc_connection *conn)
{
        ENTRY;

        cfs_atomic_inc(&conn->c_refcount);
        CDEBUG(D_INFO, "conn=%p refcount %d to %s\n",
               conn, cfs_atomic_read(&conn->c_refcount),
               libcfs_nid2str(conn->c_peer.nid));

        RETURN(conn);
}

int ptlrpc_connection_init(void)
{
        ENTRY;

        conn_hash = cfs_hash_create("CONN_HASH",
                                    HASH_CONN_CUR_BITS,
                                    HASH_CONN_MAX_BITS,
                                    &conn_hash_ops, CFS_HASH_REHASH);
        if (!conn_hash)
                RETURN(-ENOMEM);

        RETURN(0);
}

void ptlrpc_connection_fini(void) {
        ENTRY;
        cfs_hash_putref(conn_hash);
        EXIT;
}

/*
 * Hash operations for net_peer<->connection
 */
static unsigned
conn_hashfn(cfs_hash_t *hs,  void *key, unsigned mask)
{
        return cfs_hash_djb2_hash(key, sizeof(lnet_process_id_t), mask);
}

static int
conn_compare(void *key, cfs_hlist_node_t *hnode)
{
        struct ptlrpc_connection *conn;
        lnet_process_id_t *conn_key;

        LASSERT(key != NULL);
        conn_key = (lnet_process_id_t*)key;
        conn = cfs_hlist_entry(hnode, struct ptlrpc_connection, c_hash);

        return conn_key->nid == conn->c_peer.nid &&
               conn_key->pid == conn->c_peer.pid;
}

static void *
conn_key(cfs_hlist_node_t *hnode)
{
        struct ptlrpc_connection *conn;
        conn = cfs_hlist_entry(hnode, struct ptlrpc_connection, c_hash);
        return &conn->c_peer;
}

static void *
conn_get(cfs_hlist_node_t *hnode)
{
        struct ptlrpc_connection *conn;

        conn = cfs_hlist_entry(hnode, struct ptlrpc_connection, c_hash);
        cfs_atomic_inc(&conn->c_refcount);

        return conn;
}

static void *
conn_put(cfs_hlist_node_t *hnode)
{
        struct ptlrpc_connection *conn;

        conn = cfs_hlist_entry(hnode, struct ptlrpc_connection, c_hash);
        cfs_atomic_dec(&conn->c_refcount);

        return conn;
}

static void
conn_exit(cfs_hlist_node_t *hnode)
{
        struct ptlrpc_connection *conn;

        conn = cfs_hlist_entry(hnode, struct ptlrpc_connection, c_hash);
        /*
         * Nothing should be left. Connection user put it and
         * connection also was deleted from table by this time
         * so we should have 0 refs.
         */
        LASSERTF(cfs_atomic_read(&conn->c_refcount) == 0,
                 "Busy connection with %d refs\n",
                 cfs_atomic_read(&conn->c_refcount));
        OBD_FREE_PTR(conn);
}

static cfs_hash_ops_t conn_hash_ops = {
        .hs_hash    = conn_hashfn,
        .hs_compare = conn_compare,
        .hs_key     = conn_key,
        .hs_get     = conn_get,
        .hs_put     = conn_put,
        .hs_exit    = conn_exit,
};
