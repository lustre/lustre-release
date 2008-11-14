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
#include <class_hash.h>

static lustre_hash_t *conn_hash = NULL;
static lustre_hash_ops_t conn_hash_ops;

struct ptlrpc_connection *
ptlrpc_connection_get(lnet_process_id_t peer, lnet_nid_t self,
                      struct obd_uuid *uuid)
{
        struct ptlrpc_connection *conn, *conn2;
        ENTRY;

        conn = lustre_hash_lookup(conn_hash, &peer);
        if (conn)
                GOTO(out, conn);

        OBD_ALLOC_PTR(conn);
        if (!conn)
                RETURN(NULL);

        conn->c_peer = peer;
        conn->c_self = self;
        INIT_HLIST_NODE(&conn->c_hash);
        atomic_set(&conn->c_refcount, 1);
        if (uuid)
                obd_str2uuid(&conn->c_remote_uuid, uuid->uuid);

        /* 
         * Add the newly created conn to the hash, on key collision we
         * lost a racing addition and must destroy our newly allocated
         * connection.  The object which exists in the has will be
         * returned and may be compared against out object. 
         */
        conn2 = lustre_hash_findadd_unique(conn_hash, &peer, &conn->c_hash);
        if (conn != conn2) {
                OBD_FREE_PTR(conn);
                conn = conn2;
        }
        EXIT;
out:
        CDEBUG(D_INFO, "conn=%p refcount %d to %s\n",
               conn, atomic_read(&conn->c_refcount), 
               libcfs_nid2str(conn->c_peer.nid));
        return conn;
}
  
int ptlrpc_connection_put(struct ptlrpc_connection *conn)
{
        int rc = 0;
        ENTRY;
  
        if (!conn)
                RETURN(rc);
  
        LASSERT(!hlist_unhashed(&conn->c_hash));
  
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
        if (atomic_dec_return(&conn->c_refcount) == 1)
                rc = 1;

        CDEBUG(D_INFO, "PUT conn=%p refcount %d to %s\n",
               conn, atomic_read(&conn->c_refcount),
               libcfs_nid2str(conn->c_peer.nid));

        RETURN(rc);
}
  
struct ptlrpc_connection *
ptlrpc_connection_addref(struct ptlrpc_connection *conn)
{
        ENTRY;

        atomic_inc(&conn->c_refcount);
        CDEBUG(D_INFO, "conn=%p refcount %d to %s\n",
               conn, atomic_read(&conn->c_refcount),
               libcfs_nid2str(conn->c_peer.nid));

        RETURN(conn);
}
  
int ptlrpc_connection_init(void)
{
        ENTRY;

        conn_hash = lustre_hash_init("CONN_HASH", 5, 15,
                                     &conn_hash_ops, LH_REHASH);
        if (!conn_hash)
                RETURN(-ENOMEM);
  
        RETURN(0);
}
  
void ptlrpc_connection_fini(void) {
        ENTRY;
        lustre_hash_exit(conn_hash);
        EXIT;
}

/*
 * Hash operations for net_peer<->connection
 */
static unsigned
conn_hashfn(lustre_hash_t *lh,  void *key, unsigned mask)
{
        return lh_djb2_hash(key, sizeof(lnet_process_id_t), mask);
}

static int
conn_compare(void *key, struct hlist_node *hnode)
{
        struct ptlrpc_connection *conn;
        lnet_process_id_t *conn_key;

        LASSERT(key != NULL);
        conn_key = (lnet_process_id_t*)key;
        conn = hlist_entry(hnode, struct ptlrpc_connection, c_hash);

        return conn_key->nid == conn->c_peer.nid &&
               conn_key->pid == conn->c_peer.pid;
}

static void *
conn_key(struct hlist_node *hnode)
{
        struct ptlrpc_connection *conn;
        conn = hlist_entry(hnode, struct ptlrpc_connection, c_hash);
        return &conn->c_peer;
}

static void *
conn_get(struct hlist_node *hnode)
{
        struct ptlrpc_connection *conn;

        conn = hlist_entry(hnode, struct ptlrpc_connection, c_hash);
        atomic_inc(&conn->c_refcount);

        return conn;
}

static void *
conn_put(struct hlist_node *hnode)
{
        struct ptlrpc_connection *conn;

        conn = hlist_entry(hnode, struct ptlrpc_connection, c_hash);
        atomic_dec(&conn->c_refcount);

        return conn;
}

static void
conn_exit(struct hlist_node *hnode)
{
        struct ptlrpc_connection *conn;

        conn = hlist_entry(hnode, struct ptlrpc_connection, c_hash);
        /* 
         * Nothing should be left. Connection user put it and
         * connection also was deleted from table by this time
         * so we should have 0 refs.
         */
        LASSERTF(atomic_read(&conn->c_refcount) == 0, 
                 "Busy connection with %d refs\n", 
                 atomic_read(&conn->c_refcount));
        OBD_FREE_PTR(conn);
}

static lustre_hash_ops_t conn_hash_ops = {
        .lh_hash    = conn_hashfn,
        .lh_compare = conn_compare,
        .lh_key     = conn_key,
        .lh_get     = conn_get,
        .lh_put     = conn_put,
        .lh_exit    = conn_exit,
};
