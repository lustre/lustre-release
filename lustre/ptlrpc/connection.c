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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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

static spinlock_t conn_lock;
static struct list_head conn_list;
static struct list_head conn_unused_list;
static struct lustre_class_hash_body *conn_hash_body;
static struct lustre_class_hash_body *conn_unused_hash_body;

extern struct lustre_hash_operations conn_hash_operations;

void ptlrpc_dump_connections(void)
{
        struct list_head *tmp;
        struct ptlrpc_connection *c;
        ENTRY;

        list_for_each(tmp, &conn_list) {
                c = list_entry(tmp, struct ptlrpc_connection, c_link);
                CERROR("Connection %p/%s has refcount %d (nid=%s->%s)\n",
                       c, c->c_remote_uuid.uuid, atomic_read(&c->c_refcount),
                       libcfs_nid2str(c->c_self), 
                       libcfs_nid2str(c->c_peer.nid));
        }
        EXIT;
}

struct ptlrpc_connection*
ptlrpc_lookup_conn_locked (lnet_process_id_t peer)
{
        struct ptlrpc_connection *c;

        c = lustre_hash_get_object_by_key(conn_hash_body, &peer);
        if (c != NULL)
                return c;

        c = lustre_hash_get_object_by_key(conn_unused_hash_body, &peer);
        if (c != NULL)
                return c;

        return NULL;
}


struct ptlrpc_connection *ptlrpc_get_connection(lnet_process_id_t peer,
                                                lnet_nid_t self, struct obd_uuid *uuid)
{
        struct ptlrpc_connection *c;
        struct ptlrpc_connection *c2;
        int rc = 0;
        ENTRY;

        CDEBUG(D_INFO, "self %s peer %s\n", 
               libcfs_nid2str(self), libcfs_id2str(peer));

        spin_lock(&conn_lock);

        c = ptlrpc_lookup_conn_locked(peer);
        
        spin_unlock(&conn_lock);

        if (c != NULL)
                RETURN (c);
        
        OBD_ALLOC(c, sizeof(*c));
        if (c == NULL)
                RETURN (NULL);

        atomic_set(&c->c_refcount, 1);
        c->c_peer = peer;
        c->c_self = self;
        INIT_HLIST_NODE(&c->c_hash);
        CFS_INIT_LIST_HEAD(&c->c_link);
        if (uuid != NULL)
                obd_str2uuid(&c->c_remote_uuid, uuid->uuid);

        spin_lock(&conn_lock);

        c2 = ptlrpc_lookup_conn_locked(peer);
        if (c2 == NULL) {
                list_add(&c->c_link, &conn_list);
                rc = lustre_hash_additem_unique(conn_hash_body, &peer, 
                                                &c->c_hash);
                if (rc != 0) {
                        list_del(&c->c_link);
                        CERROR("Cannot add connection to conn_hash_body\n");
                        goto out_conn;
                }
        }

out_conn:

        spin_unlock(&conn_lock);

        if (c2 == NULL && rc == 0)
                RETURN (c);

        if (c != NULL) 
                OBD_FREE(c, sizeof(*c));
        RETURN (c2);
}

int ptlrpc_put_connection(struct ptlrpc_connection *c)
{
        int rc = 0;
        ENTRY;

        if (c == NULL) {
                CERROR("NULL connection\n");
                RETURN(0);
        }

        CDEBUG (D_INFO, "connection=%p refcount %d to %s\n",
                c, atomic_read(&c->c_refcount) - 1, 
                libcfs_nid2str(c->c_peer.nid));

        spin_lock(&conn_lock);
        LASSERT(!hlist_unhashed(&c->c_hash));
        spin_unlock(&conn_lock);

        if (atomic_dec_return(&c->c_refcount) == 1) {

                spin_lock(&conn_lock);

                lustre_hash_delitem(conn_hash_body, &c->c_peer, &c->c_hash);
                list_del(&c->c_link);

                list_add(&c->c_link, &conn_unused_list);
                rc = lustre_hash_additem_unique(conn_unused_hash_body, &c->c_peer, 
                                                &c->c_hash);
                if (rc != 0) {
                        spin_unlock(&conn_lock);
                        CERROR("Cannot hash connection to conn_hash_body\n");
                        GOTO(ret, rc);
                }

                spin_unlock(&conn_lock);
                rc = 1;
 
        } 

        if (atomic_read(&c->c_refcount) < 0)
                CERROR("connection %p refcount %d!\n",
                       c, atomic_read(&c->c_refcount));
ret :

        RETURN(rc);
}

struct ptlrpc_connection *ptlrpc_connection_addref(struct ptlrpc_connection *c)
{
        ENTRY;
        atomic_inc(&c->c_refcount);
        CDEBUG (D_INFO, "connection=%p refcount %d to %s\n",
                c, atomic_read(&c->c_refcount),
                libcfs_nid2str(c->c_peer.nid));
        RETURN(c);
}

int ptlrpc_init_connection(void)
{
        int rc = 0;
        CFS_INIT_LIST_HEAD(&conn_list);
        rc = lustre_hash_init(&conn_hash_body, "CONN_HASH", 
                              128, &conn_hash_operations);
        if (rc)
                GOTO(ret, rc);

        CFS_INIT_LIST_HEAD(&conn_unused_list);
        rc = lustre_hash_init(&conn_unused_hash_body, "CONN_UNUSED_HASH", 
                              128, &conn_hash_operations);
        if (rc)
                GOTO(ret, rc);

        spin_lock_init(&conn_lock);
ret:
        if (rc) {
                lustre_hash_exit(&conn_hash_body);
                lustre_hash_exit(&conn_unused_hash_body);
        }
        RETURN(rc);
}

void ptlrpc_cleanup_connection(void)
{
        struct list_head *tmp, *pos;
        struct ptlrpc_connection *c;

        spin_lock(&conn_lock);

        lustre_hash_exit(&conn_unused_hash_body);
        list_for_each_safe(tmp, pos, &conn_unused_list) {
                c = list_entry(tmp, struct ptlrpc_connection, c_link);
                list_del(&c->c_link);
                OBD_FREE(c, sizeof(*c));
        }

        lustre_hash_exit(&conn_hash_body);
        list_for_each_safe(tmp, pos, &conn_list) {
                c = list_entry(tmp, struct ptlrpc_connection, c_link);
                CERROR("Connection %p/%s has refcount %d (nid=%s)\n",
                       c, c->c_remote_uuid.uuid, atomic_read(&c->c_refcount),
                       libcfs_nid2str(c->c_peer.nid));
                list_del(&c->c_link);
                OBD_FREE(c, sizeof(*c));
        }
        spin_unlock(&conn_lock);
}
