/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 *
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

static spinlock_t conn_lock;
static struct list_head conn_list;
static struct list_head conn_unused_list;

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
        struct list_head         *tmp;

        list_for_each(tmp, &conn_list) {
                c = list_entry(tmp, struct ptlrpc_connection, c_link);

                if (peer.nid == c->c_peer.nid &&
                    peer.pid == c->c_peer.pid)
                        return ptlrpc_connection_addref(c);
        }

        list_for_each(tmp, &conn_unused_list) {
                c = list_entry(tmp, struct ptlrpc_connection, c_link);

                if (peer.nid == c->c_peer.nid &&
                    peer.pid == c->c_peer.pid) {
                        list_del(&c->c_link);
                        list_add(&c->c_link, &conn_list);
                        return ptlrpc_connection_addref(c);
                }
        }

        return NULL;
}


struct ptlrpc_connection *ptlrpc_get_connection(lnet_process_id_t peer,
                                                lnet_nid_t self, struct obd_uuid *uuid)
{
        struct ptlrpc_connection *c;
        struct ptlrpc_connection *c2;
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
        if (uuid != NULL)
                obd_str2uuid(&c->c_remote_uuid, uuid->uuid);

        spin_lock(&conn_lock);

        c2 = ptlrpc_lookup_conn_locked(peer);
        if (c2 == NULL)
                list_add(&c->c_link, &conn_list);
        
        spin_unlock(&conn_lock);

        if (c2 == NULL)
                RETURN (c);
        
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

        if (atomic_dec_and_test(&c->c_refcount)) {
                spin_lock(&conn_lock);
                list_del(&c->c_link);
                list_add(&c->c_link, &conn_unused_list);
                spin_unlock(&conn_lock);
                rc = 1;
        }
        if (atomic_read(&c->c_refcount) < 0)
                CERROR("connection %p refcount %d!\n",
                       c, atomic_read(&c->c_refcount));

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

void ptlrpc_init_connection(void)
{
        CFS_INIT_LIST_HEAD(&conn_list);
        CFS_INIT_LIST_HEAD(&conn_unused_list);
        spin_lock_init(&conn_lock);
}

void ptlrpc_cleanup_connection(void)
{
        struct list_head *tmp, *pos;
        struct ptlrpc_connection *c;

        spin_lock(&conn_lock);
        list_for_each_safe(tmp, pos, &conn_unused_list) {
                c = list_entry(tmp, struct ptlrpc_connection, c_link);
                list_del(&c->c_link);
                OBD_FREE(c, sizeof(*c));
        }
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
