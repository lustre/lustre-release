/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define DEBUG_SUBSYSTEM S_RPC
#ifdef __KERNEL__
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_net.h>
#else
#include <liblustre.h>
#endif

#include "ptlrpc_internal.h"

static spinlock_t conn_lock;
static struct list_head conn_list;
static struct list_head conn_unused_list;

void ptlrpc_dump_connections(void)
{
        char str[PTL_NALFMT_SIZE];
        struct list_head *tmp;
        struct ptlrpc_connection *c;
        ENTRY;

        list_for_each(tmp, &conn_list) {
                c = list_entry(tmp, struct ptlrpc_connection, c_link);
                CERROR("Connection %p/%s has refcount %d (nid=%s on %s)\n",
                       c, c->c_remote_uuid.uuid, atomic_read(&c->c_refcount),
                       ptlrpc_peernid2str(&c->c_peer, str),
                       c->c_peer.peer_ni->pni_name);
        }
        EXIT;
}

struct ptlrpc_connection *ptlrpc_get_connection(struct ptlrpc_peer *peer,
                                                struct obd_uuid *uuid)
{
        char str[PTL_NALFMT_SIZE];
        struct list_head *tmp, *pos;
        struct ptlrpc_connection *c;
        ENTRY;


        CDEBUG(D_INFO, "peer is %s on %s\n",
               ptlrpc_peernid2str(peer, str), peer->peer_ni->pni_name);

        spin_lock(&conn_lock);
        list_for_each(tmp, &conn_list) {
                c = list_entry(tmp, struct ptlrpc_connection, c_link);
                if (peer->peer_nid == c->c_peer.peer_nid &&
                    peer->peer_ni == c->c_peer.peer_ni) {
                        ptlrpc_connection_addref(c);
                        GOTO(out, c);
                }
        }

        list_for_each_safe(tmp, pos, &conn_unused_list) {
                c = list_entry(tmp, struct ptlrpc_connection, c_link);
                if (peer->peer_nid == c->c_peer.peer_nid &&
                    peer->peer_ni == c->c_peer.peer_ni) {
                        ptlrpc_connection_addref(c);
                        list_del(&c->c_link);
                        list_add(&c->c_link, &conn_list);
                        GOTO(out, c);
                }
        }

        /* FIXME: this should be a slab once we can validate slab addresses
         * without OOPSing */
        OBD_ALLOC_GFP(c, sizeof(*c), GFP_ATOMIC);
	
        if (c == NULL)
                GOTO(out, c);

        if (uuid && uuid->uuid)                         /* XXX ???? */
                obd_str2uuid(&c->c_remote_uuid, uuid->uuid);
        atomic_set(&c->c_refcount, 0);
        memcpy(&c->c_peer, peer, sizeof(c->c_peer));

        ptlrpc_connection_addref(c);

        list_add(&c->c_link, &conn_list);

        EXIT;
 out:
        spin_unlock(&conn_lock);
        return c;
}

int ptlrpc_put_connection(struct ptlrpc_connection *c)
{
        char str[PTL_NALFMT_SIZE];
        int rc = 0;
        ENTRY;

        if (c == NULL) {
                CERROR("NULL connection\n");
                RETURN(0);
        }

        CDEBUG (D_INFO, "connection=%p refcount %d to %s on %s\n",
                c, atomic_read(&c->c_refcount) - 1, 
                ptlrpc_peernid2str(&c->c_peer, str),
                c->c_peer.peer_ni->pni_name);

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
        char str[PTL_NALFMT_SIZE];
        ENTRY;
        atomic_inc(&c->c_refcount);
        CDEBUG (D_INFO, "connection=%p refcount %d to %s on %s\n",
                c, atomic_read(&c->c_refcount),
                ptlrpc_peernid2str(&c->c_peer, str),
                c->c_peer.peer_ni->pni_name);
        RETURN(c);
}

void ptlrpc_init_connection(void)
{
        INIT_LIST_HEAD(&conn_list);
        INIT_LIST_HEAD(&conn_unused_list);
        conn_lock = SPIN_LOCK_UNLOCKED;
}

void ptlrpc_cleanup_connection(void)
{
        char str[PTL_NALFMT_SIZE];
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
                CERROR("Connection %p/%s has refcount %d (nid=%s on %s)\n",
                       c, c->c_remote_uuid.uuid, atomic_read(&c->c_refcount),
                       ptlrpc_peernid2str(&c->c_peer, str),
                       c->c_peer.peer_ni->pni_name);
                list_del(&c->c_link);
                OBD_FREE(c, sizeof(*c));
        }
        spin_unlock(&conn_lock);
}
