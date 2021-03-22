/*
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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_RPC

#include <linux/delay.h>
#include <libcfs/linux/linux-hash.h>
#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>

#include "ptlrpc_internal.h"

static struct rhashtable conn_hash;

/*
 * struct lnet_process_id may contain unassigned bytes which might not
 * be zero, so we cannot just hash and compare bytes.
 */

static u32 lnet_process_id_hash(const void *data, u32 len, u32 seed)
{
	const struct lnet_process_id *lpi = data;

	seed = cfs_hash_32(seed ^ lpi->pid, 32);
	seed ^= cfs_hash_64(lpi->nid, 32);
	return seed;
}

static int lnet_process_id_cmp(struct rhashtable_compare_arg *arg,
			       const void *obj)
{
	const struct lnet_process_id *lpi = arg->key;
	const struct ptlrpc_connection *con = obj;

	if (lpi->nid == con->c_peer.nid &&
	    lpi->pid == con->c_peer.pid)
		return 0;
	return -ESRCH;
}

static const struct rhashtable_params conn_hash_params = {
	.key_len	= 1,	/* actually variable-length */
	.key_offset	= offsetof(struct ptlrpc_connection, c_peer),
	.head_offset	= offsetof(struct ptlrpc_connection, c_hash),
	.hashfn		= lnet_process_id_hash,
	.obj_cmpfn	= lnet_process_id_cmp,
};

struct ptlrpc_connection *
ptlrpc_connection_get(struct lnet_process_id peer, lnet_nid_t self,
		      struct obd_uuid *uuid)
{
	struct ptlrpc_connection *conn, *conn2;
	ENTRY;

	peer.nid = LNetPrimaryNID(peer.nid);
	conn = rhashtable_lookup_fast(&conn_hash, &peer, conn_hash_params);
	if (conn) {
		ptlrpc_connection_addref(conn);
		GOTO(out, conn);
	}

	OBD_ALLOC_PTR(conn);
	if (!conn)
		RETURN(NULL);

	conn->c_peer = peer;
	conn->c_self = self;
	atomic_set(&conn->c_refcount, 1);
	if (uuid)
		obd_str2uuid(&conn->c_remote_uuid, uuid->uuid);

	/*
	 * Add the newly created conn to the hash, on key collision we
	 * lost a racing addition and must destroy our newly allocated
	 * connection.	The object which exists in the hash will be
	 * returned,otherwise NULL is returned on success.
	 */
try_again:
	conn2 = rhashtable_lookup_get_insert_fast(&conn_hash, &conn->c_hash,
						  conn_hash_params);
	if (conn2) {
		/* insertion failed */
		OBD_FREE_PTR(conn);
		if (IS_ERR(conn2)) {
			/* hash table could be resizing. */
			if (PTR_ERR(conn2) == -ENOMEM ||
			    PTR_ERR(conn2) == -EBUSY) {
				msleep(5);
				goto try_again;
			}
			return NULL;
		}
		conn = conn2;
		ptlrpc_connection_addref(conn);
	}
	EXIT;
out:
	CDEBUG(D_INFO, "conn=%p refcount %d to %s\n",
	       conn, atomic_read(&conn->c_refcount),
	       libcfs_nid2str(conn->c_peer.nid));
	return conn;
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

static void
conn_exit(void *vconn, void *data)
{
	struct ptlrpc_connection *conn = vconn;

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

int ptlrpc_connection_init(void)
{
	return rhashtable_init(&conn_hash, &conn_hash_params);
}

void ptlrpc_connection_fini(void)
{
	rhashtable_free_and_destroy(&conn_hash, conn_exit, NULL);
}
