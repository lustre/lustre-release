// SPDX-License-Identifier: GPL-2.0

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
#include <linux/rhashtable.h>
#include <linux/lnet/lib-lnet.h>
#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>

#include "ptlrpc_internal.h"

static struct rhashtable conn_hash;

/* system wide PM QoS management */
struct cpu_latency_qos ptlrpc_cpu_latency_qos;

/*
 * struct lnet_process_id may contain unassigned bytes which might not
 * be zero, so we cannot just hash and compare bytes.
 */

static u32 lnet_process_id_hash(const void *data, u32 len, u32 seed)
{
	const struct lnet_processid *lpi = data;

	seed = hash_32(seed ^ lpi->pid, 32);
	seed = hash_32(nidhash(&lpi->nid) ^ seed, 32);
	return seed;
}

static int lnet_process_id_cmp(struct rhashtable_compare_arg *arg,
			       const void *obj)
{
	const struct lnet_processid *lpi = arg->key;
	const struct ptlrpc_connection *con = obj;

	if (nid_same(&lpi->nid, &con->c_peer.nid) &&
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

/*
 * No lock on the PM QoS request: a work item never runs twice in parallel,
 * and ptlrpc_latency_req_fini() cancels it before removing the request.
 */
static void cpu_latency_work(struct work_struct *work)
{
	struct cpu_latency_qos *latency_qos;
	/* read once: re-reading it below could underflow the requeue delay */
	u64 now = get_jiffies_64();
	u64 delay, timeout, last;

	latency_qos = container_of(work, struct cpu_latency_qos,
				   delayed_work.work);

	/* the tunable may have been cleared since the work was queued */
	if (unlikely(!ptlrpc_enable_pmqos)) {
		CDEBUG(D_INFO, "PM QoS disabled, at %llu\n", now);
		goto drop;
	}

	/*
	 * no send for this long means the RPCs have stopped, last_send_time
	 * drops the part of the send time below a jiffy, the + 1 adds it back
	 */
	if (ptlrpc_pmqos_use_stats_for_duration) {
		/*
		 * longest reply delay or delay between sends, a jiffy at least
		 */
		delay = max(atomic64_read(&latency_qos->max_reply_delay),
			    atomic64_read(&latency_qos->max_send_delay));
		delay = max_t(u64, delay, 1);
		timeout = delay * CPU_LATENCY_SILENCE_FACTOR + 1;
	} else {
		/* set by the admin, held as is */
		delay = usecs_to_jiffies(ptlrpc_pmqos_default_duration_usec);
		timeout = delay + 1;
	}

	last = atomic64_read(&latency_qos->last_send_time);

	if (!cpu_latency_qos_request_active(&latency_qos->pm_qos_req)) {
		cpu_latency_qos_add_request(&latency_qos->pm_qos_req,
					    ptlrpc_pmqos_latency_max_usec);
		CDEBUG(D_INFO,
		       "PM QoS request now active, delay %llu, timeout %llu\n",
		       delay, timeout);
		/* just added, give it a whole window before looking again */
		mod_delayed_work(system_highpri_wq,
				 &latency_qos->delayed_work, timeout);
		return;
	}

	if (time_after_eq64(now, last + timeout)) {
		CDEBUG(D_INFO, "PM QoS no RPC since %llu, at %llu\n",
		       last, now);
		goto drop;
	}

	CDEBUG(D_INFO, "PM QoS held, last RPC %llu, timeout %llu, at %llu\n",
	       last, timeout, now);
	/* the tunable may have changed since the request was added */
	cpu_latency_qos_update_request(&latency_qos->pm_qos_req,
				       ptlrpc_pmqos_latency_max_usec);
	/*
	 * look again exactly when the silence would be complete, the check
	 * above just proved that instant is still ahead of us
	 */
	mod_delayed_work(system_highpri_wq, &latency_qos->delayed_work,
			 last + timeout - now);
	return;

drop:
	/* a send since the check above queued us again, keep the request */
	if (delayed_work_pending(&latency_qos->delayed_work))
		return;
	if (cpu_latency_qos_request_active(&latency_qos->pm_qos_req))
		cpu_latency_qos_remove_request(&latency_qos->pm_qos_req);
	/* decay by 1/8 instead of clearing, unless a newer sample came in */
	delay = atomic64_read(&latency_qos->max_reply_delay);
	atomic64_cmpxchg(&latency_qos->max_reply_delay, delay, delay * 7 >> 3);
	delay = atomic64_read(&latency_qos->max_send_delay);
	atomic64_cmpxchg(&latency_qos->max_send_delay, delay, delay * 7 >> 3);
}

/**
 * ptlrpc_connection_get_primary() - Get the connection for a primary NID.
 * @peer: Peer process ID. @peer->nid must be the current primary NID.
 *
 * Unlike ptlrpc_connection_get(), this function does not call
 * LNetPrimaryNID(). It never waits on discovery.
 *
 * Context: Can sleep, because it can allocate the connection.
 * Return: The connection keyed on @peer, or NULL if the allocation fails.
 */
struct ptlrpc_connection *
ptlrpc_connection_get_primary(struct lnet_processid *peer)
{
	struct ptlrpc_connection *conn, *conn2;

	ENTRY;

	conn = rhashtable_lookup_fast(&conn_hash, peer, conn_hash_params);
	if (conn) {
		ptlrpc_connection_addref(conn);
		GOTO(out, conn);
	}

	OBD_ALLOC_PTR(conn);
	if (!conn)
		RETURN(NULL);

	conn->c_peer = *peer;
	atomic_set(&conn->c_refcount, 1);

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
		if (IS_ERR(conn2)) {
			/* hash table could be resizing. */
			if (PTR_ERR(conn2) == -ENOMEM ||
			    PTR_ERR(conn2) == -EBUSY) {
				msleep(5);
				goto try_again;
			}
			conn2 = NULL;
		}
		OBD_FREE_PTR(conn);
		conn = conn2;
		if (conn)
			ptlrpc_connection_addref(conn);
	}
	EXIT;
out:
	CDEBUG(D_INFO, "conn=%p refcount %d to %s\n",
	       conn, atomic_read(&conn->c_refcount),
	       libcfs_nidstr(&conn->c_peer.nid));
	return conn;
}

struct ptlrpc_connection *
ptlrpc_connection_get(struct lnet_processid *peer, struct lnet_nid *self,
		      struct obd_uuid *uuid)
{
	struct lnet_processid primary = *peer;

	LNetPrimaryNID(&primary.nid);

	return ptlrpc_connection_get_primary(&primary);
}

struct ptlrpc_connection *
ptlrpc_connection_addref(struct ptlrpc_connection *conn)
{
	ENTRY;

	atomic_inc(&conn->c_refcount);
	CDEBUG(D_INFO, "conn=%p refcount %d to %s\n",
	       conn, atomic_read(&conn->c_refcount),
	       libcfs_nidstr(&conn->c_peer.nid));

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

static void ptlrpc_latency_req_init(struct cpu_latency_qos *lq)
{
	INIT_DELAYED_WORK(&lq->delayed_work, cpu_latency_work);
}

int ptlrpc_connection_init(void)
{
	ptlrpc_latency_req_init(&ptlrpc_cpu_latency_qos);

	return rhashtable_init(&conn_hash, &conn_hash_params);
}

static void ptlrpc_latency_req_fini(struct cpu_latency_qos *lq)
{
	/*
	 * Wait for any in-flight (or self-rescheduling) cpu_latency_work() to
	 * finish before touching what it dereferences.
	 * cancel_delayed_work() alone does not wait for a work item that has
	 * already been dispatched, so it could still requeue itself after the
	 * module is unloaded.  A sender can queue it again too, but ptlrpc is
	 * torn down only once no RPC is sent anymore.
	 */
	cancel_delayed_work_sync(&lq->delayed_work);

	if (cpu_latency_qos_request_active(&lq->pm_qos_req)) {
		cpu_latency_qos_remove_request(&lq->pm_qos_req);
		CDEBUG(D_INFO, "remove PM QoS request %p and associated work item, still active\n",
		       lq);
	}
}

void ptlrpc_connection_fini(void)
{
	rhashtable_free_and_destroy(&conn_hash, conn_exit, NULL);

	ptlrpc_latency_req_fini(&ptlrpc_cpu_latency_qos);
}
