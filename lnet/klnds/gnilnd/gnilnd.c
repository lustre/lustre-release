/*
 * Copyright (C) 2012 Cray, Inc.
 *
 * Copyright (c) 2013, 2017, Intel Corporation.
 *
 *   Author: Nic Henke <nic@cray.com>
 *   Author: James Shimek <jshimek@cray.com>
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
#include "gnilnd.h"

/* Primary entry points from LNET.  There are no guarantees against reentrance. */
struct lnet_lnd the_kgnilnd = {
	.lnd_type       = GNILND,
	.lnd_startup    = kgnilnd_startup,
	.lnd_shutdown   = kgnilnd_shutdown,
	.lnd_ctl        = kgnilnd_ctl,
	.lnd_send       = kgnilnd_send,
	.lnd_recv       = kgnilnd_recv,
	.lnd_eager_recv = kgnilnd_eager_recv,
	.lnd_query      = kgnilnd_query,
};

kgn_data_t      kgnilnd_data;

int
kgnilnd_thread_start(int(*fn)(void *arg), void *arg, char *name, int id)
{
	struct task_struct *thrd;

	thrd = kthread_run(fn, arg, "%s_%02d", name, id);
	if (IS_ERR(thrd))
		return PTR_ERR(thrd);

	atomic_inc(&kgnilnd_data.kgn_nthreads);
	return 0;
}

/* bind scheduler threads to cpus */
int
kgnilnd_start_sd_threads(void)
{
	int cpu;
	int i = 0;
	struct task_struct *task;

	for_each_online_cpu(cpu) {
		/* don't bind to cpu 0 - all interrupts are processed here */
		if (cpu == 0)
			continue;

		task = kthread_create(kgnilnd_scheduler, (void *)((long)i),
				      "%s_%02d", "kgnilnd_sd", i);
		if (!IS_ERR(task)) {
			kthread_bind(task, cpu);
			wake_up_process(task);
		} else {
			CERROR("Can't spawn gnilnd scheduler[%d] %ld\n", i,
				PTR_ERR(task));
			return PTR_ERR(task);
		}
		atomic_inc(&kgnilnd_data.kgn_nthreads);

		if (++i >= *kgnilnd_tunables.kgn_sched_threads) {
			break;
		}
	}

	return 0;
}

/* needs write_lock on kgn_peer_conn_lock */
int
kgnilnd_close_stale_conns_locked(kgn_peer_t *peer, kgn_conn_t *newconn)
{
	kgn_conn_t         *conn;
	struct list_head   *ctmp, *cnxt;
	int                 loopback;
	int                 count = 0;

	loopback = peer->gnp_nid == peer->gnp_net->gnn_ni->ni_nid;

	list_for_each_safe(ctmp, cnxt, &peer->gnp_conns) {
		conn = list_entry(ctmp, kgn_conn_t, gnc_list);

		if (conn->gnc_state != GNILND_CONN_ESTABLISHED)
			continue;

		if (conn == newconn)
			continue;

		if (conn->gnc_device != newconn->gnc_device)
			continue;

		/* This is a two connection loopback - one talking to the other */
		if (loopback &&
		    newconn->gnc_my_connstamp == conn->gnc_peer_connstamp &&
		    newconn->gnc_peer_connstamp == conn->gnc_my_connstamp) {
			CDEBUG(D_NET, "skipping prune of %p, "
				"loopback and matching stamps"
				" connstamp %llu(%llu)"
				" peerstamp %llu(%llu)\n",
				conn, newconn->gnc_my_connstamp,
				conn->gnc_peer_connstamp,
				newconn->gnc_peer_connstamp,
				conn->gnc_my_connstamp);
			continue;
		}

		if (conn->gnc_peerstamp != newconn->gnc_peerstamp) {
			LASSERTF(conn->gnc_peerstamp < newconn->gnc_peerstamp,
				"conn 0x%p peerstamp %llu >= "
				"newconn 0x%p peerstamp %llu\n",
				conn, conn->gnc_peerstamp,
				newconn, newconn->gnc_peerstamp);

			CDEBUG(D_NET, "Closing stale conn nid: %s "
			       " peerstamp:%#llx(%#llx)\n",
			       libcfs_nid2str(peer->gnp_nid),
			       conn->gnc_peerstamp, newconn->gnc_peerstamp);
		} else {

			LASSERTF(conn->gnc_peer_connstamp < newconn->gnc_peer_connstamp,
				"conn 0x%p peer_connstamp %llu >= "
				"newconn 0x%p peer_connstamp %llu\n",
				conn, conn->gnc_peer_connstamp,
				newconn, newconn->gnc_peer_connstamp);

			CDEBUG(D_NET, "Closing stale conn nid: %s"
			       " connstamp:%llu(%llu)\n",
			       libcfs_nid2str(peer->gnp_nid),
			       conn->gnc_peer_connstamp, newconn->gnc_peer_connstamp);
		}

		count++;
		kgnilnd_close_conn_locked(conn, -ESTALE);
	}

	if (count != 0) {
		CWARN("Closed %d stale conns to %s\n", count, libcfs_nid2str(peer->gnp_nid));
	}

	RETURN(count);
}

int
kgnilnd_conn_isdup_locked(kgn_peer_t *peer, kgn_conn_t *newconn)
{
	kgn_conn_t       *conn;
	struct list_head *tmp;
	int               loopback;
	ENTRY;

	loopback = peer->gnp_nid == peer->gnp_net->gnn_ni->ni_nid;

	list_for_each(tmp, &peer->gnp_conns) {
		conn = list_entry(tmp, kgn_conn_t, gnc_list);
		CDEBUG(D_NET, "checking conn 0x%p for peer %s"
			" lo %d new %llu existing %llu"
			" new peer %llu existing peer %llu"
			" new dev %p existing dev %p\n",
			conn, libcfs_nid2str(peer->gnp_nid),
			loopback,
			newconn->gnc_peerstamp, conn->gnc_peerstamp,
			newconn->gnc_peer_connstamp, conn->gnc_peer_connstamp,
			newconn->gnc_device, conn->gnc_device);

		/* conn is in the process of closing */
		if (conn->gnc_state != GNILND_CONN_ESTABLISHED)
			continue;

		/* 'newconn' is from an earlier version of 'peer'!!! */
		if (newconn->gnc_peerstamp < conn->gnc_peerstamp)
			RETURN(1);

		/* 'conn' is from an earlier version of 'peer': it will be
		 * removed when we cull stale conns later on... */
		if (newconn->gnc_peerstamp > conn->gnc_peerstamp)
			continue;

		/* Different devices are OK */
		if (conn->gnc_device != newconn->gnc_device)
			continue;

		/* It's me connecting to myself */
		if (loopback &&
		    newconn->gnc_my_connstamp == conn->gnc_peer_connstamp &&
		    newconn->gnc_peer_connstamp == conn->gnc_my_connstamp)
			continue;

		/* 'newconn' is an earlier connection from 'peer'!!! */
		if (newconn->gnc_peer_connstamp < conn->gnc_peer_connstamp)
			RETURN(2);

		/* 'conn' is an earlier connection from 'peer': it will be
		 * removed when we cull stale conns later on... */
		if (newconn->gnc_peer_connstamp > conn->gnc_peer_connstamp)
			continue;

		/* 'newconn' has the SAME connection stamp; 'peer' isn't
		 * playing the game... */
		RETURN(3);
	}

	RETURN(0);
}

int
kgnilnd_create_conn(kgn_conn_t **connp, kgn_device_t *dev)
{
	kgn_conn_t	*conn;
	gni_return_t	rrc;
	int		rc = 0;

	LASSERT (!in_interrupt());
	atomic_inc(&kgnilnd_data.kgn_nconns);

	/* divide by 2 to allow for complete reset and immediate reconnect */
	if (atomic_read(&kgnilnd_data.kgn_nconns) >= GNILND_MAX_CQID/2) {
		CERROR("Too many conn are live: %d > %d\n",
			atomic_read(&kgnilnd_data.kgn_nconns), GNILND_MAX_CQID/2);
		atomic_dec(&kgnilnd_data.kgn_nconns);
		return -E2BIG;
	}

	LIBCFS_ALLOC(conn, sizeof(*conn));
	if (conn == NULL) {
		atomic_dec(&kgnilnd_data.kgn_nconns);
		return -ENOMEM;
	}

	conn->gnc_tx_ref_table =
		kgnilnd_vzalloc(GNILND_MAX_MSG_ID * sizeof(void *));
	if (conn->gnc_tx_ref_table == NULL) {
		CERROR("Can't allocate conn tx_ref_table\n");
		GOTO(failed, rc = -ENOMEM);
	}

	mutex_init(&conn->gnc_smsg_mutex);
	mutex_init(&conn->gnc_rdma_mutex);
	atomic_set(&conn->gnc_refcount, 1);
	atomic_set(&conn->gnc_reaper_noop, 0);
	atomic_set(&conn->gnc_sched_noop, 0);
	atomic_set(&conn->gnc_tx_in_use, 0);
	INIT_LIST_HEAD(&conn->gnc_list);
	INIT_LIST_HEAD(&conn->gnc_hashlist);
	INIT_LIST_HEAD(&conn->gnc_schedlist);
	INIT_LIST_HEAD(&conn->gnc_fmaq);
	INIT_LIST_HEAD(&conn->gnc_mdd_list);
	INIT_LIST_HEAD(&conn->gnc_delaylist);
	spin_lock_init(&conn->gnc_list_lock);
	spin_lock_init(&conn->gnc_tx_lock);
	conn->gnc_magic = GNILND_CONN_MAGIC;

	/* set tx id to nearly the end to make sure we find wrapping
	 * issues soon */
	conn->gnc_next_tx = (int) GNILND_MAX_MSG_ID - 10;

	/* if this fails, we have conflicts and MAX_TX is too large */
	CLASSERT(GNILND_MAX_MSG_ID < GNILND_MSGID_CLOSE);

	/* get a new unique CQ id for this conn */
	write_lock(&kgnilnd_data.kgn_peer_conn_lock);
	conn->gnc_my_connstamp = kgnilnd_data.kgn_connstamp++;
	conn->gnc_cqid = kgnilnd_get_cqid_locked();
	write_unlock(&kgnilnd_data.kgn_peer_conn_lock);

	if (conn->gnc_cqid == 0) {
		CERROR("Could not allocate unique CQ ID for conn 0x%p\n", conn);
		GOTO(failed, rc = -E2BIG);
	}

	CDEBUG(D_NET, "alloc cqid %u for conn 0x%p\n",
		conn->gnc_cqid, conn);

	/* need to be set before gnc_ephandle to allow kgnilnd_destroy_conn_ep to
	 * check context */
	conn->gnc_device = dev;

	conn->gnc_timeout = MAX(*kgnilnd_tunables.kgn_timeout,
				GNILND_MIN_TIMEOUT);
	kgnilnd_update_reaper_timeout(conn->gnc_timeout);

	/* this is the ep_handle for doing SMSG & BTE */
	mutex_lock(&dev->gnd_cq_mutex);
	rrc = kgnilnd_ep_create(dev->gnd_handle, dev->gnd_snd_fma_cqh,
				&conn->gnc_ephandle);
	mutex_unlock(&dev->gnd_cq_mutex);
	if (rrc != GNI_RC_SUCCESS)
		GOTO(failed, rc = -ENETDOWN);

	CDEBUG(D_NET, "created conn 0x%p ep_hndl 0x%p\n",
	       conn, conn->gnc_ephandle);

	/* add ref for EP canceling */
	kgnilnd_conn_addref(conn);
	atomic_inc(&dev->gnd_neps);

	*connp = conn;
	return 0;

failed:
	atomic_dec(&kgnilnd_data.kgn_nconns);
	kgnilnd_vfree(conn->gnc_tx_ref_table,
		      GNILND_MAX_MSG_ID * sizeof(void *));
	LIBCFS_FREE(conn, sizeof(*conn));
	return rc;
}

/* needs to be called with kgn_peer_conn_lock held (read or write) */
kgn_conn_t *
kgnilnd_find_conn_locked(kgn_peer_t *peer)
{
	kgn_conn_t      *conn = NULL;

	/* if we are in reset, this conn is going to die soon */
	if (unlikely(kgnilnd_data.kgn_in_reset)) {
		RETURN(NULL);
	}

	/* just return the first ESTABLISHED connection */
	list_for_each_entry(conn, &peer->gnp_conns, gnc_list) {
		/* kgnilnd_finish_connect doesn't put connections on the
		 * peer list until they are actually established */
		LASSERTF(conn->gnc_state >= GNILND_CONN_ESTABLISHED,
			"found conn %p state %s on peer %p (%s)\n",
			conn, kgnilnd_conn_state2str(conn), peer,
			libcfs_nid2str(peer->gnp_nid));
		if (conn->gnc_state != GNILND_CONN_ESTABLISHED)
			continue;

		RETURN(conn);
	}
	RETURN(NULL);
}

/* needs write_lock on kgn_peer_conn_lock held */
kgn_conn_t *
kgnilnd_find_or_create_conn_locked(kgn_peer_t *peer) {

	kgn_device_t    *dev = peer->gnp_net->gnn_dev;
	kgn_conn_t      *conn;

	conn = kgnilnd_find_conn_locked(peer);

	if (conn != NULL) {
		return conn;
	}

	/* if the peer was previously connecting, check if we should
	 * trigger another connection attempt yet. */
	if (time_before(jiffies, peer->gnp_reconnect_time)) {
		return NULL;
	}

	/* This check prevents us from creating a new connection to a peer while we are
	 * still in the process of closing an existing connection to the peer.
	 */
	list_for_each_entry(conn, &peer->gnp_conns, gnc_list) {
		if (conn->gnc_ephandle != NULL) {
			CDEBUG(D_NET, "Not connecting non-null ephandle found peer 0x%p->%s\n", peer,
				libcfs_nid2str(peer->gnp_nid));
			return NULL;
		}
	}

	if (peer->gnp_connecting != GNILND_PEER_IDLE) {
		/* if we are not connecting, fire up a new connection */
		/* or if we are anything but IDLE DONT start a new connection */
	       return NULL;
	}

	CDEBUG(D_NET, "starting connect to %s\n",
		libcfs_nid2str(peer->gnp_nid));
	peer->gnp_connecting = GNILND_PEER_CONNECT;
	kgnilnd_peer_addref(peer); /* extra ref for connd */

	spin_lock(&dev->gnd_connd_lock);
	list_add_tail(&peer->gnp_connd_list, &dev->gnd_connd_peers);
	spin_unlock(&dev->gnd_connd_lock);

	kgnilnd_schedule_dgram(dev);
	CDEBUG(D_NETTRACE, "scheduling new connect\n");

	return NULL;
}

/* Caller is responsible for deciding if/when to call this */
void
kgnilnd_destroy_conn_ep(kgn_conn_t *conn)
{
	gni_return_t    rrc;
	gni_ep_handle_t tmp_ep;

	/* only if we actually initialized it,
	 *  then set NULL to tell kgnilnd_destroy_conn to leave it alone */

	tmp_ep = xchg(&conn->gnc_ephandle, NULL);
	if (tmp_ep != NULL) {
		/* we never re-use the EP, so unbind is not needed */
		mutex_lock(&conn->gnc_device->gnd_cq_mutex);
		rrc = kgnilnd_ep_destroy(tmp_ep);

		mutex_unlock(&conn->gnc_device->gnd_cq_mutex);

		/* if this fails, it could hork up kgni smsg retransmit and others
		 * since we could free the SMSG mbox memory, etc. */
		LASSERTF(rrc == GNI_RC_SUCCESS, "rrc %d conn 0x%p ep 0x%p\n",
			 rrc, conn, conn->gnc_ephandle);

		atomic_dec(&conn->gnc_device->gnd_neps);

		/* clear out count added in kgnilnd_close_conn_locked
		 * conn will have a peer once it hits finish_connect, where it
		 * is the first spot we'll mark it ESTABLISHED as well */
		if (conn->gnc_peer) {
			kgnilnd_admin_decref(conn->gnc_peer->gnp_dirty_eps);
		}

		/* drop ref for EP */
		kgnilnd_conn_decref(conn);
	}
}

void
kgnilnd_destroy_conn(kgn_conn_t *conn)
{
	LASSERTF(!in_interrupt() &&
		!conn->gnc_scheduled &&
		!conn->gnc_in_purgatory &&
		conn->gnc_ephandle == NULL &&
		list_empty(&conn->gnc_list) &&
		list_empty(&conn->gnc_hashlist) &&
		list_empty(&conn->gnc_schedlist) &&
		list_empty(&conn->gnc_mdd_list) &&
		list_empty(&conn->gnc_delaylist) &&
		conn->gnc_magic == GNILND_CONN_MAGIC,
		"conn 0x%p->%s IRQ %d sched %d purg %d ep 0x%p Mg %d lists %d/%d/%d/%d/%d\n",
		conn, conn->gnc_peer ? libcfs_nid2str(conn->gnc_peer->gnp_nid)
				     : "<?>",
		!!in_interrupt(), conn->gnc_scheduled,
		conn->gnc_in_purgatory,
		conn->gnc_ephandle,
		conn->gnc_magic,
		list_empty(&conn->gnc_list),
		list_empty(&conn->gnc_hashlist),
		list_empty(&conn->gnc_schedlist),
		list_empty(&conn->gnc_mdd_list),
		list_empty(&conn->gnc_delaylist));

	/* Tripping these is especially bad, as it means we have items on the
	 *  lists that didn't keep their refcount on the connection - or
	 *  somebody evil released their own */
	LASSERTF(list_empty(&conn->gnc_fmaq) &&
		 atomic_read(&conn->gnc_nlive_fma) == 0 &&
		 atomic_read(&conn->gnc_nlive_rdma) == 0,
		 "conn 0x%p fmaq %d@0x%p nfma %d nrdma %d\n",
		 conn, kgnilnd_count_list(&conn->gnc_fmaq), &conn->gnc_fmaq,
		 atomic_read(&conn->gnc_nlive_fma), atomic_read(&conn->gnc_nlive_rdma));

	CDEBUG(D_NET, "destroying conn %p ephandle %p error %d\n",
		conn, conn->gnc_ephandle, conn->gnc_error);

	/* We are freeing this memory remove the magic value from the connection */
	conn->gnc_magic = 0;

	/* if there is an FMA blk left here, we'll tear it down */
	if (conn->gnc_fma_blk) {
		if (conn->gnc_peer) {
			kgn_mbox_info_t *mbox;
			mbox = &conn->gnc_fma_blk->gnm_mbox_info[conn->gnc_mbox_id];
			mbox->mbx_prev_nid = conn->gnc_peer->gnp_nid;
		}
		kgnilnd_release_mbox(conn, 0);
	}

	if (conn->gnc_peer != NULL)
		kgnilnd_peer_decref(conn->gnc_peer);

	if (conn->gnc_tx_ref_table != NULL) {
		kgnilnd_vfree(conn->gnc_tx_ref_table,
			      GNILND_MAX_MSG_ID * sizeof(void *));
	}

	LIBCFS_FREE(conn, sizeof(*conn));
	atomic_dec(&kgnilnd_data.kgn_nconns);
}

/* peer_alive and peer_notify done in the style of the o2iblnd */
void
kgnilnd_peer_alive(kgn_peer_t *peer)
{
	time64_t now = ktime_get_seconds();

	set_mb(peer->gnp_last_alive, now);
}

void
kgnilnd_peer_notify(kgn_peer_t *peer, int error, int alive)
{
	int                     tell_lnet = 0;
	int                     nnets = 0;
	int                     rc;
	int                     i, j;
	kgn_conn_t             *conn;
	kgn_net_t             **nets;
	kgn_net_t              *net;


	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_DONT_NOTIFY))
		return;

	/* Tell LNet we are giving ups on this peer - but only
	 * if it isn't already reconnected or trying to reconnect */
	read_lock(&kgnilnd_data.kgn_peer_conn_lock);

	/* use kgnilnd_find_conn_locked to avoid any conns in the process of being nuked
	 *
	 * don't tell LNet if we are in reset - we assume that everyone will be able to
	 * reconnect just fine
	 */
	conn = kgnilnd_find_conn_locked(peer);

	CDEBUG(D_NETTRACE, "peer 0x%p->%s ting %d conn 0x%p, rst %d error %d\n",
	       peer, libcfs_nid2str(peer->gnp_nid), peer->gnp_connecting, conn,
	       kgnilnd_data.kgn_in_reset, error);

	if (((peer->gnp_connecting == GNILND_PEER_IDLE) &&
	    (conn == NULL) &&
	    (!kgnilnd_data.kgn_in_reset) &&
	    (!kgnilnd_conn_clean_errno(error))) || alive) {
		tell_lnet = 1;
	}

	read_unlock(&kgnilnd_data.kgn_peer_conn_lock);

	if (!tell_lnet) {
		/* short circuit if we dont need to notify Lnet */
		return;
	}

	rc = down_read_trylock(&kgnilnd_data.kgn_net_rw_sem);

	if (rc) {
	    /* dont do this if this fails since LNET is in shutdown or something else
	     */

		for (i = 0; i < *kgnilnd_tunables.kgn_net_hash_size; i++) {
			list_for_each_entry(net , &kgnilnd_data.kgn_nets[i], gnn_list) {
				/* if gnn_shutdown set for any net shutdown is in progress just return */
				if (net->gnn_shutdown) {
					up_read(&kgnilnd_data.kgn_net_rw_sem);
					return;
				}
				nnets++;
			}
		}

		if (nnets == 0) {
			/* shutdown in progress most likely */
			up_read(&kgnilnd_data.kgn_net_rw_sem);
			return;
		}

		LIBCFS_ALLOC(nets, nnets * sizeof(*nets));

		if (nets == NULL) {
			up_read(&kgnilnd_data.kgn_net_rw_sem);
			CERROR("Failed to allocate nets[%d]\n", nnets);
			return;
		}

		j = 0;
		for (i = 0; i < *kgnilnd_tunables.kgn_net_hash_size; i++) {
			list_for_each_entry(net, &kgnilnd_data.kgn_nets[i], gnn_list) {
				nets[j] = net;
				kgnilnd_net_addref(net);
				j++;
			}
		}
		up_read(&kgnilnd_data.kgn_net_rw_sem);

		for (i = 0; i < nnets; i++) {
			lnet_nid_t peer_nid;

			net = nets[i];

			peer_nid = kgnilnd_lnd2lnetnid(net->gnn_ni->ni_nid,
								 peer->gnp_nid);

			CDEBUG(D_NET, "peer 0x%p->%s last_alive %lld (%llds ago)\n",
				peer, libcfs_nid2str(peer_nid), peer->gnp_last_alive,
				ktime_get_seconds() - peer->gnp_last_alive);

			lnet_notify(net->gnn_ni, peer_nid, alive,
				    peer->gnp_last_alive);

			kgnilnd_net_decref(net);
		}

		LIBCFS_FREE(nets, nnets * sizeof(*nets));
	}
}

/* need write_lock on kgn_peer_conn_lock */
void
kgnilnd_close_conn_locked(kgn_conn_t *conn, int error)
{
	kgn_peer_t        *peer = conn->gnc_peer;
	ENTRY;

	LASSERT(!in_interrupt());

	/* store error for tx completion */
	conn->gnc_error = error;
	peer->gnp_last_errno = error;

	/* use real error from peer if possible */
	if (error == -ECONNRESET) {
		error = conn->gnc_peer_error;
	}

	/* if we NETERROR, make sure it is rate limited */
	if (!kgnilnd_conn_clean_errno(error) &&
	    peer->gnp_state != GNILND_PEER_DOWN) {
		CNETERR("closing conn to %s: error %d\n",
		       libcfs_nid2str(peer->gnp_nid), error);
	} else {
		CDEBUG(D_NET, "closing conn to %s: error %d\n",
		       libcfs_nid2str(peer->gnp_nid), error);
	}

	LASSERTF(conn->gnc_state == GNILND_CONN_ESTABLISHED,
		"conn %p to %s with bogus state %s\n", conn,
		libcfs_nid2str(conn->gnc_peer->gnp_nid),
		kgnilnd_conn_state2str(conn));
	LASSERT(!list_empty(&conn->gnc_hashlist));
	LASSERT(!list_empty(&conn->gnc_list));


	/* mark peer count here so any place the EP gets destroyed will
	 * open up the peer count so that a new ESTABLISHED conn is then free
	 * to send new messages -- sending before the previous EPs are destroyed
	 * could end up with messages on the network for the old conn _after_
	 * the new conn and break the mbox safety protocol */
	kgnilnd_admin_addref(conn->gnc_peer->gnp_dirty_eps);

	/* Remove from conn hash table: no new callbacks */
	list_del_init(&conn->gnc_hashlist);
	kgnilnd_data.kgn_conn_version++;
	kgnilnd_conn_decref(conn);

	/* if we are in reset, go right to CLOSED as there is no scheduler
	 * thread to move from CLOSING to CLOSED */
	if (unlikely(kgnilnd_data.kgn_in_reset)) {
		conn->gnc_state = GNILND_CONN_CLOSED;
	} else {
		conn->gnc_state = GNILND_CONN_CLOSING;
	}

	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_RDMA_CQ_ERROR)) {
		msleep_interruptible(MSEC_PER_SEC);
	}

	/* leave on peer->gnp_conns to make sure we don't let the reaper
	 * or others try to unlink this peer until the conn is fully
	 * processed for closing */

	if (kgnilnd_check_purgatory_conn(conn)) {
		kgnilnd_add_purgatory_locked(conn, conn->gnc_peer);
	}

	/* Reset RX timeout to ensure we wait for an incoming CLOSE
	 * for the full timeout.  If we get a CLOSE we know the
	 * peer has stopped all RDMA.  Otherwise if we wait for
	 * the full timeout we can also be sure all RDMA has stopped. */
	conn->gnc_last_rx = conn->gnc_last_rx_cq = jiffies;
	mb();

	/* schedule sending CLOSE - if we are in quiesce, this adds to
	 * gnd_ready_conns and allows us to find it in quiesce processing */
	kgnilnd_schedule_conn(conn);

	EXIT;
}

void
kgnilnd_close_conn(kgn_conn_t *conn, int error)
{
	write_lock(&kgnilnd_data.kgn_peer_conn_lock);
	/* need to check the state here - this call is racy and we don't
	 * know the state until after the lock is grabbed */
	if (conn->gnc_state == GNILND_CONN_ESTABLISHED) {
		kgnilnd_close_conn_locked(conn, error);
	}
	write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
}

void
kgnilnd_complete_closed_conn(kgn_conn_t *conn)
{
	LIST_HEAD		(sinners);
	kgn_tx_t               *tx, *txn;
	int                     nlive = 0;
	int                     nrdma = 0;
	int                     nq_rdma = 0;
	int                     logmsg;
	ENTRY;

	/* Dump log  on cksum error - wait until complete phase to let
	 * RX of error happen */
	if (*kgnilnd_tunables.kgn_checksum_dump &&
	    (conn != NULL && conn->gnc_peer_error == -ENOKEY)) {
		libcfs_debug_dumplog();
	}

	/* _CLOSED set in kgnilnd_process_fmaq once we decide to
	 * send the CLOSE or not */
	LASSERTF(conn->gnc_state == GNILND_CONN_CLOSED,
		 "conn 0x%p->%s with bad state %s\n",
		 conn, conn->gnc_peer ?
			libcfs_nid2str(conn->gnc_peer->gnp_nid) :
			"<?>",
		 kgnilnd_conn_state2str(conn));

	LASSERT(list_empty(&conn->gnc_hashlist));
	/* We shouldnt be on the delay list, the conn can 
	 * get added to this list during a retransmit, and retransmits
	 * only occur within scheduler threads.
	 */
	LASSERT(list_empty(&conn->gnc_delaylist));

	/* we've sent the close, start nuking */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_SCHEDULE_COMPLETE))
		kgnilnd_schedule_conn(conn);

	if (conn->gnc_scheduled != GNILND_CONN_PROCESS) {
		CDEBUG(D_NETERROR, "Error someone scheduled us after we were "
				"done, Attempting to recover conn 0x%p "
				"scheduled %d function: %s line: %d\n", conn,
				conn->gnc_scheduled, conn->gnc_sched_caller,
				conn->gnc_sched_line);
		RETURN_EXIT;
	}

	/* we don't use lists to track things that we can get out of the
	 * tx_ref table... */

	/* need to hold locks for tx_list_state, sampling it is too racy:
	 * - the lock actually protects tx != NULL, but we can't take the proper
	 *   lock until we check tx_list_state, which would be too late and
	 *   we could have the TX change under us.
	 * gnd_rdmaq_lock and gnd_lock and not used together, so taking both
	 * should be fine */
	spin_lock(&conn->gnc_device->gnd_rdmaq_lock);
	spin_lock(&conn->gnc_device->gnd_lock);

	for (nrdma = 0; nrdma < GNILND_MAX_MSG_ID; nrdma++) {
		tx = conn->gnc_tx_ref_table[nrdma];

		if (tx != NULL) {
			/* only print the first error and if not CLOSE, we often don't see
			 * CQ events for that by the time we get here... and really don't care */
			if (nlive || tx->tx_msg.gnm_type == GNILND_MSG_CLOSE)
				tx->tx_state |= GNILND_TX_QUIET_ERROR;
			nlive++;
			GNIDBG_TX(D_NET, tx, "cleaning up on close, nlive %d", nlive);

			/* don't worry about gnc_lock here as nobody else should be
			 * touching this conn */
			kgnilnd_tx_del_state_locked(tx, NULL, conn, GNILND_TX_ALLOCD);
			list_add_tail(&tx->tx_list, &sinners);
		}
	}
	spin_unlock(&conn->gnc_device->gnd_lock);
	spin_unlock(&conn->gnc_device->gnd_rdmaq_lock);

	/* nobody should have marked this as needing scheduling after
	 * we called close - so only ref should be us handling it */
	if (conn->gnc_scheduled != GNILND_CONN_PROCESS) {
		CDEBUG(D_NETERROR, "Error someone scheduled us after we were "
				"done, Attempting to recover conn 0x%p "
				"scheduled %d function %s line: %d\n", conn,
				conn->gnc_scheduled, conn->gnc_sched_caller,
				conn->gnc_sched_line);
	}
	/* now reset a few to actual counters... */
	nrdma = atomic_read(&conn->gnc_nlive_rdma);
	nq_rdma = atomic_read(&conn->gnc_nq_rdma);

	if (!list_empty(&sinners)) {
		list_for_each_entry_safe(tx, txn, &sinners, tx_list) {
			/* clear tx_list to make tx_add_list_locked happy */
			list_del_init(&tx->tx_list);
			/* The error codes determine if we hold onto the MDD */
			kgnilnd_tx_done(tx, conn->gnc_error);
		}
	}

	logmsg = (nlive + nrdma + nq_rdma);

	if (logmsg) {
		int level = conn->gnc_peer->gnp_state == GNILND_PEER_UP ?
				D_NETERROR : D_NET;
		CDEBUG(level, "Closed conn 0x%p->%s (errno %d,"
			" peer errno %d): canceled %d TX, %d/%d RDMA\n",
			conn, libcfs_nid2str(conn->gnc_peer->gnp_nid),
			conn->gnc_error, conn->gnc_peer_error,
			nlive, nq_rdma, nrdma);
	}

	kgnilnd_destroy_conn_ep(conn);

	/* Bug 765042 - race this with completing a new conn to same peer - we need
	 * finish_connect to detach purgatory before we can do it ourselves here */
	CFS_RACE(CFS_FAIL_GNI_FINISH_PURG);

	/* now it is safe to remove from peer list - anyone looking at
	 * gnp_conns now is free to unlink if not on purgatory */
	write_lock(&kgnilnd_data.kgn_peer_conn_lock);

	conn->gnc_state = GNILND_CONN_DONE;

	/* Decrement counter if we are marked by del_conn_or_peers for closing
	 */
	if (conn->gnc_needs_closing)
		kgnilnd_admin_decref(kgnilnd_data.kgn_npending_conns);

	/* Remove from peer's list of valid connections if its not in purgatory */
	if (!conn->gnc_in_purgatory) {
		list_del_init(&conn->gnc_list);
		/* Lose peers reference on the conn */
		kgnilnd_conn_decref(conn);
	}

	/* NB - only unlinking if we set pending in del_peer_locked from admin or
	 * shutdown */
	if (kgnilnd_peer_active(conn->gnc_peer) &&
	    conn->gnc_peer->gnp_pending_unlink &&
	    kgnilnd_can_unlink_peer_locked(conn->gnc_peer)) {
		kgnilnd_unlink_peer_locked(conn->gnc_peer);
	}

	write_unlock(&kgnilnd_data.kgn_peer_conn_lock);

	/* I'm telling Mommy! - use peer_error if they initiated close */
	kgnilnd_peer_notify(conn->gnc_peer,
			    conn->gnc_error == -ECONNRESET ?
			    conn->gnc_peer_error : conn->gnc_error, 0);

	EXIT;
}

int
kgnilnd_set_conn_params(kgn_dgram_t *dgram)
{
	kgn_conn_t             *conn = dgram->gndg_conn;
	kgn_connreq_t          *connreq = &dgram->gndg_conn_in;
	kgn_gniparams_t        *rem_param = &connreq->gncr_gnparams;
	gni_return_t            rrc;
	int                     rc = 0;
	gni_smsg_attr_t        *remote = &connreq->gncr_gnparams.gnpr_smsg_attr;

	/* set timeout vals in conn early so we can use them for the NAK */

	/* use max of the requested and our timeout, peer will do the same */
	conn->gnc_timeout = MAX(conn->gnc_timeout, connreq->gncr_timeout);

	/* only ep_bind really mucks around with the CQ */
	/* only ep bind if we are not connecting to ourself and the dstnid is not a wildcard. this check
	 * is necessary as you can only bind an ep once and we must make sure we dont bind when already bound.
	 */
	if (connreq->gncr_dstnid != LNET_NID_ANY && dgram->gndg_conn_out.gncr_dstnid != connreq->gncr_srcnid) {
		mutex_lock(&conn->gnc_device->gnd_cq_mutex);
		rrc = kgnilnd_ep_bind(conn->gnc_ephandle,
			connreq->gncr_gnparams.gnpr_host_id,
			conn->gnc_cqid);
		mutex_unlock(&conn->gnc_device->gnd_cq_mutex);
		if (rrc != GNI_RC_SUCCESS) {
			rc = -ECONNABORTED;
			goto return_out;
		}
	}

	rrc = kgnilnd_ep_set_eventdata(conn->gnc_ephandle, conn->gnc_cqid,
			 connreq->gncr_gnparams.gnpr_cqid);
	if (rrc != GNI_RC_SUCCESS) {
		rc = -ECONNABORTED;
		goto cleanup_out;
	}

	/* Initialize SMSG */
	rrc = kgnilnd_smsg_init(conn->gnc_ephandle, &conn->gnpr_smsg_attr,
			&connreq->gncr_gnparams.gnpr_smsg_attr);
	if (unlikely(rrc == GNI_RC_INVALID_PARAM)) {
		gni_smsg_attr_t *local = &conn->gnpr_smsg_attr;
		/* help folks figure out if there is a tunable off, etc. */
		LCONSOLE_ERROR("SMSG attribute mismatch. Data from local/remote:"
			       " type %d/%d msg_maxsize %u/%u"
			       " mbox_maxcredit %u/%u. Please check kgni"
			       " logs for further data\n",
			       local->msg_type, remote->msg_type,
			       local->msg_maxsize, remote->msg_maxsize,
			       local->mbox_maxcredit, remote->mbox_maxcredit);
	}
	if (rrc != GNI_RC_SUCCESS) {
		rc = -ECONNABORTED;
		goto cleanup_out;
	}

	/* log this for help in debuggin SMSG buffer re-use */
	CDEBUG(D_NET, "conn %p src %s dst %s smsg %p acquired"
		" local cqid %u SMSG %p->%u hndl %#llx.%#llx"
		" remote cqid %u SMSG %p->%u hndl %#llx.%#llx\n",
		conn, libcfs_nid2str(connreq->gncr_srcnid),
		libcfs_nid2str(connreq->gncr_dstnid),
		&conn->gnpr_smsg_attr,
		conn->gnc_cqid,
		conn->gnpr_smsg_attr.msg_buffer,
		conn->gnpr_smsg_attr.mbox_offset,
		conn->gnpr_smsg_attr.mem_hndl.qword1,
		conn->gnpr_smsg_attr.mem_hndl.qword2,
		rem_param->gnpr_cqid,
		rem_param->gnpr_smsg_attr.msg_buffer,
		rem_param->gnpr_smsg_attr.mbox_offset,
		rem_param->gnpr_smsg_attr.mem_hndl.qword1,
		rem_param->gnpr_smsg_attr.mem_hndl.qword2);

	conn->gnc_peerstamp = connreq->gncr_peerstamp;
	conn->gnc_peer_connstamp = connreq->gncr_connstamp;
	conn->remote_mbox_addr = (void *)((char *)remote->msg_buffer + remote->mbox_offset);

	/* We update the reaper timeout once we have a valid conn and timeout */
	kgnilnd_update_reaper_timeout(GNILND_TO2KA(conn->gnc_timeout));

	return 0;

cleanup_out:
	rrc = kgnilnd_ep_unbind(conn->gnc_ephandle);
	/* not sure I can just let this fly */
	LASSERTF(rrc == GNI_RC_SUCCESS,
		"bad rc from gni_ep_unbind trying to cleanup: %d\n", rrc);

return_out:
	LASSERTF(rc != 0, "SOFTWARE BUG: rc == 0\n");
	CERROR("Error setting connection params from %s: %d\n",
	       libcfs_nid2str(connreq->gncr_srcnid), rc);
	return rc;
}

/* needs down_read on kgn_net_rw_sem held from before this call until
 * after the write_lock on kgn_peer_conn_lock - this ensures we stay sane
 * with kgnilnd_shutdown - it'll get the sem and set shutdown, then get the
 * kgn_peer_conn_lock to start del_peer'ing. If we hold the sem until after
 * kgn_peer_conn_lock is held, we guarantee that nobody calls
 * kgnilnd_add_peer_locked without checking gnn_shutdown */
int
kgnilnd_create_peer_safe(kgn_peer_t **peerp,
			 lnet_nid_t nid,
			 kgn_net_t *net,
			 int node_state)
{
	kgn_peer_t	*peer;
	int		rc;

	LASSERT(nid != LNET_NID_ANY);

	/* We dont pass the net around in the dgram anymore so here is where we find it
	 * this will work unless its in shutdown or the nid has a net that is invalid.
	 * Either way error code needs to be returned in that case.
	 *
	 * If the net passed in is not NULL then we can use it, this alleviates looking it
	 * when the calling function has access to the data.
	 */
	if (net == NULL) {
		rc = kgnilnd_find_net(nid, &net);
		if (rc < 0)
			return rc;
	} else {
		/* find net adds a reference on the net if we are not using
		 * it we must do it manually so the net references are
		 * correct when tearing down the net
		 */
		kgnilnd_net_addref(net);
	}

	LIBCFS_ALLOC(peer, sizeof(*peer));
	if (peer == NULL) {
		kgnilnd_net_decref(net);
		return -ENOMEM;
	}
	peer->gnp_nid = nid;
	peer->gnp_state = node_state;

	/* translate from nid to nic addr & store */
	rc = kgnilnd_nid_to_nicaddrs(LNET_NIDADDR(nid), 1, &peer->gnp_host_id);
	if (rc <= 0) {
		kgnilnd_net_decref(net);
		LIBCFS_FREE(peer, sizeof(*peer));
		return -ESRCH;
	}
	CDEBUG(D_NET, "peer 0x%p->%s -> NIC 0x%x\n", peer,
		libcfs_nid2str(nid), peer->gnp_host_id);

	atomic_set(&peer->gnp_refcount, 1);     /* 1 ref for caller */
	atomic_set(&peer->gnp_dirty_eps, 0);

	INIT_LIST_HEAD(&peer->gnp_list);
	INIT_LIST_HEAD(&peer->gnp_connd_list);
	INIT_LIST_HEAD(&peer->gnp_conns);
	INIT_LIST_HEAD(&peer->gnp_tx_queue);

	/* the first reconnect should happen immediately, so we leave
	 * gnp_reconnect_interval set to 0 */

	LASSERTF(net != NULL, "peer 0x%p->%s with NULL net\n",
		 peer, libcfs_nid2str(nid));

	/* must have kgn_net_rw_sem held for this...  */
	if (net->gnn_shutdown) {
		/* shutdown has started already */
		kgnilnd_net_decref(net);
		LIBCFS_FREE(peer, sizeof(*peer));
		return -ESHUTDOWN;
	}

	peer->gnp_net = net;

	atomic_inc(&kgnilnd_data.kgn_npeers);

	*peerp = peer;
	return 0;
}

void
kgnilnd_destroy_peer(kgn_peer_t *peer)
{
	CDEBUG(D_NET, "peer %s %p deleted\n",
	       libcfs_nid2str(peer->gnp_nid), peer);
	LASSERTF(atomic_read(&peer->gnp_refcount) == 0,
		 "peer 0x%p->%s refs %d\n",
		 peer, libcfs_nid2str(peer->gnp_nid),
		 atomic_read(&peer->gnp_refcount));
	LASSERTF(atomic_read(&peer->gnp_dirty_eps) == 0,
		 "peer 0x%p->%s dirty eps %d\n",
		 peer, libcfs_nid2str(peer->gnp_nid),
		 atomic_read(&peer->gnp_dirty_eps));
	LASSERTF(peer->gnp_net != NULL, "peer %p (%s) with NULL net\n",
		 peer, libcfs_nid2str(peer->gnp_nid));
	LASSERTF(!kgnilnd_peer_active(peer),
		 "peer 0x%p->%s\n",
		peer, libcfs_nid2str(peer->gnp_nid));
	LASSERTF(peer->gnp_connecting == GNILND_PEER_IDLE || peer->gnp_connecting == GNILND_PEER_KILL,
		 "peer 0x%p->%s, connecting %d\n",
		peer, libcfs_nid2str(peer->gnp_nid), peer->gnp_connecting);
	LASSERTF(list_empty(&peer->gnp_conns),
		 "peer 0x%p->%s\n",
		peer, libcfs_nid2str(peer->gnp_nid));
	LASSERTF(list_empty(&peer->gnp_tx_queue),
		 "peer 0x%p->%s\n",
		peer, libcfs_nid2str(peer->gnp_nid));
	LASSERTF(list_empty(&peer->gnp_connd_list),
		 "peer 0x%p->%s\n",
		peer, libcfs_nid2str(peer->gnp_nid));

	/* NB a peer's connections keep a reference on their peer until
	 * they are destroyed, so we can be assured that _all_ state to do
	 * with this peer has been cleaned up when its refcount drops to
	 * zero. */

	atomic_dec(&kgnilnd_data.kgn_npeers);
	kgnilnd_net_decref(peer->gnp_net);

	LIBCFS_FREE(peer, sizeof(*peer));
}

/* the conn might not have made it all the way through to a connected
 * state - but we need to purgatory any conn that a remote peer might
 * have seen through a posted dgram as well */
void
kgnilnd_add_purgatory_locked(kgn_conn_t *conn, kgn_peer_t *peer)
{
	kgn_mbox_info_t *mbox = NULL;
	ENTRY;

	/* NB - the caller should own conn by removing him from the
	 * scheduler thread when finishing the close */

	LASSERTF(peer != NULL, "conn %p with NULL peer\n", conn);

	/* If this is still true, need to add the calls to unlink back in and
	 * figure out how to close the hole on loopback conns */
	LASSERTF(kgnilnd_peer_active(peer), "can't use inactive peer %s (%p)"
		" we'll never recover the resources\n",
		libcfs_nid2str(peer->gnp_nid), peer);

	CDEBUG(D_NET, "conn %p peer %p dev %p\n", conn, peer,
		conn->gnc_device);

	LASSERTF(conn->gnc_in_purgatory == 0,
		"Conn already in purgatory\n");
	conn->gnc_in_purgatory = 1;

	mbox = &conn->gnc_fma_blk->gnm_mbox_info[conn->gnc_mbox_id];
	mbox->mbx_prev_purg_nid = peer->gnp_nid;
	mbox->mbx_add_purgatory = jiffies;
	kgnilnd_release_mbox(conn, 1);

	LASSERTF(list_empty(&conn->gnc_mdd_list),
		"conn 0x%p->%s with active purgatory hold MDD %d\n",
		conn, libcfs_nid2str(peer->gnp_nid),
		kgnilnd_count_list(&conn->gnc_mdd_list));

	EXIT;
}

/* Instead of detaching everything from purgatory here we just mark the conn as needing
 * detach, when the reaper checks the conn the next time it will detach it.
 * Calling function requires write_lock held on kgn_peer_conn_lock
 */
void
kgnilnd_mark_for_detach_purgatory_all_locked(kgn_peer_t *peer) {
	kgn_conn_t       *conn;

	list_for_each_entry(conn, &peer->gnp_conns, gnc_list) {
		if (conn->gnc_in_purgatory && !conn->gnc_needs_detach) {
			conn->gnc_needs_detach = 1;
			kgnilnd_admin_addref(kgnilnd_data.kgn_npending_detach);
		}
	}
}

/* Calling function needs a write_lock held on kgn_peer_conn_lock */
void
kgnilnd_detach_purgatory_locked(kgn_conn_t *conn, struct list_head *conn_list)
{
	kgn_mbox_info_t *mbox = NULL;

	/* if needed, add the conn purgatory data to the list passed in */
	if (conn->gnc_in_purgatory) {
		CDEBUG(D_NET, "peer %p->%s purg_conn %p@%s mdd_list #tx %d\n",
			conn->gnc_peer, libcfs_nid2str(conn->gnc_peer->gnp_nid),
			conn, kgnilnd_conn_state2str(conn),
			kgnilnd_count_list(&conn->gnc_mdd_list));

		mbox = &conn->gnc_fma_blk->gnm_mbox_info[conn->gnc_mbox_id];
		mbox->mbx_detach_of_purgatory = jiffies;

		/* conn->gnc_list is the entry point on peer->gnp_conns, so detaching it
		 * here removes it from the list of 'valid' peer connections.
		 * We put the current conn onto a list of conns to call kgnilnd_release_purgatory_locked()
		 * and as such the caller of kgnilnd_detach_purgatory_locked() now owns that conn, since its not
		 * on the peer's conn_list anymore.
		 */

		list_del_init(&conn->gnc_list);

		/* NB - only unlinking if we set pending in del_peer_locked from admin or
		 * shutdown */
		if (kgnilnd_peer_active(conn->gnc_peer) &&
		    conn->gnc_peer->gnp_pending_unlink &&
		    kgnilnd_can_unlink_peer_locked(conn->gnc_peer)) {
			kgnilnd_unlink_peer_locked(conn->gnc_peer);
		}
		/* The reaper will not call detach unless the conn is fully through kgnilnd_complete_closed_conn.
		 * If the conn is not in a DONE state somehow we are attempting to detach even though
		 * the conn has not been fully cleaned up. If we detach while the conn is still closing
		 * we will end up with an orphaned connection that has valid ep_handle, that is not on a
		 * peer.
		 */

		LASSERTF(conn->gnc_state == GNILND_CONN_DONE, "Conn in invalid state  %p@%s \n",
				conn, kgnilnd_conn_state2str(conn));

		/* move from peer to the delayed release list */
		list_add_tail(&conn->gnc_list, conn_list);
	}
}

void
kgnilnd_release_purgatory_list(struct list_head *conn_list)
{
	kgn_device_t            *dev;
	kgn_conn_t              *conn, *connN;
	kgn_mdd_purgatory_t     *gmp, *gmpN;

	list_for_each_entry_safe(conn, connN, conn_list, gnc_list) {
		dev = conn->gnc_device;

		kgnilnd_release_mbox(conn, -1);
		conn->gnc_in_purgatory = 0;

		list_del_init(&conn->gnc_list);

		/* gnc_needs_detach is set in kgnilnd_del_conn_or_peer. It is used to keep track
		 * of conns that have been marked for detach by kgnilnd_del_conn_or_peer.
		 * The function uses kgn_npending_detach to verify the conn has
		 * actually been detached.
		 */

		if (conn->gnc_needs_detach)
			kgnilnd_admin_decref(kgnilnd_data.kgn_npending_detach);

		/* if this guy is really dead (we are doing release from reaper),
		 * make sure we tell LNet - if this is from other context,
		 * the checks in the function will prevent an errant
		 * notification */
		kgnilnd_peer_notify(conn->gnc_peer, conn->gnc_error, 0);

		list_for_each_entry_safe(gmp, gmpN, &conn->gnc_mdd_list,
					 gmp_list) {
			CDEBUG(D_NET,
			       "dev %p releasing held mdd %#llx.%#llx\n",
			       conn->gnc_device, gmp->gmp_map_key.qword1,
			       gmp->gmp_map_key.qword2);

			atomic_dec(&dev->gnd_n_mdd_held);
			kgnilnd_mem_mdd_release(conn->gnc_device->gnd_handle,
						&gmp->gmp_map_key);
			/* ignoring the return code - if kgni/ghal can't find it
			 * it must be released already */

			list_del_init(&gmp->gmp_list);
			LIBCFS_FREE(gmp, sizeof(*gmp));
		}
		/* lose conn ref for purgatory */
		kgnilnd_conn_decref(conn);
	}
}

/* needs write_lock on kgnilnd_data.kgn_peer_conn_lock held */
void
kgnilnd_peer_increase_reconnect_locked(kgn_peer_t *peer)
{
	int current_to;

	current_to = peer->gnp_reconnect_interval;

	/* we'll try to reconnect fast the first time, then back-off */
	if (current_to == 0) {
		peer->gnp_reconnect_time = jiffies - 1;
		current_to = *kgnilnd_tunables.kgn_min_reconnect_interval;
	} else {
		peer->gnp_reconnect_time = jiffies + cfs_time_seconds(current_to);
		/* add 50% of min timeout & retry */
		current_to += *kgnilnd_tunables.kgn_min_reconnect_interval / 2;
	}

	current_to = MIN(current_to,
				*kgnilnd_tunables.kgn_max_reconnect_interval);

	peer->gnp_reconnect_interval = current_to;
	CDEBUG(D_NET, "peer %s can reconnect at %lu interval %lu\n",
	       libcfs_nid2str(peer->gnp_nid), peer->gnp_reconnect_time,
	       peer->gnp_reconnect_interval);
}

/* needs kgnilnd_data.kgn_peer_conn_lock held */
kgn_peer_t *
kgnilnd_find_peer_locked(lnet_nid_t nid)
{
	struct list_head *peer_list = kgnilnd_nid2peerlist(nid);
	kgn_peer_t       *peer;

	/* Chopping nid down to only NIDADDR using LNET_NIDADDR so we only
	 * have a single peer per device instead of a peer per nid/net combo.
	 */

	list_for_each_entry(peer, peer_list, gnp_list) {
		if (LNET_NIDADDR(nid) != LNET_NIDADDR(peer->gnp_nid))
			continue;

		CDEBUG(D_NET, "got peer [%p] -> %s c %d (%d)\n",
		       peer, libcfs_nid2str(nid),
		       peer->gnp_connecting,
		       atomic_read(&peer->gnp_refcount));
		return peer;
	}
	return NULL;
}

/* need write_lock on kgn_peer_conn_lock */
void
kgnilnd_unlink_peer_locked(kgn_peer_t *peer)
{
	LASSERTF(list_empty(&peer->gnp_conns),
		"peer 0x%p->%s\n",
		 peer, libcfs_nid2str(peer->gnp_nid));
	LASSERTF(list_empty(&peer->gnp_tx_queue),
		"peer 0x%p->%s\n",
		 peer, libcfs_nid2str(peer->gnp_nid));
	LASSERTF(kgnilnd_peer_active(peer),
		"peer 0x%p->%s\n",
		 peer, libcfs_nid2str(peer->gnp_nid));
	CDEBUG(D_NET, "unlinking peer 0x%p->%s\n",
		peer, libcfs_nid2str(peer->gnp_nid));

	list_del_init(&peer->gnp_list);
	kgnilnd_data.kgn_peer_version++;
	kgnilnd_admin_decref(kgnilnd_data.kgn_npending_unlink);
	/* lose peerlist's ref */
	kgnilnd_peer_decref(peer);
}

int
kgnilnd_get_peer_info(int index,
		      kgn_peer_t **found_peer,
		      lnet_nid_t *id, __u32 *nic_addr,
		      int *refcount, int *connecting)
{
	struct list_head  *ptmp;
	kgn_peer_t        *peer;
	int               i;
	int               rc = -ENOENT;

	read_lock(&kgnilnd_data.kgn_peer_conn_lock);

	for (i = 0; i < *kgnilnd_tunables.kgn_peer_hash_size; i++) {

		list_for_each(ptmp, &kgnilnd_data.kgn_peers[i]) {
			peer = list_entry(ptmp, kgn_peer_t, gnp_list);

			if (index-- > 0)
				continue;

			CDEBUG(D_NET, "found peer %p (%s) at index %d\n",
			       peer, libcfs_nid2str(peer->gnp_nid), index);

			*found_peer  = peer;
			*id          = peer->gnp_nid;
			*nic_addr    = peer->gnp_host_id;
			*refcount    = atomic_read(&peer->gnp_refcount);
			*connecting  = peer->gnp_connecting;

			rc = 0;
			goto out;
		}
	}
out:
	read_unlock(&kgnilnd_data.kgn_peer_conn_lock);
	if (rc)
		CDEBUG(D_NET, "no gni peer at index %d\n", index);
	return rc;
}

/* requires write_lock on kgn_peer_conn_lock held */
void
kgnilnd_add_peer_locked(lnet_nid_t nid, kgn_peer_t *new_stub_peer, kgn_peer_t **peerp)
{
	kgn_peer_t        *peer, *peer2;

	LASSERTF(new_stub_peer != NULL, "bad stub peer for nid %s\n",
		 libcfs_nid2str(nid));

	peer2 = kgnilnd_find_peer_locked(nid);
	if (peer2 != NULL) {
		/* A peer was created during the lock transition, so drop
		 * the new one we created */
		kgnilnd_peer_decref(new_stub_peer);
		peer = peer2;
	} else {
		peer = new_stub_peer;
		/* peer table takes existing ref on peer */

		LASSERTF(!kgnilnd_peer_active(peer),
			"peer 0x%p->%s already in peer table\n",
			peer, libcfs_nid2str(peer->gnp_nid));
		list_add_tail(&peer->gnp_list,
			      kgnilnd_nid2peerlist(nid));
		kgnilnd_data.kgn_peer_version++;
	}

	LASSERTF(peer->gnp_net != NULL, "peer 0x%p->%s with NULL net\n",
		 peer, libcfs_nid2str(peer->gnp_nid));
	*peerp = peer;
}

int
kgnilnd_add_peer(kgn_net_t *net, lnet_nid_t nid, kgn_peer_t **peerp)
{
	kgn_peer_t        *peer;
	int                rc;
	int                node_state;
	ENTRY;

	if (nid == LNET_NID_ANY)
		return -EINVAL;

	node_state = kgnilnd_get_node_state(LNET_NIDADDR(nid));

	/* NB - this will not block during normal operations -
	 * the only writer of this is in the startup/shutdown path. */
	rc = down_read_trylock(&kgnilnd_data.kgn_net_rw_sem);
	if (!rc) {
		rc = -ESHUTDOWN;
		RETURN(rc);
	}
	rc = kgnilnd_create_peer_safe(&peer, nid, net, node_state);
	if (rc != 0) {
		up_read(&kgnilnd_data.kgn_net_rw_sem);
		RETURN(rc);
	}

	write_lock(&kgnilnd_data.kgn_peer_conn_lock);
	up_read(&kgnilnd_data.kgn_net_rw_sem);

	kgnilnd_add_peer_locked(nid, peer, peerp);

	CDEBUG(D_NET, "peer 0x%p->%s connecting %d\n",
	       peerp, libcfs_nid2str((*peerp)->gnp_nid),
	       (*peerp)->gnp_connecting);

	write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
	RETURN(0);
}

/* needs write_lock on kgn_peer_conn_lock */
void
kgnilnd_cancel_peer_connect_locked(kgn_peer_t *peer, struct list_head *zombies)
{
	kgn_tx_t        *tx, *txn;

	/* we do care about state of gnp_connecting - we could be between
	 * reconnect attempts, so try to find the dgram and cancel the TX
	 * anyways. If we are in the process of posting DONT do anything;
	 * once it fails or succeeds we can nuke the connect attempt.
	 * We have no idea where in kgnilnd_post_dgram we are so we cant
	 * attempt to cancel until the function is done.
	 */

	/* make sure peer isn't in process of connecting or waiting for connect*/
	spin_lock(&peer->gnp_net->gnn_dev->gnd_connd_lock);
	if (!(list_empty(&peer->gnp_connd_list))) {
		list_del_init(&peer->gnp_connd_list);
		/* remove connd ref */
		kgnilnd_peer_decref(peer);
	}
	spin_unlock(&peer->gnp_net->gnn_dev->gnd_connd_lock);

	if (peer->gnp_connecting == GNILND_PEER_POSTING || peer->gnp_connecting == GNILND_PEER_NEEDS_DEATH) {
		peer->gnp_connecting = GNILND_PEER_NEEDS_DEATH;
		/* We are in process of posting right now the xchg set it up for us to
		 * cancel the connect so we are finished for now */
	} else {
		/* no need for exchange we have the peer lock and its ready for us to nuke */
		LASSERTF(peer->gnp_connecting != GNILND_PEER_POSTING,
			"Peer in invalid state 0x%p->%s, connecting %d\n",
			peer, libcfs_nid2str(peer->gnp_nid), peer->gnp_connecting);
		peer->gnp_connecting = GNILND_PEER_IDLE;
		set_mb(peer->gnp_last_dgram_errno, -ETIMEDOUT);
		kgnilnd_find_and_cancel_dgram(peer->gnp_net->gnn_dev,
						      peer->gnp_nid);
	}

	/* The least we can do is nuke the tx's no matter what.... */
	list_for_each_entry_safe(tx, txn, &peer->gnp_tx_queue, tx_list) {
		kgnilnd_tx_del_state_locked(tx, peer, NULL,
					   GNILND_TX_ALLOCD);
		list_add_tail(&tx->tx_list, zombies);
	}
}

/* needs write_lock on kgn_peer_conn_lock */
void
kgnilnd_del_peer_locked(kgn_peer_t *peer, int error)
{
	/* this peer could be passive and only held for purgatory,
	 * take a ref to ensure it doesn't disappear in this function */
	kgnilnd_peer_addref(peer);

	CFS_RACE(CFS_FAIL_GNI_FIND_TARGET);

	/* if purgatory release cleared it out, don't try again */
	if (kgnilnd_peer_active(peer)) {
		/* always do this to allow kgnilnd_start_connect and
		 * kgnilnd_finish_connect to catch this before they
		 * wrap up their operations */
		if (kgnilnd_can_unlink_peer_locked(peer)) {
			/* already released purgatory, so only active
			 * conns hold it */
			kgnilnd_unlink_peer_locked(peer);
		} else {
			kgnilnd_close_peer_conns_locked(peer, error);
			/* peer unlinks itself when last conn is closed */
		}
	}

	/* we are done, release back to the wild */
	kgnilnd_peer_decref(peer);
}

int
kgnilnd_del_conn_or_peer(kgn_net_t *net, lnet_nid_t nid, int command,
			  int error)
{
	LIST_HEAD		(souls);
	LIST_HEAD		(zombies);
	struct list_head	*ptmp, *pnxt;
	kgn_peer_t		*peer;
	int			lo;
	int			hi;
	int			i;
	int			rc = -ENOENT;

	write_lock(&kgnilnd_data.kgn_peer_conn_lock);

	if (nid != LNET_NID_ANY)
		lo = hi = kgnilnd_nid2peerlist(nid) - kgnilnd_data.kgn_peers;
	else {
		lo = 0;
		hi = *kgnilnd_tunables.kgn_peer_hash_size - 1;
		/* wildcards always succeed */
		rc = 0;
	}

	for (i = lo; i <= hi; i++) {
		list_for_each_safe(ptmp, pnxt, &kgnilnd_data.kgn_peers[i]) {
			peer = list_entry(ptmp, kgn_peer_t, gnp_list);

			LASSERTF(peer->gnp_net != NULL,
				"peer %p (%s) with NULL net\n",
				 peer, libcfs_nid2str(peer->gnp_nid));

			if (net != NULL && peer->gnp_net != net)
				continue;

			if (!(nid == LNET_NID_ANY || LNET_NIDADDR(peer->gnp_nid) == LNET_NIDADDR(nid)))
				continue;

			/* In both cases, we want to stop any in-flight
			 * connect attempts */
			kgnilnd_cancel_peer_connect_locked(peer, &zombies);

			switch (command) {
			case GNILND_DEL_CONN:
				kgnilnd_close_peer_conns_locked(peer, error);
				break;
			case GNILND_DEL_PEER:
				peer->gnp_pending_unlink = 1;
				kgnilnd_admin_addref(kgnilnd_data.kgn_npending_unlink);
				kgnilnd_mark_for_detach_purgatory_all_locked(peer);
				kgnilnd_del_peer_locked(peer, error);
				break;
			case GNILND_CLEAR_PURGATORY:
				/* Mark everything ready for detach reaper will cleanup
				 * once we release the kgn_peer_conn_lock
				 */
				kgnilnd_mark_for_detach_purgatory_all_locked(peer);
				peer->gnp_last_errno = -EISCONN;
				/* clear reconnect so he can reconnect soon */
				peer->gnp_reconnect_time = 0;
				peer->gnp_reconnect_interval = 0;
				break;
			default:
				CERROR("bad command %d\n", command);
				LBUG();
			}
			/* we matched something */
			rc = 0;
		}
	}

	write_unlock(&kgnilnd_data.kgn_peer_conn_lock);

	/* nuke peer TX */
	kgnilnd_txlist_done(&zombies, error);

	/* This function does not return until the commands it initiated have completed,
	 * since they have to work there way through the other threads. In the case of shutdown
	 * threads are not woken up until after this call is initiated so we cannot wait, we just
	 * need to return. The same applies for stack reset we shouldnt wait as the reset thread
	 * handles closing.
	 */

	CFS_RACE(CFS_FAIL_GNI_RACE_RESET);

	if (error == -ENOTRECOVERABLE || error == -ESHUTDOWN) {
		return rc;
	}

	i = 4;
	while (atomic_read(&kgnilnd_data.kgn_npending_conns)   ||
	       atomic_read(&kgnilnd_data.kgn_npending_detach)  ||
	       atomic_read(&kgnilnd_data.kgn_npending_unlink)) {

		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(cfs_time_seconds(1));
		i++;

		CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, "Waiting on %d peers %d closes %d detaches\n",
				atomic_read(&kgnilnd_data.kgn_npending_unlink),
				atomic_read(&kgnilnd_data.kgn_npending_conns),
				atomic_read(&kgnilnd_data.kgn_npending_detach));
	}

	return rc;
}

kgn_conn_t *
kgnilnd_get_conn_by_idx(int index)
{
	kgn_peer_t        *peer;
	struct list_head  *ptmp;
	kgn_conn_t        *conn;
	struct list_head  *ctmp;
	int                i;


	for (i = 0; i < *kgnilnd_tunables.kgn_peer_hash_size; i++) {
		read_lock(&kgnilnd_data.kgn_peer_conn_lock);
		list_for_each(ptmp, &kgnilnd_data.kgn_peers[i]) {

			peer = list_entry(ptmp, kgn_peer_t, gnp_list);

			list_for_each(ctmp, &peer->gnp_conns) {
				conn = list_entry(ctmp, kgn_conn_t, gnc_list);

				if (conn->gnc_state != GNILND_CONN_ESTABLISHED)
					continue;

				if (index-- > 0)
					continue;

				CDEBUG(D_NET, "++conn[%p] -> %s (%d)\n", conn,
				       libcfs_nid2str(conn->gnc_peer->gnp_nid),
				       atomic_read(&conn->gnc_refcount));
				kgnilnd_conn_addref(conn);
				read_unlock(&kgnilnd_data.kgn_peer_conn_lock);
				return conn;
			}
		}
		read_unlock(&kgnilnd_data.kgn_peer_conn_lock);
	}

	return NULL;
}

int
kgnilnd_get_conn_info(kgn_peer_t *peer,
		      int *device_id, __u64 *peerstamp,
		      int *tx_seq, int *rx_seq,
		      int *fmaq_len, int *nfma, int *nrdma)
{
	kgn_conn_t        *conn;
	int               rc = 0;

	read_lock(&kgnilnd_data.kgn_peer_conn_lock);

	conn = kgnilnd_find_conn_locked(peer);
	if (conn == NULL) {
		rc = -ENOENT;
		goto out;
	}

	*device_id = conn->gnc_device->gnd_host_id;
	*peerstamp = conn->gnc_peerstamp;
	*tx_seq = atomic_read(&conn->gnc_tx_seq);
	*rx_seq = atomic_read(&conn->gnc_rx_seq);
	*fmaq_len = kgnilnd_count_list(&conn->gnc_fmaq);
	*nfma = atomic_read(&conn->gnc_nlive_fma);
	*nrdma = atomic_read(&conn->gnc_nlive_rdma);
out:
	read_unlock(&kgnilnd_data.kgn_peer_conn_lock);
	return rc;
}

/* needs write_lock on kgn_peer_conn_lock */
int
kgnilnd_close_peer_conns_locked(kgn_peer_t *peer, int why)
{
	kgn_conn_t         *conn;
	struct list_head   *ctmp, *cnxt;
	int                 count = 0;

	list_for_each_safe(ctmp, cnxt, &peer->gnp_conns) {
		conn = list_entry(ctmp, kgn_conn_t, gnc_list);

		if (conn->gnc_state != GNILND_CONN_ESTABLISHED)
			continue;

		count++;
		/* we mark gnc_needs closing and increment kgn_npending_conns so that
		 * kgnilnd_del_conn_or_peer can wait on the other threads closing
		 * and cleaning up the connection.
		 */
		if (!conn->gnc_needs_closing) {
			conn->gnc_needs_closing = 1;
			kgnilnd_admin_addref(kgnilnd_data.kgn_npending_conns);
		}
		kgnilnd_close_conn_locked(conn, why);
	}
	return count;
}

int
kgnilnd_report_node_state(lnet_nid_t nid, int down)
{
	int         rc;
	kgn_peer_t  *peer, *new_peer;
	LIST_HEAD(zombies);

	write_lock(&kgnilnd_data.kgn_peer_conn_lock);
	peer = kgnilnd_find_peer_locked(nid);

	if (peer == NULL) {
		int       i;
		int       found_net = 0;
		kgn_net_t *net;

		write_unlock(&kgnilnd_data.kgn_peer_conn_lock);

		/* Don't add a peer for node up events */
		if (down == GNILND_PEER_UP)
			return 0;

		/* find any valid net - we don't care which one... */
		down_read(&kgnilnd_data.kgn_net_rw_sem);
		for (i = 0; i < *kgnilnd_tunables.kgn_net_hash_size; i++) {
			list_for_each_entry(net, &kgnilnd_data.kgn_nets[i],
					    gnn_list) {
				found_net = 1;
				break;
			}

			if (found_net) {
				break;
			}
		}
		up_read(&kgnilnd_data.kgn_net_rw_sem);

		if (!found_net) {
			CNETERR("Could not find a net for nid %lld\n", nid);
			return 1;
		}

		/* The nid passed in does not yet contain the net portion.
		 * Let's build it up now
		 */
		nid = LNET_MKNID(LNET_NIDNET(net->gnn_ni->ni_nid), nid);
		rc = kgnilnd_add_peer(net, nid, &new_peer);

		if (rc) {
			CNETERR("Could not add peer for nid %lld, rc %d\n",
				nid, rc);
			return 1;
		}

		write_lock(&kgnilnd_data.kgn_peer_conn_lock);
		peer = kgnilnd_find_peer_locked(nid);

		if (peer == NULL) {
			CNETERR("Could not find peer for nid %lld\n", nid);
			write_unlock(&kgnilnd_data.kgn_peer_conn_lock);
			return 1;
		}
	}

	peer->gnp_state = down;

	if (down == GNILND_PEER_DOWN) {
		kgn_conn_t *conn;

		peer->gnp_down_event_time = jiffies;
		kgnilnd_cancel_peer_connect_locked(peer, &zombies);
		conn = kgnilnd_find_conn_locked(peer);

		if (conn != NULL) {
			kgnilnd_close_conn_locked(conn, -ENETRESET);
		}
	} else {
		peer->gnp_up_event_time = jiffies;
	}

	write_unlock(&kgnilnd_data.kgn_peer_conn_lock);

	if (down == GNILND_PEER_DOWN) {
		/* using ENETRESET so we don't get messages from
		 * kgnilnd_tx_done
		 */
		kgnilnd_txlist_done(&zombies, -ENETRESET);
		kgnilnd_peer_notify(peer, -ECONNRESET, 0);
		LCONSOLE_INFO("Received down event for nid %d\n",
			      LNET_NIDADDR(nid));
	}

	return 0;
}

int
kgnilnd_ctl(struct lnet_ni *ni, unsigned int cmd, void *arg)
{
	struct libcfs_ioctl_data *data = arg;
	kgn_net_t                *net = ni->ni_data;
	int                       rc = -EINVAL;

	LASSERT(ni == net->gnn_ni);

	switch (cmd) {
	case IOC_LIBCFS_GET_PEER: {
		lnet_nid_t   nid = 0;
		kgn_peer_t  *peer = NULL;
		__u32 nic_addr = 0;
		__u64 peerstamp = 0;
		int peer_refcount = 0, peer_connecting = 0;
		int device_id = 0;
		int tx_seq = 0, rx_seq = 0;
		int fmaq_len = 0, nfma = 0, nrdma = 0;

		rc = kgnilnd_get_peer_info(data->ioc_count, &peer,
					   &nid, &nic_addr, &peer_refcount,
					   &peer_connecting);
		if (rc)
			break;

		/* Barf */
		/* LNET_MKNID is used to mask from lnet the multiplexing/demultiplexing of connections and peers
		 * LNET assumes a conn and peer per net, the LNET_MKNID/LNET_NIDADDR allows us to let Lnet see what it
		 * wants to see instead of the underlying network that is being used to send the data
		 */
		data->ioc_nid    = LNET_MKNID(LNET_NIDNET(ni->ni_nid), LNET_NIDADDR(nid));
		data->ioc_flags  = peer_connecting;
		data->ioc_count  = peer_refcount;

		rc = kgnilnd_get_conn_info(peer, &device_id, &peerstamp,
					   &tx_seq, &rx_seq, &fmaq_len,
					   &nfma, &nrdma);

		/* This is allowable - a persistent peer could not
		 * have a connection */
		if (rc) {
			/* flag to indicate we are not connected -
			 * need to print as such */
			data->ioc_flags |= (1<<16);
			rc = 0;
		} else {
			/* still barf */
			data->ioc_net = device_id;
			data->ioc_u64[0] = peerstamp;
			data->ioc_u32[0] = fmaq_len;
			data->ioc_u32[1] = nfma;
			data->ioc_u32[2] = tx_seq;
			data->ioc_u32[3] = rx_seq;
			data->ioc_u32[4] = nrdma;
		}
		break;
	}
	case IOC_LIBCFS_ADD_PEER: {
		/* just dummy value to allow using common interface */
		kgn_peer_t      *peer;
		rc = kgnilnd_add_peer(net, data->ioc_nid, &peer);
		break;
	}
	case IOC_LIBCFS_DEL_PEER: {
		/* NULL is passed in so it affects all peers in existence without regard to network
		 * as the peer may not exist on the network LNET believes it to be on.
		 */
		rc = kgnilnd_del_conn_or_peer(NULL, data->ioc_nid,
					      GNILND_DEL_PEER, -EUCLEAN);
		break;
	}
	case IOC_LIBCFS_GET_CONN: {
		kgn_conn_t *conn = kgnilnd_get_conn_by_idx(data->ioc_count);

		if (conn == NULL)
			rc = -ENOENT;
		else {
			rc = 0;
			/* LNET_MKNID is used to build the correct address based on what LNET wants to see instead of
			 * the generic connection that is used to send the data
			 */
			data->ioc_nid    = LNET_MKNID(LNET_NIDNET(ni->ni_nid), LNET_NIDADDR(conn->gnc_peer->gnp_nid));
			data->ioc_u32[0] = conn->gnc_device->gnd_id;
			kgnilnd_conn_decref(conn);
		}
		break;
	}
	case IOC_LIBCFS_CLOSE_CONNECTION: {
		/* use error = -ENETRESET to indicate it was lctl disconnect */
		/* NULL is passed in so it affects all the nets as the connection is virtual
		 * and may not exist on the network LNET believes it to be on.
		 */
		rc = kgnilnd_del_conn_or_peer(NULL, data->ioc_nid,
					      GNILND_DEL_CONN, -ENETRESET);
		break;
	}
	case IOC_LIBCFS_PUSH_CONNECTION: {
		/* we use this to flush purgatory */
		rc = kgnilnd_del_conn_or_peer(NULL, data->ioc_nid,
					      GNILND_CLEAR_PURGATORY, -EUCLEAN);
		break;
	}
	case IOC_LIBCFS_REGISTER_MYNID: {
		/* Ignore if this is a noop */
		if (data->ioc_nid == ni->ni_nid) {
			rc = 0;
		} else {
			CERROR("obsolete IOC_LIBCFS_REGISTER_MYNID: %s(%s)\n",
			       libcfs_nid2str(data->ioc_nid),
			       libcfs_nid2str(ni->ni_nid));
			rc = -EINVAL;
		}
		break;
	}
	}

	return rc;
}

void
kgnilnd_query(struct lnet_ni *ni, lnet_nid_t nid, time64_t *when)
{
	kgn_net_t               *net = ni->ni_data;
	kgn_tx_t                *tx;
	kgn_peer_t              *peer = NULL;
	kgn_conn_t              *conn = NULL;
	struct lnet_process_id       id = {
		.nid = nid,
		.pid = LNET_PID_LUSTRE,
	};
	ENTRY;

	/* I expect to find him, so only take a read lock */
	read_lock(&kgnilnd_data.kgn_peer_conn_lock);
	peer = kgnilnd_find_peer_locked(nid);
	if (peer != NULL) {
		/* LIE if in a quiesce - we will update the timeouts after,
		 * but we don't want sends failing during it */
		if (kgnilnd_data.kgn_quiesce_trigger) {
			*when = ktime_get_seconds();
			read_unlock(&kgnilnd_data.kgn_peer_conn_lock);
			GOTO(out, 0);
		}

		/* Update to best guess, might refine on later checks */
		*when = peer->gnp_last_alive;

		/* we have a peer, how about a conn? */
		conn = kgnilnd_find_conn_locked(peer);

		if (conn == NULL)  {
			/* if there is no conn, check peer last errno to see if clean disconnect
			 * - if it was, we lie to LNet because we believe a TX would complete
			 * on reconnect */
			if (kgnilnd_conn_clean_errno(peer->gnp_last_errno)) {
				*when = ktime_get_seconds();
			}
			/* we still want to fire a TX and new conn in this case */
		} else {
			/* gnp_last_alive is valid, run for the hills */
			read_unlock(&kgnilnd_data.kgn_peer_conn_lock);
			GOTO(out, 0);
		}
	}
	/* if we get here, either we have no peer or no conn for him, so fire off
	 * new TX to trigger conn setup */
	read_unlock(&kgnilnd_data.kgn_peer_conn_lock);

	/* if we couldn't find him, we'll fire up a TX and get connected -
	 * if we don't do this, after ni_peer_timeout, LNet will declare him dead.
	 * So really we treat kgnilnd_query as a bit of a 'connect now' type
	 * event because it'll only do this when it wants to send
	 *
	 * Use a real TX for this to get the proper gnp_tx_queue behavior, etc
	 * normally we'd use kgnilnd_send_ctlmsg for this, but we don't really
	 * care that this goes out quickly since we already know we need a new conn
	 * formed */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_NOOP_SEND))
		return;

	tx = kgnilnd_new_tx_msg(GNILND_MSG_NOOP, ni->ni_nid);
	if (tx != NULL) {
		kgnilnd_launch_tx(tx, net, &id);
	}
out:
	CDEBUG(D_NETTRACE, "peer 0x%p->%s when %lld\n", peer,
	       libcfs_nid2str(nid), *when);
	EXIT;
}

int
kgnilnd_dev_init(kgn_device_t *dev)
{
	gni_return_t      rrc;
	int               rc = 0;
	unsigned int      cq_size;
	ENTRY;

	/* size of these CQs should be able to accommodate the outgoing
	 * RDMA and SMSG transactions.  Since we really don't know what we
	 * really need here, we'll take credits * 2 * 3 to allow a bunch.
	 * We need to dig into this more with the performance work. */
	cq_size = *kgnilnd_tunables.kgn_credits * 2 * 3;

	rrc = kgnilnd_cdm_create(dev->gnd_id, *kgnilnd_tunables.kgn_ptag,
				 *kgnilnd_tunables.kgn_pkey, 0,
				 &dev->gnd_domain);
	if (rrc != GNI_RC_SUCCESS) {
		CERROR("Can't create CDM %d (%d)\n", dev->gnd_id, rrc);
		GOTO(failed, rc = -ENODEV);
	}

	rrc = kgnilnd_cdm_attach(dev->gnd_domain, dev->gnd_id,
				 &dev->gnd_host_id, &dev->gnd_handle);
	if (rrc != GNI_RC_SUCCESS) {
		CERROR("Can't attach CDM to device %d (%d)\n",
			dev->gnd_id, rrc);
		GOTO(failed, rc = -ENODEV);
	}

	/* a bit gross, but not much we can do - Aries Sim doesn't have
	 * hardcoded NIC/NID that we can use */
	rc = kgnilnd_setup_nic_translation(dev->gnd_host_id);
	if (rc != 0)
		GOTO(failed, rc = -ENODEV);

	/* only dev 0 gets the errors - no need to reset the stack twice
	 * - this works because we have a single PTAG, if we had more
	 * then we'd need to have multiple handlers */
	if (dev->gnd_id == 0) {
		rrc = kgnilnd_subscribe_errors(dev->gnd_handle,
						GNI_ERRMASK_CRITICAL |
						GNI_ERRMASK_UNKNOWN_TRANSACTION,
					      0, NULL, kgnilnd_critical_error,
					      &dev->gnd_err_handle);
		if (rrc != GNI_RC_SUCCESS) {
			CERROR("Can't subscribe for errors on device %d: rc %d\n",
				dev->gnd_id, rrc);
			GOTO(failed, rc = -ENODEV);
		}

		rc = kgnilnd_set_quiesce_callback(dev->gnd_handle,
						  kgnilnd_quiesce_end_callback);
		if (rc != GNI_RC_SUCCESS) {
			CERROR("Can't subscribe for quiesce callback on device %d: rc %d\n",
				dev->gnd_id, rrc);
			GOTO(failed, rc = -ENODEV);
		}
	}

	rc = kgnilnd_nicaddr_to_nid(dev->gnd_host_id, &dev->gnd_nid);
	if (rc < 0) {
		/* log messages during startup */
		if (kgnilnd_data.kgn_init < GNILND_INIT_ALL) {
			CERROR("couldn't translate host_id 0x%x to nid. rc %d\n",
				dev->gnd_host_id, rc);
		}
		GOTO(failed, rc = -ESRCH);
	}
	CDEBUG(D_NET, "NIC %x -> NID %d\n", dev->gnd_host_id, dev->gnd_nid);

	rrc = kgnilnd_cq_create(dev->gnd_handle, *kgnilnd_tunables.kgn_credits,
				0, kgnilnd_device_callback,
				dev->gnd_id, &dev->gnd_snd_rdma_cqh);
	if (rrc != GNI_RC_SUCCESS) {
		CERROR("Can't create rdma send cq size %u for device "
		       "%d (%d)\n", cq_size, dev->gnd_id, rrc);
		GOTO(failed, rc = -EINVAL);
	}

	rrc = kgnilnd_cq_create(dev->gnd_handle, cq_size,
			0, kgnilnd_device_callback, dev->gnd_id,
			&dev->gnd_snd_fma_cqh);
	if (rrc != GNI_RC_SUCCESS) {
		CERROR("Can't create fma send cq size %u for device %d (%d)\n",
		       cq_size, dev->gnd_id, rrc);
		GOTO(failed, rc = -EINVAL);
	}

	/* This one we size differently - overflows are possible and it needs to be
	 * sized based on machine size */
	rrc = kgnilnd_cq_create(dev->gnd_handle,
			*kgnilnd_tunables.kgn_fma_cq_size,
			0, kgnilnd_device_callback, dev->gnd_id,
			&dev->gnd_rcv_fma_cqh);
	if (rrc != GNI_RC_SUCCESS) {
		CERROR("Can't create fma cq size %d for device %d (%d)\n",
		       *kgnilnd_tunables.kgn_fma_cq_size, dev->gnd_id, rrc);
		GOTO(failed, rc = -EINVAL);
	}

	rrc = kgnilnd_register_smdd_buf(dev);
	if (rrc != GNI_RC_SUCCESS) {
		GOTO(failed, rc = -EINVAL);
	}

	RETURN(0);

failed:
	kgnilnd_dev_fini(dev);
	RETURN(rc);
}

void
kgnilnd_dev_fini(kgn_device_t *dev)
{
	gni_return_t rrc;
	ENTRY;

	/* At quiesce or rest time, need to loop through and clear gnd_ready_conns ?*/
	LASSERTF(list_empty(&dev->gnd_ready_conns) &&
		 list_empty(&dev->gnd_map_tx) &&
		 list_empty(&dev->gnd_rdmaq) &&
		 list_empty(&dev->gnd_delay_conns),
		 "dev 0x%p ready_conns %d@0x%p delay_conns %d@0x%p" 
		 "map_tx %d@0x%p rdmaq %d@0x%p\n",
		 dev, kgnilnd_count_list(&dev->gnd_ready_conns), &dev->gnd_ready_conns,
		 kgnilnd_count_list(&dev->gnd_delay_conns), &dev->gnd_delay_conns,
		 kgnilnd_count_list(&dev->gnd_map_tx), &dev->gnd_map_tx,
		 kgnilnd_count_list(&dev->gnd_rdmaq), &dev->gnd_rdmaq);

	/* These should follow from tearing down all connections */
	LASSERTF(dev->gnd_map_nphys == 0 && dev->gnd_map_physnop == 0,
		"%d physical mappings of %d pages still mapped\n",
		 dev->gnd_map_nphys, dev->gnd_map_physnop);

	LASSERTF(dev->gnd_map_nvirt == 0 && dev->gnd_map_virtnob == 0,
		"%d virtual mappings of %llu bytes still mapped\n",
		 dev->gnd_map_nvirt, dev->gnd_map_virtnob);

	LASSERTF(atomic_read(&dev->gnd_n_mdd) == 0 &&
		 atomic_read(&dev->gnd_n_mdd_held) == 0 &&
		 atomic64_read(&dev->gnd_nbytes_map) == 0,
		"%d SMSG mappings of %ld bytes still mapped or held %d\n",
		 atomic_read(&dev->gnd_n_mdd),
		 atomic64_read(&dev->gnd_nbytes_map), atomic_read(&dev->gnd_n_mdd_held));

	LASSERT(list_empty(&dev->gnd_map_list));

	/* What other assertions needed to ensure all connections torn down ? */

	/* check all counters == 0 (EP, MDD, etc) */

	/* if we are resetting due to quiese (stack reset), don't check
	 * thread states */
	LASSERTF(kgnilnd_data.kgn_quiesce_trigger ||
		atomic_read(&kgnilnd_data.kgn_nthreads) == 0,
		"tried to shutdown with threads active\n");

	if (dev->gnd_smdd_hold_buf) {
		rrc = kgnilnd_deregister_smdd_buf(dev);
		LASSERTF(rrc == GNI_RC_SUCCESS,
			"bad rc from deregistion of sMDD buffer: %d\n", rrc);
		dev->gnd_smdd_hold_buf = NULL;
	}

	if (dev->gnd_rcv_fma_cqh) {
		rrc = kgnilnd_cq_destroy(dev->gnd_rcv_fma_cqh);
		LASSERTF(rrc == GNI_RC_SUCCESS,
			"bad rc from gni_cq_destroy on rcv_fma_cqh: %d\n", rrc);
		dev->gnd_rcv_fma_cqh = NULL;
	}

	if (dev->gnd_snd_rdma_cqh) {
		rrc = kgnilnd_cq_destroy(dev->gnd_snd_rdma_cqh);
		LASSERTF(rrc == GNI_RC_SUCCESS,
			"bad rc from gni_cq_destroy on send_rdma_cqh: %d\n", rrc);
		dev->gnd_snd_rdma_cqh = NULL;
	}

	if (dev->gnd_snd_fma_cqh) {
		rrc = kgnilnd_cq_destroy(dev->gnd_snd_fma_cqh);
		LASSERTF(rrc == GNI_RC_SUCCESS,
			"bad rc from gni_cq_destroy on snd_fma_cqh: %d\n", rrc);
		dev->gnd_snd_fma_cqh = NULL;
	}

	if (dev->gnd_err_handle) {
		rrc = kgnilnd_release_errors(dev->gnd_err_handle);
		LASSERTF(rrc == GNI_RC_SUCCESS,
			"bad rc from gni_release_errors: %d\n", rrc);
		dev->gnd_err_handle = NULL;
	}

	if (dev->gnd_domain) {
		rrc = kgnilnd_cdm_destroy(dev->gnd_domain);
		LASSERTF(rrc == GNI_RC_SUCCESS,
			"bad rc from gni_cdm_destroy: %d\n", rrc);
		dev->gnd_domain = NULL;
	}

	EXIT;
}

int kgnilnd_base_startup(void)
{
	struct timeval       tv;
	int                  pkmem = atomic_read(&libcfs_kmemory);
	int                  rc;
	int                  i;
	kgn_device_t        *dev;
	struct task_struct  *thrd;

#if defined(CONFIG_CRAY_XT) && !defined(CONFIG_CRAY_COMPUTE)
	/* limit how much memory can be allocated for fma blocks in
	 * instances where many nodes need to reconnects at the same time */
	struct sysinfo si;
	si_meminfo(&si);
	kgnilnd_data.free_pages_limit = si.totalram/4;
#endif

	ENTRY;

	LASSERTF(kgnilnd_data.kgn_init == GNILND_INIT_NOTHING,
		"init %d\n", kgnilnd_data.kgn_init);

	/* zero pointers, flags etc */
	memset(&kgnilnd_data, 0, sizeof(kgnilnd_data));
	kgnilnd_check_kgni_version();

	/* CAVEAT EMPTOR: Every 'Fma' message includes the sender's NID and
	 * a unique (for all time) connstamp so we can uniquely identify
	 * the sender.  The connstamp is an incrementing counter
	 * initialised with seconds + microseconds at startup time.  So we
	 * rely on NOT creating connections more frequently on average than
	 * 1MHz to ensure we don't use old connstamps when we reboot. */
	do_gettimeofday(&tv);
	kgnilnd_data.kgn_connstamp =
		 kgnilnd_data.kgn_peerstamp =
			(((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;

	init_rwsem(&kgnilnd_data.kgn_net_rw_sem);

	for (i = 0; i < GNILND_MAXDEVS; i++) {
		kgn_device_t  *dev = &kgnilnd_data.kgn_devices[i];

		dev->gnd_id = i;
		INIT_LIST_HEAD(&dev->gnd_ready_conns);
		INIT_LIST_HEAD(&dev->gnd_delay_conns);
		INIT_LIST_HEAD(&dev->gnd_map_tx);
		INIT_LIST_HEAD(&dev->gnd_fma_buffs);
		mutex_init(&dev->gnd_cq_mutex);
		mutex_init(&dev->gnd_fmablk_mutex);
		spin_lock_init(&dev->gnd_fmablk_lock);
		init_waitqueue_head(&dev->gnd_waitq);
		init_waitqueue_head(&dev->gnd_dgram_waitq);
		init_waitqueue_head(&dev->gnd_dgping_waitq);
		spin_lock_init(&dev->gnd_lock);
		INIT_LIST_HEAD(&dev->gnd_map_list);
		spin_lock_init(&dev->gnd_map_lock);
		atomic_set(&dev->gnd_nfmablk, 0);
		atomic_set(&dev->gnd_fmablk_vers, 1);
		atomic_set(&dev->gnd_neps, 0);
		atomic_set(&dev->gnd_canceled_dgrams, 0);
		INIT_LIST_HEAD(&dev->gnd_connd_peers);
		spin_lock_init(&dev->gnd_connd_lock);
		spin_lock_init(&dev->gnd_dgram_lock);
		spin_lock_init(&dev->gnd_rdmaq_lock);
		INIT_LIST_HEAD(&dev->gnd_rdmaq);
		init_rwsem(&dev->gnd_conn_sem);

		/* alloc & setup nid based dgram table */
		LIBCFS_ALLOC(dev->gnd_dgrams,
			    sizeof(struct list_head) * *kgnilnd_tunables.kgn_peer_hash_size);

		if (dev->gnd_dgrams == NULL)
			GOTO(failed, rc = -ENOMEM);

		for (i = 0; i < *kgnilnd_tunables.kgn_peer_hash_size; i++) {
			INIT_LIST_HEAD(&dev->gnd_dgrams[i]);
		}
		atomic_set(&dev->gnd_ndgrams, 0);
		atomic_set(&dev->gnd_nwcdgrams, 0);
		/* setup timer for RDMAQ processing */
		setup_timer(&dev->gnd_rdmaq_timer, kgnilnd_schedule_device_timer,
			    (unsigned long)dev);

		/* setup timer for mapping processing */
		setup_timer(&dev->gnd_map_timer, kgnilnd_schedule_device_timer,
			    (unsigned long)dev);

	}

	/* CQID 0 isn't allowed, set to MAX_MSG_ID - 1 to check for conflicts early */
	kgnilnd_data.kgn_next_cqid = GNILND_MAX_MSG_ID - 1;
	kgnilnd_data.kgn_new_min_timeout = *kgnilnd_tunables.kgn_timeout;
	init_waitqueue_head(&kgnilnd_data.kgn_reaper_waitq);
	init_waitqueue_head(&kgnilnd_data.kgn_ruhroh_waitq);
	spin_lock_init(&kgnilnd_data.kgn_reaper_lock);

	mutex_init(&kgnilnd_data.kgn_quiesce_mutex);
	atomic_set(&kgnilnd_data.kgn_nquiesce, 0);
	atomic_set(&kgnilnd_data.kgn_npending_conns, 0);
	atomic_set(&kgnilnd_data.kgn_npending_unlink, 0);
	atomic_set(&kgnilnd_data.kgn_npending_detach, 0);
	atomic_set(&kgnilnd_data.kgn_rev_offset, 0);
	atomic_set(&kgnilnd_data.kgn_rev_length, 0);
	atomic_set(&kgnilnd_data.kgn_rev_copy_buff, 0);

	/* OK to call kgnilnd_api_shutdown() to cleanup now */
	kgnilnd_data.kgn_init = GNILND_INIT_DATA;
	try_module_get(THIS_MODULE);

	rwlock_init(&kgnilnd_data.kgn_peer_conn_lock);

	LIBCFS_ALLOC(kgnilnd_data.kgn_peers,
		    sizeof(struct list_head) * *kgnilnd_tunables.kgn_peer_hash_size);

	if (kgnilnd_data.kgn_peers == NULL)
		GOTO(failed, rc = -ENOMEM);

	for (i = 0; i < *kgnilnd_tunables.kgn_peer_hash_size; i++) {
		INIT_LIST_HEAD(&kgnilnd_data.kgn_peers[i]);
	}

	LIBCFS_ALLOC(kgnilnd_data.kgn_conns,
		    sizeof(struct list_head) * *kgnilnd_tunables.kgn_peer_hash_size);

	if (kgnilnd_data.kgn_conns == NULL)
		GOTO(failed, rc = -ENOMEM);

	for (i = 0; i < *kgnilnd_tunables.kgn_peer_hash_size; i++) {
		INIT_LIST_HEAD(&kgnilnd_data.kgn_conns[i]);
	}

	LIBCFS_ALLOC(kgnilnd_data.kgn_nets,
		    sizeof(struct list_head) * *kgnilnd_tunables.kgn_net_hash_size);

	if (kgnilnd_data.kgn_nets == NULL)
		GOTO(failed, rc = -ENOMEM);

	for (i = 0; i < *kgnilnd_tunables.kgn_net_hash_size; i++) {
		INIT_LIST_HEAD(&kgnilnd_data.kgn_nets[i]);
	}

	kgnilnd_data.kgn_mbox_cache =
		kmem_cache_create("kgn_mbox_block", GNILND_MBOX_SIZE, 0,
				  SLAB_HWCACHE_ALIGN, NULL);
	if (kgnilnd_data.kgn_mbox_cache == NULL) {
		CERROR("Can't create slab for physical mbox blocks\n");
		GOTO(failed, rc = -ENOMEM);
	}

	kgnilnd_data.kgn_rx_cache =
		kmem_cache_create("kgn_rx_t", sizeof(kgn_rx_t), 0, 0, NULL);
	if (kgnilnd_data.kgn_rx_cache == NULL) {
		CERROR("Can't create slab for kgn_rx_t descriptors\n");
		GOTO(failed, rc = -ENOMEM);
	}

	kgnilnd_data.kgn_tx_cache =
		kmem_cache_create("kgn_tx_t", sizeof(kgn_tx_t), 0, 0, NULL);
	if (kgnilnd_data.kgn_tx_cache == NULL) {
		CERROR("Can't create slab for kgn_tx_t\n");
		GOTO(failed, rc = -ENOMEM);
	}

	kgnilnd_data.kgn_tx_phys_cache =
		kmem_cache_create("kgn_tx_phys",
				   LNET_MAX_IOV * sizeof(gni_mem_segment_t),
				   0, 0, NULL);
	if (kgnilnd_data.kgn_tx_phys_cache == NULL) {
		CERROR("Can't create slab for kgn_tx_phys\n");
		GOTO(failed, rc = -ENOMEM);
	}

	kgnilnd_data.kgn_dgram_cache =
		kmem_cache_create("kgn_dgram_t", sizeof(kgn_dgram_t), 0, 0, NULL);
	if (kgnilnd_data.kgn_dgram_cache == NULL) {
		CERROR("Can't create slab for outgoing datagrams\n");
		GOTO(failed, rc = -ENOMEM);
	}

	/* allocate a MAX_IOV array of page pointers for each cpu */
	kgnilnd_data.kgn_cksum_map_pages = kmalloc(num_possible_cpus() * sizeof (struct page *),
						   GFP_KERNEL);
	if (kgnilnd_data.kgn_cksum_map_pages == NULL) {
		CERROR("Can't allocate vmap cksum pages\n");
		GOTO(failed, rc = -ENOMEM);
	}
	kgnilnd_data.kgn_cksum_npages = num_possible_cpus();
	memset(kgnilnd_data.kgn_cksum_map_pages, 0,
		kgnilnd_data.kgn_cksum_npages * sizeof (struct page *));

	for (i = 0; i < kgnilnd_data.kgn_cksum_npages; i++) {
		kgnilnd_data.kgn_cksum_map_pages[i] = kmalloc(LNET_MAX_IOV * sizeof (struct page *),
							      GFP_KERNEL);
		if (kgnilnd_data.kgn_cksum_map_pages[i] == NULL) {
			CERROR("Can't allocate vmap cksum pages for cpu %d\n", i);
			GOTO(failed, rc = -ENOMEM);
		}
	}

	LASSERT(kgnilnd_data.kgn_ndevs == 0);

	/* Use all available GNI devices */
	for (i = 0; i < GNILND_MAXDEVS; i++) {
		dev = &kgnilnd_data.kgn_devices[kgnilnd_data.kgn_ndevs];

		rc = kgnilnd_dev_init(dev);
		if (rc == 0) {
			/* Increment here so base_shutdown cleans it up */
			kgnilnd_data.kgn_ndevs++;

			rc = kgnilnd_allocate_phys_fmablk(dev);
			if (rc)
				GOTO(failed, rc);
		}
	}

	if (kgnilnd_data.kgn_ndevs == 0) {
		CERROR("Can't initialise any GNI devices\n");
		GOTO(failed, rc = -ENODEV);
	}

	rc = kgnilnd_thread_start(kgnilnd_reaper, NULL, "kgnilnd_rpr", 0);
	if (rc != 0) {
		CERROR("Can't spawn gnilnd reaper: %d\n", rc);
		GOTO(failed, rc);
	}

	rc = kgnilnd_start_rca_thread();
	if (rc != 0) {
		CERROR("Can't spawn gnilnd rca: %d\n", rc);
		GOTO(failed, rc);
	}

	/*
	 * Start ruhroh thread.  We can't use kgnilnd_thread_start() because
	 * we don't want this thread included in kgnilnd_data.kgn_nthreads
	 * count.  This thread controls quiesce, so it mustn't
	 * quiesce itself.
	 */
	thrd = kthread_run(kgnilnd_ruhroh_thread, NULL, "%s_%02d", "kgnilnd_rr", 0);
	if (IS_ERR(thrd)) {
		rc = PTR_ERR(thrd);
		CERROR("Can't spawn gnilnd ruhroh thread: %d\n", rc);
		GOTO(failed, rc);
	}

	/* threads will load balance across devs as they are available */
	if (*kgnilnd_tunables.kgn_thread_affinity) {
		rc = kgnilnd_start_sd_threads();
		if (rc != 0)
			GOTO(failed, rc);
	} else {
		for (i = 0; i < *kgnilnd_tunables.kgn_sched_threads; i++) {
			rc = kgnilnd_thread_start(kgnilnd_scheduler,
						  (void *)((long)i),
						  "kgnilnd_sd", i);
			if (rc != 0) {
				CERROR("Can't spawn gnilnd scheduler[%d]: %d\n",
				       i, rc);
				GOTO(failed, rc);
			}
		}
	}

	for (i = 0; i < kgnilnd_data.kgn_ndevs; i++) {
		dev = &kgnilnd_data.kgn_devices[i];
		rc = kgnilnd_thread_start(kgnilnd_dgram_mover, dev,
					  "kgnilnd_dg", dev->gnd_id);
		if (rc != 0) {
			CERROR("Can't spawn gnilnd dgram_mover[%d]: %d\n",
			       dev->gnd_id, rc);
			GOTO(failed, rc);
		}

		rc = kgnilnd_thread_start(kgnilnd_dgram_waitq, dev,
					  "kgnilnd_dgn", dev->gnd_id);
		if (rc != 0) {
			CERROR("Can't spawn gnilnd dgram_waitq[%d]: %d\n",
				dev->gnd_id, rc);
			GOTO(failed, rc);
		}

		rc = kgnilnd_setup_wildcard_dgram(dev);

		if (rc != 0) {
			CERROR("Can't create wildcard dgrams[%d]: %d\n",
				dev->gnd_id, rc);
			GOTO(failed, rc);
		}
	}

	/* flag everything initialised */
	kgnilnd_data.kgn_init = GNILND_INIT_ALL;
	/*****************************************************/

	CDEBUG(D_MALLOC, "initial kmem %d\n", pkmem);
	RETURN(0);

failed:
	kgnilnd_base_shutdown();
	kgnilnd_data.kgn_init = GNILND_INIT_NOTHING;
	RETURN(rc);
}

void
kgnilnd_base_shutdown(void)
{
	int			i, j;
	ENTRY;

	while (CFS_FAIL_TIMEOUT(CFS_FAIL_GNI_PAUSE_SHUTDOWN, 1)) {};

	kgnilnd_data.kgn_wc_kill = 1;

	for (i = 0; i < kgnilnd_data.kgn_ndevs; i++) {
		kgn_device_t *dev = &kgnilnd_data.kgn_devices[i];
		kgnilnd_cancel_wc_dgrams(dev);
		kgnilnd_cancel_dgrams(dev);
		kgnilnd_del_conn_or_peer(NULL, LNET_NID_ANY, GNILND_DEL_PEER, -ESHUTDOWN);
		kgnilnd_wait_for_canceled_dgrams(dev);
	}

	/* We need to verify there are no conns left before we let the threads
	 * shut down otherwise we could clean up the peers but still have
	 * some outstanding conns due to orphaned datagram conns that are
	 * being cleaned up.
	 */
	i = 2;
	while (atomic_read(&kgnilnd_data.kgn_nconns) != 0) {
		i++;

		for(j = 0; j < kgnilnd_data.kgn_ndevs; ++j) {
			kgn_device_t *dev = &kgnilnd_data.kgn_devices[j];
			kgnilnd_schedule_device(dev);
		}

		CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET,
			"Waiting for conns to be cleaned up %d\n",atomic_read(&kgnilnd_data.kgn_nconns));
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(cfs_time_seconds(1));
	}
	/* Peer state all cleaned up BEFORE setting shutdown, so threads don't
	 * have to worry about shutdown races.  NB connections may be created
	 * while there are still active connds, but these will be temporary
	 * since peer creation always fails after the listener has started to
	 * shut down.
	 * all peers should have been cleared out on the nets */
	LASSERTF(atomic_read(&kgnilnd_data.kgn_npeers) == 0,
		"peers left %d\n", atomic_read(&kgnilnd_data.kgn_npeers));

	/* Wait for the ruhroh thread to shut down. */
	kgnilnd_data.kgn_ruhroh_shutdown = 1;
	wake_up(&kgnilnd_data.kgn_ruhroh_waitq);
	i = 2;
	while (kgnilnd_data.kgn_ruhroh_running != 0) {
		i++;
		CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET,
		       "Waiting for ruhroh thread to terminate\n");
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(cfs_time_seconds(1));
	}

       /* Flag threads to terminate */
	kgnilnd_data.kgn_shutdown = 1;

	for (i = 0; i < kgnilnd_data.kgn_ndevs; i++) {
		kgn_device_t *dev = &kgnilnd_data.kgn_devices[i];

		/* should clear all the MDDs */
		kgnilnd_unmap_fma_blocks(dev);

		kgnilnd_schedule_device(dev);
		wake_up_all(&dev->gnd_dgram_waitq);
		wake_up_all(&dev->gnd_dgping_waitq);
		LASSERT(list_empty(&dev->gnd_connd_peers));
	}

	spin_lock(&kgnilnd_data.kgn_reaper_lock);
	wake_up_all(&kgnilnd_data.kgn_reaper_waitq);
	spin_unlock(&kgnilnd_data.kgn_reaper_lock);

	if (atomic_read(&kgnilnd_data.kgn_nthreads))
		kgnilnd_wakeup_rca_thread();

	/* Wait for threads to exit */
	i = 2;
	while (atomic_read(&kgnilnd_data.kgn_nthreads) != 0) {
		i++;
		CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
		       "Waiting for %d threads to terminate\n",
		       atomic_read(&kgnilnd_data.kgn_nthreads));
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(cfs_time_seconds(1));
	}

	LASSERTF(atomic_read(&kgnilnd_data.kgn_npeers) == 0,
		"peers left %d\n", atomic_read(&kgnilnd_data.kgn_npeers));

	if (kgnilnd_data.kgn_peers != NULL) {
		for (i = 0; i < *kgnilnd_tunables.kgn_peer_hash_size; i++)
			LASSERT(list_empty(&kgnilnd_data.kgn_peers[i]));

		LIBCFS_FREE(kgnilnd_data.kgn_peers,
			    sizeof (struct list_head) *
			    *kgnilnd_tunables.kgn_peer_hash_size);
	}

	down_write(&kgnilnd_data.kgn_net_rw_sem);
	if (kgnilnd_data.kgn_nets != NULL) {
		for (i = 0; i < *kgnilnd_tunables.kgn_net_hash_size; i++)
			LASSERT(list_empty(&kgnilnd_data.kgn_nets[i]));

		LIBCFS_FREE(kgnilnd_data.kgn_nets,
			    sizeof (struct list_head) *
			    *kgnilnd_tunables.kgn_net_hash_size);
	}
	up_write(&kgnilnd_data.kgn_net_rw_sem);

	LASSERTF(atomic_read(&kgnilnd_data.kgn_nconns) == 0,
		"conns left %d\n", atomic_read(&kgnilnd_data.kgn_nconns));

	if (kgnilnd_data.kgn_conns != NULL) {
		for (i = 0; i < *kgnilnd_tunables.kgn_peer_hash_size; i++)
			LASSERT(list_empty(&kgnilnd_data.kgn_conns[i]));

		LIBCFS_FREE(kgnilnd_data.kgn_conns,
			    sizeof (struct list_head) *
			    *kgnilnd_tunables.kgn_peer_hash_size);
	}

	for (i = 0; i < kgnilnd_data.kgn_ndevs; i++) {
		kgn_device_t *dev = &kgnilnd_data.kgn_devices[i];
		kgnilnd_dev_fini(dev);

		LASSERTF(atomic_read(&dev->gnd_ndgrams) == 0,
			"dgrams left %d\n", atomic_read(&dev->gnd_ndgrams));

		if (dev->gnd_dgrams != NULL) {
			for (i = 0; i < *kgnilnd_tunables.kgn_peer_hash_size; i++)
				LASSERT(list_empty(&dev->gnd_dgrams[i]));

			LIBCFS_FREE(dev->gnd_dgrams,
				    sizeof (struct list_head) *
				    *kgnilnd_tunables.kgn_peer_hash_size);
		}

		kgnilnd_free_phys_fmablk(dev);
	}

	if (kgnilnd_data.kgn_mbox_cache != NULL)
		kmem_cache_destroy(kgnilnd_data.kgn_mbox_cache);

	if (kgnilnd_data.kgn_rx_cache != NULL)
		kmem_cache_destroy(kgnilnd_data.kgn_rx_cache);

	if (kgnilnd_data.kgn_tx_cache != NULL)
		kmem_cache_destroy(kgnilnd_data.kgn_tx_cache);

	if (kgnilnd_data.kgn_tx_phys_cache != NULL)
		kmem_cache_destroy(kgnilnd_data.kgn_tx_phys_cache);

	if (kgnilnd_data.kgn_dgram_cache != NULL)
		kmem_cache_destroy(kgnilnd_data.kgn_dgram_cache);

	if (kgnilnd_data.kgn_cksum_map_pages != NULL) {
		for (i = 0; i < kgnilnd_data.kgn_cksum_npages; i++) {
			if (kgnilnd_data.kgn_cksum_map_pages[i] != NULL) {
				kfree(kgnilnd_data.kgn_cksum_map_pages[i]);
			}
		}
		kfree(kgnilnd_data.kgn_cksum_map_pages);
	}

	CDEBUG(D_MALLOC, "after NAL cleanup: kmem %d\n",
	       atomic_read(&libcfs_kmemory));

	kgnilnd_data.kgn_init = GNILND_INIT_NOTHING;
	module_put(THIS_MODULE);

	EXIT;
}

int
kgnilnd_startup(struct lnet_ni *ni)
{
	int               rc, devno;
	kgn_net_t        *net;
	ENTRY;

	LASSERTF(ni->ni_net->net_lnd == &the_kgnilnd,
		"bad LND 0x%p != the_kgnilnd @ 0x%p\n",
		ni->ni_net->net_lnd, &the_kgnilnd);

	if (kgnilnd_data.kgn_init == GNILND_INIT_NOTHING) {
		rc = kgnilnd_base_startup();
		if (rc != 0)
			RETURN(rc);
	}

	/* Serialize with shutdown. */
	mutex_lock(&kgnilnd_data.kgn_quiesce_mutex);

	LIBCFS_ALLOC(net, sizeof(*net));
	if (net == NULL) {
		CERROR("could not allocate net for new interface instance\n");
		/* no need to cleanup the CDM... */
		GOTO(failed, rc = -ENOMEM);
	}
	INIT_LIST_HEAD(&net->gnn_list);
	ni->ni_data = net;
	net->gnn_ni = ni;
	if (!ni->ni_net->net_tunables_set) {
		ni->ni_net->net_tunables.lct_max_tx_credits =
			*kgnilnd_tunables.kgn_credits;
		ni->ni_net->net_tunables.lct_peer_tx_credits =
			*kgnilnd_tunables.kgn_peer_credits;
	}

	if (*kgnilnd_tunables.kgn_peer_health) {
		int     fudge;
		int     timeout;
		/* give this a bit of leeway - we don't have a hard timeout
		 * as we only check timeouts periodically - see comment in kgnilnd_reaper */
		fudge = (GNILND_TO2KA(*kgnilnd_tunables.kgn_timeout) / GNILND_REAPER_NCHECKS);
		timeout = *kgnilnd_tunables.kgn_timeout + fudge;

		if (*kgnilnd_tunables.kgn_peer_timeout >= timeout) {
			ni->ni_net->net_tunables.lct_peer_timeout =
				 *kgnilnd_tunables.kgn_peer_timeout;
		} else if (*kgnilnd_tunables.kgn_peer_timeout > -1) {
			LCONSOLE_ERROR("Peer_timeout is set to %d but needs to be >= %d\n",
					*kgnilnd_tunables.kgn_peer_timeout,
					timeout);
			ni->ni_data = NULL;
			LIBCFS_FREE(net, sizeof(*net));
			GOTO(failed, rc = -EINVAL);
		} else
			ni->ni_net->net_tunables.lct_peer_timeout = timeout;

		LCONSOLE_INFO("Enabling LNet peer health for gnilnd, timeout %ds\n",
			      ni->ni_net->net_tunables.lct_peer_timeout);
	}

	atomic_set(&net->gnn_refcount, 1);

	/* if we have multiple devices, spread the nets around */
	net->gnn_netnum = LNET_NETNUM(LNET_NIDNET(ni->ni_nid));

	devno = LNET_NIDNET(ni->ni_nid) % GNILND_MAXDEVS;
	net->gnn_dev = &kgnilnd_data.kgn_devices[devno];

	/* allocate a 'dummy' cdm for datagram use. We can only have a single
	 * datagram between a nid:inst_id and nid2:inst_id. The fake cdm
	 * give us additional inst_id to use, allowing the datagrams to flow
	 * like rivers of honey and beer */

	/* the instance id for the cdm is the NETNUM offset by MAXDEVS -
	 * ensuring we'll have a unique id */


	ni->ni_nid = LNET_MKNID(LNET_NIDNET(ni->ni_nid), net->gnn_dev->gnd_nid);
	CDEBUG(D_NET, "adding net %p nid=%s on dev %d \n",
		net, libcfs_nid2str(ni->ni_nid), net->gnn_dev->gnd_id);
	/* until the gnn_list is set, we need to cleanup ourselves as
	 * kgnilnd_shutdown is just gonna get confused */

	down_write(&kgnilnd_data.kgn_net_rw_sem);
	list_add_tail(&net->gnn_list, kgnilnd_netnum2netlist(net->gnn_netnum));
	up_write(&kgnilnd_data.kgn_net_rw_sem);

	/* we need a separate thread to call probe_wait_by_id until
	 * we get a function callback notifier from kgni */
	mutex_unlock(&kgnilnd_data.kgn_quiesce_mutex);
	RETURN(0);
 failed:
	mutex_unlock(&kgnilnd_data.kgn_quiesce_mutex);
	kgnilnd_shutdown(ni);
	RETURN(rc);
}

void
kgnilnd_shutdown(struct lnet_ni *ni)
{
	kgn_net_t     *net = ni->ni_data;
	int           i;
	int           rc;
	ENTRY;

	CFS_RACE(CFS_FAIL_GNI_SR_DOWN_RACE);

	LASSERTF(kgnilnd_data.kgn_init == GNILND_INIT_ALL,
		"init %d\n", kgnilnd_data.kgn_init);

	/* Serialize with startup. */
	mutex_lock(&kgnilnd_data.kgn_quiesce_mutex);
	CDEBUG(D_MALLOC, "before NAL cleanup: kmem %d\n",
	       atomic_read(&libcfs_kmemory));

	if (net == NULL) {
		CERROR("got NULL net for ni %p\n", ni);
		GOTO(out, rc = -EINVAL);
	}

	LASSERTF(ni == net->gnn_ni,
		"ni %p gnn_ni %p\n", net, net->gnn_ni);

	ni->ni_data = NULL;

	LASSERT(!net->gnn_shutdown);
	LASSERTF(atomic_read(&net->gnn_refcount) != 0,
		"net %p refcount %d\n",
		 net, atomic_read(&net->gnn_refcount));

	if (!list_empty(&net->gnn_list)) {
		/* serialize with peer creation */
		down_write(&kgnilnd_data.kgn_net_rw_sem);
		net->gnn_shutdown = 1;
		up_write(&kgnilnd_data.kgn_net_rw_sem);

		kgnilnd_cancel_net_dgrams(net);

		kgnilnd_del_conn_or_peer(net, LNET_NID_ANY, GNILND_DEL_PEER, -ESHUTDOWN);

		/* if we are quiesced, need to wake up - we need those threads
		 * alive to release peers, etc */
		if (GNILND_IS_QUIESCED) {
			set_mb(kgnilnd_data.kgn_quiesce_trigger, GNILND_QUIESCE_IDLE);
			kgnilnd_quiesce_wait("shutdown");
		}

		kgnilnd_wait_for_canceled_dgrams(net->gnn_dev);

		/* We wait until the nets ref's are 1, we will release final ref which is ours
		 * this allows us to make sure everything else is done before we free the
		 * net.
		 */
		i = 4;
		while (atomic_read(&net->gnn_refcount) != 1) {
			i++;
			CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET,
				"Waiting for %d references to clear on net %d\n",
				atomic_read(&net->gnn_refcount),
				net->gnn_netnum);
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout(cfs_time_seconds(1));
		}

		/* release ref from kgnilnd_startup */
		kgnilnd_net_decref(net);
		/* serialize with reaper and conn_task looping */
		down_write(&kgnilnd_data.kgn_net_rw_sem);
		list_del_init(&net->gnn_list);
		up_write(&kgnilnd_data.kgn_net_rw_sem);

	}

	/* not locking, this can't race with writers */
	LASSERTF(atomic_read(&net->gnn_refcount) == 0,
		"net %p refcount %d\n",
		 net, atomic_read(&net->gnn_refcount));
	LIBCFS_FREE(net, sizeof(*net));

out:
	down_read(&kgnilnd_data.kgn_net_rw_sem);
	for (i = 0; i < *kgnilnd_tunables.kgn_net_hash_size; i++) {
		if (!list_empty(&kgnilnd_data.kgn_nets[i])) {
			up_read(&kgnilnd_data.kgn_net_rw_sem);
			break;
		}

		if (i == *kgnilnd_tunables.kgn_net_hash_size - 1) {
			up_read(&kgnilnd_data.kgn_net_rw_sem);
			kgnilnd_base_shutdown();
		}
	}
	CDEBUG(D_MALLOC, "after NAL cleanup: kmem %d\n",
	       atomic_read(&libcfs_kmemory));

	mutex_unlock(&kgnilnd_data.kgn_quiesce_mutex);
	EXIT;
}

static void __exit kgnilnd_exit(void)
{
	lnet_unregister_lnd(&the_kgnilnd);
	kgnilnd_proc_fini();
	kgnilnd_remove_sysctl();
}

static int __init kgnilnd_init(void)
{
	int    rc;

	rc = kgnilnd_tunables_init();
	if (rc != 0)
		return rc;

	LCONSOLE_INFO("Lustre: kgnilnd build version: "LUSTRE_VERSION_STRING"\n");

	kgnilnd_insert_sysctl();
	kgnilnd_proc_init();

	lnet_register_lnd(&the_kgnilnd);

	return 0;
}

MODULE_AUTHOR("Cray, Inc. <nic@cray.com>");
MODULE_DESCRIPTION("Gemini LNet Network Driver");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(kgnilnd_init);
module_exit(kgnilnd_exit);
