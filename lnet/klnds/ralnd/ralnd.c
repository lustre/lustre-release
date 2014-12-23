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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/ralnd/ralnd.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 */
#include "ralnd.h"

static int        kranal_devids[RANAL_MAXDEVS] = {RAPK_MAIN_DEVICE_ID,
                                                  RAPK_EXPANSION_DEVICE_ID};

lnd_t the_kralnd = {
        .lnd_type       = RALND,
        .lnd_startup    = kranal_startup,
        .lnd_shutdown   = kranal_shutdown,
        .lnd_ctl        = kranal_ctl,
        .lnd_send       = kranal_send,
        .lnd_recv       = kranal_recv,
        .lnd_eager_recv = kranal_eager_recv,
        .lnd_accept     = kranal_accept,
};

kra_data_t              kranal_data;

void
kranal_pack_connreq(kra_connreq_t *connreq, kra_conn_t *conn, lnet_nid_t dstnid)
{
        RAP_RETURN   rrc;

        memset(connreq, 0, sizeof(*connreq));

        connreq->racr_magic     = RANAL_MSG_MAGIC;
        connreq->racr_version   = RANAL_MSG_VERSION;

        if (conn == NULL)                       /* prepping a "stub" reply */
                return;

        connreq->racr_devid     = conn->rac_device->rad_id;
        connreq->racr_srcnid    = kranal_data.kra_ni->ni_nid;
        connreq->racr_dstnid    = dstnid;
        connreq->racr_peerstamp = kranal_data.kra_peerstamp;
        connreq->racr_connstamp = conn->rac_my_connstamp;
        connreq->racr_timeout   = conn->rac_timeout;

        rrc = RapkGetRiParams(conn->rac_rihandle, &connreq->racr_riparams);
        LASSERT(rrc == RAP_SUCCESS);
}

int
kranal_recv_connreq(struct socket *sock, kra_connreq_t *connreq, int active)
{
        int         timeout = active ? *kranal_tunables.kra_timeout :
                                        lnet_acceptor_timeout();
        int         swab;
        int         rc;

        /* return 0 on success, -ve on error, +ve to tell the peer I'm "old" */

        rc = libcfs_sock_read(sock, &connreq->racr_magic, 
                              sizeof(connreq->racr_magic), timeout);
        if (rc != 0) {
                CERROR("Read(magic) failed(1): %d\n", rc);
                return -EIO;
        }

        if (connreq->racr_magic != RANAL_MSG_MAGIC &&
            connreq->racr_magic != __swab32(RANAL_MSG_MAGIC)) {
                /* Unexpected magic! */
                if (!active &&
                    (connreq->racr_magic == LNET_PROTO_MAGIC ||
                     connreq->racr_magic == __swab32(LNET_PROTO_MAGIC))) {
                        /* future protocol version compatibility!
                         * When LNET unifies protocols over all LNDs, the first
                         * thing sent will be a version query.  +ve rc means I
                         * reply with my current magic/version */
                        return EPROTO;
                }

                CERROR("Unexpected magic %08x (%s)\n",
                       connreq->racr_magic, active ? "active" : "passive");
                return -EPROTO;
        }

        swab = (connreq->racr_magic == __swab32(RANAL_MSG_MAGIC));

        rc = libcfs_sock_read(sock, &connreq->racr_version,
                              sizeof(connreq->racr_version), timeout);
        if (rc != 0) {
                CERROR("Read(version) failed: %d\n", rc);
                return -EIO;
        }

        if (swab)
                __swab16s(&connreq->racr_version);
        
        if (connreq->racr_version != RANAL_MSG_VERSION) {
                if (active) {
                        CERROR("Unexpected version %d\n", connreq->racr_version);
                        return -EPROTO;
                }
                /* If this is a future version of the ralnd protocol, and I'm
                 * passive (accepted the connection), tell my peer I'm "old"
                 * (+ve rc) */
                return EPROTO;
        }

        rc = libcfs_sock_read(sock, &connreq->racr_devid,
                              sizeof(connreq->racr_version) -
                              offsetof(kra_connreq_t, racr_devid),
                              timeout);
        if (rc != 0) {
                CERROR("Read(body) failed: %d\n", rc);
                return -EIO;
        }

        if (swab) {
                __swab32s(&connreq->racr_magic);
                __swab16s(&connreq->racr_version);
                __swab16s(&connreq->racr_devid);
                __swab64s(&connreq->racr_srcnid);
                __swab64s(&connreq->racr_dstnid);
                __swab64s(&connreq->racr_peerstamp);
                __swab64s(&connreq->racr_connstamp);
                __swab32s(&connreq->racr_timeout);

                __swab32s(&connreq->racr_riparams.HostId);
                __swab32s(&connreq->racr_riparams.FmaDomainHndl);
                __swab32s(&connreq->racr_riparams.PTag);
                __swab32s(&connreq->racr_riparams.CompletionCookie);
        }

        if (connreq->racr_srcnid == LNET_NID_ANY ||
            connreq->racr_dstnid == LNET_NID_ANY) {
                CERROR("Received LNET_NID_ANY\n");
                return -EPROTO;
        }

        if (connreq->racr_timeout < RANAL_MIN_TIMEOUT) {
                CERROR("Received timeout %d < MIN %d\n",
                       connreq->racr_timeout, RANAL_MIN_TIMEOUT);
                return -EPROTO;
        }

        return 0;
}

int
kranal_close_stale_conns_locked (kra_peer_t *peer, kra_conn_t *newconn)
{
        kra_conn_t         *conn;
        cfs_list_t         *ctmp;
        cfs_list_t         *cnxt;
        int                 loopback;
        int                 count = 0;

        loopback = peer->rap_nid == kranal_data.kra_ni->ni_nid;

        cfs_list_for_each_safe (ctmp, cnxt, &peer->rap_conns) {
                conn = cfs_list_entry(ctmp, kra_conn_t, rac_list);

                if (conn == newconn)
                        continue;

                if (conn->rac_peerstamp != newconn->rac_peerstamp) {
                        CDEBUG(D_NET, "Closing stale conn nid: %s "
                               " peerstamp:"LPX64"("LPX64")\n", 
                               libcfs_nid2str(peer->rap_nid),
                               conn->rac_peerstamp, newconn->rac_peerstamp);
                        LASSERT (conn->rac_peerstamp < newconn->rac_peerstamp);
                        count++;
                        kranal_close_conn_locked(conn, -ESTALE);
                        continue;
                }

                if (conn->rac_device != newconn->rac_device)
                        continue;

                if (loopback &&
                    newconn->rac_my_connstamp == conn->rac_peer_connstamp &&
                    newconn->rac_peer_connstamp == conn->rac_my_connstamp)
                        continue;

                LASSERT (conn->rac_peer_connstamp < newconn->rac_peer_connstamp);

                CDEBUG(D_NET, "Closing stale conn nid: %s"
                       " connstamp:"LPX64"("LPX64")\n", 
                       libcfs_nid2str(peer->rap_nid),
                       conn->rac_peer_connstamp, newconn->rac_peer_connstamp);

                count++;
                kranal_close_conn_locked(conn, -ESTALE);
        }

        return count;
}

int
kranal_conn_isdup_locked(kra_peer_t *peer, kra_conn_t *newconn)
{
        kra_conn_t       *conn;
        cfs_list_t       *tmp;
        int               loopback;

        loopback = peer->rap_nid == kranal_data.kra_ni->ni_nid;

        cfs_list_for_each(tmp, &peer->rap_conns) {
                conn = cfs_list_entry(tmp, kra_conn_t, rac_list);

                /* 'newconn' is from an earlier version of 'peer'!!! */
                if (newconn->rac_peerstamp < conn->rac_peerstamp)
                        return 1;

                /* 'conn' is from an earlier version of 'peer': it will be
                 * removed when we cull stale conns later on... */
                if (newconn->rac_peerstamp > conn->rac_peerstamp)
                        continue;

                /* Different devices are OK */
                if (conn->rac_device != newconn->rac_device)
                        continue;

                /* It's me connecting to myself */
                if (loopback &&
                    newconn->rac_my_connstamp == conn->rac_peer_connstamp &&
                    newconn->rac_peer_connstamp == conn->rac_my_connstamp)
                        continue;

                /* 'newconn' is an earlier connection from 'peer'!!! */
                if (newconn->rac_peer_connstamp < conn->rac_peer_connstamp)
                        return 2;

                /* 'conn' is an earlier connection from 'peer': it will be
                 * removed when we cull stale conns later on... */
                if (newconn->rac_peer_connstamp > conn->rac_peer_connstamp)
                        continue;

                /* 'newconn' has the SAME connection stamp; 'peer' isn't
                 * playing the game... */
                return 3;
        }

        return 0;
}

void
kranal_set_conn_uniqueness (kra_conn_t *conn)
{
        unsigned long  flags;

	write_lock_irqsave(&kranal_data.kra_global_lock, flags);

        conn->rac_my_connstamp = kranal_data.kra_connstamp++;

        do {    /* allocate a unique cqid */
                conn->rac_cqid = kranal_data.kra_next_cqid++;
        } while (kranal_cqid2conn_locked(conn->rac_cqid) != NULL);

	write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);
}

int
kranal_create_conn(kra_conn_t **connp, kra_device_t *dev)
{
	kra_conn_t    *conn;
	RAP_RETURN     rrc;

	LASSERT (!in_interrupt());
	LIBCFS_ALLOC(conn, sizeof(*conn));

	if (conn == NULL)
		return -ENOMEM;

        memset(conn, 0, sizeof(*conn));
	atomic_set(&conn->rac_refcount, 1);
        CFS_INIT_LIST_HEAD(&conn->rac_list);
        CFS_INIT_LIST_HEAD(&conn->rac_hashlist);
        CFS_INIT_LIST_HEAD(&conn->rac_schedlist);
        CFS_INIT_LIST_HEAD(&conn->rac_fmaq);
        CFS_INIT_LIST_HEAD(&conn->rac_rdmaq);
        CFS_INIT_LIST_HEAD(&conn->rac_replyq);
	spin_lock_init(&conn->rac_lock);

        kranal_set_conn_uniqueness(conn);

        conn->rac_device = dev;
        conn->rac_timeout = MAX(*kranal_tunables.kra_timeout, RANAL_MIN_TIMEOUT);
        kranal_update_reaper_timeout(conn->rac_timeout);

        rrc = RapkCreateRi(dev->rad_handle, conn->rac_cqid,
                           &conn->rac_rihandle);
        if (rrc != RAP_SUCCESS) {
                CERROR("RapkCreateRi failed: %d\n", rrc);
                LIBCFS_FREE(conn, sizeof(*conn));
                return -ENETDOWN;
        }

	atomic_inc(&kranal_data.kra_nconns);
        *connp = conn;
        return 0;
}

void
kranal_destroy_conn(kra_conn_t *conn)
{
	RAP_RETURN         rrc;

	LASSERT (!in_interrupt());
	LASSERT (!conn->rac_scheduled);
	LASSERT (cfs_list_empty(&conn->rac_list));
	LASSERT (cfs_list_empty(&conn->rac_hashlist));
	LASSERT (cfs_list_empty(&conn->rac_schedlist));
	LASSERT (atomic_read(&conn->rac_refcount) == 0);
	LASSERT (cfs_list_empty(&conn->rac_fmaq));
	LASSERT (cfs_list_empty(&conn->rac_rdmaq));
	LASSERT (cfs_list_empty(&conn->rac_replyq));

	rrc = RapkDestroyRi(conn->rac_device->rad_handle,
			    conn->rac_rihandle);
	LASSERT (rrc == RAP_SUCCESS);

	if (conn->rac_peer != NULL)
		kranal_peer_decref(conn->rac_peer);

	LIBCFS_FREE(conn, sizeof(*conn));
	atomic_dec(&kranal_data.kra_nconns);
}

void
kranal_terminate_conn_locked (kra_conn_t *conn)
{
	LASSERT (!in_interrupt());
	LASSERT (conn->rac_state == RANAL_CONN_CLOSING);
	LASSERT (!cfs_list_empty(&conn->rac_hashlist));
	LASSERT (cfs_list_empty(&conn->rac_list));

	/* Remove from conn hash table: no new callbacks */
	cfs_list_del_init(&conn->rac_hashlist);
	kranal_conn_decref(conn);

	conn->rac_state = RANAL_CONN_CLOSED;

	/* schedule to clear out all uncompleted comms in context of dev's
	 * scheduler */
	kranal_schedule_conn(conn);
}

void
kranal_close_conn_locked (kra_conn_t *conn, int error)
{
	kra_peer_t        *peer = conn->rac_peer;

	CDEBUG_LIMIT(error == 0 ? D_NET : D_NETERROR,
		     "closing conn to %s: error %d\n",
		     libcfs_nid2str(peer->rap_nid), error);

	LASSERT (!in_interrupt());
	LASSERT (conn->rac_state == RANAL_CONN_ESTABLISHED);
	LASSERT (!cfs_list_empty(&conn->rac_hashlist));
	LASSERT (!cfs_list_empty(&conn->rac_list));

	cfs_list_del_init(&conn->rac_list);

	if (cfs_list_empty(&peer->rap_conns) &&
	    peer->rap_persistence == 0) {
		/* Non-persistent peer with no more conns... */
		kranal_unlink_peer_locked(peer);
	}

	/* Reset RX timeout to ensure we wait for an incoming CLOSE for the
	 * full timeout.  If we get a CLOSE we know the peer has stopped all
	 * RDMA.  Otherwise if we wait for the full timeout we can also be sure
	 * all RDMA has stopped. */
	conn->rac_last_rx = jiffies;
	smp_mb();

	conn->rac_state = RANAL_CONN_CLOSING;
	kranal_schedule_conn(conn);             /* schedule sending CLOSE */

	kranal_conn_decref(conn);               /* lose peer's ref */
}

void
kranal_close_conn (kra_conn_t *conn, int error)
{
        unsigned long    flags;


	write_lock_irqsave(&kranal_data.kra_global_lock, flags);

        if (conn->rac_state == RANAL_CONN_ESTABLISHED)
                kranal_close_conn_locked(conn, error);

	write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);
}

int
kranal_set_conn_params(kra_conn_t *conn, kra_connreq_t *connreq,
                       __u32 peer_ip, int peer_port)
{
	kra_device_t  *dev = conn->rac_device;
	unsigned long  flags;
	RAP_RETURN     rrc;

	/* CAVEAT EMPTOR: we're really overloading rac_last_tx + rac_keepalive
	 * to do RapkCompleteSync() timekeeping (see kibnal_scheduler). */
	conn->rac_last_tx = jiffies;
	conn->rac_keepalive = 0;

	rrc = RapkSetRiParams(conn->rac_rihandle, &connreq->racr_riparams);
	if (rrc != RAP_SUCCESS) {
		CERROR("Error setting riparams from %u.%u.%u.%u/%d: %d\n",
		       HIPQUAD(peer_ip), peer_port, rrc);
		return -ECONNABORTED;
	}

	/* Schedule conn on rad_new_conns */
	kranal_conn_addref(conn);
	spin_lock_irqsave(&dev->rad_lock, flags);
	cfs_list_add_tail(&conn->rac_schedlist, &dev->rad_new_conns);
	wake_up(&dev->rad_waitq);
	spin_unlock_irqrestore(&dev->rad_lock, flags);

	rrc = RapkWaitToConnect(conn->rac_rihandle);
	if (rrc != RAP_SUCCESS) {
		CERROR("Error waiting to connect to %u.%u.%u.%u/%d: %d\n",
		       HIPQUAD(peer_ip), peer_port, rrc);
		return -ECONNABORTED;
	}

	/* Scheduler doesn't touch conn apart from to deschedule and decref it
	 * after RapkCompleteSync() return success, so conn is all mine */

	conn->rac_peerstamp = connreq->racr_peerstamp;
	conn->rac_peer_connstamp = connreq->racr_connstamp;
	conn->rac_keepalive = RANAL_TIMEOUT2KEEPALIVE(connreq->racr_timeout);
	kranal_update_reaper_timeout(conn->rac_keepalive);
	return 0;
}

int
kranal_passive_conn_handshake (struct socket *sock, lnet_nid_t *src_nidp,
                               lnet_nid_t *dst_nidp, kra_conn_t **connp)
{
        __u32                peer_ip;
        unsigned int         peer_port;
        kra_connreq_t        rx_connreq;
        kra_connreq_t        tx_connreq;
        kra_conn_t          *conn;
        kra_device_t        *dev;
        int                  rc;
        int                  i;

        rc = libcfs_sock_getaddr(sock, 1, &peer_ip, &peer_port);
        if (rc != 0) {
                CERROR("Can't get peer's IP: %d\n", rc);
                return rc;
        }

        rc = kranal_recv_connreq(sock, &rx_connreq, 0);

        if (rc < 0) {
                CERROR("Can't rx connreq from %u.%u.%u.%u/%d: %d\n",
                       HIPQUAD(peer_ip), peer_port, rc);
                return rc;
        }

        if (rc > 0) {
                /* Request from "new" peer: send reply with my MAGIC/VERSION to
                 * tell her I'm old... */
                kranal_pack_connreq(&tx_connreq, NULL, LNET_NID_ANY);

                rc = libcfs_sock_write(sock, &tx_connreq, sizeof(tx_connreq),
                                       lnet_acceptor_timeout());
                if (rc != 0)
                        CERROR("Can't tx stub connreq to %u.%u.%u.%u/%d: %d\n",
                               HIPQUAD(peer_ip), peer_port, rc);

                return -EPROTO;
        }

        for (i = 0;;i++) {
                if (i == kranal_data.kra_ndevs) {
                        CERROR("Can't match dev %d from %u.%u.%u.%u/%d\n",
                               rx_connreq.racr_devid, HIPQUAD(peer_ip), peer_port);
                        return -ENODEV;
                }
                dev = &kranal_data.kra_devices[i];
                if (dev->rad_id == rx_connreq.racr_devid)
                        break;
        }

        rc = kranal_create_conn(&conn, dev);
        if (rc != 0)
                return rc;

        kranal_pack_connreq(&tx_connreq, conn, rx_connreq.racr_srcnid);

        rc = libcfs_sock_write(sock, &tx_connreq, sizeof(tx_connreq),
                               lnet_acceptor_timeout());
        if (rc != 0) {
                CERROR("Can't tx connreq to %u.%u.%u.%u/%d: %d\n",
                       HIPQUAD(peer_ip), peer_port, rc);
                kranal_conn_decref(conn);
                return rc;
        }

        rc = kranal_set_conn_params(conn, &rx_connreq, peer_ip, peer_port);
        if (rc != 0) {
                kranal_conn_decref(conn);
                return rc;
        }

        *connp = conn;
        *src_nidp = rx_connreq.racr_srcnid;
        *dst_nidp = rx_connreq.racr_dstnid;
        return 0;
}

int
kranal_active_conn_handshake(kra_peer_t *peer,
                             lnet_nid_t *dst_nidp, kra_conn_t **connp)
{
        kra_connreq_t       connreq;
        kra_conn_t         *conn;
        kra_device_t       *dev;
        struct socket      *sock;
        int                 rc;
        unsigned int        idx;

        /* spread connections over all devices using both peer NIDs to ensure
         * all nids use all devices */
        idx = peer->rap_nid + kranal_data.kra_ni->ni_nid;
        dev = &kranal_data.kra_devices[idx % kranal_data.kra_ndevs];

        rc = kranal_create_conn(&conn, dev);
        if (rc != 0)
                return rc;

        kranal_pack_connreq(&connreq, conn, peer->rap_nid);

        if (the_lnet.ln_testprotocompat != 0) {
                /* single-shot proto test */
                LNET_LOCK();
                if ((the_lnet.ln_testprotocompat & 1) != 0) {
                        connreq.racr_version++;
                        the_lnet.ln_testprotocompat &= ~1;
                }
                if ((the_lnet.ln_testprotocompat & 2) != 0) {
                        connreq.racr_magic = LNET_PROTO_MAGIC;
                        the_lnet.ln_testprotocompat &= ~2;
                }
                LNET_UNLOCK();
        }

        rc = lnet_connect(&sock, peer->rap_nid,
                         0, peer->rap_ip, peer->rap_port);
        if (rc != 0)
                goto failed_0;

        /* CAVEAT EMPTOR: the passive side receives with a SHORT rx timeout
         * immediately after accepting a connection, so we connect and then
         * send immediately. */

        rc = libcfs_sock_write(sock, &connreq, sizeof(connreq),
                               lnet_acceptor_timeout());
        if (rc != 0) {
                CERROR("Can't tx connreq to %u.%u.%u.%u/%d: %d\n",
                       HIPQUAD(peer->rap_ip), peer->rap_port, rc);
                goto failed_2;
        }

        rc = kranal_recv_connreq(sock, &connreq, 1);
        if (rc != 0) {
                CERROR("Can't rx connreq from %u.%u.%u.%u/%d: %d\n",
                       HIPQUAD(peer->rap_ip), peer->rap_port, rc);
                goto failed_2;
        }

        libcfs_sock_release(sock);
        rc = -EPROTO;

        if (connreq.racr_srcnid != peer->rap_nid) {
                CERROR("Unexpected srcnid from %u.%u.%u.%u/%d: "
                       "received %s expected %s\n",
                       HIPQUAD(peer->rap_ip), peer->rap_port,
                       libcfs_nid2str(connreq.racr_srcnid), 
                       libcfs_nid2str(peer->rap_nid));
                goto failed_1;
        }

        if (connreq.racr_devid != dev->rad_id) {
                CERROR("Unexpected device id from %u.%u.%u.%u/%d: "
                       "received %d expected %d\n",
                       HIPQUAD(peer->rap_ip), peer->rap_port,
                       connreq.racr_devid, dev->rad_id);
                goto failed_1;
        }

        rc = kranal_set_conn_params(conn, &connreq,
                                    peer->rap_ip, peer->rap_port);
        if (rc != 0)
                goto failed_1;

        *connp = conn;
        *dst_nidp = connreq.racr_dstnid;
        return 0;

 failed_2:
        libcfs_sock_release(sock);
 failed_1:
        lnet_connect_console_error(rc, peer->rap_nid,
                                  peer->rap_ip, peer->rap_port);
 failed_0:
        kranal_conn_decref(conn);
        return rc;
}

int
kranal_conn_handshake (struct socket *sock, kra_peer_t *peer)
{
        kra_peer_t        *peer2;
        kra_tx_t          *tx;
        lnet_nid_t         peer_nid;
        lnet_nid_t         dst_nid;
        unsigned long      flags;
        kra_conn_t        *conn;
        int                rc;
        int                nstale;
        int                new_peer = 0;

        if (sock == NULL) {
                /* active: connd wants to connect to 'peer' */
                LASSERT (peer != NULL);
                LASSERT (peer->rap_connecting);

                rc = kranal_active_conn_handshake(peer, &dst_nid, &conn);
                if (rc != 0)
                        return rc;

		write_lock_irqsave(&kranal_data.kra_global_lock, flags);

                if (!kranal_peer_active(peer)) {
                        /* raced with peer getting unlinked */
			write_unlock_irqrestore(&kranal_data. \
                                                    kra_global_lock,
                                                    flags);
                        kranal_conn_decref(conn);
                        return -ESTALE;
                }

                peer_nid = peer->rap_nid;
        } else {
                /* passive: listener accepted 'sock' */
                LASSERT (peer == NULL);

                rc = kranal_passive_conn_handshake(sock, &peer_nid,
                                                   &dst_nid, &conn);
                if (rc != 0)
                        return rc;

                /* assume this is a new peer */
                rc = kranal_create_peer(&peer, peer_nid);
                if (rc != 0) {
                        CERROR("Can't create conn for %s\n", 
                               libcfs_nid2str(peer_nid));
                        kranal_conn_decref(conn);
                        return -ENOMEM;
                }

		write_lock_irqsave(&kranal_data.kra_global_lock, flags);

                peer2 = kranal_find_peer_locked(peer_nid);
                if (peer2 == NULL) {
                        new_peer = 1;
                } else {
                        /* peer_nid already in the peer table */
                        kranal_peer_decref(peer);
                        peer = peer2;
                }
        }

        LASSERT ((!new_peer) != (!kranal_peer_active(peer)));

        /* Refuse connection if peer thinks we are a different NID.  We check
         * this while holding the global lock, to synch with connection
         * destruction on NID change. */
        if (kranal_data.kra_ni->ni_nid != dst_nid) {
		write_unlock_irqrestore(&kranal_data.kra_global_lock,
                                            flags);

                CERROR("Stale/bad connection with %s: dst_nid %s, expected %s\n",
                       libcfs_nid2str(peer_nid), libcfs_nid2str(dst_nid), 
                       libcfs_nid2str(kranal_data.kra_ni->ni_nid));
                rc = -ESTALE;
                goto failed;
        }

        /* Refuse to duplicate an existing connection (both sides might try to
         * connect at once).  NB we return success!  We _are_ connected so we
         * _don't_ have any blocked txs to complete with failure. */
        rc = kranal_conn_isdup_locked(peer, conn);
        if (rc != 0) {
                LASSERT (!cfs_list_empty(&peer->rap_conns));
                LASSERT (cfs_list_empty(&peer->rap_tx_queue));
		write_unlock_irqrestore(&kranal_data.kra_global_lock,
                                            flags);
                CWARN("Not creating duplicate connection to %s: %d\n",
                      libcfs_nid2str(peer_nid), rc);
                rc = 0;
                goto failed;
        }

        if (new_peer) {
                /* peer table takes my ref on the new peer */
                cfs_list_add_tail(&peer->rap_list,
                                  kranal_nid2peerlist(peer_nid));
        }

        /* initialise timestamps before reaper looks at them */
        conn->rac_last_tx = conn->rac_last_rx = jiffies;

        kranal_peer_addref(peer);               /* +1 ref for conn */
        conn->rac_peer = peer;
        cfs_list_add_tail(&conn->rac_list, &peer->rap_conns);

        kranal_conn_addref(conn);               /* +1 ref for conn table */
        cfs_list_add_tail(&conn->rac_hashlist,
                          kranal_cqid2connlist(conn->rac_cqid));

        /* Schedule all packets blocking for a connection */
        while (!cfs_list_empty(&peer->rap_tx_queue)) {
                tx = cfs_list_entry(peer->rap_tx_queue.next,
                                    kra_tx_t, tx_list);

                cfs_list_del(&tx->tx_list);
                kranal_post_fma(conn, tx);
        }

        nstale = kranal_close_stale_conns_locked(peer, conn);

	write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);

        /* CAVEAT EMPTOR: passive peer can disappear NOW */

        if (nstale != 0)
                CWARN("Closed %d stale conns to %s\n", nstale, 
                      libcfs_nid2str(peer_nid));

        CWARN("New connection to %s on devid[%d] = %d\n",
               libcfs_nid2str(peer_nid), 
               conn->rac_device->rad_idx, conn->rac_device->rad_id);

        /* Ensure conn gets checked.  Transmits may have been queued and an
         * FMA event may have happened before it got in the cq hash table */
        kranal_schedule_conn(conn);
        return 0;

 failed:
        if (new_peer)
                kranal_peer_decref(peer);
        kranal_conn_decref(conn);
        return rc;
}

void
kranal_connect (kra_peer_t *peer)
{
        kra_tx_t          *tx;
        unsigned long      flags;
        cfs_list_t         zombies;
        int                rc;

        LASSERT (peer->rap_connecting);

        CDEBUG(D_NET, "About to handshake %s\n", 
               libcfs_nid2str(peer->rap_nid));

        rc = kranal_conn_handshake(NULL, peer);

        CDEBUG(D_NET, "Done handshake %s:%d \n", 
               libcfs_nid2str(peer->rap_nid), rc);

	write_lock_irqsave(&kranal_data.kra_global_lock, flags);

        LASSERT (peer->rap_connecting);
        peer->rap_connecting = 0;

        if (rc == 0) {
                /* kranal_conn_handshake() queues blocked txs immediately on
                 * success to avoid messages jumping the queue */
                LASSERT (cfs_list_empty(&peer->rap_tx_queue));

                peer->rap_reconnect_interval = 0; /* OK to reconnect at any time */

		write_unlock_irqrestore(&kranal_data.kra_global_lock,
                                            flags);
                return;
        }

        peer->rap_reconnect_interval *= 2;
        peer->rap_reconnect_interval =
                MAX(peer->rap_reconnect_interval,
                    *kranal_tunables.kra_min_reconnect_interval);
        peer->rap_reconnect_interval =
                MIN(peer->rap_reconnect_interval,
                    *kranal_tunables.kra_max_reconnect_interval);

	peer->rap_reconnect_time = jiffies +
		msecs_to_jiffies(peer->rap_reconnect_interval * MSEC_PER_SEC);

        /* Grab all blocked packets while we have the global lock */
        cfs_list_add(&zombies, &peer->rap_tx_queue);
        cfs_list_del_init(&peer->rap_tx_queue);

	write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);

        if (cfs_list_empty(&zombies))
                return;

        CNETERR("Dropping packets for %s: connection failed\n",
                libcfs_nid2str(peer->rap_nid));

        do {
                tx = cfs_list_entry(zombies.next, kra_tx_t, tx_list);

                cfs_list_del(&tx->tx_list);
                kranal_tx_done(tx, -EHOSTUNREACH);

        } while (!cfs_list_empty(&zombies));
}

void
kranal_free_acceptsock (kra_acceptsock_t *ras)
{
        libcfs_sock_release(ras->ras_sock);
        LIBCFS_FREE(ras, sizeof(*ras));
}

int
kranal_accept (lnet_ni_t *ni, struct socket *sock)
{
	kra_acceptsock_t  *ras;
	int                rc;
	__u32              peer_ip;
	int                peer_port;
	unsigned long      flags;

	rc = libcfs_sock_getaddr(sock, 1, &peer_ip, &peer_port);
	LASSERT (rc == 0);                      /* we succeeded before */

	LIBCFS_ALLOC(ras, sizeof(*ras));
	if (ras == NULL) {
		CERROR("ENOMEM allocating connection request from "
		       "%u.%u.%u.%u\n", HIPQUAD(peer_ip));
		return -ENOMEM;
	}

	ras->ras_sock = sock;

	spin_lock_irqsave(&kranal_data.kra_connd_lock, flags);

	cfs_list_add_tail(&ras->ras_list, &kranal_data.kra_connd_acceptq);
	wake_up(&kranal_data.kra_connd_waitq);

	spin_unlock_irqrestore(&kranal_data.kra_connd_lock, flags);
	return 0;
}

int
kranal_create_peer (kra_peer_t **peerp, lnet_nid_t nid)
{
        kra_peer_t    *peer;
        unsigned long  flags;

        LASSERT (nid != LNET_NID_ANY);

        LIBCFS_ALLOC(peer, sizeof(*peer));
        if (peer == NULL)
                return -ENOMEM;

        memset(peer, 0, sizeof(*peer));         /* zero flags etc */

        peer->rap_nid = nid;
	atomic_set(&peer->rap_refcount, 1);     /* 1 ref for caller */

        CFS_INIT_LIST_HEAD(&peer->rap_list);
        CFS_INIT_LIST_HEAD(&peer->rap_connd_list);
        CFS_INIT_LIST_HEAD(&peer->rap_conns);
        CFS_INIT_LIST_HEAD(&peer->rap_tx_queue);

        peer->rap_reconnect_interval = 0;       /* OK to connect at any time */

	write_lock_irqsave(&kranal_data.kra_global_lock, flags);

        if (kranal_data.kra_nonewpeers) {
                /* shutdown has started already */
		write_unlock_irqrestore(&kranal_data.kra_global_lock,
                                            flags);

                LIBCFS_FREE(peer, sizeof(*peer));
                CERROR("Can't create peer: network shutdown\n");
                return -ESHUTDOWN;
        }

	atomic_inc(&kranal_data.kra_npeers);

	write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);

        *peerp = peer;
        return 0;
}

void
kranal_destroy_peer (kra_peer_t *peer)
{
        CDEBUG(D_NET, "peer %s %p deleted\n", 
               libcfs_nid2str(peer->rap_nid), peer);

	LASSERT (atomic_read(&peer->rap_refcount) == 0);
        LASSERT (peer->rap_persistence == 0);
        LASSERT (!kranal_peer_active(peer));
        LASSERT (!peer->rap_connecting);
        LASSERT (cfs_list_empty(&peer->rap_conns));
        LASSERT (cfs_list_empty(&peer->rap_tx_queue));
        LASSERT (cfs_list_empty(&peer->rap_connd_list));

        LIBCFS_FREE(peer, sizeof(*peer));

        /* NB a peer's connections keep a reference on their peer until
         * they are destroyed, so we can be assured that _all_ state to do
         * with this peer has been cleaned up when its refcount drops to
         * zero. */
	atomic_dec(&kranal_data.kra_npeers);
}

kra_peer_t *
kranal_find_peer_locked (lnet_nid_t nid)
{
        cfs_list_t       *peer_list = kranal_nid2peerlist(nid);
        cfs_list_t       *tmp;
        kra_peer_t       *peer;

        cfs_list_for_each (tmp, peer_list) {

                peer = cfs_list_entry(tmp, kra_peer_t, rap_list);

                LASSERT (peer->rap_persistence > 0 ||     /* persistent peer */
                         !cfs_list_empty(&peer->rap_conns));  /* active conn */

                if (peer->rap_nid != nid)
                        continue;

                CDEBUG(D_NET, "got peer [%p] -> %s (%d)\n",
                       peer, libcfs_nid2str(nid), 
		       atomic_read(&peer->rap_refcount));
                return peer;
        }
        return NULL;
}

kra_peer_t *
kranal_find_peer (lnet_nid_t nid)
{
        kra_peer_t     *peer;

	read_lock(&kranal_data.kra_global_lock);
        peer = kranal_find_peer_locked(nid);
        if (peer != NULL)                       /* +1 ref for caller? */
                kranal_peer_addref(peer);
	read_unlock(&kranal_data.kra_global_lock);

        return peer;
}

void
kranal_unlink_peer_locked (kra_peer_t *peer)
{
        LASSERT (peer->rap_persistence == 0);
        LASSERT (cfs_list_empty(&peer->rap_conns));

        LASSERT (kranal_peer_active(peer));
        cfs_list_del_init(&peer->rap_list);

        /* lose peerlist's ref */
        kranal_peer_decref(peer);
}

int
kranal_get_peer_info (int index, lnet_nid_t *nidp, __u32 *ipp, int *portp,
                      int *persistencep)
{
        kra_peer_t        *peer;
        cfs_list_t        *ptmp;
        int                i;

	read_lock(&kranal_data.kra_global_lock);

        for (i = 0; i < kranal_data.kra_peer_hash_size; i++) {

                cfs_list_for_each(ptmp, &kranal_data.kra_peers[i]) {

                        peer = cfs_list_entry(ptmp, kra_peer_t, rap_list);
                        LASSERT (peer->rap_persistence > 0 ||
                                 !cfs_list_empty(&peer->rap_conns));

                        if (index-- > 0)
                                continue;

                        *nidp = peer->rap_nid;
                        *ipp = peer->rap_ip;
                        *portp = peer->rap_port;
                        *persistencep = peer->rap_persistence;

			read_unlock(&kranal_data.kra_global_lock);
                        return 0;
                }
        }

	read_unlock(&kranal_data.kra_global_lock);
        return -ENOENT;
}

int
kranal_add_persistent_peer (lnet_nid_t nid, __u32 ip, int port)
{
        unsigned long      flags;
        kra_peer_t        *peer;
        kra_peer_t        *peer2;
        int                rc;

        if (nid == LNET_NID_ANY)
                return -EINVAL;

        rc = kranal_create_peer(&peer, nid);
        if (rc != 0)
                return rc;

	write_lock_irqsave(&kranal_data.kra_global_lock, flags);

        peer2 = kranal_find_peer_locked(nid);
        if (peer2 != NULL) {
                kranal_peer_decref(peer);
                peer = peer2;
        } else {
                /* peer table takes existing ref on peer */
                cfs_list_add_tail(&peer->rap_list,
                              kranal_nid2peerlist(nid));
        }

        peer->rap_ip = ip;
        peer->rap_port = port;
        peer->rap_persistence++;

	write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);
        return 0;
}

void
kranal_del_peer_locked (kra_peer_t *peer)
{
        cfs_list_t       *ctmp;
        cfs_list_t       *cnxt;
        kra_conn_t       *conn;

        peer->rap_persistence = 0;

        if (cfs_list_empty(&peer->rap_conns)) {
                kranal_unlink_peer_locked(peer);
        } else {
                cfs_list_for_each_safe(ctmp, cnxt, &peer->rap_conns) {
                        conn = cfs_list_entry(ctmp, kra_conn_t, rac_list);

                        kranal_close_conn_locked(conn, 0);
                }
                /* peer unlinks itself when last conn is closed */
        }
}

int
kranal_del_peer (lnet_nid_t nid)
{
        unsigned long      flags;
        cfs_list_t        *ptmp;
        cfs_list_t        *pnxt;
        kra_peer_t        *peer;
        int                lo;
        int                hi;
        int                i;
        int                rc = -ENOENT;

	write_lock_irqsave(&kranal_data.kra_global_lock, flags);

        if (nid != LNET_NID_ANY)
                lo = hi = kranal_nid2peerlist(nid) - kranal_data.kra_peers;
        else {
                lo = 0;
                hi = kranal_data.kra_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                cfs_list_for_each_safe (ptmp, pnxt, &kranal_data.kra_peers[i]) {
                        peer = cfs_list_entry(ptmp, kra_peer_t, rap_list);
                        LASSERT (peer->rap_persistence > 0 ||
                                 !cfs_list_empty(&peer->rap_conns));

                        if (!(nid == LNET_NID_ANY || peer->rap_nid == nid))
                                continue;

                        kranal_del_peer_locked(peer);
                        rc = 0;         /* matched something */
                }
        }

	write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);

        return rc;
}

kra_conn_t *
kranal_get_conn_by_idx (int index)
{
        kra_peer_t        *peer;
        cfs_list_t        *ptmp;
        kra_conn_t        *conn;
        cfs_list_t        *ctmp;
        int                i;

	read_lock(&kranal_data.kra_global_lock);

        for (i = 0; i < kranal_data.kra_peer_hash_size; i++) {
                cfs_list_for_each (ptmp, &kranal_data.kra_peers[i]) {

                        peer = cfs_list_entry(ptmp, kra_peer_t, rap_list);
                        LASSERT (peer->rap_persistence > 0 ||
                                 !cfs_list_empty(&peer->rap_conns));

                        cfs_list_for_each (ctmp, &peer->rap_conns) {
                                if (index-- > 0)
                                        continue;

                                conn = cfs_list_entry(ctmp, kra_conn_t,
                                                      rac_list);
                                CDEBUG(D_NET, "++conn[%p] -> %s (%d)\n", conn,
                                       libcfs_nid2str(conn->rac_peer->rap_nid),
				       atomic_read(&conn->rac_refcount));
				atomic_inc(&conn->rac_refcount);
				read_unlock(&kranal_data.kra_global_lock);
                                return conn;
                        }
                }
        }

	read_unlock(&kranal_data.kra_global_lock);
        return NULL;
}

int
kranal_close_peer_conns_locked (kra_peer_t *peer, int why)
{
        kra_conn_t         *conn;
        cfs_list_t         *ctmp;
        cfs_list_t         *cnxt;
        int                 count = 0;

        cfs_list_for_each_safe (ctmp, cnxt, &peer->rap_conns) {
                conn = cfs_list_entry(ctmp, kra_conn_t, rac_list);

                count++;
                kranal_close_conn_locked(conn, why);
        }

        return count;
}

int
kranal_close_matching_conns (lnet_nid_t nid)
{
        unsigned long       flags;
        kra_peer_t         *peer;
        cfs_list_t         *ptmp;
        cfs_list_t         *pnxt;
        int                 lo;
        int                 hi;
        int                 i;
        int                 count = 0;

	write_lock_irqsave(&kranal_data.kra_global_lock, flags);

        if (nid != LNET_NID_ANY)
                lo = hi = kranal_nid2peerlist(nid) - kranal_data.kra_peers;
        else {
                lo = 0;
                hi = kranal_data.kra_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                cfs_list_for_each_safe (ptmp, pnxt, &kranal_data.kra_peers[i]) {

                        peer = cfs_list_entry(ptmp, kra_peer_t, rap_list);
                        LASSERT (peer->rap_persistence > 0 ||
                                 !cfs_list_empty(&peer->rap_conns));

                        if (!(nid == LNET_NID_ANY || nid == peer->rap_nid))
                                continue;

                        count += kranal_close_peer_conns_locked(peer, 0);
                }
        }

	write_unlock_irqrestore(&kranal_data.kra_global_lock, flags);

        /* wildcards always succeed */
        if (nid == LNET_NID_ANY)
                return 0;

        return (count == 0) ? -ENOENT : 0;
}

int
kranal_ctl(lnet_ni_t *ni, unsigned int cmd, void *arg)
{
        struct libcfs_ioctl_data *data = arg;
        int                       rc = -EINVAL;

        LASSERT (ni == kranal_data.kra_ni);

        switch(cmd) {
        case IOC_LIBCFS_GET_PEER: {
                lnet_nid_t   nid = 0;
                __u32       ip = 0;
                int         port = 0;
                int         share_count = 0;

                rc = kranal_get_peer_info(data->ioc_count,
                                          &nid, &ip, &port, &share_count);
                data->ioc_nid    = nid;
                data->ioc_count  = share_count;
                data->ioc_u32[0] = ip;
                data->ioc_u32[1] = port;
                break;
        }
        case IOC_LIBCFS_ADD_PEER: {
                rc = kranal_add_persistent_peer(data->ioc_nid,
                                                data->ioc_u32[0], /* IP */
                                                data->ioc_u32[1]); /* port */
                break;
        }
        case IOC_LIBCFS_DEL_PEER: {
                rc = kranal_del_peer(data->ioc_nid);
                break;
        }
        case IOC_LIBCFS_GET_CONN: {
                kra_conn_t *conn = kranal_get_conn_by_idx(data->ioc_count);

                if (conn == NULL)
                        rc = -ENOENT;
                else {
                        rc = 0;
                        data->ioc_nid    = conn->rac_peer->rap_nid;
                        data->ioc_u32[0] = conn->rac_device->rad_id;
                        kranal_conn_decref(conn);
                }
                break;
        }
        case IOC_LIBCFS_CLOSE_CONNECTION: {
                rc = kranal_close_matching_conns(data->ioc_nid);
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
kranal_free_txdescs(cfs_list_t *freelist)
{
        kra_tx_t    *tx;

        while (!cfs_list_empty(freelist)) {
                tx = cfs_list_entry(freelist->next, kra_tx_t, tx_list);

                cfs_list_del(&tx->tx_list);
                LIBCFS_FREE(tx->tx_phys, LNET_MAX_IOV * sizeof(*tx->tx_phys));
                LIBCFS_FREE(tx, sizeof(*tx));
        }
}

int
kranal_alloc_txdescs(cfs_list_t *freelist, int n)
{
        int            i;
        kra_tx_t      *tx;

        LASSERT (freelist == &kranal_data.kra_idle_txs);
        LASSERT (cfs_list_empty(freelist));

        for (i = 0; i < n; i++) {

                LIBCFS_ALLOC(tx, sizeof(*tx));
                if (tx == NULL) {
                        CERROR("Can't allocate tx[%d]\n", i);
                        kranal_free_txdescs(freelist);
                        return -ENOMEM;
                }

                LIBCFS_ALLOC(tx->tx_phys,
                             LNET_MAX_IOV * sizeof(*tx->tx_phys));
                if (tx->tx_phys == NULL) {
                        CERROR("Can't allocate tx[%d]->tx_phys\n", i);

                        LIBCFS_FREE(tx, sizeof(*tx));
                        kranal_free_txdescs(freelist);
                        return -ENOMEM;
                }

                tx->tx_buftype = RANAL_BUF_NONE;
                tx->tx_msg.ram_type = RANAL_MSG_NONE;

                cfs_list_add(&tx->tx_list, freelist);
        }

        return 0;
}

int
kranal_device_init(int id, kra_device_t *dev)
{
        int               total_ntx = *kranal_tunables.kra_ntx;
        RAP_RETURN        rrc;

        dev->rad_id = id;
        rrc = RapkGetDeviceByIndex(id, kranal_device_callback,
                                   &dev->rad_handle);
        if (rrc != RAP_SUCCESS) {
                CERROR("Can't get Rapidarray Device %d: %d\n", id, rrc);
                goto failed_0;
        }

        rrc = RapkReserveRdma(dev->rad_handle, total_ntx);
        if (rrc != RAP_SUCCESS) {
                CERROR("Can't reserve %d RDMA descriptors"
                       " for device %d: %d\n", total_ntx, id, rrc);
                goto failed_1;
        }

        rrc = RapkCreateCQ(dev->rad_handle, total_ntx, RAP_CQTYPE_SEND,
                           &dev->rad_rdma_cqh);
        if (rrc != RAP_SUCCESS) {
                CERROR("Can't create rdma cq size %d for device %d: %d\n",
                       total_ntx, id, rrc);
                goto failed_1;
        }

        rrc = RapkCreateCQ(dev->rad_handle, 
                           *kranal_tunables.kra_fma_cq_size, 
                           RAP_CQTYPE_RECV, &dev->rad_fma_cqh);
        if (rrc != RAP_SUCCESS) {
                CERROR("Can't create fma cq size %d for device %d: %d\n", 
                       *kranal_tunables.kra_fma_cq_size, id, rrc);
                goto failed_2;
        }

        return 0;

 failed_2:
        RapkDestroyCQ(dev->rad_handle, dev->rad_rdma_cqh);
 failed_1:
        RapkReleaseDevice(dev->rad_handle);
 failed_0:
        return -ENODEV;
}

void
kranal_device_fini(kra_device_t *dev)
{
        LASSERT (cfs_list_empty(&dev->rad_ready_conns));
        LASSERT (cfs_list_empty(&dev->rad_new_conns));
        LASSERT (dev->rad_nphysmap == 0);
        LASSERT (dev->rad_nppphysmap == 0);
        LASSERT (dev->rad_nvirtmap == 0);
        LASSERT (dev->rad_nobvirtmap == 0);

        LASSERT(dev->rad_scheduler == NULL);
        RapkDestroyCQ(dev->rad_handle, dev->rad_fma_cqh);
        RapkDestroyCQ(dev->rad_handle, dev->rad_rdma_cqh);
        RapkReleaseDevice(dev->rad_handle);
}

void
kranal_shutdown (lnet_ni_t *ni)
{
        int           i;
        unsigned long flags;

        CDEBUG(D_MALLOC, "before NAL cleanup: kmem %d\n",
	       atomic_read(&libcfs_kmemory));

        LASSERT (ni == kranal_data.kra_ni);
        LASSERT (ni->ni_data == &kranal_data);

        switch (kranal_data.kra_init) {
        default:
                CERROR("Unexpected state %d\n", kranal_data.kra_init);
                LBUG();

        case RANAL_INIT_ALL:
                /* Prevent new peers from being created */
		write_lock_irqsave(&kranal_data.kra_global_lock, flags);
                kranal_data.kra_nonewpeers = 1;
		write_unlock_irqrestore(&kranal_data.kra_global_lock,
                                            flags);

                /* Remove all existing peers from the peer table */
                kranal_del_peer(LNET_NID_ANY);

                /* Wait for pending conn reqs to be handled */
                i = 2;
		spin_lock_irqsave(&kranal_data.kra_connd_lock, flags);
                while (!cfs_list_empty(&kranal_data.kra_connd_acceptq)) {
			spin_unlock_irqrestore(&kranal_data.kra_connd_lock,
                                                   flags);
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* 2**n */
                               "waiting for conn reqs to clean up\n");
                        cfs_pause(cfs_time_seconds(1));

			spin_lock_irqsave(&kranal_data.kra_connd_lock,
                                              flags);
                }
		spin_unlock_irqrestore(&kranal_data.kra_connd_lock, flags);

                /* Wait for all peers to be freed */
                i = 2;
		while (atomic_read(&kranal_data.kra_npeers) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* 2**n */
                               "waiting for %d peers to close down\n",
			       atomic_read(&kranal_data.kra_npeers));
                        cfs_pause(cfs_time_seconds(1));
                }
                /* fall through */

        case RANAL_INIT_DATA:
                break;
        }

        /* Peer state all cleaned up BEFORE setting shutdown, so threads don't
         * have to worry about shutdown races.  NB connections may be created
         * while there are still active connds, but these will be temporary
         * since peer creation always fails after the listener has started to
         * shut down. */
	LASSERT (atomic_read(&kranal_data.kra_npeers) == 0);
        
        /* Flag threads to terminate */
        kranal_data.kra_shutdown = 1;

	for (i = 0; i < kranal_data.kra_ndevs; i++) {
		kra_device_t *dev = &kranal_data.kra_devices[i];

		spin_lock_irqsave(&dev->rad_lock, flags);
		wake_up(&dev->rad_waitq);
		spin_unlock_irqrestore(&dev->rad_lock, flags);
	}

	spin_lock_irqsave(&kranal_data.kra_reaper_lock, flags);
	wake_up_all(&kranal_data.kra_reaper_waitq);
	spin_unlock_irqrestore(&kranal_data.kra_reaper_lock, flags);

	LASSERT (cfs_list_empty(&kranal_data.kra_connd_peers));
	spin_lock_irqsave(&kranal_data.kra_connd_lock, flags);
	wake_up_all(&kranal_data.kra_connd_waitq);
	spin_unlock_irqrestore(&kranal_data.kra_connd_lock, flags);

        /* Wait for threads to exit */
        i = 2;
	while (atomic_read(&kranal_data.kra_nthreads) != 0) {
                i++;
                CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                       "Waiting for %d threads to terminate\n",
		       atomic_read(&kranal_data.kra_nthreads));
                cfs_pause(cfs_time_seconds(1));
        }

	LASSERT (atomic_read(&kranal_data.kra_npeers) == 0);
        if (kranal_data.kra_peers != NULL) {
                for (i = 0; i < kranal_data.kra_peer_hash_size; i++)
                        LASSERT (cfs_list_empty(&kranal_data.kra_peers[i]));

                LIBCFS_FREE(kranal_data.kra_peers,
                            sizeof (cfs_list_t) *
                            kranal_data.kra_peer_hash_size);
        }

	LASSERT (atomic_read(&kranal_data.kra_nconns) == 0);
        if (kranal_data.kra_conns != NULL) {
                for (i = 0; i < kranal_data.kra_conn_hash_size; i++)
                        LASSERT (cfs_list_empty(&kranal_data.kra_conns[i]));

                LIBCFS_FREE(kranal_data.kra_conns,
                            sizeof (cfs_list_t) *
                            kranal_data.kra_conn_hash_size);
        }

        for (i = 0; i < kranal_data.kra_ndevs; i++)
                kranal_device_fini(&kranal_data.kra_devices[i]);

        kranal_free_txdescs(&kranal_data.kra_idle_txs);

        CDEBUG(D_MALLOC, "after NAL cleanup: kmem %d\n",
	       atomic_read(&libcfs_kmemory));

	kranal_data.kra_init = RANAL_INIT_NOTHING;
	module_put(THIS_MODULE);
}

int
kranal_startup (lnet_ni_t *ni)
{
        struct timeval    tv;
	int               pkmem = atomic_read(&libcfs_kmemory);
        int               rc;
        int               i;
        kra_device_t     *dev;
	char		  name[16];

        LASSERT (ni->ni_lnd == &the_kralnd);

        /* Only 1 instance supported */
        if (kranal_data.kra_init != RANAL_INIT_NOTHING) {
                CERROR ("Only 1 instance supported\n");
                return -EPERM;
        }

        if (lnet_set_ip_niaddr(ni) != 0) {
                CERROR ("Can't determine my NID\n");
                return -EPERM;
        }

        if (*kranal_tunables.kra_credits > *kranal_tunables.kra_ntx) {
                CERROR ("Can't set credits(%d) > ntx(%d)\n",
                        *kranal_tunables.kra_credits,
                        *kranal_tunables.kra_ntx);
                return -EINVAL;
        }
        
        memset(&kranal_data, 0, sizeof(kranal_data)); /* zero pointers, flags etc */

        ni->ni_maxtxcredits = *kranal_tunables.kra_credits;
        ni->ni_peertxcredits = *kranal_tunables.kra_peercredits;

        ni->ni_data = &kranal_data;
        kranal_data.kra_ni = ni;

	/* CAVEAT EMPTOR: Every 'Fma' message includes the sender's NID and
	 * a unique (for all time) connstamp so we can uniquely identify
	 * the sender.  The connstamp is an incrementing counter
	 * initialised with seconds + microseconds at startup time.  So we
	 * rely on NOT creating connections more frequently on average than
	 * 1MHz to ensure we don't use old connstamps when we reboot. */
	do_gettimeofday(&tv);
	kranal_data.kra_connstamp =
	kranal_data.kra_peerstamp = (((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;

	rwlock_init(&kranal_data.kra_global_lock);

	for (i = 0; i < RANAL_MAXDEVS; i++ ) {
		kra_device_t  *dev = &kranal_data.kra_devices[i];

		dev->rad_idx = i;
		CFS_INIT_LIST_HEAD(&dev->rad_ready_conns);
		CFS_INIT_LIST_HEAD(&dev->rad_new_conns);
		init_waitqueue_head(&dev->rad_waitq);
		spin_lock_init(&dev->rad_lock);
	}

	kranal_data.kra_new_min_timeout = MAX_SCHEDULE_TIMEOUT;
	init_waitqueue_head(&kranal_data.kra_reaper_waitq);
	spin_lock_init(&kranal_data.kra_reaper_lock);

	CFS_INIT_LIST_HEAD(&kranal_data.kra_connd_acceptq);
	CFS_INIT_LIST_HEAD(&kranal_data.kra_connd_peers);
	init_waitqueue_head(&kranal_data.kra_connd_waitq);
	spin_lock_init(&kranal_data.kra_connd_lock);

        CFS_INIT_LIST_HEAD(&kranal_data.kra_idle_txs);
	spin_lock_init(&kranal_data.kra_tx_lock);

	/* OK to call kranal_api_shutdown() to cleanup now */
	kranal_data.kra_init = RANAL_INIT_DATA;
	try_module_get(THIS_MODULE);

        kranal_data.kra_peer_hash_size = RANAL_PEER_HASH_SIZE;
        LIBCFS_ALLOC(kranal_data.kra_peers,
                     sizeof(cfs_list_t) *
                            kranal_data.kra_peer_hash_size);
        if (kranal_data.kra_peers == NULL)
                goto failed;

        for (i = 0; i < kranal_data.kra_peer_hash_size; i++)
                CFS_INIT_LIST_HEAD(&kranal_data.kra_peers[i]);

        kranal_data.kra_conn_hash_size = RANAL_PEER_HASH_SIZE;
        LIBCFS_ALLOC(kranal_data.kra_conns,
                     sizeof(cfs_list_t) *
                            kranal_data.kra_conn_hash_size);
        if (kranal_data.kra_conns == NULL)
                goto failed;

        for (i = 0; i < kranal_data.kra_conn_hash_size; i++)
                CFS_INIT_LIST_HEAD(&kranal_data.kra_conns[i]);

        rc = kranal_alloc_txdescs(&kranal_data.kra_idle_txs, 
                                  *kranal_tunables.kra_ntx);
        if (rc != 0)
                goto failed;

	rc = kranal_thread_start(kranal_reaper, NULL, "kranal_reaper");
        if (rc != 0) {
                CERROR("Can't spawn ranal reaper: %d\n", rc);
                goto failed;
        }

        for (i = 0; i < *kranal_tunables.kra_n_connd; i++) {
		snprintf(name, sizeof(name), "kranal_connd_%02ld", i);
		rc = kranal_thread_start(kranal_connd,
					 (void *)(unsigned long)i, name);
                if (rc != 0) {
                        CERROR("Can't spawn ranal connd[%d]: %d\n",
                               i, rc);
                        goto failed;
                }
        }

        LASSERT (kranal_data.kra_ndevs == 0);

        /* Use all available RapidArray devices */
        for (i = 0; i < RANAL_MAXDEVS; i++) {
                dev = &kranal_data.kra_devices[kranal_data.kra_ndevs];

                rc = kranal_device_init(kranal_devids[i], dev);
                if (rc == 0)
                        kranal_data.kra_ndevs++;
        }

        if (kranal_data.kra_ndevs == 0) {
                CERROR("Can't initialise any RapidArray devices\n");
                goto failed;
        }
        
        for (i = 0; i < kranal_data.kra_ndevs; i++) {
                dev = &kranal_data.kra_devices[i];
		snprintf(name, sizeof(name), "kranal_sd_%02d", dev->rad_idx);
		rc = kranal_thread_start(kranal_scheduler, dev, name);
                if (rc != 0) {
                        CERROR("Can't spawn ranal scheduler[%d]: %d\n",
                               i, rc);
                        goto failed;
                }
        }

        /* flag everything initialised */
        kranal_data.kra_init = RANAL_INIT_ALL;
        /*****************************************************/

        CDEBUG(D_MALLOC, "initial kmem %d\n", pkmem);
        return 0;

 failed:
        kranal_shutdown(ni);
        return -ENETDOWN;
}

void __exit
kranal_module_fini (void)
{
        lnet_unregister_lnd(&the_kralnd);
        kranal_tunables_fini();
}

int __init
kranal_module_init (void)
{
        int    rc;

        rc = kranal_tunables_init();
        if (rc != 0)
                return rc;

        lnet_register_lnd(&the_kralnd);

        return 0;
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Kernel RapidArray LND v0.01");
MODULE_LICENSE("GPL");

module_init(kranal_module_init);
module_exit(kranal_module_fini);
