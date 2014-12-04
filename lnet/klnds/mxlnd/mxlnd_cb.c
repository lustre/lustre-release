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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 *
 * Copyright (C) 2006 Myricom, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/mxlnd/mxlnd.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 * Author: Scott Atchley <atchley at myri.com>
 */

#include <asm/page.h>
#include "mxlnd.h"

mx_endpoint_addr_t MX_EPA_NULL; /* use to determine if an endpoint is NULL */

inline int
mxlnd_endpoint_addr_null(mx_endpoint_addr_t epa)
{
        /* if memcmp() == 0, it is NULL */
        return !(memcmp(&epa, &MX_EPA_NULL, sizeof(epa)));
}

char *
mxlnd_ctxstate_to_str(int mxc_state)
{
        switch (mxc_state) {
        case MXLND_CTX_INIT:
                return "MXLND_CTX_INIT";
        case MXLND_CTX_IDLE:
                return "MXLND_CTX_IDLE";
        case MXLND_CTX_PREP:
                return "MXLND_CTX_PREP";
        case MXLND_CTX_PENDING:
                return "MXLND_CTX_PENDING";
        case MXLND_CTX_COMPLETED:
                return "MXLND_CTX_COMPLETED";
        case MXLND_CTX_CANCELED:
                return "MXLND_CTX_CANCELED";
        default:
                return "*unknown*";
        }
}

char *
mxlnd_connstatus_to_str(int mxk_status)
{
        switch (mxk_status) {
        case MXLND_CONN_READY:
                return "MXLND_CONN_READY";
        case MXLND_CONN_INIT:
                return "MXLND_CONN_INIT";
        case MXLND_CONN_WAIT:
                return "MXLND_CONN_WAIT";
        case MXLND_CONN_DISCONNECT:
                return "MXLND_CONN_DISCONNECT";
        case MXLND_CONN_FAIL:
                return "MXLND_CONN_FAIL";
        default:
                return "unknown";
        }
}

char *
mxlnd_msgtype_to_str(int type) {
        switch (type) {
        case MXLND_MSG_EAGER:
                return "MXLND_MSG_EAGER";
        case MXLND_MSG_CONN_REQ:
                return "MXLND_MSG_CONN_REQ";
        case MXLND_MSG_CONN_ACK:
                return "MXLND_MSG_CONN_ACK";
        case MXLND_MSG_BYE:
                return "MXLND_MSG_BYE";
        case MXLND_MSG_NOOP:
                return "MXLND_MSG_NOOP";
        case MXLND_MSG_PUT_REQ:
                return "MXLND_MSG_PUT_REQ";
        case MXLND_MSG_PUT_ACK:
                return "MXLND_MSG_PUT_ACK";
        case MXLND_MSG_PUT_DATA:
                return "MXLND_MSG_PUT_DATA";
        case MXLND_MSG_GET_REQ:
                return "MXLND_MSG_GET_REQ";
        case MXLND_MSG_GET_DATA:
                return "MXLND_MSG_GET_DATA";
        default:
                return "unknown";
        }
}

char *
mxlnd_lnetmsg_to_str(int type)
{
        switch (type) {
        case LNET_MSG_ACK:
                return "LNET_MSG_ACK";
        case LNET_MSG_PUT:
                return "LNET_MSG_PUT";
        case LNET_MSG_GET:
                return "LNET_MSG_GET";
        case LNET_MSG_REPLY:
                return "LNET_MSG_REPLY";
        case LNET_MSG_HELLO:
                return "LNET_MSG_HELLO";
        default:
                LBUG();
                return "*unknown*";
        }
}

static inline u64
mxlnd_create_match(kmx_ctx_t *ctx, u8 error)
{
        u64 type        = (u64) ctx->mxc_msg_type;
        u64 err         = (u64) error;
        u64 match       = 0ULL;

        mxlnd_valid_msg_type(ctx->mxc_msg_type);
        LASSERT(ctx->mxc_cookie >> MXLND_ERROR_OFFSET == 0);
        match = (type << MXLND_MSG_OFFSET) | (err << MXLND_ERROR_OFFSET) | ctx->mxc_cookie;
        return match;
}

static inline void
mxlnd_parse_match(u64 match, u8 *msg_type, u8 *error, u64 *cookie)
{
        *msg_type = (u8) MXLND_MSG_TYPE(match);
        *error    = (u8) MXLND_ERROR_VAL(match);
        *cookie   = match & MXLND_MAX_COOKIE;
        mxlnd_valid_msg_type(*msg_type);
        return;
}

kmx_ctx_t *
mxlnd_get_idle_rx(kmx_conn_t *conn)
{
        cfs_list_t              *rxs    = NULL;
        kmx_ctx_t               *rx     = NULL;

        LASSERT(conn != NULL);

        rxs = &conn->mxk_rx_idle;

	spin_lock(&conn->mxk_lock);

	if (cfs_list_empty (rxs)) {
		spin_unlock(&conn->mxk_lock);
		return NULL;
	}

	rx = cfs_list_entry (rxs->next, kmx_ctx_t, mxc_list);
	cfs_list_del_init(&rx->mxc_list);
	spin_unlock(&conn->mxk_lock);

#if MXLND_DEBUG
        if (rx->mxc_get != rx->mxc_put) {
                CNETERR("*** RX get (%llu) != put (%llu) ***\n", rx->mxc_get, rx->mxc_put);
                CNETERR("*** incarnation= %lld ***\n", rx->mxc_incarnation);
                CNETERR("*** deadline= %ld ***\n", rx->mxc_deadline);
                CNETERR("*** state= %s ***\n", mxlnd_ctxstate_to_str(rx->mxc_state));
                CNETERR("*** listed?= %d ***\n", !cfs_list_empty(&rx->mxc_list));
                CNETERR("*** nid= 0x%llx ***\n", rx->mxc_nid);
                CNETERR("*** peer= 0x%p ***\n", rx->mxc_peer);
                CNETERR("*** msg_type= %s ***\n", mxlnd_msgtype_to_str(rx->mxc_msg_type));
                CNETERR("*** cookie= 0x%llx ***\n", rx->mxc_cookie);
                CNETERR("*** nob= %d ***\n", rx->mxc_nob);
        }
#endif
        LASSERT (rx->mxc_get == rx->mxc_put);

        rx->mxc_get++;

        LASSERT (rx->mxc_state == MXLND_CTX_IDLE);
        rx->mxc_state = MXLND_CTX_PREP;
        rx->mxc_deadline = jiffies + MXLND_COMM_TIMEOUT;

        return rx;
}

int
mxlnd_put_idle_rx(kmx_ctx_t *rx)
{
        kmx_conn_t              *conn   = rx->mxc_conn;
        cfs_list_t              *rxs    = &conn->mxk_rx_idle;

        LASSERT(rx->mxc_type == MXLND_REQ_RX);

        mxlnd_ctx_init(rx);

        rx->mxc_put++;
        LASSERT(rx->mxc_get == rx->mxc_put);

	spin_lock(&conn->mxk_lock);
	cfs_list_add(&rx->mxc_list, rxs);
	spin_unlock(&conn->mxk_lock);
	return 0;
}

kmx_ctx_t *
mxlnd_get_idle_tx(void)
{
	cfs_list_t		*tmp    = &kmxlnd_data.kmx_tx_idle;
	kmx_ctx_t		*tx     = NULL;

	spin_lock(&kmxlnd_data.kmx_tx_idle_lock);

	if (cfs_list_empty (&kmxlnd_data.kmx_tx_idle)) {
		CNETERR("%d txs in use\n", kmxlnd_data.kmx_tx_used);
		spin_unlock(&kmxlnd_data.kmx_tx_idle_lock);
		return NULL;
	}

        tmp = &kmxlnd_data.kmx_tx_idle;
        tx = cfs_list_entry (tmp->next, kmx_ctx_t, mxc_list);
        cfs_list_del_init(&tx->mxc_list);

        /* Allocate a new completion cookie.  It might not be needed,
         * but we've got a lock right now and we're unlikely to
         * wrap... */
        tx->mxc_cookie = kmxlnd_data.kmx_tx_next_cookie++;
        if (kmxlnd_data.kmx_tx_next_cookie > MXLND_MAX_COOKIE) {
                kmxlnd_data.kmx_tx_next_cookie = 1;
        }
        kmxlnd_data.kmx_tx_used++;
	spin_unlock(&kmxlnd_data.kmx_tx_idle_lock);

        LASSERT (tx->mxc_get == tx->mxc_put);

        tx->mxc_get++;

        LASSERT (tx->mxc_state == MXLND_CTX_IDLE);
        LASSERT (tx->mxc_lntmsg[0] == NULL);
        LASSERT (tx->mxc_lntmsg[1] == NULL);

        tx->mxc_state = MXLND_CTX_PREP;
        tx->mxc_deadline = jiffies + MXLND_COMM_TIMEOUT;

        return tx;
}

void
mxlnd_conn_disconnect(kmx_conn_t *conn, int mx_dis, int send_bye);

int
mxlnd_put_idle_tx(kmx_ctx_t *tx)
{
        int             result  = 0;
        lnet_msg_t      *lntmsg[2];

        LASSERT(tx->mxc_type == MXLND_REQ_TX);

        if (tx->mxc_status.code != MX_STATUS_SUCCESS || tx->mxc_errno != 0) {
                kmx_conn_t      *conn   = tx->mxc_conn;

                result = -EIO;
                if (tx->mxc_errno != 0) result = tx->mxc_errno;
                /* FIXME should we set mx_dis? */
                mxlnd_conn_disconnect(conn, 0, 1);
        }

        lntmsg[0] = tx->mxc_lntmsg[0];
        lntmsg[1] = tx->mxc_lntmsg[1];

        mxlnd_ctx_init(tx);

        tx->mxc_put++;
        LASSERT(tx->mxc_get == tx->mxc_put);

	spin_lock(&kmxlnd_data.kmx_tx_idle_lock);
	cfs_list_add_tail(&tx->mxc_list, &kmxlnd_data.kmx_tx_idle);
	kmxlnd_data.kmx_tx_used--;
	spin_unlock(&kmxlnd_data.kmx_tx_idle_lock);

	if (lntmsg[0] != NULL)
		lnet_finalize(kmxlnd_data.kmx_ni, lntmsg[0], result);
	if (lntmsg[1] != NULL)
		lnet_finalize(kmxlnd_data.kmx_ni, lntmsg[1], result);
	return 0;
}


void
mxlnd_connparams_free(kmx_connparams_t *cp)
{
        LASSERT(cfs_list_empty(&cp->mxr_list));
        MXLND_FREE(cp, sizeof(*cp));
        return;
}

int
mxlnd_connparams_alloc(kmx_connparams_t **cp, void *context,
                            mx_endpoint_addr_t epa, u64 match, u32 length,
                            kmx_conn_t *conn, kmx_peer_t *peer, void *data)
{
        kmx_connparams_t *c = NULL;

        MXLND_ALLOC(c, sizeof(*c));
        if (!c) return -ENOMEM;

        CFS_INIT_LIST_HEAD(&c->mxr_list);
        c->mxr_context = context;
        c->mxr_epa = epa;
        c->mxr_match = match;
        c->mxr_nob = length;
        c->mxr_conn = conn;
        c->mxr_peer = peer;
        c->mxr_msg = *((kmx_msg_t *) data);

        *cp = c;
        return 0;
}

static inline void
mxlnd_set_conn_status(kmx_conn_t *conn, int status)
{
	conn->mxk_status = status;
	smp_mb();
}

/**
 * mxlnd_conn_free_locked - free the conn
 * @conn - a kmx_conn pointer
 *
 * The calling function should remove the conn from the conns list first
 * then destroy it. Caller should have write-locked kmx_global_lock.
 */
void
mxlnd_conn_free_locked(kmx_conn_t *conn)
{
        int             valid   = !mxlnd_endpoint_addr_null(conn->mxk_epa);
        kmx_peer_t      *peer   = conn->mxk_peer;

        CDEBUG(D_NET, "freeing conn 0x%p *****\n", conn);
        LASSERT (cfs_list_empty (&conn->mxk_tx_credit_queue) &&
                 cfs_list_empty (&conn->mxk_tx_free_queue) &&
                 cfs_list_empty (&conn->mxk_pending));
        if (!cfs_list_empty(&conn->mxk_list)) {
                cfs_list_del_init(&conn->mxk_list);
                if (peer->mxp_conn == conn) {
                        peer->mxp_conn = NULL;
                        if (valid) {
                                kmx_conn_t      *temp   = NULL;

                                mx_get_endpoint_addr_context(conn->mxk_epa,
                                                             (void **) &temp);
                                if (conn == temp) {
                                        mx_set_endpoint_addr_context(conn->mxk_epa,
                                                                     (void *) NULL);
                                }
                        }
                        /* unlink from global list and drop its ref */
                        cfs_list_del_init(&peer->mxp_list);
                        mxlnd_peer_decref(peer);
                }
        }
        mxlnd_peer_decref(peer); /* drop conn's ref to peer */
        if (conn->mxk_rx_pages) {
                LASSERT (conn->mxk_rxs != NULL);
                mxlnd_free_pages(conn->mxk_rx_pages);
        }
        if (conn->mxk_rxs) {
                int             i       = 0;
                kmx_ctx_t       *rx     = NULL;

                for (i = 0; i < MXLND_RX_MSGS(); i++) {
                        rx = &conn->mxk_rxs[i];
                        if (rx->mxc_seg_list != NULL) {
                                LASSERT(rx->mxc_nseg > 0);
                                MXLND_FREE(rx->mxc_seg_list,
                                           rx->mxc_nseg *
                                           sizeof(*rx->mxc_seg_list));
                        }
                }
                MXLND_FREE(conn->mxk_rxs, MXLND_RX_MSGS() * sizeof(kmx_ctx_t));
        }

        MXLND_FREE(conn, sizeof (*conn));
        return;
}


int
mxlnd_conn_cancel_pending_rxs(kmx_conn_t *conn)
{
        int             found   = 0;
        int             count   = 0;
        kmx_ctx_t       *ctx    = NULL;
        kmx_ctx_t       *next   = NULL;
        mx_return_t     mxret   = MX_SUCCESS;
        u32             result  = 0;

        do {
                found = 0;
		spin_lock(&conn->mxk_lock);
                cfs_list_for_each_entry_safe(ctx, next, &conn->mxk_pending,
                                             mxc_list) {
                        cfs_list_del_init(&ctx->mxc_list);
                        if (ctx->mxc_type == MXLND_REQ_RX) {
                                found = 1;
                                mxret = mx_cancel(kmxlnd_data.kmx_endpt,
                                                  &ctx->mxc_mxreq,
                                                  &result);
                                if (mxret != MX_SUCCESS) {
                                        CNETERR("mx_cancel() returned %s (%d)\n", mx_strerror(mxret), mxret);
                                }
                                if (result == 1) {
                                        ctx->mxc_errno = -ECONNABORTED;
                                        ctx->mxc_state = MXLND_CTX_CANCELED;
					spin_unlock(&conn->mxk_lock);
					spin_lock(&kmxlnd_data.kmx_conn_lock);
                                        /* we may be holding the global lock,
                                         * move to orphan list so that it can free it */
                                        cfs_list_add_tail(&ctx->mxc_list,
                                                          &kmxlnd_data.kmx_orphan_msgs);
                                        count++;
					spin_unlock(&kmxlnd_data.kmx_conn_lock);
					spin_lock(&conn->mxk_lock);
				}
				break;
			}
		}
		spin_unlock(&conn->mxk_lock);
	} while (found);

	return count;
}

int
mxlnd_cancel_queued_txs(kmx_conn_t *conn)
{
	int		count   = 0;
	cfs_list_t	*tmp    = NULL;

	spin_lock(&conn->mxk_lock);
        while (!cfs_list_empty(&conn->mxk_tx_free_queue) ||
               !cfs_list_empty(&conn->mxk_tx_credit_queue)) {

                kmx_ctx_t       *tx     = NULL;

                if (!cfs_list_empty(&conn->mxk_tx_free_queue)) {
                        tmp = &conn->mxk_tx_free_queue;
                } else {
                        tmp = &conn->mxk_tx_credit_queue;
                }

                tx = cfs_list_entry(tmp->next, kmx_ctx_t, mxc_list);
                cfs_list_del_init(&tx->mxc_list);
		spin_unlock(&conn->mxk_lock);
		tx->mxc_errno = -ECONNABORTED;
		tx->mxc_state = MXLND_CTX_CANCELED;
		/* move to orphan list and then abort */
		spin_lock(&kmxlnd_data.kmx_conn_lock);
		cfs_list_add_tail(&tx->mxc_list, &kmxlnd_data.kmx_orphan_msgs);
		spin_unlock(&kmxlnd_data.kmx_conn_lock);
		count++;
		spin_lock(&conn->mxk_lock);
	}
	spin_unlock(&conn->mxk_lock);

	return count;
}

void
mxlnd_send_message(mx_endpoint_addr_t epa, u8 msg_type, int error, u64 cookie)
{
        u64 match = (((u64) msg_type) << MXLND_MSG_OFFSET) |
                    (((u64) error) << MXLND_ERROR_OFFSET) | cookie;

        mx_kisend(kmxlnd_data.kmx_endpt, NULL, 0, MX_PIN_PHYSICAL,
                  epa, match, NULL, NULL);
        return;
}

/**
 * mxlnd_conn_disconnect - shutdown a connection
 * @conn - a kmx_conn pointer
 * @mx_dis - call mx_disconnect()
 * @send_bye - send peer a BYE msg
 *
 * This function sets the status to DISCONNECT, completes queued
 * txs with failure, calls mx_disconnect, which will complete
 * pending txs and matched rxs with failure.
 */
void
mxlnd_conn_disconnect(kmx_conn_t *conn, int mx_dis, int send_bye)
{
	mx_endpoint_addr_t	epa	= conn->mxk_epa;
	int			valid	= !mxlnd_endpoint_addr_null(epa);
	int			count	= 0;

	spin_lock(&conn->mxk_lock);
	if (conn->mxk_status == MXLND_CONN_DISCONNECT) {
		spin_unlock(&conn->mxk_lock);
		return;
	}
	mxlnd_set_conn_status(conn, MXLND_CONN_DISCONNECT);
	conn->mxk_timeout = 0;
	spin_unlock(&conn->mxk_lock);

	count = mxlnd_cancel_queued_txs(conn);
	count += mxlnd_conn_cancel_pending_rxs(conn);

	if (count) /* let connd call kmxlnd_abort_msgs() */
		up(&kmxlnd_data.kmx_conn_sem);

        if (send_bye && valid &&
            conn->mxk_peer->mxp_nid != kmxlnd_data.kmx_ni->ni_nid) {
                /* send a BYE to the peer */
                CDEBUG(D_NET, "%s: sending a BYE msg to %s\n", __func__,
                                libcfs_nid2str(conn->mxk_peer->mxp_nid));
                mxlnd_send_message(epa, MXLND_MSG_BYE, 0, 0);
                /* wait to allow the peer to ack our message */
                mxlnd_sleep(msecs_to_jiffies(20));
        }

	if (atomic_read(&kmxlnd_data.kmx_shutdown) != 1) {
		unsigned long   last_msg        = 0;

                /* notify LNET that we are giving up on this peer */
                if (cfs_time_after(conn->mxk_last_rx, conn->mxk_last_tx))
                        last_msg = conn->mxk_last_rx;
                else
                        last_msg = conn->mxk_last_tx;

                lnet_notify(kmxlnd_data.kmx_ni, conn->mxk_peer->mxp_nid, 0, last_msg);

                if (mx_dis && valid &&
                    (memcmp(&epa, &kmxlnd_data.kmx_epa, sizeof(epa) != 0)))
                        mx_disconnect(kmxlnd_data.kmx_endpt, epa);
        }
        mxlnd_conn_decref(conn); /* drop the owning peer's reference */

        return;
}

/**
 * mxlnd_conn_alloc - allocate and initialize a new conn struct
 * @connp - address of a kmx_conn pointer
 * @peer - owning kmx_peer
 *
 * Returns 0 on success and -ENOMEM on failure
 */
int
mxlnd_conn_alloc_locked(kmx_conn_t **connp, kmx_peer_t *peer)
{
        int             i       = 0;
        int             ret     = 0;
        int             ipage   = 0;
        int             offset  = 0;
        void           *addr    = NULL;
        kmx_conn_t     *conn    = NULL;
        kmx_pages_t    *pages   = NULL;
        struct page    *page    = NULL;
        kmx_ctx_t      *rx      = NULL;

        LASSERT(peer != NULL);

        MXLND_ALLOC(conn, sizeof (*conn));
        if (conn == NULL) {
                CNETERR("Cannot allocate conn\n");
                return -ENOMEM;
        }
        CDEBUG(D_NET, "allocated conn 0x%p for peer 0x%p\n", conn, peer);

        memset(conn, 0, sizeof(*conn));

        ret = mxlnd_alloc_pages(&pages, MXLND_RX_MSG_PAGES());
        if (ret != 0) {
                CERROR("Can't allocate rx pages\n");
                MXLND_FREE(conn, sizeof(*conn));
                return -ENOMEM;
        }
        conn->mxk_rx_pages = pages;

        MXLND_ALLOC(conn->mxk_rxs, MXLND_RX_MSGS() * sizeof(kmx_ctx_t));
        if (conn->mxk_rxs == NULL) {
                CERROR("Can't allocate %d rx descriptors\n", MXLND_RX_MSGS());
                mxlnd_free_pages(pages);
                MXLND_FREE(conn, sizeof(*conn));
                return -ENOMEM;
        }

        memset(conn->mxk_rxs, 0, MXLND_RX_MSGS() * sizeof(kmx_ctx_t));

	conn->mxk_peer = peer;
	CFS_INIT_LIST_HEAD(&conn->mxk_list);
	CFS_INIT_LIST_HEAD(&conn->mxk_zombie);
	atomic_set(&conn->mxk_refcount, 2); /* ref for owning peer
						   and one for the caller */
	if (peer->mxp_nid == kmxlnd_data.kmx_ni->ni_nid) {
		u64     nic_id  = 0ULL;
                u32     ep_id   = 0;

                /* this is localhost, set the epa and status as up */
                mxlnd_set_conn_status(conn, MXLND_CONN_READY);
                conn->mxk_epa = kmxlnd_data.kmx_epa;
                mx_set_endpoint_addr_context(conn->mxk_epa, (void *) conn);
                peer->mxp_reconnect_time = 0;
                mx_decompose_endpoint_addr(kmxlnd_data.kmx_epa, &nic_id, &ep_id);
                peer->mxp_nic_id = nic_id;
                peer->mxp_ep_id = ep_id;
                conn->mxk_incarnation = kmxlnd_data.kmx_incarnation;
                conn->mxk_timeout = 0;
        } else {
                /* conn->mxk_incarnation = 0 - will be set by peer */
                /* conn->mxk_sid = 0 - will be set by peer */
                mxlnd_set_conn_status(conn, MXLND_CONN_INIT);
                /* mxk_epa - to be set after mx_iconnect() */
        }
	spin_lock_init(&conn->mxk_lock);
        /* conn->mxk_timeout = 0 */
        /* conn->mxk_last_tx = 0 */
        /* conn->mxk_last_rx = 0 */
        CFS_INIT_LIST_HEAD(&conn->mxk_rx_idle);

        conn->mxk_credits = *kmxlnd_tunables.kmx_peercredits;
        /* mxk_outstanding = 0 */

        CFS_INIT_LIST_HEAD(&conn->mxk_tx_credit_queue);
        CFS_INIT_LIST_HEAD(&conn->mxk_tx_free_queue);
        /* conn->mxk_ntx_msgs = 0 */
        /* conn->mxk_ntx_data = 0 */
        /* conn->mxk_ntx_posted = 0 */
        /* conn->mxk_data_posted = 0 */
        CFS_INIT_LIST_HEAD(&conn->mxk_pending);

        for (i = 0; i < MXLND_RX_MSGS(); i++) {

                rx = &conn->mxk_rxs[i];
                rx->mxc_type = MXLND_REQ_RX;
                CFS_INIT_LIST_HEAD(&rx->mxc_list);

                /* map mxc_msg to page */
                page = pages->mxg_pages[ipage];
                addr = page_address(page);
                LASSERT(addr != NULL);
                rx->mxc_msg = (kmx_msg_t *)(addr + offset);
                rx->mxc_seg.segment_ptr = MX_PA_TO_U64(virt_to_phys(rx->mxc_msg));

                rx->mxc_conn = conn;
                rx->mxc_peer = peer;
                rx->mxc_nid = peer->mxp_nid;

                mxlnd_ctx_init(rx);

                offset += MXLND_MSG_SIZE;
                LASSERT (offset <= PAGE_SIZE);

                if (offset == PAGE_SIZE) {
                        offset = 0;
                        ipage++;
                        LASSERT (ipage <= MXLND_TX_MSG_PAGES());
                }

                cfs_list_add_tail(&rx->mxc_list, &conn->mxk_rx_idle);
        }

        *connp = conn;

        mxlnd_peer_addref(peer);        /* add a ref for this conn */

        /* add to front of peer's conns list */
        cfs_list_add(&conn->mxk_list, &peer->mxp_conns);
        peer->mxp_conn = conn;
        return 0;
}

int
mxlnd_conn_alloc(kmx_conn_t **connp, kmx_peer_t *peer)
{
        int             ret     = 0;
	rwlock_t   *g_lock  = &kmxlnd_data.kmx_global_lock;

	write_lock(g_lock);
        ret = mxlnd_conn_alloc_locked(connp, peer);
	write_unlock(g_lock);
        return ret;
}

int
mxlnd_q_pending_ctx(kmx_ctx_t *ctx)
{
	int		ret	= 0;
	kmx_conn_t	*conn	= ctx->mxc_conn;

	ctx->mxc_state = MXLND_CTX_PENDING;
	if (conn != NULL) {
		spin_lock(&conn->mxk_lock);
                if (conn->mxk_status >= MXLND_CONN_INIT) {
                        cfs_list_add_tail(&ctx->mxc_list, &conn->mxk_pending);
                        if (conn->mxk_timeout == 0 || ctx->mxc_deadline < conn->mxk_timeout) {
                                conn->mxk_timeout = ctx->mxc_deadline;
                        }
                } else {
                        ctx->mxc_state = MXLND_CTX_COMPLETED;
                        ret = -1;
                }
		spin_unlock(&conn->mxk_lock);
	}
	return ret;
}

int
mxlnd_deq_pending_ctx(kmx_ctx_t *ctx)
{
        LASSERT(ctx->mxc_state == MXLND_CTX_PENDING ||
                ctx->mxc_state == MXLND_CTX_COMPLETED);
        if (ctx->mxc_state != MXLND_CTX_PENDING &&
            ctx->mxc_state != MXLND_CTX_COMPLETED) {
                CNETERR("deq ctx->mxc_state = %s\n",
                        mxlnd_ctxstate_to_str(ctx->mxc_state));
        }
        ctx->mxc_state = MXLND_CTX_COMPLETED;
        if (!cfs_list_empty(&ctx->mxc_list)) {
                kmx_conn_t      *conn = ctx->mxc_conn;
                kmx_ctx_t       *next = NULL;

                LASSERT(conn != NULL);
		spin_lock(&conn->mxk_lock);
                cfs_list_del_init(&ctx->mxc_list);
                conn->mxk_timeout = 0;
                if (!cfs_list_empty(&conn->mxk_pending)) {
                        next = cfs_list_entry(conn->mxk_pending.next,
                                              kmx_ctx_t, mxc_list);
                        conn->mxk_timeout = next->mxc_deadline;
                }
		spin_unlock(&conn->mxk_lock);
	}
	return 0;
}

/**
 * mxlnd_peer_free - free the peer
 * @peer - a kmx_peer pointer
 *
 * The calling function should decrement the rxs, drain the tx queues and
 * remove the peer from the peers list first then destroy it.
 */
void
mxlnd_peer_free(kmx_peer_t *peer)
{
	CDEBUG(D_NET, "freeing peer 0x%p %s\n", peer, libcfs_nid2str(peer->mxp_nid));

	LASSERT (atomic_read(&peer->mxp_refcount) == 0);

	if (!cfs_list_empty(&peer->mxp_list)) {
		/* assume we are locked */
		cfs_list_del_init(&peer->mxp_list);
	}

	MXLND_FREE(peer, sizeof (*peer));
	atomic_dec(&kmxlnd_data.kmx_npeers);
	return;
}

static int
mxlnd_lookup_mac(u32 ip, u64 *tmp_id)
{
        int                     ret     = -EHOSTUNREACH;
        unsigned char           *haddr  = NULL;
        struct net_device       *dev    = NULL;
        struct neighbour        *n      = NULL;
        __be32                  dst_ip  = htonl(ip);

        dev = dev_get_by_name(*kmxlnd_tunables.kmx_default_ipif);
        if (dev == NULL)
                return -ENODEV;

        haddr = (unsigned char *) tmp_id + 2; /* MAC is only 6 bytes */

        n = neigh_lookup(&arp_tbl, &dst_ip, dev);
        if (n) {
                n->used = jiffies;
                if (n->nud_state & NUD_VALID) {
                        memcpy(haddr, n->ha, dev->addr_len);
                        neigh_release(n);
                        ret = 0;
                }
        }

        dev_put(dev);

        return ret;
}


/* We only want the MAC address of the peer's Myricom NIC. We
 * require that each node has the IPoMX interface (myriN) up.
 * We will not pass any traffic over IPoMX, but it allows us
 * to get the MAC address. */
static int
mxlnd_ip2nic_id(u32 ip, u64 *nic_id, int tries)
{
        int                     ret     = 0;
        int                     try     = 1;
        int                     fatal   = 0;
        u64                     tmp_id  = 0ULL;
        cfs_socket_t            *sock   = NULL;

        do {
                CDEBUG(D_NET, "try %d of %d tries\n", try, tries);
                ret = mxlnd_lookup_mac(ip, &tmp_id);
                if (ret == 0) {
                        break;
                } else {
                        /* not found, try to connect (force an arp) */
                        ret = libcfs_sock_connect(&sock, &fatal, 0, 0, ip, 987);
                        if (ret == -ECONNREFUSED) {
                                /* peer is there, get the MAC address */
                                mxlnd_lookup_mac(ip, &tmp_id);
                                if (tmp_id != 0ULL)
                                        ret = 0;
                                break;
			} else if (ret == -EHOSTUNREACH && try < tries) {
				/* add a little backoff */
				CDEBUG(D_NET, "sleeping for %lu jiffies\n",
				       msecs_to_jiffies(MSEC_PER_SEC / 4));
				mxlnd_sleep(msecs_to_jiffies(MSEC_PER_SEC / 4));
			}
                }
        } while (try++ < tries);
        CDEBUG(D_NET, "done trying. ret = %d\n", ret);

        if (tmp_id == 0ULL)
                ret = -EHOSTUNREACH;
#if __BYTE_ORDER == __LITTLE_ENDIAN
        *nic_id = ___arch__swab64(tmp_id);
#else
        *nic_id = tmp_id;
#endif
        return ret;
}

/**
 * mxlnd_peer_alloc - allocate and initialize a new peer struct
 * @peerp - address of a kmx_peer pointer
 * @nid - LNET node id
 *
 * Returns 0 on success and -ENOMEM on failure
 */
int
mxlnd_peer_alloc(kmx_peer_t **peerp, lnet_nid_t nid, u32 board, u32 ep_id, u64 nic_id)
{
        int             ret     = 0;
        u32             ip      = LNET_NIDADDR(nid);
        kmx_peer_t     *peer    = NULL;

        LASSERT (nid != LNET_NID_ANY && nid != 0LL);

        MXLND_ALLOC(peer, sizeof (*peer));
        if (peer == NULL) {
                CNETERR("Cannot allocate peer for NID 0x%llx\n",
                       nid);
                return -ENOMEM;
        }
        CDEBUG(D_NET, "allocated peer 0x%p for NID 0x%llx\n", peer, nid);

        memset(peer, 0, sizeof(*peer));

	CFS_INIT_LIST_HEAD(&peer->mxp_list);
	peer->mxp_nid = nid;
	/* peer->mxp_ni unused - may be used for multi-rail */
	atomic_set(&peer->mxp_refcount, 1);     /* ref for kmx_peers list */

        peer->mxp_board = board;
        peer->mxp_ep_id = ep_id;
        peer->mxp_nic_id = nic_id;

        CFS_INIT_LIST_HEAD(&peer->mxp_conns);
        ret = mxlnd_conn_alloc(&peer->mxp_conn, peer); /* adds 2nd conn ref here... */
        if (ret != 0) {
                mxlnd_peer_decref(peer);
                return ret;
        }
        CFS_INIT_LIST_HEAD(&peer->mxp_tx_queue);

        if (peer->mxp_nic_id != 0ULL)
                nic_id = peer->mxp_nic_id;

        if (nic_id == 0ULL) {
                ret = mxlnd_ip2nic_id(ip, &nic_id, 1);
                if (ret == 0) {
                        peer->mxp_nic_id = nic_id;
                        mx_nic_id_to_board_number(nic_id, &peer->mxp_board);
                }
        }

        peer->mxp_nic_id = nic_id; /* may be 0ULL if ip2nic_id() failed */

        /* peer->mxp_reconnect_time = 0 */
        /* peer->mxp_incompatible = 0 */

        *peerp = peer;
        return 0;
}

static inline kmx_peer_t *
mxlnd_find_peer_by_nid_locked(lnet_nid_t nid)
{
        int             found   = 0;
        int             hash    = 0;
        kmx_peer_t      *peer   = NULL;

        hash = mxlnd_nid_to_hash(nid);

        cfs_list_for_each_entry(peer, &kmxlnd_data.kmx_peers[hash], mxp_list) {
                if (peer->mxp_nid == nid) {
                        found = 1;
                        mxlnd_peer_addref(peer);
                        break;
                }
        }
        return (found ? peer : NULL);
}

static kmx_peer_t *
mxlnd_find_peer_by_nid(lnet_nid_t nid, int create)
{
        int             ret     = 0;
        int             hash    = 0;
        kmx_peer_t      *peer   = NULL;
        kmx_peer_t      *old    = NULL;
	rwlock_t    *g_lock = &kmxlnd_data.kmx_global_lock;

	read_lock(g_lock);
        peer = mxlnd_find_peer_by_nid_locked(nid); /* adds peer ref */

        if ((peer && peer->mxp_conn) || /* found peer with conn or */
            (!peer && !create)) {       /* did not find peer and do not create one */
		read_unlock(g_lock);
                return peer;
        }

	read_unlock(g_lock);

        /* if peer but _not_ conn */
        if (peer && !peer->mxp_conn) {
                if (create) {
			write_lock(g_lock);
                        if (!peer->mxp_conn) { /* check again */
                                /* create the conn */
                                ret = mxlnd_conn_alloc_locked(&peer->mxp_conn, peer);
                                if (ret != 0) {
                                        /* we tried, return the peer only.
                                         * the caller needs to see if the conn exists */
                                        CNETERR("%s: %s could not alloc conn\n",
                                        __func__, libcfs_nid2str(peer->mxp_nid));
                                } else {
                                        /* drop extra conn ref */
                                        mxlnd_conn_decref(peer->mxp_conn);
                                }
                        }
			write_unlock(g_lock);
                }
                return peer;
        }

        /* peer not found and we need to create one */
        hash = mxlnd_nid_to_hash(nid);

        /* create peer (and conn) */
        /* adds conn ref for peer and one for this function */
        ret = mxlnd_peer_alloc(&peer, nid, *kmxlnd_tunables.kmx_board,
                               *kmxlnd_tunables.kmx_ep_id, 0ULL);
        if (ret != 0) /* no memory, peer is NULL */
                return NULL;

	write_lock(g_lock);

        /* look again */
        old = mxlnd_find_peer_by_nid_locked(nid);
        if (old) {
                /* someone already created one */
                mxlnd_conn_decref(peer->mxp_conn); /* drop ref taken above.. */
                mxlnd_conn_decref(peer->mxp_conn); /* drop peer's ref */
                mxlnd_peer_decref(peer);
                peer = old;
        } else {
		/* no other peer, use this one */
		cfs_list_add_tail(&peer->mxp_list,
				  &kmxlnd_data.kmx_peers[hash]);
		atomic_inc(&kmxlnd_data.kmx_npeers);
		mxlnd_peer_addref(peer);
		mxlnd_conn_decref(peer->mxp_conn); /* drop ref from peer_alloc */
        }

	write_unlock(g_lock);

        return peer;
}

static inline int
mxlnd_tx_requires_credit(kmx_ctx_t *tx)
{
        return (tx->mxc_msg_type == MXLND_MSG_EAGER ||
                tx->mxc_msg_type == MXLND_MSG_GET_REQ ||
                tx->mxc_msg_type == MXLND_MSG_PUT_REQ ||
                tx->mxc_msg_type == MXLND_MSG_NOOP);
}

/**
 * mxlnd_init_msg - set type and number of bytes
 * @msg - msg pointer
 * @type - of message
 * @body_nob - bytes in msg body
 */
static inline void
mxlnd_init_msg(kmx_msg_t *msg, u8 type, int body_nob)
{
        msg->mxm_type = type;
        msg->mxm_nob  = offsetof(kmx_msg_t, mxm_u) + body_nob;
}

static inline void
mxlnd_init_tx_msg (kmx_ctx_t *tx, u8 type, int body_nob, lnet_nid_t nid)
{
        int             nob     = offsetof (kmx_msg_t, mxm_u) + body_nob;
        kmx_msg_t       *msg    = NULL;

        LASSERT (tx != NULL);
        LASSERT (nob <= MXLND_MSG_SIZE);

        tx->mxc_nid = nid;
        /* tx->mxc_peer should have already been set if we know it */
        tx->mxc_msg_type = type;
        tx->mxc_nseg = 1;
        /* tx->mxc_seg.segment_ptr is already pointing to mxc_page */
        tx->mxc_seg.segment_length = nob;
        tx->mxc_pin_type = MX_PIN_PHYSICAL;

        msg = tx->mxc_msg;
        msg->mxm_type = type;
        msg->mxm_nob  = nob;

        return;
}

static inline __u32
mxlnd_cksum (void *ptr, int nob)
{
        char  *c  = ptr;
        __u32  sum = 0;

        while (nob-- > 0)
                sum = ((sum << 1) | (sum >> 31)) + *c++;

        /* ensure I don't return 0 (== no checksum) */
        return (sum == 0) ? 1 : sum;
}

/**
 * mxlnd_pack_msg_locked - complete msg info
 * @tx - msg to send
 */
static inline void
mxlnd_pack_msg_locked(kmx_ctx_t *tx)
{
        kmx_msg_t       *msg    = tx->mxc_msg;

        /* type and nob should already be set in init_msg() */
        msg->mxm_magic    = MXLND_MSG_MAGIC;
        msg->mxm_version  = MXLND_MSG_VERSION;
        /*   mxm_type */
        /* don't use mxlnd_tx_requires_credit() since we want PUT_ACK to
         * return credits as well */
        if (tx->mxc_msg_type != MXLND_MSG_CONN_REQ &&
            tx->mxc_msg_type != MXLND_MSG_CONN_ACK) {
                msg->mxm_credits  = tx->mxc_conn->mxk_outstanding;
                tx->mxc_conn->mxk_outstanding = 0;
        } else {
                msg->mxm_credits  = 0;
        }
        /*   mxm_nob */
        msg->mxm_cksum    = 0;
        msg->mxm_srcnid   = kmxlnd_data.kmx_ni->ni_nid;
        msg->mxm_srcstamp = kmxlnd_data.kmx_incarnation;
        msg->mxm_dstnid   = tx->mxc_nid;
        /* if it is a new peer, the dststamp will be 0 */
        msg->mxm_dststamp = tx->mxc_conn->mxk_incarnation;

        if (*kmxlnd_tunables.kmx_cksum) {
                msg->mxm_cksum = mxlnd_cksum(msg, msg->mxm_nob);
        }
}

int
mxlnd_unpack_msg(kmx_msg_t *msg, int nob)
{
        const int hdr_size      = offsetof(kmx_msg_t, mxm_u);
        __u32     msg_cksum     = 0;
        int       flip          = 0;
        int       msg_nob       = 0;

        /* 6 bytes are enough to have received magic + version */
        if (nob < 6) {
                CNETERR("not enough bytes for magic + hdr: %d\n", nob);
                return -EPROTO;
        }

        if (msg->mxm_magic == MXLND_MSG_MAGIC) {
                flip = 0;
        } else if (msg->mxm_magic == __swab32(MXLND_MSG_MAGIC)) {
                flip = 1;
        } else {
                CNETERR("Bad magic: %08x\n", msg->mxm_magic);
                return -EPROTO;
        }

        if (msg->mxm_version !=
            (flip ? __swab16(MXLND_MSG_VERSION) : MXLND_MSG_VERSION)) {
                CNETERR("Bad version: %d\n", msg->mxm_version);
                return -EPROTO;
        }

        if (nob < hdr_size) {
                CNETERR("not enough for a header: %d\n", nob);
                return -EPROTO;
        }

        msg_nob = flip ? __swab32(msg->mxm_nob) : msg->mxm_nob;
        if (msg_nob > nob) {
                CNETERR("Short message: got %d, wanted %d\n", nob, msg_nob);
                return -EPROTO;
        }

        /* checksum must be computed with mxm_cksum zero and BEFORE anything
         * gets flipped */
        msg_cksum = flip ? __swab32(msg->mxm_cksum) : msg->mxm_cksum;
        msg->mxm_cksum = 0;
        if (msg_cksum != 0 && msg_cksum != mxlnd_cksum(msg, msg_nob)) {
                CNETERR("Bad checksum\n");
                return -EPROTO;
        }
        msg->mxm_cksum = msg_cksum;

        if (flip) {
                /* leave magic unflipped as a clue to peer endianness */
                __swab16s(&msg->mxm_version);
                CLASSERT (sizeof(msg->mxm_type) == 1);
                CLASSERT (sizeof(msg->mxm_credits) == 1);
                msg->mxm_nob = msg_nob;
                __swab64s(&msg->mxm_srcnid);
                __swab64s(&msg->mxm_srcstamp);
                __swab64s(&msg->mxm_dstnid);
                __swab64s(&msg->mxm_dststamp);
        }

        if (msg->mxm_srcnid == LNET_NID_ANY) {
                CNETERR("Bad src nid: %s\n", libcfs_nid2str(msg->mxm_srcnid));
                return -EPROTO;
        }

        switch (msg->mxm_type) {
        default:
                CNETERR("Unknown message type %x\n", msg->mxm_type);
                return -EPROTO;

        case MXLND_MSG_NOOP:
                break;

        case MXLND_MSG_EAGER:
                if (msg_nob < offsetof(kmx_msg_t, mxm_u.eager.mxem_payload[0])) {
                        CNETERR("Short EAGER: %d(%d)\n", msg_nob,
                               (int)offsetof(kmx_msg_t, mxm_u.eager.mxem_payload[0]));
                        return -EPROTO;
                }
                break;

        case MXLND_MSG_PUT_REQ:
                if (msg_nob < hdr_size + sizeof(msg->mxm_u.put_req)) {
                        CNETERR("Short PUT_REQ: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->mxm_u.put_req)));
                        return -EPROTO;
                }
                if (flip)
                        __swab64s(&msg->mxm_u.put_req.mxprm_cookie);
                break;

        case MXLND_MSG_PUT_ACK:
                if (msg_nob < hdr_size + sizeof(msg->mxm_u.put_ack)) {
                        CNETERR("Short PUT_ACK: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->mxm_u.put_ack)));
                        return -EPROTO;
                }
                if (flip) {
                        __swab64s(&msg->mxm_u.put_ack.mxpam_src_cookie);
                        __swab64s(&msg->mxm_u.put_ack.mxpam_dst_cookie);
                }
                break;

        case MXLND_MSG_GET_REQ:
                if (msg_nob < hdr_size + sizeof(msg->mxm_u.get_req)) {
                        CNETERR("Short GET_REQ: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->mxm_u.get_req)));
                        return -EPROTO;
                }
                if (flip) {
                        __swab64s(&msg->mxm_u.get_req.mxgrm_cookie);
                }
                break;

        case MXLND_MSG_CONN_REQ:
        case MXLND_MSG_CONN_ACK:
                if (msg_nob < hdr_size + sizeof(msg->mxm_u.conn_req)) {
                        CNETERR("Short connreq/ack: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->mxm_u.conn_req)));
                        return -EPROTO;
                }
                if (flip) {
                        __swab32s(&msg->mxm_u.conn_req.mxcrm_queue_depth);
                        __swab32s(&msg->mxm_u.conn_req.mxcrm_eager_size);
                }
                break;
        }
        return 0;
}


/**
 * mxlnd_recv_msg
 * @lntmsg - the LNET msg that this is continuing. If EAGER, then NULL.
 * @rx
 * @msg_type
 * @cookie
 * @length - length of incoming message
 * @pending - add to kmx_pending (0 is NO and 1 is YES)
 *
 * The caller gets the rx and sets nid, peer and conn if known.
 *
 * Returns 0 on success and -1 on failure
 */
int
mxlnd_recv_msg(lnet_msg_t *lntmsg, kmx_ctx_t *rx, u8 msg_type, u64 cookie, u32 length)
{
        int             ret     = 0;
        mx_return_t     mxret   = MX_SUCCESS;
        uint64_t        mask    = ~(MXLND_ERROR_MASK);

        rx->mxc_msg_type = msg_type;
        rx->mxc_lntmsg[0] = lntmsg; /* may be NULL if EAGER */
        rx->mxc_cookie = cookie;
        /* rx->mxc_match may already be set */
        /* rx->mxc_seg.segment_ptr is already set */
        rx->mxc_seg.segment_length = length;
        ret = mxlnd_q_pending_ctx(rx);
        if (ret == -1) {
                /* the caller is responsible for calling conn_decref() if needed */
                return -1;
        }
        mxret = mx_kirecv(kmxlnd_data.kmx_endpt, &rx->mxc_seg, 1, MX_PIN_PHYSICAL,
                          cookie, mask, (void *) rx, &rx->mxc_mxreq);
        if (mxret != MX_SUCCESS) {
                mxlnd_deq_pending_ctx(rx);
                CNETERR("mx_kirecv() failed with %s (%d)\n",
                        mx_strerror(mxret), (int) mxret);
                return -1;
        }
        return 0;
}


/**
 * mxlnd_unexpected_recv - this is the callback function that will handle
 *                         unexpected receives
 * @context - NULL, ignore
 * @source - the peer's mx_endpoint_addr_t
 * @match_value - the msg's bits, should be MXLND_MSG_EAGER
 * @length - length of incoming message
 * @data_if_available - used for CONN_[REQ|ACK]
 *
 * If it is an eager-sized msg, we will call recv_msg() with the actual
 * length. If it is a large message, we will call recv_msg() with a
 * length of 0 bytes to drop it because we should never have a large,
 * unexpected message.
 *
 * NOTE - The MX library blocks until this function completes. Make it as fast as
 * possible. DO NOT allocate memory which can block!
 *
 * If we cannot get a rx or the conn is closed, drop the message on the floor
 * (i.e. recv 0 bytes and ignore).
 */
mx_unexp_handler_action_t
mxlnd_unexpected_recv(void *context, mx_endpoint_addr_t source,
                 uint64_t match_value, uint32_t length, void *data_if_available)
{
        int             ret             = 0;
        kmx_ctx_t       *rx             = NULL;
        mx_ksegment_t   seg;
        u8              msg_type        = 0;
        u8              error           = 0;
        u64             cookie          = 0ULL;
        kmx_conn_t      *conn           = NULL;
        kmx_peer_t      *peer           = NULL;
        u64             nic_id          = 0ULL;
        u32             ep_id           = 0;
        u32             sid             = 0;

        /* TODO this will change to the net struct */
        if (context != NULL) {
                CNETERR("non-NULL context\n");
        }

#if MXLND_DEBUG
        CDEBUG(D_NET, "bits=0x%llx length=%d\n", match_value, length);
#endif

        mx_decompose_endpoint_addr2(source, &nic_id, &ep_id, &sid);
        mxlnd_parse_match(match_value, &msg_type, &error, &cookie);
	read_lock(&kmxlnd_data.kmx_global_lock);
        mx_get_endpoint_addr_context(source, (void **) &conn);
        if (conn) {
                mxlnd_conn_addref(conn); /* add ref for this function */
                peer = conn->mxk_peer;
        }
	read_unlock(&kmxlnd_data.kmx_global_lock);

        if (msg_type == MXLND_MSG_BYE) {
                if (conn) {
                        CDEBUG(D_NET, "peer %s sent BYE msg\n",
                                        libcfs_nid2str(peer->mxp_nid));
                        mxlnd_conn_disconnect(conn, 1, 0);
                        mxlnd_conn_decref(conn); /* drop ref taken above */
                }
                return MX_RECV_FINISHED;
        }

        if (msg_type == MXLND_MSG_CONN_REQ) {
                kmx_connparams_t       *cp      = NULL;
                const int       expected        = offsetof(kmx_msg_t, mxm_u) +
                                                  sizeof(kmx_connreq_msg_t);

                if (conn) mxlnd_conn_decref(conn); /* drop ref taken above */
                if (unlikely(length != expected || !data_if_available)) {
                        CNETERR("received invalid CONN_REQ from %llx "
                                "length=%d (expected %d)\n", nic_id, length, expected);
                        mxlnd_send_message(source, MXLND_MSG_CONN_ACK, EPROTO, 0);
                        return MX_RECV_FINISHED;
                }

                ret = mxlnd_connparams_alloc(&cp, context, source, match_value, length,
                                         conn, peer, data_if_available);
                if (unlikely(ret != 0)) {
                        CNETERR("unable to alloc CONN_REQ from %llx:%d\n",
                                nic_id, ep_id);
                        mxlnd_send_message(source, MXLND_MSG_CONN_ACK, ENOMEM, 0);
                        return MX_RECV_FINISHED;
                }
		spin_lock(&kmxlnd_data.kmx_conn_lock);
		cfs_list_add_tail(&cp->mxr_list, &kmxlnd_data.kmx_conn_reqs);
		spin_unlock(&kmxlnd_data.kmx_conn_lock);
		up(&kmxlnd_data.kmx_conn_sem);
		return MX_RECV_FINISHED;
	}
        if (msg_type == MXLND_MSG_CONN_ACK) {
                kmx_connparams_t  *cp           = NULL;
                const int       expected        = offsetof(kmx_msg_t, mxm_u) +
                                                  sizeof(kmx_connreq_msg_t);

                LASSERT(conn);
                if (unlikely(error != 0)) {
                        CNETERR("received CONN_ACK from %s with error -%d\n",
                               libcfs_nid2str(peer->mxp_nid), (int) error);
                        mxlnd_conn_disconnect(conn, 1, 0);
                } else if (unlikely(length != expected || !data_if_available)) {
                        CNETERR("received %s CONN_ACK from %s "
                               "length=%d (expected %d)\n",
                               data_if_available ? "short" : "missing",
                               libcfs_nid2str(peer->mxp_nid), length, expected);
                        mxlnd_conn_disconnect(conn, 1, 1);
                } else {
                        /* peer is ready for messages */
                        ret = mxlnd_connparams_alloc(&cp, context, source, match_value, length,
                                         conn, peer, data_if_available);
                        if (unlikely(ret != 0)) {
                                CNETERR("unable to alloc kmx_connparams_t"
                                               " from %llx:%d\n", nic_id, ep_id);
                                mxlnd_conn_disconnect(conn, 1, 1);
			} else {
				spin_lock(&kmxlnd_data.kmx_conn_lock);
				cfs_list_add_tail(&cp->mxr_list,
						  &kmxlnd_data.kmx_conn_reqs);
				spin_unlock(&kmxlnd_data.kmx_conn_lock);
				up(&kmxlnd_data.kmx_conn_sem);
			}
                }
                mxlnd_conn_decref(conn); /* drop ref taken above */

                return MX_RECV_FINISHED;
        }

        /* Handle unexpected messages (PUT_REQ and GET_REQ) */

        LASSERT(peer != NULL && conn != NULL);

        rx = mxlnd_get_idle_rx(conn);
        if (rx != NULL) {
                if (length <= MXLND_MSG_SIZE) {
                        ret = mxlnd_recv_msg(NULL, rx, msg_type, match_value, length);
                } else {
                        CNETERR("unexpected large receive with "
                                "match_value=0x%llx length=%d\n",
                                match_value, length);
                        ret = mxlnd_recv_msg(NULL, rx, msg_type, match_value, 0);
                }

                if (ret == 0) {
                        /* hold conn ref until rx completes */
                        rx->mxc_conn = conn;
                        rx->mxc_peer = peer;
                        rx->mxc_nid = peer->mxp_nid;
                } else {
                        CNETERR("could not post receive\n");
                        mxlnd_put_idle_rx(rx);
                }
        }

        /* Encountered error, drop incoming message on the floor */
        /* We could use MX_RECV_FINISHED but posting the receive of 0 bytes
         * uses the standard code path and acks the sender normally */

        if (rx == NULL || ret != 0) {
                mxlnd_conn_decref(conn); /* drop ref taken above */
                if (rx == NULL) {
                        CNETERR("no idle rxs available - dropping rx"
                                " 0x%llx from %s\n", match_value,
                                libcfs_nid2str(peer->mxp_nid));
                } else {
                        /* ret != 0 */
                        CNETERR("disconnected peer - dropping rx\n");
                }
                seg.segment_ptr = 0ULL;
                seg.segment_length = 0;
                mx_kirecv(kmxlnd_data.kmx_endpt, &seg, 1, MX_PIN_PHYSICAL,
                          match_value, ~0ULL, NULL, NULL);
        }

        return MX_RECV_CONTINUE;
}


int
mxlnd_get_peer_info(int index, lnet_nid_t *nidp, int *count)
{
        int              i      = 0;
        int              ret    = -ENOENT;
        kmx_peer_t      *peer   = NULL;

	read_lock(&kmxlnd_data.kmx_global_lock);
        for (i = 0; i < MXLND_HASH_SIZE; i++) {
                cfs_list_for_each_entry(peer, &kmxlnd_data.kmx_peers[i],
                                        mxp_list) {
			if (index-- == 0) {
				*nidp = peer->mxp_nid;
				*count = atomic_read(&peer->mxp_refcount);
				ret = 0;
				break;
			}
                }
        }
	read_unlock(&kmxlnd_data.kmx_global_lock);

        return ret;
}

void
mxlnd_del_peer_locked(kmx_peer_t *peer)
{
        if (peer->mxp_conn) {
                mxlnd_conn_disconnect(peer->mxp_conn, 1, 1);
        } else {
                cfs_list_del_init(&peer->mxp_list); /* remove from the global list */
                mxlnd_peer_decref(peer); /* drop global list ref */
        }
        return;
}

int
mxlnd_del_peer(lnet_nid_t nid)
{
        int             i       = 0;
        int             ret     = 0;
        kmx_peer_t      *peer   = NULL;
        kmx_peer_t      *next   = NULL;

        if (nid != LNET_NID_ANY) {
                peer = mxlnd_find_peer_by_nid(nid, 0); /* adds peer ref */
        }
	write_lock(&kmxlnd_data.kmx_global_lock);
        if (nid != LNET_NID_ANY) {
                if (peer == NULL) {
                        ret = -ENOENT;
                } else {
                        mxlnd_peer_decref(peer); /* and drops it */
                        mxlnd_del_peer_locked(peer);
                }
        } else { /* LNET_NID_ANY */
                for (i = 0; i < MXLND_HASH_SIZE; i++) {
                        cfs_list_for_each_entry_safe(peer, next,
                                                     &kmxlnd_data.kmx_peers[i],
                                                     mxp_list) {
                                mxlnd_del_peer_locked(peer);
                        }
                }
        }
	write_unlock(&kmxlnd_data.kmx_global_lock);

        return ret;
}

kmx_conn_t *
mxlnd_get_conn_by_idx(int index)
{
        int              i      = 0;
        kmx_peer_t      *peer   = NULL;
        kmx_conn_t      *conn   = NULL;

	read_lock(&kmxlnd_data.kmx_global_lock);
        for (i = 0; i < MXLND_HASH_SIZE; i++) {
                cfs_list_for_each_entry(peer, &kmxlnd_data.kmx_peers[i],
                                        mxp_list) {
                        cfs_list_for_each_entry(conn, &peer->mxp_conns,
                                                mxk_list) {
                                if (index-- > 0) {
                                        continue;
                                }

                                mxlnd_conn_addref(conn); /* add ref here, dec in ctl() */
				read_unlock(&kmxlnd_data.kmx_global_lock);
                                return conn;
                        }
                }
        }
	read_unlock(&kmxlnd_data.kmx_global_lock);

        return NULL;
}

void
mxlnd_close_matching_conns_locked(kmx_peer_t *peer)
{
        kmx_conn_t      *conn   = NULL;
        kmx_conn_t      *next   = NULL;

        cfs_list_for_each_entry_safe(conn, next, &peer->mxp_conns, mxk_list)
                mxlnd_conn_disconnect(conn, 0, 1);

        return;
}

int
mxlnd_close_matching_conns(lnet_nid_t nid)
{
        int             i       = 0;
        int             ret     = 0;
        kmx_peer_t      *peer   = NULL;

	write_lock(&kmxlnd_data.kmx_global_lock);
        if (nid != LNET_NID_ANY) {
                peer = mxlnd_find_peer_by_nid_locked(nid); /* adds peer ref */
                if (peer == NULL) {
                        ret = -ENOENT;
                } else {
                        mxlnd_close_matching_conns_locked(peer);
                        mxlnd_peer_decref(peer); /* and drops it here */
                }
        } else { /* LNET_NID_ANY */
                for (i = 0; i < MXLND_HASH_SIZE; i++) {
                        cfs_list_for_each_entry(peer, &kmxlnd_data.kmx_peers[i],                                                mxp_list)
                                mxlnd_close_matching_conns_locked(peer);
                }
        }
	write_unlock(&kmxlnd_data.kmx_global_lock);

        return ret;
}

/**
 * mxlnd_ctl - modify MXLND parameters
 * @ni - LNET interface handle
 * @cmd - command to change
 * @arg - the ioctl data
 */
int
mxlnd_ctl(lnet_ni_t *ni, unsigned int cmd, void *arg)
{
        struct libcfs_ioctl_data *data  = arg;
        int                       ret   = -EINVAL;

        LASSERT (ni == kmxlnd_data.kmx_ni);

        switch (cmd) {
        case IOC_LIBCFS_GET_PEER: {
                lnet_nid_t      nid     = 0;
                int             count   = 0;

                ret = mxlnd_get_peer_info(data->ioc_count, &nid, &count);
                data->ioc_nid    = nid;
                data->ioc_count  = count;
                break;
        }
        case IOC_LIBCFS_DEL_PEER: {
                ret = mxlnd_del_peer(data->ioc_nid);
                break;
        }
        case IOC_LIBCFS_GET_CONN: {
                kmx_conn_t      *conn = NULL;

                conn = mxlnd_get_conn_by_idx(data->ioc_count);
                if (conn == NULL) {
                        ret = -ENOENT;
                } else {
                        ret = 0;
                        data->ioc_nid = conn->mxk_peer->mxp_nid;
                        mxlnd_conn_decref(conn); /* dec ref taken in get_conn_by_idx() */
                }
                break;
        }
        case IOC_LIBCFS_CLOSE_CONNECTION: {
                ret = mxlnd_close_matching_conns(data->ioc_nid);
                break;
        }
        default:
                CNETERR("unknown ctl(%d)\n", cmd);
                break;
        }

        return ret;
}

/**
 * mxlnd_peer_queue_tx_locked - add the tx to the peer's tx queue
 * @tx
 *
 * Add the tx to the peer's msg or data queue. The caller has locked the peer.
 */
void
mxlnd_peer_queue_tx_locked(kmx_ctx_t *tx)
{
        u8              msg_type        = tx->mxc_msg_type;
        kmx_conn_t      *conn           = tx->mxc_conn;

        LASSERT (msg_type != 0);
        LASSERT (tx->mxc_nid != 0);
        LASSERT (tx->mxc_peer != NULL);
        LASSERT (tx->mxc_conn != NULL);

        tx->mxc_incarnation = conn->mxk_incarnation;

        if (msg_type != MXLND_MSG_PUT_DATA &&
            msg_type != MXLND_MSG_GET_DATA) {
                /* msg style tx */
                if (mxlnd_tx_requires_credit(tx)) {
                        cfs_list_add_tail(&tx->mxc_list,
                                          &conn->mxk_tx_credit_queue);
                        conn->mxk_ntx_msgs++;
                } else if (msg_type == MXLND_MSG_CONN_REQ ||
                           msg_type == MXLND_MSG_CONN_ACK) {
                        /* put conn msgs at the front of the queue */
                        cfs_list_add(&tx->mxc_list, &conn->mxk_tx_free_queue);
                } else {
                        /* PUT_ACK, PUT_NAK */
                        cfs_list_add_tail(&tx->mxc_list,
                                          &conn->mxk_tx_free_queue);
                        conn->mxk_ntx_msgs++;
                }
        } else {
                /* data style tx */
                cfs_list_add_tail(&tx->mxc_list, &conn->mxk_tx_free_queue);
                conn->mxk_ntx_data++;
        }

        return;
}

/**
 * mxlnd_peer_queue_tx - add the tx to the global tx queue
 * @tx
 *
 * Add the tx to the peer's msg or data queue
 */
static inline void
mxlnd_peer_queue_tx(kmx_ctx_t *tx)
{
	LASSERT(tx->mxc_peer != NULL);
	LASSERT(tx->mxc_conn != NULL);
	spin_lock(&tx->mxc_conn->mxk_lock);
	mxlnd_peer_queue_tx_locked(tx);
	spin_unlock(&tx->mxc_conn->mxk_lock);

	return;
}

/**
 * mxlnd_queue_tx - add the tx to the global tx queue
 * @tx
 *
 * Add the tx to the global queue and up the tx_queue_sem
 */
void
mxlnd_queue_tx(kmx_ctx_t *tx)
{
        kmx_peer_t *peer   = tx->mxc_peer;
        LASSERT (tx->mxc_nid != 0);

        if (peer != NULL) {
                if (peer->mxp_incompatible &&
                    tx->mxc_msg_type != MXLND_MSG_CONN_ACK) {
                        /* let this fail now */
                        tx->mxc_errno = -ECONNABORTED;
                        mxlnd_conn_decref(peer->mxp_conn);
                        mxlnd_put_idle_tx(tx);
                        return;
                }
                if (tx->mxc_conn == NULL) {
                        int             ret     = 0;
                        kmx_conn_t      *conn   = NULL;

                        ret = mxlnd_conn_alloc(&conn, peer); /* adds 2nd ref for tx... */
                        if (ret != 0) {
                                tx->mxc_errno = ret;
                                mxlnd_put_idle_tx(tx);
                                goto done;
                        }
                        tx->mxc_conn = conn;
                        mxlnd_peer_decref(peer); /* and takes it from peer */
                }
                LASSERT(tx->mxc_conn != NULL);
                mxlnd_peer_queue_tx(tx);
                mxlnd_check_sends(peer);
        } else {
		spin_lock(&kmxlnd_data.kmx_tx_queue_lock);
		cfs_list_add_tail(&tx->mxc_list, &kmxlnd_data.kmx_tx_queue);
		spin_unlock(&kmxlnd_data.kmx_tx_queue_lock);
		up(&kmxlnd_data.kmx_tx_queue_sem);
	}
done:
	return;
}

int
mxlnd_setup_iov(kmx_ctx_t *ctx, u32 niov, struct iovec *iov, u32 offset, u32 nob)
{
        int             i                       = 0;
        int             sum                     = 0;
        int             old_sum                 = 0;
        int             nseg                    = 0;
        int             first_iov               = -1;
        int             first_iov_offset        = 0;
        int             first_found             = 0;
        int             last_iov                = -1;
        int             last_iov_length         = 0;
        mx_ksegment_t  *seg                     = NULL;

        if (niov == 0) return 0;
        LASSERT(iov != NULL);

        for (i = 0; i < niov; i++) {
                sum = old_sum + (u32) iov[i].iov_len;
                if (!first_found && (sum > offset)) {
                        first_iov = i;
                        first_iov_offset = offset - old_sum;
                        first_found = 1;
                        sum = (u32) iov[i].iov_len - first_iov_offset;
                        old_sum = 0;
                }
                if (sum >= nob) {
                        last_iov = i;
                        last_iov_length = (u32) iov[i].iov_len - (sum - nob);
                        if (first_iov == last_iov) last_iov_length -= first_iov_offset;
                        break;
                }
                old_sum = sum;
        }
        LASSERT(first_iov >= 0 && last_iov >= first_iov);
        nseg = last_iov - first_iov + 1;
        LASSERT(nseg > 0);

        MXLND_ALLOC(seg, nseg * sizeof(*seg));
        if (seg == NULL) {
                CNETERR("MXLND_ALLOC() failed\n");
                return -1;
        }
        memset(seg, 0, nseg * sizeof(*seg));
        ctx->mxc_nseg = nseg;
        sum = 0;
        for (i = 0; i < nseg; i++) {
                seg[i].segment_ptr = MX_PA_TO_U64(virt_to_phys(iov[first_iov + i].iov_base));
                seg[i].segment_length = (u32) iov[first_iov + i].iov_len;
                if (i == 0) {
                        seg[i].segment_ptr += (u64) first_iov_offset;
                        seg[i].segment_length -= (u32) first_iov_offset;
                }
                if (i == (nseg - 1)) {
                        seg[i].segment_length = (u32) last_iov_length;
                }
                sum += seg[i].segment_length;
        }
        ctx->mxc_seg_list = seg;
        ctx->mxc_pin_type = MX_PIN_PHYSICAL;
#ifdef MX_PIN_FULLPAGES
        ctx->mxc_pin_type |= MX_PIN_FULLPAGES;
#endif
        LASSERT(nob == sum);
        return 0;
}

int
mxlnd_setup_kiov(kmx_ctx_t *ctx, u32 niov, lnet_kiov_t *kiov, u32 offset, u32 nob)
{
        int             i                       = 0;
        int             sum                     = 0;
        int             old_sum                 = 0;
        int             nseg                    = 0;
        int             first_kiov              = -1;
        int             first_kiov_offset       = 0;
        int             first_found             = 0;
        int             last_kiov               = -1;
        int             last_kiov_length        = 0;
        mx_ksegment_t  *seg                     = NULL;

        if (niov == 0) return 0;
        LASSERT(kiov != NULL);

        for (i = 0; i < niov; i++) {
                sum = old_sum + kiov[i].kiov_len;
                if (i == 0) sum -= kiov[i].kiov_offset;
                if (!first_found && (sum > offset)) {
                        first_kiov = i;
                        first_kiov_offset = offset - old_sum;
                        if (i == 0) first_kiov_offset = kiov[i].kiov_offset;
                        first_found = 1;
                        sum = kiov[i].kiov_len - first_kiov_offset;
                        old_sum = 0;
                }
                if (sum >= nob) {
                        last_kiov = i;
                        last_kiov_length = kiov[i].kiov_len - (sum - nob);
                        if (first_kiov == last_kiov) last_kiov_length -= first_kiov_offset;
                        break;
                }
                old_sum = sum;
        }
        LASSERT(first_kiov >= 0 && last_kiov >= first_kiov);
        nseg = last_kiov - first_kiov + 1;
        LASSERT(nseg > 0);

        MXLND_ALLOC(seg, nseg * sizeof(*seg));
        if (seg == NULL) {
                CNETERR("MXLND_ALLOC() failed\n");
                return -1;
        }
        memset(seg, 0, niov * sizeof(*seg));
        ctx->mxc_nseg = niov;
        sum = 0;
        for (i = 0; i < niov; i++) {
		seg[i].segment_ptr =
			page_to_phys(kiov[first_kiov + i].kiov_page);
                seg[i].segment_length = kiov[first_kiov + i].kiov_len;
                if (i == 0) {
                        seg[i].segment_ptr += (u64) first_kiov_offset;
                        /* we have to add back the original kiov_offset */
                        seg[i].segment_length -= first_kiov_offset +
                                                 kiov[first_kiov].kiov_offset;
                }
                if (i == (nseg - 1)) {
                        seg[i].segment_length = last_kiov_length;
                }
                sum += seg[i].segment_length;
        }
        ctx->mxc_seg_list = seg;
        ctx->mxc_pin_type = MX_PIN_PHYSICAL;
#ifdef MX_PIN_FULLPAGES
        ctx->mxc_pin_type |= MX_PIN_FULLPAGES;
#endif
        LASSERT(nob == sum);
        return 0;
}

void
mxlnd_send_nak(kmx_ctx_t *tx, lnet_nid_t nid, int type, int status, __u64 cookie)
{
        LASSERT(type == MXLND_MSG_PUT_ACK);
        mxlnd_init_tx_msg(tx, type, sizeof(kmx_putack_msg_t), tx->mxc_nid);
        tx->mxc_cookie = cookie;
        tx->mxc_msg->mxm_u.put_ack.mxpam_src_cookie = cookie;
        tx->mxc_msg->mxm_u.put_ack.mxpam_dst_cookie = ((u64) status << MXLND_ERROR_OFFSET); /* error code */
        tx->mxc_match = mxlnd_create_match(tx, status);

        mxlnd_queue_tx(tx);
}


/**
 * mxlnd_send_data - get tx, map [k]iov, queue tx
 * @ni
 * @lntmsg
 * @peer
 * @msg_type
 * @cookie
 *
 * This setups the DATA send for PUT or GET.
 *
 * On success, it queues the tx, on failure it calls lnet_finalize()
 */
void
mxlnd_send_data(lnet_ni_t *ni, lnet_msg_t *lntmsg, kmx_peer_t *peer, u8 msg_type, u64 cookie)
{
        int                     ret     = 0;
        lnet_process_id_t       target  = lntmsg->msg_target;
        unsigned int            niov    = lntmsg->msg_niov;
        struct iovec           *iov     = lntmsg->msg_iov;
        lnet_kiov_t            *kiov    = lntmsg->msg_kiov;
        unsigned int            offset  = lntmsg->msg_offset;
        unsigned int            nob     = lntmsg->msg_len;
        kmx_ctx_t              *tx      = NULL;

        LASSERT(lntmsg != NULL);
        LASSERT(peer != NULL);
        LASSERT(msg_type == MXLND_MSG_PUT_DATA || msg_type == MXLND_MSG_GET_DATA);
        LASSERT((cookie>>MXLND_ERROR_OFFSET) == 0);

        tx = mxlnd_get_idle_tx();
        if (tx == NULL) {
                CNETERR("Can't allocate %s tx for %s\n",
                        msg_type == MXLND_MSG_PUT_DATA ? "PUT_DATA" : "GET_DATA",
                        libcfs_nid2str(target.nid));
                goto failed_0;
        }
        tx->mxc_nid = target.nid;
        /* NOTE called when we have a ref on the conn, get one for this tx */
        mxlnd_conn_addref(peer->mxp_conn);
        tx->mxc_peer = peer;
        tx->mxc_conn = peer->mxp_conn;
        tx->mxc_msg_type = msg_type;
        tx->mxc_lntmsg[0] = lntmsg;
        tx->mxc_cookie = cookie;
        tx->mxc_match = mxlnd_create_match(tx, 0);

        /* This setups up the mx_ksegment_t to send the DATA payload  */
        if (nob == 0) {
                /* do not setup the segments */
                CNETERR("nob = 0; why didn't we use an EAGER reply "
                        "to %s?\n", libcfs_nid2str(target.nid));
                ret = 0;
        } else if (kiov == NULL) {
                ret = mxlnd_setup_iov(tx, niov, iov, offset, nob);
        } else {
                ret = mxlnd_setup_kiov(tx, niov, kiov, offset, nob);
        }
        if (ret != 0) {
                CNETERR("Can't setup send DATA for %s\n",
                        libcfs_nid2str(target.nid));
                tx->mxc_errno = -EIO;
                goto failed_1;
        }
        mxlnd_queue_tx(tx);
        return;

failed_1:
        mxlnd_conn_decref(peer->mxp_conn);
        mxlnd_put_idle_tx(tx);
        return;

failed_0:
        CNETERR("no tx avail\n");
        lnet_finalize(ni, lntmsg, -EIO);
        return;
}

/**
 * mxlnd_recv_data - map [k]iov, post rx
 * @ni
 * @lntmsg
 * @rx
 * @msg_type
 * @cookie
 *
 * This setups the DATA receive for PUT or GET.
 *
 * On success, it returns 0, on failure it returns -1
 */
int
mxlnd_recv_data(lnet_ni_t *ni, lnet_msg_t *lntmsg, kmx_ctx_t *rx, u8 msg_type, u64 cookie)
{
        int                     ret     = 0;
        lnet_process_id_t       target  = lntmsg->msg_target;
        unsigned int            niov    = lntmsg->msg_niov;
        struct iovec           *iov     = lntmsg->msg_iov;
        lnet_kiov_t            *kiov    = lntmsg->msg_kiov;
        unsigned int            offset  = lntmsg->msg_offset;
        unsigned int            nob     = lntmsg->msg_len;
        mx_return_t             mxret   = MX_SUCCESS;
        u64                     mask    = ~(MXLND_ERROR_MASK);

        /* above assumes MXLND_MSG_PUT_DATA */
        if (msg_type == MXLND_MSG_GET_DATA) {
                niov = lntmsg->msg_md->md_niov;
                iov = lntmsg->msg_md->md_iov.iov;
                kiov = lntmsg->msg_md->md_iov.kiov;
                offset = 0;
                nob = lntmsg->msg_md->md_length;
        }

        LASSERT(lntmsg != NULL);
        LASSERT(rx != NULL);
        LASSERT(msg_type == MXLND_MSG_PUT_DATA || msg_type == MXLND_MSG_GET_DATA);
        LASSERT((cookie>>MXLND_ERROR_OFFSET) == 0); /* ensure top 12 bits are 0 */

        rx->mxc_msg_type = msg_type;
        rx->mxc_state = MXLND_CTX_PENDING;
        rx->mxc_nid = target.nid;
        /* if posting a GET_DATA, we may not yet know the peer */
        if (rx->mxc_peer != NULL) {
                rx->mxc_conn = rx->mxc_peer->mxp_conn;
        }
        rx->mxc_lntmsg[0] = lntmsg;
        rx->mxc_cookie = cookie;
        rx->mxc_match = mxlnd_create_match(rx, 0);
        /* This setups up the mx_ksegment_t to receive the DATA payload  */
        if (kiov == NULL) {
                ret = mxlnd_setup_iov(rx, niov, iov, offset, nob);
        } else {
                ret = mxlnd_setup_kiov(rx, niov, kiov, offset, nob);
        }
        if (msg_type == MXLND_MSG_GET_DATA) {
                rx->mxc_lntmsg[1] = lnet_create_reply_msg(kmxlnd_data.kmx_ni, lntmsg);
                if (rx->mxc_lntmsg[1] == NULL) {
                        CNETERR("Can't create reply for GET -> %s\n",
                                libcfs_nid2str(target.nid));
                        ret = -1;
                }
        }
        if (ret != 0) {
                CNETERR("Can't setup %s rx for %s\n",
                       msg_type == MXLND_MSG_PUT_DATA ? "PUT_DATA" : "GET_DATA",
                       libcfs_nid2str(target.nid));
                return -1;
        }
        ret = mxlnd_q_pending_ctx(rx);
        if (ret == -1) {
                return -1;
        }
        CDEBUG(D_NET, "receiving %s 0x%llx\n", mxlnd_msgtype_to_str(msg_type), rx->mxc_cookie);
        mxret = mx_kirecv(kmxlnd_data.kmx_endpt,
                          rx->mxc_seg_list, rx->mxc_nseg,
                          rx->mxc_pin_type, rx->mxc_match,
                          mask, (void *) rx,
                          &rx->mxc_mxreq);
        if (mxret != MX_SUCCESS) {
                if (rx->mxc_conn != NULL) {
                        mxlnd_deq_pending_ctx(rx);
                }
                CNETERR("mx_kirecv() failed with %d for %s\n",
                        (int) mxret, libcfs_nid2str(target.nid));
                return -1;
        }

        return 0;
}

/**
 * mxlnd_send - the LND required send function
 * @ni
 * @private
 * @lntmsg
 *
 * This must not block. Since we may not have a peer struct for the receiver,
 * it will append send messages on a global tx list. We will then up the
 * tx_queued's semaphore to notify it of the new send.
 */
int
mxlnd_send(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg)
{
        int                     ret             = 0;
        int                     type            = lntmsg->msg_type;
        lnet_hdr_t             *hdr             = &lntmsg->msg_hdr;
        lnet_process_id_t       target          = lntmsg->msg_target;
        lnet_nid_t              nid             = target.nid;
        int                     target_is_router = lntmsg->msg_target_is_router;
        int                     routing         = lntmsg->msg_routing;
        unsigned int            payload_niov    = lntmsg->msg_niov;
        struct iovec           *payload_iov     = lntmsg->msg_iov;
        lnet_kiov_t            *payload_kiov    = lntmsg->msg_kiov;
        unsigned int            payload_offset  = lntmsg->msg_offset;
        unsigned int            payload_nob     = lntmsg->msg_len;
        kmx_ctx_t              *tx              = NULL;
        kmx_msg_t              *txmsg           = NULL;
        kmx_ctx_t              *rx              = (kmx_ctx_t *) private; /* for REPLY */
        kmx_ctx_t              *rx_data         = NULL;
        kmx_conn_t             *conn            = NULL;
        int                     nob             = 0;
        uint32_t                length          = 0;
        kmx_peer_t             *peer            = NULL;
	rwlock_t		*g_lock		=&kmxlnd_data.kmx_global_lock;

        CDEBUG(D_NET, "sending %d bytes in %d frags to %s\n",
                       payload_nob, payload_niov, libcfs_id2str(target));

        LASSERT (payload_nob == 0 || payload_niov > 0);
        LASSERT (payload_niov <= LNET_MAX_IOV);
        /* payload is either all vaddrs or all pages */
        LASSERT (!(payload_kiov != NULL && payload_iov != NULL));

        /* private is used on LNET_GET_REPLY only, NULL for all other cases */

        /* NOTE we may not know the peer if it is the very first PUT_REQ or GET_REQ
         * to a new peer, so create one if not found */
        peer = mxlnd_find_peer_by_nid(nid, 1); /* adds peer ref */
        if (peer == NULL || peer->mxp_conn == NULL) {
                /* we could not find it nor could we create one or
                 * one exists but we cannot create a conn,
                 * fail this message */
                if (peer) {
                        /* found peer without conn, drop ref taken above */
                        LASSERT(peer->mxp_conn == NULL);
                        mxlnd_peer_decref(peer);
                }
                return -ENOMEM;
        }

        /* we have a peer with a conn */

        if (unlikely(peer->mxp_incompatible)) {
                mxlnd_peer_decref(peer); /* drop ref taken above */
        } else {
		read_lock(g_lock);
		conn = peer->mxp_conn;
		if (conn && conn->mxk_status != MXLND_CONN_DISCONNECT)
			mxlnd_conn_addref(conn);
		else
			conn = NULL;
		read_unlock(g_lock);
                mxlnd_peer_decref(peer); /* drop peer ref taken above */
                if (!conn)
                        return -ENOTCONN;
        }

        LASSERT(peer && conn);

        CDEBUG(D_NET, "%s: peer 0x%llx is 0x%p\n", __func__, nid, peer);

        switch (type) {
        case LNET_MSG_ACK:
                LASSERT (payload_nob == 0);
                break;

        case LNET_MSG_REPLY:
        case LNET_MSG_PUT:
                /* Is the payload small enough not to need DATA? */
                nob = offsetof(kmx_msg_t, mxm_u.eager.mxem_payload[payload_nob]);
                if (nob <= MXLND_MSG_SIZE)
                        break;                  /* send EAGER */

                tx = mxlnd_get_idle_tx();
                if (unlikely(tx == NULL)) {
                        CNETERR("Can't allocate %s tx for %s\n",
                                type == LNET_MSG_PUT ? "PUT" : "REPLY",
                                libcfs_nid2str(nid));
                        if (conn) mxlnd_conn_decref(conn);
                        return -ENOMEM;
                }

                tx->mxc_peer = peer;
                tx->mxc_conn = conn;
                /* we added a conn ref above */
                mxlnd_init_tx_msg (tx, MXLND_MSG_PUT_REQ, sizeof(kmx_putreq_msg_t), nid);
                txmsg = tx->mxc_msg;
                txmsg->mxm_u.put_req.mxprm_hdr = *hdr;
                txmsg->mxm_u.put_req.mxprm_cookie = tx->mxc_cookie;
                tx->mxc_match = mxlnd_create_match(tx, 0);

                /* we must post a receive _before_ sending the request.
                 * we need to determine how much to receive, it will be either
                 * a put_ack or a put_nak. The put_ack is larger, so use it. */

                rx = mxlnd_get_idle_rx(conn);
                if (unlikely(rx == NULL)) {
                        CNETERR("Can't allocate rx for PUT_ACK for %s\n",
                                libcfs_nid2str(nid));
                        mxlnd_put_idle_tx(tx);
                        if (conn) mxlnd_conn_decref(conn); /* for the ref taken above */
                        return -ENOMEM;
                }
                rx->mxc_nid = nid;
                rx->mxc_peer = peer;
                mxlnd_conn_addref(conn); /* for this rx */
                rx->mxc_conn = conn;
                rx->mxc_msg_type = MXLND_MSG_PUT_ACK;
                rx->mxc_cookie = tx->mxc_cookie;
                rx->mxc_match = mxlnd_create_match(rx, 0);

                length = offsetof(kmx_msg_t, mxm_u) + sizeof(kmx_putack_msg_t);
                ret = mxlnd_recv_msg(lntmsg, rx, MXLND_MSG_PUT_ACK, rx->mxc_match, length);
                if (unlikely(ret != 0)) {
                        CNETERR("recv_msg() failed for PUT_ACK for %s\n",
                                           libcfs_nid2str(nid));
                        rx->mxc_lntmsg[0] = NULL;
                        mxlnd_put_idle_rx(rx);
                        mxlnd_put_idle_tx(tx);
                        mxlnd_conn_decref(conn); /* for the rx... */
                        mxlnd_conn_decref(conn); /* and for the tx */
                        return -EHOSTUNREACH;
                }

                mxlnd_queue_tx(tx);
                return 0;

        case LNET_MSG_GET:
                if (routing || target_is_router)
                        break;                  /* send EAGER */

                /* is the REPLY message too small for DATA? */
                nob = offsetof(kmx_msg_t, mxm_u.eager.mxem_payload[lntmsg->msg_md->md_length]);
                if (nob <= MXLND_MSG_SIZE)
                        break;                  /* send EAGER */

                /* get tx (we need the cookie) , post rx for incoming DATA,
                 * then post GET_REQ tx */
                tx = mxlnd_get_idle_tx();
                if (unlikely(tx == NULL)) {
                        CNETERR("Can't allocate GET tx for %s\n",
                                libcfs_nid2str(nid));
                        mxlnd_conn_decref(conn); /* for the ref taken above */
                        return -ENOMEM;
                }
                rx_data = mxlnd_get_idle_rx(conn);
                if (unlikely(rx_data == NULL)) {
                        CNETERR("Can't allocate DATA rx for %s\n",
                                libcfs_nid2str(nid));
                        mxlnd_put_idle_tx(tx);
                        mxlnd_conn_decref(conn); /* for the ref taken above */
                        return -ENOMEM;
                }
                rx_data->mxc_peer = peer;
                /* NOTE no need to lock peer before adding conn ref since we took
                 * a conn ref for the tx (it cannot be freed between there and here ) */
                mxlnd_conn_addref(conn); /* for the rx_data */
                rx_data->mxc_conn = conn;

                ret = mxlnd_recv_data(ni, lntmsg, rx_data, MXLND_MSG_GET_DATA, tx->mxc_cookie);
                if (unlikely(ret != 0)) {
                        CNETERR("Can't setup GET sink for %s\n",
                                libcfs_nid2str(nid));
                        mxlnd_put_idle_rx(rx_data);
                        mxlnd_put_idle_tx(tx);
                        mxlnd_conn_decref(conn); /* for the rx_data... */
                        mxlnd_conn_decref(conn); /* and for the tx */
                        return -EIO;
                }

                tx->mxc_peer = peer;
                tx->mxc_conn = conn;
                /* conn ref taken above */
                mxlnd_init_tx_msg(tx, MXLND_MSG_GET_REQ, sizeof(kmx_getreq_msg_t), nid);
                txmsg = tx->mxc_msg;
                txmsg->mxm_u.get_req.mxgrm_hdr = *hdr;
                txmsg->mxm_u.get_req.mxgrm_cookie = tx->mxc_cookie;
                tx->mxc_match = mxlnd_create_match(tx, 0);

                mxlnd_queue_tx(tx);
                return 0;

        default:
                LBUG();
                mxlnd_conn_decref(conn); /* drop ref taken above */
                return -EIO;
        }

        /* send EAGER */

        LASSERT (offsetof(kmx_msg_t, mxm_u.eager.mxem_payload[payload_nob])
                <= MXLND_MSG_SIZE);

        tx = mxlnd_get_idle_tx();
        if (unlikely(tx == NULL)) {
                CNETERR("Can't send %s to %s: tx descs exhausted\n",
                        mxlnd_lnetmsg_to_str(type), libcfs_nid2str(nid));
                mxlnd_conn_decref(conn); /* drop ref taken above */
                return -ENOMEM;
        }

        tx->mxc_peer = peer;
        tx->mxc_conn = conn;
        /* conn ref taken above */
        nob = offsetof(kmx_eager_msg_t, mxem_payload[payload_nob]);
        mxlnd_init_tx_msg (tx, MXLND_MSG_EAGER, nob, nid);
        tx->mxc_match = mxlnd_create_match(tx, 0);

        txmsg = tx->mxc_msg;
        txmsg->mxm_u.eager.mxem_hdr = *hdr;

        if (payload_kiov != NULL)
                lnet_copy_kiov2flat(MXLND_MSG_SIZE, txmsg,
                            offsetof(kmx_msg_t, mxm_u.eager.mxem_payload),
                            payload_niov, payload_kiov, payload_offset, payload_nob);
        else
                lnet_copy_iov2flat(MXLND_MSG_SIZE, txmsg,
                            offsetof(kmx_msg_t, mxm_u.eager.mxem_payload),
                            payload_niov, payload_iov, payload_offset, payload_nob);

        tx->mxc_lntmsg[0] = lntmsg;              /* finalise lntmsg on completion */
        mxlnd_queue_tx(tx);
        return 0;
}

/**
 * mxlnd_recv - the LND required recv function
 * @ni
 * @private
 * @lntmsg
 * @delayed
 * @niov
 * @kiov
 * @offset
 * @mlen
 * @rlen
 *
 * This must not block.
 */
int
mxlnd_recv (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg, int delayed,
             unsigned int niov, struct iovec *iov, lnet_kiov_t *kiov,
             unsigned int offset, unsigned int mlen, unsigned int rlen)
{
        int             ret             = 0;
        int             nob             = 0;
        int             len             = 0;
        kmx_ctx_t       *rx             = private;
        kmx_msg_t       *rxmsg          = rx->mxc_msg;
        lnet_nid_t       nid            = rx->mxc_nid;
        kmx_ctx_t       *tx             = NULL;
        kmx_msg_t       *txmsg          = NULL;
        kmx_peer_t      *peer           = rx->mxc_peer;
        kmx_conn_t      *conn           = peer->mxp_conn;
        u64              cookie         = 0ULL;
        int              msg_type       = rxmsg->mxm_type;
        int              repost         = 1;
        int              credit         = 0;
        int              finalize       = 0;

        LASSERT (mlen <= rlen);
        /* Either all pages or all vaddrs */
        LASSERT (!(kiov != NULL && iov != NULL));
        LASSERT (peer && conn);

        /* conn_addref(conn) already taken for the primary rx */

        switch (msg_type) {
        case MXLND_MSG_EAGER:
                nob = offsetof(kmx_msg_t, mxm_u.eager.mxem_payload[rlen]);
                len = rx->mxc_status.xfer_length;
                if (unlikely(nob > len)) {
                        CNETERR("Eager message from %s too big: %d(%d)\n",
                                libcfs_nid2str(nid), nob, len);
                        ret = -EPROTO;
                        break;
                }

                if (kiov != NULL)
                        lnet_copy_flat2kiov(niov, kiov, offset,
                                MXLND_MSG_SIZE, rxmsg,
                                offsetof(kmx_msg_t, mxm_u.eager.mxem_payload),
                                mlen);
                else
                        lnet_copy_flat2iov(niov, iov, offset,
                                MXLND_MSG_SIZE, rxmsg,
                                offsetof(kmx_msg_t, mxm_u.eager.mxem_payload),
                                mlen);
                finalize = 1;
                credit = 1;
                break;

        case MXLND_MSG_PUT_REQ:
                /* we are going to reuse the rx, store the needed info */
                cookie = rxmsg->mxm_u.put_req.mxprm_cookie;

                /* get tx, post rx, send PUT_ACK */

                tx = mxlnd_get_idle_tx();
                if (unlikely(tx == NULL)) {
                        CNETERR("Can't allocate tx for %s\n", libcfs_nid2str(nid));
                        /* Not replying will break the connection */
                        ret = -ENOMEM;
                        break;
                }
                if (unlikely(mlen == 0)) {
                        finalize = 1;
                        tx->mxc_peer = peer;
                        tx->mxc_conn = conn;
                        mxlnd_send_nak(tx, nid, MXLND_MSG_PUT_ACK, 0, cookie);
                        /* repost = 1 */
                        break;
                }

                mxlnd_init_tx_msg(tx, MXLND_MSG_PUT_ACK, sizeof(kmx_putack_msg_t), nid);
                tx->mxc_peer = peer;
                tx->mxc_conn = conn;
                /* no need to lock peer first since we already have a ref */
                mxlnd_conn_addref(conn); /* for the tx */
                txmsg = tx->mxc_msg;
                txmsg->mxm_u.put_ack.mxpam_src_cookie = cookie;
                txmsg->mxm_u.put_ack.mxpam_dst_cookie = tx->mxc_cookie;
                tx->mxc_cookie = cookie;
                tx->mxc_match = mxlnd_create_match(tx, 0);

                /* we must post a receive _before_ sending the PUT_ACK */
                mxlnd_ctx_init(rx);
                rx->mxc_state = MXLND_CTX_PREP;
                rx->mxc_peer = peer;
                rx->mxc_conn = conn;
                /* do not take another ref for this rx, it is already taken */
                rx->mxc_nid = peer->mxp_nid;
                ret = mxlnd_recv_data(ni, lntmsg, rx, MXLND_MSG_PUT_DATA,
                                      txmsg->mxm_u.put_ack.mxpam_dst_cookie);

                if (unlikely(ret != 0)) {
                        /* Notify peer that it's over */
                        CNETERR("Can't setup PUT_DATA rx for %s: %d\n",
                                libcfs_nid2str(nid), ret);
                        mxlnd_ctx_init(tx);
                        tx->mxc_state = MXLND_CTX_PREP;
                        tx->mxc_peer = peer;
                        tx->mxc_conn = conn;
                        /* finalize = 0, let the PUT_ACK tx finalize this */
                        tx->mxc_lntmsg[0] = rx->mxc_lntmsg[0];
                        tx->mxc_lntmsg[1] = rx->mxc_lntmsg[1];
                        /* conn ref already taken above */
                        mxlnd_send_nak(tx, nid, MXLND_MSG_PUT_ACK, ret, cookie);
                        /* repost = 1 */
                        break;
                }

                mxlnd_queue_tx(tx);
                /* do not return a credit until after PUT_DATA returns */
                repost = 0;
                break;

        case MXLND_MSG_GET_REQ:
                cookie = rxmsg->mxm_u.get_req.mxgrm_cookie;

                if (likely(lntmsg != NULL)) {
                        mxlnd_send_data(ni, lntmsg, rx->mxc_peer, MXLND_MSG_GET_DATA,
                                        cookie);
                } else {
                        /* GET didn't match anything */
                        /* The initiator has a rx mapped to [k]iov. We cannot send a nak.
                         * We have to embed the error code in the match bits.
                         * Send the error in bits 52-59 and the cookie in bits 0-51 */
                        tx = mxlnd_get_idle_tx();
                        if (unlikely(tx == NULL)) {
                                CNETERR("Can't get tx for GET NAK for %s\n",
                                        libcfs_nid2str(nid));
                                /* we can't get a tx, notify the peer that the GET failed */
                                mxlnd_send_message(conn->mxk_epa, MXLND_MSG_GET_DATA,
                                                   ENODATA, cookie);
                                ret = -ENOMEM;
                                break;
                        }
                        tx->mxc_msg_type = MXLND_MSG_GET_DATA;
                        tx->mxc_state = MXLND_CTX_PENDING;
                        tx->mxc_nid = nid;
                        tx->mxc_peer = peer;
                        tx->mxc_conn = conn;
                        /* no need to lock peer first since we already have a ref */
                        mxlnd_conn_addref(conn); /* for this tx */
                        tx->mxc_cookie = cookie;
                        tx->mxc_match = mxlnd_create_match(tx, ENODATA);
                        tx->mxc_pin_type = MX_PIN_PHYSICAL;
                        mxlnd_queue_tx(tx);
                }
                /* finalize lntmsg after tx completes */
                break;

        default:
                LBUG();
        }

        if (repost) {
                /* we received a message, increment peer's outstanding credits */
		if (credit == 1) {
			spin_lock(&conn->mxk_lock);
			conn->mxk_outstanding++;
			spin_unlock(&conn->mxk_lock);
		}
                /* we are done with the rx */
                mxlnd_put_idle_rx(rx);
                mxlnd_conn_decref(conn);
        }

        if (finalize == 1) lnet_finalize(kmxlnd_data.kmx_ni, lntmsg, 0);

        /* we received a credit, see if we can use it to send a msg */
        if (credit) mxlnd_check_sends(peer);

        return ret;
}

void
mxlnd_sleep(unsigned long timeout)
{
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(timeout);
	return;
}

/**
 * mxlnd_tx_queued - the generic send queue thread
 * @arg - thread id (as a void *)
 *
 * This thread moves send messages from the global tx_queue to the owning
 * peer's tx_[msg|data]_queue. If the peer does not exist, it creates one and adds
 * it to the global peer list.
 */
int
mxlnd_tx_queued(void *arg)
{
        long                    id      = (long) arg;
        int                     ret     = 0;
        int                     found   = 0;
        kmx_ctx_t              *tx      = NULL;
        kmx_peer_t             *peer    = NULL;
        cfs_list_t             *queue   = &kmxlnd_data.kmx_tx_queue;
	spinlock_t		*tx_q_lock = &kmxlnd_data.kmx_tx_queue_lock;
	rwlock_t		*g_lock  = &kmxlnd_data.kmx_global_lock;

	while (!(atomic_read(&kmxlnd_data.kmx_shutdown))) {
		ret = down_interruptible(&kmxlnd_data.kmx_tx_queue_sem);
		if (atomic_read(&kmxlnd_data.kmx_shutdown))
			break;
		if (ret != 0) /* Should we check for -EINTR? */
			continue;
		spin_lock(tx_q_lock);
		if (cfs_list_empty(&kmxlnd_data.kmx_tx_queue)) {
			spin_unlock(tx_q_lock);
			continue;
		}
		tx = cfs_list_entry(queue->next, kmx_ctx_t, mxc_list);
		cfs_list_del_init(&tx->mxc_list);
		spin_unlock(tx_q_lock);

		found = 0;
		peer = mxlnd_find_peer_by_nid(tx->mxc_nid, 0); /* adds ref*/
		if (peer != NULL) {
			tx->mxc_peer = peer;
			write_lock(g_lock);
			if (peer->mxp_conn == NULL) {
				ret = mxlnd_conn_alloc_locked(&peer->mxp_conn,
							      peer);
				if (ret != 0) {
					/* out of memory: give up, fail tx */
					tx->mxc_errno = -ENOMEM;
					mxlnd_peer_decref(peer);
					write_unlock(g_lock);
					mxlnd_put_idle_tx(tx);
					continue;
				}
			}
			tx->mxc_conn = peer->mxp_conn;
			mxlnd_conn_addref(tx->mxc_conn); /* for this tx */
			mxlnd_peer_decref(peer); /* drop peer ref taken above */
			write_unlock(g_lock);
                        mxlnd_queue_tx(tx);
                        found = 1;
                }
                if (found == 0) {
                        int             hash    = 0;
                        kmx_peer_t     *peer    = NULL;
                        kmx_peer_t     *old     = NULL;

                        hash = mxlnd_nid_to_hash(tx->mxc_nid);

                        LASSERT(tx->mxc_msg_type != MXLND_MSG_PUT_DATA &&
                                tx->mxc_msg_type != MXLND_MSG_GET_DATA);
                        /* create peer */
                        /* adds conn ref for this function */
                        ret = mxlnd_peer_alloc(&peer, tx->mxc_nid,
                                        *kmxlnd_tunables.kmx_board,
                                        *kmxlnd_tunables.kmx_ep_id, 0ULL);
                        if (ret != 0) {
                                /* finalize message */
                                tx->mxc_errno = ret;
                                mxlnd_put_idle_tx(tx);
                                continue;
                        }
                        tx->mxc_peer = peer;
                        tx->mxc_conn = peer->mxp_conn;
                        /* this tx will keep the conn ref taken in peer_alloc() */

                        /* add peer to global peer list, but look to see
                         * if someone already created it after we released
                         * the read lock */
			write_lock(g_lock);
                        old = mxlnd_find_peer_by_nid_locked(peer->mxp_nid);
                        if (old) {
                                /* we have a peer ref on old */
                                if (old->mxp_conn) {
                                        found = 1;
                                } else {
                                        /* no conn */
                                        /* drop our ref taken above... */
                                        mxlnd_peer_decref(old);
                                        /* and delete it */
                                        mxlnd_del_peer_locked(old);
                                }
                        }

			if (found == 0) {
				cfs_list_add_tail(&peer->mxp_list,
						  &kmxlnd_data.kmx_peers[hash]);
				atomic_inc(&kmxlnd_data.kmx_npeers);
			} else {
                                tx->mxc_peer = old;
                                tx->mxc_conn = old->mxp_conn;
                                LASSERT(old->mxp_conn != NULL);
                                mxlnd_conn_addref(old->mxp_conn);
                                mxlnd_conn_decref(peer->mxp_conn); /* drop ref taken above.. */
                                mxlnd_conn_decref(peer->mxp_conn); /* drop peer's ref */
                                mxlnd_peer_decref(peer);
                        }
			write_unlock(g_lock);

                        mxlnd_queue_tx(tx);
                }
        }
        mxlnd_thread_stop(id);
        return 0;
}

/* When calling this, we must not have the peer lock. */
void
mxlnd_iconnect(kmx_peer_t *peer, u8 msg_type)
{
        mx_return_t     mxret           = MX_SUCCESS;
        mx_request_t    request;
        kmx_conn_t      *conn           = peer->mxp_conn;
        u64             match           = ((u64) msg_type) << MXLND_MSG_OFFSET;

        /* NOTE we are holding a conn ref every time we call this function,
         * we do not need to lock the peer before taking another ref */
        mxlnd_conn_addref(conn); /* hold until CONN_REQ or CONN_ACK completes */

        LASSERT(msg_type == MXLND_MSG_ICON_REQ || msg_type == MXLND_MSG_ICON_ACK);

        if (peer->mxp_reconnect_time == 0) {
                peer->mxp_reconnect_time = jiffies;
        }

        if (peer->mxp_nic_id == 0ULL) {
                int     ret     = 0;

                ret = mxlnd_ip2nic_id(LNET_NIDADDR(peer->mxp_nid),
                                      &peer->mxp_nic_id, MXLND_LOOKUP_COUNT);
                if (ret == 0) {
                        mx_nic_id_to_board_number(peer->mxp_nic_id, &peer->mxp_board);
                }
                if (peer->mxp_nic_id == 0ULL && conn->mxk_status == MXLND_CONN_WAIT) {
			/* not mapped yet, return */
			spin_lock(&conn->mxk_lock);
			mxlnd_set_conn_status(conn, MXLND_CONN_INIT);
			spin_unlock(&conn->mxk_lock);
                }
        }

        if (cfs_time_after(jiffies,
                           peer->mxp_reconnect_time + MXLND_CONNECT_TIMEOUT) &&
            conn->mxk_status != MXLND_CONN_DISCONNECT) {
                /* give up and notify LNET */
                CDEBUG(D_NET, "timeout trying to connect to %s\n",
                       libcfs_nid2str(peer->mxp_nid));
                mxlnd_conn_disconnect(conn, 0, 0);
                mxlnd_conn_decref(conn);
                return;
        }

        mxret = mx_iconnect(kmxlnd_data.kmx_endpt, peer->mxp_nic_id,
                            peer->mxp_ep_id, MXLND_MSG_MAGIC, match,
                            (void *) peer, &request);
        if (unlikely(mxret != MX_SUCCESS)) {
		spin_lock(&conn->mxk_lock);
		mxlnd_set_conn_status(conn, MXLND_CONN_FAIL);
		spin_unlock(&conn->mxk_lock);
                CNETERR("mx_iconnect() failed with %s (%d) to %s\n",
                       mx_strerror(mxret), mxret, libcfs_nid2str(peer->mxp_nid));
                mxlnd_conn_decref(conn);
        }
	mx_set_request_timeout(kmxlnd_data.kmx_endpt, request,
			       jiffies_to_msecs(MXLND_CONNECT_TIMEOUT));
	return;
}

#define MXLND_STATS 0

int
mxlnd_check_sends(kmx_peer_t *peer)
{
        int             ret             = 0;
        int             found           = 0;
        mx_return_t     mxret           = MX_SUCCESS;
        kmx_ctx_t       *tx             = NULL;
        kmx_conn_t      *conn           = NULL;
        u8              msg_type        = 0;
        int             credit          = 0;
        int             status          = 0;
        int             ntx_posted      = 0;
        int             credits         = 0;
#if MXLND_STATS
        static unsigned long last       = 0;
#endif

        if (unlikely(peer == NULL)) {
                LASSERT(peer != NULL);
                return -1;
        }
	write_lock(&kmxlnd_data.kmx_global_lock);
	conn = peer->mxp_conn;
	/* NOTE take a ref for the duration of this function since it is
	 * called when there might not be any queued txs for this peer */
	if (conn) {
		if (conn->mxk_status == MXLND_CONN_DISCONNECT) {
			write_unlock(&kmxlnd_data.kmx_global_lock);
			return -1;
		}
		mxlnd_conn_addref(conn); /* for duration of this function */
	}
	write_unlock(&kmxlnd_data.kmx_global_lock);

        /* do not add another ref for this tx */

        if (conn == NULL) {
                /* we do not have any conns */
                CNETERR("peer %s has no conn\n", libcfs_nid2str(peer->mxp_nid));
                return -1;
        }

#if MXLND_STATS
	if (cfs_time_after(jiffies, last)) {
		last = jiffies + msecs_to_jiffies(MSEC_PER_SEC);
		CDEBUG(D_NET, "status= %s credits= %d outstanding= %d ntx_msgs= %d "
			      "ntx_posted= %d ntx_data= %d data_posted= %d\n",
			      mxlnd_connstatus_to_str(conn->mxk_status), conn->mxk_credits,
			      conn->mxk_outstanding, conn->mxk_ntx_msgs, conn->mxk_ntx_posted,
			      conn->mxk_ntx_data, conn->mxk_data_posted);
	}
#endif

	spin_lock(&conn->mxk_lock);
        ntx_posted = conn->mxk_ntx_posted;
        credits = conn->mxk_credits;

        LASSERT(ntx_posted <= *kmxlnd_tunables.kmx_peercredits);
        LASSERT(ntx_posted >= 0);

        LASSERT(credits <= *kmxlnd_tunables.kmx_peercredits);
        LASSERT(credits >= 0);

        /* check number of queued msgs, ignore data */
        if (conn->mxk_outstanding >= MXLND_CREDIT_HIGHWATER()) {
                /* check if any txs queued that could return credits... */
                if (cfs_list_empty(&conn->mxk_tx_credit_queue) ||
                    conn->mxk_ntx_msgs == 0) {
                        /* if not, send a NOOP */
                        tx = mxlnd_get_idle_tx();
                        if (likely(tx != NULL)) {
                                tx->mxc_peer = peer;
                                tx->mxc_conn = peer->mxp_conn;
                                mxlnd_conn_addref(conn); /* for this tx */
                                mxlnd_init_tx_msg (tx, MXLND_MSG_NOOP, 0, peer->mxp_nid);
                                tx->mxc_match = mxlnd_create_match(tx, 0);
                                mxlnd_peer_queue_tx_locked(tx);
                                found = 1;
                                goto done_locked;
                        }
                }
        }

        /* if the peer is not ready, try to connect */
        if (unlikely(conn->mxk_status == MXLND_CONN_INIT ||
            conn->mxk_status == MXLND_CONN_FAIL)) {
                CDEBUG(D_NET, "status=%s\n", mxlnd_connstatus_to_str(conn->mxk_status));
                mxlnd_set_conn_status(conn, MXLND_CONN_WAIT);
		spin_unlock(&conn->mxk_lock);
                mxlnd_iconnect(peer, (u8) MXLND_MSG_ICON_REQ);
                goto done;
        }

        while (!cfs_list_empty(&conn->mxk_tx_free_queue) ||
               !cfs_list_empty(&conn->mxk_tx_credit_queue)) {
                /* We have something to send. If we have a queued tx that does not
                 * require a credit (free), choose it since its completion will
                 * return a credit (here or at the peer), complete a DATA or
                 * CONN_REQ or CONN_ACK. */
                cfs_list_t *tmp_tx = NULL;
                if (!cfs_list_empty(&conn->mxk_tx_free_queue)) {
                        tmp_tx = &conn->mxk_tx_free_queue;
                } else {
                        tmp_tx = &conn->mxk_tx_credit_queue;
                }
                tx = cfs_list_entry(tmp_tx->next, kmx_ctx_t, mxc_list);

                msg_type = tx->mxc_msg_type;

                /* don't try to send a rx */
                LASSERT(tx->mxc_type == MXLND_REQ_TX);

                /* ensure that it is a valid msg type */
                LASSERT(msg_type == MXLND_MSG_CONN_REQ ||
                        msg_type == MXLND_MSG_CONN_ACK ||
                        msg_type == MXLND_MSG_NOOP     ||
                        msg_type == MXLND_MSG_EAGER    ||
                        msg_type == MXLND_MSG_PUT_REQ  ||
                        msg_type == MXLND_MSG_PUT_ACK  ||
                        msg_type == MXLND_MSG_PUT_DATA ||
                        msg_type == MXLND_MSG_GET_REQ  ||
                        msg_type == MXLND_MSG_GET_DATA);
                LASSERT(tx->mxc_peer == peer);
                LASSERT(tx->mxc_nid == peer->mxp_nid);

                credit = mxlnd_tx_requires_credit(tx);
                if (credit) {

                        if (conn->mxk_ntx_posted == *kmxlnd_tunables.kmx_peercredits) {
                                CDEBUG(D_NET, "%s: posted enough\n",
                                              libcfs_nid2str(peer->mxp_nid));
                                goto done_locked;
                        }

                        if (conn->mxk_credits == 0) {
                                CDEBUG(D_NET, "%s: no credits\n",
                                              libcfs_nid2str(peer->mxp_nid));
                                goto done_locked;
                        }

                        if (conn->mxk_credits == 1 &&      /* last credit reserved for */
                            conn->mxk_outstanding == 0) {  /* giving back credits */
                                CDEBUG(D_NET, "%s: not using last credit\n",
                                              libcfs_nid2str(peer->mxp_nid));
                                goto done_locked;
                        }
                }

                if (unlikely(conn->mxk_status != MXLND_CONN_READY)) {
                        if ( ! (msg_type == MXLND_MSG_CONN_REQ ||
                                msg_type == MXLND_MSG_CONN_ACK)) {
                                CDEBUG(D_NET, "peer status is %s for tx 0x%llx (%s)\n",
                                             mxlnd_connstatus_to_str(conn->mxk_status),
                                             tx->mxc_cookie,
                                             mxlnd_msgtype_to_str(tx->mxc_msg_type));
                                if (conn->mxk_status == MXLND_CONN_DISCONNECT ||
                                    cfs_time_aftereq(jiffies, tx->mxc_deadline)) {
                                        cfs_list_del_init(&tx->mxc_list);
                                        tx->mxc_errno = -ECONNABORTED;
					spin_unlock(&conn->mxk_lock);
                                        mxlnd_put_idle_tx(tx);
                                        mxlnd_conn_decref(conn);
                                        goto done;
                                }
                                goto done_locked;
                        }
                }

                cfs_list_del_init(&tx->mxc_list);

                /* handle credits, etc now while we have the lock to avoid races */
                if (credit) {
                        conn->mxk_credits--;
                        conn->mxk_ntx_posted++;
                }
                if (msg_type != MXLND_MSG_PUT_DATA &&
                    msg_type != MXLND_MSG_GET_DATA) {
                        if (msg_type != MXLND_MSG_CONN_REQ &&
                            msg_type != MXLND_MSG_CONN_ACK) {
                                conn->mxk_ntx_msgs--;
                        }
                }
                if (tx->mxc_incarnation == 0 &&
                    conn->mxk_incarnation != 0) {
                        tx->mxc_incarnation = conn->mxk_incarnation;
                }

                /* if this is a NOOP and (1) mxp_conn->mxk_outstanding < CREDIT_HIGHWATER
                 * or (2) there is a non-DATA msg that can return credits in the
                 * queue, then drop this duplicate NOOP */
                if (unlikely(msg_type == MXLND_MSG_NOOP)) {
                        if ((conn->mxk_outstanding < MXLND_CREDIT_HIGHWATER()) ||
                            (conn->mxk_ntx_msgs >= 1)) {
                                conn->mxk_credits++;
                                conn->mxk_ntx_posted--;
				spin_unlock(&conn->mxk_lock);
                                /* redundant NOOP */
                                mxlnd_put_idle_tx(tx);
                                mxlnd_conn_decref(conn);
                                CDEBUG(D_NET, "%s: redundant noop\n",
                                              libcfs_nid2str(peer->mxp_nid));
                                found = 1;
                                goto done;
                        }
                }

                found = 1;
                if (likely((msg_type != MXLND_MSG_PUT_DATA) &&
                    (msg_type != MXLND_MSG_GET_DATA))) {
                        mxlnd_pack_msg_locked(tx);
                }

                mxret = MX_SUCCESS;

                status = conn->mxk_status;
		spin_unlock(&conn->mxk_lock);

                if (likely((status == MXLND_CONN_READY) ||
                    (msg_type == MXLND_MSG_CONN_REQ) ||
                    (msg_type == MXLND_MSG_CONN_ACK))) {
                        ret = 0;
                        if (msg_type != MXLND_MSG_CONN_REQ &&
                            msg_type != MXLND_MSG_CONN_ACK) {
                                /* add to the pending list */
                                ret = mxlnd_q_pending_ctx(tx);
                        } else {
                                /* CONN_REQ/ACK */
                                tx->mxc_state = MXLND_CTX_PENDING;
                        }

                        if (ret == 0) {
                                if (likely(msg_type != MXLND_MSG_PUT_DATA &&
                                    msg_type != MXLND_MSG_GET_DATA)) {
                                        /* send a msg style tx */
                                        LASSERT(tx->mxc_nseg == 1);
                                        LASSERT(tx->mxc_pin_type == MX_PIN_PHYSICAL);
                                        CDEBUG(D_NET, "sending %s 0x%llx\n",
                                               mxlnd_msgtype_to_str(msg_type),
                                               tx->mxc_cookie);
                                        mxret = mx_kisend(kmxlnd_data.kmx_endpt,
                                                          &tx->mxc_seg,
                                                          tx->mxc_nseg,
                                                          tx->mxc_pin_type,
                                                          conn->mxk_epa,
                                                          tx->mxc_match,
                                                          (void *) tx,
                                                          &tx->mxc_mxreq);
                                } else {
                                        /* send a DATA tx */
					spin_lock(&conn->mxk_lock);
					conn->mxk_ntx_data--;
					conn->mxk_data_posted++;
					spin_unlock(&conn->mxk_lock);
                                        CDEBUG(D_NET, "sending %s 0x%llx\n",
                                               mxlnd_msgtype_to_str(msg_type),
                                               tx->mxc_cookie);
                                        mxret = mx_kisend(kmxlnd_data.kmx_endpt,
                                                          tx->mxc_seg_list,
                                                          tx->mxc_nseg,
                                                          tx->mxc_pin_type,
                                                          conn->mxk_epa,
                                                          tx->mxc_match,
                                                          (void *) tx,
                                                          &tx->mxc_mxreq);
                                }
                        } else {
                                /* ret != 0 */
                                mxret = MX_CONNECTION_FAILED;
                        }
                        if (likely(mxret == MX_SUCCESS)) {
                                ret = 0;
                        } else {
                                CNETERR("mx_kisend() failed with %s (%d) "
                                        "sending to %s\n", mx_strerror(mxret), (int) mxret,
                                       libcfs_nid2str(peer->mxp_nid));
                                /* NOTE mx_kisend() only fails if there are not enough
                                * resources. Do not change the connection status. */
                                if (mxret == MX_NO_RESOURCES) {
                                        tx->mxc_errno = -ENOMEM;
                                } else {
                                        tx->mxc_errno = -ECONNABORTED;
                                }
                                if (credit) {
					spin_lock(&conn->mxk_lock);
					conn->mxk_ntx_posted--;
					conn->mxk_credits++;
					spin_unlock(&conn->mxk_lock);
				} else if (msg_type == MXLND_MSG_PUT_DATA ||
					   msg_type == MXLND_MSG_GET_DATA) {
					spin_lock(&conn->mxk_lock);
					conn->mxk_data_posted--;
					spin_unlock(&conn->mxk_lock);
				}
				if (msg_type != MXLND_MSG_PUT_DATA &&
				    msg_type != MXLND_MSG_GET_DATA &&
				    msg_type != MXLND_MSG_CONN_REQ &&
				    msg_type != MXLND_MSG_CONN_ACK) {
					spin_lock(&conn->mxk_lock);
					conn->mxk_outstanding +=
						tx->mxc_msg->mxm_credits;
					spin_unlock(&conn->mxk_lock);
                                }
                                if (msg_type != MXLND_MSG_CONN_REQ &&
                                    msg_type != MXLND_MSG_CONN_ACK) {
                                        /* remove from the pending list */
                                        mxlnd_deq_pending_ctx(tx);
                                }
                                mxlnd_put_idle_tx(tx);
                                mxlnd_conn_decref(conn);
                        }
                }
		spin_lock(&conn->mxk_lock);
	}
done_locked:
	spin_unlock(&conn->mxk_lock);
done:
	mxlnd_conn_decref(conn); /* drop ref taken at start of function */
	return found;
}


/**
 * mxlnd_handle_tx_completion - a tx completed, progress or complete the msg
 * @ctx - the tx descriptor
 *
 * Determine which type of send request it was and start the next step, if needed,
 * or, if done, signal completion to LNET. After we are done, put back on the
 * idle tx list.
 */
void
mxlnd_handle_tx_completion(kmx_ctx_t *tx)
{
        int             code    = tx->mxc_status.code;
        int             failed  = (code != MX_STATUS_SUCCESS || tx->mxc_errno != 0);
        kmx_msg_t       *msg    = tx->mxc_msg;
        kmx_peer_t      *peer   = tx->mxc_peer;
        kmx_conn_t      *conn   = tx->mxc_conn;
        u8              type    = tx->mxc_msg_type;
        int             credit  = mxlnd_tx_requires_credit(tx);
        u64             cookie  = tx->mxc_cookie;

        CDEBUG(D_NET, "entering %s (0x%llx):\n",
                      mxlnd_msgtype_to_str(tx->mxc_msg_type), cookie);

        LASSERT (peer != NULL);
        LASSERT (conn != NULL);

        if (type != MXLND_MSG_PUT_DATA && type != MXLND_MSG_GET_DATA) {
                LASSERT (type == msg->mxm_type);
        }

        if (failed) {
                if (tx->mxc_errno == 0) tx->mxc_errno = -EIO;
        } else {
		spin_lock(&conn->mxk_lock);
		conn->mxk_last_tx = cfs_time_current(); /* jiffies */
		spin_unlock(&conn->mxk_lock);
	}

	switch (type) {

	case MXLND_MSG_GET_DATA:
		spin_lock(&conn->mxk_lock);
		if (conn->mxk_incarnation == tx->mxc_incarnation) {
			conn->mxk_outstanding++;
			conn->mxk_data_posted--;
		}
		spin_unlock(&conn->mxk_lock);
		break;

	case MXLND_MSG_PUT_DATA:
		spin_lock(&conn->mxk_lock);
		if (conn->mxk_incarnation == tx->mxc_incarnation) {
			conn->mxk_data_posted--;
		}
		spin_unlock(&conn->mxk_lock);
		break;

        case MXLND_MSG_NOOP:
        case MXLND_MSG_PUT_REQ:
        case MXLND_MSG_PUT_ACK:
        case MXLND_MSG_GET_REQ:
        case MXLND_MSG_EAGER:
                break;

        case MXLND_MSG_CONN_ACK:
                if (peer->mxp_incompatible) {
                        /* we sent our params, now close this conn */
                        mxlnd_conn_disconnect(conn, 0, 1);
                }
        case MXLND_MSG_CONN_REQ:
                if (failed) {
                        CNETERR("%s failed with %s (%d) (errno = %d) to %s\n",
                               type == MXLND_MSG_CONN_REQ ? "CONN_REQ" : "CONN_ACK",
                               mx_strstatus(code), code, tx->mxc_errno,
                               libcfs_nid2str(tx->mxc_nid));
                        if (!peer->mxp_incompatible) {
				spin_lock(&conn->mxk_lock);
				if (code == MX_STATUS_BAD_SESSION)
					mxlnd_set_conn_status(conn,
							      MXLND_CONN_INIT);
				else
					mxlnd_set_conn_status(conn,
							      MXLND_CONN_FAIL);
				spin_unlock(&conn->mxk_lock);
                        }
                }
                break;

        default:
                CNETERR("Unknown msg type of %d\n", type);
                LBUG();
        }

        if (credit) {
		spin_lock(&conn->mxk_lock);
		if (conn->mxk_incarnation == tx->mxc_incarnation) {
			conn->mxk_ntx_posted--;
		}
		spin_unlock(&conn->mxk_lock);
        }

        mxlnd_put_idle_tx(tx);
        mxlnd_conn_decref(conn);

        mxlnd_check_sends(peer);

        CDEBUG(D_NET, "leaving\n");
        return;
}

/* Handle completion of MSG or DATA rx.
 * CONN_REQ and CONN_ACK are handled elsewhere. */
void
mxlnd_handle_rx_completion(kmx_ctx_t *rx)
{
        int             ret             = 0;
        int             repost          = 1;
        int             credit          = 1;
        u32             nob             = rx->mxc_status.xfer_length;
        u64             bits            = rx->mxc_status.match_info;
        kmx_msg_t      *msg             = rx->mxc_msg;
        kmx_peer_t     *peer            = rx->mxc_peer;
        kmx_conn_t     *conn            = rx->mxc_conn;
        u8              type            = rx->mxc_msg_type;
        u64             seq             = bits;
        lnet_msg_t     *lntmsg[2];
        int             result          = 0;
        int             peer_ref        = 0;
        int             conn_ref        = 0;

        /* NOTE We may only know the peer's nid if it is a PUT_REQ, GET_REQ,
         * failed GET reply */

        /* NOTE peer may still be NULL if it is a new peer and
         *      conn may be NULL if this is a re-connect */
        if (likely(peer != NULL && conn != NULL)) {
                /* we have a reference on the conn */
                conn_ref = 1;
        } else if (peer != NULL && conn == NULL) {
                /* we have a reference on the peer */
                peer_ref = 1;
        } else if (peer == NULL && conn != NULL) {
                /* fatal error */
                CERROR("rx 0x%llx from %s has conn but no peer\n",
                       bits, libcfs_nid2str(rx->mxc_nid));
                LBUG();
        } /* else peer and conn == NULL */

        if (conn == NULL && peer != NULL) {
		write_lock(&kmxlnd_data.kmx_global_lock);
                conn = peer->mxp_conn;
                if (conn) {
                        mxlnd_conn_addref(conn); /* conn takes ref... */
                        mxlnd_peer_decref(peer); /* from peer */
                        conn_ref = 1;
                        peer_ref = 0;
                }
		write_unlock(&kmxlnd_data.kmx_global_lock);
                rx->mxc_conn = conn;
        }

#if MXLND_DEBUG
        CDEBUG(D_NET, "receiving msg bits=0x%llx nob=%d peer=0x%p\n", bits, nob, peer);
#endif

        lntmsg[0] = NULL;
        lntmsg[1] = NULL;

        if (rx->mxc_status.code != MX_STATUS_SUCCESS &&
            rx->mxc_status.code != MX_STATUS_TRUNCATED) {
                CNETERR("rx from %s failed with %s (%d)\n",
                        libcfs_nid2str(rx->mxc_nid),
                        mx_strstatus(rx->mxc_status.code),
                        rx->mxc_status.code);
                credit = 0;
                goto cleanup;
        }

        if (nob == 0) {
                /* this may be a failed GET reply */
                if (type == MXLND_MSG_GET_DATA) {
                        /* get the error (52-59) bits from the match bits */
                        ret = (u32) MXLND_ERROR_VAL(rx->mxc_status.match_info);
                        lntmsg[0] = rx->mxc_lntmsg[0];
                        result = -ret;
                        goto cleanup;
                } else {
                        /* we had a rx complete with 0 bytes (no hdr, nothing) */
                        CNETERR("rx from %s returned with 0 bytes\n",
                                libcfs_nid2str(rx->mxc_nid));
                        goto cleanup;
                }
        }

        /* NOTE PUT_DATA and GET_DATA do not have mxc_msg, do not call unpack() */
        if (type == MXLND_MSG_PUT_DATA) {
                /* result = 0; */
                lntmsg[0] = rx->mxc_lntmsg[0];
                goto cleanup;
        } else if (type == MXLND_MSG_GET_DATA) {
                /* result = 0; */
                lntmsg[0] = rx->mxc_lntmsg[0];
                lntmsg[1] = rx->mxc_lntmsg[1];
                goto cleanup;
        }

        ret = mxlnd_unpack_msg(msg, nob);
        if (ret != 0) {
                CNETERR("Error %d unpacking rx from %s\n",
                        ret, libcfs_nid2str(rx->mxc_nid));
                goto cleanup;
        }
        rx->mxc_nob = nob;
        type = msg->mxm_type;

        if (rx->mxc_nid != msg->mxm_srcnid ||
            kmxlnd_data.kmx_ni->ni_nid != msg->mxm_dstnid) {
                CNETERR("rx with mismatched NID (type %s) (my nid is "
                       "0x%llx and rx msg dst is 0x%llx)\n",
                       mxlnd_msgtype_to_str(type), kmxlnd_data.kmx_ni->ni_nid,
                       msg->mxm_dstnid);
                goto cleanup;
        }

        if ((conn != NULL && msg->mxm_srcstamp != conn->mxk_incarnation) ||
            msg->mxm_dststamp != kmxlnd_data.kmx_incarnation) {
                CNETERR("Stale rx from %s with type %s "
                       "(mxm_srcstamp (%lld) != mxk_incarnation (%lld) "
                       "|| mxm_dststamp (%lld) != kmx_incarnation (%lld))\n",
                       libcfs_nid2str(rx->mxc_nid), mxlnd_msgtype_to_str(type),
                       msg->mxm_srcstamp, conn->mxk_incarnation,
                       msg->mxm_dststamp, kmxlnd_data.kmx_incarnation);
                credit = 0;
                goto cleanup;
        }

        CDEBUG(D_NET, "Received %s with %d credits\n",
                      mxlnd_msgtype_to_str(type), msg->mxm_credits);

        LASSERT(peer != NULL && conn != NULL);
        if (msg->mxm_credits != 0) {
		spin_lock(&conn->mxk_lock);
                if (msg->mxm_srcstamp == conn->mxk_incarnation) {
                        if ((conn->mxk_credits + msg->mxm_credits) >
                             *kmxlnd_tunables.kmx_peercredits) {
                                CNETERR("mxk_credits %d  mxm_credits %d\n",
                                        conn->mxk_credits, msg->mxm_credits);
                        }
                        conn->mxk_credits += msg->mxm_credits;
                        LASSERT(conn->mxk_credits >= 0);
                        LASSERT(conn->mxk_credits <= *kmxlnd_tunables.kmx_peercredits);
                }
		spin_unlock(&conn->mxk_lock);
        }

        CDEBUG(D_NET, "switch %s for rx (0x%llx)\n", mxlnd_msgtype_to_str(type), seq);
        switch (type) {
        case MXLND_MSG_NOOP:
                break;

        case MXLND_MSG_EAGER:
                ret = lnet_parse(kmxlnd_data.kmx_ni, &msg->mxm_u.eager.mxem_hdr,
                                        msg->mxm_srcnid, rx, 0);
                repost = ret < 0;
                break;

        case MXLND_MSG_PUT_REQ:
                ret = lnet_parse(kmxlnd_data.kmx_ni, &msg->mxm_u.put_req.mxprm_hdr,
                                        msg->mxm_srcnid, rx, 1);
                repost = ret < 0;
                break;

        case MXLND_MSG_PUT_ACK: {
                u64  cookie = (u64) msg->mxm_u.put_ack.mxpam_dst_cookie;
                if (cookie > MXLND_MAX_COOKIE) {
                        CNETERR("NAK for msg_type %d from %s\n", rx->mxc_msg_type,
                                libcfs_nid2str(rx->mxc_nid));
                        result = -((u32) MXLND_ERROR_VAL(cookie));
                        lntmsg[0] = rx->mxc_lntmsg[0];
                } else {
                        mxlnd_send_data(kmxlnd_data.kmx_ni, rx->mxc_lntmsg[0],
                                        rx->mxc_peer, MXLND_MSG_PUT_DATA,
                                        rx->mxc_msg->mxm_u.put_ack.mxpam_dst_cookie);
                }
                /* repost == 1 */
                break;
        }
        case MXLND_MSG_GET_REQ:
                ret = lnet_parse(kmxlnd_data.kmx_ni, &msg->mxm_u.get_req.mxgrm_hdr,
                                        msg->mxm_srcnid, rx, 1);
                repost = ret < 0;
                break;

        default:
                CNETERR("Bad MXLND message type %x from %s\n", msg->mxm_type,
                        libcfs_nid2str(rx->mxc_nid));
                ret = -EPROTO;
                break;
        }

        if (ret < 0) {
                CDEBUG(D_NET, "setting PEER_CONN_FAILED\n");
		spin_lock(&conn->mxk_lock);
		mxlnd_set_conn_status(conn, MXLND_CONN_FAIL);
		spin_unlock(&conn->mxk_lock);
	}

cleanup:
	if (conn != NULL) {
		spin_lock(&conn->mxk_lock);
		conn->mxk_last_rx = cfs_time_current(); /* jiffies */
		spin_unlock(&conn->mxk_lock);
        }

        if (repost) {
                /* lnet_parse() failed, etc., repost now */
                mxlnd_put_idle_rx(rx);
                if (conn != NULL && credit == 1) {
                        if (type == MXLND_MSG_PUT_DATA ||
                            type == MXLND_MSG_EAGER ||
                            type == MXLND_MSG_PUT_REQ ||
                            type == MXLND_MSG_NOOP) {
				spin_lock(&conn->mxk_lock);
				conn->mxk_outstanding++;
				spin_unlock(&conn->mxk_lock);
                        }
                }
                if (conn_ref) mxlnd_conn_decref(conn);
                LASSERT(peer_ref == 0);
        }

        if (type == MXLND_MSG_PUT_DATA || type == MXLND_MSG_GET_DATA) {
                CDEBUG(D_NET, "leaving for rx (0x%llx)\n", bits);
        } else {
                CDEBUG(D_NET, "leaving for rx (0x%llx)\n", seq);
        }

        if (lntmsg[0] != NULL) lnet_finalize(kmxlnd_data.kmx_ni, lntmsg[0], result);
        if (lntmsg[1] != NULL) lnet_finalize(kmxlnd_data.kmx_ni, lntmsg[1], result);

        if (conn != NULL && credit == 1) mxlnd_check_sends(peer);

        return;
}

void
mxlnd_handle_connect_msg(kmx_peer_t *peer, u8 msg_type, mx_status_t status)
{
        kmx_ctx_t       *tx     = NULL;
        kmx_msg_t       *txmsg  = NULL;
        kmx_conn_t      *conn   = peer->mxp_conn;
        u64             nic_id  = 0ULL;
        u32             ep_id   = 0;
        u32             sid     = 0;
        u8              type    = (msg_type == MXLND_MSG_ICON_REQ ?
                                   MXLND_MSG_CONN_REQ : MXLND_MSG_CONN_ACK);

        /* a conn ref was taken when calling mx_iconnect(),
         * hold it until CONN_REQ or CONN_ACK completes */

        CDEBUG(D_NET, "entering\n");
        if (status.code != MX_STATUS_SUCCESS) {
                int send_bye    = (msg_type == MXLND_MSG_ICON_REQ ? 0 : 1);

                CNETERR("mx_iconnect() failed for %s with %s (%d) "
                        "to %s mxp_nid = 0x%llx mxp_nic_id = 0x%0llx mxp_ep_id = %d\n",
                        mxlnd_msgtype_to_str(msg_type),
                        mx_strstatus(status.code), status.code,
                        libcfs_nid2str(peer->mxp_nid),
                        peer->mxp_nid,
                        peer->mxp_nic_id,
                        peer->mxp_ep_id);
		spin_lock(&conn->mxk_lock);
		mxlnd_set_conn_status(conn, MXLND_CONN_FAIL);
		spin_unlock(&conn->mxk_lock);

                if (cfs_time_after(jiffies, peer->mxp_reconnect_time +
                                   MXLND_CONNECT_TIMEOUT)) {
                        CNETERR("timeout, calling conn_disconnect()\n");
                        mxlnd_conn_disconnect(conn, 0, send_bye);
                }

                mxlnd_conn_decref(conn);
                return;
        }
        mx_decompose_endpoint_addr2(status.source, &nic_id, &ep_id, &sid);
	write_lock(&kmxlnd_data.kmx_global_lock);
	spin_lock(&conn->mxk_lock);
	conn->mxk_epa = status.source;
	mx_set_endpoint_addr_context(conn->mxk_epa, (void *) conn);
	if (msg_type == MXLND_MSG_ICON_ACK && likely(!peer->mxp_incompatible)) {
		mxlnd_set_conn_status(conn, MXLND_CONN_READY);
	}
	spin_unlock(&conn->mxk_lock);
	write_unlock(&kmxlnd_data.kmx_global_lock);

	/* mx_iconnect() succeeded, reset delay to 0 */
	write_lock(&kmxlnd_data.kmx_global_lock);
	peer->mxp_reconnect_time = 0;
	peer->mxp_conn->mxk_sid = sid;
	write_unlock(&kmxlnd_data.kmx_global_lock);

        /* marshal CONN_REQ or CONN_ACK msg */
        /* we are still using the conn ref from iconnect() - do not take another */
        tx = mxlnd_get_idle_tx();
        if (tx == NULL) {
                CNETERR("Can't obtain %s tx for %s\n",
                       mxlnd_msgtype_to_str(type),
                       libcfs_nid2str(peer->mxp_nid));
		spin_lock(&conn->mxk_lock);
		mxlnd_set_conn_status(conn, MXLND_CONN_FAIL);
		spin_unlock(&conn->mxk_lock);
                mxlnd_conn_decref(conn);
                return;
        }

        tx->mxc_peer = peer;
        tx->mxc_conn = conn;
        tx->mxc_deadline = jiffies + MXLND_CONNECT_TIMEOUT;
        CDEBUG(D_NET, "sending %s\n", mxlnd_msgtype_to_str(type));
        mxlnd_init_tx_msg (tx, type, sizeof(kmx_connreq_msg_t), peer->mxp_nid);
        txmsg = tx->mxc_msg;
        txmsg->mxm_u.conn_req.mxcrm_queue_depth = *kmxlnd_tunables.kmx_peercredits;
        txmsg->mxm_u.conn_req.mxcrm_eager_size = MXLND_MSG_SIZE;
        tx->mxc_match = mxlnd_create_match(tx, 0);

        mxlnd_queue_tx(tx);
        return;
}

/**
 * mxlnd_request_waitd - the MX request completion thread(s)
 * @arg - thread id (as a void *)
 *
 * This thread waits for a MX completion and then completes the request.
 * We will create one thread per CPU.
 */
int
mxlnd_request_waitd(void *arg)
{
        long                    id              = (long) arg;
        __u32                   result          = 0;
        mx_return_t             mxret           = MX_SUCCESS;
        mx_status_t             status;
        kmx_ctx_t              *ctx             = NULL;
        enum kmx_req_state      req_type        = MXLND_REQ_TX;
        kmx_peer_t             *peer            = NULL;
        kmx_conn_t             *conn            = NULL;
#if MXLND_POLLING
        int                     count           = 0;
#endif

        memset(&status, 0, sizeof(status));

        CDEBUG(D_NET, "%s starting\n", name);

	while (!(atomic_read(&kmxlnd_data.kmx_shutdown))) {
		u8      msg_type        = 0;

                mxret = MX_SUCCESS;
                result = 0;
#if MXLND_POLLING
                if (id == 0 && count++ < *kmxlnd_tunables.kmx_polling) {
                        mxret = mx_test_any(kmxlnd_data.kmx_endpt, 0ULL, 0ULL,
                                            &status, &result);
                } else {
                        count = 0;
                        mxret = mx_wait_any(kmxlnd_data.kmx_endpt, MXLND_WAIT_TIMEOUT,
                                            0ULL, 0ULL, &status, &result);
                }
#else
                mxret = mx_wait_any(kmxlnd_data.kmx_endpt, MXLND_WAIT_TIMEOUT,
                                    0ULL, 0ULL, &status, &result);
#endif
		if (unlikely(atomic_read(&kmxlnd_data.kmx_shutdown)))
			break;

                if (result != 1) {
                        /* nothing completed... */
                        continue;
                }

                CDEBUG(D_NET, "wait_any() returned with %s (%d) with "
                       "match_info 0x%llx and length %d\n",
                       mx_strstatus(status.code), status.code,
                       (u64) status.match_info, status.msg_length);

                if (status.code != MX_STATUS_SUCCESS) {
                        CNETERR("wait_any() failed with %s (%d) with "
                                "match_info 0x%llx and length %d\n",
                                mx_strstatus(status.code), status.code,
                                (u64) status.match_info, status.msg_length);
                }

                msg_type = MXLND_MSG_TYPE(status.match_info);

                /* This may be a mx_iconnect() request completing,
                 * check the bit mask for CONN_REQ and CONN_ACK */
                if (msg_type == MXLND_MSG_ICON_REQ ||
                    msg_type == MXLND_MSG_ICON_ACK) {
                        peer = (kmx_peer_t*) status.context;
                        mxlnd_handle_connect_msg(peer, msg_type, status);
                        continue;
                }

                /* This must be a tx or rx */

                /* NOTE: if this is a RX from the unexpected callback, it may
                 * have very little info. If we dropped it in unexpected_recv(),
                 * it will not have a context. If so, ignore it. */
                ctx = (kmx_ctx_t *) status.context;
                if (ctx != NULL) {

                        req_type = ctx->mxc_type;
                        conn = ctx->mxc_conn; /* this may be NULL */
                        mxlnd_deq_pending_ctx(ctx);

                        /* copy status to ctx->mxc_status */
                        ctx->mxc_status = status;

                        switch (req_type) {
                        case MXLND_REQ_TX:
                                mxlnd_handle_tx_completion(ctx);
                                break;
                        case MXLND_REQ_RX:
                                mxlnd_handle_rx_completion(ctx);
                                break;
                        default:
                                CNETERR("Unknown ctx type %d\n", req_type);
                                LBUG();
                                break;
                        }

                        /* conn is always set except for the first CONN_REQ rx
                         * from a new peer */
                        if (status.code != MX_STATUS_SUCCESS && conn != NULL) {
                                mxlnd_conn_disconnect(conn, 1, 1);
                        }
                }
                CDEBUG(D_NET, "waitd() completed task\n");
        }
        CDEBUG(D_NET, "%s stopping\n", name);
        mxlnd_thread_stop(id);
        return 0;
}


unsigned long
mxlnd_check_timeouts(unsigned long now)
{
        int             i               = 0;
        int             disconnect      = 0;
        unsigned long   next            = 0; /* jiffies */
        kmx_peer_t      *peer           = NULL;
        kmx_conn_t      *conn           = NULL;
	rwlock_t	*g_lock		= &kmxlnd_data.kmx_global_lock;

	read_lock(g_lock);
	for (i = 0; i < MXLND_HASH_SIZE; i++) {
		cfs_list_for_each_entry(peer, &kmxlnd_data.kmx_peers[i],
					mxp_list) {

			if (unlikely(atomic_read(&kmxlnd_data.kmx_shutdown))) {
				read_unlock(g_lock);
				return next;
			}

                        conn = peer->mxp_conn;
                        if (conn) {
                                mxlnd_conn_addref(conn);
                        } else {
                                continue;
                        }

			spin_lock(&conn->mxk_lock);

			/* if nothing pending (timeout == 0) or
			 * if conn is already disconnected,
			 * skip this conn */
			if (conn->mxk_timeout == 0 ||
			    conn->mxk_status == MXLND_CONN_DISCONNECT) {
				spin_unlock(&conn->mxk_lock);
                                mxlnd_conn_decref(conn);
                                continue;
                        }

                        /* we want to find the timeout that will occur first.
                         * if it is in the future, we will sleep until then.
                         * if it is in the past, then we will sleep one
                         * second and repeat the process. */
                        if ((next == 0) ||
                            (cfs_time_before(conn->mxk_timeout, next))) {
                                next = conn->mxk_timeout;
                        }

                        disconnect = 0;

			if (cfs_time_aftereq(now, conn->mxk_timeout))
				disconnect = 1;
			spin_unlock(&conn->mxk_lock);

			if (disconnect)
				mxlnd_conn_disconnect(conn, 1, 1);
			mxlnd_conn_decref(conn);
		}
	}
	read_unlock(g_lock);
	if (next == 0)
		next = now + MXLND_COMM_TIMEOUT;

	return next;
}

void
mxlnd_passive_connect(kmx_connparams_t *cp)
{
        int             ret             = 0;
        int             incompatible    = 0;
        u64             nic_id          = 0ULL;
        u32             ep_id           = 0;
        u32             sid             = 0;
        int             conn_ref        = 0;
        kmx_msg_t       *msg            = &cp->mxr_msg;
        kmx_peer_t      *peer           = cp->mxr_peer;
        kmx_conn_t      *conn           = NULL;
	rwlock_t	*g_lock		= &kmxlnd_data.kmx_global_lock;

        mx_decompose_endpoint_addr2(cp->mxr_epa, &nic_id, &ep_id, &sid);

        ret = mxlnd_unpack_msg(msg, cp->mxr_nob);
        if (ret != 0) {
                if (peer) {
                        CNETERR("Error %d unpacking CONN_REQ from %s\n",
                               ret, libcfs_nid2str(peer->mxp_nid));
                } else {
                        CNETERR("Error %d unpacking CONN_REQ from "
                               "unknown host with nic_id 0x%llx\n", ret, nic_id);
                }
                goto cleanup;
        }
        if (kmxlnd_data.kmx_ni->ni_nid != msg->mxm_dstnid) {
                CNETERR("Can't accept %s: bad dst nid %s\n",
                                libcfs_nid2str(msg->mxm_srcnid),
                                libcfs_nid2str(msg->mxm_dstnid));
                goto cleanup;
        }
        if (msg->mxm_u.conn_req.mxcrm_queue_depth != *kmxlnd_tunables.kmx_peercredits) {
                CNETERR("Can't accept %s: incompatible queue depth "
                            "%d (%d wanted)\n",
                                libcfs_nid2str(msg->mxm_srcnid),
                                msg->mxm_u.conn_req.mxcrm_queue_depth,
                                *kmxlnd_tunables.kmx_peercredits);
                incompatible = 1;
        }
        if (msg->mxm_u.conn_req.mxcrm_eager_size != MXLND_MSG_SIZE) {
                CNETERR("Can't accept %s: incompatible EAGER size "
                            "%d (%d wanted)\n",
                                libcfs_nid2str(msg->mxm_srcnid),
                                msg->mxm_u.conn_req.mxcrm_eager_size,
                                (int) MXLND_MSG_SIZE);
                incompatible = 1;
        }

        if (peer == NULL) {
                peer = mxlnd_find_peer_by_nid(msg->mxm_srcnid, 0); /* adds peer ref */
                if (peer == NULL) {
                        int             hash    = 0;
                        u32             board   = 0;
                        kmx_peer_t      *existing_peer    = NULL;

                        hash = mxlnd_nid_to_hash(msg->mxm_srcnid);

                        mx_nic_id_to_board_number(nic_id, &board);

                        /* adds conn ref for peer and one for this function */
                        ret = mxlnd_peer_alloc(&peer, msg->mxm_srcnid,
                                               board, ep_id, 0ULL);
                        if (ret != 0) {
                                goto cleanup;
                        }
                        peer->mxp_conn->mxk_sid = sid;
                        LASSERT(peer->mxp_ep_id == ep_id);
			write_lock(g_lock);
                        existing_peer = mxlnd_find_peer_by_nid_locked(msg->mxm_srcnid);
                        if (existing_peer) {
                                mxlnd_conn_decref(peer->mxp_conn);
                                mxlnd_peer_decref(peer);
                                peer = existing_peer;
                                mxlnd_conn_addref(peer->mxp_conn);
                                conn = peer->mxp_conn;
			} else {
				cfs_list_add_tail(&peer->mxp_list,
						  &kmxlnd_data.kmx_peers[hash]);
				atomic_inc(&kmxlnd_data.kmx_npeers);
			}
			write_unlock(g_lock);
                } else {
                        ret = mxlnd_conn_alloc(&conn, peer); /* adds 2nd ref */
			write_lock(g_lock);
                        mxlnd_peer_decref(peer); /* drop ref taken above */
			write_unlock(g_lock);
                        if (ret != 0) {
                                CNETERR("Cannot allocate mxp_conn\n");
                                goto cleanup;
                        }
                }
                conn_ref = 1; /* peer/conn_alloc() added ref for this function */
                conn = peer->mxp_conn;
        } else { /* unexpected handler found peer */
                kmx_conn_t      *old_conn       = peer->mxp_conn;

                if (sid != peer->mxp_conn->mxk_sid) {
                        /* do not call mx_disconnect() or send a BYE */
                        mxlnd_conn_disconnect(old_conn, 0, 0);

                        /* This allocs a conn, points peer->mxp_conn to this one.
                        * The old conn is still on the peer->mxp_conns list.
                        * As the pending requests complete, they will call
                        * conn_decref() which will eventually free it. */
                        ret = mxlnd_conn_alloc(&conn, peer);
                        if (ret != 0) {
                                CNETERR("Cannot allocate peer->mxp_conn\n");
                                goto cleanup;
                        }
                        /* conn_alloc() adds one ref for the peer and one
                         * for this function */
                        conn_ref = 1;

                        peer->mxp_conn->mxk_sid = sid;
                } else {
                        /* same sid */
                        conn = peer->mxp_conn;
                }
        }
	write_lock(g_lock);
	peer->mxp_incompatible = incompatible;
	write_unlock(g_lock);
	spin_lock(&conn->mxk_lock);
	conn->mxk_incarnation = msg->mxm_srcstamp;
	mxlnd_set_conn_status(conn, MXLND_CONN_WAIT);
	spin_unlock(&conn->mxk_lock);

        /* handle_conn_ack() will create the CONN_ACK msg */
        mxlnd_iconnect(peer, (u8) MXLND_MSG_ICON_ACK);

cleanup:
        if (conn_ref) mxlnd_conn_decref(conn);

        mxlnd_connparams_free(cp);
        return;
}

void
mxlnd_check_conn_ack(kmx_connparams_t *cp)
{
        int             ret             = 0;
        int             incompatible    = 0;
        u64             nic_id          = 0ULL;
        u32             ep_id           = 0;
        u32             sid             = 0;
        kmx_msg_t       *msg            = &cp->mxr_msg;
        kmx_peer_t      *peer           = cp->mxr_peer;
        kmx_conn_t      *conn           = cp->mxr_conn;

        mx_decompose_endpoint_addr2(cp->mxr_epa, &nic_id, &ep_id, &sid);

        ret = mxlnd_unpack_msg(msg, cp->mxr_nob);
        if (ret != 0) {
                if (peer) {
                        CNETERR("Error %d unpacking CONN_ACK from %s\n",
                               ret, libcfs_nid2str(peer->mxp_nid));
                } else {
                        CNETERR("Error %d unpacking CONN_ACK from "
                               "unknown host with nic_id 0x%llx\n", ret, nic_id);
                }
                ret = -1;
                incompatible = 1;
                goto failed;
        }
        if (kmxlnd_data.kmx_ni->ni_nid != msg->mxm_dstnid) {
                CNETERR("Can't accept CONN_ACK from %s: "
                       "bad dst nid %s\n", libcfs_nid2str(msg->mxm_srcnid),
                        libcfs_nid2str(msg->mxm_dstnid));
                ret = -1;
                goto failed;
        }
        if (msg->mxm_u.conn_req.mxcrm_queue_depth != *kmxlnd_tunables.kmx_peercredits) {
                CNETERR("Can't accept CONN_ACK from %s: "
                       "incompatible queue depth %d (%d wanted)\n",
                        libcfs_nid2str(msg->mxm_srcnid),
                        msg->mxm_u.conn_req.mxcrm_queue_depth,
                        *kmxlnd_tunables.kmx_peercredits);
                incompatible = 1;
                ret = -1;
                goto failed;
        }
        if (msg->mxm_u.conn_req.mxcrm_eager_size != MXLND_MSG_SIZE) {
                CNETERR("Can't accept CONN_ACK from %s: "
                        "incompatible EAGER size %d (%d wanted)\n",
                        libcfs_nid2str(msg->mxm_srcnid),
                        msg->mxm_u.conn_req.mxcrm_eager_size,
                        (int) MXLND_MSG_SIZE);
                incompatible = 1;
                ret = -1;
                goto failed;
        }
	write_lock(&kmxlnd_data.kmx_global_lock);
	peer->mxp_incompatible = incompatible;
	write_unlock(&kmxlnd_data.kmx_global_lock);
	spin_lock(&conn->mxk_lock);
        conn->mxk_credits = *kmxlnd_tunables.kmx_peercredits;
        conn->mxk_outstanding = 0;
        conn->mxk_incarnation = msg->mxm_srcstamp;
        conn->mxk_timeout = 0;
        if (!incompatible) {
                CDEBUG(D_NET, "setting peer %s CONN_READY\n",
                       libcfs_nid2str(msg->mxm_srcnid));
                mxlnd_set_conn_status(conn, MXLND_CONN_READY);
        }
	spin_unlock(&conn->mxk_lock);

	if (!incompatible)
		mxlnd_check_sends(peer);

failed:
	if (ret < 0) {
		spin_lock(&conn->mxk_lock);
		mxlnd_set_conn_status(conn, MXLND_CONN_FAIL);
		spin_unlock(&conn->mxk_lock);
	}

	if (incompatible) mxlnd_conn_disconnect(conn, 0, 0);

	mxlnd_connparams_free(cp);
	return;
}

int
mxlnd_abort_msgs(void)
{
	int			count		= 0;
	cfs_list_t		*orphans	= &kmxlnd_data.kmx_orphan_msgs;
	spinlock_t		*g_conn_lock	= &kmxlnd_data.kmx_conn_lock;

	/* abort orphans */
	spin_lock(g_conn_lock);
	while (!cfs_list_empty(orphans)) {
		kmx_ctx_t       *ctx     = NULL;
		kmx_conn_t      *conn   = NULL;

		ctx = cfs_list_entry(orphans->next, kmx_ctx_t, mxc_list);
		cfs_list_del_init(&ctx->mxc_list);
		spin_unlock(g_conn_lock);

                ctx->mxc_errno = -ECONNABORTED;
                conn = ctx->mxc_conn;
                CDEBUG(D_NET, "aborting %s %s %s\n",
                       mxlnd_msgtype_to_str(ctx->mxc_msg_type),
                       ctx->mxc_type == MXLND_REQ_TX ? "(TX) to" : "(RX) from",
                       libcfs_nid2str(ctx->mxc_nid));
                if (ctx->mxc_type == MXLND_REQ_TX) {
                        mxlnd_put_idle_tx(ctx); /* do not hold any locks */
                        if (conn) mxlnd_conn_decref(conn); /* for this tx */
                } else {
                        ctx->mxc_state = MXLND_CTX_CANCELED;
                        mxlnd_handle_rx_completion(ctx);
                }

                count++;
		spin_lock(g_conn_lock);
	}
	spin_unlock(g_conn_lock);

	return count;
}

int
mxlnd_free_conn_zombies(void)
{
	int		count		= 0;
	cfs_list_t	*zombies	= &kmxlnd_data.kmx_conn_zombies;
	spinlock_t	*g_conn_lock	= &kmxlnd_data.kmx_conn_lock;
	rwlock_t	*g_lock		= &kmxlnd_data.kmx_global_lock;

	/* cleanup any zombies */
	spin_lock(g_conn_lock);
	while (!cfs_list_empty(zombies)) {
		kmx_conn_t	*conn   = NULL;

		conn = cfs_list_entry(zombies->next, kmx_conn_t, mxk_zombie);
		cfs_list_del_init(&conn->mxk_zombie);
		spin_unlock(g_conn_lock);

		write_lock(g_lock);
		mxlnd_conn_free_locked(conn);
		write_unlock(g_lock);

		count++;
		spin_lock(g_conn_lock);
	}
	spin_unlock(g_conn_lock);
	CDEBUG(D_NET, "%s: freed %d zombies\n", __func__, count);
	return count;
}

/**
 * mxlnd_connd - handles incoming connection requests
 * @arg - thread id (as a void *)
 *
 * This thread handles incoming connection requests
 */
int
mxlnd_connd(void *arg)
{
	long                    id              = (long) arg;

	CDEBUG(D_NET, "connd starting\n");

	while (!(atomic_read(&kmxlnd_data.kmx_shutdown))) {
		int                ret             = 0;
		kmx_connparams_t  *cp              = NULL;
		spinlock_t	  *g_conn_lock	= &kmxlnd_data.kmx_conn_lock;
		cfs_list_t	  *conn_reqs	= &kmxlnd_data.kmx_conn_reqs;

		ret = down_interruptible(&kmxlnd_data.kmx_conn_sem);

		if (atomic_read(&kmxlnd_data.kmx_shutdown))
			break;

                if (ret != 0)
                        continue;

                ret = mxlnd_abort_msgs();
                ret += mxlnd_free_conn_zombies();

		spin_lock(g_conn_lock);
		if (cfs_list_empty(conn_reqs)) {
			if (ret == 0)
				CNETERR("connd woke up but did not find a "
					"kmx_connparams_t or zombie conn\n");
			spin_unlock(g_conn_lock);
			continue;
		}
		cp = cfs_list_entry(conn_reqs->next, kmx_connparams_t,
				    mxr_list);
		cfs_list_del_init(&cp->mxr_list);
		spin_unlock(g_conn_lock);

                switch (MXLND_MSG_TYPE(cp->mxr_match)) {
                case MXLND_MSG_CONN_REQ:
                        /* We have a connection request. Handle it. */
                        mxlnd_passive_connect(cp);
                        break;
                case MXLND_MSG_CONN_ACK:
                        /* The peer is ready for messages */
                        mxlnd_check_conn_ack(cp);
                        break;
                }
        }

        mxlnd_free_conn_zombies();

        CDEBUG(D_NET, "connd stopping\n");
        mxlnd_thread_stop(id);
        return 0;
}

/**
 * mxlnd_timeoutd - enforces timeouts on messages
 * @arg - thread id (as a void *)
 *
 * This thread queries each peer for its earliest timeout. If a peer has timed out,
 * it calls mxlnd_conn_disconnect().
 *
 * After checking for timeouts, try progressing sends (call check_sends()).
 */
int
mxlnd_timeoutd(void *arg)
{
	int             i       = 0;
	long            id      = (long) arg;
	unsigned long   now     = 0;
	unsigned long   next    = 0;
	unsigned long   delay   = msecs_to_jiffies(MSEC_PER_SEC);
	kmx_peer_t     *peer    = NULL;
	kmx_peer_t     *temp    = NULL;
	kmx_conn_t     *conn    = NULL;
	rwlock_t   *g_lock  = &kmxlnd_data.kmx_global_lock;

        CDEBUG(D_NET, "timeoutd starting\n");

	while (!(atomic_read(&kmxlnd_data.kmx_shutdown))) {

                now = jiffies;
                /* if the next timeout has not arrived, go back to sleep */
                if (cfs_time_after(now, next)) {
                        next = mxlnd_check_timeouts(now);
                }

                /* try to progress peers' txs */
		write_lock(g_lock);
                for (i = 0; i < MXLND_HASH_SIZE; i++) {
                        cfs_list_t *peers = &kmxlnd_data.kmx_peers[i];

                        /* NOTE we are safe against the removal of peer, but
                         * not against the removal of temp */
                        cfs_list_for_each_entry_safe(peer, temp, peers,
                                                     mxp_list) {
				if (atomic_read(&kmxlnd_data.kmx_shutdown))
                                        break;
                                mxlnd_peer_addref(peer); /* add ref... */
                                conn = peer->mxp_conn;
                                if (conn && conn->mxk_status != MXLND_CONN_DISCONNECT) {
                                        mxlnd_conn_addref(conn); /* take ref... */
                                } else {
                                        CDEBUG(D_NET, "ignoring %s\n",
                                               libcfs_nid2str(peer->mxp_nid));
                                        mxlnd_peer_decref(peer); /* ...to here */
                                        continue;
                                }

				if ((conn->mxk_status == MXLND_CONN_READY ||
				    conn->mxk_status == MXLND_CONN_FAIL) &&
				    cfs_time_after(now,
						   conn->mxk_last_tx +
						   msecs_to_jiffies(MSEC_PER_SEC))) {
					write_unlock(g_lock);
					mxlnd_check_sends(peer);
					write_lock(g_lock);
				}
				mxlnd_conn_decref(conn); /* until here */
				mxlnd_peer_decref(peer); /* ...to here */
			}
		}
		write_unlock(g_lock);

                mxlnd_sleep(delay);
        }
        CDEBUG(D_NET, "timeoutd stopping\n");
        mxlnd_thread_stop(id);
        return 0;
}
