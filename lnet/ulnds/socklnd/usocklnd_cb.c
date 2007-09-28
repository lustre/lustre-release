/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Maxim Patlasov <maxim@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 */

#include "usocklnd.h"

static int
usocklnd_send_tx_immediately(usock_conn_t *conn, usock_tx_t *tx)
{
        int           rc;
        int           rc2;
        int           partial_send = 0;
        usock_peer_t *peer         = conn->uc_peer;

        LASSERT (peer != NULL);

        /* usocklnd_enqueue_tx() turned it on for us */
        LASSERT(conn->uc_sending);

        //counter_imm_start++;
        rc = usocklnd_send_tx(conn, tx);
        if (rc == 0) { /* partial send or connection closed */
                pthread_mutex_lock(&conn->uc_lock);
                list_add(&tx->tx_list, &conn->uc_tx_list);
                conn->uc_sending = 0;
                pthread_mutex_unlock(&conn->uc_lock);
                partial_send = 1;
        } else {                
                usocklnd_destroy_tx(peer->up_ni, tx);
                /* NB: lnetmsg was finalized, so we *must* return 0 */

                if (rc < 0) { /* real error */                       
                        usocklnd_conn_kill(conn);
                        return 0;
                }
                
                /* rc == 1: tx was sent completely */
                rc = 0; /* let's say to caller 'Ok' */
                //counter_imm_complete++;
        }

        pthread_mutex_lock(&conn->uc_lock);
        conn->uc_sending = 0;               

        /* schedule write handler */
        if (partial_send ||
            (conn->uc_state == UC_READY &&
             (!list_empty(&conn->uc_tx_list) ||
              !list_empty(&conn->uc_zcack_list)))) {
                conn->uc_tx_deadline = 
                        cfs_time_shift(usock_tuns.ut_timeout);
                conn->uc_tx_flag = 1;
                rc2 = usocklnd_add_pollrequest(conn, POLL_TX_SET_REQUEST, POLLOUT);
                if (rc2 != 0)
                        usocklnd_conn_kill_locked(conn);
                else
                        usocklnd_wakeup_pollthread(conn->uc_pt_idx);
        }

        pthread_mutex_unlock(&conn->uc_lock);

        return rc;
}

int
usocklnd_send(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg)
{
        usock_tx_t       *tx;
        lnet_process_id_t target = lntmsg->msg_target;
        usock_peer_t     *peer;
        int               type;
        int               rc;
        usock_conn_t     *conn;
        int               send_immediately;
        
        tx = usocklnd_create_tx(lntmsg);
        if (tx == NULL)
                return -ENOMEM;
        
        rc = usocklnd_find_or_create_peer(ni, target, &peer);
        if (rc) {
                LIBCFS_FREE (tx, tx->tx_size);
                return rc;
        }                
        /* peer cannot disappear now because its refcount was incremented */

        type = usocklnd_get_conn_type(lntmsg);
        rc = usocklnd_find_or_create_conn(peer, type, &conn, tx, NULL,
                                          &send_immediately);
        if (rc != 0) {
                usocklnd_peer_decref(peer);
                usocklnd_check_peer_stale(ni, target);
                LIBCFS_FREE (tx, tx->tx_size);
                return rc;
        }
        /* conn cannot disappear now because its refcount was incremented */

        if (send_immediately)
                rc = usocklnd_send_tx_immediately(conn, tx);

        usocklnd_conn_decref(conn);
        usocklnd_peer_decref(peer);
        return rc;
}

int
usocklnd_recv(lnet_ni_t *ni, void *private, lnet_msg_t *msg, int delayed,
              unsigned int niov, struct iovec *iov, lnet_kiov_t *kiov,
              unsigned int offset, unsigned int mlen, unsigned int rlen)
{
        int           rc   = 0;
        usock_conn_t *conn = (usock_conn_t *)private;

        /* I don't think that we'll win much concurrency moving lock()
         * call below lnet_extract_iov() */
        pthread_mutex_lock(&conn->uc_lock);
        
        conn->uc_rx_lnetmsg = msg;
        conn->uc_rx_nob_wanted = mlen;
        conn->uc_rx_nob_left = rlen;
        conn->uc_rx_iov = conn->uc_rx_iova;
        conn->uc_rx_niov =
                lnet_extract_iov(LNET_MAX_IOV, conn->uc_rx_iov,
                                 niov, iov, offset, mlen);

        /* the gap between lnet_parse() and usocklnd_recv() happened? */
        if (conn->uc_rx_state == UC_RX_PARSE_WAIT) {
                conn->uc_rx_flag = 1; /* waiting for incoming lnet payload */
                conn->uc_rx_deadline = 
                        cfs_time_shift(usock_tuns.ut_timeout);                
                rc = usocklnd_add_pollrequest(conn, POLL_RX_SET_REQUEST, POLLIN);
                if (rc != 0) {
                        usocklnd_conn_kill_locked(conn);
                        goto recv_out;
                }
                usocklnd_wakeup_pollthread(conn->uc_pt_idx);
        }

        conn->uc_rx_state = UC_RX_LNET_PAYLOAD;
  recv_out:        
        pthread_mutex_unlock(&conn->uc_lock);
        usocklnd_conn_decref(conn);
        return rc;
}

int
usocklnd_accept(lnet_ni_t *ni, int sock_fd)
{
        int           rc;
        usock_conn_t *conn;
        
        rc = usocklnd_create_passive_conn(ni, sock_fd, &conn);
        if (rc)
                return rc;
        LASSERT(conn != NULL);
        
        /* disable shutdown event temporarily */
        lnet_ni_addref(ni);

        rc = usocklnd_add_pollrequest(conn, POLL_ADD_REQUEST, POLLIN);
        if (rc == 0)
                usocklnd_wakeup_pollthread(conn->uc_pt_idx);

        /* NB: conn reference counter was incremented while adding
         * poll request if rc == 0 */
        
        usocklnd_conn_decref(conn); /* should destroy conn if rc != 0 */
        return rc;
}
