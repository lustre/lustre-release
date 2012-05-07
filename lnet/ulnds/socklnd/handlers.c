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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/ulnds/socklnd/handlers.c
 *
 * Author: Maxim Patlasov <maxim@clusterfs.com>
 */

#include "usocklnd.h"
#include <unistd.h>
#include <sys/syscall.h>

int
usocklnd_notifier_handler(int fd)
{
        int notification;
        return syscall(SYS_read, fd, &notification, sizeof(notification));
}

void
usocklnd_exception_handler(usock_conn_t *conn)
{
        pthread_mutex_lock(&conn->uc_lock);

        if (conn->uc_state == UC_CONNECTING ||
            conn->uc_state == UC_SENDING_HELLO)
                usocklnd_conn_kill_locked(conn);

        pthread_mutex_unlock(&conn->uc_lock);
}

int
usocklnd_read_handler(usock_conn_t *conn)
{
        int rc;
        int continue_reading;
        int state;

  read_again:
        rc = 0;
        pthread_mutex_lock(&conn->uc_lock);
        state = conn->uc_state;

        /* process special case: LNET calls lnd_recv() asyncronously */
        if (state == UC_READY && conn->uc_rx_state == UC_RX_PARSE) {
                /* still don't have usocklnd_recv() called */
                rc = usocklnd_add_pollrequest(conn, POLL_RX_SET_REQUEST, 0);
                if (rc == 0)
                        conn->uc_rx_state = UC_RX_PARSE_WAIT;
                else
                        usocklnd_conn_kill_locked(conn);

                pthread_mutex_unlock(&conn->uc_lock);
                return rc;
        }

        pthread_mutex_unlock(&conn->uc_lock);
        /* From here and below the conn cannot be changed
         * asyncronously, except:
         * 1) usocklnd_send() can work with uc_tx_list and uc_zcack_list,
         * 2) usocklnd_shutdown() can change uc_state to UC_DEAD */

        switch (state) {

        case UC_RECEIVING_HELLO:
        case UC_READY:
                if (conn->uc_rx_nob_wanted != 0) {
                        /* read from conn fd as much wanted data as possible */
                        rc = usocklnd_read_data(conn);
                        if (rc == 0) /* partial read */
                                break;
                        if (rc < 0) {/* error happened or EOF */
                                usocklnd_conn_kill(conn);
                                break;
                        }
                }

                /* process incoming data */
                if (state == UC_READY )
                        rc = usocklnd_read_msg(conn, &continue_reading);
                else /* state == UC_RECEIVING_HELLO */
                        rc = usocklnd_read_hello(conn, &continue_reading);

                if (rc < 0) {
                        usocklnd_conn_kill(conn);
                        break;
                }

                if (continue_reading)
                        goto read_again;

                break;

        case UC_DEAD:
                break;

        default:
                LBUG();
        }

        return rc;
}

/* Switch on rx_state.
 * Return 0 on success, 1 if whole packet is read, else return <0
 * Always set cont_flag: 1 if we're ready to continue reading, else 0
 * NB: If whole packet is read, cont_flag will be set to zero to take
 * care of fairess
 */
int
usocklnd_read_msg(usock_conn_t *conn, int *cont_flag)
{
        int   rc = 0;
        __u64 cookie;

       *cont_flag = 0;

        /* smth. new emerged in RX part - let's process it */
        switch (conn->uc_rx_state) {
        case UC_RX_KSM_HEADER:
                if (conn->uc_flip) {
                        __swab32s(&conn->uc_rx_msg.ksm_type);
                        __swab32s(&conn->uc_rx_msg.ksm_csum);
                        __swab64s(&conn->uc_rx_msg.ksm_zc_cookies[0]);
                        __swab64s(&conn->uc_rx_msg.ksm_zc_cookies[1]);
                }

                /* we never send packets for wich zc-acking is required */
                if (conn->uc_rx_msg.ksm_type != KSOCK_MSG_LNET ||
                    conn->uc_rx_msg.ksm_zc_cookies[1] != 0) {
                        conn->uc_errored = 1;
                        return -EPROTO;
                }

                /* zc_req will be processed later, when
                   lnet payload will be received */

                usocklnd_rx_lnethdr_state_transition(conn);
                *cont_flag = 1;
                break;

        case UC_RX_LNET_HEADER:
                if (the_lnet.ln_pid & LNET_PID_USERFLAG) {
                        /* replace dest_nid,pid (ksocknal sets its own) */
                        conn->uc_rx_msg.ksm_u.lnetmsg.ksnm_hdr.dest_nid =
                                cpu_to_le64(conn->uc_peer->up_ni->ni_nid);
                        conn->uc_rx_msg.ksm_u.lnetmsg.ksnm_hdr.dest_pid =
                                cpu_to_le32(the_lnet.ln_pid);

                } else if (conn->uc_peer->up_peerid.pid & LNET_PID_USERFLAG) {
                        /* Userspace peer */
                        lnet_process_id_t *id = &conn->uc_peer->up_peerid;
                        lnet_hdr_t        *lhdr = &conn->uc_rx_msg.ksm_u.lnetmsg.ksnm_hdr;

                        /* Substitute process ID assigned at connection time */
                        lhdr->src_pid = cpu_to_le32(id->pid);
                        lhdr->src_nid = cpu_to_le64(id->nid);
                }

                conn->uc_rx_state = UC_RX_PARSE;
                usocklnd_conn_addref(conn); /* ++ref while parsing */

                rc = lnet_parse(conn->uc_peer->up_ni,
                                &conn->uc_rx_msg.ksm_u.lnetmsg.ksnm_hdr,
                                conn->uc_peerid.nid, conn, 0);

                if (rc < 0) {
                        /* I just received garbage: give up on this conn */
                        conn->uc_errored = 1;
                        usocklnd_conn_decref(conn);
                        return -EPROTO;
                }

                /* Race with usocklnd_recv() is possible */
                pthread_mutex_lock(&conn->uc_lock);
                LASSERT (conn->uc_rx_state == UC_RX_PARSE ||
                         conn->uc_rx_state == UC_RX_LNET_PAYLOAD);

                /* check whether usocklnd_recv() got called */
                if (conn->uc_rx_state == UC_RX_LNET_PAYLOAD)
                        *cont_flag = 1;
                pthread_mutex_unlock(&conn->uc_lock);
                break;

        case UC_RX_PARSE:
                LBUG(); /* it's error to be here, because this special
                         * case is handled by caller */
                break;

        case UC_RX_PARSE_WAIT:
                LBUG(); /* it's error to be here, because the conn
                         * shouldn't wait for POLLIN event in this
                         * state */
                break;

        case UC_RX_LNET_PAYLOAD:
                /* payload all received */

                lnet_finalize(conn->uc_peer->up_ni, conn->uc_rx_lnetmsg, 0);

                cookie = conn->uc_rx_msg.ksm_zc_cookies[0];
                if (cookie != 0)
                        rc = usocklnd_handle_zc_req(conn->uc_peer, cookie);

                if (rc != 0) {
                        /* change state not to finalize twice */
                        conn->uc_rx_state = UC_RX_KSM_HEADER;
                        return -EPROTO;
                }

                /* Fall through */

        case UC_RX_SKIPPING:
                if (conn->uc_rx_nob_left != 0) {
                        usocklnd_rx_skipping_state_transition(conn);
                        *cont_flag = 1;
                } else {
                        usocklnd_rx_ksmhdr_state_transition(conn);
                        rc = 1; /* whole packet is read */
                }

                break;

        default:
                LBUG(); /* unknown state */
        }

        return rc;
}

/* Handle incoming ZC request from sender.
 * NB: it's called only from read_handler, so we're sure that
 * the conn cannot become zombie in the middle of processing */
int
usocklnd_handle_zc_req(usock_peer_t *peer, __u64 cookie)
{
        usock_conn_t   *conn;
        usock_zc_ack_t *zc_ack;
        int             type;
        int             rc;
        int             dummy;

        LIBCFS_ALLOC (zc_ack, sizeof(*zc_ack));
        if (zc_ack == NULL)
                return -ENOMEM;
        zc_ack->zc_cookie = cookie;

        /* Let's assume that CONTROL is the best type for zcack,
         * but userspace clients don't use typed connections */
        if (the_lnet.ln_pid & LNET_PID_USERFLAG)
                type = SOCKLND_CONN_ANY;
        else
                type = SOCKLND_CONN_CONTROL;

        rc = usocklnd_find_or_create_conn(peer, type, &conn, NULL, zc_ack,
                                          &dummy);
        if (rc != 0) {
                LIBCFS_FREE (zc_ack, sizeof(*zc_ack));
                return rc;
        }
        usocklnd_conn_decref(conn);

        return 0;
}

/* Switch on rx_state.
 * Return 0 on success, else return <0
 * Always set cont_flag: 1 if we're ready to continue reading, else 0
 */
int
usocklnd_read_hello(usock_conn_t *conn, int *cont_flag)
{
        int                rc = 0;
        ksock_hello_msg_t *hello = conn->uc_rx_hello;

        *cont_flag = 0;

        /* smth. new emerged in hello - let's process it */
        switch (conn->uc_rx_state) {
        case UC_RX_HELLO_MAGIC:
                if (hello->kshm_magic == LNET_PROTO_MAGIC)
                        conn->uc_flip = 0;
                else if (hello->kshm_magic == __swab32(LNET_PROTO_MAGIC))
                        conn->uc_flip = 1;
                else
                        return -EPROTO;

                usocklnd_rx_helloversion_state_transition(conn);
                *cont_flag = 1;
                break;

        case UC_RX_HELLO_VERSION:
                if ((!conn->uc_flip &&
                     (hello->kshm_version != KSOCK_PROTO_V2)) ||
                    (conn->uc_flip &&
                     (hello->kshm_version != __swab32(KSOCK_PROTO_V2))))
                        return -EPROTO;

                usocklnd_rx_hellobody_state_transition(conn);
                *cont_flag = 1;
                break;

        case UC_RX_HELLO_BODY:
                if (conn->uc_flip) {
                        ksock_hello_msg_t *hello = conn->uc_rx_hello;
                        __swab32s(&hello->kshm_src_pid);
                        __swab64s(&hello->kshm_src_nid);
                        __swab32s(&hello->kshm_dst_pid);
                        __swab64s(&hello->kshm_dst_nid);
                        __swab64s(&hello->kshm_src_incarnation);
                        __swab64s(&hello->kshm_dst_incarnation);
                        __swab32s(&hello->kshm_ctype);
                        __swab32s(&hello->kshm_nips);
                }

                if (conn->uc_rx_hello->kshm_nips > LNET_MAX_INTERFACES) {
                        CERROR("Bad nips %d from ip %u.%u.%u.%u port %d\n",
                               conn->uc_rx_hello->kshm_nips,
                               HIPQUAD(conn->uc_peer_ip), conn->uc_peer_port);
                        return -EPROTO;
                }

                if (conn->uc_rx_hello->kshm_nips) {
                        usocklnd_rx_helloIPs_state_transition(conn);
                        *cont_flag = 1;
                        break;
                }
                /* fall through */

        case UC_RX_HELLO_IPS:
                if (conn->uc_activeflag == 1) /* active conn */
                        rc = usocklnd_activeconn_hellorecv(conn);
                else                          /* passive conn */
                        rc = usocklnd_passiveconn_hellorecv(conn);

                break;

        default:
                LBUG(); /* unknown state */
        }

        return rc;
}

/* All actions that we need after receiving hello on active conn:
 * 1) Schedule removing if we're zombie
 * 2) Restart active conn if we lost the race
 * 3) Else: update RX part to receive KSM header
 */
int
usocklnd_activeconn_hellorecv(usock_conn_t *conn)
{
        int                rc    = 0;
        ksock_hello_msg_t *hello = conn->uc_rx_hello;
        usock_peer_t      *peer  = conn->uc_peer;

        /* Active conn with peer==NULL is zombie.
         * Don't try to link it to peer because the conn
         * has already had a chance to proceed at the beginning */
        if (peer == NULL) {
                LASSERT(cfs_list_empty(&conn->uc_tx_list) &&
                        cfs_list_empty(&conn->uc_zcack_list));

                usocklnd_conn_kill(conn);
                return 0;
        }

        peer->up_last_alive = cfs_time_current();

        /* peer says that we lost the race */
        if (hello->kshm_ctype == SOCKLND_CONN_NONE) {
                /* Start new active conn, relink txs and zc_acks from
                 * the conn to new conn, schedule removing the conn.
                 * Actually, we're expecting that a passive conn will
                 * make us zombie soon and take care of our txs and
                 * zc_acks */

                cfs_list_t tx_list, zcack_list;
                usock_conn_t *conn2;
                int idx = usocklnd_type2idx(conn->uc_type);

                CFS_INIT_LIST_HEAD (&tx_list);
                CFS_INIT_LIST_HEAD (&zcack_list);

                /* Block usocklnd_send() to check peer->up_conns[idx]
                 * and to enqueue more txs */
                pthread_mutex_lock(&peer->up_lock);
                pthread_mutex_lock(&conn->uc_lock);

                /* usocklnd_shutdown() could kill us */
                if (conn->uc_state == UC_DEAD) {
                        pthread_mutex_unlock(&conn->uc_lock);
                        pthread_mutex_unlock(&peer->up_lock);
                        return 0;
                }

                LASSERT (peer == conn->uc_peer);
                LASSERT (peer->up_conns[idx] == conn);

                rc = usocklnd_create_active_conn(peer, conn->uc_type, &conn2);
                if (rc) {
                        conn->uc_errored = 1;
                        pthread_mutex_unlock(&conn->uc_lock);
                        pthread_mutex_unlock(&peer->up_lock);
                        return rc;
                }

                usocklnd_link_conn_to_peer(conn2, peer, idx);
                conn2->uc_peer = peer;

                /* unlink txs and zcack from the conn */
                cfs_list_add(&tx_list, &conn->uc_tx_list);
                cfs_list_del_init(&conn->uc_tx_list);
                cfs_list_add(&zcack_list, &conn->uc_zcack_list);
                cfs_list_del_init(&conn->uc_zcack_list);

                /* link they to the conn2 */
                cfs_list_add(&conn2->uc_tx_list, &tx_list);
                cfs_list_del_init(&tx_list);
                cfs_list_add(&conn2->uc_zcack_list, &zcack_list);
                cfs_list_del_init(&zcack_list);

                /* make conn zombie */
                conn->uc_peer = NULL;
                usocklnd_peer_decref(peer);

                /* schedule conn2 for processing */
                rc = usocklnd_add_pollrequest(conn2, POLL_ADD_REQUEST, POLLOUT);
                if (rc) {
                        peer->up_conns[idx] = NULL;
                        usocklnd_conn_decref(conn2); /* should destroy conn */
                } else {
                        usocklnd_conn_kill_locked(conn);
                }

                pthread_mutex_unlock(&conn->uc_lock);
                pthread_mutex_unlock(&peer->up_lock);
                usocklnd_conn_decref(conn);

        } else { /* hello->kshm_ctype != SOCKLND_CONN_NONE */
                if (conn->uc_type != usocklnd_invert_type(hello->kshm_ctype))
                        return -EPROTO;

                pthread_mutex_lock(&peer->up_lock);
                usocklnd_cleanup_stale_conns(peer, hello->kshm_src_incarnation,
                                             conn);
                pthread_mutex_unlock(&peer->up_lock);

                /* safely transit to UC_READY state */
                /* rc == 0 */
                pthread_mutex_lock(&conn->uc_lock);
                if (conn->uc_state != UC_DEAD) {
                        usocklnd_rx_ksmhdr_state_transition(conn);

                        /* POLLIN is already set because we just
                         * received hello, but maybe we've smth. to
                         * send? */
                        LASSERT (conn->uc_sending == 0);
                        if ( !cfs_list_empty(&conn->uc_tx_list) ||
                             !cfs_list_empty(&conn->uc_zcack_list) ) {

                                conn->uc_tx_deadline =
                                        cfs_time_shift(usock_tuns.ut_timeout);
                                conn->uc_tx_flag = 1;
                                rc = usocklnd_add_pollrequest(conn,
                                                              POLL_SET_REQUEST,
                                                              POLLIN | POLLOUT);
                        }

                        if (rc == 0)
                                conn->uc_state = UC_READY;
                }
                pthread_mutex_unlock(&conn->uc_lock);
        }

        return rc;
}

/* All actions that we need after receiving hello on passive conn:
 * 1) Stash peer's nid, pid, incarnation and conn type
 * 2) Cope with easy case: conn[idx] is empty - just save conn there
 * 3) Resolve race:
 *    a) if our nid is higher - reply with CONN_NONE and make us zombie
 *    b) if peer's nid is higher - postpone race resolution till
 *       READY state
 * 4) Anyhow, send reply hello
*/
int
usocklnd_passiveconn_hellorecv(usock_conn_t *conn)
{
        ksock_hello_msg_t *hello = conn->uc_rx_hello;
        int                type;
        int                idx;
        int                rc;
        usock_peer_t      *peer;
        lnet_ni_t         *ni        = conn->uc_ni;
        __u32              peer_ip   = conn->uc_peer_ip;
        __u16              peer_port = conn->uc_peer_port;

        /* don't know parent peer yet and not zombie */
        LASSERT (conn->uc_peer == NULL &&
                 ni != NULL);

        /* don't know peer's nid and incarnation yet */
        if (peer_port > LNET_ACCEPTOR_MAX_RESERVED_PORT) {
                /* do not trust liblustre clients */
                conn->uc_peerid.pid = peer_port | LNET_PID_USERFLAG;
                conn->uc_peerid.nid = LNET_MKNID(LNET_NIDNET(ni->ni_nid),
                                                 peer_ip);
                if (hello->kshm_ctype != SOCKLND_CONN_ANY) {
                        lnet_ni_decref(ni);
                        conn->uc_ni = NULL;
                        CERROR("Refusing to accept connection of type=%d from "
                               "userspace process %u.%u.%u.%u:%d\n", hello->kshm_ctype,
                               HIPQUAD(peer_ip), peer_port);
                        return -EINVAL;
                }
        } else {
                conn->uc_peerid.pid = hello->kshm_src_pid;
                conn->uc_peerid.nid = hello->kshm_src_nid;
        }
        conn->uc_type = type = usocklnd_invert_type(hello->kshm_ctype);

        rc = usocklnd_find_or_create_peer(ni, conn->uc_peerid, &peer);
        if (rc) {
                lnet_ni_decref(ni);
                conn->uc_ni = NULL;
                return rc;
        }

        peer->up_last_alive = cfs_time_current();

        idx = usocklnd_type2idx(conn->uc_type);

        /* safely check whether we're first */
        pthread_mutex_lock(&peer->up_lock);

        usocklnd_cleanup_stale_conns(peer, hello->kshm_src_incarnation, NULL);

        if (peer->up_conns[idx] == NULL) {
                peer->up_last_alive = cfs_time_current();
                conn->uc_peer = peer;
                conn->uc_ni = NULL;
                usocklnd_link_conn_to_peer(conn, peer, idx);
                usocklnd_conn_addref(conn);
        } else {
                usocklnd_peer_decref(peer);

                /* Resolve race in favour of higher NID */
                if (conn->uc_peerid.nid < conn->uc_ni->ni_nid) {
                        /* make us zombie */
                        conn->uc_ni = NULL;
                        type = SOCKLND_CONN_NONE;
                }

                /* if conn->uc_peerid.nid > conn->uc_ni->ni_nid,
                 * postpone race resolution till READY state
                 * (hopefully that conn[idx] will die because of
                 * incoming hello of CONN_NONE type) */
        }
        pthread_mutex_unlock(&peer->up_lock);

        /* allocate and initialize fake tx with hello */
        conn->uc_tx_hello = usocklnd_create_hello_tx(ni, type,
                                                     conn->uc_peerid.nid);
        if (conn->uc_ni == NULL)
                lnet_ni_decref(ni);

        if (conn->uc_tx_hello == NULL)
                return -ENOMEM;

        /* rc == 0 */
        pthread_mutex_lock(&conn->uc_lock);
        if (conn->uc_state == UC_DEAD)
                goto passive_hellorecv_done;

        conn->uc_state = UC_SENDING_HELLO;
        conn->uc_tx_deadline = cfs_time_shift(usock_tuns.ut_timeout);
        conn->uc_tx_flag = 1;
        rc = usocklnd_add_pollrequest(conn, POLL_SET_REQUEST, POLLOUT);

  passive_hellorecv_done:
        pthread_mutex_unlock(&conn->uc_lock);
        return rc;
}

int
usocklnd_write_handler(usock_conn_t *conn)
{
        usock_tx_t   *tx;
        int           ret;
        int           rc = 0;
        int           state;
        usock_peer_t *peer;
        lnet_ni_t    *ni;

        pthread_mutex_lock(&conn->uc_lock); /* like membar */
        state = conn->uc_state;
        pthread_mutex_unlock(&conn->uc_lock);

        switch (state) {
        case UC_CONNECTING:
                /* hello_tx has already been initialized
                 * in usocklnd_create_active_conn() */
                usocklnd_conn_new_state(conn, UC_SENDING_HELLO);
                /* fall through */

        case UC_SENDING_HELLO:
                rc = usocklnd_send_tx(conn, conn->uc_tx_hello);
                if (rc <= 0) /* error or partial send or connection closed */
                        break;

                /* tx with hello was sent successfully */
                usocklnd_destroy_tx(NULL, conn->uc_tx_hello);
                conn->uc_tx_hello = NULL;

                if (conn->uc_activeflag == 1) /* active conn */
                        rc = usocklnd_activeconn_hellosent(conn);
                else                          /* passive conn */
                        rc = usocklnd_passiveconn_hellosent(conn);

                break;

        case UC_READY:
                pthread_mutex_lock(&conn->uc_lock);

                peer = conn->uc_peer;
                LASSERT (peer != NULL);
                ni = peer->up_ni;

                if (cfs_list_empty(&conn->uc_tx_list) &&
                    cfs_list_empty(&conn->uc_zcack_list)) {
                        LASSERT(usock_tuns.ut_fair_limit > 1);
                        pthread_mutex_unlock(&conn->uc_lock);
                        return 0;
                }

                tx = usocklnd_try_piggyback(&conn->uc_tx_list,
                                            &conn->uc_zcack_list);
                if (tx != NULL)
                        conn->uc_sending = 1;
                else
                        rc = -ENOMEM;

                pthread_mutex_unlock(&conn->uc_lock);

                if (rc)
                        break;

                rc = usocklnd_send_tx(conn, tx);
                if (rc == 0) { /* partial send or connection closed */
                        pthread_mutex_lock(&conn->uc_lock);
                        cfs_list_add(&tx->tx_list, &conn->uc_tx_list);
                        conn->uc_sending = 0;
                        pthread_mutex_unlock(&conn->uc_lock);
                        break;
                }
                if (rc < 0) { /* real error */
                        usocklnd_destroy_tx(ni, tx);
                        break;
                }

                /* rc == 1: tx was sent completely */
                usocklnd_destroy_tx(ni, tx);

                pthread_mutex_lock(&conn->uc_lock);
                conn->uc_sending = 0;
                if (conn->uc_state != UC_DEAD &&
                    cfs_list_empty(&conn->uc_tx_list) &&
                    cfs_list_empty(&conn->uc_zcack_list)) {
                        conn->uc_tx_flag = 0;
                        ret = usocklnd_add_pollrequest(conn,
                                                      POLL_TX_SET_REQUEST, 0);
                        if (ret)
                                rc = ret;
                }
                pthread_mutex_unlock(&conn->uc_lock);

                break;

        case UC_DEAD:
                break;

        default:
                LBUG();
        }

        if (rc < 0)
                usocklnd_conn_kill(conn);

        return rc;
}

/* Return the first tx from tx_list with piggybacked zc_ack
 * from zcack_list when possible. If tx_list is empty, return
 * brand new noop tx for zc_ack from zcack_list. Return NULL
 * if an error happened */
usock_tx_t *
usocklnd_try_piggyback(cfs_list_t *tx_list_p,
                       cfs_list_t *zcack_list_p)
{
        usock_tx_t     *tx;
        usock_zc_ack_t *zc_ack;

        /* assign tx and zc_ack */
        if (cfs_list_empty(tx_list_p))
                tx = NULL;
        else {
                tx = cfs_list_entry(tx_list_p->next, usock_tx_t, tx_list);
                cfs_list_del(&tx->tx_list);

                /* already piggybacked or partially send */
                if (tx->tx_msg.ksm_zc_cookies[1] != 0 ||
                    tx->tx_resid != tx->tx_nob)
                        return tx;
        }

        if (cfs_list_empty(zcack_list_p)) {
                /* nothing to piggyback */
                return tx;
        } else {
                zc_ack = cfs_list_entry(zcack_list_p->next,
                                        usock_zc_ack_t, zc_list);
                cfs_list_del(&zc_ack->zc_list);
        }

        if (tx != NULL)
                /* piggyback the zc-ack cookie */
                tx->tx_msg.ksm_zc_cookies[1] = zc_ack->zc_cookie;
        else
                /* cannot piggyback, need noop */
                tx = usocklnd_create_noop_tx(zc_ack->zc_cookie);

        LIBCFS_FREE (zc_ack, sizeof(*zc_ack));
        return tx;
}

/* All actions that we need after sending hello on active conn:
 * 1) update RX iov to receive hello
 * 2) state transition to UC_RECEIVING_HELLO
 * 3) notify poll_thread that we're waiting for incoming hello */
int
usocklnd_activeconn_hellosent(usock_conn_t *conn)
{
        int rc = 0;

        pthread_mutex_lock(&conn->uc_lock);

        if (conn->uc_state != UC_DEAD) {
                usocklnd_rx_hellomagic_state_transition(conn);
                conn->uc_state = UC_RECEIVING_HELLO;
                conn->uc_tx_flag = 0;
                rc = usocklnd_add_pollrequest(conn, POLL_SET_REQUEST, POLLIN);
        }

        pthread_mutex_unlock(&conn->uc_lock);

        return rc;
}

/* All actions that we need after sending hello on passive conn:
 * 1) Cope with 1st easy case: conn is already linked to a peer
 * 2) Cope with 2nd easy case: remove zombie conn
  * 3) Resolve race:
 *    a) find the peer
 *    b) link the conn to the peer if conn[idx] is empty
 *    c) if the conn[idx] isn't empty and is in READY state,
 *       remove the conn as duplicated
 *    d) if the conn[idx] isn't empty and isn't in READY state,
 *       override conn[idx] with the conn
 */
int
usocklnd_passiveconn_hellosent(usock_conn_t *conn)
{
        usock_conn_t    *conn2;
        usock_peer_t    *peer;
        cfs_list_t       tx_list;
        cfs_list_t       zcack_list;
        int              idx;
        int              rc = 0;

        /* almost nothing to do if conn is already linked to peer hash table */
        if (conn->uc_peer != NULL)
                goto passive_hellosent_done;

        /* conn->uc_peer == NULL, so the conn isn't accessible via
         * peer hash list, so nobody can touch the conn but us */

        if (conn->uc_ni == NULL) /* remove zombie conn */
                goto passive_hellosent_connkill;

        /* all code below is race resolution, because normally
         * passive conn is linked to peer just after receiving hello */
        CFS_INIT_LIST_HEAD (&tx_list);
        CFS_INIT_LIST_HEAD (&zcack_list);

        /* conn is passive and isn't linked to any peer,
           so its tx and zc_ack lists have to be empty */
        LASSERT (cfs_list_empty(&conn->uc_tx_list) &&
                 cfs_list_empty(&conn->uc_zcack_list) &&
                 conn->uc_sending == 0);

        rc = usocklnd_find_or_create_peer(conn->uc_ni, conn->uc_peerid, &peer);
        if (rc)
                return rc;

        idx = usocklnd_type2idx(conn->uc_type);

        /* try to link conn to peer */
        pthread_mutex_lock(&peer->up_lock);
        if (peer->up_conns[idx] == NULL) {
                usocklnd_link_conn_to_peer(conn, peer, idx);
                usocklnd_conn_addref(conn);
                conn->uc_peer = peer;
                usocklnd_peer_addref(peer);
        } else {
                conn2 = peer->up_conns[idx];
                pthread_mutex_lock(&conn2->uc_lock);

                if (conn2->uc_state == UC_READY) {
                        /* conn2 is in READY state, so conn is "duplicated" */
                        pthread_mutex_unlock(&conn2->uc_lock);
                        pthread_mutex_unlock(&peer->up_lock);
                        usocklnd_peer_decref(peer);
                        goto passive_hellosent_connkill;
                }

                /* uc_state != UC_READY => switch conn and conn2 */
                /* Relink txs and zc_acks from conn2 to conn.
                 * We're sure that nobody but us can access to conn,
                 * nevertheless we use mutex (if we're wrong yet,
                 * deadlock is easy to see that corrupted list */
                cfs_list_add(&tx_list, &conn2->uc_tx_list);
                cfs_list_del_init(&conn2->uc_tx_list);
                cfs_list_add(&zcack_list, &conn2->uc_zcack_list);
                cfs_list_del_init(&conn2->uc_zcack_list);

                pthread_mutex_lock(&conn->uc_lock);
                cfs_list_add_tail(&conn->uc_tx_list, &tx_list);
                cfs_list_del_init(&tx_list);
                cfs_list_add_tail(&conn->uc_zcack_list, &zcack_list);
                cfs_list_del_init(&zcack_list);
                conn->uc_peer = peer;
                pthread_mutex_unlock(&conn->uc_lock);

                conn2->uc_peer = NULL; /* make conn2 zombie */
                pthread_mutex_unlock(&conn2->uc_lock);
                usocklnd_conn_decref(conn2);

                usocklnd_link_conn_to_peer(conn, peer, idx);
                usocklnd_conn_addref(conn);
                conn->uc_peer = peer;
        }

        lnet_ni_decref(conn->uc_ni);
        conn->uc_ni = NULL;
        pthread_mutex_unlock(&peer->up_lock);
        usocklnd_peer_decref(peer);

  passive_hellosent_done:
        /* safely transit to UC_READY state */
        /* rc == 0 */
        pthread_mutex_lock(&conn->uc_lock);
        if (conn->uc_state != UC_DEAD) {
                usocklnd_rx_ksmhdr_state_transition(conn);

                /* we're ready to recive incoming packets and maybe
                   already have smth. to transmit */
                LASSERT (conn->uc_sending == 0);
                if ( cfs_list_empty(&conn->uc_tx_list) &&
                     cfs_list_empty(&conn->uc_zcack_list) ) {
                        conn->uc_tx_flag = 0;
                        rc = usocklnd_add_pollrequest(conn, POLL_SET_REQUEST,
                                                 POLLIN);
                } else {
                        conn->uc_tx_deadline =
                                cfs_time_shift(usock_tuns.ut_timeout);
                        conn->uc_tx_flag = 1;
                        rc = usocklnd_add_pollrequest(conn, POLL_SET_REQUEST,
                                                      POLLIN | POLLOUT);
                }

                if (rc == 0)
                        conn->uc_state = UC_READY;
        }
        pthread_mutex_unlock(&conn->uc_lock);
        return rc;

  passive_hellosent_connkill:
        usocklnd_conn_kill(conn);
        return 0;
}

/* Send as much tx data as possible.
 * Returns 0 or 1 on succsess, <0 if fatal error.
 * 0 means partial send or non-fatal error, 1 - complete.
 * Rely on libcfs_sock_writev() for differentiating fatal and
 * non-fatal errors. An error should be considered as non-fatal if:
 * 1) it still makes sense to continue reading &&
 * 2) anyway, poll() will set up POLLHUP|POLLERR flags */
int
usocklnd_send_tx(usock_conn_t *conn, usock_tx_t *tx)
{
        struct iovec *iov;
        int           nob;
        cfs_time_t    t;

        LASSERT (tx->tx_resid != 0);

        do {
                usock_peer_t *peer = conn->uc_peer;

                LASSERT (tx->tx_niov > 0);

                nob = libcfs_sock_writev(conn->uc_sock,
                                         tx->tx_iov, tx->tx_niov);
                if (nob < 0)
                        conn->uc_errored = 1;
                if (nob <= 0) /* write queue is flow-controlled or error */
                        return nob;

                LASSERT (nob <= tx->tx_resid);
                tx->tx_resid -= nob;
                t = cfs_time_current();
                conn->uc_tx_deadline = cfs_time_add(t, cfs_time_seconds(usock_tuns.ut_timeout));

                if(peer != NULL)
                        peer->up_last_alive = t;

                /* "consume" iov */
                iov = tx->tx_iov;
                do {
                        LASSERT (tx->tx_niov > 0);

                        if (nob < iov->iov_len) {
                                iov->iov_base = (void *)(((unsigned long)(iov->iov_base)) + nob);
                                iov->iov_len -= nob;
                                break;
                        }

                        nob -= iov->iov_len;
                        tx->tx_iov = ++iov;
                        tx->tx_niov--;
                } while (nob != 0);

        } while (tx->tx_resid != 0);

        return 1; /* send complete */
}

/* Read from wire as much data as possible.
 * Returns 0 or 1 on succsess, <0 if error or EOF.
 * 0 means partial read, 1 - complete */
int
usocklnd_read_data(usock_conn_t *conn)
{
        struct iovec *iov;
        int           nob;
        cfs_time_t    t;

        LASSERT (conn->uc_rx_nob_wanted != 0);

        do {
                usock_peer_t *peer = conn->uc_peer;

                LASSERT (conn->uc_rx_niov > 0);

                nob = libcfs_sock_readv(conn->uc_sock,
                                        conn->uc_rx_iov, conn->uc_rx_niov);
                if (nob <= 0) {/* read nothing or error */
                        if (nob < 0)
                                conn->uc_errored = 1;
                        return nob;
                }

                LASSERT (nob <= conn->uc_rx_nob_wanted);
                conn->uc_rx_nob_wanted -= nob;
                conn->uc_rx_nob_left -= nob;
                t = cfs_time_current();
                conn->uc_rx_deadline = cfs_time_add(t, cfs_time_seconds(usock_tuns.ut_timeout));

                if(peer != NULL)
                        peer->up_last_alive = t;

                /* "consume" iov */
                iov = conn->uc_rx_iov;
                do {
                        LASSERT (conn->uc_rx_niov > 0);

                        if (nob < iov->iov_len) {
                                iov->iov_base = (void *)(((unsigned long)(iov->iov_base)) + nob);
                                iov->iov_len -= nob;
                                break;
                        }

                        nob -= iov->iov_len;
                        conn->uc_rx_iov = ++iov;
                        conn->uc_rx_niov--;
                } while (nob != 0);

        } while (conn->uc_rx_nob_wanted != 0);

        return 1; /* read complete */
}
