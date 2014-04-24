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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/ulnds/socklnd/usocklnd.h
 *
 * Author: Maxim Patlasov <maxim@clusterfs.com>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>
#include <poll.h>
#include <lnet/lib-lnet.h>
#include <lnet/socklnd.h>

typedef struct {
	struct list_head       tx_list;    /* neccessary to form tx list */
        lnet_msg_t      *tx_lnetmsg; /* lnet message for lnet_finalize() */
        ksock_msg_t      tx_msg;     /* buffer for wire header of ksock msg */
        int              tx_resid;   /* # of residual bytes */
        int              tx_nob;     /* # of packet bytes */
        int              tx_size;    /* size of this descriptor */
        struct iovec    *tx_iov;     /* points to tx_iova[i] */
        int              tx_niov;    /* # of packet iovec frags */
        struct iovec     tx_iova[1]; /* iov for header */
} usock_tx_t;

struct usock_peer_s;

typedef struct {
        cfs_socket_t        *uc_sock;        /* socket */
        int                  uc_type;        /* conn type */
        int                  uc_activeflag;  /* active side of connection? */
        int                  uc_flip;        /* is peer other endian? */
        int                  uc_state;       /* connection state */
        struct usock_peer_s *uc_peer;        /* owning peer */
        lnet_process_id_t    uc_peerid;      /* id of remote peer */
        int                  uc_pt_idx;      /* index in ud_pollthreads[] of
                                              * owning poll thread */
        lnet_ni_t            *uc_ni;         /* parent NI while accepting */
        struct usock_preq_s  *uc_preq;       /* preallocated request */
        __u32                 uc_peer_ip;    /* IP address of the peer */
        __u16                 uc_peer_port;  /* port of the peer */
	struct list_head            uc_stale_list; /* orphaned connections */

        /* Receive state */
        int                uc_rx_state;      /* message or hello state */
        ksock_hello_msg_t *uc_rx_hello;      /* hello buffer */
        struct iovec      *uc_rx_iov;        /* points to uc_rx_iova[i] */
        struct iovec       uc_rx_iova[LNET_MAX_IOV]; /* message frags */
        int                uc_rx_niov;       /* # frags */
        int                uc_rx_nob_left;   /* # bytes to next hdr/body */
        int                uc_rx_nob_wanted; /* # of bytes actually wanted */
        void              *uc_rx_lnetmsg;    /* LNET message being received */
        cfs_time_t         uc_rx_deadline;   /* when to time out */
        int                uc_rx_flag;       /* deadline valid? */
        ksock_msg_t        uc_rx_msg;        /* message buffer */

        /* Send state */
	struct list_head         uc_tx_list;       /* pending txs */
	struct list_head         uc_zcack_list;    /* pending zc_acks */
        cfs_time_t         uc_tx_deadline;   /* when to time out */
        int                uc_tx_flag;       /* deadline valid? */
        int                uc_sending;       /* send op is in progress */
        usock_tx_t        *uc_tx_hello;      /* fake tx with hello */

	mt_atomic_t    uc_refcount;      /* # of users */
        pthread_mutex_t    uc_lock;          /* serialize */
        int                uc_errored;       /* a flag for lnet_notify() */
} usock_conn_t;

/* Allowable conn states are: */
#define UC_CONNECTING 1
#define UC_SENDING_HELLO 2
#define UC_RECEIVING_HELLO 3
#define UC_READY 4
#define UC_DEAD 5

/* Allowable RX states are: */
#define UC_RX_HELLO_MAGIC 1
#define UC_RX_HELLO_VERSION 2
#define UC_RX_HELLO_BODY 3
#define UC_RX_HELLO_IPS 4
#define UC_RX_KSM_HEADER 5
#define UC_RX_LNET_HEADER 6
#define UC_RX_PARSE 7
#define UC_RX_PARSE_WAIT 8
#define UC_RX_LNET_PAYLOAD 9
#define UC_RX_SKIPPING 10

#define N_CONN_TYPES 3 /* CONTROL, BULK_IN and BULK_OUT */

typedef struct usock_peer_s {
	/* neccessary to form peer list */
	struct list_head  up_list;
        lnet_process_id_t up_peerid;      /* id of remote peer */
        usock_conn_t     *up_conns[N_CONN_TYPES]; /* conns that connect us
                                                       * us with the peer */
        lnet_ni_t        *up_ni;          /* pointer to parent NI */
        __u64             up_incarnation; /* peer's incarnation */
        int               up_incrn_is_set;/* 0 if peer's incarnation
                                               * hasn't been set so far */
	mt_atomic_t	  up_refcount;    /* # of users */
        pthread_mutex_t   up_lock;        /* serialize */
        int               up_errored;     /* a flag for lnet_notify() */
        cfs_time_t        up_last_alive;  /* when the peer was last alive */
} usock_peer_t;

typedef struct {
        cfs_socket_t       *upt_notifier[2];    /* notifier sockets: 1st for
                                                 * writing, 2nd for reading */
        struct pollfd      *upt_pollfd;         /* poll fds */
        int                 upt_nfds;           /* active poll fds */
        int                 upt_npollfd;        /* allocated poll fds */
        usock_conn_t      **upt_idx2conn;       /* conns corresponding to
                                                 * upt_pollfd[idx] */
        int                *upt_skip;           /* skip chain */
        int                *upt_fd2idx;         /* index into upt_pollfd[]
                                                 * by fd */
        int                 upt_nfd2idx;        /* # of allocated elements
                                                 * of upt_fd2idx[] */
	struct list_head    upt_stale_list;     /* list of orphaned conns */
	struct list_head    upt_pollrequests;   /* list of poll requests */
        pthread_mutex_t     upt_pollrequests_lock; /* serialize */
        int                 upt_errno;         /* non-zero if errored */
	struct completion   upt_completion;	/* wait/signal facility for
						 * syncronizing shutdown */
} usock_pollthread_t;

/* Number of elements in upt_pollfd[], upt_idx2conn[] and upt_fd2idx[]
 * at initialization time. Will be resized on demand */
#define UPT_START_SIZ 32

/* # peer lists */
#define UD_PEER_HASH_SIZE  101

typedef struct {
        int                 ud_state;          /* initialization state */
        int                 ud_npollthreads;   /* # of poll threads */
        usock_pollthread_t *ud_pollthreads;    /* their state */
        int                 ud_shutdown;       /* shutdown flag */
        int                 ud_nets_count;     /* # of instances */
	struct list_head    ud_peers[UD_PEER_HASH_SIZE]; /* peer hash table */
        pthread_rwlock_t    ud_peers_lock;     /* serialize */
} usock_data_t;

extern usock_data_t usock_data;

/* ud_state allowed values */
#define UD_STATE_INIT_NOTHING 0
#define UD_STATE_INITIALIZED 1

typedef struct {
        int             un_peercount;   /* # of peers */
        int             un_shutdown;    /* shutdown flag */
        __u64           un_incarnation; /* my epoch */
        pthread_cond_t  un_cond;        /* condvar to wait for notifications */
        pthread_mutex_t un_lock;        /* a lock to protect un_cond */
} usock_net_t;

typedef struct {
        int ut_poll_timeout;  /* the third arg for poll(2) (seconds) */
        int ut_timeout;       /* "stuck" socket timeout (seconds) */
        int ut_npollthreads;  /* number of poll thread to spawn */
        int ut_fair_limit;    /* how many packets can we receive or transmit
                               * without calling poll(2) */
        int ut_min_bulk;      /* smallest "large" message */
        int ut_txcredits;     /* # concurrent sends */
        int ut_peertxcredits; /* # concurrent sends to 1 peer */
        int ut_socknagle;     /* Is Nagle alg on ? */
        int ut_sockbufsiz;    /* size of socket buffers */
} usock_tunables_t;

extern usock_tunables_t usock_tuns;

typedef struct usock_preq_s {
        int              upr_type;   /* type of requested action */
        short            upr_value; /* bitmask of POLLIN and POLLOUT bits */
        usock_conn_t *   upr_conn;  /* a conn for the sake of which
                                     * action will be performed */
	struct list_head       upr_list;  /* neccessary to form list */
} usock_pollrequest_t;

/* Allowable poll request types are: */
#define POLL_ADD_REQUEST 1
#define POLL_DEL_REQUEST 2
#define POLL_RX_SET_REQUEST 3
#define POLL_TX_SET_REQUEST 4
#define POLL_SET_REQUEST 5

typedef struct {
	struct list_head       zc_list;   /* neccessary to form zc_ack list */
        __u64            zc_cookie; /* zero-copy cookie */
} usock_zc_ack_t;

static inline void
usocklnd_conn_addref(usock_conn_t *conn)
{
	LASSERT(mt_atomic_read(&conn->uc_refcount) > 0);
	mt_atomic_inc(&conn->uc_refcount);
}

void usocklnd_destroy_conn(usock_conn_t *conn);

static inline void
usocklnd_conn_decref(usock_conn_t *conn)
{
	LASSERT(mt_atomic_read(&conn->uc_refcount) > 0);
	if (mt_atomic_dec_and_test(&conn->uc_refcount))
                usocklnd_destroy_conn(conn);
}

static inline void
usocklnd_peer_addref(usock_peer_t *peer)
{
	LASSERT(mt_atomic_read(&peer->up_refcount) > 0);
	mt_atomic_inc(&peer->up_refcount);
}

void usocklnd_destroy_peer(usock_peer_t *peer);

static inline void
usocklnd_peer_decref(usock_peer_t *peer)
{
	LASSERT(mt_atomic_read(&peer->up_refcount) > 0);
	if (mt_atomic_dec_and_test(&peer->up_refcount))
                usocklnd_destroy_peer(peer);
}

static inline int
usocklnd_ip2pt_idx(__u32 ip) {
        return ip % usock_data.ud_npollthreads;
}

static inline struct list_head *
usocklnd_nid2peerlist(lnet_nid_t nid)
{
        unsigned int hash = ((unsigned int)nid) % UD_PEER_HASH_SIZE;

        return &usock_data.ud_peers[hash];
}

int usocklnd_startup(lnet_ni_t *ni);
void usocklnd_shutdown(lnet_ni_t *ni);
int usocklnd_send(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg);
int usocklnd_recv(lnet_ni_t *ni, void *private, lnet_msg_t *msg, int delayed,
                  unsigned int niov, struct iovec *iov, lnet_kiov_t *kiov,
                  unsigned int offset, unsigned int mlen, unsigned int rlen);
int usocklnd_accept(lnet_ni_t *ni, cfs_socket_t *sock);

int usocklnd_poll_thread(void *arg);
int usocklnd_add_pollrequest(usock_conn_t *conn, int type, short value);
void usocklnd_add_killrequest(usock_conn_t *conn);
int usocklnd_process_pollrequest(usock_pollrequest_t *pr,
                                 usock_pollthread_t *pt_data);
void usocklnd_execute_handlers(usock_pollthread_t *pt_data);
int usocklnd_calculate_chunk_size(int num);
void usocklnd_wakeup_pollthread(int i);

int usocklnd_notifier_handler(int fd);
void usocklnd_exception_handler(usock_conn_t *conn);
int usocklnd_read_handler(usock_conn_t *conn);
int usocklnd_read_msg(usock_conn_t *conn, int *cont_flag);
int usocklnd_handle_zc_req(usock_peer_t *peer, __u64 cookie);
int usocklnd_read_hello(usock_conn_t *conn, int *cont_flag);
int usocklnd_activeconn_hellorecv(usock_conn_t *conn);
int usocklnd_passiveconn_hellorecv(usock_conn_t *conn);
int usocklnd_write_handler(usock_conn_t *conn);
usock_tx_t *usocklnd_try_piggyback(struct list_head *tx_list_p,
				   struct list_head *zcack_list_p);
int usocklnd_activeconn_hellosent(usock_conn_t *conn);
int usocklnd_passiveconn_hellosent(usock_conn_t *conn);
int usocklnd_send_tx(usock_conn_t *conn, usock_tx_t *tx);
int usocklnd_read_data(usock_conn_t *conn);

void usocklnd_release_poll_states(int n);
int usocklnd_base_startup();
void usocklnd_base_shutdown(int n);
__u64 usocklnd_new_incarnation();
void usocklnd_del_all_peers(lnet_ni_t *ni);
void usocklnd_del_peer_and_conns(usock_peer_t *peer);
void usocklnd_del_conns_locked(usock_peer_t *peer);

int usocklnd_conn_timed_out(usock_conn_t *conn, cfs_time_t current_time);
void usocklnd_conn_kill(usock_conn_t *conn);
void usocklnd_conn_kill_locked(usock_conn_t *conn);
usock_conn_t *usocklnd_conn_allocate();
void usocklnd_conn_free(usock_conn_t *conn);
void usocklnd_tear_peer_conn(usock_conn_t *conn);
void usocklnd_check_peer_stale(lnet_ni_t *ni, lnet_process_id_t id);
int usocklnd_create_passive_conn(lnet_ni_t *ni,
                                 cfs_socket_t *sock, usock_conn_t **connp);
int usocklnd_create_active_conn(usock_peer_t *peer, int type,
                                usock_conn_t **connp);
int usocklnd_connect_srv_mode(cfs_socket_t **sockp,
                              __u32 dst_ip, __u16 dst_port);
int usocklnd_connect_cli_mode(cfs_socket_t **sockp,
                              __u32 dst_ip, __u16 dst_port);
int usocklnd_set_sock_options(cfs_socket_t *sock);
usock_tx_t *usocklnd_create_noop_tx(__u64 cookie);
usock_tx_t *usocklnd_create_tx(lnet_msg_t *lntmsg);
void usocklnd_init_hello_msg(ksock_hello_msg_t *hello,
                             lnet_ni_t *ni, int type, lnet_nid_t peer_nid);
usock_tx_t *usocklnd_create_hello_tx(lnet_ni_t *ni,
                                     int type, lnet_nid_t peer_nid);
usock_tx_t *usocklnd_create_cr_hello_tx(lnet_ni_t *ni,
                                        int type, lnet_nid_t peer_nid);
void usocklnd_destroy_tx(lnet_ni_t *ni, usock_tx_t *tx);
void usocklnd_destroy_txlist(lnet_ni_t *ni, struct list_head *txlist);
void usocklnd_destroy_zcack_list(struct list_head *zcack_list);
void usocklnd_destroy_peer (usock_peer_t *peer);
int usocklnd_get_conn_type(lnet_msg_t *lntmsg);
int usocklnd_type2idx(int type);
usock_peer_t *usocklnd_find_peer_locked(lnet_ni_t *ni, lnet_process_id_t id);
int usocklnd_create_peer(lnet_ni_t *ni, lnet_process_id_t id,
                         usock_peer_t **peerp);
int usocklnd_find_or_create_peer(lnet_ni_t *ni, lnet_process_id_t id,
                                 usock_peer_t **peerp);
int usocklnd_find_or_create_conn(usock_peer_t *peer, int type,
                                 usock_conn_t **connp,
                                 usock_tx_t *tx, usock_zc_ack_t *zc_ack,
                                 int *send_immediately_flag);
void usocklnd_link_conn_to_peer(usock_conn_t *conn, usock_peer_t *peer, int idx);
int usocklnd_invert_type(int type);
void usocklnd_conn_new_state(usock_conn_t *conn, int new_state);
void usocklnd_cleanup_stale_conns(usock_peer_t *peer, __u64 incrn,
                                  usock_conn_t *skip_conn);

void usocklnd_rx_hellomagic_state_transition(usock_conn_t *conn);
void usocklnd_rx_helloversion_state_transition(usock_conn_t *conn);
void usocklnd_rx_hellobody_state_transition(usock_conn_t *conn);
void usocklnd_rx_helloIPs_state_transition(usock_conn_t *conn);
void usocklnd_rx_lnethdr_state_transition(usock_conn_t *conn);
void usocklnd_rx_ksmhdr_state_transition(usock_conn_t *conn);
void usocklnd_rx_skipping_state_transition(usock_conn_t *conn);
