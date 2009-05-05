/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/openiblnd/openiblnd.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 */

#include "openiblnd.h"

lnd_t the_kiblnd = {
#ifdef USING_TSAPI
        .lnd_type       = CIBLND,
#else
        .lnd_type       = OPENIBLND,
#endif
        .lnd_startup    = kibnal_startup,
        .lnd_shutdown   = kibnal_shutdown,
        .lnd_ctl        = kibnal_ctl,
        .lnd_send       = kibnal_send,
        .lnd_recv       = kibnal_recv,
        .lnd_eager_recv = kibnal_eager_recv,
        .lnd_accept     = kibnal_accept,
};

kib_data_t              kibnal_data;

__u32 
kibnal_cksum (void *ptr, int nob)
{
        char  *c  = ptr;
        __u32  sum = 0;

        while (nob-- > 0)
                sum = ((sum << 1) | (sum >> 31)) + *c++;

        /* ensure I don't return 0 (== no checksum) */
        return (sum == 0) ? 1 : sum;
}

void
kibnal_init_msg(kib_msg_t *msg, int type, int body_nob)
{
        msg->ibm_type = type;
        msg->ibm_nob  = offsetof(kib_msg_t, ibm_u) + body_nob;
}

void
kibnal_pack_msg(kib_msg_t *msg, int version, int credits, 
                lnet_nid_t dstnid, __u64 dststamp)
{
        /* CAVEAT EMPTOR! all message fields not set here should have been
         * initialised previously. */
        msg->ibm_magic    = IBNAL_MSG_MAGIC;
        msg->ibm_version  = version;
        /*   ibm_type */
        msg->ibm_credits  = credits;
        /*   ibm_nob */
        msg->ibm_cksum    = 0;
        msg->ibm_srcnid   = lnet_ptlcompat_srcnid(kibnal_data.kib_ni->ni_nid,
                                                  dstnid);
        msg->ibm_srcstamp = kibnal_data.kib_incarnation;
        msg->ibm_dstnid   = dstnid;
        msg->ibm_dststamp = dststamp;

        if (*kibnal_tunables.kib_cksum) {
                /* NB ibm_cksum zero while computing cksum */
                msg->ibm_cksum    = kibnal_cksum(msg, msg->ibm_nob);
        }
}

int
kibnal_unpack_msg(kib_msg_t *msg, int expected_version, int nob)
{
        const int hdr_size = offsetof(kib_msg_t, ibm_u);
        __u32     msg_cksum;
        int       msg_version;
        int       flip;
        int       msg_nob;

        if (nob < 6) {
                CERROR("Short message: %d\n", nob);
                return -EPROTO;
        }

        if (msg->ibm_magic == IBNAL_MSG_MAGIC) {
                flip = 0;
        } else if (msg->ibm_magic == __swab32(IBNAL_MSG_MAGIC)) {
                flip = 1;
        } else {
                CERROR("Bad magic: %08x\n", msg->ibm_magic);
                return -EPROTO;
        }

        msg_version = flip ? __swab16(msg->ibm_version) : msg->ibm_version;
        if ((expected_version == 0) ?
            (msg_version != IBNAL_MSG_VERSION &&
             msg_version != IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD) :
            (msg_version != expected_version)) {
                CERROR("Bad version: %x\n", msg_version);
                return -EPROTO;
        }

        if (nob < hdr_size) {
                CERROR("Short message: %d\n", nob);
                return -EPROTO;
        }

        msg_nob = flip ? __swab32(msg->ibm_nob) : msg->ibm_nob;
        if (msg_nob > nob) {
                CERROR("Short message: got %d, wanted %d\n", nob, msg_nob);
                return -EPROTO;
        }

        /* checksum must be computed with ibm_cksum zero and BEFORE anything
         * gets flipped */
        msg_cksum = flip ? __swab32(msg->ibm_cksum) : msg->ibm_cksum;
        msg->ibm_cksum = 0;
        if (msg_cksum != 0 &&
            msg_cksum != kibnal_cksum(msg, msg_nob)) {
                CERROR("Bad checksum\n");
                return -EPROTO;
        }
        msg->ibm_cksum = msg_cksum;
        
        if (flip) {
                /* leave magic unflipped as a clue to peer endianness */
                msg->ibm_version = msg_version;
                LASSERT (sizeof(msg->ibm_type) == 1);
                LASSERT (sizeof(msg->ibm_credits) == 1);
                msg->ibm_nob = msg_nob;
                __swab64s(&msg->ibm_srcnid);
                __swab64s(&msg->ibm_srcstamp);
                __swab64s(&msg->ibm_dstnid);
                __swab64s(&msg->ibm_dststamp);
        }
        
        if (msg->ibm_srcnid == LNET_NID_ANY) {
                CERROR("Bad src nid: %s\n", libcfs_nid2str(msg->ibm_srcnid));
                return -EPROTO;
        }

        switch (msg->ibm_type) {
        default:
                CERROR("Unknown message type %x\n", msg->ibm_type);
                return -EPROTO;
                
        case IBNAL_MSG_SVCQRY:
        case IBNAL_MSG_NOOP:
                break;

        case IBNAL_MSG_SVCRSP:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.svcrsp)) {
                        CERROR("Short SVCRSP: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.svcrsp)));
                        return -EPROTO;
                }
                if (flip) {
                        __swab64s(&msg->ibm_u.svcrsp.ibsr_svc_id);
                        __swab16s(&msg->ibm_u.svcrsp.ibsr_svc_pkey);
                }
                break;

        case IBNAL_MSG_CONNREQ:
        case IBNAL_MSG_CONNACK:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.connparams)) {
                        CERROR("Short CONNREQ: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.connparams)));
                        return -EPROTO;
                }
                if (flip)
                        __swab32s(&msg->ibm_u.connparams.ibcp_queue_depth);
                break;

        case IBNAL_MSG_IMMEDIATE:
                if (msg_nob < offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[0])) {
                        CERROR("Short IMMEDIATE: %d(%d)\n", msg_nob,
                               (int)offsetof(kib_msg_t, ibm_u.immediate.ibim_payload[0]));
                        return -EPROTO;
                }
                break;

        case IBNAL_MSG_PUT_RDMA:
        case IBNAL_MSG_GET_RDMA:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.rdma)) {
                        CERROR("Short RDMA req: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.rdma)));
                        return -EPROTO;
                }
                if (flip) {
                        __swab32s(&msg->ibm_u.rdma.ibrm_desc.rd_key);
                        __swab32s(&msg->ibm_u.rdma.ibrm_desc.rd_nob);
                        __swab64s(&msg->ibm_u.rdma.ibrm_desc.rd_addr);
                }
                break;

        case IBNAL_MSG_PUT_DONE:
        case IBNAL_MSG_GET_DONE:
                if (msg_nob < hdr_size + sizeof(msg->ibm_u.completion)) {
                        CERROR("Short RDMA completion: %d(%d)\n", msg_nob,
                               (int)(hdr_size + sizeof(msg->ibm_u.completion)));
                        return -EPROTO;
                }
                if (flip)
                        __swab32s(&msg->ibm_u.completion.ibcm_status);
                break;
        }
        return 0;
}

int
kibnal_make_svcqry (kib_conn_t *conn) 
{
        kib_peer_t    *peer = conn->ibc_peer;
        int            version = IBNAL_MSG_VERSION;
        int            msg_version;
        kib_msg_t     *msg;
        struct socket *sock;
        int            rc;
        int            nob;

        LASSERT (conn->ibc_connreq != NULL);
        msg = &conn->ibc_connreq->cr_msg;

 again:
        kibnal_init_msg(msg, IBNAL_MSG_SVCQRY, 0);
        kibnal_pack_msg(msg, version, 0, peer->ibp_nid, 0);

        rc = lnet_connect(&sock, peer->ibp_nid,
                          0, peer->ibp_ip, peer->ibp_port);
        if (rc != 0)
                return -ECONNABORTED;
        
        rc = libcfs_sock_write(sock, msg, msg->ibm_nob,
                               lnet_acceptor_timeout());
        if (rc != 0) {
                CERROR("Error %d sending svcqry to %s at %u.%u.%u.%u/%d\n", 
                       rc, libcfs_nid2str(peer->ibp_nid), 
                       HIPQUAD(peer->ibp_ip), peer->ibp_port);
                goto out;
        }

        /* The first 6 bytes are invariably MAGIC + proto version */
        rc = libcfs_sock_read(sock, msg, 6, *kibnal_tunables.kib_timeout);
        if (rc != 0) {
                CERROR("Error %d receiving svcrsp from %s at %u.%u.%u.%u/%d\n", 
                       rc, libcfs_nid2str(peer->ibp_nid), 
                       HIPQUAD(peer->ibp_ip), peer->ibp_port);
                goto out;
        }

        if (msg->ibm_magic != IBNAL_MSG_MAGIC &&
            msg->ibm_magic != __swab32(IBNAL_MSG_MAGIC)) {
                CERROR("Bad magic: %08x from %s at %u.%u.%u.%u/%d\n",
                       msg->ibm_magic, libcfs_nid2str(peer->ibp_nid),
                       HIPQUAD(peer->ibp_ip), peer->ibp_port);
                rc = -EPROTO;
                goto out;
        }

        msg_version = (msg->ibm_magic == IBNAL_MSG_MAGIC) ? 
                      msg->ibm_version : __swab16(msg->ibm_version);
        if (msg_version != version) {
                if (version == IBNAL_MSG_VERSION) {
                        /* retry with previous version */
                        libcfs_sock_release(sock);
                        version = IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD;
                        goto again;
                }
                
                CERROR("Bad version %x from %s at %u.%u.%u.%u/%d\n",
                       msg_version, libcfs_nid2str(peer->ibp_nid),
                       HIPQUAD(peer->ibp_ip), peer->ibp_port);
                rc = -EPROTO;
                goto out;
        }

        /* Read in the rest of the message now we know the expected format */
        nob = offsetof(kib_msg_t, ibm_u) + sizeof(kib_svcrsp_t);
        rc = libcfs_sock_read(sock, ((char *)msg) + 6, nob - 6,
                              *kibnal_tunables.kib_timeout);
        if (rc != 0) {
                CERROR("Error %d receiving svcrsp from %s at %u.%u.%u.%u/%d\n", 
                       rc, libcfs_nid2str(peer->ibp_nid), 
                       HIPQUAD(peer->ibp_ip), peer->ibp_port);
                goto out;
        }

        rc = kibnal_unpack_msg(msg, version, nob);
        if (rc != 0) {
                CERROR("Error %d unpacking svcrsp from %s at %u.%u.%u.%u/%d\n", 
                       rc, libcfs_nid2str(peer->ibp_nid), 
                       HIPQUAD(peer->ibp_ip), peer->ibp_port);
                goto out;
        }
                       
        if (msg->ibm_type != IBNAL_MSG_SVCRSP) {
                CERROR("Unexpected response type %d from %s at %u.%u.%u.%u/%d\n", 
                       msg->ibm_type, libcfs_nid2str(peer->ibp_nid), 
                       HIPQUAD(peer->ibp_ip), peer->ibp_port);
                rc = -EPROTO;
                goto out;
        }
        
        if (!lnet_ptlcompat_matchnid(kibnal_data.kib_ni->ni_nid,
                                     msg->ibm_dstnid) ||
            msg->ibm_dststamp != kibnal_data.kib_incarnation) {
                CERROR("Unexpected dst NID/stamp %s/"LPX64" from "
                       "%s at %u.%u.%u.%u/%d\n", 
                       libcfs_nid2str(msg->ibm_dstnid), msg->ibm_dststamp,
                       libcfs_nid2str(peer->ibp_nid), HIPQUAD(peer->ibp_ip), 
                       peer->ibp_port);
                rc = -EPROTO;
                goto out;
        }

        if (!lnet_ptlcompat_matchnid(peer->ibp_nid, msg->ibm_srcnid)) {
                CERROR("Unexpected src NID %s from %s at %u.%u.%u.%u/%d\n", 
                       libcfs_nid2str(msg->ibm_srcnid),
                       libcfs_nid2str(peer->ibp_nid), 
                       HIPQUAD(peer->ibp_ip), peer->ibp_port);
                rc = -EPROTO;
                goto out;
        }

        conn->ibc_incarnation = msg->ibm_srcstamp;
        conn->ibc_connreq->cr_svcrsp = msg->ibm_u.svcrsp;
        conn->ibc_version = version;
        
 out:
        libcfs_sock_release(sock);
        return rc;
}

void
kibnal_handle_svcqry (struct socket *sock)
{
        __u32                peer_ip;
        unsigned int         peer_port;
        kib_msg_t           *msg;
        __u64                srcnid;
        __u64                srcstamp;
        int                  version;
        int                  reject = 0;
        int                  rc;

        rc = libcfs_sock_getaddr(sock, 1, &peer_ip, &peer_port);
        if (rc != 0) {
                CERROR("Can't get peer's IP: %d\n", rc);
                return;
        }

        LIBCFS_ALLOC(msg, sizeof(*msg));
        if (msg == NULL) {
                CERROR("Can't allocate msgs for %u.%u.%u.%u/%d\n",
                       HIPQUAD(peer_ip), peer_port);
                return;
        }
        
        rc = libcfs_sock_read(sock, &msg->ibm_magic, sizeof(msg->ibm_magic),
                              lnet_acceptor_timeout());
        if (rc != 0) {
                CERROR("Error %d receiving svcqry(1) from %u.%u.%u.%u/%d\n",
                       rc, HIPQUAD(peer_ip), peer_port);
                goto out;
        }

        if (msg->ibm_magic != IBNAL_MSG_MAGIC &&
            msg->ibm_magic != __swab32(IBNAL_MSG_MAGIC)) {
                /* Unexpected magic! */
                if (the_lnet.ln_ptlcompat == 0) {
                        if (msg->ibm_magic == LNET_PROTO_MAGIC ||
                            msg->ibm_magic == __swab32(LNET_PROTO_MAGIC)) {
                                /* future protocol version compatibility!
                                 * When LNET unifies protocols over all LNDs,
                                 * the first thing sent will be a version
                                 * query.  I send back a reply in my current
                                 * protocol to tell her I'm "old" */
                                kibnal_init_msg(msg, 0, 0);
                                kibnal_pack_msg(msg, IBNAL_MSG_VERSION, 0, 
                                                LNET_NID_ANY, 0);
                                reject = 1;
                                goto reply;
                        }

                        CERROR ("Bad magic(1) %#08x (%#08x expected) from "
                                "%u.%u.%u.%u/%d\n", msg->ibm_magic,
                                IBNAL_MSG_MAGIC, HIPQUAD(peer_ip), peer_port);
                        goto out;
                }

                /* When portals compatibility is set, I may be passed a new
                 * connection "blindly" by the acceptor, and I have to
                 * determine if my peer has sent an acceptor connection request
                 * or not. */
                rc = lnet_accept(kibnal_data.kib_ni, sock, msg->ibm_magic);
                if (rc != 0)
                        goto out;

                /* It was an acceptor connection request!
                 * Now I should see my magic... */
                rc = libcfs_sock_read(sock, &msg->ibm_magic,
                                      sizeof(msg->ibm_magic),
                                      lnet_acceptor_timeout());
                if (rc != 0) {
                        CERROR("Error %d receiving svcqry(2) from %u.%u.%u.%u/%d\n",
                               rc, HIPQUAD(peer_ip), peer_port);
                        goto out;
                }

                if (msg->ibm_magic != IBNAL_MSG_MAGIC &&
                    msg->ibm_magic != __swab32(IBNAL_MSG_MAGIC)) {
                        CERROR ("Bad magic(2) %#08x (%#08x expected) from "
                                "%u.%u.%u.%u/%d\n", msg->ibm_magic,
                                IBNAL_MSG_MAGIC, HIPQUAD(peer_ip), peer_port);
                        goto out;
                }
        }

        /* Now check version */

        rc = libcfs_sock_read(sock, &msg->ibm_version, sizeof(msg->ibm_version),
                              lnet_acceptor_timeout());
        if (rc != 0) {
                CERROR("Error %d receiving svcqry(3) from %u.%u.%u.%u/%d\n",
                       rc, HIPQUAD(peer_ip), peer_port);
                goto out;
        }

        version = (msg->ibm_magic == IBNAL_MSG_MAGIC) ?
                  msg->ibm_version : __swab16(msg->ibm_version);
        /* Peer is a different protocol version: reply in my current protocol
         * to tell her I'm "old" */
        if (version != IBNAL_MSG_VERSION &&
            version != IBNAL_MSG_VERSION_RDMAREPLYNOTRSRVD) {
                kibnal_init_msg(msg, 0, 0);
                kibnal_pack_msg(msg, IBNAL_MSG_VERSION, 0, LNET_NID_ANY, 0);
                reject = 1;
                goto reply;
        }
        
        /* Now read in all the rest */
        rc = libcfs_sock_read(sock, &msg->ibm_type,
                              offsetof(kib_msg_t, ibm_u) -
                              offsetof(kib_msg_t, ibm_type),
                              lnet_acceptor_timeout());
        if (rc != 0) {
                CERROR("Error %d receiving svcqry(4) from %u.%u.%u.%u/%d\n",
                       rc, HIPQUAD(peer_ip), peer_port);
                goto out;
        }
        
        rc = kibnal_unpack_msg(msg, version, offsetof(kib_msg_t, ibm_u));
        if (rc != 0) {
                CERROR("Error %d unpacking svcqry from %u.%u.%u.%u/%d\n",
                       rc, HIPQUAD(peer_ip), peer_port);
                goto out;
        }
        
        if (msg->ibm_type != IBNAL_MSG_SVCQRY) {
                CERROR("Unexpected message %d from %u.%u.%u.%u/%d\n",
                       msg->ibm_type, HIPQUAD(peer_ip), peer_port);
                goto out;
        }
        
        if (!lnet_ptlcompat_matchnid(kibnal_data.kib_ni->ni_nid,
                                     msg->ibm_dstnid)) {
                CERROR("Unexpected dstnid %s: expected %s from %u.%u.%u.%u/%d\n",
                       libcfs_nid2str(msg->ibm_dstnid),
                       libcfs_nid2str(kibnal_data.kib_ni->ni_nid),
                       HIPQUAD(peer_ip), peer_port);
                goto out;
        }

        srcnid = msg->ibm_srcnid;
        srcstamp = msg->ibm_srcstamp;
        
        kibnal_init_msg(msg, IBNAL_MSG_SVCRSP, sizeof(msg->ibm_u.svcrsp));

        msg->ibm_u.svcrsp.ibsr_svc_id = kibnal_data.kib_svc_id;
        memcpy(msg->ibm_u.svcrsp.ibsr_svc_gid, kibnal_data.kib_svc_gid,
               sizeof(kibnal_data.kib_svc_gid));
        msg->ibm_u.svcrsp.ibsr_svc_pkey = kibnal_data.kib_svc_pkey;

        kibnal_pack_msg(msg, version, 0, srcnid, srcstamp);

 reply:
        rc = libcfs_sock_write (sock, msg, msg->ibm_nob,
                                lnet_acceptor_timeout());
        if (!reject && rc != 0) {
                /* Only complain if we're not rejecting */
                CERROR("Error %d replying to svcqry from %u.%u.%u.%u/%d\n",
                       rc, HIPQUAD(peer_ip), peer_port);
                goto out;
        }
        
 out:
        LIBCFS_FREE(msg, sizeof(*msg));
}

void
kibnal_free_acceptsock (kib_acceptsock_t *as)
{
        libcfs_sock_release(as->ibas_sock);
        LIBCFS_FREE(as, sizeof(*as));
}

int
kibnal_accept(lnet_ni_t *ni, struct socket *sock)
{
        kib_acceptsock_t  *as;
        unsigned long      flags;

        LIBCFS_ALLOC(as, sizeof(*as));
        if (as == NULL) {
                CERROR("Out of Memory\n");
                return -ENOMEM;
        }

        as->ibas_sock = sock;
                
        spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);
                
        list_add_tail(&as->ibas_list, &kibnal_data.kib_connd_acceptq);
        wake_up(&kibnal_data.kib_connd_waitq);

        spin_unlock_irqrestore(&kibnal_data.kib_connd_lock, flags);
        return 0;
}

int
kibnal_start_ib_listener (void) 
{
        int    rc;

        LASSERT (kibnal_data.kib_listen_handle == NULL);

        kibnal_data.kib_svc_id = ib_cm_service_assign();
        CDEBUG(D_NET, "svc id "LPX64"\n", kibnal_data.kib_svc_id);

        rc = ib_cached_gid_get(kibnal_data.kib_device,
                               kibnal_data.kib_port, 0,
                               kibnal_data.kib_svc_gid);
        if (rc != 0) {
                CERROR("Can't get port %d GID: %d\n",
                       kibnal_data.kib_port, rc);
                return rc;
        }
        
        rc = ib_cached_pkey_get(kibnal_data.kib_device,
                                kibnal_data.kib_port, 0,
                                &kibnal_data.kib_svc_pkey);
        if (rc != 0) {
                CERROR ("Can't get port %d PKEY: %d\n",
                        kibnal_data.kib_port, rc);
                return rc;
        }

        rc = ib_cm_listen(kibnal_data.kib_svc_id,
                          TS_IB_CM_SERVICE_EXACT_MASK,
                          kibnal_passive_conn_callback, NULL,
                          &kibnal_data.kib_listen_handle);
        if (rc != 0) {
                kibnal_data.kib_listen_handle = NULL;
                CERROR ("Can't create IB listener: %d\n", rc);
                return rc;
        }
        
        LASSERT (kibnal_data.kib_listen_handle != NULL);
        return 0;
}

void
kibnal_stop_ib_listener (void) 
{
        int    rc;
        
        LASSERT (kibnal_data.kib_listen_handle != NULL);

        rc = ib_cm_listen_stop (kibnal_data.kib_listen_handle);
        if (rc != 0)
                CERROR("Error stopping IB listener: %d\n", rc);
                
        kibnal_data.kib_listen_handle = NULL;
}

int
kibnal_create_peer (kib_peer_t **peerp, lnet_nid_t nid)
{
        kib_peer_t     *peer;
        unsigned long   flags;
        int             rc;

        LASSERT (nid != LNET_NID_ANY);

        LIBCFS_ALLOC(peer, sizeof (*peer));
        if (peer == NULL) {
                CERROR("Cannot allocate peer\n");
                return -ENOMEM;
        }

        memset(peer, 0, sizeof(*peer));         /* zero flags etc */

        peer->ibp_nid = nid;
        atomic_set (&peer->ibp_refcount, 1);    /* 1 ref for caller */

        INIT_LIST_HEAD (&peer->ibp_list);       /* not in the peer table yet */
        INIT_LIST_HEAD (&peer->ibp_conns);
        INIT_LIST_HEAD (&peer->ibp_tx_queue);
        INIT_LIST_HEAD (&peer->ibp_connd_list); /* not queued for connecting */

        peer->ibp_error = 0;
        peer->ibp_last_alive = cfs_time_current();
        peer->ibp_reconnect_interval = 0;       /* OK to connect at any time */

        write_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        if (atomic_read(&kibnal_data.kib_npeers) >=
            *kibnal_tunables.kib_concurrent_peers) {
                rc = -EOVERFLOW;        /* !! but at least it distinguishes */
        } else if (kibnal_data.kib_nonewpeers) {
                rc = -ESHUTDOWN;        /* shutdown has started */
        } else {
                rc = 0;
                /* npeers only grows with kib_global_lock held */
                atomic_inc(&kibnal_data.kib_npeers);
        }
        
        write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);

        if (rc != 0) {
                CERROR("Can't create peer: %s\n", 
                       (rc == -ESHUTDOWN) ? "shutting down" : 
                       "too many peers");
                LIBCFS_FREE(peer, sizeof(*peer));
        } else {
                *peerp = peer;
        }
        
        return rc;
}

void
kibnal_destroy_peer (kib_peer_t *peer)
{
        CDEBUG (D_NET, "peer %s %p deleted\n", 
                libcfs_nid2str(peer->ibp_nid), peer);

        LASSERT (atomic_read (&peer->ibp_refcount) == 0);
        LASSERT (peer->ibp_persistence == 0);
        LASSERT (!kibnal_peer_active(peer));
        LASSERT (peer->ibp_connecting == 0);
        LASSERT (peer->ibp_accepting == 0);
        LASSERT (list_empty (&peer->ibp_connd_list));
        LASSERT (list_empty (&peer->ibp_conns));
        LASSERT (list_empty (&peer->ibp_tx_queue));

        LIBCFS_FREE (peer, sizeof (*peer));

        /* NB a peer's connections keep a reference on their peer until
         * they are destroyed, so we can be assured that _all_ state to do
         * with this peer has been cleaned up when its refcount drops to
         * zero. */
        atomic_dec(&kibnal_data.kib_npeers);
}

kib_peer_t *
kibnal_find_peer_locked (lnet_nid_t nid)
{
        struct list_head *peer_list = kibnal_nid2peerlist (nid);
        struct list_head *tmp;
        kib_peer_t       *peer;

        list_for_each (tmp, peer_list) {

                peer = list_entry (tmp, kib_peer_t, ibp_list);

                LASSERT (peer->ibp_persistence != 0 || /* persistent peer */
                         peer->ibp_connecting != 0 || /* creating conns */
                         peer->ibp_accepting != 0 ||
                         !list_empty (&peer->ibp_conns));  /* active conn */

                if (peer->ibp_nid != nid)
                        continue;

                return (peer);
        }
        return (NULL);
}

kib_peer_t *
kibnal_get_peer (lnet_nid_t nid)
{
        kib_peer_t     *peer;
        unsigned long   flags;

        read_lock_irqsave(&kibnal_data.kib_global_lock, flags);
        peer = kibnal_find_peer_locked (nid);
        if (peer != NULL)                       /* +1 ref for caller? */
                kibnal_peer_addref(peer);
        read_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);

        return (peer);
}

void
kibnal_unlink_peer_locked (kib_peer_t *peer)
{
        LASSERT (peer->ibp_persistence == 0);
        LASSERT (list_empty(&peer->ibp_conns));

        LASSERT (kibnal_peer_active(peer));
        list_del_init (&peer->ibp_list);
        /* lose peerlist's ref */
        kibnal_peer_decref(peer);
}

int
kibnal_get_peer_info (int index, lnet_nid_t *nidp, __u32 *ipp, int *portp,
                      int *persistencep)
{
        kib_peer_t        *peer;
        struct list_head  *ptmp;
        unsigned long      flags;
        int                i;

        read_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        for (i = 0; i < kibnal_data.kib_peer_hash_size; i++) {

                list_for_each (ptmp, &kibnal_data.kib_peers[i]) {
                        
                        peer = list_entry (ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence != 0 ||
                                 peer->ibp_connecting != 0 ||
                                 peer->ibp_accepting != 0 ||
                                 !list_empty (&peer->ibp_conns));

                        if (index-- > 0)
                                continue;

                        *nidp = peer->ibp_nid;
                        *ipp = peer->ibp_ip;
                        *portp = peer->ibp_port;
                        *persistencep = peer->ibp_persistence;
                        
                        read_unlock_irqrestore(&kibnal_data.kib_global_lock,
                                               flags);
                        return (0);
                }
        }

        read_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
        return (-ENOENT);
}

int
kibnal_add_persistent_peer (lnet_nid_t nid, __u32 ip, int port)
{
        unsigned long      flags;
        kib_peer_t        *peer;
        kib_peer_t        *peer2;
        int                rc;
        
        if (nid == LNET_NID_ANY)
                return (-EINVAL);

        rc = kibnal_create_peer (&peer, nid);
        if (rc != 0)
                return rc;

        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        /* I'm always called with a reference on kibnal_data.kib_ni
         * so shutdown can't have started */
        LASSERT (kibnal_data.kib_nonewpeers == 0);

        peer2 = kibnal_find_peer_locked (nid);
        if (peer2 != NULL) {
                kibnal_peer_decref(peer);
                peer = peer2;
        } else {
                /* peer table takes existing ref on peer */
                list_add_tail (&peer->ibp_list,
                               kibnal_nid2peerlist (nid));
        }

        peer->ibp_ip = ip;
        peer->ibp_port = port;
        peer->ibp_persistence++;
        
        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);
        return (0);
}

void
kibnal_del_peer_locked (kib_peer_t *peer)
{
        struct list_head *ctmp;
        struct list_head *cnxt;
        kib_conn_t       *conn;

        peer->ibp_persistence = 0;

        if (list_empty(&peer->ibp_conns)) {
                kibnal_unlink_peer_locked(peer);
        } else {
                list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                        conn = list_entry(ctmp, kib_conn_t, ibc_list);

                        kibnal_close_conn_locked (conn, 0);
                }
                /* NB peer is no longer persistent; closing its last conn
                 * unlinked it. */
        }
        /* NB peer now unlinked; might even be freed if the peer table had the
         * last ref on it. */
}

int
kibnal_del_peer (lnet_nid_t nid)
{
        unsigned long      flags;
        CFS_LIST_HEAD     (zombies);
        struct list_head  *ptmp;
        struct list_head  *pnxt;
        kib_peer_t        *peer;
        int                lo;
        int                hi;
        int                i;
        int                rc = -ENOENT;

        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        if (nid != LNET_NID_ANY)
                lo = hi = kibnal_nid2peerlist(nid) - kibnal_data.kib_peers;
        else {
                lo = 0;
                hi = kibnal_data.kib_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                list_for_each_safe (ptmp, pnxt, &kibnal_data.kib_peers[i]) {
                        peer = list_entry (ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence != 0 ||
                                 peer->ibp_connecting != 0 ||
                                 peer->ibp_accepting != 0 ||
                                 !list_empty (&peer->ibp_conns));

                        if (!(nid == LNET_NID_ANY || peer->ibp_nid == nid))
                                continue;

                        if (!list_empty(&peer->ibp_tx_queue)) {
                                LASSERT (list_empty(&peer->ibp_conns));

                                list_splice_init(&peer->ibp_tx_queue, &zombies);
                        }

                        kibnal_del_peer_locked (peer);
                        rc = 0;         /* matched something */
                }
        }

        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);

        kibnal_txlist_done(&zombies, -EIO);

        return (rc);
}

kib_conn_t *
kibnal_get_conn_by_idx (int index)
{
        kib_peer_t        *peer;
        struct list_head  *ptmp;
        kib_conn_t        *conn;
        struct list_head  *ctmp;
        unsigned long      flags;
        int                i;

        read_lock_irqsave(&kibnal_data.kib_global_lock, flags);

        for (i = 0; i < kibnal_data.kib_peer_hash_size; i++) {
                list_for_each (ptmp, &kibnal_data.kib_peers[i]) {

                        peer = list_entry (ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence > 0 ||
                                 peer->ibp_connecting != 0 ||
                                 peer->ibp_accepting != 0 ||
                                 !list_empty (&peer->ibp_conns));

                        list_for_each (ctmp, &peer->ibp_conns) {
                                if (index-- > 0)
                                        continue;

                                conn = list_entry (ctmp, kib_conn_t, ibc_list);
                                kibnal_conn_addref(conn);
                                read_unlock_irqrestore(&kibnal_data.kib_global_lock,
                                                       flags);
                                return (conn);
                        }
                }
        }

        read_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);
        return (NULL);
}

kib_conn_t *
kibnal_create_conn (void)
{
        kib_conn_t  *conn;
        int          i;
        __u64        vaddr = 0;
        __u64        vaddr_base;
        int          page_offset;
        int          ipage;
        int          rc;
        union {
                struct ib_qp_create_param  qp_create;
                struct ib_qp_attribute     qp_attr;
        } params;
        
        LIBCFS_ALLOC (conn, sizeof (*conn));
        if (conn == NULL) {
                CERROR ("Can't allocate connection\n");
                return (NULL);
        }

        /* zero flags, NULL pointers etc... */
        memset (conn, 0, sizeof (*conn));

        INIT_LIST_HEAD (&conn->ibc_tx_queue_nocred);
        INIT_LIST_HEAD (&conn->ibc_tx_queue);
        INIT_LIST_HEAD (&conn->ibc_tx_queue_rsrvd);
        INIT_LIST_HEAD (&conn->ibc_active_txs);
        spin_lock_init (&conn->ibc_lock);
        
        atomic_inc (&kibnal_data.kib_nconns);
        /* well not really, but I call destroy() on failure, which decrements */

        LIBCFS_ALLOC (conn->ibc_rxs, IBNAL_RX_MSGS * sizeof (kib_rx_t));
        if (conn->ibc_rxs == NULL)
                goto failed;
        memset (conn->ibc_rxs, 0, IBNAL_RX_MSGS * sizeof(kib_rx_t));

        rc = kibnal_alloc_pages(&conn->ibc_rx_pages,
                                IBNAL_RX_MSG_PAGES,
                                IB_ACCESS_LOCAL_WRITE);
        if (rc != 0)
                goto failed;

        vaddr_base = vaddr = conn->ibc_rx_pages->ibp_vaddr;

        for (i = ipage = page_offset = 0; i < IBNAL_RX_MSGS; i++) {
                struct page *page = conn->ibc_rx_pages->ibp_pages[ipage];
                kib_rx_t   *rx = &conn->ibc_rxs[i];

                rx->rx_conn = conn;
                rx->rx_vaddr = vaddr;
                rx->rx_msg = (kib_msg_t *)(((char *)page_address(page)) + page_offset);
                
                vaddr += IBNAL_MSG_SIZE;
                LASSERT (vaddr <= vaddr_base + IBNAL_RX_MSG_BYTES);
                
                page_offset += IBNAL_MSG_SIZE;
                LASSERT (page_offset <= PAGE_SIZE);

                if (page_offset == PAGE_SIZE) {
                        page_offset = 0;
                        ipage++;
                        LASSERT (ipage <= IBNAL_RX_MSG_PAGES);
                }
        }

        /* We can post up to IBNAL_RX_MSGS, which may also include an
         * additional RDMA work item */

        params.qp_create = (struct ib_qp_create_param) {
                .limit = {
                        .max_outstanding_send_request    = 2 * IBNAL_RX_MSGS,
                        .max_outstanding_receive_request = IBNAL_RX_MSGS,
                        .max_send_gather_element         = 1,
                        .max_receive_scatter_element     = 1,
                },
                .pd              = kibnal_data.kib_pd,
                .send_queue      = kibnal_data.kib_cq,
                .receive_queue   = kibnal_data.kib_cq,
                .send_policy     = IB_WQ_SIGNAL_SELECTABLE,
                .receive_policy  = IB_WQ_SIGNAL_SELECTABLE,
                .rd_domain       = 0,
                .transport       = IB_TRANSPORT_RC,
                .device_specific = NULL,
        };
        
        rc = ib_qp_create (&params.qp_create, &conn->ibc_qp, &conn->ibc_qpn);
        if (rc != 0) {
                CERROR ("Failed to create queue pair: %d\n", rc);
                goto failed;
        }
        
        /* Mark QP created */
        conn->ibc_state = IBNAL_CONN_INIT_QP;

        params.qp_attr = (struct ib_qp_attribute) {
                .state             = IB_QP_STATE_INIT,
                .port              = kibnal_data.kib_port,
                .enable_rdma_read  = 1,
                .enable_rdma_write = 1,
                .valid_fields      = (IB_QP_ATTRIBUTE_STATE |
                                      IB_QP_ATTRIBUTE_PORT |
                                      IB_QP_ATTRIBUTE_PKEY_INDEX |
                                      IB_QP_ATTRIBUTE_RDMA_ATOMIC_ENABLE),
        };
        rc = ib_qp_modify(conn->ibc_qp, &params.qp_attr);
        if (rc != 0) {
                CERROR ("Failed to modify queue pair: %d\n", rc);
                goto failed;
        }

        /* 1 ref for caller */
        atomic_set (&conn->ibc_refcount, 1);
        return (conn);
        
 failed:
        kibnal_destroy_conn (conn);
        return (NULL);
}

void
kibnal_destroy_conn (kib_conn_t *conn)
{
        int    rc;
        
        CDEBUG (D_NET, "connection %p\n", conn);

        LASSERT (atomic_read (&conn->ibc_refcount) == 0);
        LASSERT (list_empty(&conn->ibc_tx_queue));
        LASSERT (list_empty(&conn->ibc_tx_queue_rsrvd));
        LASSERT (list_empty(&conn->ibc_tx_queue_nocred));
        LASSERT (list_empty(&conn->ibc_active_txs));
        LASSERT (conn->ibc_nsends_posted == 0);
        LASSERT (conn->ibc_connreq == NULL);

        switch (conn->ibc_state) {
        case IBNAL_CONN_ZOMBIE:
                /* called after connection sequence initiated */

        case IBNAL_CONN_INIT_QP:
                rc = ib_qp_destroy(conn->ibc_qp);
                if (rc != 0)
                        CERROR("Can't destroy QP: %d\n", rc);
                /* fall through */
                
        case IBNAL_CONN_INIT_NOTHING:
                break;

        default:
                LASSERT (0);
        }

        if (conn->ibc_rx_pages != NULL) 
                kibnal_free_pages(conn->ibc_rx_pages);
        
        if (conn->ibc_rxs != NULL)
                LIBCFS_FREE(conn->ibc_rxs, 
                            IBNAL_RX_MSGS * sizeof(kib_rx_t));

        if (conn->ibc_peer != NULL)
                kibnal_peer_decref(conn->ibc_peer);

        LIBCFS_FREE(conn, sizeof (*conn));

        atomic_dec(&kibnal_data.kib_nconns);
        
        if (atomic_read (&kibnal_data.kib_nconns) == 0 &&
            kibnal_data.kib_shutdown) {
                /* I just nuked the last connection on shutdown; wake up
                 * everyone so they can exit. */
                wake_up_all(&kibnal_data.kib_sched_waitq);
                wake_up_all(&kibnal_data.kib_reaper_waitq);
        }
}

int
kibnal_close_peer_conns_locked (kib_peer_t *peer, int why)
{
        kib_conn_t         *conn;
        struct list_head   *ctmp;
        struct list_head   *cnxt;
        int                 count = 0;

        list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                conn = list_entry (ctmp, kib_conn_t, ibc_list);

                count++;
                kibnal_close_conn_locked (conn, why);
        }

        return (count);
}

int
kibnal_close_stale_conns_locked (kib_peer_t *peer, __u64 incarnation)
{
        kib_conn_t         *conn;
        struct list_head   *ctmp;
        struct list_head   *cnxt;
        int                 count = 0;

        list_for_each_safe (ctmp, cnxt, &peer->ibp_conns) {
                conn = list_entry (ctmp, kib_conn_t, ibc_list);

                if (conn->ibc_incarnation == incarnation)
                        continue;

                CDEBUG(D_NET, "Closing stale conn %p nid: %s"
                       " incarnation:"LPX64"("LPX64")\n", conn,
                       libcfs_nid2str(peer->ibp_nid), 
                       conn->ibc_incarnation, incarnation);
                
                count++;
                kibnal_close_conn_locked (conn, -ESTALE);
        }

        return (count);
}

int
kibnal_close_matching_conns (lnet_nid_t nid)
{
        unsigned long       flags;
        kib_peer_t         *peer;
        struct list_head   *ptmp;
        struct list_head   *pnxt;
        int                 lo;
        int                 hi;
        int                 i;
        int                 count = 0;

        write_lock_irqsave (&kibnal_data.kib_global_lock, flags);

        if (nid != LNET_NID_ANY)
                lo = hi = kibnal_nid2peerlist(nid) - kibnal_data.kib_peers;
        else {
                lo = 0;
                hi = kibnal_data.kib_peer_hash_size - 1;
        }

        for (i = lo; i <= hi; i++) {
                list_for_each_safe (ptmp, pnxt, &kibnal_data.kib_peers[i]) {

                        peer = list_entry (ptmp, kib_peer_t, ibp_list);
                        LASSERT (peer->ibp_persistence != 0 ||
                                 peer->ibp_connecting != 0 ||
                                 peer->ibp_accepting != 0 ||
                                 !list_empty (&peer->ibp_conns));

                        if (!(nid == LNET_NID_ANY || nid == peer->ibp_nid))
                                continue;

                        count += kibnal_close_peer_conns_locked (peer, 0);
                }
        }

        write_unlock_irqrestore (&kibnal_data.kib_global_lock, flags);

        /* wildcards always succeed */
        if (nid == LNET_NID_ANY)
                return (0);
        
        return (count == 0 ? -ENOENT : 0);
}

int
kibnal_ctl(lnet_ni_t *ni, unsigned int cmd, void *arg)
{
        struct libcfs_ioctl_data *data = arg;
        int                       rc = -EINVAL;

        LASSERT (ni == kibnal_data.kib_ni);

        switch(cmd) {
        case IOC_LIBCFS_GET_PEER: {
                lnet_nid_t   nid = 0;
                __u32       ip = 0;
                int         port = 0;
                int         share_count = 0;

                rc = kibnal_get_peer_info(data->ioc_count,
                                          &nid, &ip, &port, &share_count);
                data->ioc_nid    = nid;
                data->ioc_count  = share_count;
                data->ioc_u32[0] = ip;
                data->ioc_u32[1] = port;
                break;
        }
        case IOC_LIBCFS_ADD_PEER: {
                rc = kibnal_add_persistent_peer (data->ioc_nid,
                                                 data->ioc_u32[0], /* IP */
                                                 data->ioc_u32[1]); /* port */
                break;
        }
        case IOC_LIBCFS_DEL_PEER: {
                rc = kibnal_del_peer (data->ioc_nid);
                break;
        }
        case IOC_LIBCFS_GET_CONN: {
                kib_conn_t *conn = kibnal_get_conn_by_idx (data->ioc_count);

                if (conn == NULL)
                        rc = -ENOENT;
                else {
                        rc = 0;
                        data->ioc_nid = conn->ibc_peer->ibp_nid;
                        kibnal_conn_decref(conn);
                }
                break;
        }
        case IOC_LIBCFS_CLOSE_CONNECTION: {
                rc = kibnal_close_matching_conns (data->ioc_nid);
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
kibnal_free_pages (kib_pages_t *p)
{
        int     npages = p->ibp_npages;
        int     rc;
        int     i;
        
        if (p->ibp_mapped) {
                rc = ib_memory_deregister(p->ibp_handle);
                if (rc != 0)
                        CERROR ("Deregister error: %d\n", rc);
        }
        
        for (i = 0; i < npages; i++)
                if (p->ibp_pages[i] != NULL)
                        __free_page(p->ibp_pages[i]);
        
        LIBCFS_FREE (p, offsetof(kib_pages_t, ibp_pages[npages]));
}

int
kibnal_alloc_pages (kib_pages_t **pp, int npages, int access)
{
        kib_pages_t                *p;
        struct ib_physical_buffer  *phys_pages;
        int                         i;
        int                         rc;

        LIBCFS_ALLOC(p, offsetof(kib_pages_t, ibp_pages[npages]));
        if (p == NULL) {
                CERROR ("Can't allocate buffer %d\n", npages);
                return (-ENOMEM);
        }

        memset (p, 0, offsetof(kib_pages_t, ibp_pages[npages]));
        p->ibp_npages = npages;
        
        for (i = 0; i < npages; i++) {
                p->ibp_pages[i] = alloc_page (GFP_KERNEL);
                if (p->ibp_pages[i] == NULL) {
                        CERROR ("Can't allocate page %d of %d\n", i, npages);
                        kibnal_free_pages(p);
                        return (-ENOMEM);
                }
        }

        LIBCFS_ALLOC(phys_pages, npages * sizeof(*phys_pages));
        if (phys_pages == NULL) {
                CERROR ("Can't allocate physarray for %d pages\n", npages);
                kibnal_free_pages(p);
                return (-ENOMEM);
        }

        for (i = 0; i < npages; i++) {
                phys_pages[i].size = PAGE_SIZE;
                phys_pages[i].address =
                        lnet_page2phys(p->ibp_pages[i]);
        }

        p->ibp_vaddr = 0;
        rc = ib_memory_register_physical(kibnal_data.kib_pd,
                                         phys_pages, npages,
                                         &p->ibp_vaddr,
                                         npages * PAGE_SIZE, 0,
                                         access,
                                         &p->ibp_handle,
                                         &p->ibp_lkey,
                                         &p->ibp_rkey);
        
        LIBCFS_FREE(phys_pages, npages * sizeof(*phys_pages));
        
        if (rc != 0) {
                CERROR ("Error %d mapping %d pages\n", rc, npages);
                kibnal_free_pages(p);
                return (rc);
        }
        
        p->ibp_mapped = 1;
        *pp = p;
        return (0);
}

int
kibnal_setup_tx_descs (void)
{
        int           ipage = 0;
        int           page_offset = 0;
        __u64         vaddr;
        __u64         vaddr_base;
        struct page  *page;
        kib_tx_t     *tx;
        int           i;
        int           rc;

        /* pre-mapped messages are not bigger than 1 page */
        LASSERT (IBNAL_MSG_SIZE <= PAGE_SIZE);

        /* No fancy arithmetic when we do the buffer calculations */
        LASSERT (PAGE_SIZE % IBNAL_MSG_SIZE == 0);

        rc = kibnal_alloc_pages(&kibnal_data.kib_tx_pages,
                                IBNAL_TX_MSG_PAGES(), 
                                0);            /* local read access only */
        if (rc != 0)
                return (rc);

        vaddr = vaddr_base = kibnal_data.kib_tx_pages->ibp_vaddr;

        for (i = 0; i < IBNAL_TX_MSGS(); i++) {
                page = kibnal_data.kib_tx_pages->ibp_pages[ipage];
                tx = &kibnal_data.kib_tx_descs[i];

                memset (tx, 0, sizeof(*tx));    /* zero flags etc */
                
                tx->tx_msg = (kib_msg_t *)(((char *)page_address(page)) + page_offset);
                tx->tx_vaddr = vaddr;
                tx->tx_mapped = KIB_TX_UNMAPPED;

                CDEBUG(D_NET, "Tx[%d] %p->%p - "LPX64"\n", 
                       i, tx, tx->tx_msg, tx->tx_vaddr);

                list_add (&tx->tx_list, &kibnal_data.kib_idle_txs);

                vaddr += IBNAL_MSG_SIZE;
                LASSERT (vaddr <= vaddr_base + IBNAL_TX_MSG_BYTES());

                page_offset += IBNAL_MSG_SIZE;
                LASSERT (page_offset <= PAGE_SIZE);

                if (page_offset == PAGE_SIZE) {
                        page_offset = 0;
                        ipage++;
                        LASSERT (ipage <= IBNAL_TX_MSG_PAGES());
                }
        }
        
        return (0);
}

void
kibnal_shutdown (lnet_ni_t *ni)
{
        int           i;
        int           rc;
        unsigned long flags;

        CDEBUG(D_MALLOC, "before NAL cleanup: kmem %d\n",
               atomic_read (&libcfs_kmemory));

        LASSERT(ni == kibnal_data.kib_ni);
        LASSERT(ni->ni_data == &kibnal_data);

        switch (kibnal_data.kib_init) {
        default:
                CERROR ("Unexpected state %d\n", kibnal_data.kib_init);
                LBUG();

        case IBNAL_INIT_ALL:
                /* Prevent new peers from being created */
                write_lock_irqsave(&kibnal_data.kib_global_lock, flags);
                kibnal_data.kib_nonewpeers = 1;
                write_unlock_irqrestore(&kibnal_data.kib_global_lock, flags);

                kibnal_stop_ib_listener();

                /* Remove all existing peers from the peer table */
                kibnal_del_peer(LNET_NID_ANY);
                
                /* Wait for pending conn reqs to be handled */
                i = 2;
                spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);
                while (!list_empty(&kibnal_data.kib_connd_acceptq)) {
                        spin_unlock_irqrestore(&kibnal_data.kib_connd_lock, 
                                               flags);
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* 2**n */
                               "waiting for conn reqs to clean up\n");
                        cfs_pause(cfs_time_seconds(1));
                        
                        spin_lock_irqsave(&kibnal_data.kib_connd_lock, flags);
                }
                spin_unlock_irqrestore(&kibnal_data.kib_connd_lock, flags);

                /* Wait for all peer state to clean up */
                i = 2;
                while (atomic_read(&kibnal_data.kib_npeers) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "waiting for %d peers to close down\n",
                               atomic_read(&kibnal_data.kib_npeers));
                        cfs_pause(cfs_time_seconds(1));
                }
                /* fall through */

        case IBNAL_INIT_CQ:
                rc = ib_cq_destroy (kibnal_data.kib_cq);
                if (rc != 0)
                        CERROR ("Destroy CQ error: %d\n", rc);
                /* fall through */

        case IBNAL_INIT_TXD:
                kibnal_free_pages (kibnal_data.kib_tx_pages);
                /* fall through */
#if IBNAL_FMR
        case IBNAL_INIT_FMR:
                rc = ib_fmr_pool_destroy (kibnal_data.kib_fmr_pool);
                if (rc != 0)
                        CERROR ("Destroy FMR pool error: %d\n", rc);
                /* fall through */
#endif
        case IBNAL_INIT_PD:
                rc = ib_pd_destroy(kibnal_data.kib_pd);
                if (rc != 0)
                        CERROR ("Destroy PD error: %d\n", rc);
                /* fall through */

        case IBNAL_INIT_DATA:
                /* Module refcount only gets to zero when all peers
                 * have been closed so all lists must be empty */
                LASSERT (atomic_read(&kibnal_data.kib_npeers) == 0);
                LASSERT (kibnal_data.kib_peers != NULL);
                for (i = 0; i < kibnal_data.kib_peer_hash_size; i++) {
                        LASSERT (list_empty (&kibnal_data.kib_peers[i]));
                }
                LASSERT (atomic_read (&kibnal_data.kib_nconns) == 0);
                LASSERT (list_empty (&kibnal_data.kib_sched_rxq));
                LASSERT (list_empty (&kibnal_data.kib_sched_txq));
                LASSERT (list_empty (&kibnal_data.kib_reaper_conns));
                LASSERT (list_empty (&kibnal_data.kib_connd_peers));
                LASSERT (list_empty (&kibnal_data.kib_connd_acceptq));

                /* flag threads to terminate; wake and wait for them to die */
                kibnal_data.kib_shutdown = 1;
                wake_up_all (&kibnal_data.kib_sched_waitq);
                wake_up_all (&kibnal_data.kib_reaper_waitq);
                wake_up_all (&kibnal_data.kib_connd_waitq);

                i = 2;
                while (atomic_read (&kibnal_data.kib_nthreads) != 0) {
                        i++;
                        CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                               "Waiting for %d threads to terminate\n",
                               atomic_read (&kibnal_data.kib_nthreads));
                        cfs_pause(cfs_time_seconds(1));
                }
                /* fall through */
                
        case IBNAL_INIT_NOTHING:
                break;
        }

        if (kibnal_data.kib_tx_descs != NULL)
                LIBCFS_FREE (kibnal_data.kib_tx_descs,
                             IBNAL_TX_MSGS() * sizeof(kib_tx_t));

        if (kibnal_data.kib_peers != NULL)
                LIBCFS_FREE (kibnal_data.kib_peers,
                             sizeof (struct list_head) * 
                             kibnal_data.kib_peer_hash_size);

        CDEBUG(D_MALLOC, "after NAL cleanup: kmem %d\n",
               atomic_read (&libcfs_kmemory));

        kibnal_data.kib_init = IBNAL_INIT_NOTHING;
        PORTAL_MODULE_UNUSE;
}

int
kibnal_get_ipoibidx(void)
{
        /* NB single threaded! */
        static struct ib_port_properties port_props;

        int               ipoibidx = 0;
        int               devidx;
        int               port;
        int               rc;
        struct ib_device *device;

        for (devidx = 0; devidx <= kibnal_data.kib_hca_idx; devidx++) {
                device = ib_device_get_by_index(devidx);
                
                if (device == NULL) {
                        CERROR("Can't get IB device %d\n", devidx);
                        return -1;
                }
                
                for (port = 1; port <= 2; port++) {
                        if (devidx == kibnal_data.kib_hca_idx &&
                            port == kibnal_data.kib_port)
                                return ipoibidx;
                        
                        rc = ib_port_properties_get(device, port,
                                                    &port_props);
                        if (rc == 0)
                                ipoibidx++;
                }
        }

        LBUG();
        return -1;
}

int
kibnal_startup (lnet_ni_t *ni)
{
        char              ipif_name[32];
        __u32             ip;
        __u32             netmask;
        int               up;
        struct timeval    tv;
        int               rc;
        int               hca;
        int               port;
        int               i;
        int               nob;

        LASSERT (ni->ni_lnd == &the_kiblnd);

        /* Only 1 instance supported */
        if (kibnal_data.kib_init != IBNAL_INIT_NOTHING) {
                CERROR ("Only 1 instance supported\n");
                return -EPERM;
        }

        if (*kibnal_tunables.kib_credits > *kibnal_tunables.kib_ntx) {
                CERROR ("Can't set credits(%d) > ntx(%d)\n",
                        *kibnal_tunables.kib_credits,
                        *kibnal_tunables.kib_ntx);
                return -EINVAL;
        }

        memset (&kibnal_data, 0, sizeof (kibnal_data)); /* zero pointers, flags etc */

        ni->ni_maxtxcredits = *kibnal_tunables.kib_credits;
        ni->ni_peertxcredits = *kibnal_tunables.kib_peercredits;

        CLASSERT (LNET_MAX_INTERFACES > 1);


        kibnal_data.kib_hca_idx = 0;            /* default: first HCA */
        kibnal_data.kib_port = 0;               /* any port */

        if (ni->ni_interfaces[0] != NULL) {
                /* hca.port specified in 'networks=openib(h.p)' */
                if (ni->ni_interfaces[1] != NULL) {
                        CERROR("Multiple interfaces not supported\n");
                        return -EPERM;
                }
                
                nob = strlen(ni->ni_interfaces[0]);
                i = sscanf(ni->ni_interfaces[0], "%d.%d%n", &hca, &port, &nob);
                if (i >= 2 && nob == strlen(ni->ni_interfaces[0])) {
                        kibnal_data.kib_hca_idx = hca;
                        kibnal_data.kib_port = port;
                } else {
                        nob = strlen(ni->ni_interfaces[0]);
                        i = sscanf(ni->ni_interfaces[0], "%d%n", &hca, &nob);

                        if (i >= 1 && nob == strlen(ni->ni_interfaces[0])) {
                                kibnal_data.kib_hca_idx = hca;
                        } else {
                                CERROR("Can't parse interface '%s'\n",
                                       ni->ni_interfaces[0]);
                                return -EINVAL;
                        }
                }
        }
        
        kibnal_data.kib_ni = ni;
        ni->ni_data = &kibnal_data;
        
        do_gettimeofday(&tv);
        kibnal_data.kib_incarnation = (((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;

        PORTAL_MODULE_USE;

        rwlock_init(&kibnal_data.kib_global_lock);

        kibnal_data.kib_peer_hash_size = IBNAL_PEER_HASH_SIZE;
        LIBCFS_ALLOC (kibnal_data.kib_peers,
                      sizeof (struct list_head) * kibnal_data.kib_peer_hash_size);
        if (kibnal_data.kib_peers == NULL) {
                goto failed;
        }
        for (i = 0; i < kibnal_data.kib_peer_hash_size; i++)
                INIT_LIST_HEAD(&kibnal_data.kib_peers[i]);

        spin_lock_init (&kibnal_data.kib_reaper_lock);
        INIT_LIST_HEAD (&kibnal_data.kib_reaper_conns);
        init_waitqueue_head (&kibnal_data.kib_reaper_waitq);

        spin_lock_init (&kibnal_data.kib_connd_lock);
        INIT_LIST_HEAD (&kibnal_data.kib_connd_acceptq);
        INIT_LIST_HEAD (&kibnal_data.kib_connd_peers);
        init_waitqueue_head (&kibnal_data.kib_connd_waitq);

        spin_lock_init (&kibnal_data.kib_sched_lock);
        INIT_LIST_HEAD (&kibnal_data.kib_sched_txq);
        INIT_LIST_HEAD (&kibnal_data.kib_sched_rxq);
        init_waitqueue_head (&kibnal_data.kib_sched_waitq);

        spin_lock_init (&kibnal_data.kib_tx_lock);
        INIT_LIST_HEAD (&kibnal_data.kib_idle_txs);

        LIBCFS_ALLOC (kibnal_data.kib_tx_descs,
                      IBNAL_TX_MSGS() * sizeof(kib_tx_t));
        if (kibnal_data.kib_tx_descs == NULL) {
                CERROR ("Can't allocate tx descs\n");
                goto failed;
        }

        /* lists/ptrs/locks initialised */
        kibnal_data.kib_init = IBNAL_INIT_DATA;
        /*****************************************************/

        for (i = 0; i < IBNAL_N_SCHED; i++) {
                rc = kibnal_thread_start (kibnal_scheduler,
                                          (void *)((unsigned long)i));
                if (rc != 0) {
                        CERROR("Can't spawn openibnal scheduler[%d]: %d\n",
                               i, rc);
                        goto failed;
                }
        }

        /* must have at least 2 connds to remain responsive to svcqry while
         * connecting */
        if (*kibnal_tunables.kib_n_connd < 2)
                *kibnal_tunables.kib_n_connd = 2;


        for (i = 0; i < *kibnal_tunables.kib_n_connd; i++) {
                rc = kibnal_thread_start (kibnal_connd,
                                          (void *)((unsigned long)i));
                if (rc != 0) {
                        CERROR("Can't spawn openibnal connd[%d]: %d\n",
                               i, rc);
                        goto failed;
                }
        }

        rc = kibnal_thread_start (kibnal_reaper, NULL);
        if (rc != 0) {
                CERROR ("Can't spawn openibnal reaper: %d\n", rc);
                goto failed;
        }

        kibnal_data.kib_device = ib_device_get_by_index(kibnal_data.kib_hca_idx);
        if (kibnal_data.kib_device == NULL) {
                CERROR ("Can't open ib device %d\n",
                        kibnal_data.kib_hca_idx);
                goto failed;
        }
        
        rc = ib_device_properties_get(kibnal_data.kib_device,
                                      &kibnal_data.kib_device_props);
        if (rc != 0) {
                CERROR ("Can't get device props: %d\n", rc);
                goto failed;
        }

        CDEBUG(D_NET, "Max Initiator: %d Max Responder %d\n", 
               kibnal_data.kib_device_props.max_initiator_per_qp,
               kibnal_data.kib_device_props.max_responder_per_qp);

        if (kibnal_data.kib_port != 0) {
                rc = ib_port_properties_get(kibnal_data.kib_device, 
                                            kibnal_data.kib_port,
                                            &kibnal_data.kib_port_props);
                if (rc != 0) {
                        CERROR("Error %d open port %d on HCA %d\n", rc,
                               kibnal_data.kib_port,
                               kibnal_data.kib_hca_idx);
                        goto failed;
                }
        } else {
                for (i = 1; i <= 2; i++) {
                        rc = ib_port_properties_get(kibnal_data.kib_device, i,
                                                    &kibnal_data.kib_port_props);
                        if (rc == 0) {
                                kibnal_data.kib_port = i;
                                break;
                        }
                }
                if (kibnal_data.kib_port == 0) {
                        CERROR ("Can't find a port\n");
                        goto failed;
                }
        }

        i = kibnal_get_ipoibidx();
        if (i < 0)
                goto failed;
        
        snprintf(ipif_name, sizeof(ipif_name), "%s%d",
                 *kibnal_tunables.kib_ipif_basename, i);
        if (strlen(ipif_name) == sizeof(ipif_name) - 1) {
                CERROR("IPoIB interface name %s truncated\n", ipif_name);
                return -EINVAL;
        }
        
        rc = libcfs_ipif_query(ipif_name, &up, &ip, &netmask);
        if (rc != 0) {
                CERROR("Can't query IPoIB interface %s: %d\n", ipif_name, rc);
                goto failed;
        }
        
        if (!up) {
                CERROR("Can't query IPoIB interface %s: it's down\n", ipif_name);
                goto failed;
        }
        
        ni->ni_nid = LNET_MKNID(LNET_NIDNET(ni->ni_nid), ip);

        rc = ib_pd_create(kibnal_data.kib_device,
                          NULL, &kibnal_data.kib_pd);
        if (rc != 0) {
                CERROR ("Can't create PD: %d\n", rc);
                goto failed;
        }
        
        /* flag PD initialised */
        kibnal_data.kib_init = IBNAL_INIT_PD;
        /*****************************************************/
#if IBNAL_FMR
        {
                const int pool_size = *kibnal_tunables.kib_ntx;
                struct ib_fmr_pool_param params = {
                        .max_pages_per_fmr = LNET_MAX_PAYLOAD/PAGE_SIZE,
                        .access            = (IB_ACCESS_LOCAL_WRITE |
                                              IB_ACCESS_REMOTE_WRITE |
                                              IB_ACCESS_REMOTE_READ),
                        .pool_size         = pool_size,
                        .dirty_watermark   = (pool_size * 3)/4,
                        .flush_function    = NULL,
                        .flush_arg         = NULL,
                        .cache             = 1,
                };
                rc = ib_fmr_pool_create(kibnal_data.kib_pd, &params,
                                        &kibnal_data.kib_fmr_pool);
                if (rc != 0) {
                        CERROR ("Can't create FMR pool size %d: %d\n", 
                                pool_size, rc);
                        goto failed;
                }
        }

        /* flag FMR pool initialised */
        kibnal_data.kib_init = IBNAL_INIT_FMR;
#endif
        /*****************************************************/

        rc = kibnal_setup_tx_descs();
        if (rc != 0) {
                CERROR ("Can't register tx descs: %d\n", rc);
                goto failed;
        }
        
        /* flag TX descs initialised */
        kibnal_data.kib_init = IBNAL_INIT_TXD;
        /*****************************************************/
        
        {
                struct ib_cq_callback callback = {
                        .context        = IBNAL_CALLBACK_CTXT,
                        .policy         = IB_CQ_PROVIDER_REARM,
                        .function       = {
                                .entry  = kibnal_callback,
                        },
                        .arg            = NULL,
                };
                int  nentries = IBNAL_CQ_ENTRIES();
                
                rc = ib_cq_create (kibnal_data.kib_device, 
                                   &nentries, &callback, NULL,
                                   &kibnal_data.kib_cq);
                if (rc != 0) {
                        CERROR ("Can't create CQ: %d\n", rc);
                        goto failed;
                }

                /* I only want solicited events */
                rc = ib_cq_request_notification(kibnal_data.kib_cq, 1);
                LASSERT (rc == 0);
        }

        /* flag CQ initialised */
        kibnal_data.kib_init = IBNAL_INIT_CQ;
        /*****************************************************/

        rc = kibnal_start_ib_listener();
        if (rc != 0)
                goto failed;
        
        /* flag everything initialised */
        kibnal_data.kib_init = IBNAL_INIT_ALL;
        /*****************************************************/

        return 0;

 failed:
        kibnal_shutdown(ni);    
        return -ENETDOWN;
}

void __exit
kibnal_module_fini (void)
{
        lnet_unregister_lnd(&the_kiblnd);
        kibnal_tunables_fini();
}

int __init
kibnal_module_init (void)
{
        int    rc;

        rc = kibnal_tunables_init();
        if (rc != 0)
                return rc;
        
        lnet_register_lnd(&the_kiblnd);

        return (0);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
#ifdef USING_TSAPI
MODULE_DESCRIPTION("Kernel Cisco IB LND v1.00");
#else
MODULE_DESCRIPTION("Kernel OpenIB(gen1) LND v1.00");
#endif
MODULE_LICENSE("GPL");

module_init(kibnal_module_init);
module_exit(kibnal_module_fini);
